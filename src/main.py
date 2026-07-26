import argparse
import json
import sys
from pathlib import Path

from src.data_loader import load_train_samples
from src.env_loader import load_project_env
from src.evaluate import load_untrusted_context_list, run_evaluation, write_report_json
from src.llm import MissingApiKeyError, OpenRouterClient, dedupe_findings, request_additional_findings
from src.paths import OUTPUT_DIR
from src.predict import predict_split
from src.patcher import generate_patch_for_sample
from src.scan_pipeline import collect_findings


def _add_llm_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Augment rule-based findings with OpenRouter (requires OPENROUTER_API_KEY).",
    )


def _print_scan_results(report, sample_id: str | None, use_llm: bool) -> None:
    print(f"Loaded {report.sample_count} sample(s)")
    print(f"Using {report.untrusted_context_count} untrusted context(s)")
    if use_llm:
        print("LLM augmentation: enabled\n")
    else:
        print()

    for result in report.results:
        status = "VULN" if result.predicted_vulnerable else "CLEAN"
        label = "VULN" if result.actual_vulnerable else "CLEAN"
        match = "ok" if result.is_correct else "MISS"
        print(
            f"[{match}] {result.sample_id}: predicted={status}, "
            f"label={label}, hits={result.findings_count}"
        )

        if sample_id and result.findings_count > 0:
            sample = next(s for s in load_train_samples() if s.sample_id == sample_id)
            findings = collect_findings(
                sample.workflow_path,
                load_untrusted_context_list(),
                use_llm=use_llm,
            )
            print(json.dumps([finding.__dict__ for finding in findings], indent=2))

    metrics = report.metrics
    print(
        f"\nChecked {report.sample_count} samples | "
        f"TP={metrics.tp} FP={metrics.fp} FN={metrics.fn} TN={metrics.tn}"
    )


def _print_eval_summary(report) -> None:
    metrics = report.metrics
    print(f"Evaluated {report.sample_count} samples")
    print(f"Untrusted contexts: {report.untrusted_context_count}\n")
    print(f"TP={metrics.tp}  FP={metrics.fp}  FN={metrics.fn}  TN={metrics.tn}")
    print(f"Precision={metrics.precision:.3f}  Recall={metrics.recall:.3f}  F1={metrics.f1:.3f}")

    misses = [result for result in report.results if not result.is_correct]
    if misses:
        print(f"\nMisses ({len(misses)}):")
        for result in misses:
            predicted = "VULN" if result.predicted_vulnerable else "CLEAN"
            actual = "VULN" if result.actual_vulnerable else "CLEAN"
            print(f"  {result.sample_id}: predicted={predicted}, label={actual}")


def cmd_scan(args: argparse.Namespace) -> None:
    try:
        report = run_evaluation(
            sample_id=args.sample_id,
            limit=None if args.full else args.limit,
            use_llm=args.use_llm,
        )
    except MissingApiKeyError as error:
        raise SystemExit(str(error)) from error
    except ValueError as error:
        raise SystemExit(str(error)) from error
    _print_scan_results(report, args.sample_id, args.use_llm)


def cmd_eval(args: argparse.Namespace) -> None:
    try:
        limit = None if args.full else args.limit
        report = run_evaluation(
            sample_id=args.sample_id,
            limit=limit,
            use_llm=args.use_llm,
        )
    except MissingApiKeyError as error:
        raise SystemExit(str(error)) from error
    except ValueError as error:
        raise SystemExit(str(error)) from error

    _print_eval_summary(report)
    if args.json:
        write_report_json(report, Path(args.json))
        print(f"\nWrote report to {args.json}")


def cmd_patch(args: argparse.Namespace) -> None:
    if not args.sample_id:
        raise SystemExit("--sample-id is required for patch")

    samples = load_train_samples()
    sample = next((item for item in samples if item.sample_id == args.sample_id), None)
    if sample is None:
        raise SystemExit(f"Unknown sample_id: {args.sample_id}")

    untrusted = load_untrusted_context_list()
    try:
        findings = collect_findings(sample.workflow_path, untrusted, use_llm=args.use_llm)
    except MissingApiKeyError as error:
        raise SystemExit(str(error)) from error

    patch_text = generate_patch_for_sample(args.sample_id, findings, untrusted)
    if not patch_text:
        print("No patch generated (no findings or no applicable fixes).")
        return

    if args.write:
        patch_dir = Path(args.write)
        patch_dir.mkdir(parents=True, exist_ok=True)
        patch_path = patch_dir / f"{args.sample_id}.patch"
        patch_path.write_text(patch_text, encoding="utf-8")
        print(f"Wrote patch to {patch_path}")
    print(patch_text)


def cmd_predict(args: argparse.Namespace) -> None:
    output_path = Path(args.output)
    patch_dir = Path(args.patch_dir) if args.patch_dir else OUTPUT_DIR / "patches"
    try:
        rows = predict_split(
            args.split,
            output_path,
            patch_dir,
            use_llm=args.use_llm,
        )
    except MissingApiKeyError as error:
        raise SystemExit(str(error)) from error
    print(f"Wrote {len(rows)} rows to {output_path}")


def cmd_llm(args: argparse.Namespace) -> None:
    samples = load_train_samples()
    sample = next((item for item in samples if item.sample_id == args.sample_id), None)
    if sample is None:
        raise SystemExit(f"Unknown sample_id: {args.sample_id}")

    untrusted = load_untrusted_context_list()
    rule_findings = collect_findings(sample.workflow_path, untrusted, use_llm=False)
    content = sample.workflow_path.read_text(encoding="utf-8", errors="replace")

    try:
        client = OpenRouterClient.from_env()
        llm_findings = request_additional_findings(
            sample.workflow_path,
            content,
            untrusted,
            rule_findings,
            client=client,
        )
    except MissingApiKeyError as error:
        raise SystemExit(str(error)) from error

    print(f"Rule findings: {len(rule_findings)}")
    print(f"LLM additional findings: {len(llm_findings)}")
    merged = dedupe_findings(rule_findings + llm_findings)
    print(json.dumps([finding.__dict__ for finding in merged], indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Challenge 02: GitHub Actions vulnerability detection toolkit."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan samples and show per-sample results.")
    scan_parser.add_argument("--sample-id", help="Analyze one sample by sample_id.")
    scan_parser.add_argument("--limit", type=int, default=10, help="Max samples to scan (default: 10).")
    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Scan all training samples (overrides --limit).",
    )
    _add_llm_flag(scan_parser)
    scan_parser.set_defaults(func=cmd_scan)

    eval_parser = subparsers.add_parser("eval", help="Run evaluation and print summary metrics.")
    eval_parser.add_argument("--sample-id", help="Evaluate one sample by sample_id.")
    eval_parser.add_argument("--limit", type=int, default=10, help="Max samples to evaluate (default: 10).")
    eval_parser.add_argument(
        "--full",
        action="store_true",
        help="Evaluate all training samples (overrides --limit).",
    )
    eval_parser.add_argument("--json", help="Write evaluation report JSON to this path.")
    _add_llm_flag(eval_parser)
    eval_parser.set_defaults(func=cmd_eval)

    patch_parser = subparsers.add_parser("patch", help="Generate env-wrap patch for a sample.")
    patch_parser.add_argument("--sample-id", required=True, help="Sample ID to patch.")
    patch_parser.add_argument("--write", help="Directory to write .patch file.")
    _add_llm_flag(patch_parser)
    patch_parser.set_defaults(func=cmd_patch)

    predict_parser = subparsers.add_parser("predict", help="Generate submission CSV for a split.")
    predict_parser.add_argument(
        "--split",
        choices=["train", "validation"],
        default="train",
        help="Dataset split to predict (default: train).",
    )
    predict_parser.add_argument(
        "--output",
        default=str(OUTPUT_DIR / "submission_train.csv"),
        help="Output submission CSV path.",
    )
    predict_parser.add_argument(
        "--patch-dir",
        help="Directory for sidecar .patch files (default: output/patches).",
    )
    _add_llm_flag(predict_parser)
    predict_parser.set_defaults(func=cmd_predict)

    llm_parser = subparsers.add_parser(
        "llm",
        help="Run OpenRouter augmentation for one sample and print merged findings.",
    )
    llm_parser.add_argument("--sample-id", required=True, help="Sample ID to analyze.")
    llm_parser.set_defaults(func=cmd_llm)

    return parser


def main(argv: list[str] | None = None) -> None:
    load_project_env()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
