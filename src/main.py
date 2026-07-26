import argparse
import json
import sys
from pathlib import Path

from src.data_loader import load_train_samples
from src.detector import scan_workflow
from src.evaluate import load_untrusted_context_list, run_evaluation, write_report_json


def _print_scan_results(report, sample_id: str | None) -> None:
    print(f"Loaded {report.sample_count} sample(s)")
    print(f"Using {report.untrusted_context_count} untrusted context(s)\n")

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
            findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
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
        report = run_evaluation(sample_id=args.sample_id, limit=None if args.full else args.limit)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    _print_scan_results(report, args.sample_id)


def cmd_eval(args: argparse.Namespace) -> None:
    try:
        limit = None if args.full else args.limit
        report = run_evaluation(sample_id=args.sample_id, limit=limit)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    _print_eval_summary(report)
    if args.json:
        write_report_json(report, Path(args.json))
        print(f"\nWrote report to {args.json}")


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
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
