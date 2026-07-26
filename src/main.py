import argparse
import json
from pathlib import Path

from src.data_loader import load_train_samples, load_untrusted_contexts
from src.detector import DEFAULT_UNTRUSTED_CONTEXTS, scan_workflow
from src.paths import UNTRUSTED_CSV


def evaluate_sample(sample_id: str | None, limit: int) -> None:
    samples = load_train_samples()
    if sample_id:
        samples = [sample for sample in samples if sample.sample_id == sample_id]
        if not samples:
            raise SystemExit(f"Unknown sample_id: {sample_id}")

    untrusted = load_untrusted_contexts(UNTRUSTED_CSV) or DEFAULT_UNTRUSTED_CONTEXTS
    print(f"Loaded {len(samples)} sample(s)")
    print(f"Using {len(untrusted)} untrusted context(s)\n")

    checked = 0
    true_positive = 0
    false_positive = 0
    false_negative = 0

    for sample in samples[:limit]:
        findings = scan_workflow(sample.workflow_path, untrusted)
        predicted = len(findings) > 0
        actual = sample.is_vulnerable

        if predicted and actual:
            true_positive += 1
        elif predicted and not actual:
            false_positive += 1
        elif not predicted and actual:
            false_negative += 1

        checked += 1
        status = "VULN" if predicted else "CLEAN"
        label = "VULN" if actual else "CLEAN"
        match = "ok" if predicted == actual else "MISS"

        print(f"[{match}] {sample.sample_id}: predicted={status}, label={label}, hits={len(findings)}")
        if sample_id and findings:
            print(json.dumps([finding.__dict__ for finding in findings], indent=2))

    print(
        f"\nChecked {checked} samples | "
        f"TP={true_positive} FP={false_positive} FN={false_negative}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Challenge 02 starter: load workflows and detect injection patterns."
    )
    parser.add_argument(
        "--sample-id",
        help="Analyze one sample (matches train.csv sample_id).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of training samples to scan (default: 10).",
    )
    args = parser.parse_args()
    evaluate_sample(args.sample_id, args.limit)


if __name__ == "__main__":
    main()
