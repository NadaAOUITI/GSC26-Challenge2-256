import csv
import json
from pathlib import Path

from src.data_loader import Sample, load_train_samples
from src.detector import Finding, scan_workflow
from src.evaluate import load_untrusted_context_list
from src.paths import OUTPUT_DIR, VALIDATION_WORKFLOWS
from src.patcher import generate_patch_for_sample


def findings_to_vulnerabilities(findings: list[Finding]) -> list[dict]:
    vulnerabilities: list[dict] = []
    for finding in findings:
        location = f"{finding.rel_path}:{finding.line}"
        vulnerabilities.append(
            {
                "from": location,
                "to": location,
                "explanation": finding.explanation,
            }
        )
    return vulnerabilities


def findings_to_patches(
    sample_id: str,
    patch_text: str,
    findings: list[Finding],
    patch_prefix: str = "output/patches",
) -> list[dict]:
    if not patch_text or not findings:
        return []

    primary_file = findings[0].rel_path
    return [
        {
            "file": primary_file,
            "patch_file": f"{patch_prefix}/{sample_id}.patch",
            "explanation": (
                "Env-wrapped untrusted/tainted expressions in run: shell blocks "
                "following GitHub Actions injection hardening guidance."
            ),
        }
    ]


def scan_sample(sample: Sample, untrusted_contexts: list[str]) -> list[Finding]:
    return scan_workflow(sample.workflow_path, untrusted_contexts)


def predict_sample(
    sample: Sample,
    untrusted_contexts: list[str],
    write_patch_dir: Path | None = None,
    patch_prefix: str = "output/patches",
) -> dict:
    findings = scan_sample(sample, untrusted_contexts)
    patch_text = generate_patch_for_sample(sample.sample_id, findings, untrusted_contexts)

    if write_patch_dir and patch_text:
        write_patch_dir.mkdir(parents=True, exist_ok=True)
        patch_path = write_patch_dir / f"{sample.sample_id}.patch"
        patch_path.write_text(patch_text, encoding="utf-8")

    return {
        "sample_id": sample.sample_id,
        "vulnerabilities": json.dumps(findings_to_vulnerabilities(findings)),
        "patches": json.dumps(findings_to_patches(sample.sample_id, patch_text or "", findings, patch_prefix)),
    }


def load_samples_for_split(split: str) -> list[Sample]:
    if split == "train":
        return load_train_samples()
    if split == "validation":
        if not VALIDATION_WORKFLOWS.exists():
            raise ValueError(
                "Validation split not found. Clone/download validation workflows to dataset/validation/workflows/"
            )
        samples: list[Sample] = []
        for workflow_path in sorted(VALIDATION_WORKFLOWS.glob("*.yml")):
            samples.append(
                Sample(
                    sample_id=workflow_path.stem,
                    vulnerabilities=[],
                    patches=[],
                    workflow_path_override=workflow_path,
                )
            )
        return samples
    raise ValueError(f"Unknown split: {split}")


def write_submission_csv(rows: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "vulnerabilities", "patches"])
        writer.writeheader()
        writer.writerows(rows)


def predict_split(
    split: str,
    output_path: Path,
    patch_dir: Path | None = None,
) -> list[dict]:
    untrusted = load_untrusted_context_list()
    samples = load_samples_for_split(split)
    patch_dir = patch_dir or OUTPUT_DIR / "patches"
    rows = [predict_sample(sample, untrusted, patch_dir) for sample in samples]
    write_submission_csv(rows, output_path)
    return rows
