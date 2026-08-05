import csv
import json
from pathlib import Path

from src.data_loader import Sample, load_train_samples
from src.detector import Finding
from src.evaluate import load_untrusted_context_list
from src.paths import OUTPUT_DIR, SAMPLE_SUBMISSION_CSV, VALIDATION_WORKFLOWS
from src.patcher import generate_patch_for_sample
from src.scan_pipeline import collect_findings


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


def scan_sample(
    sample: Sample,
    untrusted_contexts: list[str],
    use_llm: bool = False,
    llm_client=None,
) -> list[Finding]:
    return collect_findings(
        sample.workflow_path,
        untrusted_contexts,
        use_llm=use_llm,
        llm_client=llm_client,
    )


def predict_sample(
    sample: Sample,
    untrusted_contexts: list[str],
    write_patch_dir: Path | None = None,
    patch_prefix: str = "output/patches",
    use_llm: bool = False,
    llm_client=None,
) -> dict:
    findings = scan_sample(sample, untrusted_contexts, use_llm=use_llm, llm_client=llm_client)
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


def load_validation_sample_ids() -> list[str]:
    if SAMPLE_SUBMISSION_CSV.exists():
        with SAMPLE_SUBMISSION_CSV.open(encoding="utf-8", newline="") as handle:
            return [row["sample_id"] for row in csv.DictReader(handle)]
    return []


def load_samples_for_split(split: str) -> list[Sample]:
    if split == "train":
        return load_train_samples()
    if split == "validation":
        if not VALIDATION_WORKFLOWS.exists():
            raise ValueError(
                "Validation workflows not found at dataset/validation/workflows/.\n"
                "Pull the latest competition GitHub repo:\n"
                "  cd dataset && git pull origin main\n"
                "Also download sample_submission.csv from Kaggle into data/."
            )
        workflow_by_id = {path.stem: path for path in VALIDATION_WORKFLOWS.glob("*.yml")}
        template_ids = load_validation_sample_ids()
        sample_ids = template_ids if template_ids else sorted(workflow_by_id)
        if template_ids:
            missing = [sample_id for sample_id in template_ids if sample_id not in workflow_by_id]
            if missing:
                raise ValueError(
                    f"Missing {len(missing)} validation workflow(s), e.g. {missing[0]}. "
                    "Run `cd dataset && git pull origin main`."
                )
        samples: list[Sample] = []
        for sample_id in sample_ids:
            workflow_path = workflow_by_id[sample_id]
            samples.append(
                Sample(
                    sample_id=sample_id,
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
    use_llm: bool = False,
    llm_client=None,
) -> list[dict]:
    untrusted = load_untrusted_context_list()
    samples = load_samples_for_split(split)
    patch_dir = patch_dir or OUTPUT_DIR / "patches"
    rows = [
        predict_sample(sample, untrusted, patch_dir, use_llm=use_llm, llm_client=llm_client)
        for sample in samples
    ]
    write_submission_csv(rows, output_path)
    return rows
