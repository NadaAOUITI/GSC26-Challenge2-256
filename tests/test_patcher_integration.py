import pytest

from src.data_loader import load_train_samples
from src.detector import scan_file, scan_workflow
from src.evaluate import load_untrusted_context_list
from src.patcher import apply_patch_to_content, generate_patch_for_sample

ANCHOR_SAMPLES = [
    "63dd948580aa29a6fd4868f5",
    "63dd94b83c0647426a8ca60b",
    "63dd950d80aa29a6fd4877fb",
    "63dd95c080aa29a6fd48843c",
]


@pytest.mark.usefixtures("require_dataset")
@pytest.mark.parametrize("sample_id", ANCHOR_SAMPLES)
def test_generated_patch_rescans_clean_per_file(sample_id: str) -> None:
    untrusted = load_untrusted_context_list()
    sample = next(item for item in load_train_samples() if item.sample_id == sample_id)
    findings = scan_workflow(sample.workflow_path, untrusted)
    assert findings

    patch_text = generate_patch_for_sample(sample_id, findings, untrusted)
    assert patch_text
    assert "diff --git" in patch_text

    by_file: dict[str, list] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for file_path, file_findings in by_file.items():
        path = __import__("pathlib").Path(file_path)
        original = path.read_text(encoding="utf-8")
        patched = apply_patch_to_content(original, file_findings, untrusted)
        rescanned = scan_file(path, untrusted, content=patched)
        assert len(rescanned) == 0, f"Still vulnerable after patch: {path} -> {rescanned}"
