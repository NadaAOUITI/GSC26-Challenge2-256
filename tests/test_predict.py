import csv
import json
from pathlib import Path

import pytest

from src.predict import predict_sample, write_submission_csv
from src.data_loader import load_train_samples
from src.evaluate import load_untrusted_context_list


def test_submission_row_schema(tmp_path: Path) -> None:
    samples = load_train_samples()[:3]
    untrusted = load_untrusted_context_list()
    rows = [predict_sample(sample, untrusted) for sample in samples]
    output = tmp_path / "submission.csv"
    write_submission_csv(rows, output)

    with output.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == ["sample_id", "vulnerabilities", "patches"]
        loaded = list(reader)
    assert len(loaded) == 3
    for row in loaded:
        json.loads(row["vulnerabilities"])
        json.loads(row["patches"])


@pytest.mark.usefixtures("require_dataset")
def test_predict_vulnerable_sample_has_patch_entry() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == "63dd948580aa29a6fd4868f5")
    row = predict_sample(sample, load_untrusted_context_list())
    patches = json.loads(row["patches"])
    vulnerabilities = json.loads(row["vulnerabilities"])
    assert vulnerabilities
    assert patches
    assert patches[0]["patch_file"].endswith(f"{sample.sample_id}.patch")
