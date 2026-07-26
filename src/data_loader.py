import csv
import json
from dataclasses import dataclass
from pathlib import Path

from src.paths import TRAIN_CSV, TRAIN_WORKFLOWS


@dataclass
class Sample:
    sample_id: str
    vulnerabilities: list[dict]
    patches: list[dict]
    workflow_path_override: Path | None = None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def workflow_path(self) -> Path:
        if self.workflow_path_override is not None:
            return self.workflow_path_override
        return TRAIN_WORKFLOWS / f"{self.sample_id}.yml"


def load_train_samples(csv_path: Path = TRAIN_CSV) -> list[Sample]:
    samples: list[Sample] = []
    with csv_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            samples.append(
                Sample(
                    sample_id=row["sample_id"],
                    vulnerabilities=json.loads(row["vulnerabilities"]),
                    patches=json.loads(row["patches"]),
                )
            )
    return samples


def load_untrusted_contexts(csv_path: Path) -> list[str]:
    if not csv_path.exists():
        return []

    contexts: list[str] = []
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        column = reader.fieldnames[0] if reader.fieldnames else None
        if column is None:
            return contexts
        for row in reader:
            value = row[column].strip()
            if value:
                contexts.append(value)
    return contexts
