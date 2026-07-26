from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATASET_DIR = ROOT / "dataset"

TRAIN_CSV = DATA_DIR / "train.csv"
UNTRUSTED_CSV = DATA_DIR / "untrusted_data.csv"

TRAIN_WORKFLOWS = DATASET_DIR / "train" / "workflows"
TRAIN_ACTIONS = DATASET_DIR / "train" / "actions"
TRAIN_REUSABLE = DATASET_DIR / "train" / "reusable_workflows"
TRAIN_PATCHES = DATASET_DIR / "train" / "patches"
VALIDATION_WORKFLOWS = DATASET_DIR / "validation" / "workflows"
OUTPUT_DIR = ROOT / "output"
