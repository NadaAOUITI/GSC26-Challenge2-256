import pytest

from src.paths import TRAIN_WORKFLOWS


@pytest.fixture
def dataset_available() -> bool:
    return TRAIN_WORKFLOWS.exists() and any(TRAIN_WORKFLOWS.glob("*.yml"))


@pytest.fixture
def require_dataset(dataset_available: bool) -> None:
    if not dataset_available:
        pytest.skip("dataset/train/workflows not found; clone competition dataset to run integration tests")
