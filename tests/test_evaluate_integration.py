import pytest

from src.evaluate import evaluate_samples, run_evaluation
from src.data_loader import load_train_samples, load_untrusted_contexts
from src.detector import DEFAULT_UNTRUSTED_CONTEXTS
from src.paths import UNTRUSTED_CSV

KNOWN_VULN_SAMPLE = "63dd948580aa29a6fd4868f5"
KNOWN_CLEAN_SAMPLE = "63c493e38052faa2781a7ce4"

BASELINE_TP = 15
BASELINE_FP = 0
TOTAL_VULNERABLE = 29


@pytest.mark.usefixtures("require_dataset")
def test_known_vulnerable_sample_is_detected() -> None:
    samples = [sample for sample in load_train_samples() if sample.sample_id == KNOWN_VULN_SAMPLE]
    untrusted = load_untrusted_contexts(UNTRUSTED_CSV) or DEFAULT_UNTRUSTED_CONTEXTS
    results, _ = evaluate_samples(samples, untrusted)
    assert len(results) == 1
    assert results[0].predicted_vulnerable is True
    assert results[0].actual_vulnerable is True


@pytest.mark.usefixtures("require_dataset")
def test_known_clean_sample_stays_clean() -> None:
    samples = [sample for sample in load_train_samples() if sample.sample_id == KNOWN_CLEAN_SAMPLE]
    untrusted = load_untrusted_contexts(UNTRUSTED_CSV) or DEFAULT_UNTRUSTED_CONTEXTS
    results, _ = evaluate_samples(samples, untrusted)
    assert len(results) == 1
    assert results[0].predicted_vulnerable is False
    assert results[0].actual_vulnerable is False


@pytest.mark.usefixtures("require_dataset")
def test_full_train_baseline_metrics() -> None:
    report = run_evaluation(limit=None)
    assert report.sample_count == 150
    assert report.metrics.tp >= BASELINE_TP
    assert report.metrics.fp == BASELINE_FP
    assert report.metrics.tp + report.metrics.fn == TOTAL_VULNERABLE
