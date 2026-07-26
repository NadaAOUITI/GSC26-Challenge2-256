from src.evaluate import EvalMetrics, SampleResult, compute_metrics


def test_compute_metrics_perfect_score() -> None:
    results = [
        SampleResult("a", True, True, 1),
        SampleResult("b", False, False, 0),
    ]
    metrics = compute_metrics(results)
    assert metrics == EvalMetrics(tp=1, fp=0, fn=0, tn=1, precision=1.0, recall=1.0, f1=1.0)


def test_compute_metrics_false_positive_and_false_negative() -> None:
    results = [
        SampleResult("a", True, True, 2),
        SampleResult("b", True, False, 1),
        SampleResult("c", False, True, 0),
        SampleResult("d", False, False, 0),
    ]
    metrics = compute_metrics(results)
    assert metrics.tp == 1
    assert metrics.fp == 1
    assert metrics.fn == 1
    assert metrics.tn == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5


def test_compute_metrics_zero_division_returns_zero() -> None:
    results = [
        SampleResult("a", False, False, 0),
        SampleResult("b", False, False, 0),
    ]
    metrics = compute_metrics(results)
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0


def test_sample_result_is_correct() -> None:
    assert SampleResult("x", True, True, 1).is_correct is True
    assert SampleResult("x", False, True, 0).is_correct is False
