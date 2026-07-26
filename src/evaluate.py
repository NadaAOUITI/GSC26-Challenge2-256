import json
from dataclasses import asdict, dataclass
from pathlib import Path

from src.data_loader import Sample, load_train_samples, load_untrusted_contexts
from src.detector import DEFAULT_UNTRUSTED_CONTEXTS, scan_workflow
from src.paths import UNTRUSTED_CSV


@dataclass
class SampleResult:
    sample_id: str
    predicted_vulnerable: bool
    actual_vulnerable: bool
    findings_count: int

    @property
    def is_correct(self) -> bool:
        return self.predicted_vulnerable == self.actual_vulnerable


@dataclass
class EvalMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_metrics(results: list[SampleResult]) -> EvalMetrics:
    tp = sum(1 for result in results if result.predicted_vulnerable and result.actual_vulnerable)
    fp = sum(1 for result in results if result.predicted_vulnerable and not result.actual_vulnerable)
    fn = sum(1 for result in results if not result.predicted_vulnerable and result.actual_vulnerable)
    tn = sum(1 for result in results if not result.predicted_vulnerable and not result.actual_vulnerable)

    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = 0.0
    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)

    return EvalMetrics(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1)


def evaluate_samples(
    samples: list[Sample],
    untrusted_contexts: list[str],
) -> tuple[list[SampleResult], EvalMetrics]:
    results: list[SampleResult] = []
    for sample in samples:
        findings = scan_workflow(sample.workflow_path, untrusted_contexts)
        results.append(
            SampleResult(
                sample_id=sample.sample_id,
                predicted_vulnerable=len(findings) > 0,
                actual_vulnerable=sample.is_vulnerable,
                findings_count=len(findings),
            )
        )
    return results, compute_metrics(results)


def load_untrusted_context_list() -> list[str]:
    return load_untrusted_contexts(UNTRUSTED_CSV) or DEFAULT_UNTRUSTED_CONTEXTS


@dataclass
class EvaluationReport:
    sample_count: int
    untrusted_context_count: int
    results: list[SampleResult]
    metrics: EvalMetrics

    def to_dict(self) -> dict:
        return {
            "sample_count": self.sample_count,
            "untrusted_context_count": self.untrusted_context_count,
            "results": [asdict(result) for result in self.results],
            "metrics": asdict(self.metrics),
        }


def run_evaluation(
    sample_id: str | None = None,
    limit: int | None = None,
) -> EvaluationReport:
    samples = load_train_samples()
    if sample_id:
        samples = [sample for sample in samples if sample.sample_id == sample_id]
        if not samples:
            raise ValueError(f"Unknown sample_id: {sample_id}")
    elif limit is not None:
        samples = samples[:limit]

    untrusted = load_untrusted_context_list()
    results, metrics = evaluate_samples(samples, untrusted)
    return EvaluationReport(
        sample_count=len(samples),
        untrusted_context_count=len(untrusted),
        results=results,
        metrics=metrics,
    )


def write_report_json(report: EvaluationReport, output_path: Path) -> None:
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
