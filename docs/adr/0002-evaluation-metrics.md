# ADR 0002: Evaluation Metrics and Test Harness

**Status:** Accepted  
**Date:** 2026-07-26  
**Depends on:** [ADR 0001](0001-project-architecture.md)

## Context

The baseline detector in `src/detector.py` reports findings per workflow sample, but evaluation logic lived inline in `src/main.py`. As we add features (taint tracking, patching, LLM assist), we need:

1. A reusable evaluation module with structured output
2. Regression tests that catch precision/recall regressions
3. A clear definition of what we measure in Phase 1 vs later

Training set: 150 samples (29 vulnerable, 121 clean). Current baseline: **8 TP, 0 FP, 21 FN, 121 TN**.

## Decision

### Phase 1 granularity: sample-level binary classification

A sample is **predicted vulnerable** if the detector returns one or more findings. Compare against ground truth: `len(vulnerabilities) > 0` in `train.csv`.

Location-level matching (`from`/`to` paths and line numbers in label JSON) is **deferred** until the detector emits compatible findings.

### Metrics

| Metric | Definition |
|--------|------------|
| TP | Predicted vuln, actually vuln |
| FP | Predicted vuln, actually clean |
| FN | Predicted clean, actually vuln |
| TN | Predicted clean, actually clean |
| Precision | TP / (TP + FP), 0.0 if denominator is 0 |
| Recall | TP / (TP + FN), 0.0 if denominator is 0 |
| F1 | Harmonic mean of precision and recall, 0.0 if both are 0 |

### Test tiers

| Tier | Requires `dataset/` | Purpose |
|------|---------------------|---------|
| Unit | No | Test `compute_metrics()` with synthetic results |
| Integration | Yes (skip if missing) | Anchor samples + full-train baseline bounds |

Integration tests skip gracefully when `dataset/train/workflows/` is absent (e.g. fresh clone on CI without data download).

### Module layout

- `src/evaluate.py` — `SampleResult`, `EvalMetrics`, `evaluate_samples()`, `run_evaluation()`
- `src/main.py` — CLI with `scan` and `eval` subcommands
- `tests/` — pytest unit + integration tests

## Alternatives considered

### A. Manual CLI only (status quo)

**Pros:** No new code.  
**Cons:** No regression safety; hard to compare feature branches.  
**Rejected.**

### B. Location-level evaluation now

**Pros:** Closer to final competition scoring.  
**Cons:** Detector does not emit `from`/`to` yet; premature complexity.  
**Deferred** to a future ADR when detection output format stabilizes.

### C. Commit `dataset/` for CI

**Pros:** Integration tests always run in CI.  
**Cons:** ~400 MB; duplicates competition repo.  
**Rejected.** Dataset clone remains documented in README.

## Consequences

### Positive

- Every feature branch can run `pytest` and `python -m src.main eval --full`
- Baseline metrics (TP=8, FP=0, FN=21) encoded in integration tests
- JSON export option supports future branch comparisons

### Negative / risks

- Sample-level metrics overstate quality when we detect only some vulns in a multi-vuln sample
- Integration tests won't run on CI until we add a dataset download step (future feature)

### Follow-up

- ADR for location-level matching when detector emits structured findings with file:line
- Optional GitHub Actions CI feature with sparse dataset checkout
