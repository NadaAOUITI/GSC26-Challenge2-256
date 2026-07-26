# ADR 0001: Project Architecture and Delivery Strategy

**Status:** Accepted  
**Date:** 2026-07-26  
**Challenge:** GSC 2026 — Challenge 02 (GitHub Actions vulnerability detection & patching)

## Context

We must build a system that:

1. Loads competition samples (workflow YAML + referenced actions/reusable workflows)
2. Detects code-injection vulnerabilities from untrusted GitHub contexts
3. Generates secure patches
4. Produces a Kaggle submission

Constraints:

- Competition data lives outside our repo (`dataset/` clone, CSV metadata in `data/`)
- OpenRouter tokens are for **in-pipeline LLM calls**, not IDE assistance
- Team wants feature-by-feature delivery: plan → ADR → code → test → push
- Baseline detector already exists (~8/29 vulnerable training samples detected, 0 false positives)

## Decision

Adopt a **staged pipeline architecture** with a **rules-first core** and **optional LLM augmentation** later.

```text
┌─────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────────┐
│ Data layer  │ → │  Detection   │ → │   Patching  │ → │  Submission  │
│ (samples)   │   │  (findings)  │   │  (diffs)    │   │  (Kaggle)    │
└─────────────┘   └──────────────┘   └─────────────┘   └──────────────┘
                         ↑
                  optional LLM assist
                  (OpenRouter, Phase 6)
```

### Module boundaries

| Module | Responsibility | Current file(s) |
|--------|----------------|-----------------|
| `data_loader` | Load CSV labels, untrusted contexts, resolve sample paths | `src/data_loader.py`, `src/paths.py` |
| `resolver` | Map `uses:` refs → local action/reusable-workflow files | `src/resolver.py` |
| `detector` | Find untrusted `${{ }}` in `run:` blocks (+ graph walk) | `src/detector.py` |
| `taint` *(planned)* | Track multi-step flows through `env:` / outputs / inputs | TBD |
| `patcher` *(planned)* | Emit unified diff patches | TBD |
| `llm` *(planned)* | OpenRouter client for hard cases | TBD |
| `submit` *(planned)* | Format Kaggle prediction JSON/CSV | TBD |
| `cli` | Entry point, evaluation against train labels | `src/main.py` |

### Delivery order (features)

| Phase | Feature | Goal |
|-------|---------|------|
| 1 | Foundation | ADRs, tests harness, eval metrics |
| 2 | Data layer hardening | Robust loading, path validation |
| 3 | Detection v1 | Rules + `uses:` graph walk *(mostly done)* |
| 4 | Taint tracking | Fix multi-step false negatives |
| 5 | Patch generation | Produce valid `.patch` files |
| 6 | OpenRouter integration | LLM for detection/patch refinement |
| 7 | Kaggle submission | End-to-end predict on validation set |

Each phase gets its own ADR before coding.

## Alternatives considered

### A. LLM-only solution (prompt workflow YAML → get vuln + patch)

**Pros:** Faster to prototype on hard cases; matches organizer research direction.  
**Cons:** Non-deterministic, costly, hard to test; bad baseline for competition scoring.  
**Rejected as primary approach.** Use as augmentation after rules work.

### B. Static analyzer fork (CodeQL / custom CodeQL queries)

**Pros:** Industry-standard taint analysis; high precision potential.  
**Cons:** Heavy setup; competition expects patch generation in our pipeline; team Python skill stack; time cost.  
**Deferred.** Revisit only if rule+taint approach plateaus.

### C. Rules-first pipeline *(chosen)*

**Pros:** Testable, debuggable, no API cost, matches 8/29 detection already; easy incremental improvement.  
**Cons:** Will miss subtle taint flows until Phase 4; patch quality may lag detection.  
**Accepted** as foundation.

## Consequences

### Positive

- Clear feature boundaries for parallel team work
- Each phase has measurable success criteria (precision/recall on train set)
- OpenRouter spend deferred until pipeline is useful

### Negative / risks

- Taint analysis (Phase 4) is the hardest engineering piece
- Patch format must match competition evaluator exactly — needs early spec research
- Current detector uses regex on YAML text; may break on edge-case formatting

### Follow-up ADRs needed

| ADR | Topic | When |
|-----|-------|------|
| 0002 | Evaluation metrics and test harness | Phase 1 (next) |
| 0003 | Taint tracking design | Before Phase 4 |
| 0004 | Patch output format | Before Phase 5 |
| 0005 | OpenRouter model selection and prompting | Before Phase 6 |

## Success criteria (Phase 1)

- [ ] `pytest` runs on CI/local with at least smoke tests
- [ ] Evaluation script reports TP/FP/FN on full train set
- [ ] ADR index updated as new decisions are made
