# ADR 0003: Taint Tracking for Multi-Step Injection Flows

**Status:** Accepted  
**Date:** 2026-07-26  
**Depends on:** [ADR 0001](0001-project-architecture.md), [ADR 0002](0002-evaluation-metrics.md)

## Context

The baseline detector (Feature 1) flags direct `${{ github.* }}` interpolation inside `run:` blocks and follows `uses:` references. On the training set this yields **8 TP, 0 FP, 21 FN**.

Ground-truth labels show vulnerabilities where untrusted data flows through:

1. Step `env:` bindings → later `${{ env.VAR }}` in `run:`
2. `with:` inputs → `${{ inputs.key }}` inside composite actions
3. Step outputs → `${{ steps.id.outputs.name }}` in later `run:` blocks
4. `$GITHUB_ENV` writes propagating taint across steps

Additionally, regex-based `run:` extraction missed list-step syntax (`- run: |`).

## Decision

Implement **ordered step-graph taint analysis** within each job (and composite action scope):

- **Sources:** expressions matching [`data/untrusted_data.csv`](../../data/untrusted_data.csv)
- **Propagation:** `env:`, `with:`, `$GITHUB_ENV` echo patterns, tainted step outputs
- **Sinks:** `${{ expr }}` inside `run:` shell blocks where `expr` is a tainted symbol or direct untrusted source

Use YAML-aware step walking instead of regex-only file scanning.

### Propagation rules

| Binding | Effect |
|---------|--------|
| `env.VAR: ${{ expr }}` | Taint `env.VAR` if `expr` is untrusted or tainted |
| `with.key: ${{ expr }}` on reusable workflow jobs | Taint `inputs.key` in callee reusable workflow |
| `with.key: ${{ expr }}` on composite action steps | Not propagated (avoids FP); rely on action input defaults |
| Action `inputs.key.default: ${{ expr }}` | Taint `inputs.key` when scanning composite action |
| `echo "VAR=..." >> $GITHUB_ENV` | Taint `env.VAR` if value expression is tainted/untrusted |
| Step `with` tainted | Taint all `steps.<id>.outputs.*` for that step |

### Target

Conservative improvement: **TP >= 15**, **FP == 0** on train set.

## Alternatives considered

### Full inter-procedural CodeQL-style analysis

**Rejected** — too heavy for current timeline and team scope.

### LLM-based taint inference

**Deferred** to Feature 6 (OpenRouter).

## Consequences

### Positive

- Covers majority of false-negative patterns in train labels
- Ordered step walk also fixes `- run: |` parsing gap

### Negative / risks

- `$GITHUB_OUTPUT` not tracked yet (may leave residual FNs)
- Input name casing (`inputs.head_ref` vs `inputs.HEAD_REF`) may miss edge cases
- Step output tainting is conservative (all outputs when any `with` value tainted)

### Follow-up

- Location-level eval (match `from`/`to` in labels)
- `$GITHUB_OUTPUT` propagation if FN count remains high after Feature 2
