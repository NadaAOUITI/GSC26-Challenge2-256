# ADR 0004: Patch Generation

**Status:** Accepted  
**Date:** 2026-07-26  
**Depends on:** [ADR 0003](0003-taint-tracking.md)

## Context

Detection (Feature 2) finds vulnerabilities with **TP=22, FP=0** on train. Kaggle submission requires both `vulnerabilities` and `patches` JSON per sample (see [`data/train.csv`](../../data/train.csv)). Reference patches in [`dataset/train/patches/`](../../dataset/train/patches/) consistently use **env-wrap + quoted shell variables**.

## Decision

### Fix strategy: rule-based env-wrap

| Finding | Patch action |
|---------|--------------|
| Direct untrusted `${{ github.* }}` in `run:` | Add step `env: VAR: ${{ expr }}`; replace inline with `"$VAR"` |
| Tainted `${{ env.VAR }}` with step `env: VAR:` present | Replace with `"$VAR"` in `run:` |
| Tainted `${{ steps.id.outputs.name }}` | Add `env: ALIAS: ${{ ... }}`; replace with `"$ALIAS"` |
| Tainted `${{ inputs.key }}` | Add `env: INPUTS_KEY: ${{ inputs.key }}`; replace with `"$INPUTS_KEY"` |

### Output format

- Unified diff via `difflib.unified_diff`, paths prefixed with `train/`
- One combined patch string per sample (may include multiple files)
- Submission CSV columns: `sample_id`, `vulnerabilities`, `patches` (same as train.csv)
- Vulnerability entry: `{from, to, explanation}` with `train/.../file:line`
- Patch entry: `{file, patch_file, explanation}`

### Validation

After applying patch in memory, re-run detector on patched file content; expect zero findings in that file.

## Alternatives rejected

- **LLM patches (Feature 6)** — deferred until rule baseline works
- **Copy reference train patches** — does not generalize to validation set
- **Byte-identical diffs** — reference patches include extra hardening (e.g. removing `eval`)

## Consequences

### Positive

- Enables `predict` CLI and first Kaggle submission path
- Deterministic, testable patches

### Negative / risks

- ruamel/PyYAML round-trip may alter whitespace in edge cases
- Patches for undetected samples (7 FN) remain empty until detection improves
- Multi-file samples may not match reference patch grouping exactly

### Follow-up

- OpenRouter patch refinement (Feature 6)
- Validation split predict when Kaggle validation data is downloaded
