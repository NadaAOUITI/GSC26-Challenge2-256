# ADR 0005: OpenRouter LLM Integration

**Status:** Accepted  
**Date:** 2026-07-26  
**Depends on:** [ADR 0004](0004-patch-generation.md)

## Context

The rules-first pipeline (Features 1–3) reaches **TP=22, FP=0, FN=7** on train. Remaining false negatives involve subtle taint chains or patterns the regex/YAML walker misses. OpenRouter tokens are provided for **in-pipeline** LLM calls only.

## Decision

### Role: augmentation, not replacement

| Layer | Responsibility |
|-------|----------------|
| Rules + taint | Primary detector; deterministic baseline |
| OpenRouter | Optional second pass when `--use-llm` is set |
| Patcher | Still rule-based env-wrap (LLM does not rewrite YAML directly in MVP) |

### When LLM runs

- Opt-in via CLI flag `--use-llm` on `scan`, `eval`, `patch`, and `predict`
- Requires `OPENROUTER_API_KEY` in environment
- Default model: `google/gemma-2-9b-it:free` (override with `OPENROUTER_MODEL`)

### Prompt contract

1. Input: primary workflow YAML, untrusted context list, existing rule findings
2. Output: JSON array of `{file, line, expression, explanation}` for **additional** `run:` injection sinks
3. Parser strips markdown fences; invalid JSON → empty augmentation (logged to stderr)

### Finding merge

- Union rule findings + LLM findings
- Dedupe key: `(rel_path, line, normalized expression)`
- LLM findings get `propagated=False` unless expression matches taint heuristics

## Alternatives rejected

- **LLM-only pipeline** — non-deterministic, costly, hard to test (see ADR 0001)
- **LLM-generated patches** — deferred; env-wrap rules are safer and re-scan testable
- **Always-on LLM** — would burn tokens on all 150 samples; opt-in only

## Consequences

### Positive

- Can recover some FN samples without hand-coded taint rules
- Same submission schema; predict pipeline unchanged except finding source

### Negative / risks

- API latency and rate limits on full train runs
- Possible LLM false positives — monitor FP on train after enabling
- Free models may be slow or unavailable; model string is configurable

## Success criteria

- [ ] `pytest` passes with mocked OpenRouter responses
- [ ] `--use-llm` without API key exits with clear error
- [ ] `scan --sample-id … --use-llm` merges LLM JSON into findings when key is set
