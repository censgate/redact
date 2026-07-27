# Pattern quality corpus (v1)

Owned regression fixtures for **pattern-default** precision (and later recall).

## Config contract

| Setting | Value |
|---------|-------|
| Engine | `AnalyzerEngine::new()` (default pattern registry) |
| Language | `en` |
| Min score | `0.5` |
| NER | off |
| Matching | Exact UTF-8 byte span + `entity_type` string |
| In-scope types | Listed in `pattern-v1.json` → `config.entity_types_in_scope` |

Predictions whose `entity_type` is **outside** that allowlist are ignored for scoring (shared-family diagnostic). In-scope extras are false positives.

## Run

```bash
cargo test -p redact-core --test quality_pattern_v1
```

## Baseline

`pattern-v1-baseline.json` records:

- `corpus_sha256` of `pattern-v1.json` (bytes on disk)
- `max_fp_overall`, `max_fp_negative_tier`
- `min_precision_ppm` (parts per million; `1000000` = 100%)
- `require_contract_exact`: every `contract` case must have 0 FN and 0 FP

Tightening the baseline in the same PR as a precision fix is encouraged. Loosening requires an explicit rationale.

## Provenance

Some cases are adapted from [`tcheuD/anon-pii`](https://github.com/tcheuD/anon-pii) at commit `1a22680e43b29c80e141a39b0a66eb3dcafb7522` (Apache-2.0). Per-case `provenance` fields list source case ids. Fixtures are owned by this repository; do not treat third-party aggregate scores as ours.

See `docs/superpowers/specs/2026-07-27-pattern-precision-quality-design.md`.
