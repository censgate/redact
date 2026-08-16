# Pattern quality corpora

Hermetic, project-owned precision sets. They are **not** a general
precision or recall result, and they are not the performance tree in
`docs/benchmarks/`.

| Set | Test | What it scores |
|-----|------|----------------|
| `pattern-v1.json` | `cargo test -p redact-core --test quality_pattern_v1` | Default-engine PII precision (11 types) plus adversarial gate regressions |
| secrets-default (runtime) | `cargo test -p redact-core --test quality_secrets_default` | Compiled named secrets + `GENERIC_SECRET` exact spans |
| optional providers (runtime) | `cargo test -p redact-gateway --test packs quality_optional` | Opt-in `patterns/optional/providers-v1.yaml` only |

NER and formatted-value recall are out of scope. Do not claim gitleaks
parity. A `min_precision_ppm` of `1000000` means zero in-scope false
positives **on that named set**.

`pattern-v1-baseline.json` ratchets the PII set. Update
`corpus_sha256` when the JSON bytes change.
