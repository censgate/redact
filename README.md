<div align="center">
<img src="https://raw.githubusercontent.com/censgate/redact/main/assets/censgate-redact-logo-v1.png" alt="Censgate Redact" width="400">

[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/censgate/redact/workflows/CI/badge.svg)](https://github.com/censgate/redact/actions)
[![Crates.io](https://img.shields.io/crates/v/redact-core.svg)](https://crates.io/crates/redact-core)
[![Crates.io](https://img.shields.io/crates/v/redact-gateway.svg)](https://crates.io/crates/redact-gateway)

**Detect and redact PII and secrets — then prove what left.**

For teams that gate secrets in CI, inventory PII in Postgres, or send prompts
to a model provider and need a third party to verify the evidence pack.
One Rust engine: CLI, gateway, scanner, WASM. Apache-2.0.

```bash
cargo install redact-cli
redact analyze --fail-on-detect "Email jane@example.com"
```

[Quick Start](#quick-start) · [Evidence](#evidence-and-attestation) · [Docs](docs/README.md) · [Contributing](#contributing)

</div>

---

- **Secrets in CI** — `redact analyze --fail-on-detect`. Deterministic, no NER, no network. Adjacent to gitleaks, at runtime rather than at rest. Default compiled set is **61** types (`redact --format json list-entities`); the long tail is an opt-in pack, not gitleaks parity.
- **Postgres PII discovery** — `redact-scan`. Read-only (replica/staging preferred). Locations and counts only; sample values never leave the host. `--report-url` is an explicit opt-in POST of that findings JSON. An input to a records-of-processing inventory (GDPR Art. 30), not a certification.
- **Prove what left** — gateway + ledger + `redact-verify`. The gateway is the delivery mechanism. The evidence pack is what a third party can check offline.
- **Embed the engine** — `redact-core` library, REST API, and pattern-only WASM.

p50 latency vs Presidio was **32×** on the 2026-04-18 oha payload ([benchmark](docs/benchmarks/results-20260418-175909.md)). That is a throughput/latency measurement, not a quality score.

## Evidence and attestation

A log you control is not evidence. The gateway can emit audit records
([schema](docs/gateway/audit.md)), but those records are written by the same
operator who ran the proxy: the in-process queue can drop under load, the sink
is yours, and nothing stops a rewrite.

Censgate ledger evidence packs are a different artifact:

1. **Hash chaining** — each event is bound to the previous tip. `redact-verify` recomputes `body_hash` and checks `prev_hash` chain consistency. Tip-signature fields must be present; Ed25519 verification is applied to `body_signature` (builder-signed), not to each tip.
2. **External anchoring** — Merkle inclusion plus a Rekor receipt. `pack_anchored` (R2) is **computed** from the receipt and the compiled-in trust set (`src/trust.rs`, EUTL snapshot). Pack-supplied keys cannot pass the offline test. `attestation.status` is a hint, never a pass.
3. **Offline third-party verification** — `redact-verify` has no `redact-core` dependency and does not dial the network. `--online` is accepted and unused; it does not re-query Rekor. Exit 0 only if every check passes **and** R2 is `pass`. Stripped attestation is `unproven`, never pass.

Compliance YAML under `patterns/compliance/` is a **mapping input** (which
entity types a profile treats as in-scope). It is not SOC 2, GDPR, HIPAA, or
ISO 27001 certification.

Verifier: [`crates/redact-verify/README.md`](crates/redact-verify/README.md).

## Quick Start

### Secrets in CI and pre-commit

Zero extra services. Deterministic pattern engine; NER is off unless you add it.

```bash
cargo install redact-cli
redact analyze --fail-on-detect -i secrets-check.txt
```

`--fail-on-detect` exits 1 when anything is detected; output still prints.
Without the flag, `analyze` exits 0 on success regardless of detections.

```bash
# Pre-commit (NUL-safe paths; skip when nothing is staged)
if [ "$(git diff --cached --name-only -z --diff-filter=ACMRT | wc -c)" -gt 0 ]; then
  git diff --cached --name-only -z --diff-filter=ACMRT | xargs -0 redact analyze --fail-on-detect -i || exit 1
fi
```

```bash
redact analyze "Contact Jane at jane@example.com or call (555) 123-4567"
redact anonymize --strategy mask "Email: jane@example.com"
redact --format json list-entities
```

`--disable` subtracts from the compiled set (or from `--entities` when both are
set). Gateway equivalent: `{ action: allow }` on the profile.

### Postgres PII discovery

Read-only. Prefer a replica or staging database. The report is locations and
counts — never sample values. Superuser and write grants are refused.

```bash
cargo install redact-scan
redact-scan --url postgres://reader@localhost/app --schema public --out report.json
```

Crate: [`redact-scan`](https://crates.io/crates/redact-scan) 0.10.0.

`--fail-on` exits 1 when findings match. `--include-samples` is a local sidecar
only and cannot be combined with `--report-url`.

Layers and safety rails: [`docs/scanning-model.md`](docs/scanning-model.md).

### Prove what left

The gateway redacts prompts on the way to a provider. The ledger pack is what
you hand a third party. Verify the pack offline; do not trust a self-hosted
log viewer.

```bash
cargo install redact-gateway
export OTEL_SDK_DISABLED=true
redact-gateway --host 127.0.0.1

curl -s http://127.0.0.1:8080/v1/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Email me at jane@example.com"}'
```

```bash
cargo install redact-verify
redact-verify --pack <file> --pubkey <file> [--online] [--format json]
```

Crate: [`redact-verify`](https://crates.io/crates/redact-verify) 0.10.0. `--online` does not dial the network.

Exit **0** only if every check passes and R2 (`pack_anchored`) is `pass`.
**1** on any fail or R2 unproven. **2** if the pack is malformed.

Gateway walkthrough: [`docs/gateway/getting-started.md`](docs/gateway/getting-started.md).
Image: `ghcr.io/censgate/redact-gateway:latest`.

### Embed the engine

Library (version pin is updated by Prepare Release):

```toml
[dependencies]
redact-core = "0.12.2"
redact-ner = "0.12.2"  # optional ONNX NER
```

```rust
use redact_core::AnalyzerEngine;

let engine = AnalyzerEngine::new();
let result = engine.analyze("Email jane@example.com", None)?;
```

WASM (pattern engine only — not `redact-core` compiled alone):

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build --target web crates/redact-wasm
```

REST: `cargo run --release -p redact-api` then `POST /api/v1/analyze`.
Install and Docker: [`docs/install.md`](docs/install.md). WASM details:
[`docs/wasm.md`](docs/wasm.md). NER: [`docs/ner.md`](docs/ner.md).

## Documentation

- [Docs index](docs/README.md)
- [Entity types](docs/entity-types.md) — 61 compiled types; source of truth is `list-entities`
- [Secrets detection](docs/secrets-detection.md)
- [Postgres scanning model](docs/scanning-model.md)
- [Gateway](docs/gateway/getting-started.md)
- [Project structure](docs/project-structure.md) · [Testing](docs/testing.md) · [Roadmap](docs/roadmap.md)
- [Project scope](docs/PROJECT_SCOPE.md) · [Contributing](CONTRIBUTING.md)
- [docs.rs/redact-core](https://docs.rs/redact-core) · [Examples](examples/)

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md), and [CLA.md](CLA.md).

New prefixed provider tokens belong in a YAML **pattern pack**, not in
`redact-core`. Core will not absorb the full gitleaks rule set. See
[CONTRIBUTING.md](CONTRIBUTING.md#pattern-pack-prs-provider-coverage).

Sign every commit (`git commit -s`). The CLA bot asks first-time human
contributors to sign on the pull request.

## License

[Apache License 2.0](LICENSE). Copyright (c) 2026 Censgate LLC.

## Support

- [GitHub Issues](https://github.com/censgate/redact/issues)
- [GitHub Discussions](https://github.com/censgate/redact/discussions)
- Email: support@censgate.com
