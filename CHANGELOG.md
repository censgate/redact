# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `redact-scan`: new workspace crate and `redact-scan` binary for read-only
  Postgres PII discovery. This revision adds the report types, credential
  scrubber, and CLI preflight (`--include-samples` cannot be combined with
  `--report-url`). Reports contain locations and counts only — never sample
  values.

## [0.9.1] - 2026-08-08

### Fixed

- Docker images: pin Rust builders to `rust:1.93-slim-bookworm` so binaries
  match `gcr.io/distroless/cc-debian12` glibc (fixes
  `GLIBC_2.38 not found` on `redact-gateway` / API images; #114).
- CI/release: reject floating `rust:*-slim` builders and enforce that the
  builder's Debian release matches the distroless runtime; smoke-test
  gateway (`--version`) and slim API (`/healthz`) before publish.
- Publish `redact-gateway` to crates.io (was incorrectly `publish = false` in the
  0.9.0 tag). Release automation now publishes it after `redact-cli`.

## [0.9.0] - 2026-07-27

### Added

- `redact-gateway`: policy profiles with per-entity actions (`allow`, `block`,
  `mask`, `replace`, `hash`, `tokenize`), confidence floors, scan targets, and
  bundled `default` / `reversible` / `strict` / `secrets_only` / `permissive`
  profiles (fail-closed by default on traffic-handling profiles).
- `redact-gateway`: resolved configuration from YAML and/or `CENSGATE_*`
  environment variables (`env` / `file` / `layered`), `deny_unknown_fields`
  schema, `SIGHUP` reload that keeps the last good snapshot, and
  `validate-config` / `print-config` / `print-policy` subcommands.
- `redact-gateway`: reversible tokenization with AES-256-GCM sealed mappings
  (`CENSGATE_TOKEN_DEK`) and token map backends `off`, process-local `memory`,
  and shared `vault_kv2` (HashiCorp Vault or OpenBao KV v2).
- `redact-gateway`: inbound authentication modes `none`, static `api_key`, and
  OIDC/JWT resource-server validation with JWKS refresh and tenant/profile
  claim mapping.
- `redact-gateway`: OpenTelemetry traces, metrics, and logs (`OTEL_*`),
  gateway operation spans (`CENSGATE_TRACE_OPERATIONS`), opt-in development-stage
  `gen_ai.*` attributes, and audit records via `stdout` / `file` / `otlp` sinks.
- `redact-gateway`: runtime YAML pattern packs (`CENSGATE_PATTERN_PACKS` /
  `packs.paths`) loaded alongside or instead of built-in patterns.
- `redact-gateway`: expanded HTTP surface — `/v1/chat/completions`,
  `/v1/completions`, `/v1/embeddings`, `/v1/models`, `/v1/redact`, `/v1/restore`,
  `/v1/compliance/status`, `/v1/compliance/check`, plus `/health`/`/livez`/
  `/readyz`/`/metrics` outside the auth layer.
- `redact-gateway`: streaming redaction modes `buffered` (default, full-stream
  detection with in-place SSE rewrite of content and tool-call argument deltas)
  and `incremental` (hold-back window).
- `redact-gateway`: deployment assets — `Dockerfile.gateway`,
  `docker-compose.gateway.yml`, an audit-grade OpenTelemetry Collector config
  and Kubernetes manifests under `deploy/`, and example configurations under
  `crates/redact-gateway/examples/` validated in CI.
- Docs: operator guide under `docs/gateway/` (including
  `docs/gateway/getting-started.md`) and rewritten
  `crates/redact-gateway/README.md`.
- `redact-core`: 18 new secret/credential entity types (`PRIVATE_KEY`, `JWT_TOKEN`,
  `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK`,
  `STRIPE_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `NPM_TOKEN`, `PYPI_TOKEN`, `SENDGRID_API_KEY`, `TWILIO_API_KEY`,
  `TELEGRAM_BOT_TOKEN`, `HASHICORP_VAULT_TOKEN`, `DATABASE_CONNECTION_STRING`),
  bringing the pattern-based entity count to 54. Detection uses anchored,
  high-precision prefix regexes (e.g. `AKIA...`, `ghp_...`, `sk-ant-...`,
  `-----BEGIN ... PRIVATE KEY-----` blocks); generic `key=...` / `password=...`
  catch-alls are deliberately excluded pending entropy scoring. Available via
  `--entities` in the CLI. Phase 1 of #101.
- CLI: `redact analyze --fail-on-detect` opt-in flag exits with code 1 when PII is
  detected, for CI gates and pre-commit hooks. Default behavior (exit 0 on success)
  is unchanged (#95).
- CLI: `redact analyze -i`/`--file` now accepts multiple paths (`-i f1 f2` or repeated
  `-i f1 -i f2`). Text output prints a `--- <path> ---` header per file; JSON output
  for multiple files is a single array of `{ "file", "result" }` objects. Single-file
  and inline-text output are unchanged (#94).
- WASM: `redact-wasm` now exposes a real `RedactEngine` backed by `redact-core`'s
  pattern engine (54 entity types, including secrets/credentials) via
  `wasm-bindgen`, with `analyze`, `anonymize` (replace/mask),
  `anonymize_with_hash` (required non-empty salt), and `supported_entities`
  bindings. Compiles for `wasm32-unknown-unknown`; CI runs `cargo check` plus
  Node `wasm-pack test` runtime coverage. `redact-wasm` is the only supported
  WASM entry point (standalone `redact-core` wasm32 builds are not supported).

### Changed

- `redact-gateway`: the inference destination is called a **provider**
  throughout, matching the OpenTelemetry GenAI conventions the gateway emits
  (`gen_ai.provider.name`). `backend` refers only to token map storage and
  `upstream` only to direction. Settings are `CENSGATE_PROVIDER_*`, the YAML
  section is `provider:`, and the flags are `--provider-base-url` /
  `--provider-api-key`. Each setting has exactly one name; `VAULT_ADDR` /
  `VAULT_TOKEN` (and the OpenBao `BAO_` spellings) are the only unprefixed
  variables read, since they configure the token map server rather than the
  gateway.
- `redact-gateway`: `redaction.allow_profile_header` defaults to `false`; the
  profile header is ignored unless enabled. Startup refuses
  `forward_client_authorization` with inbound auth, non-32-byte sealing keys,
  and all-zero sealing keys; warns for tokenize without a durable token map and
  for profile-header-with-auth-off. `/v1/restore` requires authentication;
  authenticated token-map keys are subject-bound. KV v2 writes use check-and-set
  with bounded retries. SIGHUP reload applies a documented subset of settings
  and logs restart-required field names.
- `redact-gateway`: `gen_ai.operation.name` is derived from the surface being
  called (`chat`, `embeddings`, `text_completion`), `gen_ai.request.stream`
  marks streamed requests, streamed provider calls now get a client span, and
  `gen_ai.provider.name` is configurable with `CENSGATE_PROVIDER_NAME` for
  deployments whose provider is not OpenAI.
- `redact-core`: `Instant::now()` (which panics on `wasm32-unknown-unknown`) is now
  gated behind a `Timer` helper so the engine is WASM-safe; native timing behavior is
  unchanged.
- `chrono` workspace dependency now disables default `clock` feature (only the
  `DateTime<Utc>` type and `serde` are used); no behavior change for native builds.
- WASM scope: NER (`PERSON`, `ORGANIZATION`, `LOCATION` in prose) is not available in
  the WASM build because the ONNX model + runtime do not fit browser/Cloudflare Workers
  limits. See the README "WebAssembly" section for the hybrid alternative.

### Fixed

- `patterns/security/credentials.yaml`: the password-field pattern escaped a
  quote with a backslash inside a single-quoted YAML scalar, which made the
  whole pack unparseable. Pattern packs are now parsed strictly rather than
  repaired by the loader.

### Security

- WASM: `anonymize(..., "hash")` is rejected; unsalted hashing of low-entropy PII
  is enumerable. Callers must use `anonymize_with_hash(text, salt)` with
  non-empty caller-provided salt for deterministic pseudonymization (no random
  salt is generated).
- Bump `openssl` to 0.10.80 to fix CVE-2026-45784 (GHSA-phqj-4mhp-q6mq, out-of-bounds write in AES-KW-PAD cipher path)
- Bump `rand` to 0.9.3 to fix GHSA-cq8v-f236-94qc (unsoundness UB when custom logger accesses ThreadRng during reseeding)
  - Updated transitive dependencies in `quinn-proto` and `tokenizers` that also depended on `rand 0.9.2`

## [0.8.3] - 2026-04-19

### Changed

- Docs: crates.io metadata, benchmarks, and release documentation updates (#54).

## [0.8.2] - 2026-04-17

### Fixed

- Replace stale BUSL-1.1 per-file copyright headers with Apache-2.0 across all source files (fixes #50)

## [0.5.0] - 2026-01-31

### Added

This is the first release of the Rust rewrite, replacing the previous Go implementation (v0.1.0-v0.4.1).

#### Core Engine
- **Pattern-based PII detection** with 36+ entity types (emails, SSNs, credit cards, phone numbers, etc.)
- **ML-powered NER** using ONNX Runtime for transformer models (BERT, RoBERTa, DistilBERT)
- **Four anonymization strategies**: replace, mask, hash, encrypt
- **Policy-aware processing** with configurable rules and thresholds

#### Crates
- `redact-core` - Core detection and anonymization engine
- `redact-ner` - ONNX-based Named Entity Recognition
- `redact-api` - REST API service (Axum-based)
- `redact-cli` - Command-line tool
- `redact-wasm` - WebAssembly bindings (placeholder)

#### Infrastructure
- Multi-architecture Docker images (AMD64/ARM64)
- Distroless container runtime for minimal attack surface
- GitHub Actions CI/CD with automated releases
- Automated publishing to crates.io and GHCR

### Performance

Benchmarked against Microsoft Presidio:

| Metric | Redact (Rust) | Presidio (Python) | Speedup |
|--------|---------------|-------------------|---------|
| p50 Latency | 0.20 ms | 6.96 ms | **34x** |
| p99 Latency | 0.96 ms | 22.50 ms | **23x** |
| Throughput | 16,223 req/s | 171 req/s | **95x** |

### Changed

- Complete rewrite from Go to Rust
- License changed from Apache-2.0 to BUSL-1.1

### Migration from Go (v0.4.x)

The Rust version is a complete rewrite with a different API. Key differences:

| Go (v0.4.x) | Rust (v0.8.2) |
|-------------|---------------|
| `redactctl` CLI | `redact` CLI |
| Go library import | Rust crate dependency |
| In-process only | REST API + CLI + WASM |
| Pattern-based only | Pattern + ML-based NER |

See [README.md](README.md) for usage examples.

---

## Previous Releases (Go Implementation)

For historical reference, versions v0.1.0 through v0.4.1 were the Go implementation.
Those versions are no longer maintained. Please upgrade to v0.9.1 or later.
