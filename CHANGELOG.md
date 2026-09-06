# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- PERSON spans from hybrid identity no longer keep a trailing `'s` / `’s`,
  and adjacent same-type fragments of one word (ONNX split names) merge
  before tokenize. The vault reuses one PERSON token for the same
  normalized surface (`Nimbus` / `Nimbus's` / `nimbus`) in a session.

## [0.12.0] - 2026-09-05

Crate/image release of the NER serving-path and `vault_kv2` Kubernetes-auth
work merged in #168. Notes also appear under 0.11.2 (changelog merge during
that patch). This heading unblocks `scripts/ci/changelog-notes.sh`.

## [0.11.2] - 2026-09-04

### Added

- `vault_kv2` Kubernetes auth (`CENSGATE_VAULT_AUTH=kubernetes`) against
  `openbao-tokens`, with in-process token cache/renew. Static
  `CENSGATE_VAULT_TOKEN` is local-dev only. Role `external-secrets` is
  refused. CAS retries are jittered (8 attempts); empty puts are skipped;
  `/readyz` caches OpenBao health for 2s. Kubernetes-auth KV calls share a
  read lock so login refresh does not serialize every OpenBao request.
- Sample `deploy/kubernetes/redact-gateway.yaml`: min 2 replicas, HPA,
  PDB, startupProbe, ServiceAccount, Guaranteed 2 CPU / 4Gi, NetworkPolicy
  to `openbao-tokens`. ESO ExternalSecret owns `redact-gateway-dek`; API
  keys live in a separately provisioned Secret this manifest never applies.
- `scripts/bench-gateway-ner.sh` and `docs/gateway/openbao-tokens-spike.md`
  (do not quote the 32× Presidio redact-api number on the NER gateway).
- `scripts/validate-distilbert-ner.sh` (gated; default model unchanged).
- `export_ner_model.py --quantize` now runs dynamic INT8.
- `CENSGATE_NER_INTRA_THREADS` (default 1). Gateway/API analyze and
  anonymize use `block_in_place` on multi-thread tokio.
- Standalone `POST /v1/redact` emits the same detect / policy / tokenmap
  child spans as the proxy path, plus stage spans for patterns,
  contextual identity, tokenizer, ONNX lock wait, ONNX exec, and decode.
  No text attributes. Detection and token bytes are unchanged from 0.11.1.

### Changed

- Same exported ONNX model: when `input_ids` sequence dim is dynamic, pad
  to 32/64/128/256/512 instead of always 512. A bounded session pool
  (`CENSGATE_NER_SESSION_POOL`, default 2, cap 4) acquires with try_lock
  round-robin then block. Detection and token bytes stay 0.11.1-identical.

## [0.11.1] - 2026-09-02

### Fixed

- Identity detection skips spans that already sit inside a vault token
  (`[PERSON_1]`, `[LOCATION_2]`, `[EMAIL_ADDRESS_3]`, and the same shape
  for other uppercase types). Re-redacting tokenized text no longer mints
  nested placeholders such as `[[PERSON_3]_1]`.

## [0.11.0] - 2026-09-01

### Added

- Hybrid identity detection in `redact-ner` / `redact-gateway`: a contextual
  parser plus optional ONNX NER. Pet-context names emit `PERSON`. Location
  cues emit `LOCATION`. Capitalization alone never creates an entity.
- Gateway image (`Dockerfile.gateway`) bakes the NER model and ONNX Runtime
  and sets `CENSGATE_NER_REQUIRED=true`. Local and tests stay contextual-only
  when no model is present.
- Config: `CENSGATE_NER_MODEL_PATH`, `CENSGATE_NER_REQUIRED`, YAML `ner:`.
  NER load is restart-required.

### Changed

- Removed the Title-case `global_full_name` regex from `global_pii.yaml`
  (false positives on multi-word places; missed single-token given names).
- Shipped pack pattern count is 81 (enabled 70).
- Default policy names `PERSON` / `LOCATION` / `ORGANIZATION` (replace).
  The `reversible` profile tokenizes those types.

### Changed

- README leads with CI secrets, Postgres discovery, and offline evidence
  verification instead of the gateway-as-headline framing. Project structure,
  testing, roadmap, and acknowledgments moved under `docs/`.
- `redact-scan` and `redact-verify` 0.10.0 are on crates.io. Workspace crate
  keywords/homepage aligned for crates.io discovery. Subsequent tags publish
  both crates in the Release workflow.

## [0.10.0] - 2026-08-16

### Added

- `GENERIC_SECRET`: charset-aware Shannon entropy over assignment-like values
  only (length-aware floor, segment keyword allow/deny, value-only spans).
  It will catch `api_key=…` / `export SERVICE_SECRET=…` that pass the
  charset, length, and keyword gates. It will not catch arbitrary
  high-entropy blobs, hashes or UUIDs on a digest LHS, lockfile
  `integrity=` lines, placeholders, or prefixed types (those stay named
  types). Independently disableable via CLI `--disable`, WASM
  `analyze_excluding`, or gateway `{ action: allow }`. See
  `docs/secrets-detection.md`. Phase 2 of #101 (#138).
- Named secret types: `HUGGINGFACE_TOKEN`, `DATABRICKS_TOKEN`,
  `DIGITALOCEAN_TOKEN`, `NOTION_API_KEY`, `PERPLEXITY_API_KEY`,
  `HTTP_BASIC_AUTH` (decode-validated). GitLab length-closed shapes and AWS
  Bedrock under `AWS_ACCESS_KEY`. Compiled entity count is 61 (60 pattern +
  `GENERIC_SECRET`) (#138).
- Optional long-tail pack `patterns/optional/providers-v1.yaml` (gitleaks MIT,
  pinned commit). Opt-in only: not on the Docker / compose / Kubernetes
  default path, and not compiled into WASM. This is not gitleaks parity
  (#138).
- CLI `--disable` (subtracts from `--entities`, or from the full compiled
  set when `--entities` is omitted; empty remaining set is an error),
  `redact --format json list-entities`, and host-only
  `scripts/extract-facts.mjs` → `data/facts.json` (#138).
- `redact-scan`: new workspace crate and `redact-scan` binary for read-only
  Postgres PII discovery. Report types, credential scrubber, CLI preflight,
  a read-only safety session (refuse superuser and write grants), and
  layers 0 / 0.5 / 1 / 2 (catalog, `pg_stats`, bounded `TABLESAMPLE`,
  JSON paths). Optional `--report-url` POSTs the report JSON; `--fail-on`
  exits 1 on matching findings. Reports contain locations and counts
  only — never sample values. See `docs/scanning-model.md` (#131).
- `redact-verify`: new workspace crate and `redact-verify` binary for
  independent offline verification of Censgate ledger evidence packs.
  No `redact-core` dependency; default path does not dial the network
  (#132).
- Contributor License Agreement and Code of Conduct, with a CLA GitHub
  Action (#119, #120).

### Changed

- **Gateway default pattern-pack path (migration).** 0.9.x images set
  `CENSGATE_PATTERN_PACKS=/app/patterns`, which loaded the whole tree
  including `patterns/security`. Images now set
  `/app/patterns/compliance:/app/patterns/pii`. Existing gateway users
  lose `patterns/security` on the default path (including the now-disabled
  credentials catch-alls). Directories named `optional/` and `quarantine/`
  are never auto-walked. Restore the old tree with
  `CENSGATE_PATTERN_PACKS=/app/patterns` only if you accept the catch-all
  risk; the supported opt-in for long-tail prefixes is
  `patterns/optional/providers-v1.yaml` (#138).
- Release: GitHub Release publication waits for all three image jobs and a
  post-push digest smoke on `linux/amd64` and `linux/arm64` (the load-then-push
  split is what let #114 ship). Gateway image smoke asserts `/v1/redact`
  (email replace + AWS key block on the default profile), not only
  `--version`. crates.io publish is checked against the index after the
  `continue-on-error` publish steps. A no-checkout stranger-path job
  installs from crates.io and pulls the published gateway image (#137).
  `publish-crates` now waits for `verify-pushed-images`. Hyphenated
  (prerelease) versions push only the exact version tag so `:latest` /
  `:MAJOR` / `:MINOR` / `:full` are not rewritten.

### Fixed

- `GENERIC_SECRET` rejects SCREAMING_SNAKE and path-shaped values instead of
  scoring them as alphanumeric. HTTP Basic auth requires canonical base64
  (decode + re-encode), so unused padding bits are rejected. AGE keeps its
  full labelled span. AWS Bedrock and Grafana Cloud tokens use a trailing
  delimiter instead of `\\b` after `=`. Pack `entropy: generic` requires
  capture group 1 at analyze time. Non-entropy pack rules keep the full
  match unless they set `value_group`. HTTP Basic matching is
  case-insensitive (#138).
- Removed the `api_key` → `PRIVATE_KEY` alias (#138).
- Encrypt nonces adapted for `aes-gcm` 0.11 (`Nonce::from` instead of
  deprecated `Nonce::from_slice`); envelope layout unchanged (#135).
- Pin `ort` to `=2.0.0-rc.12` so the full image matches
  `redact-ner-base:v2` (ONNX Runtime 1.24.4). `^2.0.0-rc.12` had
  resolved to `rc.13`, which requires ONNX Runtime 1.28 and panicked
  on startup (`BadVersion`). Caught by the `v0.10.0-rc.1` NER smoke.
- Published images no longer compile the native-arch path with
  `target-cpu=native`. That baked the builder runner's µarch and
  SIGILL'd `verify-pushed-images` on a different GitHub Actions
  runner (empty logs, ~1s exit). Native amd64 now uses `x86-64-v3`
  and native arm64 uses `neoverse-n1`, matching the existing
  cross-compile flags.
- `create-release` downloads only `redact-*` binary artifacts so
  buildx `*-dockerbuild` cache uploads cannot flake the GitHub
  Release step after images already verified.
- Stranger-path crate install uses a non-login shell (Cargo stays
  on `PATH`) and `cargo install --version` so a prerelease tag is
  what gets installed.
- `redact-scan`: upgrade `testcontainers-modules` so CI `cargo audit` is not
  failed by `astral-tokio-tar` advisories in the Postgres acceptance-test
  tree. Ignore unfixed `RUSTSEC-2023-0071` (`rsa` / Marvin) which is pulled
  only by unused optional `sqlx-mysql` — this crate enables Postgres only
  (#131).
- `redact-scan`: retry testcontainer start and pre-pull `postgres:16-alpine`
  in CI so Hub `bytes remaining on stream` flakes do not fail the job
  (#131).

### Security

- `patterns/security/credentials.yaml` catch-alls are disabled. In
  particular `sec_aws_secret_key` was `\b[A-Za-z0-9/+=]{40}\b`, which
  matched any 40-character blob — including every SHA-1. Combined with
  the default pack-path change above, those rules are no longer on the
  Docker path (#138).

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
Those versions are no longer maintained. Please upgrade to v0.12.0 or later.
