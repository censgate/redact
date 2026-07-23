# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CLI: `redact analyze --fail-on-detect` opt-in flag exits with code 1 when PII is
  detected, for CI gates and pre-commit hooks. Default behavior (exit 0 on success)
  is unchanged (#95).
- CLI: `redact analyze -i`/`--file` now accepts multiple paths (`-i f1 f2` or repeated
  `-i f1 -i f2`). Text output prints a `--- <path> ---` header per file; JSON output
  for multiple files is a single array of `{ "file", "result" }` objects. Single-file
  and inline-text output are unchanged (#94).
- WASM: `redact-wasm` now exposes a real `RedactEngine` backed by `redact-core`'s
  pattern engine (36 entity types) via `wasm-bindgen`, with `analyze`,
  `anonymize` (replace/mask), `anonymize_with_hash` (required non-empty salt),
  and `supported_entities` bindings. Compiles for `wasm32-unknown-unknown`; CI
  runs `cargo check` plus Node `wasm-pack test` runtime coverage. `redact-wasm`
  is the only supported WASM entry point (standalone `redact-core` wasm32 builds
  are not supported).

### Changed

- `redact-core`: `Instant::now()` (which panics on `wasm32-unknown-unknown`) is now
  gated behind a `Timer` helper so the engine is WASM-safe; native timing behavior is
  unchanged.
- `chrono` workspace dependency now disables default `clock` feature (only the
  `DateTime<Utc>` type and `serde` are used); no behavior change for native builds.
- WASM scope: NER (`PERSON`, `ORGANIZATION`, `LOCATION` in prose) is not available in
  the WASM build because the ONNX model + runtime do not fit browser/Cloudflare Workers
  limits. See the README "WebAssembly" section for the hybrid alternative.

### Security

- WASM: `anonymize(..., "hash")` is rejected; unsalted hashing of low-entropy PII
  is enumerable. Callers must use `anonymize_with_hash(text, salt)` with
  non-empty caller-provided salt for deterministic pseudonymization (no random
  salt is generated).
- Bump `openssl` to 0.10.80 to fix CVE-2026-45784 (GHSA-phqj-4mhp-q6mq, out-of-bounds write in AES-KW-PAD cipher path)
- Bump `rand` to 0.9.3 to fix GHSA-cq8v-f236-94qc (unsoundness UB when custom logger accesses ThreadRng during reseeding)
  - Updated transitive dependencies in `quinn-proto` and `tokenizers` that also depended on `rand 0.9.2`

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
Those versions are no longer maintained. Please upgrade to v0.8.2 or later.
