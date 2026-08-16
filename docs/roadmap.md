# Roadmap

Shipped items below are historical. Current compiled entity count is **61**
(`redact --format json list-entities`). See [CHANGELOG](../CHANGELOG.md).

## Pre-1.0.0

### v0.8.2

- [x] Complete Rust rewrite (replacing Go v0.1.0-v0.4.1)
- [x] Pattern-based entity types with checksum validation
- [x] Full ONNX NER integration (PERSON, ORGANIZATION, LOCATION)
- [x] 4 anonymization strategies (replace, mask, hash, encrypt)
- [x] REST API service
- [x] CLI tool
- [x] Multi-arch Docker images (AMD64/ARM64)
- [x] Full Docker image with embedded NER model (`ghcr.io/censgate/redact:full`)
- [x] Comprehensive test suite (~75% coverage)
- [x] Entity overlap resolution with specificity scoring
- [x] Publish crates to crates.io

### v0.9.0

- [x] 18 secret/credential entity types (54 pattern-based total at that release) — Phase 1 of #101
- [x] Entropy-gated `GENERIC_SECRET` + 6 named types (61 compiled total) — Phase 2 of #101
- [x] `redact-gateway`: policy profiles, reversible tokenization, OIDC and API key auth,
      OpenTelemetry traces/metrics/logs, runtime pattern packs, streaming redaction,
      container and Kubernetes assets (`ghcr.io/censgate/redact-gateway`)
- [x] CLI: `--fail-on-detect` and multi-file `-i` / `--file` analyze
- [x] WebAssembly bindings — real pattern engine (browser + Cloudflare Workers)
- [ ] Streaming API for large texts
- [ ] Enhanced documentation
- [ ] WebAssembly + inline NER — deferred; ONNX model + runtime do not fit
      Cloudflare Workers limits. Use the hybrid architecture in
      [WebAssembly](wasm.md) for name-based detection.

### v0.9.1

- [x] Docker images: pin Rust builders to `rust:1.93-slim-bookworm` so binaries
      match `gcr.io/distroless/cc-debian12` (fixes `GLIBC_2.38 not found` on
      published gateway/API images; #114)
- [x] CI/release guards: Dockerfile builder/runtime Debian pairing check and
      gateway/API image smoke tests before publish

### v0.10.0

- [x] `redact-scan`: read-only Postgres PII discovery (locations and counts only)
- [x] `redact-verify`: independent offline ledger evidence-pack verifier
- [x] CLI `--disable` / `list-entities`; entropy-gated `GENERIC_SECRET` (61 compiled types)
