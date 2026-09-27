# Testing

```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run benchmarks
cargo bench --package redact-core
cargo bench -p redact-gateway --bench hot_path

# Release-mode gateway latency ceiling (also runs in CI)
cargo test -p redact-gateway --release --test hot_path_budget -- --nocapture

# Run NER E2E tests (requires ONNX model)
cargo test --package redact-ner --test ner_e2e -- --ignored

# Reference-language smoke (Davlan ONNX directory; see docs/ner.md)
REDACT_NER_SMOKE_DIR=models/multilingual-ner \
  cargo test -p redact-ner --test ner_e2e -- --ignored test_reference_language_ner_smoke

# Run specific test suites
cargo test --package redact-core --test pattern_coverage
cargo test --package redact-core --test error_scenarios
cargo test --package redact-core --test concurrent_operations
```

See [TEST_COVERAGE.md](../TEST_COVERAGE.md) for the coverage report.

Host-only compiled-type facts (must match `redact --format json list-entities`):

```bash
cargo build -p redact-cli
node scripts/extract-facts.mjs --check --bin ./target/debug/redact
```
