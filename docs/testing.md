# Testing

```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run benchmarks
cargo bench --package redact-core

# Run NER E2E tests (requires ONNX model)
cargo test --package redact-ner --test ner_e2e -- --ignored

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
