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

Host-only compiled-type facts (must match `redact --format json list-entities`).
The same script also checks CLI `--help` flags, crate versions in `README.md`,
`docs/install.md`, and `crates/*/README.md`, and the `SECURITY.md` support table:

```bash
cargo build -p redact-cli
node scripts/extract-facts.mjs --check --bin ./target/debug/redact
```

Documented `redact` CLI examples (`README.md` and `docs/`). Opt out of an
illustrative fence with `<!-- redact-doc-examples: skip -->` immediately
before the block:

```bash
node scripts/run-doc-examples.mjs --bin ./target/debug/redact
```

Multilingual redaction coverage (emails, cards, AWS keys, 16–17 digit bank
numbers):

```bash
./scripts/ci/check-multilingual-coverage.sh ./target/debug/redact
```

Public-hygiene gate. Deny regexes come from `PUBLIC_HYGIENE_PATTERNS`
(newline-separated). The job skips when that variable is unset. Optional
path allowlist: `data/public-hygiene-allowlist.txt`.

```bash
node scripts/check-public-hygiene.mjs
```
