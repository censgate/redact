# Agent Instructions

Concise guidance for AI agents working with the Redact codebase.

## Project Overview

**Redact** is a high-performance, open-source PII (Personally Identifiable Information) detection and anonymization engine built in Rust. It serves as a drop-in replacement for Microsoft Presidio with 10-100x better performance.

**Key capabilities:**
- Pattern-based detection (54 entity types via regex, including secrets/credentials)
- ML-powered NER using ONNX Runtime (BERT, RoBERTa, DistilBERT)
- Multiple anonymization strategies (replace, mask, hash, encrypt)
- Multi-platform: REST API, CLI, WebAssembly, privacy gateway (`redact-gateway`)

## Crate Architecture

```
crates/
├── redact-core/    # Core engine - recognizers, anonymizers, analyzer
├── redact-ner/     # ONNX-based Named Entity Recognition (CRITICAL)
├── redact-api/     # REST API server (Axum)
├── redact-cli/     # Command-line interface (Clap)
├── redact-wasm/    # WebAssembly bindings
├── redact-gateway/ # OpenAI-compatible privacy gateway (embeds redact-core)
└── redact-verify/  # Independent ledger pack verifier (no redact-core)
```

### Crate Dependencies

```
redact-ner ──────► redact-core
redact-api ──────► redact-core
redact-cli ──────► redact-core
redact-wasm ─────► redact-core
redact-gateway ─► redact-core
```

### Critical Components

**redact-core** (`crates/redact-core/`)
- `engine/` - AnalyzerEngine orchestrates detection and anonymization
- `recognizers/` - Pattern-based PII detection (regex)
- `anonymizers/` - Replace, mask, hash, encrypt strategies
- `types/` - EntityType, RecognizerResult, AnalysisResult

**redact-ner** (`crates/redact-ner/`) - **CRITICAL COMPONENT**
- `recognizer.rs` - NerRecognizer with ONNX Runtime integration
- `tokenizer_wrapper.rs` - HuggingFace tokenizer integration
- Uses `ort` crate for ONNX inference
- Supports quantized int8 models for efficiency

## Development Commands

```bash
# Build
cargo build --workspace
cargo build --release

# Test
cargo test --workspace
cargo test --package redact-core
cargo test --package redact-ner --test ner_e2e -- --ignored  # Requires ONNX model

# Quality
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Benchmarks
cargo bench --package redact-core

# Run API server
cargo run --release --bin redact-api

# Run CLI
cargo run --bin redact-cli -- analyze "test@example.com"
```

## Code Conventions

### Rust Style
- Follow official Rust style guide
- Use `cargo fmt` before committing
- All public APIs require doc comments (`///`)
- Target >75% test coverage

### Naming
- Types: `PascalCase` (e.g., `AnalyzerEngine`, `EntityType`)
- Functions: `snake_case` (e.g., `analyze_text`)
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(ner): add multilingual model support
fix(anonymizer): handle empty string input
docs: update API examples
test(core): add pattern coverage tests
```

## Key Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace configuration, shared dependencies |
| `crates/*/Cargo.toml` | Per-crate dependencies |
| `patterns/*.yaml` | PII detection patterns (GDPR, HIPAA, CCPA) |
| `scripts/export_ner_model.py` | Export HuggingFace models to ONNX |

## NER/ONNX Pipeline

The NER pipeline is critical for detecting contextual entities (names, organizations, locations).

### Model Export
```bash
pip install transformers optimum[exporters]
python scripts/export_ner_model.py \
    --model dslim/bert-base-NER \
    --output models/bert-base-ner
```

### Integration
```rust
use redact_ner::{NerRecognizer, NerConfig};
use redact_core::AnalyzerEngine;
use std::sync::Arc;

let config = NerConfig {
    model_path: "models/bert-base-ner/model.onnx".to_string(),
    tokenizer_path: Some("models/bert-base-ner/tokenizer.json".to_string()),
    min_confidence: 0.7,
    ..Default::default()
};

let ner = NerRecognizer::from_config(config)?;
let mut engine = AnalyzerEngine::new();
engine.recognizer_registry_mut().add_recognizer(Arc::new(ner));
```

### Recommended Models
- `dslim/bert-base-NER` - Best accuracy/size balance
- `dbmdz/bert-large-cased-finetuned-conll03-english` - Highest accuracy
- `Davlan/distilbert-base-multilingual-cased-ner-hrl` - Multilingual

## Testing Strategy

```bash
# Unit tests
cargo test --package redact-core

# Integration tests
cargo test --package redact-core --test integration_policy
cargo test --package redact-core --test pattern_coverage
cargo test --package redact-core --test error_scenarios
cargo test --package redact-core --test concurrent_operations

# CLI tests
cargo test --package redact-cli

# NER E2E (requires model)
cargo test --package redact-ner --test ner_e2e -- --ignored
```

## Benchmarking

```bash
# REST API comparison vs Presidio (requires Docker)
./scripts/benchmark-comparison.sh

# Criterion micro-benchmarks (Redact internals)
cargo bench --package redact-core
```

Results saved to `docs/benchmarks/results-*.md`. The REST API benchmark is the fairest comparison since both tools are deployed as HTTP services.

## Common Tasks

### Adding a New Entity Pattern
1. Add pattern to `crates/redact-core/src/recognizers/pattern.rs`
2. Add entity type to `crates/redact-core/src/types/entity.rs`
3. Add tests to `crates/redact-core/tests/pattern_coverage.rs`

### Adding a New Anonymization Strategy
1. Create module in `crates/redact-core/src/anonymizers/`
2. Implement the `Anonymizer` trait
3. Register in `crates/redact-core/src/anonymizers/registry.rs`

### Modifying the API
1. Update handlers in `crates/redact-api/src/handlers.rs`
2. Update models in `crates/redact-api/src/models.rs`
3. Update routes in `crates/redact-api/src/routes.rs`

## Quality Gates

Before committing:
1. `cargo fmt --all` - Format code
2. `cargo clippy --all-targets --all-features -- -D warnings` - No warnings
3. `cargo test --workspace` - All tests pass
4. Commit messages follow Conventional Commits

## Environment

- **Rust**: 1.93.0 (see `.tool-versions`)
- **MSRV**: 1.88
- **Python**: 3.8+ (for NER model export only)

## Cursor Cloud specific instructions

The VM snapshot already has Rust 1.93.0 (rustfmt + clippy), the native build deps
(`pkg-config`, `cmake`, `g++`, `libssl-dev`), and the fixes below applied; the startup
update script only refreshes the toolchain and pre-fetches crates (`cargo fetch --locked`).
Standard build/lint/test/run commands live in **Development Commands** and **Testing
Strategy** above — use those. Non-obvious caveats:

- **C++ compiler must be GNU, not clang.** The workspace pulls in `tokenizers` →
  `esaxx-rs`, whose C++ build fails under clang with `esaxx.cpp: 'cstdint' file not found`.
  The environment sets `cc`/`c++` to GNU via `update-alternatives` (`gcc`/`g++`). If you
  ever hit that error, either re-run `sudo update-alternatives --set c++ /usr/bin/g++`
  and `sudo update-alternatives --set cc /usr/bin/gcc`, or build with `CC=gcc CXX=g++`.
- **CLI has no root default-run binary.** Use `cargo run -p redact-cli -- <args>`
  (e.g. `... -- analyze "test@example.com"`); `--bin redact-cli` fails from the workspace root.
- **redact-api and redact-gateway both default to port 8080.** Run only one on 8080, or
  override: `redact-api` uses `HOST`/`PORT`; `redact-gateway` uses `--host/--port`
  (or `CENSGATE_HOST`/`CENSGATE_PORT`). Example dev split: API on 8080, gateway on 8081.
- **Gateway dev tips.** Pass `OTEL_SDK_DISABLED=true` to silence telemetry-export noise.
  Health: `GET /healthz`. Redaction: `POST /v1/redact` with a `profile`
  (`strict` blocks, `reversible` tokenizes). `POST /v1/restore` returns `403` under the
  default no-auth config — that is expected; it needs `auth.mode = api_key` or `oidc`.
- **NER is optional.** `redact-ner` builds without a model (the `ort` crate uses
  `load-dynamic`), but the NER e2e tests are `#[ignore]` and need an exported ONNX model
  plus `libonnxruntime.so` (`ORT_DYLIB_PATH`) — not provisioned by default.
