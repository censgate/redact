<div align="center">
<img src="https://raw.githubusercontent.com/censgate/redact/main/assets/censgate-redact-logo-v1.png" alt="Censgate Redact" width="400">

[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/censgate/redact/workflows/CI/badge.svg)](https://github.com/censgate/redact/actions)
[![Crates.io](https://img.shields.io/crates/v/redact-core.svg)](https://crates.io/crates/redact-core)

**High-performance PII detection, anonymization, and AI privacy gateway**

A production-ready Rust engine — drop-in Presidio replacement for detection and anonymization, plus an OpenAI-compatible gateway that redacts prompts and model answers in flight. Pattern detection covers 54 entity types (including secrets and credentials); WebAssembly ships the same pattern engine for browsers and edge runtimes.

[Quick Start](#quick-start) · [Privacy Gateway](#privacy-gateway) · [Documentation](#documentation) · [Examples](#examples) · [Contributing](#contributing)

</div>

---

## Features

- **High Performance** — 10-100x faster than Python-based solutions with sub-millisecond inference
- **Memory Safe** — Rust's borrow checker eliminates entire classes of security vulnerabilities
- **Production Ready** — 54 pattern-based entity types with validation (including secrets/credentials), plus transformer-based NER
- **AI Privacy Gateway** — OpenAI-compatible proxy (`redact-gateway`) with policy profiles, reversible tokenization, API key/OIDC auth, OpenTelemetry, and buffered/incremental streaming redaction
- **Multi-Platform** — REST API, CLI, WebAssembly (pattern-only), and privacy gateway
- **ML-Powered** — Full ONNX Runtime integration for transformer models (BERT, RoBERTa, DistilBERT)
- **Lightweight** — ~20-50MB memory footprint vs ~300MB for Presidio
- **Extensible** — Plugin architecture for custom recognizers and anonymization strategies

## Quick Start

### Install the CLI

```bash
cargo install redact-cli
redact --version
```

### Privacy Gateway (OpenAI-compatible proxy)

`redact-gateway` embeds `redact-core` and sits between your app and a model provider. Start with local redaction (no provider), then point an OpenAI SDK at the gateway.

```bash
# Install from crates.io
cargo install redact-gateway
export OTEL_SDK_DISABLED=true
redact-gateway --host 127.0.0.1

# Or run from a source checkout
cargo run -p redact-gateway -- --host 127.0.0.1

curl -s http://127.0.0.1:8080/v1/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Email me at alice@example.com"}'
```

Full walkthrough (Ollama chat, OpenAI SDK, policy profiles): [`docs/gateway/getting-started.md`](docs/gateway/getting-started.md). Docker image: `ghcr.io/censgate/redact-gateway:latest`. Crates.io: [`redact-gateway`](https://crates.io/crates/redact-gateway).

### Analyze Text for PII

```bash
redact analyze "Contact John Doe at john@example.com or call (555) 123-4567"
```

Output:

```
Detected 2 PII entities:

  EmailAddress at 21..37 (score: 0.80): john@example.com
  PhoneNumber at 46..60 (score: 0.70): (555) 123-4567

Processing time: 2ms
```

### Anonymize PII

```bash
# Replace with placeholders (default)
redact anonymize "My SSN is 123-45-6789"
# Output: My SSN is [US_SSN]

# Mask sensitive data
redact anonymize --strategy mask "Email: john@example.com"
# Output: Email: jo**@****le.com

# Hash for consistent pseudonymization
redact anonymize --strategy hash "Card: 4532-1234-5678-9010"
# Output: Card: [CREDIT_CARD_a1b2c3d4]
```

### Process Files

```bash
# Analyze a file
redact analyze -i sensitive_data.txt

# Analyze multiple files at once (`-i` accepts several paths)
redact analyze -i logs/a.txt logs/b.txt logs/c.txt

# Pipe from stdin
cat document.txt | redact anonymize --strategy mask

# Output as JSON
redact analyze --format json "test@example.com" > results.json

# Multiple files as a single JSON array (one document, machine-parseable)
redact analyze --format json -i logs/a.txt logs/b.txt > results.json
```

When multiple files are analyzed, text output prints a `--- <path> ---` header before
each file's results, and JSON output is emitted as a single array of
`{ "file": "<path>", "result": <AnalysisResult> }` objects. Single-file and inline-text
output remain unchanged for backward compatibility.

### CI Gates and Pre-commit Hooks

Use `--fail-on-detect` to exit with code 1 when PII is detected, so `redact analyze`
can gate CI pipelines or git pre-commit hooks. Output is printed normally before the
non-zero exit. The flag is opt-in — without it, `analyze` exits 0 on success regardless
of detections, preserving existing behavior.

```bash
# Fail the build if a file contains PII
redact analyze --fail-on-detect -i secrets-check.txt

# Pre-commit hook example (NUL-safe paths; skip when nothing is staged)
if [ "$(git diff --cached --name-only -z --diff-filter=ACMRT | wc -c)" -gt 0 ]; then
  git diff --cached --name-only -z --diff-filter=ACMRT | xargs -0 redact analyze --fail-on-detect -i || exit 1
fi
```

### Filter by Entity Type

```bash
redact analyze --entities EmailAddress --entities UsSsn \
  "Email: test@example.com, SSN: 123-45-6789, Phone: (555) 123-4567"
# Only detects EmailAddress and UsSsn, ignores PhoneNumber
```

## WebAssembly

The **`redact-wasm`** crate is the supported WASM entry point. It compiles
`redact-core`'s **pattern engine** to `wasm32-unknown-unknown` for browsers and
edge runtimes such as Cloudflare Workers, and wires the JS RNG backends
(`getrandom` / `uuid`) required on that target. Compiling `redact-core` alone
for `wasm32-unknown-unknown` is **not** supported.

It exposes a `RedactEngine` with `analyze`, `anonymize` (replace/mask),
`anonymize_with_hash` (requires a non-empty caller-provided salt), and
`supported_entities` via `wasm-bindgen`.

```bash
# Build (requires wasm-pack and the wasm32-unknown-unknown target)
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.13.1
wasm-pack build --target web crates/redact-wasm

# Runtime tests under Node (wasm-bindgen-test)
wasm-pack test --node crates/redact-wasm
```

```js
import init, { RedactEngine } from "./pkg/redact_wasm.js";
await init();
const engine = new RedactEngine();
engine.analyze("Contact john@example.com");
engine.anonymize("Email: john@example.com", "replace");
// Hash requires caller-provided salt (never generated randomly):
engine.anonymize_with_hash("SSN 123-45-6789", "app-secret-salt");
```

### What is available

All **54 pattern-based entity types** (email, phone, SSN, credit cards, IBAN, UK
identifiers, crypto addresses, hashes, GUIDs, URLs, IP, dates, secrets and
credentials, ...) and the replace/mask anonymization strategies, plus salted
hash via `anonymize_with_hash`. Typical bundle size is ~1-3 MB.

### What is NOT available in WASM

Contextual named-entity recognition — `PERSON`, `ORGANIZATION`, `LOCATION` in
prose like "John met Acme in Boston" — requires an ONNX transformer model
(~250-420 MB) plus the ONNX Runtime. That stack does not fit Cloudflare Workers
(128 MB isolate, 64 MiB bundle, ~50 ms CPU) and is impractical to inline in a
browser module. For name-based detection, use a **hybrid architecture**:

```mermaid
sequenceDiagram
  participant Client
  participant Worker as CF Worker (pattern WASM)
  participant API as redact-api :full or Workers AI

  Client->>Worker: text
  Worker->>Worker: pattern PII scan locally
  alt names / orgs / locations needed
    Worker->>API: NER subset request
    API-->>Worker: PERSON / ORG / LOC spans
  end
  Worker-->>Client: merged redaction result
```

This tiered approach keeps fast structured-PII detection at the edge and
delegates contextual NER to a service boundary (`redact-api` `:full` image or
Cloudflare Workers AI). Inline WASM NER remains a deferred roadmap item.

## Installation

### Using Cargo (Recommended)

```bash
cargo install redact-gateway   # OpenAI-compatible privacy gateway
cargo install redact-cli       # CLI for analyze / anonymize
```

### From Source

```bash
git clone https://github.com/censgate/redact.git
cd redact
cargo build --release
cargo test --workspace
```

### Using Docker

Multi-architecture images available for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/censgate/redact:latest
docker run -p 8080:8080 ghcr.io/censgate/redact:latest
```

The image uses a minimal [distroless](https://github.com/GoogleContainerTools/distroless) base (~37MB) optimized for ARM64 (AWS Graviton, Apple Silicon) and AMD64.

The privacy gateway ships as a separate image:

```bash
docker pull ghcr.io/censgate/redact-gateway:latest
docker run -p 8080:8080 -e CENSGATE_PROVIDER_BASE_URL=http://host.docker.internal:11434 \
  ghcr.io/censgate/redact-gateway:latest
```

#### Full image (pattern + ONNX NER)

To enable **all entities** including ONNX NER (PERSON, ORGANIZATION, LOCATION, DATE_TIME), use the full image. It is **published on every release** to GHCR with tags `full`, `X.Y.Z-full`, etc.:

```bash
docker pull ghcr.io/censgate/redact:full
docker run -p 8080:8080 ghcr.io/censgate/redact:full
```

To build locally instead:

```bash
docker build -f Dockerfile.ner -t ghcr.io/censgate/redact:full .
docker run -p 8080:8080 ghcr.io/censgate/redact:full
```

The full image uses a pre-built [NER base layer](https://github.com/censgate/redact/pkgs/container/redact-ner-base) (`NER_BASE`, default `ghcr.io/censgate/redact-ner-base:v2`). Override with `--build-arg NER_BASE=...` only if you publish a different tag.

**Platform URL (`PLATFORM_REDACT_API_URL`)** — set this to the HTTP **origin only** (scheme + host + port, **no path**). Clients append `/api/v1/analyze` and `/api/v1/anonymize`. Container listens on **`8080`** by default (`PORT`). Example local compose mapping host `8081` → container `8080`: `http://localhost:8081`.

**Health** — use **`GET /healthz`** or **`GET /health`** (both **HTTP 200**, JSON body includes `"status":"healthy"`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8080` | Listen port inside the container |
| `NER_MODEL_PATH` | *(unset)* / `/app/model/model.onnx` in full image | ONNX model path; full image enables NER when set |
| `ORT_DYLIB_PATH` | *(unset)* / `/app/lib/libonnxruntime.so` in full image | ONNX Runtime `.so` for dynamic loading (`ort`) |
| `ENABLE_TRACING` | `true` | Tower HTTP trace middleware |

The full image bakes in a pre-exported NER model (`dslim/bert-base-NER`) and sets `NER_MODEL_PATH=/app/model/model.onnx`, so NER is enabled at startup. To enable NER with the default image, mount a directory containing `model.onnx` and `tokenizer.json` and set:

```bash
docker run -p 8080:8080 -v /path/to/model:/app/model -e NER_MODEL_PATH=/app/model/model.onnx ghcr.io/censgate/redact:latest
```

### Rust Version

This project requires Rust **1.93.0**. Use [Mise](https://mise.jdx.dev/) or [ASDF](https://asdf-vm.com/) for version management:

```bash
# Using Mise (recommended)
mise install rust@1.93.0

# Using ASDF
asdf install rust 1.93.0

# Using rustup
rustup install 1.93.0
rustup default 1.93.0
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
redact-core = "0.9.0"
redact-ner = "0.9.0"  # Optional: for ML-based NER
```

### Basic Pattern Detection

```rust
use redact_core::{AnalyzerEngine, AnonymizerConfig, AnonymizationStrategy};

fn main() -> anyhow::Result<()> {
    let engine = AnalyzerEngine::new();

    // Analyze text
    let text = "Contact John Doe at john@example.com or call (555) 123-4567";
    let result = engine.analyze(text, None)?;

    println!("Found {} PII entities", result.detected_entities.len());
    for entity in &result.detected_entities {
        println!(
            "  {:?}: {} (score: {:.2})",
            entity.entity_type,
            entity.text.as_deref().unwrap_or_default(),
            entity.score
        );
    }

    // Anonymize
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };
    let anonymized = engine.anonymize(text, None, &config)?;
    println!("\nAnonymized: {}", anonymized.text);

    Ok(())
}
```

### ML-Powered NER

For detecting contextual entities like person names, organizations, and locations:

```rust
use redact_core::AnalyzerEngine;
use redact_ner::{NerRecognizer, NerConfig};
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    // Configure NER with ONNX model
    let ner_config = NerConfig {
        model_path: "models/bert-base-ner/model.onnx".to_string(),
        tokenizer_path: Some("models/bert-base-ner/tokenizer.json".to_string()),
        min_confidence: 0.7,
        ..Default::default()
    };

    let ner = NerRecognizer::from_config(ner_config)?;

    // Add NER to analyzer
    let mut engine = AnalyzerEngine::new();
    engine.recognizer_registry_mut().add_recognizer(Arc::new(ner));

    // Detect both pattern-based and contextual entities
    let text = "John Doe works at Acme Corp. Email: john@acme.com";
    let result = engine.analyze(text, None)?;

    for entity in &result.detected_entities {
        println!("{:?}: {}", entity.entity_type, entity.text.as_deref().unwrap_or_default());
    }
    // Output: PERSON: John Doe, ORGANIZATION: Acme Corp, EMAIL: john@acme.com

    Ok(())
}
```

## REST API

### Start the Server

```bash
cargo run --release --bin redact-api
# Server listening on http://0.0.0.0:8080
# GET /healthz or /health — readiness probe (HTTP 200, JSON)
```

### Analyze Endpoint

```bash
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email john@example.com, SSN 123-45-6789",
    "language": "en"
  }'
```

Response:

```json
{
  "results": [
    {
      "entity_type": "EMAIL_ADDRESS",
      "start": 6,
      "end": 22,
      "score": 0.8,
      "text": "john@example.com",
      "recognizer_name": "PatternRecognizer"
    },
    {
      "entity_type": "US_SSN",
      "start": 28,
      "end": 39,
      "score": 0.9,
      "text": "123-45-6789",
      "recognizer_name": "PatternRecognizer"
    }
  ],
  "metadata": {
    "recognizers_used": 1,
    "processing_time_ms": 2,
    "language": "en"
  }
}
```

By default, `results[].text` includes the detected literal text. Set
`"include_text": false` on analyze or anonymize requests to omit literal entity
text while retaining `entity_type`, `start`, `end`, `score`, and
`recognizer_name`:

```bash
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email john@example.com, SSN 123-45-6789",
    "language": "en",
    "include_text": false
  }'
```

### Anonymize Endpoint

```bash
curl -X POST http://localhost:8080/api/v1/anonymize \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact John at john@example.com",
    "config": {
      "strategy": "mask",
      "mask_char": "*",
      "mask_start_chars": 2,
      "mask_end_chars": 4
    },
    "include_text": false
  }'
```

## Privacy Gateway

`redact-gateway` is an OpenAI-compatible proxy that embeds `redact-core` in-process. It sits between your application and a model provider: outbound prompts are scanned and rewritten according to a policy profile, and inbound completions can be scanned and (when using reversible tokens) restored for the caller.

**Start here:** [`docs/gateway/getting-started.md`](docs/gateway/getting-started.md) — `/v1/redact` with no provider, then Ollama chat, then an OpenAI SDK.

```bash
# Local redaction without a model provider
export OTEL_SDK_DISABLED=true
cargo run -p redact-gateway -- --host 127.0.0.1

curl -s http://127.0.0.1:8080/v1/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Email me at alice@example.com"}'

# Chat proxy (requires a provider such as Ollama with a pulled model)
cargo run -p redact-gateway -- --provider-base-url http://127.0.0.1:11434

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

With the bundled `default` profile the provider sees `[EMAIL_ADDRESS]` instead of the raw address. Surfaces include `/v1/chat/completions` (JSON and SSE), `/v1/completions`, `/v1/embeddings`, `/v1/redact`, `/v1/restore`, and compliance helpers. Configuration is YAML and/or `CENSGATE_*` environment variables; `validate-config`, `print-config`, and `print-policy` subcommands inspect the resolved settings without serving.

| Capability | Notes |
|------------|--------|
| Policy profiles | Per-entity `allow` / `block` / `mask` / `replace` / `hash` / `tokenize` |
| Token map | `off`, process-local `memory`, or shared `vault_kv2` (Vault / OpenBao); configured via `CENSGATE_VAULT_BACKEND` |
| Auth | `none`, static API keys, or OIDC bearer JWTs |
| Telemetry | OpenTelemetry traces, metrics, and audit log records (`OTEL_*` + `CENSGATE_TRACE_*`) |
| Streaming | Buffered (default, in-place SSE rewrite) or incremental with a hold-back window |

Docker / Compose / Kubernetes assets: `Dockerfile.gateway`, `docker-compose.gateway.yml`, `deploy/`. Full docs: [`docs/gateway/getting-started.md`](docs/gateway/getting-started.md), [`crates/redact-gateway/README.md`](crates/redact-gateway/README.md), and [`docs/gateway/`](docs/gateway/).

## Supported Entity Types

### Pattern-Based (54 types)

| Category | Entity Types |
|----------|--------------|
| **Contact** | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IP_ADDRESS`, `URL`, `DOMAIN_NAME` |
| **Financial** | `CREDIT_CARD`, `IBAN_CODE`, `US_BANK_NUMBER` |
| **US** | `US_SSN`, `US_DRIVER_LICENSE`, `US_PASSPORT`, `US_ZIP_CODE` |
| **UK** | `UK_NHS`, `UK_NINO`, `UK_POSTCODE`, `UK_PHONE_NUMBER`, `UK_MOBILE_NUMBER`, `UK_SORT_CODE`, `UK_DRIVER_LICENSE`, `UK_PASSPORT_NUMBER`, `UK_COMPANY_NUMBER` |
| **Healthcare** | `MEDICAL_LICENSE`, `MEDICAL_RECORD_NUMBER` |
| **Crypto** | `CRYPTO_WALLET`, `BTC_ADDRESS`, `ETH_ADDRESS` |
| **Technical** | `GUID`, `MAC_ADDRESS`, `MD5_HASH`, `SHA1_HASH`, `SHA256_HASH` |
| **Generic** | `PASSPORT_NUMBER`, `AGE`, `ISBN`, `PO_BOX`, `DATE_TIME` |
| **Secrets and credentials** | `PRIVATE_KEY`, `JWT_TOKEN`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK`, `STRIPE_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NPM_TOKEN`, `PYPI_TOKEN`, `SENDGRID_API_KEY`, `TWILIO_API_KEY`, `TELEGRAM_BOT_TOKEN`, `HASHICORP_VAULT_TOKEN`, `DATABASE_CONNECTION_STRING` |

Pattern-based detection includes validation (Luhn for credit cards, mod-11 for NHS, IBAN checksums) to reduce false positives.

Secrets and credentials use anchored, high-precision prefixes (e.g. `AKIA...`
for AWS keys, `ghp_...` for GitHub tokens, `sk-ant-...` for Anthropic keys,
`-----BEGIN ... PRIVATE KEY-----` blocks) rather than generic `key=...` /
`password=...` catch-alls, which need entropy scoring to avoid false
positives — that's future work.

### NER-Based (ML-Powered)

| Entity Type | Description |
|-------------|-------------|
| `PERSON` | Person names (e.g., "John Doe", "Marie Curie") |
| `ORGANIZATION` | Organization names (e.g., "Acme Corp", "Microsoft") |
| `LOCATION` | Location names (e.g., "New York", "London") |
| `DATE_TIME` | Date/time expressions in context |

*Requires ONNX model. See [ML-Powered NER](#ml-powered-ner-1) section.*

## Anonymization Strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| **Replace** | Simple placeholder | `[EMAIL_ADDRESS]` |
| **Mask** | Partial masking | `jo**@****le.com` |
| **Hash** | Irreversible hashing | `[EMAIL_ADDRESS_a1b2c3d4]` |
| **Encrypt** | Reversible encryption | `<TOKEN_uuid>` |

```rust
use redact_core::anonymizers::{AnonymizerConfig, AnonymizationStrategy};

let config = AnonymizerConfig {
    strategy: AnonymizationStrategy::Mask,
    mask_char: '*',
    mask_start_chars: 2,
    mask_end_chars: 4,
    ..Default::default()
};
// "john@example.com" → "jo**@****le.com"
```

## ML-Powered NER

Redact includes full ONNX Runtime integration for transformer-based Named Entity Recognition.

### Setup

**1. Export a HuggingFace model to ONNX:**

```bash
pip install transformers optimum[exporters]
python scripts/export_ner_model.py \
    --model dslim/bert-base-NER \
    --output models/bert-base-ner
```

**2. Use in your code:**

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

### Model Directory Structure

The export script creates a directory with the following files:

```
models/bert-base-ner/
├── model.onnx           # ONNX model file (REQUIRED)
├── tokenizer.json       # HuggingFace tokenizer (REQUIRED)
├── config.json          # Model config with label mappings
├── special_tokens_map.json
└── tokenizer_config.json
```

**Required files for inference:**
- `model.onnx` - The ONNX-exported transformer model
- `tokenizer.json` - HuggingFace fast tokenizer (must be in same directory as model, or specify via `tokenizer_path`)

### Recommended Models

| Model | Size | Use Case |
|-------|------|----------|
| `dslim/bert-base-NER` | ~420MB | Best accuracy/size balance (default) |
| `dbmdz/bert-large-cased-finetuned-conll03-english` | ~1.2GB | Highest accuracy |
| `Davlan/distilbert-base-multilingual-cased-ner-hrl` | ~500MB | Multilingual support |
| `elastic/distilbert-base-cased-finetuned-conll03-english` | ~250MB | Smaller/faster |

All models must be trained on CoNLL-2003 or similar NER datasets with BIO tagging scheme (B-PER, I-PER, B-ORG, I-ORG, B-LOC, I-LOC labels).

### Performance

- **Inference**: ~2-10ms per text (depending on model and text length)
- **Memory**: ~50-200MB (depending on model)
- **Startup**: ~100-500ms model load time
- **Concurrency**: Thread-safe via mutex-wrapped sessions

## Performance

### Benchmark Results (2026-04-18)

Measured using [oha](https://github.com/hatoo/oha) with both services running in Docker containers. See [docs/benchmarks/results-20260418-175909.md](docs/benchmarks/results-20260418-175909.md).

| Metric | Redact (Rust) | Presidio (Python) | Speedup |
|--------|---------------|-------------------|---------|
| p50 Latency | 0.196 ms | 6.25 ms | **32x** |
| p99 Latency | 1.90 ms | 21.68 ms | **11x** |
| Throughput | 19,416 req/s | 170 req/s | **114x** |

Test payload: `Contact john.doe@example.com or call (555) 123-4567. SSN: 123-45-6789.`

### Run Benchmarks

```bash
# REST API comparison vs Presidio (requires Docker; oha on PATH or auto-downloaded)
./scripts/benchmark-comparison.sh

# Criterion micro-benchmarks (Redact internals)
cargo bench --package redact-core
```

See [docs/benchmarks/](/censgate/redact/blob/main/docs/benchmarks) for methodology and detailed results.

## Project Structure

```
redact/
├── crates/
│   ├── redact-core/      # Core detection & anonymization engine
│   ├── redact-ner/       # ONNX NER integration
│   ├── redact-api/       # REST API service (Axum)
│   ├── redact-cli/       # Command-line tool
│   ├── redact-wasm/      # WebAssembly bindings
│   └── redact-gateway/   # OpenAI-compatible privacy gateway (embeds redact-core)
├── patterns/             # PII detection patterns (GDPR, HIPAA, CCPA)
├── deploy/               # Gateway Collector config and Kubernetes manifests
├── scripts/              # Utility scripts (model export)
├── examples/             # Usage examples
├── docs/
│   ├── gateway/          # Gateway operator documentation
│   └── benchmarks/       # Benchmark methodology and results
├── Dockerfile.gateway
└── docker-compose.gateway.yml
```

## Testing

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

See [TEST_COVERAGE.md](/censgate/redact/blob/main/TEST_COVERAGE.md) for detailed coverage report.

## Documentation

- [API Documentation](https://docs.rs/redact-core) — Rust API docs
- [Gateway getting started](/censgate/redact/blob/main/docs/gateway/getting-started.md) — Local redaction, Ollama chat, OpenAI SDK
- [Gateway Documentation](/censgate/redact/blob/main/docs/gateway) — Configuration, policy, tokenization, auth, telemetry, audit, streaming, deployment
- [Test Coverage](/censgate/redact/blob/main/TEST_COVERAGE.md) — Testing details
- [Contributing Guide](/censgate/redact/blob/main/CONTRIBUTING.md) — How to contribute
- [Examples](/censgate/redact/blob/main/examples) — Code examples

## Roadmap

### Pre-1.0.0

#### v0.8.2

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

#### v0.9.0

- [x] 18 secret/credential entity types (54 pattern-based total) — Phase 1 of #101
- [x] `redact-gateway`: policy profiles, reversible tokenization, OIDC and API key auth,
      OpenTelemetry traces/metrics/logs, runtime pattern packs, streaming redaction,
      container and Kubernetes assets (`ghcr.io/censgate/redact-gateway`)
- [x] CLI: `--fail-on-detect` and multi-file `-i` / `--file` analyze
- [x] WebAssembly bindings — real pattern engine (browser + Cloudflare Workers)
- [ ] Streaming API for large texts
- [ ] Enhanced documentation
- [ ] WebAssembly + inline NER — deferred; ONNX model + runtime do not fit
      Cloudflare Workers limits. Use the hybrid architecture in the
      [WebAssembly](#webassembly) section for name-based detection.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](/censgate/redact/blob/main/CONTRIBUTING.md) for guidelines.

```bash
# Fork and clone
git clone https://github.com/censgate/redact.git
cd redact

# Create a feature branch
git checkout -b feature/my-new-feature

# Make changes and test
cargo test --workspace
cargo clippy --all-targets --all-features
cargo fmt --all

# Commit and push
git commit -m "feat: add amazing feature"
git push origin feature/my-new-feature
```

## License

Censgate Redact is licensed under the [Apache License 2.0](LICENSE).

See the [LICENSE](LICENSE) file for the complete license terms.

Copyright (c) 2026 Censgate LLC

## Acknowledgments

- Inspired by [Microsoft Presidio](https://microsoft.github.io/presidio/)
- Built with [ONNX Runtime](https://onnxruntime.ai/)
- Powered by [Rust](https://www.rust-lang.org/)
- ML models from [HuggingFace](https://huggingface.co/)

## Support

- [GitHub Issues](https://github.com/censgate/redact/issues) — Bug reports and feature requests
- [GitHub Discussions](https://github.com/censgate/redact/discussions) — Questions and general discussion
- Email: support@censgate.com

---

**[Star us on GitHub](https://github.com/censgate/redact)** if you find this project useful!
