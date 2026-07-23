# Censgate Gateway

OpenAI-compatible AI privacy gateway that embeds [`redact-core`](../redact-core) in-process.

Redacts PII/PHI in chat prompts **before** forwarding to an upstream OpenAI-compatible backend (OpenAI, Azure OpenAI, Ollama, etc.).

> **Status:** Early open-core foundation. Bidirectional restore, token vault, OIDC, and immutable audit are planned follow-ups. Streaming is not implemented yet.

## Quick start

```bash
# From repo root
cargo run -p gateway -- --backend-url http://127.0.0.1:11434

curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

Response headers:

- `x-censgate-redactions-applied`
- `x-censgate-redaction-types`

## Configuration

| Variable / flag | Default | Meaning |
|-----------------|---------|---------|
| `HOST` / `--host` | `0.0.0.0` | Bind address |
| `PORT` / `--port` | `8080` | Bind port |
| `BACKEND_URL` / `--backend-url` | `http://127.0.0.1:11434` | Upstream base URL |
| `BACKEND_API_KEY` / `OPENAI_API_KEY` | unset | Bearer token for upstream |
| `REDACTION_STRATEGY` | `replace` | `replace`, `mask`, or `hash` |
| `ENABLE_TRACING` | `true` | HTTP tracing |

## Library

```rust
use gateway::redact::redact_chat_request;
use gateway::openai::ChatCompletionRequest;
use redact_core::{AnalyzerEngine, AnonymizerConfig};

let engine = AnalyzerEngine::new();
let mut req = /* ChatCompletionRequest */;
let outcome = redact_chat_request(&engine, &mut req, &AnonymizerConfig::default())?;
```

## Open core

This crate is the OSS data-plane runtime for Censgate. Control-plane features (hosted multi-region, vault ops, admin UI, billing) live in `censgate/platform`.
