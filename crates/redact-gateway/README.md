# redact-gateway

OpenAI-compatible AI privacy gateway crate (`redact-gateway`) that embeds [`redact-core`](../redact-core) in-process.

Redacts PII/PHI in **prompts and model outputs** before they leave the gateway boundary.

> **Status:** Open-core foundation. Token vault / reversible restore, OIDC, and immutable audit are planned follow-ups.

## Quick start

```bash
# From repo root
cargo run -p redact-gateway -- --backend-url http://127.0.0.1:11434

curl -s http://127.0.0.1:8080/health

# Non-streaming
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'

# Streaming (SSE)
curl -sN http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "stream": true,
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

## Behavior

| Direction | Behavior |
|-----------|----------|
| **Request** | Anonymize `messages[].content` with `redact-core`, then forward |
| **Response (JSON)** | Anonymize `choices[].message.content` before returning |
| **Response (stream)** | Consume upstream SSE, concatenate `delta.content`, redact the full text, re-emit OpenAI-compatible SSE |

Streaming buffers the upstream event stream on purpose so entities split across token deltas are not missed. Clients still receive `text/event-stream` with `data: [DONE]`.

Response headers:

- `x-censgate-redactions-applied` — request + response total
- `x-censgate-request-redactions`
- `x-censgate-response-redactions`
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
use redact_gateway::redact::{redact_chat_request, redact_chat_response_json};
use redact_gateway::openai::ChatCompletionRequest;
use redact_core::{AnalyzerEngine, AnonymizerConfig};

let engine = AnalyzerEngine::new();
let config = AnonymizerConfig::default();
let mut req = /* ChatCompletionRequest */;
redact_chat_request(&engine, &mut req, &config)?;
let mut resp = /* serde_json::Value chat.completion */;
redact_chat_response_json(&engine, &mut resp, &config)?;
```

## Open core

This crate is the OSS data-plane runtime for Censgate. Control-plane features (hosted multi-region, vault ops, admin UI, billing) live in `censgate/platform`.
