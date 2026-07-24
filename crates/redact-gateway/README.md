# redact-gateway

OpenAI-compatible AI privacy gateway crate (`redact-gateway`) that embeds [`redact-core`](../redact-core) in-process.

Redacts PII/PHI in **prompts and model outputs** before they leave the gateway boundary.

> **Status:** Open-core foundation. Token vault / reversible restore, OIDC, and immutable audit are planned follow-ups. This crate sets `publish = false` until it is ready to ship on crates.io.

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
| **Request** | Anonymize `messages[].content` (string or text content-parts) and top-level `user`, then forward |
| **Response (JSON)** | Anonymize `choices[].message.content` before returning |
| **Response (stream)** | Consume upstream SSE, concatenate `delta.content`, redact the full text, re-emit OpenAI-compatible SSE |

Streaming buffers the upstream event stream on purpose so entities split across token deltas are not missed. Clients still receive `text/event-stream` with `data: [DONE]`. Upstream `finish_reason` and `created` are preserved on the re-emitted chunks.

Response headers:

- `x-censgate-redactions-applied` — request + response total
- `x-censgate-request-redactions`
- `x-censgate-response-redactions`
- `x-censgate-redaction-types`

### What is redacted

- `messages[].content` when it is a string
- `messages[].content[]` parts with `"type": "text"`
- Top-level OpenAI `user` field (when present as a string)
- Assistant `choices[].message.content` in non-streaming responses
- Concatenated streamed `choices[0].delta.content`

### What is NOT redacted

These are forwarded (or dropped on stream rebuild) without redaction today:

- `tool_calls[].function.arguments` and other tool payload fields (preserved on request round-trip; not scanned)
- `tools[].function.description` / schema text
- Non-text multimodal parts (`image_url`, `input_audio`, …)
- Streamed `tool_calls` deltas (not re-emitted)
- Stream `usage` chunks (`stream_options.include_usage`)
- Choices beyond index `0` when `n > 1`

## Known streaming limitations

- Upstream SSE is fully buffered (size-capped) before redaction and re-emit
- Only `choices[0]` content is extracted and returned
- Streamed tool-call responses come back without tool-call deltas
- Token `usage` on the stream is not preserved

## Configuration

Config for the binary is owned by clap (flags and env). Invalid `REDACTION_STRATEGY` fails startup.

| Variable / flag | Default | Meaning |
|-----------------|---------|---------|
| `HOST` / `--host` | `0.0.0.0` | Bind address |
| `PORT` / `--port` | `8080` | Bind port |
| `BACKEND_URL` / `--backend-url` | `http://127.0.0.1:11434` | Upstream base URL |
| `BACKEND_API_KEY` / `--backend-api-key` / `OPENAI_API_KEY` | unset | Bearer token for upstream |
| `REDACTION_STRATEGY` / `--redaction-strategy` | `replace` | `replace`, `mask`, or `hash` |
| `ENABLE_TRACING` / `--enable-tracing` | `true` | HTTP tracing |
| `CONNECT_TIMEOUT_SECS` / `--connect-timeout-secs` | `10` | Upstream connect timeout |
| `REQUEST_TIMEOUT_SECS` / `--request-timeout-secs` | `600` | Upstream request timeout |
| `MAX_UPSTREAM_BODY_BYTES` / `--max-upstream-body-bytes` | `33554432` | Cap on buffered upstream bodies |

Library callers can use `GatewayConfig::try_from_env()`.

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
