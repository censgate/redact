# Getting started with the privacy gateway

A short path from a fresh checkout to a working gateway. Each step builds on the last; you can stop after step 1 if you only need local redaction.

Related: [configuration](configuration.md) · [policy](policy.md) · [tokenization](tokenization.md) · [authentication](authentication.md) · [streaming](streaming.md) · [telemetry](telemetry.md) · [audit](audit.md) · [deployment](deployment.md) · [secrets detection](../secrets-detection.md)

## 1. Try it with no provider

Build and run the gateway. It does not need Ollama, Vault, or any other service for `/v1/redact` and `/v1/compliance/check`.

```bash
# From the repository root
export CXX=g++                    # needed on some Linux toolchains
export OTEL_SDK_DISABLED=true     # skip OpenTelemetry exporters for a local try
cargo build -p redact-gateway
./target/debug/redact-gateway --host 127.0.0.1 --port 8080
```

In another shell, replace an email:

```bash
curl -s http://127.0.0.1:8080/v1/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Email me at alice@example.com"}'
```

```json
{
  "text": "Email me at [EMAIL_ADDRESS]",
  "profile": "default",
  "session_id": "1f6b704a-2c2a-494c-8511-4d7f2b40cd73",
  "blocked": false,
  "outcome": {
    "redactions_applied": 1,
    "entity_counts": { "EMAIL_ADDRESS": 1 },
    "action_counts": { "replace": 1 },
    "entity_action_counts": { "EMAIL_ADDRESS": { "replace": 1 } },
    "blocked_entities": [],
    "tokens_issued": 0,
    "allowed": 0
  },
  "content_sha256": "c5c6a42ac1b14d09df035a98d226a849e72a59a92b34b7ac76b5485861fbcdcf"
}
```

`session_id` is generated per request when you omit it. The bundled `default` profile replaces emails and **blocks** AWS access keys. A body that contains both shows the block.

Assemble the sample access key at the shell so docs never embed a contiguous secret-shaped literal (secret-scanning false positive):

```bash
# AWS docs sample shape: prefix + body (AKIA + IOSFODNN7EXAMPLE)
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"
curl -s http://127.0.0.1:8080/v1/redact \
  -H 'content-type: application/json' \
  -d "{\"text\":\"Contact alice@example.com with key ${AWS_KEY}\"}"
```

```json
{
  "text": "Contact alice@example.com with key <aws-access-key-id>",
  "profile": "default",
  "session_id": "9f1315f5-6172-4833-b251-b7742f7e215a",
  "blocked": true,
  "outcome": {
    "redactions_applied": 1,
    "entity_counts": { "EMAIL_ADDRESS": 1 },
    "action_counts": { "block": 1, "replace": 1 },
    "entity_action_counts": { "EMAIL_ADDRESS": { "replace": 1 } },
    "blocked_entities": ["AWS_ACCESS_KEY"],
    "tokens_issued": 0,
    "allowed": 0
  },
  "content_sha256": "0a693dcd98f77f838566beb6455336d974ed4e6babf5ca199445c620c1754434"
}
```

When the pass is blocked, the response keeps the original `text` and sets `blocked: true` with the offending entity in `blocked_entities`. Use `/v1/compliance/check` for a dry-run that never persists tokens:

```bash
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"
curl -s http://127.0.0.1:8080/v1/compliance/check \
  -H 'content-type: application/json' \
  -d "{\"text\":\"Contact alice@example.com with key ${AWS_KEY}\"}"
```

```json
{
  "action_counts": { "block": 1, "replace": 1 },
  "allowed": false,
  "blocked_entities": ["AWS_ACCESS_KEY"],
  "entity_counts": { "EMAIL_ADDRESS": 1 },
  "profile": "default",
  "would_tokenize": false
}
```

Health probes work without authentication: `GET /livez`, `GET /readyz`, `GET /health`.

## 2. Chat proxy with Ollama

Point the gateway at a local OpenAI-compatible provider. The examples use [Ollama](https://ollama.com/) and the `llama3.2` model.

1. Install Ollama from the project site for your OS, then start it (the install usually starts a service on port `11434`).
2. Pull the model and wait until the pull finishes:

```bash
ollama pull llama3.2
```

3. Confirm Ollama is up:

```bash
curl -s http://127.0.0.1:11434/api/tags
# JSON listing local models; llama3.2 should appear after the pull
```

4. Restart the gateway against Ollama (default base URL is already `http://127.0.0.1:11434`):

```bash
export OTEL_SDK_DISABLED=true
./target/debug/redact-gateway --host 127.0.0.1 --port 8080 \
  --provider-base-url http://127.0.0.1:11434
```

5. Send a chat completion:

```bash
curl -sD - http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

What to look for:

- The provider receives the email as `[EMAIL_ADDRESS]` (bundled `default` profile).
- Response headers such as `x-censgate-redactions-applied`, `x-censgate-request-redactions`, `x-censgate-response-redactions`, and `x-censgate-redaction-types`.
- An OpenAI-compatible JSON body with the model's answer (also scanned on the way back).

If Ollama has no model yet, the chat request fails until you finish `ollama pull`. The same applies to the Compose stack — see [deployment](deployment.md#docker-compose).

## 3. Point an OpenAI SDK at it

Any OpenAI-compatible client can use the gateway by setting the base URL to `http://127.0.0.1:8080/v1`.

### Python

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    # With auth.mode = none (default), the gateway ignores this value for
    # inbound auth. With forward_client_authorization = true it is also what
    # the gateway forwards to the provider. Prefer CENSGATE_PROVIDER_API_KEY
    # on the gateway when the provider needs a real key.
    api_key="unused-when-auth-is-none",
)

completion = client.chat.completions.create(
    model="llama3.2",
    messages=[{"role": "user", "content": "Email me at alice@example.com"}],
)
print(completion.choices[0].message.content)
```

### TypeScript

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "unused-when-auth-is-none",
});

const completion = await client.chat.completions.create({
  model: "llama3.2",
  messages: [{ role: "user", content: "Email me at alice@example.com" }],
});
console.log(completion.choices[0]?.message?.content);
```

When you enable inbound authentication (`CENSGATE_AUTH_MODE=api_key` or `oidc`), put the gateway credential in the SDK's `api_key` / `apiKey` field (sent as `Authorization: Bearer …`). Configure the provider's own key with `CENSGATE_PROVIDER_API_KEY` — `provider.forward_client_authorization` cannot be combined with inbound auth, because that header already carries the gateway credential.

## 4. Where to go next

| Page | Contents |
|------|----------|
| [configuration.md](configuration.md) | YAML schema, `CENSGATE_*` env vars, validation, SIGHUP reload |
| [policy.md](policy.md) | Profiles, actions, scan targets, bundled policies |
| [tokenization.md](tokenization.md) | Token map backends, sealing key, sessions, `/v1/restore` |
| [authentication.md](authentication.md) | `none` / `api_key` / `oidc`, claim mapping |
| [streaming.md](streaming.md) | Buffered vs incremental SSE redaction |
| [telemetry.md](telemetry.md) | OpenTelemetry traces, metrics, GenAI attributes |
| [audit.md](audit.md) | Audit record shape and sinks |
| [deployment.md](deployment.md) | Docker, Compose, Kubernetes, hardening |

Crate overview and library usage: [`crates/redact-gateway/README.md`](../../crates/redact-gateway/README.md).
