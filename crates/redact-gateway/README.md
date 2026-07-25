# redact-gateway

OpenAI-compatible privacy gateway that embeds [`redact-core`](../redact-core) in-process.

The gateway sits between your application and a model provider. On the way out it detects sensitive values and applies the action a policy profile specifies for each entity type (`allow`, `block`, `mask`, `replace`, `hash`, or `tokenize`). On the way back it can restore tokenized values so the caller sees a complete answer while the provider only ever saw placeholders.

Further reading:

| Topic | Page |
|-------|------|
| Configuration (YAML, env, reload) | [docs/gateway/configuration.md](../../docs/gateway/configuration.md) |
| Policy profiles and actions | [docs/gateway/policy.md](../../docs/gateway/policy.md) |
| Reversible tokenization | [docs/gateway/tokenization.md](../../docs/gateway/tokenization.md) |
| Authentication | [docs/gateway/authentication.md](../../docs/gateway/authentication.md) |
| OpenTelemetry traces and metrics | [docs/gateway/telemetry.md](../../docs/gateway/telemetry.md) |
| Audit records | [docs/gateway/audit.md](../../docs/gateway/audit.md) |
| Docker, Compose, Kubernetes | [docs/gateway/deployment.md](../../docs/gateway/deployment.md) |
| Streaming modes | [docs/gateway/streaming.md](../../docs/gateway/streaming.md) |

## Quick start

Requires an OpenAI-compatible provider. The default is Ollama at `http://127.0.0.1:11434`.

```bash
# From the repository root
cargo run -p redact-gateway -- --provider-base-url http://127.0.0.1:11434

# Health probe (no authentication)
curl -s http://127.0.0.1:8080/health

# Chat completion — the email is replaced before the provider sees it
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

With the bundled `default` profile, the provider receives `Email me at [EMAIL_ADDRESS]`. The JSON response includes the provider's answer (also scanned) plus response headers such as:

| Header | Meaning |
|--------|---------|
| `x-censgate-redactions-applied` | Request + response rewrite total |
| `x-censgate-request-redactions` | Rewrites on the outbound body |
| `x-censgate-response-redactions` | Rewrites on the inbound body |
| `x-censgate-redaction-types` | Comma-separated entity types rewritten |
| `x-censgate-tokens-issued` | Present when tokenization minted placeholders |
| `x-censgate-tokens-restored` | Present when placeholders were restored |

Validate configuration without serving:

```bash
cargo run -p redact-gateway -- validate-config
# configuration is valid: 5 profiles, default `default`, source `env`
```

Example configs live under [`examples/`](examples/).

## Request and response path

Middleware order on the model surfaces is authenticate, evaluate policy, redact, forward, restore, then emit an audit record. Health and metrics sit outside authentication so orchestrators can probe a gateway that rejects unauthenticated traffic.

**Outbound (application → provider)**

1. Authenticate the caller (`none`, `api_key`, or `oidc`).
2. Select a policy profile (credential claim wins over `x-censgate-profile`).
3. Detect entities with `redact-core` and apply per-entity actions.
4. Persist newly minted sealed token mappings when a token map backend is configured.
5. Forward the rewritten body to the provider.

**Inbound (provider → application)**

1. Scan assistant text (and tool-call arguments when the profile asks for them).
2. Restore reversible tokens when the profile has `restore_responses: true`.
3. Return OpenAI-compatible JSON or SSE with compliance headers.

### What is scanned

Controlled by each profile's `scan` section (all on by default):

| Target | Locations |
|--------|-----------|
| Request messages | `messages[].content` (string or text parts) |
| Request tool calls | `messages[].tool_calls[].function.arguments` |
| Request tools / functions | Descriptions and schema description strings |
| Request user | Top-level `user` |
| Request input | Embeddings `input`, legacy `prompt` / `suffix` |
| Response messages | `choices[].message.content`, `reasoning_content`, `delta.content`, legacy `text` |
| Response tool calls | Tool-call arguments on messages and deltas |
| Custom pointers | Additional RFC 6901 JSON pointers |

Non-text multimodal parts (`image_url`, `input_audio`, …) are forwarded without scanning.

## Policy model

A [`PolicySet`](src/policy/mod.rs) holds named profiles. Each detection is decided independently, so one string can mask a card number, tokenize an email, and block an API key in a single pass.

| Action | Effect |
|--------|--------|
| `allow` | Leave the value untouched |
| `block` | Reject the whole request |
| `mask` | Replace with a mask (for example `*****@*******.***`) |
| `replace` | Replace with an entity label such as `[EMAIL_ADDRESS]` |
| `hash` | Replace with a salted digest `[HASH:…]` |
| `tokenize` | Replace with a reversible placeholder such as `[EMAIL_ADDRESS_1]` |

Bundled profiles: `default`, `reversible`, `strict`, `secrets_only`, `permissive`. Details and a custom-policy walkthrough are in [policy.md](../../docs/gateway/policy.md).

Worked example — select the reversible profile and round-trip an email:

```bash
# Token map + sealing key required for durable tokenize / restore
export CENSGATE_VAULT_BACKEND=memory
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
export CENSGATE_DEFAULT_PROFILE=reversible

cargo run -p redact-gateway -- --provider-base-url http://127.0.0.1:11434

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-censgate-session-id: demo-session' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Contact alice@example.com"}]
  }'
```

The provider sees `[EMAIL_ADDRESS_1]`. When the model echoes that placeholder, the gateway restores `alice@example.com` for the caller. The same session header reuses tokens across turns.

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/health`, `/healthz` | No | Liveness + version, recognizer count, profiles |
| `GET` | `/livez` | No | Process liveness |
| `GET` | `/readyz` | No | Readiness (token map + auth backends) |
| `GET` | `/metrics` | No | Prometheus exposition (when enabled) |
| `POST` | `/v1/chat/completions` | Yes | Chat completions (JSON or SSE) |
| `POST` | `/v1/completions` | Yes | Legacy completions |
| `POST` | `/v1/embeddings` | Yes | Embeddings (input scanned; vectors not) |
| `GET` | `/v1/models` | Yes | Proxied model list |
| `POST` | `/v1/redact` | Yes | Redact text without calling a provider |
| `POST` | `/v1/restore` | Yes | Restore tokens for a session |
| `GET` | `/v1/compliance/status` | Yes | Effective profiles and runtime summary |
| `POST` | `/v1/compliance/check` | Yes | Dry-run policy decision (tokens not persisted) |

## Configuration reference

Configuration reaches the request path as a single [`ResolvedConfig`](src/config/mod.rs). Sources: environment only (`env`), YAML only (`file`), or YAML overlaid by environment (`layered`). When `CENSGATE_CONFIG_SOURCE` is unset, the gateway uses `layered` if `CENSGATE_CONFIG_FILE` is set and `env` otherwise.

Full tables, YAML schema, and reload semantics: [configuration.md](../../docs/gateway/configuration.md).

### Environment variables

Every gateway knob uses the `CENSGATE_` prefix. Legacy unprefixed names remain accepted where noted. Telemetry transport uses standard `OTEL_*` variables (see [telemetry.md](../../docs/gateway/telemetry.md)).

| Variable | Default | Description |
|----------|---------|-------------|
| `CENSGATE_CONFIG_SOURCE` | `env` / `layered` | `env`, `file`, or `layered` |
| `CENSGATE_CONFIG_FILE` | unset | Path to the YAML document |
| `CENSGATE_POLICY_FILE` | unset | Standalone policy YAML |
| `CENSGATE_DEFAULT_PROFILE` | `default` | Default profile name |
| `CENSGATE_HOST` / `HOST` | `0.0.0.0` | Bind address |
| `CENSGATE_PORT` / `PORT` | `8080` | Bind port |
| `CENSGATE_PROVIDER_NAME` | `openai` | Provider identity reported as `gen_ai.provider.name` |
| `CENSGATE_PROVIDER_BASE_URL` | `http://127.0.0.1:11434` | Provider base URL |
| `CENSGATE_PROVIDER_API_KEY` | unset | Provider bearer token |
| `CENSGATE_PROVIDER_FORWARD_CLIENT_AUTHORIZATION` | `false` | Forward the caller's `Authorization` to the provider |
| `CENSGATE_ENABLE_TRACING` / `ENABLE_TRACING` | `true` | HTTP request tracing |
| `CENSGATE_METRICS_ENDPOINT` | `true` | Serve `/metrics` |
| `CENSGATE_PROVIDER_CONNECT_TIMEOUT_SECS` | `10` | Provider connect timeout |
| `CENSGATE_PROVIDER_REQUEST_TIMEOUT_SECS` | `600` | Provider request timeout |
| `CENSGATE_PROVIDER_MAX_BODY_BYTES` | `33554432` | Cap on buffered provider response bodies |
| `CENSGATE_STREAM_MODE` | `buffered` | `buffered` or `incremental` |
| `CENSGATE_STREAM_HOLDBACK_BYTES` | `256` | Hold-back window in incremental mode |
| `CENSGATE_SESSION_HEADER` | `x-censgate-session-id` | Session id header |
| `CENSGATE_PROFILE_HEADER` | `x-censgate-profile` | Profile selection header |
| `CENSGATE_ALLOW_PROFILE_HEADER` | `true` | Honor the profile header |
| `CENSGATE_PATTERN_PACKS` | unset | Pack files/dirs (`:` / `,` / `;` separated) |
| `CENSGATE_DISABLE_BUILTIN_PATTERNS` | `false` | Skip patterns compiled into the engine |
| `CENSGATE_VAULT_BACKEND` | `off` | `off`, `memory`, or `vault_kv2` |
| `CENSGATE_VAULT_ADDR` / `VAULT_ADDR` / `BAO_ADDR` | unset | KV v2 server address |
| `CENSGATE_VAULT_TOKEN` / `VAULT_TOKEN` / `BAO_TOKEN` | unset | KV v2 auth token |
| `CENSGATE_VAULT_MOUNT` | `secret` | KV v2 mount |
| `CENSGATE_VAULT_PATH_PREFIX` | `redact-gateway` | Path prefix under the mount |
| `CENSGATE_VAULT_NAMESPACE` / `VAULT_NAMESPACE` | unset | Enterprise namespace header |
| `CENSGATE_TOKEN_TTL_SECS` | `3600` | Mapping lifetime in seconds |
| `CENSGATE_TOKEN_DEK` | ephemeral | Base64 32-byte sealing key |
| `CENSGATE_AUTH_MODE` | `none` | `none`, `api_key`, or `oidc` |
| `CENSGATE_API_KEYS` | unset | Comma-separated static keys |
| `CENSGATE_OIDC_ENABLED` | unset | Legacy switch; `true` selects OIDC mode |
| `CENSGATE_OIDC_ISSUER` | unset | OIDC issuer URL |
| `CENSGATE_OIDC_AUDIENCE` | unset | Expected audience |
| `CENSGATE_OIDC_JWKS_URL` | unset | Explicit JWKS URL |
| `CENSGATE_OIDC_REQUIRED_SCOPES` | unset | Comma-separated required scopes |
| `CENSGATE_OIDC_TENANT_CLAIM` | unset | Claim for tenant id |
| `CENSGATE_OIDC_PROFILE_CLAIM` | unset | Claim for policy profile |
| `CENSGATE_OIDC_JWKS_REFRESH_SECS` | `300` | JWKS refresh interval |
| `CENSGATE_OIDC_LEEWAY_SECS` | `60` | Clock skew allowance |
| `CENSGATE_AUDIT_EXPORT` | `off` | `off`, `stdout`, `file`, or `otlp` |
| `CENSGATE_AUDIT_FILE` | unset | Path for the `file` sink |
| `CENSGATE_AUDIT_QUEUE_CAPACITY` | `4096` | Bounded audit queue size |
| `CENSGATE_TRACE_OPERATIONS` | `basic` | `off`, `basic`, or `detailed` |
| `CENSGATE_TRACE_FILTER` | unset | Span target filter directive |
| `CENSGATE_GENAI_ATTRIBUTES` | `false` | Emit development-stage `gen_ai.*` attributes |
| `OTEL_SEMCONV_STABILITY_OPT_IN` | unset | Also enables `gen_ai.*` when it contains `gen_ai_latest_experimental` |

### YAML schema (overview)

Documents use `deny_unknown_fields`. Unknown keys fail startup. Sections:

```yaml
server:      # host, port, enable_http_trace, metrics_endpoint
provider:    # name, base_url, api_key, timeouts, max_body_bytes, forward_client_authorization
redaction:   # stream_mode, stream_holdback_bytes, session_header, profile_header, allow_profile_header
packs:       # paths, disable_builtin
vault:       # backend, address, token, mount, path_prefix, namespace, ttl_secs, data_encryption_key
auth:        # mode, api_keys, oidc: { … }
audit:       # export, file_path, queue_capacity, include_entity_types
telemetry:   # operations, filter, genai_attributes
policy:      # inline PolicySet  — mutually exclusive with policy_file
policy_file: # path relative to this document
```

CLI flags (`--config`, `--provider-base-url`, `--profile`, …) are applied through the same environment overlay, so precedence matches library loading. Subcommands: `serve` (default), `validate-config`, `print-config`, `print-policy`. On Unix, `SIGHUP` reloads configuration; a failed reload keeps the last good snapshot.

## Library usage

```rust,no_run
use redact_gateway::{config::ResolvedConfig, GatewayServer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ResolvedConfig::load()?;
    GatewayServer::new(config).await?.run().await
}
```

For unit tests or custom hosts, build a `ResolvedConfig`, wrap it in `ConfigHandle`, and call into `redact_gateway::redact` / `routes` directly. See the crate docs (`cargo doc -p redact-gateway --open`).

## Operational boundaries

These are present-tense boundaries of the OSS runtime. Closing each gap is an operator responsibility.

| Boundary | Operator responsibility |
|----------|-------------------------|
| Audit emission only | The gateway emits audit records (`stdout`, `file`, or OTLP logs). Durable and immutable retention is provided by the sink you point it at — for example an OpenTelemetry Collector writing to object storage with retention locks. See [`deploy/otel-collector.yaml`](../../deploy/otel-collector.yaml). |
| Process-local token map | With the `memory` backend, the token map is process-local: tokens do not survive a restart or reach another replica. Use the `vault_kv2` backend (HashiCorp Vault or OpenBao) for shared state, and set the same `CENSGATE_TOKEN_DEK` on every replica. |
| Ephemeral sealing key | Without `CENSGATE_TOKEN_DEK`, the process generates an ephemeral key; tokens cannot be restored after a restart or by another replica. |
| Auth mode `none` | Inbound authentication is off by default and is only appropriate on a trusted network. Enable `api_key` or `oidc` before exposing the gateway on an untrusted edge. |
| Fail-closed profiles | When `fail_closed` is true, token-map or tokenization failures reject the request instead of forwarding unredacted content. Keep this enabled for production profiles. |
| Buffered streaming default | Buffered mode sees the full provider stream before redacting, so entities cannot hide in a token split. Incremental mode trades that guarantee for lower time-to-first-token within a hold-back window. |

## Design notes

**Why the provider client is hand-rolled.** The gateway talks to providers through a thin `reqwest` wrapper over `serde_json::Value` rather than one of the Rust LLM client crates. A proxy must return the provider's response with only the spans it redacted changed, and typed clients deserialize into fixed structs that silently drop fields they do not model — which would discard provider extensions and anything the wire format gains next. Working on `Value` keeps unknown fields intact, and owning the transport keeps raw byte access for incremental streaming, response size caps, and verbatim provider error bodies. See [`src/proxy.rs`](src/proxy.rs).

**Why "provider".** The inference destination is a *provider*; *inference* is the operation performed against it; *backend* refers only to token map storage. This lines up with the OpenTelemetry GenAI conventions the gateway emits, and [`docs/gateway/telemetry.md`](../../docs/gateway/telemetry.md#vocabulary-gen_ai-provider-inference-backend) sets out the full vocabulary.

## Features

Default Cargo features: `otlp`, `vault`, `oidc`, `prometheus`.

| Feature | Provides |
|---------|----------|
| `otlp` | OTLP exporters for traces, metrics, and logs |
| `vault` | `vault_kv2` token map backend |
| `oidc` | OIDC / JWT resource-server authentication |
| `prometheus` | Pull-based `/metrics` from the OpenTelemetry meter provider |

## License

Licensed under the Apache License, Version 2.0. See the repository root.
