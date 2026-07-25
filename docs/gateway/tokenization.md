# Reversible tokenization

Tokenization replaces a detected value with a stable placeholder such as `[EMAIL_ADDRESS_1]`. The original is sealed with AES-256-GCM before it leaves the process, so a token map backend only ever stores ciphertext.

Related: [policy](policy.md) · [configuration](configuration.md) · [authentication](authentication.md) · [deployment](deployment.md)

## How it works

1. Detection finds a span; policy decides `tokenize`.
2. The session looks up the plaintext: the same value in one session reuses the same token so the model sees a consistent world.
3. Otherwise it mints `[ENTITY_TYPE_N]`, seals the original with the process sealing key (DEK), and records a `TokenMapping`.
4. After the request is rewritten, new mappings are written to the token map (`put`) under `(tenant, session)`.
5. On the response path (when `restore_responses` is true), known tokens are opened with the DEK and substituted back into the body returned to the caller.

Tokens without a mapping are left verbatim during restore so a missing entry does not silently delete model text.

## Sealing key (`CENSGATE_TOKEN_DEK`)

| Setting | Behavior |
|---------|----------|
| `CENSGATE_TOKEN_DEK` / `vault.data_encryption_key` | Base64-encoded 32-byte key shared by every replica that must restore each other's tokens |
| Unset | Process generates an ephemeral key; tokens cannot be restored after a restart or by another replica |

Generate a key:

```bash
openssl rand -base64 32
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
```

The DEK never leaves the process in telemetry or `print-config` (shown as `"<set>"`). Horizontally scaled deployments must inject the **same** key on every replica; otherwise peer-minted tokens cannot be opened.

## Token map backends

| Backend | `CENSGATE_VAULT_BACKEND` | Semantics |
|---------|--------------------------|-----------|
| Off | `off` (default) | No persistence. `/v1/restore` is unavailable. Within a single request, in-memory mappings still allow response restore for that round-trip. |
| Memory | `memory` | Process-local map with TTL. Tokens do not survive a restart or reach another replica. Suitable for development and single-node testing. |
| KV v2 | `vault_kv2` | Speaks the HashiCorp Vault KV v2 HTTP API; works with both **HashiCorp Vault** and **OpenBao**. Auth token is an opaque `X-Vault-Token`. |

Sealed-mapping property: stores hold only `sealed_value` ciphertext plus metadata (`token`, `entity_type`, `created_at`). Opening always requires the gateway DEK.

### Memory

```bash
export CENSGATE_VAULT_BACKEND=memory
export CENSGATE_TOKEN_TTL_SECS=3600
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
export CENSGATE_DEFAULT_PROFILE=reversible
```

### Vault / OpenBao KV v2

```bash
export CENSGATE_VAULT_BACKEND=vault_kv2
export CENSGATE_VAULT_ADDR=http://127.0.0.1:8200   # or BAO_ADDR / VAULT_ADDR
export CENSGATE_VAULT_TOKEN=hvs.…                    # or BAO_TOKEN / VAULT_TOKEN
export CENSGATE_VAULT_MOUNT=secret
export CENSGATE_VAULT_PATH_PREFIX=redact-gateway
export CENSGATE_TOKEN_TTL_SECS=3600
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
```

Paths are `{prefix}/{tenant}/{session}` with tenant and session percent-encoded so `/` and `..` cannot escape the prefix. Writes merge with existing mappings; expired sessions are treated as absent.

Requires the `vault` Cargo feature (enabled by default).

## Session semantics

| Piece | Role |
|-------|------|
| Session header | Default `x-censgate-session-id`. When present, prior mappings are loaded before redaction. When absent, a new UUID is generated and prior tokens are not loaded. |
| Tenant | From auth context (`default` when anonymous). Isolates the token namespace. |
| TTL | `CENSGATE_TOKEN_TTL_SECS` / `vault.ttl_secs` (default 3600). Applied by the backend on write. |

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-censgate-session-id: conversation-42' \
  -H 'x-censgate-profile: reversible' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Write to alice@example.com"}]
  }'
```

Response headers may include `x-censgate-tokens-issued` and `x-censgate-tokens-restored`.

## Restore endpoint

`POST /v1/restore` loads sealed mappings for a session and replaces tokens in arbitrary text.

```bash
curl -s http://127.0.0.1:8080/v1/restore \
  -H 'content-type: application/json' \
  -d '{
    "session_id": "conversation-42",
    "text": "We emailed [EMAIL_ADDRESS_1] already."
  }'
```

```json
{
  "text": "We emailed alice@example.com already.",
  "session_id": "conversation-42",
  "restored": 1,
  "missing": 0
}
```

Requires a non-`off` token map backend. Authentication applies like other `/v1/*` surfaces; the caller's tenant scopes the lookup.

## Fail-closed behavior

When a profile has `fail_closed: true` (the bundled default for traffic-handling profiles):

- Token map read/write failures reject the request instead of continuing without mappings.
- Tokenization without a usable session context returns a dependency error rather than forwarding plaintext.

When the backend is `off`, newly minted mappings stay in the request scope for that round-trip's restore path but are not durable. Prefer `memory` or `vault_kv2` whenever you select a tokenize profile.

See also [`examples/reversible.yaml`](../../crates/redact-gateway/examples/reversible.yaml).
