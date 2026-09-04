# Reversible tokenization

Tokenization replaces a detected value with a stable placeholder such as `[EMAIL_ADDRESS_1]`. The original is sealed with AES-256-GCM before it leaves the process, so a token map backend only ever stores ciphertext.

Related: [getting started](getting-started.md) · [policy](policy.md) · [configuration](configuration.md) · [authentication](authentication.md) · [deployment](deployment.md)

## Token map (not “Vault” by default)

The subsystem that stores sealed mappings is the **token map**. You configure it with `CENSGATE_VAULT_BACKEND` / the YAML `vault:` section — the `vault` name is historical and refers to the **KV v2 backend option**, not to every backend.

| Backend | `CENSGATE_VAULT_BACKEND` | What it is |
|---------|--------------------------|------------|
| Off | `off` (default) | No durable map. Not HashiCorp Vault. |
| Memory | `memory` | Process-local map with TTL. Not HashiCorp Vault. |
| KV v2 | `vault_kv2` | Speaks the HashiCorp Vault KV v2 HTTP API (HashiCorp Vault or OpenBao). |

Setting `CENSGATE_VAULT_BACKEND=memory` selects the in-process token map. It does not contact Vault.

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

Startup refuses a key that is not valid base64, that does not decode to 32 bytes, or that is all zero bytes (a common placeholder). The DEK never leaves the process in telemetry or `print-config` (shown as `"<set>"`). Horizontally scaled deployments must inject the **same** key on every replica; otherwise peer-minted tokens cannot be opened.

## Token map backends

| Backend | `CENSGATE_VAULT_BACKEND` | Semantics |
|---------|--------------------------|-----------|
| Off | `off` (default) | No persistence. Tokens are minted and restored **within the request that created them**; they cannot be resumed by a later request, recovered through `/v1/restore`, or shared with another replica. |
| Memory | `memory` | Process-local map with TTL. Tokens do not survive a restart or reach another replica. Suitable for development and single-node testing. |
| KV v2 | `vault_kv2` | Speaks the HashiCorp Vault KV v2 HTTP API; works with both **HashiCorp Vault** and **OpenBao**. Production authenticates with **Kubernetes auth** against `openbao-tokens`. A static token is local-dev only. |

Sealed-mapping property: stores hold only `sealed_value` ciphertext plus metadata (`token`, `entity_type`, `created_at`). Opening always requires the gateway DEK.

When any profile uses `tokenize` with backend `off`, startup succeeds and logs a warning describing the in-request-only boundary above. Prefer `memory` or `vault_kv2` whenever sessions must span requests.

### Memory

```bash
export CENSGATE_VAULT_BACKEND=memory
export CENSGATE_TOKEN_TTL_SECS=3600
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
export CENSGATE_DEFAULT_PROFILE=reversible
```

### Vault / OpenBao KV v2

Local-dev (static token, compose OpenBao `-dev`):

```bash
export CENSGATE_VAULT_BACKEND=vault_kv2
export CENSGATE_VAULT_ADDR=http://127.0.0.1:8200   # or BAO_ADDR / VAULT_ADDR
export CENSGATE_VAULT_AUTH=token
export CENSGATE_VAULT_TOKEN=hvs.…                    # or BAO_TOKEN / VAULT_TOKEN
export CENSGATE_VAULT_MOUNT=secret
export CENSGATE_VAULT_PATH_PREFIX=redact-gateway
export CENSGATE_TOKEN_TTL_SECS=3600
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"
```

AKS / beta (Kubernetes auth against **openbao-tokens**, DEK from secrets OpenBao):

```bash
export CENSGATE_VAULT_BACKEND=vault_kv2
export CENSGATE_VAULT_ADDR=http://openbao-tokens.openbao-tokens.svc.cluster.local:8200
export CENSGATE_VAULT_AUTH=kubernetes
export CENSGATE_VAULT_K8S_ROLE=redact-gateway   # never external-secrets
export CENSGATE_VAULT_MOUNT=tokens
export CENSGATE_TOKEN_DEK   # projected by ESO from the secrets cluster
```

Paths are `{prefix}/{tenant}/{session}` with tenant and session percent-encoded so `/` and `..` cannot escape the prefix. Writes merge with existing mappings using KV v2 check-and-set (`options.cas`) with up to eight jittered read-merge-write retries. An empty incoming mapping set skips the write. Under sustained contention on a single session a write can still exhaust those retries and fail the request. Expired sessions are treated as absent. `/readyz` caches OpenBao health for two seconds.

OSS gateway `vault_kv2` on `openbao-tokens` is the supported multi-replica path. Platform may still seal display names locally with its own DEK; that is a different contract.

Requires the `vault` Cargo feature (enabled by default).

## Session semantics

| Piece | Role |
|-------|------|
| Session header | Default `x-censgate-session-id`. When present, prior mappings are loaded before redaction. When absent, a new UUID is generated and prior tokens are not loaded. |
| Subject binding | With inbound auth (`api_key` or `oidc`), the storage key is `SHA-256(subject ‖ 0x00 ‖ session_id)`. One subject cannot read another's mappings even within the same tenant. The caller-facing session id in headers and responses is unchanged. |
| Tenant | From auth context (`default` when anonymous). Isolates the token namespace. |
| TTL | `CENSGATE_TOKEN_TTL_SECS` / `vault.ttl_secs` (default 3600). Applied by the backend on write. |

With `auth.mode = none` there is no subject, so cross-request session resumption on the chat surface keys off the caller-supplied `x-censgate-session-id` alone. Anyone who can reach the port and reuse that header can resume another caller's session — appropriate only on a trusted network. In-request tokenize-then-restore (same HTTP request) does not depend on that header and is unaffected.

```bash
# Profile selection by header requires CENSGATE_ALLOW_PROFILE_HEADER=true
# (default is false). Prefer CENSGATE_DEFAULT_PROFILE=reversible, or an OIDC
# profile claim, unless you intentionally enable the header.
export CENSGATE_DEFAULT_PROFILE=reversible
export CENSGATE_VAULT_BACKEND=memory
export CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-censgate-session-id: conversation-42' \
  -d '{
    "model": "llama3.2",
    "messages": [{"role":"user","content":"Write to alice@example.com"}]
  }'
```

Response headers may include `x-censgate-tokens-issued` and `x-censgate-tokens-restored`.

## Restore endpoint

`POST /v1/restore` loads sealed mappings for a session and replaces tokens in arbitrary text. It requires an authenticated subject: with `auth.mode = none` the endpoint returns **403**. Missing and foreign-subject sessions both yield an empty mapping list so callers cannot probe whether a session id exists for another subject.

```bash
export CENSGATE_AUTH_MODE=api_key
export CENSGATE_API_KEYS=dev-key
# plus a non-off token map backend and CENSGATE_TOKEN_DEK

curl -s http://127.0.0.1:8080/v1/restore \
  -H 'authorization: Bearer dev-key' \
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

Requires a non-`off` token map backend. The caller's tenant and subject-bound session key scope the lookup.

## Fail-closed behavior

When a profile has `fail_closed: true` (the bundled default for traffic-handling profiles):

- Token map read/write failures reject the request instead of continuing without mappings.
- Tokenization without a usable session context returns a dependency error rather than forwarding plaintext.

See also [`examples/reversible.yaml`](../../crates/redact-gateway/examples/reversible.yaml).
