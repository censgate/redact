# Gateway configuration

Configuration reaches the request path as a single [`ResolvedConfig`](../../crates/redact-gateway/src/config/mod.rs). File documents and environment variables are mapped into it by adapters; handlers read an immutable snapshot through `ConfigHandle`, which can be swapped atomically on reload.

Related: [policy](policy.md) · [tokenization](tokenization.md) · [authentication](authentication.md) · [telemetry](telemetry.md) · [audit](audit.md) · [deployment](deployment.md) · [streaming](streaming.md)

## Sources and precedence

| Source | Behavior |
|--------|----------|
| `env` | Environment variables and CLI flags only |
| `file` | YAML file only |
| `layered` | YAML file, then environment overlay |

Selection:

1. If `CENSGATE_CONFIG_SOURCE` is set, use that value (`env`, `file` / `local` / `yaml`, or `layered`).
2. Otherwise, if `CENSGATE_CONFIG_FILE` is set, use `layered`.
3. Otherwise use `env`.

CLI flags (`--config`, `--host`, `--provider-base-url`, `--profile`, `--policy`, `--pattern-pack`, …) are written into the corresponding environment variables before load, so precedence is identical whether you launch via flags or env.

In `layered` mode, every non-empty environment value replaces the file value for that field. Secrets such as API keys are never printed by `print-config` (they appear as `"<set>"` or a count).

## Subcommands

```bash
# Load and validate without serving
cargo run -p redact-gateway -- validate-config
# configuration is valid: 5 profiles, default `default`, source `env`

# Resolved settings with secrets redacted (JSON)
cargo run -p redact-gateway -- print-config

# Effective policy as YAML
cargo run -p redact-gateway -- print-policy

# Serve (default when no subcommand is given)
cargo run -p redact-gateway -- serve
cargo run -p redact-gateway -- --config crates/redact-gateway/examples/minimal.yaml
```

With a config file:

```bash
cargo run -p redact-gateway -- \
  --config crates/redact-gateway/examples/reversible.yaml \
  validate-config
# configuration is valid: 1 profiles, default `reversible`, source `layered`
```

## Reload on SIGHUP

On Unix, the binary listens for `SIGHUP` and reloads configuration from the same source. A failed reload keeps the last known good snapshot so a typo in a policy file does not take a running gateway offline. Handlers call `ConfigHandle::load` once per request and work from that snapshot, so a reload never changes behavior mid-request.

Reload does not rebuild the process sealing key or reconnect every dependency from scratch for in-flight work; treat key rotation and backend address changes as a rolling restart when you need a hard cutover.

## YAML schema

Documents use `deny_unknown_fields`. Unknown keys fail parse at startup. Relative `policy_file` and pack paths resolve against the document's directory.

```yaml
server:
  host: 0.0.0.0
  port: 8080
  enable_http_trace: true
  metrics_endpoint: true

provider:
  name: openai                     # gen_ai.provider.name value
  base_url: http://127.0.0.1:11434
  api_key: null                    # prefer CENSGATE_PROVIDER_API_KEY
  connect_timeout_secs: 10
  request_timeout_secs: 600
  max_body_bytes: 33554432
  forward_client_authorization: false

redaction:
  stream_mode: buffered            # buffered | incremental
  stream_holdback_bytes: 256
  session_header: x-censgate-session-id
  profile_header: x-censgate-profile
  allow_profile_header: true

packs:
  paths: []                        # files or directories
  disable_builtin: false

vault:
  backend: "off"                   # off | memory | vault_kv2  (quote "off")
  address: null
  token: null
  mount: secret
  path_prefix: redact-gateway
  namespace: null
  ttl_secs: 3600
  data_encryption_key: null        # base64 32-byte key

auth:
  mode: none                       # none | api_key | oidc
  api_keys: []
  oidc:
    issuer: null
    audience: null
    jwks_url: null
    required_scopes: []
    tenant_claim: null
    profile_claim: null
    jwks_refresh_secs: 300
    leeway_secs: 60

audit:
  export: "off"                    # off | stdout | file | otlp
  file_path: null
  queue_capacity: 4096
  include_entity_types: true

telemetry:
  operations: basic                # off | basic | detailed
  filter: null
  genai_attributes: false

# Choose one of:
policy:                            # inline PolicySet
  default_profile: default
  profiles: { … }

policy_file: ./policy.yaml         # mutually exclusive with policy
```

Quote `backend: "off"` and `export: "off"` so YAML does not parse them as booleans.

Example documents:

- [`crates/redact-gateway/examples/minimal.yaml`](../../crates/redact-gateway/examples/minimal.yaml)
- [`crates/redact-gateway/examples/reversible.yaml`](../../crates/redact-gateway/examples/reversible.yaml)
- [`crates/redact-gateway/examples/oidc.yaml`](../../crates/redact-gateway/examples/oidc.yaml)
- [`crates/redact-gateway/examples/observability.yaml`](../../crates/redact-gateway/examples/observability.yaml)
- [`crates/redact-gateway/examples/policy-healthcare.yaml`](../../crates/redact-gateway/examples/policy-healthcare.yaml)

## Naming

The inference destination is called the **provider** throughout: configuration, documentation, telemetry and audit records all use that one word. It matches how comparable AI gateways name the concept, and it matches the OpenTelemetry GenAI conventions this gateway emits, where the attribute is `gen_ai.provider.name`.

Three neighbouring words mean different things. **Inference** is the operation performed against a provider, reported as `gen_ai.operation.name`, not a name for the destination. **Backend** means the token map storage backend (`vault.backend`) and nothing else. **Upstream** appears only as directional English in prose, never as the name of a setting. [Gateway telemetry](telemetry.md#vocabulary-gen_ai-provider-inference-backend) sets this out in full alongside the conventions it follows.

Settings that used to say `backend` or `upstream` were renamed accordingly. Every earlier spelling still works as an alias, so existing deployments and configuration files keep loading unchanged:

| Preferred | Still accepted |
|-----------|----------------|
| `CENSGATE_PROVIDER_BASE_URL` | `CENSGATE_BACKEND_URL`, `BACKEND_URL` |
| `CENSGATE_PROVIDER_API_KEY` | `CENSGATE_BACKEND_API_KEY`, `BACKEND_API_KEY`, `OPENAI_API_KEY` |
| `CENSGATE_PROVIDER_CONNECT_TIMEOUT_SECS` | `CENSGATE_CONNECT_TIMEOUT_SECS`, `CONNECT_TIMEOUT_SECS` |
| `CENSGATE_PROVIDER_REQUEST_TIMEOUT_SECS` | `CENSGATE_REQUEST_TIMEOUT_SECS`, `REQUEST_TIMEOUT_SECS` |
| `CENSGATE_PROVIDER_MAX_BODY_BYTES` | `CENSGATE_MAX_UPSTREAM_BODY_BYTES`, `MAX_UPSTREAM_BODY_BYTES` |
| `CENSGATE_PROVIDER_FORWARD_CLIENT_AUTHORIZATION` | `CENSGATE_FORWARD_CLIENT_AUTHORIZATION` |
| YAML `provider:` | YAML `upstream:` |
| `--provider-base-url` | `--backend-url` |
| `--provider-api-key` | `--backend-api-key` |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CENSGATE_CONFIG_SOURCE` | `env` or `layered` | Source kind |
| `CENSGATE_CONFIG_FILE` | unset | YAML path |
| `CENSGATE_POLICY_FILE` | unset | Standalone policy YAML |
| `CENSGATE_DEFAULT_PROFILE` | `default` | Default profile name |
| `CENSGATE_HOST` / `HOST` | `0.0.0.0` | Bind address |
| `CENSGATE_PORT` / `PORT` | `8080` | Bind port |
| `CENSGATE_PROVIDER_NAME` | `openai` | Provider identity reported as `gen_ai.provider.name` |
| `CENSGATE_PROVIDER_BASE_URL` | `http://127.0.0.1:11434` | Provider base URL (aliases: `CENSGATE_BACKEND_URL`, `BACKEND_URL`) |
| `CENSGATE_PROVIDER_API_KEY` | unset | Provider bearer token (aliases: `CENSGATE_BACKEND_API_KEY`, `BACKEND_API_KEY`, `OPENAI_API_KEY`) |
| `CENSGATE_PROVIDER_FORWARD_CLIENT_AUTHORIZATION` | `false` | Forward the caller's `Authorization` to the provider (alias: `CENSGATE_FORWARD_CLIENT_AUTHORIZATION`) |
| `CENSGATE_ENABLE_TRACING` / `ENABLE_TRACING` | `true` | HTTP tracing |
| `CENSGATE_METRICS_ENDPOINT` | `true` | Serve `/metrics` |
| `CENSGATE_PROVIDER_CONNECT_TIMEOUT_SECS` | `10` | Provider connect timeout (aliases: `CENSGATE_CONNECT_TIMEOUT_SECS`, `CONNECT_TIMEOUT_SECS`) |
| `CENSGATE_PROVIDER_REQUEST_TIMEOUT_SECS` | `600` | Provider request timeout (aliases: `CENSGATE_REQUEST_TIMEOUT_SECS`, `REQUEST_TIMEOUT_SECS`) |
| `CENSGATE_PROVIDER_MAX_BODY_BYTES` | `33554432` | Buffered body cap (aliases: `CENSGATE_MAX_UPSTREAM_BODY_BYTES`, `MAX_UPSTREAM_BODY_BYTES`) |
| `CENSGATE_STREAM_MODE` | `buffered` | Streaming mode |
| `CENSGATE_STREAM_HOLDBACK_BYTES` | `256` | Incremental hold-back |
| `CENSGATE_SESSION_HEADER` | `x-censgate-session-id` | Session header name |
| `CENSGATE_PROFILE_HEADER` | `x-censgate-profile` | Profile header name |
| `CENSGATE_ALLOW_PROFILE_HEADER` | `true` | Honor profile header |
| `CENSGATE_PATTERN_PACKS` | unset | Pack paths (`:` / `,` / `;`) |
| `CENSGATE_DISABLE_BUILTIN_PATTERNS` | `false` | Skip built-in patterns |
| `CENSGATE_VAULT_BACKEND` | `off` | Token map backend |
| `CENSGATE_VAULT_ADDR` / `VAULT_ADDR` / `BAO_ADDR` | unset | KV v2 address |
| `CENSGATE_VAULT_TOKEN` / `VAULT_TOKEN` / `BAO_TOKEN` | unset | KV v2 token |
| `CENSGATE_VAULT_MOUNT` | `secret` | KV v2 mount |
| `CENSGATE_VAULT_PATH_PREFIX` | `redact-gateway` | Path prefix |
| `CENSGATE_VAULT_NAMESPACE` / `VAULT_NAMESPACE` | unset | Namespace header |
| `CENSGATE_TOKEN_TTL_SECS` | `3600` | Mapping TTL |
| `CENSGATE_TOKEN_DEK` | ephemeral | Base64 32-byte sealing key |
| `CENSGATE_AUTH_MODE` | `none` | Auth mode |
| `CENSGATE_API_KEYS` | unset | Static API keys |
| `CENSGATE_OIDC_ENABLED` | unset | Legacy: `true` → OIDC mode |
| `CENSGATE_OIDC_ISSUER` | unset | Issuer URL |
| `CENSGATE_OIDC_AUDIENCE` | unset | Expected audience |
| `CENSGATE_OIDC_JWKS_URL` | unset | Explicit JWKS |
| `CENSGATE_OIDC_REQUIRED_SCOPES` | unset | Required scopes |
| `CENSGATE_OIDC_TENANT_CLAIM` | unset | Tenant claim |
| `CENSGATE_OIDC_PROFILE_CLAIM` | unset | Profile claim |
| `CENSGATE_OIDC_JWKS_REFRESH_SECS` | `300` | JWKS refresh |
| `CENSGATE_OIDC_LEEWAY_SECS` | `60` | Clock skew |
| `CENSGATE_AUDIT_EXPORT` | `off` | Audit sink |
| `CENSGATE_AUDIT_FILE` | unset | File sink path |
| `CENSGATE_AUDIT_QUEUE_CAPACITY` | `4096` | Audit queue capacity |
| `CENSGATE_TRACE_OPERATIONS` | `basic` | Operation span detail |
| `CENSGATE_TRACE_FILTER` | unset | Span filter directive |
| `CENSGATE_GENAI_ATTRIBUTES` | `false` | Opt-in `gen_ai.*` |
| `OTEL_SEMCONV_STABILITY_OPT_IN` | unset | Enables `gen_ai.*` when it contains `gen_ai_latest_experimental` |
| `REDACTION_STRATEGY` | unset | Legacy default-profile action (`replace` / `mask` / `hash`) |

Boolean env values accept `1` / `true` / `yes` / `on` / `enabled` and `0` / `false` / `no` / `off` / `disabled`.

Telemetry **transport** (exporters, endpoints, protocol, sampling, resource attributes) is configured only with standard `OTEL_*` variables — see [telemetry.md](telemetry.md).

## Validation rules

`ResolvedConfig::validate` rejects combinations that would silently weaken protection:

- Upstream URL must be non-empty and start with `http://` or `https://`
- `auth.mode = api_key` requires at least one key
- `auth.mode = oidc` requires an issuer
- `vault.backend = vault_kv2` requires an address
- `audit.export = file` requires a path
- `stream_holdback_bytes` must be greater than zero

When any profile uses `tokenize` and the token map backend is `off`, validation succeeds with a warning: fail-closed profiles reject those requests at runtime if tokenization cannot complete.

## Pattern packs

`CENSGATE_PATTERN_PACKS` / `packs.paths` load additional YAML pattern packs at startup (same schema as `/patterns/**/*.yaml`). A single bad third-party regex is skipped and reported rather than taking the process down. Set `disable_builtin: true` only when your packs fully replace the compiled engine patterns.
