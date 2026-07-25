# Gateway authentication

Inbound authentication identifies the caller and can select tenant and policy profile. When mode is `api_key` or `oidc`, requests without valid credentials are rejected (fail closed).

Related: [getting started](getting-started.md) · [configuration](configuration.md) · [policy](policy.md) · [tokenization](tokenization.md) · [deployment](deployment.md)

## Modes

| Mode | `CENSGATE_AUTH_MODE` | Behavior |
|------|----------------------|----------|
| None | `none` (default) | Accept every request as anonymous tenant `default`. Only appropriate on a trusted network. |
| API key | `api_key` | Static bearer keys (or `x-api-key`) compared in constant time after SHA-256 hashing. |
| OIDC | `oidc` | OAuth 2.0 / OIDC resource server validating bearer JWTs against JWKS. |

Legacy: `CENSGATE_OIDC_ENABLED=true` selects OIDC mode when `CENSGATE_AUTH_MODE` is unset.

Requires the `oidc` Cargo feature for OIDC (enabled by default).

## Endpoints that bypass authentication

Health and metrics sit outside the auth middleware so orchestrators can probe a gateway that rejects unauthenticated traffic:

| Path | Auth |
|------|------|
| `/health`, `/healthz`, `/livez`, `/readyz` | Skipped |
| `/metrics` | Skipped |
| `/v1/*` | Required when mode ≠ `none` |

`/readyz` reports whether the auth backend is ready (for OIDC: JWKS fetched successfully).

## API key mode

```bash
export CENSGATE_AUTH_MODE=api_key
export CENSGATE_API_KEYS='key-one,key-two'
```

```yaml
auth:
  mode: api_key
  api_keys:
    - key-one
    - key-two
```

Present credentials as either:

```http
Authorization: Bearer key-one
```

or

```http
x-api-key: key-one
```

Subject id in audit/telemetry is a non-secret digest prefix (`key:<8 hex>`), never the key itself. Startup fails if mode is `api_key` with an empty key list.

## OIDC mode

The gateway validates:

- Signature against JWKS (RS256/384/512, ES256/384; `alg: none` rejected)
- `iss` against the configured issuer
- `exp` (with `leeway_secs` clock skew)
- Optional `aud`
- Optional required scopes (all must be present)

JWKS is cached and refreshed every `jwks_refresh_secs` (default 300). On a `kid` miss the cache is force-refreshed once so key rotation does not require downtime. When `jwks_url` is omitted, the gateway discovers it from `{issuer}/.well-known/openid-configuration`.

### Claim mapping

| Setting | Effect |
|---------|--------|
| `tenant_claim` | String claim → `AuthContext.tenant`. If unset, falls back to `tid`, then `tenant`, then `"default"`. |
| `profile_claim` | String claim → preferred policy profile (wins over the profile header). |
| `required_scopes` | Every listed scope must appear in `scope` / `scp`. |

Credential-supplied profile wins over `x-censgate-profile` so callers cannot widen their granted policy. `allow_profile_header` already defaults to `false`; leave it off when profiles come only from credentials. Enabling the header without inbound authentication lets any caller choose any configured profile — the gateway logs a warning for that combination.

Standalone `POST /v1/restore` requires an authenticated subject and returns **403** when `auth.mode` is `none`. With auth enabled, token-map storage keys are bound to the subject (`SHA-256` of subject plus session id) so one caller cannot restore another's mappings even within the same tenant. With `auth.mode = none`, cross-request session resumption on the chat surface still keys only on the caller-supplied `x-censgate-session-id` — anyone who can reach the port and reuse that header can resume another caller's session. That mode is appropriate only on a trusted network. In-request tokenize-then-restore is unaffected.

### Keycloak-style example

```yaml
# See also crates/redact-gateway/examples/oidc.yaml
auth:
  mode: oidc
  oidc:
    issuer: https://keycloak.example.com/realms/production
    audience: redact-gateway
    # Optional; discovery is used when omitted:
    # jwks_url: https://keycloak.example.com/realms/production/protocol/openid-connect/certs
    required_scopes:
      - redact.invoke
    tenant_claim: tid
    profile_claim: redact_profile
    jwks_refresh_secs: 300
    leeway_secs: 60

redaction:
  allow_profile_header: false
```

```bash
export CENSGATE_AUTH_MODE=oidc
export CENSGATE_OIDC_ISSUER=https://keycloak.example.com/realms/production
export CENSGATE_OIDC_AUDIENCE=redact-gateway
export CENSGATE_OIDC_REQUIRED_SCOPES=redact.invoke
export CENSGATE_OIDC_TENANT_CLAIM=tid
export CENSGATE_OIDC_PROFILE_CLAIM=redact_profile
export CENSGATE_ALLOW_PROFILE_HEADER=false

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "authorization: Bearer ${ACCESS_TOKEN}" \
  -H 'content-type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"hello"}]}'
```

### Auth0-style example

```bash
export CENSGATE_AUTH_MODE=oidc
export CENSGATE_OIDC_ISSUER=https://YOUR_TENANT.auth0.com/
export CENSGATE_OIDC_AUDIENCE=https://gateway.example.com
export CENSGATE_OIDC_JWKS_URL=https://YOUR_TENANT.auth0.com/.well-known/jwks.json
export CENSGATE_OIDC_REQUIRED_SCOPES=redact:invoke
# Custom claims often appear as https://example.com/tid — set tenant_claim accordingly
export CENSGATE_OIDC_TENANT_CLAIM='https://example.com/tid'
export CENSGATE_OIDC_PROFILE_CLAIM='https://example.com/redact_profile'
```

Configure the API in Auth0 with that identifier as the audience, and mint access tokens that include the custom claims (Auth0 Action / Rule) plus any required scopes.

## Auth context fields

| Field | Source |
|-------|--------|
| `subject` | JWT `sub`, or API-key digest id |
| `tenant` | Claim mapping or `"default"` |
| `profile` | Optional claim |
| `scopes` | JWT scopes |
| `mode` | `"none"`, `"api_key"`, or `"oidc"` |

Denied authentications emit an audit event `redact.gateway.auth_denied` and a `redact.gateway.authenticate` span with outcome `denied`.
