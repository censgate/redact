# Gateway deployment

Run `redact-gateway` with Docker, Compose, or Kubernetes. Harden before exposing the service beyond a trusted network.

Related: [getting started](getting-started.md) · [configuration](configuration.md) · [authentication](authentication.md) · [tokenization](tokenization.md) · [telemetry](telemetry.md) · [audit](audit.md)

## Docker

Image build (multi-arch capable):

```bash
docker build -f Dockerfile.gateway -t redact-gateway .
```

The image is distroless (`gcr.io/distroless/cc-debian12`), runs as UID `65532`, and has no shell. There is no `HEALTHCHECK` instruction — probe `/livez` and `/readyz` from the orchestrator.

```bash
docker run --rm -p 8080:8080 \
  -e CENSGATE_PROVIDER_BASE_URL=http://host.docker.internal:11434 \
  -e CENSGATE_PROVIDER_API_KEY \
  -e CENSGATE_AUTH_MODE=api_key \
  -e CENSGATE_API_KEYS=dev-key \
  -e CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)" \
  redact-gateway
```

Repository pattern packs are copied to `/app/patterns`. `CENSGATE_PATTERN_PACKS` defaults to `/app/patterns/compliance:/app/patterns/pii` in the image (security and optional packs are opt-in).

## Docker Compose

[`docker-compose.gateway.yml`](../../docker-compose.gateway.yml) starts the gateway, Ollama, and an OpenTelemetry Collector. Optional OpenBao for the KV v2 **token map** (`CENSGATE_VAULT_BACKEND=vault_kv2` — the `vault` name is the backend option, not a requirement to run HashiCorp Vault for every deployment).

```bash
# Base stack
docker compose -f docker-compose.gateway.yml up --build

# With OpenBao token map
CENSGATE_VAULT_BACKEND=vault_kv2 \
  docker compose -f docker-compose.gateway.yml --profile vault up --build

# Point at a different OpenAI-compatible provider
PROVIDER_BASE_URL=https://api.openai.com \
CENSGATE_PROVIDER_API_KEY=sk-… \
  docker compose -f docker-compose.gateway.yml up --build
```

Ollama starts with an empty model store. The first chat request fails until you pull a model into the `ollama` service:

```bash
docker compose -f docker-compose.gateway.yml exec ollama ollama pull llama3.2
# Wait until the pull finishes, then confirm:
docker compose -f docker-compose.gateway.yml exec ollama ollama list
curl -s http://localhost:11434/api/tags
```

Probe the gateway from the host:

```bash
curl -s http://localhost:8080/livez
curl -s http://localhost:8080/readyz
```

Collector config: [`deploy/otel-collector.yaml`](../../deploy/otel-collector.yaml).

With `vault_kv2`, concurrent writers to the same session use KV v2 check-and-set with up to eight jittered read-merge-write retries. Empty incoming mapping sets skip the write. Under sustained contention on a single session a write can still exhaust those retries and fail the request; each attempt costs a read plus a write. Production maps belong on a **dedicated KV v2 token-map service**, not the cluster secrets manager.

Compose `--profile vault` is OpenBao **dev mode** + a static token. Local only. It is not a production cluster.

## Kubernetes

Manifests: [`deploy/kubernetes/redact-gateway.yaml`](../../deploy/kubernetes/redact-gateway.yaml).

The example production shape is **n replicas + HPA + `vault_kv2` against
a dedicated token-map service**. `replica=1` / `vault.backend=off` is not a
supported production topology.

```bash
# Provider key + inbound API keys (do not commit real values).
# This Secret is operator-owned. The sample manifest does not include it,
# so `kubectl apply -f` cannot overwrite live keys with placeholders.
kubectl create secret generic redact-gateway-secrets \
  --from-literal=CENSGATE_PROVIDER_API_KEY='…' \
  --from-literal=CENSGATE_API_KEYS='…'

# CENSGATE_TOKEN_DEK comes from the secrets store via ESO
# (ExternalSecret target `redact-gateway-dek`). For a local cluster without ESO:
kubectl create secret generic redact-gateway-dek \
  --from-literal=CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"

kubectl apply -f deploy/kubernetes/redact-gateway.yaml
```

The sample:

- ServiceAccount `redact-gateway` with a projected JWT for Kubernetes auth
- ConfigMap: `vault.backend=vault_kv2`, address
  `http://token-map.example.svc.cluster.local:8200`,
  `auth=kubernetes`, role `redact-gateway` (never `external-secrets`)
- ExternalSecret owns `redact-gateway-dek` (`CENSGATE_TOKEN_DEK`) from a
  secrets-store path such as `secret/redact-gateway/dek`. Replace the
  ClusterSecretStore name and remote key with values from your environment.
- Deployment `replicas: 2`, Guaranteed QoS 2 CPU / 4Gi (choose nodes that
  can allocate that request), startupProbe on `/readyz` (NER load + token-map
  health), topology spread
- HPA minReplicas 2 / maxReplicas 8; ClusterIP **without** session affinity
- NetworkPolicy: egress to the token-map service on port 8200 only for KV
- `auth.mode: api_key` (not `none`)

## Hardening checklist

| Item | Guidance |
|------|----------|
| Enable auth | Set `CENSGATE_AUTH_MODE` to `api_key` or `oidc` before any untrusted edge. Mode `none` is only for trusted networks. |
| Sealing key | Set `CENSGATE_TOKEN_DEK` (base64 32 bytes) whenever tokenization is used. Share the same value across replicas. |
| Shared token map | Production must use `vault_kv2` against a **dedicated token-map service** plus a shared `CENSGATE_TOKEN_DEK` from the secrets store via ESO. `off` / `memory` are local-dev only. Do not point the gateway at the cluster secrets manager. |
| Fail-closed profiles | Keep `fail_closed: true` on production profiles so dependency failures reject rather than forward unprotected content. |
| Audit sink | Set `CENSGATE_AUDIT_EXPORT` to `otlp` (preferred) or `file`, and retain records in a collector / object store with your retention policy. |
| Resource limits | Guaranteed QoS: integer CPU request = limit (sample is 2/2 CPU, 4Gi; choose nodes that can allocate that request). Cap bodies with `CENSGATE_PROVIDER_MAX_BODY_BYTES`. Set `CENSGATE_NER_SESSION_POOL` × `CENSGATE_NER_INTRA_THREADS` to match those cores. |
| Upstream TLS | Prefer `https://` upstream URLs. Inject provider keys via secrets, not ConfigMaps. |
| Profile selection | `allow_profile_header` defaults to `false`. Leave it off when profiles come from JWT claims; enabling it without inbound auth lets any caller choose any profile. |
| Session restore | `/v1/restore` requires `api_key` or `oidc`. With `auth.mode = none`, chat-surface session resumption keys only on `x-censgate-session-id` — safe only on a trusted network. |
| Metrics / health | Leave `/livez` and `/readyz` unauthenticated (they already are). Protect `/metrics` at the network layer if scrape labels are sensitive in your environment. |
| Pattern packs | Pin `CENSGATE_PATTERN_PACKS` to known paths; review third-party pack regexes before load. |

## Example configs

| File | Use |
|------|-----|
| [`examples/minimal.yaml`](../../crates/redact-gateway/examples/minimal.yaml) | Smallest useful proxy |
| [`examples/reversible.yaml`](../../crates/redact-gateway/examples/reversible.yaml) | Memory token map + tokenize |
| [`examples/oidc.yaml`](../../crates/redact-gateway/examples/oidc.yaml) | OIDC resource server |
| [`examples/observability.yaml`](../../crates/redact-gateway/examples/observability.yaml) | OTLP audit + detailed traces |
| [`examples/policy-healthcare.yaml`](../../crates/redact-gateway/examples/policy-healthcare.yaml) | Custom PHI-oriented policy |
