# Gateway deployment

Run `redact-gateway` with Docker, Compose, or Kubernetes. Harden before exposing the service beyond a trusted network.

Related: [configuration](configuration.md) · [authentication](authentication.md) · [tokenization](tokenization.md) · [telemetry](telemetry.md) · [audit](audit.md)

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

Repository pattern packs are copied to `/app/patterns` and `CENSGATE_PATTERN_PACKS` defaults to that path in the image.

## Docker Compose

[`docker-compose.gateway.yml`](../../docker-compose.gateway.yml) starts the gateway, Ollama, and an OpenTelemetry Collector. Optional OpenBao for the KV v2 token map:

```bash
# Base stack
docker compose -f docker-compose.gateway.yml up --build

# With OpenBao token map
CENSGATE_VAULT_BACKEND=vault_kv2 \
  docker compose -f docker-compose.gateway.yml --profile vault up --build

# Point at a hosted OpenAI-compatible provider
BACKEND_URL=https://api.openai.com \
CENSGATE_PROVIDER_API_KEY=sk-… \
  docker compose -f docker-compose.gateway.yml up --build
```

Probe from the host:

```bash
curl -s http://localhost:8080/livez
curl -s http://localhost:8080/readyz
```

Collector config: [`deploy/otel-collector.yaml`](../../deploy/otel-collector.yaml).

## Kubernetes

Manifests: [`deploy/kubernetes/redact-gateway.yaml`](../../deploy/kubernetes/redact-gateway.yaml).

```bash
# Create secrets (do not commit real values)
kubectl create secret generic redact-gateway-secrets \
  --from-literal=CENSGATE_PROVIDER_API_KEY='…' \
  --from-literal=CENSGATE_TOKEN_DEK="$(openssl rand -base64 32)"

kubectl apply -f deploy/kubernetes/redact-gateway.yaml
```

The Deployment:

- Mounts a ConfigMap gateway YAML at `/etc/redact-gateway`
- Injects secrets via env
- Sets OTLP exporter env vars toward a collector service
- Uses HTTP liveness (`/livez`) and readiness (`/readyz`) probes
- Runs non-root with a read-only root filesystem and dropped capabilities
- Defaults to two replicas (pair with `vault_kv2` + shared `CENSGATE_TOKEN_DEK` when using tokenize)

## Hardening checklist

| Item | Guidance |
|------|----------|
| Enable auth | Set `CENSGATE_AUTH_MODE` to `api_key` or `oidc` before any untrusted edge. Mode `none` is only for trusted networks. |
| Sealing key | Set `CENSGATE_TOKEN_DEK` (base64 32 bytes) whenever tokenization is used. Share the same value across replicas. |
| Shared token map | Use `vault_kv2` (Vault or OpenBao) for multi-replica deployments. The `memory` backend is process-local. |
| Fail-closed profiles | Keep `fail_closed: true` on production profiles so dependency failures reject rather than forward unprotected content. |
| Audit sink | Set `CENSGATE_AUDIT_EXPORT` to `otlp` (preferred) or `file`, and retain records in a collector / object store with your retention policy. |
| Resource limits | Set CPU/memory requests and limits (the sample Deployment uses 100m–2 CPU and 256Mi–1Gi as a starting point). Cap bodies with `CENSGATE_PROVIDER_MAX_BODY_BYTES`. |
| Upstream TLS | Prefer `https://` upstream URLs. Inject provider keys via secrets, not ConfigMaps. |
| Profile selection | When profiles come from JWT claims, set `allow_profile_header: false`. |
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
