# Gateway telemetry

OpenTelemetry traces, metrics, and logs for `redact-gateway`. Transport is configured with standard `OTEL_*` variables; gateway-specific detail uses `CENSGATE_TRACE_*` and related settings.

Related: [configuration](configuration.md) · [audit](audit.md) · [deployment](deployment.md)

## Enablement matrix

### OpenTelemetry SDK / exporters

| Variable | Role | Default |
|----------|------|---------|
| `OTEL_SDK_DISABLED` | When `true`, all signals become no-ops | unset |
| `OTEL_SERVICE_NAME` | Resource service name | `redact-gateway` when unset |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes | unset |
| `OTEL_TRACES_EXPORTER` | `otlp`, `console`, `none` | `otlp` (or `none` without the `otlp` feature) |
| `OTEL_METRICS_EXPORTER` | `otlp`, `console`, `none` (comma-separated) | `otlp` |
| `OTEL_LOGS_EXPORTER` | `otlp`, `console`, `none` | `otlp` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector endpoint (per-signal overrides exist) | SDK default |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` or `http/protobuf` | SDK default |
| `OTEL_EXPORTER_OTLP_HEADERS` | Exporter headers | unset |
| `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` | Sampling | SDK default |
| `OTEL_BSP_*` | Batch span processor | SDK default |
| `OTEL_METRIC_EXPORT_INTERVAL` | Periodic metric reader | SDK default |
| `OTEL_PROPAGATORS` | Comma-separated propagators | `tracecontext,baggage` |

### Gateway-specific

| Variable / setting | Role | Default |
|--------------------|------|---------|
| `CENSGATE_TRACE_OPERATIONS` / `telemetry.operations` | Operation span detail: `off`, `basic`, `detailed` | `basic` |
| `CENSGATE_TRACE_FILTER` / `telemetry.filter` | Optional `EnvFilter` directive for gateway targets | unset |
| `CENSGATE_GENAI_ATTRIBUTES` / `telemetry.genai_attributes` | Emit development-stage `gen_ai.*` attributes | `false` |
| `OTEL_SEMCONV_STABILITY_OPT_IN` | When it contains `gen_ai_latest_experimental`, enables `gen_ai.*` | unset |
| `CENSGATE_ENABLE_TRACING` | tower-http request logging | `true` |
| `CENSGATE_METRICS_ENDPOINT` | Serve Prometheus `/metrics` (needs `prometheus` feature) | `true` |

| `CENSGATE_TRACE_OPERATIONS` | HTTP server/client spans | Pipeline stage spans | Extra detail attributes |
|-----------------------------|--------------------------|----------------------|-------------------------|
| `off` | Yes | No | No |
| `basic` | Yes | Yes | Minimal |
| `detailed` | Yes | Yes | Stream chunk counts, GenAI response fields when enabled |

## Semantic convention stability

| Convention set | Status | Default |
|----------------|--------|---------|
| Stable HTTP (`http.request.method`, `http.route`, `http.server.request.duration`, …) | Stable upstream | Always used for HTTP spans and metrics |
| `gen_ai.*` (`gen_ai.request.model`, usage, finish reasons, …) | **Development** upstream; names may change | Opt-in via `CENSGATE_GENAI_ATTRIBUTES` or `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental` |

Prefer stable HTTP conventions for production dashboards and alerts. Treat `gen_ai.*` as experimental enrichment.

## W3C propagation

Default propagators are W3C `tracecontext` and `baggage` (`OTEL_PROPAGATORS`).

- Inbound: the HTTP server span adopts the caller's remote parent from request headers (`traceparent` / `tracestate`).
- Outbound: context is injected into upstream request headers so the provider call continues the same trace.

A malformed inbound `traceparent` does not fail the request; the span starts a new trace instead.

## Spans

Operation spans are ordinary `tracing` spans (filterable with `RUST_LOG` / `CENSGATE_TRACE_FILTER`). Constructors accept counts, enums, and identifiers — never prompt text, completions, or entity values.

| Span name | Kind | When | Attributes |
|-----------|------|------|------------|
| `{method} {route}` (`http.server`) | server | Every request | `http.request.method`, `http.route`, `url.scheme`, `http.response.status_code`, `error.type` |
| `http.client` | client | Generic HTTP client helper | `http.request.method`, `server.address`, `server.port`, status, `error.type` |
| `redact.gateway.authenticate` | internal | Protected routes | `redact.auth.mode`, `redact.auth.outcome`, `error.type` |
| `redact.gateway.policy.evaluate` | internal | Redaction pass | `redact.policy.profile`, `redact.policy.decision` |
| `redact.gateway.detect` | internal | Detection | `redact.text.bytes`, `redact.entities.count` |
| `redact.gateway.anonymize` | internal | Anonymize helper | `redact.redactions.count` |
| `redact.gateway.tokenmap.put` | client* / internal | Persist tokens | `redact.tokenmap.backend`, `redact.tokenmap.entries`, `server.address`/`port` when remote |
| `redact.gateway.tokenmap.get` | client* / internal | Load tokens | same |
| `redact.gateway.restore` | internal | Response restore | `redact.tokens.restored`, `redact.tokens.missing` |
| `redact.gateway.upstream.chat` | client | Upstream chat call | HTTP client attrs; optional `gen_ai.*` |
| `redact.gateway.stream.redact` | internal | Streaming redaction | `redact.stream.mode`, `redact.stream.chunks` |
| `redact.gateway.config.reload` | internal | SIGHUP reload | `redact.config.source`, `redact.config.outcome` |

\* Token map spans use kind `client` when a server address is present (KV v2), otherwise `internal` (memory).

### Tracing targets

| Target | Subsystem |
|--------|-----------|
| `redact_gateway::http` | HTTP server |
| `redact_gateway::auth` | Authentication |
| `redact_gateway::policy` | Policy |
| `redact_gateway::detect` | Detection |
| `redact_gateway::anonymize` | Anonymize |
| `redact_gateway::tokenmap` | Token map |
| `redact_gateway::restore` | Restore |
| `redact_gateway::upstream` | Upstream client |
| `redact_gateway::stream` | Streaming |
| `redact_gateway::config` | Config reload |

Example filter: `CENSGATE_TRACE_FILTER=redact_gateway=info,tower_http=info`.

### Optional GenAI attributes (on `redact.gateway.upstream.chat`)

| Attribute | Notes |
|-----------|-------|
| `gen_ai.operation.name` | e.g. `chat` |
| `gen_ai.provider.name` | e.g. `openai` |
| `gen_ai.request.model` | From request body |
| `gen_ai.response.model` | Detailed + enabled |
| `gen_ai.usage.input_tokens` | Detailed + enabled |
| `gen_ai.usage.output_tokens` | Detailed + enabled |
| `gen_ai.response.finish_reasons` | Detailed + enabled |

## Metrics

| Name | Instrument | Unit | Attributes |
|------|------------|------|------------|
| `http.server.request.duration` | Histogram | `s` | `http.request.method`, `url.scheme`, `http.route`, `http.response.status_code`, `error.type` |
| `http.client.request.duration` | Histogram | `s` | `http.request.method`, `http.response.status_code`, `error.type` |
| `http.server.active_requests` | UpDownCounter | `{request}` | `http.request.method`, `url.scheme` |
| `redact.gateway.redactions` | Counter | `{redaction}` | `redact.entity_type`, `redact.action` |
| `redact.gateway.policy.decisions` | Counter | `{decision}` | `redact.policy.profile`, `redact.policy.decision` |
| `redact.gateway.tokenmap.operations` | Counter | `{operation}` | `redact.tokenmap.backend`, `redact.tokenmap.operation`, `error.type` |
| `redact.gateway.tokenmap.operation.duration` | Histogram | `s` | same as operations |
| `redact.gateway.audit.records_dropped` | Counter | `{record}` | (none) |

HTTP duration histograms use the spec-advised explicit bucket boundaries: `0.005` … `10.0` seconds.

Pull-based scrape: `GET /metrics` when `CENSGATE_METRICS_ENDPOINT=true` and the `prometheus` feature is enabled. Otherwise export metrics over OTLP.

## Trace one request end to end

1. Run a collector (Compose includes one — see [deployment.md](deployment.md)):

   ```bash
   export OTEL_SERVICE_NAME=redact-gateway
   export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
   export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
   export OTEL_TRACES_EXPORTER=otlp
   export OTEL_METRICS_EXPORTER=otlp
   export OTEL_LOGS_EXPORTER=otlp
   export CENSGATE_TRACE_OPERATIONS=detailed
   export CENSGATE_AUDIT_EXPORT=otlp
   ```

2. Start the gateway and send a traced request:

   ```bash
   cargo run -p redact-gateway -- --backend-url http://127.0.0.1:11434

   TRACE_ID=$(openssl rand -hex 16)
   SPAN_ID=$(openssl rand -hex 8)
   curl -s http://127.0.0.1:8080/v1/chat/completions \
     -H "traceparent: 00-${TRACE_ID}-${SPAN_ID}-01" \
     -H 'content-type: application/json' \
     -d '{"model":"llama3.2","messages":[{"role":"user","content":"Email alice@example.com"}]}'
   ```

3. In the collector / backend, open the trace. Expect a tree similar to:

   ```
   POST /v1/chat/completions          (http.server, parent = your traceparent)
   ├─ redact.gateway.authenticate
   ├─ redact.gateway.policy.evaluate
   ├─ redact.gateway.detect
   ├─ redact.gateway.tokenmap.put     (when tokens were minted)
   ├─ redact.gateway.upstream.chat    (client; continues trace upstream)
   └─ redact.gateway.restore          (when restore ran)
   ```

4. Correlate audit log records by `trace_id` / `span_id` when the audit sink is `otlp` (see [audit.md](audit.md)).

Example YAML: [`crates/redact-gateway/examples/observability.yaml`](../../crates/redact-gateway/examples/observability.yaml).
