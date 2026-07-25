# Gateway audit

The gateway emits audit records as structured events. Durable, immutable, or WORM retention is provided by the sink you point it at — for example an OpenTelemetry Collector writing to object storage with retention locks. The gateway does not implement a database.

Related: [telemetry](telemetry.md) · [configuration](configuration.md) · [deployment](deployment.md)

## Event names

| Name | When |
|------|------|
| `redact.gateway.request` | Inbound request accepted after redaction |
| `redact.gateway.response` | Response path completed |
| `redact.gateway.policy_block` | Policy blocked the payload |
| `redact.gateway.auth_denied` | Authentication denied |
| `redact.gateway.config_reload` | Configuration reload |

Outcomes: `allowed`, `blocked`, `denied`, `error`.

## Event schema

Records never carry prompt text, completions, or entity **values**. Optional entity **type names** are controlled by `audit.include_entity_types` (default `true`).

| Field | Type | Description |
|-------|------|-------------|
| `event_name` | string | Stable name from the table above |
| `event_id` | string | UUID v4 |
| `timestamp` | string | RFC 3339 UTC |
| `action` | string | Gateway action (e.g. `chat.completions`) |
| `outcome` | string | `allowed` / `blocked` / `denied` / `error` |
| `profile` | string | Policy profile name |
| `tenant` | string | Tenant id |
| `session_id` | string? | Session when known |
| `subject` | string? | Non-secret caller id |
| `redactions` | number | Spans rewritten |
| `tokens_issued` | number | Reversible tokens minted |
| `entity_types` | string[] | Types rewritten (when enabled) |
| `entity_counts` | object | Counts per entity type |
| `blocked_entities` | string[] | Types that triggered block |
| `content_sha256` | string? | SHA-256 of the **redacted** payload |
| `upstream_status` | number? | Provider HTTP status |
| `error_type` | string? | Low-cardinality error class |
| `trace_id` | string? | Correlated trace |
| `span_id` | string? | Correlated span |

### Example record

```json
{
  "event_name": "redact.gateway.request",
  "event_id": "3f2a9c8e-1b4d-4e6a-9c2f-8a7b6c5d4e3f",
  "timestamp": "2026-07-25T19:30:00.123456789Z",
  "action": "chat.completions",
  "outcome": "allowed",
  "profile": "default",
  "tenant": "default",
  "session_id": "conversation-42",
  "subject": "key:a1b2c3d4",
  "redactions": 1,
  "tokens_issued": 0,
  "entity_types": ["EMAIL_ADDRESS"],
  "entity_counts": {"EMAIL_ADDRESS": 1},
  "blocked_entities": [],
  "content_sha256": "c5c6a42ac1b14d09df035a98d226a849e72a59a92b34b7ac76b5485861fbcdcf",
  "upstream_status": 200,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7"
}
```

## Sinks

| Export | `CENSGATE_AUDIT_EXPORT` | Behavior |
|--------|-------------------------|----------|
| Off | `off` (default) | No emission |
| Stdout | `stdout` | One JSON object per line on standard output |
| File | `file` | Append JSON lines to `CENSGATE_AUDIT_FILE` / `audit.file_path` (reopens after rotation) |
| OTLP | `otlp` | OpenTelemetry log records via the process logger provider |

```bash
export CENSGATE_AUDIT_EXPORT=stdout
# or
export CENSGATE_AUDIT_EXPORT=file
export CENSGATE_AUDIT_FILE=/var/log/redact-gateway/audit.jsonl
# or
export CENSGATE_AUDIT_EXPORT=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
```

## Ordering and drop semantics

Emission is asynchronous:

1. The request path enqueues the record on a bounded channel (`queue_capacity`, default `4096`).
2. A background worker drains the queue and calls the sink.
3. Sink failures retry up to three times with exponential backoff (10 ms, 20 ms, 40 ms).
4. If the queue is **full**, the record is **dropped**, a drop counter increments, and a rate-limited warning is logged (first drop and every 100 thereafter). The HTTP request is never blocked on audit I/O.
5. Dropped counts are exported as metric `redact.gateway.audit.records_dropped`.

Under sustained overload, prefer a larger queue and a durable OTLP collector pipeline rather than relying on the in-process buffer alone.

## Building a durable pipeline

The Compose stack and [`deploy/otel-collector.yaml`](../../deploy/otel-collector.yaml) show an operator-owned pipeline:

1. Gateway: `CENSGATE_AUDIT_EXPORT=otlp` with `OTEL_LOGS_EXPORTER=otlp`.
2. Collector receives OTLP logs on `4317` / `4318`.
3. Audit path uses a dedicated batch processor **without** probabilistic sampling.
4. Exporter writes to a file (or your SIEM / object store) with a durable sending queue and indefinite retry.
5. Mount the destination on storage with retention locks / object-lock if you need immutability.

The Collector configuration is a starting point for retention policy; immutability is enforced by the storage layer you attach, not by the gateway process.

See also [`examples/observability.yaml`](../../crates/redact-gateway/examples/observability.yaml).
