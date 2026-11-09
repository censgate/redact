# Field-preserving redact batches

`POST /v1/redact` accepts either the existing `text` string or `texts`, an
array of independent strings. Single-text responses are unchanged. Batch
responses contain `texts` in request order, plus `profile`, `session_id`,
`blocked`, and an aggregate `outcome`. They do not contain a legacy `text`
field. `/v1/compliance/check` stays single-text.

```json
{"texts":["ada@example.com","no address"],"profile":"default","session_id":"example-session"}
```

Batching is off unless `server.redact_batch_enabled` is true or
`CENSGATE_REDACT_BATCH_ENABLED=true`. `GET /v1/compliance/status` advertises <!-- pragma: allowlist secret -->
`capabilities.redact_texts_v1`. Clients should treat a missing or false
capability as serial `text`. The enabled switch reloads with configuration.
In-flight, queue wait and queue depth are read once at startup:

| Setting | Default | Bound |
|---|---|---|
| `server.redact_batch_inflight` | 1 | 1–8 |
| `server.redact_batch_queue_ms` | 5000 | 0–30000 |
| `server.redact_batch_queue_depth` | 4 | 0–32 |

Environment names are `CENSGATE_REDACT_BATCH_INFLIGHT`, <!-- pragma: allowlist secret -->
`CENSGATE_REDACT_BATCH_QUEUE_MS` and `CENSGATE_REDACT_BATCH_QUEUE_DEPTH`. <!-- pragma: allowlist secret -->

## Limits

- 1–800 strings, at most 65,536 UTF-8 bytes each and 1,048,576 bytes total.
  Shape violations are HTTP 400. Malformed JSON is rejected without echoing
  the body.
- One session and one token-map write cover the request. A conflict retries
  the whole batch, up to the existing attempt budget, and does not extend
  the deadline.
- Sending both `text` and `texts`, neither, or an empty array fails closed.
  Scalar requests do not take a batch permit.

## Admission and deadline

`x-censgate-redact-timeout-ms` can shorten the 30 second deadline and cannot <!-- pragma: allowlist secret -->
extend it. That deadline starts before the request waits for a permit and
covers detection and the token write. Time spent queued is not added on top.

Past the queue depth, or when the queue wait elapses while the deadline
remains, the response is HTTP 503 `error.type=overload`. When the deadline
elapses in the queue or between detection chunks, the response is HTTP 504
`error.type=deadline`. Neither path detects or writes. Dropping a queued
handler releases its queue slot.

The in-flight ONNX forward runs to completion. The next chunk and the write
do not start after the deadline.

## Detection

Leaves are grouped by padded sequence length. Equal lengths share one ONNX
forward, at most 32 sequences and 2048 tokens. A 32-token row packs 32 per
forward, so 800 short leaves are 25 forwards rather than 800. Texts are not
concatenated. Pattern and contextual recognizers still run per text. Pad
buckets are 32, 48, 64, 96, 128, 192, 256, 384 and 512. Extra pad positions
are attention-masked.

Token history that does not fit a single vault document belongs in indexed
token storage (`vault.indexed`), not in additional documents under the same
session.

## RED metrics

Every `/v1/redact` call records three instruments, including overload,
deadline and other errors:

| Instrument | Meaning |
|---|---|
| `redact.gateway.redact.requests` | Rate. One increment per call. |
| `redact.gateway.redact.errors` | Errors. Omitted when the outcome is `completed`. |
| `redact.gateway.redact.duration` | Caller-visible seconds, including queue time. |

Attributes are `redact.mode` (`text` or `texts`) and `redact.outcome`
(`completed`, `error`, `overload`, `deadline`). No request text, token or
entity value is a label.
