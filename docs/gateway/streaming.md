# Streaming redaction

Chat completions with `"stream": true` return `text/event-stream`. The gateway redacts assistant text before the client sees it. Two modes trade detection completeness against time to first token.

Related: [getting started](getting-started.md) · [configuration](configuration.md) · [policy](policy.md) · [telemetry](telemetry.md)

## Modes

| Mode | Config | Behavior |
|------|--------|----------|
| Buffered (default) | `stream_mode: buffered` / `CENSGATE_STREAM_MODE=buffered` | Consume the whole upstream SSE body (size-capped by `max_body_bytes`), transform chunks **in place**, then emit the rewritten stream. |
| Incremental | `stream_mode: incremental` | Forward redacted text as it arrives while retaining a trailing hold-back window. |

```bash
export CENSGATE_STREAM_MODE=buffered          # default
export CENSGATE_STREAM_HOLDBACK_BYTES=256     # incremental only
```

```yaml
redaction:
  stream_mode: buffered
  stream_holdback_bytes: 256
```

## Detection guarantees

| Mode | Guarantee |
|------|-----------|
| Buffered | Detection sees the complete assistant text for the stream. No entity can hide in a token split. Time to first token equals upstream completion time for the full stream. |
| Incremental | Detection is reliable for any entity **shorter than the hold-back window**. The gateway never emits inside a detected entity: the cut point moves back to the entity start when a match straddles the boundary. Entities longer than the hold-back can still straddle the window — that is why buffered remains the default. |

Choose buffered when completeness matters more than latency. Choose incremental when interactive latency matters and entity lengths fit under the hold-back.

## Hold-back window

`stream_holdback_bytes` (default `256`, must be > 0) is the trailing byte count retained before emission in incremental mode.

Algorithm (per flush):

1. If buffered text length ≤ hold-back, emit nothing yet.
2. Else propose a cut at `len - holdback`.
3. If any detected entity straddles the cut, move the cut to that entity's start (repeat).
4. Align to a UTF-8 character boundary.
5. Redact and emit the prefix; retain the suffix.

A token placeholder that would be split by the cut is also carried forward, because half a placeholder can never be restored. That carry-forward is bounded by the hold-back size, so a stray `[` in ordinary prose cannot stall the stream.

Size the window above the longest entity you must catch in incremental mode (emails and phone numbers typically fit in 256 bytes; long private-key blocks do not).

## Buffered fidelity

Buffered mode preserves the upstream chunk **sequence** and every JSON field on every chunk. The only values rewritten are:

- `choices[i].delta.content`
- `choices[i].delta.tool_calls[j].function.arguments`

Chunks that do not carry those fields (role announcements, `finish_reason`, `usage`, `system_fingerprint`, `logprobs`, `service_tier`, provider extensions, and any other unknown fields) keep all fields intact. Re-serialization via `serde_json` may reorder object keys; field **presence and values** are what this guarantee covers.

Content and tool-argument fragments are coalesced per stream for detection. The redacted string lands on the **first** chunk that carried text for that stream; later fragments become empty strings. Clients therefore receive fewer content deltas than the provider sent. That is inherent to buffered mode (which already waits for the whole upstream body).

Every choice is redacted in **buffered** mode, including when `n > 1`. Incremental mode redacts `choices[0].delta.content` (plus the hold-back window) and is intended for single-choice chat UIs; use buffered mode when `n > 1`, tool-call argument streams, or response-side `block` must fail closed before any bytes reach the client. Incremental responses add header `x-censgate-stream-mode: incremental`. Compliance headers on incremental streams report request-side counts; response totals complete as the stream drains (telemetry still records outcomes).

## Example

```bash
curl -sN http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "llama3.2",
    "stream": true,
    "messages": [{"role":"user","content":"Email me at alice@example.com"}]
  }'
```

Provider errors on a streaming request may arrive as JSON even when the client asked for SSE; the gateway surfaces those status codes and bodies without pretending they are successful streams.

## Telemetry

Streaming redaction records span `redact.gateway.stream.redact` with `redact.stream.mode` and (when operations are enabled) `redact.stream.chunks`. See [telemetry.md](telemetry.md).
