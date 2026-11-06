# Field-preserving redact batches

`POST /v1/redact` accepts either the existing `text` string or `texts`, an
array of independent strings. Existing single-text responses remain unchanged.
Batch responses contain `texts` in request order, plus `profile`, `session_id`,
`blocked`, and an aggregate `outcome`. They contain no legacy `text` field.
The session/vault aliases and credential-bound profile and subject rules are
identical to single-text calls. `/v1/compliance/check` remains single-text.

```json
{"texts":["synthetic leaf one","synthetic leaf two"],"profile":"reversible","session_id":"synthetic-session"}
```

## Negotiation and rollback

Authenticated `GET /v1/compliance/status` advertises:

```json
{"capabilities":{"redact_texts_v1":true,"max_texts":800,"max_text_bytes":65536,"max_total_bytes":1048576,"timeout_ms":30000}}
```

A client must discover the explicit `redact_texts_v1: true` before requiring
batch semantics. Missing/false/invalid capabilities mean serial single-text
fallback. After opt-in, a missing array, any null/non-string item, or order/
cardinality failure must fail closed without applying any output. Old clients
continue to send `text`; unknown additive fields remain accepted. Sending both
recognized fields, neither, null fields, or an empty batch fails closed.

Set `CENSGATE_REDACT_BATCH_ENABLED=false` or YAML
`server.redact_batch_enabled: false` to withdraw support and reject batches.
The YAML setting is hot-reloadable through the existing config reload path.
Clients should recheck capabilities so a rollout/rollback does not require
simultaneously deploying both repositories.

## Limits, atomicity and cancellation

- 1–800 leaves, at most 65,536 UTF-8 bytes per leaf, 1,048,576 total decoded
  UTF-8 bytes. No truncation. Shape/decoded-size violations are 400; malformed
  JSON/types are rejected by Axum (400/422); the redact route's encoded body
  limit is 8 MiB (413). Other routes retain their existing body limits.
- Batch detection remains sequential per leaf, including normal NER processing
  for metadata/token-looking plaintext. No concatenation or token-shaped bypass
  is added. Empty/whitespace handling follows the existing core engine.
- One resumed TokenSession and RedactionContext cover all leaves. New mappings
  are collected and submitted in one store `put` after all leaves succeed.
  A batch with no new mappings makes no write. Duplicate values reuse the
  existing TokenSession identity rules. Tokenizing batches require persistence.
- Existing memory merge locking and KV-v2 CAS protect the entire mapping set.
  The handler re-reads/re-mints after conflicts, with eight handler attempts;
  KV-v2 also has an eight-attempt CAS budget. Contention can therefore cause
  more than one attempted write, but only one successful batch commit.
  The existing KV-v2 mapping representation has four strings per mapping.
  OpenBao defaults can reject a document above roughly 124 entities; leaf
  count is not an entity-count guarantee. A larger batch or accumulated session
  requires adequate local/deployed KV JSON-string limits. Capacity errors fail
  closed, with no splitting into independent writes or automatic batch sharding.
- Batch read, detect, tokenize, CAS-exhaustion and persist failures always
  error, even for profiles with legacy `fail_closed: false`. No mixed result
  list is returned. Batch error bodies contain static classes, never detector
  or vault error details. Single-text error semantics remain compatible.
- A batch has a 30-second deadline. `x-censgate-redact-timeout-ms` can shorten
  it (positive integer milliseconds). Read/write/retry futures are dropped on
  timeout. Explicit deadline checks and yields occur between leaves and before
  persistence. Blocking ONNX inference cannot be interrupted inside a leaf;
  after that leaf finishes no subsequent leaf/persist starts past the deadline.
- No detached task continues a cancelled handler. Dropping the handler before
  persist leaves no mappings; cancelling an in-flight KV CAS may leave the
  **whole** batch committed if the backend already accepted it. This matches
  serial write uncertainty and never commits a partial batch. HTTP disconnect
  detection follows the existing Axum/Hyper handler lifetime; callers should
  send their remaining deadline. A lost response is retried/fails closed.
- Telemetry records aggregate outcome counts and the existing per-leaf detect
  spans. Request strings are never added to logs/spans. No new global inference
  fan-out or client-side parallel single-text calls are part of this contract.

## Verification and real-stack benchmark

`cargo +1.93.0 test -p redact-gateway --test redact_batch` covers C1–C9 with
synthetic fixture recognizers and instrumented stores. Existing gateway tests
also exercise the actual KV-v2 client against a synthetic CAS HTTP server.
These are correctness checks, not NER quality/performance measurements.

For performance, provide an **isolated local** OpenBao instance with a dedicated
KV-v2 mount with adequate JSON-string capacity for the accumulated map, and
an exported NER model/tokenizer. Do not point the harness at a
production endpoint or tunnel. The harness starts the actual gateway itself
with required NER, forces KV-v2, and reports successful vault writes from KV
metadata versions. It requires only the Python standard library.

```bash
CC=gcc CXX=g++ cargo +1.93.0 build --release -p redact-gateway
# Set CENSGATE_NER_MODEL_PATH and ORT_DYLIB_PATH to local files.
# Set REDACT_BENCH_VAULT_ADDR, REDACT_BENCH_VAULT_TOKEN and
# REDACT_BENCH_VAULT_MOUNT to the isolated local stack (credential via env).
python3 scripts/benchmark-redact-batch.py --check
python3 scripts/benchmark-redact-batch.py --samples 10 --output /workspace/plans/redaction-batching-realstack.json
```

The same synthetic fixtures run serial and batch at 139, 347 and 800 leaves,
with a warmup and fresh session per sample. Output includes p50/p95, sample
walls, HTTP counts, successful vault-write counts, model hash and versions.
Completed rows are written as each shape finishes. A later HTTP failure keeps
those rows, adds a status-only error for the failing shape, and exits non-zero.
An 800-leaf batch can hit the 30-second deadline on a single CPU and fail closed.
Use existing detect spans/profiling to attribute ONNX/transport time separately;
the harness does not invent an inference-time split. It deliberately preserves
local synthetic mapping records for review; dispose of the dedicated mount
through the local test-stack owner afterward.

Missing models, credentials or local KV-v2 are a **BLOCKED** performance result.
Mocked transport numbers and historical incident durations do not establish
production gains. Merge/performance rollout review remains gated on actual
NER+vault measurements.
