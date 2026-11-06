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
  A stored mapping has four keys and four string values. OpenBao's listener
  limit counts keys and string values, not one string per entity. The default
  limit is 1000 and rejects a growing map near 124 entities. A candidate
  listener value of 10000 accepted 1249 mappings (9998 strings, about 205 KiB
  for the short sealed-value probe) and   rejected 1250. One 800-leaf batch of unique values fits in that document.
  The listener change is paired with a document limit, not with an
  unbounded map. `CENSGATE_REDACT_MAP_DOC_LIMIT` defaults to 1249, the
  measured ceiling at 10000 strings. A caller keeps one session id. Mappings
  that still fit stay in that document. A later request whose new mappings
  do not fit is written, in one compare-and-set, to `:mapdoc:N` (at most 8
  documents). That suffix is not the platform client's `:kvshard:` cursor.
  Token numbers keep counting across documents, so a repeated value keeps its
  token and restore uses the same session id. One request that itself exceeds
  a document, or that arrives after all 8 documents are full, returns HTTP 409
  `session_map_full` and writes nothing. Set the document limit no higher
  than the listener accepts. Near-cap and over-cap failures are closed.
- Detection of a texts[] request packs equal-length token rows into one ONNX
  forward, at most 32 sequences and 2048 tokens. Each text is tokenized,
  decoded, and minted on its own. Texts are not concatenated. Pattern and
  contextual recognizers still run per text. One TokenSession and one mapping
  write cover the request. `CENSGATE_REDACT_BATCH_INFLIGHT` (default 1, cap 8)
  admits that many texts[] requests. `CENSGATE_REDACT_BATCH_QUEUE_MS` (default
  5000, cap 30000) is how long a request waits, and
  `CENSGATE_REDACT_BATCH_QUEUE_DEPTH` (default 4, cap 32) is how many may wait.
  A waiter does not detect beside the in-flight request. Past the depth or the
  wait, the response is HTTP 503 `error.type=overload` and nothing is detected
  or written. Set the wait to 0 to reject immediately. This queue is
  backpressure. Throughput for concurrent sessions is additional gateway
  replicas, each with its own CPU.
- Batch read, detect, tokenize, CAS-exhaustion and persist failures always
  error, even for profiles with legacy `fail_closed: false`. No mixed result
  list is returned. Batch error bodies contain static classes, never detector
  or vault error details. Policy blocks stay `policy_violation`. Vault
  failures stay `dependency_unavailable`. Admission stays `overload`.
  Single-text error semantics remain compatible.
- The batch deadline is 30 seconds. Callers shorten it with
  `x-censgate-redact-timeout-ms` and cannot extend it. On one CPU, short-leaf
  800 p99 was 23.8s after micro-batching (n=3). The same shape with one forward
  per leaf was 42.6s and missed 30s. This is a fail-closed bound, not an SLO.
  The current micro-batch finishes, then no further chunk or write starts.
  A full re-detect on a conflict retry can still exceed 30s and fails closed.
  The deadline does not grow with attempt count.
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
python3 scripts/benchmark-redact-red.py --samples 3 --output /workspace/plans/redaction-batching-red.json
```

`benchmark-redact-batch.py` compares serial and batch at 139, 347 and 800,
including a cold sample, warm samples, and one accumulated write. It also
records the mapping-document ceiling, a near-cap add, and two writers on one
session. `benchmark-redact-red.py` records short, byte-heavy, and entity-heavy
shapes, p50/p95/p99 of the sample, queue time, overload versus dependency
versus invalid-request, shared-session admission, cumulative session growth,
an 801-leaf reject, cancellation before the write, and a single-flight rate.
Small-sample p99 is an order statistic, not an approved SLO. Set
`CENSGATE_REDACT_BATCH_INFLIGHT` and the gateway cgroup before starting it.
`--leaves 347,800` repeats only those short shapes.
Use existing detect spans/profiling to attribute ONNX/transport time separately;
the harness does not invent an inference-time split. It deliberately preserves
local synthetic mapping records for review; dispose of the dedicated mount
through the local test-stack owner afterward.

Missing models, credentials or local KV-v2 are a **BLOCKED** performance result.
Mocked transport numbers and historical incident durations do not establish
production gains. Merge/performance rollout review remains gated on actual
NER+vault measurements.
