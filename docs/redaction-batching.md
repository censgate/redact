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
- Detection of a texts[] request groups leaves by pad length and packs
  equal-length token rows into one ONNX forward. The token budget is 2048
  tokens and at most 32 sequences: a 32-token row packs 32, a 96-token row
  packs 21, a 128-token row packs 16, a 192-token row packs 10. Pad lengths
  are 32, 48, 64, 96, 128, 192, 256, 384, and 512. Extra pad positions are
  attention-masked. Each text is tokenized, decoded, and minted on its own.
  Texts are not concatenated. Pattern and contextual recognizers still run
  per text. One TokenSession and one mapping write cover the request.
  The session uses graph optimization Level3. In ONNX Runtime that level is
  applied after Level2, and Level2 includes CPU attention fusion. ort
  2.0.0-rc.12 has no separate fusion switch. `CENSGATE_NER_OPT_LEVEL=all`
  selects every optimization for a probe; the default stays Level3.
  The checked-in ONNX Runtime 1.24.4 CPU library does not link OpenMP, so
  `CENSGATE_NER_INTRA_THREADS` is the thread count that takes effect. Keep it
  equal to the cgroup CPU count. The session is sequential with one inter-op
  thread. Intra-op spinning is off by default so an idle thread does not spend
  a CPU-cgroup quota. `CENSGATE_NER_INTRA_SPIN=1` turns spinning back on for
  an A/B probe. `CENSGATE_REDACT_BATCH_INFLIGHT` (default 1, cap 8)
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
- Telemetry for a texts[] request is metadata only. Admission records
  `accepted` or `overload`, queue duration, and the offered leaf and byte
  counts. After admission, the result records `completed`, `deadline`,
  `session_map_full`, or `error`, plus NER duration, vault duration, and the
  number of tokens persisted. Response headers carry the same numbers:
  queue, NER, and vault milliseconds, and leaf, byte, and token counts.
  No request text, token string, or entity value is added to a metric, header,
  or log. No new global inference fan-out or client-side parallel single-text
  calls are part of this contract.

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
python3 scripts/benchmark-redact-openloop.py --output /workspace/plans/redaction-batching-openloop.json
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

Production AKS limits, from `cloud-infrastructure`
`apps/aks-censgate/platform/deployment-redact-gateway.yaml`, are 1 CPU and
2Gi. Requests are 100m CPU and 512Mi. There is no HPA and no pod disruption
budget. The 100m request is the scheduling guarantee and the cgroup weight
under CPU contention. It is not a promise of 1 CPU. The 1 CPU / 2Gi pair is
the hard cap. `deploy/kubernetes/redact-gateway.yaml` in this repo is a public
example at 2 CPU / 4Gi. Measurements taken under a 4Gi cap do not show that
the process fits in 2Gi. Idle RSS is not load proof.

`scripts/bench-redact-manual.sh` is the manual entrypoint for the ONNX and
OpenBao load. It exits immediately when `CI` or `GITHUB_ACTIONS` is set. It
is safe to point a future scheduler at that script. This change does not add
one. Fast correctness tests stay in `cargo test`. The load script is not a
CI step.

One fresh cgroup sample at `cpu.max` 100000 100000 and `memory.max` 2147483648
(2Gi), swap off. Not an approved SLO.

- After the model loaded, memory.current was 576 MiB and memory.peak was
  576 MiB. After the mixed run, current was 763 MiB and peak was 763 MiB.
  The process was not killed. This is the peak for this binary, not the
  production image that idles near 1319 MiB.
- 12 mixed leaves: serial and batch output equal. NER 631 ms, ONNX 630 ms
  across 2 forwards, vault 4 ms.
- 800 short leaves: HTTP 503 deadline at 31044 ms. NER 31034 ms, ONNX 30971 ms
  across 24 forwards, no vault write. An earlier 1 CPU sample on a different
  cgroup completed in 22571 ms. These are two samples, not a percentile.
- A 139-leaf tenant offered with that 800 returned HTTP 503 overload at
  15003 ms. ONNX did not run.
- 800 leaves of 315 bytes: HTTP 503 deadline at 32787 ms. ONNX 32723 ms
  across 20 forwards. Nothing written.
- 800 mixed lengths: HTTP 503 deadline at 31131 ms. ONNX 31061 ms across
  32 forwards.
- Two 139-leaf tenants: both HTTP 200. One queued 4101 ms and finished at
  8266 ms. Each used 5 ONNX forwards. Vault was 11–12 ms.
- 64 short leaves at the 100m request (`cpu.max` 10000 100000): HTTP 200 in
  19857 ms, ONNX 19843 ms, 2 forwards. That is the scheduling share under a
  hard 100m cap, not the 1 CPU limit.

`benchmark-redact-openloop.py` schedules arrivals on a clock instead of waiting
for the previous response. It records one 800-leaf short request, one 800-leaf
request of about 315 bytes, one mixed-length 800, two concurrent short
tenants, and a burst that must shed load as overload. Stage headers are the
RED split. The numbers are a candidate envelope, not an approved SLO.

One-sample candidate on the 1 CPU cgroup (`cpu.max` 100000 100000), pool 1,
intra threads 1, spinning off, Level3. Not an approved SLO:

- 12 mixed leaves, serial and batch output equal. Raw addresses did not
  survive. NER 438 ms, vault 2 ms.
- 16 leaves of 315 bytes, serial and batch output equal. NER 1437 ms.
- 800 short leaves: HTTP 200 in 22571 ms. NER 22553 ms, vault 9 ms, 800 tokens.
- A 139-leaf tenant arriving with that 800 waited the 15000 ms queue and
  returned HTTP 503 overload. NER did not run. The admitted 800 still completed.
- 800 leaves of 315 bytes: HTTP 503 deadline at 30851 ms. Nothing was written.
- 800 mixed short and 315-byte leaves: HTTP 503 deadline at 31257 ms.
- Two 139-leaf tenants: both HTTP 200. One waited 3937 ms and finished at
  7862 ms. NER about 3.9 s, vault 3–4 ms.
- The same 315-byte 800 on 2 CPU (`intra_threads=2`) still missed the deadline
  at 30491 ms. On 4 CPU (`intra_threads=4`) it completed in 18636 ms, NER
  18620 ms, vault 7 ms, 800 tokens. That is under the 30 s gateway deadline
  and over the 10 s client default. 3 CPU was not measured. Do not apply the
  CPU change from this note.
- Spinning on versus off, and Level3 versus all optimizations, moved a 32-leaf
  and a 64-leaf probe by tens of milliseconds. The defaults stay spin off and
  Level3. Quantized weights were not loaded. There is no recall comparison
  for them.

Missing models, credentials or local KV-v2 are a **BLOCKED** performance result.
Mocked transport numbers and historical incident durations do not establish
production gains. Merge/performance rollout review remains gated on actual
NER+vault measurements.

## Later slice: a dynamically batched NER plane

This increment stays inside the gateway process. A later slice can move
detection to a separate plane only after a design review. The contract for
that slice, not implemented here:

- One request is still one token assignment and one mapping write. The NER
  plane returns spans and offsets only. It does not mint tokens and it does
  not see the vault.
- The plane may coalesce leaves from several requests into one forward when
  they share a pad length and fit the same 2048-token budget. Coalescing must
  not concatenate texts or share a TokenSession.
- Admission stays at the gateway: a request that cannot be queued inside the
  deadline is overload, and a cancelled request is dropped from the plane
  before the next forward. An in-flight forward is not cancelled mid-kernel.
- Quantized weights ship only with a recall and offset comparison against the
  current fp32 model on a fixed synthetic set. A silent recall drop is a
  failed release, not a performance win.
- The plane does not change `texts[]`, the 30s deadline, or the map-document
  spill. Those stay gateway contracts.
