# Synthetic two-replica acceptance and load procedure

Use with the [infrastructure specification](token-store-beta-infrastructure.md)
and [activation runbook](token-store-beta-readiness.md). No command here authorizes
a deployment, publication or mutation of an existing environment.

## Reproducible local rehearsal

Preparation exposed three regressions that are fixed with this procedure: a
concurrent first import could mistake a peer's completed source cleanup for an
integrity failure (31 successes and one 409 in the reproduction); adjacent emails
sharing a separator lost every other regex match (five of ten remained raw).
The gateway now rechecks committed target lifecycle after freezing and bounds a
retry of a source data/metadata race. Genuine missing/corrupt history still fails
closed. Email detection checks the right boundary without consuming the next
address's separator. Deterministic peer-import and separator regressions accompany
the fixes; the load fixture must tokenize every seeded value. The real OTLP/HTTP
sink also received zero trace/metric bytes with the prior async HTTP client.
The gateway now selects the blocking HTTP exporter client for the SDK's default
background batch processors/readers; the fixture requires actual delivery from
both processes. This does not verify the deployed gRPC collector/exporter path.

The opt-in harness owns temporary databases, a dev OpenBao, two actual gateway
child processes and a loopback OTLP HTTP/protobuf sink. It never takes a remote
gateway URL or existing credential. PostgreSQL PID/data-directory checks precede
administrative writes; Linux `/proc` socket ownership checks precede gateway HTTP
traffic. All child processes and temporary credentials are removed on exit.

From the repository root, with the three binary paths selected for the local
machine (and any required local dynamic-library path):

```sh
TOKEN_STORE_PG_BIN=/path/to/postgresql/bin \
TOKEN_STORE_PG_SHARE=/path/to/postgresql/share \
TOKEN_STORE_BAO_BIN=/path/to/bao \
TOKEN_STORE_RUN_BETA_ACCEPTANCE=1 \
TOKEN_STORE_BETA_SIZES=10,1000,10000 \
TOKEN_STORE_BETA_OUTPUT=/tmp/token-store-synthetic-result.json \
python3 scripts/token-store/test-local.py
```

The regular backend/migration/preflight tests run first. The additional procedure:

1. Seeds a synthetic token through a real legacy gateway, stops that child and
   verifies shutdown before starting indexed writers.
2. Starts two independent gateway processes with identical key/map and two
   logical database pools. Imports the legacy identity and restores it through
   both peers; a second authenticated principal cannot restore it.
3. Races 32 allocations of the same value/context across both processes; checks
   one identity, restarts one process and restores through the restarted peer.
4. Seeds contexts of the selected sizes in <=100-value batches. For each size,
   runs 96 resolve and 96 reuse requests at concurrency 1, 8 and 32, alternating
   peer endpoints. Resolve repeats one reference eight times to exercise bounded
   duplicate expansion. Every response must match; failures abort the run rather
   than silently disappearing from latency percentiles.
5. Disables connections and terminates sessions to the **owned second logical
   database**. Both peers must become unready. Re-enables it and verifies readiness
   and original-token restoration. This is not an independent-server/zone outage.
6. Erases a context through one peer; the other must withhold restoration and
   reject reallocation with 410.
7. Captures bounded OTLP trace/metric requests locally, requires intern/resolve
   and backend/peer markers plus the HTTP duration metric, and checks that known
   synthetic values, context IDs, labels and credentials appear in neither the
   capture nor gateway logs. Exports only aggregate counts/timings, no raw capture.

The sink proves transport delivery and known-canary exclusion. It is not a full
protobuf attribute-schema audit or proof of Azure Monitor delivery. Existing
telemetry contract tests cover attribute shapes. The local fixture uses a debug
binary, regex detection, one PostgreSQL server with two databases, plaintext
loopback and synthetic API-key principals. It does not measure production NER,
TLS/PgBouncer, two-server independence, real OIDC tenancy, Platform history/recall,
provider/MCP/A2A flows, or cloud backup/PITR. Those remain separate gates below.

## Isolated beta acceptance record

The [local result recorded on 2026-11-08](benchmarks/token-store-beta-local-20261108.json)
contains 1,728 successful load requests and zero errors across 18 size/concurrency/
operation points, plus the correctness stages above. Both processes delivered
OTLP data: 268 requests and 5,467,464 bytes; the required markers were present and
known privacy canaries absent. The result records source hashes and dependency
versions. These are debug, loopback measurements under the limitations above,
not a beta capacity target or evidence that the operator gates have passed.

Before running any operator test, fill in an evidence record with approved
environment, source SHAs and image/NER-base digests, config/schema hashes,
PostgreSQL/pooler versions, replica/node count, resource limits, collector
destination, request deadline and owner. Keep endpoint and credential details in
the restricted operational system, not the report. Use newly generated synthetic
principals and canary values; never a real user or demo tenant.

| Stage | Procedure | Pass evidence |
| --- | --- | --- |
| Preflight | Run `validate-config` and `check-token-store` with the candidate image/secret mounts through both real runtime endpoints. Exercise wrong key/map, unsafe SET-only role, unavailable second shard and invalid CA in an isolated copy. | Expected failure categories, all-shard checks, no new contexts/fences. Never weaken validation to proceed. |
| Auth/isolation | Use two authorized synthetic tenants with two principals each through the actual beta authentication mode. Attempt own, foreign-principal and foreign-tenant restore. | Exact owner parity; foreign requests reveal no original and cannot create a shared namespace. Local API-key tests alone are insufficient. |
| Writer drain | Seed legacy identities, stop new writes/jobs, drain and stop all old writers, verify credential/control-plane inventory, then activate the candidate generation. | Named operator record and zero surviving old writers. Preserve inbound principal identity and source lineage. |
| Peer behavior | Address each peer directly through the authorized test path; repeat concurrent reuse, lost-response retry and one-at-a-time process restart. | Stable identities and authorized restore through either peer; no dependence on session affinity. |
| Real Platform paths | Run UUID/mixed-shard restart tests, long streamed branch history, old/new owner pages and exact-token recall through the candidate Platform. Exercise provider/tool/MCP/A2A routes with a synthetic capture upstream. | Owner text restored; provider/tool/MCP/A2A output remains tokenized; relevant recall survives; foreign scope denied. |
| Shard/source failure | In isolated infrastructure only, deny one shard's connections or stop its server; separately deny source access. | Readiness withdraws both replicas; 503/backpressure remains bounded; no routing/key change, fallback or plaintext release. After recovery identities are unchanged. |
| Lifecycle | Force short TTL only in a fresh synthetic generation; execute approved expiry runner repeatedly. Interrupt erasure and resume from the recorded checkpoint. | Ciphertext removed, reservations/fences retained, no restored expired/erased values, no early completion. |
| Backup/recovery | Back up, then allocate and erase additional fixtures; restore to new quarantined endpoints and replay all accepted post-backup state/erasures. | Measured RPO/RTO, original identities preserved and later erasures denied before traffic. Missing reconciliation evidence keeps the restore offline. |
| Observability | Query the chosen collector/exporter for both replica resources and intern/resolve/retire spans, HTTP counts/status/duration, pool/DB pressure and exporter drops. | End-to-end visibility with no values, tokens, credentials, SQL parameters or scope identifiers. Inspect canaries in the restricted sink and retain only the boolean/count result. |

## Load matrix and proposed stop criteria

Do correctness first, then run 60-second warm-up and five-minute measured windows
for each accepted point. Proposed matrix: mappings/context 10/1,000/10,000;
concurrency 1/8/32/64; one replica then two; uniform synthetic tenants then 80%
traffic to one hot synthetic principal. Use 50% resolve, 30% reuse and 20% new
allocation, batches 1/8/64 and separate capped-limit probes. Keep growing
allocation contexts distinct from fixed-size resolve/reuse contexts so reported
sizes remain true. Include a cold restart and a bounded migration wave.

Record total offered/completed requests, all HTTP outcomes, successful-request
p50/p95/p99, throughput, deadline failures, CPU/RSS, pool waiting/acquire latency,
PG rows/buffers/locks, collector rejected/dropped counts and actual replica count.
Do not exclude 429/503/413 from the denominator or label successful-only percentiles
as whole-workload latency. Run an open-loop arrival-rate test separately to expose
queueing; the local Python fixture is closed-loop and cannot establish an SLO.

Proposed correctness gates are zero cross-scope restores, identity changes,
plaintext leaks and successful rebinding. Stop immediately on any such failure.
Proposed operational stops: sustained >1% unexpected 5xx/deadline failures over
one minute, collector loss, OOM, storage >80%, or DB/pool pressure exceeding the
reviewed limit. These are review targets, not achieved results or approved SLOs.
Choose the latency/error budget before the beta run, including NER and migration
costs. Report throughput changes from one to two replicas without assuming linear
scaling; a shared hot context or database may remain the limit.

After each stage preserve only redacted aggregates and signed-off gate outcomes.
Keep synthetic resources isolated until the recovery owner authorizes their
cleanup. No production activation follows automatically from a passing test.
