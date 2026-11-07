# Token-store comparison — 2026-11-07

This is a local storage-only experiment for the new `redact-token-store` crate,
not a production gateway or NER benchmark. There are no approved latency SLOs in
this report. The crate is not enabled in the gateway.

## Setup and workload

- PostgreSQL 17.11, OpenBao 2.7.2 dev server, Rust 1.93.0, Linux 6.18.57, 9 CPUs
  visible to `nproc`; CPU/memory quotas were not established. No controlled resource
  envelope, TLS, remote network, persistence/failover equivalence or cold-cache run.
- Two independent benchmark processes, each with an 8-connection PostgreSQL pool,
  a 32-operation facade bound and 10-second deadline. Processes use different
  contexts; tasks within each process contend on the same context. This is not a
  multi-shard or same-context cross-process throughput measurement.
- PostgreSQL: 16 hash partitions on tenant/context, forced tenant RLS, non-owner
  NOSUPERUSER NOBYPASSRLS runtime role. OpenBao: KV v2 document adapter, CAS and a
  512-KiB adapter bound. The disposable OpenBao listener's
  `max_request_json_strings` was raised to 100000 for this run; all other settings
  come from dev mode. This is a test condition, not a deployment recommendation.
- Synthetic values only. Initial contexts: 10, 1000, 10000 mappings; request batches:
  1 and 8; concurrent tasks: 1 and 8; operations: resolve, reuse, allocate new.
  Each task performs 32 requests per scenario. New allocations grow the context;
  `start_records` records the actual count at scenario start. Scenarios execute
  serially per worker, so later scenarios are neither independent nor controlled
  comparisons at the initial context size.
- Percentiles include successful requests only. `errors` counts failed requests
  separately. Throughput is successful requests divided by full scenario time.
  Zero samples means no successful latency measurement, not zero latency. Error
  categories are not separated in the CSV. Setup-capacity rows are not requests.

## Measured results

One-reference resolve, one concurrent task, 32 successful requests per worker:

| Backend | Initial mappings | Worker 0 p50 / p99 (ms) | Worker 1 p50 / p99 (ms) |
|---|---:|---:|---:|
| PostgreSQL | 10 | 0.400 / 1.902 | 0.418 / 2.424 |
| PostgreSQL | 1000 | 0.442 / 0.699 | 0.416 / 0.688 |
| PostgreSQL | 10000 | 0.508 / 0.831 | 0.583 / 1.024 |
| OpenBao KV v2 | 10 | 0.619 / 1.413 | 0.612 / 1.118 |
| OpenBao KV v2 | 1000 | 5.715 / 8.079 | 5.506 / 7.966 |
| OpenBao KV v2 | 10000 | setup capacity exceeded | setup capacity exceeded |

Both OpenBao workers stopped the 10000-mapping setup after 1536 committed mappings
because the next batch exceeded the adapter's document bound. At smaller initial
sizes, subsequent new-write scenarios also grow toward capacity. Across the full
run, PostgreSQL completed 10368 requests with zero errors; OpenBao completed 6002
with 910 failed requests plus two setup-capacity events. Do not interpret successful
OpenBao percentiles as its latency at an equivalent success rate.

The plan regression independently seeds 10000 mappings and uses
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` under the restricted role. Resolve and
reuse each visited one mapping for a one-key request. It counts scanned and filtered
mapping rows, rather than assuming an Index Scan is bounded. The initial implementation
failed this check by visiting 10000 mappings: index ordering and parameterized
point queries were corrected before the reported run. Those earlier measurements
are not evidence for the final implementation.

The data supports selective PostgreSQL access at these tested sizes and shows the
whole-document growth/capacity cost of this OpenBao adapter. It does not establish
production p99, availability, maximum tenant size, linear horizontal scaling or a
deployment-ready replacement for the gateway's existing store.

## Validation and reproduction

The same harness passed real-backend contracts for atomic reuse, concurrent writers,
lost-response retry, ordered selective resolution, tenant/principal denial, expiry
reservation, permanent retirement and races, all-or-nothing collision rollback and
authenticated expiry. Separate tests exercise admission/deadline failure and scoped
index framing. PostgreSQL tests also reject unscoped queries through RLS and direct
child-partition reads. No live resource was contacted or changed.

Use the commands in [the crate README](../../crates/redact-token-store/README.md#reproduce)
and the exact dependency versions above. Raw rows:
[worker 0](token-store-20261107-worker-0.csv),
[worker 1](token-store-20261107-worker-1.csv).

Remaining benchmark work: end-to-end gateway integration, actual Platform traces,
many tenant/principal distributions and skew, same-context multi-process races,
multiple database shards, cold/warm repetition, resource/bytes/SQL-operation metrics,
error categorization, backend outage/restart/failover, cancellation and key rotation.
Any proposed performance targets should be reviewed separately from these results.
