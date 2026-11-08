# Indexed token storage: review and beta activation

This is a review/runbook package, not evidence of a deployment. The indexed
backend is opt-in; merging compatible binaries does not change the current
storage mode. No registry publication or live configuration change was performed
for this PR. See the [contract and migration protocol](../crates/redact-token-store/README.md)
and [measured storage comparison](benchmarks/token-store-20261107.md).

## Release and registry gates

The future release workflow publishes `redact-token-store` before
`redact-gateway`. It refuses to publish the gateway until the exact dependency
version is visible and not yanked in Cargo's sparse index. Local `cargo package`
verification builds normalized archives; it does not upload packages.

Read-only registry checks on 2026-11-08 returned HTTP 404 for both the crates.io
`redact-token-store` API and its sparse-index entry. The name was not registered
at that check. This does not prove who can register it or that publishing is
configured. Before an explicitly authorized release, the release owner must:

1. Verify namespace/owner access and the repository/workflow/environment identity
   accepted by crates.io trusted publishing. Arrange any first-publication
   credential through the registry's approved process; never put it in a PR.
2. Confirm the release version and dependency versions agree. Existing immutable
   versions must not be overwritten. Review the exact release workflow revision.
3. Run the workflow only after approval. Retain its package verification and
   sparse-index results, image provenance and immutable digests in the release record.

No authenticated registry-owner settings were available for verification here.
The 404 is an outstanding release prerequisite, not a failed local package test.

## Phase A: compatible binaries, legacy storage

Review and release the companion Platform changes before any indexed writes.
Platform must handle native UUID-u128 labels, mixed legacy shard labels and the
`N * 2^128 + label` routing envelope. Upgrade all gateway writers to the
freeze-aware release while retaining their current legacy storage configuration.
Confirm there are no stale deployments, jobs or old credentials able to mutate
the source. Merely adding a new replica is not a writer-drain barrier.

Exercise synthetic owner restore, foreign-principal denial, provider tokenization
and existing conversations with legacy storage. Record application and gateway
image digests and configuration revisions. At this stage, before any context has
been frozen/imported, ordinary compatible-binary rollback remains possible.

## Phase B prerequisites: indexed storage remains disabled until complete

| Gate | Evidence required from the operator |
| --- | --- |
| Dedicated Postgres shards | Reviewed schema, runtime role, TLS verification, bounded connection allowance, storage capacity, backups/PITR and service ownership. |
| Isolation | Runtime owns no schema/tables and cannot assume their owner; no superuser/BYPASSRLS, schema CREATE, TRUNCATE, direct child-partition access or configuration writes. Parent RLS/policies and required grants match v1. |
| Key and routing | Existing durable root DEK preserved; ordered shard IDs, matching runtime connection environment names and all 256 ownership entries identical across replicas. Operator-installed commitment and logical ID match each database. |
| Network and secrets | Reviewed GitOps config mount, secret references and PG egress; source OpenBao/Kubernetes auth, lineage access, write/metadata/destruction privileges and TLS remain available. No connection strings or key material in Git. |
| Source history | Authorized inventory of existing principal contexts and predecessor/shard contexts. Recover pruned, rebound, unreadable or over-limit history offline; automatic import must reject evidence gaps. |
| Writer barrier | All old binaries and in-flight legacy mutations drained, old credentials restricted, no legacy erase/write path active. Record who verified this before setting `legacy_writers_drained`. |
| Lifecycle | Named owner and authorized context inventory for repeated bounded expiry cleanup; durable retry of incomplete erasure. A scheduler is not installed by this PR. Define retention for WAL, replicas, snapshots and backups. |
| Recovery | Restore rehearsal preserves mappings, equality reservations, aliases, retirement fences, configuration, source fences/lineage and the backed-up key/map together. Replay erasures after any older snapshot before serving. |
| Operational acceptance | Agreed workload, latency/error budgets, synthetic probes, OTel export and alert ownership; deployment window and stop/recovery decision owner. |

Runtime currently allows 16 connections per configured shard per gateway replica.
Budget `16 × replicas` on each shard, plus migrations, maintenance and monitoring;
startup validates even currently unassigned configured shards. Request admission
is bounded to 64 operations per replica. Request batches are at most 256 mappings
or references, with independent byte limits. A 413 is terminal; do not turn it
into an unbounded retry loop. There is no promise of linear throughput.

## Candidate preflight and activation

Prepare the complete candidate configuration using the settings documented in the
contract. Keep secrets in the existing secret manager. With that candidate's
runtime identity, connection environment, root key and source authentication, run:

```sh
redact-gateway --config /run/config/gateway.yaml validate-config
redact-gateway --config /run/config/gateway.yaml check-token-store
```

`check-token-store` requires indexed configuration. It validates every database's
key/map commitment, logical ID, runtime privileges and exact v1 RLS policies, then
checks every target shard and the legacy source. It has a 30-second overall bound;
indexed readiness has a two-second bound. It does not load NER, call the inference
provider, open a listener, create a context, freeze a source or change mappings.
Source authentication can log in or renew a lease. Errors are content-free.

The candidate must contain the explicit drain acknowledgement. A successful
preflight does **not** prove the real drain or authorize activation. It also does
not prove write/destruction permissions, production history recoverability,
database capacity, backup restoration or end-to-end service readiness.

Only after the gates above and separate deployment approval, promote immutable
images and the reviewed configuration through the application's GitOps process.
The map and key are startup-only; do not use hot reload to change them. Run at
least two gateway replicas with the same generation for the beta acceptance run.
First authorized access performs freeze → atomic import → source destruction →
cleanup acknowledgement. A transient failure resumes; it never falls back.

`/readyz` reports `postgres_sharded` and fails if any configured target shard or
the source is unavailable. It intentionally withdraws the whole replica when one
shard fails; requests are never rerouted to a different namespace. A source outage
also blocks lineage and migration, even for already imported contexts. `/livez`
remains a process check. Health does not prove write permissions.

## Acceptance and recovery rehearsal

Use synthetic identities in an isolated environment; retain counts/timings/error
categories, not plaintext, token labels, tenant/principal identifiers or credentials.

| Exercise | Required result |
| --- | --- |
| Existing legacy and mixed-shard history, including a nonzero retained shard | Labels unchanged; exact authorized restore parity after gateway and Platform restart. |
| Two replicas concurrently intern/reuse; retry a lost response | One stable identity; no rebinding or raw fallback. |
| Foreign tenant/principal, provider, tools, MCP/A2A | No cross-scope restore or plaintext release. |
| Interrupted import/cleanup and retry after restart | Durable checkpoints resume, frozen source stays fenced, no duplicate namespace. |
| Damaged/pruned history erasure; interrupted erasure | Source fencing and destruction still progress without safe-import proof; verification cannot report complete early. |
| One shard/source unavailable, wrong map/key, unsafe runtime grants | Startup/readiness or requests fail closed; no rerouting or namespace recreation. |
| Expiry and erasure after retry/restart | No restoration or reuse of retired identities; ciphertext cleanup completes and reservations remain. |
| Cold/warm, growing contexts, skewed tenants and multi-replica load | Record end-to-end p50/p95/p99, throughput, 429/503/413, DB rows/buffers/locks, pool pressure, CPU/RSS and source migration costs. Compare against agreed targets. |
| OTel | Spans/errors reach the chosen exporter without values, labels, credentials or high-cardinality scope attributes. |

The committed disposable harness covers backend isolation, concurrent identities,
mixed-client migration, failure/retry and preflight rejection/recovery. Storage
benchmarks are measured loopback results, not end-to-end beta measurements. Cold
cache, production trace replay, exporter operation, backup/PITR and capacity under
actual beta traffic still require operator acceptance.

## Rollback boundary

**After the first source fence, rollback to legacy-only storage is prohibited.**
The source may already be frozen or emptied. Disabling `vault.indexed`, reverting
Platform's UUID-capable routing, changing the key/map, deleting configuration or
restoring an old database without later erasure fences can lose identities or
resurrect erased data. A compatible legacy writer is tested to reject the fence;
older writers are not a safe fallback.

Stop traffic and recover forward with an indexed-compatible gateway/Platform
digest and the same key, map and complete durable state. Retry incomplete import
or destruction using the existing checkpoint. Keep all source/target fences and
identity reservations. A previous indexed-compatible digest is usable only after
its schema, label and lifecycle compatibility has been verified. Key rotation,
online bucket migration, automatic DB failover and replica reads are not provided
by this change; do not substitute them for a rehearsed recovery plan.
