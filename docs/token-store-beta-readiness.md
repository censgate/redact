# Indexed token storage: review and beta activation

This is a review/runbook package, not evidence of a deployment. The indexed
backend is opt-in; merging compatible binaries does not change the current
storage mode. No registry publication or live configuration change was performed
for this PR. See the [contract and migration protocol](../crates/redact-token-store/README.md)
and [measured storage comparison](benchmarks/token-store-20261107.md).

## Source-built beta images and public release gates

Source-built beta images use the checked-out workspace crates through path
dependencies in `Dockerfile.gateway`; they do **not** require crates.io publication.
The existing Docker build/smoke CI checks that path. Building/pushing an approved
image, verifying its NER base/provenance and recording its immutable digest remain
separate operator actions. This workspace has no container runtime; no candidate
image was built or pushed here. Public package publication is a distinct process.

See the [concrete infrastructure specification](token-store-beta-infrastructure.md)
and [two-process acceptance/load procedure](token-store-beta-acceptance.md) for
configuration, connection/rollout budgets, writer drain and recovery evidence.

The future release workflow publishes `redact-token-store` before
`redact-gateway`. It refuses to publish the gateway until the exact dependency
version is visible and not yanked in Cargo's sparse index. Local `cargo package`
verification builds normalized archives; it does not upload packages.

Read-only checks on 2026-11-09 still return HTTP 404 for
`https://crates.io/api/v1/crates/redact-token-store` and
`https://index.crates.io/re/da/redact-token-store`. The name is not registered.
crates.io's trusted-publishing documentation requires the crate to exist before
a publisher can be saved, and the publish API rejects a trusted-publishing
token for a new crate ("Trusted Publishing tokens do not support creating new
crates"). This repository does not contain a trusted-publisher record, and
none can be attached to a name that does not exist. Crate settings were not
readable from this checkout. Nothing here is a claim that a publisher is
configured for this crate or for the crates that already exist.

Before an explicitly authorized release, a crates.io owner has to do the
following outside any pull request. Do not put an API token in the repository,
a workflow, or a pull request.

1. Publish the first `redact-token-store` version with an API token. Trusted
   publishing cannot create the crate. The release job
   (`.github/workflows/release.yml`, job `publish-crates`) has no token
   fallback. It exchanges a GitHub OIDC token with
   `rust-lang/crates-io-auth-action` v1.0.6
   (`3268eb413133e2960fa4ae0e963ca76380c54cd9`). That job sets
   `id-token: write` and does not set `environment:`.
2. After the crate exists, add a GitHub trusted publisher on the crate's
   crates.io settings (Settings → Trusted Publishing → Add → GitHub):
   repository owner and repository name of the GitHub repository that runs
   this workflow, workflow filename `release.yml` (the bare filename, not a
   path), and no environment. An environment value would not match this job.
3. Confirm the release version and dependency versions agree. Existing
   immutable versions must not be overwritten. Review the exact release
   workflow revision.
4. Run the workflow only after approval. Retain its package verification and
   sparse-index results, image provenance and immutable digests in the release
   record.

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
| Isolation | Login/effective identities and their entire direct/indirect role-membership closure have no ownership, SUPERUSER/BYPASSRLS/CREATEROLE/REPLICATION, predefined server-file/program roles, schema CREATE, parent TRUNCATE, child-partition access or configuration writes (including column grants). Non-inheriting and SET-only memberships are checked; SET FALSE edges are conservatively included. Parent RLS/policies and required grants match v1. |
| Key and routing | Existing durable root DEK preserved; ordered shard IDs, matching runtime connection environment names and all 256 ownership entries identical across replicas. Operator-installed commitment and logical ID match each database. |
| Network and secrets | Reviewed GitOps config mount, secret references and PG egress; source OpenBao/Kubernetes auth, lineage access, write/metadata/destruction privileges and TLS remain available. No connection strings or key material in Git. |
| Source history | Authorized inventory of existing principal contexts and predecessor/shard contexts. Recover pruned, rebound, unreadable or over-limit history offline; automatic import must reject evidence gaps. |
| Writer barrier | All old binaries and in-flight legacy mutations drained, old credentials restricted, no legacy erase/write path active. Record who verified this before setting `legacy_writers_drained`. |
| Lifecycle | Named owner and authorized context inventory for repeated bounded expiry cleanup; durable retry of incomplete erasure. A scheduler is not installed by this PR. Define retention for WAL, replicas, snapshots and backups. |
| Recovery | Restore rehearsal preserves mappings, equality reservations, aliases, retirement fences, configuration, source fences/lineage and the backed-up key/map together. Replay erasures after any older snapshot before serving. |
| Operational acceptance | Agreed workload, latency/error budgets, synthetic probes, OTel export and alert ownership; deployment window and stop/recovery decision owner. |

Runtime currently allows 16 connections per configured shard per gateway replica.
Budget `16 × replicas` on each shard, plus migrations, maintenance and monitoring;
include rolling-surge and separate preflight processes in that budget. Startup
validates even currently unassigned configured shards. Request admission
is bounded to 64 operations per replica. Request batches are at most 256 mappings
or references, with independent byte limits. A 413 is terminal; do not turn it
into an unbounded retry loop. There is no promise of linear throughput.

## Expiry maintenance

`redact-gateway maintain-token-store` is the bounded expiry worker. Run it with the
same candidate configuration, image and runtime secrets as `check-token-store`, as
one process per generation (it keeps one batch in flight):

```sh
redact-gateway --config /run/config/gateway.yaml maintain-token-store \
  --inventory /run/maintenance/inventory.jsonl \
  --checkpoint /var/lib/redact-maintenance/cursor.json
```

The inventory is supplied by the authorized owning system (for example Platform)
and lists subject-bound contexts, one `{"tenant":"…","context":"…"}` object per
line. Mount it as a secret: it contains identifiers. The worker never enumerates
storage. For each entry it reads the target lifecycle without importing, freezing
or cleaning the legacy source:

| State | Action |
| --- | --- |
| Imported, legacy cleanup complete | `IndexedStore::purge_expired` in batches of `--batch-limit` (<=256) until a batch clears zero |
| Imported, cleanup pending | Skipped; the request path owns cleanup |
| Retired | Skipped; ciphertext was already destroyed |
| Never imported | Skipped; maintenance never starts a migration |

Expired identities stay reserved: rows keep their fingerprint and token and only
ciphertext is cleared. `IndexedStore::purge_expired` itself rejects contexts that
are not imported, so no caller can expand migration scope through maintenance.

Progress is a durable cursor (inventory SHA-256, length, pass and next index; no
identifiers) replaced atomically after every context. `<checkpoint>.lock` keeps a
single worker. SIGTERM or Ctrl-C (CronJob deadline, eviction, node drain) stops the
run, releases the lock and exits 1; a hard kill (SIGKILL, OOM) leaves the lock behind
and the next run fails closed until an operator confirms no worker runs and removes
it. Purging is idempotent, so the
interrupted context is safely repeated. An unfinished cursor bound to a different
inventory is rejected unless `--restart-pass` is given; a completed pass accepts a
refreshed inventory and starts the next pass.

Each run is bounded by `--max-contexts`, `--max-batches-per-context`,
`--max-attempts` (<=10, exponential backoff for `Unavailable`/`Busy` only) and
`--deadline-secs`. Budget and deadline stops exit 0 and resume next run.
Integrity, invalid-state, capacity and other non-retryable errors, and exhausted
retries, stop immediately without advancing the cursor and exit 1. The command
prints an identifier-free JSON summary (counts, stop reason, error category,
remaining contexts, pass age).

Telemetry uses the standard `OTEL_*` exporter settings. RED metrics:
`redact.gateway.tokenstore.maintenance.batches` (purge attempts only, by
outcome/`error.type`; eligibility lookups are not batches),
`…batch.duration` (s), `…entries_cleared`, `…contexts` (by outcome), `…retries`,
and gauges `…backlog.contexts` and `…pass.age` (s). Spans
`redact.gateway.tokenstore.maintenance.run` and `…batch` carry only backend,
limits, counts and error category. Alert on failed runs, rising backlog or pass
age, and sustained retries. The scheduler, its owner and the inventory export are
deployment-specific and remain activation gates.

### Request-path RED metrics and proposed objectives

Every indexed-store operation on the request path (`intern`, `resolve`, and
`erase` through `DELETE /v1/vault/context`) is recorded on the existing
`redact.gateway.tokenmap.operations` counter and
`redact.gateway.tokenmap.operation.duration` histogram with
`redact.tokenmap.backend="indexed"`, the fixed `redact.tokenmap.operation`, and,
on failure, a typed `error.type`: `invalid`, `retired`, `unavailable`, `busy`,
`capacity`, `integrity` or `dependency`. No identifier, label, scope or backend
diagnostic is ever an attribute. `retired` is the expected terminal answer for
an erased context; keep it out of the error rate and alert on its rate
separately. `busy`/`capacity` are overload, `unavailable` is dependency loss,
`integrity` must never occur in steady state.

Proposed objectives, for the owner to confirm (not approved SLOs): a rolling
success rate and p95/p99 duration per operation, evaluated from these series for
each replica count and for a hot principal, so the objective is the steady-state
rate, error and duration, not one large pass or a longer timeout. Alert when the
error rate (everything except `retired`) or p99 duration exceeds budget over a
five-minute window, or when `integrity` is non-zero. Choose the budgets before
the beta run, as the load matrix above requires.

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
