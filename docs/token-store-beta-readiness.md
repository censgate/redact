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
| Source history | **Hard gate: Source history inventory** (see [Pruned legacy history](#pruned-legacy-history)). Authorized, identifier-free inventory of every existing principal and predecessor/shard context, run immediately before activation and again after the writer drain: `current_version`, `oldest_version`, retained count, deleted/destroyed flags, frozen flag and mapping count, with every sealed value opened. Include key/version creation times, updated time and retained TTLs. Classify complete, proven-pruned or blocked/unproven; pruned contexts need pinned fingerprints plus writer/TTL/rollback attestations. Recover blocked history offline or obtain an explicit deletion/reset decision. Zero unresolved blocked contexts before `legacy_writers_drained` is set. Activation without a recorded inventory is not allowed. |
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

## Pruned legacy history

**Strict by default.** Any source whose oldest retained version is greater than
1 fails with `Integrity` (`409 token integrity check failed`). A contiguous,
cumulative tail cannot prove identity across missing history: after TTL expiry,
legacy `put` resets mappings and can reuse `[PERSON_1]` for a different value.
Pruning can remove the version that would reveal this rebinding. Complete history
still verifies every version from 1, with no operator evidence required.

Pruned import is an explicit opt-in, requiring both a reviewed, digest-pinned
operator evidence artifact and these checks on every first freeze:

- Retained versions are contiguous through the current version, live, readable,
  not deleted/destroyed/frozen/malformed, and every retained mapping reappears
  unchanged in the latest. At most 2,048 retained versions are checked; the
  lifetime counter may be larger.
- The evidence has not expired and lists this exact path digest. Its fingerprint
  matches the live `current_version`, reported `oldest_version`, key
  `created_time` and `updated_time` exactly, including timestamp strings. A new
  write, fence or generation change invalidates the entry.
- The key's RFC3339 creation time is at or after the attested `identity_epoch`.
  Pre-epoch generations are ineligible (see [Identity epoch](#identity-epoch)).
- Let W be the latest version's creation time minus the key's creation time.
  Every retained payload, including the latest, has
  `expires_at - version.created_time >= W`. This excludes the expiry-reset
  mechanism under the attested writer/TTL history; a self-consistent tail alone
  does not.
- Retained creation times are non-decreasing, and each consecutive gap is
  strictly less than the earlier version's TTL. Unparseable times reject.
- `IndexedStore::prepare` requires the target context to be Absent before import.
  CAS protects the verified source snapshot; a racing put is either included in
  the frozen snapshot or invalidates the proof, never silently discarded.

The operator artifact's JSON schema is `redact-legacy-pruned-evidence-v1`, with
`evidence_id`, RFC3339 `generated_at`, `not_after`, `identity_epoch`, and `entries`.
Each entry key is lowercase hex SHA-256 of `b"redact-legacy-pruned-v1\0"` followed
by the KV path (without the mount). Each entry contains `current_version`,
`oldest_version`, `key_created_time` and `updated_time`; preserve the metadata's
exact strings. It contains no mappings. Unknown fields are rejected. The loader
verifies the file's pinned SHA-256, schema, expiry, generation time (at most five
minutes ahead), epoch (not after generation or in the future), at most 100,000
entries and 64-hex entry keys. Missing, malformed, expired or digest-mismatched
evidence fails startup, without logging identifiers or file contents.

Configure the source under `vault` (alongside `indexed`):

```yaml
vault:
  legacy_pruned_history:
    evidence_file: legacy-pruned-evidence.json
    evidence_sha256: "<SHA-256 of the exact reviewed file bytes>"
```

Relative paths resolve against the YAML document directory, like `jwt_path`.
Only the file path and digest appear in configuration summaries/JSON. This is a
restart-required setting; absence keeps strict rejection. Programmatic callers
use `LegacyHistoryPolicy { pruned: PrunedHistoryPolicy::Proven(PrunedProof {
evidence }), max_retained_versions: 2048 }`. There is no allowlist-only bypass of
the live proof. Already-frozen snapshots remain idempotent and are not re-proven.
Scope is exactly the inventoried entries until `not_after`; re-inventory to
re-issue evidence after source drift.

### Identity epoch

When evidence is configured, `identity_epoch` is the instant from which the
history of every legacy context is trusted. It applies to **every** first freeze,
not only pruned ones: a key whose KV v2 `created_time` is before the epoch is
rejected with `Integrity` (409) even when its history is complete from version 1.
A complete history proves the retained versions are consistent with each other;
it cannot show that labels were not minted elsewhere before the migration.
Deployments with no evidence configured have no epoch and behave exactly as
before (complete history verified from version 1, pruned history rejected).
Already-frozen snapshots and contexts with no source key are unaffected.

**Beta: `identity_epoch = 2026-09-26T18:14:16Z`**, the first write on
the migrated OpenBao store (`BETA_MIGRATION_IDENTITY_EPOCH`; the enforced value is
always the one in the reviewed, digest-pinned evidence file). Why:

- The OpenBao data was copied at the storage layer on 2026-09-26. The previous
  gateway moved to a separate Raft store (`openbao-tokens`, mount `tokens/`,
  `max_versions=1`) on 2026-09-10 01:17Z, and that store was not carried over.
  The migrated KV v2 store has no creates or updates between 2026-09-10 01:17:08Z
  and 2026-09-26 18:14:16Z.
- Any context whose key was created before the epoch may have received labels
  during that window only in the Raft store. Importing it would risk reusing a
  label for a different value, so it fails closed. The supporting evidence is a values-free metadata
  inventory plus deployment and git history, kept with the reviewed operator
  evidence.
- Consequence for beta: contexts created before the epoch (about 80 paths dated
  2026-09-03 to 2026-09-10 in the inventory) remain 409 until they are reset or
  recovered offline under the tenant/principal reset decision below. Contexts
  created at or after the epoch import normally.
- Telemetry: `pre_epoch_context` (complete history) and `before_epoch` (pruned
  history) are distinct from every other rejection reason.

The epoch can only be moved earlier by new evidence; never to make a rejected
context pass without that evidence.

**Accepted residual risk: writer-history and rollback attestation.** Since
`identity_epoch`, every writer must have used cumulative CAS merge with a lifetime
TTL sufficient for W, the write role must have been gateway-only, no manual or
foreign writer may have changed the data, and no Raft snapshot restore may have
rewound storage. Gateway writer provenance (cumulative CAS merge since `db77542`)
and deployed TTL/config history support that review. KV metadata cannot establish
writer history or absence of rollback; without an audit device these are explicit
operator attestations backed by policy/deployment evidence. They are never
inferred from a cumulative tail, an allowlist or telemetry. Without those
attestations, pruned contexts stay rejected.

**Telemetry.** Only the replica winning a proven pruned freeze emits
`token_store_legacy_pruned_import` and increments
`redact.gateway.tokenstore.legacy.pruned_imports`, with version counts only.
Rejected proofs emit `token_store_legacy_pruned_rejected` and increment
`redact.gateway.tokenstore.legacy.pruned_rejections` with a bounded `reason`:
`evidence_expired`, `no_entry`, `fingerprint_mismatch`, `before_epoch`,
`pre_epoch_context` (complete history created before the epoch),
`bad_timestamp`, `ttl_below_exposure`, `non_monotonic_versions`,
`retained_gap_exceeds_ttl`, or `invalid_history` for structural failures.
Neither event/counter includes path, tenant, principal, token or value. Unexpected
imports, proof rejections or integrity errors are stop signals.

**Operator requirements.**

1. **Source history inventory is a hard gate.** Run an authorized inventory of
   every existing principal and predecessor/shard context immediately before
   activation and again after writer drain. Record values-free key/version
   metadata, TTLs and structural checks; separately verify every sealed value
   can be opened without placing values in the artifact. Classify complete,
   proven-pruned and blocked/unproven contexts. Pin exact fingerprints and
   record writer/TTL/rollback attestations. Zero unresolved blocked contexts
   before `legacy_writers_drained`; no activation without the recorded inventory.
2. Set `max_versions` explicitly on the KV v2 engine with
   `bao write secret/config max_versions=<n>` and read `secret/config` back to
   record it. `sys/mounts/<mount>/tune` does not set it and leaves the default 10.
   Per-key metadata can override retention and must also be inventoried. Raising
   retention never recovers versions already pruned.
3. If identities cannot be proven or recovered offline, a tenant/principal reset
   needs **Mark's explicit deletion decision**, including scope and approval
   time. Platform must issue a new durable context generation, delete or rewrite
   old dependent token references to unrecoverable markers, and preserve an empty
   erasure fence on the old source with bounded destruction. Do not purge the
   old path or re-mint old labels. Record values-free before/after evidence.
   Reset/deletion is an operator decision, outside this code change.

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
