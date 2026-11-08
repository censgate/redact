# Purpose-built token storage (draft)

Atomic token allocation, selective resolution, permanent retirement and bounded
expiry cleanup are implemented with PostgreSQL and an OpenBao KV v2 reference
adapter. The gateway has an opt-in PostgreSQL integration. No existing settings
select it automatically; this draft must not be deployed before its migration
and release gates are reviewed.

## Contract and Platform access patterns

`Vault::intern` accepts up to 256 `(entity type, original value)` pairs and commits
atomically. Concurrent replicas reuse the winning identity; retrying after a lost
response preserves it. `resolve` fetches/decrypts distinct requested references,
then preserves input order and duplicates. Foreign, missing and expired references
are absent. No raw-data fallback exists. Crypto input and expanded response bytes
are bounded independently to 1 MiB. Deadlines include crypto and result construction;
content-free tracing spans use the gateway's existing OTel subscriber. Admission
uses a bounded semaphore and returns `Busy` without an unbounded queue.

Scope derives from authenticated tenant, principal and caller context. Gateway
integration preserves the existing subject-bound context derivation, including
Platform's principal-wide context shared across chats. Tokens do not authorize
reads. Platform selects complete owner-message pages, validated branches and useful
recall candidates before restoration; model/tool/MCP/A2A data stays tokenized.

The gateway builds request-local random placeholders, atomically interns only new
values, and replaces placeholders before provider or owner release. Proxy restoration
loads references from the outbound request; standalone restore loads references
from its input. Neither path enumerates a migrated context. Storage failures always
fail closed, even for a profile with `fail_closed: false`. Unknown references stay
unchanged. Legacy aliases preserve existing cross-kind and PERSON-normalization
reuse. Native values use entity-type-scoped equality and UUID-based numeric labels.

Backends receive keyed BLAKE3 equality indexes and AES-256-GCM ciphertext only.
Separate keys derive from a durable root; AAD binds scope, fingerprint, token and
expiry. Traces contain operation/backend/count, never identifiers, values, tokens,
credentials or ciphertext. Retention is absolute: reuse does not extend it.

## PostgreSQL partitioning and horizontal operation

Apply `src/schema.sql` with a migration role to a dedicated database. Runtime uses
NOSUPERUSER NOBYPASSRLS, owns no tables, receives schema USAGE and
SELECT/INSERT/UPDATE/DELETE on `contexts`, `entries`, `aliases` only, plus SELECT
on `configuration`. Do not grant child-partition access, schema CREATE or migration
rights. Startup rejects privileged/owner roles. Every operation binds scope and
sets the tenant transaction-locally for forced RLS. This defends missing predicates;
it does not authorize a compromised trusted service role.

Sixteen hash partitions use tenant/context. Fingerprint/token-leading indexes and
parameterized lateral queries keep point reads independent of context size.
Retirement's scope-leading expression index avoids unrelated tenants in a partition.
Real plans visit one mapping for resolve/reuse in 10,000 entries and eight rows for
a small retirement scope among 512 unrelated contexts.

`ShardedPostgres` routes 256 immutable virtual buckets to independent bounded pools.
Service replicas share the root key and explicit map; adding replicas requires no
storage rewrite. Startup validates an operator-installed key/routing commitment
and logical shard ID on each database. Wrong keys/maps/IDs or absent configuration
fail closed. A two-database test verifies replica routing, cross-shard absence and
that one unavailable pool does not reroute requests into another namespace.
This is functional isolation evidence, not a linear-throughput claim. Online
rebalance, automatic database failover and replica reads are not implemented.

## Migration protocol

Configuration is startup-only under `vault.indexed`:

- `shard_ids`: ordered stable logical names.
- `connection_env`: matching environment-variable names holding runtime URLs.
- `ownership`: exactly 256 shard indices, immutable across replicas.
- `legacy_writers_drained`: explicit operator acknowledgement of the barrier below.

Authentication, a durable existing DEK and a `vault_kv2` source are required.
The source keeps renewable Kubernetes authentication and credential lineage.
The indexed backend does not replace the predecessor graph; erasure still walks it.

1. Review both draft PRs. Upgrade legacy writers to the freeze-aware code, then drain
   all old binaries and in-flight legacy mutations before enabling indexed traffic.
   Old binaries ignore the new field; a CAS fence cannot protect against them.
   Restrict old credentials as necessary. Never run legacy erase/write routes after
   migration begins. No mixed old/new writer deployment is supported.
2. Apply schema and privileges on every dedicated shard. Compute the configuration
   commitment using `cargo run -p redact-token-store --example configuration` with
   `TOKEN_STORE_ROOT_KEY_FILE` and stdin JSON `[shard_ids, ownership]`. It prints
   only the non-secret commitment. With the migration role, insert one configuration
   row per shard containing `singleton=true`, that commitment and its logical ID.
   Runtime must never insert/update this row. Back up keys and maps securely.
3. On first authorized access, freeze the source with CAS. Validate all available
   historical labels against the current cumulative map, preserving every label,
   exact alias, PERSON alias and original expiry. Import atomically into the target.
   A stable keyed source digest makes retries idempotent despite new encryption nonces.
4. Destroy source ciphertext and older versions, preserving a permanent empty
   frozen record. Persist cleanup progress after bounded version batches. Mark target
   cleanup complete only after destruction succeeds. Timeout/restart retries resume
   the durable checkpoint; normal accesses after completion read no source mappings.
5. Verify authorized restore parity, foreign-scope denial, concurrent reuse, expiry,
   erasure and provider tokenization before considering rollout complete.

Automatic import intentionally rejects pruned/deleted/unreadable history, more than
2,048 source versions, historical label drops/rebinding, conflicting imports and
oversized snapshots (16,384 entries/16 MiB). These require offline identity recovery
from authoritative history/backups. If history was destroyed, the importer cannot
prove identities; do not invent replacements or silently start a fresh namespace.
The task did not inspect production history, so compatibility of actual existing
contexts remains a deployment gate. A new empty context imports an empty frozen
source and still receives the same permanent lifecycle protection.

## Cleanup and recovery

`retire` commits the context write fence before physical PostgreSQL cleanup, then
commits batches of at most 256 entries (eight batches per call). Alias deletion uses
an indexed FK cascade. `Busy` means retry: the fence already prevents reuse/restore.
Erase verification retries cleanup and never reports physical completion merely
because the context is fenced. OpenBao destruction records a durable version cursor;
repeated calls make progress without restarting from version one.

Erasure uses a separate CAS source fence, not the strict identity-import freeze.
Pruned, destroyed, malformed, rebound or over-limit legacy histories can therefore
be erased without proving safe import. Target retirement commits first; the source
then receives an empty permanent fence using its metadata revision, and all earlier
versions are destroyed in bounded batches. Retries preserve the destruction cursor,
including after restart or a lost fence acknowledgement. Verification of a retired
context finishes source fencing/cleanup before reporting absence. Verification of
an absent target only reads legacy existence and never creates a source record.
Source metadata, write and destruction privileges are still required; failures
remain errors until cleanup can be verified. Tests cover interrupted HTTP erasure,
both target backends and a 2,090-version source requiring multiple cleanup calls.

`Vault::purge_expired` and `IndexedStore::purge_expired` clear expired ciphertext in
bounded batches while retaining fingerprint/token reservations. PostgreSQL uses a
partial expiry index; OpenBao rewrites the bounded document and destroys prior
versions. Retry until zero. An authorized maintenance worker must supply subject-bound
contexts from its inventory; no global tenant-enumerating API or automatic scheduler
is installed here. Backups, WAL, replicas and storage-level remnants require their
own retention/erasure procedures; row updates are not physical-media zeroization.

On uncertain commit, retry the same operation. On interrupted migration, retain both
fences and retry cleanup; never fall back to legacy writes. On lost root key, stop:
restoration requires the backed-up key. Key rotation and bucket moves require an
explicit offline, fenced migration with restore parity; no automatic key ring or
online mover is provided. Database restore must restore mappings, reservations,
aliases, tombstones and configuration together. Restoring an older snapshot without
replaying subsequent retirement fences can resurrect data and is prohibited.

## OpenBao reference adapter

OpenBao implements the same atomic contract with KV v2 CAS, eight jittered retries
and a 512-KiB document limit. Its whole-document cost is measured, not hidden by the
contract. Gateway integration tests exercise it through the adapter constructor;
production configuration selects PostgreSQL. The reference adapter accepts a supplied
credential and does not renew it; production use would need renewable authentication
and HTTPS. The legacy migration/lineage client already supports Kubernetes renewal.
Never use harness dev-server credentials outside disposable tests.

## Evidence and release gates

Gateway errors preserve typed storage outcomes: invalid requests return 400,
integrity failures 409, retired identities 410, capacity limits 413, contention or
admission exhaustion 429, and unavailable dependencies 503. Bodies expose only
static error categories. The 256-reference/mapping limit is a terminal response;
the gateway does not partially release a request or retry it as an outage. Platform
tests ensure terminal statuses do not retry or advance legacy shards. OpenBao's
non-CAS HTTP 400 rejection is terminal; HTTP 413 and 429 retain capacity/busy semantics.

Platform must be upgraded with #445 before indexed writes. Native UUID-u128 numeric
labels are not machine-sized counters. For a retained legacy shard N, Platform
stores the routing envelope `N * 2^128 + native_label`, then strips it before restore.
Small legacy labels keep their existing `N * 10000 + label` encoding. Mixed native,
legacy and enveloped labels must restore through the matching context after restart.
This changes routing, never the target's token identity or principal-wide scope.

Contract tests cover concurrency, lost acknowledgements, principal/tenant isolation,
legacy alias preservation, expiry reservations, ciphertext integrity, response/crypto
budgets and deadlines. Real gateway tests migrate an OpenBao source into both targets,
restore through a second replica, race eight requests, protect a foreign principal,
verify provider tokenization and reject rebinding after erasure. See the measured
[storage comparison](../../docs/benchmarks/token-store-20261107.md); proposed production
SLOs, actual traffic traces and availability claims are not measurements.

Remaining operational gates: production history recovery where automatic import
refuses evidence gaps; scheduled expiry maintenance and backup retention; online
rebalance/key rotation/failover; end-to-end production-shaped load/OTel exporter
validation. The draft makes this crate publishable to crates.io and orders its
future publication before `redact-gateway`. An exact-version, non-yanked sparse
index check gates the gateway step and the final release verification includes
this crate. Registry ownership/trusted-publisher setup and the actual release
remain separate operational actions. Local package validation does not publish
anything. No package was published and no live resource or feature flag was changed.

## Reproduce

`cargo fmt --all -- --check`,
`cargo clippy -p redact-token-store -p redact-gateway --all-targets -- -D warnings`,
and `cargo test -p redact-token-store` run dependency-free checks. Real-backend tests
are ignored by default in ordinary Cargo runs, but `.github/workflows/token-store.yml`
runs them on every pull request against actual PostgreSQL and checksum-pinned OpenBao.
The following harness creates disposable local PostgreSQL
and OpenBao instances, two databases, restricted roles and synthetic data:

```sh
TOKEN_STORE_PG_BIN=/path/to/postgresql/bin \
TOKEN_STORE_PG_SHARE=/path/to/postgresql/share \
TOKEN_STORE_BAO_BIN=/path/to/bao \
python3 scripts/token-store/test-local.py
```

For the cross-repository mixed-shard migration contract, also set
`TOKEN_STORE_PLATFORM_TEST_DIR` to the companion Platform #445 checkout and put
Go 1.26 on `PATH`. The gateway integration tests start disposable legacy/indexed
loopback HTTP routers and run Platform's actual Go client against both backends.
This optional private-checkout check passed locally; public Redact CI runs the
backend and HTTP migration contracts without requiring private repository access.

For benchmarks build `cargo build --release -p redact-token-store --example compare`
and add `TOKEN_STORE_RUN_BENCH=1`, `TOKEN_STORE_BENCH_OUTPUT=/tmp/token-store-results`
and `TOKEN_STORE_BAO_JSON_STRINGS=100000` for the documented tuned listener.
The harness uses ephemeral loopback ports and checks child liveness, postmaster PID
and the temporary data directory before setup mutations. `test_harness.py` covers
readiness/identity failures. Do not run the trust-auth disposable cluster on a host
with untrusted local users. No deployed service is contacted.
