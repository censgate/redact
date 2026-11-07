# Token-store contract (draft, not wired into the gateway)

This crate separates atomic token allocation, selective resolution and permanent
context retirement from whole-session serialization. It is a storage foundation;
adding it to the workspace does not change the running gateway or migrate data.

## Contract and Platform access patterns

`Vault::intern` accepts up to 256 `(entity type, original value)` pairs. The entire
batch commits atomically; concurrent replicas reuse the winning identity. A retry
after a lost response finds that identity without a process-local counter or map.
`resolve` accepts only requested references and preserves input order and duplicates.
Foreign, missing and expired references are absent. No raw-data fallback exists.
`retire` permanently fences a scope and removes its stored ciphertext. Keep the
tombstone: deleting it would permit a stale writer to resurrect the namespace.

The service must derive scope from authenticated tenant and principal, never from
token possession or unverified request fields. Use one stable principal-wide
context across that principal's conversations, memory, owner display and tools.
Changing a chat must not change this context. Page selection, branch ancestry and
memory relevance are Platform responsibilities before requesting token resolution.
Do not restore model/tool/MCP/A2A output; owner display remains a separate boundary.

The backend sees keyed BLAKE3 equality indexes and AES-256-GCM ciphertext. Separate
index and encryption keys are derived from a durable root key. AAD binds scope,
fingerprint, token and expiry. Traces contain operation, backend and item count,
never scope, values, tokens, credentials or ciphertext. The `tracing` spans can use
the gateway's existing OTel subscriber when integration lands; this crate does not
install a subscriber or exporter. Admission is a bounded semaphore without an
unbounded queue, and each operation has a deadline. An uncertain commit returns an
error; retry the same values. Overload returns `Busy`.

Resolve deduplicates references before backend fetch and decryption, then restores
request order. Sealed bytes available for crypto and expanded plaintext responses
are independently bounded to 1 MiB. Oversized results fail as a whole before
duplicate expansion. PostgreSQL checks the aggregate sealed-byte budget inside the
query so an oversized batch is not transferred into the service. The request
deadline covers backend I/O, decryption and response construction; synchronous
crypto is bounded by bytes and checked between items and before returning.

## PostgreSQL

Apply `src/schema.sql` with an operator migration role to a dedicated database.
Use a separate NOSUPERUSER NOBYPASSRLS runtime role which owns no tables, with
schema USAGE and SELECT/INSERT/UPDATE/DELETE on the two parent tables only. Do not
grant child-partition access, schema CREATE or migration privileges. Startup
rejects superuser, BYPASSRLS and table-owner roles. Configure a finite pool size
and acquisition timeout. All queries bind scope; transactions also SET LOCAL the
tenant for forced row-level security. RLS is defense in depth against missing
tenant predicates, not authorization against a compromised trusted service role.

Sixteen hash partitions use `(tenant, context)`, so a large tenant's principals can
spread across partitions. Lookup indexes lead with fingerprint/token, followed by
scope; lateral point queries prevent context-wide joins. The real-database plan
test checks visited mapping rows for resolve and reuse at 10,000 stored mappings,
including the fresh-partition case before ANALYZE. Intern and retire serialize on
one context row across replicas; independent contexts do not share that lock.
Retirement deletes all entries in the scope and therefore scales with scope size.
An explicit scope-expression index keeps that deletion from scanning unrelated
tenants or contexts in the partition. A regression checks the delete plan with
512 unrelated contexts alongside the selective resolve/reuse plan tests.

`ShardedPostgres` routes 256 stable virtual buckets to independent database pools.
All replicas must share the same immutable ownership map and root key. Adding a
replica requires no storage rewrite. Adding a database is supported by explicitly
assigning buckets, but changing existing ownership requires an offline, fenced
migration. Online rebalancing, routing-generation validation, failover and replica
reads are not implemented. No multi-database throughput claim is made here.

## OpenBao KV v2 reference adapter

KV v2 CAS makes intern/reuse and retirement atomic across replicas. The adapter
still reads and rewrites a whole context document. It is a comparative reference,
not a claim that KV v2 provides selective indexed lookup. Documents are bounded to
512 KiB; the server can impose lower JSON complexity or request limits. CAS has an
eight-attempt jittered retry budget. Erasure writes a permanent tombstone, then
destroys older versions in bounded requests. Retrying erasure completes version
destruction. Operator policies must permit those destroy requests and preserve
tombstones. Long version histories can exceed the operation deadline and require
repeated calls; a checkpointed maintenance job is still needed for that case.

Production integration must use HTTPS, a narrowly scoped mount credential and
renewable authentication. This initial adapter accepts a supplied credential and
does not implement renewal. Never use the test harness's dev-server authentication
outside the isolated local harness. Backups and replicas require separate retention
and erasure policies for both backends.

## Migration and remaining release gates

Do not switch existing gateway traffic to this crate. Existing sequential token
identities and sealed whole-map data are not imported. New UUID-based numeric
references preserve the bracketed syntax, but value canonicalization is explicitly
entity-type-scoped and does not match all legacy `by_value` behavior. A safe rollout
needs an importer that preserves every existing token identity, validates collisions
and scope, fences legacy writers, verifies restore parity, and records retirement
and expiry reservations. A documented explicit new namespace is another option
only if old history remains resolvable through an authorized legacy reader. Neither
mechanism is implemented here. Do not silently mint replacements for old mappings.

Root-key rotation, routing changes and context changes must never happen implicitly.
There is no key-ring or migration tool in this draft. Logical expiry prevents reads
and rebinding but retains ciphertext until retirement; expiry-time physical cleanup
with durable reservations is outstanding. Missing-key and configuration-generation
startup checks, gateway HTTP/auth integration, token syntax compatibility tests,
field batching, OTel exporter validation and production fault/recovery tests remain
release gates. The facade itself is not a caller authenticator.

## Reproduce

Run `cargo fmt --all -- --check`,
`cargo clippy -p redact-token-store --all-targets -- -D warnings`, and
`cargo test -p redact-token-store` for checks without dependencies.

The real-backend tests are explicitly ignored unless selected. The local harness
creates throwaway PostgreSQL and OpenBao dev instances, applies the schema using an
owner, grants a restricted runtime role, and runs all contract/plan tests. Supply
paths to installed binaries; no deployed service is contacted:

```sh
TOKEN_STORE_PG_BIN=/path/to/postgresql/bin \
TOKEN_STORE_PG_SHARE=/path/to/postgresql/share \
TOKEN_STORE_BAO_BIN=/path/to/bao \
python3 scripts/token-store/test-local.py
```

For the comparison, build `cargo build --release -p redact-token-store --example compare`
and add `TOKEN_STORE_RUN_BENCH=1`, `TOKEN_STORE_BENCH_OUTPUT=/tmp/token-store-results`
and, to reproduce the documented tuned run, `TOKEN_STORE_BAO_JSON_STRINGS=100000`.
The latter changes only the disposable server's additional listener. Bindings use
temporary loopback ports. Before setup writes the harness checks its PostgreSQL
child process, postmaster PID and reported temporary data directory; an unrelated
listener cannot satisfy readiness. `python3 scripts/token-store/test_harness.py`
exercises failure cases. Do not run this harness on a shared host
with untrusted local users (the disposable PostgreSQL cluster uses trust auth).
