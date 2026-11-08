# Indexed token storage: proposed beta infrastructure specification

This is a reviewable specification, **not an applied manifest or an activation
approval**. It supplements the [activation runbook](token-store-beta-readiness.md)
and [synthetic acceptance procedure](token-store-beta-acceptance.md). Values marked
operator evidence must be resolved in the infrastructure PR before activation.

## Verified source facts and available resources

On 2026-11-08, infrastructure source revision
`250b71214a48afe54d1448b7d11e04876bfc2e4a` still defines one legacy gateway replica
under `apps/aks-censgate/platform`, no indexed configuration/PG environment refs,
and no gateway PG egress. Its collector receives OTLP on 4317/4318 and exports
traces/metrics to Azure Monitor. Source configuration is not proof of live state.

The implementation workspace has PostgreSQL 17 and OpenBao 2.7.2 binaries and can
run isolated child processes. It has no Docker/Podman daemon, Azure CLI, kubectl,
Helm or Kustomize. No live cloud account, cluster capacity, database, secret,
backup, collector destination or registry-owner setting was queried.

`Dockerfile.gateway` copies the workspace manifests, lockfile **and crates** and
builds `redact-gateway` with its path dependencies. Therefore a source-built beta
image does **not** require publishing `redact-token-store` to crates.io. The
existing Docker CI job builds and smoke-tests this path. Public crate release
ordering/ownership is a separate gate. Image-registry push/pull permission, final
image provenance/digest and NER-base availability remain image-release gates.

## Resource specification for the infrastructure reviewer

All names below are logical names, not existing cloud resource identifiers.
Use Azure `centralus` and the current approved GitOps target. Do not recreate a
deprecated beta cluster or connect this experiment to production data.

| Resource | Proposed configuration | Evidence required before use |
| --- | --- | --- |
| Two isolated shard servers | Dedicated PostgreSQL 16 servers, one `token_store` database each; logical IDs `beta-token-a`, `beta-token-b`; private access only; no public firewall rule. Initial proposal: 2 vCPU/8 GiB, 128 GiB auto-grow each. | Operator confirms quota, cost, available SKU, private DNS/TLS and separation from application databases. These sizes are starting proposals, not measured capacity. |
| Runtime identity | Separate least-privilege login per shard, no ownership or privileged role memberships; fixed grants below. | Exact production preflight passes through the actual runtime endpoint on every shard. |
| Schema owner | NOLOGIN migration owner; separate short-lived migration login. Direct port 5432 for schema work. | Ownership, schema checksum, partition/index definitions and operator identity recorded without credentials. |
| Runtime pooler | Existing infrastructure convention is transaction-pooled PgBouncer on 6432. Require named prepared-statement support and bounded server/client pools. | Run all contracts through the selected pooler and TLS path. Direct local tests do not establish pooler compatibility. Any direct-5432 exception needs explicit infra review. |
| Gateway deployment | Two replicas; same immutable image, root key, config generation and routing map. Preserve current 25% surge / 25% unavailable strategy. | Two ready replicas on separate nodes; capacity for a third during rollout. Do not reduce availability to make scheduling fit. |
| Gateway scheduling | Retain required workload/node-pool constraints and tolerations. Prefer pod anti-affinity across hostnames; verify actual placement. PDB `minAvailable: 1`. | Two suitable nodes and rollout headroom. PDB alone does not establish rollout availability. |
| Gateway resources | Retain current request/limit: 4 CPU; 512 MiB memory request / 2 GiB limit per replica pending NER load measurements. | 8 CPU steady / 12 CPU surge capacity, plus other workloads; measure RSS/OOM and CPU throttling with the real model. No memory increase is claimed validated. |
| Config/secret wiring | Versioned ConfigMap mounted read-only at `/run/config/gateway.yaml`; `--config` argument. Secret refs for two runtime URLs; reuse existing DEK, inbound auth and source scope. | Approved secret-manager objects, source credential permissions, CA trust and consistent config checksums. Never put URLs with credentials or keys in Git. |
| Maintenance | Dedicated approved worker/runner with subject-bound inventory and bounded concurrency; no general SQL cleanup cron. | Worker implementation/owner and durable retry ledger exist. The current gateway exposes a Rust maintenance method, not an expiry CLI or installed scheduler. |
| Backups | Proposed 14-day regional PITR retention, encryption, deletion protection and access audit; explicit approved backup geography. | Measured restore/replay rehearsal and retention approval. Retention is not a ciphertext-erasure guarantee. |

The new runtime has a hard maximum of 16 client connections per configured shard
per process, a two-second pool-acquire bound and 64 admitted operations per
replica. For two replicas reserve 32 client connections **on each shard**; a
three-pod rolling surge can consume 48. A simultaneous preflight process can add
another 16: sequence it before rollout or budget 64 plus migration/maintenance/
monitoring. Configure PgBouncer server-side limits from measured DB capacity,
not this client maximum. Reserve headroom and stop load on sustained queues.
Do not install an unbounded HPA; its replica maximum must fit this same budget.

PgBouncer must preserve the intended backend runtime identity. Its
[`max_prepared_statements`](https://www.pgbouncer.org/config.html#max_prepared_statements)
must support the SQLx protocol-level prepared statements used here. Verify
transaction-local tenant settings, reconnects and alternating principals through
the actual pooler. Do not enable statement pooling or silently change to an owner
account to make preflight pass.

## Database bootstrap specification

Execute only after a separately reviewed target selection, on each fresh shard.
Use the committed `crates/redact-token-store/src/schema.sql` under the migration
owner, then the following grant shape. Credential provisioning is external.

```sql
CREATE ROLE token_runtime LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA redact_tokens_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA redact_tokens_v1 TO token_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    redact_tokens_v1.contexts, redact_tokens_v1.entries, redact_tokens_v1.aliases
    TO token_runtime;
GRANT SELECT ON redact_tokens_v1.configuration TO token_runtime;
```

No child-partition grants, default grants, TRUNCATE, configuration writes or
schema CREATE. The schema owner must differ from runtime. Review the entire
membership closure, including SET-only roles. Bootstrap scripts are not migration
credentials for the running gateway. Require `sslmode=verify-full`, the approved
CA trust path and expected private hostname in both runtime URLs. A successful
TCP connection or `sslmode=require` alone does not prove hostname verification.

Install the configuration singleton on each database with that shard's logical
ID and the **same** key/map commitment. Generate the commitment using
`cargo run --locked -p redact-token-store --example configuration`, with the
existing base64 DEK supplied via protected `TOKEN_STORE_ROOT_KEY_FILE` and the
JSON pair `[shard_ids, ownership]` on stdin. It prints only the commitment. Never
replace the DEK or initialize a new generation to bypass a mismatch.

The proposed fixed mapping is `ownership[b] = b % 2`, for all 256 buckets. Use
this only for a new indexed generation; an already initialized map is immutable.
Generate the **indexed section** for review without embedding credentials:

```python
import json
print(json.dumps({"shard_ids": ["beta-token-a", "beta-token-b"],
                  "connection_env": ["TOKEN_STORE_PG_A", "TOKEN_STORE_PG_B"],
                  "ownership": [b % 2 for b in range(256)],
                  "legacy_writers_drained": False}, indent=2))
```

This is an intentionally unactivatable candidate: a false drain acknowledgment
must fail validation. Phase A omits `vault.indexed` entirely. Phase B changes the
acknowledgment only after the verified writer barrier, retaining the source
backend, address/mount/prefix, root key, TTL and authenticated principal mapping.
Both replicas use an identical ordered shard list and map. The commitment is not
a load-balancing knob; moving a bucket requires a separate migration design.

## Exact GitOps change inventory

Prepare these changes in the current infrastructure overlay, reviewed together:

1. New versioned gateway ConfigMap and volume/argument wiring, with config digest
   annotation on the Pod template. No inline secrets or hot reload of indexed
   settings. Keep the legacy Phase A and activated Phase B revisions distinct.
2. ExternalSecret references for `TOKEN_STORE_PG_A` and `TOKEN_STORE_PG_B`, plus
   read-only CA mount if required. Preserve inbound API-key/OIDC principal
   identity and the root DEK. Source service credentials may be replaced through
   their approved process; principal credentials must not be rotated as a drain
   shortcut because their identity/lineage affects existing tokens.
3. Gateway replicas=2, approved immutable image digest, current scheduling and
   security context, preferred anti-affinity and PDB. Preserve `/livez` and
   `/readyz`; give readiness at least the application's two-second dependency
   deadline (propose three-second probe timeout). Keep liveness independent of DB
   availability to avoid restart loops. Record startup/model warm-up time.
4. Gateway NetworkPolicy egress to exact approved private shard CIDRs/ports and
   any required secret-auth endpoint; retain scoped DNS, source OpenBao and OTLP.
   Do not add `0.0.0.0/0`, an Internet provider route, or a public DB endpoint.
   Kubernetes IP policies do not resolve DNS names: coordinate stable subnet/IP
   rules and Azure firewall/private DNS with the networking owner.
5. Allow the synthetic runner to reach both peer endpoints and the collector in
   an isolated environment. Do not expose a public gateway or use demo tenants.
6. Collector changes only if needed for the selected exporter/allowlists. Current
   source already has traces and metrics pipelines; delivery/auth/capacity still
   require end-to-end evidence. Keep raw SQL parameters, context IDs, tokens,
   bodies and credentials out of telemetry and query logs.

The gateway's OTLP/HTTP dependency now uses the blocking client appropriate for
default SDK batch processors and periodic readers; the local real-export test
guards delivery. Keep the selected protocol explicit. Review the
[OTLP client feature definitions](https://docs.rs/opentelemetry-otlp/0.33.1/opentelemetry_otlp/#feature-flags)
before enabling another HTTP client feature: async-client selection takes
precedence when features are unified. Actual gRPC/TLS delivery to the approved
collector remains an operator test.

The current deployment's percentage strategy rounds to one surge pod and zero
unavailable pods at two replicas; see
[Kubernetes rollout rules](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#rolling-update-deployment).
Draining old writers for first activation is a separate barrier, not an ordinary
rolling update across incompatible storage modes.

## Writer barrier and recovery ownership

The release owner records: old/new image digests, config generation, affected
writer inventory (gateway, API/worker, maintenance, migration and direct KV
clients), queued-job pause state, traffic stop time, shutdown completion and
source credential cutover. Stop admission of new mutations, allow bounded
in-flight work to finish, and prove every old writer is stopped. Prevent stale
controllers/jobs from recreating old binaries. New binaries must pass preflight
before traffic resumes. Readiness and the configuration boolean do not prove
this barrier. A single old process can ignore source fences.

Back up all shard tables including configuration, aliases and reservations;
source fences/lineage and cleanup checkpoints; key material and the immutable
routing map through their approved secret/backup systems. Restore into **new,
quarantined endpoints**, with no gateway traffic and no automatic source import.
Recover WAL and all later erasure/retirement decisions before exposing data.
Verify imported identities, expired reservations and deleted-context denial.
If the recovered mapping/fence state cannot be reconciled to the accepted
recovery point, keep affected scopes unavailable; do not mint a replacement
namespace or fall back to source ciphertext.

Azure PITR restores a server and has workload-dependent recovery time; see the
[backup/restore documentation](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore).
An RPO/RTO target is not a measurement. Propose RPO <=5 minutes and RTO <=60
minutes for the isolated rehearsal, subject to owner approval and measured
results. A backup older than an erasure cannot be served without replaying it.
No automated erasure replay or cross-system backup coordinator is provided here.

Maintenance must call `IndexedStore::purge_expired` with an authorized
subject-bound context, limit <=256, bounded retries and a durable cursor over the
authorized inventory; repeat each context until zero. Restrict the initial
inventory to already imported contexts; do not expand migration scope through
maintenance's preparation path. Propose one worker and one
batch in flight per shard initially. Record counts/backlog age only. Never delete
identity reservations, enumerate live subjects into logs, or implement expiry by
dropping partitions. A concrete worker/runner and its authorization source remain
an activation prerequisite; assigning an owner alone does not implement it.

After any source fence, recover forward using compatible gateway and Platform
images with the same root key/map. Do not disable indexed storage, restore an
old source snapshot into traffic, or advertise generic image rollback as safe.
