# SPIKE: OpenBao tokens cluster (high concurrency / low latency)

This is **not** a claim that OpenBao cannot scale. KV v2 + Raft is a proven
write path when the cluster is sized for it. The claim is: the AKS **secrets**
OpenBao (`100m`/`256Mi`, Raft multiplier 5, shared with ESO) will not meet
gateway p99, and **must not** be retuned to try.

Run this SPIKE only against **`openbao-tokens`**.

Related: cloud-infrastructure PR
[#111](https://github.com/censgate/cloud-infrastructure/pull/111)
(`infrastructure/openbao-tokens`),
[`scripts/bench-gateway-ner.sh`](../../scripts/bench-gateway-ner.sh).

## Two deployments

| Cluster | Workload | Tune for |
|---|---|---|
| `openbao` (secrets) | ESO, `CENSGATE_TOKEN_DEK`, JWT, Stripe | Read-mostly. Leave as-is. |
| `openbao-tokens` | Gateway `vault_kv2` session maps | Write + CAS, Premium SSD, `performance_multiplier=1`, 2 CPU / 2Gi |

Gateway `CENSGATE_VAULT_ADDR` →
`http://openbao-tokens.openbao-tokens.svc.cluster.local:8200`.

The DEK still comes from the **secrets** cluster via ESO. Token blobs never
land there. Kubernetes auth role is `redact-gateway`, never `external-secrets`.

## Hypotheses

**A. Operator knobs** (cloud-infrastructure `openbao-tokens`) — own
HelmRelease/namespace/PVCs, `max_versions=1`, `cas_required=true`, Raft
multiplier 1, Guaranteed QoS, Premium SSD.

**B. Client knobs** (this repo) — cache the Kubernetes-auth token and renew
before lease expiry; jitter CAS backoff (8 attempts); skip `put` when
`mappings` is empty; cache `/readyz` health for 2s so probes do not serialize
on the Raft leader.

**C. Key shape** — today one JSON blob per session (CAS domain = session).
Alt: one key per token. Measure same-session conc 20 before changing.

**D. OpenBao 2.5+ read standbys** — only if the running image actually serves
KV reads on standbys. Chart `0.28.3` does not guarantee that.

**E. Escape hatch** — Transit-on-tokens + Valkey for blobs **only** after A–C
miss the bar on this cluster. Not the default. No plaintext in Redis. No
session affinity.

## Experiment design

Hold NER weights fixed. Drive `POST /v1/redact` tokenize + `POST /v1/restore`.

```bash
GATEWAY_URL=http://127.0.0.1:8080 \
GATEWAY_API_KEY=… \
./scripts/bench-gateway-ner.sh
```

| Slice | What we learn |
|---|---|
| Unique sessions, conc 1/20/100 | Leader write / fsync floor |
| Same session, conc 5/20 | CAS collision rate and retry tax |
| Restore-only, n replicas | Read path; standby benefit if 2.5+ |
| After each of A, then B, then C | Which knob moves p50/p99 |

## Draft pass bar

Refine after first numbers. Do **not** quote the 32× Presidio figure here
(that number is `redact-api`, conc 1, pattern-only).

- Unique-session tokenize OpenBao overhead: **p50 < 5 ms**, **p99 < 20 ms**
- Same-session conc 20: **< 1%** fail-closed CAS exhaustion
- Restore-after-scale: **100%** (pod B opens a token minted on pod A)

## Go / no-go

- **Go:** stay on KV v2 session blobs against `openbao-tokens`.
- **No-go:** only after A–C miss the bar on that cluster. Then evaluate
  Transit + Valkey. Document measured numbers in this file before changing
  the default architecture.
