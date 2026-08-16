# redact-verify

Independent offline verifier for Censgate ledger evidence packs.

Apache-2.0. **No `redact-core` dependency.** Default path does not dial the network and does not call `GET /v1/evidence/{id}/attestation`.

```bash
cargo install redact-verify
redact-verify --pack <file> --pubkey <file> [--online] [--format json]
```

## Checks

| Check | Result |
|-------|--------|
| Chain internal consistency | pass / fail |
| Tip signature fields present | pass / fail |
| `body_hash` recomputation | pass / fail |
| `body_signature` | pass / fail (`builder_signed` only) |
| R1 — `events_anchored` | pass / fail |
| R2 — `pack_anchored` | pass / fail / **unproven** + `pack_anchored_reason` |
| `complete_within_range` | true / false |
| `range_covers_tip` | true / false |

Exit: **0** only if every check passes **and** R2 is `pass`. **1** any fail or R2 unproven. **2** malformed.

`attestation.status` is a hint. `pack_anchored` is computed. Stripped attestation is `unproven` (`r2_stripped`), never pass.

Compiled-in trust: `src/trust.rs` (anchor key ids) and `trust/eutl-2026-08-15/` (EUTL snapshot date). Pack-supplied keys cannot pass the offline test. `qualified` is computed here, never copied from the receipt.

`--online` is accepted and unused. It does not dial the network and is never required for a pass.
