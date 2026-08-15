# EUTL snapshot 2026-08-15

Pinned European Union Trusted List snapshot date for `redact-verify`.

`qualified` is computed from this snapshot (QTST trust-service type + QCStatement at the token `genTime`). A live EUTL fetch is never used. A stale or empty snapshot cannot make `pack_anchored` or `events_anchored` pass as qualified.

This directory does not ship operator QTSA credentials. Tokens that do not chain here are `qtsa_unqualified` / `unproven`, never pass.
