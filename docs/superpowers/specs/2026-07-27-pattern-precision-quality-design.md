# Pattern-Default Precision & Quality Harness

**Date:** 2026-07-27  
**Status:** Draft for review  
**Owner:** Censgate / redact-core  
**Related:** anon-pii comparison (`tcheuD/anon-pii` shared-family diagnostic); Approach 1 (validator hardening first)

## Goal

Improve **pattern-default** detection **precision** for `censgate/redact` with a durable, owned quality corpus and CI ratchet—without mixing optional NER into the score, and without a recall-first push until the precision floor holds.

## Non-goals (wave 1)

- Formatted-value recall (spaced/hyphenated cards, Cisco MAC, intl E.164, fullwidth email, etc.)
- NER / `:full` accuracy work, or merging NER into the pattern score
- Latency/throughput optimization
- Gateway or OpenClaw changes
- Public “we beat X” marketing claims against third-party scoreboards

## Decisions (locked)

| Decision | Choice |
|----------|--------|
| Priority mix | Pattern accuracy + measurement harness primary; NER packaging secondary later |
| Precision vs recall | **Precision first** |
| Success bar | **C:** adapt comparable cases as fixtures **and** own long-term corpus/CI |
| Approach | **1:** validator/context hardening behind an owned harness, then careful recall |

## Context

A pinned comparison in `tcheuD/anon-pii` (`docs/comparison-redact.md`) scored pattern-default `redact-cli` poorly on a shared-family exact-span protocol. Arithmetic matched their artifact, but:

- The corpus is project-owned by anon-pii (home-field).
- Exact byte-span matching double-counts partial detections as FP+FN.
- NER would not fix most misses (no PERSON/ORG/LOC labels in that slice).
- Several FPs are real precision debt: impossible dates, null/broadcast MAC, order-like phone/card, commit-shaped SHA1, junk `DOMAIN_NAME` after email misses.

We respond by **owning measurement** and fixing **precision** first.

## Architecture

```
testdata/quality/
  README.md                 # provenance, how to run, config contract
  pattern-v1.json           # cases + expected exact spans
  pattern-v1-baseline.json  # ratchets (FP/precision floors)

crates/redact-core/
  tests/quality_pattern_v1.rs   # loads corpus, scores, asserts baseline
  src/recognizers/
    validation.rs               # calendar/MAC/card/… validators
    pattern.rs                  # patterns, context, scoring
```

**Fixed evaluation config (pattern-v1):**

- `AnalyzerEngine` default pattern registry only
- Language: `en`
- Minimum score: `0.5`
- **No NER** registered
- No entity-type filter
- Matching: exact UTF-8 byte span + entity type/family
- No post-hoc prediction filtering in the scorer

A future `ner-v1` corpus/config is allowed but **must never** be merged into the pattern-v1 score.

## Corpus design

### Case schema

Each case in `pattern-v1.json`:

- `id` (stable string)
- `input` (UTF-8 string)
- `expected`: list of `{ entity_type, start, end, raw }` (exact span; `raw` must equal `input[start:end]`)
- `tier`: `contract` | `challenge` | `negative`
- Optional `notes`, `provenance` (source case id if adapted)

### Tiers

| Tier | Meaning |
|------|---------|
| `negative` | `expected` empty; any prediction is FP |
| `contract` | Must stay exact; regressions fail CI |
| `challenge` | Tracked; may have reviewed exceptions in baseline |

### Family scope (v1)

Shared families aligned with the comparison slice: email, URL, IP, phone, payment card, IBAN, UUID, MAC, date/time—plus negatives that stress those detectors (and SHA1 where it pollutes negatives).

### Provenance

- Cases adapted from `tcheuD/anon-pii` list source repo, commit, and case ids in `testdata/quality/README.md` (and/or per-case `provenance`).
- Fixtures are rewritten as needed so Redact **owns** them; do not vendor their runner or republish their aggregate as ours.
- Attribution must remain Apache-2.0 compatible.

### Integrity

- Baseline (or test) records SHA-256 of `pattern-v1.json`.
- Changing labels/corpus without updating the hash/baseline is a hard fail.

## Wave 1 — precision fixes

Ordered work in `redact-core`:

1. **Impossible / invalid dates** — Reject non-calendar `DATE_TIME` values (e.g. `2026-99-13`, `2026-02-31`). Prefer full ISO-8601 spans when matching timestamps.
2. **MAC negatives** — Suppress null (`00:…:00`) and broadcast (`ff:…:ff`) unless strong device context; keep ordinary MACs.
3. **Order-like phone/card** — Require context (or stronger cues) when values sit under `order` / `order_id`-style labels; keep explicit phone/card contexts working.
4. **Commit-shaped SHA1** — Lower or suppress bare 40-hex under `commit=` / VCS-ish labels so negatives do not fire as `SHA1_HASH`.
5. **Domain fallback cleanup** — Do not emit junk `DOMAIN_NAME` from failed email parses (e.g. `40example.com`, `u0040example.com`); prefer email or no detection.
6. **Fixtures + ratchet** — Land adapted negatives/shared-family cases; tighten baseline as FPs fall.

**Success for wave 1:**

- Quality test green in CI
- **0 FP on the negative tier** (or a documented tiny allowance only if unavoidable)
- All `contract` compact positives still pass
- Precision baseline ratcheted upward vs the initial “debt” baseline

## CI & rollout

1. Land corpus + runner + **current** baseline (documents today’s FP debt).
2. Land wave-1 validator/context PRs; tighten `pattern-v1-baseline.json` as FPs drop (loosening requires explicit PR rationale).
3. Optional short `docs/` note on how to run/report scores—not a competitive claim.
4. **Wave 2 (recall)** only after negative-tier FP target is met: spaced/hyphenated cards, spaced/lowercase IBAN, Cisco MAC, intl phones, fullwidth/encoded email, span completeness (DATE_TIME, IPv4-mapped IPv6)—each change must preserve the precision floor.

Hook: existing workspace CI via `cargo test -p redact-core --test quality_pattern_v1` (name may vary slightly; no network/ONNX).

## Testing strategy

- Unit tests beside validator/pattern changes for each FP class.
- Corpus integration test for aggregate TP/FP/FN and baseline.
- Existing `pattern_coverage.rs` remains; quality corpus is the regression gate for precision policy, not a replacement for per-entity smoke coverage.

## Risks

| Risk | Mitigation |
|------|------------|
| Context gates hurt real recall | Contract positives for compact forms; challenge tier can lag |
| Corpus gaming / silent relabeling | Content hash + reviewed baseline diffs |
| Scope creep into NER or gateway | Explicit non-goals; separate future corpus |
| Over-claiming vs anon-pii | Own scores only; provenance without scoreboard marketing |

## Implementation sketch (post-approval)

Not part of this approval gate beyond orientation:

1. Add `testdata/quality/` + README + initial corpus/baseline.
2. Add `quality_pattern_v1` test runner.
3. Implement wave-1 fixes with unit tests; ratchet baseline.
4. Open wave-2 recall plan only after wave-1 success criteria.

## Approval

Design sections reviewed in conversation:

- §1 Corpus & measurement — approved
- §2 Wave-1 precision fixes & out of scope — approved
- §3 CI, attribution, rollout — approved

**Next step after human review of this file:** write the implementation plan (`writing-plans`), then implement.
