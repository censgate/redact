# Pattern-Default Precision & Quality Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an owned `pattern-v1` quality corpus + CI ratchet and wave-1 precision fixes so negative-tier FPs drop to zero without regressing compact contract positives.

**Architecture:** Add `testdata/quality/` fixtures and a `redact-core` integration test that scores exact spans. Extend `validation.rs` / `pattern.rs` analyze path with value validators and surrounding-text precision gates. Ratchet baseline after fixes.

**Tech Stack:** Rust, serde_json corpus, `AnalyzerEngine` / `PatternRecognizer`, cargo test in existing CI.

## Global Constraints

- Pattern-default only: `AnalyzerEngine::new()`, language `en`, min score `0.5`, no NER.
- Exact UTF-8 byte span + entity type matching; no post-filter of predictions in the scorer.
- Precision first; wave-2 recall is out of scope for this plan.
- Apache-2.0 compatible provenance for adapted cases; do not vendor anon-pii runner.
- Conventional commits; keep public APIs documented.

## File map

| Path | Responsibility |
|------|----------------|
| `testdata/quality/README.md` | How to run, config contract, provenance |
| `testdata/quality/pattern-v1.json` | Cases |
| `testdata/quality/pattern-v1-baseline.json` | Ratchets + corpus sha256 |
| `crates/redact-core/tests/quality_pattern_v1.rs` | Load, score, assert baseline |
| `crates/redact-core/src/recognizers/validation.rs` | `validate_date_time`, `validate_mac_address`, `precision_gate` |
| `crates/redact-core/src/recognizers/pattern.rs` | Call validators/gates in `analyze`; unit tests |

---

### Task 1: Quality corpus + runner (documents current debt)

**Files:**
- Create: `testdata/quality/README.md`
- Create: `testdata/quality/pattern-v1.json`
- Create: `testdata/quality/pattern-v1-baseline.json`
- Create: `crates/redact-core/tests/quality_pattern_v1.rs`

**Interfaces:**
- Produces: corpus schema `{ version, cases: [{ id, input, expected: [{ entity_type, start, end, raw }], tier, provenance? }] }`
- Produces: baseline `{ corpus_sha256, max_fp_overall, max_fp_negative_tier, min_precision_ppm, require_contract_exact: true }`
- Scorer uses `AnalyzerEngine::analyze(input, Some("en"))` and maps `EntityType::as_str()` to expected `entity_type`.

- [ ] **Step 1:** Add README with config contract and provenance note (anon-pii commit `1a22680e43b29c80e141a39b0a66eb3dcafb7522`, adapted case ids).

- [ ] **Step 2:** Add `pattern-v1.json` with at least:
  - **Negatives:** `negative-date-month`, `negative-impossible-calendar-date`, `negative-mac-null`, `negative-mac-broadcast`, `negative-phone-like-order`, `negative-card-like-order`, `negative-commit-hash`, `negative-card-luhn`
  - **Contracts (compact TPs):** `email-basic`, `card-visa-compact`, `iban-gb-compact`, `uuid-request-id`, `mac-locally-administered`, `url-basic`, `ipv4-documentation`
  - Use exact byte spans; set `raw` == slice.

- [ ] **Step 3:** Implement `quality_pattern_v1.rs` that:
  - Loads corpus/baseline from `CARGO_MANIFEST_DIR/../../testdata/quality/`
  - Verifies corpus sha256 matches baseline
  - Scores TP/FP/FN (exact start/end + entity_type string)
  - Asserts contract cases have zero FN/FP each
  - Asserts overall FP ≤ `max_fp_overall`, negative-tier FP ≤ `max_fp_negative_tier`, precision ≥ floor
  - Initially set baseline to **current** measured debt (allow FPs) so the test is green before fixes

- [ ] **Step 4:** Run `cargo test -p redact-core --test quality_pattern_v1` — expect PASS with debt baseline.

- [ ] **Step 5:** Commit `test(core): add pattern-v1 quality corpus and ratchet harness`

---

### Task 2: DateTime + MAC validators

**Files:**
- Modify: `crates/redact-core/src/recognizers/validation.rs`
- Modify: `crates/redact-core/src/recognizers/pattern.rs` (unit tests; `validate_entity` match arms)

**Interfaces:**
- `pub fn validate_date_time(value: &str) -> f32` — `1.0` valid calendar date (and optional time), `0.0` otherwise
- `pub fn validate_mac_address(value: &str) -> f32` — `0.0` for null/broadcast, else `1.0`
- Wire both into `validate_entity`

- [ ] **Step 1:** Write failing unit tests in `validation.rs` or `pattern.rs` tests for invalid dates and null/broadcast MAC.

- [ ] **Step 2:** Implement validators; run unit tests — PASS.

- [ ] **Step 3:** Run quality test; tighten negative-tier allowance if those FPs are gone.

- [ ] **Step 4:** Commit `fix(core): reject invalid DATE_TIME and null/broadcast MAC`

---

### Task 3: Surrounding-text precision gate (order/commit/domain)

**Files:**
- Modify: `crates/redact-core/src/recognizers/validation.rs`
- Modify: `crates/redact-core/src/recognizers/pattern.rs` `analyze`

**Interfaces:**
- `pub fn precision_gate(entity_type: &EntityType, text: &str, start: usize, end: usize, value: &str) -> f32`
  - Phone/CreditCard: if left context (50 chars) matches order-like labels (`order_id`, `order`) and lacks phone/card cues → `0.0`
  - Sha1Hash: if left context has `commit` → `0.0`
  - DomainName: if previous char is `%`/`\`/`@`, or value looks like email-decode fragment (`^\d+example\.`, `^u00[0-9a-f]{2}`) → `0.0`
  - Else `1.0`
- In `analyze`, after `validate_entity`: `score *= precision_gate(...)`

- [ ] **Step 1:** Failing unit tests for order phone/card, commit SHA1, junk domains.

- [ ] **Step 2:** Implement gate + wire into analyze.

- [ ] **Step 3:** Run unit + quality tests.

- [ ] **Step 4:** Commit `fix(core): precision-gate order IDs, commit SHA1, junk domains`

---

### Task 4: Ratchet baseline to wave-1 success

**Files:**
- Modify: `testdata/quality/pattern-v1-baseline.json`
- Modify: `testdata/quality/README.md` if needed

- [ ] **Step 1:** Run quality test, set `max_fp_negative_tier: 0`, `max_fp_overall` to measured, raise `min_precision_ppm` accordingly, update `corpus_sha256` if corpus unchanged still same.

- [ ] **Step 2:** `cargo test -p redact-core --test quality_pattern_v1` PASS; `cargo test -p redact-core` PASS; `cargo fmt`; clippy on touched crates if feasible.

- [ ] **Step 3:** Commit `test(core): ratchet pattern-v1 baseline after precision fixes`

- [ ] **Step 4:** Push branch and open PR against `main`.

---

## Spec coverage check

| Spec item | Task |
|-----------|------|
| Owned corpus + baseline + sha256 | 1, 4 |
| Exact-span scorer, pattern-only config | 1 |
| Provenance README | 1 |
| Invalid dates / MAC negatives | 2 |
| Order phone/card, commit SHA1, domain junk | 3 |
| Ratchet to 0 negative FP | 4 |
| CI via cargo test | 1 (existing workspace job) |
| No NER / no recall wave | Global constraints |
