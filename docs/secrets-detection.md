# Secrets detection

Phase 2 of [#101](https://github.com/censgate/redact/issues/101). The detector is WASM-pure, deterministic, and offline. Precision is the gate: a noisier detector is a regression.

Related: [gateway policy](gateway/policy.md) · [gateway deployment](gateway/deployment.md)

## Pipeline

```
input → named SECRET_PATTERNS → overlap
      → GenericSecretRecognizer → closed LHS + denylist → exclusions → entropy → overlap
      → gateway / CLI / WASM policy
```

Named prefixed types (GitHub, Stripe, `hf_`, …) always win over `GENERIC_SECRET`. `GENERIC_SECRET` suppresses `GUID` / `MD5_HASH` / `SHA1_HASH` / `SHA256_HASH` so a secret-shaped hex assignment is not un-redacted by the default profile (which **allows** hashes and GUIDs).

## Compiled-in vs pack

| Layer | What belongs there | Loaded by default |
|-------|--------------------|-------------------|
| `SECRET_PATTERNS` in `redact-core` | Length-closed, high-precision prefixes (`ghp_`, `AKIA`, `hf_`, …) plus decode-validated `HTTP_BASIC_AUTH` | Yes (CLI, WASM, gateway) |
| `GENERIC_SECRET` | Assignment-like positions only, entropy-gated | Yes; independently disableable |
| `patterns/optional/providers-v1.yaml` | Long-tail prefixes (Shopify, Postman, …) adapted from [gitleaks](https://github.com/gitleaks/gitleaks) (`config/gitleaks.toml` @ `09242ce9c8a60d9b051fc2d166f9e849b88c7ac0`, MIT) | **No.** Not on the Docker path. Not `include_str!` into WASM. |

Gateway images set `CENSGATE_PATTERN_PACKS=/app/patterns/compliance:/app/patterns/pii`. The loader skips directories named `optional/` and `quarantine/` even if `ENV` points at `/app/patterns`. Noisy `patterns/security/credentials.yaml` rules stay `enabled: false` as a safety net.

## Entropy model

Shannon \(\hat H\) is computed over **characters**, not bytes, of the candidate **value**.

Charset priority:

1. ASCII hex (must contain `a–f` / `A–F`)
2. Base64 **only** with structural evidence (`+`, `/`, `=`, or both `-` and `_`)
3. Alphanumeric
4. Otherwise reject

Markerless `[A-Za-z0-9]+` is alphanumeric, never base64. SCREAMING_SNAKE and path-shaped values are rejected before base64 classification.

Length-aware floor (length \(N \in [20, 128]\)):

- \(\hat H \ge \mathbb{E}[\hat H_{\mathrm{uniform}}(K,N)] - 0.30\)
- and \(N \cdot \hat H \ge 80\) bits

Non-hex values need at least one digit and one letter.

Confidence is lerped **0.60 → 0.85** and never reaches 0.90. The gateway `default` / `reversible` profiles use `{ action: replace, min_confidence: 0.6 }` so the band is reachable. A 0.8 floor would drop essentially all true positives.

Core and YAML packs share one entry point:

```rust
evaluate_generic_candidate(value, lhs, surrounding) -> Option<f32>
```

Packs cannot call a value-only scorer and skip the keyword gate. `entropy: generic` pack rules must expose capture group 1 (the value).

## Keyword gate

Segment-aware: split on `_` / `-` / `.` / camelCase, lowercase, match whole segments or adjacent pairs (`api`+`key`). Not a raw substring (`sha` does not veto `SHARED_SECRET`).

**Allow** (secret-LHS): `secret`, `token`, `password`, `passwd`, `pwd`, `api_key`, `apikey`, `access_key`, `access_token`, `private_key`, `client_secret`, `credential`, `auth`, `bearer`, `x-api-key`, plus env suffixes `*_API_KEY` / `*_SECRET` / `*_TOKEN` / `*_PASSWORD` / `*_ACCESS_KEY`.

**Deny** (digest-context, no emit): `checksum`, `integrity`, `digest`, `sha`, `sha1`, `sha256`, `md5`, `etag`, `revision`, `rev`, `commit`, `fingerprint`, `thumbprint`, `key_id`, `public_key`, `secret_name`, `secretKeyRef`, `token_type`, `tokenizer`.

Precedence: any allow token → secret-LHS (`password_hash` emits). Else any deny token → digest-context. `hash` is deny only in that else-branch.

Closed assignment forms: `KEY=`, `KEY =`, `KEY:`, `"KEY":`, `'KEY':`, `export KEY=`, `-e KEY=`, `Authorization: Bearer`. `Authorization: Basic` is handed to `HTTP_BASIC_AUTH`.

Spans are **value-only** (never the key, quotes, or a multi-value blob).

## Exclusions

- `#RGB` / `#RRGGBB` (and 8-digit hex colors)
- `data:` URIs
- PEM armor
- `eyJ` JWTs (named `JWT_TOKEN` handles those)
- Stopwords: `password`, `changeme`, `secret`, `xxx`, `your_*_here`, `test`, `example`, `todo`, `placeholder`
- Identifier-only `^[A-Za-z_.-]+$`
- UUID shape: emit `GENERIC_SECRET` (no entropy, confidence 0.70) only under a **strong** keyword (`api_key`, `client_secret`, `access_token`, `secret`). Otherwise exclude. This is the documented UUID hole.
- Hash-shaped hex (32 / 40 / 64 / 128) is excluded on digest-LHS, not on secret-LHS.

## Two confidence floors

| Floor | Where | Why |
|-------|--------|-----|
| Engine 0.60 | `score_generic_secret` lerp start | Lowest emit from the recognizer |
| Gateway 0.6 | `default` / `reversible` `GENERIC_SECRET` rule | Same band; detections are **replaced**, not blocked |

`secrets_only` **blocks** `GENERIC_SECRET`. `strict` inherits the profile default (`block` above 0.6).

## Disabling `GENERIC_SECRET`

Independent of the rest of the engine (not full [#113](https://github.com/censgate/redact/issues/113) UX):

- CLI: `redact analyze --disable GENERIC_SECRET` (PascalCase `GenericSecret` also works). Applied after `--entities`; an empty remaining set is an error.
- WASM: `analyze_excluding(text, '["GENERIC_SECRET"]')`. `analyze(text)` is unchanged.
- Gateway: set `GENERIC_SECRET: { action: allow }` on the profile.

List compiled types (source of truth for facts):

```bash
redact --format json list-entities
```

## Compiled-in named types (Phase 2)

In addition to the Phase 1 prefixes: `HUGGINGFACE_TOKEN`, `DATABRICKS_TOKEN`, `DIGITALOCEAN_TOKEN`, `NOTION_API_KEY`, `PERPLEXITY_API_KEY`, `HTTP_BASIC_AUTH` (hand-rolled base64 decode, canonical padding including unused bits, `user:password` both non-empty). GitLab keeps `glpat-` length 20 and adds gitleaks-closed routable / `glcbt-` / `glagent-` / `gloas-` / `gldt-` / `glft-` / `glptt-` shapes. AWS Bedrock (`ABSK…` and the short-lived `bedrock-api-key-YmVk…` literal) is an `AWS_ACCESS_KEY` alternation. Trailing `=` uses a delimiter class rather than `\\b`.

Not compiled-in (pack or later): Azure AD `Q~` infix, GCP SA JSON, Teams webhooks, Discord, Datadog, Azure storage, Cloudflare global, generic-api-key, live API checks.

## Precision corpora (measured)

These figures are from hermetic tests in this repository. They are **not**
a general precision/recall claim. The meaningful gates are the negative
corpora. CI prints the numbers; it does not print raw secret values.

### Exclusion / lockfile / digest-keyed corpus

Test: `crates/redact-core/tests/generic_secret_corpus.rs`
(`exclusion_corpus_has_zero_generic_secret`).

**Gate: 0 `GENERIC_SECRET`.** Measured on this tree:
`exclusion_generic_secret_count=0`. Covers weak-keyword UUIDs,
digest-keyed hashes, `password=password`, `api_key=your-key-here`,
lockfile `integrity=sha512-…`, all-alpha identifiers, prose, `#fff` /
`#aabbcc`, `data:image;base64,…`.

### Labeled generated positives

Test: `labeled_positive_corpus_precision_recall` in the same file.

Seeded fixtures, assembled at run time (labels and spans only in output).
This is a labelled set, not a production sample. Do not restate these
figures as a general result.

Gates: recall **≥ 0.90**; default gateway profile (`replace` @ 0.6) must
**act on ≥ 90%** of labeled generics. The test also prints
`generic_secret_precision = tp / (tp + exclusion_fps)` using the same
exclusion corpus helper as the gate above. That is a labelled-set plus
negative-corpus ratio, not a general precision result.

Measured on this tree (labelled set + exclusion corpus only):
`generic_secret_precision=1.0000`, `generic_secret_recall=1.0000`,
`generic_secret_acted_under_default_profile=1.0000`.

### Vendored OSS slice

Test: `crates/redact-core/tests/oss_slice.rs`.

Hermetic MIT/BSD/Apache slice (pinned SHAs of `facebook/react`,
`redis/redis` 7.2.4 BSD-3 — not RSALv2/SSPL — `pallets/flask`,
`clap-rs/clap`). Do not vendor `git/git` (GPL).

- **≤ 5 unreviewed `GENERIC_SECRET` / 100k lines**
- Secret-named + secret-shaped literals in upstream docs count as true
  positives, not FPs
- Every remaining hit is a reviewed fingerprint (`tp` or `waived`)

Measured on this tree: `oss_slice_lines=56201` `generic_hits=0`
`unreviewed=0` `unreviewed_per_100k=0.0000`.

Exceeding a ceiling is a detector bug. Do not raise N to land a change.
