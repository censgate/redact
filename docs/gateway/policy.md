# Gateway policy

A policy set holds named profiles. Each profile maps entity types to actions, with a confidence floor and optional per-entity overrides. Profiles are immutable once resolved; the request path only ever reads an `Arc` snapshot.

Related: [getting started](getting-started.md) · [configuration](configuration.md) · [tokenization](tokenization.md) · [authentication](authentication.md)

## Selecting a profile

Resolution order for each request:

1. Profile claim from the credential (`oidc` `profile_claim`, when set) — wins so a caller cannot widen the policy their credential was issued for.
2. Else, if `allow_profile_header` is true, the `x-censgate-profile` header (name configurable).
3. Else the configured `default_profile`.

`allow_profile_header` defaults to **`false`**: the profile header is ignored unless an operator enables it. An OIDC profile claim still selects a profile regardless. Enabling the header while `auth.mode` is `none` lets any caller choose any configured profile (including weaker ones); the gateway logs a warning for that combination.

An unknown explicit name is an error (HTTP 400). The gateway never silently falls back to a weaker profile.

```bash
# Header is honored only when allow_profile_header is true:
export CENSGATE_ALLOW_PROFILE_HEADER=true

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'x-censgate-profile: strict' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"hi"}]}'
```

Without enabling the header, set the process default instead:

```bash
export CENSGATE_DEFAULT_PROFILE=strict
```

## The six actions

| Action | Effect |
|--------|--------|
| `allow` | Leave the matched span untouched |
| `block` | Reject the whole request; body is not forwarded |
| `mask` | Replace with a mask controlled by profile `mask` options |
| `replace` | Replace with an entity label (or a per-rule `replacement` string) |
| `hash` | Replace with `[HASH:<16 hex>]` from SHA-256, optionally salted |
| `tokenize` | Replace with a reversible placeholder such as `[EMAIL_ADDRESS_1]` |

Aliases accepted when parsing: `pass`→`allow`, `reject`→`block`, `redact`→`replace`, `transform`→`tokenize`.

One pass can mix actions: a string may mask a card number, tokenize a name, and block an API key at the same time.

`tokenize` describes what happens to outbound content. When a model's own answer contains a detected value, there is nobody downstream to restore a placeholder for, so a tokenize rule acts as `replace` on the response path. The value is removed either way.

`GENERIC_SECRET` is independently disableable: set `{ action: allow }` on the profile. Named secret types stay `block` on `default`, `reversible`, and `secrets_only`. See [secrets detection](../secrets-detection.md).

## Confidence floors

Each profile has `min_confidence` (default `0.5`). Per-entity rules may set their own floor. Detections below the applicable floor are treated as `allow`, so low-confidence noise never rewrites user content.

```yaml
entities:
  US_SSN: { action: mask, min_confidence: 0.7 }
```

## Scan targets

| Field | Default | What it covers |
|-------|---------|----------------|
| `request_messages` | `true` | `messages[].content` (string or text parts) |
| `request_tool_calls` | `true` | Tool-call `function.arguments` on requests |
| `request_tools` | `true` | Tool / function descriptions and schema strings |
| `request_user` | `true` | Top-level OpenAI `user` |
| `request_input` | `true` | Embeddings `input`, legacy `prompt` / `suffix` |
| `response_messages` | `true` | Assistant content / deltas / legacy `text` |
| `response_tool_calls` | `true` | Tool-call arguments on responses |
| `request_pointers` | `[]` | Extra RFC 6901 pointers on requests |
| `response_pointers` | `[]` | Extra RFC 6901 pointers on responses |

Non-text multimodal parts are not scanned. Custom pointers let you cover provider extensions without forking the gateway.

## Fail-closed semantics

| Setting | Default | Meaning |
|---------|---------|---------|
| `fail_closed` | `true` | Reject the request when a required subsystem fails (token map unavailable, tokenization cannot run) instead of forwarding unprotected content |
| `restore_responses` | `true` | On the response path, replace known tokens with originals when the sealing key can open them |

`fail_closed: false` is appropriate for observe-only profiles such as `permissive`. Keep it true for production traffic-handling profiles.

## Bundled profiles

Shipped in [`default_policy.yaml`](../../crates/redact-gateway/src/policy/default_policy.yaml):

| Profile | Default action | Intent |
|---------|----------------|--------|
| `default` | `replace` | Replace personal data; **block** named credentials/secrets; **replace** `GENERIC_SECRET` at confidence ≥ 0.6; **mask** high-sensitivity IDs (SSN, cards, MRN, …) at confidence ≥ 0.7; allow common false positives (dates, URLs, hashes, GUIDs) |
| `reversible` | `tokenize` | Tokenize personal data for restore; block a core credential set; allow the same noise entities |
| `strict` | `block` | Block any detection above confidence 0.6 (except allow-listed noise); no response restore |
| `secrets_only` | `allow` | Block credentials/secrets only; leave everything else alone |
| `permissive` | `allow` | Detect and report without modifying payloads; `fail_closed: false` |

Inspect the effective document:

```bash
cargo run -p redact-gateway -- print-policy
```

## Profile schema

```yaml
default_profile: default
profiles:
  my_profile:
    description: Optional human-readable summary
    default_action: replace          # allow | block | mask | replace | hash | tokenize
    min_confidence: 0.5
    restore_responses: true
    fail_closed: true
    packs: []                        # empty = every loaded pack
    entities:
      EMAIL_ADDRESS:
        action: tokenize
      US_SSN:
        action: mask
        min_confidence: 0.7
      PERSON:
        action: replace
        replacement: "[NAME]"        # only valid with action: replace
    scan:
      request_messages: true
      request_tool_calls: true
      request_tools: true
      request_user: true
      request_input: true
      response_messages: true
      response_tool_calls: true
      request_pointers: []
      response_pointers: []
    mask:
      mask_char: "*"
      start_chars: 0
      end_chars: 0
      preserve_format: true          # keep punctuation; mask alphanumerics
    hash:
      salt: optional-pepper          # without a salt, digests are comparable across deployments
```

Validation rejects `min_confidence` outside `[0.0, 1.0]` and `replacement` on a non-`replace` rule.

## Custom policy example

Healthcare-oriented example (also in [`examples/policy-healthcare.yaml`](../../crates/redact-gateway/examples/policy-healthcare.yaml)):

```yaml
policy:
  default_profile: healthcare
  profiles:
    healthcare:
      description: Mask PHI identifiers; block credentials.
      default_action: replace
      min_confidence: 0.55
      restore_responses: false
      fail_closed: true
      entities:
        PRIVATE_KEY: { action: block }
        AWS_ACCESS_KEY: { action: block }
        MEDICAL_RECORD_NUMBER: { action: mask, min_confidence: 0.7 }
        US_SSN: { action: mask, min_confidence: 0.7 }
        EMAIL_ADDRESS: { action: replace }
        DATE_TIME: { action: allow }
        AGE: { action: allow }
      mask:
        mask_char: "*"
        preserve_format: true
```

Load it:

```bash
cargo run -p redact-gateway -- \
  --config crates/redact-gateway/examples/policy-healthcare.yaml \
  --provider-base-url http://127.0.0.1:11434
```

Or point `CENSGATE_POLICY_FILE` / `policy_file` at a standalone document. Inline `policy` and `policy_file` are mutually exclusive.

## Dry-run without calling a provider

```bash
# AWS docs sample shape assembled at the shell (avoids secret-scanning FPs in docs).
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"
curl -s http://127.0.0.1:8080/v1/compliance/check \
  -H 'content-type: application/json' \
  -d "{\"text\":\"SSN 123-45-6789 and key ${AWS_KEY}\",\"profile\":\"default\"}"
```

Returns whether the content would be allowed, which entities would block, and action/entity counts. Tokens minted during a check are throwaway and never persisted.
