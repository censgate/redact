# Entity types

Compiled pattern types are the names printed by:

```bash
redact --format json list-entities
```

That list is also stored in [`data/facts.json`](../data/facts.json) (`entity_type_count`).
CI checks it with `node scripts/extract-facts.mjs --check`. Do not edit the count
in prose by hand.

`EntityType` in [`crates/redact-core/src/types/entity.rs`](../crates/redact-core/src/types/entity.rs)
includes additional variants that the pattern engine does **not** register:
NER labels (`PERSON`, `ORGANIZATION`, `LOCATION`), the `IBAN` alias of
`IBAN_CODE`, and `Custom(String)`. Those are not part of the compiled count.

Current compiled count: **61** (60 pattern types + `GENERIC_SECRET`).

## Pattern-based (61 compiled types)

| Category | Entity Types |
|----------|--------------|
| **Contact** | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IP_ADDRESS`, `URL`, `DOMAIN_NAME` |
| **Financial** | `CREDIT_CARD`, `IBAN_CODE`, `US_BANK_NUMBER` |
| **US** | `US_SSN`, `US_DRIVER_LICENSE`, `US_PASSPORT`, `US_ZIP_CODE` |
| **UK** | `UK_NHS`, `UK_NINO`, `UK_POSTCODE`, `UK_PHONE_NUMBER`, `UK_MOBILE_NUMBER`, `UK_SORT_CODE`, `UK_DRIVER_LICENSE`, `UK_PASSPORT_NUMBER`, `UK_COMPANY_NUMBER` |
| **Healthcare** | `MEDICAL_LICENSE`, `MEDICAL_RECORD_NUMBER` |
| **Crypto** | `CRYPTO_WALLET`, `BTC_ADDRESS`, `ETH_ADDRESS` |
| **Technical** | `GUID`, `MAC_ADDRESS`, `MD5_HASH`, `SHA1_HASH`, `SHA256_HASH` |
| **Generic** | `PASSPORT_NUMBER`, `AGE`, `ISBN`, `PO_BOX`, `DATE_TIME` |
| **Secrets and credentials** | `PRIVATE_KEY`, `JWT_TOKEN`, `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK`, `STRIPE_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NPM_TOKEN`, `PYPI_TOKEN`, `SENDGRID_API_KEY`, `TWILIO_API_KEY`, `TELEGRAM_BOT_TOKEN`, `HASHICORP_VAULT_TOKEN`, `DATABASE_CONNECTION_STRING`, `HUGGINGFACE_TOKEN`, `DATABRICKS_TOKEN`, `DIGITALOCEAN_TOKEN`, `NOTION_API_KEY`, `PERPLEXITY_API_KEY`, `HTTP_BASIC_AUTH`, `GENERIC_SECRET` |

Pattern-based detection includes validation (Luhn for credit cards, mod-11 for NHS, IBAN checksums) to reduce false positives.

Secrets and credentials use anchored prefixes (for example `AKIA…`, `ghp_…`,
`sk-ant-…`, `-----BEGIN … PRIVATE KEY-----`). Assignment-like `api_key=…` /
`password=…` values are handled by entropy-gated `GENERIC_SECRET`. See
[secrets detection](secrets-detection.md).

The opt-in long-tail pack at `patterns/optional/providers-v1.yaml` is **not**
compiled in, **not** on the gateway default path, and is **not** gitleaks parity.
Further provider coverage belongs in a pack PR, not in `redact-core`.

## NER-based (optional ONNX)

| Entity Type | Description |
|-------------|-------------|
| `PERSON` | Person names in prose |
| `ORGANIZATION` | Organization names in prose |
| `LOCATION` | Location names in prose |
| `DATE_TIME` | Date/time expressions in context (also a compiled pattern type) |

Requires an ONNX model. See [NER](ner.md).

## Anonymization strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| **Replace** | Placeholder | `[EMAIL_ADDRESS]` |
| **Mask** | Partial masking | `jo**@****le.com` |
| **Hash** | Irreversible hashing | `[EMAIL_ADDRESS_a1b2c3d4]` |
| **Encrypt** | Reversible encryption | `<TOKEN_uuid>` |
