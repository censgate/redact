# Project scope

Read this before investing time in a contribution. Pull requests that
implement out-of-scope work will not be merged.

If a proposal might sit on the boundary, [open an issue](https://github.com/censgate/redact/issues)
first.

## In scope

This Apache-2.0 repository accepts contributions to:

| Crate | Role |
| --- | --- |
| `redact-core` | Pattern-based detection and anonymization engine |
| `redact-ner` | ONNX-based named entity recognition |
| `redact-api` | REST API server |
| `redact-cli` | Command-line interface |
| `redact-wasm` | WebAssembly bindings |
| `redact-gateway` | Self-hosted OpenAI-compatible privacy gateway |
| `redact-scan` | Read-only Postgres PII discovery scanner |

Also in scope: documentation, tests, examples, packaging, and CI for those
crates.

## Out of scope

The following are **not accepted** in this repository:

- Immutable / attested audit storage
- Hosted control plane
- Tenant administration
- Support or indemnity commitments

Those capabilities are outside the Apache-2.0 project. Please do not open
pull requests that implement them here.
