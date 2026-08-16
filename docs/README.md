# Documentation

- [Installation](install.md) — Cargo, source, Docker, full NER image
- [Entity types](entity-types.md) — 61 compiled types (`list-entities` / `data/facts.json`)
- [Secrets detection](secrets-detection.md) — Entropy model, exclusions, named types, optional pack
- [Postgres scanning model](scanning-model.md) — `redact-scan` layers, safety rails, report shape
- [WebAssembly](wasm.md) — Pattern engine for browsers and Workers
- [NER](ner.md) — Optional ONNX named-entity recognition
- [Gateway getting started](gateway/getting-started.md) — Local redaction, Ollama, OpenAI SDK
- [Gateway](gateway/) — Configuration, policy, tokenization, auth, telemetry, audit, streaming, deployment
- [Benchmarks](benchmarks/) — oha vs Presidio (p50 **32×** on the 2026-04-18 payload)
- [Project structure](project-structure.md)
- [Testing](testing.md)
- [Roadmap](roadmap.md)
- [Project scope](PROJECT_SCOPE.md) — What this repository accepts
- [Acknowledgments](acknowledgments.md)

Crate READMEs: [`redact-scan`](../crates/redact-scan/README.md) · [`redact-verify`](../crates/redact-verify/README.md) · [`redact-gateway`](../crates/redact-gateway/README.md)

Rust API docs: [docs.rs/redact-core](https://docs.rs/redact-core)
