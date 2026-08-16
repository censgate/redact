# Project structure

```
redact/
├── crates/
│   ├── redact-gateway/   # OpenAI-compatible privacy gateway (crates.io: redact-gateway)
│   ├── redact-core/      # Detection and anonymization engine
│   ├── redact-ner/       # ONNX NER integration (optional engine add-on)
│   ├── redact-api/       # REST API service (Axum) over the same engine
│   ├── redact-cli/       # Command-line tool (`redact`)
│   ├── redact-scan/      # Read-only Postgres PII discovery scanner
│   ├── redact-verify/    # Offline ledger evidence-pack verifier (no redact-core)
│   └── redact-wasm/      # WebAssembly bindings (pattern engine)
├── docs/
│   ├── README.md         # Documentation index
│   ├── secrets-detection.md
│   ├── scanning-model.md
│   ├── entity-types.md
│   ├── gateway/          # Gateway operator documentation
│   └── benchmarks/       # Benchmark methodology and results
├── deploy/               # Gateway Collector config and Kubernetes manifests
├── Dockerfile.gateway
├── docker-compose.gateway.yml
├── patterns/             # Default PII / compliance / security packs
├── scripts/              # Utility scripts (facts, model export, CI)
└── examples/             # Usage examples
```
