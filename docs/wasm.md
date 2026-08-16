# WebAssembly

The **`redact-wasm`** crate is the supported WASM entry point. It compiles
`redact-core`'s **pattern engine** to `wasm32-unknown-unknown` for browsers and
edge runtimes such as Cloudflare Workers, and wires the JS RNG backends
(`getrandom` / `uuid`) required on that target. Compiling `redact-core` alone
for `wasm32-unknown-unknown` is **not** supported.

It exposes a `RedactEngine` with `analyze`, `anonymize` (replace/mask),
`anonymize_with_hash` (requires a non-empty caller-provided salt), and
`supported_entities` via `wasm-bindgen`.

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.13.1
wasm-pack build --target web crates/redact-wasm

# Runtime tests under Node (wasm-bindgen-test)
wasm-pack test --node crates/redact-wasm
```

```js
import init, { RedactEngine } from "./pkg/redact_wasm.js";
await init();
const engine = new RedactEngine();
engine.analyze("Contact john@example.com");
engine.anonymize("Email: john@example.com", "replace");
engine.anonymize_with_hash("SSN 123-45-6789", "app-secret-salt");
```

## What is available

All **61 compiled entity types** (`redact --format json list-entities`) and the
replace/mask anonymization strategies, plus salted hash via `anonymize_with_hash`.
Typical bundle size is ~1-3 MB.

## What is not available

Contextual NER — `PERSON`, `ORGANIZATION`, `LOCATION` in prose — requires an
ONNX transformer model (~250-420 MB) plus the ONNX Runtime. That stack does not
fit Cloudflare Workers (128 MB isolate, 64 MiB bundle, ~50 ms CPU) and is
impractical to inline in a browser module. For name-based detection, use a
hybrid architecture: run the pattern WASM at the edge and send a NER subset to
`redact-api` `:full` or Workers AI.

Inline WASM NER remains a deferred roadmap item. See [roadmap](roadmap.md).
