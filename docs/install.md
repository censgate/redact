# Installation

MSRV is Rust **1.88** (`rust-version` in the workspace `Cargo.toml`). CI and
published images use **1.93**. Use [Mise](https://mise.jdx.dev/) or [rustup](https://rustup.rs/):

```bash
mise install rust@1.93.0
# or
rustup install 1.93.0
rustup default 1.93.0
```

## Cargo

```bash
cargo install redact-cli       # `redact` analyze / anonymize
cargo install redact-gateway   # OpenAI-compatible privacy gateway
cargo install redact-scan      # read-only Postgres PII discovery
cargo install redact-verify    # offline ledger evidence-pack verifier
```

Published crates: [`redact-scan`](https://crates.io/crates/redact-scan) · [`redact-verify`](https://crates.io/crates/redact-verify) (0.10.0).

## From source

```bash
git clone https://github.com/censgate/redact.git
cd redact
cargo build --release
cargo test --workspace
```

## Docker

Multi-architecture images for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/censgate/redact:latest
docker run -p 8080:8080 ghcr.io/censgate/redact:latest
```

The image uses a minimal [distroless](https://github.com/GoogleContainerTools/distroless) base.

Privacy gateway:

```bash
docker pull ghcr.io/censgate/redact-gateway:latest
docker run -p 8080:8080 -e CENSGATE_PROVIDER_BASE_URL=http://host.docker.internal:11434 \
  ghcr.io/censgate/redact-gateway:latest
```

### Full image (pattern + ONNX NER)

Published on every release as `full` / `X.Y.Z-full`:

```bash
docker pull ghcr.io/censgate/redact:full
docker run -p 8080:8080 ghcr.io/censgate/redact:full
```

The full image uses a pre-built [NER base layer](https://github.com/censgate/redact/pkgs/container/redact-ner-base) (`NER_BASE`, default `ghcr.io/censgate/redact-ner-base:v2`).

**Health** — `GET /healthz` or `GET /health` (HTTP 200, JSON `"status":"healthy"`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8080` | Listen port inside the container |
| `NER_MODEL_PATH` | *(unset)* / `/app/model/model.onnx` in full image | ONNX model path |
| `ORT_DYLIB_PATH` | *(unset)* / `/app/lib/libonnxruntime.so` in full image | ONNX Runtime `.so` |
| `ENABLE_TRACING` | `true` | Tower HTTP trace middleware |

To enable NER with the default image, mount a directory containing `model.onnx` and `tokenizer.json` and set `NER_MODEL_PATH`.
