# Benchmarks

Performance benchmarks comparing Redact against Microsoft Presidio.

## Tool

We use [**oha**](https://github.com/hatoo/oha) - a modern HTTP load testing tool written in Rust that provides:

- Proper statistical analysis (percentiles: p50, p90, p99)
- Latency histograms
- JSON output for programmatic analysis
- Consistent, reproducible measurements

## Why REST API Comparison?

The **REST API benchmark is the fairest comparison** because:

1. **Real-world deployment** - Both tools are typically deployed as HTTP services
2. **Apples-to-apples** - Same protocol, same serialization overhead
3. **Language-agnostic** - Removes Python vs Rust runtime comparison noise
4. **User-relevant** - This is how most teams would actually use either tool

## Quick Start

```bash
# Optional: install oha (the script can download a pinned v1.10.0 binary if your system oha mis-handles -c)
cargo install oha

# Run benchmark (requires Docker for Presidio)
./scripts/benchmark-comparison.sh

# Custom parameters
./scripts/benchmark-comparison.sh --requests 500 --concurrency 4
```

## Requirements

- [oha](https://github.com/hatoo/oha) on `PATH`, or set `OHA_BIN` to a compatible binary; `curl` is used to auto-download a pinned release if needed
- Docker (for Presidio container)
- `jq`

## Output

The benchmark produces:

1. **Console output** - oha's histogram and statistics for each service
2. **Raw text** - oha output (`redact-*.txt`, `presidio-*.txt`)
3. **Markdown report** - Summary comparison (`results-*.md`)

## Criterion Micro-Benchmarks

For Redact-internal performance (no HTTP overhead):

```bash
cargo bench --package redact-core
```

Benchmarks include:
- Single entity detection (email, SSN, phone, etc.)
- Multiple entity detection
- Text length scaling (100-5000 chars)
- Anonymization strategies (replace, mask, hash)
- Cold vs warm start performance

## Latest Results (2026-04-18)

The **current** release is **[v0.8.2](https://github.com/censgate/redact/releases/tag/v0.8.2)**. Full report: [results-20260418-175909.md](results-20260418-175909.md).

### Latency (concurrency=1)

| Metric | Redact (Rust) | Presidio (Python) | Speedup |
|--------|---------------|-------------------|---------|
| p50 Latency | 0.196 ms | 6.25 ms | **32x** |
| p99 Latency | 1.90 ms | 21.68 ms | **11x** |
| Avg Latency | 0.25 ms | 7.19 ms | — |

### Throughput (concurrency=10)

| Metric | Redact (Rust) | Presidio (Python) | Speedup |
|--------|---------------|-------------------|---------|
| Requests/sec | 19,416 | 170 | **114x** |

**Environment:** Darwin arm64, Docker containers (builder: `rust:1.93-slim`; Redact runtime uses distroless). Benchmark tool: oha v1.10.0

Results vary by hardware. Run `./scripts/benchmark-comparison.sh` to benchmark on your system.
