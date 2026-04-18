#!/usr/bin/env bash
#
# Benchmark Redact vs Microsoft Presidio using Oha
#
# Both services run in Docker for consistent, reproducible results.
# Uses Oha (https://github.com/hatoo/oha) for objective HTTP benchmarking.
#
# Requirements:
#   - Docker
#   - oha (https://github.com/hatoo/oha), or set OHA_BIN to a compatible binary.
#     Some Homebrew builds mis-map -c; this script falls back to pinned v1.10.0.
#   - jq
#
# Usage:
#   ./scripts/benchmark-comparison.sh
#   ./scripts/benchmark-comparison.sh --requests 500
#   ./scripts/benchmark-comparison.sh --concurrency 4
#

set -euo pipefail

# Defaults
REQUESTS=200
CONCURRENCY=1
PRESIDIO_PORT=5011
REDACT_PORT=8081
RESULTS_DIR="docs/benchmarks"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--requests) REQUESTS="$2"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--requests N] [--concurrency N]"
            echo "  --requests N     Number of requests per benchmark (default: 200)"
            echo "  --concurrency N  Concurrent connections (default: 1)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Test payload - representative PII sample
TEST_TEXT="Contact john.doe@example.com or call (555) 123-4567. SSN: 123-45-6789."
PAYLOAD=$(jq -n --arg t "$TEST_TEXT" '{"text":$t,"language":"en"}')

info() { echo "[*] $1"; }
ok() { echo "[✓] $1"; }
err() { echo "[!] $1" >&2; exit 1; }

cleanup() {
    info "Cleaning up..."
    docker rm -f redact-bench presidio-bench 2>/dev/null || true
}
trap cleanup EXIT

# Check dependencies
command -v docker >/dev/null || err "docker not found"
command -v jq >/dev/null || err "jq not found"
command -v curl >/dev/null || err "curl not found (needed for oha fallback)"

# Resolve oha: optional OHA_BIN, else PATH; if -c is broken, use pinned release binary.
resolve_oha() {
    if [[ -n "${OHA_BIN:-}" ]]; then
        [[ -x "$OHA_BIN" ]] || err "OHA_BIN is not executable: $OHA_BIN"
        OHABIN=$OHA_BIN
        return
    fi
    command -v oha >/dev/null || err "oha not found. Install from https://github.com/hatoo/oha/releases or set OHA_BIN"
    local probe
    probe=$(oha -n 1 -c 1 http://127.0.0.1:1/ 2>&1) || true
    if echo "$probe" | grep -q "invalid value.*no-color"; then
        local cache="${HOME}/.cache/redact-benchmark"
        local ver="1.10.0"
        local asset
        case "$(uname -s)/$(uname -m)" in
            Darwin/arm64) asset="oha-macos-arm64" ;;
            Darwin/x86_64) asset="oha-macos-amd64" ;;
            Linux/x86_64) asset="oha-linux-amd64" ;;
            Linux/aarch64) asset="oha-linux-arm64" ;;
            *) err "Unsupported OS/arch for automatic oha download; set OHA_BIN" ;;
        esac
        mkdir -p "$cache"
        if [[ ! -x "${cache}/oha-${ver}" ]]; then
            info "Downloading oha ${ver} (${asset}) — system oha mis-handles -c..."
            curl -fsSL "https://github.com/hatoo/oha/releases/download/v${ver}/${asset}" -o "${cache}/oha-${ver}"
            chmod +x "${cache}/oha-${ver}"
        fi
        OHABIN="${cache}/oha-${ver}"
    else
        OHABIN=oha
    fi
}
resolve_oha

echo ""
echo "========================================"
echo "  Redact vs Presidio Benchmark"
echo "========================================"
echo ""

# Build Redact Docker image
info "Building Redact Docker image..."
docker build -t redact:bench -f Dockerfile . 2>&1 | tail -5
ok "Redact image built"

# Start Presidio
info "Starting Presidio (Docker)..."
docker rm -f presidio-bench 2>/dev/null || true
docker run -d --name presidio-bench -p ${PRESIDIO_PORT}:3000 \
    mcr.microsoft.com/presidio-analyzer:latest >/dev/null
ok "Presidio container started"

# Start Redact
info "Starting Redact (Docker)..."
docker rm -f redact-bench 2>/dev/null || true
docker run -d --name redact-bench -p ${REDACT_PORT}:8080 \
    redact:bench >/dev/null
ok "Redact container started"

# Wait for services
info "Waiting for services to be ready..."
for i in {1..60}; do
    p=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PRESIDIO_PORT}/health" 2>/dev/null || echo "0")
    r=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${REDACT_PORT}/health" 2>/dev/null || echo "0")
    if [[ "$p" == "200" && "$r" == "200" ]]; then
        ok "Both services ready"
        break
    fi
    if [[ $i -eq 60 ]]; then
        err "Services failed to start within 60 seconds"
    fi
    sleep 1
done

# Warm up
info "Warming up services..."
for i in {1..10}; do
    curl -s -X POST "http://localhost:${REDACT_PORT}/api/v1/analyze" \
        -H "Content-Type: application/json" -d "$PAYLOAD" >/dev/null
    curl -s -X POST "http://localhost:${PRESIDIO_PORT}/analyze" \
        -H "Content-Type: application/json" -d "$PAYLOAD" >/dev/null
done
ok "Warmup complete"

mkdir -p "$RESULTS_DIR"

echo ""
echo "========================================"
echo "  Running Benchmarks"
echo "========================================"

# Latency test (concurrency 1)
echo ""
info "Latency Test (concurrency=1, requests=$REQUESTS)"
echo ""
echo "--- Redact ---"
"$OHABIN" -n "$REQUESTS" -c 1 \
    --method POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "http://localhost:${REDACT_PORT}/api/v1/analyze" \
    | tee "${RESULTS_DIR}/redact-latency-${TIMESTAMP}.txt"

echo ""
echo "--- Presidio ---"
"$OHABIN" -n "$REQUESTS" -c 1 \
    --method POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "http://localhost:${PRESIDIO_PORT}/analyze" \
    | tee "${RESULTS_DIR}/presidio-latency-${TIMESTAMP}.txt"

# Throughput test (concurrency 10)
THROUGHPUT_REQUESTS=$((REQUESTS * 5))
echo ""
info "Throughput Test (concurrency=10, requests=$THROUGHPUT_REQUESTS)"
echo ""
echo "--- Redact ---"
"$OHABIN" -n "$THROUGHPUT_REQUESTS" -c 10 \
    --method POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "http://localhost:${REDACT_PORT}/api/v1/analyze" \
    | tee "${RESULTS_DIR}/redact-throughput-${TIMESTAMP}.txt"

echo ""
echo "--- Presidio ---"
"$OHABIN" -n "$THROUGHPUT_REQUESTS" -c 10 \
    --method POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "http://localhost:${PRESIDIO_PORT}/analyze" \
    | tee "${RESULTS_DIR}/presidio-throughput-${TIMESTAMP}.txt"

# Extract metrics from text output
extract_percentile() {
    local file="$1"
    local pct="$2"
    grep -E "^\s+${pct}% in" "$file" | awk '{print $3}'
}

# Latency metrics (from concurrency=1 test)
REDACT_P50=$(extract_percentile "${RESULTS_DIR}/redact-latency-${TIMESTAMP}.txt" "50.00")
REDACT_P99=$(extract_percentile "${RESULTS_DIR}/redact-latency-${TIMESTAMP}.txt" "99.00")
REDACT_AVG=$(grep "Average:" "${RESULTS_DIR}/redact-latency-${TIMESTAMP}.txt" | awk '{print $2}')

PRESIDIO_P50=$(extract_percentile "${RESULTS_DIR}/presidio-latency-${TIMESTAMP}.txt" "50.00")
PRESIDIO_P99=$(extract_percentile "${RESULTS_DIR}/presidio-latency-${TIMESTAMP}.txt" "99.00")
PRESIDIO_AVG=$(grep "Average:" "${RESULTS_DIR}/presidio-latency-${TIMESTAMP}.txt" | awk '{print $2}')

# Throughput metrics (from concurrency=10 test)
REDACT_RPS=$(grep "Requests/sec" "${RESULTS_DIR}/redact-throughput-${TIMESTAMP}.txt" | awk '{print $2}')
PRESIDIO_RPS=$(grep "Requests/sec" "${RESULTS_DIR}/presidio-throughput-${TIMESTAMP}.txt" | awk '{print $2}')

# Calculate speedups (strip 'ms' suffix for calculation)
strip_ms() { echo "$1" | sed 's/ *ms//'; }
REDACT_P50_NUM=$(strip_ms "$REDACT_P50")
REDACT_P99_NUM=$(strip_ms "$REDACT_P99")
PRESIDIO_P50_NUM=$(strip_ms "$PRESIDIO_P50")
PRESIDIO_P99_NUM=$(strip_ms "$PRESIDIO_P99")

P50_SPEEDUP=$(echo "scale=1; $PRESIDIO_P50_NUM / $REDACT_P50_NUM" | bc 2>/dev/null || echo "-")
P99_SPEEDUP=$(echo "scale=1; $PRESIDIO_P99_NUM / $REDACT_P99_NUM" | bc 2>/dev/null || echo "-")
RPS_SPEEDUP=$(echo "scale=1; $REDACT_RPS / $PRESIDIO_RPS" | bc 2>/dev/null || echo "-")

# Generate markdown report
cat > "${RESULTS_DIR}/results-${TIMESTAMP}.md" << EOF
# Benchmark Results

**Date:** $(date +%Y-%m-%d)  
**Tool:** [oha](https://github.com/hatoo/oha)  
**Requests:** $REQUESTS | **Concurrency:** $CONCURRENCY  
**Platform:** $(uname -s) $(uname -m)  
**Environment:** Both services running in Docker containers

## Summary

| Metric | Redact (Rust) | Presidio (Python) | Speedup |
|--------|---------------|-------------------|---------|
| p50 Latency | ${REDACT_P50} ms | ${PRESIDIO_P50} ms | **${P50_SPEEDUP}x** |
| p99 Latency | ${REDACT_P99} ms | ${PRESIDIO_P99} ms | **${P99_SPEEDUP}x** |
| Avg Latency | ${REDACT_AVG} ms | ${PRESIDIO_AVG} ms | - |
| Requests/sec | ${REDACT_RPS} | ${PRESIDIO_RPS} | **${RPS_SPEEDUP}x** |

## Test Payload

\`\`\`
${TEST_TEXT}
\`\`\`

Entities detected: EMAIL_ADDRESS, PHONE_NUMBER, US_SSN

## Environment Details

- **Redact:** Docker container (rust:1.93-slim base)
- **Presidio:** Docker container (mcr.microsoft.com/presidio-analyzer:latest)
- **Benchmark tool:** oha v$("$OHABIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")

## Raw Data

- Latency test: [redact-latency-${TIMESTAMP}.txt](redact-latency-${TIMESTAMP}.txt), [presidio-latency-${TIMESTAMP}.txt](presidio-latency-${TIMESTAMP}.txt)
- Throughput test: [redact-throughput-${TIMESTAMP}.txt](redact-throughput-${TIMESTAMP}.txt), [presidio-throughput-${TIMESTAMP}.txt](presidio-throughput-${TIMESTAMP}.txt)

## Reproduce

\`\`\`bash
./scripts/benchmark-comparison.sh --requests $REQUESTS --concurrency $CONCURRENCY
\`\`\`
EOF

echo ""
echo "========================================"
echo "  Summary"
echo "========================================"
echo ""
printf "%-20s %-15s %-15s %-10s\n" "Metric" "Redact" "Presidio" "Speedup"
printf "%-20s %-15s %-15s %-10s\n" "------" "------" "--------" "-------"
printf "%-20s %-15s %-15s %-10s\n" "p50 Latency" "${REDACT_P50} ms" "${PRESIDIO_P50} ms" "${P50_SPEEDUP}x"
printf "%-20s %-15s %-15s %-10s\n" "p99 Latency" "${REDACT_P99} ms" "${PRESIDIO_P99} ms" "${P99_SPEEDUP}x"
printf "%-20s %-15s %-15s %-10s\n" "Requests/sec" "${REDACT_RPS}" "${PRESIDIO_RPS}" "${RPS_SPEEDUP}x"
echo ""
ok "Results saved to ${RESULTS_DIR}/results-${TIMESTAMP}.md"
