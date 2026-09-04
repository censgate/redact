#!/usr/bin/env bash
# Opt-in wall-clock of POST /v1/redact at concurrency 1 vs 5.
# Does not replace the platform latency harness. Skip if URL unset.
#
# Usage:
#   PLATFORM_REDACT_GATEWAY_URL=http://127.0.0.1:8080 \
#   PLATFORM_REDACT_GATEWAY_API_KEY=... \
#   ./scripts/bench-redact-concurrency.sh
set -euo pipefail

BASE="${PLATFORM_REDACT_GATEWAY_URL:-}"
if [[ -z "${BASE}" ]]; then
  echo "skip: PLATFORM_REDACT_GATEWAY_URL unset"
  exit 0
fi
BASE="${BASE%/}"
KEY="${PLATFORM_REDACT_GATEWAY_API_KEY:-}"
AUTH=()
if [[ -n "${KEY}" ]]; then
  AUTH=(-H "Authorization: Bearer ${KEY}")
fi

short='{"text":"Ada Lovelace","session_id":"bench-short"}'
long_text="$(python3 - <<'PY'
print("Ada Lovelace " * 80)
PY
)"
long="$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1], "session_id": "bench-long"}))' "${long_text}")"

curl_one() {
  local body="$1"
  local start end
  start="$(date +%s%N)"
  curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    "${AUTH[@]}" \
    -d "${body}" \
    "${BASE}/v1/redact" >/tmp/bench-redact-status
  end="$(date +%s%N)"
  python3 -c "print((${end}-${start})/1e6)"
}

run_conc() {
  local n="$1"
  local body="$2"
  local pids=()
  local i
  local start end
  start="$(date +%s%N)"
  for ((i = 0; i < n; i++)); do
    curl -sS -o /dev/null \
      -H 'Content-Type: application/json' \
      "${AUTH[@]}" \
      -d "${body}" \
      "${BASE}/v1/redact" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "${pid}"
  done
  end="$(date +%s%N)"
  python3 -c "print((${end}-${start})/1e6)"
}

echo "gateway ${BASE}"
echo "short conc1_ms=$(curl_one "${short}") conc5_ms=$(run_conc 5 "${short}")"
echo "long  conc1_ms=$(curl_one "${long}") conc5_ms=$(run_conc 5 "${long}")"
echo "If conc5 ≈ 5× conc1, the ONNX session mutex is serializing parallel /v1/redact."
