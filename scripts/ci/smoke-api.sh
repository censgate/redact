#!/usr/bin/env bash
# Smoke-test a redact-api image: start it and wait for /healthz.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

IMAGE="${1:-${IMAGE:?IMAGE is required (arg or env)}}"
NAME="${SMOKE_NAME:-api-smoke}"
HOST_PORT="${SMOKE_PORT:-8080}"
WAIT_SECS="$(smoke_wait_secs)"

require_cmd docker
require_cmd curl

run_cmd=(docker run -d --name "${NAME}" -p "${HOST_PORT}:8080")
append_platform run_cmd
run_cmd+=("${IMAGE}")
"${run_cmd[@]}"
cleanup() { docker rm -f "${NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_for_http "http://127.0.0.1:${HOST_PORT}/healthz" "${NAME}" "${WAIT_SECS}"
curl -sf "http://127.0.0.1:${HOST_PORT}/healthz" | python3 -m json.tool
echo "OK: API smoke passed (${IMAGE})"
