#!/usr/bin/env bash
# Smoke-test a redact-full (pattern + ONNX NER) image.
# Asserts recognizers >= 2 and at least two of PERSON/ORGANIZATION/LOCATION
# on a real sentence — the same bar the release job already set.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

IMAGE="${1:-${IMAGE:?IMAGE is required (arg or env)}}"
NAME="${SMOKE_NAME:-ner-smoke}"
HOST_PORT="${SMOKE_PORT:-8080}"
WAIT_SECS="$(smoke_wait_secs)"

require_cmd docker
require_cmd curl
require_cmd python3

run_cmd=(docker run -d --name "${NAME}" -p "${HOST_PORT}:8080")
append_platform run_cmd
run_cmd+=("${IMAGE}")
"${run_cmd[@]}"
cleanup() { docker rm -f "${NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_for_http "http://127.0.0.1:${HOST_PORT}/healthz" "${NAME}" "${WAIT_SECS}"

echo "--- Health check ---"
HEALTH="$(curl -sf "http://127.0.0.1:${HOST_PORT}/healthz")"
echo "${HEALTH}" | python3 -m json.tool
RECOGNIZERS="$(echo "${HEALTH}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('recognizers',0))")"
if [[ "${RECOGNIZERS}" -lt 2 ]]; then
  fail "Expected at least 2 recognizers (pattern + NER), got ${RECOGNIZERS}"
fi
echo "OK: ${RECOGNIZERS} recognizers"

echo "--- NER entity detection ---"
RESULT="$(curl -sf "http://127.0.0.1:${HOST_PORT}/api/v1/analyze" \
  -H 'Content-Type: application/json' \
  -d '{"text": "John Smith works at Microsoft in Seattle"}')"
echo "${RESULT}" | python3 -m json.tool
NER_FOUND="$(echo "${RESULT}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('results', [])
types = {e['entity_type'] for e in results}
ner_types = types & {'PERSON', 'ORGANIZATION', 'LOCATION'}
print(len(ner_types))
")"
if [[ "${NER_FOUND}" -lt 2 ]]; then
  fail "Expected at least 2 NER entity types (PERSON/ORG/LOC), found ${NER_FOUND}"
fi
echo "OK: ${NER_FOUND} NER entity types detected"
echo "OK: NER smoke passed (${IMAGE})"
