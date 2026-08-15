#!/usr/bin/env bash
# Smoke-test a redact-gateway image: it must redact, not merely link.
#
# Two POSTs, matching docs/gateway/getting-started.md:
#   1. Email only → replaced, blocked=false
#   2. Email + AWS sample key → blocked=true, text unchanged, AWS_ACCESS_KEY
#      in blocked_entities. Default profile fail-closes on credentials.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

IMAGE="${1:-${IMAGE:?IMAGE is required (arg or env)}}"
NAME="${SMOKE_NAME:-gw-smoke}"
HOST_PORT="${SMOKE_PORT:-8080}"
WAIT_SECS="$(smoke_wait_secs)"
BASE="http://127.0.0.1:${HOST_PORT}"

require_cmd docker
require_cmd curl
require_cmd python3

run_cmd=(docker run -d --name "${NAME}" -p "${HOST_PORT}:8080" -e OTEL_SDK_DISABLED=true)
append_platform run_cmd
run_cmd+=("${IMAGE}")
"${run_cmd[@]}"
cleanup() { docker rm -f "${NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_for_http "${BASE}/healthz" "${NAME}" "${WAIT_SECS}"

echo "--- Email-only redact ---"
EMAIL_BODY="$(curl -sf "${BASE}/v1/redact" \
  -H 'content-type: application/json' \
  -d '{"text":"Email me at alice@example.com"}')"
echo "${EMAIL_BODY}" | python3 -m json.tool
echo "${EMAIL_BODY}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
text = data.get('text', '')
if data.get('blocked') is not False:
    raise SystemExit('ERROR: email-only request must set blocked=false, got ' + repr(data.get('blocked')))
if 'alice@example.com' in text:
    raise SystemExit('ERROR: plaintext email still present')
if '[EMAIL_ADDRESS]' not in text:
    raise SystemExit('ERROR: expected [EMAIL_ADDRESS] placeholder, got: ' + text)
print('OK: email replaced, blocked=false')
"

echo "--- Email + AWS access key (default profile blocks credentials) ---"
# AWS docs sample shape; split so scanners do not see a contiguous secret.
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"
ORIGINAL="Contact alice@example.com with key ${AWS_KEY}"
COMBO_BODY="$(curl -sf "${BASE}/v1/redact" \
  -H 'content-type: application/json' \
  -d "{\"text\":\"${ORIGINAL}\"}")"
echo "${COMBO_BODY}" | python3 -m json.tool
echo "${COMBO_BODY}" | ORIGINAL="${ORIGINAL}" python3 -c "
import json, os, sys
data = json.load(sys.stdin)
original = os.environ['ORIGINAL']
if data.get('blocked') is not True:
    raise SystemExit('ERROR: expected blocked=true for AWS access key')
got = data.get('text')
if got != original:
    raise SystemExit(
        'ERROR: blocked response must keep original text; '
        f'expected {original!r}, got {got!r}'
    )
blocked = data.get('outcome', {}).get('blocked_entities') or []
if 'AWS_ACCESS_KEY' not in blocked:
    raise SystemExit('ERROR: expected AWS_ACCESS_KEY in blocked_entities, got ' + str(blocked))
email_replace = (
    data.get('outcome', {})
    .get('entity_action_counts', {})
    .get('EMAIL_ADDRESS', {})
    .get('replace', 0)
)
if email_replace < 1:
    raise SystemExit('ERROR: expected EMAIL_ADDRESS replace in outcome')
print('OK: blocked=true, original text preserved, email counted as replace')
"

echo "OK: gateway smoke passed (${IMAGE})"
