#!/usr/bin/env bash
# Assert each expected crate version is present on the crates.io index.
# Used after `cargo publish` steps that carry continue-on-error (already-published
# vs genuine failure are otherwise indistinguishable).
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

TAG_VERSION="${TAG_VERSION:?TAG_VERSION is required (semver without leading v)}"
# Space-separated; override when publishing a subset (publish-crates.yml).
CRATES="${CRATES:-redact-core redact-ner redact-api redact-cli redact-gateway redact-scan redact-verify}"
USER_AGENT="${CRATES_USER_AGENT:-censgate-redact-ci (https://github.com/censgate/redact)}"
TIMEOUT_SECS="${CRATES_VERIFY_TIMEOUT_SECS:-300}"
SLEEP_SECS="${CRATES_VERIFY_SLEEP_SECS:-15}"

require_cmd curl
require_cmd python3

crate_has_version() {
  local crate="$1"
  local version="$2"
  local body
  body="$(curl -fsSL -A "${USER_AGENT}" "https://crates.io/api/v1/crates/${crate}")" || return 1
  echo "${body}" | python3 -c "
import json, sys
wanted = sys.argv[1]
data = json.load(sys.stdin)
nums = {v.get('num') for v in data.get('versions', [])}
sys.exit(0 if wanted in nums else 1)
" "${version}"
}

deadline=$((SECONDS + TIMEOUT_SECS))
pending="${CRATES}"
echo "Waiting up to ${TIMEOUT_SECS}s for crates.io to list ${TAG_VERSION}:"
echo "  ${pending}"

while :; do
  still=""
  for crate in ${pending}; do
    if crate_has_version "${crate}" "${TAG_VERSION}"; then
      echo "OK: ${crate} ${TAG_VERSION} is on crates.io"
    else
      echo "missing: ${crate} ${TAG_VERSION}"
      still="${still} ${crate}"
    fi
  done
  still="${still# }"
  if [[ -z "${still}" ]]; then
    echo "All expected crate versions are present."
    exit 0
  fi
  if (( SECONDS >= deadline )); then
    fail "crates.io still missing ${TAG_VERSION} for:${still}"
  fi
  pending="${still}"
  echo "Retrying in ${SLEEP_SECS}s..."
  sleep "${SLEEP_SECS}"
done
