#!/usr/bin/env bash
# Assert each expected crate version is present on the crates.io index.
# Used after `cargo publish` steps that carry continue-on-error (already-published
# vs genuine failure are otherwise indistinguishable).
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [[ "${1:-}" == "--self-test" ]]; then
  # All requests are intercepted by a temporary curl fixture. No registry
  # credentials, publication commands or network access are used by this test.
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cat >"$work/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
url="${!#}"
[[ "$url" == https://index.crates.io/* ]] || exit 99
printf '%s\n' "$url" >>"$FIXTURE_REQUESTS"
crate="${url##*/}"
case "${FIXTURE_MODE:-present}" in
  missing) exit 22 ;;
  wrong) printf '{"name":"%s","vers":"0.0.0","yanked":false}\n' "$crate" ;;
  yanked) printf '{"name":"%s","vers":"9.9.9","yanked":true}\n' "$crate" ;;
  malformed) printf 'not-json\n' ;;
  retry)
    if [[ $(wc -l <"$FIXTURE_REQUESTS") -eq 1 ]]; then exit 22; fi
    printf '{"name":"%s","vers":"9.9.9","yanked":false}\n' "$crate"
    ;;
  *) printf '{"name":"%s","vers":"9.9.9","yanked":false}\n' "$crate" ;;
esac
STUB
  chmod +x "$work/curl"
  export PATH="$work:$PATH" TAG_VERSION=9.9.9 FIXTURE_REQUESTS="$work/requests"
  export CRATES_VERIFY_TIMEOUT_SECS=0 CRATES_VERIFY_SLEEP_SECS=0
  unset CRATES
  bash "${BASH_SOURCE[0]}" >"$work/result" 2>&1
  grep -q '/re/da/redact-token-store$' "$FIXTURE_REQUESTS"
  grep -q '/re/da/redact-gateway$' "$FIXTURE_REQUESTS"
  [[ $(wc -l <"$FIXTURE_REQUESTS") -eq 8 ]]
  for mode in missing wrong yanked malformed; do
    if FIXTURE_MODE="$mode" CRATES=redact-token-store bash "${BASH_SOURCE[0]}" >"$work/result" 2>&1; then
      fail "registry gate accepted $mode fixture"
    fi
  done
  : >"$FIXTURE_REQUESTS"
  FIXTURE_MODE=retry CRATES=redact-token-store CRATES_VERIFY_TIMEOUT_SECS=2 bash "${BASH_SOURCE[0]}" >"$work/result" 2>&1
  [[ $(wc -l <"$FIXTURE_REQUESTS") -eq 2 ]]
  echo "OK: verify-crates.sh self-test (presence, absence, version, yank, malformed, retry)"
  exit 0
fi

TAG_VERSION="${TAG_VERSION:?TAG_VERSION is required (semver without leading v)}"
# Space-separated; override when publishing a subset (publish-crates.yml).
CRATES="${CRATES:-redact-core redact-ner redact-api redact-cli redact-token-store redact-gateway redact-scan redact-verify}"
USER_AGENT="${CRATES_USER_AGENT:-censgate-redact-ci (https://github.com/censgate/redact)}"
TIMEOUT_SECS="${CRATES_VERIFY_TIMEOUT_SECS:-300}"
SLEEP_SECS="${CRATES_VERIFY_SLEEP_SECS:-15}"

require_cmd curl
require_cmd python3

crate_has_version() {
  local crate="$1"
  local version="$2"
  local body index_path
  [[ "$crate" =~ ^[a-z0-9_-]+$ ]] || return 1
  case "${#crate}" in
    1) index_path="1/$crate" ;;
    2) index_path="2/$crate" ;;
    3) index_path="3/${crate:0:1}/$crate" ;;
    *) index_path="${crate:0:2}/${crate:2:2}/$crate" ;;
  esac
  # API visibility can precede index propagation. Query what Cargo resolves,
  # and reject yanked versions even when the publication itself succeeded.
  body="$(curl -fsSL --connect-timeout 10 --max-time 20 -A "${USER_AGENT}" "https://index.crates.io/${index_path}")" || return 1
  printf '%s\n' "${body}" | python3 -c "
import json, sys
crate, wanted = sys.argv[1:]
try:
    entries = [json.loads(line) for line in sys.stdin if line.strip()]
    found = any(v.get('name') == crate and v.get('vers') == wanted and v.get('yanked') is False for v in entries)
except (ValueError, AttributeError):
    sys.exit(1)
sys.exit(0 if found else 1)
" "${crate}" "${version}"
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
