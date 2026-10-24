#!/usr/bin/env bash
# Multilingual redaction coverage: anonymize per-locale fixtures and
# fail if an original value, or any 4+ digit substring of one, is still
# present.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${1:-$ROOT/target/debug/redact}"
FIXTURE_DIR="${2:-$ROOT/scripts/ci/fixtures/multilingual-coverage}"
VALUES_FILE="${FIXTURE_DIR}/values.txt"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: redact binary not executable: $BIN" >&2
  exit 1
fi
if [[ ! -f "$VALUES_FILE" ]]; then
  echo "ERROR: missing $VALUES_FILE" >&2
  exit 1
fi

mapfile -t VALUES < <(grep -vE '^\s*(#|$)' "$VALUES_FILE")
if [[ ${#VALUES[@]} -eq 0 ]]; then
  echo "ERROR: no fixture values listed in $VALUES_FILE" >&2
  exit 1
fi

failed=0
scanned=0

digit_runs() {
  local value="$1"
  grep -oE '[0-9]{4,}' <<<"$value" || true
}

for fixture in "${FIXTURE_DIR}"/*.txt; do
  lang="$(basename "$fixture" .txt)"
  if [[ "$lang" == "values" ]]; then
    continue
  fi
  scanned=$((scanned + 1))
  echo "=== locale ${lang} ==="
  out="$("$BIN" --language "$lang" anonymize --strategy replace -i "$fixture")"
  for value in "${VALUES[@]}"; do
    if grep -F -q -- "$value" <<<"$out"; then
      echo "${lang}: fixture value still present after anonymize" >&2
      failed=1
    fi
    while IFS= read -r digits; do
      [[ -z "$digits" ]] && continue
      if grep -F -q -- "$digits" <<<"$out"; then
        echo "${lang}: 4+ digit run still present after anonymize" >&2
        failed=1
      fi
    done < <(digit_runs "$value")
  done
done

if [[ "$scanned" -eq 0 ]]; then
  echo "ERROR: no locale fixtures in $FIXTURE_DIR" >&2
  exit 1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "multilingual redaction coverage failed (${scanned} locales)" >&2
  exit 1
fi

echo "multilingual redaction coverage ok: ${scanned} locales"
