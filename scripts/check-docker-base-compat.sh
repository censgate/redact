#!/usr/bin/env bash
# Verify multi-stage Dockerfiles pin the Rust builder Debian train to match
# the distroless runtime (avoids GLIBC symbol mismatches like #114).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILES=(
  "${ROOT}/Dockerfile"
  "${ROOT}/Dockerfile.gateway"
  "${ROOT}/Dockerfile.ner"
)

# bookworm -> debian12, trixie -> debian13, bullseye -> debian11
expected_debian_major() {
  case "$1" in
    bookworm) echo 12 ;;
    trixie) echo 13 ;;
    bullseye) echo 11 ;;
    *) return 1 ;;
  esac
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

check_file() {
  local file="$1"
  local builder_line runtime_line builder_image runtime_image
  local codename debian_major expected

  [[ -f "$file" ]] || fail "missing Dockerfile: $file"

  builder_line="$(grep -E '^FROM[[:space:]]' "$file" | grep -E 'rust:' | tail -n1 || true)"
  runtime_line="$(grep -E '^FROM[[:space:]]' "$file" | grep -E 'distroless/cc-debian' | tail -n1 || true)"

  [[ -n "$builder_line" ]] || fail "$file: no rust builder FROM line found"
  [[ -n "$runtime_line" ]] || fail "$file: no distroless/cc-debian runtime FROM line found"

  # Strip optional --platform=... and AS stage name
  builder_image="$(sed -E 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?//; s/[[:space:]]+AS[[:space:]].*$//' <<<"$builder_line")"
  runtime_image="$(sed -E 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?//; s/[[:space:]]+AS[[:space:]].*$//' <<<"$runtime_line")"

  if [[ "$builder_image" =~ ^rust:([0-9]+\.[0-9]+(\.[0-9]+)?)-slim$ ]]; then
    fail "$file: floating builder '$builder_image' (use an explicit Debian codename, e.g. rust:${BASH_REMATCH[1]}-slim-bookworm)"
  fi

  if [[ "$builder_image" =~ ^rust:[^[:space:]]+-slim-(bookworm|trixie|bullseye)(@.+)?$ ]]; then
    codename="${BASH_REMATCH[1]}"
  elif [[ "$builder_image" =~ ^rust:[^[:space:]]+-(bookworm|trixie|bullseye)(@.+)?$ ]]; then
    codename="${BASH_REMATCH[1]}"
  else
    fail "$file: builder '$builder_image' must include an explicit Debian codename (-bookworm/-trixie/-bullseye)"
  fi

  expected="$(expected_debian_major "$codename")" \
    || fail "$file: unsupported builder Debian codename '$codename'"

  if [[ "$runtime_image" =~ distroless/cc-debian([0-9]+) ]]; then
    debian_major="${BASH_REMATCH[1]}"
  else
    fail "$file: could not parse distroless Debian major from '$runtime_image'"
  fi

  if [[ "$debian_major" != "$expected" ]]; then
    fail "$file: builder codename '$codename' expects distroless/cc-debian${expected}, found '$runtime_image'"
  fi

  echo "OK: $(basename "$file") builder=$builder_image runtime=$runtime_image"
}

main() {
  local f
  for f in "${FILES[@]}"; do
    check_file "$f"
  done
  echo "All Dockerfiles have matching builder/runtime Debian trains."
}

main "$@"
