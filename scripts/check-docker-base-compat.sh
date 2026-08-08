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

# Strip optional --platform=... and AS/as stage name from a FROM line.
parse_image() {
  sed -E 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?//; s/[[:space:]]+[Aa][Ss][[:space:]].*$//' <<<"$1"
}

# Validate one rust builder image against the expected distroless Debian major.
check_builder_image() {
  local file="$1"
  local builder_image="$2"
  local expected="$3"
  local codename

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

  local builder_expected
  builder_expected="$(expected_debian_major "$codename")" \
    || fail "$file: unsupported builder Debian codename '$codename'"

  if [[ "$builder_expected" != "$expected" ]]; then
    fail "$file: builder '$builder_image' (codename $codename) expects distroless/cc-debian${builder_expected}, runtime requires debian${expected}"
  fi
}

check_file() {
  local file="$1"
  local runtime_line runtime_image debian_major expected
  local -a builder_lines=()
  local builder_line builder_image

  [[ -f "$file" ]] || fail "missing Dockerfile: $file"

  mapfile -t builder_lines < <(grep -E '^FROM[[:space:]]' "$file" | grep -E 'rust:' || true)
  runtime_line="$(grep -E '^FROM[[:space:]]' "$file" | grep -E 'distroless/cc-debian' | tail -n1 || true)"

  [[ ${#builder_lines[@]} -gt 0 ]] || fail "$file: no rust builder FROM line found"
  [[ -n "$runtime_line" ]] || fail "$file: no distroless/cc-debian runtime FROM line found"

  runtime_image="$(parse_image "$runtime_line")"

  if [[ "$runtime_image" =~ distroless/cc-debian([0-9]+) ]]; then
    debian_major="${BASH_REMATCH[1]}"
  else
    fail "$file: could not parse distroless Debian major from '$runtime_image'"
  fi
  expected="$debian_major"

  for builder_line in "${builder_lines[@]}"; do
    builder_image="$(parse_image "$builder_line")"
    check_builder_image "$file" "$builder_image" "$expected"
    echo "OK: $(basename "$file") builder=$builder_image runtime=$runtime_image"
  done
}

main() {
  local f
  for f in "${FILES[@]}"; do
    check_file "$f"
  done
  echo "All Dockerfiles have matching builder/runtime Debian trains."
}

main "$@"
