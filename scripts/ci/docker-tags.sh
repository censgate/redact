#!/usr/bin/env bash
# Compute the Docker tag list for a release image family.
#
# Usage:
#   docker-tags.sh <family> <version> [image]
#
# family:  api | full | gateway
# version: semver without a leading v (0.10.0 or 0.10.0-rc.1)
# image:   optional repository prefix; when set, each tag is printed as image:tag
#
# Prints a CSV on stdout. Hyphenated (prerelease) versions emit only the
# exact version tag so :latest / :MAJOR / :MINOR / :full are not rewritten.
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

usage() {
  echo "Usage: docker-tags.sh <family> <version> [image]" >&2
  echo "       docker-tags.sh --self-test" >&2
}

is_prerelease() {
  [[ "$1" == *-* ]]
}

# Strip a leading v so callers can pass ${VERSION#v} or the raw tag.
normalize_version() {
  local ver="$1"
  ver="${ver#v}"
  [[ -n "${ver}" ]] || fail "empty version"
  echo "${ver}"
}

tag_csv() {
  local family="$1"
  local ver="$2"
  local major minor

  case "${family}" in
    api|gateway)
      if is_prerelease "${ver}"; then
        echo "${ver}"
      else
        major="${ver%%.*}"
        minor="${ver%.*}"
        echo "${ver},${minor},${major},latest"
      fi
      ;;
    full)
      if is_prerelease "${ver}"; then
        echo "${ver}-full"
      else
        major="${ver%%.*}"
        minor="${ver%.*}"
        echo "${ver}-full,${minor}-full,${major}-full,full"
      fi
      ;;
    *)
      fail "unknown family: ${family} (expected api, full, or gateway)"
      ;;
  esac
}

prefix_csv() {
  local csv="$1"
  local image="$2"
  local out="" tag
  local IFS=','
  # shellcheck disable=SC2086
  for tag in ${csv}; do
    out="${out:+${out},}${image}:${tag}"
  done
  echo "${out}"
}

expect_eq() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [[ "${got}" != "${want}" ]]; then
    fail "self-test ${label}: got '${got}', want '${want}'"
  fi
}

self_test() {
  expect_eq "$(tag_csv api 0.10.0)" "0.10.0,0.10,0,latest" "api stable"
  expect_eq "$(tag_csv gateway 0.10.0)" "0.10.0,0.10,0,latest" "gateway stable"
  expect_eq "$(tag_csv full 0.10.0)" "0.10.0-full,0.10-full,0-full,full" "full stable"
  expect_eq "$(tag_csv api 0.10.0-rc.1)" "0.10.0-rc.1" "api prerelease"
  expect_eq "$(tag_csv gateway 0.10.0-rc.1)" "0.10.0-rc.1" "gateway prerelease"
  expect_eq "$(tag_csv full 0.10.0-rc.1)" "0.10.0-rc.1-full" "full prerelease"
  expect_eq "$(tag_csv api 0.9.1)" "0.9.1,0.9,0,latest" "api patch"
  expect_eq \
    "$(prefix_csv "$(tag_csv api 0.10.0-rc.1)" "ghcr.io/censgate/redact")" \
    "ghcr.io/censgate/redact:0.10.0-rc.1" \
    "prefixed prerelease"
  echo "OK: docker-tags.sh self-test"
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    return
  fi
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 2 ]]; then
    usage
    [[ $# -ge 2 ]] || exit 1
    exit 0
  fi

  local family="$1"
  local ver
  ver="$(normalize_version "$2")"
  local image="${3:-}"
  local csv
  csv="$(tag_csv "${family}" "${ver}")"
  if [[ -n "${image}" ]]; then
    prefix_csv "${csv}" "${image}"
  else
    echo "${csv}"
  fi
}

main "$@"
