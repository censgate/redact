#!/usr/bin/env bash
# Resolve a family of tags on one repository to a single manifest-list digest.
# Prints the digest on stdout; tag comparisons go to stderr.
#
# Usage: verify-image-digest.sh <repo> <tag,tag,tag>
# Example: verify-image-digest.sh ghcr.io/censgate/redact-gateway 0.9.1,0.9,0,latest
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

REPO="${1:-${IMAGE_REPO:?IMAGE_REPO or repo arg is required}}"
TAGS_CSV="${2:-${IMAGE_TAGS:?IMAGE_TAGS or tags arg is required}}"

require_cmd docker

digest_for() {
  local ref="$1"
  local out digest
  out="$(docker buildx imagetools inspect "${ref}")" || fail "imagetools inspect failed for ${ref}"
  digest="$(awk '/^Digest:/{print $2; exit}' <<<"${out}")"
  [[ -n "${digest}" ]] || fail "could not parse Digest from imagetools inspect of ${ref}"
  echo "${digest}"
}

IFS=',' read -r -a tags <<<"${TAGS_CSV}"
[[ ${#tags[@]} -gt 0 ]] || fail "no tags provided"

first_tag=""
first_digest=""
for tag in "${tags[@]}"; do
  tag="${tag#"${tag%%[![:space:]]*}"}"
  tag="${tag%"${tag##*[![:space:]]}"}"
  [[ -n "${tag}" ]] || continue
  ref="${REPO}:${tag}"
  digest="$(digest_for "${ref}")"
  echo "${ref} -> ${digest}" >&2
  if [[ -z "${first_digest}" ]]; then
    first_tag="${tag}"
    first_digest="${digest}"
  elif [[ "${digest}" != "${first_digest}" ]]; then
    fail "${REPO}:${tag} digest ${digest} != ${REPO}:${first_tag} digest ${first_digest}"
  fi
done

[[ -n "${first_digest}" ]] || fail "no tags resolved"
echo "OK: ${#tags[@]} tags share ${first_digest}" >&2
echo "${first_digest}"
