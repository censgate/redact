#!/usr/bin/env bash
# Shared helpers for release/CI image smoke scripts.
# shellcheck shell=bash

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# Default wait: 30s native, 180s under QEMU/arm64 (NER especially).
smoke_wait_secs() {
  if [[ -n "${SMOKE_WAIT_SECS:-}" ]]; then
    echo "${SMOKE_WAIT_SECS}"
    return
  fi
  case "${PLATFORM:-${SMOKE_PLATFORM:-}}" in
    *arm64*) echo 180 ;;
    *) echo 30 ;;
  esac
}

# Append --platform when PLATFORM or SMOKE_PLATFORM is set.
append_platform() {
  local -n _smoke_args=$1
  local platform="${PLATFORM:-${SMOKE_PLATFORM:-}}"
  if [[ -n "${platform}" ]]; then
    _smoke_args+=(--platform "${platform}")
  fi
}

# Wait until url answers, or the named container exits.
wait_for_http() {
  local url="$1"
  local name="$2"
  local secs="$3"
  local i
  echo "Waiting for ${url} (${secs}s)..."
  for i in $(seq 1 "${secs}"); do
    if curl -sf "${url}" >/dev/null 2>&1; then
      echo "Ready after ${i}s"
      return 0
    fi
    if ! docker ps -q -f "name=^/${name}$" | grep -q .; then
      echo "ERROR: container ${name} exited early" >&2
      docker logs "${name}" >&2 || true
      return 1
    fi
    sleep 1
  done
  echo "ERROR: ${url} not ready within ${secs}s" >&2
  docker logs "${name}" >&2 || true
  return 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}
