#!/usr/bin/env bash
# Create or update the GitHub release for a tag that already exists.
#
# Idempotent. A second run refreshes the notes and leaves the release
# published. Missing assets are uploaded; assets already on a published
# release are left in place so a re-run succeeds when GitHub will not
# replace them. Draft releases are updated, their assets replaced, and
# then published.
#
# The script does not create git tags and does not publish crates or
# container images. Release notes are the changelog file plus GitHub's
# generated "What's Changed" section, matching the full release path.
#
# Usage:
#   publish-github-release.sh <tag> <notes-file> <assets-dir>
#   publish-github-release.sh --self-test
set -euo pipefail

usage() {
  echo "Usage: publish-github-release.sh <tag> <notes-file> <assets-dir>" >&2
  echo "       publish-github-release.sh --self-test" >&2
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

repo_slug() {
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    printf '%s\n' "${GITHUB_REPOSITORY}"
    return
  fi
  gh repo view --json nameWithOwner --jq .nameWithOwner
}

require_tag() {
  local repo="$1"
  local tag="$2"
  if ! gh api "repos/${repo}/git/ref/tags/${tag}" >/dev/null; then
    fail "tag ${tag} does not exist; refusing to create a tag"
  fi
}

write_body() {
  local repo="$1"
  local tag="$2"
  local notes_file="$3"
  local dest="$4"
  local gen_json
  gen_json="$(mktemp)"
  gh api --method POST "repos/${repo}/releases/generate-notes" \
    -f tag_name="${tag}" >"${gen_json}"
  python3 - "${notes_file}" "${gen_json}" "${dest}" <<'PY'
import json
import pathlib
import sys

notes_path, gen_path, dest = sys.argv[1:]
changelog = pathlib.Path(notes_path).read_text(encoding="utf-8")
if not changelog.endswith("\n"):
    changelog += "\n"
payload = json.loads(pathlib.Path(gen_path).read_text(encoding="utf-8"))
generated = str(payload["body"]).rstrip() + "\n"
# Same join as softprops/action-gh-release: changelog, a blank line, then
# the generated notes.
pathlib.Path(dest).write_text(changelog + "\n\n" + generated, encoding="utf-8")
PY
  rm -f "${gen_json}"
}

collect_assets() {
  local -n _out=$1
  local dir="$2"
  local f
  _out=()
  shopt -s nullglob
  for f in "${dir}"/*; do
    if [[ -f "${f}" ]]; then
      _out+=("${f}")
    fi
  done
  shopt -u nullglob
  [[ ${#_out[@]} -gt 0 ]] || fail "no release assets in ${dir}"
}

prerelease_arg() {
  local ver="${1#v}"
  if [[ "${ver}" == *-* ]]; then
    printf '%s\n' "--prerelease"
  else
    printf '%s\n' "--prerelease=false"
  fi
}

# Prints "missing", or "draft"/"published" plus one asset name per line.
release_state() {
  local tag="$1"
  local err json
  err="$(mktemp)"
  if json="$(gh release view "${tag}" --json isDraft,assets 2>"${err}")"; then
    rm -f "${err}"
    python3 -c 'import json,sys
data=json.loads(sys.argv[1])
print("draft" if data.get("isDraft") else "published")
for asset in data.get("assets") or []:
    print(asset["name"])
' "${json}"
    return 0
  fi
  if grep -Eqi 'not found|404' "${err}"; then
    rm -f "${err}"
    printf '%s\n' "missing"
    return 0
  fi
  cat "${err}" >&2
  rm -f "${err}"
  return 1
}

publish_release() {
  local tag="$1"
  local notes_file="$2"
  local assets_dir="$3"
  local repo body pr title state mode existing
  local -a assets missing
  local asset name missing_any

  require_cmd gh
  require_cmd python3
  [[ -n "${tag}" ]] || fail "tag is required"
  [[ -f "${notes_file}" ]] || fail "notes file not found: ${notes_file}"
  [[ -s "${notes_file}" ]] || fail "notes file is empty: ${notes_file}"
  [[ -d "${assets_dir}" ]] || fail "assets directory not found: ${assets_dir}"

  repo="$(repo_slug)"
  require_tag "${repo}" "${tag}"

  body="$(mktemp)"
  write_body "${repo}" "${tag}" "${notes_file}" "${body}"
  collect_assets assets "${assets_dir}"
  pr="$(prerelease_arg "${tag}")"
  title="Release ${tag}"

  state="$(release_state "${tag}")"
  mode="$(head -n 1 <<<"${state}")"
  existing="$(tail -n +2 <<<"${state}" || true)"

  if [[ "${mode}" == "missing" ]]; then
    gh release create "${tag}" \
      --verify-tag \
      --draft \
      --title "${title}" \
      --notes-file "${body}" \
      "${pr}"
    gh release upload "${tag}" "${assets[@]}"
    gh release edit "${tag}" \
      --verify-tag \
      --draft=false \
      --title "${title}" \
      --notes-file "${body}" \
      "${pr}"
    echo "Created GitHub release ${tag}"
  elif [[ "${mode}" == "draft" ]]; then
    gh release edit "${tag}" \
      --verify-tag \
      --draft=true \
      --title "${title}" \
      --notes-file "${body}" \
      "${pr}"
    gh release upload "${tag}" "${assets[@]}" --clobber
    gh release edit "${tag}" \
      --verify-tag \
      --draft=false \
      --title "${title}" \
      --notes-file "${body}" \
      "${pr}"
    echo "Updated draft and published GitHub release ${tag}"
  elif [[ "${mode}" == "published" ]]; then
    gh release edit "${tag}" \
      --verify-tag \
      --draft=false \
      --title "${title}" \
      --notes-file "${body}" \
      "${pr}"
    missing=()
    missing_any=false
    for asset in "${assets[@]}"; do
      name="$(basename "${asset}")"
      if ! grep -Fxq "${name}" <<<"${existing}"; then
        missing+=("${asset}")
        missing_any=true
      fi
    done
    if [[ "${missing_any}" == true ]]; then
      gh release upload "${tag}" "${missing[@]}"
    fi
    echo "Updated GitHub release ${tag}"
  else
    fail "unexpected release state for ${tag}: ${mode}"
  fi
  rm -f "${body}"
}

self_test() {
  local root bin state log notes assets script
  root="$(mktemp -d)"
  bin="${root}/bin"
  state="${root}/state"
  log="${root}/gh.log"
  notes="${root}/notes.md"
  assets="${root}/assets"
  script="${BASH_SOURCE[0]}"
  mkdir -p "${bin}" "${state}" "${assets}"
  printf '%s\n' '## [0.12.7] - 2026-11-01' '' '- nightly workflow' >"${notes}"
  printf 'bin' >"${assets}/redact-linux.tar.gz"
  printf 'bin' >"${assets}/redact-mac.tar.gz"

  cat >"${bin}/git" <<'EOF'
#!/bin/sh
echo "git invoked: $*" >&2
exit 99
EOF
  cat >"${bin}/gh" <<'EOF'
#!/usr/bin/env bash
# Test double. Records every invocation and keeps a fake release record.
set -euo pipefail
printf '%s\n' "$*" >> "${GH_LOG}"
joined="$*"
if [[ "$1" == "api" ]]; then
  if [[ "${joined}" == *"git/ref/tags/"* ]]; then
    if [[ "${GH_TAG_EXISTS:-1}" == "0" ]]; then
      echo "HTTP 404: Not Found" >&2
      exit 1
    fi
    echo '{"object":{"sha":"abc"}}'
    exit 0
  fi
  if [[ "${joined}" == *"generate-notes"* ]]; then
    printf '%s\n' '{"body":"## What'\''s Changed\n* sample"}'
    exit 0
  fi
  echo "unexpected api: ${joined}" >&2
  exit 1
fi
if [[ "$1" == "release" ]]; then
  python3 - "${GH_STATE}" "$@" <<'PY'
import json, os, sys
state = sys.argv[1]
args = sys.argv[2:]
record = os.path.join(state, "release.json")
notes_out = os.path.join(state, "last-notes.md")

def load():
    if not os.path.exists(record):
        return None
    return json.loads(open(record, encoding="utf-8").read())

def save(data):
    open(record, "w", encoding="utf-8").write(json.dumps(data))

def notes_from(argv):
    if "--notes-file" not in argv:
        return None
    path = argv[argv.index("--notes-file") + 1]
    return open(path, encoding="utf-8").read()

cmd = args[1]
if cmd == "view":
    data = load()
    if data is None:
        sys.stderr.write("release not found\n")
        sys.exit(1)
    sys.stdout.write(json.dumps({"isDraft": data["isDraft"], "assets": data["assets"]}))
elif cmd == "create":
    if "--verify-tag" not in args:
        sys.stderr.write("create without --verify-tag\n")
        sys.exit(1)
    if "--target" in args or any(a.startswith("--target=") for a in args):
        sys.stderr.write("create must not retarget\n")
        sys.exit(1)
    if load() is not None:
        sys.stderr.write("release already exists\n")
        sys.exit(1)
    text = notes_from(args) or ""
    open(notes_out, "w", encoding="utf-8").write(text)
    save({"isDraft": True, "assets": [], "notes": text})
elif cmd == "upload":
    data = load()
    if data is None:
        sys.stderr.write("upload without release\n")
        sys.exit(1)
    files = []
    for arg in args[3:]:
        if arg.startswith("--"):
            continue
        files.append(os.path.basename(arg))
    names = [asset["name"] for asset in data["assets"]]
    if "--clobber" in args:
        names = files
    else:
        for name in files:
            if name not in names:
                names.append(name)
    data["assets"] = [{"name": name} for name in names]
    save(data)
elif cmd == "edit":
    if "--verify-tag" not in args:
        sys.stderr.write("edit without --verify-tag\n")
        sys.exit(1)
    if "--target" in args or any(a.startswith("--target=") for a in args):
        sys.stderr.write("edit must not retarget\n")
        sys.exit(1)
    data = load()
    if data is None:
        sys.stderr.write("edit without release\n")
        sys.exit(1)
    text = notes_from(args)
    if text is not None:
        data["notes"] = text
        open(notes_out, "w", encoding="utf-8").write(text)
    if "--draft=false" in args:
        data["isDraft"] = False
    elif "--draft" in args or "--draft=true" in args:
        data["isDraft"] = True
    save(data)
else:
    sys.stderr.write("unexpected release command\n")
    sys.exit(1)
PY
  exit 0
fi
echo "unexpected gh command: ${joined}" >&2
exit 1
EOF
  chmod +x "${bin}/git" "${bin}/gh"

  run() {
    PATH="${bin}:${PATH}" \
      GITHUB_REPOSITORY="example/redact" \
      GH_LOG="${log}" \
      GH_STATE="${state}" \
      GH_TAG_EXISTS="${GH_TAG_EXISTS:-1}" \
      "${script}" "$@"
  }

  assert() {
    local label="$1"
    shift
    local negate=false
    if [[ "${1:-}" == "!" ]]; then
      negate=true
      shift
    fi
    local ok=false
    if "$@"; then
      ok=true
    fi
    if [[ "${negate}" == true ]]; then
      ok=$([[ "${ok}" == true ]] && echo false || echo true)
    fi
    if [[ "${ok}" != true ]]; then
      echo "self-test failed: ${label}" >&2
      echo "---- gh log ----" >&2
      cat "${log}" >&2 || true
      echo "---- stderr ----" >&2
      cat "${root}/err.txt" >&2 || true
      exit 1
    fi
  }

  # Missing tag: do not create a release or a tag.
  : >"${log}"
  rm -f "${state}/release.json" "${state}/last-notes.md"
  GH_TAG_EXISTS=0
  if run v0.12.7 "${notes}" "${assets}" >"${root}/out.txt" 2>"${root}/err.txt"; then
    echo "missing tag should fail" >&2
    exit 1
  fi
  assert "missing tag still created a release" ! grep -q 'release create' "${log}"
  assert "missing tag invoked git" ! grep -q 'git invoked' "${root}/err.txt"
  GH_TAG_EXISTS=1

  # First run creates a draft, uploads, and publishes. Second run only edits.
  : >"${log}"
  rm -f "${state}/release.json" "${state}/last-notes.md"
  run v0.12.7 "${notes}" "${assets}" >"${root}/out.txt"
  assert "create uses --verify-tag" grep -q 'release create v0.12.7 --verify-tag --draft' "${log}"
  assert "create retargets" ! grep -q -- '--target' "${log}"
  assert "first run uploads" grep -q 'release upload v0.12.7' "${log}"
  assert "first run publishes" grep -q 'release edit v0.12.7 --verify-tag --draft=false' "${log}"
  assert "notes include changelog" grep -q 'nightly workflow' "${state}/last-notes.md"
  assert "notes include generated section" grep -q "What's Changed" "${state}/last-notes.md"
  python3 - "${state}/release.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["isDraft"] is False, data
names = sorted(asset["name"] for asset in data["assets"])
assert names == ["redact-linux.tar.gz", "redact-mac.tar.gz"], names
PY
  local creates uploads
  creates="$(grep -c 'release create ' "${log}")"
  uploads="$(grep -c 'release upload ' "${log}")"
  run v0.12.7 "${notes}" "${assets}" >"${root}/out.txt"
  assert "second run created another release" test "$(grep -c 'release create ' "${log}")" -eq "${creates}"
  assert "second run uploaded again" test "$(grep -c 'release upload ' "${log}")" -eq "${uploads}"
  assert "second run updated notes" grep -q 'Updated GitHub release v0.12.7' "${root}/out.txt"

  # A published release with one asset uploads only the missing file.
  : >"${log}"
  python3 - "${state}/release.json" <<'PY'
import json, sys
json.dump(
    {"isDraft": False, "assets": [{"name": "redact-linux.tar.gz"}]},
    open(sys.argv[1], "w", encoding="utf-8"),
)
PY
  run v0.12.7 "${notes}" "${assets}" >"${root}/out.txt"
  assert "published re-run created a release" ! grep -q 'release create ' "${log}"
  assert "published re-run clobbered" ! grep -q -- '--clobber' "${log}"
  assert "published re-run uploaded the missing asset" \
    grep -q 'release upload v0.12.7 .*/redact-mac.tar.gz$' "${log}"
  python3 - "${state}/release.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
names = sorted(asset["name"] for asset in data["assets"])
assert names == ["redact-linux.tar.gz", "redact-mac.tar.gz"], names
PY

  # A draft retry replaces assets and publishes, without creating a tag.
  : >"${log}"
  python3 - "${state}/release.json" <<'PY'
import json, sys
json.dump({"isDraft": True, "assets": []}, open(sys.argv[1], "w", encoding="utf-8"))
PY
  run v0.12.7 "${notes}" "${assets}" >"${root}/out.txt"
  assert "draft retry created a release" ! grep -q 'release create ' "${log}"
  assert "draft retry did not clobber" grep -q -- '--clobber' "${log}"
  assert "draft retry did not publish" grep -q -- '--draft=false' "${log}"
  python3 - "${state}/release.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["isDraft"] is False, data
assert len(data["assets"]) == 2, data
PY

  # Prerelease tags keep the prerelease flag and still require the tag.
  : >"${log}"
  rm -f "${state}/release.json"
  run v0.12.7-rc.1 "${notes}" "${assets}" >"${root}/out.txt"
  assert "prerelease flag missing" grep -q 'release create v0.12.7-rc.1 --verify-tag --draft .* --prerelease$' "${log}"
  assert "stable flag on prerelease" ! grep -q -- '--prerelease=false' "${log}"

  # No assets is a hard failure and does not create a release.
  : >"${log}"
  rm -f "${state}/release.json"
  rm -rf "${root}/empty-assets"
  mkdir -p "${root}/empty-assets"
  if run v0.12.7 "${notes}" "${root}/empty-assets" >"${root}/out.txt" 2>"${root}/err.txt"; then
    echo "empty assets should fail" >&2
    exit 1
  fi
  assert "empty assets created a release" ! grep -q 'release create ' "${log}"

  rm -rf "${root}"
  echo "OK: publish-github-release.sh self-test"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 3 ]]; then
  usage
  [[ $# -ge 3 ]] || exit 1
  exit 0
fi

publish_release "$1" "$2" "$3"
