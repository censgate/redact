#!/usr/bin/env bash
# Move the ## [Unreleased] body in CHANGELOG.md under a dated version heading.
#
# Prepare Release runs this during the version bump so the commit that becomes
# the tag already has a ## [X.Y.Z] section. changelog-notes.sh reads that
# section for the GitHub release body.
#
# Usage:
#   version-changelog.sh <version> <YYYY-MM-DD> [CHANGELOG.md]
#   version-changelog.sh --self-test
#
# A second run is a no-op when that version heading already exists and
# Unreleased has no notes. It fails if both the version heading and
# Unreleased notes exist, so notes are not duplicated or dropped.
set -euo pipefail

usage() {
  echo "Usage: version-changelog.sh <version> <YYYY-MM-DD> [CHANGELOG.md]" >&2
  echo "       version-changelog.sh --self-test" >&2
}

version_changelog() {
  local version="$1"
  local date="$2"
  local file="$3"
  python3 - "$file" "$version" "$date" <<'PY'
import re
import sys
from pathlib import Path

path, version, date = sys.argv[1:]
if version.startswith("v"):
    version = version[1:]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
    sys.exit(f"invalid version: {version}")
if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
    sys.exit(f"invalid date: {date}")

file_path = Path(path)
text = file_path.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)

unreleased = None
for i, line in enumerate(lines):
    if re.match(r"^## \[Unreleased\]\s*$", line):
        unreleased = i
        break
if unreleased is None:
    sys.exit(f"{path} has no ## [Unreleased] section")

next_heading = None
for i in range(unreleased + 1, len(lines)):
    if lines[i].startswith("## ["):
        next_heading = i
        break
if next_heading is None:
    sys.exit(f"{path} has no section after ## [Unreleased]")

body = lines[unreleased + 1 : next_heading]
while body and not body[0].strip():
    body.pop(0)
while body and not body[-1].strip():
    body.pop()

version_heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)")
exists = any(version_heading.match(line) for line in lines)
if exists:
    if body:
        sys.exit(
            f"{path} already has ## [{version}] and Unreleased still has notes"
        )
    sys.exit(0)

heading = f"## [{version}] - {date}\n"
new_lines = list(lines[: unreleased + 1])
if not new_lines[-1].endswith("\n"):
    new_lines[-1] += "\n"
new_lines.append("\n")
new_lines.append(heading)
new_lines.append("\n")
if body:
    new_lines.extend(body)
    if not new_lines[-1].endswith("\n"):
        new_lines[-1] += "\n"
    new_lines.append("\n")
new_lines.extend(lines[next_heading:])
file_path.write_text("".join(new_lines), encoding="utf-8")
PY
}

self_test() {
  local tmp got
  tmp="$(mktemp)"
  cat >"$tmp" <<'EOF'
# Changelog

## [Unreleased]

### Added

- nightly workflow

### Fixed

- gateway token merge

## [0.12.6] - 2026-10-23

### Fixed

- older
EOF
  local notes_sh before stamped
  notes_sh="${BASH_SOURCE[0]%/*}/changelog-notes.sh"
  version_changelog 0.12.7 2026-11-01 "$tmp"
  grep -q '^## \[Unreleased\]$' "$tmp" || { echo "missing Unreleased heading" >&2; exit 1; }
  grep -q '^## \[0.12.7\] - 2026-11-01$' "$tmp" || { echo "missing 0.12.7 heading" >&2; exit 1; }
  # Unreleased is empty: the next heading is the new version.
  got="$(awk 'f && /^## \[/{print; exit} /^## \[Unreleased\]$/{f=1}' "$tmp")"
  [[ "$got" == "## [0.12.7] - 2026-11-01" ]] || {
    echo "Unreleased is not empty: next heading is '$got'" >&2
    exit 1
  }
  got="$("$notes_sh" 0.12.7 "$tmp")"
  echo "$got" | grep -q 'nightly workflow' || { echo "0.12.7 missing moved notes" >&2; exit 1; }
  echo "$got" | grep -q '0.12.6' && { echo "0.12.7 extract leaked 0.12.6" >&2; exit 1; }
  echo "$got" | grep -q 'older' && { echo "0.12.7 extract leaked older notes" >&2; exit 1; }
  before="$(cat "$tmp")"
  version_changelog v0.12.7 2026-11-01 "$tmp"
  [[ "$(cat "$tmp")" == "$before" ]] || { echo "second run rewrote an empty Unreleased" >&2; exit 1; }
  # Insert a note under Unreleased and expect a refusal, file unchanged.
  python3 - "$tmp" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = "## [Unreleased]\n\n"
insert = "## [Unreleased]\n\n### Added\n\n- later\n\n"
if needle not in text:
    sys.exit("self-test fixture lost Unreleased heading")
path.write_text(text.replace(needle, insert, 1), encoding="utf-8")
PY
  stamped="$(cat "$tmp")"
  if version_changelog 0.12.7 2026-11-01 "$tmp" 2>/dev/null; then
    echo "expected failure when version exists and Unreleased has notes" >&2
    exit 1
  fi
  [[ "$(cat "$tmp")" == "$stamped" ]] || { echo "failed run modified the changelog" >&2; exit 1; }
  # Restore and cover an empty Unreleased that still needs a heading.
  cat >"$tmp" <<'EOF'
# Changelog

## [Unreleased]

## [0.12.6] - 2026-10-23

### Fixed

- older
EOF
  version_changelog 0.12.8 2026-12-01 "$tmp"
  grep -q '^## \[0.12.8\] - 2026-12-01$' "$tmp" || { echo "empty Unreleased did not create 0.12.8" >&2; exit 1; }
  if version_changelog 0.12.7 not-a-date "$tmp" 2>/dev/null; then
    echo "expected invalid date to fail" >&2
    exit 1
  fi
  rm -f "$tmp"
  echo "OK: version-changelog.sh self-test"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 2 ]]; then
  usage
  [[ $# -ge 2 ]] || exit 1
  exit 0
fi

version_changelog "$1" "$2" "${3:-CHANGELOG.md}"
