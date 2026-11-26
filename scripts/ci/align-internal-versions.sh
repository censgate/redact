#!/usr/bin/env bash
# Set workspace.package.version and every workspace-internal path dependency
# version to the same release version.
#
# Prepare Release and scripts/update-version.sh both call this. The old
# updater was an allowlist of crate files and dependency names, maintained
# twice. A name missing from the list was left behind, and `sed` still
# exited 0 because a pattern that matches nothing is success. The 0.13.0
# prepare-release dry run (Actions run 42547446505) bumped the workspace to
# 0.13.0, rewrote only redact-core and redact-ner pins, and left
# redact-gateway requiring redact-token-store ^0.12.7. `cargo check` then
# failed. This script discovers pins from the manifests and exits non-zero
# when any pin does not equal the release version. It does not publish.
#
# Usage:
#   align-internal-versions.sh <version> [root]
#   align-internal-versions.sh --check [root]
#   align-internal-versions.sh --dry-run <version> [root]
#   align-internal-versions.sh --audit [root]
#   align-internal-versions.sh --self-test
set -euo pipefail

usage() {
  echo "Usage: align-internal-versions.sh <version> [root]" >&2
  echo "       align-internal-versions.sh --check [root]" >&2
  echo "       align-internal-versions.sh --dry-run <version> [root]" >&2
  echo "       align-internal-versions.sh --audit [root]" >&2
  echo "       align-internal-versions.sh --self-test" >&2
}

repo_of_script() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

run_align() {
  local mode="$1"
  local version="$2"
  local root="$3"
  python3 - "$mode" "$version" "$root" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

mode, version, root_arg = sys.argv[1:]
root = Path(root_arg).resolve()
VERSION_RE = re.compile(
    r"""(?<![.\w])version(\s*=\s*)(?:"[^"]*"|'[^']*')"""
)
DEP_TABLE_KEYS = ("dependencies", "dev-dependencies", "build-dependencies")


def die(messages):
    if isinstance(messages, str):
        messages = [messages]
    for message in messages:
        print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_version(raw):
    if raw.startswith("v"):
        raw = raw[1:]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", raw):
        die(f"invalid version: {raw}")
    return raw


def skip_string(text, i):
    quote = text[i]
    triple = quote * 3
    if text.startswith(triple, i):
        end = text.find(triple, i + 3)
        return len(text) if end < 0 else end + 3
    i += 1
    while i < len(text):
        if quote == '"' and text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return i


def match_brace(text, open_at):
    depth = 1
    i = open_at + 1
    while i < len(text):
        char = text[i]
        if char in {'"', "'"}:
            i = skip_string(text, i)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def inline_assignments(text):
    found = []
    i = 0
    while i < len(text):
        newline = text.find("\n", i)
        if newline < 0:
            newline = len(text)
        line = text[i:newline]
        if not re.match(r"[ \t]*#", line):
            match = re.match(r"[ \t]*([A-Za-z0-9_-]+)[ \t]*=[ \t]*\{", line)
            if match:
                brace_at = i + match.end() - 1
                close_at = match_brace(text, brace_at)
                if close_at is None:
                    die(f"unbalanced '{{' in an inline table near {match.group(1)}")
                found.append((match.group(1), brace_at + 1, close_at))
                i = close_at + 1
                continue
        i = newline + 1 if newline < len(text) else len(text)
    return found


def flatten_inline_newlines(text):
    # tomllib implements TOML 1.0, which rejects newlines inside inline
    # tables. Cargo accepts them. A multiline path pin must still be visible
    # to the checker; flattening is only for parsing, not for the bytes written.
    out = []
    i = 0
    depth = 0
    while i < len(text):
        char = text[i]
        if char in {'"', "'"}:
            end = skip_string(text, i)
            out.append(text[i:end])
            i = end
            continue
        if char == "{":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
        if char == "\n" and depth:
            out.append(" ")
        else:
            out.append(char)
        i += 1
    return "".join(out)


def loads(text):
    return tomllib.loads(flatten_inline_newlines(text))


def parse_inline(body):
    try:
        parsed = loads("x = {" + body + "}")["x"]
    except tomllib.TOMLDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def load_root(text):
    try:
        return loads(text)
    except tomllib.TOMLDecodeError as exc:
        die(f"Cargo.toml did not parse: {exc}")


def member_manifests(root_text, root_dir):
    data = load_root(root_text)
    members = data.get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        die("workspace.members is missing")
    manifests = {"Cargo.toml": root_dir / "Cargo.toml"}
    dirs = set()
    if "package" in data:
        dirs.add(root_dir)
    for rel in members:
        if not isinstance(rel, str):
            die(f"workspace member is not a path: {rel!r}")
        manifest = root_dir / rel / "Cargo.toml"
        if not manifest.is_file():
            die(f"workspace member has no Cargo.toml: {rel}")
        manifests[str(Path(rel) / "Cargo.toml")] = manifest
        dirs.add(manifest.parent.resolve())
    return manifests, dirs, data


def read_manifests(root_dir):
    root_manifest = root_dir / "Cargo.toml"
    if not root_manifest.is_file():
        die(f"no Cargo.toml in {root_dir}")
    root_text = root_manifest.read_text(encoding="utf-8")
    manifests, dirs, root_data = member_manifests(root_text, root_dir)
    texts = {}
    for rel, path in manifests.items():
        texts[rel] = path.read_text(encoding="utf-8")
    return texts, dirs, root_data


def is_internal(manifest_path, dep_path, member_dirs):
    if not isinstance(dep_path, str) or not dep_path:
        return False
    return (manifest_path.parent / dep_path).resolve() in member_dirs


def iter_dep_tables(data):
    for key in DEP_TABLE_KEYS:
        table = data.get(key)
        if isinstance(table, dict):
            yield table
    targets = data.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in DEP_TABLE_KEYS:
                table = target.get(key)
                if isinstance(table, dict):
                    yield table
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        table = workspace.get("dependencies")
        if isinstance(table, dict):
            yield table


def replace_header_version(text, header, new_version):
    pattern = re.compile(
        rf"(?ms)^\[{re.escape(header)}\][^\n]*\n(.*?)(?=^\[|\Z)"
    )
    match = pattern.search(text)
    if not match:
        return text, 0
    body = match.group(1)
    new_body, count = re.subn(
        r"""^(version)(\s*=\s*)(?:"[^"]*"|'[^']*')""",
        rf'\1\2"{new_version}"',
        body,
        count=1,
        flags=re.M,
    )
    if count != 1:
        return text, 0
    return text[: match.start(1)] + new_body + text[match.end(1) :], 1


def rewrite_text(rel, text, manifest_path, member_dirs, new_version):
    errors = []
    if rel == "Cargo.toml":
        text, count = replace_header_version(text, "workspace.package", new_version)
        if count != 1:
            errors.append(f"{rel}: workspace.package version was not rewritten")
    try:
        loaded = loads(text)
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"{rel}: manifest did not parse during rewrite: {exc}")
        return text, errors
    package = loaded.get("package") if not errors else None
    if isinstance(package, dict) and isinstance(package.get("version"), str):
        if package["version"] != new_version:
            text, count = replace_header_version(text, "package", new_version)
            if count != 1:
                errors.append(f"{rel}: package version was not rewritten")
    pieces = inline_assignments(text)
    for _name, body_start, body_end in reversed(pieces):
        body = text[body_start:body_end]
        table = parse_inline(body)
        if table is None or "path" not in table:
            continue
        if not is_internal(manifest_path, table.get("path"), member_dirs):
            continue
        if not isinstance(table.get("version"), str):
            continue
        new_body, count = VERSION_RE.subn(
            lambda match: f'version{match.group(1)}"{new_version}"',
            body,
            count=1,
        )
        if count != 1:
            errors.append(
                f"{rel}: could not rewrite internal path pin "
                f"{table.get('version')!r}; refusing to leave it"
            )
            continue
        text = text[:body_start] + new_body + text[body_end:]
    return text, errors


def parsed_manifests(texts):
    parsed = {}
    errors = []
    for rel, text in texts.items():
        try:
            parsed[rel] = loads(text)
        except tomllib.TOMLDecodeError as exc:
            errors.append(f"{rel}: manifest did not parse after rewrite: {exc}")
    return parsed, errors


def workspace_version_of(parsed):
    workspace = parsed.get("Cargo.toml", {}).get("workspace", {})
    package = workspace.get("package", {}) if isinstance(workspace, dict) else {}
    version = package.get("version") if isinstance(package, dict) else None
    return version if isinstance(version, str) else None


def collect_pins(parsed, texts_paths, member_dirs):
    pins = []
    for rel, data in parsed.items():
        manifest = texts_paths[rel]
        for table in iter_dep_tables(data):
            for name, spec in table.items():
                if not isinstance(spec, dict) or "path" not in spec:
                    continue
                if not is_internal(manifest, spec.get("path"), member_dirs):
                    continue
                version = spec.get("version")
                pins.append((rel, name, version if isinstance(version, str) else None))
    return pins


def manifest_paths(root_dir, rels):
    return {rel: root_dir / rel for rel in rels}


def check_texts(texts, root_dir, expected):
    root_text = texts["Cargo.toml"]
    _manifests, member_dirs, _root = member_manifests(root_text, root_dir)
    parsed, errors = parsed_manifests(texts)
    if errors:
        return errors
    actual = workspace_version_of(parsed)
    if actual != expected:
        errors.append(
            f"workspace.package.version is {actual!r}, expected {expected!r}"
        )
    paths = manifest_paths(root_dir, texts)
    for rel, data in parsed.items():
        package = data.get("package")
        if not isinstance(package, dict) or "version" not in package:
            continue
        version = package["version"]
        if isinstance(version, dict) and version.get("workspace") is True:
            continue
        if version != expected:
            errors.append(f"{rel}: package version is {version!r}, expected {expected!r}")
    for rel, name, pin_version in collect_pins(parsed, paths, member_dirs):
        # A path dependency with no version is not a release pin. Published
        # crates are required to have one by --audit; unpublished path deps
        # (examples, wasm) stay as written.
        if pin_version is None:
            continue
        if pin_version != expected:
            errors.append(
                f"{rel}: {name} path pin is {pin_version}, expected {expected}"
            )
    return errors


def transform(texts, root_dir, new_version):
    _manifests, member_dirs, _root_data = member_manifests(texts["Cargo.toml"], root_dir)
    paths = manifest_paths(root_dir, texts)
    rewritten = {}
    errors = []
    for rel, text in texts.items():
        new_text, rel_errors = rewrite_text(
            rel, text, paths[rel], member_dirs, new_version
        )
        rewritten[rel] = new_text
        errors.extend(rel_errors)
    errors.extend(check_texts(rewritten, root_dir, new_version))
    return rewritten, errors


def describe(before, after, root_dir):
    def pins_of(texts):
        _manifests, member_dirs, _root = member_manifests(texts["Cargo.toml"], root_dir)
        parsed, errors = parsed_manifests(texts)
        if errors:
            return None
        paths = manifest_paths(root_dir, texts)
        found = {
            ("workspace.package",): workspace_version_of(parsed),
        }
        for rel, name, pin_version in collect_pins(parsed, paths, member_dirs):
            found[(rel, name)] = pin_version
        for rel, data in parsed.items():
            package = data.get("package")
            if isinstance(package, dict) and isinstance(package.get("version"), str):
                found[(rel, "package")] = package["version"]
        return found

    old = pins_of(before)
    new = pins_of(after)
    if old is None or new is None:
        return []
    lines = []
    for key in sorted(set(old) | set(new), key=lambda item: (item[0], item[-1])):
        if old.get(key) == new.get(key):
            continue
        label = key[0] if len(key) == 1 else f"{key[0]} {key[1]}"
        lines.append(f"{label}: {old.get(key)} -> {new.get(key)}")
    return lines


def pin_count(texts, root_dir, expected):
    _manifests, member_dirs, _root = member_manifests(texts["Cargo.toml"], root_dir)
    parsed, errors = parsed_manifests(texts)
    if errors:
        return 0
    paths = manifest_paths(root_dir, texts)
    return sum(
        1
        for _rel, _name, pin_version in collect_pins(parsed, paths, member_dirs)
        if pin_version == expected
    )


def release_job(text):
    match = re.search(
        r"(?ms)^  publish-crates:.*?(?=^  [A-Za-z0-9-]+:|\Z)",
        text,
    )
    if not match:
        die("release.yml has no publish-crates job")
    return match.group(0)


def audit(root_dir):
    release = (root_dir / ".github/workflows/release.yml").read_text(encoding="utf-8")
    prepare = (root_dir / ".github/workflows/prepare-release.yml").read_text(encoding="utf-8")
    updater = (root_dir / "scripts/update-version.sh").read_text(encoding="utf-8")
    verifier = (root_dir / "scripts/ci/verify-crates.sh").read_text(encoding="utf-8")
    errors = []
    if "align-internal-versions.sh" not in prepare:
        errors.append("prepare-release.yml does not call align-internal-versions.sh")
    if re.search(r"redact-(?:core|ner|token-store) = \{ path", prepare):
        errors.append("prepare-release.yml still hardcodes internal path rewrites")
    if "align-internal-versions.sh" not in updater:
        errors.append("update-version.sh does not call align-internal-versions.sh")
    if "update_crate_dependency" in updater:
        errors.append("update-version.sh still has a dependency allowlist")
    job = release_job(release)
    if "id-token: write" not in job:
        errors.append("publish-crates is missing id-token: write")
    pin = "rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9"
    if pin not in job:
        errors.append("publish-crates trusted-publishing action pin changed")
    if "secrets." in job:
        errors.append("publish-crates references a stored secret")
    if job.count("./scripts/ci/verify-crates.sh") < 2:
        errors.append("publish-crates no longer gates token-store and the full set")
    published = re.findall(r"cargo publish[^\n]*-p ([A-Za-z0-9_-]+)", job)
    if len(published) != len(set(published)):
        errors.append(f"duplicate cargo publish steps: {published}")
    default = re.search(r'CRATES="\$\{CRATES:-([^"}]+)\}"', verifier)
    if not default:
        errors.append("verify-crates.sh default CRATES list was not found")
        listed = []
    else:
        listed = default.group(1).split()
    if set(listed) != set(published):
        errors.append(
            "verify-crates.sh default crates "
            f"{listed} differ from publish steps {published}"
        )
    texts, member_dirs, _root = read_manifests(root_dir)
    parsed, parse_errors = parsed_manifests(texts)
    errors.extend(parse_errors)
    if parse_errors:
        die(errors)
    paths = manifest_paths(root_dir, texts)
    names = {}
    for rel, data in parsed.items():
        package = data.get("package")
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            names[package["name"]] = rel
    workspace_deps = {}
    workspace = parsed["Cargo.toml"].get("workspace", {})
    if isinstance(workspace, dict) and isinstance(workspace.get("dependencies"), dict):
        workspace_deps = workspace["dependencies"]
    positions = {name: job.find(f"-p {name}") for name in published}
    published_set = set(published)
    for rel, data in parsed.items():
        manifest = paths[rel]
        package = data.get("package", {})
        package_name = package.get("name") if isinstance(package, dict) else None
        if package_name not in published_set:
            continue
        for table in iter_dep_tables(data):
            for dep_name, spec in table.items():
                if not isinstance(spec, dict) or "path" not in spec:
                    continue
                if not is_internal(manifest, spec.get("path"), member_dirs):
                    continue
                target = (manifest.parent / spec["path"]).resolve()
                target_name = None
                for candidate, candidate_rel in names.items():
                    if paths[candidate_rel].parent.resolve() == target:
                        target_name = candidate
                        break
                if target_name is None:
                    errors.append(f"{rel}: internal path {spec['path']} has no package name")
                    continue
                if target_name not in published_set:
                    errors.append(
                        f"{package_name} path-depends on {target_name}, "
                        "which is not in the release publish list"
                    )
                    continue
                version = spec.get("version")
                if not isinstance(version, str):
                    inherited = workspace_deps.get(spec.get("package", dep_name))
                    version = inherited.get("version") if isinstance(inherited, dict) else None
                if not isinstance(version, str):
                    errors.append(
                        f"{package_name} path dependency {dep_name} has no version pin"
                    )
                if positions[target_name] > positions[package_name]:
                    errors.append(
                        f"{target_name} is published after {package_name}, "
                        "which path-depends on it"
                    )
    if errors:
        die(errors)
    print(
        "OK: publish list covers internal path dependencies "
        f"({len(published)} crates) and trusted publishing is unchanged"
    )


if mode == "audit":
    audit(root)
    raise SystemExit(0)

texts, _member_dirs, _root_data = read_manifests(root)
if mode == "check":
    parsed, errors = parsed_manifests(texts)
    if errors:
        die(errors)
    expected = workspace_version_of(parsed)
    if expected is None:
        die("workspace.package.version is missing")
    errors = check_texts(texts, root, expected)
    if errors:
        die(errors)
    print(
        f"internal path pins match workspace version {expected} "
        f"({pin_count(texts, root, expected)} pins)"
    )
    raise SystemExit(0)

if mode not in {"apply", "dry-run"}:
    die(f"unknown mode: {mode}")
new_version = validate_version(version)
rewritten, errors = transform(texts, root, new_version)
if errors:
    die(errors)
for line in describe(texts, rewritten, root):
    print(line)
count = pin_count(rewritten, root, new_version)
if count == 0:
    die("refusing to report success with zero internal path pins")
if mode == "apply":
    for rel, text in rewritten.items():
        (root / rel).write_text(text, encoding="utf-8")
print(f"aligned {count} internal path pins to {new_version}")
PY
}

self_test() {
  local repo work stage synth broken status
  repo="$(repo_of_script)"
  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" RETURN

  run_align audit "" "$repo"

  # Read the checkout's version. A release branch is already bumped, so the
  # assertions below must not name 0.12.7 or any other fixed release.
  current="$(
    python3 - "$repo/Cargo.toml" <<'PY'
import sys
import tomllib
from pathlib import Path

data = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(data["workspace"]["package"]["version"])
PY
  )"
  # Not a release version, and not equal to the tree under test.
  target="0.0.0-aligntest"
  stale="1.2.3"
  if [[ "$current" == "$target" || "$current" == "$stale" ]]; then
    echo "ERROR: workspace version collided with a self-test sentinel" >&2
    exit 1
  fi

  if ! run_align check "" "$repo" >"$work/check.txt"; then
    echo "ERROR: real workspace path pins are already misaligned" >&2
    exit 1
  fi
  grep -F -q "internal path pins match workspace version ${current}" "$work/check.txt"

  manifest_digest() {
    (
      cd "$1" && find . -name Cargo.toml -not -path './.git/*' -not -path './target/*' -print0 \
        | sort -z | xargs -0 sha256sum
    )
  }
  before_digest="$(manifest_digest "$repo")"
  run_align dry-run "$target" "$repo" >"$work/dry.txt"
  after_digest="$(manifest_digest "$repo")"
  if [[ "$before_digest" != "$after_digest" ]]; then
    echo "ERROR: dry-run modified a manifest" >&2
    exit 1
  fi
  grep -F -q "crates/redact-gateway/Cargo.toml redact-token-store: ${current} -> ${target}" "$work/dry.txt"
  grep -F -q "crates/redact-gateway/Cargo.toml redact-ner: ${current} -> ${target}" "$work/dry.txt"
  grep -F -q "crates/redact-gateway/Cargo.toml redact-core: ${current} -> ${target}" "$work/dry.txt"
  grep -F -q "aligned " "$work/dry.txt"
  grep -F -q "internal path pins to ${target}" "$work/dry.txt"

  stage="$work/stage"
  mkdir -p "$stage"
  while IFS= read -r manifest; do
    mkdir -p "$stage/$(dirname "$manifest")"
    cp "$repo/$manifest" "$stage/$manifest"
  done < <(cd "$repo" && find . -name Cargo.toml -not -path './.git/*' -not -path './target/*')
  run_align apply "$target" "$stage" >"$work/apply.txt"
  grep -F -q "crates/redact-gateway/Cargo.toml redact-token-store: ${current} -> ${target}" "$work/apply.txt"
  grep -F -q "crates/redact-gateway/Cargo.toml redact-ner: ${current} -> ${target}" "$work/apply.txt"
  grep -F -q "crates/redact-gateway/Cargo.toml redact-core: ${current} -> ${target}" "$work/apply.txt"
  python3 - "$stage" "$repo" "$target" <<'PY'
import sys
from pathlib import Path

stage = Path(sys.argv[1])
source = Path(sys.argv[2])
target = sys.argv[3]
root = (stage / "Cargo.toml").read_text(encoding="utf-8")
source_root = (source / "Cargo.toml").read_text(encoding="utf-8")
gateway = (stage / "crates/redact-gateway/Cargo.toml").read_text(encoding="utf-8")
wasm = (stage / "crates/redact-wasm/Cargo.toml").read_text(encoding="utf-8")
source_wasm = (source / "crates/redact-wasm/Cargo.toml").read_text(encoding="utf-8")
package = root.split("[workspace.package]", 1)[1].split("[", 1)[0]
if f'version = "{target}"' not in package:
    sys.exit("workspace version was not aligned")


def line_with(text, needle):
    for line in text.splitlines():
        if needle in line:
            return line
    sys.exit(f"missing {needle}")


for needle in ("pbkdf2 =", "uuid ="):
    if line_with(root, needle) != line_with(source_root, needle):
        sys.exit(f"external dependency changed: {needle}")
for name in ("redact-core", "redact-ner", "redact-token-store"):
    needle = f'{name} = {{ path = "../{name}", version = "{target}" }}'
    if needle not in gateway:
        sys.exit(f"gateway pin not aligned: {name}")
if wasm != source_wasm:
    sys.exit("versionless wasm manifest was rewritten")
PY
  run_align check "" "$stage" >/dev/null
  run_align apply "$target" "$stage" >/dev/null

  python3 - "$stage" "$target" "$stale" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "crates/redact-gateway/Cargo.toml"
target, stale = sys.argv[2], sys.argv[3]
text = path.read_text(encoding="utf-8")
old = f'redact-token-store = {{ path = "../redact-token-store", version = "{target}" }}'
new = f'redact-token-store = {{ path = "../redact-token-store", version = "{stale}" }}'
if old not in text:
    sys.exit("aligned token-store pin was not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
  set +e
  run_align check "" "$stage" >"$work/stale-out.txt" 2>"$work/stale-err.txt"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: --check accepted a stale redact-token-store pin" >&2
    exit 1
  fi
  if [[ "$status" -ne 1 ]]; then
    echo "ERROR: stale pin check exited $status, want 1" >&2
    cat "$work/stale-err.txt" >&2
    exit 1
  fi
  grep -F -q "redact-token-store" "$work/stale-err.txt"
  grep -F -q "$stale" "$work/stale-err.txt"
  if grep -F -q "redact-core path pin" "$work/stale-err.txt"; then
    echo "ERROR: stale check blamed an aligned pin" >&2
    cat "$work/stale-err.txt" >&2
    exit 1
  fi

  copy_release_tree() {
    local dest="$1"
    mkdir -p "$dest/scripts/ci" "$dest/.github/workflows"
    cp "$repo/Cargo.toml" "$dest/Cargo.toml"
    cp "$repo/.github/workflows/release.yml" "$dest/.github/workflows/release.yml"
    cp "$repo/.github/workflows/prepare-release.yml" "$dest/.github/workflows/prepare-release.yml"
    cp "$repo/scripts/update-version.sh" "$dest/scripts/update-version.sh"
    cp "$repo/scripts/ci/verify-crates.sh" "$dest/scripts/ci/verify-crates.sh"
    local manifest
    while IFS= read -r manifest; do
      mkdir -p "$dest/$(dirname "$manifest")"
      cp "$repo/$manifest" "$dest/$manifest"
    done < <(cd "$repo" && find crates -name Cargo.toml)
  }

  order="$work/order"
  copy_release_tree "$order"
  python3 - "$order/.github/workflows/release.yml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
token = "-p redact-token-store"
gateway = "-p redact-gateway"
if text.find(token) < 0 or text.find(gateway) < 0 or text.find(token) > text.find(gateway):
    sys.exit("fixture no longer publishes token-store before gateway")
text = text.replace(token, "-p TOKEN_PLACEHOLDER", 1)
text = text.replace(gateway, token, 1)
text = text.replace("-p TOKEN_PLACEHOLDER", gateway, 1)
path.write_text(text, encoding="utf-8")
PY
  set +e
  run_align audit "" "$order" >"$work/order-out.txt" 2>"$work/order-err.txt"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: audit accepted gateway published before its token-store dependency" >&2
    exit 1
  fi
  if [[ "$status" -ne 1 ]]; then
    echo "ERROR: publish-order audit exited $status, want 1" >&2
    cat "$work/order-err.txt" >&2
    exit 1
  fi
  grep -F -q "redact-token-store is published after redact-gateway" "$work/order-err.txt"

  insecure="$work/insecure"
  copy_release_tree "$insecure"
  python3 - "$insecure/.github/workflows/release.yml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "id-token: write"
if old not in text:
    sys.exit("publish job has no id-token: write to remove")
path.write_text(text.replace(old, "id-token: read", 1), encoding="utf-8")
PY
  set +e
  run_align audit "" "$insecure" >"$work/insecure-out.txt" 2>"$work/insecure-err.txt"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: audit accepted a publish job without id-token: write" >&2
    exit 1
  fi
  if [[ "$status" -ne 1 ]]; then
    echo "ERROR: trusted-publishing audit exited $status, want 1" >&2
    cat "$work/insecure-err.txt" >&2
    exit 1
  fi
  grep -F -q "publish-crates is missing id-token: write" "$work/insecure-err.txt"

  synth="$work/synth"
  mkdir -p "$synth/crates/alpha" "$synth/crates/beta" "$synth/crates/gamma" \
    "$synth/crates/app" "$synth/crates/hidden" "$synth/not-a-member"
  cat >"$synth/Cargo.toml" <<'EOF'
[workspace]
members = [
    "crates/alpha",
    "crates/beta",
    "crates/gamma",
    "crates/app",
    "crates/hidden",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
alpha = { path = "crates/alpha", version = "0.1.0" }
EOF
  cat >"$synth/crates/alpha/Cargo.toml" <<'EOF'
[package]
name = "alpha"
version.workspace = true
edition.workspace = true
EOF
  cat >"$synth/crates/beta/Cargo.toml" <<'EOF'
[package]
name = "beta"
version = "0.1.0"
edition.workspace = true

[dependencies]
gamma = {
  path = "../gamma",
  version = "0.1.0"
}
EOF
  cat >"$synth/crates/gamma/Cargo.toml" <<'EOF'
[package]
name = "widget-store"
version.workspace = true
edition.workspace = true
EOF
  cat >"$synth/crates/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version.workspace = true
edition.workspace = true

[dependencies]
widget-store = { version = '0.1.0', path = "../gamma" }
serde = { version = "1.0.0" }
outside = { path = "../../not-a-member", version = "9.9.9" }
alpha-loose = { path = "../alpha" }

[target.'cfg(unix)'.dependencies]
beta = { path = "../beta", version = "0.1.0" }
EOF
  cat >"$synth/crates/hidden/Cargo.toml" <<'EOF'
[package]
name = "hidden"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
alpha = { path = "../alpha", version = "0.1.0" }
EOF
  run_align apply 0.13.0 "$synth" >"$work/synth.txt"
  python3 - "$synth" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
root_text = (root / "Cargo.toml").read_text(encoding="utf-8")
beta = (root / "crates/beta/Cargo.toml").read_text(encoding="utf-8")
app = (root / "crates/app/Cargo.toml").read_text(encoding="utf-8")
hidden = (root / "crates/hidden/Cargo.toml").read_text(encoding="utf-8")
if 'alpha = { path = "crates/alpha", version = "0.13.0" }' not in root_text:
    sys.exit("workspace.dependencies pin was not aligned")
if 'version = "0.13.0"' not in beta.split("[dependencies]", 1)[0]:
    sys.exit("explicit package version was not aligned")
if 'version = "0.13.0"' not in beta.split("gamma", 1)[1]:
    sys.exit("multiline internal pin was not aligned")
if 'widget-store = { version = "0.13.0", path = "../gamma" }' not in app:
    sys.exit("single-quoted widget-store pin was not aligned")
if 'beta = { path = "../beta", version = "0.13.0" }' not in app:
    sys.exit("target-specific internal pin was not aligned")
if 'serde = { version = "1.0.0" }' not in app:
    sys.exit("external version was rewritten")
if 'outside = { path = "../../not-a-member", version = "9.9.9" }' not in app:
    sys.exit("path outside the workspace was rewritten")
if 'alpha-loose = { path = "../alpha" }' not in app:
    sys.exit("versionless path dependency was rewritten")
if 'alpha = { path = "../alpha", version = "0.13.0" }' not in hidden:
    sys.exit("unpublished crate pin was skipped")
PY
  if ! grep -q "widget-store" "$work/synth.txt"; then
    echo "ERROR: new crate pin was not reported" >&2
    exit 1
  fi

  broken="$work/broken"
  mkdir -p "$broken/crates/alpha" "$broken/crates/delta"
  cat >"$broken/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/alpha", "crates/delta"]

[workspace.package]
version = "0.1.0"
edition = "2021"
EOF
  cat >"$broken/crates/alpha/Cargo.toml" <<'EOF'
[package]
name = "alpha"
version.workspace = true
edition.workspace = true
EOF
  cat >"$broken/crates/delta/Cargo.toml" <<'EOF'
[package]
name = "delta"
version.workspace = true
edition.workspace = true

[dependencies]
alpha = { path = "../alpha", version = """0.1.0""" }
EOF
  set +e
  run_align apply 0.13.0 "$broken" >"$work/broken-out.txt" 2>"$work/broken-err.txt"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: apply accepted an internal pin it could not rewrite" >&2
    exit 1
  fi
  if [[ "$status" -ne 1 ]]; then
    echo "ERROR: unrewritable pin apply exited $status, want 1" >&2
    cat "$work/broken-err.txt" >&2
    exit 1
  fi
  grep -q "ERROR:" "$work/broken-err.txt"
  if grep -q 'version = "0.13.0"' "$broken/crates/delta/Cargo.toml"; then
    echo "ERROR: failed apply wrote a partial manifest" >&2
    exit 1
  fi

  # prepare-release.yml sed must match live docs/benchmarks/README.md.
  # Drift left the 0.13.0 release on an old "latest tagged" line.
  BM="docs/benchmarks/README.md"
  PR=".github/workflows/prepare-release.yml"
  BM_RE='The \*\*current\*\* release is \*\*\[v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?\]\(https://github.com/censgate/redact/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?\)\*\*'
  if [[ ! -f "$BM" ]] || ! grep -qE "$BM_RE" "$BM"; then
    echo "ERROR: $BM missing prepare-release 'current release' version link" >&2
    exit 1
  fi
  if [[ ! -f "$PR" ]] || ! grep -q 'docs/benchmarks/README.md' "$PR" \
    || ! grep -qF 'The **current** release is **[v${VERSION}]' "$PR"; then
    echo "ERROR: $PR missing benchmarks current-release version substitution" >&2
    exit 1
  fi

  echo "OK: align-internal-versions.sh self-test"
}

main() {
  local mode="apply"
  local version=""
  local root=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --self-test)
        self_test
        exit 0
        ;;
      --check)
        mode="check"
        shift
        ;;
      --dry-run)
        mode="dry-run"
        shift
        ;;
      --audit)
        mode="audit"
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
      *)
        if [[ -z "$version" && "$mode" != "check" && "$mode" != "audit" ]]; then
          version="$1"
        elif [[ -z "$root" ]]; then
          root="$1"
        else
          echo "Unexpected argument: $1" >&2
          usage
          exit 1
        fi
        shift
        ;;
    esac
  done
  if [[ -z "$root" ]]; then
    root="$(pwd)"
  fi
  if [[ "$mode" == "apply" || "$mode" == "dry-run" ]]; then
    if [[ -z "$version" ]]; then
      usage
      exit 1
    fi
  fi
  run_align "$mode" "$version" "$root"
}

main "$@"
