#!/usr/bin/env node
// Host-only facts extractor. Reads compiled entity types from
// `redact --format json list-entities`, CLI `--help` flags, crate versions
// in selected docs, and the SECURITY.md support table.
// Never writes sample secrets.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FACTS_PATH = join(ROOT, "data", "facts.json");
const CRATE_NAMES = [
  "redact-core",
  "redact-ner",
  "redact-api",
  "redact-cli",
  "redact-wasm",
  "redact-gateway",
  "redact-scan",
  "redact-verify",
];
const VERSION_DOC_PATHS = [
  "README.md",
  "docs/install.md",
  ...CRATE_NAMES.map((name) => `crates/${name}/README.md`),
];

function parseArgs(argv) {
  const out = { check: false, bin: "redact", write: true };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") out.check = true;
    else if (a === "--no-write") out.write = false;
    else if (a === "--bin") out.bin = argv[++i];
    else if (a === "--help" || a === "-h") {
      console.log(
        "Usage: extract-facts.mjs [--check] [--bin <redact>] [--no-write]",
      );
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
  return out;
}

function listEntities(bin) {
  const raw = execFileSync(bin, ["--format", "json", "list-entities"], {
    encoding: "utf8",
  });
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error("list-entities JSON must be an array of type names");
  }
  return parsed.slice().sort();
}

function helpText(bin, args) {
  return execFileSync(bin, args, { encoding: "utf8" });
}

function flagsFromHelp(text) {
  const flags = new Set();
  const re = /--[a-z0-9][a-z0-9-]*/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    flags.add(m[0]);
  }
  return [...flags].sort();
}

function cliFlags(bin) {
  return {
    global: flagsFromHelp(helpText(bin, ["--help"])),
    analyze: flagsFromHelp(helpText(bin, ["analyze", "--help"])),
    anonymize: flagsFromHelp(helpText(bin, ["anonymize", "--help"])),
    "list-entities": flagsFromHelp(helpText(bin, ["list-entities", "--help"])),
  };
}

function walkYaml(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "optional" || name === "quarantine") continue;
      walkYaml(p, acc);
    } else if (name.endsWith(".yaml") || name.endsWith(".yml")) {
      acc.push(p);
    }
  }
  return acc;
}

function countEnabled(file) {
  const text = readFileSync(file, "utf8");
  const ids = (text.match(/^\s+-\s+id:/gm) || []).length;
  const disabled = (text.match(/^\s+enabled:\s*false\s*$/gm) || []).length;
  return { total: ids, enabled: Math.max(0, ids - disabled) };
}

function packCounts() {
  const patternsRoot = join(ROOT, "patterns");
  const shipped = walkYaml(patternsRoot);
  let pattern_count = 0;
  let pattern_count_enabled = 0;
  for (const f of shipped) {
    const c = countEnabled(f);
    pattern_count += c.total;
    pattern_count_enabled += c.enabled;
  }
  const optional = join(patternsRoot, "optional", "providers-v1.yaml");
  const opt = countEnabled(optional);
  return {
    pattern_pack_files: shipped.map((f) => relative(ROOT, f)).sort(),
    pattern_count,
    pattern_count_enabled,
    optional_pack_rule_count: opt.total,
    optional_pack_rule_count_enabled: opt.enabled,
  };
}

function workspacePackageTable() {
  const text = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
  const section = text.match(
    /\[workspace\.package\]\n([\s\S]*?)(?:\n\[|\n$)/,
  );
  if (!section) {
    throw new Error("workspace.package table not found in Cargo.toml");
  }
  const version = section[1].match(/^version = "([^"]+)"/m);
  const rust = section[1].match(/^rust-version = "([^"]+)"/m);
  if (!version) {
    throw new Error("workspace.package.version not found");
  }
  return {
    version: version[1],
    rustVersion: rust ? rust[1] : null,
  };
}

function crateVersion(name, workspaceVersion) {
  const file = join(ROOT, "crates", name, "Cargo.toml");
  const text = readFileSync(file, "utf8");
  if (/^version\.workspace\s*=\s*true\s*$/m.test(text)) {
    return workspaceVersion;
  }
  const m = text.match(/^version = "([^"]+)"/m);
  if (!m) {
    throw new Error(`version not found in crates/${name}/Cargo.toml`);
  }
  return m[1];
}

function buildFacts(bin) {
  const entity_types = listEntities(bin);
  const packs = packCounts();
  const workspace = workspacePackageTable();
  const crate_versions = Object.fromEntries(
    CRATE_NAMES.map((name) => [name, crateVersion(name, workspace.version)]),
  );
  return {
    entity_types,
    entity_type_count: entity_types.length,
    ...packs,
    cli_flags: cliFlags(bin),
    workspace_version: workspace.version,
    crate_versions,
  };
}

function walkMarkdown(dir, acc = []) {
  if (!statSync(dir, { throwIfNoEntry: false })) {
    return acc;
  }
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      walkMarkdown(p, acc);
    } else if (name.endsWith(".md")) {
      acc.push(p);
    }
  }
  return acc;
}

function redactCommandTails(line) {
  const tails = [];
  const re = /(?<![A-Za-z0-9_./-])redact(?![-a-zA-Z0-9])([^`\n]*)/g;
  let m;
  while ((m = re.exec(line)) !== null) {
    const tail = m[1].split(/[;&|]/)[0];
    tails.push(tail);
  }
  return tails;
}

function documentedRedactFlags() {
  const files = [join(ROOT, "README.md"), ...walkMarkdown(join(ROOT, "docs"))];
  const hits = [];
  for (const file of files) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    lines.forEach((line, idx) => {
      for (const tail of redactCommandTails(line)) {
        const flags = tail.match(/--[a-z0-9][a-z0-9-]*/g) || [];
        for (const flag of flags) {
          hits.push({
            file: relative(ROOT, file),
            line: idx + 1,
            flag,
          });
        }
      }
    });
  }
  return hits;
}

function knownCliFlags(facts) {
  const all = new Set();
  for (const flags of Object.values(facts.cli_flags)) {
    for (const flag of flags) all.add(flag);
  }
  return all;
}

function checkDocumentedFlags(facts) {
  const known = knownCliFlags(facts);
  const errors = [];
  for (const hit of documentedRedactFlags()) {
    if (!known.has(hit.flag)) {
      errors.push(
        `${hit.file}:${hit.line}: documented flag ${hit.flag} is not in redact --help`,
      );
    }
  }
  return errors;
}

function checkEntityCountMentions(count) {
  const files = [
    "README.md",
    "docs/README.md",
    "docs/entity-types.md",
    "CONTRIBUTING.md",
  ];
  const errors = [];
  const patterns = [
    /\*\*(\d+)\*\*\s+types/g,
    /(\d+)\s+compiled types/g,
    /Current compiled count:\s+\*\*(\d+)\*\*/g,
    /Default compiled set is \*\*(\d+)\*\*/g,
  ];
  for (const rel of files) {
    const p = join(ROOT, rel);
    let text;
    try {
      text = readFileSync(p, "utf8");
    } catch {
      continue;
    }
    for (const re of patterns) {
      const copy = new RegExp(re.source, "g");
      let m;
      while ((m = copy.exec(text)) !== null) {
        const n = Number(m[1]);
        if (n !== count) {
          errors.push(
            `${rel}: compiled-type mention ${n} does not match list-entities count ${count}`,
          );
        }
      }
    }
  }
  return errors;
}

function extractDocVersions(relPath) {
  const p = join(ROOT, relPath);
  let text;
  try {
    text = readFileSync(p, "utf8");
  } catch {
    return [];
  }
  const found = [];
  const crateAlt = CRATE_NAMES.join("|");
  const pin = new RegExp(`(${crateAlt}) = "(\\d+\\.\\d+\\.\\d+)"`, "g");
  let m;
  while ((m = pin.exec(text)) !== null) {
    found.push({ crate: m[1], version: m[2], kind: "toml-pin" });
  }
  const adjacent = new RegExp(
    `\\b(${crateAlt})\\b(?:\\]\\([^\\)]*\\))?(?:\`)?\\s+(\\d+\\.\\d+\\.\\d+)`,
    "g",
  );
  while ((m = adjacent.exec(text)) !== null) {
    found.push({ crate: m[1], version: m[2], kind: "adjacent" });
  }
  const paren = new RegExp(`\\((\\d+\\.\\d+\\.\\d+)\\)`, "g");
  while ((m = paren.exec(text)) !== null) {
    const start = Math.max(0, m.index - 160);
    const window = text.slice(start, m.index + m[0].length);
    const named = CRATE_NAMES.filter((name) => window.includes(name));
    if (named.length === 0) continue;
    for (const crate of named) {
      found.push({ crate, version: m[1], kind: "parenthetical" });
    }
  }
  const scanner = text.match(
    /"scanner"\s*:\s*\{[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+)"/s,
  );
  if (scanner && relPath.includes("redact-scan")) {
    found.push({
      crate: "redact-scan",
      version: scanner[1],
      kind: "scanner-json",
    });
  }
  return found;
}

function checkDocVersions(facts) {
  const errors = [];
  for (const rel of VERSION_DOC_PATHS) {
    for (const hit of extractDocVersions(rel)) {
      const expected = facts.crate_versions[hit.crate];
      if (hit.version !== expected) {
        errors.push(
          `${rel}: ${hit.crate} ${hit.kind} ${hit.version} != Cargo.toml ${expected}`,
        );
      }
    }
  }
  return errors;
}

function parseVersionCell(cell) {
  const range = cell.match(
    /(\d+)\.(\d+)(?:\.x|\.\d+)?\s*[-–—]\s*(\d+)\.(\d+)/,
  );
  if (range) {
    return {
      kind: "range",
      from: [Number(range[1]), Number(range[2])],
      to: [Number(range[3]), Number(range[4])],
    };
  }
  const one = cell.match(/(\d+)\.(\d+)/);
  if (one) {
    return { kind: "minor", major: Number(one[1]), minor: Number(one[2]) };
  }
  return null;
}

function covers(spec, major, minor) {
  if (!spec) return false;
  const n = major * 1000 + minor;
  if (spec.kind === "minor") {
    return spec.major === major && spec.minor === minor;
  }
  const a = spec.from[0] * 1000 + spec.from[1];
  const b = spec.to[0] * 1000 + spec.to[1];
  return n >= Math.min(a, b) && n <= Math.max(a, b);
}

function parseWorkspaceSemver(version) {
  const m = version.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) throw new Error(`unparseable workspace version: ${version}`);
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

function checkSecurityTable(facts) {
  const text = readFileSync(join(ROOT, "SECURITY.md"), "utf8");
  const section = text.split("## Supported Versions")[1];
  if (!section) {
    return ["SECURITY.md: missing ## Supported Versions section"];
  }
  const table = section.split(/^## /m)[0];
  const rows = [];
  for (const line of table.split(/\r?\n/)) {
    if (!line.startsWith("|")) continue;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 2) continue;
    if (/^-{2,}/.test(cells[0]) || /^version$/i.test(cells[0])) continue;
    const spec = parseVersionCell(cells[0]);
    const supported = /yes/i.test(cells[1]);
    const unsupported = /no/i.test(cells[1]);
    if (!spec || (!supported && !unsupported)) {
      return [`SECURITY.md: unparseable support row: ${line}`];
    }
    rows.push({ spec, supported, raw: line });
  }
  if (rows.length === 0) {
    return ["SECURITY.md: no parseable support rows"];
  }
  const { major, minor } = parseWorkspaceSemver(facts.workspace_version);
  const errors = [];
  const yesCurrent = rows.some((r) => r.supported && covers(r.spec, major, minor));
  if (!yesCurrent) {
    errors.push(
      `SECURITY.md: ${major}.${minor}.x (workspace ${facts.workspace_version}) must be listed as supported`,
    );
  }
  if (minor > 0) {
    const prior = minor - 1;
    const yesPrior = rows.some(
      (r) => r.supported && covers(r.spec, major, prior),
    );
    if (!yesPrior) {
      errors.push(
        `SECURITY.md: prior minor ${major}.${prior}.x must be listed as supported`,
      );
    }
  }
  for (const row of rows) {
    if (!row.supported) continue;
    const allowed =
      covers(row.spec, major, minor) ||
      (minor > 0 && covers(row.spec, major, minor - 1));
    if (!allowed) {
      errors.push(
        `SECURITY.md: supported row is outside current/prior minor: ${row.raw}`,
      );
    }
  }
  return errors;
}

function runDocChecks(facts) {
  return [
    ...checkDocumentedFlags(facts),
    ...checkEntityCountMentions(facts.entity_type_count),
    ...checkDocVersions(facts),
    ...checkSecurityTable(facts),
  ];
}

function main() {
  const args = parseArgs(process.argv);
  const facts = buildFacts(args.bin);
  const serialized = `${JSON.stringify(facts, null, 2)}\n`;
  const extraErrors = runDocChecks(facts);
  if (args.check) {
    const existing = readFileSync(FACTS_PATH, "utf8");
    if (existing !== serialized) {
      console.error("data/facts.json is stale. Run:");
      console.error("  cargo build -p redact-cli");
      console.error(
        "  node scripts/extract-facts.mjs --bin ./target/debug/redact",
      );
      process.exit(1);
    }
  }
  if (extraErrors.length > 0) {
    for (const err of extraErrors) {
      console.error(err);
    }
    process.exit(1);
  }
  if (args.check) {
    console.log(
      `facts ok: ${facts.entity_type_count} entity types, ${facts.pattern_count} pack patterns, ${facts.optional_pack_rule_count} optional rules, workspace ${facts.workspace_version}`,
    );
    return;
  }
  if (args.write) {
    writeFileSync(FACTS_PATH, serialized);
    console.log(`wrote ${relative(ROOT, FACTS_PATH)}`);
  } else {
    process.stdout.write(serialized);
  }
}

main();
