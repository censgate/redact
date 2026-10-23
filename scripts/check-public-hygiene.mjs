#!/usr/bin/env node
// Scan tracked files against deny regexes from PUBLIC_HYGIENE_PATTERNS
// (newline-separated). When that variable is unset or empty, exit 0
// with a skip notice. Reports only path:line and a 1-based rule id
// (rule-1, rule-2, …) — never the pattern or the matched text.

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWLIST_PATH = join(ROOT, "data", "public-hygiene-allowlist.txt");

const SKIP_PATHS = new Set([
  "data/public-hygiene-allowlist.txt",
  "scripts/check-public-hygiene.mjs",
  ".lychee.toml",
  "Cargo.lock",
]);

const SKIP_PREFIXES = ["target/", ".git/"];
const SKIP_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".woff",
  ".woff2",
  ".patch",
]);
const MAX_BYTES = 256 * 1024;

function parseArgs(argv) {
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      console.log("Usage: check-public-hygiene.mjs");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
}

function loadPatterns() {
  const raw = process.env.PUBLIC_HYGIENE_PATTERNS || "";
  const lines = raw.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
  return lines;
}

function compilePatterns(lines) {
  const compiled = [];
  const errors = [];
  lines.forEach((source, idx) => {
    try {
      compiled.push(new RegExp(source));
    } catch {
      errors.push(idx + 1);
    }
  });
  if (errors.length > 0) {
    console.error(
      `public hygiene: invalid regex at rule-${errors.join(", rule-")}`,
    );
    process.exit(2);
  }
  return compiled;
}

function loadAllowlist() {
  const set = new Set();
  if (!existsSync(ALLOWLIST_PATH)) return set;
  for (const raw of readFileSync(ALLOWLIST_PATH, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    set.add(line);
  }
  return set;
}

function pathAllowed(rel, allow) {
  for (const entry of allow) {
    if (entry.endsWith("/")) {
      if (rel.startsWith(entry)) return true;
    } else if (rel === entry) {
      return true;
    }
  }
  return false;
}

function trackedFiles() {
  const out = execFileSync("git", ["ls-files", "-z"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return out.split("\0").filter(Boolean);
}

function shouldScan(rel) {
  if (SKIP_PATHS.has(rel)) return false;
  if (SKIP_PREFIXES.some((p) => rel.startsWith(p))) return false;
  const ext = rel.includes(".") ? `.${rel.split(".").pop().toLowerCase()}` : "";
  if (SKIP_EXTS.has(ext)) return false;
  return true;
}

function scanFile(rel, patterns) {
  const abs = join(ROOT, rel);
  let buf;
  try {
    buf = readFileSync(abs);
  } catch {
    return [];
  }
  if (buf.includes(0) || buf.length > MAX_BYTES) return [];
  const text = buf.toString("utf8");
  const hits = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, idx) => {
    patterns.forEach((re, patternIdx) => {
      re.lastIndex = 0;
      if (re.test(line)) {
        hits.push({ path: rel, line: idx + 1, rule: patternIdx + 1 });
      }
    });
  });
  return hits;
}

function main() {
  parseArgs(process.argv);
  const sources = loadPatterns();
  if (sources.length === 0) {
    console.log("public hygiene: PUBLIC_HYGIENE_PATTERNS is unset; skipping");
    return;
  }
  const patterns = compilePatterns(sources);
  const allow = loadAllowlist();
  const hits = [];
  for (const rel of trackedFiles()) {
    if (!shouldScan(rel)) continue;
    if (pathAllowed(rel, allow)) continue;
    hits.push(...scanFile(rel, patterns));
  }
  if (hits.length > 0) {
    for (const h of hits) {
      console.error(`${h.path}:${h.line}: rule-${h.rule}`);
    }
    console.error(`public hygiene: ${hits.length} hit(s)`);
    process.exit(1);
  }
  console.log(`public hygiene ok: ${patterns.length} rule(s), no hits`);
}

main();
