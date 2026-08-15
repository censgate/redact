#!/usr/bin/env node
// Host-only facts extractor. Reads compiled entity types from
// `redact --format json list-entities` plus pack YAML rule counts.
// Never writes sample secrets.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FACTS_PATH = join(ROOT, "data", "facts.json");

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

function countPatterns(file) {
  const text = readFileSync(file, "utf8");
  const ids = text.match(/^\s+-\s+id:/gm);
  return ids ? ids.length : 0;
}

function countEnabled(file) {
  const text = readFileSync(file, "utf8");
  // Count pattern entries, then subtract those with enabled: false immediately
  // after (same item). Conservative: count all `- id:` minus `enabled: false`.
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

function buildFacts(bin) {
  const entity_types = listEntities(bin);
  const packs = packCounts();
  return {
    entity_types,
    entity_type_count: entity_types.length,
    ...packs,
  };
}

function main() {
  const args = parseArgs(process.argv);
  const facts = buildFacts(args.bin);
  const serialized = `${JSON.stringify(facts, null, 2)}\n`;
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
    console.log(
      `facts ok: ${facts.entity_type_count} entity types, ${facts.pattern_count} pack patterns, ${facts.optional_pack_rule_count} optional rules`,
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
