#!/usr/bin/env node
// Extract bash/console fences from README.md and docs/ that invoke the
// `redact` CLI, then run them against a built binary.
//
// Opt out of a block by putting `<!-- redact-doc-examples: skip -->`
// immediately before the fence, or `redact-doc-examples-skip` in the
// info string (` ```bash redact-doc-examples-skip `).

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const out = { bin: "redact" };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--bin") out.bin = argv[++i];
    else if (a === "--help" || a === "-h") {
      console.log("Usage: run-doc-examples.mjs [--bin <redact>]");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
  return out;
}

function walkMarkdown(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walkMarkdown(p, acc);
    else if (name.endsWith(".md")) acc.push(p);
  }
  return acc;
}

function extractFences(text) {
  const lines = text.split(/\r?\n/);
  const fences = [];
  let i = 0;
  while (i < lines.length) {
    const start = lines[i].match(/^```(\w[^\s`]*)?(.*)$/);
    if (!start) {
      i += 1;
      continue;
    }
    const lang = (start[1] || "").toLowerCase();
    const info = `${start[1] || ""}${start[2] || ""}`;
    const body = [];
    i += 1;
    while (i < lines.length && !lines[i].startsWith("```")) {
      body.push(lines[i]);
      i += 1;
    }
    const startLine = i - body.length;
    fences.push({
      lang,
      info,
      body: body.join("\n"),
      startLine,
      preceding: lines.slice(0, startLine - 1),
    });
    i += 1;
  }
  return fences;
}

function optedOut(fence) {
  if (/\bredact-doc-examples-skip\b/.test(fence.info)) return true;
  for (let i = fence.preceding.length - 1; i >= 0; i--) {
    const line = fence.preceding[i].trim();
    if (line === "") continue;
    return line === "<!-- redact-doc-examples: skip -->";
  }
  return false;
}

function callsRedactCli(body) {
  return body.split(/\r?\n/).some((line) => {
    const trimmed = line.replace(/^\s*#.*$/, "").trim();
    if (!trimmed) return false;
    // argv0 only: `redact ...`, not `cd redact` or `.../redact.git`.
    return /(?:^|[;&|]\s*)redact(?:\s|$)/.test(trimmed);
  });
}

function looksIllustrative(body) {
  if (/\b(if|for|while)\s+/.test(body)) return "control-flow";
  if (/\bgit\s+diff\b/.test(body)) return "git-diff-pipeline";
  if (/\bgit\s+clone\b/.test(body)) return "git-clone";
  if (/\bcargo\s+(build|test|run|install)\b/.test(body) && !/(?:^|[;&|]\s*)redact(?:\s|$)/m.test(body)) {
    return "cargo-without-redact-cli";
  }
  const fileArgs = [...body.matchAll(/(?:^|\s)(?:-i|--file|--files)\s+(\S+)/g)];
  for (const m of fileArgs) {
    const raw = m[1].replace(/^['"]|['"]$/g, "");
    if (raw.startsWith("<") || raw.includes("$")) continue;
    if (!existsSync(join(ROOT, raw))) return `missing-file:${raw}`;
  }
  return null;
}

function runnableLines(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return false;
      if (/^cargo\s+install\b/.test(trimmed)) return false;
      return true;
    })
    .join("\n");
}

function runBlock(bin, body) {
  const script = runnableLines(body);
  if (!script.trim()) {
    throw new Error("block had no runnable lines after stripping cargo install");
  }
  const dir = mkdtempSync(join(tmpdir(), "redact-doc-ex-"));
  const path = join(dir, "block.sh");
  const wrapped = `#!/usr/bin/env bash
set -uo pipefail
run() {
  local st=0
  "$@" || st=$?
  if [[ "$*" == *--fail-on-detect* ]]; then
    if [[ "$st" -eq 0 || "$st" -eq 1 ]]; then
      return 0
    fi
    return "$st"
  fi
  return "$st"
}
${script
  .split(/\n/)
  .map((line) => {
    if (/(?:^|[;&|]|\s)redact(?![-a-zA-Z0-9])/.test(line)) {
      return `run ${line}`;
    }
    return line;
  })
  .join("\n")}
`;
  writeFileSync(path, wrapped, { mode: 0o755 });
  try {
    execFileSync("bash", [path], {
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        PATH: `${dirname(bin)}:${process.env.PATH || ""}`,
      },
      cwd: ROOT,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function markdownTargets() {
  const files = [join(ROOT, "README.md")];
  walkMarkdown(join(ROOT, "docs"), files);
  return files.sort();
}

function main() {
  const args = parseArgs(process.argv);
  const bin = args.bin;
  let ran = 0;
  let skipped = 0;
  const errors = [];
  for (const file of markdownTargets()) {
    const rel = relative(ROOT, file);
    const fences = extractFences(readFileSync(file, "utf8"));
    for (const fence of fences) {
      if (fence.lang !== "bash" && fence.lang !== "console" && fence.lang !== "sh") {
        continue;
      }
      if (!callsRedactCli(fence.body)) continue;
      const loc = `${rel}:${fence.startLine}`;
      if (optedOut(fence)) {
        skipped += 1;
        console.log(`skip ${loc} (opt-out)`);
        continue;
      }
      const reason = looksIllustrative(fence.body);
      if (reason) {
        errors.push(
          `${loc}: illustrative block needs <!-- redact-doc-examples: skip --> (${reason})`,
        );
        continue;
      }
      try {
        runBlock(bin, fence.body);
        ran += 1;
        console.log(`ok   ${loc}`);
      } catch (err) {
        const detail = err.stderr || err.stdout || err.message;
        errors.push(`${loc}: ${detail}`);
      }
    }
  }
  if (errors.length > 0) {
    for (const err of errors) console.error(err);
    process.exit(1);
  }
  if (ran === 0) {
    console.error("no runnable redact CLI examples found");
    process.exit(1);
  }
  console.log(`doc examples ok: ${ran} ran, ${skipped} skipped`);
}

main();
