#!/usr/bin/env node
// Diff two bench JSON files (as produced by `runner.mjs`) and emit a
// markdown table of median-ms deltas.
//
// Usage:
//   node bench/compare.mjs --baseline base.json --current cur.json [--out cmp.md]

import { readFile, writeFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    baseline: { type: "string" },
    current: { type: "string" },
    out: { type: "string", default: "-" },
    title: { type: "string", default: "sunspot_wasm bench (chrome / wasm)" },
  },
});

if (!values.current) {
  console.error(
    "usage: compare.mjs --current cur.json [--baseline base.json] [--out out.md]",
  );
  process.exit(2);
}

async function loadJson(path) {
  if (!path) return null;
  try {
    if (!(await stat(path)).isFile()) return null;
  } catch {
    return null;
  }
  return JSON.parse(await readFile(path, "utf-8"));
}

function fmt(n) {
  if (n == null || !Number.isFinite(n)) return "-";
  if (n < 1) return n.toFixed(3);
  if (n < 100) return n.toFixed(2);
  return n.toFixed(1);
}

function fmtDelta(deltaPct) {
  const s = deltaPct >= 0 ? `+${deltaPct.toFixed(1)}%` : `${deltaPct.toFixed(1)}%`;
  if (deltaPct >= 10) return `⚠️ ${s}`;
  if (deltaPct <= -10) return `🟢 ${s}`;
  return s;
}

const baseline = await loadJson(values.baseline);
const current = await loadJson(values.current);
if (!current) {
  console.error(`could not read current: ${values.current}`);
  process.exit(2);
}

const baseMap = new Map();
if (baseline) {
  for (const run of baseline.runs ?? []) {
    for (const b of run.benches ?? []) {
      baseMap.set(`${run.project}/${b.name}`, b);
    }
  }
}

const lines = [];
lines.push(`## ${values.title}`);
lines.push("");
if (baseline) {
  lines.push(
    `Baseline: \`${values.baseline}\` • Head: \`${values.current}\` • ` +
      `\`${current.userAgent ?? "unknown UA"}\``,
  );
} else {
  lines.push(
    `Head: \`${values.current}\` • baseline missing — showing head only ` +
      `(\`${current.userAgent ?? "unknown UA"}\`)`,
  );
}
lines.push("");
lines.push("| project | bench | base median ms | head median ms | Δ |");
lines.push("| --- | --- | ---: | ---: | ---: |");

let regressions = 0;
for (const run of current.runs ?? []) {
  for (const b of run.benches ?? []) {
    const key = `${run.project}/${b.name}`;
    const base = baseMap.get(key);
    if (b.error) {
      lines.push(
        `| ${run.project} | ${b.name} | ${fmt(base?.median_ms)} | error | - |`,
      );
      continue;
    }
    if (b.skipped) {
      lines.push(
        `| ${run.project} | ${b.name} | ${fmt(base?.median_ms)} | n/a | - |`,
      );
      continue;
    }
    if (!base || base.median_ms == null) {
      lines.push(
        `| ${run.project} | ${b.name} | - | ${fmt(b.median_ms)} | new |`,
      );
      continue;
    }
    const delta = ((b.median_ms - base.median_ms) / base.median_ms) * 100;
    if (delta >= 10) regressions += 1;
    lines.push(
      `| ${run.project} | ${b.name} | ${fmt(base.median_ms)} | ${fmt(b.median_ms)} | ${fmtDelta(delta)} |`,
    );
  }
}

lines.push("");
if (regressions > 0) {
  lines.push(`> ⚠️ ${regressions} bench(es) regressed by ≥10% — CI noise is high, repeat to confirm.`);
} else if (baseline) {
  lines.push(`> No bench regressed by ≥10% vs baseline.`);
}
lines.push("");

const md = lines.join("\n");
if (values.out === "-") process.stdout.write(md + "\n");
else await writeFile(values.out, md + "\n");
