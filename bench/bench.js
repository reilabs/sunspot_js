// Headless bench driver. Loads the wasm module, fetches a Noir project's
// artifacts, calls each `bench_*` entry point in turn, and stores a JSON-
// serialisable result on `window.benchResults` (or `window.benchError`).
//
// Driven by Playwright via `runner.mjs`; navigate to
//   /bench/?project=<name>&iters=<n>&foldN=<n>
//
// The wasm must be built with `--features bench`.

import init, * as sw from "../pkg/sunspot_wasm.js";

const TIMING_COLS = ["iterations", "total_ms", "min_ms", "median_ms", "mean_ms", "max_ms"];
const STAGE_COLS = [
  "iterations", "setup_ms", "compute_h_ms", "bsb22_pok_ms",
  "prove_ar_bs_bs1_ms", "prove_krs_ms", "total_sequential_ms",
];

const BENCHES = [
  {
    name: "parse_r1cs",
    needs: ["ccs"],
    table: "timings",
    call: (a, iters) => sw.bench_parse_r1cs(a.ccs, iters),
  },
  {
    name: "parse_proving_key_streaming",
    needs: ["pk"],
    table: "timings",
    call: (a, iters) => sw.bench_parse_proving_key(a.pk, iters),
  },
  {
    name: "parse_proving_key_batched",
    needs: ["pk"],
    table: "timings",
    call: (a, iters) => sw.bench_parse_proving_key_batched(a.pk, iters),
  },
  {
    name: "parse_proving_key_streaming_unchecked",
    needs: ["pk"],
    table: "timings",
    call: (a, iters) => sw.bench_parse_proving_key_unchecked(a.pk, iters),
  },
  {
    name: "parse_proving_key_batched_unchecked",
    needs: ["pk"],
    table: "timings",
    call: (a, iters) => sw.bench_parse_proving_key_unchecked_batched(a.pk, iters),
  },
  {
    name: "solve",
    needs: ["ccs", "json", "gz", "pk"],
    table: "timings",
    call: (a, iters) => sw.bench_solve(a.ccs, a.json, a.gz, a.pk, iters),
  },
  {
    name: "prove",
    needs: ["ccs", "json", "gz", "pk"],
    table: "timings",
    call: (a, iters) => sw.bench_prove(a.ccs, a.json, a.gz, a.pk, iters),
  },
];

// Tuned so each sample takes ~tens of µs (median Fr mul ≈ a few hundred
// nanoseconds on wasm). Adjust if `min_ms` falls below ~0.05ms.
const MUL_PAIRS = 16384;
const nsPerMul = (r) => (r.median_ms * 1e6) / MUL_PAIRS;

async function fetchBytes(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`fetch ${path}: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function loadArtifacts(project, exts) {
  const base = `../tests/noir_projects/${project}/target/${project}`;
  const out = {};
  await Promise.all(
    exts.map(async (ext) => {
      out[ext] = await fetchBytes(`${base}.${ext}`);
    }),
  );
  return out;
}

function serialize(r) {
  return {
    iterations: r.iterations,
    total_ms: r.total_ms,
    min_ms: r.min_ms,
    median_ms: r.median_ms,
    mean_ms: r.mean_ms,
    max_ms: r.max_ms,
  };
}

const statusEl = () => document.getElementById("status");
const headerEl = () => document.getElementById("header");
const projectsEl = () => document.getElementById("projects");
const setStatus = (msg) => { const el = statusEl(); if (el) el.textContent = msg; };

const COLS_FOR = { timings: TIMING_COLS, stages: STAGE_COLS };
const TABLE_HEADERS = {
  timings: ["bench", "iters", "total", "min", "median", "mean", "max"],
  stages: ["bench", "iters", "setup", "compute_h", "bsb22_pok", "ar_bs_bs1", "krs", "total_seq"],
};

function fmt(v) {
  if (v == null) return "";
  if (typeof v !== "number") return String(v);
  if (!isFinite(v)) return String(v);
  if (Number.isInteger(v)) return v.toString();
  return v.toFixed(3);
}

function makeTable(kind, caption) {
  const t = document.createElement("table");
  const cap = document.createElement("caption");
  cap.textContent = caption;
  t.appendChild(cap);
  const thead = document.createElement("thead");
  const tr = document.createElement("tr");
  for (const h of TABLE_HEADERS[kind]) {
    const th = document.createElement("th");
    th.textContent = h;
    tr.appendChild(th);
  }
  thead.appendChild(tr);
  t.appendChild(thead);
  t.appendChild(document.createElement("tbody"));
  return t;
}

function buildProjectSection(project) {
  const wrap = document.createElement("section");
  wrap.className = "project";
  wrap.dataset.project = project;
  const h = document.createElement("h2");
  h.textContent = project;
  wrap.appendChild(h);
  const timings = makeTable("timings", "timings (ms)");
  timings.dataset.kind = "timings";
  const stages = makeTable("stages", "prove_stages (ms)");
  stages.dataset.kind = "stages";
  wrap.appendChild(timings);
  wrap.appendChild(stages);
  projectsEl().appendChild(wrap);
  return wrap;
}

function ensureRow(section, b) {
  const tbl = section.querySelector(`table[data-kind="${b.table}"]`);
  if (!tbl) return null;
  const tbody = tbl.querySelector("tbody");
  let row = tbody.querySelector(`tr[data-bench="${b.name}"]`);
  if (!row) {
    row = document.createElement("tr");
    row.dataset.bench = b.name;
    row.className = "pending";
    const cols = COLS_FOR[b.table];
    row.innerHTML = `<td>${b.name}</td>` + cols.map(() => `<td>…</td>`).join("");
    tbody.appendChild(row);
  }
  return row;
}

function fillRow(section, b, entry, cls = "") {
  const row = ensureRow(section, b);
  if (!row) return;
  row.className = cls;
  const cols = COLS_FOR[b.table];
  const cells = row.querySelectorAll("td");
  cells[0].textContent = b.name;
  cols.forEach((c, i) => { cells[i + 1].textContent = fmt(entry?.[c]); });
}

function markSkipped(section, b) {
  const row = ensureRow(section, b);
  if (!row) return;
  row.className = "skipped";
  const cells = row.querySelectorAll("td");
  cells[0].textContent = b.name;
  cells[1].textContent = "skipped";
  for (let i = 2; i < cells.length; i++) cells[i].textContent = "";
}

function markError(section, b, msg) {
  const row = ensureRow(section, b);
  if (!row) return;
  row.className = "err";
  const cells = row.querySelectorAll("td");
  cells[0].textContent = b.name;
  cells[1].textContent = "error";
  for (let i = 2; i < cells.length; i++) cells[i].textContent = "";
  row.title = msg;
}

// Runs every bench against a single project. Per-bench errors are captured
// inline so one failure doesn't shadow the rest; `null` results are recorded
// as `skipped` (e.g. pedersen on an algebraic-only circuit).
async function runProject({ project, iters, foldN }, section) {
  const exts = new Set();
  for (const b of BENCHES) for (const e of b.needs) exts.add(e);

  for (const b of BENCHES) ensureRow(section, b);

  setStatus(`[${project}] fetching artifacts…`);
  const artifacts = await loadArtifacts(project, [...exts]);

  const benches = [];
  for (const b of BENCHES) {
    setStatus(`[${project}] running ${b.name} (${iters} iters)…`);
    await new Promise((r) => setTimeout(r, 0));
    try {
      const result = b.call(artifacts, iters, { foldN });
      if (result == null) {
        benches.push({ name: b.name, skipped: true });
        markSkipped(section, b);
      } else {
        const ser = b.serialize ?? serialize;
        const entry = { name: b.name, ...ser(result) };
        benches.push(entry);
        fillRow(section, b, entry);
      }
    } catch (e) {
      const msg = e.message ?? String(e);
      benches.push({ name: b.name, error: msg });
      markError(section, b, msg);
    }
  }
  return { project, iters, foldN, benches };
}

function parseProjects(params) {
  const raw = params.getAll("project");
  const list = raw.flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean);
  return [...new Set(list)];
}

function showError(msg) {
  window.benchError = msg;
  const s = statusEl();
  if (s) { s.textContent = "error"; s.classList.add("err"); }
  const h = headerEl();
  if (h) { h.classList.add("err"); h.textContent = msg; }
}

async function main() {
  setStatus("initialising wasm…");
  try {
    await init();
    /// only init threadPool on threaded builds
    if (typeof sw.initThreadPool === "function") {
      await sw.initThreadPool(navigator.hardwareConcurrency);
    }
  } catch (e) {
    showError(
      "failed to load wasm — did you run `CARGO_UNSTABLE_BUILD_STD=panic_abort,std wasm-pack build --release --target web --features bench`?\n\n" +
      (e.stack ?? String(e)),
    );
    return;
  }

  const params = new URLSearchParams(location.search);
  const projects = parseProjects(params);
  if (projects.length === 0) {
    showError("missing required query param: project (comma-separated or repeated)");
    return;
  }
  const iters = parseInt(params.get("iters") ?? "20", 10);
  const foldN = parseInt(params.get("foldN") ?? "1024", 10);
  const h = headerEl();
  if (h) h.textContent = `projects=${projects.join(",")}  iters=${iters}  foldN=${foldN}`;

  const sections = new Map();
  for (const project of projects) sections.set(project, buildProjectSection(project));

  const all = [];
  let hadError = false;
  for (const project of projects) {
    try {
      const result = await runProject({ project, iters, foldN }, sections.get(project));
      all.push(result);
    } catch (e) {
      hadError = true;
      const msg = e.stack ?? e.message ?? String(e);
      console.error(`[${project}]`, msg);
      all.push({ project, iters, foldN, error: msg });
      const sec = sections.get(project);
      if (sec) {
        const note = document.createElement("div");
        note.className = "err";
        note.textContent = msg;
        sec.appendChild(note);
      }
    }
  }

  // Keep single-project shape so runner.mjs (which navigates per project)
  // still sees the same object on window.benchResults.
  window.benchResults = all.length === 1 ? all[0] : all;
  if (hadError && all.length === 1) window.benchError = all[0].error;
  setStatus(`done (${all.length} project${all.length === 1 ? "" : "s"})`);
}

main();
