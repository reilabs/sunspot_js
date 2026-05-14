// Headless bench driver. Loads the wasm module, fetches a Noir project's
// artifacts, calls each `bench_*` entry point in turn, and stores a JSON-
// serialisable result on `window.benchResults` (or `window.benchError`).
//
// Driven by Playwright via `runner.mjs`; navigate to
//   /bench/?project=<name>&iters=<n>&foldN=<n>
//
// The wasm must be built with `--features bench`.

import init, * as sw from "../pkg/sunspot_wasm.js";

const BENCHES = [
  {
    name: "parse_r1cs",
    needs: ["ccs"],
    call: (a, iters) => sw.bench_parse_r1cs(a.ccs, iters),
  },
  {
    name: "solve",
    needs: ["ccs", "json", "gz"],
    call: (a, iters) => sw.bench_solve(a.ccs, a.json, a.gz, iters),
  },
];

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

// Runs every bench against a single project. Per-bench errors are captured
// inline so one failure doesn't shadow the rest; `null` results are recorded
// as `skipped` (e.g. pedersen on an algebraic-only circuit).
async function runProject({ project, iters, foldN }) {
  const exts = new Set();
  for (const b of BENCHES) for (const e of b.needs) exts.add(e);

  const artifacts = await loadArtifacts(project, [...exts]);

  const benches = [];
  for (const b of BENCHES) {
    await new Promise((r) => setTimeout(r, 0));
    try {
      const result = b.call(artifacts, iters, { foldN });
      if (result == null) {
        benches.push({ name: b.name, skipped: true });
      } else {
        benches.push({ name: b.name, ...serialize(result) });
      }
    } catch (e) {
      benches.push({ name: b.name, error: e.message ?? String(e) });
    }
  }
  return { project, iters, foldN, benches };
}

async function main() {
  try {
    await init();
    // Spin up the rayon thread pool. The wasm module is threaded — it imports
    // shared memory and expects workers, so this must run before any solver
    // call. Requires the page to be cross-origin isolated (COOP/COEP).
    await sw.initThreadPool(navigator.hardwareConcurrency);
  } catch (e) {
    window.benchError =
      "failed to load wasm — did you run `wasm-pack build --release --target web --features bench`?\n\n" +
      (e.stack ?? String(e));
    return;
  }

  const params = new URLSearchParams(location.search);
  const project = params.get("project");
  if (!project) {
    window.benchError = "missing required query param: project";
    return;
  }
  const opts = {
    project,
    iters: parseInt(params.get("iters") ?? "20", 10),
    foldN: parseInt(params.get("foldN") ?? "1024", 10),
  };
  try {
    window.benchResults = await runProject(opts);
  } catch (e) {
    window.benchError = e.stack ?? e.message ?? String(e);
  }
}

main();
