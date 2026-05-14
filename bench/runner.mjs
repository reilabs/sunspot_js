#!/usr/bin/env node
// Headless bench driver. Spins up a tiny static server, launches Playwright
// Chromium, and drives `bench/` against each project in turn.
// Writes a JSON file in the format consumed by `compare.mjs`.
//
// Usage:
//   node bench/runner.mjs --pkg ./pkg --out results.json \
//     --projects sum_a_b,polynomial,poseidon2 --iters 20 --foldN 1024
//
// The `--pkg <dir>` flag aliases `/pkg/*` to a chosen directory, so the
// same harness can bench multiple wasm builds without copying files.

import { createServer } from "node:http";
import { readFile, writeFile, stat } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".gz": "application/gzip",
};

async function fileExists(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function startServer({ root, pkg }) {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      let pathname = decodeURIComponent(url.pathname);
      if (pathname.endsWith("/")) pathname += "index.html";

      let filePath;
      if (pathname.startsWith("/pkg/")) {
        filePath = resolve(pkg, pathname.slice("/pkg/".length));
      } else {
        filePath = resolve(root, "." + pathname);
      }
      // Block path escapes.
      const allowed =
        filePath.startsWith(resolve(root)) || filePath.startsWith(resolve(pkg));
      if (!allowed || !(await fileExists(filePath))) {
        res.writeHead(404);
        res.end("not found");
        return;
      }

      const buf = await readFile(filePath);
      res.writeHead(200, {
        "Content-Type":
          MIME[extname(filePath)] ?? "application/octet-stream",
        "Cache-Control": "no-store",
        // `bench_*` runs are heavy; let the browser hold the response open.
        "Content-Length": buf.length,
        // Cross-origin isolation — required for SharedArrayBuffer.
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
      });
      res.end(buf);
    } catch (e) {
      res.writeHead(500);
      res.end(String(e));
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function main() {
  const { values } = parseArgs({
    options: {
      pkg: { type: "string", default: "pkg" },
      out: { type: "string", default: "bench-results.json" },
      projects: {
        type: "string",
        default: "sum_a_b,polynomial,poseidon2",
      },
      iters: { type: "string", default: "20" },
      foldN: { type: "string", default: "1024" },
      root: { type: "string", default: "." },
      label: { type: "string", default: "" },
      timeoutMs: { type: "string", default: "600000" },
    },
  });

  const root = resolve(values.root);
  const pkg = resolve(values.pkg);

  const server = await startServer({ root, pkg });
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  console.error(`server: ${baseUrl}  (root=${root}, pkg=${pkg})`);

  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on("console", (msg) => {
    if (msg.type() === "error") console.error("[page]", msg.text());
  });
  page.on("pageerror", (err) => console.error("[page]", err.message));

  const projects = values.projects.split(",").map((s) => s.trim()).filter(Boolean);
  const timeoutMs = parseInt(values.timeoutMs, 10);

  const out = {
    timestamp: new Date().toISOString(),
    label: values.label,
    iters: parseInt(values.iters, 10),
    foldN: parseInt(values.foldN, 10),
    pkg: values.pkg,
    userAgent: await page.evaluate(() => navigator.userAgent).catch(() => null),
    runs: [],
  };

  try {
    for (const project of projects) {
      const params = new URLSearchParams({
        project,
        iters: values.iters,
        foldN: values.foldN,
      });
      const url = `${baseUrl}/bench/?${params}`;
      console.error(`> ${project}`);
      await page.goto(url, { waitUntil: "load", timeout: timeoutMs });
      await page.waitForFunction(
        () => window.benchResults || window.benchError,
        null,
        { timeout: timeoutMs },
      );
      const result = await page.evaluate(() =>
        window.benchResults ?? { error: window.benchError },
      );
      if (!out.userAgent) {
        out.userAgent = await page.evaluate(() => navigator.userAgent);
      }
      out.runs.push(result);
    }
  } finally {
    await browser.close();
    server.close();
  }

  await writeFile(values.out, JSON.stringify(out, null, 2));
  console.error(`wrote ${values.out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
