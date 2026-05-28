#!/usr/bin/env node
// Long-running static server for manual browser profiling. Same files,
// headers, and `/pkg/*` aliasing as `runner.mjs`, but doesn't launch
// Playwright — you point your own browser at the printed URL.
//
// Usage:
//   node bench/serve.mjs --pkg ./pkg --port 8080 --root .

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { startServer } from "./server.mjs";

const { values } = parseArgs({
  options: {
    pkg: { type: "string", default: "pkg" },
    root: { type: "string", default: "." },
    port: { type: "string", default: "8080" },
  },
});

const root = resolve(values.root);
const pkg = resolve(values.pkg);
const port = parseInt(values.port, 10);

const server = await startServer({ root, pkg, port });
const { port: bound } = server.address();
console.error(`server: http://127.0.0.1:${bound}/bench/  (root=${root}, pkg=${pkg})`);
console.error("Ctrl-C to stop.");

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    server.close();
    process.exit(0);
  });
}
