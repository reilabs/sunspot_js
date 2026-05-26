// Static file server shared by `runner.mjs` (headless Playwright driver)
// and `serve.mjs` (long-running server for manual browser profiling).
//
// Aliases `/pkg/*` to a chosen pkg directory so multiple wasm builds can
// be benched against the same `bench/` files. Sends COOP/COEP so that
// `SharedArrayBuffer` (needed by wasm-bindgen-rayon) is available.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve } from "node:path";

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

// Resolves the package.json `"main"` entry for a pkg directory.
async function resolvePkgMain(pkgDir) {
  try {
    const json = JSON.parse(
      await readFile(resolve(pkgDir, "package.json"), "utf-8"),
    );
    return typeof json.main === "string" ? json.main : null;
  } catch {
    return null;
  }
}

// Starts a server on `port` (0 = pick a free port). Resolves to the
// listening server. Caller is responsible for `server.close()`.
export async function startServer({ root, pkg, port = 0 }) {
  const pkgMain = await resolvePkgMain(pkg);
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      let pathname = decodeURIComponent(url.pathname);
      if (pkgMain && (pathname === "/pkg" || pathname === "/pkg/")) {
        pathname = "/pkg/" + pkgMain;
      } else if (pathname.endsWith("/")) {
        pathname += "index.html";
      }

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
  return new Promise((res) =>
    server.listen(port, "127.0.0.1", () => res(server)),
  );
}
