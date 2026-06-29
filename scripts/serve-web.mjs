import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const webRoot = path.join(repo, "apps", "web");
const port = Number(process.env.PORT || 4173);

const MIME = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
  ".zkey": "application/octet-stream",
};

function candidatePaths(pathname) {
  const decoded = decodeURIComponent(pathname);
  const clean = path.normalize(`/${decoded}`).slice(1);
  if (!clean || clean === ".") return ["index.html"];
  if (path.extname(clean)) return [clean];
  return [`${clean}.html`, path.join(clean, "index.html")];
}

function resolveWebFile(pathname, root = webRoot) {
  for (const candidate of candidatePaths(pathname)) {
    const resolved = path.resolve(root, candidate);
    if (!resolved.startsWith(`${root}${path.sep}`) && resolved !== root) {
      continue;
    }
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      return resolved;
    }
  }
  return null;
}

function createServer(root = webRoot) {
  return http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const file = resolveWebFile(url.pathname, root);
    if (!file) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("not found");
      return;
    }
    const ext = path.extname(file);
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    fs.createReadStream(file).pipe(res);
  });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  createServer().listen(port, "127.0.0.1", () => {
    console.log(`AnchorShield web serving http://127.0.0.1:${port}`);
  });
}

export { createServer, resolveWebFile };
