import assert from "node:assert";
import http from "node:http";

import { createServer } from "./serve-web.mjs";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function request(server, path) {
  return new Promise((resolve, reject) => {
    http
      .get(
        {
          hostname: "127.0.0.1",
          port: server.address().port,
          path,
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => {
            body += chunk;
          });
          res.on("end", () => resolve({ status: res.statusCode, body }));
        },
      )
      .on("error", reject);
  });
}

const apiBackend = http.createServer((req, res) => {
  if (req.url === "/api/ping") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "missing" }));
});
await listen(apiBackend);

const server = createServer(undefined, { apiPort: apiBackend.address().port });
await listen(server);
try {
  for (const route of ["/", "/console", "/console.html", "/issuer", "/rwa"]) {
    const response = await request(server, route);
    assert.strictEqual(response.status, 200, `${route} should resolve`);
    assert.match(response.body, /<title>/, `${route} should return html`);
  }
  const asset = await request(server, "/assets/app.js");
  assert.strictEqual(asset.status, 200);
  assert.match(asset.body, /FLOW_CONFIG/);
  const api = await request(server, "/api/ping");
  assert.strictEqual(api.status, 200);
  assert.deepStrictEqual(JSON.parse(api.body), { ok: true });
  const missing = await request(server, "/missing-page");
  assert.strictEqual(missing.status, 404);
} finally {
  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => apiBackend.close(resolve));
}

console.log("web server route test OK");
