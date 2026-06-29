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

const server = createServer();
await listen(server);
try {
  for (const route of ["/", "/console", "/console.html", "/issuer", "/rwa"]) {
    const response = await request(server, route);
    assert.strictEqual(response.status, 200, `${route} should resolve`);
    assert.match(response.body, /<title>/, `${route} should return html`);
  }
  const missing = await request(server, "/missing-page");
  assert.strictEqual(missing.status, 404);
} finally {
  await new Promise((resolve) => server.close(resolve));
}

console.log("web server route test OK");
