const assert = require("assert");
const http = require("http");
const { createServer, clientIp } = require("./server");

function request(server, { method = "GET", path = "/", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        method,
        path,
        headers,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: body ? JSON.parse(body) : null,
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

async function withServer(provider, fn) {
  const server = createServer(provider);
  await listen(server);
  try {
    await fn(server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const provider = {
  levelName: "anchorshield-kyc",
  async createAccessToken(userId) {
    return `token:${userId}`;
  },
  async getApplicant() {
    return {
      id: "applicant-id-not-public",
      review: { reviewResult: { reviewAnswer: "GREEN" } },
    };
  },
  async verifiedCredential() {
    return {
      kyc_passed: 1,
      country: 566,
      age: 22,
      applicant_id: "applicant-id-not-public",
      review_answer: "GREEN",
    };
  },
};

async function main() {
  assert.strictEqual(
    clientIp({
      headers: {
        "x-forwarded-for": "203.0.113.9",
        "x-real-ip": "198.51.100.7",
      },
      socket: { remoteAddress: "10.0.0.5" },
    }),
    "10.0.0.5",
  );
  assert.strictEqual(
    clientIp({
      headers: {
        "x-forwarded-for": "203.0.113.9",
        "x-real-ip": "198.51.100.7",
      },
      socket: { remoteAddress: "127.0.0.1" },
    }),
    "198.51.100.7",
  );

  await withServer(provider, async (server) => {
    const token = await request(server, {
      method: "POST",
      path: "/api/kyc/token",
    });
    assert.strictEqual(token.status, 200);
    assert.match(token.body.userId, /^as-web-[a-f0-9-]{36}$/);
    assert.ok(token.body.statusToken);

    const denied = await request(server, {
      path: `/api/kyc/status?userId=${token.body.userId}`,
    });
    assert.strictEqual(denied.status, 401);

    const status = await request(server, {
      path: `/api/kyc/status?statusToken=${encodeURIComponent(token.body.statusToken)}`,
    });
    assert.strictEqual(status.status, 200);
    assert.deepStrictEqual(status.body.credential, {
      kyc_passed: 1,
      country: 566,
      age: 22,
    });
  });

  await withServer(
    {
      ...provider,
      async verifiedCredential() {
        throw new Error("provider included private internals");
      },
    },
    async (server) => {
      const token = await request(server, {
        method: "POST",
        path: "/api/kyc/token",
      });
      const status = await request(server, {
        path: `/api/kyc/status?statusToken=${encodeURIComponent(token.body.statusToken)}`,
      });
      assert.strictEqual(status.status, 502);
      assert.deepStrictEqual(status.body, {
        error: "kyc credential unavailable",
      });
    },
  );

  console.log("kyc backend server test OK");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
