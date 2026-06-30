const assert = require("assert");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { Keypair } = require("@stellar/stellar-sdk");
const {
  createServer,
  clientIp,
  stellarMessageHash,
  walletProofMessage,
} = require("./server");

function request(
  server,
  { method = "GET", path = "/", headers = {}, body = null } = {},
) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        method,
        path,
        headers: {
          ...headers,
          ...(payload
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(payload),
              }
            : {}),
        },
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
    req.end(payload);
  });
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

async function withServer(provider, fn, options = {}) {
  const server = createServer(provider, options);
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
const walletKeypair = Keypair.random();
const WALLET = walletKeypair.publicKey();

function walletProof({
  action,
  statusToken,
  userCommitment = "",
  wallet = WALLET,
  issuedAt = new Date().toISOString(),
} = {}) {
  const message = walletProofMessage({
    wallet,
    action,
    statusToken,
    userCommitment,
    issuedAt,
  });
  return {
    message,
    issuedAt,
    signerAddress: wallet,
    signature: walletKeypair
      .sign(stellarMessageHash(message))
      .toString("base64"),
  };
}

function tempEnrollmentOptions(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-enroll-"));
  return {
    enrollment: {
      statePath: path.join(dir, "enrollments.json"),
      rootPublisher({ credentialRoot }) {
        return { mode: "test", credentialRoot };
      },
      now: () => "2026-06-30T00:00:00.000Z",
      ...overrides,
    },
  };
}

async function main() {
  assert.strictEqual(
    Keypair.fromPublicKey(
      "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L",
    ).verify(
      stellarMessageHash("Hello, World!"),
      Buffer.from(
        "fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==",
        "base64",
      ),
    ),
    true,
  );

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
      method: "POST",
      path: "/api/kyc/status",
      body: { userId: token.body.userId },
    });
    assert.strictEqual(denied.status, 401);

    const freshInsteadOfHijack = await request(server, {
      method: "POST",
      path: "/api/kyc/token",
      body: { userId: token.body.userId },
    });
    assert.strictEqual(freshInsteadOfHijack.status, 200);
    assert.notStrictEqual(freshInsteadOfHijack.body.userId, token.body.userId);

    const refreshed = await request(server, {
      method: "POST",
      path: "/api/kyc/token",
      body: {
        userId: token.body.userId,
        statusToken: token.body.statusToken,
      },
    });
    assert.strictEqual(refreshed.status, 200);
    assert.strictEqual(refreshed.body.userId, token.body.userId);

    const status = await request(server, {
      method: "POST",
      path: "/api/kyc/status",
      body: { statusToken: token.body.statusToken },
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
        method: "POST",
        path: "/api/kyc/status",
        body: { statusToken: token.body.statusToken },
      });
      assert.strictEqual(status.status, 502);
      assert.deepStrictEqual(status.body, {
        error: "kyc credential unavailable",
      });
    },
  );

  await withServer(
    provider,
    async (server) => {
      const token = await request(server, {
        method: "POST",
        path: "/api/kyc/token",
      });
      const anonymous = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
        },
      });
      assert.strictEqual(anonymous.status, 401);

      const noWalletProof = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
          statusToken: token.body.statusToken,
        },
      });
      assert.strictEqual(noWalletProof.status, 401);

      const badWalletProof = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
          statusToken: token.body.statusToken,
          walletProof: {
            ...walletProof({
              action: "enroll",
              statusToken: token.body.statusToken,
              userCommitment: "12345",
            }),
            message: "tampered",
          },
        },
      });
      assert.strictEqual(badWalletProof.status, 401);

      const enrolled = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
          statusToken: token.body.statusToken,
          walletProof: walletProof({
            action: "enroll",
            statusToken: token.body.statusToken,
            userCommitment: "12345",
          }),
        },
      });
      assert.strictEqual(enrolled.status, 200);
      assert.strictEqual(enrolled.body.root_publish.mode, "test");
      assert.strictEqual(enrolled.body.credential.wallet, WALLET);
      assert.strictEqual(enrolled.body.credential.user_commitment, "12345");
      assert.strictEqual(enrolled.body.credential.attributes.country, "566");
      assert.ok(Array.isArray(enrolled.body.credential.merkle_siblings));
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(
          enrolled.body.credential,
          "user_secret",
        ),
        false,
      );

      const credential = await request(server, {
        method: "POST",
        path: "/api/credential",
        body: {
          wallet: WALLET,
          statusToken: token.body.statusToken,
          walletProof: walletProof({
            action: "credential",
            statusToken: token.body.statusToken,
          }),
        },
      });
      assert.strictEqual(credential.status, 200);
      assert.strictEqual(
        credential.body.credential.credential_root,
        enrolled.body.credential.credential_root,
      );

      const otherToken = await request(server, {
        method: "POST",
        path: "/api/kyc/token",
      });
      const deniedCredential = await request(server, {
        method: "POST",
        path: "/api/credential",
        body: {
          wallet: WALLET,
          statusToken: otherToken.body.statusToken,
          walletProof: walletProof({
            action: "credential",
            statusToken: otherToken.body.statusToken,
          }),
        },
      });
      assert.strictEqual(deniedCredential.status, 403);

      const conflict = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "67890",
          statusToken: token.body.statusToken,
          walletProof: walletProof({
            action: "enroll",
            statusToken: token.body.statusToken,
            userCommitment: "67890",
          }),
        },
      });
      assert.strictEqual(conflict.status, 409);
    },
    tempEnrollmentOptions(),
  );

  await withServer(
    {
      ...provider,
      async verifiedCredential() {
        return null;
      },
    },
    async (server) => {
      const token = await request(server, {
        method: "POST",
        path: "/api/kyc/token",
      });
      const enrolled = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
          statusToken: token.body.statusToken,
          walletProof: walletProof({
            action: "enroll",
            statusToken: token.body.statusToken,
            userCommitment: "12345",
          }),
        },
      });
      assert.strictEqual(enrolled.status, 409);
      assert.deepStrictEqual(enrolled.body, { error: "kyc is not approved" });
    },
    tempEnrollmentOptions(),
  );

  await withServer(
    provider,
    async (server) => {
      const token = await request(server, {
        method: "POST",
        path: "/api/kyc/token",
      });
      const enrolled = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          wallet: WALLET,
          userCommitment: "12345",
          statusToken: token.body.statusToken,
          walletProof: walletProof({
            action: "enroll",
            statusToken: token.body.statusToken,
            userCommitment: "12345",
          }),
        },
      });
      assert.strictEqual(enrolled.status, 502);
      assert.deepStrictEqual(enrolled.body, {
        error: "credential root publish failed",
      });
    },
    tempEnrollmentOptions({
      rootPublisher() {
        const error = new Error("provider internals");
        error.code = "ROOT_PUBLISH_FAILED";
        throw error;
      },
    }),
  );

  console.log("kyc backend server test OK");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
