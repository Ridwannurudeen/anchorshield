const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { Keypair } = require("@stellar/stellar-sdk");
const { credentialFromTemplate } = require("../issuer/enrollment-store");
const { credentialHash, decimal } = require("../issuer/lib/zk-tree");
const {
  loadVoucherKeyFromPem,
  messageRepresentative,
  toBytesBE,
} = require("./blind-voucher");
const {
  assertPublicMetadataUrl,
  fetchIssuerMetadata,
  isPrivateIp,
} = require("./issuer-directory");
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
          const contentType = res.headers["content-type"] || "";
          resolve({
            status: res.statusCode,
            body:
              body && contentType.includes("application/json")
                ? JSON.parse(body)
                : body || null,
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

let voucherKey;
function testVoucherKey() {
  if (!voucherKey) {
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });
    voucherKey = loadVoucherKeyFromPem(
      privateKey.export({ type: "pkcs8", format: "pem" }),
    );
  }
  return voucherKey;
}

function modpow(base, exponent, modulus) {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = egcd(b, a % b);
  return [g, y, x - (a / b) * y];
}

function modinv(value, modulus) {
  const [g, x] = egcd(((value % modulus) + modulus) % modulus, modulus);
  if (g !== 1n) throw new Error("blinding factor is not invertible");
  return ((x % modulus) + modulus) % modulus;
}

function blindCredentialLeaf(credentialLeaf, key) {
  const message = messageRepresentative(credentialLeaf);
  let r = 2n;
  while (egcd(r, key.N)[0] !== 1n) r += 1n;
  return {
    blinded: toBytesBE((message * modpow(r, key.e, key.N)) % key.N),
    r,
  };
}

function unblind(blindSignature, r, key) {
  return toBytesBE((BigInt(blindSignature) * modinv(r, key.N)) % key.N);
}

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

function webhookSignature(body, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(JSON.stringify(body))
    .digest("hex");
}

function tempEnrollmentOptions(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-enroll-"));
  return {
    enrollment: {
      statePath: path.join(dir, "enrollments.json"),
      rootPublisher({ credentialRoot, memberCount }) {
        return { mode: "test", credentialRoot, memberCount };
      },
      now: () => "2026-06-30T00:00:00.000Z",
      ...overrides,
    },
  };
}

async function main() {
  assert.strictEqual(isPrivateIp("127.0.0.1"), true);
  assert.strictEqual(isPrivateIp("10.0.0.1"), true);
  assert.strictEqual(isPrivateIp("198.51.100.7"), false);
  await assert.rejects(
    () => assertPublicMetadataUrl("http://127.0.0.1/metadata.json"),
    /private IP/,
  );
  await assert.rejects(
    () =>
      assertPublicMetadataUrl(
        "https://issuer.internal/metadata.json",
        async () => [{ address: "10.0.0.7", family: 4 }],
      ),
    /private IP/,
  );
  const issuerMetadata = await fetchIssuerMetadata(
    "https://issuer.example/metadata.json",
    {
      lookup: async () => [{ address: "198.51.100.7", family: 4 }],
      fetchImpl: async (href, init) => {
        assert.strictEqual(href, "https://issuer.example/metadata.json");
        assert.strictEqual(init.redirect, "manual");
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              name: "AnchorShield Issuer",
              website: "https://issuer.example",
              proof_policy: "https://issuer.example/policy",
              ignored_private_field: "do not surface",
            });
          },
        };
      },
    },
  );
  assert.deepStrictEqual(issuerMetadata, {
    name: "AnchorShield Issuer",
    website: "https://issuer.example",
    proof_policy: "https://issuer.example/policy",
  });
  await assert.rejects(
    () =>
      fetchIssuerMetadata("https://issuer.example/metadata.json", {
        lookup: async () => [{ address: "198.51.100.7", family: 4 }],
        fetchImpl: async () => ({ ok: false, status: 302, async text() {} }),
      }),
    /redirects/,
  );

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

    const health = await request(server, {
      method: "GET",
      path: "/api/kyc/healthz",
    });
    assert.strictEqual(health.status, 200);
    assert.strictEqual(health.body.issuer_id, "101");
    assert.strictEqual(health.body.active_member_count, 1);
    assert.strictEqual(health.body.status_tokens >= 1, true);

    const metrics = await request(server, {
      method: "GET",
      path: "/api/kyc/metrics",
    });
    assert.strictEqual(metrics.status, 200);
    assert.match(metrics.body, /anchorshield_kyc_status_tokens/);
    assert.match(
      metrics.body,
      /anchorshield_issuer_active_members\{issuer_id="101"\} 1/,
    );
  });

  await withServer(
    provider,
    async (server) => {
      const event = {
        type: "applicantReviewed",
        externalUserId: "as-web-11111111-1111-4111-8111-111111111111",
        reviewStatus: "completed",
        reviewResult: { reviewAnswer: "GREEN" },
      };
      const headers = {
        "x-payload-digest": webhookSignature(event, "webhook-secret"),
        "x-payload-digest-alg": "HMAC_SHA256_HEX",
      };
      const accepted = await request(server, {
        method: "POST",
        path: "/api/kyc/webhook",
        headers,
        body: event,
      });
      assert.strictEqual(accepted.status, 200);
      assert.deepStrictEqual(accepted.body, { ok: true, duplicate: false });

      const duplicate = await request(server, {
        method: "POST",
        path: "/api/kyc/webhook",
        headers,
        body: event,
      });
      assert.strictEqual(duplicate.status, 200);
      assert.deepStrictEqual(duplicate.body, { ok: true, duplicate: true });

      const forged = await request(server, {
        method: "POST",
        path: "/api/kyc/webhook",
        headers: {
          "x-payload-digest": "00".repeat(32),
          "x-payload-digest-alg": "HMAC_SHA256_HEX",
        },
        body: {
          ...event,
          externalUserId: "as-web-22222222-2222-4222-8222-222222222222",
        },
      });
      assert.strictEqual(forged.status, 401);
    },
    { sumsubWebhookSecret: "webhook-secret" },
  );

  await withServer(
    provider,
    async (server) => {
      const directory = await request(server, {
        method: "GET",
        path: "/api/issuers",
      });
      assert.strictEqual(directory.status, 200);
      assert.deepStrictEqual(directory.body.issuers, [
        {
          issuer_id: "101",
          metadata_uri: "https://issuer.example/metadata.json",
          metadata: {
            name: "AnchorShield Issuer",
            jurisdiction: "NG",
          },
        },
      ]);

      const rejected = await request(server, {
        method: "GET",
        path: "/api/issuers/metadata?uri=http%3A%2F%2F127.0.0.1%2Fmetadata.json",
      });
      assert.strictEqual(rejected.status, 400);
      assert.deepStrictEqual(rejected.body, {
        error: "metadata fetch rejected",
      });
    },
    {
      issuerDirectory: [
        {
          issuer_id: "101",
          metadata_uri: "https://issuer.example/metadata.json",
        },
      ],
      lookup: async () => [{ address: "198.51.100.7", family: 4 }],
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            name: "AnchorShield Issuer",
            jurisdiction: "NG",
            secret: "not surfaced",
          });
        },
      }),
    },
  );

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
    provider,
    async (server) => {
      const key = testVoucherKey();
      const pubkey = await request(server, {
        method: "GET",
        path: "/api/kyc/voucher/pubkey",
      });
      assert.strictEqual(pubkey.status, 200);
      assert.strictEqual(pubkey.body.configured, true);
      assert.ok(pubkey.body.publicKey.n.startsWith("0x"));

      const session = await request(server, {
        method: "POST",
        path: "/api/kyc/voucher/session",
      });
      assert.strictEqual(session.status, 200);
      assert.match(session.body.userId, /^as-web-[a-f0-9-]{36}$/);

      const userCommitment = "24680";
      const expectedTemplate = {
        schema: "anchorshield.credential_template.v1",
        issuer_id: "101",
        kyc_passed: "1",
        country: "566",
        age: "22",
        investor_type: "1",
        tx_limit: "1000",
        issued_at: "1",
        expires_at: "99",
      };
      const credentialLeaf = decimal(
        credentialHash(
          credentialFromTemplate({
            userCommitment,
            issuerId: 101,
            template: expectedTemplate,
          }),
        ),
      );
      const blinded = blindCredentialLeaf(credentialLeaf, key);
      const voucher = await request(server, {
        method: "POST",
        path: "/api/kyc/voucher",
        body: {
          statusToken: session.body.statusToken,
          blinded: blinded.blinded,
        },
      });
      assert.strictEqual(voucher.status, 200);
      assert.deepStrictEqual(voucher.body.credentialTemplate, expectedTemplate);
      const signature = unblind(voucher.body.blindSignature, blinded.r, key);
      assert.strictEqual(
        modpow(BigInt(signature), key.e, key.N),
        messageRepresentative(credentialLeaf),
      );

      const replayVoucher = await request(server, {
        method: "POST",
        path: "/api/kyc/voucher",
        body: {
          statusToken: session.body.statusToken,
          blinded: blinded.blinded,
        },
      });
      assert.strictEqual(replayVoucher.status, 409);

      const credentialVoucher = {
        signature,
        credentialTemplate: voucher.body.credentialTemplate,
        credentialTemplateMac: voucher.body.credentialTemplateMac,
      };
      const enrolled = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          userCommitment,
          voucher: credentialVoucher,
        },
      });
      assert.strictEqual(enrolled.status, 200);
      assert.strictEqual(enrolled.body.credential.wallet, null);
      assert.strictEqual(
        enrolled.body.credential.user_commitment,
        userCommitment,
      );

      const fetched = await request(server, {
        method: "POST",
        path: "/api/credential",
        body: {
          userCommitment,
          voucher: credentialVoucher,
        },
      });
      assert.strictEqual(fetched.status, 200);
      assert.strictEqual(
        fetched.body.credential.credential_root,
        enrolled.body.credential.credential_root,
      );

      const replayEnroll = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          userCommitment,
          voucher: credentialVoucher,
        },
      });
      assert.strictEqual(replayEnroll.status, 409);

      const tampered = await request(server, {
        method: "POST",
        path: "/api/enroll",
        body: {
          userCommitment: "13579",
          voucher: {
            ...credentialVoucher,
            credentialTemplate: {
              ...credentialVoucher.credentialTemplate,
              country: "840",
            },
          },
        },
      });
      assert.strictEqual(tampered.status, 401);
    },
    {
      ...tempEnrollmentOptions(),
      voucherKey: testVoucherKey(),
      voucherTemplateSecret: "test-template-key",
    },
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
