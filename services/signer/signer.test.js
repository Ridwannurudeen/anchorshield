const assert = require("assert");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const {
  createEnrollmentStore,
  rootCommand,
} = require("../issuer/enrollment-store");
const { createSigner } = require("./signer");
const { publishCredentialRootViaSigner } = require("./client");

const TOKEN = "test-signer-token";
const ADMIN = "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U";
const WALLET = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function request(
  server,
  { method = "GET", path = "/", token = TOKEN, body = null } = {},
) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {};
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        method,
        path,
        headers,
      },
      (res) => {
        let raw = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          raw += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: raw ? JSON.parse(raw) : null,
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

async function withServer(server, fn) {
  await listen(server);
  try {
    await fn(server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function fixture({ approved = false, runner, loopbackCheck } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-signer-"));
  const statePath = path.join(dir, "enrollments.json");
  const deploymentsPath = path.join(dir, "deployments.json");
  const deployments = {
    network: "testnet",
    admin: ADMIN,
    contracts: {
      issuer_registry: "CDR74XLWGRE35SOQ2FHMRXEXLUQWDOUSLLM2ECAW4IIBLRWFGLBBSDDG",
    },
  };
  writeJson(deploymentsPath, deployments);

  const store = createEnrollmentStore({
    statePath,
    deploymentsPath,
    rootPublisher({ credentialRoot }) {
      return { mode: "test", credentialRoot };
    },
    now: () => "2026-06-30T00:00:00.000Z",
  });
  const enrolled = store.enroll({
    wallet: WALLET,
    userCommitment: "12345",
    kycCredential: {
      kyc_passed: 1,
      country: 566,
      age: 22,
      external_user_id: "as-web-00000000-0000-4000-8000-000000000000",
    },
  });

  const calls = [];
  const defaultRunner = (program, args, options = {}) => {
    calls.push({ program, args, options });
    if (
      program === "stellar" &&
      args[0] === "keys" &&
      args[1] === "address"
    ) {
      return { status: 0, stdout: `${ADMIN}\n`, stderr: "" };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  const server = createSigner({
    signerToken: TOKEN,
    approved,
    statePath,
    deploymentsPath,
    runner: runner || defaultRunner,
    loopbackCheck,
    logger: { log() {} },
  });

  return {
    calls,
    deployments,
    enrolled,
    server,
    store,
  };
}

async function main() {
  let posted;
  await assert.rejects(
    publishCredentialRootViaSigner({
      issuerId: "101",
      credentialRoot: "999999",
      signerToken: TOKEN,
      fetchImpl: async (url, init) => {
        assert.strictEqual(
          url,
          "http://127.0.0.1:3099/publish-credential-root",
        );
        assert.strictEqual(init.headers.Authorization, `Bearer ${TOKEN}`);
        posted = JSON.parse(init.body);
        return {
          ok: false,
          status: 502,
          async json() {
            return { error: "signer unavailable" };
          },
        };
      },
    }),
    (error) => {
      assert.strictEqual(error.code, "ROOT_PUBLISH_FAILED");
      assert.strictEqual(error.message, "signer unavailable");
      return true;
    },
  );
  assert.deepStrictEqual(posted, { issuerId: "101" });

  {
    const { server, enrolled, store } = fixture();
    await withServer(server, async (live) => {
      const response = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        body: {
          issuerId: store.issuerId,
          credentialRoot: "999999",
        },
      });
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.mode, "dry-run");
      assert.strictEqual(
        response.body.credential_root,
        enrolled.credential.credential_root,
      );
    });
  }

  {
    const { server, store } = fixture();
    await withServer(server, async (live) => {
      const missing = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        token: null,
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(missing.status, 401);
    });
  }

  {
    const { server, store } = fixture({ loopbackCheck: () => false });
    await withServer(server, async (live) => {
      const denied = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        token: TOKEN,
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(denied.status, 403);
    });
  }

  {
    const calls = [];
    const runner = (program, args, options = {}) => {
      calls.push({ program, args, options });
      return { status: 0, stdout: "GDIFFERENTADMINADDRESS\n", stderr: "" };
    };
    const { server, store } = fixture({ runner });
    await withServer(server, async (live) => {
      const response = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(response.status, 403);
      assert.match(response.body.error, /expected deployed admin/);
    });
  }

  {
    const { server, calls, store } = fixture();
    await withServer(server, async (live) => {
      const response = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.mode, "dry-run");
      assert.strictEqual(
        calls.filter((call) => call.args.includes("set_root")).length,
        0,
      );
    });
  }

  {
    const { server, calls, deployments, enrolled, store } = fixture({
      approved: true,
    });
    await withServer(server, async (live) => {
      const response = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.mode, "executed");
      const invoke = calls.find((call) => call.args[0] === "contract");
      assert.deepStrictEqual(
        [invoke.program, ...invoke.args],
        rootCommand({
          deployments,
          issuerId: store.issuerId,
          credentialRoot: enrolled.credential.credential_root,
          source: "anchorshield-admin",
        }),
      );
    });
  }

  {
    const runner = (program, args) => {
      if (
        program === "stellar" &&
        args[0] === "keys" &&
        args[1] === "address"
      ) {
        return { status: 0, stdout: `${ADMIN}\n`, stderr: "" };
      }
      return { status: 1, stdout: "", stderr: "invoke failed" };
    };
    const { server, store } = fixture({ approved: true, runner });
    await withServer(server, async (live) => {
      const response = await request(live, {
        method: "POST",
        path: "/publish-credential-root",
        body: { issuerId: store.issuerId },
      });
      assert.strictEqual(response.status, 502);
      assert.match(response.body.error, /status 1/);
    });
  }

  console.log("signer service test OK");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
