const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  createEnrollmentStore,
  DEFAULT_DEPLOYMENTS_PATH,
  DEFAULT_STATE_PATH,
  DEFAULT_TEMPLATE_PATH,
  rootCommand,
} = require("../issuer/enrollment-store");
const { assertPublishIdentity } = require("../issuer/publish-roots");
const { DEFAULT_SIGNER_PORT } = require("./client");

const repo = path.resolve(__dirname, "..", "..");
const RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 30 };
const hits = new Map();

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function text(res, code, body, contentType = "text/plain; version=0.0.4") {
  res.writeHead(code, { "Content-Type": contentType });
  res.end(body);
}

function metricLine(name, value, labels = {}) {
  const labelText = Object.entries(labels)
    .map(
      ([key, labelValue]) =>
        `${key}="${String(labelValue).replace(/"/g, '\\"')}"`,
    )
    .join(",");
  return `${name}${labelText ? `{${labelText}}` : ""} ${Number(value)}`;
}

function isLoopback(remoteAddress) {
  return (
    remoteAddress === "127.0.0.1" ||
    remoteAddress === "::1" ||
    remoteAddress === "::ffff:127.0.0.1"
  );
}

function safeTokenEqual(left, right) {
  const leftBytes = Buffer.from(String(left), "utf8");
  const rightBytes = Buffer.from(String(right), "utf8");
  return (
    leftBytes.length === rightBytes.length &&
    crypto.timingSafeEqual(leftBytes, rightBytes)
  );
}

function authorized(req, signerToken) {
  const header = req.headers.authorization || "";
  const prefix = "Bearer ";
  return (
    header.startsWith(prefix) &&
    safeTokenEqual(header.slice(prefix.length), signerToken)
  );
}

function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < RATE.windowMs);
  if (recent.length >= RATE.maxPerIp) {
    hits.set(ip, recent);
    return true;
  }
  recent.push(now);
  hits.set(ip, recent);
  return false;
}

function readJsonBody(req, maxBytes = 4 * 1024) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > maxBytes) {
        const error = new Error("request body too large");
        error.code = "BODY_TOO_LARGE";
        reject(error);
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        const error = new Error("invalid JSON body");
        error.code = "INVALID_JSON";
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function rootPublishError(message, cause) {
  const error = new Error(message);
  error.code = "ROOT_PUBLISH_FAILED";
  if (cause) {
    error.cause = cause;
  }
  return error;
}

async function publisherBalanceStatus({
  address,
  balanceFetcher = globalThis.fetch,
  warnXlm = 50,
  errorXlm = 10,
}) {
  if (!address) {
    return { configured: false, status: "unknown", xlm: null };
  }
  if (typeof balanceFetcher !== "function") {
    return { configured: false, status: "unknown", xlm: null };
  }
  const response = await balanceFetcher(
    `https://horizon-testnet.stellar.org/accounts/${address}`,
  );
  if (!response.ok) {
    return { configured: true, status: "unavailable", xlm: null };
  }
  const account = await response.json();
  const native = (account.balances || []).find(
    (balance) => balance.asset_type === "native",
  );
  const xlm = native ? Number(native.balance) : 0;
  return {
    configured: true,
    status: xlm < errorXlm ? "error" : xlm < warnXlm ? "warn" : "ok",
    xlm,
    warn_xlm: warnXlm,
    error_xlm: errorXlm,
  };
}

function commandString(command) {
  return command.join(" ");
}

function assertSignerIdentity({ deployments, command, runner }) {
  try {
    return assertPublishIdentity({
      issuance: {
        root_publish: {
          admin: deployments.admin,
        },
      },
      commands: [commandString(command)],
      runner,
    });
  } catch (error) {
    error.statusCode = 403;
    throw error;
  }
}

function publishRoot({
  issuerId,
  approved,
  deploymentsPath,
  statePath,
  templatePath,
  source,
  runner,
}) {
  const deployments = readJson(deploymentsPath);
  const publishSource =
    source ||
    process.env.ANCHORSHIELD_STELLAR_SOURCE ||
    deployments.admin_source ||
    "anchorshield-admin";
  const store = createEnrollmentStore({
    statePath,
    deploymentsPath,
    templatePath,
  });
  if (String(issuerId) !== String(store.issuerId)) {
    const error = new Error("issuerId does not match enrollment issuer");
    error.statusCode = 400;
    throw error;
  }

  const { view } = store.loadView();
  const credentialRoot = view.roots.credential_root;
  const command = rootCommand({
    deployments,
    issuerId: store.issuerId,
    credentialRoot,
    memberCount: view.activeMemberCount,
    source: publishSource,
  });
  const identity = assertSignerIdentity({
    deployments,
    command,
    runner,
  });
  const [program, ...args] = command;
  const commandText = commandString(command);

  if (!approved) {
    return {
      mode: "dry-run",
      issuer_id: String(store.issuerId),
      credential_root: credentialRoot,
      member_count: view.activeMemberCount,
      command: commandText,
      identity,
    };
  }

  const result = runner(program, args);
  if (result.error) {
    throw rootPublishError("credential root publish failed", result.error);
  }
  if (result.status !== 0) {
    throw rootPublishError(
      `credential root publish failed with status ${result.status}`,
    );
  }
  return {
    mode: "executed",
    issuer_id: String(store.issuerId),
    credential_root: credentialRoot,
    member_count: view.activeMemberCount,
    command: commandText,
    identity,
  };
}

function createSigner({
  signerToken = process.env.SIGNER_TOKEN,
  approved = process.env.ANCHORSHIELD_ROOT_PUBLISH_APPROVED === "1",
  deploymentsPath = DEFAULT_DEPLOYMENTS_PATH,
  statePath = DEFAULT_STATE_PATH,
  templatePath = DEFAULT_TEMPLATE_PATH,
  source,
  runner,
  loopbackCheck = isLoopback,
  balanceMonitor = process.env.ANCHORSHIELD_PUBLISHER_BALANCE_MONITOR === "1",
  balanceFetcher,
  balanceWarnXlm = Number(
    process.env.ANCHORSHIELD_PUBLISHER_BALANCE_WARN_XLM || 50,
  ),
  balanceErrorXlm = Number(
    process.env.ANCHORSHIELD_PUBLISHER_BALANCE_ERROR_XLM || 10,
  ),
  logger = console,
} = {}) {
  if (!signerToken) {
    throw new Error("SIGNER_TOKEN is required");
  }
  if (typeof runner !== "function") {
    const { spawnSync } = require("child_process");
    runner = (program, args, { capture = false } = {}) =>
      spawnSync(program, args, {
        cwd: repo,
        encoding: capture ? "utf8" : undefined,
        stdio: capture ? "pipe" : "inherit",
        shell: false,
      });
  }

  return http.createServer(async (req, res) => {
    const remoteAddress = req.socket.remoteAddress || "";
    if (!loopbackCheck(remoteAddress)) {
      return json(res, 403, { error: "loopback access required" });
    }
    if (!authorized(req, signerToken)) {
      return json(res, 401, { error: "unauthorized" });
    }
    if (rateLimited(remoteAddress)) {
      return json(res, 429, { error: "rate limit exceeded" });
    }

    const url = new URL(req.url, "http://127.0.0.1");
    try {
      if (req.method === "GET" && url.pathname === "/healthz") {
        const deployments = readJson(deploymentsPath);
        const publisher_balance = balanceMonitor
          ? await publisherBalanceStatus({
              address: deployments.admin,
              balanceFetcher,
              warnXlm: balanceWarnXlm,
              errorXlm: balanceErrorXlm,
            })
          : { configured: false, status: "disabled", xlm: null };
        return json(res, 200, {
          ok: true,
          approved,
          admin: deployments.admin,
          publisher_balance,
        });
      }
      if (req.method === "GET" && url.pathname === "/metrics") {
        const deployments = readJson(deploymentsPath);
        const publisherBalance = balanceMonitor
          ? await publisherBalanceStatus({
              address: deployments.admin,
              balanceFetcher,
              warnXlm: balanceWarnXlm,
              errorXlm: balanceErrorXlm,
            })
          : { configured: false, status: "disabled", xlm: null };
        const balanceLabels = { account: deployments.admin };
        return text(
          res,
          200,
          [
            metricLine("anchorshield_signer_approved", approved ? 1 : 0),
            metricLine(
              "anchorshield_signer_publisher_balance_configured",
              publisherBalance.configured ? 1 : 0,
              balanceLabels,
            ),
            metricLine(
              "anchorshield_signer_publisher_balance_xlm",
              publisherBalance.xlm ?? 0,
              balanceLabels,
            ),
            metricLine(
              "anchorshield_signer_publisher_balance_low",
              publisherBalance.status === "warn" ||
                publisherBalance.status === "error"
                ? 1
                : 0,
              balanceLabels,
            ),
          ].join("\n") + "\n",
        );
      }
      if (
        req.method === "POST" &&
        url.pathname === "/publish-credential-root"
      ) {
        let body;
        try {
          body = await readJsonBody(req);
        } catch (error) {
          return json(res, error.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              error.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        const result = publishRoot({
          issuerId: body.issuerId,
          approved,
          deploymentsPath,
          statePath,
          templatePath,
          source,
          runner,
        });
        logger.log(
          JSON.stringify({
            level: "info",
            context: "publishCredentialRoot",
            mode: result.mode,
            issuer_id: result.issuer_id,
            credential_root: result.credential_root,
          }),
        );
        return json(res, 200, result);
      }
      return json(res, 404, { error: "not found" });
    } catch (error) {
      if (error.statusCode) {
        return json(res, error.statusCode, { error: error.message });
      }
      if (error.code === "ROOT_PUBLISH_FAILED") {
        return json(res, 502, { error: error.message });
      }
      return json(res, 500, { error: "signer error" });
    }
  });
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const keep = arr.filter((t) => now - t < RATE.windowMs);
    if (keep.length) hits.set(ip, keep);
    else hits.delete(ip);
  }
}, RATE.windowMs).unref();

if (require.main === module) {
  const port = Number(process.env.SIGNER_PORT || DEFAULT_SIGNER_PORT);
  createSigner().listen(port, "127.0.0.1", () => {
    console.log(`signer listening on 127.0.0.1:${port}`);
  });
}

module.exports = {
  createSigner,
  isLoopback,
  publisherBalanceStatus,
  publishRoot,
};
