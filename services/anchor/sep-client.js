const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function urlWithParams(base, params) {
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function endpoint(base, route) {
  const trimmedBase = String(base).replace(/\/+$/, "");
  const trimmedRoute = route.replace(/^\/+/, "");
  return new URL(`${trimmedBase}/${trimmedRoute}`);
}

const REQUIRED_CONFIG_FIELDS = [
  "homeDomain",
  "webAuthEndpoint",
  "transferServerSep31",
  "anchorQuoteServer",
  "token",
  "sellAsset",
  "buyAsset",
  "receiveAssetCode",
  "senderId",
  "receiverId",
  "quoteExpiresAt",
  "packetHash",
  "actionBinding",
];

function validateHttpsUrl(config, key) {
  const url = new URL(config[key]);
  if (url.protocol !== "https:") {
    throw new Error(`${key} must be an https URL`);
  }
}

function validateAnchorConfig(config) {
  for (const field of REQUIRED_CONFIG_FIELDS) {
    if (!config[field] || typeof config[field] !== "string") {
      throw new Error(`anchor config missing ${field}`);
    }
  }
  validateHttpsUrl(config, "webAuthEndpoint");
  validateHttpsUrl(config, "transferServerSep31");
  validateHttpsUrl(config, "anchorQuoteServer");
  const placeholders = new Map([
    ["homeDomain", "anchor.example"],
    ["webAuthEndpoint", "https://anchor.example/auth"],
    ["transferServerSep31", "https://anchor.example/sep31"],
    ["anchorQuoteServer", "https://anchor.example/sep38"],
    ["token", "SEP10_JWT_FROM_ANCHOR_SANDBOX"],
    ["senderId", "sender-customer-id-from-anchor-sandbox"],
    ["receiverId", "receiver-customer-id-from-anchor-sandbox"],
    ["packetHash", "public-signal-1-from-generated-proof"],
    ["actionBinding", "public-signal-3-from-generated-proof"],
  ]);
  for (const [field, placeholder] of placeholders) {
    if (config[field] === placeholder) {
      throw new Error(
        `anchor config field ${field} still contains placeholder data`,
      );
    }
  }
  Date.parse(config.quoteExpiresAt);
  if (Number.isNaN(Date.parse(config.quoteExpiresAt))) {
    throw new Error("quoteExpiresAt must be an ISO timestamp");
  }
  return config;
}

async function requestJson(url, { method = "GET", token, body } = {}) {
  const headers = {
    Accept: "application/json",
  };
  const options = { method, headers };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (body) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const message = data.error || data.message || response.statusText;
    throw new Error(
      `${method} ${url} failed: HTTP ${response.status} ${message}`,
    );
  }
  return data;
}

async function sep10Challenge({
  webAuthEndpoint,
  account,
  homeDomain,
  clientDomain,
  memo,
}) {
  return requestJson(
    urlWithParams(webAuthEndpoint, {
      account,
      home_domain: homeDomain,
      client_domain: clientDomain,
      memo,
    }),
  );
}

async function sep10Token({ webAuthEndpoint, transaction }) {
  return requestJson(webAuthEndpoint, {
    method: "POST",
    body: { transaction },
  });
}

async function sep31Info({ transferServerSep31, token }) {
  return requestJson(endpoint(transferServerSep31, "info"), { token });
}

async function sep31PostTransaction({
  transferServerSep31,
  token,
  transaction,
}) {
  return requestJson(endpoint(transferServerSep31, "transactions"), {
    method: "POST",
    token,
    body: transaction,
  });
}

async function sep31GetTransaction({
  transferServerSep31,
  token,
  id,
  stellarTransactionId,
}) {
  return requestJson(
    urlWithParams(endpoint(transferServerSep31, "transactions"), {
      id,
      stellar_transaction_id: stellarTransactionId,
    }),
    { token },
  );
}

async function sep38Info({ anchorQuoteServer, token }) {
  return requestJson(endpoint(anchorQuoteServer, "info"), { token });
}

async function sep38Price({ anchorQuoteServer, token, price }) {
  return requestJson(
    urlWithParams(endpoint(anchorQuoteServer, "price"), price),
    {
      token,
    },
  );
}

async function sep38PostQuote({ anchorQuoteServer, token, quote }) {
  return requestJson(endpoint(anchorQuoteServer, "quote"), {
    method: "POST",
    token,
    body: quote,
  });
}

function buildSep31Transaction({ config, quote, payment }) {
  return {
    kind: "receive",
    asset_code: config.receiveAssetCode,
    amount: String(payment.amount),
    sender_id: config.senderId,
    receiver_id: config.receiverId,
    fields: {
      transaction: {
        quote_id: quote.id,
        anchorshield_policy_id: String(payment.policy_id),
        anchorshield_packet_hash: payment.packet_hash,
        anchorshield_action_binding: payment.action_binding,
      },
    },
  };
}

async function runSandboxFlow({
  configPath = path.join(__dirname, "anchor.config.json"),
  paymentPath = path.join(repo, "services", "issuer", "out", "issuance.json"),
} = {}) {
  const config = validateAnchorConfig(readJson(configPath));
  const issuance = readJson(paymentPath);
  const clean = issuance.users.find(
    (user) => !user.blocked && user.proof_input,
  );
  if (!clean) {
    throw new Error("no clean issuer user with proof input found");
  }

  const payment = {
    policy_id: clean.proof_input.policy_id,
    amount: clean.proof_input.amount,
    packet_hash: config.packetHash,
    action_binding: config.actionBinding,
  };
  const price = await sep38Price({
    anchorQuoteServer: config.anchorQuoteServer,
    token: config.token,
    price: {
      sell_asset: config.sellAsset,
      buy_asset: config.buyAsset,
      sell_amount: payment.amount,
    },
  });
  const quote = await sep38PostQuote({
    anchorQuoteServer: config.anchorQuoteServer,
    token: config.token,
    quote: {
      sell_asset: config.sellAsset,
      buy_asset: config.buyAsset,
      sell_amount: payment.amount,
      expire_after: config.quoteExpiresAt,
    },
  });
  const transaction = await sep31PostTransaction({
    transferServerSep31: config.transferServerSep31,
    token: config.token,
    transaction: buildSep31Transaction({
      config,
      quote,
      payment,
    }),
  });

  return {
    schema: "anchorshield.anchor_sandbox_run.v1",
    mode: "real-anchor-sandbox",
    homeDomain: config.homeDomain,
    price,
    quote,
    transaction,
  };
}

async function main() {
  const result = await runSandboxFlow();
  const outPath = path.join(
    repo,
    "services",
    "anchor",
    "out",
    "sandbox-run.json",
  );
  writeJson(outPath, result);
  console.log(
    JSON.stringify({ wrote: path.relative(repo, outPath), result }, null, 2),
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  urlWithParams,
  endpoint,
  requestJson,
  validateAnchorConfig,
  sep10Challenge,
  sep10Token,
  sep31Info,
  sep31PostTransaction,
  sep31GetTransaction,
  sep38Info,
  sep38Price,
  sep38PostQuote,
  buildSep31Transaction,
  runSandboxFlow,
};
