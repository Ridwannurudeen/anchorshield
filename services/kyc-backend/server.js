// Minimal KYC backend for the live in-browser Sumsub WebSDK flow.
//
// The WebSDK needs a short-lived access token minted server-side (the Sumsub secret must never
// reach the browser). This service mints those tokens and reports applicant status. It is
// dependency-free (node http only) and reuses the issuer KYC adapter for the signed Sumsub calls.
//
// Config via env (never commit secrets): SUMSUB_APP_TOKEN, SUMSUB_SECRET_KEY, SUMSUB_LEVEL_NAME,
// optional KYC_PORT (default 3088). Binds to 127.0.0.1; expose via an nginx /api/kyc/ proxy.
const http = require("http");
const crypto = require("crypto");
const net = require("net");
const { Keypair } = require("@stellar/stellar-sdk");
const { createKycProvider } = require("../issuer/lib/kyc");
const {
  createEnrollmentStore,
  credentialFromTemplate,
  normalizeWallet,
} = require("../issuer/enrollment-store");
const { credentialHash, decimal } = require("../issuer/lib/zk-tree");
const {
  blindSign,
  getVoucherKey,
  publicKeyHex,
  verifySignature,
} = require("./blind-voucher");
const { fetchIssuerMetadata } = require("./issuer-directory");

const PORT = Number(process.env.KYC_PORT || 3088);
const provider = createKycProvider();
const USER_ID_RE = /^as-web-[a-f0-9-]{36}$/;
const WALLET_PROOF_MAX_AGE_MS = 10 * 60 * 1000;
const STELLAR_SIGNED_MESSAGE_PREFIX = "Stellar Signed Message:\n";

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

// Per-IP rate limit on token minting (protects the Sumsub sandbox quota from abuse). In-memory is
// fine for this single-process service. The app only trusts X-Real-IP from a loopback nginx proxy.
const RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 10 };
const ENROLL_RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 20 };
const STATUS_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const tokenHits = new Map();
const enrollHits = new Map();
const credentialHits = new Map();
const statusTokens = new Map();
const spentVoucherStatusTokens = new Map();
const spentVoucherDigests = new Map();
const spentWalletProofDigests = new Map();
const webhookDigests = new Map();
const webhookStatuses = new Map();

function isLoopback(remoteAddress) {
  return (
    remoteAddress === "127.0.0.1" ||
    remoteAddress === "::1" ||
    remoteAddress === "::ffff:127.0.0.1"
  );
}

function clientIp(req) {
  const remote = req.socket.remoteAddress || "unknown";
  const realIp = req.headers["x-real-ip"];
  if (isLoopback(remote) && typeof realIp === "string" && net.isIP(realIp)) {
    return realIp;
  }
  return remote;
}

function rateLimited(hits, policy, ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < policy.windowMs);
  if (recent.length >= policy.maxPerIp) {
    hits.set(ip, recent);
    return true;
  }
  recent.push(now);
  hits.set(ip, recent);
  return false;
}

function tokenRateLimited(ip) {
  return rateLimited(tokenHits, RATE, ip);
}

function enrollRateLimited(ip) {
  return rateLimited(enrollHits, ENROLL_RATE, ip);
}

function credentialRateLimited(ip) {
  return rateLimited(credentialHits, ENROLL_RATE, ip);
}

function createStatusToken(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  statusTokens.set(token, {
    userId,
    expiresAt: Date.now() + STATUS_TOKEN_TTL_MS,
  });
  return token;
}

function userIdForStatusToken(token) {
  const entry = statusTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) {
    if (entry) statusTokens.delete(token);
    return null;
  }
  return entry.userId;
}

function burnExpiring(map, key, ttlMs) {
  const text = String(key || "");
  if (!text) return false;
  const expiresAt = map.get(text);
  if (expiresAt && expiresAt > Date.now()) {
    return false;
  }
  map.set(text, Date.now() + ttlMs);
  return true;
}

function statusTokenMatchesUser(token, userId) {
  return userIdForStatusToken(token) === userId;
}

function sha256Hex(value) {
  return crypto
    .createHash("sha256")
    .update(String(value), "utf8")
    .digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function safeEqualHex(left, right) {
  if (
    typeof left !== "string" ||
    typeof right !== "string" ||
    left.length !== right.length ||
    !/^[0-9a-f]+$/i.test(left) ||
    !/^[0-9a-f]+$/i.test(right)
  ) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(left, "hex"),
    Buffer.from(right, "hex"),
  );
}

function verifyWebhookSignature(rawBody, signature, algo, secret) {
  if (!secret || !signature) return false;
  const normalizedAlgo = String(algo || "HMAC_SHA256_HEX").toUpperCase();
  const hashAlgo =
    normalizedAlgo === "HMAC_SHA1_HEX"
      ? "sha1"
      : normalizedAlgo === "HMAC_SHA512_HEX"
        ? "sha512"
        : "sha256";
  const expected = crypto
    .createHmac(hashAlgo, secret)
    .update(rawBody)
    .digest("hex");
  return safeEqualHex(expected, String(signature).toLowerCase());
}

function credentialTemplate({ issuerId, credential }) {
  return {
    schema: "anchorshield.credential_template.v1",
    issuer_id: String(issuerId),
    kyc_passed: String(credential.kyc_passed),
    country: String(credential.country),
    age: String(credential.age),
    investor_type: "1",
    tx_limit: "1000",
    issued_at: "1",
    expires_at: "99",
  };
}

function templateMac(template, secret) {
  return crypto
    .createHmac("sha256", Buffer.from(String(secret), "utf8"))
    .update(canonicalJson(template), "utf8")
    .digest("hex");
}

function verifyTemplateMac(template, mac, secret) {
  return safeEqualHex(templateMac(template, secret), String(mac || ""));
}

function credentialLeafFromTemplate({ issuerId, userCommitment, template }) {
  return decimal(
    credentialHash(
      credentialFromTemplate({
        userCommitment,
        issuerId,
        template,
      }),
    ),
  );
}

function voucherDigest(voucher) {
  return sha256Hex(canonicalJson(voucher));
}

function publicCredential(credential) {
  if (!credential) return null;
  return {
    kyc_passed: credential.kyc_passed,
    country: credential.country,
    age: credential.age,
  };
}

function readJsonBody(req, maxBytes = 16 * 1024) {
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

function walletProofMessage({
  wallet,
  action,
  statusToken,
  userCommitment = "",
  issuedAt,
}) {
  const lines = [
    "AnchorShield wallet authorization v1",
    "network:stellar-testnet",
    `action:${action}`,
    `wallet:${wallet}`,
    `status-token-sha256:${sha256Hex(statusToken)}`,
  ];
  if (action === "enroll" || action === "resume") {
    lines.push(`user-commitment:${String(userCommitment)}`);
  }
  lines.push(`issued-at:${issuedAt}`);
  return lines.join("\n");
}

function stellarMessageHash(message) {
  return crypto
    .createHash("sha256")
    .update(STELLAR_SIGNED_MESSAGE_PREFIX, "utf8")
    .update(String(message), "utf8")
    .digest();
}

function signatureBytes(value) {
  if (typeof value !== "string") {
    throw new Error("wallet proof signature must be a string");
  }
  if (/^[0-9a-fA-F]{128}$/.test(value)) {
    return Buffer.from(value, "hex");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = Buffer.from(normalized, "base64");
  if (decoded.length !== 64) {
    throw new Error("wallet proof signature must be 64 bytes");
  }
  return decoded;
}

function verifyWalletProof({
  wallet,
  action,
  statusToken,
  userCommitment,
  proof,
}) {
  if (!proof || typeof proof !== "object") {
    const error = new Error("wallet proof required");
    error.statusCode = 401;
    throw error;
  }
  if (proof.signerAddress && proof.signerAddress !== wallet) {
    const error = new Error("wallet proof signer mismatch");
    error.statusCode = 401;
    throw error;
  }
  const issuedAt = String(proof.issuedAt || "");
  const issuedAtMs = Date.parse(issuedAt);
  if (
    !Number.isFinite(issuedAtMs) ||
    Math.abs(Date.now() - issuedAtMs) > WALLET_PROOF_MAX_AGE_MS
  ) {
    const error = new Error("wallet proof expired");
    error.statusCode = 401;
    throw error;
  }
  const expectedMessage = walletProofMessage({
    wallet,
    action,
    statusToken,
    userCommitment,
    issuedAt,
  });
  if (proof.message !== expectedMessage) {
    const error = new Error("wallet proof message mismatch");
    error.statusCode = 401;
    throw error;
  }
  let verified = false;
  try {
    verified = Keypair.fromPublicKey(wallet).verify(
      stellarMessageHash(expectedMessage),
      signatureBytes(proof.signature),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    const error = new Error("wallet proof signature invalid");
    error.statusCode = 401;
    throw error;
  }
  const digest = sha256Hex(
    JSON.stringify({
      action,
      wallet,
      signature: proof.signature,
      issuedAt,
    }),
  );
  if (!burnExpiring(spentWalletProofDigests, digest, WALLET_PROOF_MAX_AGE_MS)) {
    const error = new Error("wallet proof already used");
    error.statusCode = 401;
    throw error;
  }
}

function readRawBody(req, maxBytes = 256 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        const error = new Error("request body too large");
        error.code = "BODY_TOO_LARGE";
        reject(error);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function verifiedCredentialForStatusToken(kycProvider, statusToken) {
  if (!statusToken) {
    const error = new Error("status token required");
    error.statusCode = 401;
    throw error;
  }
  const userId = userIdForStatusToken(statusToken);
  if (!userId) {
    const error = new Error("invalid status token");
    error.statusCode = 401;
    throw error;
  }
  const credential = await kycProvider.verifiedCredential(userId);
  if (!credential) {
    const error = new Error("kyc is not approved");
    error.statusCode = 409;
    throw error;
  }
  return {
    userId,
    credential: {
      ...publicCredential(credential),
      external_user_id: userId,
    },
  };
}

function logProviderError(context, error) {
  console.error(
    JSON.stringify({
      level: "error",
      context,
      message: error.provider
        ? "kyc provider request failed"
        : "kyc backend error",
      provider: error.provider,
      status: error.status,
      method: error.method,
      uri: error.uri,
    }),
  );
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of tokenHits) {
    const keep = arr.filter((t) => now - t < RATE.windowMs);
    if (keep.length) tokenHits.set(ip, keep);
    else tokenHits.delete(ip);
  }
  for (const [ip, arr] of enrollHits) {
    const keep = arr.filter((t) => now - t < ENROLL_RATE.windowMs);
    if (keep.length) enrollHits.set(ip, keep);
    else enrollHits.delete(ip);
  }
  for (const [ip, arr] of credentialHits) {
    const keep = arr.filter((t) => now - t < ENROLL_RATE.windowMs);
    if (keep.length) credentialHits.set(ip, keep);
    else credentialHits.delete(ip);
  }
  for (const [token, entry] of statusTokens) {
    if (entry.expiresAt < now) statusTokens.delete(token);
  }
  for (const [token, expiresAt] of spentVoucherStatusTokens) {
    if (expiresAt < now) spentVoucherStatusTokens.delete(token);
  }
  for (const [digest, expiresAt] of spentVoucherDigests) {
    if (expiresAt < now) spentVoucherDigests.delete(digest);
  }
  for (const [digest, expiresAt] of spentWalletProofDigests) {
    if (expiresAt < now) spentWalletProofDigests.delete(digest);
  }
  for (const [digest, expiresAt] of webhookDigests) {
    if (expiresAt < now) webhookDigests.delete(digest);
  }
}, RATE.windowMs).unref();

function createServer(kycProvider = provider, options = {}) {
  const enrollmentStore =
    options.enrollmentStore || createEnrollmentStore(options.enrollment || {});
  let voucherKey = options.voucherKey || null;
  if (
    !voucherKey &&
    (process.env.VOUCHER_RSA_PRIVATE_KEY ||
      process.env.VOUCHER_RSA_PRIVATE_KEY_FILE)
  ) {
    voucherKey = getVoucherKey();
  }
  const voucherTemplateSecret =
    options.voucherTemplateSecret ||
    process.env.VOUCHER_TEMPLATE_HMAC_KEY ||
    voucherKey?.privateKeySha256 ||
    "";
  const sumsubWebhookSecret =
    options.sumsubWebhookSecret || process.env.SUMSUB_WEBHOOK_SECRET || "";
  const issuerDirectory = options.issuerDirectory || [
    {
      issuer_id: String(enrollmentStore.issuerId),
      metadata_uri: process.env.ANCHORSHIELD_ISSUER_METADATA_URI || null,
    },
  ];
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/api/kyc/healthz") {
        const view = enrollmentStore.loadView().view;
        return json(res, 200, {
          ok: true,
          configured: Boolean(kycProvider),
          voucher_configured: Boolean(voucherKey && voucherTemplateSecret),
          webhook_configured: Boolean(sumsubWebhookSecret),
          issuer_id: String(enrollmentStore.issuerId),
          active_member_count: view.activeMemberCount,
          status_tokens: statusTokens.size,
          webhook_dedup_entries: webhookDigests.size,
          level: kycProvider?.levelName || null,
        });
      }
      if (req.method === "GET" && url.pathname === "/api/kyc/metrics") {
        const view = enrollmentStore.loadView().view;
        return text(
          res,
          200,
          [
            metricLine("anchorshield_kyc_configured", kycProvider ? 1 : 0),
            metricLine(
              "anchorshield_kyc_voucher_configured",
              voucherKey && voucherTemplateSecret ? 1 : 0,
            ),
            metricLine(
              "anchorshield_kyc_webhook_configured",
              sumsubWebhookSecret ? 1 : 0,
            ),
            metricLine("anchorshield_kyc_status_tokens", statusTokens.size),
            metricLine(
              "anchorshield_kyc_webhook_dedup_entries",
              webhookDigests.size,
            ),
            metricLine(
              "anchorshield_issuer_active_members",
              view.activeMemberCount,
              { issuer_id: enrollmentStore.issuerId },
            ),
          ].join("\n") + "\n",
        );
      }
      if (req.method === "POST" && url.pathname === "/api/kyc/webhook") {
        if (!sumsubWebhookSecret) {
          return json(res, 503, { error: "webhook secret not configured" });
        }
        let rawBody;
        try {
          rawBody = await readRawBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid webhook body",
          });
        }
        const signature = req.headers["x-payload-digest"];
        const algo = req.headers["x-payload-digest-alg"];
        if (
          !verifyWebhookSignature(
            rawBody,
            Array.isArray(signature) ? signature[0] : signature,
            Array.isArray(algo) ? algo[0] : algo,
            sumsubWebhookSecret,
          )
        ) {
          return json(res, 401, { error: "invalid webhook signature" });
        }
        const digest = crypto
          .createHash("sha256")
          .update(rawBody)
          .digest("hex");
        if (!burnExpiring(webhookDigests, digest, STATUS_TOKEN_TTL_MS)) {
          return json(res, 200, { ok: true, duplicate: true });
        }
        let event;
        try {
          event = rawBody.length ? JSON.parse(rawBody.toString("utf8")) : {};
        } catch {
          return json(res, 400, { error: "invalid JSON body" });
        }
        const externalUserId = String(event.externalUserId || "");
        if (externalUserId && USER_ID_RE.test(externalUserId)) {
          webhookStatuses.set(externalUserId, {
            receivedAt: new Date().toISOString(),
            reviewAnswer: event.reviewResult?.reviewAnswer || null,
            reviewStatus: event.reviewStatus || null,
            type: event.type || null,
          });
        }
        return json(res, 200, { ok: true, duplicate: false });
      }
      if (req.method === "GET" && url.pathname === "/api/kyc/voucher/pubkey") {
        return json(res, 200, {
          configured: Boolean(voucherKey && voucherTemplateSecret),
          publicKey: voucherKey ? publicKeyHex(voucherKey) : null,
        });
      }
      if (req.method === "GET" && url.pathname === "/api/issuers") {
        const issuers = await Promise.all(
          issuerDirectory.map(async (issuer) => {
            if (!issuer.metadata_uri) return issuer;
            try {
              return {
                ...issuer,
                metadata: await fetchIssuerMetadata(issuer.metadata_uri, {
                  fetchImpl: options.fetchImpl,
                  lookup: options.lookup,
                }),
              };
            } catch {
              return { ...issuer, metadata_error: "metadata unavailable" };
            }
          }),
        );
        return json(res, 200, { issuers });
      }
      if (req.method === "GET" && url.pathname === "/api/issuers/metadata") {
        const uri = url.searchParams.get("uri");
        if (!uri) return json(res, 400, { error: "metadata uri required" });
        try {
          return json(res, 200, {
            metadata: await fetchIssuerMetadata(uri, {
              fetchImpl: options.fetchImpl,
              lookup: options.lookup,
            }),
          });
        } catch {
          return json(res, 400, { error: "metadata fetch rejected" });
        }
      }
      if (!kycProvider) {
        return json(res, 503, {
          error: "KYC provider not configured (set SUMSUB_APP_TOKEN/SECRET)",
        });
      }
      if (req.method === "POST" && url.pathname === "/api/kyc/token") {
        if (tokenRateLimited(clientIp(req))) {
          return json(res, 429, {
            error: "rate limit exceeded - try again in a few minutes",
          });
        }
        let body;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        // Reuse a userId when refreshing an existing session; otherwise mint a fresh one.
        const existing = body.userId || url.searchParams.get("userId");
        const refreshStatusToken = body.statusToken;
        const userId =
          existing &&
          USER_ID_RE.test(existing) &&
          statusTokenMatchesUser(refreshStatusToken, existing)
            ? existing
            : `as-web-${crypto.randomUUID()}`;
        const token = await kycProvider.createAccessToken(userId, 600);
        return json(res, 200, {
          token,
          userId,
          statusToken: createStatusToken(userId),
          level: kycProvider.levelName,
        });
      }
      if (
        req.method === "POST" &&
        url.pathname === "/api/kyc/voucher/session"
      ) {
        if (!voucherKey || !voucherTemplateSecret) {
          return json(res, 503, { error: "voucher issuer not configured" });
        }
        if (tokenRateLimited(clientIp(req))) {
          return json(res, 429, {
            error: "rate limit exceeded - try again in a few minutes",
          });
        }
        const userId = `as-web-${crypto.randomUUID()}`;
        const token = await kycProvider.createAccessToken(userId, 600);
        return json(res, 200, {
          token,
          userId,
          statusToken: createStatusToken(userId),
          level: kycProvider.levelName,
          publicKey: publicKeyHex(voucherKey),
        });
      }
      if (req.method === "POST" && url.pathname === "/api/kyc/status") {
        let body;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        const statusToken = body.statusToken;
        if (!statusToken)
          return json(res, 401, { error: "status token required" });
        const userId = userIdForStatusToken(statusToken);
        if (!userId) return json(res, 401, { error: "invalid status token" });
        let applicant;
        try {
          applicant = await kycProvider.getApplicant(userId);
        } catch {
          return json(res, 200, { reviewAnswer: null, status: "not_started" });
        }
        const answer = applicant?.review?.reviewResult?.reviewAnswer || null;
        const webhookStatus = webhookStatuses.get(userId);
        let credential = null;
        if (answer === "GREEN") {
          try {
            credential = publicCredential(
              await kycProvider.verifiedCredential(userId),
            );
          } catch (e) {
            logProviderError("verifiedCredential", e);
            return json(res, 502, { error: "kyc credential unavailable" });
          }
        }
        return json(res, 200, {
          reviewAnswer: answer || webhookStatus?.reviewAnswer || null,
          credential,
          webhook: webhookStatus || null,
        });
      }
      if (req.method === "POST" && url.pathname === "/api/kyc/voucher") {
        if (!voucherKey || !voucherTemplateSecret) {
          return json(res, 503, { error: "voucher issuer not configured" });
        }
        let body;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        let verified;
        try {
          verified = await verifiedCredentialForStatusToken(
            kycProvider,
            body.statusToken,
          );
        } catch (e) {
          if (e.statusCode)
            return json(res, e.statusCode, { error: e.message });
          logProviderError("voucherCredential", e);
          return json(res, 502, { error: "kyc credential unavailable" });
        }
        if (
          !burnExpiring(
            spentVoucherStatusTokens,
            body.statusToken,
            STATUS_TOKEN_TTL_MS,
          )
        ) {
          return json(res, 409, { error: "voucher session already spent" });
        }
        try {
          const template = credentialTemplate({
            issuerId: enrollmentStore.issuerId,
            credential: verified.credential,
          });
          const blindSignature = blindSign(body.blinded, voucherKey);
          return json(res, 200, {
            blindSignature,
            credentialTemplate: template,
            credentialTemplateMac: templateMac(template, voucherTemplateSecret),
          });
        } catch (e) {
          logProviderError("voucher", e);
          return json(res, 400, { error: "voucher request invalid" });
        }
      }
      if (req.method === "POST" && url.pathname === "/api/enroll") {
        if (enrollRateLimited(clientIp(req))) {
          return json(res, 429, {
            error: "rate limit exceeded - try again in a few minutes",
          });
        }
        let body;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        try {
          const userCommitment = body.userCommitment || body.user_commitment;
          if (body.voucher) {
            if (!voucherKey || !voucherTemplateSecret) {
              return json(res, 503, { error: "voucher issuer not configured" });
            }
            const template = body.voucher.credentialTemplate;
            const mac = body.voucher.credentialTemplateMac;
            if (!verifyTemplateMac(template, mac, voucherTemplateSecret)) {
              return json(res, 401, { error: "credential template invalid" });
            }
            const credentialLeaf = credentialLeafFromTemplate({
              issuerId: enrollmentStore.issuerId,
              userCommitment,
              template,
            });
            if (
              !verifySignature(
                credentialLeaf,
                body.voucher.signature,
                voucherKey,
              )
            ) {
              return json(res, 401, { error: "credential voucher invalid" });
            }
            const digest = voucherDigest(body.voucher);
            if (
              !burnExpiring(spentVoucherDigests, digest, STATUS_TOKEN_TTL_MS)
            ) {
              return json(res, 409, {
                error: "credential voucher already used",
              });
            }
            const result = await enrollmentStore.enrollBlind({
              userCommitment,
              credentialTemplate: template,
              voucherDigest: digest,
            });
            return json(res, 200, result);
          }
          let verified;
          try {
            verified = await verifiedCredentialForStatusToken(
              kycProvider,
              body.statusToken,
            );
          } catch (e) {
            if (e.statusCode)
              return json(res, e.statusCode, { error: e.message });
            logProviderError("enrollCredential", e);
            return json(res, 502, { error: "kyc credential unavailable" });
          }
          const wallet = body.wallet;
          verifyWalletProof({
            wallet,
            action: "enroll",
            statusToken: body.statusToken,
            userCommitment,
            proof: body.walletProof,
          });
          const result = await enrollmentStore.enroll({
            wallet,
            userCommitment,
            kycCredential: verified.credential,
          });
          return json(res, 200, result);
        } catch (e) {
          if (e.statusCode) {
            return json(res, e.statusCode, { error: e.message });
          }
          if (e.code === "COMMITMENT_CONFLICT" || e.code === "VOUCHER_REPLAY") {
            return json(res, 409, { error: e.message });
          }
          if (e.code === "ROOT_PUBLISH_FAILED") {
            logProviderError("enrollRootPublish", e);
            return json(res, 502, {
              error: "credential root publish failed",
            });
          }
          logProviderError("enroll", e);
          return json(res, 400, { error: "enrollment request invalid" });
        }
      }
      if (req.method === "POST" && url.pathname === "/api/credential") {
        if (credentialRateLimited(clientIp(req))) {
          return json(res, 429, {
            error: "rate limit exceeded - try again in a few minutes",
          });
        }
        let body;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return json(res, e.code === "BODY_TOO_LARGE" ? 413 : 400, {
            error:
              e.code === "BODY_TOO_LARGE"
                ? "request body too large"
                : "invalid JSON body",
          });
        }
        try {
          if (body.voucher) {
            if (!voucherKey || !voucherTemplateSecret) {
              return json(res, 503, { error: "voucher issuer not configured" });
            }
            const template = body.voucher.credentialTemplate;
            const mac = body.voucher.credentialTemplateMac;
            if (!verifyTemplateMac(template, mac, voucherTemplateSecret)) {
              return json(res, 401, { error: "credential template invalid" });
            }
            const userCommitment = body.userCommitment || body.user_commitment;
            const credentialLeaf = credentialLeafFromTemplate({
              issuerId: enrollmentStore.issuerId,
              userCommitment,
              template,
            });
            if (
              !verifySignature(
                credentialLeaf,
                body.voucher.signature,
                voucherKey,
              )
            ) {
              return json(res, 401, { error: "credential voucher invalid" });
            }
            const credential =
              enrollmentStore.credentialByCommitment(userCommitment);
            if (!credential) return json(res, 404, { error: "not enrolled" });
            return json(res, 200, { credential });
          }
          const userCommitment = body.userCommitment || body.user_commitment;
          if (userCommitment && !body.statusToken) {
            const wallet = normalizeWallet(body.wallet);
            verifyWalletProof({
              wallet,
              action: "resume",
              statusToken: "",
              userCommitment,
              proof: body.walletProof,
            });
            const credential =
              enrollmentStore.credentialByCommitment(userCommitment);
            if (!credential) return json(res, 404, { error: "not enrolled" });
            if (credential.wallet !== wallet) {
              return json(res, 403, { error: "credential access denied" });
            }
            return json(res, 200, {
              credential,
              path: {
                credential_root: credential.credential_root,
                anonymity_set_size: credential.anonymity_set_size,
                merkle_index: credential.merkle_index,
                merkle_siblings: credential.merkle_siblings,
                sanctions_root: credential.sanctions_root,
                sanctions_low_value: credential.sanctions_low_value,
                sanctions_low_next: credential.sanctions_low_next,
                sanctions_low_index: credential.sanctions_low_index,
                sanctions_low_siblings: credential.sanctions_low_siblings,
                revocation_root: credential.revocation_root,
                revocation_low_value: credential.revocation_low_value,
                revocation_low_next: credential.revocation_low_next,
                revocation_low_index: credential.revocation_low_index,
                revocation_low_siblings: credential.revocation_low_siblings,
              },
            });
          }
          const statusToken = body.statusToken;
          let verified;
          try {
            verified = await verifiedCredentialForStatusToken(
              kycProvider,
              statusToken,
            );
          } catch (e) {
            if (e.statusCode)
              return json(res, e.statusCode, { error: e.message });
            logProviderError("credentialStatus", e);
            return json(res, 502, { error: "kyc credential unavailable" });
          }
          verifyWalletProof({
            wallet: body.wallet,
            action: "credential",
            statusToken,
            proof: body.walletProof,
          });
          const credential = enrollmentStore.credential(body.wallet, {
            externalUserId: verified.userId,
          });
          if (!credential) return json(res, 404, { error: "not enrolled" });
          return json(res, 200, { credential });
        } catch (e) {
          if (e.statusCode) {
            return json(res, e.statusCode, { error: e.message });
          }
          if (e.code === "OWNER_MISMATCH") {
            return json(res, 403, { error: "credential access denied" });
          }
          logProviderError("credential", e);
          return json(res, 400, { error: "credential request invalid" });
        }
      }
      return json(res, 404, { error: "not found" });
    } catch (e) {
      logProviderError("request", e);
      return json(res, 500, { error: "kyc backend error" });
    }
  });
}

if (require.main === module) {
  createServer().listen(PORT, "127.0.0.1", () => {
    console.log(
      `kyc-backend listening on 127.0.0.1:${PORT} (level ${provider?.levelName || "UNCONFIGURED"})`,
    );
  });
}

module.exports = {
  createServer,
  clientIp,
  stellarMessageHash,
  walletProofMessage,
};
