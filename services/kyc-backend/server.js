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
const { createEnrollmentStore } = require("../issuer/enrollment-store");

const PORT = Number(process.env.KYC_PORT || 3088);
const provider = createKycProvider();
const USER_ID_RE = /^as-web-[a-f0-9-]{36}$/;
const WALLET_PROOF_MAX_AGE_MS = 10 * 60 * 1000;
const STELLAR_SIGNED_MESSAGE_PREFIX = "Stellar Signed Message:\n";

function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

// Per-IP rate limit on token minting (protects the Sumsub sandbox quota from abuse). In-memory is
// fine for this single-process service. The app only trusts X-Real-IP from a loopback nginx proxy.
const RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 10 };
const ENROLL_RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 20 };
const STATUS_TOKEN_TTL_MS = 30 * 60 * 1000;
const tokenHits = new Map();
const enrollHits = new Map();
const statusTokens = new Map();

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

function statusTokenMatchesUser(token, userId) {
  return userIdForStatusToken(token) === userId;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
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
  if (action === "enroll") {
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
  for (const [token, entry] of statusTokens) {
    if (entry.expiresAt < now) statusTokens.delete(token);
  }
}, RATE.windowMs).unref();

function createServer(kycProvider = provider, options = {}) {
  const enrollmentStore =
    options.enrollmentStore || createEnrollmentStore(options.enrollment || {});
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/api/kyc/healthz") {
        return json(res, 200, {
          ok: true,
          configured: Boolean(kycProvider),
          level: kycProvider?.levelName || null,
        });
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
        return json(res, 200, { reviewAnswer: answer, credential });
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
        try {
          const wallet = body.wallet;
          const userCommitment = body.userCommitment || body.user_commitment;
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
          if (e.code === "COMMITMENT_CONFLICT") {
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
        try {
          verifyWalletProof({
            wallet: body.wallet,
            action: "credential",
            statusToken,
            proof: body.walletProof,
          });
          const credential = enrollmentStore.credential(
            body.wallet,
            { externalUserId: verified.userId },
          );
          if (!credential) return json(res, 404, { error: "not enrolled" });
          return json(res, 200, { credential });
        } catch (e) {
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
