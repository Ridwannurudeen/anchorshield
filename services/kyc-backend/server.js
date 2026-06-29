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
const { createKycProvider } = require("../issuer/lib/kyc");

const PORT = Number(process.env.KYC_PORT || 3088);
const provider = createKycProvider();
const USER_ID_RE = /^as-web-[a-f0-9-]{36}$/;

function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

// Per-IP rate limit on token minting (protects the Sumsub sandbox quota from abuse). In-memory is
// fine for this single-process service. The app only trusts X-Real-IP from a loopback nginx proxy.
const RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 10 };
const STATUS_TOKEN_TTL_MS = 30 * 60 * 1000;
const tokenHits = new Map();
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

function tokenRateLimited(ip) {
  const now = Date.now();
  const recent = (tokenHits.get(ip) || []).filter(
    (t) => now - t < RATE.windowMs,
  );
  if (recent.length >= RATE.maxPerIp) {
    tokenHits.set(ip, recent);
    return true;
  }
  recent.push(now);
  tokenHits.set(ip, recent);
  return false;
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

function publicCredential(credential) {
  if (!credential) return null;
  return {
    kyc_passed: credential.kyc_passed,
    country: credential.country,
    age: credential.age,
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
  for (const [token, entry] of statusTokens) {
    if (entry.expiresAt < now) statusTokens.delete(token);
  }
}, RATE.windowMs).unref();

function createServer(kycProvider = provider) {
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
            error: "rate limit exceeded — try again in a few minutes",
          });
        }
        // Reuse a userId when refreshing an existing session; otherwise mint a fresh one.
        const existing = url.searchParams.get("userId");
        const userId =
          existing && USER_ID_RE.test(existing)
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
      if (req.method === "GET" && url.pathname === "/api/kyc/status") {
        const statusToken = url.searchParams.get("statusToken");
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
};
