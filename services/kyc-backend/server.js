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
const { createKycProvider } = require("../issuer/lib/kyc");

const PORT = Number(process.env.KYC_PORT || 3088);
const provider = createKycProvider();

function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

// Per-IP rate limit on token minting (protects the Sumsub sandbox quota from abuse). In-memory is
// fine for this single-process service; nginx forwards the real client IP via X-Forwarded-For.
const RATE = { windowMs: 10 * 60 * 1000, maxPerIp: 10 };
const tokenHits = new Map();

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
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

setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of tokenHits) {
    const keep = arr.filter((t) => now - t < RATE.windowMs);
    if (keep.length) tokenHits.set(ip, keep);
    else tokenHits.delete(ip);
  }
}, RATE.windowMs).unref();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  try {
    if (req.method === "GET" && url.pathname === "/api/kyc/healthz") {
      return json(res, 200, {
        ok: true,
        configured: Boolean(provider),
        level: provider?.levelName || null,
      });
    }
    if (!provider) {
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
        existing && /^as-web-[a-f0-9-]{36}$/.test(existing)
          ? existing
          : `as-web-${crypto.randomUUID()}`;
      const token = await provider.createAccessToken(userId, 600);
      return json(res, 200, { token, userId, level: provider.levelName });
    }
    if (req.method === "GET" && url.pathname === "/api/kyc/status") {
      const userId = url.searchParams.get("userId");
      if (!userId) return json(res, 400, { error: "userId required" });
      let applicant;
      try {
        applicant = await provider.getApplicant(userId);
      } catch {
        return json(res, 200, { reviewAnswer: null, status: "not_started" });
      }
      const answer = applicant?.review?.reviewResult?.reviewAnswer || null;
      let credential = null;
      if (answer === "GREEN") {
        try {
          credential = await provider.verifiedCredential(userId);
        } catch (e) {
          credential = { error: e.message };
        }
      }
      return json(res, 200, { reviewAnswer: answer, credential });
    }
    return json(res, 404, { error: "not found" });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(
    `kyc-backend listening on 127.0.0.1:${PORT} (level ${provider?.levelName || "UNCONFIGURED"})`,
  );
});
