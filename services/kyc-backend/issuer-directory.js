const dns = require("dns/promises");
const net = require("net");

const MAX_METADATA_BYTES = 64 * 1024;
const ALLOWED_FIELDS = new Set([
  "metadata_version",
  "name",
  "legal_name",
  "jurisdiction",
  "license_id",
  "website",
  "support_email",
  "proof_policy",
]);

function isPrivateIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split(".").map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 0
    );
  }
  if (family === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80:") ||
      normalized === "::" ||
      normalized.startsWith("::ffff:127.") ||
      normalized.startsWith("::ffff:10.") ||
      normalized.startsWith("::ffff:192.168.")
    );
  }
  return false;
}

async function assertPublicMetadataUrl(uri, lookup = dns.lookup) {
  const url = new URL(uri);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("metadata URI must be http or https");
  }
  if (url.username || url.password) {
    throw new Error("metadata URI must not include credentials");
  }
  if (net.isIP(url.hostname)) {
    if (isPrivateIp(url.hostname)) {
      throw new Error("metadata URI resolves to a private IP");
    }
    return url;
  }
  const records = await lookup(url.hostname, { all: true });
  if (
    !records.length ||
    records.some((record) => isPrivateIp(record.address))
  ) {
    throw new Error("metadata URI resolves to a private IP");
  }
  return url;
}

function cleanString(value, max = 160) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return null;
  return trimmed;
}

function sanitizeIssuerMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("issuer metadata must be an object");
  }
  const result = {};
  for (const [key, raw] of Object.entries(value)) {
    if (!ALLOWED_FIELDS.has(key)) continue;
    const cleaned = cleanString(raw, key === "proof_policy" ? 400 : 160);
    if (!cleaned) continue;
    if (
      (key === "website" || key === "proof_policy") &&
      !cleaned.startsWith("https://")
    ) {
      continue;
    }
    result[key] = cleaned;
  }
  if (!result.name) {
    throw new Error("issuer metadata is missing name");
  }
  return result;
}

async function fetchIssuerMetadata(uri, options = {}) {
  const url = await assertPublicMetadataUrl(uri, options.lookup);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available");
  }
  const response = await fetchImpl(url.href, {
    headers: { accept: "application/json" },
    redirect: "manual",
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error("metadata redirects are not allowed");
  }
  if (!response.ok) {
    throw new Error(`metadata fetch failed with status ${response.status}`);
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_METADATA_BYTES) {
    throw new Error("metadata response too large");
  }
  return sanitizeIssuerMetadata(JSON.parse(text));
}

module.exports = {
  assertPublicMetadataUrl,
  fetchIssuerMetadata,
  isPrivateIp,
  sanitizeIssuerMetadata,
};
