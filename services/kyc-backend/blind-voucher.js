const crypto = require("crypto");
const fs = require("fs");

const NLEN = 256;

function b64uToBig(value) {
  return BigInt(`0x${Buffer.from(value, "base64url").toString("hex")}`);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function i2osp(value, len) {
  const bytes = Buffer.alloc(len);
  let remaining = BigInt(value);
  for (let i = len - 1; i >= 0; i -= 1) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function toBytesBE(value, len = NLEN) {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return `0x${hex.padStart(len * 2, "0")}`;
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

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

function messageRepresentative(message) {
  const messageField = BigInt(String(message));
  if (messageField <= 0n) {
    throw new Error("message must be a positive field element");
  }
  const seed = sha256(i2osp(messageField, 32));
  const representative = Buffer.alloc(NLEN);
  let offset = 0;
  let counter = 0;
  while (offset < NLEN) {
    const block = sha256(Buffer.concat([seed, i2osp(BigInt(counter), 4)]));
    block.copy(
      representative,
      offset,
      0,
      Math.min(block.length, NLEN - offset),
    );
    offset += block.length;
    counter += 1;
  }
  representative[0] = 0;
  return bytesToBigInt(representative);
}

function loadVoucherKeyFromPem(pem) {
  const jwk = crypto.createPrivateKey(pem).export({ format: "jwk" });
  if (jwk.kty !== "RSA" || !jwk.n || !jwk.e || !jwk.d) {
    throw new Error("voucher signing key is not an RSA private key");
  }
  const key = {
    N: b64uToBig(jwk.n),
    e: b64uToBig(jwk.e),
    d: b64uToBig(jwk.d),
    privateKeySha256: crypto.createHash("sha256").update(pem).digest("hex"),
  };
  const bits = key.N.toString(2).length;
  if (bits < 2041 || bits > 2048) {
    throw new Error(`voucher RSA key must be 2048-bit; got ${bits}-bit`);
  }
  return key;
}

function readVoucherPem(env = process.env) {
  if (env.VOUCHER_RSA_PRIVATE_KEY) return env.VOUCHER_RSA_PRIVATE_KEY;
  if (
    env.VOUCHER_RSA_PRIVATE_KEY_FILE &&
    fs.existsSync(env.VOUCHER_RSA_PRIVATE_KEY_FILE)
  ) {
    return fs.readFileSync(env.VOUCHER_RSA_PRIVATE_KEY_FILE, "utf8");
  }
  return "";
}

function publicKeyHex(key) {
  return { n: toBytesBE(key.N), e: toBytesBE(key.e, 0) };
}

function parseHex(value, label) {
  const text = String(value || "");
  const hex = text.startsWith("0x") ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`${label} must be hex`);
  }
  return BigInt(`0x${hex}`);
}

function blindSign(blindedHex, key) {
  const blinded = parseHex(blindedHex, "blinded");
  if (blinded <= 1n || blinded >= key.N) {
    throw new Error("blinded value out of range");
  }
  return toBytesBE(modpow(blinded, key.d, key.N));
}

function verifySignature(message, signatureHex, key) {
  const signature = parseHex(signatureHex, "signature");
  if (signature <= 1n || signature >= key.N) return false;
  return modpow(signature, key.e, key.N) === messageRepresentative(message);
}

let cachedKey = null;
function getVoucherKey(env = process.env) {
  const pem = readVoucherPem(env);
  if (!pem) {
    throw new Error("voucher signing key not configured");
  }
  if (!cachedKey) cachedKey = loadVoucherKeyFromPem(pem);
  return cachedKey;
}

module.exports = {
  NLEN,
  blindSign,
  getVoucherKey,
  loadVoucherKeyFromPem,
  messageRepresentative,
  publicKeyHex,
  toBytesBE,
  verifySignature,
};
