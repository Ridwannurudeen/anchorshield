(function () {
  const NLEN = 256;

  function parseHex(value, label) {
    const text = String(value || "");
    const hex = text.startsWith("0x") ? text.slice(2) : text;
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error(`${label} must be hex`);
    }
    return BigInt(`0x${hex}`);
  }

  function toHex(value, len = NLEN) {
    let hex = BigInt(value).toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    return `0x${hex.padStart(len * 2, "0")}`;
  }

  function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
  }

  function i2osp(value, len) {
    const bytes = new Uint8Array(len);
    let remaining = BigInt(value);
    for (let i = len - 1; i >= 0; i -= 1) {
      bytes[i] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    return bytes;
  }

  async function sha256(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
  }

  function concatBytes(left, right) {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
  }

  async function messageRepresentative(message) {
    const messageField = BigInt(String(message));
    if (messageField <= 0n) {
      throw new Error("message must be a positive field element");
    }
    const seed = await sha256(i2osp(messageField, 32));
    const representative = new Uint8Array(NLEN);
    let offset = 0;
    let counter = 0;
    while (offset < NLEN) {
      const block = await sha256(concatBytes(seed, i2osp(BigInt(counter), 4)));
      representative.set(block.slice(0, NLEN - offset), offset);
      offset += block.length;
      counter += 1;
    }
    representative[0] = 0;
    return bytesToBigInt(representative);
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
    if (g !== 1n) {
      throw new Error("blinding factor is not invertible");
    }
    return ((x % modulus) + modulus) % modulus;
  }

  function randomBelow(modulus) {
    const bytes = new Uint8Array(NLEN);
    for (;;) {
      crypto.getRandomValues(bytes);
      bytes[0] = 0;
      const value = bytesToBigInt(bytes);
      if (value > 1n && value < modulus && egcd(value, modulus)[0] === 1n) {
        return value;
      }
    }
  }

  function publicParts(publicKey) {
    return {
      N: parseHex(publicKey.n, "publicKey.n"),
      e: parseHex(publicKey.e, "publicKey.e"),
    };
  }

  async function blindMessage(message, publicKey) {
    const { N, e } = publicParts(publicKey);
    const representative = await messageRepresentative(message);
    const r = randomBelow(N);
    return {
      blinded: toHex((representative * modpow(r, e, N)) % N),
      r: toHex(r),
    };
  }

  function unblind(blindSignature, r, publicKey) {
    const { N } = publicParts(publicKey);
    const signature =
      (parseHex(blindSignature, "blindSignature") *
        modinv(parseHex(r, "r"), N)) %
      N;
    return toHex(signature);
  }

  async function verify(message, signature, publicKey) {
    const { N, e } = publicParts(publicKey);
    const sig = parseHex(signature, "signature");
    if (sig <= 1n || sig >= N) return false;
    return modpow(sig, e, N) === (await messageRepresentative(message));
  }

  window.AnchorShieldBlind = {
    blindMessage,
    messageRepresentative,
    unblind,
    verify,
  };
})();
