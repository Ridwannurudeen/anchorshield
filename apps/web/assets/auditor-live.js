// Live, in-browser selective-disclosure decrypt. A regulator holding the view key decrypts the real
// encrypted packet client-side (Web Crypto: X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM) and reveals
// the payment's compliance fields — the same fields the chain never saw. The demo auditor key is
// published on purpose (it's the stand-in regulator key). Mirrors services/disclosure/disclosure.js.
(function () {
  function set(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (cls) el.className = cls;
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function pemToDer(pem) {
    const body = pem
      .replace(/-----BEGIN [^-]+-----/, "")
      .replace(/-----END [^-]+-----/, "")
      .replace(/\s+/g, "");
    return b64ToBytes(body);
  }

  async function decryptDisclosure(pkg, privatePkcs8B64) {
    const auditorPriv = await crypto.subtle.importKey(
      "pkcs8",
      b64ToBytes(privatePkcs8B64),
      { name: "X25519" },
      false,
      ["deriveBits"],
    );
    const ephPub = await crypto.subtle.importKey(
      "spki",
      pemToDer(pkg.ephemeralPublicKeyPem),
      { name: "X25519" },
      false,
      [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: "X25519", public: ephPub },
      auditorPriv,
      256,
    );
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      shared,
      "HKDF",
      false,
      ["deriveBits"],
    );
    const keyBits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: b64ToBytes(pkg.salt),
        info: new TextEncoder().encode("anchorshield-disclosure-v1"),
      },
      hkdfKey,
      256,
    );
    const aesKey = await crypto.subtle.importKey(
      "raw",
      keyBits,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const ct = b64ToBytes(pkg.ciphertext);
    const tag = b64ToBytes(pkg.tag);
    const ctTag = new Uint8Array(ct.length + tag.length);
    ctTag.set(ct);
    ctTag.set(tag, ct.length);
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64ToBytes(pkg.iv),
        additionalData: new TextEncoder().encode(pkg.aad.packetHash),
        tagLength: 128,
      },
      aesKey,
      ctTag,
    );
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function run() {
    const btn = document.getElementById("decryptDisclosure");
    btn.disabled = true;
    set("discStatus", "loading encrypted packet + view key…", "pending");
    try {
      if (!window.isSecureContext || !crypto.subtle) {
        throw new Error("Web Crypto requires a secure (https) context");
      }
      const [pkg, key] = await Promise.all([
        fetch("./data/payment-disclosure.json").then((r) => r.json()),
        fetch("./data/auditor-demo-key.json").then((r) => r.json()),
      ]);
      set(
        "discStatus",
        "deriving shared secret + decrypting (X25519 → HKDF → AES-GCM)…",
        "pending",
      );
      const packet = await decryptDisclosure(pkg, key.privatePkcs8B64);
      set("discRecipient", packet.recipient || "-");
      set("discAmount", packet.amount || "-");
      set("discAction", packet.actionId || "-");
      set("discCorridor", packet.corridorCountry || "-");
      set("discParties", `${packet.originator} → ${packet.beneficiary}`);
      set(
        "discStatus",
        "decrypted — the view-key holder sees these fields; the chain never did.",
        "success",
      );
    } catch (e) {
      set("discStatus", `error: ${e.message}`, "error");
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("decryptDisclosure");
    if (btn) btn.addEventListener("click", run);
  });
})();
