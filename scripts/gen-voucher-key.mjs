import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const outPath = process.argv[2];
if (!outPath) {
  console.error("usage: node scripts/gen-voucher-key.mjs <private-key.pem>");
  process.exit(1);
}

const resolved = path.resolve(outPath);
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicExponent: 0x10001,
});
const pem = privateKey.export({ type: "pkcs8", format: "pem" });
fs.mkdirSync(path.dirname(resolved), { recursive: true });
fs.writeFileSync(resolved, pem, { flag: "wx", mode: 0o600 });

const jwk = publicKey.export({ format: "jwk" });
console.log(
  JSON.stringify(
    {
      wrote: resolved,
      env: {
        VOUCHER_RSA_PRIVATE_KEY_FILE: resolved,
      },
      publicKey: {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
      },
      privateKeySha256: crypto.createHash("sha256").update(pem).digest("hex"),
    },
    null,
    2,
  ),
);
