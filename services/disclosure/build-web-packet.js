// One-time generator for the live in-browser disclosure-decrypt demo.
//
// Emits a PERSISTENT demo auditor/regulator x25519 keypair and an encrypted disclosure packet to
// apps/web/data/, so the browser can decrypt the real packet client-side (Web Crypto) and reveal the
// payment's compliance fields WITHOUT identity. The demo private key is published on purpose — it is
// the stand-in "regulator view key" for the demo, not a production secret.
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { mapPacket, encryptPacket, decryptPacket } = require("./disclosure");

const repo = path.join(__dirname, "..", "..");
const dataDir = path.join(repo, "apps", "web", "data");
const keyPath = path.join(dataDir, "auditor-demo-key.json");
const defaultInputPath = path.join(
  repo,
  "testdata",
  "eligibility",
  "input.valid.json",
);

function loadOrCreateAuditorKey() {
  if (fs.existsSync(keyPath)) {
    return JSON.parse(fs.readFileSync(keyPath, "utf8"));
  }
  const kp = crypto.generateKeyPairSync("x25519");
  const key = {
    note: "DEMO regulator/auditor view key — published on purpose for the live in-browser disclosure decrypt. NOT a production secret.",
    privatePkcs8B64: kp.privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
    publicSpkiPem: kp.publicKey.export({ type: "spki", format: "pem" }),
  };
  fs.writeFileSync(keyPath, `${JSON.stringify(key, null, 2)}\n`);
  return key;
}

function computePublicSignals(inputPath) {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-web-"));
  const proofPath = path.join(outDir, "proof.json");
  const publicPath = path.join(outDir, "public.json");
  try {
    const result = spawnSync(
      process.execPath,
      [
        path.join(repo, "node_modules", "snarkjs", "build", "cli.cjs"),
        "groth16",
        "fullprove",
        inputPath,
        path.join(dataDir, "..", "proving", "eligibility.wasm"),
        path.join(dataDir, "..", "proving", "eligibility_final.zkey"),
        proofPath,
        publicPath,
      ],
      { cwd: repo, encoding: "utf8", timeout: 600000 },
    );
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error(
        result.stderr || result.stdout || "snarkjs fullprove failed",
      );
    }
    return JSON.parse(fs.readFileSync(publicPath, "utf8"));
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
}

async function main() {
  const inputPath = process.env.ANCHORSHIELD_PAYMENT_INPUT || defaultInputPath;
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const deployments = JSON.parse(
    fs.readFileSync(path.join(dataDir, "deployments.json"), "utf8"),
  );
  const publicSignals = computePublicSignals(inputPath);
  const key = loadOrCreateAuditorKey();
  const auditorPublicKey = crypto.createPublicKey(key.publicSpkiPem);
  const packet = mapPacket(input, publicSignals, deployments);
  const encrypted = encryptPacket(packet, auditorPublicKey);
  fs.writeFileSync(
    path.join(dataDir, "payment-disclosure.json"),
    `${JSON.stringify(encrypted, null, 2)}\n`,
  );

  const auditorPrivateKey = crypto.createPrivateKey({
    key: Buffer.from(key.privatePkcs8B64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const plain = decryptPacket(encrypted, auditorPrivateKey);
  console.log("ground-truth plaintext:");
  console.log(JSON.stringify(plain));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
