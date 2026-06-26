const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const repo = path.resolve(__dirname, "..", "..");
const privateOutDir = path.join(repo, ".m4", "disclosure");
const publicOutDir = path.join(repo, "testdata", "disclosure");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function b64(value) {
  return Buffer.from(value).toString("base64");
}

function fromB64(value) {
  return Buffer.from(value, "base64");
}

function mapPacket(input, publicSignals, deployments) {
  return {
    schema: "anchorshield.travel_rule.v1",
    network: "testnet",
    paymentContract: deployments.m1GatePayment.contractId,
    paymentTx: deployments.m1GatePayment.verifyAndPayTx,
    policyId: input.policy_id,
    assetId: input.asset_id,
    amount: input.amount,
    recipient: input.recipient,
    actionId: input.action_id,
    originator: input.packet_originator,
    beneficiary: input.packet_beneficiary,
    corridorCountry: input.packet_corridor,
    packetHash: publicSignals[1],
    nullifier: publicSignals[2],
  };
}

function encryptPacket(packet, auditorPublicKey) {
  const ephemeral = crypto.generateKeyPairSync("x25519");
  const shared = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: auditorPublicKey,
  });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(packet.packetHash);
  const key = Buffer.from(
    crypto.hkdfSync("sha256", shared, salt, Buffer.from("anchorshield-disclosure-v1"), 32),
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(packet), "utf8"),
    cipher.final(),
  ]);

  return {
    schema: "anchorshield.encrypted_disclosure.v1",
    algorithm: "x25519-hkdf-sha256-aes-256-gcm",
    aad: {
      packetHash: packet.packetHash,
      paymentTx: packet.paymentTx,
    },
    ephemeralPublicKeyPem: ephemeral.publicKey.export({
      type: "spki",
      format: "pem",
    }),
    salt: b64(salt),
    iv: b64(iv),
    tag: b64(cipher.getAuthTag()),
    ciphertext: b64(ciphertext),
  };
}

function decryptPacket(packageJson, auditorPrivateKey) {
  const ephemeralPublicKey = crypto.createPublicKey(packageJson.ephemeralPublicKeyPem);
  const shared = crypto.diffieHellman({
    privateKey: auditorPrivateKey,
    publicKey: ephemeralPublicKey,
  });
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      shared,
      fromB64(packageJson.salt),
      Buffer.from("anchorshield-disclosure-v1"),
      32,
    ),
  );
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, fromB64(packageJson.iv));
  decipher.setAAD(Buffer.from(packageJson.aad.packetHash));
  decipher.setAuthTag(fromB64(packageJson.tag));
  const plaintext = Buffer.concat([
    decipher.update(fromB64(packageJson.ciphertext)),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

async function computePublicSignals(input) {
  const { publicSignals } = await snarkjs.groth16.fullProve(
    input,
    path.join(repo, "apps", "web", "proving", "eligibility.wasm"),
    path.join(repo, "apps", "web", "proving", "eligibility_final.zkey"),
    undefined,
    undefined,
    { singleThread: true },
  );
  return publicSignals;
}

async function main() {
  fs.mkdirSync(privateOutDir, { recursive: true });
  fs.mkdirSync(publicOutDir, { recursive: true });

  const input = readJson("testdata/eligibility/input.valid.json");
  const expectedPublicSignals = readJson("testdata/eligibility/public.json");
  const deployments = readJson("deployments/testnet.json");
  const auditor = crypto.generateKeyPairSync("x25519");
  const auditorPublicKeyPem = auditor.publicKey.export({ type: "spki", format: "pem" });
  const auditorPrivateKeyPem = auditor.privateKey.export({ type: "pkcs8", format: "pem" });
  fs.writeFileSync(path.join(privateOutDir, "auditor-view-key.pem"), auditorPrivateKeyPem);

  const packet = mapPacket(input, expectedPublicSignals, deployments);
  const encrypted = encryptPacket(packet, auditor.publicKey);
  const decrypted = decryptPacket(encrypted, auditor.privateKey);
  const recomputedPublicSignals = await computePublicSignals(input);
  const verified =
    decrypted.packetHash === encrypted.aad.packetHash &&
    decrypted.packetHash === expectedPublicSignals[1] &&
    recomputedPublicSignals[1] === expectedPublicSignals[1] &&
    decrypted.paymentTx === deployments.m1GatePayment.verifyAndPayTx &&
    decrypted.amount === input.amount &&
    decrypted.actionId === input.action_id;

  if (!verified) {
    throw new Error("disclosure verification failed");
  }

  const disclosurePackage = {
    ...encrypted,
    auditorPublicKeyPem,
  };
  const summary = {
    verified: true,
    packetHash: decrypted.packetHash,
    paymentTx: decrypted.paymentTx,
    actionId: decrypted.actionId,
    amount: decrypted.amount,
    corridorCountry: decrypted.corridorCountry,
    privateViewKeyPath: ".m4/disclosure/auditor-view-key.pem",
  };

  writeJson(path.join(publicOutDir, "payment-disclosure.json"), disclosurePackage);
  writeJson(path.join(publicOutDir, "summary.json"), summary);
  writeJson(path.join(repo, "apps", "web", "data", "disclosure-summary.json"), summary);

  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
