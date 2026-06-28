const assert = require("assert");
const fs = require("fs");
const path = require("path");

const { buildVault } = require("./vault");

const repo = path.resolve(__dirname, "..", "..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

const vault = buildVault({
  disclosure: readJson("apps/web/data/disclosure-summary.json"),
  packageJson: readJson("testdata/disclosure/payment-disclosure.json"),
  deployments: readJson("deployments/testnet-hardened.json"),
  complianceEvents: readJson("apps/web/data/compliance-events.json"),
});

assert.strictEqual(vault.verification.encryptedPacketMatchesSummary, true);
assert.strictEqual(vault.verification.privateViewKeyPublished, false);
assert.strictEqual(vault.grants[0].status, "active");
assert.strictEqual(vault.packet.paymentTx, vault.encryption.aad.paymentTx);
assert(!JSON.stringify(vault).includes("PRIVATE KEY"));

console.log("disclosure vault test OK");
