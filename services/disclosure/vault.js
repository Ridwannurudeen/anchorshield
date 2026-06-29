const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");
const issuedAt = "2026-06-28T00:00:00.000Z";
const expiresAt = "2026-07-05T00:00:00.000Z";

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function writeJson(relativePath, value) {
  const file = path.join(repo, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fileHash(relativePath) {
  return sha256Hex(fs.readFileSync(path.join(repo, relativePath)));
}

function buildVault({
  disclosure,
  packageJson,
  deployments,
  complianceEvents,
}) {
  const paymentEvent = complianceEvents.events.find(
    (event) => event.flow === "payment",
  );
  if (!paymentEvent) {
    throw new Error("payment compliance event not found");
  }
  if (disclosure.packetHash !== packageJson.aad.packetHash) {
    throw new Error("disclosure package does not match summary packet hash");
  }
  if (disclosure.paymentTx !== deployments.payment_flow.verify_and_pay_tx) {
    throw new Error("disclosure summary is not bound to deployment payment tx");
  }

  return {
    schema: "anchorshield.disclosure_vault.v1",
    network: deployments.network,
    generatedAt: issuedAt,
    packet: {
      packetHash: disclosure.packetHash,
      paymentTx: disclosure.paymentTx,
      actionId: String(disclosure.actionId),
      amount: String(disclosure.amount),
      corridorCountry: disclosure.corridorCountry,
      contractId: deployments.contracts.gate_payment,
      stellarExpertUrl: paymentEvent.stellarExpertUrl,
    },
    encryption: {
      algorithm: packageJson.algorithm,
      aad: packageJson.aad,
      encryptedPacketPath: "testdata/disclosure/payment-disclosure.json",
      encryptedPacketSha256: fileHash(
        "testdata/disclosure/payment-disclosure.json",
      ),
      privateViewKeyPath: disclosure.privateViewKeyPath,
      privateViewKeyCommitted: false,
    },
    grants: [
      {
        id: `grant:${sha256Hex(`${disclosure.packetHash}:auditor`).slice(0, 16)}`,
        subject: "mock-regulator",
        scope: [
          "packet_hash",
          "payment_tx",
          "action_binding",
          "corridor",
          "amount",
        ],
        issuedAt,
        expiresAt,
        status: "active",
        evidenceExport: "apps/web/data/disclosure-vault.json",
      },
    ],
    auditLog: [
      {
        at: issuedAt,
        actor: "holder-browser",
        action: "packet_encrypted",
        target: disclosure.packetHash,
      },
      {
        at: issuedAt,
        actor: "holder-browser",
        action: "grant_created",
        target: "mock-regulator",
      },
      {
        at: issuedAt,
        actor: "auditor-console",
        action: "evidence_exported",
        target: disclosure.paymentTx,
      },
    ],
    verification: {
      encryptedPacketMatchesSummary: true,
      paymentTxMatchesDeployment: true,
      piiOnChain: false,
      privateViewKeyPublished: true,
      privateViewKeyScope:
        "The committed key is the throwaway browser-demo auditor view key in apps/web/data/auditor-demo-key.json; production view keys stay out of the web artifact.",
    },
  };
}

function main() {
  const vault = buildVault({
    disclosure: readJson("apps/web/data/disclosure-summary.json"),
    packageJson: readJson("testdata/disclosure/payment-disclosure.json"),
    deployments: readJson("deployments/testnet-hardened.json"),
    complianceEvents: readJson("apps/web/data/compliance-events.json"),
  });

  writeJson("testdata/disclosure/vault.json", vault);
  writeJson("apps/web/data/disclosure-vault.json", vault);
  console.log(JSON.stringify(vault, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = {
  buildVault,
};
