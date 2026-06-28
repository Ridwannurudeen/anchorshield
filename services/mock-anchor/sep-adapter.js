const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");
const issuedAt = "2026-06-28T00:00:00.000Z";

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function writeJson(relativePath, value) {
  const file = path.join(repo, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function digest(...parts) {
  return crypto.createHash("sha256").update(parts.join(":")).digest("hex");
}

function buildMockAnchor({ deployments, paymentInput, paymentPublic, rwaInput, rwaPublic }) {
  const account = deployments.admin;
  const challengeNonce = digest("sep10", account, paymentPublic[3]).slice(0, 32);
  const sep10Challenge = `ANCHORSHIELD-SEP10-MOCK ${account} ${challengeNonce}`;
  const quoteId = `Q-${digest("sep38", paymentInput.policy_id, paymentInput.asset_id, paymentInput.amount, paymentInput.recipient).slice(0, 12)}`;
  const transactionId = `T-${digest("sep31", deployments.payment_flow.verify_and_pay_tx, paymentPublic[2]).slice(0, 12)}`;
  const webhookId = `W-${digest("webhook", deployments.payment_flow.verify_and_pay_tx, rwaPublic[3]).slice(0, 12)}`;

  return {
    schema: "anchorshield.mock_anchor.v1",
    mode: "mock-only",
    generatedAt: issuedAt,
    homeDomain: "mock.anchor.local",
    sep10: {
      account,
      challenge: sep10Challenge,
      challengeNonce,
      sessionTokenHash: digest("session", sep10Challenge),
      authenticated: true,
    },
    sep38: {
      quoteId,
      sellAsset: "iso4217:USD",
      buyAsset: "stellar:native",
      amount: String(paymentInput.amount),
      expiresAt: "2026-07-05T00:00:00.000Z",
      boundPolicyId: String(paymentInput.policy_id),
      boundActionBinding: paymentPublic[3],
      boundPacketHash: paymentPublic[1],
    },
    sep31: {
      transactionId,
      status: "completed",
      kind: "receive",
      amountIn: String(paymentInput.amount),
      amountOut: String(paymentInput.amount),
      paymentTx: deployments.payment_flow.verify_and_pay_tx,
      holdStartedAt: issuedAt,
      releasedAt: issuedAt,
    },
    rwaIssuer: {
      authorization: "attest_for_mint",
      policyId: String(rwaInput.policy_id),
      assetId: String(rwaInput.asset_id),
      amount: String(rwaInput.amount),
      recipientId: String(rwaInput.recipient),
      actionBinding: rwaPublic[3],
      attestTx: deployments.rwa_flow.attest_for_mint_tx || deployments.rwa_flow.mint_tx,
      mintTx: deployments.rwa_flow.mint_tx,
    },
    webhooks: [
      {
        id: webhookId,
        type: "sep31.transaction.completed",
        transactionId,
        txHash: deployments.payment_flow.verify_and_pay_tx,
        quoteId,
      },
      {
        id: `W-${digest("rwa", deployments.rwa_flow.mint_tx, rwaPublic[2]).slice(0, 12)}`,
        type: "rwa.mint.authorized",
        txHash: deployments.rwa_flow.attest_for_mint_tx || deployments.rwa_flow.mint_tx,
        mintTx: deployments.rwa_flow.mint_tx,
      },
    ],
    boundaries: [
      "SEP-10, SEP-31, and SEP-38 are deterministic mock adapters for the local demo.",
      "No real anchor, KYC provider, fiat rail, or issuer pilot is claimed.",
    ],
  };
}

function main() {
  const fixture = buildMockAnchor({
    deployments: readJson("deployments/testnet-hardened.json"),
    paymentInput: readJson("testdata/eligibility/input.valid.json"),
    paymentPublic: readJson("testdata/eligibility/public.json"),
    rwaInput: readJson("testdata/rwa/input.valid.json"),
    rwaPublic: readJson("testdata/rwa/public.json"),
  });

  writeJson("testdata/mock-anchor/mock-anchor.json", fixture);
  writeJson("apps/web/data/mock-anchor.json", fixture);
  console.log(JSON.stringify(fixture, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = {
  buildMockAnchor,
};
