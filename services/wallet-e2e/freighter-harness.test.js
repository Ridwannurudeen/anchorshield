const assert = require("assert");
const { mockFreighter, mockStellarSdk, runFreighterE2E } = require("./freighter-harness");

async function main() {
  const stellarSdk = mockStellarSdk();
  const freighterApi = mockFreighter();
  const { result } = await runFreighterE2E({ stellarSdk, freighterApi });

  assert.strictEqual(result.status, "SUCCESS");
  assert.strictEqual(result.txHash, "f".repeat(64));
  assert.strictEqual(stellarSdk.calls.getAccount.length, 1);
  assert.strictEqual(stellarSdk.calls.simulateTransaction.length, 1);
  assert.strictEqual(stellarSdk.calls.sendTransaction.length, 1);
  assert.strictEqual(freighterApi.calls.length, 1);
  assert.strictEqual(
    freighterApi.calls[0].options.networkPassphrase,
    "Test SDF Network ; September 2015",
  );
  assert.ok(freighterApi.calls[0].xdr.includes("verify_and_pay"));
  console.log("wallet E2E harness tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
