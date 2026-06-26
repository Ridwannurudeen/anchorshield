const assert = require("assert");
const path = require("path");
const sdk = require("./src");

const root = path.resolve(__dirname, "..", "..");
const paymentInput = sdk.readJson(path.join(root, "testdata/eligibility/input.valid.json"));
const paymentPublic = sdk.readJson(path.join(root, "testdata/eligibility/public.json"));
const paymentCliArgs = sdk.readJson(path.join(root, "testdata/eligibility/cli-args.json"));
const rwaInput = sdk.readJson(path.join(root, "testdata/rwa/input.valid.json"));
const rwaPublic = sdk.readJson(path.join(root, "testdata/rwa/public.json"));
const rwaCliArgs = sdk.readJson(path.join(root, "testdata/rwa/cli-args.json"));

assert.strictEqual(sdk.PUBLIC_SIGNAL_NAMES.length, 17);
assert.strictEqual(sdk.parsePublicSignals(paymentPublic).policy_id, "202");
assert.strictEqual(sdk.parsePublicSignals(rwaPublic).policy_id, "303");

assert.doesNotThrow(() => sdk.assertPaymentAction(paymentInput, paymentPublic));
assert.doesNotThrow(() => sdk.assertRwaAction(rwaInput, rwaPublic));
assert.throws(
  () => sdk.assertPaymentAction({ ...paymentInput, amount: "251" }, paymentPublic),
  /public signal mismatch/,
);
assert.throws(() => sdk.assertPaymentAction(rwaInput, rwaPublic), /payment proof/);

assert.deepStrictEqual(sdk.formatSorobanPubSignals(paymentPublic), paymentCliArgs.pub_signals);
assert.deepStrictEqual(sdk.formatImplicitCliPubSignals(paymentCliArgs.pub_signals), paymentPublic);
assert.strictEqual(typeof sdk.formatBindingPubSignals(paymentPublic)[0], "bigint");

const paymentInvoke = sdk.buildPaymentInvokeArgs(paymentCliArgs, paymentInput);
assert.strictEqual(paymentInvoke.policy_id, 202);
assert.strictEqual(paymentInvoke.asset_id, 9001);
assert.strictEqual(paymentInvoke.amount, 250n);
assert.strictEqual(paymentInvoke.packet_hash, BigInt(sdk.parsePublicSignals(paymentPublic).packet_hash));
assert.ok(Buffer.isBuffer(paymentInvoke.proof.a));
assert.ok(Buffer.isBuffer(paymentInvoke.vk.ic[0]));

const rwaInvoke = sdk.buildRwaInvokeArgs(rwaCliArgs, rwaInput);
assert.strictEqual(rwaInvoke.policy_id, 303);
assert.strictEqual(rwaInvoke.asset_id, 9101);
assert.strictEqual(rwaInvoke.terms_hash, BigInt(sdk.parsePublicSignals(rwaPublic).packet_hash));

assert.strictEqual(
  sdk.stellarExpertTxUrl(
    "testnet",
    "e17e8fda2496824569d3497cddc845fd7721c560822de5e6912984e9ab2bde7d",
  ),
  "https://stellar.expert/explorer/testnet/tx/e17e8fda2496824569d3497cddc845fd7721c560822de5e6912984e9ab2bde7d",
);

console.log("sdk tests passed");
