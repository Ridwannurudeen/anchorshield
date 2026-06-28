const assert = require("assert");
const fs = require("fs");
const path = require("path");

const { buildMockAnchor } = require("./sep-adapter");

const repo = path.resolve(__dirname, "..", "..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

const fixture = buildMockAnchor({
  deployments: readJson("deployments/testnet-hardened.json"),
  paymentInput: readJson("testdata/eligibility/input.valid.json"),
  paymentPublic: readJson("testdata/eligibility/public.json"),
  rwaInput: readJson("testdata/rwa/input.valid.json"),
  rwaPublic: readJson("testdata/rwa/public.json"),
});

assert.strictEqual(fixture.mode, "mock-only");
assert.strictEqual(fixture.sep10.authenticated, true);
assert.strictEqual(fixture.sep38.boundPacketHash, readJson("testdata/eligibility/public.json")[1]);
assert.strictEqual(fixture.sep31.paymentTx, readJson("deployments/testnet-hardened.json").payment_flow.verify_and_pay_tx);
assert.strictEqual(fixture.webhooks.length, 2);

console.log("mock anchor adapter test OK");
