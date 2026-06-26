const assert = require("assert");
const { execFileSync } = require("child_process");
const path = require("path");

const root = path.resolve(__dirname, "..", "..");
const cli = path.join(__dirname, "anchorshield.js");

function run(args) {
  return execFileSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

const inspected = JSON.parse(run(["inspect-public", "--public", "testdata/eligibility/public.json"]));
assert.strictEqual(inspected.policy_id, "202");

const validation = JSON.parse(
  run([
    "validate-action",
    "--input",
    "testdata/rwa/input.valid.json",
    "--public",
    "testdata/rwa/public.json",
  ]),
);
assert.deepStrictEqual(validation, {
  flow: "rwa",
  valid: true,
  action_id: "515151",
  policy_id: "303",
});

const events = JSON.parse(run(["events", "--file", "apps/web/data/compliance-events.json"]));
assert.strictEqual(events.network, "testnet");
assert.strictEqual(events.count, 2);
assert.strictEqual(events.events[0].piiOnChain, false);

const disclosure = JSON.parse(
  run(["disclosure", "verify", "--summary", "testdata/disclosure/summary.json"]),
);
assert.strictEqual(disclosure.verified, true);

const command = run([
  "gate",
  "payment",
  "--contract",
  "CD4FWZ5HH6H4XDSWVVQCZ354LWHJVCN6TV72UEHTLOMKQPKJAGHU5WGE",
  "--cli-args",
  "testdata/eligibility/cli-args.json",
  "--input",
  "testdata/eligibility/input.valid.json",
  "--source-account",
  "GAKI4FQWG2UXV5OUKFHDMK6QTIAQ3XZCWQ675BCVNEUH4JERH2MW2KNS",
  "--out-dir",
  ".m6/test-invoke/payment",
]).trim();
assert.match(command, /^stellar contract invoke --network testnet/);
assert.match(command, /--source-account GAKI4FQWG2UXV5OUKFHDMK6QTIAQ3XZCWQ675BCVNEUH4JERH2MW2KNS/);
assert.match(command, /verify_and_pay/);
assert.match(command, /--vk-file-path '.m6[\\/]test-invoke[\\/]payment[\\/]vk.json'/);
assert.match(command, /--packet_hash 24670719664893401973220249033732801233037657582921080313758662537416974078540/);

console.log("cli tests passed");
