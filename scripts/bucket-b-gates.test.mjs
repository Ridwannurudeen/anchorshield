import assert from "node:assert";
import sepClient from "../services/anchor/sep-client.js";
import { validAnchorEvidence } from "./bucket-b-preflight.mjs";
import publishRootsModule from "../services/issuer/publish-roots.js";

const { validateAnchorConfig } = sepClient;
const {
  decimalRootToHex,
  parseHexRootOutput,
  parseRootCommand,
  publicKeyOrIdentityAddress,
  rootGetterCommands,
  verifyPublishedRoots,
} = publishRootsModule;

const command =
  "stellar contract invoke --id CDH4LER4DMTKKQPBRJNYUJJMFYEDETODHRV7T5VNGBCSGNKRVM5TW7R4 --source anchorshield-admin --network testnet -- set_root --issuer_id 101 --root 3594049153834496365048415731714516938958311638082949354083622427305805247490";
const parsed = parseRootCommand(command);
assert.strictEqual(parsed.source, "anchorshield-admin");
assert.strictEqual(parsed.fnName, "set_root");
assert.strictEqual(parsed.issuerId, "101");
assert.strictEqual(
  decimalRootToHex(parsed.root),
  "07f228e445d37df69c12e6bfdb95c685f2e7e2ddc440713f59d71c6d00b27402",
);
assert.strictEqual(
  parseHexRootOutput(
    '"07f228e445d37df69c12e6bfdb95c685f2e7e2ddc440713f59d71c6d00b27402"',
  ),
  "07f228e445d37df69c12e6bfdb95c685f2e7e2ddc440713f59d71c6d00b27402",
);

const issuance = {
  issuer_id: 101,
  roots: {
    credential_root:
      "3594049153834496365048415731714516938958311638082949354083622427305805247490",
    sanctions_root:
      "28244391006650305950885317775462315324257726777689173131376288148674963252046",
    revocation_root:
      "16121972906969319149086174845384184675905388596140385334169034751742031498531",
  },
  root_publish: {
    admin: "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
  },
  root_commands: [
    command,
    "stellar contract invoke --id CDH4LER4DMTKKQPBRJNYUJJMFYEDETODHRV7T5VNGBCSGNKRVM5TW7R4 --source anchorshield-admin --network testnet -- set_sanctions_root --root 28244391006650305950885317775462315324257726777689173131376288148674963252046",
    "stellar contract invoke --id CDH4LER4DMTKKQPBRJNYUJJMFYEDETODHRV7T5VNGBCSGNKRVM5TW7R4 --source anchorshield-admin --network testnet -- set_revocation_root --issuer_id 101 --root 16121972906969319149086174845384184675905388596140385334169034751742031498531",
  ],
};

assert.deepStrictEqual(
  rootGetterCommands({ issuance }).map((check) => check.name),
  ["credential_root", "sanctions_root", "revocation_root"],
);

assert.strictEqual(
  publicKeyOrIdentityAddress(
    "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
  ),
  "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
);
assert.throws(
  () =>
    publicKeyOrIdentityAddress("anchorshield-admin", () => ({
      status: 1,
      stdout: "",
      stderr: "not found",
    })),
  /import the deployed admin identity/,
);

const validAnchorConfig = {
  homeDomain: "anchor.partner.test",
  webAuthEndpoint: "https://auth.partner.test",
  transferServerSep31: "https://sep31.partner.test",
  anchorQuoteServer: "https://sep38.partner.test",
  token: "sep10-token",
  sellAsset: "iso4217:USD",
  buyAsset: "stellar:native",
  receiveAssetCode: "native",
  senderId: "sender-1",
  receiverId: "receiver-1",
  fundingMethod: "bank_account",
  quoteExpiresAt: "2026-07-05T00:00:00Z",
  packetHash:
    "24670719664893401973220249033732801233037657582921080313758662537416974078540",
  actionBinding: "313131",
};
assert.strictEqual(validateAnchorConfig(validAnchorConfig), validAnchorConfig);
assert.throws(
  () =>
    validateAnchorConfig({
      ...validAnchorConfig,
      token: "SEP10_JWT_FROM_ANCHOR_SANDBOX",
    }),
  /placeholder/,
);

assert.strictEqual(
  validAnchorEvidence({
    schema: "anchorshield.anchor_sandbox_run.v1",
    mode: "real-anchor-sandbox",
    steps: {
      sep38_price: { ok: true },
      sep38_quote: { ok: true },
      sep31_create: { ok: true },
    },
  }),
  true,
);
assert.strictEqual(
  validAnchorEvidence({
    schema: "anchorshield.anchor_sandbox_run.v1",
    mode: "real-anchor-sandbox",
    steps: {
      sep38_price: { ok: true },
      sep38_quote: { ok: true },
      sep31_create: { ok: false },
    },
  }),
  false,
);

const outputs = [
  '"07f228e445d37df69c12e6bfdb95c685f2e7e2ddc440713f59d71c6d00b27402"',
  '"3e71c2407160748fd0c768ca1ffd4040ed32c949a84ae98fb67b59bab16f234e"',
  '"23a4b69aad6e639c54cd6845ca6e4d6eb19d632ecc8ae9380416418b6de10d23"',
];
let callIndex = 0;
const report = verifyPublishedRoots({
  issuance,
  runner: () => ({
    status: 0,
    stdout: outputs[callIndex++],
    stderr: "",
  }),
  readSource: "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
});
assert.strictEqual(report.verified, true);

console.log("bucket B gate tests passed");
