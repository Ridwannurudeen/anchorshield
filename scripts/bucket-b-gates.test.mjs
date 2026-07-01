import assert from "node:assert";
import sepClient from "../services/anchor/sep-client.js";
import { validAnchorEvidence } from "./bucket-b-preflight.mjs";
import publishRootsModule from "../services/issuer/publish-roots.js";

const { validateAnchorConfig } = sepClient;
const {
  assertPublishExtendsOnChain,
  decimalRootToHex,
  parseHexRootOutput,
  parseRootCommand,
  publicKeyOrIdentityAddress,
  rootGetterCommands,
  rootReconcileCommands,
  verifyPublishedRoots,
} = publishRootsModule;

const command =
  "stellar contract invoke --id CDR74XLWGRE35SOQ2FHMRXEXLUQWDOUSLLM2ECAW4IIBLRWFGLBBSDDG --source anchorshield-admin --network testnet -- set_root --issuer_id 101 --root 16968264084686815019409457797653750977845222036686396343320997197469327511410 --member_count 1";
const parsed = parseRootCommand(command);
assert.strictEqual(parsed.source, "anchorshield-admin");
assert.strictEqual(parsed.fnName, "set_root");
assert.strictEqual(parsed.issuerId, "101");
assert.strictEqual(parsed.memberCount, "1");
assert.strictEqual(
  decimalRootToHex(parsed.root),
  "2583b277181627271a13db592dd32b857861220ad24cfd8a8d7a3f36e38f4f72",
);
assert.strictEqual(
  parseHexRootOutput(
    '"2583b277181627271a13db592dd32b857861220ad24cfd8a8d7a3f36e38f4f72"',
  ),
  "2583b277181627271a13db592dd32b857861220ad24cfd8a8d7a3f36e38f4f72",
);

const issuance = {
  issuer_id: 101,
  roots: {
    credential_root:
      "16968264084686815019409457797653750977845222036686396343320997197469327511410",
    sanctions_root:
      "39994942323213274039216662394779445131518412504488084715131745479549489087767",
    revocation_root:
      "36194922186915982915970352615194123427043924252243819068188131198562594449181",
  },
  root_publish: {
    admin: "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
  },
  active_member_count: 1,
  expected_previous_roots: {
    credential_root:
      "16968264084686815019409457797653750977845222036686396343320997197469327511410",
    sanctions_root:
      "39994942323213274039216662394779445131518412504488084715131745479549489087767",
    revocation_root:
      "36194922186915982915970352615194123427043924252243819068188131198562594449181",
    active_member_count: 1,
  },
  root_commands: [
    command,
    "stellar contract invoke --id CDR74XLWGRE35SOQ2FHMRXEXLUQWDOUSLLM2ECAW4IIBLRWFGLBBSDDG --source anchorshield-admin --network testnet -- set_sanctions_root --root 39994942323213274039216662394779445131518412504488084715131745479549489087767",
    "stellar contract invoke --id CDR74XLWGRE35SOQ2FHMRXEXLUQWDOUSLLM2ECAW4IIBLRWFGLBBSDDG --source anchorshield-admin --network testnet -- set_revocation_root --issuer_id 101 --root 36194922186915982915970352615194123427043924252243819068188131198562594449181",
  ],
};

assert.deepStrictEqual(
  rootGetterCommands({ issuance }).map((check) => check.name),
  [
    "credential_root",
    "credential_member_count",
    "sanctions_root",
    "revocation_root",
  ],
);
assert.deepStrictEqual(
  rootReconcileCommands({ issuance }).map((check) => check.name),
  [
    "previous_credential_root",
    "previous_credential_member_count",
    "previous_sanctions_root",
    "previous_revocation_root",
  ],
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
  '"2583b277181627271a13db592dd32b857861220ad24cfd8a8d7a3f36e38f4f72"',
  "1",
  '"586c55cc9dd3d2e6014c43c95ece4fe60e5fff5db30a5f9f4d483c7fdba98517"',
  '"50059997fe5d78d40f052c296a8971b65cc5bd850e66e836193c5ccd216be71d"',
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

callIndex = 0;
const reconcile = assertPublishExtendsOnChain({
  issuance,
  runner: () => ({
    status: 0,
    stdout: outputs[callIndex++],
    stderr: "",
  }),
  readSource: "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
});
assert.strictEqual(reconcile.checked, true);
assert.strictEqual(reconcile.checks.length, 4);

assert.throws(
  () =>
    assertPublishExtendsOnChain({
      issuance,
      runner: () => ({
        status: 0,
        stdout:
          '"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"',
        stderr: "",
      }),
      readSource: "GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U",
    }),
  /previous_credential_root mismatch/,
);

console.log("bucket B gate tests passed");
