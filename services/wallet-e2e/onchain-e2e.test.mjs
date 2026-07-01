import assert from "node:assert";
import fs from "node:fs";
import { createRequire } from "node:module";

import {
  buildEnrolledPaymentInput,
  buildPaymentInvocation,
  createEnrollmentContext,
  deriveWalletSecret,
  dryRunSubmit,
  enrollWallet,
  onboardingSecretMessage,
} from "./onchain-e2e.mjs";

const require = createRequire(import.meta.url);
const StellarSdk = require("@stellar/stellar-sdk");
const sdk = require("../../packages/sdk/src");
const { decimal, poseidon255 } = require("../issuer/lib/zk-tree");

const keypair = StellarSdk.Keypair.random();
const context = createEnrollmentContext({
  broadcast: false,
  now: () => "2026-07-01T00:00:00.000Z",
});

try {
  const derived = deriveWalletSecret({
    keypair,
    issuerId: context.store.issuerId,
  });
  assert.strictEqual(derived.address, keypair.publicKey());
  assert.strictEqual(
    derived.message,
    onboardingSecretMessage({
      issuerId: context.store.issuerId,
      address: keypair.publicKey(),
    }),
  );
  assert.strictEqual(
    derived.userCommitment,
    decimal(poseidon255([derived.userSecret, context.store.issuerId])),
  );

  const enrolled = await enrollWallet({
    store: context.store,
    wallet: keypair.publicKey(),
    userCommitment: derived.userCommitment,
  });
  assert.strictEqual(enrolled.root_publish.mode, "dry-run");
  assert.strictEqual(enrolled.credential.attributes.country, "566");
  assert.strictEqual(enrolled.credential.attributes.age, "22");
  assert.strictEqual(fs.existsSync(context.statePath), true);

  const input = buildEnrolledPaymentInput({
    store: context.store,
    wallet: keypair.publicKey(),
    userSecret: derived.userSecret,
  });
  assert.strictEqual(input.user_secret, derived.userSecret);
  assert.strictEqual(input.user_commitment, derived.userCommitment);
  assert.strictEqual(input.credential_root, undefined);
  assert.strictEqual(input.sanctions_root, enrolled.credential.sanctions_root);
  assert.strictEqual(
    input.revocation_root,
    enrolled.credential.revocation_root,
  );
  assert.strictEqual(input.policy_id, "202");
  assert.strictEqual(input.action_type, "0");
  assert.strictEqual(input.amount, "250");

  const fixtureInput = sdk.readJson("testdata/eligibility/input.valid.json");
  const proof = sdk.readJson("testdata/eligibility/proof.json");
  const publicSignals = sdk.readJson("testdata/eligibility/public.json");
  const invocation = buildPaymentInvocation({
    proof,
    publicSignals,
    input: fixtureInput,
  });
  assert.strictEqual(invocation.scVals.length, 9);
  assert.strictEqual(
    dryRunSubmit({ invocation }).simulation,
    "local-soroban-args",
  );

  assert.throws(
    () => createEnrollmentContext({ broadcast: true }),
    /ANCHORSHIELD_ROOT_PUBLISH_APPROVED/,
  );

  console.log("on-chain wallet E2E runner tests passed");
} finally {
  context.cleanup();
}
