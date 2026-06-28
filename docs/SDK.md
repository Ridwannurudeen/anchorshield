# SDK And CLI Guide

## Scope

AnchorShield ships three local developer surfaces:

- `packages/sdk`: CommonJS helpers for public-signal parsing, action-binding checks, proof generation, generated-binding argument formatting, and Freighter/RPC payment submission.
- `packages/cli`: `anchorshield` CLI for inspecting proof artifacts, validating action binding, viewing compliance events, checking disclosure summaries, and printing Stellar invoke commands.
- `packages/bindings/*`: generated TypeScript bindings for `gate-payment`, `gate-rwa`, `identity-verifier`, and `rwa-compliance-adapter`.

The package is private until package naming, production ceremony, mainnet deploy, and publishing approval are complete.

## Public Signal Order

The SDK exports the canonical order as `PUBLIC_SIGNAL_NAMES`:

1. `credential_root`
2. `packet_hash`
3. `nullifier`
4. `action_binding`
5. `issuer_id`
6. `policy_id`
7. `kyc_required`
8. `sanctions_required`
9. `allowed_country`
10. `min_age`
11. `min_investor_type`
12. `action_type`
13. `asset_id`
14. `amount`
15. `recipient`
16. `action_id`
17. `epoch`
18. `sanctions_root`
19. `revocation_root`

Indices 0-16 are byte-stable from the original payment/RWA circuit. Root signals were appended at indices 17 and 18.

## SDK Use

```js
const sdk = require("./packages/sdk/src");

const input = sdk.readJson("testdata/eligibility/input.valid.json");
const verificationKey = sdk.readJson("apps/web/data/verification_key.json");

const request = sdk.createProofRequest({ input });
const generated = await sdk.prove({
  input: request.input,
  wasmPath: "apps/web/proving/eligibility.wasm",
  zkeyPath: "apps/web/proving/eligibility_final.zkey",
  verificationKey,
});

const args = sdk.paymentContractArgs({
  proof: generated.proof,
  publicSignals: generated.publicSignals,
  action: request.action,
});
```

`@stellar/stellar-sdk@14.6.1` represents `u256` binding values as `bigint`, so the SDK converts public signals and proof hashes before passing them to generated bindings.

`submitPaymentProof` performs the browser payment path: construct `verify_and_pay`, simulate through Soroban RPC, request Freighter signing, submit, and poll the transaction.

## CLI Use

```bash
node packages/cli/anchorshield.js inspect-public --public testdata/eligibility/public.json
node packages/cli/anchorshield.js validate-action --input testdata/rwa/input.valid.json --public testdata/rwa/public.json
node packages/cli/anchorshield.js events --file apps/web/data/compliance-events.json
node packages/cli/anchorshield.js disclosure verify --summary testdata/disclosure/summary.json
```

Print a testnet payment invoke command:

```bash
node packages/cli/anchorshield.js gate payment \
  --contract CCS7UJWD6OP2DGKEGLUCI55SROUC4A3XJ3G4QDQN35HYV3CNT47F5U3R \
  --cli-args testdata/eligibility/cli-args.json \
  --input testdata/eligibility/input.valid.json \
  --source-account G...
```

The command writes split argument files under `.m6/invoke/payment` by default and prints a `stellar contract invoke ... --send no` command. It does not submit transactions or publish packages.

## Regenerate Bindings

Verified with Stellar CLI 27:

```bash
stellar contract bindings typescript --wasm contracts/gate_payment/target/wasm32v1-none/release/anchorshield_gate_payment.wasm --output-dir packages/bindings/gate-payment --overwrite
stellar contract bindings typescript --wasm contracts/gate_rwa/target/wasm32v1-none/release/anchorshield_gate_rwa.wasm --output-dir packages/bindings/gate-rwa --overwrite
stellar contract bindings typescript --wasm contracts/identity_verifier/target/wasm32v1-none/release/anchorshield_identity_verifier.wasm --output-dir packages/bindings/identity-verifier --overwrite
stellar contract bindings typescript --wasm contracts/rwa_compliance_adapter/target/wasm32v1-none/release/anchorshield_rwa_compliance_adapter.wasm --output-dir packages/bindings/rwa-compliance-adapter --overwrite
```

To use a generated binding package directly, run `npm install && npm run build` inside the specific binding directory.
