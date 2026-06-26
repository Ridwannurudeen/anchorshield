# SDK & CLI Guide

## Scope

M6 ships three developer surfaces:

- `packages/sdk`: dependency-free CommonJS helpers for public-signal parsing, action-binding checks, converter argument formatting, implicit Stellar CLI argument formatting, generated-binding argument formatting, and local proof wrappers.
- `packages/cli`: dependency-free `anchorshield` CLI for inspecting proof artifacts, validating action binding, viewing compliance events, checking disclosure summaries, and printing Stellar invoke commands.
- `packages/bindings/gate-payment` and `packages/bindings/gate-rwa`: generated TypeScript bindings from `stellar contract bindings typescript`.

The package is intentionally private until package naming, production ceremony, mainnet deploy, and publishing approval are complete.

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

This matches `docs/M1.md`, `contracts/gate_payment`, and `contracts/gate_rwa`.

## SDK Use

```js
const sdk = require("./packages/sdk/src");

const input = sdk.readJson("testdata/eligibility/input.valid.json");
const publicSignals = sdk.readJson("testdata/eligibility/public.json");
const cliArgs = sdk.readJson("testdata/eligibility/cli-args.json");

sdk.assertPaymentAction(input, publicSignals);

const invokeArgs = sdk.buildPaymentInvokeArgs(cliArgs, input);
// invokeArgs is shaped for the generated gate-payment Client.verify_and_pay method.
```

For generated bindings, `@stellar/stellar-sdk@14.5.0` defines `u256` as `bigint`, so `buildPaymentInvokeArgs` and `buildRwaInvokeArgs` convert public signals and hash fields to `bigint`.

`formatSorobanPubSignals` preserves the converter fixture shape (`[{ "u256": "..." }]`). `formatImplicitCliPubSignals` returns the plain decimal-string array required by the current `stellar contract invoke` implicit CLI's `--pub_signals-file-path`.

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
  --contract CD4FWZ5HH6H4XDSWVVQCZ354LWHJVCN6TV72UEHTLOMKQPKJAGHU5WGE \
  --cli-args testdata/eligibility/cli-args.json \
  --input testdata/eligibility/input.valid.json \
  --source-account G...
```

The command writes split argument files under `.m6/invoke/payment` by default and prints a `stellar contract invoke ... --send no` command using the verified implicit CLI file-path flags. It does not submit transactions or publish packages.

## Regenerate Bindings

Verified with `stellar 27.0.0`:

```bash
stellar contract bindings typescript \
  --wasm contracts/gate_payment/target/wasm32v1-none/release/anchorshield_gate_payment.wasm \
  --output-dir packages/bindings/gate-payment \
  --overwrite

stellar contract bindings typescript \
  --wasm contracts/gate_rwa/target/wasm32v1-none/release/anchorshield_gate_rwa.wasm \
  --output-dir packages/bindings/gate-rwa \
  --overwrite
```

To use a generated binding package directly, run `npm install && npm run build` inside the specific binding directory.
