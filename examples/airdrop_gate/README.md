# AnchorShield Airdrop Gate Example

This example is the smallest integration path: a third-party Soroban contract
checks an AnchorShield account attestation before allowing an action.

It uses the live testnet `identity_verifier` address from
`apps/web/data/deployments.json`:

```text
identity_verifier = CAZGAQYFM2NMHJU2AW4HIUP3DFAKOG52NPKOSDFGDTSYBO6QBSTDEPRG
network = testnet
```

## Build And Test

```bash
cargo build -p airdrop-gate
cargo test -p airdrop-gate
```

## Deploy To Testnet

Build the WASM and deploy it with Stellar CLI:

```bash
cargo build -p airdrop-gate --target wasm32v1-none --release
stellar contract deploy \
  --wasm target/wasm32v1-none/release/airdrop_gate.wasm \
  --source-account <ADMIN_SECRET_OR_PROFILE> \
  --network testnet
```

Initialize it with your admin and the deployed AnchorShield identity verifier:

```bash
stellar contract invoke \
  --id <AIRDROP_GATE_CONTRACT_ID> \
  --source-account <ADMIN_SECRET_OR_PROFILE> \
  --network testnet \
  -- \
  init \
  --admin <ADMIN_PUBLIC_KEY> \
  --identity_verifier CAZGAQYFM2NMHJU2AW4HIUP3DFAKOG52NPKOSDFGDTSYBO6QBSTDEPRG
```

## User Flow

1. The user creates an AnchorShield attestation by calling
   `identity_verifier.attest` with a valid proof and public signals.
2. The user claims from this example:

```bash
stellar contract invoke \
  --id <AIRDROP_GATE_CONTRACT_ID> \
  --source-account <USER_SECRET_OR_PROFILE> \
  --network testnet \
  -- \
  claim \
  --account <USER_PUBLIC_KEY>
```

The example contract calls `verify_identity(account)` on AnchorShield and then
sets its own one-claim-per-account flag. That claim flag is application state;
it is separate from AnchorShield nullifiers.
