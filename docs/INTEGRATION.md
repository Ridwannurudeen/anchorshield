# Integrate AnchorShield In Your Contract

AnchorShield gives Stellar dApps two integration models. Pick the one that
matches your privacy and implementation budget.

| Model                     | Use When                                                                            | Contract Work                                                                                      | Privacy Trade-Off                                                     |
| ------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Model A: attestation read | You want the fastest integration and can tolerate an on-chain account attestation.  | Call `identity_verifier.verify_identity(account)` before your action.                              | The account address is linked to a live attestation until it expires. |
| Model B: per-action proof | You need unlinkable, per-action eligibility with your own nullifier/action binding. | Verify proof + public signals and check issuer/nullifier peers like `gate_payment.verify_and_pay`. | More contract work, but each action can be proven privately.          |

Both models reuse the deployed AnchorShield proof system. You do not build a ZK
circuit or verifier from scratch.

The current testnet deployment IDs are in `apps/web/data/deployments.json`.
At the time this recipe was written, the `identity_verifier` contract is:

```text
CD647AFZSYWVVMBZXNMBIGCADL5FAUDJQDMHJTMVBW5NIGMZOFJKHOB7
```

## Model A: Attestation Read

This is the one-line eligibility model. The user proves once by calling
`identity_verifier.attest(account, proof, pub_signals, policy_id, epoch,
valid_until)`. Your contract then calls `verify_identity(account)` and continues
only if AnchorShield says that account has a live attestation.

Use the same peer-client pattern as the core gates: define the remote interface
you call, then construct the generated client from the configured contract
address. Do not depend on the peer contract crate from your production contract;
that links the peer's exported wasm symbols into your wasm.

```rust
use soroban_sdk::{contractclient, Address, Env};

#[contractclient(name = "IdentityVerifierPeerClient")]
pub trait IdentityVerifierPeer {
    fn verify_identity(env: Env, account: Address);
}

fn require_anchorshield_identity(env: &Env, identity_verifier: &Address, account: &Address) {
    IdentityVerifierPeerClient::new(env, identity_verifier).verify_identity(account);
}
```

In your action:

```rust
account.require_auth();
require_anchorshield_identity(&env, &identity_verifier, &account);
```

If the account is not attested or the attestation is expired, the peer call
reverts and your action does not proceed. See `examples/airdrop_gate` for a
complete claim-gated contract and tests.

## Model B: Per-Action Proof

Use Model B when every action needs its own unlinkable proof and nullifier. Your
contract should depend on the shared helper crate:

```toml
[dependencies]
soroban-sdk = { version = "=26.1.0" }
anchorshield-shared = { path = "../shared" }
```

Then follow the same shape as `contracts/gate_payment/src/lib.rs`:

1. Accept `proof: Proof` and `pub_signals: Vec<Fr>`.
2. Load your policy from `PolicyRegistryPeerClient`.
3. Use `require_signal_u32` and `require_signal_u128` to bind every public
   signal to the exact action your contract is about to perform.
4. Check the issuer root, sanctions root, and revocation root through
   `IssuerRegistryPeerClient`.
5. Check the nullifier through `NullifierRegistryPeerClient`.
6. Check the configured verifier metadata and call `VerifierPeerClient.verify`.
7. Execute your action and mark the nullifier used.

The shared helpers are in `contracts/shared/src/lib.rs`. The production gates
delegate Groth16 verification to the deployed verifier through
`VerifierPeerClient.verify`; the deployed verifier uses the same shared
`verify_proof(env, vk, proof, pub_signals)` helper internally. If you embed a
verification key in your own contract instead of delegating to the deployed
verifier, call `verify_proof` directly and keep the same public-signal checks.

```rust
use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, verify_proof,
    IssuerRegistryPeerClient, NullifierRegistryPeerClient, PolicyRegistryPeerClient,
    Proof, VerifierPeerClient, ACTION_ID, ACTION_TYPE, AMOUNT, CREDENTIAL_ROOT,
    EPOCH, ISSUER_ID, NULLIFIER, POLICY_ID,
};
```

The canonical implementation is `gate_payment.verify_and_pay`: it binds policy,
issuer root, action type, asset id, amount, recipient id, action id, packet hash,
and epoch before transferring value. Copy that structure for your own private
per-action gate.

## Frontend Proof Flow

For Model A, use the generated identity-verifier binding to record the account
attestation after the user has built a valid AnchorShield proof. In this repo,
build `packages/bindings/identity-verifier` and add that package to your dApp.
External dApps can regenerate the same binding from the deployed contract ID.
The binding source exposes `Client.attest({ account, proof, pub_signals,
policy_id, epoch, valid_until })`; the Stellar SDK client options are
`contractId`, `rpcUrl`, `networkPassphrase`, and optional `publicKey` plus a
Freighter-compatible signer.

```js
const sdk = require("@anchorshield/sdk");

async function attestAccount({
  account,
  signTransaction,
  cliArgsPath,
  validUntil,
}) {
  const { Client: IdentityVerifierClient } = await import("identity-verifier");
  const cliArgs = sdk.readJson(cliArgsPath);
  const identity = new IdentityVerifierClient({
    contractId: "CD647AFZSYWVVMBZXNMBIGCADL5FAUDJQDMHJTMVBW5NIGMZOFJKHOB7",
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
    publicKey: account,
    signTransaction,
  });

  const tx = await identity.attest({
    account,
    proof: sdk.formatBindingProof(cliArgs.proof),
    pub_signals: sdk.formatBindingPubSignals(cliArgs.pub_signals),
    policy_id: 303,
    epoch: 12,
    valid_until: BigInt(validUntil),
  });

  return tx.signAndSend();
}
```

`cliArgsPath` is the converted AnchorShield proof-argument JSON shape used in
`testdata/*/cli-args.json`: `{ proof: { a, b, c }, pub_signals: [...] }`. If
your browser builds a raw snarkjs Groth16 proof, convert it first with the same
converter used by the web console in `apps/web/assets/groth16-convert.js`, then
pass the converted `{ a, b, c }` proof to `formatBindingProof`.

For Model B, use `@anchorshield/sdk` to build and format proof artifacts:

```js
const sdk = require("@anchorshield/sdk");

const input = sdk.readJson("testdata/eligibility/input.valid.json");
const verificationKey = sdk.readJson("apps/web/data/verification_key.json");

const request = sdk.createProofRequest({ input });
const generated = await sdk.prove({
  input: request.input,
  wasmPath: "apps/web/proving/eligibility.wasm",
  zkeyPath: "apps/web/proving/eligibility_final.zkey",
  verificationKey,
});

const pubSignals = sdk.formatSorobanPubSignals(generated.publicSignals);
```

For a React payment-style proof submission, the SDK also exposes:

```js
const {
  AnchorShieldGate,
  useAnchorShield,
} = require("@anchorshield/sdk/react");
```

`useAnchorShield` manages Freighter connection state and `submitPaymentProof`.
`AnchorShieldGate` wraps the same submit path in a button component. For custom
contracts, use the core helpers to format the proof and generated binding
package for your contract method.

## Testnet Walkthrough

1. Generate a proof in the AnchorShield console or with `@anchorshield/sdk`.
2. For Model A, call `identity_verifier.attest` on testnet with the user's
   account, proof, public signals, policy id, epoch, and validity timestamp.
3. Deploy and initialize your contract with the testnet `identity_verifier`
   address from `apps/web/data/deployments.json`.
4. Call your gated method. The `examples/airdrop_gate` claim path succeeds only
   for accounts with a live AnchorShield attestation.

No core AnchorShield contracts need to be redeployed for either model.
