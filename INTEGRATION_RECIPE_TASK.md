# Task for Codex — "Integrate AnchorShield in your own contract" recipe + example dApp

Branch: `feat/integration-recipe` off `main`. Goal: make "any Stellar dApp can gate on AnchorShield
eligibility instead of building ZK from scratch" **real and demonstrable** — a documented recipe plus one
runnable example. The on-chain primitives already exist (verified below); this is mostly docs + a working
example, NOT new core contracts. Do NOT modify any deployed/core contract.

## Verified starting facts (read these first, confirm they still hold)
- `contracts/identity_verifier/src/lib.rs`
  - `attest(env, account, proof, pub_signals, policy_id, epoch, valid_until) -> Result<(),Error>` (~:356):
    user proves once; validates the proof, marks the nullifier, stores an attestation expiry for `account`.
  - `verify_identity(env, account) -> Result<(),Error>` (~:527): read-only eligibility check — returns
    `Ok` if the account holds a live attestation, else `NotEligible`/`Expired`. **This is the "one require
    line" a third-party contract calls.**
  - `attestation_expiry(env, account) -> Option<u64>` (~:546): read the expiry.
- `contracts/shared/src/lib.rs`: reusable `verify_proof(env, vk, proof, pub_signals) -> Result<bool,_>`
  (~:123) + `require_signal_u32/u128`, `signal`, `bool_as_u32`. Both `gate_payment` and `gate_rwa` depend on
  it via `anchorshield-shared = { path = "../shared" }`. The file also documents the **cross-contract peer
  client** pattern (gates call peers through generated clients, NOT by depending on peer crates — avoids
  duplicate-symbol wasm link errors). **Follow that exact pattern** for any cross-contract call.
- `contracts/gate_payment/src/lib.rs` `verify_and_pay(...)` (~:346) is the canonical per-action gate:
  load policy from policy_registry → assert every public signal against the policy → check credential root
  in issuer_registry → anonymity-set floor → nullifier → action. Use as the template for Model B.
- There is **no `examples/` directory** yet. `docs/SDK.md` exists but is thin. `packages/sdk` (published
  `@anchorshield/sdk`) exposes proof build/verify/submit + `formatSorobanPubSignals`/`normalizePublicSignals`;
  `packages/sdk/src/react.js` has `<AnchorShieldGate>` + `useAnchorShield`. Testnet deployment IDs are in
  `apps/web/data/deployments.json` (verifier `CBZQCAVZ…`, identity_verifier `CAZGAQYF…`, etc. — re-read, do
  not hardcode from memory).

## Deliverable 1 — `docs/INTEGRATION.md` (the recipe)
Document **both** integration models, with a clear "which do I use" up top:
- **Model A — attestation read (simplest).** User attests once (`identity_verifier.attest`); your contract
  makes ONE cross-contract call to `verify_identity(account)` and proceeds only on `Ok`. Trade-off: easiest to
  integrate; the account address is linked on-chain to its attestation (no per-action unlinkability).
  Show the exact Soroban peer-client call (follow the peer-client pattern from `shared`) — the literal
  "one require line" equivalent.
- **Model B — per-action proof (private).** Your contract depends on `anchorshield-shared`, takes the
  `proof` + `pub_signals`, calls `verify_proof` + `require_signal_*`, checks the credential root via the
  issuer_registry peer client and the nullifier via the nullifier_registry peer client — copying
  `gate_payment.verify_and_pay`. Trade-off: unlinkable per-action, sybil-resistant; more integration work.
- A short frontend section: how the dApp gets the proof/attestation client-side with `@anchorshield/sdk`
  (`generateProof`, `formatSorobanPubSignals`) and the `<AnchorShieldGate>` component.
- Link it from `docs/SDK.md`.

## Deliverable 2 — `examples/airdrop_gate` (the runnable example)
A minimal, real, testnet-wired example dApp proving a third party can integrate without ZK plumbing.
- **Contract** `examples/airdrop_gate/`: a new Soroban contract with `claim(env, account, ...)` that
  (a) calls `verify_identity(account)` on the identity_verifier via the peer-client pattern, rejecting
  `NotEligible`/`Expired`, and (b) enforces one-claim-per-account (simple persistent flag — this is the
  example's own anti-double-claim, distinct from AnchorShield nullifiers). Keep it tiny and legible; match
  the style/error-enum/`init`-admin pattern of the existing contracts. This is the "integrate us for
  anything" proof in ~100 lines.
- **Tests** `examples/airdrop_gate/src/test.rs`: register a mock/real identity_verifier, attest an account,
  assert `claim` succeeds for an attested account and fails for an unattested/expired one, and that a second
  claim by the same account is rejected. Use the same test harness style as `contracts/*/src/test.rs`.
- Add the crate to the workspace `Cargo.toml` members so `cargo test` picks it up.
- A short `examples/airdrop_gate/README.md`: build, deploy-to-testnet, and how a user attests then claims,
  referencing the deployment IDs from `apps/web/data/deployments.json`.

## Out of scope (do NOT do)
- No Policy Composer (that's the later automation layer).
- No changes to deployed core contracts, no redeploy of core, no on-chain broadcast, no live/staging server
  changes, no mainnet. Testnet only. A Model B second example is optional stretch — skip if it grows scope.

## Acceptance
- `cargo build` (workspace) + `cargo test -p airdrop-gate` (or the crate's chosen name) green; existing
  workspace tests still green.
- `docs/INTEGRATION.md` steps reproduce against testnet (attest → claim) — describe the exact CLI/SDK calls.
- No modification to `contracts/{verifier,identity_verifier,gate_payment,gate_rwa,issuer_registry,
  policy_registry,nullifier_registry,governance,rwa_compliance_adapter}` core logic.
- Leave the work committed on `feat/integration-recipe` (do not merge, do not push tags). Claude/user reviews.
