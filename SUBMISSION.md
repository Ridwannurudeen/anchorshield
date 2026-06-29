# AnchorShield — Submission

> ZK compliance gates for Stellar payments and real-world assets: prove KYC, sanctions-absence,
> revocation-absence, freshness, and action-binding **without putting identity on-chain**.

- **Live demo:** https://anchorshield.gudman.xyz
- **Repo:** https://github.com/Ridwannurudeen/anchorshield (branch `build/m0-toolchain`)
- **Network:** Stellar testnet (Soroban / Protocol 26)
- **Demo video:** _pending recording_

> Note: structured to the dimensions a "Real-World ZK on Stellar" track implies. Confirm the
> exact rubric on the DoraHacks page and reorder to match.

## The problem

Regulated money movement — cross-border payments, tokenized real-world assets — requires
compliance checks: Is the party KYC-verified? Sanctioned? Eligible for this corridor? Doing this
on-chain normally means publishing identity data permanently and publicly. AnchorShield lets a
party **prove they passed every check without revealing any of the underlying identity data.**

## The solution

A reusable on-chain compliance primitive. A user's wallet generates a Groth16 proof in the
browser asserting: valid credential, not on the deny-list, not revoked, still fresh, and bound to
*this specific* action. The Stellar contract verifies the proof and only then lets the transaction
proceed. Private credential fields and Merkle witnesses never leave the device.

It is demonstrated through two gates over one shared primitive: a **travel-rule payment** gate and
a **regulated-asset (RWA) mint** gate.

## Why ZK is load-bearing

The gate **cannot execute without a valid proof.** `gate_payment.verify_and_pay` checks the
Groth16 proof, policy fields, on-chain-committed roots, action fields, packet hash, epoch, and
nullifier before moving any value. A forged proof fails with `InvalidProof`; a replayed proof
fails through the nullifier registry. The public statement is limited to proof signals, action
data, committed roots, packet hash, nullifier, and action binding — everything identifying stays
off-chain.

## What is real (verified)

- **In-browser Groth16 proving** that verifies on a real Soroban verifier (frozen, versioned VK).
- **Real value movement on testnet:** `verify_and_pay` SAC transfer; action-bound RWA mint via a
  one-time, proof-bound authorization consumed by a compliance adapter.
- **Real sanctions data:** the on-chain sanctions/revocation roots are screened against the **live
  OFAC SDN list**; an OFAC-matched user provably cannot generate a passing proof, a clean user can.
- **Real anchor seam:** verified live against the SDF public reference anchor through SEP-10 auth,
  SEP-12 customer registration, and a real SEP-38 quote.
- **Eight Soroban contracts** (verifier, two gates, three registries, identity verifier, RWA
  adapter) **plus a timelock/multisig governance contract**, 40 contract tests, and adversarial
  security reviews with findings resolved or documented as deferred risks (`docs/SECURITY_REVIEW.md`).

## Honest scope (Real vs Mock)

The cryptography, on-chain verification, value transfer, and sanctions data are real on testnet.
Stand-ins, clearly marked: the roster mixes a real Sumsub-KYC-backed clean user with two synthetic
blocked-path fixtures (sanctioned, revoked); `investor_type` is issuer-asserted, not independently
verified; the final SEP-31 receive-create needs a configured/licensed anchor; nothing is on mainnet
(which requires an external audit and a production trusted-setup ceremony). Full breakdown in `README.md`.

## Stellar / Soroban integration

soroban-sdk 26.1.0; BLS12-381 Groth16 verified on-chain; real Stellar Asset Contract transfer;
OpenZeppelin SEP-57 token for the RWA mint; admin-pinned + frozen verification key; per-issuer
root registries with fail-closed root binding.

## Try it

```bash
npm install
node services/issuer/test.js          # issuer + end-to-end fullProve gate (11/11)
bash scripts/test.sh                   # contract workspace (run in WSL): 40 tests
npm run m3:web                         # browser demo at http://localhost:4173
```

Or open https://anchorshield.gudman.xyz/console and run a payment proof in the browser.

## Live on-chain artifacts

Contract IDs and transaction links (verifier, gates, registries, issuer-root publish txs, payment
and RWA mint txs) are in `README.md` and `deployments/testnet-hardened.json`, each linking to
Stellar Expert.

## Real-world path

Documented and partly built: real KYC issuer integration, licensed anchor (SEP-10/31/38),
multisig/timelock governance (contract built; cutover runbook in `docs/MAINNET_RUNBOOK.md`),
production ceremony, and external audit before mainnet. See `docs/ROADMAP.md`.
