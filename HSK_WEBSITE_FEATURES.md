# Features grabbed from the HSK Passport live site → AnchorShield (Stellar-aligned)

Source: https://hskpassport.gudman.xyz/ (fetched 2026-07-01). Mapped against AnchorShield's actual
code. Goal: adopt what adds value and fits Stellar/Soroban; skip HashKey-specific bits.

## Already covered (do NOT rebuild)
- ZK verify without on-chain PII; **caller/action-bound proofs**; **per-action nullifiers**;
  **revocation + expiry**; **real Sumsub KYC**; **published npm SDK**; **governance timelock/multisig
  contract**; **credential freshness** (partial) — all present in AnchorShield.
- Already in `ONBOARDING_CUTOVER_SCOPE.md` follow-ups: Sumsub **webhook HMAC + replay** (B6),
  **issuer directory** (B7), **freshness range-check hardening** (B2), **issuer staking/slashing** (B3),
  React `<AnchorShieldGate>` (B9, done), observability/benchmarks incl. gas/fee metrics (B8).
- HashKey-specific, **SKIP** (no Stellar analog worth it): IKycSBT soulbound bridge, .key DID bridge.
  (A Stellar-native analog would be a SEP-8 regulated-asset / SEP-12 KYC bridge — optional, low priority.)

## ⭐ NEW — highest value: **Policy Composer** (the crown jewel)
HSK's site headline dev tool: *"generates deployable Solidity contracts, React gates, and Hardhat
tests in 30 seconds"* — "One require line. Full compliance." AnchorShield has **no** equivalent, and it
is exactly the piece that turns AnchorShield from "integrate us for payments/RWA" into **"integrate us
to gate ANY action."** This directly closes the generic-gate gap.

**Build for Stellar/Soroban:** a Composer (web tool + CLI in `packages/cli`) that takes a policy spec
(issuer_id, required attrs: kyc/country-set/min-age/investor-tier, freshness window, min anonymity set)
and emits: (1) a **deployable Soroban gate contract** (Rust) wired to the AnchorShield verifier +
issuer/policy/nullifier registries — parameterized from the existing `gate_payment`/`identity_verifier`
as templates; (2) a **`<AnchorShieldGate>` React snippet** using `@anchorshield/sdk`; (3) **contract
tests**. Output is copy-paste, deploy-ready. This is the single best thing to take from HSK.

## NEW — developer experience / "integrate us" surface
- **Hosted `/developers` + `/quickstart` pages** with the one-liner integration story. HSK shows a
  literal `require(passport.verifyCredential(25, proof), "KYC required")`; AnchorShield's Soroban analog
  is a `verifier.verify_proof(...)` + policy/root check — publish the copy-paste snippet + a real
  quickstart. AnchorShield today has only a thin `docs/SDK.md` and no hosted dev page.
- **A minimal example dApp** (airdrop or lending gate) showing end-to-end third-party integration —
  HSK documents sybil-resistant airdrops + tiered (retail vs accredited) lending as use cases. Ship one
  as a runnable sample against the AnchorShield verifier.
- **Publish the contract bindings** (`packages/bindings/*` are 0.0.0/unpublished) so integrators get
  typed Soroban args, not just the raw contract id.

## NEW — product pages (parity + polish)
- **User credential Dashboard** ("my credentials"): a wallet-connected page showing the wallet's
  credential status/attributes/freshness (pairs with the new resume/recognize-enrolled-wallet flow).
- **Issuers page** (public directory; = B7) + **Governance inspection page** (AnchorShield has the
  governance contract but no UI surfacing timelock/threshold/pending actions) + **Ecosystem/Partners**
  + **Roadmap** pages. HSK exposes all of these; AnchorShield surfaces none.
- **Status/trust badges** on the site ("Protocol 26 · N tests · real Sumsub + ZK freshness · verifier
  frozen") — HSK shows "v6 live · 74 tests · real Sumsub + ZK freshness".

## NEW — positioning / messaging (cheap, high-leverage)
Adopt HSK's framing, Stellar-ified, on the landing page:
- **"The default compliance layer for Stellar"** (HSK: "…for HashKey Chain").
- **"Verify once with a trusted issuer. Privately prove KYC, accreditation, or jurisdiction to any
  Stellar dApp. Reveal nothing on-chain."**
- **"We're not replacing Stellar's SEP compliance stack — we're making it reusable and private."**
- **"0 bytes PII on-chain by design."** / **"One require line. Full compliance."**

## Recommended order
1. **Policy Composer** (unlocks arbitrary-action integration — the biggest value + most Stellar-aligned).
2. Developer page + quickstart + one example dApp + publish bindings.
3. User Dashboard + Issuers/Governance/Ecosystem pages + landing-page messaging.
4. (B6/B7/B2/B3 already queued.)
