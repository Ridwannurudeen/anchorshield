# Circuit + freshness hardening batch (pre-mainnet, ceremony-bearing)

Verified against the working tree 2026-07-01 (`release/onboarding-prod`, circuits/eligibility.circom 337
lines). This batch changes the VK → requires recompile + ceremony + fixture regen + testnet redeploy
(broadcast approval-gated). Execute in a focused session; it invalidates every existing proof fixture.

## Verified current state (do not re-do what exists)
- **B2's circuit-side ask is ALREADY IMPLEMENTED.** eligibility.circom has `Num2Bits(64)` range
  constraints on `epoch`/`issued_at`/`expires_at` (:188-195) and two-sided range-checked comparisons
  `issuedCheck: issued_at <= epoch` (:236-239) + `expiryCheck: epoch <= expires_at` (:241-244) — exactly
  the HSK "range-checked comparison" pattern B2 in ONBOARDING_CUTOVER_SCOPE.md asks for. The missing B2
  acceptance item is only the **negative circuit test** (expired credential cannot produce a passing
  proof) — add it without touching constraints.
- **The REAL freshness gap is contract-side, not circuit-side:** in `gate_payment.verify_and_pay`,
  `epoch` is a caller-supplied arg that is only *bound* (`require_signal_u32(EPOCH, epoch)` :400), never
  anchored to ledger time. A caller can replay an old epoch value, so in-circuit expiry checks compare
  against a number the prover's caller picks. (The RWA path is already time-anchored: identity_verifier
  clamps `valid_until` to `env.ledger().timestamp() + MAX_ATTESTATION_TTL` :731 and checks timestamps on
  use :506/:534.)
- **`sanctions_required` is decorative in-circuit:** it gets `Boolean()` (:177) but the sanctions
  ExclusionProof (:276-282) is enforced unconditionally; only `kyc_required` gates its check
  (`kyc_required * (1 - kyc_passed) === 0` :218). Fails safe (stricter), but policy flag ≠ behavior.

## Work items

### 1. Gate `sanctions_required` in-circuit (the ceremony-bearing change)
Make the sanctions exclusion enforced iff `sanctions_required == 1`, mirroring how kyc gating works but
for a Merkle sub-proof: the clean pattern is to multiplex the root equality — compute the exclusion
proof root as today, then constrain `sanctions_required * (computed_root - sanctions_root) === 0`
(flag=0 → constraint vacuous; flag=1 → roots must match). Keep the witness inputs required either way
(prover supplies a dummy path when not required — document that the JS witness builder
services/issuer/enrollment-store.js `buildProofInput` must then emit a valid-or-dummy path per policy).
IMPORTANT design review point: ensure a flag=0 proof cannot be replayed against a flag=1 policy — the
contract already binds SANCTIONS_REQUIRED to the policy (require_signal :387-392 area), so the policy
pins the flag; verify that binding stays.
Decide-and-document alternative: drop the flag entirely and declare sanctions always-on (simpler, no
witness changes; requires removing the field from Policy — larger contract API change). RECOMMENDED:
implement the multiplex gating (keeps Policy API stable).

### 2. Anchor `epoch` to ledger time in gate_payment (contract-only, NO ceremony)
Add an epoch-window check in `verify_and_pay`: derive `current_epoch = env.ledger().timestamp() /
EPOCH_SECONDS` (pick EPOCH_SECONDS to match how the web/demo derives epochs — READ
apps/web/assets/app.js epoch derivation FIRST; the demo uses preset epochs, so this changes demo UX:
the web flow must derive the same time-based epoch) and require `epoch` within ±1 of it. This is what
makes the in-circuit `epoch <= expires_at` an actual freshness guarantee. Rides the
feat/pre-mainnet-hardening redeploy batch. Add tests: stale epoch rejected, current accepted.

### 3. Negative circuit tests (B2 acceptance, no constraint changes)
Witness tests proving: expired credential (epoch > expires_at) fails, not-yet-issued (epoch <
issued_at) fails, and (after item 1) sanctioned+required fails while sanctioned+not-required passes.
Wire into the existing circuit test runner (scripts/m1-circuit-smoke.js pattern).

### 4. Ceremony + artifact regen + redeploy (after 1 is merged)
scripts/ceremony.sh (power-16 BLS12-381, fresh entropy, beacon) → regenerate
testdata/{eligibility,rwa}/* fixtures + apps/web/proving/{eligibility.wasm,eligibility_final.zkey} +
apps/web/data/verification_key.json + SRI updates for changed web assets → redeploy verifier (+ any
contract from feat/pre-mainnet-hardening in the same batch) → re-pin VK on-chain → full e2e
(services/wallet-e2e) + live web revalidation. ALL broadcasts approval-gated. Fixture regen invalidates
packages/cli generated-crate tests' fixtures and the enrollment-store template — re-run everything.

## Sequencing
Items 2+3 are safe now (no VK change). Item 1 then 4 together. Combine with the
feat/pre-mainnet-hardening contract redeploy so testnet gets ONE coordinated cutover.
