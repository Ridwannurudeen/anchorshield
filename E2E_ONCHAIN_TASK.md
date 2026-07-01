# Task for Codex — On-chain fresh-wallet E2E runner (testnet proof-of-life)

Branch: `release/onboarding-prod`. This is the last technical gate before the production swap
(`ONBOARDING_CUTOVER_SCOPE.md` Part A3 acceptance). Build a **non-interactive** script that proves a
brand-new wallet can go enroll → prove → submit and have its **depth-16 Groth16 proof verified
on-chain** — no Freighter UI, no browser Sumsub.

## Already verified on-chain (2026-07-01, read-only queries — do NOT redeploy)
The depth-16 stack is live, frozen, admin-owned, and proven — Step 1 is DONE:
- verifier `CAOEADWQGIZH3JWK3PRVLB3DRYNUTLL5GGEBI3P4UQ4T7USWADRVW3XZ` → `is_frozen=true`, `circuit_version=1`
- issuer_registry `CDR74XLWGRE35SOQ2FHMRXEXLUQWDOUSLLM2ECAW4IIBLRWFGLBBSDDG` → admin `GAJJW5XC…35U` (WSL alias `anchorshield-m0`, ~9762 XLM); `root(101)=2583b277…` (== expected `16968264…`), `sanctions_root=586c55cc…`, `revocation_root(101)=50059997…`, `pending_admin`=none
- gate_payment `CB5DKGBSBPARDD64E4BRJVTLOWL76OZAQRAIJOJX5RT6Y42K54NTYJKS`, native_sac `CDLZFC3S…`, identity_verifier `CBVZ56BA…`
- recorded `verify_and_pay_tx fa40b339…` is on-chain `successful:true` (ledger 3365321) — the gate already verified a depth-16 proof. Full IDs in `deployments/testnet-hardened.json`.

## Deliverable
`services/wallet-e2e/onchain-e2e.mjs` + `npm run wallet:e2e:onchain`. **Default = DRY-RUN** (build
witness + local `snarkjs` prove/verify + simulate submit; NO broadcast). Real broadcasts only when
`ANCHORSHIELD_E2E_BROADCAST=1` (Claude/user runs that; you build+test to dry-run green only).

## Flow (reuse existing helpers — do NOT reinvent poseidon/tree/convert)
1. **Fresh wallet:** generate a Stellar keypair (`@stellar/stellar-sdk`); fund via friendbot on testnet.
2. **Wallet-derived secret (match the browser exactly):** sign the *same* domain-separated message the
   browser signs (see `apps/web/assets/app.js` `deriveOnboardingSecret:940` + `digestField:240`), then
   `user_secret = digestField(...)`, `userCommitment = poseidon255T3(user_secret, issuer_id)`. Reuse the
   node poseidon255 in `services/issuer/lib/zk-tree.js` (it reads the same `poseidon255_constants.circom`,
   so it can't drift from the browser `data/poseidon255-t3.json`). A mismatch here = proof silently fails.
3. **Enroll (operator-direct, KYC-gate bypassed — document it):** call `enrollment-store.js`
   (`credentialFromKyc:116` + `buildEnrollmentView:166` + `enroll`) with GREEN attributes
   (`country=566, age, kyc_passed=1` — reuse the real `clean-demo-user` attrs from `data/roster.json`).
   This appends the wallet's leaf, rebuilds the depth-16 tree, and publishes the new credential root
   on-chain via the signer (`services/signer/`). The HTTP `/api/enroll` Sumsub-GREEN gate is bypassed on
   purpose (the live `/issuer` Sumsub flow already proves that gate); state clearly in output + the PR
   that this runner tests the crypto+on-chain path, not the KYC gate.
   - Broadcast the `set_root` only under `ANCHORSHIELD_E2E_BROADCAST=1` with `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1`
     + `SIGNER_TOKEN`. `STELLAR_NO_CACHE=true`; one clean tx; if publishing multiple roots, ≥6-9s gap
     (TxBadSeq). Capture the `set_root` tx hash.
4. **Witness:** build the full circuit input for the enrolled wallet with `issue.js buildProofInput:115`
   (credential Merkle path from the NEW tree + sanctions/revocation non-membership + action binding +
   packet hash for a **payment** action). The path MUST correspond to the just-published on-chain root.
5. **Prove:** `snarkjs.groth16.fullProve(input, apps/web/proving/eligibility.wasm,
   apps/web/proving/eligibility_final.zkey)`; verify locally against `apps/web/data/verification_key.json`.
6. **Submit:** convert to Soroban form (reuse `apps/web/assets/groth16-convert.js` node/UMD path, and/or
   `packages/sdk` `submitPaymentProof`) and invoke `gate_payment.verify_and_pay` on `CB5DKGBS…`, signed by
   the fresh wallet. Capture the tx hash. (Broadcast only under the flag.)
7. **Assert:** local verify == true; `verify_and_pay` tx `successful:true` on Horizon; a **replay** of the
   same proof is rejected by the nullifier registry.

## After a successful broadcast run (reconcile the demo)
Enrolling changes `root(101)` away from `2583b277…`. Regenerate so the existing demo user still proves:
`apps/web/assets/app.js` FLOW_CONFIG expected `credentialRoot`, `scripts/make-demo-witness.mjs`,
`deployments/testnet-hardened.json` + `apps/web/data/deployments.json`, README artifacts — all to the new
root. Keep the test wallet enrolled (harmless second user). Re-run `node scripts/check-web-security.mjs`
if any SRI'd asset changed. Use a **deterministic** test identity so reruns are idempotent.

## Acceptance
- DRY-RUN: `npm run wallet:e2e:onchain` builds the witness, `fullProve`+verify pass locally, submit is
  simulated — all green, no broadcast. Add a unit/integration test where feasible.
- BROADCAST (flagged, run by Claude/user): fresh wallet → set_root → prove → `verify_and_pay`
  `successful:true` on testnet + replay rejected; tx hashes printed; demo artifacts regenerated.
- `bash scripts/test.sh` (WSL) + `node services/issuer/test.js` + kyc `server.test.js` still green;
  `check-web-security.mjs` green; no secrets committed.

## Environment / gotchas (see ONBOARDING_CUTOVER_SCOPE.md "Hard invariants")
Contracts/circuit build + stellar CLI in WSL; snarkjs runs on node (Win or WSL); artifacts under
`apps/web/proving/` are gitignored but present locally; admin alias `anchorshield-m0`; `STELLAR_NO_CACHE=true`;
one clean tx per action; never commit `.env`/keys.

## Approval gate
Build to DRY-RUN only. Do NOT broadcast `set_root` or `verify_and_pay` — Claude/user runs the flagged
broadcast and verifies on-chain.
