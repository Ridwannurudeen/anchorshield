# Task for Codex — Recognize an already-enrolled wallet (no re-KYC)

Branch: `release/onboarding-prod`. High-priority correctness fix in the wallet-bound onboarding, found
during live staging validation. **Do this before the production flip.**

## Problem (verified in source)
A wallet that already holds an on-chain credential must be recognized on reconnect and **skip KYC** —
the on-chain credential *is* the durable proof of prior KYC (this is the HSK model). Today the
`/console` flow forces a full re-KYC after any browser refresh. Two causes, both confirmed:
1. `apps/web/assets/app.js` keeps `state.onboarding` (KYC status token, `user_secret`, credential) in
   **browser memory only** — a refresh wipes it.
2. `services/kyc-backend/server.js` `POST /api/credential` non-voucher path **gates on a fresh GREEN
   status token** (`const statusToken = body.statusToken; if (!statusToken) 401` →
   `verifiedCredentialForStatusToken`) instead of wallet ownership. So there's no way to fetch an
   already-enrolled wallet's credential without re-doing KYC.

The backend ALREADY has the needed lookup: `services/issuer/enrollment-store.js`
`credentialByCommitment(userCommitment)` (line ~340, exported) + `buildProofInput` (exported) for the
Merkle path. It just isn't wired to a wallet-signature-gated resume.

## Backend change
1. **Add a `resume` wallet-proof action.** In `walletProofMessage({wallet, action, statusToken,
   userCommitment, issuedAt})` (server.js), the message currently appends `user-commitment:` **only for
   `action === "enroll"`**. Also append it for `action === "resume"` so a resume proof binds the wallet
   to its commitment. The `status-token-sha256:` line stays but the resume flow passes `statusToken: ""`
   (a resume proof is NOT bound to a KYC session).
2. **Add a wallet-gated resume branch** to `POST /api/credential` (or a new `POST /api/credential/resume`):
   input `{ wallet, userCommitment, walletProof }`. Steps: `verifyWalletProof({ wallet, action:
   "resume", statusToken: "", userCommitment, proof: walletProof })` — **no KYC token, no
   `verifiedCredentialForStatusToken`, no GREEN check**. On valid signature, `const credential =
   enrollmentStore.credentialByCommitment(userCommitment); if (!credential) return 404 { error: "not
   enrolled" }`. Return `{ credential, path }` where `path` is the current-tree Merkle proof for that
   wallet (reuse the same shape the enroll response returns — `buildProofInput`/`buildEnrollmentView`).
   Keep the existing GREEN-gated path for first-time enroll unchanged.
3. **Security:** returning the credential (country/age/kyc_passed + path) to a caller who proved wallet
   ownership of that commitment is correct — they own it, and enrollment (the KYC gate) already
   happened. Keep the 10-min `issuedAt` freshness check in `verifyWalletProof`. Rate-limit the endpoint.

## Frontend change (`apps/web/assets/app.js`, `console.html`)
On wallet connect: `connectWallet()` → `deriveOnboardingSecret()` (sign → `user_secret` → `poseidon255`
commitment) → **first call the resume lookup** with a `resume`-action wallet proof.
- **If enrolled (200):** set `state.onboarding.credential`/path, mark steps 02-KYC and 04-Enroll as
  **already done** ("wallet already verified — credential on-chain", show root/index as evidence), and
  jump straight to generate-proof. No Sumsub, no enroll.
- **If 404 not enrolled:** run the existing KYC → derive → enroll flow.
Do NOT persist the raw secret — re-derive it from the signature each session (deterministic). You may
cache only non-sensitive hints. The Sumsub `userId` is already `localStorage`-cached (app.js:899-903)
for the first-time path.

## Acceptance
- Fresh wallet: connect → resume lookup 404 → KYC → enroll → prove works (unchanged first-run flow).
- **Enrolled wallet after a full page refresh: connect → sign → recognized as already verified →
  straight to generate-proof, NO KYC prompt.** This is the core acceptance.
- Wrong/forged wallet proof → 401; a different wallet cannot fetch someone else's credential.
- `node services/kyc-backend/server.test.js` + `node services/issuer/test.js` green; add a test for the
  resume branch (valid proof returns credential; missing/forged proof rejected; unenrolled → 404).
- `node scripts/check-web-security.mjs` green (recompute SRI for any changed `apps/web/assets/*.js` — use
  `git show HEAD:<asset>` blob hashes, NOT `git archive`, which mangles vendored `.min.js`).

## Test target + gates
Validate against the live staging: web `/opt/anchorshield-beta/web`, backend/signer
`/opt/anchorshield-beta-svc` (kyc :3192 / signer :3199, deployment `CBZQCAVZ…`, admin `anchorshield-m0`).
Do NOT touch `/opt/anchorshield` (live) or flip the domain — Claude/user does the flip after this is
validated on `beta.anchorshield.gudman.xyz`. No on-chain redeploy needed (resume is read-only; only the
first-time enroll publishes a root, which already works). Testnet only.
