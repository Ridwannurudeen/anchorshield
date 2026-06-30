# Build Scope — Self-Serve User Onboarding (for Codex)

## Goal
Let real end users use AnchorShield with **zero files and zero CLI**: connect wallet → do KYC → get a credential → prove → submit. The user's secret is **derived from their own wallet** and never sent to a server or shipped by the site. This is the "for the masses" architecture, replacing today's operator-only "upload a witness JSON" demo step.

## Non-negotiable rule: do NOT break the working demo
The current site is **live, deployed, and CI-green**, and is the hackathon submission. Build all of this on a branch and keep `main` deployable at all times. Do not swap the new flow into the live deploy until it is end-to-end proven on testnet. If anything here can't be finished safely, leave `main`'s working demo intact.

## The hard constraint you must solve first (verified)
`circuits/eligibility.circom:331` instantiates `Eligibility(2, 20, 20)` — the **credential tree depth is 2**, i.e. **max 4 users total** (`CREDENTIAL_DEPTH = 2` in `services/issuer/issue.js:18`, `services/issuer/out/issuance.json`). Self-serve onboarding for many users requires raising that depth, which is a **cryptographic-core change**, not an app change:

1. **Circuit:** raise the first param of `Eligibility(...)` (credential depth) to **16** (65,536 users — enough for a demo+; do not go to 20 unless proving time stays acceptable). Update `CREDENTIAL_DEPTH` in `services/issuer/issue.js` and any depth constant in `services/issuer/lib/zk-tree.js` / tests to match. Keep `denyDepth`/`revocationDepth` at 20.
2. **Recompile** the circuit and **run a fresh Groth16 setup** (`scripts/ceremony.sh`, autonomous-tier is fine for testnet) → new `eligibility_final.zkey` + new `verification_key.json` + new `eligibility.wasm`. Build on WSL/Windows per the existing toolchain (circom 2.2.3, snarkjs; contracts build only in WSL — Windows has no MSVC linker).
3. **Verifier is frozen** (`contracts/verifier/src/lib.rs`: `init`→`set_vk`→`freeze_vk`→`is_frozen`). The deployed verifier's VK can't be changed. So **deploy a NEW verifier**, `init` + `set_vk` with the new VK, then `freeze_vk`. **Rewire** every contract that references the verifier (check `deployments/testnet-hardened.json` + `apps/web/data/deployments.json` + `scripts/deploy-testnet.sh`): `gate_payment` and `identity_verifier` must point at the new verifier ID (redeploy or update as their interface requires). Admin key = `anchorshield-m0` (alias in the WSL stellar keystore; = `GAJJW5XC…35U`).
4. **Update site proving artifacts:** copy the new `eligibility.wasm` + `eligibility_final.zkey` + `verification_key.json` into `apps/web/proving/` and `apps/web/data/`. Note `*.wasm`/`*.zkey` are gitignored — they ship by deploy, not git.
5. **Update the in-browser converter test** golden vector (`apps/web/assets/groth16-convert.js` logic is depth-independent, but `apps/web/assets/testdata/groth16-convert-vector.json` is tied to a specific proof — regenerate it).

## Phase 2 — Wallet-derived secret (the user's key)
- The only true secret in the witness is `user_secret` (everything else — attributes, `merkle_index`, `merkle_siblings`, the non-membership witnesses — is issuer-known or derivable from the public tree; confirm against the witness fields in `services/issuer/issue.js`'s `proof_input`).
- Derive `user_secret` deterministically from the user's wallet so it's reproducible by them and never stored/shipped. **Verify the exact Freighter primitive** available in `@stellar/freighter-api@6.0.1` (the site uses `window.freighterApi`): prefer a stable message/blob signature (`signMessage`/`signBlob` if present) over a fixed string → hash to the BLS field. If Freighter has no deterministic message-sign, fall back to a WebAuthn/passkey-derived secret. The browser sends the issuer only the **commitment** (the field element / leaf-relevant value), never the raw secret.

## Phase 3 — Enrollment backend (issuer)
Add to the existing Node services (mirror `services/kyc-backend/server.js` patterns: dependency-free http, systemd + nginx `/api/...` proxy, secrets in `/etc/...` env, no error leakage, per-IP rate limit, X-Real-IP from loopback only):
- `POST /api/enroll` — input: wallet pubkey, the user's secret commitment, and a **KYC status token** proving GREEN (reuse the `/api/kyc/status` token-gating; do not trust client claims). Server: builds the credential leaf from the commitment + the KYC-verified attributes (country, age, kyc_passed) using `services/issuer/lib/zk-tree.js`, **appends the user to the credential tree**, **republishes the credential root on-chain** via `issuer_registry.set_root` (see `services/issuer/publish-roots.js`), and returns the user's `merkle_index`, `merkle_siblings` (for the NEW root), `issuer_id`, and their attributes.
- **Tree state** must persist server-side (append-only list of leaves) so the tree can be rebuilt/extended deterministically. Keep it out of the public web artifact (the `verify.mjs:8` guard bans witness material under `apps/web/data/`).
- **Root-mutation / concurrency:** the credential root changes on every enroll. Handle it so a user's proof matches the current on-chain root: serve the Merkle path **on demand right before proving** (`GET /api/credential?wallet=…` returns the path for the current tree), and/or have `issuer_registry`/the gates accept the **last N credential roots** (small ring buffer) so an enroll between path-fetch and submit doesn't fail in-flight proofs. Pick one and document it. For demo concurrency, on-demand path + accept-last-2-roots is enough.

## Phase 4 — In-browser onboarding UX (no files)
On `/console` (and `/rwa`): replace the witness-file upload with a guided flow:
1. **Connect wallet** (Freighter).
2. **Verify identity** — launch the existing Sumsub WebSDK; wait for GREEN.
3. **Enroll** — derive the wallet secret, POST `/api/enroll`, store nothing sensitive; cache only the public credential data in memory.
4. **Prove** — assemble the full witness **in-browser** from (wallet-derived secret) + (served attributes + fresh Merkle path) + (the chosen action), `snarkjs.groth16.fullProve`, convert with `groth16-convert.js`, and submit with Freighter — exactly the existing submit path in `apps/web/assets/app.js`.
The user never sees a JSON file. Keep the operator "upload witness" path available behind a small "advanced" toggle if useful, but the default is the wallet flow.

## Phase 5 — Reconcile with the fixed demo
Raising the depth + republishing roots changes `credential_root` (currently `45037…`) and the fixed README artifacts. Update: `deployments/testnet-hardened.json`, `apps/web/data/deployments.json`, the README "Live testnet artifacts" + "Real vs Mock" tables, `scripts/make-demo-witness.mjs` (regenerate against the new tree), and `services/issuer/data/roster.json` (the real Sumsub `clean-demo-user` should be enrolled in the new tree so the existing KYC story holds). The blocked-path fixtures (`ofac-hit`, `revoked`) stay.

## Security requirements (must hold)
- Raw `user_secret` never leaves the browser; only its commitment is sent. No witness/secret material served under `apps/web/data/` (keep `scripts/check-web-security.mjs` + the `verify.mjs` guard green).
- The enroll endpoint must require a valid KYC status token (no anonymous enroll into the credential set), be rate-limited, and never echo provider errors.
- Re-freeze the new verifier VK after `set_vk`. Keep CSP + SRI; if any `apps/web/assets/*.js` or `styles.css` changes, recompute the `sha384` `integrity` in **all** HTML and keep `check-web-security.mjs` passing.

## Build/verify gates (all must pass before swapping into the live deploy)
- `npm run m5:verify` and `npm run m6:verify` green in a fresh-checkout condition (`rm services/issuer/out/*.json` first — CI runs `node services/issuer/issue.js` before the issuer test; mirror that for any new generated fixtures).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build --workspace --target wasm32v1-none --release` green (WSL).
- New verifier accepts a freshly generated deep-tree proof on testnet (simulate `verify_and_pay` / `attest_for_mint` against the redeployed contracts).
- End-to-end on testnet: a brand-new wallet → KYC (sandbox GREEN) → enroll → prove → on-chain submit succeeds, with no file upload.
- CI green on the branch (GitHub Actions, default branch is `main`; CI has Rust caching via `Swatinem/rust-cache`).

## Environment notes (so you don't get stuck)
- Contracts/circuit: build in **WSL Ubuntu** (Windows has no MSVC linker + Smart App Control blocks fresh exes). Toolchain pinned to Rust 1.96.0; target `wasm32v1-none`. circom 2.2.3 + snarkjs run on Windows or WSL.
- Stellar CLI is in WSL; admin alias `anchorshield-m0`. Testnet only. One clean tx per on-chain action.
- VPS deploy: static site at `/opt/anchorshield/web` (nginx, perms 755 dirs / 644 files), KYC backend systemd `anchorshield-kyc` on 127.0.0.1:3092 behind nginx `/api/kyc/`. Add the enroll service the same way. Do NOT deploy until proven.

## Deliverable
A working branch where a new user self-onboards end-to-end on testnet with no files, plus updated docs/artifacts, all gates green — ready to swap into `main` + redeploy only on explicit approval.
