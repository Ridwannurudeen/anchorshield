# Build Scope — Onboarding Production Cutover + HSK-Inspired Hardening (for Codex)

> Companion to `ONBOARDING_BUILD_SCOPE.md` (which `feat/self-serve-onboarding` was already built to).
> This doc covers three things that are NOT yet done: **(A)** finish + PROVE the wallet-onboarding
> flow end-to-end on testnet, **(B)** add the HSK-Passport-derived improvements (chiefly *unlinkable
> blind issuance*), and **(C)** do the production cutover so the LIVE site runs the wallet-bound,
> depth-16 flow instead of the shared-witness depth-2 demo.
>
> Deadline is explicitly de-scoped: build it **completely, thoroughly, and correctly**. Do not cut
> corners. But keep `main` deployable at every step and do not swap the live deploy until every gate
> in "Acceptance" passes. Nothing on mainnet. Broadcasts and the live swap are user-approval-gated.

---

## 0. Verified current state (confirmed 2026-07-01, don't re-assume — re-verify before acting)

| Thing | `main` (LIVE + submission) | `feat/self-serve-onboarding` |
|---|---|---|
| Circuit | `circuits/eligibility.circom` → `Eligibility(2, 20, 20)` (depth-2, **max 4 users**) | `Eligibility(16, 20, 20)` (depth-16, 65,536 users) |
| `CREDENTIAL_DEPTH` | `services/issuer/issue.js` = 2 | `services/issuer/issue.js:19` = 16 |
| Deployed verifier | `CC6SWCQSMNALXV6AUV67I24BQDBSAE33BRQCTMXHGAZKBDVE2L2I7OCH` (frozen, depth-2) | `CAOEADWQGIZH3JWK3PRVLB3DRYNUTLL5GGEBI3P4UQ4T7USWADRVW3XZ` (depth-16, per `deployments/testnet-hardened.json`) |
| Live `/console` | witness-file upload (`paymentWitnessFile`), shared demo witness | wallet-onboarding UI (`onboardWalletButton`/`deriveSecretButton`/`enrollButton`) |
| credential_root | `4503706044…` (depth-2 shared) | `16968264…` (depth-16) |

`main` HEAD `2b4d920`; `feat` HEAD `48c3023`. **Branch trap:** `main` history has `15e61f8` "raise credential tree depth to 16" **then `ffbf0dc` "Revert …"**. `feat` has `15e61f8` NOT reverted. So a naive `git merge feat → main` will NOT re-apply depth-16 (git thinks it's already reverted). See Part C for the reconciliation.

**The wallet-onboarding flow is already built on `feat` (verified by code trace).** Anchor map:
- Frontend (`apps/web/assets/app.js`, UI in `apps/web/console.html`): `connectWallet()` `app.js:682`; `startOnboardingKyc()` `:807`; `pollOnboardingKycStatus()` `:773`; **wallet-derived secret** `deriveOnboardingSecret()` `:853` → `digestField(...)` `:881` → `userCommitment = poseidon255T3(userSecret, issuerId)` `:889`; `enrollOnboardingCredential()` `:905` (POST `/api/enroll` with `{wallet, userCommitment, statusToken, walletProof}`); wallet-proof `walletProofMessage()` `:262` + `signWalletProof()` `:283`; `fetchOnboardingCredential()` `:946`; per-wallet witness `onboardingWitnessInput()` `:507`; `loadWitnessInput()` `:531`; `generateProof()` `:568`; `submitPaymentProof()` `:1041`. Console UI ids: `console.html:171/183/196/208/223`.
- Backend (`services/kyc-backend/server.js`): `POST /api/enroll` `:382`; GREEN gate `verifiedCredentialForStatusToken()` `:233` → `kyc.js:92-96` (returns null unless `reviewAnswer==="GREEN"`); **wallet binding** `verifyWalletProof()` `:178` (ed25519 via `Keypair.fromPublicKey(wallet).verify`, 10-min freshness, signer-address match); `POST /api/credential` `:445`.
- Issuer/tree (`services/issuer/enrollment-store.js`): `credentialFromKyc()` `:93`; `buildEnrollmentView()` `:126` (`buildTree(depth 16)` + per-user Merkle path); `enroll()` `:289` (append to `enrollments.json`, rebuild tree, publish root).
- Signer (`services/signer/`): `client.js:23 publishCredentialRootViaSigner` → `signer.js:122 publishRoot()` → `rootCommand()` `stellar contract invoke <issuer_registry> set_root` via `spawnSync` `:250`; identity-gated; **dry-run unless `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1`**.

---

## Part A — Finish + PROVE the wallet-onboarding flow (do this FIRST)

The code exists; what's missing is proof it works end-to-end for a brand-new wallet, plus two real
gaps. Treat "it's committed" as unproven until these pass.

**A1. Confirm the depth-16 on-chain deployment is real and usable.**
- From WSL (open network), query testnet for `CAOEADWQ…`: confirm the contract exists, its VK is
  **frozen** (`is_frozen`), and that `gate_payment` / `identity_verifier` on `feat` point at it
  (`deployments/testnet-hardened.json` + `apps/web/data/deployments.json`). If any of this is
  missing/stale, **redeploy** per `ONBOARDING_BUILD_SCOPE.md` Phase-1 §3 (new verifier → `set_vk` →
  `freeze_vk` → rewire gates). Admin alias `anchorshield-m0` (= `GAJJW5XC…35U`) in the WSL keystore.
- Verify the shipped artifacts match the deployed VK: `apps/web/proving/eligibility.wasm`,
  `eligibility_final.zkey`, `apps/web/data/verification_key.json` (`nPublic: 19`, bls12381). Note
  `*.wasm`/`*.zkey` are gitignored — they ship by deploy.

**A2. Fix the enroll concurrency gap (real bug, flagged in the trace).** `issuer_registry.set_root`
overwrites the root, so an enroll landing between a user's path-fetch and their submit invalidates
their in-flight proof. Implement the `ONBOARDING_BUILD_SCOPE.md` Phase-3 remedy properly:
- **On-demand path** right before proving (`GET /api/credential?wallet=…` already exists — confirm it
  returns the path for the CURRENT tree), **AND**
- **Accept last-N credential roots** in the gate/registry: add a small ring buffer (accept-last-2 or
  -3 roots) in `issuer_registry` (or a root-history check in `gate_payment.verify_and_pay`) so a
  fresh enroll doesn't fail concurrent in-flight proofs. This is a Soroban contract change → new
  deploy + rewire. Document which approach you took. (See Part B4 for the HSK event-sourced variant.)

**A3. End-to-end testnet proof (the real acceptance for Part A).** A brand-new funded Freighter
wallet, never enrolled: connect → Sumsub sandbox KYC to GREEN → enroll (real `set_root` broadcast,
requires the signer approved+running) → generate proof in-browser → submit `verify_and_pay` on
testnet → success, with **no file upload**. Capture the tx hashes. Then a second concurrent enroll to
prove A2 (first user's proof still verifies).

**A4. Regression:** the operator "upload witness" path may remain behind an "advanced" toggle, but the
default must be the wallet flow. Keep `scripts/check-web-security.mjs` + the `verify.mjs:8` guard
green (no witness/secret material under `apps/web/data/`).

---

## Part B — HSK-Passport-derived improvements (what to port, why, how)

Traced from `C:\Users\gudma\hsk-passport` (branch `master`), then cross-checked with a full HSK
feature inventory (every layer mapped HAS / PORT / SKIP against AnchorShield source). B1-B10 below are
the **PORT** items — everything AnchorShield lacks that would improve it. Items HSK has but AnchorShield
already meets or exceeds (frozen VK, nullifier/replay, action binding, in-circuit revocation +
expiry/freshness, native governance/timelock, RWA gating, CI/ceremony/monitor) are intentionally not
repeated here.

**Recommended priority order:** privacy-critical first — **B1 (unlinkable blind issuance)** + **B5
(anonymity-set floor gate)** are the two that most strengthen the "reveal no identity" claim and
should land together. Then B6 (webhook) + B8 (observability) for production-grade ops, B2 (freshness
range checks, free with the depth-16 recompile), B4/A2 (root history), B7 (issuer directory) + B9
(React SDK) for the multi-issuer/DX story, and B3 (staking) + B10 (batch hardening) last.

### B1. Unlinkable blind issuance (HIGHEST VALUE — closes AnchorShield's biggest privacy gap)
**Problem in AnchorShield today:** enroll is **linkable** — `verifyWalletProof()` + the KYC status
token mean the backend/issuer learns `wallet ↔ userCommitment ↔ Sumsub applicant`. For a privacy
compliance product that's a real weakness: the issuer can deanonymize every user.

**How HSK solves it (the pattern to adapt):**
- `GET /api/kyc/voucher/pubkey` returns RSA `(N,e)` (`backend/src/server.ts:797`).
- `POST /api/kyc/voucher/session` mints a **random `sessionId`** (NOT the commitment) with its own
  Sumsub token (`server.ts:806`, `createVoucherSession`) — Sumsub only ever sees the random session.
- Browser blinds the commitment locally: `blinded = FDH(commitment)·r^e mod N`, keeping `r` in memory
  (`frontend/src/lib/blind.ts:104-113`, MGF1-SHA256 full-domain hash `:50-65`).
- `POST /api/kyc/voucher` checks session GREEN + unspent, blind-signs `blinded^d mod N`
  (`backend/src/blind-issuer.ts:79-88`), atomically spends the session (`server.ts:897`). **Server
  never sees the commitment.**
- Browser unblinds to a real RSA-FDH signature `sig = blindSig·r⁻¹ mod N` (`blind.ts:119-125`).
- User self-submits `ClaimCredential.claim(commitment, sig)` from **any (ideally fresh) wallet**;
  contract verifies `sig^e mod N == FDH(commitment)` and burns a one-time nullifier
  (`contracts/contracts/ClaimCredential.sol:57-90`).

**Adapt to AnchorShield / Stellar-Soroban:**
- Add voucher endpoints to `services/kyc-backend/server.js` mirroring HSK: random-session KYC
  (decouple the Sumsub applicant from the wallet), blind-sign the `userCommitment`, one-voucher-per-
  session. Key material in `/etc/…` env (`VOUCHER_RSA_PRIVATE_KEY` PEM), never committed; add a
  keygen helper like HSK's `scripts/gen-voucher-key.mjs`.
- Client blind/unblind in a new `apps/web/assets/blind.js` (SubtleCrypto bigint, byte-mirror of the
  verifier). Enroll becomes: verify voucher → append leaf → publish root. The issuer sees a valid
  voucher and a commitment, but **cannot link it to the Sumsub applicant or the connecting wallet**.
- Verification of the voucher can be **off-chain in the enroll endpoint** (simplest: the endpoint
  checks the RSA-FDH sig before appending the leaf — no wallet-proof needed, so the wallet↔commitment
  link is broken) OR on-chain if you add a Soroban `claim`-style contract (RSA modexp is heavier on
  Soroban than EVM — measure first; off-chain-verify at enroll is acceptable for this protocol since
  the issuer is already the tree authority). **Recommended: off-chain verify at enroll**, drop
  `verifyWalletProof` from the blind path, and let the user prove later from any wallet.
- **Acceptance:** an enrolled credential's on-chain root cannot be linked by the backend to the
  Sumsub applicant or to the wallet that later proves. Add a unit test mirroring HSK's blind round-trip
  (client blind → server blindSign → client unblind → verify).
- **Caveat (carry HSK's honesty):** hand-rolled RSA-FDH needs external crypto review before mainnet;
  fine for testnet. Document it in `docs/THREAT_MODEL.md` + README Real-vs-Mock.

### B2. Freshness / expiry range-check hardening (feeds AnchorShield's open "H6 expiry" item)
HSK's freshness circuit proves `issuanceTime >= earliestAcceptable` with explicit `Num2Bits(64)` range
checks (`circuits/src/credential_freshness.circom:121-134`). AnchorShield already has a freshness
signal; adopt HSK's **range-checked comparison pattern** so credential expiry/oldest-issuance is a
sound in-circuit range proof (not an unchecked field compare). Update `circuits/eligibility.circom`
(or the freshness sub-circuit) accordingly; this rides along with the depth-16 recompile+ceremony so
it costs no extra ceremony. **Acceptance:** an expired credential cannot produce a passing proof;
add a circuit test.

### B3. Issuer accountability — staking / slashing / reputation (optional, governance upgrade)
HSK's `IssuerRegistry` gives issuers stake + slashing + reputation. **Verified against source:**
`contracts/issuer_registry/src/lib.rs` on BOTH `main` and `feat` has only
`init/admin/transfer_admin/set_root/root/set_sanctions_root/set_revocation_root/is_root` — **no
`stake`/`slash`/`reputation` anywhere in `contracts/*/src/lib.rs`**. So this is a genuine contract
BUILD, not UI wiring. If you want economic accountability (issuers stake, get slashed for bad roots),
build it into `contracts/issuer_registry`.
**Scope judgement:** valuable for the "real protocol" story but large and governance-adjacent — do it
only after B1/B2 land and A/C are proven. Keep it on its own branch.

### B4. Event-sourced credential set (robustness; supersedes A2's ring buffer if done well)
HSK rebuilds group membership from on-chain `CredentialIssued`/`CredentialRevoked` events with an
indexer + on-chain fallback (`frontend/src/app/demo/page.tsx:183-211`). AnchorShield's credential set
lives only in `enrollments.json` (single point of truth/failure). Consider emitting an enroll event
on-chain and reconstructing the tree from events (via the existing `services/indexer` +
`services/monitoring`), which also makes A2's "accept last-N roots" natural. **Scope:** medium; do
after A3 proves the simpler path works.

### B5. Anonymity-set-size floor gate (HIGH — do alongside B1; strongest privacy finding)
Independently flagged by multiple review agents. AnchorShield accepts a proof from a credential set of
**any size**, including a set of 1-2 leaves, which near-deanonymizes the prover — a real hole in a
"reveal no identity" product, and worst exactly for early adopters (small sets). HSK gates on a
minimum anonymity set with a low-set warning (`contracts/contracts/AnonymitySetGate.sol:91-155`).
**Map to Soroban:** issuer publishes the member/leaf count alongside each root in `issuer_registry`
(e.g. `set_root(issuer_id, root, member_count)`); `gate_payment`/`gate_rwa` (or a thin adapter)
enforce a configurable minimum before settling and emit a low-anonymity-set warning event; surface a
client-side warning in `apps/web`. **Acceptance:** a proof against a below-floor root is rejected; test it.

### B6. Sumsub webhook receiver (HMAC + raw-body + replay/dedup)
AnchorShield KYC is client-polling only (`/api/kyc/status`). HSK uses server-push webhooks with
`crypto.timingSafeEqual` HMAC over the **raw** body + a persisted digest-dedup set
(`backend/src/server.ts:688-709`, `sumsub.ts:174`, `db.ts:280`). Add `POST /api/kyc/webhook` to
`services/kyc-backend/server.js`: verify the Sumsub signature over the raw body (timing-safe), dedup
on SHA-256 of the raw body, update status server-side. Closes a captured-callback replay gap and is
the production pattern. **Acceptance:** replayed webhook ignored; forged-HMAC rejected.

### B7. Public issuer directory + SSRF-hardened metadata fetch
AnchorShield's `issuer_registry` stores only roots — no name/license/jurisdiction. For a multi-issuer
compliance layer, a public directory builds third-party trust. Add a `metadata_uri` per issuer to
`issuer_registry`; port HSK's directory service (`backend/src/issuers.ts:154-598`) — the SSRF-hardened
fetch (reject private-IP/redirects) + validation allowlists are near-verbatim reusable JS — plus a
directory page in `apps/web`. **Acceptance:** metadata fetch rejects SSRF; only allowlisted fields shown.

### B8. Observability — health/metrics + publisher-balance + restart-safe root reconcile
AnchorShield has only a boolean `/healthz` + a batch monitor. **A drained root-publisher (XLM) account
silently halts credential/sanctions/revocation root rotation** — compliance-critical and currently
unwatched. Port HSK's detailed `/healthz` + Prometheus `/metrics` + hot-wallet balance monitor
(`backend/src/health.ts:56,186-416`) across the AnchorShield services (KYC backend + signer + a small
indexer): admin/publisher XLM balance with warn/error thresholds, plus Soroban-RPC liveness/lag. Also
port the **restart-safe root reconcile / halt-on-divergence** guard (`backend/src/auto-freshness.ts:121-147`)
into `services/issuer/publish-roots.js` so it refuses to publish a root that does not extend on-chain
state. **Acceptance:** low publisher balance raises an alert; a divergent root publish is refused.

### B9. React SDK component + hook (integration DX)
AnchorShield's SDK is vanilla Node/CJS (`packages/sdk`). HSK ships a React `<Gate>` + `useHSKPassport`
hook (`frontend/src/sdk/react.tsx:47,120`) for drop-in dApp integration. Add `<AnchorShieldGate>` +
`useAnchorShield` wrapping `submitPaymentProof` + Freighter connect, published beside the existing SDK.
**Acceptance:** a sample dApp gates an action in under 10 minutes using the component.

### B10. Lower-effort hardening (batch these late)
- **Asymmetric / per-issuer / per-policy pause** — AnchorShield pause is admin-only, all-or-nothing;
  add a fast pause-only `pauser` role + granular scope (`HSKPassport.sol:44,436`).
- **Two-step admin transfer** — every AnchorShield contract uses single-step `transfer_admin`; add
  pending/accept (`HSKPassport.sol:412`) to guard the governance hand-off.
- **Single-use nonce burn** on `verifyWalletProof` — currently a freshness window only; add a
  burned-nonce set to stop in-window replay of a captured wallet proof.
- **Jurisdiction-set membership** (higher effort) — AnchorShield's `ALLOWED_COUNTRY` is a single
  public signal (reveals the country + allows exactly one). HSK proves `country ∈ set`
  (`JurisdictionSetVerifier.sol:37`) — circuit + `policy_registry` work; do only if multi-jurisdiction
  is wanted.
- **`SECURITY.md` (responsible disclosure: scope, contact, SLA) + incident runbook matrix**
  (symptom → cause → action) — cheap trust/ops hardening AnchorShield lacks.

### Explicitly NOT worth porting
- HSK's Semaphore-v4 identity model — AnchorShield's Circom/BLS12-381 + poseidon255 commitment is its
  own (working) identity scheme; don't swap it.
- HSK's revocation-via-group-removal — AnchorShield's **in-circuit non-membership** revocation is
  stronger; keep it.

---

## Part C — Production cutover (LAST; only after A + chosen B items are proven; user-approval-gated)

**C1. Build on an integration branch off `feat`** (which already has depth-16 + onboarding), e.g.
`release/onboarding-prod`. Do NOT try to `merge feat → main` (the `ffbf0dc` revert of `15e61f8` means
git won't re-apply depth-16 — the revert-merge trap).

**C2. Port the `main`-only improvements `feat` lacks** onto the integration branch (verify each with a
diff, don't assume): the `/anchor` real-capture + README Real-vs-Mock tightening (`main@2b4d920`) — port
manually because `feat`'s anchor files (`apps/web/data/mock-anchor.json`, `apps/web/anchor.html`, its
tx hashes) differ. The KYC POST `/api/kyc/status` contract, the 8h `STATUS_TOKEN_TTL_MS`, and the
camera Permissions-Policy doc note are ALREADY on `feat` — confirm, don't duplicate.

**C3. Phase-5 reconciliation of the fixed demo** (from `ONBOARDING_BUILD_SCOPE.md`): the depth-16 tree
+ new roots change the "fixed" artifacts. Update `deployments/testnet-hardened.json`,
`apps/web/data/deployments.json`, README "Live testnet artifacts" (verifier → `CAOEADWQ…`) + "Real vs
Mock", `scripts/make-demo-witness.mjs`, and enroll the real Sumsub `clean-demo-user` into the new tree
so the existing KYC story holds. Blocked-path fixtures (`ofac-hit`, `revoked`) stay.

**C4. SRI/CRLF discipline** (bit us repeatedly this project): `check-web-security.mjs` hashes
working-tree bytes; repo `integrity` values are **LF-based** (CI is Linux). On Windows, `git checkout
<branch> -- file` smudges to CRLF and changes the hash. Materialize LF with `git show <ref>:path >
file`. Any change to an SRI'd `apps/web/assets/*.js` / `styles.css` requires recomputing its `sha384`
and updating `integrity` in ALL HTML. Keep `check-web-security.mjs` green.

**C5. Make it `main` (the honest supersede).** After everything's proven and the user approves: the
integration branch becomes the new `main`. Because of the revert, do this deliberately — either
`git revert ffbf0dc` on `main` then merge the integration tree, OR (cleaner) fast-forward/replace
`main` to the integration branch content with a single merge commit that supersedes the depth-2 demo.
Document the exact commands you run; a direct-commit-to-`main` hook exists → use an `--ff-only` merge
or a merge commit (no bare `git commit` on `main`). Push. Confirm CI green.

**C6. Deploy** (only on explicit approval): static site → `/opt/anchorshield/web` (nginx, **perms 755
dirs / 644 files** — pre-existing 700 subdirs lock out `www-data` and 404 the wasm), ship the depth-16
`proving/` + `data/` artifacts, deploy the enroll/voucher backend the same way as `anchorshield-kyc`
(systemd + nginx `/api/…` proxy, secrets in `/etc/…`, X-Real-IP from loopback only), and ensure the
**signer** service is running with `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1` + `SIGNER_TOKEN`. Verify
live via headless-Chrome CDP (`--headless=new`, not the deprecated `--headless`): connect→KYC→enroll→
prove→submit with no file.

---

## Hard invariants & gotchas (verified this project — do not relearn the hard way)
- **Build contracts/circuit in WSL Ubuntu** (Windows has no MSVC linker; Smart App Control blocks
  fresh unsigned exes). Rust pinned `1.96.0`, target `wasm32v1-none`. circom 2.2.3 + snarkjs run on
  either. `bash scripts/test.sh` runs the workspace tests in WSL with `CARGO_TARGET_DIR=$HOME/as-target`.
- **Raw `user_secret` never leaves the browser** — only the commitment (or blinded commitment) is sent.
- **Signer** publishes on-chain only with `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1`; runs as a non-root
  user with the admin key isolated (kyc user gets Permission denied on the key — keep that isolation).
- **Stellar CLI gotchas:** `STELLAR_NO_CACHE=true`; rapid state-changing txs → `TxBadSeq`, so one clean
  tx per action with a ≥6-9s gap; `publish-roots --execute` fires 3 back-to-back set_roots that
  TxBadSeq — run them individually (idempotent, safe to re-run).
- **Prettier drift:** the local Windows Prettier reformats unrelated regions of some JS on save; make
  single-line edits via `sed`/surgical edits, or revert the churn, to keep diffs minimal and CI's
  format check happy.
- **Secrets:** the Sumsub sandbox creds were pasted in chat earlier and live in
  `/etc/anchorshield-kyc/env` + the signer env — **rotate them** as part of this work; never commit
  `.env`; keep `services/issuer/.env` gitignored.
- **CSP:** `script-src` needs `'wasm-unsafe-eval'` for snarkjs; `frame-src`/`connect-src` allow
  `*.sumsub.com`; the `/issuer` (and any KYC) page needs `Permissions-Policy: camera=* microphone=*`
  on the nginx vhost for Sumsub liveness (documented in `docs/OPERATIONS.md`; vhost-only, not in git).

## Acceptance (ALL green before the live swap; the swap + any broadcast are user-approved)
1. `bash scripts/test.sh` (WSL) — full contract workspace green incl. any new ring-buffer/staking tests.
2. `node services/issuer/test.js` and the KYC backend `server.test.js` green (fresh-checkout: `rm
   services/issuer/out/*.json` first, mirror CI).
3. New blind round-trip test (B1) green; expired-credential circuit test (B2) green.
4. `node scripts/check-web-security.mjs` green (SRI/CSP); `verify.mjs` guard green (no witness in web data).
5. Depth-16 verifier confirmed frozen on testnet with the shipped VK; a fresh-wallet
   connect→KYC→enroll→prove→submit succeeds on testnet with NO file upload; concurrent-enroll proof
   still verifies (A2).
6. CI green on the integration branch.
7. README/deployments/`make-demo-witness` reconciled to the depth-16 deployment; Real-vs-Mock updated
   to disclose the blind-issuance crypto-review caveat.

## Approval gates (Codex must STOP and ask)
- Any on-chain broadcast (verifier/gate redeploy, `set_root --execute`).
- Swapping the live `/opt/anchorshield/web` + backend to the new flow.
- Anything touching mainnet (out of scope here — testnet only).
