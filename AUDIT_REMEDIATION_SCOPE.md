# AnchorShield — Audit Remediation Build Scope (for Codex)

Prepared 2026-06-27. Source: ChatGPT "Stellar Hacks Real-World ZK Audit". Every finding below was
**verified against the actual code** (file:line cited). Build in the phase order given — later phases
depend on earlier ones (contract redeploy must land before live browser submit and before the web/data refresh).

Repo: `C:\Users\gudma\OneDrive\Desktop\GITHUB-FILES\anchorshield`, branch `build/m0-toolchain`.
Live site: https://anchorshield.gudman.xyz (multi-page: `/ /gates /console /onchain /auditor`).
soroban-sdk 26.1.0 (Protocol 26). VPS deploy of `apps/web` is by scp to `root@75.119.153.252:/opt/anchorshield/web` (NOT a git checkout).

## ⚠ BUILD ENVIRONMENT (verified 2026-06-27 — corrects stale "toolchain in WSL" note)
The Rust/circom/stellar toolchain is on **WINDOWS**, NOT WSL. Neither WSL distro (default `Ubuntu-24.04`/arsandbox, or `Ubuntu`/gudman) has cargo/rustc/circom/stellar — do not try to build there.
- `cargo` / `rustc` / `circom`: `C:\Users\gudma\.cargo\bin\` (on Git-Bash PATH already).
- `stellar` CLI: `C:\Program Files (x86)\Stellar CLI\stellar`.
- `snarkjs`: via repo `node_modules/.bin/snarkjs` (`npx snarkjs`).
- Build/test contracts on Windows: `cargo test --workspace`, `cargo build --target wasm32-unknown-unknown --release` (or `stellar contract build`). **Baseline `cargo test --workspace` was NOT yet run this session — Codex must run it first to confirm a green start.**
- Circuit/ceremony: run `circom` + `snarkjs` on Windows (or in the `Ubuntu`/gudman WSL distro where the repo is mounted at `/mnt/c/.../anchorshield` and `node_modules/.bin/snarkjs` exists — but circom is Windows-only here, so prefer Windows).

## Locked decisions (drive scope)
- **D1 Live browser payment submission: BUILD IT** (Freighter sign + submit `verify_and_pay`).
- **D2 Contract findings: ONE HARDENING REDEPLOY** (TTL cap, VK freeze, write-once mappings, richer events).
- **D3 RWA action-binding: REFRAME** as "ZK identity attestation for SEP-57 access" + document `gate_rwa` as the action-bound variant. **Do NOT** rewire the OZ mint to be proof-bound.
- **D4 Sanctions non-membership (audit P3): OUT OF SCOPE** this sprint (keep the issuer-attested `sanctions_clear` flag; it is already documented in `docs/STRETCH.md`).
- **D5 Demo video: USER-OWNED** (not Codex). Script is in the audit §7.

## SCOPE UPDATE — 2026-06-27b: deadline +10 days → MAXIMAL in-repo build
Decisions revised after the extension:
- **D3 → IMPLEMENT** action-bound RWA mint (was reframe). Contract-only (circuit already outputs `action_binding`); `gate_rwa` has the binding logic to port.
- **D-CIRCUIT (new): INCLUDE circuit changes + FRESH CEREMONY** — in-circuit credential revocation, freshness/expiry, and sanctions/deny-list **non-membership** (replaces the issuer-attested `sanctions_clear` flag). Invalidates the current trusted setup.
- **D-EXT (new): DEMO-GRADE in-repo** — SDK package, demo dashboards, local disclosure vault, SEP-10/31/38 adapters vs a MOCK anchor. **Tier C still deferred**: real anchor/KYC pilots, independent audit, production multi-party ceremony, mainnet, go-to-market.

### Critical-path order (STRICT — circuit invalidates ceremony; signal layout ripples downstream)
- **A. Circuit** `circuits/eligibility.circom`: add revocation-root non-membership, freshness/expiry window, sanctions deny-list non-membership; add public signals (e.g. `revocation_root`, `sanctions_root`, freshness bounds); update the `action_binding` fold + re-derive the public-signal layout. Add malicious-witness tests. **Highest risk — design before coding.**
- **B. Ceremony** re-run `scripts/ceremony.sh` (power-16 BLS12-381, multi-contribution) → new wasm/zkey/vk; regenerate `apps/web/proving/*`, `apps/web/data/verification_key.json`, and the input JSON fixtures. Update `PUBLIC_SIGNAL_INDEX` in `app.js` to the new layout.
- **C. Contracts**: apply the new signal layout from A; Phase-1 hardening (TTL cap, `freeze_vk`, write-once mappings, richer events); **`attest_for_mint`** one-time action-bound RWA authorization consumed by the OZ mint (D3); policy-engine fields (limits, asset allowlist, freshness window, revocation/sanctions roots, required-claims); circuit/VK **versioning** (`circuit_id`+version on verifier + policies); admin **multisig + pause**; a test per path.
- **D. Redeploy** hardened+versioned stack → refresh ALL artifacts (`deployments/testnet-hardened.json`, `apps/web/data/*`, hardcoded web links). [Phase 2]
- **E. Live submit + SDK** [Phase 3 + new]: browser Freighter sign+submit `verify_and_pay`; TS SDK package (`createProofRequest`/`prove`/`submitPaymentProof`) over the generated bindings.
- **F. Productization demo (Tier A/B)**: demo dashboards (anchor/issuer/RWA/auditor) as new web routes; minimal local **Disclosure Vault** (encrypt packet + access grant + time-limited key + audit log + evidence export); **SEP-10/31/38 adapter** module + webhooks wired to a MOCK anchor.
- **G. Wording + docs** [Phase 4/5]: precise claims, judge-grade README, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`.
- **H. Verify**: workspace tests green, ceremony reproducible, redeploy verified, live submit E2E, all routes 0-error, full link audit.

Everything in the original Phases 1-6 below still applies — it is RE-SEQUENCED under C-H above, with the circuit/ceremony (A/B), RWA mint, policy engine, versioning, multisig/pause, SDK, dashboards, vault, and anchor adapters added.

## Ground truth — what the audit got right, and the one thing it understates
- The **circuit already binds the full action**: `circuits/eligibility.circom:183-192` folds `action_type, asset_id, amount, recipient, action_id, packet_hash, policy_id, epoch` into the public output `action_binding` (and `packet_amount===amount`, `packet_action_id===action_id` at :147-149).
- The **payment gate already consumes those bindings**: `contracts/gate_payment/src/lib.rs:178-194` requires asset_id/amount/recipient_id/action_id/credential_root/packet_hash to match the proof signals before the SAC transfer, with nullifier-reuse check + Groth16 verify. **The payment path is genuinely action-bound on-chain — keep it the centerpiece.**
- The gap the audit calls the "biggest technical risk" is **narrow and real**: only the *hardened RWA OZ-mint* path is gated solely by eligibility (`identity_verifier.verify_identity(account)`); it does not consume amount/recipient/action_id/terms_hash. `gate_rwa` (`contracts/gate_rwa/src/lib.rs:124-236`) DOES bind the full action incl. `terms_hash` but is **not deployed** in `deployments/testnet-hardened.json`. → handled by D3 (reframe + document).
- Nothing here is a deep exploit. The work is: (1) the missing live-submit demo, (2) small contract-hardening fixes, (3) precise wording, (4) a judge-grade README.

---

# PHASE 0 — Baseline (no behavior change)
**P0.1** Confirm the workspace builds and tests are green before touching anything.
- Run: `wsl -e bash -lc "cd /mnt/c/.../anchorshield && cargo test --workspace"` and the circuit smoke (`scripts/circuit-smoke.mjs` / `npm run` equivalents).
- Acceptance: existing contract tests pass (≈19) and wasm builds. Record the baseline count.
- If anything is already red, STOP and report — do not build on a broken baseline.

---

# PHASE 1 — Contract hardening (Rust) [D2]
All changes are small and local. Add a focused test for each. Keep soroban-sdk 26.1.0 patterns already in the files.

**P1.1 Cap attestation TTL — `contracts/identity_verifier/src/lib.rs`**
- Today: `attest(env, account, proof, pub_signals, policy_id, epoch, valid_until: u64)` stores `valid_until` verbatim (`:166-168`); deploy passes `9999999999` (`scripts/deploy-testnet.sh:88`). No cap.
- Change: add `const MAX_ATTESTATION_TTL: u64 = 2_592_000; // 30 days (seconds)`. In `attest`, compute `let now = env.ledger().timestamp(); let capped = core::cmp::min(valid_until, now.saturating_add(MAX_ATTESTATION_TTL));` and store/emit `capped` instead of `valid_until`.
- Acceptance: passing `valid_until = u64::MAX` results in a stored expiry == `now + MAX_ATTESTATION_TTL`.
- Test: in `contracts/identity_verifier/src/test.rs`, set ledger timestamp, `attest(... valid_until = huge)`, assert stored attestation == now+TTL; advance ledger past it → `verify_identity` returns `Expired`.
- Risk: tests must set `env.ledger().set_timestamp(...)`. Low.

**P1.2 Freeze the VK — `contracts/verifier/src/lib.rs`**
- Today: `set_vk(env, vk)` is admin-only but an unconditional `set` (`:44-48`); `has_vk` exists (`:50-52`) but never blocks. "Pinned" is currently false.
- Change: add `DataKey::Frozen` (bool). Add `pub fn freeze_vk(env) -> Result<(),Error>` (admin-only) that sets `Frozen=true`. In `set_vk`, if `Frozen` is set → return new `Error::VkFrozen`. (Keep set_vk callable until frozen so deploy can set then freeze.)
- Update `scripts/deploy-testnet.sh` to call `freeze_vk` immediately after the existing `set_vk` step.
- Acceptance: `set_vk` → `freeze_vk` → `set_vk` again returns `VkFrozen`.
- Test: add to verifier tests. Risk: low.

**P1.3 Write-once recipient/token mappings — `contracts/gate_payment/src/lib.rs`**
- Today: `set_token` (`:104-111`) and `set_recipient` (`:113-120`) are plain admin `set`, re-pointable anytime — undercuts the non-redirectability comment (`:62-66`).
- Change: make each write-once. Before the `set`, if `env.storage().instance().has(&DataKey::Token(asset_id))` (resp. `Recipient(recipient_id)`) → return new `Error::AlreadySet`. (Write-once per id; different ids still settable.)
- Verify `scripts/deploy-testnet.sh` sets each id exactly once (it does today) so the deploy still works.
- Acceptance: second `set_recipient` for the same id errors `AlreadySet`; a new id still works.
- Test: add to gate_payment tests. Risk: confirm no test/deploy path re-sets the same id.

**P1.4 Indexer-friendly events — `contracts/gate_payment/src/lib.rs` (+ `identity_verifier`)**
- Today: `PaymentApproved` (`:69-77`) = {policy_id, asset_id, amount, recipient, action_id, nullifier}. Missing `packet_hash`, `action_binding`. `IdentityAttested` (`identity_verifier:66-72`) = {account, policy_id, valid_until, nullifier}.
- Change: add `packet_hash: BytesN<32>` and `action_binding: BytesN<32>` to `PaymentApproved`; populate from the proof public signals. Signal layout (verified): circuit public outputs are index `0=credential_root, 1=packet_hash, 2=nullifier, 3=action_binding` (`eligibility.circom:65-68`; matches `gate_payment` const `PACKET_HASH = BOUND_HASH` index 1). Read `action_binding` from the shared signal-index constants in `contracts/shared` (add an `ACTION_BINDING` const if absent, index 3). Optionally add `packet_hash` to `IdentityAttested` too.
- Acceptance: emitted `PaymentApproved` includes a non-zero `packet_hash` and `action_binding` matching the proof.
- Test: assert event fields in gate_payment test (the SDK test env exposes emitted events).
- Risk: confirm the exact signal index for `action_binding` against `contracts/shared` before reading it — do not hardcode 3 without checking the const.

**P1.5 Workspace green**
- `cargo fmt`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, and `stellar contract build` for each contract (OZ token needs the `SPEC_SHAKING` env per existing notes).
- Acceptance: fmt+clippy clean, all tests (old + new) pass, all wasm build.

---

# PHASE 2 — Hardened redeploy to testnet [D2]
**P2.1** Re-run `scripts/deploy-testnet.sh` (now with `freeze_vk` + capped TTL) to a fresh hardened deployment.
- Follow existing CLI gotchas: `STELLAR_NO_CACHE=true`, `upload`→`deploy --wasm-hash`, ≥6s sleeps between state-changing txs, arg formats (scalar Fr = bare decimal; Vec/proof/struct = JSON file).
- The script must: deploy all contracts, `set_vk` + `freeze_vk`, set roots/policies, set token+recipient (once each), run the payment `verify_and_pay` flow, and the RWA attest→mint flow — capturing **all tx hashes and the payment fee** to `deployments/testnet-hardened.json`.
- **Also capture the payment `verify_and_pay_tx` + `fee_charged_stroops` and the RWA `mint_tx` + fee** (the prior deploy omitted the payment tx; we recovered it from Horizon last time — make the script record it this time).

**P2.2** Refresh data files to the NEW addresses/txs:
- `deployments/testnet-hardened.json` (source of truth).
- `apps/web/data/deployments.json` (mirror).
- `apps/web/data/compliance-events.json` (payment + rwa event rows: new contractId + txHash + stellarExpertUrl).
- `apps/web/data/disclosure-summary.json` (`paymentTx` → new payment tx).
- The hardcoded values in `apps/web/*.html` and `apps/web/assets/app.js` (the `signatureFee` "167132" string in `app.js:268-273`, the event-table rows + contract links in `onchain.html`, the gate "View tx" links in `gates.html`/`console.html`). Grep for the old tx prefixes `92e1efdd`/`5b2e61d2` and the old contract IDs and replace consistently.
- Acceptance: `grep -rn '92e1efdd\|5b2e61d2\|<old contract ids>' apps/web/ deployments/` returns nothing; all JSON valid (`python -m json.tool`).
- Risk: this is the redeploy "address churn" — be exhaustive. Re-run the live verification in Phase 5.

---

# PHASE 3 — Live in-browser payment submission [D1] (highest ROI)
Depends on Phase 2 (final gate_payment address + ABI).

**P3.1** Use the generated bindings, not hand-rolled ScVals. `packages/bindings/gate-payment` already exists; regenerate against the new contract id if needed. Bundle a browser-loadable client (`@stellar/stellar-sdk` + the binding) into `apps/web/vendor/` (the site is static, no bundler — produce an ESM/IIFE bundle or vendor the SDK like `snarkjs.min.js`).

**P3.2** Extend `apps/web/assets/app.js` (page-aware; only on `/console` where `[data-run-flow]` exists):
- After `generateProof` succeeds, add an explicit **"Submit on-chain"** step (new button, not automatic) that:
  1. builds a `gate_payment.verify_and_pay(proof, pub_signals, policy_id, asset_id, amount, recipient_id, action_id)` invocation,
  2. `simulate`s it,
  3. requests a Freighter signature (`freighterApi.signTransaction`) — `connectWallet` currently only reads the address (`app.js:230-258`); add real signing,
  4. submits via Soroban RPC (testnet) and polls for success,
  5. renders the **new** tx hash, `PaymentApproved` event, nullifier, and the recipient balance delta in the trace/console UI.
- Keep a graceful fallback: if Freighter is absent or the user declines, show the existing proof-only result and the pre-executed tx link (do NOT fake a submission).

**P3.3 Repeatable-demo nullifier.** The demo witness (`apps/web/data/payment-input.json`) is fixed → fixed nullifier → second live submit fails `NullifierUsed`. To make the live submit repeatable, **vary a nullifier-affecting private input per session** (e.g. randomize `epoch` or `user_secret`/an entropy field in the witness before proving), provided the gate/policy does not pin that field.
- VERIFY FIRST: check whether `gate_payment`/policy constrains `epoch` to a fixed value. `gate_payment:183` binds the `epoch` signal to the `epoch` arg — confirm the policy does not pin a specific epoch. If epoch is free, randomize it per session; otherwise randomize another non-bound private input that feeds the nullifier. Document the choice.
- This is also a feature: a repeated submit of the *same* proof is the live **replay-rejection** moment for the demo (failure theater §6 of audit).
- Acceptance: from a clean browser, prove → submit → see a NEW testnet tx; repeat with a fresh session → another NEW tx; replay the exact same proof → on-chain `NullifierUsed` rejection surfaced in the UI.
- Risk: HIGH-touch item. ScVal encoding via bindings, Freighter signing API shape, and RPC submission are the main unknowns — verify the `@stellar/stellar-sdk` + freighter-api versions actually used. Time-box; if blocked, fall back to P3 "proof-only relabel" and flag immediately.

---

# PHASE 4 — Web wording precision [P0-3] (web only, no redeploy)
Fix every overclaim. Exact current strings (verified):
**P4.1** `apps/web/index.html:55` — "Reveal **nothing**." → "Reveal **no identity**." (or "Reveal no identity attributes"). Update hero gradient span accordingly.
**P4.2** `apps/web/gates.html:52` — "**Same proof**, different policy" → "**Same circuit**, different policy". `gates.html:53` — "Both gates verify the **same Groth16 proof**…" → "Both gates use the **same circuit and credential root**; each action produces **its own proof**…".
**P4.3** `apps/web/index.html:166` — "Compliance without surveillance" is acceptable but pair it with precise sub-copy; ensure nearby copy doesn't imply zero on-chain disclosure.
**P4.4** Privacy precision (reword absolutes to scoped claims): `index.html:172` "Raw identity never touches the ledger." → keep but ensure the page also states "proof signals, action data, and a nullifier ARE public" (add one line — the audit's recommended honest framing). `console.html:48` "Nothing private leaves your browser." → "Private credential inputs never leave your browser." `index.html:85` "Private inputs never leave the device." is fine.
**P4.5 RWA reframe [D3]:** on `/gates` (gate 02) and anywhere the RWA path is described, state it as **"ZK identity attestation for SEP-57 access"** — the mint is gated by proven *eligibility*, and clarify amount/recipient are set by the issuer/operator at mint, not bound by the proof. Add a note that an **action-bound RWA gate (`gate_rwa`) exists** in the repo as the alternative design.
**P4.6 VK wording:** anywhere the site/docs say "VK **pinned** on-chain" (e.g. `onchain.html` deploy facts, `deployments/*.json` `ceremony` string), change to "VK **admin-set, then frozen**" (true after P1.2) — or "admin-stored VK" if P1.2 were skipped (it isn't).
- Acceptance: no "Reveal nothing", no "same proof", no claim implying the mint amount is proof-bound, no "pinned" without the freeze being real. Re-grep to confirm.

---

# PHASE 5 — README + docs (judge-grade) [P0-4]
**P5.1 Rewrite root `README.md`** (currently 21 lines with a **DEAD demo link** to `preflight.gudman.xyz/anchorshield/` — that path was removed and now 404s). New top section per audit §8:
- One-line pitch: "ZK compliance gates for Stellar payments and RWAs."
- **Live demo: https://anchorshield.gudman.xyz** (FIX the dead URL), submission video link placeholder.
- "What works now" (proof gen, on-chain verify, payment gate live submit, RWA identity attestation, CLI/SDK, testnet artifacts).
- **"Real vs mock" table** (audit §8 — KYC/sanctions = mock credential attributes; issuer root + policy checks real; browser submission = real after P3; mainnet = not deployed; sanctions non-membership = not implemented).
- **"How ZK is load-bearing"**: name the exact call that fails without a valid proof (`gate_payment.verify_and_pay` → `InvalidProof`).
- **Live testnet artifacts table**: contract IDs + tx hashes + Stellar Expert links (from the new `testnet-hardened.json`).
- **Quickstart**: install, build circuit, generate proof, run tests, invoke testnet (pull real commands from `docs/M*.md`).
- **Security & limitations**: admin trust, VK governance (now freezable), write-once mappings, mock credential source, testnet-only, ceremony status.
**P5.2** Add `docs/SECURITY_REVIEW.md` update (file exists) capturing the audit findings + resolutions, and document `gate_rwa` as the action-bound RWA variant vs the deployed identity-attestation path (the real-vs-mock honesty the audit rewards).
**P5.3** Set the GitHub repo "About"/description + homepage to https://anchorshield.gudman.xyz.
**P5.4 [Productization audit §11] Add `docs/THREAT_MODEL.md`** — port the threat→mitigation table and add a **status column mapped to the real code**: proof replay → nullifier registry (DONE); amount/recipient/asset tamper → action-bound public signals consumed by `gate_payment` (DONE); frontend lies about policy → contract policy check (DONE); disclosure packet altered → `packet_hash` bound + now emitted (DONE after P1.4); credential expiry → attestation TTL cap (DONE after P1.1); VK replaced → `freeze_vk` (DONE after P1.2); recipient/token redirect → write-once mappings (DONE after P1.3); admin compromise / multisig / timelock / pause → PLANNED (post-hackathon). The honest status mapping is the deliverable — do not claim PLANNED items as done.
**P5.5 [Productization audit §2/§4] Positioning language** — adopt the precise compliance claim in the README + site one-liner: "AnchorShield provides cryptographic evidence that a Stellar action satisfied a configured eligibility policy at the time of execution," and frame privacy as **data minimization + selective disclosure** (reinforces Phase 4's removal of "reveal nothing"). Add a short "Production vision (post-hackathon)" line in the README pointing at `docs/ROADMAP.md` (see P-OOS) so judges see a credible path without implying it is built.
- Acceptance: a judge can understand + run the project in ≤5 min from the README; every link opens (test in incognito); no "steller"/"hackhaton" typos; demo URL is the live one; THREAT_MODEL.md status column is accurate against the shipped code.

---

# PHASE 6 — Final verification & deploy
**P6.1** Deploy refreshed `apps/web` to the VPS (scp the changed html/assets/data to `/opt/anchorshield/web`, `chown`, no nginx reload needed for static swaps). Additive only — never touch sibling apps.
**P6.2** Headless CDP verification (use `--headless=new` + `Emulation.setDeviceMetricsOverride`; the deprecated `--headless --screenshot` mis-sizes the viewport — do not trust it):
- All 5 routes 200, 0 JS errors, data hydrates (signatureFee, disclosure), **live payment submit produces a NEW testnet tx end-to-end**, replay shows on-chain rejection.
**P6.3** Link audit: every README/site link, contract id, and tx link opens. `cargo test --workspace` green. JSON valid.
- Acceptance: full green; record new contract IDs + tx hashes in memory.

---

# Out of scope / user-owned
- **Demo video** (Hackathon audit §7 script) — user records.
- **Submission form / final submit** — APPROVAL-GATED; do not submit.
- **Sanctions non-membership** (Hackathon audit P3 / Productization §10.E) — deferred (D4); leave `docs/STRETCH.md` note.
- **Mainnet** — explicitly not for the hackathon.

## P-OOS — Post-hackathon productization (capture as `docs/ROADMAP.md`, do NOT build now)
The **Productization Audit (2026-06-27)** is product strategy, not a hackathon build list — its "first 30 days" largely **restates the P0/P1 fixes already scoped above** (live submit, richer events, TTL cap, action-binding, mapping/replay hardening). Its own MVP-component table **confirms the current build already is a well-scoped Phase-1 MVP** (ZK proof + Soroban verifier + payment gate + policy/issuer/nullifier registries + encrypted disclosure + packet hash + auditor view all exist) — **no MVP rework needed**. Capture the forward-looking items in ONE task (write `docs/ROADMAP.md`); do **not** build them this sprint:
- AnchorShield **Pay / Passport / RWA** product framing, open-core model, go-to-market (§4-6, §12).
- **Anchor Platform middleware**: SEP-10 auth, SEP-31 hold/release, SEP-38 quote binding, webhooks (§10.A).
- **Disclosure Vault** productization: access grants, time-limited keys, audit log, evidence export (§10.B) — beyond the current static M4 disclosure demo.
- **Policy Engine** + **circuit registry / verifier router** with versioned circuit IDs (§10.C/D).
- **Dashboards** as real apps (§10.H) + **wallet/anchor SDK** packages (§10.G).
- **Action-bound RWA mint authorization** (§6, Days 61-90) — same path we deferred in D3; ship only post-hackathon.
- **Admin multisig / timelock / pause**, monitoring/indexer, revocation roots, production multi-party ceremony, independent audit (§11).

# Suggested commits (one per phase, no attribution, on `build/m0-toolchain`)
1. `feat(contracts): cap attestation TTL, freeze VK, write-once mappings, richer events`
2. `chore(deploy): hardened redeploy + refresh deployment/data artifacts`
3. `feat(web): live Freighter payment submission on /console`
4. `docs(web): precise privacy wording + RWA reframe`
5. `docs: judge-grade README + real-vs-mock + fix dead demo link`

---

# APPENDIX A — Phase A circuit design (VERIFIED, implementation-ready)
From a full read of `circuits/eligibility.circom`, circomlib 2.0.5, and the public-signal ABI in `contracts/shared/src/lib.rs`. This is the hardest/riskiest phase — follow it precisely.

**Current facts.** circom 2.2.0, `--prime bls12381`, Poseidon255, circomlib **2.0.5**, snarkjs 0.7.6. Public-signal vector = **outputs first, then public inputs = 17** (codified in `contracts/shared/src/lib.rs`, `PUBLIC_SIGNAL_COUNT=17`): `0 credential_root, 1 packet_hash(BOUND_HASH), 2 nullifier, 3 action_binding, 4 issuer_id, 5 policy_id, 6 kyc_required, 7 sanctions_required, 8 allowed_country, 9 min_age, 10 min_investor_type, 11 action_type, 12 asset_id, 13 amount, 14 recipient, 15 action_id, 16 epoch`. **Freshness/expiry is ALREADY implemented** in-circuit (`issued_at <= epoch <= expires_at`, `eligibility.circom:137-145`) — confirm only, no work.

**Construction (chosen): indexed/sorted-linked Merkle EXCLUSION proof ("low-leaf bracket")** on `Poseidon255` + the existing `MerkleProof` template + `LessThan(248)`/`IsZero` — for BOTH the deny-list and revocation trees. **Reject circomlib `smt`** (its Poseidon is BN254-field; no BLS off-chain tooling to build the tree). Tree leaf = `H(value, nextValue)` sorted by `value`, `nextValue=0` ⇒ +∞. Non-membership of `x` = inclusion of a low-leaf `L` with `L.value < x < L.nextValue`.
- **SOUNDNESS-CRITICAL:** truncate keys to ≤248 bits before any `LessThan` (`LessThan` needs `n<=252` and operands `< 2^n`; Poseidon255 output is ~255 bits). Compute `Poseidon255`, `Num2Bits(254)`, recompose low 248 bits. (A truncation collision can only cause a false *denial*, never a bypass.)

**Signal changes (minimize churn — APPEND public inputs, add NO new outputs, so indices 0-16 stay byte-identical):**
- New PUBLIC inputs appended after `epoch`: **`17 sanctions_root`, `18 revocation_root`**. `PUBLIC_SIGNAL_COUNT → 19`.
- New PRIVATE witness: `sanctions_{low_value,low_next,low_index,low_siblings[denyDepth]}` + `revocation_{...}`. Template → `Eligibility(treeDepth, denyDepth, revDepth)`; `main = Eligibility(2, denyDepth, revDepth)`. Recommend `denyDepth=revDepth=20`.
- **Remove `sanctions_clear`** (input + Boolean + the `sanctions_required*(1-sanctions_clear)===0` gate + its fold position); credential hash `FoldHash(10) → FoldHash(9)`. Enforce deny-list + revocation non-membership **UNCONDITIONALLY** (empty list = sentinel leaf `H(0,0)` brackets any `x>0`). `sanctions_required` stays as a policy echo.
- Bind computed roots: `sProof.out === sanctions_root`, `rProof.out === revocation_root`.

**Downstream (indices 0-16 unchanged → only count + additions):**
- `contracts/shared/src/lib.rs`: add `SANCTIONS_ROOT=17`, `REVOCATION_ROOT=18`; `PUBLIC_SIGNAL_COUNT=19`. `verify_proof`'s `ic.len()` check follows the regenerated VK.
- `gate_payment` / `identity_verifier` / `gate_rwa`: length guard auto-follows; **ADD root-binding** — compare `signal[17]/[18]` to roots from a **new/extended on-chain registry (DESIGN DECISION for Codex: add a deny-list/revocation root registry, admin-set, mirroring how `IssuerRegistry` supplies `credential_root`)**.
- `apps/web/assets/app.js` `PUBLIC_SIGNAL_INDEX`: add `sanctionsRoot:17, revocationRoot:18`.
- `packages/sdk/src/index.js` `PUBLIC_SIGNAL_NAMES`: append the two names. `scripts/m1-circuit-smoke.js`: `17→19`.
- `testdata/eligibility/input.valid.json` + `testdata/rwa/input.valid.json`: remove `sanctions_clear`; add roots + low-leaf witness (empty-tree sentinel bracket). Regenerate proof/public/vk via the ceremony. `services/disclosure` + `services/indexer` read only `[1]/[2]/[3]` — unchanged.

**Ceremony:** re-run `scripts/ceremony.sh` unchanged (circuit-agnostic). Keep `CEREMONY_POWER=16` (depth-20 ≈ ~23k constraints < 65,536); bump to 17 only if `snarkjs r1cs info` reports > ~50k. Regenerates wasm/zkey/vk → `apps/web/proving/` + `testdata/`.

**Malicious-witness tests Codex MUST add:** listed identity cannot prove absence; forged low-leaf (root mismatch); non-strict bracket (`value==key`); sentinel abuse (`next=0` on a non-max leaf); un-truncated key; revocation analogues; + an honest-path E2E regression.

---

# Handover status (2026-06-27)
- This doc is the single source of truth. Decisions locked: **maximal in-repo build** — circuit non-membership + revocation + fresh ceremony (Appendix A); contract hardening + **action-bound RWA mint** (D3 flipped to IMPLEMENT); live Freighter submission + SDK; demo-grade dashboards + local disclosure vault + mock SEP-10/31/38 adapters; wording + README + threat-model + roadmap docs. Tier C (real anchor/KYC pilots, independent audit, production ceremony, mainnet, GTM) stays deferred.
- **Not yet started in code.** Foundation only: plan locked, circuit design verified (Appendix A), build env corrected (Windows toolchain). Baseline `cargo test --workspace` still needs a first run.
- Branch: `build/m0-toolchain`. Build on **Windows** (toolchain paths above).
