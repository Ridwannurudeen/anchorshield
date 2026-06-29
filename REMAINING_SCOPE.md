# Remaining Scope — Finish Productionization

Handover for Codex to complete the work after commit `1eb047b`. Read this in full before
starting. Nothing is committed beyond your own branch work without it being obvious; nothing
is published/deployed to mainnet/submitted without explicit user approval.

## Verified current state (checked this session — build on it, don't redo)

- HEAD `1eb047b` pushed to `origin/build/m0-toolchain`, working tree clean.
- Tracks 1 & 2 DONE and proven: `node services/issuer/test.js` = **11/11 green**, including
  the end-to-end gate "clean issuer witness fullProve/verify passes deployed artifacts"
  (a populated-tree witness produces a Groth16 proof that verifies against the deployed VK).
- `services/issuer/data/sdn.csv` = 19,123 lines (real OFAC SDN list synced). `sample-sdn.csv`
  = 6 real rows.
- `services/anchor/sep-client.js` + `anchor.config.example.json` present; `anchor.config.json`
  absent (needs real partner creds). `node services/anchor/sep-client.test.js` = OK.
- npm scripts present: `ofac:sync`, `issuer:publish-roots`, `anchor:test`, `mainnet:preflight`.
- **Deployed testnet admin = `GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`**
  (the fresh maximal-build redeploy's admin — NOT the old `anchorshield-m0`/`GAKI4FQW…`).
- `stellar keys ls` returns nothing — no local identities configured.
- Packages `anchorshield` and `@anchorshield/sdk` are `0.0.0`, `private: true`.

## Build environment (unchanged)

- Rust/contract tests run in **WSL** (`bash scripts/test.sh`); the Windows host has no MSVC
  linker and Smart App Control blocks freshly-built test exes.
- Node/snarkjs run on Windows fine (pure JS/wasm).
- Security hook blocks any `0x`+64-hex literal; write field constants in decimal.
- Always re-run `node services/issuer/test.js` and `bash scripts/test.sh` after changes.

---

## BUCKET A — Build and test fully now (no external dependency)

Dependency-ordered. Each is completable + testable by Codex end-to-end on testnet/local.

### A1. Multisig + timelock admin governance (highest value)
Today every contract gates writes on a single admin `Address` (`require_admin` in
`contracts/*/src/lib.rs`, e.g. `issuer_registry/src/lib.rs:113`). Production needs distributed
control.
- Design + implement a `governance` contract (or adopt a Stellar multisig account as admin):
  propose → timelock delay → execute, with a configurable signer set/threshold and an
  emergency path. Decide and document the chosen model (dedicated governance contract that
  becomes admin of registries/verifier/gates vs. native multisig account).
- Add an admin-transfer flow + runbook to migrate each contract's admin to the governance
  address. Build and TEST it on a FRESH testnet deploy with Codex-controlled test signers.
- Add config (`governance.config.json`) + tests. The LIVE-deployment cutover is user-gated
  (needs the live admin secret) — implement and rehearse, then stop for user.

### A2. Monitoring / indexer service
- Service that watches the registries via RPC/Horizon for: root changes
  (`CredentialRootSet`/`SanctionsRootSet`/`RevocationRootSet`), replay attempts (nullifier
  reuse / `InvalidProof`), and failed proofs; emits alerts (log + webhook seam).
- Build against testnet, with tests over recorded event fixtures.

### A3. Production issuer operations
- Turn the issuer scripts into an ops workflow: scheduled `ofac:sync`, sanctions/revocation
  root rotation runbook, deny-list update flow, and root-staleness monitoring. Wire to A2.
- Tests for re-sync + rotation producing new valid roots + witnesses (reuse the fullProve gate).

### A4. Browser-wallet E2E harness
- Automated E2E for the Freighter payment path (the user-signature submit was never
  exercised). Use a mock/injected signer where a human isn't available; document the manual
  signing steps for the real-wallet run.

### A5. Cost + latency benchmarks
- Extend `docs/BENCHMARKS.md` with measured proof-generation latency (browser + node) and
  Soroban verification cost (fees/instructions) from real testnet runs.

### A6. Package publish PREP (not the publish)
- Bump `anchorshield` + `@anchorshield/sdk` off `0.0.0` to real semver, fill package.json
  metadata (description, repository, license, `files`, `exports`), and write
  `docs/PUBLISH_CHECKLIST.md`. Leave `private`/the actual `npm publish` for the user —
  publishing is approval-gated.

---

## BUCKET B — Prepare, document, then STOP for the user (human/external-gated)

Codex cannot complete these alone; make them one-command/one-step ready and hand back.

### B1. Publish issuer roots on testnet
Blocked: no local Stellar identity. The deployed admin is `GAJJW5XC…35U`; only the user holds
its secret. Action: keep `npm run issuer:publish-roots` correct and ensure it executes cleanly
once an identity is imported; document the exact import + execute steps
(`stellar keys add …`, then `ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 npm run issuer:publish-roots -- --execute`).
Verify the published roots match `services/issuer/out` afterward.

### B2. Real anchor sandbox run
Blocked: needs a licensed anchor's sandbox endpoints/token/customer IDs and a real
`services/anchor/anchor.config.json` (see `anchor.config.example.json` + `docs/ANCHOR_SANDBOX.md`).
Keep `sep-client.js` and its mocked tests current; document the exact config keys required.

### B3. Mainnet readiness (`npm run mainnet:preflight` fails closed until complete)
Needs, in order: A1 governance config present + live admin migrated; an independent
production ceremony transcript (independent contributors + public beacon — coordinate/prepare
scripts, can't run solo); an external audit report (audit firm); B2 anchor evidence; B1 roots
published. Only then the staged mainnet go/no-go. Prepare every artifact slot the preflight
checks; do not deploy mainnet (hard approval gate).

### B4. Actual package publish
After A6 + user approval only.

---

## Suggested order

A1 → A3 → A2 → A4 → A5 → A6 (Bucket A is the real engineering value), then make B1–B4
one-step-ready and hand back with a precise list of exactly what the user must supply
(admin secret, anchor creds, audit, ceremony participants, publish approval).

## Definition of done for this handover
- All Bucket A items implemented, tested (`node services/issuer/test.js` + `bash scripts/test.sh`
  green), committed, and pushed to `build/m0-toolchain`.
- Bucket B items prepared to a single documented step each, with a clear "user must provide X"
  list. No mainnet deploy, no package publish, no root execution without the user.
