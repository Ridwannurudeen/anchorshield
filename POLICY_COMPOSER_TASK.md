# Task for Codex — Policy Composer (generate a deployable AnchorShield gate from a policy spec)

Turns AnchorShield from "integrate us for payments/RWA" into "compose a policy → get a deployable gate +
frontend + tests in seconds." This is the automation layer on top of `INTEGRATION_RECIPE_TASK.md`
(the hand-written recipe). Inspired by HSK Passport's Policy Composer, built Stellar/Soroban-native.

## Branch / base — READ THIS FIRST (verified divergence)
- Build on **`feat/policy-composer` off `release/onboarding-prod`**. NOT off `main`.
- Verified: `release/onboarding-prod` is **15 commits ahead of `main`**, and its `Policy`
  (`contracts/shared/src/lib.rs`) has an extra field the live stack enforces:
  ```
  pub struct Policy { policy_id, issuer_id, circuit_id: BytesN<32>, circuit_version, kyc_required: bool,
    sanctions_required: bool, allowed_country, min_age, min_investor_type, min_credential_members }  // 10 fields
  ```
  `main`'s Policy has only 9 (no `min_credential_members`). The live `CBZQCAVZ…` stack is the
  onboarding-prod lineage. Generated gates MUST match it.
- **DONE:** the proven Model-A template is already on `release/onboarding-prod` — `examples/airdrop_gate`
  (ported + adapted to the production contracts: `set_root` member_count, `Policy.min_credential_members`;
  4/4 tests + wasm green here) and `docs/INTEGRATION.md`. Just branch `feat/policy-composer` off
  `release/onboarding-prod`; no merge needed. (Full `feat/integration-recipe` branch was NOT merged — it was
  cut from an older `main` and conflicts on `react.js`/`server.js`/testdata/binaries; only the two template
  artifacts were ported.)

## Verified primitives to template from (confirmed this session)
- `contracts/shared/src/lib.rs`: `Policy` (above); public-signal layout constants (CREDENTIAL_ROOT=0,
  BOUND_HASH=1, NULLIFIER=2, ACTION_BINDING=3, ISSUER_ID=4, POLICY_ID=5, KYC_REQUIRED=6,
  SANCTIONS_REQUIRED=7, ALLOWED_COUNTRY=8, MIN_AGE=9, MIN_INVESTOR_TYPE=10, ACTION_TYPE=11, ASSET_ID=12,
  AMOUNT=13, RECIPIENT=14, ACTION_ID=15, EPOCH=16, SANCTIONS_ROOT=17, REVOCATION_ROOT=18,
  PUBLIC_SIGNAL_COUNT=19); `verify_proof`, `require_signal_u32/u128`, `bool_as_u32`; the
  `#[contractclient]` peer-client pattern (gates call peers via generated clients, never depend on peer crates).
- `contracts/policy_registry/src/lib.rs`: `set_policy(env, policy: Policy)` (admin-gated, ~:62),
  `policy(env, policy_id) -> Option<Policy>` (~:70). Registering a composed policy yields its on-chain record.
- `contracts/gate_payment/src/lib.rs` (onboarding-prod): the Model-B template. `init(env, admin, verifier,
  policy_registry, issuer_registry, nullifier_registry, …)`; `verify_and_pay` loads the policy, asserts every
  identity signal, checks the credential root in issuer_registry, enforces `member_count <
  policy.min_credential_members` (anonymity floor) + emits a low-anonymity event, consumes the nullifier via
  `NullifierRegistryPeerClient`, then performs the action. Imports the peer clients from `shared`.
- `examples/airdrop_gate/src/lib.rs` (from feat/integration-recipe): the Model-A template — peer-client
  `verify_identity(account)` gating + one-action-per-account state + admin/init/error-enum style. Tests in
  `examples/airdrop_gate/src/test.rs` (attested / unattested / expired / repeat) are the test template.
- `packages/cli/anchorshield.js`: single-file CLI. `args(argv)` → `options._` positionals; dispatch is
  `if (command === "…")` blocks (existing: inspect-public, validate-action, soroban-args, events,
  `disclosure verify`, `gate payment|rwa`). Add the new command in the same style. `usage()` lists commands.
- `packages/sdk/src/react.js` (+ `react.d.ts`): `AnchorShieldGate` component + `useAnchorShield` hook — the
  frontend gate to reference in generated snippets. Contract IDs live in `apps/web/data/deployments.json`.

## MVP — `anchorshield compose` generates a Model-A gate bundle
Add a `compose` command to `packages/cli/anchorshield.js`. Input: a policy spec via flags or a `--spec
file.json` (fields: `name`, `issuer_id`, `kyc_required`, `sanctions_required`, `allowed_country`, `min_age`,
`min_investor_type`, `min_credential_members`, `circuit_id`, `circuit_version`, optional `once_per_account`).
`anchorshield compose --spec ./policy.json --out ./generated` emits:
1. **`policy.json`** — the composed `Policy` as the exact JSON the `set_policy` contracttype expects, PLUS the
   ready-to-run `stellar contract invoke <policy_registry_id> --source <admin> -- set_policy --policy-file-path
   policy.json` command (pull `policy_registry` id from `apps/web/data/deployments.json`). Registering it is
   how the integrator gets their `policy_id`.
2. **`gate_<name>/`** — a Soroban crate generalized from `examples/airdrop_gate`: peer-client
   `verify_identity(account)` gating against the identity_verifier, the composed `policy_id` baked into `init`,
   a clearly-marked `on_verified`/event hook where the integrator puts their action, and (if `once_per_account`)
   the claim-once persistent state. Match the airdrop_gate style exactly (error enum, DataKey, events).
3. **`gate_<name>/src/test.rs`** — generated tests mirroring airdrop_gate's four cases.
4. **`Gate.jsx`** — a React snippet wiring `<AnchorShieldGate>` / `useAnchorShield` + `@anchorshield/sdk` for
   this policy, with the contract IDs from deployments.json filled in.
5. **`README.md`** — build (`cargo build --target wasm32v1-none --release`), register-policy, deploy, and the
   attest→use walkthrough.

Also extend `usage()` and add a `packages/cli/test.js` case that runs `compose` on a fixture spec and asserts
the generated crate builds + its tests pass (or at least that files are emitted and `cargo build` succeeds).

## Stretch (only if MVP is green; do NOT jeopardize MVP correctness)
- **Model-B generator** (`--model per-action`): generate an unlinkable per-action gate from `gate_payment`
  (proof + pub_signals + nullifier consumption + anonymity floor), leaving asset/amount/recipient signals as
  generic action params. Ship ONLY if the generated crate's tests pass — a subtly-wrong per-action gate is
  worse than not shipping it. Otherwise document it as "coming next" in the README.
- **Hosted `/composer` web page** mirroring the CLI output for copy-paste (like HSK's). Separate follow-up.

## Constraints & acceptance
- Testnet only. No changes to core contract logic. No on-chain broadcast, no deploy, no live/staging server
  changes, no secrets. Do NOT rotate/paste Sumsub creds.
- `anchorshield compose --spec <fixture> --out <tmp>` produces a crate that `cargo build --target
  wasm32v1-none --release` compiles AND whose generated `cargo test` passes. `cargo fmt --check` +
  `cargo clippy` clean on the generated crate. `node packages/cli/test.js` green. Existing workspace tests
  still green.
- Leave committed on `feat/policy-composer` (do not merge, do not push tags, do not deploy). Claude/user reviews.
