# Mainnet Runbook

## Status

Mainnet deployment is not executed.

The current repo is testnet-ready and demo-ready, but production mainnet remains blocked by:

- explicit user approval for mainnet deployment
- production multi-party Groth16 ceremony
- governance cutover from the live single admin to `anchorshield-governance`
- final security review after the above changes
- real anchor sandbox evidence

## Preflight

1. Freeze `circuits/eligibility.circom` and included components.
2. Run the production ceremony in `docs/CEREMONY.md`.
3. Replace `apps/web/proving/eligibility_final.zkey` and verification keys with ceremony artifacts.
4. Rehearse `docs/GOVERNANCE.md` on a fresh testnet deployment.
5. Replace the live single-address admin with the governance contract only after user approval:
   deploy `contracts/governance`, `init` it with the signer set/thresholds from
   `deployments/admin-governance.mainnet.example.json` (copy to `admin-governance.mainnet.json`
   and fill placeholders), then call `transfer_admin(<governance_contract_id>)` on each of the
   eight governed contracts.
6. Run:

```bash
npm run m5:verify
npm run m6:verify
node services/issuer/test.js
node services/anchor/sep-client.test.js
npm run issuer:ops:test
npm run monitor:test
npm run wallet:e2e
npm run benchmarks -- --browser-ms=<measured_browser_ms>
npm run bucket-b:preflight
npm run mainnet:preflight
```

7. Generate fresh TypeScript bindings with `stellar contract bindings typescript`.
8. Create `deployments/mainnet.json` only after deployment.

## Deployment Gate

Do not deploy mainnet from this repo until the user gives explicit approval in chat.

When approved, deploy the flagship payment flow first, capture the public Stellar Expert transaction URL, then update:

- `deployments/mainnet.json`
- `docs/M6.md`
- `docs/BENCHMARKS.md`
- `README.md`

## Publishing Gate

Do not publish any new npm package version until the user gives explicit approval in chat.

Before publishing:

1. Verify package names and current versions on npm.
2. Bump the approved package version if the current version already exists.
3. Run `npm run publish:preflight`.
4. Follow `docs/PUBLISH_CHECKLIST.md`.
5. Build generated bindings.
6. Pack locally with `npm pack --dry-run`.
7. Publish only the approved package/version.
