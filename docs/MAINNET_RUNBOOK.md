# Mainnet Runbook

## Status

Mainnet deployment is not executed.

The current repo is testnet-ready and demo-ready, but production mainnet remains blocked by:

- explicit user approval for mainnet deployment
- production multi-party Groth16 ceremony
- direct packet/terms hash emission in approval events
- admin multisig/timelock/pause path
- final security review after the above changes

## Preflight

1. Freeze `circuits/eligibility.circom` and included components.
2. Run the production ceremony in `docs/CEREMONY.md`.
3. Replace `apps/web/proving/eligibility_final.zkey` and verification keys with ceremony artifacts.
4. Update gate events to emit packet/terms hash directly.
5. Replace the single-address admin with a tested multisig/timelock/pause path.
6. Run:

```bash
npm run m5:verify
npm run m6:verify
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

Do not publish npm packages until the user gives explicit approval in chat.

Before publishing:

1. Verify package name availability.
2. Remove `private: true` only from packages approved for publication.
3. Build generated bindings.
4. Pack locally with `npm pack --dry-run`.
5. Publish only the approved package/version.
