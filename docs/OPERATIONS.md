# Production Operations

## Issuer Ops

Run a deterministic root rotation from the current roster, revocation list, and OFAC data:

```bash
npm run issuer:ops
```

Outputs:

- `services/issuer/out/issuance.json`
- `services/issuer/out/rotation-report.json`
- `services/issuer/out/ops-status.json`

Use `npm run issuer:ops -- --sync` only when the environment can fetch the official OFAC `sdn.csv`. The test path uses a mocked fetch:

```bash
npm run issuer:ops:test
```

Root publishing remains separate and approval-gated:

```bash
npm run issuer:publish-roots
ANCHORSHIELD_STELLAR_SOURCE=anchorshield-admin ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 npm run issuer:publish-roots -- --execute
npm run issuer:publish-roots -- --verify
```

The source identity must be imported locally first with the live admin secret for
`GAJJW5XC23IRZXGY2F36JP4GDFSQ4A65FTZLWCO4EA4JKYZGHEKZJ35U`. The Stellar CLI supports
interactive import with `stellar keys add anchorshield-admin --secret-key`; do not commit or
paste the secret into any repo file. After execution, `--verify` writes
`services/issuer/out/root-publish-report.json` only if the on-chain root getters match the
issuer output roots.

All human-gated production blockers can be checked together:

```bash
npm run bucket-b:preflight
```

## Monitoring

The monitor reads normalized event fixtures or indexed event JSON, checks root changes, duplicate nullifiers, invalid proofs, and root freshness, then emits log alerts and optionally posts a webhook:

```bash
npm run monitor:check
ANCHORSHIELD_ALERT_WEBHOOK_URL=https://example.test/hooks/anchorshield npm run monitor:check
```

Deterministic alert tests:

```bash
npm run monitor:test
```

## Governance

Admin migration and timelock details are in `docs/GOVERNANCE.md`. Mainnet cutover requires the live admin secret and explicit user approval.

## Wallet E2E

Automated Freighter-compatible mock signer:

```bash
npm run wallet:e2e
```

Manual Freighter steps are in `docs/WALLET_E2E.md`.

## Benchmarks

Capture Node proof latency, browser timing input, and testnet fee data:

```bash
npm run benchmarks -- --browser-ms=<measured_browser_ms>
```

Latest measurements are in `docs/BENCHMARKS.md` and `docs/benchmarks/latest.json`.
