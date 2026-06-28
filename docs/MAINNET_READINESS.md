# Mainnet Readiness Gate

Mainnet deployment remains blocked until the repository has evidence for each production
requirement. The gate is executable:

```bash
npm run mainnet:preflight
```

It intentionally fails until all approval and external artifacts are present.

## Required Evidence

| Requirement            | Evidence                                                                      |
| ---------------------- | ----------------------------------------------------------------------------- |
| Explicit user approval | `ANCHORSHIELD_MAINNET_APPROVED=1`, set only after approval in chat            |
| Production ceremony    | `ceremony/production/transcript.json` with independent contributor transcript |
| External audit         | `audits/external-security-review.md` or `.pdf`                                |
| Admin governance       | `deployments/admin-governance.mainnet.json`                                   |
| Real anchor sandbox    | `services/anchor/out/sandbox-run.json`                                        |
| Issuer roots           | `services/issuer/out/issuance.json`                                           |
| Fresh deploy plan      | no pre-existing `deployments/mainnet.json` for first deploy                   |

Issuer root publishing is a separate gate:

```bash
npm run issuer:publish-roots
ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 npm run issuer:publish-roots -- --execute
```

Only run the execute form after explicit approval.

## Governance Shape

The mainnet admin should not be the current single testnet operator. Use a production
admin address controlled by multisig/timelock operations with:

- root rotation proposals for credential, sanctions, and revocation roots
- emergency pause/unpause authority
- verifier and policy changes gated behind timelock review
- runbook rehearsal before deploying live value flows

## Go/No-Go

Go only when:

- `npm run m5:verify`, `npm run m6:verify`, `node services/issuer/test.js`, and
  `node services/anchor/sep-client.test.js` pass
- the production ceremony transcript verifies against frozen circuit artifacts
- the external audit has no unresolved critical/high findings
- the anchor sandbox run proves SEP-10/31/38 quote and transaction binding
- the user gives explicit approval for mainnet deployment

No-go if any gate is missing, stale, unverifiable, or manually bypassed.
