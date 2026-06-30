# Security Review

## Scope Reviewed

- `circuits/eligibility.circom`
- `contracts/verifier`
- `contracts/issuer_registry`
- `contracts/policy_registry`
- `contracts/nullifier_registry`
- `contracts/gate_payment`
- `contracts/gate_rwa`
- `contracts/identity_verifier`
- `contracts/rwa_compliance_adapter`
- `tools/groth16-json-converter`
- `services/disclosure`
- `services/indexer`
- `services/mock-anchor`
- `packages/sdk`
- `packages/cli`
- `apps/web`

## Passing Checks

| Area | Check | Status |
| --- | --- | --- |
| Circuit | invalid KYC, country, amount, expiry, investor witnesses reject | Pass |
| Circuit | sanctions deny-list non-membership rejects listed subject | Pass |
| Circuit | revocation non-membership rejects revoked credential | Pass |
| Circuit | forged low-leaf and root mismatch witnesses reject | Pass |
| Circuit | action-binding public-signal mutation rejects | Pass |
| Converter | golden fixtures convert to Soroban CLI layout | Pass |
| Payment gate | valid proof pays; wrong action, policy, packet hash, reused nullifier, rotated root, stale roots reject | Pass |
| RWA authorization | `attest_for_mint` binds asset, amount, recipient, action id, terms hash, roots, and nullifier | Pass |
| RWA compliance adapter | consumes a mint authorization once during the OZ token mint path | Pass |
| Verifier | VK is admin-set by circuit id/version, frozen, and cannot be replaced after freeze | Pass |
| Disclosure | encrypted packet decrypts and verifies against proof `packet_hash` | Pass |
| Indexer | testnet events normalize into no-PII dashboard data with packet/action hash checks | Pass |
| Browser | self-serve wallet/KYC enrollment derives the secret in-browser, refreshes the issuer path before proving, and keeps witness upload as an advanced fallback | Pass |

## Resolved Findings

| Finding | Resolution |
| --- | --- |
| Payment event omitted packet/action hashes | `PaymentApproved` now emits `packet_hash` and `action_binding`; the indexer verifies both. |
| RWA mint was eligibility-only | `identity_verifier.attest_for_mint` creates a one-time action-bound authorization consumed by `rwa_compliance_adapter`. |
| VK could be replaced by admin after deploy | `freeze_vk` locks the configured circuit/version VK. |
| Payment recipient/token mappings were mutable | `gate_payment` mappings are write-once per id. |
| Long-lived attestations | attestation validity is capped by contract TTL logic. |
| Issuer-attested deny-list status | deny-list and revocation non-membership are proven in-circuit against committed roots. |
| Browser only linked historical txs | `/console` includes Freighter/RPC submit and self-serve proof paths; pre-executed links remain fallback evidence. |

## Remaining Risks

| Risk | Status |
| --- | --- |
| Production ceremony | Deferred. The current ceremony is autonomous-tier, not independent multi-party. |
| Admin governance | Testnet uses a single admin address. Mainnet needs multisig/timelock governance. |
| Production anchor/KYC source | Partial: `clean-demo-user` credential is Sumsub-KYC-backed and browser SEP-10/38 plus scripted SEP-12 are verified live against testanchor. Deferred: a licensed anchor (full SEP-31 receive) and independent accreditation verification. |
| Hosted disclosure vault | Deferred. Current vault is a local encrypted artifact and grant log. |
| Mainnet deployment | Deferred and approval-gated. |
| Package publishing | Packages are public-ready at `0.1.0`; future publishes remain approval-gated and must pass version-existence preflight. |
| Freighter E2E automation | Manual-wallet path only; headless tests cannot sign with a real user extension. |

## Mainnet Blockers

- Independent production ceremony.
- External security review.
- Multisig/timelock admin path and runbook rehearsal.
- Real issuer/anchor integration and revocation operations.
- Production disclosure-vault custody model.
- Explicit user approval for mainnet deployment and any future package publishing.
