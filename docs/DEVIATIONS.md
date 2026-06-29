# Deviations

This file records where the shipped implementation differs from the original `docs/BUILD-PLAN.md`. The build plan remains useful as product background, but this file and the README describe the current artifact.

## Current Implementation

- The workspace uses `soroban-sdk = 26.1.0`.
- The Groth16 circuit is BLS12-381 and exposes 19 public signals.
- Signals 0-16 keep the original payment/RWA ABI order.
- `sanctions_root` and `revocation_root` are appended at indices 17 and 18.
- Deny-list and revocation checks are in-circuit indexed Merkle non-membership proofs.
- The verifier stores VKs by `circuit_id` and `circuit_version`, then freezes the configured VK.
- Roots live in the issuer registry alongside credential roots.
- Payment and RWA flows bind roots, policy fields, action fields, packet/terms hash, epoch, action binding, and nullifier.

## Resolved Hardening Items

| Item | Resolution |
| --- | --- |
| Contract split | The verifier, issuer registry, policy registry, nullifier registry, payment gate, RWA gate, identity verifier, and RWA compliance adapter are separate contracts with shared types in `contracts/shared`. |
| Real payment transfer | `gate_payment.verify_and_pay` performs a real testnet SAC transfer after proof verification. |
| RWA proof binding | `identity_verifier.attest_for_mint` creates a one-time action-bound authorization consumed by `rwa_compliance_adapter` during the OZ token mint. |
| Ceremony | `scripts/ceremony.sh` produces the current autonomous-tier Groth16 proving key, wasm, VK, and fixtures. |
| VK replacement | `freeze_vk` prevents post-configuration VK replacement. |
| Mutable payment mappings | `gate_payment` token and recipient mappings are write-once per id. |
| Attestation lifetime | identity attestations are capped by contract TTL logic. |
| Event observability | payment and RWA events include packet/terms hash and action binding data consumed by the indexer. |
| Browser submit | `/console` includes a Freighter/RPC submit path for `verify_and_pay`; pre-executed links remain as fallback evidence. |
| SDK/CLI | `packages/sdk`, `packages/cli`, and generated TypeScript bindings are present and tested locally. |
| Demo productization | anchor, issuer, RWA, auditor, and disclosure-vault dashboards are static routes backed by generated JSON artifacts. |

## Still Deferred

- Independent production ceremony with external contributors.
- Production admin multisig/timelock governance.
- Licensed/production anchor (full SEP-31 receive) and independent accreditation verification. (Basic identity KYC via Sumsub and live SEP-10/12/38 anchor auth/quote are done.)
- Hosted disclosure vault and production key custody.
- Relayer support with caller/source binding.
- UltraHonk and RISC Zero backends.
- Mainnet deployment and package publishing.

## Historical Notes

- Early M1/M2 artifacts used co-located mock ledgers. The current hardened deployment supersedes those artifacts.
- Early M3 pages generated browser proofs and linked pre-executed transactions. The current `/console` adds the live submit path.
- Some M0-M6 docs intentionally preserve milestone history. Use the README, `docs/SECURITY_REVIEW.md`, `docs/CEREMONY.md`, and `deployments/testnet-hardened.json` for current-state claims.
