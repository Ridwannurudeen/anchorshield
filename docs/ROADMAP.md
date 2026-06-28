# Roadmap

## Shipped In This Build

- Circuit-level sanctions deny-list and credential revocation non-membership.
- Fresh autonomous-tier Groth16 ceremony and regenerated browser proving artifacts.
- Versioned verifier with frozen VK.
- Root binding against issuer, sanctions, and revocation roots.
- Payment gate hardening: TTL, write-once mappings, richer events, pause support, and replay checks.
- Action-bound RWA mint authorization consumed by a compliance adapter.
- Live Stellar testnet redeploy with payment and RWA mint transactions.
- Browser Freighter/RPC payment submission path.
- SDK, CLI, generated bindings, local disclosure vault, mock SEP-10/31/38 adapter, and product dashboards.

## Next 30 Days

- External security review focused on the circuit, root registries, event model, and RWA adapter.
- Production admin design: multisig, timelock, emergency procedures, and rotation runbooks.
- Hosted disclosure-vault prototype with auditable key grants and revocation.
- Real anchor partner sandbox for SEP-10 auth, SEP-31 receive/hold/release, and SEP-38 quote binding.
- Browser-wallet E2E tests with a dedicated manual signing harness.
- Cost and latency benchmarks for proof generation and Soroban verification.

## Days 31-90

- Independent production ceremony with public transcript.
- Production issuer/revocation operations and deny-list update workflow.
- SDK packaging plan, package naming, and publish approval checklist.
- Monitoring/indexer service with alerts for root changes, replay attempts, and failed proofs.
- Mainnet deployment plan and staged go/no-go checklist.

## Deferred Research

- UltraHonk adapter behind the verifier layer.
- RISC Zero router integration for non-circuit-native compliance computations.
- Relayer support with caller/source-account binding.
- Additional product lanes: AnchorShield Pay, AnchorShield Passport, and AnchorShield RWA.

No mainnet deployment, package publishing, production KYC pilot, or external submission is executed without explicit approval.
