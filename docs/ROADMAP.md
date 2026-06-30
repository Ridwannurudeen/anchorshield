# Roadmap

## Shipped In This Build

- Circuit-level sanctions deny-list and credential revocation non-membership.
- Fresh autonomous-tier Groth16 ceremony and regenerated browser proving artifacts.
- Versioned verifier with frozen VK.
- Root binding against issuer, sanctions, and revocation roots.
- Payment gate hardening: TTL, write-once mappings, richer events, pause support, and replay checks.
- Action-bound RWA mint authorization consumed by a compliance adapter.
- Live Stellar testnet redeploy with payment and RWA mint transactions.
- Browser Freighter/RPC payment submission path with self-serve wallet/KYC enrollment.
- Depth-16 credential tree, commitment-only enrollment state, on-demand Merkle-path refresh, and current/previous credential-root acceptance in the gates.
- SDK, CLI, generated bindings, local disclosure vault, mock SEP-10/31/38 adapter, and product dashboards.

## Productionization Tracks (Mock to Real)

These four tracks replace the hackathon stand-ins with real inputs. The cryptographic
machinery (circuit, on-chain verification, value transfer) is already real; each track
supplies real data or a real counterparty into existing, clean seams.

1. Real KYC credentials (IMPLEMENTED LOCALLY). `services/issuer/issue.js` reads a
   depth-16 roster, issues credential leaves, builds the credential Merkle tree, writes
   per-user proving witnesses, and prints the exact bare-decimal
   `issuer_registry.set_root` command. `services/issuer/enrollment-store.js` appends
   KYC-gated wallet commitments without storing user secrets, and the browser refreshes
   the Merkle path before proving. `npm run issuer:publish-roots` dry-runs root
   publication; execution remains approval-gated.
2. Real sanctions and revocation data (IMPLEMENTED LOCALLY). `npm run ofac:sync` ingests
   the live OFAC SDN CSV, `services/issuer/lib/ofac.js` screens the roster, and the issuer
   builds populated depth-20 sanctions/revocation exclusion trees. A clean user proves
   against deployed artifacts; an OFAC-matched user cannot produce a non-membership
   witness. Root publication remains approval-gated.
3. Real anchor (SANDBOX CLIENT READY). The deterministic mock remains for local fixtures,
   and `services/anchor/sep-client.js` now provides a config-driven SEP-10/31/38 sandbox
   client for a licensed anchor partner. Real credentials and partner transaction evidence
   are intentionally not committed; see `docs/ANCHOR_SANDBOX.md`.
4. Mainnet readiness (PREFLIGHT GATED). `npm run mainnet:preflight` blocks mainnet until
   explicit approval, an independent ceremony transcript, external audit evidence,
   multisig/timelock admin config, real anchor sandbox evidence, and issuer roots are
   present; see `docs/MAINNET_READINESS.md`.

## Next 30 Days

- External security review focused on the circuit, root registries, event model, and RWA adapter.
- Production admin implementation: multisig, timelock, emergency procedures, and rotation rehearsal.
- Hosted disclosure-vault prototype with auditable key grants and revocation.
- Real anchor partner sandbox run using `services/anchor/sep-client.js`.
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
