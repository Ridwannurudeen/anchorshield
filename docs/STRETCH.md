# Stretch Backends And Advanced ZK

## Verified Upstreams

Checked on 2026-06-26:

| Backend | Repo | Commit | Verified interface |
| --- | --- | --- | --- |
| UltraHonk | `NethermindEth/rs-soroban-ultrahonk` | `661db07200f890b1bd9a7349ed787c70a706dd12` | `UltraHonkVerifierContract.verify_proof(env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error>` |
| RISC Zero | `NethermindEth/stellar-risc0-verifier` | `e8ff6ea202db195352c0141ecc533ff649393fe4` | `RiscZeroVerifierRouter.verify(env, seal: Bytes, image_id: BytesN<32>, journal: BytesN<32>) -> Result<(), VerifierError>` |

## Implemented Since M6

- Sanctions deny-list non-membership is now in the Groth16 circuit.
- Credential revocation non-membership is now in the Groth16 circuit.
- Public roots are appended at signal indices 17 and 18, keeping indices 0-16 stable.
- Payment and RWA events include bound packet/action hashes for the indexer.
- The RWA mint path has a one-time action-bound authorization consumed by the compliance adapter.

## UltraHonk

UltraHonk remains deferred.

Verified details:

- Requires Noir `1.0.0-beta.9`.
- Requires Barretenberg `0.87.0`.
- The wrapper stores an immutable VK at construction.
- The verifier entrypoint accepts raw `public_inputs` and `proof_bytes`.
- The upstream workspace uses `soroban-sdk = 26.0.1`; AnchorShield now uses `soroban-sdk = 26.1.0`.

Decision: do not add an UltraHonk adapter until the AnchorShield statement is ported to Noir and measured on Protocol 26 with a real proof.

## RISC Zero

RISC Zero remains deferred.

Verified details:

- The router dispatches by the first 4 bytes of `seal`.
- The router verifies with `seal`, `image_id`, and `journal`.
- Router mutation is intended to be owned by a timelock.
- The repo includes an emergency-stop wrapper and a mock verifier for development only.

Decision: do not use the mock verifier as an acceptance artifact. The first real slice should verify a small guest whose journal commits to the same action-binding fields.

## Relayer

No relayer is implemented.

Reason: a fee-paying relayer should be added only after caller/source-account binding and front-running tests are extended.

## Production-Only Work

- Independent multi-party production ceremony.
- Real KYC/anchor pilots.
- Hosted disclosure vault with production key custody.
- Monitoring, alerting, and SLA-grade indexer.
- Mainnet deployment.

See `docs/ROADMAP.md` for the staged plan.
