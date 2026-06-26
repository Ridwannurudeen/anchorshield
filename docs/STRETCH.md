# Stretch Backends & Advanced ZK

## Verified Upstreams

Checked on 2026-06-26:

| Backend | Repo | Commit | Verified interface |
| --- | --- | --- | --- |
| UltraHonk | `NethermindEth/rs-soroban-ultrahonk` | `661db07200f890b1bd9a7349ed787c70a706dd12` | `UltraHonkVerifierContract.verify_proof(env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error>` |
| RISC Zero | `NethermindEth/stellar-risc0-verifier` | `e8ff6ea202db195352c0141ecc533ff649393fe4` | `RiscZeroVerifierRouter.verify(env, seal: Bytes, image_id: BytesN<32>, journal: BytesN<32>) -> Result<(), VerifierError>` |

## UltraHonk Status

The upstream UltraHonk verifier is real, but it is not wired into AnchorShield.

Verified details:

- Requires Noir `1.0.0-beta.9`.
- Requires Barretenberg `0.87.0`.
- The wrapper stores an immutable VK at construction.
- The verifier entrypoint accepts raw `public_inputs` and `proof_bytes`.
- The upstream workspace currently uses `soroban-sdk = 26.0.1`.
- AnchorShield is pinned to the official Groth16 example's `soroban-sdk = 25.1.0`.

Local blocker:

- `nargo` and `bb` are not installed in WSL, so a real AnchorShield UltraHonk proof cannot be generated and verified in this session.

Decision:

- Do not add an UltraHonk adapter until the project either upgrades to SDK 26 or isolates the verifier as a separate deployed contract with a documented ABI boundary.

## RISC Zero Status

The upstream RISC Zero verifier/router stack is real, but it is not wired into AnchorShield.

Verified details:

- The router dispatches by the first 4 bytes of `seal`.
- The router verifies with `seal`, `image_id`, and `journal`.
- Router mutation is intended to be owned by a timelock.
- The repo includes an emergency-stop wrapper and a mock verifier for development only.
- The workspace uses `soroban-sdk = 25.1.0`, matching AnchorShield's current SDK pin.

Local blocker:

- `rzup` and `cargo-risczero` are not installed in WSL, so a real RISC Zero Groth16 receipt cannot be generated in this session.

Decision:

- Do not use the mock verifier as an AnchorShield acceptance artifact because it provides no cryptographic security.
- The first production-shaped RISC Zero slice should verify a small guest whose journal commits to the same AnchorShield action-binding fields, then route it through the upstream router.

## Sanctions Non-Membership

Current AnchorShield status remains issuer-attested `sanctions_clear`.

Stretch requirement not implemented:

- sorted-Merkle or SMT non-membership proof against a committed `sanctions_root`
- policy field carrying the exact sanctions list root/version
- circuit constraints proving the credential subject is absent from that committed list

Reason:

- Implementing this changes the circuit statement and invalidates the current Groth16 setup. It must be done before any production ceremony.

## Relayer

No relayer was implemented.

Reason:

- The current gates bind proof public inputs to action args, but do not include caller/source-account binding. A fee-paying relayer should not be added until caller binding and replay/front-running tests are extended.

## Stretch Verdict

No stretch backend is claimed complete.

The verified next implementation order is:

1. Add packet/terms hash to approval events and finish production admin/timelock/pause.
2. Decide whether AnchorShield stays on `soroban-sdk 25.1.0` or upgrades to SDK 26.
3. If staying on SDK 25, implement RISC Zero first because the upstream router matches the current SDK pin.
4. If upgrading to SDK 26, re-run M0/M1 Groth16 gates before integrating UltraHonk.
5. Add sanctions non-membership only before a new production ceremony.
