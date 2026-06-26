# Trusted Setup Ceremony

## Current State

The current proving key is a smoke/demo Groth16 phase-2 setup for `circuits/eligibility.circom`.

It is not a production multi-party ceremony artifact.

## Artifact Hashes

| Artifact | SHA-256 |
| --- | --- |
| `circuits/eligibility.circom` | `b0420527d84d09fbb2f9b9aa0e74e07ade80267e1d6b5c6f4d3bc9a40b1949aa` |
| `apps/web/proving/eligibility.wasm` | `4a4758db973d4018bc58ab687fdb20e684904395dc3531245b6ccf5a3fef7735` |
| `apps/web/proving/eligibility_final.zkey` | `ac3008756fee121d0cea3c0a79f2d8b01f9b4c03453daa1286f1052ba914bae0` |
| `contracts/gate_payment/src/lib.rs` | `748a259669739b4e4b2ea398d5bfa85682621fa82e0238587d9d6f42ee93a9c2` |
| `contracts/gate_rwa/src/lib.rs` | `e60a9f22591b5b7f06d45e975b66d4f4f29e908237b89e9ab0f0455cfedd643a` |

## Reproducible Verification

```bash
npm run m2:circuit
cd tools/groth16-json-converter && cargo test -- --nocapture
cd ../../contracts/gate_payment && cargo test -- --nocapture
cd ../gate_rwa && cargo test -- --nocapture
```

`npm run m2:circuit` runs:

- `circom circuits/eligibility.circom --r1cs --wasm --sym --prime bls12381`
- `snarkjs powersoftau new bls12381`
- `snarkjs powersoftau contribute`
- `snarkjs powersoftau prepare phase2`
- `snarkjs groth16 setup`
- `snarkjs zkey contribute`
- `snarkjs zkv`
- `snarkjs zkey export verificationkey`
- payment and RWA `snarkjs groth16 fullprove`
- payment and RWA `snarkjs groth16 verify`

## Production Ceremony Requirement

Before mainnet:

1. Freeze `circuits/eligibility.circom` and all included component files.
2. Publish the circuit hash, R1CS hash, and initial zkey hash.
3. Collect independent contributions from multiple named participants.
4. Publish every challenge/response hash and final beacon.
5. Verify the final zkey against the frozen R1CS and transcript.
6. Destroy all local toxic waste and document the destruction steps.

Any circuit change invalidates the production ceremony and requires a new ceremony.
