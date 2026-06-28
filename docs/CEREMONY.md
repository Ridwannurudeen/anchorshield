# Trusted Setup Ceremony

## Current State

The proving key in use is an autonomous-tier Groth16 ceremony for `circuits/eligibility.circom` on BLS12-381, produced by `scripts/ceremony.sh`.

This is a real multi-contribution ceremony with fresh local entropy and beacons, but it was run by one operator. It is suitable for testnet and demo evidence. It is not a substitute for a production ceremony with independent external contributors.

## Parameters

- Circuit: `circuits/eligibility.circom`
- R1CS: 46,708 constraints, 46,491 wires
- Public statement: 19 public signals, emitted as 4 outputs plus 15 public inputs by snarkjs
- Curve: BLS12-381
- Powers of tau: 2^16, 65,536 constraints of capacity
- Phase 1: 3 named contributions, fresh OS entropy, public beacon, prepare phase2
- Phase 2: Groth16 setup, 2 named zkey contributions, fresh OS entropy, zkey beacon, zkey verification
- Beacon value: `3fa9c2e15b8d47061a2b3c4d5e6f70819293a4b5c6d7e8f90123456789abcdef`

The verifier stores the VK under `circuit_id` and `circuit_version`, then freezes it. The deployed verifier accepts proofs for the configured ceremony key and rejects post-freeze VK replacement.

## Artifact Hashes

| Artifact | SHA-256 |
| --- | --- |
| `circuits/eligibility.circom` | `931a85f36436bc30051af779374832d2a4fbc70a624789766f59e5948a8d0d86` |
| `apps/web/proving/eligibility.wasm` | `e61e35f45edc828193063148b932b059dd3614e0167c6d760a097ab4fece2c1c` |
| `apps/web/proving/eligibility_final.zkey` | `4beed077297ccb28a35ee0656b0393157653caf8189fe27417f3f1ecf89b13d0` |
| `apps/web/data/verification_key.json` | `5b672d4e5b328741c56632b8359c21aa9133b735d0e7a9ee10b3deb140e28aa1` |
| `testdata/eligibility/cli-args.json` | `392c50f0b1f0e36ff0c8724dc357c507d7041eb5b0a78a9d4d5ebc7b6a20500e` |
| `testdata/rwa/cli-args.json` | `0586504a7c3dae6ecd0066520b6d7e15ca2a8ab0db04170467c0e6279900cb87` |

## Reproduce

```bash
bash scripts/ceremony.sh
npm run m1:circuit
cargo test --workspace
```

`scripts/ceremony.sh` compiles the circuit, runs phase 1 and phase 2 contributions, verifies the zkey, exports the VK, regenerates payment and RWA proofs, refreshes `cli-args.json`, and copies the browser proving artifacts.

## Production Requirement

Before mainnet:

1. Freeze the circuit and all included component files.
2. Publish the circuit hash, R1CS hash, initial zkey hash, and ceremony instructions.
3. Collect contributions from multiple independent, named external participants.
4. Use a future public randomness value for the final beacon.
5. Publish every challenge/response hash and the final transcript.
6. Verify the final zkey against the frozen R1CS and transcript.
7. Record contributor toxic-waste destruction attestations.

Any circuit change invalidates the ceremony and requires a new one.
