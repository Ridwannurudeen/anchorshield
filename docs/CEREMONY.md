# Trusted Setup Ceremony

## Current State

The proving key in use is an autonomous-tier Groth16 ceremony for `circuits/eligibility.circom` on BLS12-381, produced by `scripts/ceremony.sh`.

This is a real multi-contribution ceremony with fresh local entropy and beacons, but it was run by one operator. It is suitable for testnet and demo evidence. It is not a substitute for a production ceremony with independent external contributors.

## Parameters

- Circuit: `circuits/eligibility.circom`
- R1CS: 56,110 constraints, 55,907 wires
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
| `circuits/eligibility.circom` | `52532e59455508b58e1652913537e579a907ef6971dc73ec702a7c82f2b74371` |
| `apps/web/proving/eligibility.wasm` | `15d6a656da557a7160da5cd42c11ced243aeef2bae420617d82f7af8c314c972` |
| `apps/web/proving/eligibility_final.zkey` | `6038f6bd130bcb70fb5b4c46d3f6c2f2dfc9e98cfb38e1dcd8322de0b6b71431` |
| `apps/web/data/verification_key.json` | `c78b1c6b135ccb1141e8a91ce5cfaee75a191aed6479ffb05ccc66e22c7a0899` |
| `testdata/eligibility/cli-args.json` | `229d76b41152612ff5341e0ff35df3dc38c01f02c90afadca731392b903fba13` |
| `testdata/rwa/cli-args.json` | `d7dfacf8039621109a12261a0837a6add8a28a65069d82a947af980f520f97ef` |

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
