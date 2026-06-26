# Trusted Setup Ceremony

## Current State — autonomous-tier ceremony (operator-run)

The proving key in use is the product of a real multi-contribution Groth16
ceremony for `circuits/eligibility.circom` on BLS12-381, produced by
`scripts/ceremony.sh`. It replaces the earlier single-contribution smoke key.

It is the **autonomous tier**: a genuine multi-contribution + beacon ceremony run
by a single operator with fresh OS entropy per contribution. It is **not** a
substitute for the true multi-party ceremony with independent external
contributors, which is deferred to pre-mainnet (see below).

## Parameters

- Circuit: `circuits/eligibility.circom` — 15,866 constraints, 15,864 wires, 17 public signals.
- Curve: BLS12-381. Powers of tau: **2^16 (65,536)** — comfortable headroom over the constraint count (allows future growth, e.g. in-circuit sanctions non-membership).
- Phase 1: `powersoftau new` → **3 named contributions** (`anchorshield-ptau-1..3`), each with fresh `/dev/urandom` entropy → **public beacon** (`powersoftau beacon`, 2^10 iterations) → `prepare phase2`.
- Phase 2: `groth16 setup` → **2 named zkey contributions** (`anchorshield-zkey-1..2`), fresh entropy each → **zkey beacon** → `zkey verify` against the R1CS (passed: `ZKey Ok!`).
- Beacon value (autonomous tier): `3fa9c2e15b8d47061a2b3c4d5e6f70819293a4b5c6d7e8f90123456789abcdef`.
- Toxic waste: the per-contribution entropy is generated from `/dev/urandom` and never written to disk; the working directory `.ceremony/` is git-ignored and is deleted at the start of each run.

## Artifact Hashes (SHA-256)

| Artifact | SHA-256 |
| --- | --- |
| `circuits/eligibility.circom` | `b0420527d84d09fbb2f9b9aa0e74e07ade80267e1d6b5c6f4d3bc9a40b1949aa` |
| `apps/web/proving/eligibility.wasm` | `4a4758db973d4018bc58ab687fdb20e684904395dc3531245b6ccf5a3fef7735` |
| `apps/web/proving/eligibility_final.zkey` | `377e97fee630ee47e82297b9d25ccba95f830e65755b73e0d43e90bad609c7f3` |
| `apps/web/data/verification_key.json` | `54a4243dd73ace8ce56791930de62d7efe9f924f0d4d67d4dacfb8974c9632bc` |
| `testdata/eligibility/cli-args.json` | `0085a8d812182ed8241bc7d7a5eb4e91914ce5e9acaa358539939299669a4cc2` |
| `testdata/rwa/cli-args.json` | `46fa758e5016223337d321ba81265f4ee67da3931a64224afce8e6042d4bb3f6` |

The verifying key is pinned on-chain via `verifier.set_vk(...)` (admin-only), so the
deployed verifier accepts proofs only for this ceremony's key.

## Reproduce

```bash
bash scripts/ceremony.sh            # re-run the full ceremony (regenerates fixtures)
cargo test --workspace              # 19 contract tests verify against the fixtures
```

`scripts/ceremony.sh` performs: circuit compile → phase 1 (new, 3 contributions,
beacon, prepare phase2, verify) → phase 2 (setup, 2 zkey contributions, beacon,
verify) → export vk → regenerate payment + RWA proofs and `cli-args.json` via the
converter → refresh `apps/web` proving/vk artifacts.

## Production Ceremony Requirement (pre-mainnet — true multi-party tier)

Before mainnet, run the true multi-party ceremony:

1. Freeze `circuits/eligibility.circom` and all included component files.
2. Publish the circuit hash, R1CS hash, and initial zkey hash.
3. Collect independent contributions from **multiple independent, named external participants** (not a single operator).
4. Replace the fixed beacon with a **future, publicly verifiable randomness value** (e.g. a specific drand round at a pre-announced time).
5. Publish every challenge/response hash and the final beacon transcript.
6. Verify the final zkey against the frozen R1CS and the full transcript.
7. Each contributor destroys their local toxic waste and attests to the destruction.

Any circuit change invalidates the ceremony and requires a new one.
