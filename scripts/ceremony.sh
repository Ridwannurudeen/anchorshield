#!/usr/bin/env bash
# AnchorShield trusted-setup ceremony (autonomous tier).
#
# Runs a real multi-contribution Groth16 setup for circuits/eligibility.circom on
# BLS12-381 with a public beacon, regenerates all proof fixtures against the new
# key, and refreshes the on-chain/web/test artifacts. Each contribution uses fresh
# OS entropy (/dev/urandom); toxic waste is the per-contribution randomness and is
# never persisted.
#
# Tier note: this is the operator-run autonomous ceremony. The TRUE multi-party
# ceremony (independent external contributors + a future public drand round as the
# beacon) is deferred to pre-mainnet and tracked in docs/CEREMONY.md.
#
# Run from repo root inside WSL/Linux:  bash scripts/ceremony.sh
set -euo pipefail

POWER="${CEREMONY_POWER:-16}"
BUILD=.ceremony
SJS="node node_modules/snarkjs/cli.js"
# Autonomous-tier beacon. Production ceremony MUST replace with a future, publicly
# verifiable randomness value (e.g. a specific drand round), documented in advance.
BEACON="3fa9c2e15b8d47061a2b3c4d5e6f70819293a4b5c6d7e8f90123456789abcdef"
BEACON_ITERS=10

rand_entropy() { od -An -tx1 -N64 /dev/urandom | tr -d ' \n'; }

rm -rf "$BUILD"
mkdir -p "$BUILD"

echo "== [1/5] compile circuit =="
circom circuits/eligibility.circom --r1cs --wasm --sym --prime bls12381 \
  -l circuits -l circuits/components -l node_modules/circomlib/circuits -o "$BUILD"
R1CS="$BUILD/eligibility.r1cs"
WASM="$BUILD/eligibility_js/eligibility.wasm"
$SJS r1cs info "$R1CS"

echo "== [2/5] phase 1 (powers of tau, power $POWER) =="
$SJS powersoftau new bls12381 "$POWER" "$BUILD/pot_0000.ptau"
$SJS powersoftau contribute "$BUILD/pot_0000.ptau" "$BUILD/pot_0001.ptau" --name="anchorshield-ptau-1" -e="$(rand_entropy)"
$SJS powersoftau contribute "$BUILD/pot_0001.ptau" "$BUILD/pot_0002.ptau" --name="anchorshield-ptau-2" -e="$(rand_entropy)"
$SJS powersoftau contribute "$BUILD/pot_0002.ptau" "$BUILD/pot_0003.ptau" --name="anchorshield-ptau-3" -e="$(rand_entropy)"
$SJS powersoftau beacon "$BUILD/pot_0003.ptau" "$BUILD/pot_beacon.ptau" "$BEACON" "$BEACON_ITERS" -n="phase1 beacon"
$SJS powersoftau prepare phase2 "$BUILD/pot_beacon.ptau" "$BUILD/pot_final.ptau"
$SJS powersoftau verify "$BUILD/pot_final.ptau"

echo "== [3/5] phase 2 (groth16 zkey) =="
$SJS groth16 setup "$R1CS" "$BUILD/pot_final.ptau" "$BUILD/zkey_0000.zkey"
$SJS zkey contribute "$BUILD/zkey_0000.zkey" "$BUILD/zkey_0001.zkey" --name="anchorshield-zkey-1" -e="$(rand_entropy)"
$SJS zkey contribute "$BUILD/zkey_0001.zkey" "$BUILD/zkey_0002.zkey" --name="anchorshield-zkey-2" -e="$(rand_entropy)"
$SJS zkey beacon "$BUILD/zkey_0002.zkey" "$BUILD/eligibility_final.zkey" "$BEACON" "$BEACON_ITERS" -n="phase2 beacon"
$SJS zkey verify "$R1CS" "$BUILD/pot_final.ptau" "$BUILD/eligibility_final.zkey"
$SJS zkey export verificationkey "$BUILD/eligibility_final.zkey" "$BUILD/verification_key.json"

echo "== [4/5] regenerate fixtures =="
for s in eligibility rwa; do
  $SJS wtns calculate "$WASM" "testdata/$s/input.valid.json" "$BUILD/$s.wtns"
  $SJS groth16 prove "$BUILD/eligibility_final.zkey" "$BUILD/$s.wtns" "$BUILD/$s.proof.json" "$BUILD/$s.public.json"
  $SJS groth16 verify "$BUILD/verification_key.json" "$BUILD/$s.public.json" "$BUILD/$s.proof.json"
  cp "$BUILD/$s.proof.json" "testdata/$s/proof.json"
  cp "$BUILD/$s.public.json" "testdata/$s/public.json"
  cp "$BUILD/verification_key.json" "testdata/$s/verification_key.json"
  cargo run --quiet --manifest-path tools/groth16-json-converter/Cargo.toml -- \
    "testdata/$s/proof.json" "testdata/$s/verification_key.json" "testdata/$s/public.json" \
    > "testdata/$s/cli-args.json"
done

echo "== [5/5] refresh web artifacts =="
cp "$BUILD/eligibility_final.zkey" apps/web/proving/eligibility_final.zkey
cp "$WASM" apps/web/proving/eligibility.wasm
cp "$BUILD/verification_key.json" apps/web/data/verification_key.json

echo "CEREMONY_OK"
