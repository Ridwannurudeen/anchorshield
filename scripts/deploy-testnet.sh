#!/usr/bin/env bash
# AnchorShield testnet deploy (run from repo root in bash with cargo, circom,
# stellar, and node on PATH):
#   bash scripts/deploy-testnet.sh
# Builds and deploys the hardened contract set + OZ SEP-57 token, wires roots,
# policies, frozen VK metadata, a real SAC payment, and an action-bound RWA mint
# authorization consumed by the compliance adapter.
set -euo pipefail

SRC=anchorshield-m0
NET=testnet
OUT=.deploy
SLEEP_SECS=6
mkdir -p "$OUT" services/indexer/raw apps/web/data
: > "$OUT/deploy.out"
: > "$OUT/deploy.err"
exec > >(tee -a "$OUT/deploy.out") 2> >(tee -a "$OUT/deploy.err" >&2)
export STELLAR_NO_CACHE=true
W=target/wasm32v1-none/release
OZ=.upstream/stellar-contracts/target/wasm32v1-none/release
CIRCUIT_ID=0707070707070707070707070707070707070707070707070707070707070707
CIRCUIT_VERSION=1

retry() {
  local i
  for i in 1 2 3 4 5 6; do
    "$@" && return 0
    sleep "$SLEEP_SECS"
  done
  return 1
}

upload() { retry stellar contract upload --wasm "$1" --source "$SRC" --network "$NET" 2>>"$OUT/deploy.err"; }
deploy() { retry stellar contract deploy --wasm-hash "$1" --source "$SRC" --network "$NET" "${@:2}" 2>>"$OUT/deploy.err"; }
inv() {
  retry stellar contract invoke --id "$1" --source "$SRC" --network "$NET" -- "${@:2}" 2>>"$OUT/deploy.err"
  local rc=$?
  sleep "$SLEEP_SECS"
  return $rc
}
send_inv() {
  local tx out start
  start=$(wc -c < "$OUT/deploy.err")
  out=$(retry stellar contract invoke --id "$1" --source "$SRC" --network "$NET" -- "${@:2}" 2>>"$OUT/deploy.err")
  sleep "$SLEEP_SECS"
  tx=$(tail -c +"$((start + 1))" "$OUT/deploy.err" \
    | grep -Eo 'stellar\.expert/explorer/testnet/tx/[0-9a-f]{64}' \
    | tail -1 \
    | sed 's#stellar\.expert/explorer/testnet/tx/##')
  if [ -z "$tx" ] && printf '%s' "$out" | grep -Eq '^[0-9a-f]{64}$'; then
    tx=$out
  fi
  if [ -z "$tx" ]; then
    echo "failed to parse tx hash for $1 ${*:2}" >&2
    return 1
  fi
  printf '%s' "$tx"
}
updep() {
  local h
  h=$(upload "$1")
  sleep "$SLEEP_SECS"
  deploy "$h" "${@:2}"
  sleep "$SLEEP_SECS"
}
fee_charged() {
  local i json
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if json=$(stellar tx fetch fee --hash "$1" --network "$NET" --output json 2>>"$OUT/deploy.err"); then
      printf '%s' "$json" \
        | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).charged.fee));"
      return 0
    fi
    sleep "$SLEEP_SECS"
  done
  echo "failed to fetch fee for tx $1" >&2
  return 1
}
require_interface() {
  local wasm=$1 pattern=$2
  stellar contract info interface --wasm "$wasm" | grep -q "$pattern" || {
    echo "missing interface pattern '$pattern' in $wasm" >&2
    exit 1
  }
}

ensure_source_identity() {
  if stellar keys address "$SRC" >/dev/null 2>>"$OUT/deploy.err"; then
    return 0
  fi
  echo "== create funded testnet source identity =="
  stellar keys generate "$SRC" --network "$NET" --fund >/dev/null 2>>"$OUT/deploy.err"
}

ensure_source_identity
SRC_ADDR=$(stellar keys address "$SRC")

echo "== build current wasm =="
cargo build --release --target wasm32v1-none
SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=true cargo build --manifest-path .upstream/stellar-contracts/Cargo.toml -p rwa-token-example --release --target wasm32v1-none

echo "== preflight wasm interfaces =="
require_interface "$W/anchorshield_verifier.wasm" "circuit_id"
require_interface "$W/anchorshield_verifier.wasm" "freeze_vk"
require_interface "$W/anchorshield_issuer_registry.wasm" "set_sanctions_root"
require_interface "$W/anchorshield_issuer_registry.wasm" "set_revocation_root"
require_interface "$W/anchorshield_identity_verifier.wasm" "attest_for_mint"
require_interface "$W/anchorshield_identity_verifier.wasm" "consume_mint_authorization"
require_interface "$W/anchorshield_rwa_compliance_adapter.wasm" "created"
require_interface "$W/anchorshield_rwa_compliance_adapter.wasm" "bind_token"

echo "== build issuer roots + deploy proofs =="
node services/issuer/issue.js >/dev/null
node scripts/make-demo-witness.mjs >/dev/null
node node_modules/snarkjs/cli.js groth16 fullprove demo-witness/payment.json apps/web/proving/eligibility.wasm apps/web/proving/eligibility_final.zkey "$OUT/pay_snark_proof.json" "$OUT/pay_public.json"
node node_modules/snarkjs/cli.js groth16 verify apps/web/data/verification_key.json "$OUT/pay_public.json" "$OUT/pay_snark_proof.json"
node node_modules/snarkjs/cli.js groth16 fullprove demo-witness/rwa.json apps/web/proving/eligibility.wasm apps/web/proving/eligibility_final.zkey "$OUT/rwa_snark_proof.json" "$OUT/rwa_public.json"
node node_modules/snarkjs/cli.js groth16 verify apps/web/data/verification_key.json "$OUT/rwa_public.json" "$OUT/rwa_snark_proof.json"
cargo run --quiet --manifest-path tools/groth16-json-converter/Cargo.toml -- "$OUT/pay_snark_proof.json" apps/web/data/verification_key.json "$OUT/pay_public.json" > "$OUT/pay_cli.json"
cargo run --quiet --manifest-path tools/groth16-json-converter/Cargo.toml -- "$OUT/rwa_snark_proof.json" apps/web/data/verification_key.json "$OUT/rwa_public.json" > "$OUT/rwa_cli.json"
CRED_ROOT=$(node -e "console.log(require('./services/issuer/out/issuance.json').roots.credential_root)")
SANCTIONS_ROOT=$(node -e "console.log(require('./services/issuer/out/issuance.json').roots.sanctions_root)")
REVOCATION_ROOT=$(node -e "console.log(require('./services/issuer/out/issuance.json').roots.revocation_root)")
PAY_PACKET=$(node -e "console.log(require('./.deploy/pay_cli.json').pub_signals[1].u256)")
RWA_TERMS=$(node -e "console.log(require('./.deploy/rwa_cli.json').pub_signals[1].u256)")
node -e "const a=require('./.deploy/pay_cli.json');const fs=require('fs');
if(a.pub_signals[0].u256 !== '$CRED_ROOT') throw new Error('payment credential root mismatch');
if(a.pub_signals[17].u256 !== '$SANCTIONS_ROOT') throw new Error('payment sanctions root mismatch');
if(a.pub_signals[18].u256 !== '$REVOCATION_ROOT') throw new Error('payment revocation root mismatch');
fs.writeFileSync('$OUT/pay_vk.json',JSON.stringify(a.vk));
fs.writeFileSync('$OUT/pay_proof.json',JSON.stringify(a.proof));
fs.writeFileSync('$OUT/pay_pub.json',JSON.stringify(a.pub_signals));"
node -e "const a=require('./.deploy/rwa_cli.json');const fs=require('fs');
if(a.pub_signals[0].u256 !== '$CRED_ROOT') throw new Error('rwa credential root mismatch');
if(a.pub_signals[17].u256 !== '$SANCTIONS_ROOT') throw new Error('rwa sanctions root mismatch');
if(a.pub_signals[18].u256 !== '$REVOCATION_ROOT') throw new Error('rwa revocation root mismatch');
fs.writeFileSync('$OUT/rwa_proof.json',JSON.stringify(a.proof));
fs.writeFileSync('$OUT/rwa_pub.json',JSON.stringify(a.pub_signals));"
printf '{"policy_id":202,"issuer_id":101,"circuit_id":"%s","circuit_version":1,"kyc_required":true,"sanctions_required":true,"allowed_country":566,"min_age":18,"min_investor_type":0}' "$CIRCUIT_ID" > "$OUT/policy_pay.json"
printf '{"policy_id":303,"issuer_id":101,"circuit_id":"%s","circuit_version":1,"kyc_required":true,"sanctions_required":true,"allowed_country":566,"min_age":18,"min_investor_type":1}' "$CIRCUIT_ID" > "$OUT/policy_rwa.json"

echo "== deploy core contracts =="
VERIFIER=$(updep "$W/anchorshield_verifier.wasm"); echo "verifier=$VERIFIER"
ISSUER=$(updep "$W/anchorshield_issuer_registry.wasm"); echo "issuer=$ISSUER"
POLICY=$(updep "$W/anchorshield_policy_registry.wasm"); echo "policy=$POLICY"
NULL=$(updep "$W/anchorshield_nullifier_registry.wasm"); echo "nullifier=$NULL"
IDV=$(updep "$W/anchorshield_identity_verifier.wasm"); echo "identity_verifier=$IDV"
ADAPTER=$(updep "$W/anchorshield_rwa_compliance_adapter.wasm"); echo "rwa_compliance_adapter=$ADAPTER"
GPAY=$(updep "$W/anchorshield_gate_payment.wasm"); echo "gate_payment=$GPAY"

echo "== init + configure core =="
inv "$VERIFIER" init --admin "$SRC" >/dev/null
inv "$VERIFIER" set_vk --circuit_id "$CIRCUIT_ID" --circuit_version "$CIRCUIT_VERSION" --vk-file-path "$OUT/pay_vk.json" >/dev/null
inv "$VERIFIER" freeze_vk >/dev/null
inv "$ISSUER" init --admin "$SRC" >/dev/null
CRED_ROOT_TX=$(send_inv "$ISSUER" set_root --issuer_id 101 --root "$CRED_ROOT")
SANCTIONS_ROOT_TX=$(send_inv "$ISSUER" set_sanctions_root --root "$SANCTIONS_ROOT")
REVOCATION_ROOT_TX=$(send_inv "$ISSUER" set_revocation_root --issuer_id 101 --root "$REVOCATION_ROOT")
inv "$POLICY" init --admin "$SRC" >/dev/null
inv "$POLICY" set_policy --policy-file-path "$OUT/policy_pay.json" >/dev/null
inv "$POLICY" set_policy --policy-file-path "$OUT/policy_rwa.json" >/dev/null
inv "$NULL" init --admin "$SRC" >/dev/null
inv "$IDV" init --admin "$SRC" --verifier "$VERIFIER" --issuer_registry "$ISSUER" --policy_registry "$POLICY" --nullifier_registry "$NULL" >/dev/null
inv "$ADAPTER" init --admin "$SRC" --identity_verifier "$IDV" >/dev/null
inv "$GPAY" init --admin "$SRC" --verifier "$VERIFIER" --issuer_registry "$ISSUER" --policy_registry "$POLICY" --nullifier_registry "$NULL" >/dev/null
inv "$NULL" allow_gate --gate "$GPAY" >/dev/null
inv "$NULL" allow_gate --gate "$IDV" >/dev/null

echo "== payment flow (real SAC transfer, native XLM) =="
NATIVE=$(stellar contract id asset --asset native --network "$NET")
stellar keys generate as-recipient --network "$NET" --fund --overwrite >/dev/null 2>>"$OUT/deploy.err"
RECIP=$(stellar keys address as-recipient)
inv "$GPAY" set_token --asset_id 9001 --token "$NATIVE" >/dev/null
inv "$GPAY" set_recipient --recipient_id 7000001 --recipient "$RECIP" >/dev/null
inv "$NATIVE" transfer --from "$SRC" --to "$GPAY" --amount 1000 >/dev/null
RECIP_BEFORE=$(inv "$NATIVE" balance --id "$RECIP" | tr -d '"')
PAYTX=$(send_inv "$GPAY" verify_and_pay \
  --proof-file-path "$OUT/pay_proof.json" --pub_signals-file-path "$OUT/pay_pub.json" \
  --policy_id 202 --asset_id 9001 --amount 250 --recipient_id 7000001 --action_id 424242 \
  --packet_hash "$PAY_PACKET" --epoch 12)
PAY_FEE=$(fee_charged "$PAYTX")
RECIP_AFTER=$(inv "$NATIVE" balance --id "$RECIP" | tr -d '"')
if stellar contract invoke --id "$GPAY" --source "$SRC" --network "$NET" -- verify_and_pay \
  --proof-file-path "$OUT/pay_proof.json" --pub_signals-file-path "$OUT/pay_pub.json" \
  --policy_id 202 --asset_id 9001 --amount 250 --recipient_id 7000001 --action_id 424242 \
  --packet_hash "$PAY_PACKET" --epoch 12 >/dev/null 2>>"$OUT/deploy.err"; then
  REPLAY_REJECTED=false
else
  REPLAY_REJECTED=true
fi
sleep "$SLEEP_SECS"
echo "payment: recipient $RECIP_BEFORE -> $RECIP_AFTER (expect +250), tx=$PAYTX"

echo "== RWA flow (action-bound attest_for_mint -> compliance adapter -> OZ token mint) =="
TH=$(upload "$OZ/rwa_token_example.wasm"); sleep "$SLEEP_SECS"
RWATOKEN=$(deploy "$TH" -- --name AnchorRWA --symbol ARWA --admin "$SRC" --manager "$SRC" --compliance "$ADAPTER" --identity_verifier "$IDV")
sleep "$SLEEP_SECS"
echo "rwa_token=$RWATOKEN"
inv "$ADAPTER" bind_token --token "$RWATOKEN" --operator "$SRC" >/dev/null
inv "$IDV" set_rwa_token --asset_id 9101 --token "$RWATOKEN" >/dev/null
inv "$IDV" set_rwa_recipient --recipient_id 8000001 --account "$SRC" >/dev/null
inv "$IDV" allow_mint_consumer --consumer "$ADAPTER" >/dev/null
ATTESTTX=$(send_inv "$IDV" attest_for_mint \
  --account "$SRC" --consumer "$ADAPTER" \
  --proof-file-path "$OUT/rwa_proof.json" --pub_signals-file-path "$OUT/rwa_pub.json" \
  --policy_id 303 --asset_id 9101 --amount 100 --recipient_id 8000001 \
  --action_id 515151 --terms_hash "$RWA_TERMS" --epoch 12 --valid_until 9999999999)
ATTEST_FEE=$(fee_charged "$ATTESTTX")
MINTTX=$(send_inv "$RWATOKEN" mint --to "$SRC" --amount 100 --operator "$SRC")
MINT_FEE=$(fee_charged "$MINTTX")
RWABAL=$(inv "$RWATOKEN" balance --account "$SRC" | tr -d '"')
TOTAL_SUPPLY=$(inv "$RWATOKEN" total_supply | tr -d '"')
echo "rwa mint: holder balance=$RWABAL (expect 100), attest=$ATTESTTX, mint=$MINTTX"

echo "== fetch events + record deployments =="
stellar tx fetch events --hash "$PAYTX" --network "$NET" --output json > services/indexer/raw/payment-events.json
stellar tx fetch events --hash "$ATTESTTX" --network "$NET" --output json > services/indexer/raw/rwa-events.json
node -e "const fs=require('fs');const d={
network:'testnet',hardened:true,sdk:'26.1.0',admin:'$SRC_ADDR',
ceremony:'autonomous-tier, power-16 BLS12-381, VK frozen on-chain',
circuit:{id:'$CIRCUIT_ID',version:$CIRCUIT_VERSION,public_signal_count:19,credential_root:'$CRED_ROOT',sanctions_root:'$SANCTIONS_ROOT',revocation_root:'$REVOCATION_ROOT',vk_frozen:true},
contracts:{verifier:'$VERIFIER',issuer_registry:'$ISSUER',policy_registry:'$POLICY',nullifier_registry:'$NULL',identity_verifier:'$IDV',rwa_compliance_adapter:'$ADAPTER',gate_payment:'$GPAY',oz_rwa_token:'$RWATOKEN',native_sac:'$NATIVE'},
payment_flow:{description:'Proof-gated SAC transfer via gate_payment.verify_and_pay.',recipient:'$RECIP',asset_id:9001,amount:250,verify_and_pay_tx:'$PAYTX',fee_charged_stroops:Number('$PAY_FEE'),recipient_balance_before:'$RECIP_BEFORE',recipient_balance_after:'$RECIP_AFTER',nullifier_replay_rejected:$REPLAY_REJECTED},
rwa_flow:{description:'Proof-bound identity_verifier.attest_for_mint authorization consumed by the compliance adapter during OZ SEP-57 token mint.',holder:'$SRC_ADDR',asset_id:9101,amount:100,recipient_id:'8000001',attest_for_mint_tx:'$ATTESTTX',attest_fee_charged_stroops:Number('$ATTEST_FEE'),mint_tx:'$MINTTX',mint_fee_charged_stroops:Number('$MINT_FEE'),rwa_balance:'$RWABAL',total_supply:'$TOTAL_SUPPLY'},
root_publish:{credential_root_tx:'$CRED_ROOT_TX',sanctions_root_tx:'$SANCTIONS_ROOT_TX',revocation_root_tx:'$REVOCATION_ROOT_TX',admin:'$SRC_ADDR',issuer_id:101,credential_root:'$CRED_ROOT',sanctions_root:'$SANCTIONS_ROOT',revocation_root:'$REVOCATION_ROOT',note:'Real OFAC-screened issuer roots published from anchorshield-m0 admin.',credential_source:'Sumsub KYC-verified applicant (GREEN, NGA passport) plus self-serve commitment append path; see services/issuer/data/roster.json kyc_provenance'}
};fs.writeFileSync('deployments/testnet-hardened.json',JSON.stringify(d,null,2)+'\n');fs.writeFileSync('apps/web/data/deployments.json',JSON.stringify(d,null,2)+'\n');console.log('wrote deployments/testnet-hardened.json and apps/web/data/deployments.json');"
node services/disclosure/disclosure.js >/dev/null
node services/indexer/build-index.js >/dev/null
echo "DEPLOY_OK"
