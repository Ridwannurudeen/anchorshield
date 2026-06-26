#!/usr/bin/env bash
# AnchorShield testnet deploy (run inside WSL/Linux from repo root):
#   bash scripts/deploy-testnet.sh
# Deploys the hardened contract set + OZ SEP-57 stack, wires them, pins the
# ceremony VK, and submits real on-chain transactions: a proof-gated SAC payment
# (verify_and_pay) and a proof-gated RWA mint (attest -> OZ token.mint ->
# our verify_identity). Records addresses + post-state to deployments/testnet.json.
#
# CLI arg formats (verified): scalar Fr -> bare decimal; Vec<Fr>/proof/vk -> JSON
# file via --<arg>-file-path; structs -> JSON file. NO_CACHE + retry/sleep avoid
# the testnet cache + TxBadSeq races.
set -euo pipefail

SRC=anchorshield-m0
NET=testnet
OUT=.deploy
mkdir -p "$OUT"
export STELLAR_NO_CACHE=true
W=target/wasm32v1-none/release
OZ=.upstream/stellar-contracts/target/wasm32v1-none/release

retry() { local i; for i in 1 2 3 4 5 6; do "$@" && return 0; sleep 6; done; return 1; }
upload() { retry stellar contract upload --wasm "$1" --source "$SRC" --network "$NET" 2>>"$OUT/deploy.err"; }
deploy() { retry stellar contract deploy --wasm-hash "$1" --source "$SRC" --network "$NET" "${@:2}" 2>>"$OUT/deploy.err"; }
inv()    { retry stellar contract invoke --id "$1" --source "$SRC" --network "$NET" -- "${@:2}" 2>>"$OUT/deploy.err"; local rc=$?; sleep 4; return $rc; }
updep()  { local h; h=$(upload "$1"); sleep 4; deploy "$h" "${@:2}"; sleep 4; }

echo "== extract fixture args =="
CRED_ROOT=$(node -e "console.log(require('./testdata/eligibility/cli-args.json').pub_signals[0].u256)")
PAY_PACKET=$(node -e "console.log(require('./testdata/eligibility/cli-args.json').pub_signals[1].u256)")
node -e "const a=require('./testdata/eligibility/cli-args.json');const fs=require('fs');
fs.writeFileSync('$OUT/pay_vk.json',JSON.stringify(a.vk));
fs.writeFileSync('$OUT/pay_proof.json',JSON.stringify(a.proof));
fs.writeFileSync('$OUT/pay_pub.json',JSON.stringify(a.pub_signals));"
node -e "const a=require('./testdata/rwa/cli-args.json');const fs=require('fs');
fs.writeFileSync('$OUT/rwa_proof.json',JSON.stringify(a.proof));
fs.writeFileSync('$OUT/rwa_pub.json',JSON.stringify(a.pub_signals));"
printf '{"policy_id":202,"issuer_id":101,"kyc_required":true,"sanctions_required":true,"allowed_country":566,"min_age":18,"min_investor_type":0}' > "$OUT/policy_pay.json"
printf '{"policy_id":303,"issuer_id":101,"kyc_required":true,"sanctions_required":true,"allowed_country":566,"min_age":18,"min_investor_type":1}' > "$OUT/policy_rwa.json"

echo "== deploy core contracts =="
VERIFIER=$(updep "$W/anchorshield_verifier.wasm");      echo "verifier=$VERIFIER"
ISSUER=$(updep "$W/anchorshield_issuer_registry.wasm");  echo "issuer=$ISSUER"
POLICY=$(updep "$W/anchorshield_policy_registry.wasm");  echo "policy=$POLICY"
NULL=$(updep "$W/anchorshield_nullifier_registry.wasm"); echo "nullifier=$NULL"
IDV=$(updep "$W/anchorshield_identity_verifier.wasm");   echo "identity_verifier=$IDV"
GPAY=$(updep "$W/anchorshield_gate_payment.wasm");       echo "gate_payment=$GPAY"

echo "== init + configure core =="
inv "$VERIFIER" init --admin "$SRC" >/dev/null
inv "$VERIFIER" set_vk --vk-file-path "$OUT/pay_vk.json" >/dev/null
inv "$ISSUER" init --admin "$SRC" >/dev/null
inv "$ISSUER" set_root --issuer_id 101 --root "$CRED_ROOT" >/dev/null
inv "$POLICY" init --admin "$SRC" >/dev/null
inv "$POLICY" set_policy --policy-file-path "$OUT/policy_pay.json" >/dev/null
inv "$POLICY" set_policy --policy-file-path "$OUT/policy_rwa.json" >/dev/null
inv "$NULL" init --admin "$SRC" >/dev/null
inv "$IDV" init --admin "$SRC" --verifier "$VERIFIER" --issuer_registry "$ISSUER" --policy_registry "$POLICY" --nullifier_registry "$NULL" >/dev/null
inv "$GPAY" init --admin "$SRC" --verifier "$VERIFIER" --issuer_registry "$ISSUER" --policy_registry "$POLICY" --nullifier_registry "$NULL" >/dev/null
inv "$NULL" allow_gate --gate "$GPAY" >/dev/null
inv "$NULL" allow_gate --gate "$IDV" >/dev/null

echo "== payment flow (real SAC transfer, native XLM) =="
NATIVE=$(stellar contract id asset --asset native --network "$NET")
stellar keys generate as-recipient --network "$NET" --fund 2>>"$OUT/deploy.err" || true
RECIP=$(stellar keys address as-recipient)
inv "$GPAY" set_token --asset_id 9001 --token "$NATIVE" >/dev/null
inv "$GPAY" set_recipient --recipient_id 7000001 --recipient "$RECIP" >/dev/null
# fund the gate with native XLM (so it can pay out)
inv "$NATIVE" transfer --from "$SRC" --to "$GPAY" --amount 1000 >/dev/null
RECIP_BEFORE=$(inv "$NATIVE" balance --id "$RECIP")
PAYTX=$(stellar contract invoke --id "$GPAY" --source "$SRC" --network "$NET" -- verify_and_pay \
  --proof-file-path "$OUT/pay_proof.json" --pub_signals-file-path "$OUT/pay_pub.json" \
  --policy_id 202 --asset_id 9001 --amount 250 --recipient_id 7000001 --action_id 424242 \
  --packet_hash "$PAY_PACKET" --epoch 12 2>>"$OUT/deploy.err"); sleep 4
RECIP_AFTER=$(inv "$NATIVE" balance --id "$RECIP")
echo "payment: recipient $RECIP_BEFORE -> $RECIP_AFTER (expect +250)"

echo "== RWA flow (OZ SEP-57 token gated by our verify_identity) =="
CH=$(upload "$OZ/rwa_compliance_example.wasm"); sleep 4
COMPLIANCE=$(deploy "$CH" -- --admin "$SRC" --manager "$SRC"); sleep 4; echo "compliance=$COMPLIANCE"
TH=$(upload "$OZ/rwa_token_example.wasm"); sleep 4
RWATOKEN=$(deploy "$TH" -- --name AnchorRWA --symbol ARWA --admin "$SRC" --manager "$SRC" --compliance "$COMPLIANCE" --identity_verifier "$IDV"); sleep 4
echo "rwa_token=$RWATOKEN"
# bind the token to the compliance contract (OZ compliance hooks require a bound token)
inv "$COMPLIANCE" bind_token --token "$RWATOKEN" --operator "$SRC" >/dev/null
# holder attests eligibility (account = SRC, bound via require_auth), then token mints to it
inv "$IDV" attest --account "$SRC" --proof-file-path "$OUT/rwa_proof.json" --pub_signals-file-path "$OUT/rwa_pub.json" --policy_id 303 --epoch 12 --valid_until 9999999999 >/dev/null
MINTTX=$(stellar contract invoke --id "$RWATOKEN" --source "$SRC" --network "$NET" -- mint --to "$SRC" --amount 100 --operator "$SRC" 2>>"$OUT/deploy.err"); sleep 6
RWABAL=$(inv "$RWATOKEN" balance --account "$SRC")
echo "rwa mint: holder balance=$RWABAL (expect 100)"

echo "== record deployments =="
node -e "const fs=require('fs');const d={network:'testnet',hardened:true,sdk:'26.1.0',ceremony:'autonomous-tier power-16',
contracts:{verifier:'$VERIFIER',issuer_registry:'$ISSUER',policy_registry:'$POLICY',nullifier_registry:'$NULL',identity_verifier:'$IDV',gate_payment:'$GPAY',oz_compliance:'$COMPLIANCE',oz_rwa_token:'$RWATOKEN',native_sac:'$NATIVE'},
payment:{recipient:'$RECIP',balance_before:'$RECIP_BEFORE',balance_after:'$RECIP_AFTER',asset_id:9001,amount:250},
rwa:{holder:'(admin)',balance:'$RWABAL',amount:100}};
fs.writeFileSync('deployments/testnet-hardened.json',JSON.stringify(d,null,2));console.log('wrote deployments/testnet-hardened.json');"
echo "DEPLOY_OK"
