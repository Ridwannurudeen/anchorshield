#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use anchorshield_nullifier_registry::{NullifierRegistry, NullifierRegistryClient};
use anchorshield_policy_registry::{PolicyRegistry, PolicyRegistryClient};
use anchorshield_verifier::{Verifier, VerifierClient};
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine, G1_SERIALIZED_SIZE,
        G2_SERIALIZED_SIZE,
    },
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    Bytes, Env, U256,
};

#[derive(Deserialize)]
struct CliArgs {
    vk: CliVerificationKey,
    proof: CliProof,
    pub_signals: std::vec::Vec<CliU256>,
}
#[derive(Deserialize)]
struct CliVerificationKey {
    alpha: std::string::String,
    beta: std::string::String,
    gamma: std::string::String,
    delta: std::string::String,
    ic: std::vec::Vec<std::string::String>,
}
#[derive(Deserialize)]
struct CliProof {
    a: std::string::String,
    b: std::string::String,
    c: std::string::String,
}
#[derive(Deserialize)]
struct CliU256 {
    u256: std::string::String,
}

struct Fixture {
    vk: VerificationKey,
    proof: Proof,
    signals: Vec<Fr>,
}

fn load_fixture(env: &Env) -> Fixture {
    let fixture: CliArgs =
        serde_json::from_str(include_str!("../../../testdata/eligibility/cli-args.json")).unwrap();
    let mut ic = Vec::new(env);
    for point in fixture.vk.ic {
        ic.push_back(g1_from_hex(env, &point));
    }
    let mut signals = Vec::new(env);
    for signal in fixture.pub_signals {
        signals.push_back(fr_from_dec(env, &signal.u256));
    }
    Fixture {
        vk: VerificationKey {
            alpha: g1_from_hex(env, &fixture.vk.alpha),
            beta: g2_from_hex(env, &fixture.vk.beta),
            gamma: g2_from_hex(env, &fixture.vk.gamma),
            delta: g2_from_hex(env, &fixture.vk.delta),
            ic,
        },
        proof: Proof {
            a: g1_from_hex(env, &fixture.proof.a),
            b: g2_from_hex(env, &fixture.proof.b),
            c: g1_from_hex(env, &fixture.proof.c),
        },
        signals,
    }
}

fn g1_from_hex(env: &Env, value: &str) -> G1Affine {
    let bytes = hex::decode(value).unwrap();
    let arr: [u8; G1_SERIALIZED_SIZE] = bytes.try_into().unwrap();
    G1Affine::from_array(env, &arr)
}
fn g2_from_hex(env: &Env, value: &str) -> G2Affine {
    let bytes = hex::decode(value).unwrap();
    let arr: [u8; G2_SERIALIZED_SIZE] = bytes.try_into().unwrap();
    G2Affine::from_array(env, &arr)
}
fn fr_from_dec(env: &Env, value: &str) -> Fr {
    let n = value.parse::<BigUint>().unwrap();
    let mut arr = [0u8; 32];
    let bytes = n.to_bytes_be();
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    Fr::from_u256(U256::from_be_bytes(env, &Bytes::from_array(env, &arr)))
}

fn circuit_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7; 32])
}

fn default_policy(env: &Env) -> Policy {
    Policy {
        policy_id: 202,
        issuer_id: 101,
        circuit_id: circuit_id(env),
        circuit_version: 1,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 0,
    }
}

struct Harness {
    env: Env,
    gate: GatePaymentClient<'static>,
    issuer: IssuerRegistryClient<'static>,
    policy: PolicyRegistryClient<'static>,
    nullifier: NullifierRegistryClient<'static>,
    token: Address,
    recipient: Address,
    fixture: Fixture,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let fixture = load_fixture(&env);
    let admin = Address::generate(&env);

    let verifier_id = env.register(Verifier, ());
    let verifier = VerifierClient::new(&env, &verifier_id);
    verifier.init(&admin);
    verifier.set_vk(&circuit_id(&env), &1, &fixture.vk);

    let issuer_id = env.register(IssuerRegistry, ());
    let issuer = IssuerRegistryClient::new(&env, &issuer_id);
    issuer.init(&admin);
    issuer.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap());
    issuer.set_sanctions_root(&fixture.signals.get(SANCTIONS_ROOT).unwrap());
    issuer.set_revocation_root(&101, &fixture.signals.get(REVOCATION_ROOT).unwrap());

    let policy_reg_id = env.register(PolicyRegistry, ());
    let policy = PolicyRegistryClient::new(&env, &policy_reg_id);
    policy.init(&admin);
    policy.set_policy(&default_policy(&env));

    let nullifier_id = env.register(NullifierRegistry, ());
    let nullifier = NullifierRegistryClient::new(&env, &nullifier_id);
    nullifier.init(&admin);

    let gate_id = env.register(GatePayment, ());
    let gate = GatePaymentClient::new(&env, &gate_id);
    gate.init(
        &admin,
        &verifier_id,
        &issuer_id,
        &policy_reg_id,
        &nullifier_id,
    );
    nullifier.allow_gate(&gate_id);

    // Real SAC: register the asset, register the payee, fund the gate.
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let recipient = Address::generate(&env);
    gate.set_token(&9001, &token);
    gate.set_recipient(&7_000_001_u128, &recipient);
    StellarAssetClient::new(&env, &token).mint(&gate_id, &1_000_i128);

    Harness {
        env,
        gate,
        issuer,
        policy,
        nullifier,
        token,
        recipient,
        fixture,
    }
}

#[test]
fn valid_proof_executes_real_payment() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();
    let nullifier = h.fixture.signals.get(NULLIFIER).unwrap();

    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Ok(Ok(()))
    );
    let token = TokenClient::new(&h.env, &h.token);
    assert_eq!(token.balance(&h.recipient), 250);
    assert_eq!(token.balance(&h.gate.address), 750);
    assert!(h.nullifier.is_used(&nullifier.to_bytes()));
}

#[test]
fn proof_for_action_a_fails_for_action_b() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();

    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &251_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_243_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
}

#[test]
fn rejects_wrong_policy_parameters() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();

    h.policy.set_policy(&Policy {
        policy_id: 202,
        issuer_id: 101,
        circuit_id: circuit_id(&h.env),
        circuit_version: 1,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 840,
        min_age: 18,
        min_investor_type: 0,
    });
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
}

#[test]
fn rejects_packet_hash_mismatch() {
    let h = setup();
    let wrong_packet_hash = Fr::from_u256(U256::from_u32(&h.env, 999));

    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &wrong_packet_hash,
            &12,
        ),
        Err(Ok(Error::PacketHashMismatch))
    );
}

#[test]
fn rejects_reused_nullifier() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();

    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Ok(Ok(()))
    );
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::NullifierUsed))
    );
}

#[test]
fn rejects_unregistered_root() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();
    let wrong_root = h.fixture.signals.get(PACKET_HASH).unwrap();
    let another_wrong_root = h.fixture.signals.get(ACTION_BINDING).unwrap();

    h.issuer.set_root(&101, &wrong_root);
    h.issuer.set_root(&101, &another_wrong_root);
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::RootMismatch))
    );
}

#[test]
fn accepts_immediately_previous_credential_root() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();
    let rotated_root = h.fixture.signals.get(PACKET_HASH).unwrap();

    h.issuer.set_root(&101, &rotated_root);
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Ok(Ok(()))
    );
}

#[test]
fn rejects_sanctions_root_mismatch() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();
    let wrong_root = h.fixture.signals.get(PACKET_HASH).unwrap();

    h.issuer.set_sanctions_root(&wrong_root);
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::SanctionsRootMismatch))
    );
}

#[test]
fn rejects_revocation_root_mismatch() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();
    let wrong_root = h.fixture.signals.get(PACKET_HASH).unwrap();

    h.issuer.set_revocation_root(&101, &wrong_root);
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::RevocationRootMismatch))
    );
}

#[test]
fn recipient_and_token_registry_lookup() {
    let h = setup();
    assert!(h.gate.token(&9001).is_some());
    assert!(h.gate.recipient(&7_000_001_u128).is_some());
    assert!(h.gate.recipient(&7_000_002_u128).is_none());
}

#[test]
fn token_mapping_is_write_once_per_asset_id() {
    let h = setup();
    let another_token = Address::generate(&h.env);

    assert_eq!(
        h.gate.try_set_token(&9001, &another_token),
        Err(Ok(Error::AlreadySet))
    );
    assert_eq!(h.gate.try_set_token(&9002, &another_token), Ok(Ok(())));
}

#[test]
fn recipient_mapping_is_write_once_per_recipient_id() {
    let h = setup();
    let another_recipient = Address::generate(&h.env);

    assert_eq!(
        h.gate
            .try_set_recipient(&7_000_001_u128, &another_recipient),
        Err(Ok(Error::AlreadySet))
    );
    assert_eq!(
        h.gate
            .try_set_recipient(&7_000_002_u128, &another_recipient),
        Ok(Ok(()))
    );
}

#[test]
fn pause_blocks_and_unpause_restores_payment() {
    let h = setup();
    let packet_hash = h.fixture.signals.get(PACKET_HASH).unwrap();

    assert_eq!(h.gate.try_pause(), Ok(Ok(())));
    assert!(h.gate.paused());
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Err(Ok(Error::Paused))
    );

    assert_eq!(h.gate.try_unpause(), Ok(Ok(())));
    assert_eq!(
        h.gate.try_verify_and_pay(
            &h.fixture.proof,
            &h.fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &packet_hash,
            &12,
        ),
        Ok(Ok(()))
    );
}
