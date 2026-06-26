#![cfg(test)]
extern crate std;

use super::*;
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G1_SERIALIZED_SIZE, G2Affine, G2_SERIALIZED_SIZE},
    testutils::Address as _,
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

fn setup() -> (Env, GatePaymentClient<'static>, Fixture) {
    let env = Env::default();
    env.mock_all_auths();
    let fixture = load_fixture(&env);
    let admin = Address::generate(&env);
    let contract_id = env.register(GatePayment, ());
    let client = GatePaymentClient::new(&env, &contract_id);

    client.init(&admin);
    client.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap());
    client.set_policy(&Policy {
        policy_id: 202,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 0,
    });
    client.fund(&9001, &1_000_i128);

    (env, client, fixture)
}

#[test]
fn valid_proof_executes_mock_payment() {
    let (_, client, fixture) = setup();
    let packet_hash = fixture.signals.get(PACKET_HASH).unwrap();
    let nullifier = fixture.signals.get(NULLIFIER).unwrap();

    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
    assert_eq!(client.balance(&9001, &7_000_001_u128), 250);
    assert_eq!(client.escrow(&9001), 750);
    assert!(client.is_nullifier_used(&nullifier));
}

#[test]
fn proof_for_action_a_fails_for_action_b() {
    let (_env, client, fixture) = setup();
    let packet_hash = fixture.signals.get(PACKET_HASH).unwrap();

    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
    let (_env, client, fixture) = setup();
    let packet_hash = fixture.signals.get(PACKET_HASH).unwrap();

    client.set_policy(&Policy {
        policy_id: 202,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 840,
        min_age: 18,
        min_investor_type: 0,
    });
    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
    let (env, client, fixture) = setup();
    let wrong_packet_hash = Fr::from_u256(U256::from_u32(&env, 999));

    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
    let (_env, client, fixture) = setup();
    let packet_hash = fixture.signals.get(PACKET_HASH).unwrap();

    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
    let (_env, client, fixture) = setup();
    let packet_hash = fixture.signals.get(PACKET_HASH).unwrap();
    let wrong_root = fixture.signals.get(PACKET_HASH).unwrap();

    client.set_root(&101, &wrong_root);
    assert_eq!(
        client.try_verify_and_pay(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
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
