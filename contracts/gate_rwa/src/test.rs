#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_gate_payment as payment_contract;
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

struct PaymentFixture {
    vk: payment_contract::VerificationKey,
    proof: payment_contract::Proof,
    signals: Vec<Fr>,
}

fn load_fixture(env: &Env, json: &str) -> Fixture {
    let fixture: CliArgs = serde_json::from_str(json).unwrap();
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

fn load_payment_fixture(env: &Env) -> PaymentFixture {
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

    PaymentFixture {
        vk: payment_contract::VerificationKey {
            alpha: g1_from_hex(env, &fixture.vk.alpha),
            beta: g2_from_hex(env, &fixture.vk.beta),
            gamma: g2_from_hex(env, &fixture.vk.gamma),
            delta: g2_from_hex(env, &fixture.vk.delta),
            ic,
        },
        proof: payment_contract::Proof {
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

fn setup() -> (Env, GateRwaClient<'static>, Fixture) {
    let env = Env::default();
    env.mock_all_auths();
    let fixture = load_fixture(&env, include_str!("../../../testdata/rwa/cli-args.json"));
    let admin = Address::generate(&env);
    let contract_id = env.register(GateRwa, ());
    let client = GateRwaClient::new(&env, &contract_id);

    client.init(&admin);
    client.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap());
    client.set_policy(&Policy {
        policy_id: 303,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 1,
    });
    client.fund(&9101, &500_i128);

    (env, client, fixture)
}

#[test]
fn same_credential_satisfies_payment_and_rwa_policies() {
    let env = Env::default();
    env.mock_all_auths();
    let payment_fixture = load_payment_fixture(&env);
    let rwa_fixture = load_fixture(&env, include_str!("../../../testdata/rwa/cli-args.json"));

    assert_eq!(
        payment_fixture.signals.get(CREDENTIAL_ROOT).unwrap(),
        rwa_fixture.signals.get(CREDENTIAL_ROOT).unwrap()
    );
    assert_ne!(
        payment_fixture.signals.get(NULLIFIER).unwrap(),
        rwa_fixture.signals.get(NULLIFIER).unwrap()
    );

    let admin = Address::generate(&env);
    let payment_id = env.register(payment_contract::GatePayment, ());
    let payment_client = payment_contract::GatePaymentClient::new(&env, &payment_id);
    payment_client.init(&admin);
    payment_client.set_root(&101, &payment_fixture.signals.get(CREDENTIAL_ROOT).unwrap());
    payment_client.set_policy(&payment_contract::Policy {
        policy_id: 202,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 0,
    });
    payment_client.fund(&9001, &1_000_i128);

    let rwa_id = env.register(GateRwa, ());
    let rwa_client = GateRwaClient::new(&env, &rwa_id);
    rwa_client.init(&admin);
    rwa_client.set_root(&101, &rwa_fixture.signals.get(CREDENTIAL_ROOT).unwrap());
    rwa_client.set_policy(&Policy {
        policy_id: 303,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 1,
    });
    rwa_client.fund(&9101, &500_i128);

    let payment_packet_hash = payment_fixture.signals.get(TERMS_HASH).unwrap();
    let payment_nullifier = payment_fixture.signals.get(NULLIFIER).unwrap();
    assert_eq!(
        payment_client.try_verify_and_pay(
            &payment_fixture.vk,
            &payment_fixture.proof,
            &payment_fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &payment_packet_hash,
            &12,
        ),
        Ok(Ok(()))
    );

    let rwa_terms_hash = rwa_fixture.signals.get(TERMS_HASH).unwrap();
    let rwa_nullifier = rwa_fixture.signals.get(NULLIFIER).unwrap();
    assert_eq!(
        rwa_client.try_verify_and_transfer(
            &rwa_fixture.vk,
            &rwa_fixture.proof,
            &rwa_fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &rwa_terms_hash,
            &12,
        ),
        Ok(Ok(()))
    );

    assert_eq!(payment_client.balance(&9001, &7_000_001_u128), 250);
    assert!(payment_client.is_nullifier_used(&payment_nullifier));
    assert_eq!(rwa_client.holding(&9101, &8_000_001_u128), 100);
    assert_eq!(rwa_client.inventory(&9101), 400);
    assert!(rwa_client.is_nullifier_used(&rwa_nullifier));
}

#[test]
fn valid_proof_executes_mock_rwa_transfer() {
    let (_, client, fixture) = setup();
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();
    let nullifier = fixture.signals.get(NULLIFIER).unwrap();

    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Ok(Ok(()))
    );
    assert_eq!(client.holding(&9101, &8_000_001_u128), 100);
    assert_eq!(client.inventory(&9101), 400);
    assert!(client.is_nullifier_used(&nullifier));
}

#[test]
fn payment_proof_cannot_execute_rwa() {
    let env = Env::default();
    env.mock_all_auths();
    let fixture = load_fixture(
        &env,
        include_str!("../../../testdata/eligibility/cli-args.json"),
    );
    let admin = Address::generate(&env);
    let contract_id = env.register(GateRwa, ());
    let client = GateRwaClient::new(&env, &contract_id);
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();

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

    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &202,
            &9001,
            &250_i128,
            &7_000_001_u128,
            &424_242_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
}

#[test]
fn rwa_proof_for_action_a_fails_for_action_b() {
    let (_env, client, fixture) = setup();
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();

    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &101_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_002_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_152_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
}

#[test]
fn rejects_wrong_rwa_policy_parameters() {
    let (_env, client, fixture) = setup();
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();

    client.set_policy(&Policy {
        policy_id: 303,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 2,
    });
    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::PublicInputMismatch))
    );
}

#[test]
fn rejects_terms_hash_mismatch() {
    let (env, client, fixture) = setup();
    let wrong_terms_hash = Fr::from_u256(U256::from_u32(&env, 999));

    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &wrong_terms_hash,
            &12,
        ),
        Err(Ok(Error::TermsHashMismatch))
    );
}

#[test]
fn rejects_rotated_root() {
    let (_env, client, fixture) = setup();
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();
    let wrong_root = fixture.signals.get(TERMS_HASH).unwrap();

    client.set_root(&101, &wrong_root);
    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::RootMismatch))
    );
}

#[test]
fn rejects_reused_nullifier() {
    let (_env, client, fixture) = setup();
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();

    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Ok(Ok(()))
    );
    assert_eq!(
        client.try_verify_and_transfer(
            &fixture.vk,
            &fixture.proof,
            &fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
        ),
        Err(Ok(Error::NullifierUsed))
    );
}
