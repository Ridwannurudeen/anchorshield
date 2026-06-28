#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_shared::VerificationKey;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine, G1_SERIALIZED_SIZE,
        G2_SERIALIZED_SIZE,
    },
    testutils::Address as _,
    BytesN, Env, Vec,
};

#[derive(Deserialize)]
struct CliArgs {
    vk: CliVerificationKey,
}

#[derive(Deserialize)]
struct CliVerificationKey {
    alpha: std::string::String,
    beta: std::string::String,
    gamma: std::string::String,
    delta: std::string::String,
    ic: std::vec::Vec<std::string::String>,
}

fn load_vk(env: &Env) -> VerificationKey {
    let fixture: CliArgs =
        serde_json::from_str(include_str!("../../../testdata/eligibility/cli-args.json")).unwrap();
    let mut ic = Vec::new(env);
    for point in fixture.vk.ic {
        ic.push_back(g1_from_hex(env, &point));
    }
    VerificationKey {
        alpha: g1_from_hex(env, &fixture.vk.alpha),
        beta: g2_from_hex(env, &fixture.vk.beta),
        gamma: g2_from_hex(env, &fixture.vk.gamma),
        delta: g2_from_hex(env, &fixture.vk.delta),
        ic,
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

fn circuit_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7; 32])
}

#[test]
fn freeze_vk_blocks_future_set_vk() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let vk = load_vk(&env);
    let verifier_id = env.register(Verifier, ());
    let verifier = VerifierClient::new(&env, &verifier_id);

    verifier.init(&admin);
    assert_eq!(verifier.try_set_vk(&circuit_id(&env), &1, &vk), Ok(Ok(())));
    assert_eq!(verifier.try_freeze_vk(), Ok(Ok(())));
    assert_eq!(
        verifier.try_set_vk(&circuit_id(&env), &1, &vk),
        Err(Ok(Error::VkFrozen))
    );
    assert!(verifier.is_frozen());
}

#[test]
fn verifier_exposes_circuit_metadata() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let vk = load_vk(&env);
    let circuit_id = circuit_id(&env);
    let verifier_id = env.register(Verifier, ());
    let verifier = VerifierClient::new(&env, &verifier_id);

    verifier.init(&admin);
    verifier.set_vk(&circuit_id, &1, &vk);

    assert_eq!(verifier.circuit_id(), Some(circuit_id));
    assert_eq!(verifier.circuit_version(), Some(1));
}
