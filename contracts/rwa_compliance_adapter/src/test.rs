#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_identity_verifier::{IdentityVerifier, IdentityVerifierClient};
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use anchorshield_nullifier_registry::{NullifierRegistry, NullifierRegistryClient};
use anchorshield_policy_registry::{PolicyRegistry, PolicyRegistryClient};
use anchorshield_shared::{
    Policy, Proof, VerificationKey, BOUND_HASH, CREDENTIAL_ROOT, REVOCATION_ROOT, SANCTIONS_ROOT,
};
use anchorshield_verifier::{Verifier, VerifierClient};
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
        G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE,
    },
    testutils::Address as _,
    Bytes, BytesN, Env, Vec, U256,
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
        serde_json::from_str(include_str!("../../../testdata/rwa/cli-args.json")).unwrap();
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

#[test]
fn bind_token_is_admin_only_and_write_once() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let stranger = Address::generate(&env);
    let identity_verifier = Address::generate(&env);
    let token = Address::generate(&env);
    let id = env.register(RwaComplianceAdapter, ());
    let adapter = RwaComplianceAdapterClient::new(&env, &id);

    adapter.init(&admin, &identity_verifier);
    assert_eq!(
        adapter.try_bind_token(&token, &stranger),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(adapter.try_bind_token(&token, &admin), Ok(Ok(())));
    assert!(adapter.is_token_bound(&token));
    assert_eq!(
        adapter.try_bind_token(&token, &admin),
        Err(Ok(Error::TokenAlreadyBound))
    );
}

#[test]
fn created_requires_bound_token() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let identity_verifier = Address::generate(&env);
    let token = Address::generate(&env);
    let account = Address::generate(&env);
    let id = env.register(RwaComplianceAdapter, ());
    let adapter = RwaComplianceAdapterClient::new(&env, &id);

    adapter.init(&admin, &identity_verifier);
    let snapshot = AccountSnapshot {
        address: account,
        balance: 0,
        frozen: 0,
    };

    assert_eq!(
        adapter.try_created(&snapshot, &100_i128, &token),
        Err(Ok(Error::TokenNotBound))
    );
}

#[test]
fn adapter_exposes_identity_verifier() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity_id = env.register(IdentityVerifier, ());
    let id = env.register(RwaComplianceAdapter, ());
    let adapter = RwaComplianceAdapterClient::new(&env, &id);

    adapter.init(&admin, &identity_id);
    assert_eq!(adapter.identity_verifier(), identity_id);
}

#[test]
fn created_consumes_real_mint_authorization() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let account = Address::generate(&env);
    let token = Address::generate(&env);
    let fixture = load_fixture(&env);

    let verifier_id = env.register(Verifier, ());
    let verifier = VerifierClient::new(&env, &verifier_id);
    verifier.init(&admin);
    verifier.set_vk(&circuit_id(&env), &1, &fixture.vk);

    let issuer_id = env.register(IssuerRegistry, ());
    let issuer = IssuerRegistryClient::new(&env, &issuer_id);
    issuer.init(&admin);
    issuer.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap(), &64);
    issuer.set_sanctions_root(&fixture.signals.get(SANCTIONS_ROOT).unwrap());
    issuer.set_revocation_root(&101, &fixture.signals.get(REVOCATION_ROOT).unwrap());

    let policy_id = env.register(PolicyRegistry, ());
    let policy = PolicyRegistryClient::new(&env, &policy_id);
    policy.init(&admin);
    policy.set_policy(&Policy {
        policy_id: 303,
        issuer_id: 101,
        circuit_id: circuit_id(&env),
        circuit_version: 1,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 1,
        min_credential_members: 32,
    });

    let nullifier_id = env.register(NullifierRegistry, ());
    let nullifier = NullifierRegistryClient::new(&env, &nullifier_id);
    nullifier.init(&admin);

    let identity_id = env.register(IdentityVerifier, ());
    let identity = IdentityVerifierClient::new(&env, &identity_id);
    identity.init(&admin, &verifier_id, &issuer_id, &policy_id, &nullifier_id);
    nullifier.allow_gate(&identity_id);

    let adapter_id = env.register(RwaComplianceAdapter, ());
    let adapter = RwaComplianceAdapterClient::new(&env, &adapter_id);
    adapter.init(&admin, &identity_id);
    adapter.bind_token(&token, &admin);

    identity.set_rwa_token(&9101, &token);
    identity.set_rwa_recipient(&8_000_001_u128, &account);
    identity.allow_mint_consumer(&adapter_id);
    let terms_hash = fixture.signals.get(BOUND_HASH).unwrap();
    identity.attest_for_mint(
        &account,
        &adapter_id,
        &fixture.proof,
        &fixture.signals,
        &303,
        &9101,
        &100_i128,
        &8_000_001_u128,
        &515_151_u128,
        &terms_hash,
        &12,
        &10_000_u64,
    );
    assert!(identity
        .mint_authorization(&adapter_id, &token, &account)
        .is_some());

    let snapshot = AccountSnapshot {
        address: account.clone(),
        balance: 0,
        frozen: 0,
    };
    assert_eq!(
        adapter.try_created(&snapshot, &100_i128, &token),
        Ok(Ok(()))
    );
    assert!(identity
        .mint_authorization(&adapter_id, &token, &account)
        .is_none());
}
