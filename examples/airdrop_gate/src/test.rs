#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_identity_verifier::{IdentityVerifier, IdentityVerifierClient};
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use anchorshield_nullifier_registry::{NullifierRegistry, NullifierRegistryClient};
use anchorshield_policy_registry::{PolicyRegistry, PolicyRegistryClient};
use anchorshield_shared::{
    Policy, Proof, VerificationKey, CREDENTIAL_ROOT, REVOCATION_ROOT, SANCTIONS_ROOT,
};
use anchorshield_verifier::{Verifier, VerifierClient};
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
        G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE,
    },
    testutils::{Address as _, Ledger},
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

struct Harness {
    env: Env,
    gate: AirdropGateClient<'static>,
    identity: IdentityVerifierClient<'static>,
    fixture: Fixture,
}

fn circuit_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7; 32])
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
    issuer.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap(), &1000);
    issuer.set_sanctions_root(&fixture.signals.get(SANCTIONS_ROOT).unwrap());
    issuer.set_revocation_root(&101, &fixture.signals.get(REVOCATION_ROOT).unwrap());

    let policy_reg_id = env.register(PolicyRegistry, ());
    let policy = PolicyRegistryClient::new(&env, &policy_reg_id);
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
        min_credential_members: 1,
    });

    let nullifier_id = env.register(NullifierRegistry, ());
    let nullifier = NullifierRegistryClient::new(&env, &nullifier_id);
    nullifier.init(&admin);

    let identity_id = env.register(IdentityVerifier, ());
    let identity = IdentityVerifierClient::new(&env, &identity_id);
    identity.init(
        &admin,
        &verifier_id,
        &issuer_id,
        &policy_reg_id,
        &nullifier_id,
    );
    nullifier.allow_gate(&identity_id);

    let gate_id = env.register(AirdropGate, ());
    let gate = AirdropGateClient::new(&env, &gate_id);
    gate.init(&admin, &identity_id);

    Harness {
        env,
        gate,
        identity,
        fixture,
    }
}

fn attest(h: &Harness, account: &Address, valid_until: u64) {
    assert_eq!(
        h.identity.try_attest(
            account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &valid_until,
        ),
        Ok(Ok(()))
    );
}

#[test]
fn attested_account_claims_once() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    assert_eq!(h.gate.try_claim(&account), Ok(Ok(())));
    assert!(h.gate.claimed(&account));
    assert_eq!(h.gate.try_claim(&account), Err(Ok(Error::AlreadyClaimed)));
}

#[test]
fn unattested_account_cannot_claim() {
    let h = setup();
    let account = Address::generate(&h.env);

    assert!(h.gate.try_claim(&account).is_err());
    assert!(!h.gate.claimed(&account));
}

#[test]
fn expired_attestation_cannot_claim() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    h.env.ledger().set_timestamp(10_001);
    assert!(h.gate.try_claim(&account).is_err());
    assert!(!h.gate.claimed(&account));
}

#[test]
fn admin_transfer_matches_contract_pattern() {
    let h = setup();
    let original_admin = h.gate.admin().unwrap();
    let next_admin = Address::generate(&h.env);

    assert_eq!(h.gate.admin(), Some(original_admin));
    assert_eq!(h.gate.try_transfer_admin(&next_admin), Ok(Ok(())));
    assert_eq!(h.gate.admin(), Some(next_admin));
}
