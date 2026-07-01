#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use anchorshield_nullifier_registry::{NullifierRegistry, NullifierRegistryClient};
use anchorshield_policy_registry::{PolicyRegistry, PolicyRegistryClient};
use anchorshield_shared::VerificationKey;
use anchorshield_verifier::{Verifier, VerifierClient};
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine, G1_SERIALIZED_SIZE,
        G2_SERIALIZED_SIZE,
    },
    testutils::{Address as _, Ledger},
    Bytes, BytesN, Env, U256,
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

struct Harness {
    env: Env,
    iv: IdentityVerifierClient<'static>,
    issuer: IssuerRegistryClient<'static>,
    policy: PolicyRegistryClient<'static>,
    fixture: Fixture,
}

fn circuit_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7; 32])
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
    issuer.set_root(&101, &fixture.signals.get(CREDENTIAL_ROOT).unwrap(), &64);
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
        min_credential_members: 32,
    });

    let nullifier_id = env.register(NullifierRegistry, ());
    let nullifier = NullifierRegistryClient::new(&env, &nullifier_id);
    nullifier.init(&admin);

    let iv_id = env.register(IdentityVerifier, ());
    let iv = IdentityVerifierClient::new(&env, &iv_id);
    iv.init(
        &admin,
        &verifier_id,
        &issuer_id,
        &policy_reg_id,
        &nullifier_id,
    );
    nullifier.allow_gate(&iv_id);

    Harness {
        env,
        iv,
        issuer,
        policy,
        fixture,
    }
}

#[test]
fn attest_then_verify_identity_succeeds() {
    let h = setup();
    let account = Address::generate(&h.env);

    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
    assert_eq!(h.iv.try_verify_identity(&account), Ok(Ok(())));
    assert_eq!(h.iv.attestation_expiry(&account), Some(10_000_u64));
}

#[test]
fn verify_identity_unknown_account_fails() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.iv.try_verify_identity(&stranger),
        Err(Ok(Error::NotEligible))
    );
}

#[test]
fn attest_rejects_reused_nullifier() {
    let h = setup();
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);

    assert_eq!(
        h.iv.try_attest(
            &a,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
    // Same proof (same nullifier) cannot attest a second account.
    assert_eq!(
        h.iv.try_attest(
            &b,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Err(Ok(Error::NullifierUsed))
    );
}

#[test]
fn attest_accepts_immediately_previous_credential_root() {
    let h = setup();
    let account = Address::generate(&h.env);
    let rotated_root = h.fixture.signals.get(BOUND_HASH).unwrap();

    h.issuer.set_root(&101, &rotated_root, &64);
    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
}

#[test]
fn attest_rejects_below_anonymity_floor() {
    let h = setup();
    let account = Address::generate(&h.env);
    h.policy.set_policy(&Policy {
        policy_id: 303,
        issuer_id: 101,
        circuit_id: circuit_id(&h.env),
        circuit_version: 1,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 1,
        min_credential_members: 65,
    });
    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Err(Ok(Error::AnonymitySetTooSmall))
    );
}

#[test]
fn caps_attestation_ttl_and_expires_after_cap() {
    let h = setup();
    h.env.ledger().set_timestamp(1_000);
    let account = Address::generate(&h.env);
    let capped = 1_000 + MAX_ATTESTATION_TTL;

    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &u64::MAX
        ),
        Ok(Ok(()))
    );
    assert_eq!(h.iv.attestation_expiry(&account), Some(capped));

    h.env.ledger().set_timestamp(capped + 1);
    assert_eq!(h.iv.try_verify_identity(&account), Err(Ok(Error::Expired)));
}

#[test]
fn pause_blocks_and_unpause_restores_identity_checks() {
    let h = setup();
    let account = Address::generate(&h.env);

    assert_eq!(h.iv.try_pause(), Ok(Ok(())));
    assert!(h.iv.paused());
    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Err(Ok(Error::Paused))
    );

    assert_eq!(h.iv.try_unpause(), Ok(Ok(())));
    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
    assert_eq!(h.iv.try_verify_identity(&account), Ok(Ok(())));
}

#[test]
fn attest_for_mint_authorizes_and_consumes_once() {
    let h = setup();
    let account = Address::generate(&h.env);
    let consumer = Address::generate(&h.env);
    let token = Address::generate(&h.env);
    let terms_hash = h.fixture.signals.get(BOUND_HASH).unwrap();

    h.iv.set_rwa_token(&9101, &token);
    h.iv.set_rwa_recipient(&8_000_001_u128, &account);
    h.iv.allow_mint_consumer(&consumer);

    assert_eq!(
        h.iv.try_attest_for_mint(
            &account,
            &consumer,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
    assert_eq!(h.iv.try_verify_identity(&account), Ok(Ok(())));

    let authorization =
        h.iv.mint_authorization(&consumer, &token, &account)
            .unwrap();
    assert_eq!(authorization.amount, 100);
    assert_eq!(authorization.action_id, 515_151);
    assert_eq!(authorization.valid_until, 10_000);

    assert_eq!(
        h.iv.try_consume_mint_authorization(&consumer, &token, &account, &100_i128),
        Ok(Ok(()))
    );
    assert!(h
        .iv
        .mint_authorization(&consumer, &token, &account)
        .is_none());
    assert_eq!(
        h.iv.try_consume_mint_authorization(&consumer, &token, &account, &100_i128),
        Err(Ok(Error::MissingMintAuthorization))
    );
}

#[test]
fn attest_for_mint_requires_registered_consumer() {
    let h = setup();
    let account = Address::generate(&h.env);
    let consumer = Address::generate(&h.env);
    let token = Address::generate(&h.env);
    let terms_hash = h.fixture.signals.get(BOUND_HASH).unwrap();

    h.iv.set_rwa_token(&9101, &token);
    h.iv.set_rwa_recipient(&8_000_001_u128, &account);

    assert_eq!(
        h.iv.try_attest_for_mint(
            &account,
            &consumer,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &9101,
            &100_i128,
            &8_000_001_u128,
            &515_151_u128,
            &terms_hash,
            &12,
            &10_000_u64
        ),
        Err(Ok(Error::MintConsumerNotAllowed))
    );
    assert_eq!(
        h.iv.try_attest(
            &account,
            &h.fixture.proof,
            &h.fixture.signals,
            &303,
            &12,
            &10_000_u64
        ),
        Ok(Ok(()))
    );
}

#[test]
fn rwa_mint_mappings_are_write_once() {
    let h = setup();
    let token = Address::generate(&h.env);
    let other_token = Address::generate(&h.env);
    let account = Address::generate(&h.env);
    let other_account = Address::generate(&h.env);

    assert_eq!(h.iv.try_set_rwa_token(&9101, &token), Ok(Ok(())));
    assert_eq!(h.iv.rwa_token(&9101), Some(token));
    assert_eq!(
        h.iv.try_set_rwa_token(&9101, &other_token),
        Err(Ok(Error::AlreadySet))
    );

    assert_eq!(
        h.iv.try_set_rwa_recipient(&8_000_001_u128, &account),
        Ok(Ok(()))
    );
    assert_eq!(h.iv.rwa_recipient(&8_000_001_u128), Some(account));
    assert_eq!(
        h.iv.try_set_rwa_recipient(&8_000_001_u128, &other_account),
        Err(Ok(Error::AlreadySet))
    );
}

#[test]
fn recovery_target_is_none() {
    let h = setup();
    let account = Address::generate(&h.env);
    assert_eq!(h.iv.recovery_target(&account), None);
}
