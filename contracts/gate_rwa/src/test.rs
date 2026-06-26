#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_gate_payment as payment_contract;
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use anchorshield_nullifier_registry::{NullifierRegistry, NullifierRegistryClient};
use anchorshield_policy_registry::{PolicyRegistry, PolicyRegistryClient};
use anchorshield_verifier::{Verifier, VerifierClient};
use num_bigint::BigUint;
use serde::Deserialize;
use soroban_sdk::{
    crypto::bls12_381::{Bls12381G1Affine as G1Affine, G1_SERIALIZED_SIZE, Bls12381G2Affine as G2Affine, G2_SERIALIZED_SIZE},
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

/// The shared AnchorShield primitive: one verifier (pinned VK) + the three
/// registries. Gates are attached to this stack.
struct Stack {
    verifier_id: Address,
    issuer_id: Address,
    policy_reg_id: Address,
    nullifier_id: Address,
    issuer: IssuerRegistryClient<'static>,
    policy: PolicyRegistryClient<'static>,
    nullifier: NullifierRegistryClient<'static>,
}

fn deploy_stack(env: &Env, admin: &Address, vk: &VerificationKey, root: &Fr) -> Stack {
    let verifier_id = env.register(Verifier, ());
    let verifier = VerifierClient::new(env, &verifier_id);
    verifier.init(admin);
    verifier.set_vk(vk);

    let issuer_id = env.register(IssuerRegistry, ());
    let issuer = IssuerRegistryClient::new(env, &issuer_id);
    issuer.init(admin);
    issuer.set_root(&101, root);

    let policy_reg_id = env.register(PolicyRegistry, ());
    let policy = PolicyRegistryClient::new(env, &policy_reg_id);
    policy.init(admin);

    let nullifier_id = env.register(NullifierRegistry, ());
    let nullifier = NullifierRegistryClient::new(env, &nullifier_id);
    nullifier.init(admin);

    Stack {
        verifier_id,
        issuer_id,
        policy_reg_id,
        nullifier_id,
        issuer,
        policy,
        nullifier,
    }
}

impl Stack {
    fn add_rwa_gate(&self, env: &Env, admin: &Address) -> GateRwaClient<'static> {
        let gate_id = env.register(GateRwa, ());
        let gate = GateRwaClient::new(env, &gate_id);
        gate.init(
            admin,
            &self.verifier_id,
            &self.issuer_id,
            &self.policy_reg_id,
            &self.nullifier_id,
        );
        self.nullifier.allow_gate(&gate_id);
        gate
    }

    fn add_payment_gate(
        &self,
        env: &Env,
        admin: &Address,
    ) -> payment_contract::GatePaymentClient<'static> {
        let gate_id = env.register(payment_contract::GatePayment, ());
        let gate = payment_contract::GatePaymentClient::new(env, &gate_id);
        gate.init(
            admin,
            &self.verifier_id,
            &self.issuer_id,
            &self.policy_reg_id,
            &self.nullifier_id,
        );
        self.nullifier.allow_gate(&gate_id);
        gate
    }
}

fn rwa_policy(min_investor_type: u32) -> Policy {
    Policy {
        policy_id: 303,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type,
    }
}

struct Harness {
    env: Env,
    gate: GateRwaClient<'static>,
    issuer: IssuerRegistryClient<'static>,
    policy: PolicyRegistryClient<'static>,
    nullifier: NullifierRegistryClient<'static>,
    fixture: Fixture,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let fixture = load_fixture(&env, include_str!("../../../testdata/rwa/cli-args.json"));
    let admin = Address::generate(&env);

    let stack = deploy_stack(
        &env,
        &admin,
        &fixture.vk,
        &fixture.signals.get(CREDENTIAL_ROOT).unwrap(),
    );
    stack.policy.set_policy(&rwa_policy(1));
    let gate = stack.add_rwa_gate(&env, &admin);
    gate.fund(&9101, &500_i128);

    Harness {
        env,
        gate,
        issuer: stack.issuer,
        policy: stack.policy,
        nullifier: stack.nullifier,
        fixture,
    }
}

#[test]
fn same_credential_satisfies_payment_and_rwa_policies() {
    let env = Env::default();
    env.mock_all_auths();
    let payment_fixture = load_fixture(
        &env,
        include_str!("../../../testdata/eligibility/cli-args.json"),
    );
    let rwa_fixture = load_fixture(&env, include_str!("../../../testdata/rwa/cli-args.json"));

    // Same credential root, distinct (action-scoped) nullifiers.
    assert_eq!(
        payment_fixture.signals.get(CREDENTIAL_ROOT).unwrap(),
        rwa_fixture.signals.get(CREDENTIAL_ROOT).unwrap()
    );
    assert_ne!(
        payment_fixture.signals.get(NULLIFIER).unwrap(),
        rwa_fixture.signals.get(NULLIFIER).unwrap()
    );

    let admin = Address::generate(&env);
    // One shared stack (same verifier VK + same issuer root) serves both gates.
    let stack = deploy_stack(
        &env,
        &admin,
        &rwa_fixture.vk,
        &rwa_fixture.signals.get(CREDENTIAL_ROOT).unwrap(),
    );
    stack.policy.set_policy(&payment_contract::Policy {
        policy_id: 202,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 0,
    });
    stack.policy.set_policy(&rwa_policy(1));

    let payment_client = stack.add_payment_gate(&env, &admin);
    payment_client.fund(&9001, &1_000_i128);
    let rwa_client = stack.add_rwa_gate(&env, &admin);
    rwa_client.fund(&9101, &500_i128);

    let payment_packet_hash = payment_fixture.signals.get(TERMS_HASH).unwrap();
    let payment_nullifier = payment_fixture.signals.get(NULLIFIER).unwrap();
    assert_eq!(
        payment_client.try_verify_and_pay(
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
    assert!(stack.nullifier.is_used(&payment_nullifier.to_bytes()));
    assert_eq!(rwa_client.holding(&9101, &8_000_001_u128), 100);
    assert_eq!(rwa_client.inventory(&9101), 400);
    assert!(stack.nullifier.is_used(&rwa_nullifier.to_bytes()));
}

#[test]
fn valid_proof_executes_mock_rwa_transfer() {
    let h = setup();
    let terms_hash = h.fixture.signals.get(TERMS_HASH).unwrap();
    let nullifier = h.fixture.signals.get(NULLIFIER).unwrap();

    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
    assert_eq!(h.gate.holding(&9101, &8_000_001_u128), 100);
    assert_eq!(h.gate.inventory(&9101), 400);
    assert!(h.nullifier.is_used(&nullifier.to_bytes()));
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
    let terms_hash = fixture.signals.get(TERMS_HASH).unwrap();

    let stack = deploy_stack(
        &env,
        &admin,
        &fixture.vk,
        &fixture.signals.get(CREDENTIAL_ROOT).unwrap(),
    );
    stack.policy.set_policy(&Policy {
        policy_id: 202,
        issuer_id: 101,
        kyc_required: true,
        sanctions_required: true,
        allowed_country: 566,
        min_age: 18,
        min_investor_type: 0,
    });
    let client = stack.add_rwa_gate(&env, &admin);
    client.fund(&9001, &1_000_i128);

    assert_eq!(
        client.try_verify_and_transfer(
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
    let h = setup();
    let terms_hash = h.fixture.signals.get(TERMS_HASH).unwrap();

    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
    let h = setup();
    let terms_hash = h.fixture.signals.get(TERMS_HASH).unwrap();

    h.policy.set_policy(&rwa_policy(2));
    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
    let h = setup();
    let wrong_terms_hash = Fr::from_u256(U256::from_u32(&h.env, 999));

    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
    let h = setup();
    let terms_hash = h.fixture.signals.get(TERMS_HASH).unwrap();
    let wrong_root = h.fixture.signals.get(TERMS_HASH).unwrap();

    h.issuer.set_root(&101, &wrong_root);
    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
    let h = setup();
    let terms_hash = h.fixture.signals.get(TERMS_HASH).unwrap();

    assert_eq!(
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
        h.gate.try_verify_and_transfer(
            &h.fixture.proof,
            &h.fixture.signals,
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
