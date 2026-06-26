#![no_std]

//! Shared AnchorShield primitives reused by every gate contract: the Groth16
//! verification-key / proof / policy types, the public-signal index layout, and
//! the proof-verification + signal-binding helpers. Extracted from the formerly
//! duplicated gate code so there is a single source of truth.

use soroban_sdk::{
    contractclient, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    vec, Address, BytesN, Env, Vec, U256,
};

// Public-signal index layout (snarkjs emits the 4 circuit outputs first, then the
// 13 declared public inputs). Index 1 is the action-bound hash: the payment gate
// reads it as `packet_hash`, the RWA gate as `terms_hash` — same slot.
pub const CREDENTIAL_ROOT: u32 = 0;
pub const BOUND_HASH: u32 = 1;
pub const NULLIFIER: u32 = 2;
pub const ACTION_BINDING: u32 = 3;
pub const ISSUER_ID: u32 = 4;
pub const POLICY_ID: u32 = 5;
pub const KYC_REQUIRED: u32 = 6;
pub const SANCTIONS_REQUIRED: u32 = 7;
pub const ALLOWED_COUNTRY: u32 = 8;
pub const MIN_AGE: u32 = 9;
pub const MIN_INVESTOR_TYPE: u32 = 10;
pub const ACTION_TYPE: u32 = 11;
pub const ASSET_ID: u32 = 12;
pub const AMOUNT: u32 = 13;
pub const RECIPIENT: u32 = 14;
pub const ACTION_ID: u32 = 15;
pub const EPOCH: u32 = 16;
pub const PUBLIC_SIGNAL_COUNT: u32 = 17;

/// Errors produced by the shared signal/verification helpers. Each gate maps
/// these into its own `#[contracterror]` enum via `From`, preserving the
/// gate-facing error codes (5, 6, 11).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SharedError {
    MalformedPublicSignals,
    PublicInputMismatch,
    MalformedVerifyingKey,
}

#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Policy {
    pub policy_id: u32,
    pub issuer_id: u32,
    pub kyc_required: bool,
    pub sanctions_required: bool,
    pub allowed_country: u32,
    pub min_age: u32,
    pub min_investor_type: u32,
}

pub fn bool_as_u32(value: bool) -> u32 {
    if value {
        1
    } else {
        0
    }
}

pub fn signal(pub_signals: &Vec<Fr>, index: u32) -> Result<Fr, SharedError> {
    pub_signals
        .get(index)
        .ok_or(SharedError::MalformedPublicSignals)
}

pub fn require_signal_u32(
    env: &Env,
    pub_signals: &Vec<Fr>,
    index: u32,
    expected: u32,
) -> Result<(), SharedError> {
    if signal(pub_signals, index)? != Fr::from_u256(U256::from_u32(env, expected)) {
        return Err(SharedError::PublicInputMismatch);
    }
    Ok(())
}

pub fn require_signal_u128(
    env: &Env,
    pub_signals: &Vec<Fr>,
    index: u32,
    expected: u128,
) -> Result<(), SharedError> {
    if signal(pub_signals, index)? != Fr::from_u256(U256::from_u128(env, expected)) {
        return Err(SharedError::PublicInputMismatch);
    }
    Ok(())
}

/// Groth16 verification over BLS12-381 host functions: accumulates `vk_x` from the
/// public signals and checks the pairing product `e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta) == 1`.
pub fn verify_proof(
    env: &Env,
    vk: VerificationKey,
    proof: Proof,
    pub_signals: &Vec<Fr>,
) -> Result<bool, SharedError> {
    if pub_signals.len() + 1 != vk.ic.len() {
        return Err(SharedError::MalformedVerifyingKey);
    }

    let bls = env.crypto().bls12_381();
    let mut vk_x = vk.ic.get(0).unwrap();
    for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
        let prod = bls.g1_mul(&v, &s);
        vk_x = bls.g1_add(&vk_x, &prod);
    }

    let neg_a = -proof.a;
    let vp1 = vec![env, neg_a, vk.alpha, vk_x, proof.c];
    let vp2 = vec![env, proof.b, vk.beta, vk.gamma, vk.delta];

    Ok(bls.pairing_check(vp1, vp2))
}

// Cross-contract peer interfaces. Gates call peers through these generated
// clients instead of depending on the peer contract crates directly, which would
// link the peers' exported wasm symbols into the gate (duplicate-symbol error).

#[contractclient(name = "VerifierPeerClient")]
pub trait VerifierPeer {
    fn verify(env: Env, proof: Proof, pub_signals: Vec<Fr>) -> bool;
}

#[contractclient(name = "IssuerRegistryPeerClient")]
pub trait IssuerRegistryPeer {
    fn root(env: Env, issuer_id: u32) -> Option<BytesN<32>>;
}

#[contractclient(name = "PolicyRegistryPeerClient")]
pub trait PolicyRegistryPeer {
    fn policy(env: Env, policy_id: u32) -> Option<Policy>;
}

#[contractclient(name = "NullifierRegistryPeerClient")]
pub trait NullifierRegistryPeer {
    fn is_used(env: Env, nullifier: BytesN<32>) -> bool;
    fn mark_used(env: Env, gate: Address, nullifier: BytesN<32>);
}
