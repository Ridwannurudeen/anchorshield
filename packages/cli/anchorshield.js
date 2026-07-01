#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sdk = require("../sdk/src");

const repoRoot = path.resolve(__dirname, "..", "..");
const U32_MAX = 0xffffffff;

function usage() {
  console.log(`anchorshield <command>

Commands:
  compose --spec <policy.json> --out <dir> [--model attestation|per-action]
  inspect-public --public <public.json>
  validate-action --input <input.json> --public <public.json> [--flow payment|rwa]
  soroban-args --cli-args <cli-args.json>
  events --file <compliance-events.json>
  disclosure verify --summary <summary.json>
  gate payment --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/payment]
  gate rwa --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/rwa]`);
}

function args(argv) {
  const parsed = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value.startsWith("--")) {
      const key = value.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        parsed[key] = true;
      } else {
        parsed[key] = next;
        i += 1;
      }
    } else {
      parsed._.push(value);
    }
  }
  return parsed;
}

function required(options, name) {
  if (!options[name] || typeof options[name] !== "string") {
    throw new Error(`missing --${name}`);
  }
  return options[name];
}

function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function fileArg(name, value) {
  return `--${name} ${quote(value)}`;
}

function writeText(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
}

function sanitizeName(name) {
  if (typeof name !== "string" || !name.trim()) {
    throw new Error("policy name is required");
  }
  const snake = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!snake || !/^[a-z]/.test(snake)) {
    throw new Error(
      "policy name must contain a letter and start with a letter after normalization",
    );
  }
  const kebab = snake.replace(/_/g, "-");
  const pascal = snake
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
  return { snake, kebab, pascal };
}

function parseBool(value, name) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value === "true" || value === "1") return true;
    if (value === "false" || value === "0") return false;
  }
  throw new Error(`${name} must be a boolean`);
}

function parseU32(value, name) {
  const parsed =
    typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > U32_MAX) {
    throw new Error(`${name} must be a u32`);
  }
  return parsed;
}

function parseOptionalU32(value, name) {
  if (value === undefined || value === null || value === "") return undefined;
  return parseU32(value, name);
}

function normalizeCircuitId(value) {
  if (typeof value !== "string") {
    throw new Error("circuit_id must be a 32-byte hex string");
  }
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("circuit_id must be a 32-byte hex string");
  }
  return hex.toLowerCase();
}

function derivePolicyId(spec) {
  const hash = crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        name: spec.name,
        issuer_id: spec.issuer_id,
        kyc_required: spec.kyc_required,
        sanctions_required: spec.sanctions_required,
        allowed_country: spec.allowed_country,
        min_age: spec.min_age,
        min_investor_type: spec.min_investor_type,
        min_credential_members: spec.min_credential_members,
        circuit_id: spec.circuit_id,
        circuit_version: spec.circuit_version,
      }),
    )
    .digest();
  const id = hash.readUInt32BE(0) & 0x7fffffff;
  return id === 0 ? 1 : id;
}

function loadComposeSpec(options) {
  const raw = options.spec
    ? sdk.readJson(path.normalize(required(options, "spec")))
    : options;
  const name = raw.name;
  const policyShape = {
    name,
    issuer_id: parseU32(raw.issuer_id, "issuer_id"),
    kyc_required: parseBool(raw.kyc_required, "kyc_required"),
    sanctions_required: parseBool(raw.sanctions_required, "sanctions_required"),
    allowed_country: parseU32(raw.allowed_country, "allowed_country"),
    min_age: parseU32(raw.min_age, "min_age"),
    min_investor_type: parseU32(raw.min_investor_type, "min_investor_type"),
    min_credential_members: parseU32(
      raw.min_credential_members,
      "min_credential_members",
    ),
    circuit_id: normalizeCircuitId(raw.circuit_id),
    circuit_version: parseU32(raw.circuit_version, "circuit_version"),
  };
  const providedPolicyId = parseOptionalU32(raw.policy_id, "policy_id");
  const policyId =
    providedPolicyId === undefined
      ? derivePolicyId(policyShape)
      : providedPolicyId;
  const actionType = parseOptionalU32(raw.action_type, "action_type");
  return {
    ...policyShape,
    policy_id: policyId,
    action_type: actionType === undefined ? 0 : actionType,
    once_per_account:
      raw.once_per_account === undefined
        ? true
        : parseBool(raw.once_per_account, "once_per_account"),
  };
}

function policyJson(spec) {
  return {
    policy_id: spec.policy_id,
    issuer_id: spec.issuer_id,
    circuit_id: spec.circuit_id,
    circuit_version: spec.circuit_version,
    kyc_required: spec.kyc_required,
    sanctions_required: spec.sanctions_required,
    allowed_country: spec.allowed_country,
    min_age: spec.min_age,
    min_investor_type: spec.min_investor_type,
    min_credential_members: spec.min_credential_members,
  };
}

function generatedCargoToml({ name }) {
  return `[package]
name = "anchorshield-gate-${name.kebab}"
version = "0.0.0"
edition = "2021"
publish = false
rust-version = "1.89.0"

[workspace]
resolver = "2"

[lib]
crate-type = ["cdylib", "rlib"]
doctest = false

[dependencies]
soroban-sdk = { version = "=26.1.0" }

[dev-dependencies]
soroban-sdk = { version = "=26.1.0", features = ["testutils"] }
`;
}

function generatedLibRs({ name, spec }) {
  const errorName = spec.once_per_account ? "AlreadyVerified" : "AlreadyUsed";
  return `#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Env,
};

pub const POLICY_ID: u32 = ${spec.policy_id};
pub const ONCE_PER_ACCOUNT: bool = ${spec.once_per_account};

#[contractclient(name = "IdentityVerifierPeerClient")]
pub trait IdentityVerifierPeer {
    fn verify_identity(env: Env, account: Address);
    fn attestation_expiry(env: Env, account: Address) -> Option<u64>;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    ${errorName} = 3,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    IdentityVerifier,
    Verified(Address),
}

#[contractevent(topics = ["anchorshield", "verified"])]
struct AccountVerified {
    account: Address,
    policy_id: u32,
    attestation_expiry: u64,
}

#[contractevent(topics = ["anchorshield", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contract]
pub struct ${name.pascal}Gate;

#[contractimpl]
impl ${name.pascal}Gate {
    pub fn init(env: Env, admin: Address, identity_verifier: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &admin);
        storage.set(&DataKey::IdentityVerifier, &identity_verifier);
        Ok(())
    }

    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let old_admin = require_admin(&env)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        AdminTransferred {
            old_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn identity_verifier(env: Env) -> Result<Address, Error> {
        config_addr(&env, DataKey::IdentityVerifier)
    }

    pub fn policy_id(_env: Env) -> u32 {
        POLICY_ID
    }

    pub fn verified(env: Env, account: Address) -> bool {
        if !ONCE_PER_ACCOUNT {
            return false;
        }
        env.storage()
            .persistent()
            .get(&DataKey::Verified(account))
            .unwrap_or(false)
    }

    pub fn verify(env: Env, account: Address) -> Result<(), Error> {
        account.require_auth();
        let key = DataKey::Verified(account.clone());
        if ONCE_PER_ACCOUNT && env.storage().persistent().has(&key) {
            return Err(Error::${errorName});
        }

        let identity_verifier = config_addr(&env, DataKey::IdentityVerifier)?;
        let identity = IdentityVerifierPeerClient::new(&env, &identity_verifier);
        identity.verify_identity(&account);
        let attestation_expiry = identity.attestation_expiry(&account).unwrap_or(0);

        if ONCE_PER_ACCOUNT {
            env.storage().persistent().set(&key, &true);
        }
        AccountVerified {
            account: account.clone(),
            policy_id: POLICY_ID,
            attestation_expiry,
        }
        .publish(&env);
        on_verified(&env, &account, attestation_expiry);
        Ok(())
    }
}

fn on_verified(_env: &Env, _account: &Address, _attestation_expiry: u64) {}

fn require_admin(env: &Env) -> Result<Address, Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
}

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
`;
}

function generatedTestRs({ name, spec }) {
  const repeatedCheck = spec.once_per_account
    ? `    assert!(h.gate.verified(&account));
    assert_eq!(h.gate.try_verify(&account), Err(Ok(Error::AlreadyVerified)));`
    : `    assert!(!h.gate.verified(&account));
    assert_eq!(h.gate.try_verify(&account), Ok(Ok(())));`;
  return `#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    testutils::{Address as _, Ledger},
    Address, Env,
};

struct Harness {
    env: Env,
    gate: ${name.pascal}GateClient<'static>,
    identity: MockIdentityVerifierClient<'static>,
}

#[derive(Clone)]
#[contracttype]
enum MockKey {
    Attestation(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
enum MockIdentityError {
    NotEligible = 1,
    Expired = 2,
}

#[contract]
struct MockIdentityVerifier;

#[contractimpl]
impl MockIdentityVerifier {
    pub fn attest(env: Env, account: Address, valid_until: u64) {
        env.storage()
            .persistent()
            .set(&MockKey::Attestation(account), &valid_until);
    }

    pub fn verify_identity(env: Env, account: Address) -> Result<(), MockIdentityError> {
        let valid_until: u64 = env
            .storage()
            .persistent()
            .get(&MockKey::Attestation(account))
            .ok_or(MockIdentityError::NotEligible)?;
        if env.ledger().timestamp() > valid_until {
            return Err(MockIdentityError::Expired);
        }
        Ok(())
    }

    pub fn attestation_expiry(env: Env, account: Address) -> Option<u64> {
        env.storage()
            .persistent()
            .get(&MockKey::Attestation(account))
    }
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let identity_id = env.register(MockIdentityVerifier, ());
    let identity = MockIdentityVerifierClient::new(&env, &identity_id);

    let gate_id = env.register(${name.pascal}Gate, ());
    let gate = ${name.pascal}GateClient::new(&env, &gate_id);
    gate.init(&admin, &identity_id);

    Harness {
        env,
        gate,
        identity,
    }
}

fn attest(h: &Harness, account: &Address, valid_until: u64) {
    h.identity.attest(account, &valid_until);
}

#[test]
fn attested_account_verifies() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    assert_eq!(h.gate.policy_id(), POLICY_ID);
    assert_eq!(h.gate.try_verify(&account), Ok(Ok(())));
${repeatedCheck}
}

#[test]
fn unattested_account_cannot_verify() {
    let h = setup();
    let account = Address::generate(&h.env);

    assert!(h.gate.try_verify(&account).is_err());
    assert!(!h.gate.verified(&account));
}

#[test]
fn expired_attestation_cannot_verify() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    h.env.ledger().set_timestamp(10_001);
    assert!(h.gate.try_verify(&account).is_err());
    assert!(!h.gate.verified(&account));
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
`;
}

function circuitIdBytes(circuitId) {
  return circuitId
    .match(/.{2}/g)
    .map((byte) => `0x${byte}`)
    .join(", ");
}

function generatedPerActionLibRs({ name, spec }) {
  return `#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
    },
    Address, BytesN, Env, Vec, U256,
};

// Action type asserted against the ACTION_TYPE public signal. 0 is the
// payment-shaped action, 1 is the RWA-shaped action; any other value requires
// circuit-side support (the deployed circuit only emits 0 or 1).
pub const GENERATED_ACTION: u32 = ${spec.action_type};
const LOW_ANONYMITY_WARNING_FLOOR: u32 = 32;

// Public-signal index layout, inlined from anchorshield-shared (snarkjs emits
// the 4 circuit outputs first, then the 15 declared public inputs).
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
pub const SANCTIONS_ROOT: u32 = 17;
pub const REVOCATION_ROOT: u32 = 18;
pub const PUBLIC_SIGNAL_COUNT: u32 = 19;

// Shared AnchorShield primitives, inlined from anchorshield-shared because this
// generated crate lives outside the AnchorShield workspace.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SharedError {
    MalformedPublicSignals,
    PublicInputMismatch,
    MalformedVerifyingKey,
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
    pub circuit_id: BytesN<32>,
    pub circuit_version: u32,
    pub kyc_required: bool,
    pub sanctions_required: bool,
    pub allowed_country: u32,
    pub min_age: u32,
    pub min_investor_type: u32,
    pub min_credential_members: u32,
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

// Cross-contract peer interfaces, inlined from anchorshield-shared. Gates call
// peers through these generated clients instead of depending on the peer
// contract crates directly.

#[contractclient(name = "VerifierPeerClient")]
pub trait VerifierPeer {
    fn verify(env: Env, proof: Proof, pub_signals: Vec<Fr>) -> bool;
    fn circuit_id(env: Env) -> Option<BytesN<32>>;
    fn circuit_version(env: Env) -> Option<u32>;
}

#[contractclient(name = "IssuerRegistryPeerClient")]
pub trait IssuerRegistryPeer {
    fn root(env: Env, issuer_id: u32) -> Option<BytesN<32>>;
    fn is_root(env: Env, issuer_id: u32, root: BytesN<32>) -> bool;
    fn member_count(env: Env, issuer_id: u32, root: BytesN<32>) -> Option<u32>;
    fn sanctions_root(env: Env) -> Option<BytesN<32>>;
    fn revocation_root(env: Env, issuer_id: u32) -> Option<BytesN<32>>;
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

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    MissingPolicy = 3,
    MissingRoot = 4,
    MalformedPublicSignals = 5,
    PublicInputMismatch = 6,
    RootMismatch = 7,
    NullifierUsed = 9,
    InvalidProof = 10,
    MalformedVerifyingKey = 11,
    MissingSanctionsRoot = 16,
    MissingRevocationRoot = 17,
    SanctionsRootMismatch = 18,
    RevocationRootMismatch = 19,
    Paused = 20,
    CircuitMismatch = 21,
    AnonymitySetTooSmall = 22,
    NotPauser = 23,
    NoPendingAdmin = 24,
}

impl From<SharedError> for Error {
    fn from(err: SharedError) -> Self {
        match err {
            SharedError::MalformedPublicSignals => Error::MalformedPublicSignals,
            SharedError::PublicInputMismatch => Error::PublicInputMismatch,
            SharedError::MalformedVerifyingKey => Error::MalformedVerifyingKey,
        }
    }
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Verifier,
    IssuerRegistry,
    PolicyRegistry,
    NullifierRegistry,
    Paused,
    Pauser,
    PausedPolicy(u32),
    PausedIssuer(u32),
}

#[contractevent(topics = ["anchorshield", "action_executed"])]
struct ActionExecuted {
    policy_id: u32,
    action_id: u128,
    nullifier: BytesN<32>,
}

#[contractevent(topics = ["anchorshield", "paused"])]
struct Paused {}

#[contractevent(topics = ["anchorshield", "unpaused"])]
struct Unpaused {}

#[contractevent(topics = ["anchorshield", "pauser_set"])]
struct PauserSet {
    pauser: Address,
}

#[contractevent(topics = ["anchorshield", "policy_paused"])]
struct PolicyPaused {
    policy_id: u32,
}

#[contractevent(topics = ["anchorshield", "policy_unpaused"])]
struct PolicyUnpaused {
    policy_id: u32,
}

#[contractevent(topics = ["anchorshield", "issuer_paused"])]
struct IssuerPaused {
    issuer_id: u32,
}

#[contractevent(topics = ["anchorshield", "issuer_unpaused"])]
struct IssuerUnpaused {
    issuer_id: u32,
}

#[contractevent(topics = ["anchorshield", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["anchorshield", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
}

#[contractevent(topics = ["anchorshield", "low_anonymity_set"])]
struct LowAnonymitySet {
    policy_id: u32,
    issuer_id: u32,
    credential_root: BytesN<32>,
    member_count: u32,
    min_credential_members: u32,
}

#[contract]
pub struct ${name.pascal}Gate;

#[contractimpl]
impl ${name.pascal}Gate {
    pub fn init(
        env: Env,
        admin: Address,
        verifier: Address,
        policy_registry: Address,
        issuer_registry: Address,
        nullifier_registry: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &admin);
        storage.set(&DataKey::Verifier, &verifier);
        storage.set(&DataKey::PolicyRegistry, &policy_registry);
        storage.set(&DataKey::IssuerRegistry, &issuer_registry);
        storage.set(&DataKey::NullifierRegistry, &nullifier_registry);
        Ok(())
    }

    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let old_admin = require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        AdminTransferStarted {
            old_admin,
            pending_admin: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    pub fn accept_admin(env: Env) -> Result<(), Error> {
        let old_admin = Self::admin(env.clone()).ok_or(Error::NotInitialized)?;
        let new_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        new_admin.require_auth();
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &new_admin);
        storage.remove(&DataKey::PendingAdmin);
        AdminTransferred {
            old_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn set_pauser(env: Env, pauser: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Pauser, &pauser);
        PauserSet { pauser }.publish(&env);
        Ok(())
    }

    pub fn pauser(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Pauser)
    }

    pub fn pause(env: Env) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {}.publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {}.publish(&env);
        Ok(())
    }

    pub fn paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn pause_policy(env: Env, policy_id: u32) -> Result<(), Error> {
        require_pauser(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PausedPolicy(policy_id), &true);
        PolicyPaused { policy_id }.publish(&env);
        Ok(())
    }

    pub fn unpause_policy(env: Env, policy_id: u32) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .remove(&DataKey::PausedPolicy(policy_id));
        PolicyUnpaused { policy_id }.publish(&env);
        Ok(())
    }

    pub fn pause_issuer(env: Env, issuer_id: u32) -> Result<(), Error> {
        require_pauser(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PausedIssuer(issuer_id), &true);
        IssuerPaused { issuer_id }.publish(&env);
        Ok(())
    }

    pub fn unpause_issuer(env: Env, issuer_id: u32) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .remove(&DataKey::PausedIssuer(issuer_id));
        IssuerUnpaused { issuer_id }.publish(&env);
        Ok(())
    }

    pub fn policy_paused(env: Env, policy_id: u32) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::PausedPolicy(policy_id))
            .unwrap_or(false)
    }

    pub fn issuer_paused(env: Env, issuer_id: u32) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::PausedIssuer(issuer_id))
            .unwrap_or(false)
    }

    pub fn verify_and_execute(
        env: Env,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        action_id: u128,
        epoch: u32,
    ) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        ensure_policy_not_paused(&env, policy_id)?;
        if pub_signals.len() != PUBLIC_SIGNAL_COUNT {
            return Err(Error::MalformedPublicSignals);
        }

        let policy: Policy =
            PolicyRegistryPeerClient::new(&env, &config_addr(&env, DataKey::PolicyRegistry)?)
                .policy(&policy_id)
                .ok_or(Error::MissingPolicy)?;
        ensure_issuer_not_paused(&env, policy.issuer_id)?;

        require_signal_u32(&env, &pub_signals, ISSUER_ID, policy.issuer_id)?;
        require_signal_u32(&env, &pub_signals, POLICY_ID, policy_id)?;
        require_signal_u32(
            &env,
            &pub_signals,
            KYC_REQUIRED,
            bool_as_u32(policy.kyc_required),
        )?;
        require_signal_u32(
            &env,
            &pub_signals,
            SANCTIONS_REQUIRED,
            bool_as_u32(policy.sanctions_required),
        )?;
        require_signal_u32(&env, &pub_signals, ALLOWED_COUNTRY, policy.allowed_country)?;
        require_signal_u32(&env, &pub_signals, MIN_AGE, policy.min_age)?;
        require_signal_u32(
            &env,
            &pub_signals,
            MIN_INVESTOR_TYPE,
            policy.min_investor_type,
        )?;
        require_signal_u32(&env, &pub_signals, ACTION_TYPE, GENERATED_ACTION)?;
        require_signal_u128(&env, &pub_signals, ACTION_ID, action_id)?;
        require_signal_u32(&env, &pub_signals, EPOCH, epoch)?;

        let issuer =
            IssuerRegistryPeerClient::new(&env, &config_addr(&env, DataKey::IssuerRegistry)?);
        if issuer.root(&policy.issuer_id).is_none() {
            return Err(Error::MissingRoot);
        }
        let credential_root = signal(&pub_signals, CREDENTIAL_ROOT)?.to_bytes();
        if !issuer.is_root(&policy.issuer_id, &credential_root) {
            return Err(Error::RootMismatch);
        }
        let member_count = issuer
            .member_count(&policy.issuer_id, &credential_root)
            .unwrap_or(0);
        if member_count < policy.min_credential_members {
            return Err(Error::AnonymitySetTooSmall);
        }
        if member_count < LOW_ANONYMITY_WARNING_FLOOR {
            LowAnonymitySet {
                policy_id,
                issuer_id: policy.issuer_id,
                credential_root: credential_root.clone(),
                member_count,
                min_credential_members: policy.min_credential_members,
            }
            .publish(&env);
        }
        let sanctions_root = issuer.sanctions_root().ok_or(Error::MissingSanctionsRoot)?;
        if signal(&pub_signals, SANCTIONS_ROOT)?.to_bytes() != sanctions_root {
            return Err(Error::SanctionsRootMismatch);
        }
        let revocation_root = issuer
            .revocation_root(&policy.issuer_id)
            .ok_or(Error::MissingRevocationRoot)?;
        if signal(&pub_signals, REVOCATION_ROOT)?.to_bytes() != revocation_root {
            return Err(Error::RevocationRootMismatch);
        }

        let nullifier = signal(&pub_signals, NULLIFIER)?.to_bytes();
        let nullifiers =
            NullifierRegistryPeerClient::new(&env, &config_addr(&env, DataKey::NullifierRegistry)?);
        if nullifiers.is_used(&nullifier) {
            return Err(Error::NullifierUsed);
        }

        let verifier = VerifierPeerClient::new(&env, &config_addr(&env, DataKey::Verifier)?);
        if verifier.circuit_id().as_ref() != Some(&policy.circuit_id)
            || verifier.circuit_version() != Some(policy.circuit_version)
        {
            return Err(Error::CircuitMismatch);
        }
        if !verifier.verify(&proof, &pub_signals) {
            return Err(Error::InvalidProof);
        }

        // YOUR ACTION HERE (see on_action below): every compliance check has
        // passed and the proof is verified.
        on_action(&env, policy_id, action_id);

        nullifiers.mark_used(&env.current_contract_address(), &nullifier);

        ActionExecuted {
            policy_id,
            action_id,
            nullifier,
        }
        .publish(&env);

        Ok(())
    }
}

// YOUR ACTION HERE: called after every policy/root/circuit/proof check has
// passed and the nullifier is confirmed unused, and before the nullifier is
// consumed — a panic here aborts the whole transaction. Perform the protected
// action (token transfer, mint, storage write, cross-contract call, ...).
fn on_action(_env: &Env, _policy_id: u32, _action_id: u128) {}

fn require_admin(env: &Env) -> Result<Address, Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
}

fn require_pauser(env: &Env) -> Result<Address, Error> {
    let pauser: Address = env
        .storage()
        .instance()
        .get(&DataKey::Pauser)
        .ok_or(Error::NotPauser)?;
    pauser.require_auth();
    Ok(pauser)
}

fn ensure_not_paused(env: &Env) -> Result<(), Error> {
    if env
        .storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
    {
        return Err(Error::Paused);
    }
    Ok(())
}

fn ensure_policy_not_paused(env: &Env, policy_id: u32) -> Result<(), Error> {
    if env
        .storage()
        .instance()
        .get(&DataKey::PausedPolicy(policy_id))
        .unwrap_or(false)
    {
        return Err(Error::Paused);
    }
    Ok(())
}

fn ensure_issuer_not_paused(env: &Env, issuer_id: u32) -> Result<(), Error> {
    if env
        .storage()
        .instance()
        .get(&DataKey::PausedIssuer(issuer_id))
        .unwrap_or(false)
    {
        return Err(Error::Paused);
    }
    Ok(())
}

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
`;
}

function generatedPerActionTestRs({ name, spec }) {
  const memberCount = Math.max(1000, spec.min_credential_members);
  return `#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bls12_381::{G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    testutils::Address as _,
    Address, Env,
};

const POLICY: u32 = ${spec.policy_id};
const TEST_ACTION_ID: u128 = 424242;
const TEST_EPOCH: u32 = 7;

// Mock peers implementing the inlined peer traits. The mock verifier rejects
// every proof, so these tests exercise the full binding chain honestly without
// faking a passing proof.

#[derive(Clone)]
#[contracttype]
enum MockIssuerKey {
    Root(u32),
    Members(u32),
    Sanctions,
    Revocation(u32),
}

#[contract]
struct MockPolicyRegistry;

#[contractimpl]
impl MockPolicyRegistry {
    pub fn set_policy(env: Env, policy: Policy) {
        env.storage().instance().set(&policy.policy_id, &policy);
    }

    pub fn policy(env: Env, policy_id: u32) -> Option<Policy> {
        env.storage().instance().get(&policy_id)
    }
}

#[contract]
struct MockIssuerRegistry;

#[contractimpl]
impl MockIssuerRegistry {
    pub fn set_root(env: Env, issuer_id: u32, root: BytesN<32>, member_count: u32) {
        env.storage()
            .instance()
            .set(&MockIssuerKey::Root(issuer_id), &root);
        env.storage()
            .instance()
            .set(&MockIssuerKey::Members(issuer_id), &member_count);
    }

    pub fn set_sanctions_root(env: Env, root: BytesN<32>) {
        env.storage().instance().set(&MockIssuerKey::Sanctions, &root);
    }

    pub fn set_revocation_root(env: Env, issuer_id: u32, root: BytesN<32>) {
        env.storage()
            .instance()
            .set(&MockIssuerKey::Revocation(issuer_id), &root);
    }

    pub fn root(env: Env, issuer_id: u32) -> Option<BytesN<32>> {
        env.storage().instance().get(&MockIssuerKey::Root(issuer_id))
    }

    pub fn is_root(env: Env, issuer_id: u32, root: BytesN<32>) -> bool {
        Self::root(env, issuer_id) == Some(root)
    }

    pub fn member_count(env: Env, issuer_id: u32, root: BytesN<32>) -> Option<u32> {
        if !Self::is_root(env.clone(), issuer_id, root) {
            return None;
        }
        env.storage()
            .instance()
            .get(&MockIssuerKey::Members(issuer_id))
    }

    pub fn sanctions_root(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&MockIssuerKey::Sanctions)
    }

    pub fn revocation_root(env: Env, issuer_id: u32) -> Option<BytesN<32>> {
        env.storage()
            .instance()
            .get(&MockIssuerKey::Revocation(issuer_id))
    }
}

#[contract]
struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn set_circuit(env: Env, circuit_id: BytesN<32>, circuit_version: u32) {
        env.storage().instance().set(&0u32, &circuit_id);
        env.storage().instance().set(&1u32, &circuit_version);
    }

    pub fn circuit_id(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&0u32)
    }

    pub fn circuit_version(env: Env) -> Option<u32> {
        env.storage().instance().get(&1u32)
    }

    // Always rejects: no real proof can pass here, so a run that reaches
    // InvalidProof has passed every other check.
    pub fn verify(_env: Env, _proof: Proof, _pub_signals: Vec<Fr>) -> bool {
        false
    }
}

#[contract]
struct MockNullifierRegistry;

#[contractimpl]
impl MockNullifierRegistry {
    pub fn seed_used(env: Env, nullifier: BytesN<32>) {
        env.storage().persistent().set(&nullifier, &true);
    }

    pub fn is_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().get(&nullifier).unwrap_or(false)
    }

    pub fn mark_used(env: Env, _gate: Address, nullifier: BytesN<32>) {
        env.storage().persistent().set(&nullifier, &true);
    }
}

struct Harness {
    env: Env,
    gate: ${name.pascal}GateClient<'static>,
    nullifiers: MockNullifierRegistryClient<'static>,
    signals: Vec<Fr>,
    proof: Proof,
}

fn circuit_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[${circuitIdBytes(spec.circuit_id)}])
}

fn fr_u32(env: &Env, value: u32) -> Fr {
    Fr::from_u256(U256::from_u32(env, value))
}

fn fr_u128(env: &Env, value: u128) -> Fr {
    Fr::from_u256(U256::from_u128(env, value))
}

fn dummy_proof(env: &Env) -> Proof {
    Proof {
        a: G1Affine::from_array(env, &[0u8; G1_SERIALIZED_SIZE]),
        b: G2Affine::from_array(env, &[0u8; G2_SERIALIZED_SIZE]),
        c: G1Affine::from_array(env, &[0u8; G1_SERIALIZED_SIZE]),
    }
}

fn test_policy(env: &Env) -> Policy {
    Policy {
        policy_id: POLICY,
        issuer_id: ${spec.issuer_id},
        circuit_id: circuit_id(env),
        circuit_version: ${spec.circuit_version},
        kyc_required: ${spec.kyc_required},
        sanctions_required: ${spec.sanctions_required},
        allowed_country: ${spec.allowed_country},
        min_age: ${spec.min_age},
        min_investor_type: ${spec.min_investor_type},
        min_credential_members: ${spec.min_credential_members},
    }
}

fn build_signals(env: &Env, action_type: u32) -> Vec<Fr> {
    let mut signals = Vec::new(env);
    for _ in 0..PUBLIC_SIGNAL_COUNT {
        signals.push_back(fr_u32(env, 0));
    }
    signals.set(CREDENTIAL_ROOT, fr_u32(env, 1111));
    signals.set(BOUND_HASH, fr_u32(env, 2222));
    signals.set(NULLIFIER, fr_u32(env, 3333));
    signals.set(ACTION_BINDING, fr_u32(env, 4444));
    signals.set(ISSUER_ID, fr_u32(env, ${spec.issuer_id}));
    signals.set(POLICY_ID, fr_u32(env, POLICY));
    signals.set(KYC_REQUIRED, fr_u32(env, bool_as_u32(${spec.kyc_required})));
    signals.set(
        SANCTIONS_REQUIRED,
        fr_u32(env, bool_as_u32(${spec.sanctions_required})),
    );
    signals.set(ALLOWED_COUNTRY, fr_u32(env, ${spec.allowed_country}));
    signals.set(MIN_AGE, fr_u32(env, ${spec.min_age}));
    signals.set(MIN_INVESTOR_TYPE, fr_u32(env, ${spec.min_investor_type}));
    signals.set(ACTION_TYPE, fr_u32(env, action_type));
    signals.set(ASSET_ID, fr_u32(env, 9001));
    signals.set(AMOUNT, fr_u128(env, 250));
    signals.set(RECIPIENT, fr_u128(env, 8000001));
    signals.set(ACTION_ID, fr_u128(env, TEST_ACTION_ID));
    signals.set(EPOCH, fr_u32(env, TEST_EPOCH));
    signals.set(SANCTIONS_ROOT, fr_u32(env, 5555));
    signals.set(REVOCATION_ROOT, fr_u32(env, 6666));
    signals
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let signals = build_signals(&env, GENERATED_ACTION);

    let verifier_id = env.register(MockVerifier, ());
    MockVerifierClient::new(&env, &verifier_id).set_circuit(&circuit_id(&env), &${spec.circuit_version});

    let policy_reg_id = env.register(MockPolicyRegistry, ());
    MockPolicyRegistryClient::new(&env, &policy_reg_id).set_policy(&test_policy(&env));

    let issuer_reg_id = env.register(MockIssuerRegistry, ());
    let issuer = MockIssuerRegistryClient::new(&env, &issuer_reg_id);
    issuer.set_root(
        &${spec.issuer_id},
        &signals.get(CREDENTIAL_ROOT).unwrap().to_bytes(),
        &${memberCount},
    );
    issuer.set_sanctions_root(&signals.get(SANCTIONS_ROOT).unwrap().to_bytes());
    issuer.set_revocation_root(
        &${spec.issuer_id},
        &signals.get(REVOCATION_ROOT).unwrap().to_bytes(),
    );

    let nullifier_id = env.register(MockNullifierRegistry, ());
    let nullifiers = MockNullifierRegistryClient::new(&env, &nullifier_id);

    let gate_id = env.register(${name.pascal}Gate, ());
    let gate = ${name.pascal}GateClient::new(&env, &gate_id);
    gate.init(
        &admin,
        &verifier_id,
        &policy_reg_id,
        &issuer_reg_id,
        &nullifier_id,
    );

    let proof = dummy_proof(&env);
    Harness {
        env,
        gate,
        nullifiers,
        signals,
        proof,
    }
}

fn execute_err(h: &Harness, signals: &Vec<Fr>) -> Error {
    match h
        .gate
        .try_verify_and_execute(&h.proof, signals, &POLICY, &TEST_ACTION_ID, &TEST_EPOCH)
    {
        Err(Ok(err)) => err,
        other => panic!("expected contract error, got {:?}", other),
    }
}

#[test]
fn init_rejects_double_init() {
    let h = setup();
    let again = Address::generate(&h.env);
    assert_eq!(
        h.gate.try_init(&again, &again, &again, &again, &again),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn admin_transfer_is_two_step() {
    let h = setup();
    let original = h.gate.admin().unwrap();
    let next = Address::generate(&h.env);

    assert_eq!(h.gate.try_transfer_admin(&next), Ok(Ok(())));
    assert_eq!(h.gate.admin(), Some(original));
    assert_eq!(h.gate.pending_admin(), Some(next.clone()));
    assert_eq!(h.gate.try_accept_admin(), Ok(Ok(())));
    assert_eq!(h.gate.admin(), Some(next));
    assert_eq!(h.gate.pending_admin(), None);
}

#[test]
fn rejects_short_pub_signals() {
    let h = setup();
    let short = Vec::from_array(&h.env, [fr_u32(&h.env, 0)]);
    assert_eq!(execute_err(&h, &short), Error::MalformedPublicSignals);
}

#[test]
fn paused_gate_rejects() {
    let h = setup();
    h.gate.pause();
    assert_eq!(execute_err(&h, &h.signals), Error::Paused);
    h.gate.unpause();
    // Past the pause check again; the run ends at the mock verifier.
    assert_eq!(execute_err(&h, &h.signals), Error::InvalidProof);
}

#[test]
fn paused_policy_rejects() {
    let h = setup();
    h.gate.set_pauser(&Address::generate(&h.env));
    h.gate.pause_policy(&POLICY);
    assert_eq!(execute_err(&h, &h.signals), Error::Paused);
    h.gate.unpause_policy(&POLICY);
    assert_eq!(execute_err(&h, &h.signals), Error::InvalidProof);
}

#[test]
fn paused_issuer_rejects() {
    let h = setup();
    h.gate.set_pauser(&Address::generate(&h.env));
    h.gate.pause_issuer(&${spec.issuer_id});
    assert_eq!(execute_err(&h, &h.signals), Error::Paused);
    h.gate.unpause_issuer(&${spec.issuer_id});
    assert_eq!(execute_err(&h, &h.signals), Error::InvalidProof);
}

#[test]
fn wrong_action_type_rejected() {
    let h = setup();
    let signals = build_signals(&h.env, GENERATED_ACTION + 1);
    assert_eq!(execute_err(&h, &signals), Error::PublicInputMismatch);
}

#[test]
fn used_nullifier_rejected() {
    let h = setup();
    h.nullifiers
        .seed_used(&h.signals.get(NULLIFIER).unwrap().to_bytes());
    assert_eq!(execute_err(&h, &h.signals), Error::NullifierUsed);
}

#[test]
fn full_binding_chain_rejects_unverified_proof() {
    let h = setup();
    // Every policy/root/nullifier/circuit binding passes; the mock verifier
    // rejects the proof, so the run must end at InvalidProof with nothing
    // consumed.
    assert_eq!(execute_err(&h, &h.signals), Error::InvalidProof);
    assert!(!h
        .nullifiers
        .is_used(&h.signals.get(NULLIFIER).unwrap().to_bytes()));
}
`;
}

function generatedGateJsx({ name, spec, deployments, model }) {
  const perActionContractId =
    model === "per-action"
      ? "ANCHORSHIELD_CONTRACTS.generatedGate"
      : `"${deployments.contracts.gate_payment}"`;
  return `import React from "react";
import { AnchorShieldGate, useAnchorShield } from "@anchorshield/sdk/react";

export const ANCHORSHIELD_POLICY_ID = ${spec.policy_id};
export const ANCHORSHIELD_CONTRACTS = {
  identityVerifier: "${deployments.contracts.identity_verifier}",
  policyRegistry: "${deployments.contracts.policy_registry}",
  generatedGate: "<DEPLOYED_${name.snake.toUpperCase()}_GATE_CONTRACT_ID>",
};

export function ${name.pascal}Gate({ children, onUse }) {
  const shield = useAnchorShield({
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  });

  async function handleUse() {
    const account = shield.address || (await shield.connect());
    const request = {
      account,
      policyId: ANCHORSHIELD_POLICY_ID,
      gateContractId: ANCHORSHIELD_CONTRACTS.generatedGate,
      identityVerifier: ANCHORSHIELD_CONTRACTS.identityVerifier,
    };
    return onUse ? onUse(request) : request;
  }

  return (
    <button
      type="button"
      disabled={shield.status === "connecting"}
      onClick={handleUse}
    >
      {children || "Use AnchorShield-gated action"}
    </button>
  );
}

export function ${name.pascal}PerActionProofButton({
  action,
  proof,
  publicSignals,
  specEntries,
  onSuccess,
  rpcUrl = "https://soroban-testnet.stellar.org",
  networkPassphrase = "Test SDF Network ; September 2015",
  contractId = ${perActionContractId},
}) {
  return (
    <AnchorShieldGate
      rpcUrl={rpcUrl}
      networkPassphrase={networkPassphrase}
      contractId={contractId}
      action={{ ...action, policy_id: ANCHORSHIELD_POLICY_ID }}
      proof={proof}
      publicSignals={publicSignals}
      specEntries={specEntries}
      onSuccess={onSuccess}
      pendingLabel="Submitting AnchorShield proof"
    >
      Submit AnchorShield proof
    </AnchorShieldGate>
  );
}
`;
}

function generatedReadme({ name, spec, deployments, registerCommand }) {
  return `# ${name.pascal} AnchorShield Gate

Generated by \`anchorshield compose\` for policy \`${spec.policy_id}\`.

## Policy

Register \`policy.json\` with the live testnet policy registry:

\`\`\`bash
${registerCommand}
\`\`\`

The policy is enforced when the user calls \`identity_verifier.attest(..., policy_id=${spec.policy_id}, ...)\`.
This Model-A gate checks that the account has a live AnchorShield attestation
with \`verify_identity(account)\`; the downstream gate does not re-verify the
policy id.

## Build And Test

\`\`\`bash
cargo build --target wasm32v1-none --release
cargo test
\`\`\`

## Deploy To Testnet

\`\`\`bash
stellar contract deploy \\
  --wasm target/wasm32v1-none/release/anchorshield_gate_${name.snake}.wasm \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet
\`\`\`

Initialize with the deployed AnchorShield identity verifier:

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  init \\
  --admin <ADMIN_PUBLIC_KEY> \\
  --identity_verifier ${deployments.contracts.identity_verifier}
\`\`\`

## Attest Then Use

1. Build or collect a proof whose public signals match \`policy_id=${spec.policy_id}\`.
2. Call \`identity_verifier.attest\` on testnet using the identity verifier:
   \`${deployments.contracts.identity_verifier}\`.
3. Call the generated gate:

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <USER_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  verify \\
  --account <USER_PUBLIC_KEY>
\`\`\`

If \`once_per_account\` is enabled, a second call by the same account is rejected
by this gate's own persistent state.
`;
}

function generatedPerActionReadme({
  name,
  spec,
  deployments,
  registerCommand,
}) {
  return `# ${name.pascal} AnchorShield Gate (Per-Action Proof)

Generated by \`anchorshield compose --model per-action\` for policy \`${spec.policy_id}\`.

Model B: every call to \`verify_and_execute\` submits a fresh Groth16 proof that
is checked against the on-chain policy, issuer roots, verifier circuit, and
nullifier registry — there is no attestation step. Add your protected action in
the \`on_action\` hook in \`src/lib.rs\` (marked \`YOUR ACTION HERE\`).

## Policy

Register \`policy.json\` with the live testnet policy registry:

\`\`\`bash
${registerCommand}
\`\`\`

## Build And Test

\`\`\`bash
cargo build --target wasm32v1-none --release
cargo test
\`\`\`

## Deploy To Testnet

Upload the wasm, then deploy from the returned hash:

\`\`\`bash
stellar contract upload \\
  --wasm target/wasm32v1-none/release/anchorshield_gate_${name.snake}.wasm \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet

stellar contract deploy \\
  --wasm-hash <WASM_HASH_FROM_UPLOAD> \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet
\`\`\`

Initialize with the deployed AnchorShield stack (addresses from
\`apps/web/data/deployments.json\`):

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  init \\
  --admin <ADMIN_PUBLIC_KEY> \\
  --verifier ${deployments.contracts.verifier} \\
  --policy_registry ${deployments.contracts.policy_registry} \\
  --issuer_registry ${deployments.contracts.issuer_registry} \\
  --nullifier_registry ${deployments.contracts.nullifier_registry}
\`\`\`

The nullifier registry only accepts \`mark_used\` from allow-listed gates, so the
registry admin must allow this gate before the first call:

\`\`\`bash
stellar contract invoke \\
  --id ${deployments.contracts.nullifier_registry} \\
  --source-account <REGISTRY_ADMIN_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  allow_gate \\
  --gate <${name.snake.toUpperCase()}_GATE_CONTRACT_ID>
\`\`\`

## Submit A Proof

Build a proof whose public signals match \`policy_id=${spec.policy_id}\`,
\`action_type=${spec.action_type}\`, and your \`action_id\`/\`epoch\`, then:

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <USER_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  verify_and_execute \\
  --proof-file-path proof.json \\
  --pub_signals-file-path pub_signals.json \\
  --policy_id ${spec.policy_id} \\
  --action_id <ACTION_ID> \\
  --epoch <EPOCH>
\`\`\`

The nullifier is consumed on success, so each proof authorizes exactly one
action.

## Action Type Caveat

This gate asserts \`ACTION_TYPE == ${spec.action_type}\` (\`GENERATED_ACTION\`).
The deployed circuit only emits action types 0 (payment-shaped) and 1
(RWA-shaped); a distinct action type requires circuit-side support before
proofs can satisfy this gate.
`;
}

function composePolicy(options) {
  const model = options.model === undefined ? "attestation" : options.model;
  if (model !== "attestation" && model !== "per-action") {
    throw new Error("--model must be attestation or per-action");
  }
  const spec = loadComposeSpec(options);
  const name = sanitizeName(spec.name);
  const deployments = sdk.readJson(
    path.join(repoRoot, "apps", "web", "data", "deployments.json"),
  );
  const outDir = path.resolve(
    options.out
      ? path.normalize(options.out)
      : path.join(".m6", "compose", name.snake),
  );
  const gateDir = path.join(outDir, `gate_${name.snake}`);
  const srcDir = path.join(gateDir, "src");
  const policyFile = path.join(outDir, "policy.json");
  const registerCommand = [
    "stellar contract invoke",
    "--network testnet",
    "--source-account <ADMIN_SECRET_OR_PROFILE>",
    `--id ${deployments.contracts.policy_registry}`,
    "-- set_policy",
    fileArg("policy-file-path", "policy.json"),
  ].join(" ");

  fs.mkdirSync(srcDir, { recursive: true });
  sdk.writeJson(policyFile, policyJson(spec));
  writeText(path.join(outDir, "register-policy.txt"), `${registerCommand}\n`);
  writeText(path.join(gateDir, "Cargo.toml"), generatedCargoToml({ name }));
  writeText(
    path.join(srcDir, "lib.rs"),
    model === "per-action"
      ? generatedPerActionLibRs({ name, spec })
      : generatedLibRs({ name, spec }),
  );
  writeText(
    path.join(srcDir, "test.rs"),
    model === "per-action"
      ? generatedPerActionTestRs({ name, spec })
      : generatedTestRs({ name, spec, srcDir }),
  );
  writeText(
    path.join(outDir, "Gate.jsx"),
    generatedGateJsx({ name, spec, deployments, model }),
  );
  writeText(
    path.join(outDir, "README.md"),
    model === "per-action"
      ? generatedPerActionReadme({ name, spec, deployments, registerCommand })
      : generatedReadme({ name, spec, deployments, registerCommand }),
  );

  return {
    model,
    outDir,
    policyFile,
    gateDir,
    policy: policyJson(spec),
    registerPolicyCommand: registerCommand,
    oncePerAccount: spec.once_per_account,
    files: [
      policyFile,
      path.join(outDir, "register-policy.txt"),
      path.join(gateDir, "Cargo.toml"),
      path.join(srcDir, "lib.rs"),
      path.join(srcDir, "test.rs"),
      path.join(outDir, "Gate.jsx"),
      path.join(outDir, "README.md"),
    ],
  };
}

function buildStellarCommand(
  flow,
  contract,
  cliArgsFile,
  inputFile,
  network,
  sourceAccount,
  outDir,
) {
  const cliArgs = sdk.readJson(cliArgsFile);
  const input = sdk.readJson(inputFile);
  const parsed =
    flow === "payment"
      ? sdk.assertPaymentAction(input, cliArgs.pub_signals)
      : sdk.assertRwaAction(input, cliArgs.pub_signals);
  const hashName = flow === "payment" ? "packet_hash" : "terms_hash";
  const fnName = flow === "payment" ? "verify_and_pay" : "verify_and_transfer";
  const hashValue = parsed.packet_hash;
  const vkPath = path.join(outDir, "vk.json");
  const proofPath = path.join(outDir, "proof.json");
  const publicPath = path.join(outDir, "pub_signals.json");

  sdk.writeJson(vkPath, cliArgs.vk);
  sdk.writeJson(proofPath, cliArgs.proof);
  sdk.writeJson(
    publicPath,
    sdk.formatImplicitCliPubSignals(cliArgs.pub_signals),
  );

  return [
    "stellar contract invoke",
    `--network ${network}`,
    `--source-account ${sourceAccount}`,
    "--send no",
    `--id ${contract}`,
    `-- ${fnName}`,
    fileArg("vk-file-path", vkPath),
    fileArg("proof-file-path", proofPath),
    fileArg("pub_signals-file-path", publicPath),
    `--policy_id ${parsed.policy_id}`,
    `--asset_id ${parsed.asset_id}`,
    `--amount ${parsed.amount}`,
    `--recipient ${parsed.recipient}`,
    `--action_id ${parsed.action_id}`,
    `--${hashName} ${hashValue}`,
    `--epoch ${parsed.epoch}`,
  ].join(" ");
}

async function main() {
  const options = args(process.argv.slice(2));
  const [command, subcommand] = options._;

  if (!command || command === "help" || command === "--help") {
    usage();
    return;
  }

  if (command === "compose") {
    printJson(composePolicy(options));
    return;
  }

  if (command === "inspect-public") {
    printJson(
      sdk.parsePublicSignals(sdk.readJson(required(options, "public"))),
    );
    return;
  }

  if (command === "validate-action") {
    const input = sdk.readJson(required(options, "input"));
    const publicSignals = sdk.readJson(required(options, "public"));
    const flow =
      options.flow ||
      (input.action_type === sdk.RWA_ACTION_TYPE ? "rwa" : "payment");
    const parsed =
      flow === "rwa"
        ? sdk.assertRwaAction(input, publicSignals)
        : sdk.assertPaymentAction(input, publicSignals);
    printJson({
      flow,
      valid: true,
      action_id: parsed.action_id,
      policy_id: parsed.policy_id,
    });
    return;
  }

  if (command === "soroban-args") {
    const cliArgs = sdk.readJson(required(options, "cli-args"));
    printJson({
      vk: cliArgs.vk,
      proof: cliArgs.proof,
      pub_signals: sdk.formatSorobanPubSignals(cliArgs.pub_signals),
    });
    return;
  }

  if (command === "events") {
    const data = sdk.readJson(required(options, "file"));
    printJson({
      network: data.network,
      indexedAt: data.indexedAt,
      count: data.events.length,
      events: data.events.map((event) => ({
        flow: event.flow,
        outcome: event.outcome,
        policyId: event.policyId,
        actionId: event.actionId,
        txHash: event.txHash,
        piiOnChain: event.piiOnChain,
      })),
    });
    return;
  }

  if (command === "disclosure" && subcommand === "verify") {
    const summary = sdk.readJson(required(options, "summary"));
    if (!summary.verified) {
      throw new Error("disclosure summary is not verified");
    }
    printJson({
      verified: true,
      packetHash: summary.packetHash,
      paymentTx: summary.paymentTx,
      actionId: summary.actionId,
    });
    return;
  }

  if (
    command === "gate" &&
    (subcommand === "payment" || subcommand === "rwa")
  ) {
    const contract = required(options, "contract");
    const cliArgsFile = path.normalize(required(options, "cli-args"));
    const inputFile = path.normalize(required(options, "input"));
    const network = options.network || "testnet";
    const sourceAccount = options["source-account"] || "<SOURCE_ACCOUNT>";
    const outDir = path.normalize(
      options["out-dir"] || path.join(".m6", "invoke", subcommand),
    );
    console.log(
      buildStellarCommand(
        subcommand,
        contract,
        cliArgsFile,
        inputFile,
        network,
        sourceAccount,
        outDir,
      ),
    );
    return;
  }

  throw new Error(`unknown command ${options._.join(" ")}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
