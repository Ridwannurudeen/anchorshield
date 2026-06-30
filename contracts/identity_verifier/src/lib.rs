#![no_std]
// Contract entrypoints bind the full action, which exceeds clippy's arg limit.
#![allow(clippy::too_many_arguments)]

//! AnchorShield ZK IdentityVerifier for the OpenZeppelin SEP-57 (ERC-3643/T-REX)
//! RWA stack. A holder calls `attest` with a zero-knowledge eligibility proof; the
//! proof is verified (policy + issuer root + nullifier + Groth16) and a per-account
//! attestation is recorded. The RWA token then calls `verify_identity(account)`
//! before every mint/transfer, which succeeds only while a valid attestation
//! exists. The account is bound to the proof via `require_auth` (the caller must
//! control the attested address), which avoids binding the address inside the
//! circuit.

use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, IssuerRegistryPeerClient,
    NullifierRegistryPeerClient, Policy, PolicyRegistryPeerClient, Proof, SharedError,
    VerifierPeerClient, ACTION_BINDING, ACTION_ID, ACTION_TYPE, ALLOWED_COUNTRY, AMOUNT, ASSET_ID,
    BOUND_HASH, CREDENTIAL_ROOT, EPOCH, ISSUER_ID, KYC_REQUIRED, MIN_AGE, MIN_INVESTOR_TYPE,
    NULLIFIER, POLICY_ID, PUBLIC_SIGNAL_COUNT, RECIPIENT, REVOCATION_ROOT, SANCTIONS_REQUIRED,
    SANCTIONS_ROOT,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, BytesN, Env, Vec,
};

const RWA_ACTION: u32 = 1;
const MAX_ATTESTATION_TTL: u64 = 2_592_000;

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
    NullifierUsed = 8,
    InvalidProof = 9,
    MalformedVerifyingKey = 10,
    NotEligible = 11,
    Expired = 12,
    MissingSanctionsRoot = 13,
    MissingRevocationRoot = 14,
    SanctionsRootMismatch = 15,
    RevocationRootMismatch = 16,
    Paused = 17,
    CircuitMismatch = 18,
    AlreadySet = 19,
    BadAmount = 20,
    MissingToken = 21,
    MissingRecipient = 22,
    RecipientMismatch = 23,
    MintConsumerNotAllowed = 24,
    MissingMintAuthorization = 25,
    AmountMismatch = 26,
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
    Verifier,
    IssuerRegistry,
    PolicyRegistry,
    NullifierRegistry,
    Attestation(Address),
    Paused,
    RwaToken(u32),
    RwaRecipient(u128),
    MintConsumer(Address),
    MintAuthorization(Address, Address, Address),
}

#[derive(Clone)]
#[contracttype]
pub struct MintAuthorization {
    pub amount: i128,
    pub valid_until: u64,
    pub nullifier: BytesN<32>,
    pub terms_hash: BytesN<32>,
    pub action_binding: BytesN<32>,
    pub action_id: u128,
}

#[contractevent(topics = ["identity", "attested"])]
struct IdentityAttested {
    account: Address,
    policy_id: u32,
    valid_until: u64,
    nullifier: BytesN<32>,
    credential_root: BytesN<32>,
    terms_hash: BytesN<32>,
    action_binding: BytesN<32>,
}

#[contractevent(topics = ["identity", "rwa_token"])]
struct RwaTokenMapped {
    asset_id: u32,
    token: Address,
}

#[contractevent(topics = ["identity", "rwa_recipient"])]
struct RwaRecipientMapped {
    recipient_id: u128,
    account: Address,
}

#[contractevent(topics = ["identity", "mint_consumer"])]
struct MintConsumerAllowed {
    consumer: Address,
    allowed: bool,
}

#[contractevent(topics = ["identity", "mint_authorized"])]
struct RwaMintAuthorized {
    consumer: Address,
    token: Address,
    account: Address,
    policy_id: u32,
    asset_id: u32,
    amount: i128,
    recipient: u128,
    action_id: u128,
    valid_until: u64,
    nullifier: BytesN<32>,
    terms_hash: BytesN<32>,
    action_binding: BytesN<32>,
}

#[contractevent(topics = ["identity", "mint_consumed"])]
struct RwaMintAuthorizationConsumed {
    consumer: Address,
    token: Address,
    account: Address,
    amount: i128,
}

#[contractevent(topics = ["identity", "paused"])]
struct Paused {}

#[contractevent(topics = ["identity", "unpaused"])]
struct Unpaused {}

#[contractevent(topics = ["identity", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contract]
pub struct IdentityVerifier;

#[contractimpl]
impl IdentityVerifier {
    pub fn init(
        env: Env,
        admin: Address,
        verifier: Address,
        issuer_registry: Address,
        policy_registry: Address,
        nullifier_registry: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &admin);
        storage.set(&DataKey::Verifier, &verifier);
        storage.set(&DataKey::IssuerRegistry, &issuer_registry);
        storage.set(&DataKey::PolicyRegistry, &policy_registry);
        storage.set(&DataKey::NullifierRegistry, &nullifier_registry);
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

    pub fn set_rwa_token(env: Env, asset_id: u32, token: Address) -> Result<(), Error> {
        require_admin(&env)?;
        let key = DataKey::RwaToken(asset_id);
        if env.storage().instance().has(&key) {
            return Err(Error::AlreadySet);
        }
        env.storage().instance().set(&key, &token);
        RwaTokenMapped { asset_id, token }.publish(&env);
        Ok(())
    }

    pub fn rwa_token(env: Env, asset_id: u32) -> Option<Address> {
        env.storage().instance().get(&DataKey::RwaToken(asset_id))
    }

    pub fn set_rwa_recipient(env: Env, recipient_id: u128, account: Address) -> Result<(), Error> {
        require_admin(&env)?;
        let key = DataKey::RwaRecipient(recipient_id);
        if env.storage().instance().has(&key) {
            return Err(Error::AlreadySet);
        }
        env.storage().instance().set(&key, &account);
        RwaRecipientMapped {
            recipient_id,
            account,
        }
        .publish(&env);
        Ok(())
    }

    pub fn rwa_recipient(env: Env, recipient_id: u128) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::RwaRecipient(recipient_id))
    }

    pub fn allow_mint_consumer(env: Env, consumer: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::MintConsumer(consumer.clone()), &true);
        MintConsumerAllowed {
            consumer,
            allowed: true,
        }
        .publish(&env);
        Ok(())
    }

    pub fn revoke_mint_consumer(env: Env, consumer: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .remove(&DataKey::MintConsumer(consumer.clone()));
        MintConsumerAllowed {
            consumer,
            allowed: false,
        }
        .publish(&env);
        Ok(())
    }

    pub fn is_mint_consumer_allowed(env: Env, consumer: Address) -> bool {
        is_mint_consumer_allowed_internal(&env, &consumer)
    }

    /// Record an eligibility attestation for `account` (who must authorize the
    /// call) from a valid ZK proof. `valid_until` is a ledger timestamp.
    pub fn attest(
        env: Env,
        account: Address,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        epoch: u32,
        valid_until: u64,
    ) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        account.require_auth();
        let checked =
            validate_rwa_proof(&env, &proof, &pub_signals, policy_id, epoch, valid_until)?;
        env.storage()
            .persistent()
            .set(&DataKey::Attestation(account.clone()), &checked.valid_until);
        mark_nullifier_used(&env, &checked.nullifier)?;

        IdentityAttested {
            account,
            policy_id,
            valid_until: checked.valid_until,
            nullifier: checked.nullifier,
            credential_root: checked.credential_root,
            terms_hash: checked.terms_hash,
            action_binding: checked.action_binding,
        }
        .publish(&env);

        Ok(())
    }

    pub fn attest_for_mint(
        env: Env,
        account: Address,
        consumer: Address,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        asset_id: u32,
        amount: i128,
        recipient_id: u128,
        action_id: u128,
        terms_hash: Fr,
        epoch: u32,
        valid_until: u64,
    ) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        account.require_auth();
        if amount <= 0 {
            return Err(Error::BadAmount);
        }

        let checked =
            validate_rwa_proof(&env, &proof, &pub_signals, policy_id, epoch, valid_until)?;
        require_signal_u32(&env, &pub_signals, ASSET_ID, asset_id)?;
        require_signal_u128(&env, &pub_signals, AMOUNT, amount as u128)?;
        require_signal_u128(&env, &pub_signals, RECIPIENT, recipient_id)?;
        require_signal_u128(&env, &pub_signals, ACTION_ID, action_id)?;
        if checked.terms_hash != terms_hash.to_bytes() {
            return Err(Error::PublicInputMismatch);
        }

        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::RwaToken(asset_id))
            .ok_or(Error::MissingToken)?;
        let expected_account: Address = env
            .storage()
            .instance()
            .get(&DataKey::RwaRecipient(recipient_id))
            .ok_or(Error::MissingRecipient)?;
        if expected_account != account {
            return Err(Error::RecipientMismatch);
        }
        if !is_mint_consumer_allowed_internal(&env, &consumer) {
            return Err(Error::MintConsumerNotAllowed);
        }

        let auth_key = DataKey::MintAuthorization(consumer.clone(), token.clone(), account.clone());
        if env.storage().persistent().has(&auth_key) {
            return Err(Error::AlreadySet);
        }
        let authorization = MintAuthorization {
            amount,
            valid_until: checked.valid_until,
            nullifier: checked.nullifier.clone(),
            terms_hash: checked.terms_hash.clone(),
            action_binding: checked.action_binding.clone(),
            action_id,
        };
        env.storage().persistent().set(&auth_key, &authorization);
        env.storage()
            .persistent()
            .set(&DataKey::Attestation(account.clone()), &checked.valid_until);
        mark_nullifier_used(&env, &checked.nullifier)?;

        RwaMintAuthorized {
            consumer,
            token,
            account,
            policy_id,
            asset_id,
            amount,
            recipient: recipient_id,
            action_id,
            valid_until: checked.valid_until,
            nullifier: checked.nullifier,
            terms_hash: checked.terms_hash,
            action_binding: checked.action_binding,
        }
        .publish(&env);

        Ok(())
    }

    pub fn mint_authorization(
        env: Env,
        consumer: Address,
        token: Address,
        account: Address,
    ) -> Option<MintAuthorization> {
        env.storage()
            .persistent()
            .get(&DataKey::MintAuthorization(consumer, token, account))
    }

    pub fn consume_mint_authorization(
        env: Env,
        consumer: Address,
        token: Address,
        account: Address,
        amount: i128,
    ) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        if !is_mint_consumer_allowed_internal(&env, &consumer) {
            return Err(Error::MintConsumerNotAllowed);
        }
        consumer.require_auth();

        let key = DataKey::MintAuthorization(consumer.clone(), token.clone(), account.clone());
        let authorization: MintAuthorization = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::MissingMintAuthorization)?;
        if env.ledger().timestamp() > authorization.valid_until {
            return Err(Error::Expired);
        }
        if authorization.amount != amount {
            return Err(Error::AmountMismatch);
        }

        env.storage().persistent().remove(&key);
        RwaMintAuthorizationConsumed {
            consumer,
            token,
            account,
            amount,
        }
        .publish(&env);
        Ok(())
    }

    /// Called by the SEP-57 RWA token before mint/transfer. Succeeds only while a
    /// non-expired attestation exists for `account`; otherwise traps, reverting the
    /// token operation.
    pub fn verify_identity(env: Env, account: Address) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        let valid_until: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Attestation(account))
            .ok_or(Error::NotEligible)?;
        if env.ledger().timestamp() > valid_until {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// IdentityVerifier interface method. AnchorShield does not implement account
    /// recovery, so there is never a recovery target.
    pub fn recovery_target(_env: Env, _old_account: Address) -> Option<Address> {
        None
    }

    pub fn attestation_expiry(env: Env, account: Address) -> Option<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::Attestation(account))
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
}

struct CheckedRwaProof {
    valid_until: u64,
    nullifier: BytesN<32>,
    credential_root: BytesN<32>,
    terms_hash: BytesN<32>,
    action_binding: BytesN<32>,
}

fn validate_rwa_proof(
    env: &Env,
    proof: &Proof,
    pub_signals: &Vec<Fr>,
    policy_id: u32,
    epoch: u32,
    valid_until: u64,
) -> Result<CheckedRwaProof, Error> {
    if pub_signals.len() != PUBLIC_SIGNAL_COUNT {
        return Err(Error::MalformedPublicSignals);
    }

    let policy: Policy =
        PolicyRegistryPeerClient::new(env, &config_addr(env, DataKey::PolicyRegistry)?)
            .policy(&policy_id)
            .ok_or(Error::MissingPolicy)?;

    require_signal_u32(env, pub_signals, ISSUER_ID, policy.issuer_id)?;
    require_signal_u32(env, pub_signals, POLICY_ID, policy_id)?;
    require_signal_u32(
        env,
        pub_signals,
        KYC_REQUIRED,
        bool_as_u32(policy.kyc_required),
    )?;
    require_signal_u32(
        env,
        pub_signals,
        SANCTIONS_REQUIRED,
        bool_as_u32(policy.sanctions_required),
    )?;
    require_signal_u32(env, pub_signals, ALLOWED_COUNTRY, policy.allowed_country)?;
    require_signal_u32(env, pub_signals, MIN_AGE, policy.min_age)?;
    require_signal_u32(
        env,
        pub_signals,
        MIN_INVESTOR_TYPE,
        policy.min_investor_type,
    )?;
    require_signal_u32(env, pub_signals, ACTION_TYPE, RWA_ACTION)?;
    require_signal_u32(env, pub_signals, EPOCH, epoch)?;

    let issuer = IssuerRegistryPeerClient::new(env, &config_addr(env, DataKey::IssuerRegistry)?);
    let credential_root = signal(pub_signals, CREDENTIAL_ROOT)?.to_bytes();
    if issuer.root(&policy.issuer_id).is_none() {
        return Err(Error::MissingRoot);
    }
    if !issuer.is_root(&policy.issuer_id, &credential_root) {
        return Err(Error::RootMismatch);
    }
    let sanctions_root = issuer.sanctions_root().ok_or(Error::MissingSanctionsRoot)?;
    if signal(pub_signals, SANCTIONS_ROOT)?.to_bytes() != sanctions_root {
        return Err(Error::SanctionsRootMismatch);
    }
    let revocation_root = issuer
        .revocation_root(&policy.issuer_id)
        .ok_or(Error::MissingRevocationRoot)?;
    if signal(pub_signals, REVOCATION_ROOT)?.to_bytes() != revocation_root {
        return Err(Error::RevocationRootMismatch);
    }

    let nullifier = signal(pub_signals, NULLIFIER)?.to_bytes();
    let nullifiers =
        NullifierRegistryPeerClient::new(env, &config_addr(env, DataKey::NullifierRegistry)?);
    if nullifiers.is_used(&nullifier) {
        return Err(Error::NullifierUsed);
    }

    let verifier = VerifierPeerClient::new(env, &config_addr(env, DataKey::Verifier)?);
    if verifier.circuit_id().as_ref() != Some(&policy.circuit_id)
        || verifier.circuit_version() != Some(policy.circuit_version)
    {
        return Err(Error::CircuitMismatch);
    }
    if !verifier.verify(proof, pub_signals) {
        return Err(Error::InvalidProof);
    }

    Ok(CheckedRwaProof {
        valid_until: core::cmp::min(
            valid_until,
            env.ledger().timestamp().saturating_add(MAX_ATTESTATION_TTL),
        ),
        nullifier,
        credential_root,
        terms_hash: signal(pub_signals, BOUND_HASH)?.to_bytes(),
        action_binding: signal(pub_signals, ACTION_BINDING)?.to_bytes(),
    })
}

fn mark_nullifier_used(env: &Env, nullifier: &BytesN<32>) -> Result<(), Error> {
    NullifierRegistryPeerClient::new(env, &config_addr(env, DataKey::NullifierRegistry)?)
        .mark_used(&env.current_contract_address(), nullifier);
    Ok(())
}

fn is_mint_consumer_allowed_internal(env: &Env, consumer: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::MintConsumer(consumer.clone()))
        .unwrap_or(false)
}

fn require_admin(env: &Env) -> Result<Address, Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
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

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
