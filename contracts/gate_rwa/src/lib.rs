#![no_std]
// Contract entrypoints bind the full action, which exceeds clippy's arg limit.
#![allow(clippy::too_many_arguments)]

use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, IssuerRegistryPeerClient,
    NullifierRegistryPeerClient, PolicyRegistryPeerClient, SharedError, VerifierPeerClient,
    ACTION_BINDING, ACTION_ID, ACTION_TYPE, ALLOWED_COUNTRY, AMOUNT, ASSET_ID, BOUND_HASH,
    CREDENTIAL_ROOT, EPOCH, ISSUER_ID, KYC_REQUIRED, MIN_AGE, MIN_INVESTOR_TYPE, NULLIFIER,
    POLICY_ID, PUBLIC_SIGNAL_COUNT, RECIPIENT, REVOCATION_ROOT, SANCTIONS_REQUIRED, SANCTIONS_ROOT,
};
pub use anchorshield_shared::{Policy, Proof, VerificationKey};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, BytesN, Env, Vec,
};

// Index 1 is read as the asset terms hash by this gate.
const TERMS_HASH: u32 = BOUND_HASH;
const RWA_ACTION: u32 = 1;
const LOW_ANONYMITY_WARNING_FLOOR: u32 = 32;

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
    TermsHashMismatch = 8,
    NullifierUsed = 9,
    InvalidProof = 10,
    MalformedVerifyingKey = 11,
    BadAmount = 12,
    InsufficientInventory = 13,
    MissingSanctionsRoot = 14,
    MissingRevocationRoot = 15,
    SanctionsRootMismatch = 16,
    RevocationRootMismatch = 17,
    Paused = 18,
    CircuitMismatch = 19,
    AnonymitySetTooSmall = 20,
    NotPauser = 21,
    NoPendingAdmin = 22,
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
    Inventory(u32),
    Holding(u32, u128),
    Paused,
    Pauser,
    PausedPolicy(u32),
    PausedIssuer(u32),
}

#[contractevent(topics = ["rwa", "approved"])]
struct RwaTransferApproved {
    policy_id: u32,
    asset_id: u32,
    amount: i128,
    recipient: u128,
    action_id: u128,
    nullifier: BytesN<32>,
    terms_hash: BytesN<32>,
    action_binding: BytesN<32>,
}

#[contractevent(topics = ["rwa", "paused"])]
struct Paused {}

#[contractevent(topics = ["rwa", "unpaused"])]
struct Unpaused {}

#[contractevent(topics = ["rwa", "pauser_set"])]
struct PauserSet {
    pauser: Address,
}

#[contractevent(topics = ["rwa", "policy_paused"])]
struct PolicyPaused {
    policy_id: u32,
}

#[contractevent(topics = ["rwa", "policy_unpaused"])]
struct PolicyUnpaused {
    policy_id: u32,
}

#[contractevent(topics = ["rwa", "issuer_paused"])]
struct IssuerPaused {
    issuer_id: u32,
}

#[contractevent(topics = ["rwa", "issuer_unpaused"])]
struct IssuerUnpaused {
    issuer_id: u32,
}

#[contractevent(topics = ["rwa", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["rwa", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
}

#[contractevent(topics = ["rwa", "low_anonymity_set"])]
struct LowAnonymitySet {
    policy_id: u32,
    issuer_id: u32,
    credential_root: BytesN<32>,
    member_count: u32,
    min_credential_members: u32,
}

#[contract]
pub struct GateRwa;

#[contractimpl]
impl GateRwa {
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

    pub fn fund(env: Env, asset_id: u32, amount: i128) -> Result<(), Error> {
        require_admin(&env)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }

        let key = DataKey::Inventory(asset_id);
        let current = env.storage().instance().get(&key).unwrap_or(0_i128);
        env.storage().instance().set(&key, &(current + amount));
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

    pub fn holding(env: Env, asset_id: u32, recipient: u128) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Holding(asset_id, recipient))
            .unwrap_or(0_i128)
    }

    pub fn inventory(env: Env, asset_id: u32) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Inventory(asset_id))
            .unwrap_or(0_i128)
    }

    pub fn verify_and_transfer(
        env: Env,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        asset_id: u32,
        amount: i128,
        recipient: u128,
        action_id: u128,
        terms_hash: Fr,
        epoch: u32,
    ) -> Result<(), Error> {
        ensure_not_paused(&env)?;
        ensure_policy_not_paused(&env, policy_id)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
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
        require_signal_u32(&env, &pub_signals, ACTION_TYPE, RWA_ACTION)?;
        require_signal_u32(&env, &pub_signals, ASSET_ID, asset_id)?;
        require_signal_u128(&env, &pub_signals, AMOUNT, amount as u128)?;
        require_signal_u128(&env, &pub_signals, RECIPIENT, recipient)?;
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
        if signal(&pub_signals, TERMS_HASH)?.to_bytes() != terms_hash.to_bytes() {
            return Err(Error::TermsHashMismatch);
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

        let inventory_key = DataKey::Inventory(asset_id);
        let inventory = env
            .storage()
            .instance()
            .get(&inventory_key)
            .unwrap_or(0_i128);
        if inventory < amount {
            return Err(Error::InsufficientInventory);
        }
        env.storage()
            .instance()
            .set(&inventory_key, &(inventory - amount));

        let holding_key = DataKey::Holding(asset_id, recipient);
        let holding = env
            .storage()
            .persistent()
            .get(&holding_key)
            .unwrap_or(0_i128);
        env.storage()
            .persistent()
            .set(&holding_key, &(holding + amount));

        nullifiers.mark_used(&env.current_contract_address(), &nullifier);

        RwaTransferApproved {
            policy_id,
            asset_id,
            amount,
            recipient,
            action_id,
            nullifier,
            terms_hash: signal(&pub_signals, TERMS_HASH)?.to_bytes(),
            action_binding: signal(&pub_signals, ACTION_BINDING)?.to_bytes(),
        }
        .publish(&env);

        Ok(())
    }
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
