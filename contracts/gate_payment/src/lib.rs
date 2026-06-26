#![no_std]

pub use anchorshield_shared::{Policy, Proof, VerificationKey};
use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, IssuerRegistryPeerClient,
    NullifierRegistryPeerClient, PolicyRegistryPeerClient, SharedError, VerifierPeerClient,
    ACTION_ID, ACTION_TYPE, ALLOWED_COUNTRY, AMOUNT, ASSET_ID, BOUND_HASH, CREDENTIAL_ROOT, EPOCH,
    ISSUER_ID, KYC_REQUIRED, MIN_AGE, MIN_INVESTOR_TYPE, NULLIFIER, POLICY_ID, PUBLIC_SIGNAL_COUNT,
    RECIPIENT, SANCTIONS_REQUIRED,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, crypto::bls12_381::Fr,
    Address, BytesN, Env, Vec,
};

// Index 1 is read as the Travel-Rule packet hash by this gate.
const PACKET_HASH: u32 = BOUND_HASH;
const PAYMENT_ACTION: u32 = 0;

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
    PacketHashMismatch = 8,
    NullifierUsed = 9,
    InvalidProof = 10,
    MalformedVerifyingKey = 11,
    BadAmount = 12,
    InsufficientEscrow = 13,
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
    Escrow(u32),
    Balance(u32, u128),
}

#[contractevent(topics = ["payment", "approved"])]
struct PaymentApproved {
    policy_id: u32,
    asset_id: u32,
    amount: i128,
    recipient: u128,
    action_id: u128,
    nullifier: BytesN<32>,
}

#[contract]
pub struct GatePayment;

#[contractimpl]
impl GatePayment {
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

    pub fn fund(env: Env, asset_id: u32, amount: i128) -> Result<(), Error> {
        require_admin(&env)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }

        let key = DataKey::Escrow(asset_id);
        let current = env.storage().instance().get(&key).unwrap_or(0_i128);
        env.storage().instance().set(&key, &(current + amount));
        Ok(())
    }

    pub fn balance(env: Env, asset_id: u32, recipient: u128) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(asset_id, recipient))
            .unwrap_or(0_i128)
    }

    pub fn escrow(env: Env, asset_id: u32) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Escrow(asset_id))
            .unwrap_or(0_i128)
    }

    pub fn verify_and_pay(
        env: Env,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        asset_id: u32,
        amount: i128,
        recipient: u128,
        action_id: u128,
        packet_hash: Fr,
        epoch: u32,
    ) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        if pub_signals.len() != PUBLIC_SIGNAL_COUNT {
            return Err(Error::MalformedPublicSignals);
        }

        let policy: Policy = PolicyRegistryPeerClient::new(&env, &config_addr(&env, DataKey::PolicyRegistry)?)
            .policy(&policy_id)
            .ok_or(Error::MissingPolicy)?;

        require_signal_u32(&env, &pub_signals, ISSUER_ID, policy.issuer_id)?;
        require_signal_u32(&env, &pub_signals, POLICY_ID, policy_id)?;
        require_signal_u32(&env, &pub_signals, KYC_REQUIRED, bool_as_u32(policy.kyc_required))?;
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
        require_signal_u32(&env, &pub_signals, ACTION_TYPE, PAYMENT_ACTION)?;
        require_signal_u32(&env, &pub_signals, ASSET_ID, asset_id)?;
        require_signal_u128(&env, &pub_signals, AMOUNT, amount as u128)?;
        require_signal_u128(&env, &pub_signals, RECIPIENT, recipient)?;
        require_signal_u128(&env, &pub_signals, ACTION_ID, action_id)?;
        require_signal_u32(&env, &pub_signals, EPOCH, epoch)?;

        let root: BytesN<32> = IssuerRegistryPeerClient::new(&env, &config_addr(&env, DataKey::IssuerRegistry)?)
            .root(&policy.issuer_id)
            .ok_or(Error::MissingRoot)?;
        if signal(&pub_signals, CREDENTIAL_ROOT)?.to_bytes() != root {
            return Err(Error::RootMismatch);
        }
        if signal(&pub_signals, PACKET_HASH)?.to_bytes() != packet_hash.to_bytes() {
            return Err(Error::PacketHashMismatch);
        }

        let nullifier = signal(&pub_signals, NULLIFIER)?.to_bytes();
        let nullifiers =
            NullifierRegistryPeerClient::new(&env, &config_addr(&env, DataKey::NullifierRegistry)?);
        if nullifiers.is_used(&nullifier) {
            return Err(Error::NullifierUsed);
        }

        let verifier = VerifierPeerClient::new(&env, &config_addr(&env, DataKey::Verifier)?);
        if !verifier.verify(&proof, &pub_signals) {
            return Err(Error::InvalidProof);
        }

        let escrow_key = DataKey::Escrow(asset_id);
        let escrow = env.storage().instance().get(&escrow_key).unwrap_or(0_i128);
        if escrow < amount {
            return Err(Error::InsufficientEscrow);
        }
        env.storage().instance().set(&escrow_key, &(escrow - amount));

        let balance_key = DataKey::Balance(asset_id, recipient);
        let balance = env
            .storage()
            .persistent()
            .get(&balance_key)
            .unwrap_or(0_i128);
        env.storage()
            .persistent()
            .set(&balance_key, &(balance + amount));

        nullifiers.mark_used(&env.current_contract_address(), &nullifier);

        PaymentApproved {
            policy_id,
            asset_id,
            amount,
            recipient,
            action_id,
            nullifier,
        }
        .publish(&env);

        Ok(())
    }
}

fn require_admin(env: &Env) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(())
}

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
