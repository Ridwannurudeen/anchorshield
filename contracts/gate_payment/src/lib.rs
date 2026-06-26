#![no_std]

pub use anchorshield_shared::{Policy, Proof, VerificationKey};
use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, verify_proof, SharedError,
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
    Root(u32),
    Policy(u32),
    Nullifier(BytesN<32>),
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
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    pub fn set_root(env: Env, issuer_id: u32, root: Fr) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Root(issuer_id), &root.to_bytes());
        Ok(())
    }

    pub fn set_policy(env: Env, policy: Policy) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Policy(policy.policy_id), &policy);
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

    pub fn is_nullifier_used(env: Env, nullifier: Fr) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.to_bytes()))
    }

    pub fn verify_and_pay(
        env: Env,
        vk: VerificationKey,
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

        let policy: Policy = env
            .storage()
            .instance()
            .get(&DataKey::Policy(policy_id))
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

        let root: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Root(policy.issuer_id))
            .ok_or(Error::MissingRoot)?;
        if signal(&pub_signals, CREDENTIAL_ROOT)?.to_bytes() != root {
            return Err(Error::RootMismatch);
        }
        if signal(&pub_signals, PACKET_HASH)?.to_bytes() != packet_hash.to_bytes() {
            return Err(Error::PacketHashMismatch);
        }

        let nullifier = signal(&pub_signals, NULLIFIER)?.to_bytes();
        let nullifier_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(Error::NullifierUsed);
        }

        if !verify_proof(&env, vk, proof, &pub_signals)? {
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

        env.storage().persistent().set(&nullifier_key, &());
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

mod test;
