#![no_std]
// Contract entrypoints bind the full action (proof + signals + policy + asset +
// amount + recipient + action_id + hash + epoch), which exceeds clippy's arg limit.
#![allow(clippy::too_many_arguments)]

use anchorshield_shared::{
    bool_as_u32, require_signal_u128, require_signal_u32, signal, IssuerRegistryPeerClient,
    NullifierRegistryPeerClient, PolicyRegistryPeerClient, SharedError, VerifierPeerClient,
    ACTION_ID, ACTION_TYPE, ALLOWED_COUNTRY, AMOUNT, ASSET_ID, BOUND_HASH, CREDENTIAL_ROOT, EPOCH,
    ISSUER_ID, KYC_REQUIRED, MIN_AGE, MIN_INVESTOR_TYPE, NULLIFIER, POLICY_ID, PUBLIC_SIGNAL_COUNT,
    RECIPIENT, SANCTIONS_REQUIRED,
};
pub use anchorshield_shared::{Policy, Proof, VerificationKey};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, token::TokenClient, Address, BytesN, Env, Vec,
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
    MissingToken = 13,
    MissingRecipient = 14,
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
    // asset_id (a circuit signal) -> the Stellar Asset Contract address to pay in.
    Token(u32),
    // recipient_id (a circuit signal) -> the registered payee address. The proof
    // binds recipient_id; the admin maps it to a real address, so a valid proof
    // cannot be redirected to an arbitrary recipient.
    Recipient(u128),
}

#[contractevent(topics = ["payment", "approved"])]
struct PaymentApproved {
    policy_id: u32,
    asset_id: u32,
    amount: i128,
    recipient: Address,
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

    /// Admin-only. Maps an `asset_id` circuit signal to a Stellar Asset Contract.
    pub fn set_token(env: Env, asset_id: u32, token: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Token(asset_id), &token);
        Ok(())
    }

    /// Admin-only. Registers the real payee address for a `recipient_id` signal.
    pub fn set_recipient(env: Env, recipient_id: u128, recipient: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Recipient(recipient_id), &recipient);
        Ok(())
    }

    pub fn token(env: Env, asset_id: u32) -> Option<Address> {
        env.storage().instance().get(&DataKey::Token(asset_id))
    }

    pub fn recipient(env: Env, recipient_id: u128) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Recipient(recipient_id))
    }

    pub fn verify_and_pay(
        env: Env,
        proof: Proof,
        pub_signals: Vec<Fr>,
        policy_id: u32,
        asset_id: u32,
        amount: i128,
        recipient_id: u128,
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

        let policy: Policy =
            PolicyRegistryPeerClient::new(&env, &config_addr(&env, DataKey::PolicyRegistry)?)
                .policy(&policy_id)
                .ok_or(Error::MissingPolicy)?;

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
        require_signal_u32(&env, &pub_signals, ACTION_TYPE, PAYMENT_ACTION)?;
        require_signal_u32(&env, &pub_signals, ASSET_ID, asset_id)?;
        require_signal_u128(&env, &pub_signals, AMOUNT, amount as u128)?;
        require_signal_u128(&env, &pub_signals, RECIPIENT, recipient_id)?;
        require_signal_u128(&env, &pub_signals, ACTION_ID, action_id)?;
        require_signal_u32(&env, &pub_signals, EPOCH, epoch)?;

        let root: BytesN<32> =
            IssuerRegistryPeerClient::new(&env, &config_addr(&env, DataKey::IssuerRegistry)?)
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

        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token(asset_id))
            .ok_or(Error::MissingToken)?;
        let recipient: Address = env
            .storage()
            .instance()
            .get(&DataKey::Recipient(recipient_id))
            .ok_or(Error::MissingRecipient)?;

        // Real value transfer: the gate sends its own SAC balance to the payee.
        TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );

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
