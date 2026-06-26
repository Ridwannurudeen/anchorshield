#![no_std]

//! AnchorShield ZK IdentityVerifier for the OpenZeppelin SEP-57 (ERC-3643/T-REX)
//! RWA stack. A holder calls `attest` with a zero-knowledge eligibility proof; the
//! proof is verified (policy + issuer root + nullifier + Groth16) and a per-account
//! attestation is recorded. The RWA token then calls `verify_identity(account)`
//! before every mint/transfer, which succeeds only while a valid attestation
//! exists. The account is bound to the proof via `require_auth` (the caller must
//! control the attested address), which avoids binding the address inside the
//! circuit.

use anchorshield_shared::{
    bool_as_u32, require_signal_u32, signal, IssuerRegistryPeerClient, NullifierRegistryPeerClient,
    PolicyRegistryPeerClient, Policy, Proof, SharedError, VerifierPeerClient, ACTION_TYPE,
    ALLOWED_COUNTRY, CREDENTIAL_ROOT, EPOCH, ISSUER_ID, KYC_REQUIRED, MIN_AGE, MIN_INVESTOR_TYPE,
    NULLIFIER, POLICY_ID, PUBLIC_SIGNAL_COUNT, SANCTIONS_REQUIRED,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, BytesN, Env, Vec,
};

const RWA_ACTION: u32 = 1;

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
}

#[contractevent(topics = ["identity", "attested"])]
struct IdentityAttested {
    account: Address,
    policy_id: u32,
    valid_until: u64,
    nullifier: BytesN<32>,
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
        account.require_auth();
        if pub_signals.len() != PUBLIC_SIGNAL_COUNT {
            return Err(Error::MalformedPublicSignals);
        }

        let policy: Policy =
            PolicyRegistryPeerClient::new(&env, &config_addr(&env, DataKey::PolicyRegistry)?)
                .policy(&policy_id)
                .ok_or(Error::MissingPolicy)?;

        // Eligibility signals (transfer-specific signals are not constrained here).
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
        require_signal_u32(&env, &pub_signals, ACTION_TYPE, RWA_ACTION)?;
        require_signal_u32(&env, &pub_signals, EPOCH, epoch)?;

        let root: BytesN<32> =
            IssuerRegistryPeerClient::new(&env, &config_addr(&env, DataKey::IssuerRegistry)?)
                .root(&policy.issuer_id)
                .ok_or(Error::MissingRoot)?;
        if signal(&pub_signals, CREDENTIAL_ROOT)?.to_bytes() != root {
            return Err(Error::RootMismatch);
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

        env.storage()
            .persistent()
            .set(&DataKey::Attestation(account.clone()), &valid_until);
        nullifiers.mark_used(&env.current_contract_address(), &nullifier);

        IdentityAttested {
            account,
            policy_id,
            valid_until,
            nullifier,
        }
        .publish(&env);

        Ok(())
    }

    /// Called by the SEP-57 RWA token before mint/transfer. Succeeds only while a
    /// non-expired attestation exists for `account`; otherwise traps, reverting the
    /// token operation.
    pub fn verify_identity(env: Env, account: Address) -> Result<(), Error> {
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
}

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
