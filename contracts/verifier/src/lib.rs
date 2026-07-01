#![no_std]

//! Standalone Groth16 verifier. The verifying key is admin-set and then frozen in
//! contract storage, so a caller cannot substitute a forged key. Gates call
//! `verify(proof, pub_signals)` against the stored key.

use anchorshield_shared::{verify_proof, Proof, VerificationKey};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, BytesN, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    VkNotSet = 3,
    MalformedVerifyingKey = 4,
    VkFrozen = 5,
    NoPendingAdmin = 6,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Vk,
    Frozen,
    CircuitId,
    CircuitVersion,
}

#[contractevent(topics = ["verifier", "vk_set"])]
struct VkSet {
    circuit_id: BytesN<32>,
    circuit_version: u32,
}

#[contractevent(topics = ["verifier", "vk_frozen"])]
struct VkFrozen {
    circuit_id: BytesN<32>,
    circuit_version: u32,
}

#[contractevent(topics = ["verifier", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["verifier", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
}

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
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

    /// Admin-only. Sets the verifying key produced by the trusted-setup ceremony.
    pub fn set_vk(
        env: Env,
        circuit_id: BytesN<32>,
        circuit_version: u32,
        vk: VerificationKey,
    ) -> Result<(), Error> {
        require_admin(&env)?;
        let storage = env.storage().instance();
        if storage.get(&DataKey::Frozen).unwrap_or(false) {
            return Err(Error::VkFrozen);
        }
        storage.set(&DataKey::Vk, &vk);
        storage.set(&DataKey::CircuitId, &circuit_id);
        storage.set(&DataKey::CircuitVersion, &circuit_version);

        VkSet {
            circuit_id,
            circuit_version,
        }
        .publish(&env);

        Ok(())
    }

    pub fn has_vk(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Vk)
    }

    pub fn freeze_vk(env: Env) -> Result<(), Error> {
        require_admin(&env)?;
        let storage = env.storage().instance();
        let circuit_id: BytesN<32> = storage.get(&DataKey::CircuitId).ok_or(Error::VkNotSet)?;
        let circuit_version: u32 = storage
            .get(&DataKey::CircuitVersion)
            .ok_or(Error::VkNotSet)?;
        storage.set(&DataKey::Frozen, &true);

        VkFrozen {
            circuit_id,
            circuit_version,
        }
        .publish(&env);

        Ok(())
    }

    pub fn is_frozen(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Frozen)
            .unwrap_or(false)
    }

    pub fn circuit_id(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::CircuitId)
    }

    pub fn circuit_version(env: Env) -> Option<u32> {
        env.storage().instance().get(&DataKey::CircuitVersion)
    }

    /// Verify a proof against the pinned verifying key.
    pub fn verify(env: Env, proof: Proof, pub_signals: Vec<Fr>) -> Result<bool, Error> {
        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&DataKey::Vk)
            .ok_or(Error::VkNotSet)?;
        verify_proof(&env, vk, proof, &pub_signals).map_err(|_| Error::MalformedVerifyingKey)
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

mod test;
