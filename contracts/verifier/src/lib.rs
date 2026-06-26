#![no_std]

//! Standalone Groth16 verifier. The verifying key is admin-pinned in contract
//! storage and is NOT a caller-supplied argument, so a caller cannot substitute
//! a forged key. Gates call `verify(proof, pub_signals)` against the stored key.

use anchorshield_shared::{verify_proof, Proof, VerificationKey};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, crypto::bls12_381::Bls12381Fr as Fr, Address, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    VkNotSet = 3,
    MalformedVerifyingKey = 4,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    Vk,
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

    /// Admin-only. Pins the verifying key produced by the trusted-setup ceremony.
    pub fn set_vk(env: Env, vk: VerificationKey) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Vk, &vk);
        Ok(())
    }

    pub fn has_vk(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Vk)
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

fn require_admin(env: &Env) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(())
}
