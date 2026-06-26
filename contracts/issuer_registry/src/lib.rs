#![no_std]

//! Registry of trusted issuers and their current credential Merkle roots.
//! Gates read the current root for an issuer; only the admin can rotate roots
//! (rotation is also the revocation mechanism).

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, crypto::bls12_381::Bls12381Fr as Fr,
    Address, BytesN, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    Root(u32),
}

#[contract]
pub struct IssuerRegistry;

#[contractimpl]
impl IssuerRegistry {
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Admin-only. Sets (or rotates) the credential root for an issuer.
    pub fn set_root(env: Env, issuer_id: u32, root: Fr) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Root(issuer_id), &root.to_bytes());
        Ok(())
    }

    pub fn root(env: Env, issuer_id: u32) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Root(issuer_id))
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
