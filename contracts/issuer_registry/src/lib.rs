#![no_std]

//! Registry of trusted issuers and their current credential Merkle roots.
//! Gates read the current root for an issuer; only the admin can rotate roots
//! (rotation is also the revocation mechanism).

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, BytesN, Env,
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
    PreviousRoot(u32),
    SanctionsRoot,
    RevocationRoot(u32),
}

#[contractevent(topics = ["issuer", "credential_root_set"])]
struct CredentialRootSet {
    issuer_id: u32,
    root: BytesN<32>,
}

#[contractevent(topics = ["issuer", "sanctions_root_set"])]
struct SanctionsRootSet {
    root: BytesN<32>,
}

#[contractevent(topics = ["issuer", "revocation_root_set"])]
struct RevocationRootSet {
    issuer_id: u32,
    root: BytesN<32>,
}

#[contractevent(topics = ["issuer", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
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

    /// Admin-only. Sets (or rotates) the credential root for an issuer.
    pub fn set_root(env: Env, issuer_id: u32, root: Fr) -> Result<(), Error> {
        require_admin(&env)?;
        let root_bytes = root.to_bytes();
        let storage = env.storage().instance();
        if let Some(current) = storage.get::<DataKey, BytesN<32>>(&DataKey::Root(issuer_id)) {
            if current != root_bytes {
                storage.set(&DataKey::PreviousRoot(issuer_id), &current);
            }
        }
        storage.set(&DataKey::Root(issuer_id), &root_bytes);
        CredentialRootSet {
            issuer_id,
            root: root_bytes,
        }
        .publish(&env);
        Ok(())
    }

    pub fn root(env: Env, issuer_id: u32) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Root(issuer_id))
    }

    pub fn is_root(env: Env, issuer_id: u32, root: BytesN<32>) -> bool {
        let storage = env.storage().instance();
        storage
            .get::<DataKey, BytesN<32>>(&DataKey::Root(issuer_id))
            .is_some_and(|current| current == root)
            || storage
                .get::<DataKey, BytesN<32>>(&DataKey::PreviousRoot(issuer_id))
                .is_some_and(|previous| previous == root)
    }

    pub fn set_sanctions_root(env: Env, root: Fr) -> Result<(), Error> {
        require_admin(&env)?;
        let root_bytes = root.to_bytes();
        env.storage()
            .instance()
            .set(&DataKey::SanctionsRoot, &root_bytes);
        SanctionsRootSet { root: root_bytes }.publish(&env);
        Ok(())
    }

    pub fn sanctions_root(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::SanctionsRoot)
    }

    pub fn set_revocation_root(env: Env, issuer_id: u32, root: Fr) -> Result<(), Error> {
        require_admin(&env)?;
        let root_bytes = root.to_bytes();
        env.storage()
            .instance()
            .set(&DataKey::RevocationRoot(issuer_id), &root_bytes);
        RevocationRootSet {
            issuer_id,
            root: root_bytes,
        }
        .publish(&env);
        Ok(())
    }

    pub fn revocation_root(env: Env, issuer_id: u32) -> Option<BytesN<32>> {
        env.storage()
            .instance()
            .get(&DataKey::RevocationRoot(issuer_id))
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
