#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Env,
};

#[contractclient(name = "IdentityVerifierPeerClient")]
pub trait IdentityVerifierPeer {
    fn verify_identity(env: Env, account: Address);
    fn attestation_expiry(env: Env, account: Address) -> Option<u64>;
}

/// TTL bump for the one-claim-per-account markers: ~60 days of 5s ledgers.
/// Archived entries fail closed (reads require a restore), so this is a
/// liveness bump, not a security control.
const PERSISTENT_ENTRY_TTL_LEDGERS: u32 = 1_036_800;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    AlreadyClaimed = 3,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    IdentityVerifier,
    Claimed(Address),
}

#[contractevent(topics = ["airdrop", "claimed"])]
struct AirdropClaimed {
    account: Address,
    attestation_expiry: u64,
}

#[contractevent(topics = ["airdrop", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contract]
pub struct AirdropGate;

#[contractimpl]
impl AirdropGate {
    pub fn init(env: Env, admin: Address, identity_verifier: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &admin);
        storage.set(&DataKey::IdentityVerifier, &identity_verifier);
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

    pub fn identity_verifier(env: Env) -> Result<Address, Error> {
        config_addr(&env, DataKey::IdentityVerifier)
    }

    pub fn claimed(env: Env, account: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Claimed(account))
            .unwrap_or(false)
    }

    pub fn claim(env: Env, account: Address) -> Result<(), Error> {
        account.require_auth();
        let key = DataKey::Claimed(account.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyClaimed);
        }

        let identity_verifier = config_addr(&env, DataKey::IdentityVerifier)?;
        let identity = IdentityVerifierPeerClient::new(&env, &identity_verifier);
        identity.verify_identity(&account);
        let attestation_expiry = identity.attestation_expiry(&account).unwrap_or(0);

        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_ENTRY_TTL_LEDGERS,
            PERSISTENT_ENTRY_TTL_LEDGERS,
        );
        AirdropClaimed {
            account,
            attestation_expiry,
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

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
