#![no_std]

//! Registry of eligibility policies. A policy parameterizes the verifier+gate
//! checks (required attributes, jurisdiction, limits). Gates read a policy by id;
//! only the admin can create or update policies.

pub use anchorshield_shared::Policy;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NoPendingAdmin = 3,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Policy(u32),
}

#[contractevent(topics = ["policy", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["policy", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
}

#[contract]
pub struct PolicyRegistry;

#[contractimpl]
impl PolicyRegistry {
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

    /// Admin-only. Creates or updates a policy.
    pub fn set_policy(env: Env, policy: Policy) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Policy(policy.policy_id), &policy);
        Ok(())
    }

    pub fn policy(env: Env, policy_id: u32) -> Option<Policy> {
        env.storage().instance().get(&DataKey::Policy(policy_id))
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
