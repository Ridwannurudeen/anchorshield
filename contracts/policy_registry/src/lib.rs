#![no_std]

//! Registry of eligibility policies. A policy parameterizes the verifier+gate
//! checks (required attributes, jurisdiction, limits). Gates read a policy by id;
//! only the admin can create or update policies.

pub use anchorshield_shared::Policy;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env};

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
    Policy(u32),
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

fn require_admin(env: &Env) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    admin.require_auth();
    Ok(())
}
