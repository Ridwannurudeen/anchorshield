#![no_std]

//! Shared spent-nullifier set. Only allow-listed gate contracts may mark a
//! nullifier as used; the mark is an atomic check-then-set. Reads are public.
//!
//! Auth model: a gate calls `mark_used(<its own address>, nullifier)`. Soroban
//! automatically authorizes a contract for its own address on calls it makes,
//! so `gate.require_auth()` succeeds for the calling gate and fails for anyone
//! impersonating it. The allow-list additionally restricts which contracts may
//! mark at all.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NotAllowed = 3,
    AlreadyUsed = 4,
    NoPendingAdmin = 5,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Gate(Address),
    Nullifier(BytesN<32>),
}

#[contractevent(topics = ["nullifier", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["nullifier", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
}

#[contract]
pub struct NullifierRegistry;

#[contractimpl]
impl NullifierRegistry {
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

    /// Admin-only. Allow a gate contract to mark nullifiers.
    pub fn allow_gate(env: Env, gate: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Gate(gate), &true);
        Ok(())
    }

    /// Admin-only. Revoke a gate's permission.
    pub fn revoke_gate(env: Env, gate: Address) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage().instance().remove(&DataKey::Gate(gate));
        Ok(())
    }

    pub fn is_gate_allowed(env: Env, gate: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Gate(gate))
            .unwrap_or(false)
    }

    pub fn is_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    /// Allow-listed gate marks a nullifier spent. Reverts if the caller is not an
    /// allow-listed gate or the nullifier was already used (atomic check-then-set).
    pub fn mark_used(env: Env, gate: Address, nullifier: BytesN<32>) -> Result<(), Error> {
        gate.require_auth();
        if !env
            .storage()
            .instance()
            .get(&DataKey::Gate(gate))
            .unwrap_or(false)
        {
            return Err(Error::NotAllowed);
        }
        let key = DataKey::Nullifier(nullifier);
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyUsed);
        }
        env.storage().persistent().set(&key, &());
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
