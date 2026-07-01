#![no_std]

//! Registry of trusted issuers and their current credential Merkle roots.
//! Gates read the current root for an issuer; only the admin can rotate roots
//! (rotation is also the revocation mechanism).

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, token::TokenClient, Address, BytesN, Env, String,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    BadAmount = 3,
    MissingStakeToken = 4,
    StakeTokenMismatch = 5,
    InsufficientStake = 6,
    NoPendingAdmin = 7,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    PendingAdmin,
    Root(u32),
    PreviousRoot(u32),
    RootMemberCount(u32, BytesN<32>),
    MetadataUri(u32),
    Stake(u32),
    StakeToken(u32),
    Reputation(u32),
    SanctionsRoot,
    RevocationRoot(u32),
}

#[contractevent(topics = ["issuer", "credential_root_set"])]
struct CredentialRootSet {
    issuer_id: u32,
    root: BytesN<32>,
    member_count: u32,
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

#[contractevent(topics = ["issuer", "metadata_uri_set"])]
struct MetadataUriSet {
    issuer_id: u32,
    metadata_uri: String,
}

#[contractevent(topics = ["issuer", "staked"])]
struct IssuerStaked {
    issuer_id: u32,
    staker: Address,
    token: Address,
    amount: i128,
    total_stake: i128,
}

#[contractevent(topics = ["issuer", "slashed"])]
struct IssuerSlashed {
    issuer_id: u32,
    recipient: Address,
    amount: i128,
    remaining_stake: i128,
    reason_code: u32,
}

#[contractevent(topics = ["issuer", "reputation_set"])]
struct IssuerReputationSet {
    issuer_id: u32,
    reputation: u32,
}

#[contractevent(topics = ["issuer", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contractevent(topics = ["issuer", "admin_transfer_started"])]
struct AdminTransferStarted {
    old_admin: Address,
    pending_admin: Address,
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

    /// Admin-only. Sets (or rotates) the credential root for an issuer.
    pub fn set_root(env: Env, issuer_id: u32, root: Fr, member_count: u32) -> Result<(), Error> {
        require_admin(&env)?;
        let root_bytes = root.to_bytes();
        let storage = env.storage().instance();
        if let Some(current) = storage.get::<DataKey, BytesN<32>>(&DataKey::Root(issuer_id)) {
            if current != root_bytes {
                // Evict the outgoing previous root's member count: is_root only
                // accepts the current or previous root, so counts for older
                // roots are dead data that would otherwise grow the instance
                // entry without bound as roots rotate.
                if let Some(old_previous) =
                    storage.get::<DataKey, BytesN<32>>(&DataKey::PreviousRoot(issuer_id))
                {
                    if old_previous != current && old_previous != root_bytes {
                        storage.remove(&DataKey::RootMemberCount(issuer_id, old_previous));
                    }
                }
                storage.set(&DataKey::PreviousRoot(issuer_id), &current);
            }
        }
        storage.set(&DataKey::Root(issuer_id), &root_bytes);
        storage.set(
            &DataKey::RootMemberCount(issuer_id, root_bytes.clone()),
            &member_count,
        );
        CredentialRootSet {
            issuer_id,
            root: root_bytes,
            member_count,
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

    pub fn member_count(env: Env, issuer_id: u32, root: BytesN<32>) -> Option<u32> {
        env.storage()
            .instance()
            .get(&DataKey::RootMemberCount(issuer_id, root))
    }

    pub fn set_metadata_uri(env: Env, issuer_id: u32, metadata_uri: String) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::MetadataUri(issuer_id), &metadata_uri);
        MetadataUriSet {
            issuer_id,
            metadata_uri,
        }
        .publish(&env);
        Ok(())
    }

    pub fn metadata_uri(env: Env, issuer_id: u32) -> Option<String> {
        env.storage()
            .instance()
            .get(&DataKey::MetadataUri(issuer_id))
    }

    pub fn stake_issuer(
        env: Env,
        issuer_id: u32,
        staker: Address,
        token: Address,
        amount: i128,
    ) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        staker.require_auth();
        let storage = env.storage().instance();
        if let Some(existing_token) =
            storage.get::<DataKey, Address>(&DataKey::StakeToken(issuer_id))
        {
            if existing_token != token {
                return Err(Error::StakeTokenMismatch);
            }
        } else {
            storage.set(&DataKey::StakeToken(issuer_id), &token);
        }
        let current = storage
            .get::<DataKey, i128>(&DataKey::Stake(issuer_id))
            .unwrap_or(0);
        let total_stake = current + amount;
        TokenClient::new(&env, &token).transfer(&staker, env.current_contract_address(), &amount);
        storage.set(&DataKey::Stake(issuer_id), &total_stake);
        IssuerStaked {
            issuer_id,
            staker,
            token,
            amount,
            total_stake,
        }
        .publish(&env);
        Ok(())
    }

    pub fn slash_issuer(
        env: Env,
        issuer_id: u32,
        recipient: Address,
        amount: i128,
        reason_code: u32,
    ) -> Result<(), Error> {
        require_admin(&env)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        let storage = env.storage().instance();
        let token: Address = storage
            .get(&DataKey::StakeToken(issuer_id))
            .ok_or(Error::MissingStakeToken)?;
        let current = storage
            .get::<DataKey, i128>(&DataKey::Stake(issuer_id))
            .unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientStake);
        }
        let remaining_stake = current - amount;
        TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );
        storage.set(&DataKey::Stake(issuer_id), &remaining_stake);
        IssuerSlashed {
            issuer_id,
            recipient,
            amount,
            remaining_stake,
            reason_code,
        }
        .publish(&env);
        Ok(())
    }

    pub fn set_reputation(env: Env, issuer_id: u32, reputation: u32) -> Result<(), Error> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::Reputation(issuer_id), &reputation);
        IssuerReputationSet {
            issuer_id,
            reputation,
        }
        .publish(&env);
        Ok(())
    }

    pub fn issuer_stake(env: Env, issuer_id: u32) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Stake(issuer_id))
            .unwrap_or(0_i128)
    }

    pub fn issuer_stake_token(env: Env, issuer_id: u32) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::StakeToken(issuer_id))
    }

    pub fn issuer_reputation(env: Env, issuer_id: u32) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Reputation(issuer_id))
            .unwrap_or(0_u32)
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
