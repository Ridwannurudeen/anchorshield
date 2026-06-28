#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Env,
};

#[derive(Clone)]
#[contracttype]
pub struct AccountSnapshot {
    pub address: Address,
    pub balance: i128,
    pub frozen: i128,
}

#[derive(Clone)]
#[contracttype]
pub enum TransferKind {
    Standard,
    Delegated(Address),
    Forced,
}

#[contractclient(name = "IdentityVerifierPeerClient")]
pub trait IdentityVerifierPeer {
    fn consume_mint_authorization(
        env: Env,
        consumer: Address,
        token: Address,
        account: Address,
        amount: i128,
    );
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NotAuthorized = 3,
    TokenAlreadyBound = 4,
    TokenNotBound = 5,
    BadAmount = 6,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    IdentityVerifier,
    Token(Address),
}

#[contractevent(topics = ["rwa_compliance", "token_bound"])]
struct TokenBound {
    token: Address,
}

#[contractevent(topics = ["rwa_compliance", "token_unbound"])]
struct TokenUnbound {
    token: Address,
}

#[contract]
pub struct RwaComplianceAdapter;

#[contractimpl]
impl RwaComplianceAdapter {
    pub fn init(env: Env, admin: Address, identity_verifier: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::IdentityVerifier, &identity_verifier);
        Ok(())
    }

    pub fn bind_token(env: Env, token: Address, operator: Address) -> Result<(), Error> {
        require_operator(&env, &operator)?;
        let key = DataKey::Token(token.clone());
        if env.storage().instance().has(&key) {
            return Err(Error::TokenAlreadyBound);
        }
        env.storage().instance().set(&key, &true);
        TokenBound { token }.publish(&env);
        Ok(())
    }

    pub fn unbind_token(env: Env, token: Address, operator: Address) -> Result<(), Error> {
        require_operator(&env, &operator)?;
        let key = DataKey::Token(token.clone());
        if !env.storage().instance().has(&key) {
            return Err(Error::TokenNotBound);
        }
        env.storage().instance().remove(&key);
        TokenUnbound { token }.publish(&env);
        Ok(())
    }

    pub fn is_token_bound(env: Env, token: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Token(token))
            .unwrap_or(false)
    }

    pub fn identity_verifier(env: Env) -> Result<Address, Error> {
        config_addr(&env, DataKey::IdentityVerifier)
    }

    pub fn created(
        env: Env,
        to: AccountSnapshot,
        amount: i128,
        token: Address,
    ) -> Result<(), Error> {
        require_bound_token(&env, &token)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        let identity_verifier = config_addr(&env, DataKey::IdentityVerifier)?;
        IdentityVerifierPeerClient::new(&env, &identity_verifier).consume_mint_authorization(
            &env.current_contract_address(),
            &token,
            &to.address,
            &amount,
        );
        Ok(())
    }

    pub fn transferred(
        env: Env,
        _from: AccountSnapshot,
        _to: AccountSnapshot,
        amount: i128,
        _kind: TransferKind,
        token: Address,
    ) -> Result<(), Error> {
        require_bound_token(&env, &token)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        Ok(())
    }

    pub fn destroyed(
        env: Env,
        _from: AccountSnapshot,
        amount: i128,
        token: Address,
    ) -> Result<(), Error> {
        require_bound_token(&env, &token)?;
        if amount <= 0 {
            return Err(Error::BadAmount);
        }
        Ok(())
    }
}

fn require_operator(env: &Env, operator: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;
    if admin != *operator {
        return Err(Error::NotAuthorized);
    }
    operator.require_auth();
    Ok(())
}

fn require_bound_token(env: &Env, token: &Address) -> Result<(), Error> {
    token.require_auth();
    if !env
        .storage()
        .instance()
        .get(&DataKey::Token(token.clone()))
        .unwrap_or(false)
    {
        return Err(Error::TokenNotBound);
    }
    Ok(())
}

fn config_addr(env: &Env, key: DataKey) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

mod test;
