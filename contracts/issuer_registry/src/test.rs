#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    crypto::bls12_381::Bls12381Fr as Fr,
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    Address, Env, String as SorobanString, U256,
};

fn fr(env: &Env, value: u32) -> Fr {
    Fr::from_u256(U256::from_u32(env, value))
}

#[test]
fn accepts_current_and_immediately_previous_credential_root() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let registry_id = env.register(IssuerRegistry, ());
    let registry = IssuerRegistryClient::new(&env, &registry_id);

    registry.init(&admin);
    let first = fr(&env, 111).to_bytes();
    let second = fr(&env, 222).to_bytes();
    let third = fr(&env, 333).to_bytes();

    registry.set_root(&101, &fr(&env, 111), &11);
    assert!(registry.is_root(&101, &first));
    assert_eq!(registry.member_count(&101, &first), Some(11));

    registry.set_root(&101, &fr(&env, 222), &22);
    assert!(registry.is_root(&101, &second));
    assert!(registry.is_root(&101, &first));
    assert_eq!(registry.member_count(&101, &second), Some(22));
    assert_eq!(registry.member_count(&101, &first), Some(11));

    registry.set_root(&101, &fr(&env, 333), &33);
    assert!(registry.is_root(&101, &third));
    assert!(registry.is_root(&101, &second));
    assert!(!registry.is_root(&101, &first));
    assert_eq!(registry.member_count(&101, &third), Some(33));
    assert_eq!(registry.member_count(&101, &second), Some(22));
}

#[test]
fn stores_public_issuer_metadata_uri() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let registry_id = env.register(IssuerRegistry, ());
    let registry = IssuerRegistryClient::new(&env, &registry_id);
    let uri = SorobanString::from_str(&env, "https://issuer.example/.well-known/anchorshield.json");

    registry.init(&admin);
    registry.set_metadata_uri(&101, &uri);

    assert_eq!(registry.metadata_uri(&101), Some(uri));
}

#[test]
fn issuer_stake_can_be_slashed_and_reputation_recorded() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let staker = Address::generate(&env);
    let registry_id = env.register(IssuerRegistry, ());
    let registry = IssuerRegistryClient::new(&env, &registry_id);

    registry.init(&admin);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let token_client = TokenClient::new(&env, &token);
    StellarAssetClient::new(&env, &token).mint(&staker, &1_000_i128);

    registry.stake_issuer(&101, &staker, &token, &500_i128);
    assert_eq!(registry.issuer_stake(&101), 500);
    assert_eq!(registry.issuer_stake_token(&101), Some(token.clone()));
    assert_eq!(token_client.balance(&staker), 500);
    assert_eq!(token_client.balance(&registry_id), 500);

    registry.set_reputation(&101, &900);
    assert_eq!(registry.issuer_reputation(&101), 900);

    registry.slash_issuer(&101, &admin, &125_i128, &42);
    assert_eq!(registry.issuer_stake(&101), 375);
    assert_eq!(token_client.balance(&registry_id), 375);
    assert_eq!(token_client.balance(&admin), 125);

    assert_eq!(
        registry.try_slash_issuer(&101, &admin, &500_i128, &43),
        Err(Ok(Error::InsufficientStake))
    );
}
