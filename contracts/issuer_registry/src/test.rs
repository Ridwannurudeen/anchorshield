#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    crypto::bls12_381::Bls12381Fr as Fr, testutils::Address as _, Address, Env, U256,
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

    registry.set_root(&101, &fr(&env, 111));
    assert!(registry.is_root(&101, &first));

    registry.set_root(&101, &fr(&env, 222));
    assert!(registry.is_root(&101, &second));
    assert!(registry.is_root(&101, &first));

    registry.set_root(&101, &fr(&env, 333));
    assert!(registry.is_root(&101, &third));
    assert!(registry.is_root(&101, &second));
    assert!(!registry.is_root(&101, &first));
}
