#![cfg(test)]
extern crate std;

use super::*;
use anchorshield_gate_payment::{GatePayment, GatePaymentClient};
use anchorshield_issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    vec, Address, Env, U256,
};

fn signers(env: &Env) -> (Address, Address, Address) {
    (
        Address::generate(env),
        Address::generate(env),
        Address::generate(env),
    )
}

#[test]
fn threshold_and_timelock_execute_root_rotation_as_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let (s1, s2, s3) = signers(&env);
    let bootstrap = Address::generate(&env);

    let issuer_id = env.register(IssuerRegistry, ());
    let issuer = IssuerRegistryClient::new(&env, &issuer_id);
    issuer.init(&bootstrap);

    let governance_id = env.register(Governance, ());
    let governance = GovernanceClient::new(&env, &governance_id);
    governance.init(
        &vec![&env, s1.clone(), s2.clone(), s3.clone()],
        &2,
        &5,
        &1,
        &0,
    );

    issuer.transfer_admin(&governance_id);
    assert_eq!(issuer.admin(), Some(bootstrap.clone()));
    assert_eq!(issuer.pending_admin(), Some(governance_id.clone()));

    let accept_action = GovernanceAction::AcceptAdmin(issuer_id.clone());
    let accept_proposal = governance.propose(&s1, &accept_action, &false);
    governance.approve(&s2, &accept_proposal);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 5);
    assert_eq!(governance.try_execute(&accept_proposal), Ok(Ok(())));
    assert_eq!(issuer.admin(), Some(governance_id.clone()));
    assert_eq!(issuer.pending_admin(), None);

    let root = Fr::from_u256(U256::from_u32(&env, 77));
    let action = GovernanceAction::SetCredentialRoot(issuer_id.clone(), 101, root.clone(), 64);
    let proposal_id = governance.propose(&s1, &action, &false);

    env.set_auths(&[]);
    assert_eq!(
        governance.try_execute(&proposal_id),
        Err(Ok(Error::ThresholdNotMet))
    );
    env.mock_all_auths();
    governance.approve(&s2, &proposal_id);
    env.set_auths(&[]);
    assert_eq!(
        governance.try_execute(&proposal_id),
        Err(Ok(Error::TimelockActive))
    );

    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 5);
    assert_eq!(governance.try_execute(&proposal_id), Ok(Ok(())));
    assert_eq!(issuer.root(&101), Some(root.to_bytes()));
    assert_eq!(issuer.member_count(&101, &root.to_bytes()), Some(64));
    assert_eq!(
        governance.try_execute(&proposal_id),
        Err(Ok(Error::AlreadyExecuted))
    );

    env.mock_all_auths();
    let reputation_action = GovernanceAction::SetIssuerReputation(issuer_id.clone(), 101, 900);
    let reputation_proposal = governance.propose(&s1, &reputation_action, &false);
    governance.approve(&s2, &reputation_proposal);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 5);
    assert_eq!(governance.try_execute(&reputation_proposal), Ok(Ok(())));
    assert_eq!(issuer.issuer_reputation(&101), 900);
}

#[test]
fn emergency_path_is_restricted_to_operational_safety_actions() {
    let env = Env::default();
    env.mock_all_auths();
    let (s1, s2, s3) = signers(&env);
    let bootstrap = Address::generate(&env);

    let governance_id = env.register(Governance, ());
    let governance = GovernanceClient::new(&env, &governance_id);
    governance.init(
        &vec![&env, s1.clone(), s2.clone(), s3.clone()],
        &2,
        &5,
        &1,
        &0,
    );

    let gate_id = env.register(GatePayment, ());
    let gate = GatePaymentClient::new(&env, &gate_id);
    gate.init(
        &bootstrap,
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
    );
    gate.transfer_admin(&governance_id);
    assert_eq!(gate.admin(), Some(bootstrap.clone()));
    assert_eq!(gate.pending_admin(), Some(governance_id.clone()));

    let accept = GovernanceAction::AcceptAdmin(gate_id.clone());
    let accept_proposal = governance.propose(&s1, &accept, &false);
    governance.approve(&s2, &accept_proposal);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + 5);
    assert_eq!(governance.try_execute(&accept_proposal), Ok(Ok(())));
    assert_eq!(gate.admin(), Some(governance_id.clone()));
    assert_eq!(gate.pending_admin(), None);

    let forbidden = GovernanceAction::SetSanctionsRoot(
        Address::generate(&env),
        Fr::from_u256(U256::from_u32(&env, 99)),
    );
    assert_eq!(
        governance.try_propose(&s1, &forbidden, &true),
        Err(Ok(Error::EmergencyActionNotAllowed))
    );

    let pause = GovernanceAction::Pause(gate_id.clone());
    let proposal_id = governance.propose(&s1, &pause, &true);
    env.set_auths(&[]);
    assert_eq!(governance.try_execute(&proposal_id), Ok(Ok(())));
    assert!(gate.paused());
}
