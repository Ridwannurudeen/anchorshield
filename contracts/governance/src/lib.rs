#![no_std]

//! Threshold/timelock admin controller for AnchorShield production contracts.
//! The live admin transfers each governed contract to this contract once; after
//! that, signer-approved proposals execute the whitelisted admin calls.

use anchorshield_shared::Policy;
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::Bls12381Fr as Fr, Address, Env, String, Vec,
};

/// TTL bump for pending proposals and approvals: ~60 days of 5s ledgers,
/// refreshed on every approval. A proposal left unexecuted past its TTL
/// archives (restorable); executed proposals are deleted outright.
const PERSISTENT_ENTRY_TTL_LEDGERS: u32 = 1_036_800;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidConfig = 3,
    NotSigner = 4,
    AlreadyApproved = 5,
    MissingProposal = 6,
    TimelockActive = 7,
    ThresholdNotMet = 8,
    EmergencyActionNotAllowed = 10,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Signers,
    Signer(Address),
    Threshold,
    DelayLedgers,
    EmergencyThreshold,
    EmergencyDelayLedgers,
    NextProposalId,
    Proposal(u32),
    Approval(u32, Address),
}

#[derive(Clone)]
#[contracttype]
pub enum GovernanceAction {
    TransferAdmin(Address, Address),
    AcceptAdmin(Address),
    SetCredentialRoot(Address, u32, Fr, u32),
    SetIssuerMetadataUri(Address, u32, String),
    SlashIssuer(Address, u32, Address, i128, u32),
    SetIssuerReputation(Address, u32, u32),
    SetSanctionsRoot(Address, Fr),
    SetRevocationRoot(Address, u32, Fr),
    SetPolicy(Address, Policy),
    AllowGate(Address, Address),
    RevokeGate(Address, Address),
    Pause(Address),
    Unpause(Address),
    FreezeVk(Address),
    UpdateConfig(Vec<Address>, u32, u32, u32, u32),
}

#[derive(Clone)]
#[contracttype]
pub struct Proposal {
    pub id: u32,
    pub proposer: Address,
    pub action: GovernanceAction,
    pub eta_ledger: u32,
    pub approvals: u32,
    pub emergency: bool,
}

#[contractevent(topics = ["governance", "proposal_created"])]
struct ProposalCreated {
    id: u32,
    proposer: Address,
    eta_ledger: u32,
    emergency: bool,
}

#[contractevent(topics = ["governance", "proposal_approved"])]
struct ProposalApproved {
    id: u32,
    signer: Address,
    approvals: u32,
}

#[contractevent(topics = ["governance", "proposal_executed"])]
struct ProposalExecuted {
    id: u32,
}

#[contractevent(topics = ["governance", "config_updated"])]
struct ConfigUpdated {
    threshold: u32,
    delay_ledgers: u32,
    emergency_threshold: u32,
    emergency_delay_ledgers: u32,
}

#[contractclient(name = "AdminPeerClient")]
#[allow(dead_code)]
trait AdminPeer {
    fn transfer_admin(env: Env, new_admin: Address);
    fn accept_admin(env: Env);
}

#[contractclient(name = "IssuerAdminPeerClient")]
#[allow(dead_code)]
trait IssuerAdminPeer {
    fn set_root(env: Env, issuer_id: u32, root: Fr, member_count: u32);
    fn set_metadata_uri(env: Env, issuer_id: u32, metadata_uri: String);
    fn slash_issuer(env: Env, issuer_id: u32, recipient: Address, amount: i128, reason_code: u32);
    fn set_reputation(env: Env, issuer_id: u32, reputation: u32);
    fn set_sanctions_root(env: Env, root: Fr);
    fn set_revocation_root(env: Env, issuer_id: u32, root: Fr);
}

#[contractclient(name = "PolicyAdminPeerClient")]
#[allow(dead_code)]
trait PolicyAdminPeer {
    fn set_policy(env: Env, policy: Policy);
}

#[contractclient(name = "NullifierAdminPeerClient")]
#[allow(dead_code)]
trait NullifierAdminPeer {
    fn allow_gate(env: Env, gate: Address);
    fn revoke_gate(env: Env, gate: Address);
}

#[contractclient(name = "PausablePeerClient")]
#[allow(dead_code)]
trait PausablePeer {
    fn pause(env: Env);
    fn unpause(env: Env);
}

#[contractclient(name = "VerifierAdminPeerClient")]
#[allow(dead_code)]
trait VerifierAdminPeer {
    fn freeze_vk(env: Env);
}

#[contract]
pub struct Governance;

#[contractimpl]
impl Governance {
    pub fn init(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
        delay_ledgers: u32,
        emergency_threshold: u32,
        emergency_delay_ledgers: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Signers) {
            return Err(Error::AlreadyInitialized);
        }
        set_config(
            &env,
            signers,
            threshold,
            delay_ledgers,
            emergency_threshold,
            emergency_delay_ledgers,
        )?;
        env.storage()
            .instance()
            .set(&DataKey::NextProposalId, &1_u32);
        Ok(())
    }

    pub fn propose(
        env: Env,
        signer: Address,
        action: GovernanceAction,
        emergency: bool,
    ) -> Result<u32, Error> {
        require_signer(&env, &signer)?;
        signer.require_auth();
        if emergency && !is_emergency_action(&action) {
            return Err(Error::EmergencyActionNotAllowed);
        }

        let id = next_proposal_id(&env)?;
        let delay = if emergency {
            get_u32(&env, DataKey::EmergencyDelayLedgers)?
        } else {
            get_u32(&env, DataKey::DelayLedgers)?
        };
        let proposal = Proposal {
            id,
            proposer: signer.clone(),
            action,
            eta_ledger: env.ledger().sequence().saturating_add(delay),
            approvals: 1,
            emergency,
        };
        // Proposals and approvals live in persistent storage (not the instance
        // map) so lifetime proposal count never grows the per-call footprint;
        // executed proposals are deleted in execute().
        set_with_ttl(&env, &DataKey::Approval(id, signer.clone()), &true);
        set_with_ttl(&env, &DataKey::Proposal(id), &proposal);
        env.storage()
            .instance()
            .set(&DataKey::NextProposalId, &(id + 1));

        ProposalCreated {
            id,
            proposer: signer,
            eta_ledger: proposal.eta_ledger,
            emergency,
        }
        .publish(&env);
        Ok(id)
    }

    pub fn approve(env: Env, signer: Address, proposal_id: u32) -> Result<(), Error> {
        require_signer(&env, &signer)?;
        signer.require_auth();
        let approval_key = DataKey::Approval(proposal_id, signer.clone());
        if env.storage().persistent().has(&approval_key) {
            return Err(Error::AlreadyApproved);
        }

        let mut proposal = load_proposal(&env, proposal_id)?;
        proposal.approvals += 1;
        set_with_ttl(&env, &approval_key, &true);
        set_with_ttl(&env, &DataKey::Proposal(proposal_id), &proposal);

        ProposalApproved {
            id: proposal_id,
            signer,
            approvals: proposal.approvals,
        }
        .publish(&env);
        Ok(())
    }

    pub fn execute(env: Env, proposal_id: u32) -> Result<(), Error> {
        let proposal = load_proposal(&env, proposal_id)?;
        let required = if proposal.emergency {
            get_u32(&env, DataKey::EmergencyThreshold)?
        } else {
            get_u32(&env, DataKey::Threshold)?
        };
        if proposal.approvals < required {
            return Err(Error::ThresholdNotMet);
        }
        if env.ledger().sequence() < proposal.eta_ledger {
            return Err(Error::TimelockActive);
        }

        execute_action(&env, &proposal.action)?;
        // Delete the executed proposal and its approvals so storage never grows
        // with lifetime proposal count (the ProposalExecuted event preserves
        // history; a re-execute attempt gets MissingProposal). Approvals from
        // signers removed by a config change before execution are left to
        // expire via their TTL.
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        for signer in signers.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Approval(proposal_id, signer));
        }
        env.storage()
            .persistent()
            .remove(&DataKey::Proposal(proposal_id));
        ProposalExecuted { id: proposal_id }.publish(&env);
        Ok(())
    }

    pub fn proposal(env: Env, proposal_id: u32) -> Option<Proposal> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
    }

    pub fn signers(env: Env) -> Result<Vec<Address>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)
    }

    pub fn threshold(env: Env) -> Result<u32, Error> {
        get_u32(&env, DataKey::Threshold)
    }

    pub fn delay_ledgers(env: Env) -> Result<u32, Error> {
        get_u32(&env, DataKey::DelayLedgers)
    }

    pub fn emergency_threshold(env: Env) -> Result<u32, Error> {
        get_u32(&env, DataKey::EmergencyThreshold)
    }

    pub fn emergency_delay_ledgers(env: Env) -> Result<u32, Error> {
        get_u32(&env, DataKey::EmergencyDelayLedgers)
    }

    pub fn is_signer(env: Env, signer: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Signer(signer))
            .unwrap_or(false)
    }
}

fn execute_action(env: &Env, action: &GovernanceAction) -> Result<(), Error> {
    match action {
        GovernanceAction::TransferAdmin(target, new_admin) => {
            AdminPeerClient::new(env, target).transfer_admin(new_admin);
        }
        GovernanceAction::AcceptAdmin(target) => {
            AdminPeerClient::new(env, target).accept_admin();
        }
        GovernanceAction::SetCredentialRoot(issuer_registry, issuer_id, root, member_count) => {
            IssuerAdminPeerClient::new(env, issuer_registry).set_root(
                issuer_id,
                root,
                member_count,
            );
        }
        GovernanceAction::SetSanctionsRoot(issuer_registry, root) => {
            IssuerAdminPeerClient::new(env, issuer_registry).set_sanctions_root(root);
        }
        GovernanceAction::SetIssuerMetadataUri(issuer_registry, issuer_id, metadata_uri) => {
            IssuerAdminPeerClient::new(env, issuer_registry)
                .set_metadata_uri(issuer_id, metadata_uri);
        }
        GovernanceAction::SlashIssuer(
            issuer_registry,
            issuer_id,
            recipient,
            amount,
            reason_code,
        ) => {
            IssuerAdminPeerClient::new(env, issuer_registry).slash_issuer(
                issuer_id,
                recipient,
                amount,
                reason_code,
            );
        }
        GovernanceAction::SetIssuerReputation(issuer_registry, issuer_id, reputation) => {
            IssuerAdminPeerClient::new(env, issuer_registry).set_reputation(issuer_id, reputation);
        }
        GovernanceAction::SetRevocationRoot(issuer_registry, issuer_id, root) => {
            IssuerAdminPeerClient::new(env, issuer_registry).set_revocation_root(issuer_id, root);
        }
        GovernanceAction::SetPolicy(policy_registry, policy) => {
            PolicyAdminPeerClient::new(env, policy_registry).set_policy(policy);
        }
        GovernanceAction::AllowGate(nullifier_registry, gate) => {
            NullifierAdminPeerClient::new(env, nullifier_registry).allow_gate(gate);
        }
        GovernanceAction::RevokeGate(nullifier_registry, gate) => {
            NullifierAdminPeerClient::new(env, nullifier_registry).revoke_gate(gate);
        }
        GovernanceAction::Pause(target) => {
            PausablePeerClient::new(env, target).pause();
        }
        GovernanceAction::Unpause(target) => {
            PausablePeerClient::new(env, target).unpause();
        }
        GovernanceAction::FreezeVk(verifier) => {
            VerifierAdminPeerClient::new(env, verifier).freeze_vk();
        }
        GovernanceAction::UpdateConfig(
            signers,
            threshold,
            delay_ledgers,
            emergency_threshold,
            emergency_delay_ledgers,
        ) => {
            set_config(
                env,
                signers.clone(),
                *threshold,
                *delay_ledgers,
                *emergency_threshold,
                *emergency_delay_ledgers,
            )?;
        }
    }
    Ok(())
}

fn set_config(
    env: &Env,
    signers: Vec<Address>,
    threshold: u32,
    delay_ledgers: u32,
    emergency_threshold: u32,
    emergency_delay_ledgers: u32,
) -> Result<(), Error> {
    validate_config(env, &signers, threshold, emergency_threshold)?;

    if let Some(old_signers) = env
        .storage()
        .instance()
        .get::<_, Vec<Address>>(&DataKey::Signers)
    {
        for old_signer in old_signers.iter() {
            env.storage()
                .instance()
                .remove(&DataKey::Signer(old_signer));
        }
    }
    for signer in signers.iter() {
        env.storage()
            .instance()
            .set(&DataKey::Signer(signer), &true);
    }
    env.storage().instance().set(&DataKey::Signers, &signers);
    env.storage()
        .instance()
        .set(&DataKey::Threshold, &threshold);
    env.storage()
        .instance()
        .set(&DataKey::DelayLedgers, &delay_ledgers);
    env.storage()
        .instance()
        .set(&DataKey::EmergencyThreshold, &emergency_threshold);
    env.storage()
        .instance()
        .set(&DataKey::EmergencyDelayLedgers, &emergency_delay_ledgers);
    ConfigUpdated {
        threshold,
        delay_ledgers,
        emergency_threshold,
        emergency_delay_ledgers,
    }
    .publish(env);
    Ok(())
}

fn validate_config(
    _env: &Env,
    signers: &Vec<Address>,
    threshold: u32,
    emergency_threshold: u32,
) -> Result<(), Error> {
    let signer_count = signers.len();
    if signer_count == 0
        || threshold == 0
        || emergency_threshold == 0
        || threshold > signer_count
        || emergency_threshold > signer_count
    {
        return Err(Error::InvalidConfig);
    }
    let mut i = 0;
    while i < signer_count {
        let signer = signers.get(i).unwrap();
        let mut j = i + 1;
        while j < signer_count {
            if signer == signers.get(j).unwrap() {
                return Err(Error::InvalidConfig);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

fn require_signer(env: &Env, signer: &Address) -> Result<(), Error> {
    if !env
        .storage()
        .instance()
        .get(&DataKey::Signer(signer.clone()))
        .unwrap_or(false)
    {
        return Err(Error::NotSigner);
    }
    Ok(())
}

fn load_proposal(env: &Env, proposal_id: u32) -> Result<Proposal, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .ok_or(Error::MissingProposal)
}

fn set_with_ttl<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(
    env: &Env,
    key: &DataKey,
    value: &V,
) {
    env.storage().persistent().set(key, value);
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_ENTRY_TTL_LEDGERS,
        PERSISTENT_ENTRY_TTL_LEDGERS,
    );
}

fn next_proposal_id(env: &Env) -> Result<u32, Error> {
    env.storage()
        .instance()
        .get(&DataKey::NextProposalId)
        .ok_or(Error::NotInitialized)
}

fn get_u32(env: &Env, key: DataKey) -> Result<u32, Error> {
    env.storage()
        .instance()
        .get(&key)
        .ok_or(Error::NotInitialized)
}

fn is_emergency_action(action: &GovernanceAction) -> bool {
    matches!(
        action,
        GovernanceAction::Pause(..)
            | GovernanceAction::Unpause(..)
            | GovernanceAction::RevokeGate(..)
    )
}

mod test;
