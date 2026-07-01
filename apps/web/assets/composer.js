// Policy Composer — in-browser port of the `anchorshield compose` CLI generator.
// Mirrors packages/cli/anchorshield.js: same spec validation, same derived
// policy id, same policy.json shape, and the same generated gate templates.

const U32_MAX = 0xffffffff;

const state = { deployments: null };

const nameInput = document.getElementById("specName");
const issuerIdInput = document.getElementById("specIssuerId");
const allowedCountryInput = document.getElementById("specAllowedCountry");
const minAgeInput = document.getElementById("specMinAge");
const minInvestorTypeInput = document.getElementById("specMinInvestorType");
const minCredentialMembersInput = document.getElementById(
  "specMinCredentialMembers",
);
const kycRequiredInput = document.getElementById("specKycRequired");
const sanctionsRequiredInput = document.getElementById("specSanctionsRequired");
const oncePerAccountInput = document.getElementById("specOncePerAccount");
const composerStatus = document.getElementById("composerStatus");
const policyIdOut = document.getElementById("composerPolicyId");
const circuitOut = document.getElementById("composerCircuit");
const policyJsonOut = document.getElementById("policyJsonOut");
const registerCommandOut = document.getElementById("registerCommandOut");
const gateLibOut = document.getElementById("gateLibOut");
const gateJsxOut = document.getElementById("gateJsxOut");

function setStatus(label, mode = "") {
  if (!composerStatus) return;
  composerStatus.textContent = label;
  composerStatus.className = mode ? `pill ${mode}` : "pill";
}

function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function fileArg(name, value) {
  return `--${name} ${quote(value)}`;
}

function sanitizeName(name) {
  if (typeof name !== "string" || !name.trim()) {
    throw new Error("policy name is required");
  }
  const snake = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!snake || !/^[a-z]/.test(snake)) {
    throw new Error(
      "policy name must contain a letter and start with a letter after normalization",
    );
  }
  const kebab = snake.replace(/_/g, "-");
  const pascal = snake
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
  return { snake, kebab, pascal };
}

function parseBool(value, name) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value === "true" || value === "1") return true;
    if (value === "false" || value === "0") return false;
  }
  throw new Error(`${name} must be a boolean`);
}

function parseU32(value, name) {
  const parsed =
    typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > U32_MAX) {
    throw new Error(`${name} must be a u32`);
  }
  return parsed;
}

function normalizeCircuitId(value) {
  if (typeof value !== "string") {
    throw new Error("circuit_id must be a 32-byte hex string");
  }
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("circuit_id must be a 32-byte hex string");
  }
  return hex.toLowerCase();
}

async function derivePolicyId(spec) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      JSON.stringify({
        name: spec.name,
        issuer_id: spec.issuer_id,
        kyc_required: spec.kyc_required,
        sanctions_required: spec.sanctions_required,
        allowed_country: spec.allowed_country,
        min_age: spec.min_age,
        min_investor_type: spec.min_investor_type,
        min_credential_members: spec.min_credential_members,
        circuit_id: spec.circuit_id,
        circuit_version: spec.circuit_version,
      }),
    ),
  );
  const id = new DataView(digest).getUint32(0, false) & 0x7fffffff;
  return id === 0 ? 1 : id;
}

async function loadComposeSpec(raw) {
  const policyShape = {
    name: raw.name,
    issuer_id: parseU32(raw.issuer_id, "issuer_id"),
    kyc_required: parseBool(raw.kyc_required, "kyc_required"),
    sanctions_required: parseBool(raw.sanctions_required, "sanctions_required"),
    allowed_country: parseU32(raw.allowed_country, "allowed_country"),
    min_age: parseU32(raw.min_age, "min_age"),
    min_investor_type: parseU32(raw.min_investor_type, "min_investor_type"),
    min_credential_members: parseU32(
      raw.min_credential_members,
      "min_credential_members",
    ),
    circuit_id: normalizeCircuitId(raw.circuit_id),
    circuit_version: parseU32(raw.circuit_version, "circuit_version"),
  };
  return {
    ...policyShape,
    policy_id: await derivePolicyId(policyShape),
    once_per_account: parseBool(raw.once_per_account, "once_per_account"),
  };
}

function policyJson(spec) {
  return {
    policy_id: spec.policy_id,
    issuer_id: spec.issuer_id,
    circuit_id: spec.circuit_id,
    circuit_version: spec.circuit_version,
    kyc_required: spec.kyc_required,
    sanctions_required: spec.sanctions_required,
    allowed_country: spec.allowed_country,
    min_age: spec.min_age,
    min_investor_type: spec.min_investor_type,
    min_credential_members: spec.min_credential_members,
  };
}

function registerPolicyCommand(deployments) {
  return [
    "stellar contract invoke",
    "--network testnet",
    "--source-account <ADMIN_SECRET_OR_PROFILE>",
    `--id ${deployments.contracts.policy_registry}`,
    "-- set_policy",
    fileArg("policy-file-path", "policy.json"),
  ].join(" ");
}

function generatedLibRs({ name, spec }) {
  const errorName = spec.once_per_account ? "AlreadyVerified" : "AlreadyUsed";
  return `#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Env,
};

pub const POLICY_ID: u32 = ${spec.policy_id};
pub const ONCE_PER_ACCOUNT: bool = ${spec.once_per_account};

#[contractclient(name = "IdentityVerifierPeerClient")]
pub trait IdentityVerifierPeer {
    fn verify_identity(env: Env, account: Address);
    fn attestation_expiry(env: Env, account: Address) -> Option<u64>;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    ${errorName} = 3,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    IdentityVerifier,
    Verified(Address),
}

#[contractevent(topics = ["anchorshield", "verified"])]
struct AccountVerified {
    account: Address,
    policy_id: u32,
    attestation_expiry: u64,
}

#[contractevent(topics = ["anchorshield", "admin_transferred"])]
struct AdminTransferred {
    old_admin: Address,
    new_admin: Address,
}

#[contract]
pub struct ${name.pascal}Gate;

#[contractimpl]
impl ${name.pascal}Gate {
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

    pub fn policy_id(_env: Env) -> u32 {
        POLICY_ID
    }

    pub fn verified(env: Env, account: Address) -> bool {
        if !ONCE_PER_ACCOUNT {
            return false;
        }
        env.storage()
            .persistent()
            .get(&DataKey::Verified(account))
            .unwrap_or(false)
    }

    pub fn verify(env: Env, account: Address) -> Result<(), Error> {
        account.require_auth();
        let key = DataKey::Verified(account.clone());
        if ONCE_PER_ACCOUNT && env.storage().persistent().has(&key) {
            return Err(Error::${errorName});
        }

        let identity_verifier = config_addr(&env, DataKey::IdentityVerifier)?;
        let identity = IdentityVerifierPeerClient::new(&env, &identity_verifier);
        identity.verify_identity(&account);
        let attestation_expiry = identity.attestation_expiry(&account).unwrap_or(0);

        if ONCE_PER_ACCOUNT {
            env.storage().persistent().set(&key, &true);
        }
        AccountVerified {
            account: account.clone(),
            policy_id: POLICY_ID,
            attestation_expiry,
        }
        .publish(&env);
        on_verified(&env, &account, attestation_expiry);
        Ok(())
    }
}

fn on_verified(_env: &Env, _account: &Address, _attestation_expiry: u64) {}

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
`;
}

function generatedGateJsx({ name, spec, deployments }) {
  return `import React from "react";
import { AnchorShieldGate, useAnchorShield } from "@anchorshield/sdk/react";

export const ANCHORSHIELD_POLICY_ID = ${spec.policy_id};
export const ANCHORSHIELD_CONTRACTS = {
  identityVerifier: "${deployments.contracts.identity_verifier}",
  policyRegistry: "${deployments.contracts.policy_registry}",
  generatedGate: "<DEPLOYED_${name.snake.toUpperCase()}_GATE_CONTRACT_ID>",
};

export function ${name.pascal}Gate({ children, onUse }) {
  const shield = useAnchorShield({
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  });

  async function handleUse() {
    const account = shield.address || (await shield.connect());
    const request = {
      account,
      policyId: ANCHORSHIELD_POLICY_ID,
      gateContractId: ANCHORSHIELD_CONTRACTS.generatedGate,
      identityVerifier: ANCHORSHIELD_CONTRACTS.identityVerifier,
    };
    return onUse ? onUse(request) : request;
  }

  return (
    <button
      type="button"
      disabled={shield.status === "connecting"}
      onClick={handleUse}
    >
      {children || "Use AnchorShield-gated action"}
    </button>
  );
}

export function ${name.pascal}PerActionProofButton({
  action,
  proof,
  publicSignals,
  specEntries,
  onSuccess,
  rpcUrl = "https://soroban-testnet.stellar.org",
  networkPassphrase = "Test SDF Network ; September 2015",
  contractId = "${deployments.contracts.gate_payment}",
}) {
  return (
    <AnchorShieldGate
      rpcUrl={rpcUrl}
      networkPassphrase={networkPassphrase}
      contractId={contractId}
      action={{ ...action, policy_id: ANCHORSHIELD_POLICY_ID }}
      proof={proof}
      publicSignals={publicSignals}
      specEntries={specEntries}
      onSuccess={onSuccess}
      pendingLabel="Submitting AnchorShield proof"
    >
      Submit AnchorShield proof
    </AnchorShieldGate>
  );
}
`;
}

async function ensureDeployments() {
  if (!state.deployments) {
    const response = await fetch("./data/deployments.json");
    if (!response.ok) {
      throw new Error("failed to load ./data/deployments.json");
    }
    state.deployments = await response.json();
  }
  return state.deployments;
}

function readSpecForm(deployments) {
  return {
    name: nameInput.value,
    issuer_id: issuerIdInput.value,
    kyc_required: kycRequiredInput.checked,
    sanctions_required: sanctionsRequiredInput.checked,
    allowed_country: allowedCountryInput.value,
    min_age: minAgeInput.value,
    min_investor_type: minInvestorTypeInput.value,
    min_credential_members: minCredentialMembersInput.value,
    circuit_id: deployments.circuit.id,
    circuit_version: deployments.circuit.version,
    once_per_account: oncePerAccountInput.checked,
  };
}

let renderSequence = 0;

async function renderComposition() {
  const sequence = ++renderSequence;
  try {
    const deployments = await ensureDeployments();
    const spec = await loadComposeSpec(readSpecForm(deployments));
    if (sequence !== renderSequence) return;
    const name = sanitizeName(spec.name);

    policyJsonOut.textContent = JSON.stringify(policyJson(spec), null, 2);
    registerCommandOut.textContent = registerPolicyCommand(deployments);
    gateLibOut.textContent = generatedLibRs({ name, spec });
    gateJsxOut.textContent = generatedGateJsx({ name, spec, deployments });
    policyIdOut.textContent = String(spec.policy_id);
    circuitOut.textContent = `${deployments.circuit.id.slice(0, 8)}… v${deployments.circuit.version}`;
    circuitOut.title = deployments.circuit.id;
    setStatus(`composed gate_${name.snake}`, "success");
  } catch (error) {
    if (sequence !== renderSequence) return;
    setStatus(error.message, "error");
  }
}

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copy);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      button.textContent = "copied";
    } catch {
      button.textContent = "copy failed";
    }
    setTimeout(() => {
      button.textContent = "copy";
    }, 1600);
  });
});

[
  nameInput,
  issuerIdInput,
  allowedCountryInput,
  minAgeInput,
  minInvestorTypeInput,
  minCredentialMembersInput,
  kycRequiredInput,
  sanctionsRequiredInput,
  oncePerAccountInput,
].forEach((input) => {
  input?.addEventListener("input", () => {
    renderComposition();
  });
});

window.addEventListener("load", () => {
  renderComposition();
});
