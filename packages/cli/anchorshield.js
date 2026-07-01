#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sdk = require("../sdk/src");

const repoRoot = path.resolve(__dirname, "..", "..");
const U32_MAX = 0xffffffff;

function usage() {
  console.log(`anchorshield <command>

Commands:
  compose --spec <policy.json> --out <dir>
  inspect-public --public <public.json>
  validate-action --input <input.json> --public <public.json> [--flow payment|rwa]
  soroban-args --cli-args <cli-args.json>
  events --file <compliance-events.json>
  disclosure verify --summary <summary.json>
  gate payment --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/payment]
  gate rwa --contract <id> --cli-args <cli-args.json> --input <input.json> [--network testnet] [--source-account <account>] [--out-dir .m6/invoke/rwa]`);
}

function args(argv) {
  const parsed = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value.startsWith("--")) {
      const key = value.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        parsed[key] = true;
      } else {
        parsed[key] = next;
        i += 1;
      }
    } else {
      parsed._.push(value);
    }
  }
  return parsed;
}

function required(options, name) {
  if (!options[name] || typeof options[name] !== "string") {
    throw new Error(`missing --${name}`);
  }
  return options[name];
}

function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function fileArg(name, value) {
  return `--${name} ${quote(value)}`;
}

function writeText(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
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

function parseOptionalU32(value, name) {
  if (value === undefined || value === null || value === "") return undefined;
  return parseU32(value, name);
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

function derivePolicyId(spec) {
  const hash = crypto
    .createHash("sha256")
    .update(
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
    )
    .digest();
  const id = hash.readUInt32BE(0) & 0x7fffffff;
  return id === 0 ? 1 : id;
}

function loadComposeSpec(options) {
  const raw = options.spec
    ? sdk.readJson(path.normalize(required(options, "spec")))
    : options;
  const name = raw.name;
  const policyShape = {
    name,
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
  const providedPolicyId = parseOptionalU32(raw.policy_id, "policy_id");
  const policyId =
    providedPolicyId === undefined
      ? derivePolicyId(policyShape)
      : providedPolicyId;
  return {
    ...policyShape,
    policy_id: policyId,
    once_per_account:
      raw.once_per_account === undefined
        ? true
        : parseBool(raw.once_per_account, "once_per_account"),
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

function generatedCargoToml({ name }) {
  return `[package]
name = "anchorshield-gate-${name.kebab}"
version = "0.0.0"
edition = "2021"
publish = false
rust-version = "1.89.0"

[workspace]
resolver = "2"

[lib]
crate-type = ["cdylib", "rlib"]
doctest = false

[dependencies]
soroban-sdk = { version = "=26.1.0" }

[dev-dependencies]
soroban-sdk = { version = "=26.1.0", features = ["testutils"] }
`;
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

function generatedTestRs({ name, spec }) {
  const repeatedCheck = spec.once_per_account
    ? `    assert!(h.gate.verified(&account));
    assert_eq!(h.gate.try_verify(&account), Err(Ok(Error::AlreadyVerified)));`
    : `    assert!(!h.gate.verified(&account));
    assert_eq!(h.gate.try_verify(&account), Ok(Ok(())));`;
  return `#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    testutils::{Address as _, Ledger},
    Address, Env,
};

struct Harness {
    env: Env,
    gate: ${name.pascal}GateClient<'static>,
    identity: MockIdentityVerifierClient<'static>,
}

#[derive(Clone)]
#[contracttype]
enum MockKey {
    Attestation(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
enum MockIdentityError {
    NotEligible = 1,
    Expired = 2,
}

#[contract]
struct MockIdentityVerifier;

#[contractimpl]
impl MockIdentityVerifier {
    pub fn attest(env: Env, account: Address, valid_until: u64) {
        env.storage()
            .persistent()
            .set(&MockKey::Attestation(account), &valid_until);
    }

    pub fn verify_identity(env: Env, account: Address) -> Result<(), MockIdentityError> {
        let valid_until: u64 = env
            .storage()
            .persistent()
            .get(&MockKey::Attestation(account))
            .ok_or(MockIdentityError::NotEligible)?;
        if env.ledger().timestamp() > valid_until {
            return Err(MockIdentityError::Expired);
        }
        Ok(())
    }

    pub fn attestation_expiry(env: Env, account: Address) -> Option<u64> {
        env.storage()
            .persistent()
            .get(&MockKey::Attestation(account))
    }
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let identity_id = env.register(MockIdentityVerifier, ());
    let identity = MockIdentityVerifierClient::new(&env, &identity_id);

    let gate_id = env.register(${name.pascal}Gate, ());
    let gate = ${name.pascal}GateClient::new(&env, &gate_id);
    gate.init(&admin, &identity_id);

    Harness {
        env,
        gate,
        identity,
    }
}

fn attest(h: &Harness, account: &Address, valid_until: u64) {
    h.identity.attest(account, &valid_until);
}

#[test]
fn attested_account_verifies() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    assert_eq!(h.gate.policy_id(), POLICY_ID);
    assert_eq!(h.gate.try_verify(&account), Ok(Ok(())));
${repeatedCheck}
}

#[test]
fn unattested_account_cannot_verify() {
    let h = setup();
    let account = Address::generate(&h.env);

    assert!(h.gate.try_verify(&account).is_err());
    assert!(!h.gate.verified(&account));
}

#[test]
fn expired_attestation_cannot_verify() {
    let h = setup();
    let account = Address::generate(&h.env);
    attest(&h, &account, 10_000);

    h.env.ledger().set_timestamp(10_001);
    assert!(h.gate.try_verify(&account).is_err());
    assert!(!h.gate.verified(&account));
}

#[test]
fn admin_transfer_matches_contract_pattern() {
    let h = setup();
    let original_admin = h.gate.admin().unwrap();
    let next_admin = Address::generate(&h.env);

    assert_eq!(h.gate.admin(), Some(original_admin));
    assert_eq!(h.gate.try_transfer_admin(&next_admin), Ok(Ok(())));
    assert_eq!(h.gate.admin(), Some(next_admin));
}
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

function generatedReadme({ name, spec, deployments, registerCommand }) {
  return `# ${name.pascal} AnchorShield Gate

Generated by \`anchorshield compose\` for policy \`${spec.policy_id}\`.

## Policy

Register \`policy.json\` with the live testnet policy registry:

\`\`\`bash
${registerCommand}
\`\`\`

The policy is enforced when the user calls \`identity_verifier.attest(..., policy_id=${spec.policy_id}, ...)\`.
This Model-A gate checks that the account has a live AnchorShield attestation
with \`verify_identity(account)\`; the downstream gate does not re-verify the
policy id.

## Build And Test

\`\`\`bash
cargo build --target wasm32v1-none --release
cargo test
\`\`\`

## Deploy To Testnet

\`\`\`bash
stellar contract deploy \\
  --wasm target/wasm32v1-none/release/anchorshield_gate_${name.snake}.wasm \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet
\`\`\`

Initialize with the deployed AnchorShield identity verifier:

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <ADMIN_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  init \\
  --admin <ADMIN_PUBLIC_KEY> \\
  --identity_verifier ${deployments.contracts.identity_verifier}
\`\`\`

## Attest Then Use

1. Build or collect a proof whose public signals match \`policy_id=${spec.policy_id}\`.
2. Call \`identity_verifier.attest\` on testnet using the identity verifier:
   \`${deployments.contracts.identity_verifier}\`.
3. Call the generated gate:

\`\`\`bash
stellar contract invoke \\
  --id <${name.snake.toUpperCase()}_GATE_CONTRACT_ID> \\
  --source-account <USER_SECRET_OR_PROFILE> \\
  --network testnet \\
  -- \\
  verify \\
  --account <USER_PUBLIC_KEY>
\`\`\`

If \`once_per_account\` is enabled, a second call by the same account is rejected
by this gate's own persistent state.
`;
}

function composePolicy(options) {
  const spec = loadComposeSpec(options);
  const name = sanitizeName(spec.name);
  const deployments = sdk.readJson(
    path.join(repoRoot, "apps", "web", "data", "deployments.json"),
  );
  const outDir = path.resolve(
    options.out
      ? path.normalize(options.out)
      : path.join(".m6", "compose", name.snake),
  );
  const gateDir = path.join(outDir, `gate_${name.snake}`);
  const srcDir = path.join(gateDir, "src");
  const policyFile = path.join(outDir, "policy.json");
  const registerCommand = [
    "stellar contract invoke",
    "--network testnet",
    "--source-account <ADMIN_SECRET_OR_PROFILE>",
    `--id ${deployments.contracts.policy_registry}`,
    "-- set_policy",
    fileArg("policy-file-path", "policy.json"),
  ].join(" ");

  fs.mkdirSync(srcDir, { recursive: true });
  sdk.writeJson(policyFile, policyJson(spec));
  writeText(path.join(outDir, "register-policy.txt"), `${registerCommand}\n`);
  writeText(path.join(gateDir, "Cargo.toml"), generatedCargoToml({ name }));
  writeText(path.join(srcDir, "lib.rs"), generatedLibRs({ name, spec }));
  writeText(
    path.join(srcDir, "test.rs"),
    generatedTestRs({ name, spec, srcDir }),
  );
  writeText(
    path.join(outDir, "Gate.jsx"),
    generatedGateJsx({ name, spec, deployments }),
  );
  writeText(
    path.join(outDir, "README.md"),
    generatedReadme({ name, spec, deployments, registerCommand }),
  );

  return {
    outDir,
    policyFile,
    gateDir,
    policy: policyJson(spec),
    registerPolicyCommand: registerCommand,
    oncePerAccount: spec.once_per_account,
    files: [
      policyFile,
      path.join(outDir, "register-policy.txt"),
      path.join(gateDir, "Cargo.toml"),
      path.join(srcDir, "lib.rs"),
      path.join(srcDir, "test.rs"),
      path.join(outDir, "Gate.jsx"),
      path.join(outDir, "README.md"),
    ],
  };
}

function buildStellarCommand(
  flow,
  contract,
  cliArgsFile,
  inputFile,
  network,
  sourceAccount,
  outDir,
) {
  const cliArgs = sdk.readJson(cliArgsFile);
  const input = sdk.readJson(inputFile);
  const parsed =
    flow === "payment"
      ? sdk.assertPaymentAction(input, cliArgs.pub_signals)
      : sdk.assertRwaAction(input, cliArgs.pub_signals);
  const hashName = flow === "payment" ? "packet_hash" : "terms_hash";
  const fnName = flow === "payment" ? "verify_and_pay" : "verify_and_transfer";
  const hashValue = parsed.packet_hash;
  const vkPath = path.join(outDir, "vk.json");
  const proofPath = path.join(outDir, "proof.json");
  const publicPath = path.join(outDir, "pub_signals.json");

  sdk.writeJson(vkPath, cliArgs.vk);
  sdk.writeJson(proofPath, cliArgs.proof);
  sdk.writeJson(
    publicPath,
    sdk.formatImplicitCliPubSignals(cliArgs.pub_signals),
  );

  return [
    "stellar contract invoke",
    `--network ${network}`,
    `--source-account ${sourceAccount}`,
    "--send no",
    `--id ${contract}`,
    `-- ${fnName}`,
    fileArg("vk-file-path", vkPath),
    fileArg("proof-file-path", proofPath),
    fileArg("pub_signals-file-path", publicPath),
    `--policy_id ${parsed.policy_id}`,
    `--asset_id ${parsed.asset_id}`,
    `--amount ${parsed.amount}`,
    `--recipient ${parsed.recipient}`,
    `--action_id ${parsed.action_id}`,
    `--${hashName} ${hashValue}`,
    `--epoch ${parsed.epoch}`,
  ].join(" ");
}

async function main() {
  const options = args(process.argv.slice(2));
  const [command, subcommand] = options._;

  if (!command || command === "help" || command === "--help") {
    usage();
    return;
  }

  if (command === "compose") {
    printJson(composePolicy(options));
    return;
  }

  if (command === "inspect-public") {
    printJson(
      sdk.parsePublicSignals(sdk.readJson(required(options, "public"))),
    );
    return;
  }

  if (command === "validate-action") {
    const input = sdk.readJson(required(options, "input"));
    const publicSignals = sdk.readJson(required(options, "public"));
    const flow =
      options.flow ||
      (input.action_type === sdk.RWA_ACTION_TYPE ? "rwa" : "payment");
    const parsed =
      flow === "rwa"
        ? sdk.assertRwaAction(input, publicSignals)
        : sdk.assertPaymentAction(input, publicSignals);
    printJson({
      flow,
      valid: true,
      action_id: parsed.action_id,
      policy_id: parsed.policy_id,
    });
    return;
  }

  if (command === "soroban-args") {
    const cliArgs = sdk.readJson(required(options, "cli-args"));
    printJson({
      vk: cliArgs.vk,
      proof: cliArgs.proof,
      pub_signals: sdk.formatSorobanPubSignals(cliArgs.pub_signals),
    });
    return;
  }

  if (command === "events") {
    const data = sdk.readJson(required(options, "file"));
    printJson({
      network: data.network,
      indexedAt: data.indexedAt,
      count: data.events.length,
      events: data.events.map((event) => ({
        flow: event.flow,
        outcome: event.outcome,
        policyId: event.policyId,
        actionId: event.actionId,
        txHash: event.txHash,
        piiOnChain: event.piiOnChain,
      })),
    });
    return;
  }

  if (command === "disclosure" && subcommand === "verify") {
    const summary = sdk.readJson(required(options, "summary"));
    if (!summary.verified) {
      throw new Error("disclosure summary is not verified");
    }
    printJson({
      verified: true,
      packetHash: summary.packetHash,
      paymentTx: summary.paymentTx,
      actionId: summary.actionId,
    });
    return;
  }

  if (
    command === "gate" &&
    (subcommand === "payment" || subcommand === "rwa")
  ) {
    const contract = required(options, "contract");
    const cliArgsFile = path.normalize(required(options, "cli-args"));
    const inputFile = path.normalize(required(options, "input"));
    const network = options.network || "testnet";
    const sourceAccount = options["source-account"] || "<SOURCE_ACCOUNT>";
    const outDir = path.normalize(
      options["out-dir"] || path.join(".m6", "invoke", subcommand),
    );
    console.log(
      buildStellarCommand(
        subcommand,
        contract,
        cliArgsFile,
        inputFile,
        network,
        sourceAccount,
        outDir,
      ),
    );
    return;
  }

  throw new Error(`unknown command ${options._.join(" ")}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
