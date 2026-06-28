const fs = require("fs");
const path = require("path");

const PUBLIC_SIGNAL_NAMES = [
  "credential_root",
  "packet_hash",
  "nullifier",
  "action_binding",
  "issuer_id",
  "policy_id",
  "kyc_required",
  "sanctions_required",
  "allowed_country",
  "min_age",
  "min_investor_type",
  "action_type",
  "asset_id",
  "amount",
  "recipient",
  "action_id",
  "epoch",
  "sanctions_root",
  "revocation_root",
];

const PUBLIC_SIGNAL_INDEX = Object.freeze(
  PUBLIC_SIGNAL_NAMES.reduce((acc, name, index) => {
    acc[name] = index;
    return acc;
  }, {}),
);

const ACTION_FIELDS = Object.freeze([
  "issuer_id",
  "policy_id",
  "kyc_required",
  "sanctions_required",
  "allowed_country",
  "min_age",
  "min_investor_type",
  "action_type",
  "asset_id",
  "amount",
  "recipient",
  "action_id",
  "epoch",
  "sanctions_root",
  "revocation_root",
]);

const PAYMENT_ACTION_TYPE = "0";
const RWA_ACTION_TYPE = "1";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function decimalString(value, label) {
  let normalized;
  if (typeof value === "bigint") {
    normalized = value.toString();
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer`);
    }
    normalized = String(value);
  } else if (typeof value === "string") {
    normalized = value;
  } else {
    throw new Error(`${label} must be a decimal string`);
  }

  if (!/^(0|[1-9][0-9]*)$/.test(normalized)) {
    throw new Error(`${label} must be a non-negative decimal string`);
  }
  return normalized;
}

function normalizePublicSignals(value) {
  let signals = value;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    signals = value.pub_signals || value.public_signals || value.publicSignals;
  }
  if (!Array.isArray(signals)) {
    throw new Error("public signals must be an array");
  }
  if (signals.length !== PUBLIC_SIGNAL_NAMES.length) {
    throw new Error(`expected ${PUBLIC_SIGNAL_NAMES.length} public signals, got ${signals.length}`);
  }
  return signals.map((signal, index) => {
    const raw = signal && typeof signal === "object" && "u256" in signal ? signal.u256 : signal;
    return decimalString(raw, PUBLIC_SIGNAL_NAMES[index]);
  });
}

function parsePublicSignals(publicSignals) {
  const normalized = normalizePublicSignals(publicSignals);
  return PUBLIC_SIGNAL_NAMES.reduce((acc, name, index) => {
    acc[name] = normalized[index];
    return acc;
  }, {});
}

function formatSorobanPubSignals(publicSignals) {
  return normalizePublicSignals(publicSignals).map((u256) => ({ u256 }));
}

function formatImplicitCliPubSignals(publicSignals) {
  return normalizePublicSignals(publicSignals);
}

function formatBindingPubSignals(publicSignals) {
  return normalizePublicSignals(publicSignals).map((signal) => BigInt(signal));
}

function assertActionMatchesPublicSignals(action, publicSignals) {
  const parsed = parsePublicSignals(publicSignals);
  const mismatches = [];
  for (const field of ACTION_FIELDS) {
    if (!(field in action)) {
      throw new Error(`missing action field ${field}`);
    }
    const expected = decimalString(action[field], field);
    if (parsed[field] !== expected) {
      mismatches.push(`${field}: expected ${expected}, got ${parsed[field]}`);
    }
  }
  if (mismatches.length > 0) {
    throw new Error(`public signal mismatch: ${mismatches.join("; ")}`);
  }
  return parsed;
}

function assertPaymentAction(action, publicSignals) {
  const parsed = assertActionMatchesPublicSignals(action, publicSignals);
  if (parsed.action_type !== PAYMENT_ACTION_TYPE) {
    throw new Error(`payment proof must use action_type ${PAYMENT_ACTION_TYPE}`);
  }
  return parsed;
}

function assertRwaAction(action, publicSignals) {
  const parsed = assertActionMatchesPublicSignals(action, publicSignals);
  if (parsed.action_type !== RWA_ACTION_TYPE) {
    throw new Error(`RWA proof must use action_type ${RWA_ACTION_TYPE}`);
  }
  return parsed;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function createProofRequest({ input, overrides = {} }) {
  const proofInput = {
    ...cloneJson(input),
    ...Object.fromEntries(
      Object.entries(overrides).map(([key, value]) => [key, decimalString(value, key)]),
    ),
  };
  return {
    input: proofInput,
    action: ACTION_FIELDS.reduce((acc, field) => {
      acc[field] = proofInput[field];
      return acc;
    }, {}),
  };
}

function hexBuffer(value, label) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} must be an even-length hex string`);
  }
  return Buffer.from(value, "hex");
}

function formatBindingProof(proof) {
  return {
    a: hexBuffer(proof.a, "proof.a"),
    b: hexBuffer(proof.b, "proof.b"),
    c: hexBuffer(proof.c, "proof.c"),
  };
}

function formatBindingVerificationKey(vk) {
  if (!Array.isArray(vk.ic)) {
    throw new Error("vk.ic must be an array");
  }
  return {
    alpha: hexBuffer(vk.alpha, "vk.alpha"),
    beta: hexBuffer(vk.beta, "vk.beta"),
    gamma: hexBuffer(vk.gamma, "vk.gamma"),
    delta: hexBuffer(vk.delta, "vk.delta"),
    ic: vk.ic.map((point, index) => hexBuffer(point, `vk.ic[${index}]`)),
  };
}

function cliArgsToBindingArgs(cliArgs) {
  return {
    vk: formatBindingVerificationKey(cliArgs.vk),
    proof: formatBindingProof(cliArgs.proof),
    pub_signals: formatBindingPubSignals(cliArgs.pub_signals),
  };
}

function buildPaymentInvokeArgs(cliArgs, action) {
  const binding = cliArgsToBindingArgs(cliArgs);
  const parsed = assertPaymentAction(action, cliArgs.pub_signals);
  return {
    ...binding,
    policy_id: Number(parsed.policy_id),
    asset_id: Number(parsed.asset_id),
    amount: BigInt(parsed.amount),
    recipient_id: BigInt(parsed.recipient),
    action_id: BigInt(parsed.action_id),
    packet_hash: BigInt(parsed.packet_hash),
    epoch: Number(parsed.epoch),
  };
}

function buildRwaInvokeArgs(cliArgs, action) {
  const binding = cliArgsToBindingArgs(cliArgs);
  const parsed = assertRwaAction(action, cliArgs.pub_signals);
  return {
    ...binding,
    policy_id: Number(parsed.policy_id),
    asset_id: Number(parsed.asset_id),
    amount: BigInt(parsed.amount),
    recipient: BigInt(parsed.recipient),
    action_id: BigInt(parsed.action_id),
    terms_hash: BigInt(parsed.packet_hash),
    epoch: Number(parsed.epoch),
  };
}

function stellarExpertTxUrl(network, txHash) {
  if (!/^[0-9a-fA-F]{64}$/.test(txHash)) {
    throw new Error("txHash must be a 64-character hex string");
  }
  return `https://stellar.expert/explorer/${network}/tx/${txHash}`;
}

async function generateProof({ input, wasmPath, zkeyPath }) {
  const snarkjs = require("snarkjs");
  return snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
}

async function prove({ input, wasmPath, zkeyPath, verificationKey }) {
  const generated = await generateProof({ input, wasmPath, zkeyPath });
  if (verificationKey) {
    const verified = await verifyProof({
      verificationKey,
      proof: generated.proof,
      publicSignals: generated.publicSignals,
    });
    if (!verified) {
      throw new Error("local Groth16 verification failed");
    }
  }
  return generated;
}

async function verifyProof({ verificationKey, proof, publicSignals }) {
  const snarkjs = require("snarkjs");
  return snarkjs.groth16.verify(verificationKey, normalizePublicSignals(publicSignals), proof);
}

function paymentContractArgs({ proof, publicSignals, action }) {
  const parsed = assertPaymentAction(action, publicSignals);
  return {
    proof: formatBindingProof(proof),
    pub_signals: formatBindingPubSignals(publicSignals),
    policy_id: Number(parsed.policy_id),
    asset_id: Number(parsed.asset_id),
    amount: BigInt(parsed.amount),
    recipient_id: BigInt(parsed.recipient),
    action_id: BigInt(parsed.action_id),
    packet_hash: BigInt(parsed.packet_hash),
    epoch: Number(parsed.epoch),
  };
}

async function submitPaymentProof({
  stellarSdk,
  freighterApi,
  rpcUrl = "https://soroban-testnet.stellar.org",
  networkPassphrase,
  contractId,
  sourceAddress,
  proof,
  publicSignals,
  action,
  specEntries,
  fee = "1000000",
  timeout = 30,
  pollIntervalMs = 2000,
  pollAttempts = 30,
}) {
  const StellarSdk = stellarSdk || require("@stellar/stellar-sdk");
  if (!freighterApi?.signTransaction) {
    throw new Error("Freighter signTransaction API is required");
  }
  if (!networkPassphrase) {
    throw new Error("networkPassphrase is required");
  }
  if (!contractId) {
    throw new Error("contractId is required");
  }
  if (!sourceAddress) {
    throw new Error("sourceAddress is required");
  }
  if (!Array.isArray(specEntries)) {
    throw new Error("generated gate-payment spec entries are required");
  }

  const server = new StellarSdk.rpc.Server(rpcUrl);
  const account = await server.getAccount(sourceAddress);
  const spec = new StellarSdk.contract.Spec(specEntries);
  const args = spec.funcArgsToScVals("verify_and_pay", paymentContractArgs({
    proof,
    publicSignals,
    action,
  }));
  const contract = new StellarSdk.Contract(contractId);
  const transaction = new StellarSdk.TransactionBuilder(account, {
    fee,
    networkPassphrase,
  })
    .addOperation(contract.call("verify_and_pay", ...args))
    .setTimeout(timeout)
    .build();
  const simulation = await server.simulateTransaction(transaction);
  if (simulation.error) {
    throw new Error(simulation.error);
  }
  const prepared = StellarSdk.rpc.assembleTransaction(transaction, simulation).build();
  const signed = await freighterApi.signTransaction(prepared.toXDR(), {
    networkPassphrase,
    address: sourceAddress,
  });
  if (signed.error) {
    throw new Error(signed.error.message || signed.error);
  }
  const signedXdr = signed.signedTxXdr || signed;
  const signedTransaction = StellarSdk.TransactionBuilder.fromXDR(
    signedXdr,
    networkPassphrase,
  );
  const submitted = await server.sendTransaction(signedTransaction);
  if (submitted.status === "ERROR") {
    throw new Error(submitted.errorResultXdr || "transaction submission failed");
  }
  const txHash = submitted.hash || submitted.txHash;
  for (let attempt = 0; attempt < pollAttempts; attempt += 1) {
    const result = await server.getTransaction(txHash);
    if (result.status === "SUCCESS") {
      return { txHash, status: result.status, result, submitted };
    }
    if (result.status === "FAILED" || result.status === "ERROR") {
      throw new Error(result.resultXdr || `transaction ${result.status.toLowerCase()}`);
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
  return { txHash, status: "PENDING", submitted };
}

module.exports = {
  ACTION_FIELDS,
  PAYMENT_ACTION_TYPE,
  PUBLIC_SIGNAL_INDEX,
  PUBLIC_SIGNAL_NAMES,
  RWA_ACTION_TYPE,
  assertActionMatchesPublicSignals,
  assertPaymentAction,
  assertRwaAction,
  buildPaymentInvokeArgs,
  buildRwaInvokeArgs,
  cliArgsToBindingArgs,
  createProofRequest,
  formatBindingProof,
  formatBindingPubSignals,
  formatBindingVerificationKey,
  formatImplicitCliPubSignals,
  formatSorobanPubSignals,
  generateProof,
  normalizePublicSignals,
  paymentContractArgs,
  parsePublicSignals,
  prove,
  readJson,
  stellarExpertTxUrl,
  submitPaymentProof,
  verifyProof,
  writeJson,
};
