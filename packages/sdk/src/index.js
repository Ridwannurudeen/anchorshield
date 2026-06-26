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
    recipient: BigInt(parsed.recipient),
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

async function verifyProof({ verificationKey, proof, publicSignals }) {
  const snarkjs = require("snarkjs");
  return snarkjs.groth16.verify(verificationKey, normalizePublicSignals(publicSignals), proof);
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
  formatBindingProof,
  formatBindingPubSignals,
  formatBindingVerificationKey,
  formatImplicitCliPubSignals,
  formatSorobanPubSignals,
  generateProof,
  normalizePublicSignals,
  parsePublicSignals,
  readJson,
  stellarExpertTxUrl,
  verifyProof,
  writeJson,
};
