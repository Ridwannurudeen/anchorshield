import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const StellarSdk = require("@stellar/stellar-sdk");
const sdk = require("../../packages/sdk/src");
const {
  DEFAULT_EVENTS_PATH,
  DEFAULT_STATE_PATH,
  createEnrollmentStore,
  rootCommand,
} = require("../issuer/enrollment-store");
const { buildProofInput } = require("../issuer/issue");
const { FIELD_PRIME, decimal, poseidon255 } = require("../issuer/lib/zk-tree");
const { convertG16Proof } = require("../../apps/web/assets/groth16-convert");

const repo = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const NETWORK_PASSPHRASE = StellarSdk.Networks.TESTNET;
const RPC_URL = "https://soroban-testnet.stellar.org";
const STELLAR_SIGNED_MESSAGE_PREFIX = "Stellar Signed Message:\n";
const CLEAN_USER_ID = "clean-demo-user";

const paths = {
  deployments: path.join(repo, "deployments", "testnet-hardened.json"),
  gatePaymentSpec: path.join(
    repo,
    "apps",
    "web",
    "data",
    "gate-payment-spec.json",
  ),
  paymentTemplate: path.join(
    repo,
    "testdata",
    "eligibility",
    "input.valid.json",
  ),
  roster: path.join(repo, "services", "issuer", "data", "roster.json"),
  snarkjsCli: path.join(repo, "node_modules", "snarkjs", "build", "cli.cjs"),
  verificationKey: path.join(
    repo,
    "apps",
    "web",
    "data",
    "verification_key.json",
  ),
  wasm: path.join(repo, "apps", "web", "proving", "eligibility.wasm"),
  zkey: path.join(repo, "apps", "web", "proving", "eligibility_final.zkey"),
};

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function assertFile(file, label) {
  if (!fs.existsSync(file)) {
    throw new Error(`${label} is missing at ${path.relative(repo, file)}`);
  }
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function digestField(value) {
  const digest = crypto
    .createHash("sha256")
    .update(JSON.stringify(value), "utf8")
    .digest();
  const field = BigInt(`0x${bytesToHex(digest)}`) % FIELD_PRIME;
  return (field === 0n ? 1n : field).toString(10);
}

function stellarMessageHash(message) {
  return crypto
    .createHash("sha256")
    .update(STELLAR_SIGNED_MESSAGE_PREFIX, "utf8")
    .update(String(message), "utf8")
    .digest();
}

function onboardingSecretMessage({ issuerId, address }) {
  return [
    "AnchorShield self-serve eligibility v1",
    "network:stellar-testnet",
    `issuer:${issuerId}`,
    `address:${address}`,
    "purpose:derive-user-secret",
  ].join("\n");
}

function signMessageLikeFreighter(keypair, message) {
  return keypair.sign(stellarMessageHash(message)).toString("base64");
}

function deriveWalletSecret({ keypair, issuerId }) {
  const address = keypair.publicKey();
  const message = onboardingSecretMessage({ issuerId, address });
  const signedMessage = signMessageLikeFreighter(keypair, message);
  const signature = bytesToHex(Buffer.from(signedMessage, "utf8"));
  const userSecret = digestField({
    domain: "anchorshield.wallet-secret.v1",
    address,
    issuer_id: String(issuerId),
    network: "testnet",
    message,
    signature,
  });
  return {
    address,
    issuerId: String(issuerId),
    message,
    userSecret,
    userCommitment: decimal(poseidon255([userSecret, issuerId])),
  };
}

function cleanDemoKycCredential({ wallet }) {
  const roster = readJson(paths.roster);
  const user = roster.users.find((entry) => entry.id === CLEAN_USER_ID);
  if (!user) {
    throw new Error(`${CLEAN_USER_ID} is missing from issuer roster`);
  }
  return {
    kyc_passed: user.kyc_passed,
    country: user.country,
    age: user.age,
    external_user_id: `wallet-e2e:${wallet}`,
  };
}

function dryRunRootPublisher({
  credentialRoot,
  issuerId,
  memberCount,
  deployments,
}) {
  return {
    mode: "dry-run",
    issuer_id: String(issuerId),
    credential_root: String(credentialRoot),
    member_count: memberCount,
    command: rootCommand({
      deployments,
      issuerId,
      credentialRoot,
      memberCount,
    }).join(" "),
  };
}

function assertBroadcastEnvironment() {
  if (process.env.ANCHORSHIELD_ROOT_PUBLISH_APPROVED !== "1") {
    throw new Error(
      "broadcast mode requires ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 for signer set_root",
    );
  }
  if (!process.env.SIGNER_TOKEN) {
    throw new Error("broadcast mode requires SIGNER_TOKEN for the root signer");
  }
}

function createEnrollmentContext({
  broadcast,
  now = () => new Date().toISOString(),
} = {}) {
  if (broadcast) {
    assertBroadcastEnvironment();
    process.env.STELLAR_NO_CACHE ||= "true";
    return {
      store: createEnrollmentStore({ now }),
      cleanup() {},
      statePath: DEFAULT_STATE_PATH,
      eventsPath: DEFAULT_EVENTS_PATH,
    };
  }

  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "anchorshield-wallet-e2e-"),
  );
  const statePath = path.join(tempDir, "enrollments.json");
  const eventsPath = path.join(tempDir, "credential-events.jsonl");
  return {
    store: createEnrollmentStore({
      statePath,
      eventsPath,
      now,
      rootPublisher: dryRunRootPublisher,
    }),
    cleanup() {
      fs.rmSync(tempDir, { recursive: true, force: true });
    },
    statePath,
    eventsPath,
  };
}

async function enrollWallet({ store, wallet, userCommitment }) {
  return store.enroll({
    wallet,
    userCommitment,
    kycCredential: cleanDemoKycCredential({ wallet }),
  });
}

function buildEnrolledPaymentInput({ store, wallet, userSecret }) {
  const template = readJson(paths.paymentTemplate);
  const { view } = store.loadView();
  const index = view.records.findIndex((record) => record.wallet === wallet);
  if (index === -1) {
    throw new Error("fresh wallet credential is missing from enrollment view");
  }
  return buildProofInput({
    template,
    credential: {
      ...view.records[index].credential,
      user_secret: userSecret,
    },
    index,
    credentialTree: view.credentialTree,
    sanctionsTree: view.sanctionsTree,
    revocationTree: view.revocationTree,
  });
}

async function proveLocally(input) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-proof-"));
  const inputPath = path.join(tempDir, "input.json");
  const proofPath = path.join(tempDir, "proof.json");
  const publicPath = path.join(tempDir, "public.json");
  try {
    writeJson(inputPath, input);
    const proved = spawnSync(
      process.execPath,
      [
        paths.snarkjsCli,
        "groth16",
        "fullprove",
        inputPath,
        paths.wasm,
        paths.zkey,
        proofPath,
        publicPath,
      ],
      { cwd: repo, encoding: "utf8", timeout: 600000 },
    );
    if (proved.error) {
      throw proved.error;
    }
    if (proved.status !== 0) {
      throw new Error(
        proved.stderr || proved.stdout || "snarkjs fullprove failed",
      );
    }
    const verified = spawnSync(
      process.execPath,
      [
        paths.snarkjsCli,
        "groth16",
        "verify",
        paths.verificationKey,
        publicPath,
        proofPath,
      ],
      { cwd: repo, encoding: "utf8", timeout: 600000 },
    );
    if (verified.error) {
      throw verified.error;
    }
    if (verified.status !== 0) {
      throw new Error(
        verified.stderr || verified.stdout || "snarkjs verify failed",
      );
    }
    const proof = readJson(proofPath);
    const publicSignals = readJson(publicPath);
    sdk.assertPaymentAction(input, publicSignals);
    return { proof, publicSignals, verified: true };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function buildPaymentInvocation({ proof, publicSignals, input }) {
  const deployments = readJson(paths.deployments);
  const specEntries = readJson(paths.gatePaymentSpec).entries;
  const proofAbc = convertG16Proof(proof);
  const contractArgs = sdk.paymentContractArgs({
    proof: proofAbc,
    publicSignals,
    action: input,
  });
  const spec = new StellarSdk.contract.Spec(specEntries);
  const scVals = spec.funcArgsToScVals("verify_and_pay", contractArgs);
  return {
    contractId: deployments.contracts.gate_payment,
    contractArgs,
    proofAbc,
    scVals,
    specEntries,
  };
}

function dryRunSubmit({ invocation }) {
  if (invocation.scVals.length !== 9) {
    throw new Error(
      `expected 9 verify_and_pay args, got ${invocation.scVals.length}`,
    );
  }
  return {
    mode: "dry-run",
    simulated: true,
    simulation: "local-soroban-args",
    contract_id: invocation.contractId,
    scval_count: invocation.scVals.length,
  };
}

async function fundFreshWallet(address) {
  const response = await fetch(`https://friendbot.stellar.org?addr=${address}`);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`friendbot funding failed (${response.status}): ${body}`);
  }
}

async function pollTransaction(server, txHash) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const result = await server.getTransaction(txHash);
    if (result.status === "SUCCESS") return result;
    if (result.status === "FAILED" || result.status === "ERROR") {
      throw new Error(
        result.resultXdr || `transaction ${result.status.toLowerCase()}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return { status: "PENDING" };
}

function replayRejected(error) {
  return /Nullifier|nullifier|used/i.test(error.message);
}

async function sendVerifyAndPay({
  keypair,
  invocation,
  expectReplayRejection = false,
}) {
  const server = new StellarSdk.rpc.Server(RPC_URL);
  const sourceAddress = keypair.publicKey();
  const account = await server.getAccount(sourceAddress);
  const contract = new StellarSdk.Contract(invocation.contractId);
  const transaction = new StellarSdk.TransactionBuilder(account, {
    fee: "1000000",
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call("verify_and_pay", ...invocation.scVals))
    .setTimeout(30)
    .build();
  const simulation = await server.simulateTransaction(transaction);
  if (simulation.error) {
    if (expectReplayRejection && replayRejected(new Error(simulation.error))) {
      return {
        replay_rejected: true,
        stage: "simulate",
        error: simulation.error,
      };
    }
    throw new Error(simulation.error);
  }
  const prepared = StellarSdk.rpc
    .assembleTransaction(transaction, simulation)
    .build();
  prepared.sign(keypair);
  const submitted = await server.sendTransaction(prepared);
  if (submitted.status === "ERROR") {
    const error = new Error(
      submitted.errorResultXdr || "transaction submission failed",
    );
    if (expectReplayRejection && replayRejected(error)) {
      return { replay_rejected: true, stage: "submit", error: error.message };
    }
    throw error;
  }
  const txHash = submitted.hash || submitted.txHash;
  const result = await pollTransaction(server, txHash);
  return { tx_hash: txHash, status: result.status, result };
}

async function runOnchainE2E({
  broadcast = process.env.ANCHORSHIELD_E2E_BROADCAST === "1",
} = {}) {
  for (const [label, file] of [
    ["eligibility wasm", paths.wasm],
    ["eligibility zkey", paths.zkey],
    ["verification key", paths.verificationKey],
    ["gate payment spec", paths.gatePaymentSpec],
    ["deployments", paths.deployments],
    ["snarkjs cli", paths.snarkjsCli],
  ]) {
    assertFile(file, label);
  }

  const keypair = StellarSdk.Keypair.random();
  const context = createEnrollmentContext({ broadcast });
  try {
    const wallet = keypair.publicKey();
    const derived = deriveWalletSecret({
      keypair,
      issuerId: context.store.issuerId,
    });
    if (broadcast) {
      await fundFreshWallet(wallet);
    }
    const enrolled = await enrollWallet({
      store: context.store,
      wallet,
      userCommitment: derived.userCommitment,
    });
    const input = buildEnrolledPaymentInput({
      store: context.store,
      wallet,
      userSecret: derived.userSecret,
    });
    const proved = await proveLocally(input);
    const invocation = buildPaymentInvocation({
      proof: proved.proof,
      publicSignals: proved.publicSignals,
      input,
    });
    const submit = broadcast
      ? await sendVerifyAndPay({ keypair, invocation })
      : dryRunSubmit({ invocation });
    const replay = broadcast
      ? await sendVerifyAndPay({
          keypair,
          invocation,
          expectReplayRejection: true,
        })
      : { replay_rejected: "not-run-in-dry-run" };

    return {
      mode: broadcast ? "broadcast" : "dry-run",
      wallet,
      kyc_gate:
        "bypassed: operator-direct GREEN credential from clean-demo-user attrs",
      root_publish: enrolled.root_publish,
      credential_root:
        proved.publicSignals[sdk.PUBLIC_SIGNAL_INDEX.credential_root],
      sanctions_root:
        proved.publicSignals[sdk.PUBLIC_SIGNAL_INDEX.sanctions_root],
      revocation_root:
        proved.publicSignals[sdk.PUBLIC_SIGNAL_INDEX.revocation_root],
      local_verify: proved.verified,
      submit,
      replay,
    };
  } finally {
    context.cleanup();
  }
}

async function main() {
  const result = await runOnchainE2E();
  console.log(JSON.stringify(result, null, 2));
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

export {
  buildEnrolledPaymentInput,
  buildPaymentInvocation,
  cleanDemoKycCredential,
  createEnrollmentContext,
  deriveWalletSecret,
  dryRunSubmit,
  enrollWallet,
  onboardingSecretMessage,
  runOnchainE2E,
};
