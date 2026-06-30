const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const {
  FIELD_PRIME,
  decimal,
  credentialHash,
  sanctionsKey,
  revocationKey,
  buildTree,
  buildExclusionTree,
} = require("./lib/zk-tree");
const {
  CREDENTIAL_DEPTH,
  EXCLUSION_DEPTH,
  buildIssuance,
  buildProofInput,
} = require("./issue");

const repo = path.resolve(__dirname, "..", "..");
const DEFAULT_STATE_PATH = path.join(__dirname, "out", "enrollments.json");
const DEFAULT_DEPLOYMENTS_PATH = path.join(
  repo,
  "deployments",
  "testnet-hardened.json",
);
const DEFAULT_TEMPLATE_PATH = path.join(
  repo,
  "testdata",
  "eligibility",
  "input.valid.json",
);
const WALLET_RE = /^G[A-Z2-7]{55}$/;

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
  });
  fs.renameSync(tmp, file);
}

function loadState(statePath) {
  if (!fs.existsSync(statePath)) {
    return {
      schema: "anchorshield.enrollment_state.v1",
      credential_depth: CREDENTIAL_DEPTH,
      users: [],
    };
  }
  const state = readJson(statePath);
  if (state.schema !== "anchorshield.enrollment_state.v1") {
    throw new Error("unsupported enrollment state schema");
  }
  if (state.credential_depth !== CREDENTIAL_DEPTH) {
    throw new Error("enrollment state credential depth mismatch");
  }
  if (!Array.isArray(state.users)) {
    throw new Error("enrollment state users must be an array");
  }
  return state;
}

function normalizeDecimalField(name, value) {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text)) {
    throw new Error(`${name} must be a decimal field element`);
  }
  const field = BigInt(text);
  if (field <= 0n || field >= FIELD_PRIME) {
    throw new Error(`${name} is outside the circuit field`);
  }
  return text;
}

function normalizeWallet(wallet) {
  const value = String(wallet || "")
    .trim()
    .toUpperCase();
  if (!WALLET_RE.test(value)) {
    throw new Error("wallet must be a Stellar public key");
  }
  return value;
}

function credentialFromKyc({ userCommitment, issuerId, kycCredential }) {
  return {
    user_commitment: normalizeDecimalField("user_commitment", userCommitment),
    issuer_id: String(issuerId),
    kyc_passed: String(kycCredential.kyc_passed),
    country: String(kycCredential.country),
    age: String(kycCredential.age),
    investor_type: "1",
    tx_limit: "1000",
    issued_at: "1",
    expires_at: "99",
  };
}

function baseRecordsFromIssuance(issuance) {
  return issuance.users.map((user) => ({
    source: "roster",
    wallet: null,
    credential: user.credential,
    blocked: user.blocked,
    blocked_reason: user.blocked_reason || null,
    revoked: Boolean(user.revoked),
  }));
}

function enrolledRecordsFromState(state) {
  return state.users.map((user) => ({
    source: "enrollment",
    wallet: user.wallet,
    credential: user.credential,
    blocked: false,
    blocked_reason: null,
    revoked: false,
  }));
}

function buildEnrollmentView({ state, issuance, template }) {
  const records = [
    ...baseRecordsFromIssuance(issuance),
    ...enrolledRecordsFromState(state),
  ];
  if (records.length > 2 ** CREDENTIAL_DEPTH) {
    throw new Error(
      `credential tree has ${records.length} users; depth ${CREDENTIAL_DEPTH} supports ${2 ** CREDENTIAL_DEPTH}`,
    );
  }

  const credentialLeaves = records.map((record) =>
    credentialHash(record.credential),
  );
  const credentialTree = buildTree(credentialLeaves, CREDENTIAL_DEPTH);
  const sanctionedKeys = issuance.users
    .filter((user) => user.blocked_reason === "ofac_match")
    .map((user) => sanctionsKey(user.credential));
  const revokedKeys = issuance.users
    .filter((user) => user.revoked)
    .map((user) => revocationKey(user.credential));
  const sanctionsTree = buildExclusionTree(sanctionedKeys, EXCLUSION_DEPTH);
  const revocationTree = buildExclusionTree(revokedKeys, EXCLUSION_DEPTH);

  return {
    records,
    credentialTree,
    sanctionsTree,
    revocationTree,
    roots: {
      credential_root: decimal(credentialTree.root),
      sanctions_root: decimal(sanctionsTree.root),
      revocation_root: decimal(revocationTree.root),
    },
    credentialForIndex(index) {
      const record = records[index];
      if (!record) {
        throw new Error(`credential index ${index} does not exist`);
      }
      return buildProofInput({
        template,
        credential: record.credential,
        index,
        credentialTree,
        sanctionsTree,
        revocationTree,
      });
    },
  };
}

function publicCredentialPayload({ view, index, wallet }) {
  const proofInput = view.credentialForIndex(index);
  return {
    wallet,
    issuer_id: proofInput.issuer_id,
    user_commitment: proofInput.user_commitment,
    credential_root: view.roots.credential_root,
    sanctions_root: view.roots.sanctions_root,
    revocation_root: view.roots.revocation_root,
    merkle_index: proofInput.merkle_index,
    merkle_siblings: proofInput.merkle_siblings,
    sanctions_low_value: proofInput.sanctions_low_value,
    sanctions_low_next: proofInput.sanctions_low_next,
    sanctions_low_index: proofInput.sanctions_low_index,
    sanctions_low_siblings: proofInput.sanctions_low_siblings,
    revocation_low_value: proofInput.revocation_low_value,
    revocation_low_next: proofInput.revocation_low_next,
    revocation_low_index: proofInput.revocation_low_index,
    revocation_low_siblings: proofInput.revocation_low_siblings,
    attributes: {
      kyc_passed: proofInput.kyc_passed,
      country: proofInput.country,
      age: proofInput.age,
      investor_type: proofInput.investor_type,
      tx_limit: proofInput.tx_limit,
      issued_at: proofInput.issued_at,
      expires_at: proofInput.expires_at,
    },
  };
}

function rootCommand({ deployments, issuerId, credentialRoot }) {
  return [
    "stellar",
    "contract",
    "invoke",
    "--id",
    deployments.contracts.issuer_registry,
    "--source",
    process.env.ANCHORSHIELD_STELLAR_SOURCE ||
      deployments.admin_source ||
      "anchorshield-admin",
    "--network",
    deployments.network,
    "--",
    "set_root",
    "--issuer_id",
    String(issuerId),
    "--root",
    String(credentialRoot),
  ];
}

function runCommand(program, args, { capture = false } = {}) {
  return spawnSync(program, args, {
    cwd: repo,
    encoding: capture ? "utf8" : undefined,
    stdio: capture ? "pipe" : "inherit",
    shell: false,
  });
}

function publishCredentialRoot({
  credentialRoot,
  issuerId,
  deployments,
  execute = process.env.ANCHORSHIELD_ENROLL_PUBLISH_ROOTS === "1",
  approved = process.env.ANCHORSHIELD_ROOT_PUBLISH_APPROVED === "1",
  runner = runCommand,
}) {
  const [program, ...args] = rootCommand({
    deployments,
    issuerId,
    credentialRoot,
  });
  const command = [program, ...args].join(" ");
  if (!execute) {
    return { mode: "dry-run", command };
  }
  if (!approved) {
    const error = new Error(
      "enrollment root publish blocked until ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1",
    );
    error.code = "ROOT_PUBLISH_FAILED";
    throw error;
  }
  const result = runner(program, args);
  if (result.error) {
    result.error.code = "ROOT_PUBLISH_FAILED";
    throw result.error;
  }
  if (result.status !== 0) {
    const error = new Error(
      `credential root publish failed with status ${result.status}`,
    );
    error.code = "ROOT_PUBLISH_FAILED";
    throw error;
  }
  return { mode: "executed", command };
}

function createEnrollmentStore({
  statePath = DEFAULT_STATE_PATH,
  deploymentsPath = DEFAULT_DEPLOYMENTS_PATH,
  templatePath = DEFAULT_TEMPLATE_PATH,
  issuance = buildIssuance(),
  now = () => new Date().toISOString(),
  rootPublisher = publishCredentialRoot,
} = {}) {
  const deployments = readJson(deploymentsPath);
  const template = readJson(templatePath);
  const issuerId = issuance.issuer_id;

  function loadView() {
    const state = loadState(statePath);
    return {
      state,
      view: buildEnrollmentView({ state, issuance, template }),
    };
  }

  function credential(wallet, { externalUserId } = {}) {
    const normalizedWallet = normalizeWallet(wallet);
    const { state, view } = loadView();
    const enrolledIndex = state.users.findIndex(
      (user) => user.wallet === normalizedWallet,
    );
    if (enrolledIndex === -1) {
      return null;
    }
    const enrolled = state.users[enrolledIndex];
    if (
      externalUserId &&
      enrolled.kyc_external_id &&
      enrolled.kyc_external_id !== externalUserId
    ) {
      const error = new Error("credential belongs to a different KYC session");
      error.code = "OWNER_MISMATCH";
      throw error;
    }
    return publicCredentialPayload({
      view,
      index: issuance.users.length + enrolledIndex,
      wallet: normalizedWallet,
    });
  }

  function enroll({ wallet, userCommitment, kycCredential }) {
    const normalizedWallet = normalizeWallet(wallet);
    const state = loadState(statePath);
    const credentialInput = credentialFromKyc({
      userCommitment,
      issuerId,
      kycCredential,
    });
    const existingIndex = state.users.findIndex(
      (user) => user.wallet === normalizedWallet,
    );
    if (existingIndex !== -1) {
      const existing = state.users[existingIndex];
      if (
        existing.credential.user_commitment !== credentialInput.user_commitment
      ) {
        const error = new Error(
          "wallet already enrolled with a different commitment",
        );
        error.code = "COMMITMENT_CONFLICT";
        throw error;
      }
      const view = buildEnrollmentView({ state, issuance, template });
      const rootPublish = rootPublisher({
        credentialRoot: view.roots.credential_root,
        issuerId,
        deployments,
      });
      return {
        credential: publicCredentialPayload({
          view,
          index: issuance.users.length + existingIndex,
          wallet: normalizedWallet,
        }),
        root_publish: rootPublish,
      };
    }

    const timestamp = now();
    const nextState = {
      ...state,
      issuer_id: String(issuerId),
      updated_at: timestamp,
      users: [
        ...state.users,
        {
          wallet: normalizedWallet,
          credential: credentialInput,
          kyc_external_id: String(kycCredential.external_user_id || ""),
          created_at: timestamp,
        },
      ],
    };
    const view = buildEnrollmentView({ state: nextState, issuance, template });
    writeJsonAtomic(statePath, nextState);
    const rootPublish = rootPublisher({
      credentialRoot: view.roots.credential_root,
      issuerId,
      deployments,
    });
    return {
      credential: publicCredentialPayload({
        view,
        index: issuance.users.length + state.users.length,
        wallet: normalizedWallet,
      }),
      root_publish: rootPublish,
    };
  }

  return {
    statePath,
    issuerId,
    credential,
    enroll,
    loadView,
  };
}

module.exports = {
  DEFAULT_STATE_PATH,
  normalizeWallet,
  credentialFromKyc,
  buildEnrollmentView,
  publicCredentialPayload,
  rootCommand,
  publishCredentialRoot,
  createEnrollmentStore,
};
