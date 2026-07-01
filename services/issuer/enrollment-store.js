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
const { publishCredentialRootViaSigner } = require("../signer/client");

const repo = path.resolve(__dirname, "..", "..");
const DEFAULT_STATE_PATH =
  process.env.ANCHORSHIELD_ENROLLMENT_STATE_PATH ||
  path.join(__dirname, "out", "enrollments.json");
const DEFAULT_EVENTS_PATH =
  process.env.ANCHORSHIELD_CREDENTIAL_EVENTS_PATH ||
  path.join(__dirname, "out", "credential-events.jsonl");
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
  const fd = fs.openSync(tmp, "wx");
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

function appendCredentialEvent(eventsPath, event) {
  fs.mkdirSync(path.dirname(eventsPath), { recursive: true });
  fs.appendFileSync(
    eventsPath,
    `${JSON.stringify({
      schema: "anchorshield.credential_event.v1",
      ...event,
    })}\n`,
  );
}

function readCredentialEvents(eventsPath = DEFAULT_EVENTS_PATH) {
  if (!fs.existsSync(eventsPath)) return [];
  return fs
    .readFileSync(eventsPath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
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

function credentialFromTemplate({ userCommitment, issuerId, template }) {
  return {
    user_commitment: normalizeDecimalField("user_commitment", userCommitment),
    issuer_id: String(template.issuer_id || issuerId),
    kyc_passed: String(template.kyc_passed),
    country: String(template.country),
    age: String(template.age),
    investor_type: String(template.investor_type),
    tx_limit: String(template.tx_limit),
    issued_at: String(template.issued_at),
    expires_at: String(template.expires_at),
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
  const activeMemberCount = records.filter(
    (record) => !record.blocked && !record.revoked,
  ).length;

  return {
    records,
    activeMemberCount,
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
    anonymity_set_size: view.activeMemberCount,
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

function rootCommand({
  deployments,
  issuerId,
  credentialRoot,
  memberCount,
  source,
}) {
  const publishSource =
    source ||
    process.env.ANCHORSHIELD_STELLAR_SOURCE ||
    deployments.admin_source ||
    "anchorshield-admin";
  return [
    "stellar",
    "contract",
    "invoke",
    "--id",
    deployments.contracts.issuer_registry,
    "--source",
    publishSource,
    "--network",
    deployments.network,
    "--",
    "set_root",
    "--issuer_id",
    String(issuerId),
    "--root",
    String(credentialRoot),
    "--member_count",
    String(memberCount),
  ];
}

function withRootPublish(rootPublish, buildResult) {
  if (rootPublish && typeof rootPublish.then === "function") {
    return rootPublish.then(buildResult);
  }
  return buildResult(rootPublish);
}

function createEnrollmentStore({
  statePath = DEFAULT_STATE_PATH,
  eventsPath = DEFAULT_EVENTS_PATH,
  deploymentsPath = DEFAULT_DEPLOYMENTS_PATH,
  templatePath = DEFAULT_TEMPLATE_PATH,
  issuance = buildIssuance(),
  now = () => new Date().toISOString(),
  rootPublisher = publishCredentialRootViaSigner,
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

  const baseActiveMemberCount = issuance.users.filter(
    (user) => !user.blocked && !user.revoked,
  ).length;

  // Cheap count for health/metrics endpoints: enrolled records are never
  // blocked/revoked (see enrolledRecordsFromState), so this matches
  // buildEnrollmentView().activeMemberCount without rebuilding the trees.
  function activeMemberCount() {
    return baseActiveMemberCount + loadState(statePath).users.length;
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

  function credentialByCommitment(userCommitment) {
    const normalizedCommitment = normalizeDecimalField(
      "user_commitment",
      userCommitment,
    );
    const { state, view } = loadView();
    const enrolledIndex = state.users.findIndex(
      (user) => user.credential.user_commitment === normalizedCommitment,
    );
    if (enrolledIndex === -1) {
      return null;
    }
    return publicCredentialPayload({
      view,
      index: issuance.users.length + enrolledIndex,
      wallet: state.users[enrolledIndex].wallet || null,
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
        memberCount: view.activeMemberCount,
        deployments,
      });
      return withRootPublish(rootPublish, (resolvedRootPublish) => ({
        credential: publicCredentialPayload({
          view,
          index: issuance.users.length + existingIndex,
          wallet: normalizedWallet,
        }),
        root_publish: resolvedRootPublish,
      }));
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
    appendCredentialEvent(eventsPath, {
      type: "credential_enrolled",
      enrolled_at: timestamp,
      issuer_id: String(issuerId),
      credential: credentialInput,
      credential_index: issuance.users.length + state.users.length,
      credential_root: view.roots.credential_root,
      active_member_count: view.activeMemberCount,
      wallet_bound: true,
    });
    const rootPublish = rootPublisher({
      credentialRoot: view.roots.credential_root,
      issuerId,
      memberCount: view.activeMemberCount,
      deployments,
    });
    return withRootPublish(rootPublish, (resolvedRootPublish) => ({
      credential: publicCredentialPayload({
        view,
        index: issuance.users.length + state.users.length,
        wallet: normalizedWallet,
      }),
      root_publish: resolvedRootPublish,
    }));
  }

  function enrollBlind({ userCommitment, credentialTemplate, voucherDigest }) {
    const state = loadState(statePath);
    const credentialInput = credentialFromTemplate({
      userCommitment,
      issuerId,
      template: credentialTemplate,
    });
    const digest = String(voucherDigest || "");
    const replayIndex = state.users.findIndex(
      (user) => user.voucher_digest && user.voucher_digest === digest,
    );
    if (
      replayIndex !== -1 &&
      state.users[replayIndex].credential.user_commitment !==
        credentialInput.user_commitment
    ) {
      const error = new Error("credential voucher already used");
      error.code = "VOUCHER_REPLAY";
      throw error;
    }

    const existingIndex = state.users.findIndex(
      (user) =>
        user.credential.user_commitment === credentialInput.user_commitment,
    );
    if (existingIndex !== -1) {
      const existing = state.users[existingIndex];
      if (
        JSON.stringify(existing.credential) !== JSON.stringify(credentialInput)
      ) {
        const error = new Error(
          "commitment already enrolled with different attributes",
        );
        error.code = "COMMITMENT_CONFLICT";
        throw error;
      }
      const view = buildEnrollmentView({ state, issuance, template });
      const rootPublish = rootPublisher({
        credentialRoot: view.roots.credential_root,
        issuerId,
        memberCount: view.activeMemberCount,
        deployments,
      });
      return withRootPublish(rootPublish, (resolvedRootPublish) => ({
        credential: publicCredentialPayload({
          view,
          index: issuance.users.length + existingIndex,
          wallet: existing.wallet || null,
        }),
        root_publish: resolvedRootPublish,
      }));
    }

    const timestamp = now();
    const nextState = {
      ...state,
      issuer_id: String(issuerId),
      updated_at: timestamp,
      users: [
        ...state.users,
        {
          wallet: null,
          credential: credentialInput,
          kyc_external_id: "",
          voucher_digest: digest,
          created_at: timestamp,
        },
      ],
    };
    const view = buildEnrollmentView({ state: nextState, issuance, template });
    writeJsonAtomic(statePath, nextState);
    appendCredentialEvent(eventsPath, {
      type: "credential_enrolled",
      enrolled_at: timestamp,
      issuer_id: String(issuerId),
      credential: credentialInput,
      credential_index: issuance.users.length + state.users.length,
      credential_root: view.roots.credential_root,
      active_member_count: view.activeMemberCount,
      wallet_bound: false,
      voucher_digest: digest,
    });
    const rootPublish = rootPublisher({
      credentialRoot: view.roots.credential_root,
      issuerId,
      memberCount: view.activeMemberCount,
      deployments,
    });
    return withRootPublish(rootPublish, (resolvedRootPublish) => ({
      credential: publicCredentialPayload({
        view,
        index: issuance.users.length + state.users.length,
        wallet: null,
      }),
      root_publish: resolvedRootPublish,
    }));
  }

  return {
    statePath,
    issuerId,
    activeMemberCount,
    credential,
    credentialByCommitment,
    enroll,
    enrollBlind,
    loadView,
  };
}

module.exports = {
  DEFAULT_DEPLOYMENTS_PATH,
  DEFAULT_EVENTS_PATH,
  DEFAULT_STATE_PATH,
  DEFAULT_TEMPLATE_PATH,
  normalizeWallet,
  credentialFromKyc,
  credentialFromTemplate,
  buildEnrollmentView,
  publicCredentialPayload,
  rootCommand,
  createEnrollmentStore,
  readCredentialEvents,
};
