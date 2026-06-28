const fs = require("fs");
const path = require("path");
const {
  decimal,
  credentialHash,
  sanctionsKey,
  revocationKey,
  buildTree,
  buildExclusionTree,
} = require("./lib/zk-tree");
const {
  parseLegacySdnCsv,
  parseLegacyAltCsv,
  screenRoster,
} = require("./lib/ofac");

const repo = path.resolve(__dirname, "..", "..");
const CREDENTIAL_DEPTH = 2;
const EXCLUSION_DEPTH = 20;

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function readTextIfExists(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
}

function loadOfacData(dataDir = path.join(__dirname, "data")) {
  const liveSdnPath = path.join(dataDir, "sdn.csv");
  const sampleSdnPath = path.join(dataDir, "sample-sdn.csv");
  const sdnPath = fs.existsSync(liveSdnPath) ? liveSdnPath : sampleSdnPath;
  const altPath = path.join(dataDir, "alt.csv");

  return {
    sdnPath,
    altPath: fs.existsSync(altPath) ? altPath : null,
    sdnRecords: parseLegacySdnCsv(fs.readFileSync(sdnPath, "utf8")),
    altRecords: fs.existsSync(altPath)
      ? parseLegacyAltCsv(readTextIfExists(altPath))
      : [],
  };
}

function credentialForUser(user, issuerId) {
  return {
    user_secret: user.user_secret,
    issuer_id: issuerId,
    kyc_passed: user.kyc_passed,
    country: user.country,
    age: user.age,
    investor_type: user.investor_type,
    tx_limit: user.tx_limit,
    issued_at: user.issued_at,
    expires_at: user.expires_at,
  };
}

function stellarRootCommands({ issuerId, roots, deployments }) {
  const issuerRegistry = deployments.contracts.issuer_registry;
  const network = deployments.network;
  const source = "anchorshield-m0";
  return [
    `stellar contract invoke --id ${issuerRegistry} --source ${source} --network ${network} -- set_root --issuer_id ${issuerId} --root ${roots.credential_root}`,
    `stellar contract invoke --id ${issuerRegistry} --source ${source} --network ${network} -- set_sanctions_root --root ${roots.sanctions_root}`,
    `stellar contract invoke --id ${issuerRegistry} --source ${source} --network ${network} -- set_revocation_root --issuer_id ${issuerId} --root ${roots.revocation_root}`,
  ];
}

function buildProofInput({
  template,
  credential,
  index,
  credentialTree,
  sanctionsTree,
  revocationTree,
}) {
  const sanctionsWitness = sanctionsTree.witnessFor(sanctionsKey(credential));
  const revocationWitness = revocationTree.witnessFor(
    revocationKey(credential),
  );
  return {
    ...template,
    sanctions_root: sanctionsWitness.root,
    revocation_root: revocationWitness.root,
    ...credential,
    merkle_index: decimal(BigInt(index)),
    merkle_siblings: credentialTree.siblings(index),
    sanctions_low_value: sanctionsWitness.low_value,
    sanctions_low_next: sanctionsWitness.low_next,
    sanctions_low_index: sanctionsWitness.low_index,
    sanctions_low_siblings: sanctionsWitness.low_siblings,
    revocation_low_value: revocationWitness.low_value,
    revocation_low_next: revocationWitness.low_next,
    revocation_low_index: revocationWitness.low_index,
    revocation_low_siblings: revocationWitness.low_siblings,
  };
}

function buildIssuance({
  rosterPath = path.join(__dirname, "data", "roster.json"),
  revocationsPath = path.join(__dirname, "data", "revocations.json"),
  deploymentsPath = path.join(repo, "deployments", "testnet-hardened.json"),
  templatePath = path.join(repo, "apps", "web", "data", "payment-input.json"),
  dataDir = path.join(__dirname, "data"),
} = {}) {
  const roster = readJson(rosterPath);
  const revocations = readJson(revocationsPath);
  const deployments = readJson(deploymentsPath);
  const template = readJson(templatePath);
  const issuerId = roster.issuer_id;
  const users = roster.users;

  if (users.length > 2 ** CREDENTIAL_DEPTH) {
    throw new Error(
      `credential roster has ${users.length} users; deployed depth ${CREDENTIAL_DEPTH} supports ${2 ** CREDENTIAL_DEPTH}`,
    );
  }

  const ofac = loadOfacData(dataDir);
  const screened = screenRoster(users, ofac.sdnRecords, ofac.altRecords);
  const screenedByUser = new Map(
    screened.map((entry) => [entry.user_id, entry]),
  );
  const revokedUserIds = new Set(revocations.revoked_user_ids);
  const credentials = users.map((user) => credentialForUser(user, issuerId));
  const credentialLeaves = credentials.map(credentialHash);
  const credentialTree = buildTree(credentialLeaves, CREDENTIAL_DEPTH);
  const sanctionKeys = users
    .map((user, index) =>
      screenedByUser.get(user.id).matched
        ? sanctionsKey(credentials[index])
        : null,
    )
    .filter((key) => key !== null);
  const revokedKeys = users
    .map((user, index) =>
      revokedUserIds.has(user.id) ? revocationKey(credentials[index]) : null,
    )
    .filter((key) => key !== null);
  const sanctionsTree = buildExclusionTree(sanctionKeys, EXCLUSION_DEPTH);
  const revocationTree = buildExclusionTree(revokedKeys, EXCLUSION_DEPTH);
  const roots = {
    credential_root: decimal(credentialTree.root),
    sanctions_root: decimal(sanctionsTree.root),
    revocation_root: decimal(revocationTree.root),
  };

  const records = users.map((user, index) => {
    const credential = credentials[index];
    const screening = screenedByUser.get(user.id);
    const revoked = revokedUserIds.has(user.id);
    const base = {
      user_id: user.id,
      legal_name: user.legal_name,
      credential,
      credential_leaf: decimal(credentialLeaves[index]),
      merkle_index: decimal(BigInt(index)),
      merkle_siblings: credentialTree.siblings(index),
      sanctions_key: decimal(sanctionsKey(credential)),
      revocation_key: decimal(revocationKey(credential)),
      ofac: screening,
      revoked,
    };

    if (screening.matched || revoked) {
      return {
        ...base,
        blocked: true,
        blocked_reason: screening.matched ? "ofac_match" : "revoked_credential",
      };
    }

    return {
      ...base,
      blocked: false,
      proof_input: buildProofInput({
        template,
        credential,
        index,
        credentialTree,
        sanctionsTree,
        revocationTree,
      }),
    };
  });

  return {
    schema: "anchorshield.issuance.v1",
    issuer_id: issuerId,
    credential_depth: CREDENTIAL_DEPTH,
    exclusion_depth: EXCLUSION_DEPTH,
    ofac: {
      sdn_source: path.relative(repo, ofac.sdnPath),
      alt_source: ofac.altPath ? path.relative(repo, ofac.altPath) : null,
      sdn_records: ofac.sdnRecords.length,
      alt_records: ofac.altRecords.length,
      matched_users: screened
        .filter((entry) => entry.matched)
        .map((entry) => entry.user_id),
    },
    roots,
    root_commands: stellarRootCommands({ issuerId, roots, deployments }),
    users: records,
  };
}

function main() {
  const issuance = buildIssuance();
  const outPath = path.join(__dirname, "out", "issuance.json");
  writeJson(outPath, issuance);
  console.log(
    JSON.stringify(
      { wrote: path.relative(repo, outPath), roots: issuance.roots },
      null,
      2,
    ),
  );
  for (const command of issuance.root_commands) {
    console.log(command);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

module.exports = {
  CREDENTIAL_DEPTH,
  EXCLUSION_DEPTH,
  credentialForUser,
  buildProofInput,
  buildIssuance,
};
