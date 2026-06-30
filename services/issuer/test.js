// Parity + correctness tests for the issuer ZK tree core.
// Parity is checked against the committed fixtures that the DEPLOYED circuit
// produced, so a pass means roots built here will verify on-chain.

const assert = require("assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const {
  decimal,
  poseidon255,
  merkleRoot,
  credentialHash,
  sanctionsKey,
  buildTree,
  buildExclusionTree,
} = require("./lib/zk-tree");
const {
  parseLegacySdnCsv,
  parseLegacyAltCsv,
  screenRoster,
} = require("./lib/ofac");
const { buildIssuance } = require("./issue");
const { publishRoots } = require("./publish-roots");

const repo = path.resolve(__dirname, "..", "..");
const snarkjsCli = path.join(repo, "node_modules", "snarkjs", "build", "cli.cjs");
const CREDENTIAL_DEPTH = 2;
const EXCLUSION_DEPTH = 20;

// Known-good values from testdata/eligibility/{input.valid,public}.json.
const FIXTURE_INPUT = {
  user_secret: "123456789",
  issuer_id: "101",
  kyc_passed: "1",
  country: "566",
  age: "33",
  investor_type: "1",
  tx_limit: "1000",
  issued_at: "1",
  expires_at: "99",
};
const FIXTURE_CREDENTIAL_ROOT =
  "5634016141864094715384210201492604405167036651107015292298066213267081614816";
const FIXTURE_EMPTY_EXCLUSION_ROOT =
  "41464577938942170799849979391610616316800580958977068940122632529344071768263";

let passed = 0;
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function runSnark(args) {
  const result = spawnSync(process.execPath, [snarkjsCli, ...args], {
    cwd: repo,
    encoding: "utf8",
    timeout: 600000,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
}

check("empty exclusion tree root matches deployed fixture", () => {
  const tree = buildExclusionTree([], EXCLUSION_DEPTH);
  assert.strictEqual(decimal(tree.root), FIXTURE_EMPTY_EXCLUSION_ROOT);
});

check("single-credential tree root matches deployed fixture", () => {
  const leaf = credentialHash(FIXTURE_INPUT);
  const tree = buildTree([leaf], CREDENTIAL_DEPTH);
  assert.strictEqual(decimal(tree.root), FIXTURE_CREDENTIAL_ROOT);
});

check("credential witness re-derives the root via the circuit fold", () => {
  const leaves = [11n, 22n, 33n].map((v) => poseidon255([v, v]));
  const tree = buildTree(leaves, CREDENTIAL_DEPTH);
  for (let index = 0; index < leaves.length; index++) {
    const recomputed = merkleRoot(leaves[index], index, tree.siblings(index));
    assert.strictEqual(decimal(recomputed), decimal(tree.root));
  }
});

check(
  "populated exclusion tree yields a verifying non-membership witness",
  () => {
    const members = [100n, 5000n, 900000n];
    const tree = buildExclusionTree(members, EXCLUSION_DEPTH);
    const cleanKey = 7777n; // between 5000 and 900000, not a member
    const w = tree.witnessFor(cleanKey);
    const leaf = poseidon255([BigInt(w.low_value), BigInt(w.low_next)]);
    const recomputed = merkleRoot(leaf, BigInt(w.low_index), w.low_siblings);
    assert.strictEqual(decimal(recomputed), w.root);
    assert.strictEqual(w.root, decimal(tree.root));
    // The low leaf must actually bracket the key.
    assert.ok(BigInt(w.low_value) < cleanKey, "low_value < key");
    assert.ok(cleanKey < BigInt(w.low_next), "key < low_next");
  },
);

check("largest-key non-member uses the sentinel (next == 0)", () => {
  const tree = buildExclusionTree([100n, 5000n], EXCLUSION_DEPTH);
  const w = tree.witnessFor(99999n);
  assert.strictEqual(w.low_value, "5000");
  assert.strictEqual(w.low_next, "0");
});

check(
  "a listed (sanctioned) key cannot produce a non-membership witness",
  () => {
    const tree = buildExclusionTree([100n, 5000n, 900000n], EXCLUSION_DEPTH);
    assert.ok(tree.isMember(5000n));
    assert.throws(() => tree.witnessFor(5000n), /member/);
  },
);

check("OFAC SDN parser preserves the official 12-column legacy layout", () => {
  const sample = fs.readFileSync(
    path.join(__dirname, "data", "sample-sdn.csv"),
    "utf8",
  );
  const records = parseLegacySdnCsv(sample);
  const recordsWithEofMarker = parseLegacySdnCsv(`${sample}\u001a\n`);
  assert.strictEqual(records.length, 6);
  assert.strictEqual(recordsWithEofMarker.length, 6);
  assert.deepStrictEqual(records[2], {
    ent_num: "306",
    sdn_name: "BANCO NACIONAL DE CUBA",
    sdn_type: "",
    program: "CUBA",
    title: "",
    call_sign: "",
    vess_type: "",
    tonnage: "",
    grt: "",
    vess_flag: "",
    vess_owner: "",
    remarks: "a.k.a. 'BNC'.",
  });
});

check("OFAC screening hits exact SDN names and optional aliases", () => {
  const sdn = parseLegacySdnCsv(
    '306,"BANCO NACIONAL DE CUBA",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. \'BNC\'."\n',
  );
  const alt = parseLegacyAltCsv('306,220,"aka","NATIONAL BANK OF CUBA",-0- \n');
  const screened = screenRoster(
    [
      { id: "hit", legal_name: "Banco Nacional de Cuba" },
      { id: "alias", legal_name: "National Bank of Cuba" },
      { id: "miss", legal_name: "Anchor Demo Customer" },
    ],
    sdn,
    alt,
  );
  assert.strictEqual(screened[0].matched, true);
  assert.strictEqual(screened[0].matches[0].source, "SDN.CSV");
  assert.strictEqual(screened[1].matched, true);
  assert.strictEqual(screened[1].matches[0].source, "ALT.CSV");
  assert.strictEqual(screened[2].matched, false);
});

check(
  "issuer build emits populated roots, witnesses, and set-root commands",
  () => {
    const issuance = buildIssuance();
    const clean = issuance.users.find(
      (user) => user.user_id === "clean-demo-user",
    );
    const hit = issuance.users.find(
      (user) => user.user_id === "ofac-hit-banco-nacional-de-cuba",
    );
    const revoked = issuance.users.find(
      (user) => user.user_id === "revoked-demo-user",
    );

    assert.strictEqual(issuance.credential_depth, CREDENTIAL_DEPTH);
    assert.strictEqual(issuance.exclusion_depth, EXCLUSION_DEPTH);
    assert.strictEqual(hit.blocked, true);
    assert.strictEqual(hit.blocked_reason, "ofac_match");
    assert.strictEqual(revoked.blocked, true);
    assert.strictEqual(revoked.blocked_reason, "revoked_credential");
    assert.strictEqual(clean.blocked, false);
    assert.ok(clean.proof_input);
    assert.strictEqual(issuance.root_commands.length, 3);
    assert.match(
      issuance.root_commands[0],
      /set_root --issuer_id 101 --root \d+$/,
    );
    assert.match(issuance.root_commands[1], /set_sanctions_root --root \d+$/);
    assert.match(
      issuance.root_commands[2],
      /set_revocation_root --issuer_id 101 --root \d+$/,
    );

    const credentialRoot = merkleRoot(
      credentialHash(clean.credential),
      BigInt(clean.merkle_index),
      clean.merkle_siblings,
    );
    assert.strictEqual(decimal(credentialRoot), issuance.roots.credential_root);

    const sanctionsLeaf = poseidon255([
      clean.proof_input.sanctions_low_value,
      clean.proof_input.sanctions_low_next,
    ]);
    const sanctionsRoot = merkleRoot(
      sanctionsLeaf,
      BigInt(clean.proof_input.sanctions_low_index),
      clean.proof_input.sanctions_low_siblings,
    );
    assert.strictEqual(decimal(sanctionsRoot), issuance.roots.sanctions_root);

    const revocationLeaf = poseidon255([
      clean.proof_input.revocation_low_value,
      clean.proof_input.revocation_low_next,
    ]);
    const revocationRoot = merkleRoot(
      revocationLeaf,
      BigInt(clean.proof_input.revocation_low_index),
      clean.proof_input.revocation_low_siblings,
    );
    assert.strictEqual(decimal(revocationRoot), issuance.roots.revocation_root);

    const sanctionsTree = buildExclusionTree(
      [sanctionsKey(hit.credential)],
      EXCLUSION_DEPTH,
    );
    assert.throws(
      () => sanctionsTree.witnessFor(sanctionsKey(hit.credential)),
      /member/,
    );
  },
);

check(
  "root publisher is dry-run by default and approval-gated for execution",
  () => {
    const dryRun = publishRoots();
    assert.strictEqual(dryRun.mode, "dry-run");
    assert.strictEqual(dryRun.commands.length, 3);
    assert.throws(
      () => publishRoots({ execute: true, approved: false }),
      /approval/,
    );
  },
);

check(
  "clean issuer witness fullProve/verify passes deployed artifacts",
  () => {
    const issuance = buildIssuance();
    const clean = issuance.users.find(
      (user) => user.user_id === "clean-demo-user",
    );
    const proofDir = path.join(__dirname, "out", "test-proof");
    fs.mkdirSync(proofDir, { recursive: true });
    const inputPath = path.join(proofDir, "input.json");
    const proofPath = path.join(proofDir, "proof.json");
    const publicPath = path.join(proofDir, "public.json");
    writeJson(inputPath, clean.proof_input);
    runSnark([
      "groth16",
      "fullprove",
      inputPath,
      path.join(repo, "apps", "web", "proving", "eligibility.wasm"),
      path.join(repo, "apps", "web", "proving", "eligibility_final.zkey"),
      proofPath,
      publicPath,
    ]);
    runSnark([
      "groth16",
      "verify",
      path.join(repo, "apps", "web", "data", "verification_key.json"),
      publicPath,
      proofPath,
    ]);
    const publicSignals = readJson(publicPath);

    assert.strictEqual(publicSignals.length, 19);
    assert.strictEqual(publicSignals[0], issuance.roots.credential_root);
    assert.strictEqual(publicSignals[17], issuance.roots.sanctions_root);
    assert.strictEqual(publicSignals[18], issuance.roots.revocation_root);
  },
);

async function main() {
  for (const [name, fn] of checks) {
    await fn();
    passed += 1;
    console.log(`ok - ${name}`);
  }
  console.log(`\n${passed} checks passed`);
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
