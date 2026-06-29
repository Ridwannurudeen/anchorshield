const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { rootStaleness, rotateRoots, syncOfac } = require("./ops");
const {
  credentialHash,
  decimal,
  merkleRoot,
  poseidon255,
} = require("./lib/zk-tree");

const sampleSdn = fs.readFileSync(path.join(__dirname, "data", "sample-sdn.csv"), "utf8");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "anchorshield-issuer-ops-"));
}

function copyFixtureData(dir) {
  fs.mkdirSync(dir, { recursive: true });
  for (const file of ["roster.json", "revocations.json", "sample-sdn.csv"]) {
    fs.copyFileSync(path.join(__dirname, "data", file), path.join(dir, file));
  }
}

async function main() {
  const dataDir = tmpDir();
  const outDir = tmpDir();
  copyFixtureData(dataDir);

  const sync = await syncOfac({
    dataDir,
    fetchImpl: async () => ({
      ok: true,
      async text() {
        return sampleSdn;
      },
    }),
  });
  assert.strictEqual(sync.records, 6);
  assert.ok(fs.existsSync(path.join(dataDir, "sdn.csv")));

  const { issuance, report } = rotateRoots({
    outDir,
    buildOptions: {
      rosterPath: path.join(dataDir, "roster.json"),
      revocationsPath: path.join(dataDir, "revocations.json"),
      dataDir,
    },
    now: new Date("2026-06-28T12:00:00Z"),
  });
  assert.strictEqual(report.clean_witnesses, 1);
  assert.strictEqual(report.blocked_users.length, 2);
  assert.ok(report.root_commands.every((command) => /--root \d+$/.test(command)));

  const clean = issuance.users.find((user) => user.user_id === "clean-demo-user");
  const credentialRoot = merkleRoot(
    credentialHash(clean.credential),
    BigInt(clean.merkle_index),
    clean.merkle_siblings,
  );
  assert.strictEqual(decimal(credentialRoot), issuance.roots.credential_root);
  const sanctionsRoot = merkleRoot(
    poseidon255([
      clean.proof_input.sanctions_low_value,
      clean.proof_input.sanctions_low_next,
    ]),
    BigInt(clean.proof_input.sanctions_low_index),
    clean.proof_input.sanctions_low_siblings,
  );
  assert.strictEqual(decimal(sanctionsRoot), issuance.roots.sanctions_root);
  const revocationRoot = merkleRoot(
    poseidon255([
      clean.proof_input.revocation_low_value,
      clean.proof_input.revocation_low_next,
    ]),
    BigInt(clean.proof_input.revocation_low_index),
    clean.proof_input.revocation_low_siblings,
  );
  assert.strictEqual(decimal(revocationRoot), issuance.roots.revocation_root);

  const stale = rootStaleness({
    issuancePath: path.join(outDir, "issuance.json"),
    maxAgeHours: 1,
    now: new Date("2026-06-28T14:00:01Z"),
  });
  assert.strictEqual(stale.stale, true);

  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(outDir, { recursive: true, force: true });
  console.log("issuer ops tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
