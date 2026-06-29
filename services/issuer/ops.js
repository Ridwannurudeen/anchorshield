const fs = require("fs");
const os = require("os");
const path = require("path");
const { buildIssuance } = require("./issue");
const { SDN_COLUMNS, parseLegacySdnCsv } = require("./lib/ofac");

const repo = path.resolve(__dirname, "..", "..");
const SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function rootDiff(previousRoots, nextRoots) {
  return Object.fromEntries(
    Object.entries(nextRoots).map(([name, value]) => [
      name,
      {
        previous: previousRoots?.[name] || null,
        current: value,
        changed: previousRoots?.[name] !== value,
      },
    ]),
  );
}

async function syncOfac({
  fetchImpl = fetch,
  url = SDN_URL,
  dataDir = path.join(__dirname, "data"),
} = {}) {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`failed to fetch SDN.CSV: HTTP ${response.status}`);
  }

  const text = await response.text();
  const records = parseLegacySdnCsv(text);
  if (records.length === 0) {
    throw new Error("SDN.CSV contained no records");
  }

  const sample = text
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .slice(0, 6)
    .join("\n");
  const sdnPath = path.join(dataDir, "sdn.csv");
  const samplePath = path.join(dataDir, "sample-sdn.csv");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(sdnPath, text.endsWith("\n") ? text : `${text}\n`);
  fs.writeFileSync(samplePath, `${sample}\n`);

  return {
    source: url,
    records: records.length,
    columns: SDN_COLUMNS,
    wrote: path.relative(repo, sdnPath),
    sample: path.relative(repo, samplePath),
  };
}

function rotateRoots({
  outDir = path.join(__dirname, "out"),
  issuancePath = path.join(outDir, "issuance.json"),
  now = new Date(),
  buildOptions = {},
} = {}) {
  const previous = fs.existsSync(issuancePath)
    ? readJson(issuancePath)
    : null;
  const issuance = {
    ...buildIssuance(buildOptions),
    generated_at: now.toISOString(),
  };
  writeJson(issuancePath, issuance);

  const cleanWitnesses = issuance.users.filter((user) => !user.blocked);
  const report = {
    schema: "anchorshield.issuer_rotation.v1",
    generated_at: issuance.generated_at,
    issuance: path.relative(repo, issuancePath),
    issuer_id: issuance.issuer_id,
    roots: issuance.roots,
    root_diff: rootDiff(previous?.roots, issuance.roots),
    ofac: issuance.ofac,
    clean_witnesses: cleanWitnesses.length,
    blocked_users: issuance.users.filter((user) => user.blocked).map((user) => ({
      user_id: user.user_id,
      reason: user.blocked_reason,
    })),
    root_commands: issuance.root_commands,
  };
  writeJson(path.join(outDir, "rotation-report.json"), report);
  return { issuance, report };
}

function rootStaleness({
  issuancePath = path.join(__dirname, "out", "issuance.json"),
  maxAgeHours = 24,
  now = new Date(),
} = {}) {
  if (!fs.existsSync(issuancePath)) {
    return {
      ok: false,
      stale: true,
      reason: "missing_issuance",
      max_age_hours: maxAgeHours,
    };
  }
  const issuance = readJson(issuancePath);
  const generatedAt = issuance.generated_at
    ? new Date(issuance.generated_at)
    : fs.statSync(issuancePath).mtime;
  const ageMs = now.getTime() - generatedAt.getTime();
  const maxAgeMs = maxAgeHours * 60 * 60 * 1000;
  return {
    ok: ageMs <= maxAgeMs,
    stale: ageMs > maxAgeMs,
    generated_at: generatedAt.toISOString(),
    age_hours: Number((ageMs / 60 / 60 / 1000).toFixed(3)),
    max_age_hours: maxAgeHours,
  };
}

async function runOnce({
  sync = false,
  rotate = true,
  maxAgeHours = 24,
  outDir = path.join(__dirname, "out"),
} = {}) {
  const status = {
    schema: "anchorshield.issuer_ops.v1",
    host: os.hostname(),
    ran_at: new Date().toISOString(),
  };
  if (sync) {
    status.ofac_sync = await syncOfac();
  }
  if (rotate) {
    status.rotation = rotateRoots({ outDir }).report;
  }
  status.root_staleness = rootStaleness({
    issuancePath: path.join(outDir, "issuance.json"),
    maxAgeHours,
  });
  writeJson(path.join(outDir, "ops-status.json"), status);
  return status;
}

function parseArgs(argv) {
  return argv.reduce(
    (acc, arg) => {
      if (arg === "--sync") acc.sync = true;
      if (arg === "--no-rotate") acc.rotate = false;
      if (arg.startsWith("--max-age-hours=")) {
        acc.maxAgeHours = Number(arg.split("=")[1]);
      }
      return acc;
    },
    { sync: false, rotate: true, maxAgeHours: 24 },
  );
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const status = await runOnce(options);
  console.log(JSON.stringify(status, null, 2));
  if (!status.root_staleness.ok) process.exit(1);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  rootDiff,
  rootStaleness,
  rotateRoots,
  runOnce,
  syncOfac,
};
