// Enrich the issuer roster with real KYC-verified attributes.
//
// For each roster user that has a `kyc_external_id`, this resolves the verified credential from
// the KYC provider (Sumsub) and bakes kyc_passed/country/age into the roster, plus a
// `kyc_provenance` record. After enrichment the roster carries the verified values, so the
// credential tree is reproducible WITHOUT live KYC access. Run from WSL (open network):
//   node services/issuer/kyc-enrich.js
// Requires SUMSUB_APP_TOKEN/SECRET in services/issuer/.env. Users without kyc_external_id are
// left as-is (synthetic).

const fs = require("fs");
const path = require("path");
const { createKycProvider } = require("./lib/kyc");

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    const key = t.slice(0, eq).trim();
    let value = t.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

async function main() {
  const rosterPath = path.join(__dirname, "data", "roster.json");
  loadEnv(path.join(__dirname, ".env"));
  const provider = createKycProvider();
  if (!provider) {
    throw new Error(
      "no KYC provider — set SUMSUB_APP_TOKEN/SECRET in services/issuer/.env",
    );
  }
  const roster = JSON.parse(fs.readFileSync(rosterPath, "utf8"));
  let enriched = 0;
  for (const user of roster.users) {
    if (!user.kyc_external_id) continue;
    const cred = await provider.verifiedCredential(user.kyc_external_id);
    if (!cred) {
      throw new Error(
        `applicant ${user.kyc_external_id} (user ${user.id}) is not GREEN`,
      );
    }
    user.kyc_passed = String(cred.kyc_passed);
    user.country = String(cred.country);
    user.age = String(cred.age);
    user.kyc_provenance = {
      provider: provider.provider,
      level: provider.levelName,
      applicant_id: cred.applicant_id,
      external_id: user.kyc_external_id,
      review_answer: cred.review_answer,
    };
    enriched += 1;
    console.log(
      `enriched ${user.id}: kyc_passed=${user.kyc_passed} country=${user.country} age=${user.age} (applicant ${cred.applicant_id})`,
    );
  }
  if (enriched === 0) {
    console.log("no roster users had kyc_external_id; nothing enriched");
    return;
  }
  fs.writeFileSync(rosterPath, `${JSON.stringify(roster, null, 2)}\n`);
  console.log(
    `wrote ${path.relative(path.join(__dirname, "..", ".."), rosterPath)} (${enriched} enriched)`,
  );
}

main().catch((e) => {
  console.error("ENRICH ERROR:", e.message);
  process.exit(1);
});
