// Live validation of the KYC adapter against a real Sumsub sandbox applicant.
// Loads services/issuer/.env (gitignored), fetches the applicant, and prints the RAW verified
// fields next to the mapped credential — so the field shapes are confirmed against reality, not
// assumed. Run from WSL (open network; the bash sandbox cannot reach api.sumsub.com).
//
//   node services/issuer/kyc-validate.js <externalUserId>
//   (or set ANCHORSHIELD_KYC_EXTERNAL_ID)
//
// .env must contain (sandbox app token has the `sbx:` prefix; never commit this file):
//   SUMSUB_APP_TOKEN=sbx:...
//   SUMSUB_SECRET_KEY=...
//   SUMSUB_LEVEL_NAME=anchorshield-basic-kyc   (or your level)

const fs = require("fs");
const path = require("path");
const { createKycProvider } = require("./lib/kyc");

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
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
  loadEnv(path.join(__dirname, ".env"));
  const externalUserId =
    process.argv[2] || process.env.ANCHORSHIELD_KYC_EXTERNAL_ID;
  if (!externalUserId) {
    throw new Error(
      "usage: node services/issuer/kyc-validate.js <externalUserId>",
    );
  }
  const provider = createKycProvider();
  if (!provider) {
    throw new Error(
      "no Sumsub creds — set SUMSUB_APP_TOKEN and SUMSUB_SECRET_KEY in services/issuer/.env",
    );
  }
  console.log(
    `provider=${provider.provider} level=${provider.levelName} externalUserId=${externalUserId}`,
  );

  const applicant = await provider.getApplicant(externalUserId);
  const answer = applicant?.review?.reviewResult?.reviewAnswer;
  console.log("reviewAnswer:", answer);
  // Dump the raw shapes so the mapping is validated against reality (sandbox PII is fake).
  console.log("info keys:", Object.keys(applicant.info || {}));
  console.log("fixedInfo keys:", Object.keys(applicant.fixedInfo || {}));
  console.log(
    "info.country:",
    applicant.info?.country,
    "| info.dob:",
    applicant.info?.dob,
  );

  const credential = await provider.verifiedCredential(externalUserId);
  console.log("mapped credential:", JSON.stringify(credential));
  if (!credential) {
    console.log(
      "=> applicant is not GREEN yet; approve it in the sandbox, then re-run.",
    );
  }
}

main().catch((e) => {
  console.error("VALIDATION ERROR:", e.message);
  process.exit(1);
});
