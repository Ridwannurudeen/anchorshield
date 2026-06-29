import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function exists(relativePath) {
  return fs.existsSync(path.join(repo, relativePath));
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

const checks = [
  {
    name: "explicit approval marker present",
    pass: () => process.env.ANCHORSHIELD_MAINNET_APPROVED === "1",
    required:
      "Set ANCHORSHIELD_MAINNET_APPROVED=1 only after explicit user approval in chat.",
  },
  {
    name: "production ceremony transcript",
    pass: () => exists("ceremony/production/transcript.json"),
    required:
      "Add verified independent ceremony transcript at ceremony/production/transcript.json.",
  },
  {
    name: "external audit report",
    pass: () =>
      exists("audits/external-security-review.pdf") ||
      exists("audits/external-security-review.md"),
    required: "Add final external audit report under audits/.",
  },
  {
    name: "production admin governance config",
    pass: () => exists("deployments/admin-governance.mainnet.json"),
    required:
      "Add multisig/timelock admin config at deployments/admin-governance.mainnet.json.",
  },
  {
    name: "real anchor sandbox evidence",
    pass: () => exists("services/anchor/out/sandbox-run.json"),
    required:
      "Run the licensed anchor sandbox client and save services/anchor/out/sandbox-run.json.",
  },
  {
    name: "issuer roots generated",
    pass: () => {
      if (!exists("services/issuer/out/issuance.json")) {
        return false;
      }
      const issuance = readJson("services/issuer/out/issuance.json");
      return Boolean(
        issuance.roots?.credential_root &&
        issuance.roots?.sanctions_root &&
        issuance.roots?.revocation_root,
      );
    },
    required: "Run npm run ofac:sync and node services/issuer/issue.js.",
  },
  {
    name: "issuer roots published and verified",
    pass: () => {
      if (
        !exists("services/issuer/out/issuance.json") ||
        !exists("services/issuer/out/root-publish-report.json")
      ) {
        return false;
      }
      const issuance = readJson("services/issuer/out/issuance.json");
      const report = readJson("services/issuer/out/root-publish-report.json");
      return Boolean(
        report.verified === true &&
        report.roots?.credential_root === issuance.roots?.credential_root &&
        report.roots?.sanctions_root === issuance.roots?.sanctions_root &&
        report.roots?.revocation_root === issuance.roots?.revocation_root,
      );
    },
    required:
      "Publish roots with the deployed admin and verify services/issuer/out/root-publish-report.json.",
  },
  {
    name: "mainnet deployment not already present",
    pass: () => !exists("deployments/mainnet.json"),
    required:
      "If deployments/mainnet.json exists, verify this is a staged redeploy plan, not a first deploy.",
  },
];

let failed = 0;
for (const check of checks) {
  const ok = check.pass();
  console.log(`${ok ? "ok" : "BLOCKED"} - ${check.name}`);
  if (!ok) {
    failed += 1;
    console.log(`  required: ${check.required}`);
  }
}

if (failed > 0) {
  console.error(
    `\nmainnet preflight blocked: ${failed} requirement(s) unresolved`,
  );
  process.exit(1);
}

console.log("\nmainnet preflight OK");
