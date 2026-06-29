import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { evaluatePublishPreflight } from "./publish-preflight.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function exists(relativePath) {
  return fs.existsSync(path.join(repo, relativePath));
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function rootPublishReady() {
  if (!exists("services/issuer/out/issuance.json")) {
    return false;
  }
  if (!exists("services/issuer/out/root-publish-report.json")) {
    return false;
  }
  const issuance = readJson("services/issuer/out/issuance.json");
  const report = readJson("services/issuer/out/root-publish-report.json");
  return (
    report.verified === true &&
    report.roots?.credential_root === issuance.roots?.credential_root &&
    report.roots?.sanctions_root === issuance.roots?.sanctions_root &&
    report.roots?.revocation_root === issuance.roots?.revocation_root
  );
}

function anchorEvidenceReady() {
  if (!exists("services/anchor/out/sandbox-run.json")) {
    return false;
  }
  const evidence = readJson("services/anchor/out/sandbox-run.json");
  return (
    evidence.schema === "anchorshield.anchor_sandbox_run.v1" &&
    evidence.mode === "real-anchor-sandbox" &&
    Boolean(evidence.price && evidence.quote && evidence.transaction)
  );
}

function checks() {
  const publish = evaluatePublishPreflight();
  return [
    {
      bucket: "B1",
      name: "issuer roots generated",
      ok: exists("services/issuer/out/issuance.json"),
      required: "Run npm run issuer:ops.",
    },
    {
      bucket: "B1",
      name: "issuer roots published and verified",
      ok: rootPublishReady(),
      required:
        "Import the deployed admin identity, run ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 npm run issuer:publish-roots -- --execute, then npm run issuer:publish-roots -- --verify.",
    },
    {
      bucket: "B2",
      name: "licensed anchor config present",
      ok: exists("services/anchor/anchor.config.json"),
      required:
        "Create services/anchor/anchor.config.json from the example using licensed anchor sandbox credentials.",
    },
    {
      bucket: "B2",
      name: "real anchor sandbox evidence",
      ok: anchorEvidenceReady(),
      required: "Run node services/anchor/sep-client.js.",
    },
    {
      bucket: "B3",
      name: "production ceremony transcript",
      ok: exists("ceremony/production/transcript.json"),
      required: "Add ceremony/production/transcript.json.",
    },
    {
      bucket: "B3",
      name: "external audit report",
      ok:
        exists("audits/external-security-review.md") ||
        exists("audits/external-security-review.pdf"),
      required: "Add audits/external-security-review.md or .pdf.",
    },
    {
      bucket: "B3",
      name: "mainnet governance config",
      ok: exists("deployments/admin-governance.mainnet.json"),
      required: "Add deployments/admin-governance.mainnet.json.",
    },
    {
      bucket: "B3",
      name: "mainnet approval marker",
      ok: process.env.ANCHORSHIELD_MAINNET_APPROVED === "1",
      required:
        "Set ANCHORSHIELD_MAINNET_APPROVED=1 only after explicit mainnet approval.",
    },
    {
      bucket: "B4",
      name: "npm publish preflight",
      ok: publish.ready,
      required: publish.blockers.join("; "),
    },
  ];
}

function main() {
  const results = checks();
  let failed = 0;
  for (const check of results) {
    console.log(
      `${check.ok ? "ok" : "BLOCKED"} - ${check.bucket} ${check.name}`,
    );
    if (!check.ok) {
      failed += 1;
      console.log(`  required: ${check.required}`);
    }
  }
  if (failed > 0) {
    console.error(
      `\nBucket B preflight blocked: ${failed} requirement(s) unresolved`,
    );
    process.exit(1);
  }
  console.log("\nBucket B preflight OK");
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}

export { anchorEvidenceReady, checks, rootPublishReady };
