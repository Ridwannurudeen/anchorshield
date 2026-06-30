// Generate operator demo witnesses for local upload, kept OUT of the public web artifact.
//
// The self-serve path no longer needs files, but these gitignored witnesses keep the operator
// fallback usable. They are generated from the current issuer tree and proving templates, so depth,
// roots, and commitment semantics cannot drift from the deployed circuit.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { buildIssuance } = require("../services/issuer/issue.js");

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repo, "demo-witness");
const flows = [
  {
    out: "payment.json",
    page: "/console",
    templatePath: path.join(
      repo,
      "testdata",
      "eligibility",
      "input.valid.json",
    ),
  },
  {
    out: "rwa.json",
    page: "/rwa",
    templatePath: path.join(repo, "testdata", "rwa", "input.valid.json"),
  },
];

fs.mkdirSync(outDir, { recursive: true });

for (const flow of flows) {
  const issuance = buildIssuance({ templatePath: flow.templatePath });
  const clean = issuance.users.find(
    (user) => user.user_id === "clean-demo-user",
  );
  if (!clean?.proof_input) {
    throw new Error(`clean-demo-user witness unavailable for ${flow.out}`);
  }
  const dest = path.join(outDir, flow.out);
  fs.writeFileSync(dest, `${JSON.stringify(clean.proof_input, null, 2)}\n`);
  console.log(`wrote demo-witness/${flow.out} - upload on ${flow.page}`);
}

console.log(
  "\nThese witnesses are gitignored and never served by the site. Upload them locally only for operator fallback demos.",
);
