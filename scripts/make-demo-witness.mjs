// Generate the operator's demo witnesses for the live demo, kept OUT of the public web artifact.
//
// The audit removed witness inputs from apps/web/data (they carry user_secret), and /console + /rwa
// now require a locally-uploaded witness JSON. This regenerates the two demo witnesses into a
// gitignored demo-witness/ dir so the operator can upload them during the demo. They are recovered
// from the last commit before they were removed from the web data, so they match the deployed
// on-chain roots and pass the gate. Run: `npm run demo:witness`.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repo, "demo-witness");

const witnesses = [
  { src: "apps/web/data/payment-input.json", out: "payment.json", page: "/console" },
  { src: "apps/web/data/rwa-input.json", out: "rwa.json", page: "/rwa" },
];

fs.mkdirSync(outDir, { recursive: true });

for (const { src, out, page } of witnesses) {
  const deletedIn = execFileSync(
    "git",
    ["log", "--diff-filter=D", "-1", "--format=%H", "--", src],
    { cwd: repo, encoding: "utf8" },
  ).trim();
  if (!deletedIn) {
    throw new Error(`could not locate the commit that removed ${src}`);
  }
  const content = execFileSync("git", ["show", `${deletedIn}~1:${src}`], {
    cwd: repo,
    encoding: "utf8",
  });
  JSON.parse(content); // fail loudly if the recovered file is not valid JSON
  const dest = path.join(outDir, out);
  fs.writeFileSync(dest, content);
  console.log(`wrote demo-witness/${out}  (recovered from ${deletedIn.slice(0, 7)}~1) — upload on ${page}`);
}

console.log(
  "\nThese witnesses are gitignored and never served by the site. Upload them locally during the demo to prove.",
);
