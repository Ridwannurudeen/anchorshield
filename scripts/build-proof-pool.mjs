import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const isWin = process.platform === "win32";
const epochs = Array.from({ length: 12 }, (_, index) => 20 + index);
const workDir = path.join(repo, ".proof-pool", "payment");
const wasmPath = path.join(repo, "apps", "web", "proving", "eligibility.wasm");
const zkeyPath = path.join(
  repo,
  "apps",
  "web",
  "proving",
  "eligibility_final.zkey",
);
const vkeyPath = path.join(
  repo,
  "apps",
  "web",
  "data",
  "verification_key.json",
);
const inputPath = process.env.ANCHORSHIELD_PAYMENT_INPUT
  ? path.resolve(process.env.ANCHORSHIELD_PAYMENT_INPUT)
  : path.join(repo, "testdata", "eligibility", "input.valid.json");
const outputPath = process.env.ANCHORSHIELD_PROOF_POOL_OUT
  ? path.resolve(process.env.ANCHORSHIELD_PROOF_POOL_OUT)
  : path.join(repo, ".proof-pool", "payment-proof-pool.json");

function wslPath(file) {
  const resolved = path.resolve(file);
  const drive = resolved[0].toLowerCase();
  return `/mnt/${drive}${resolved.slice(2).replace(/\\/g, "/")}`;
}

function convert(proofPath, publicPath) {
  const args = [
    "run",
    "--quiet",
    "--manifest-path",
    path.join(repo, "tools", "groth16-json-converter", "Cargo.toml"),
    "--",
    proofPath,
    vkeyPath,
    publicPath,
  ];
  const native = spawnSync("cargo", args, {
    cwd: repo,
    encoding: "utf8",
  });
  if (native.status === 0) {
    return JSON.parse(native.stdout);
  }
  if (!isWin) {
    process.stdout.write(native.stdout);
    process.stderr.write(native.stderr);
    throw new Error(`converter failed with status ${native.status}`);
  }

  const wslArgs = [
    "-d",
    "Ubuntu-24.04",
    "--",
    "bash",
    "-lc",
    [
      `cd '${wslPath(repo)}'`,
      [
        "cargo run --quiet --manifest-path tools/groth16-json-converter/Cargo.toml --",
        `'${wslPath(proofPath)}'`,
        `'${wslPath(vkeyPath)}'`,
        `'${wslPath(publicPath)}'`,
      ].join(" "),
    ].join(" && "),
  ];
  return JSON.parse(execFileSync("wsl", wslArgs, { encoding: "utf8" }));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

fs.rmSync(workDir, { recursive: true, force: true });
fs.mkdirSync(workDir, { recursive: true });

const baseInput = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const entries = [];

for (const epoch of epochs) {
  const epochDir = path.join(workDir, String(epoch));
  fs.mkdirSync(epochDir, { recursive: true });
  const input = {
    ...baseInput,
    epoch: String(epoch),
  };
  const proofPath = path.join(epochDir, "proof.json");
  const publicPath = path.join(epochDir, "public.json");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath,
  );
  writeJson(proofPath, proof);
  writeJson(publicPath, publicSignals);
  const converted = convert(proofPath, publicPath);
  entries.push({
    epoch,
    proof: converted.proof,
    pub_signals: converted.pub_signals,
  });
  console.log(`proof pool epoch ${epoch}`);
}

writeJson(outputPath, {
  schema: "anchorshield.payment_proof_pool.v1",
  note: "Local-only pre-converted payment proofs for operator rehearsal. Do not serve this file from apps/web.",
  entries,
});
console.log(`wrote ${outputPath}`);
process.exit(0);
