import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const snarkjsCli = path.join(
  repo,
  "node_modules",
  "snarkjs",
  "build",
  "cli.cjs",
);
const timeoutMs = Number(
  process.env.ANCHORSHIELD_BENCHMARK_TIMEOUT_MS || 600000,
);

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function writeJson(relativePath, value) {
  const file = path.join(repo, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function measureNodeProof(flow, inputPath) {
  const outDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `anchorshield-${flow}-`),
  );
  const proofPath = path.join(outDir, "proof.json");
  const publicPath = path.join(outDir, "public.json");
  const start = performance.now();
  runSnark([
    "groth16",
    "fullprove",
    path.join(repo, inputPath),
    path.join(repo, "apps", "web", "proving", "eligibility.wasm"),
    path.join(repo, "apps", "web", "proving", "eligibility_final.zkey"),
    proofPath,
    publicPath,
  ]);
  const proofMs = Math.round(performance.now() - start);
  const verifyStart = performance.now();
  runSnark([
    "groth16",
    "verify",
    path.join(repo, "apps", "web", "data", "verification_key.json"),
    publicPath,
    proofPath,
  ]);
  const verifyMs = Math.round(performance.now() - verifyStart);
  const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
  fs.rmSync(outDir, { recursive: true, force: true });
  return {
    flow,
    input: inputPath,
    proof_ms: proofMs,
    verify_ms: verifyMs,
    public_signals: publicSignals.length,
    credential_root: publicSignals[0],
    sanctions_root: publicSignals[17],
    revocation_root: publicSignals[18],
  };
}

function runSnark(args) {
  const result = spawnSync(process.execPath, [snarkjsCli, ...args], {
    cwd: repo,
    encoding: "utf8",
    timeout: timeoutMs,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `${args.join(" ")} failed: ${result.stderr || result.stdout}`,
    );
  }
}

function sorobanFees() {
  const deployments = readJson("deployments/testnet-hardened.json");
  return {
    payment_verify_and_pay_stroops:
      deployments.payment_flow?.fee_charged_stroops ?? null,
    rwa_attest_for_mint_stroops:
      deployments.rwa_flow?.attest_fee_charged_stroops ?? null,
    rwa_mint_stroops: deployments.rwa_flow?.mint_fee_charged_stroops ?? null,
    payment_tx: deployments.payment_flow?.verify_and_pay_tx ?? null,
    rwa_attest_tx: deployments.rwa_flow?.attest_for_mint_tx ?? null,
    rwa_mint_tx: deployments.rwa_flow?.mint_tx ?? null,
  };
}

async function main() {
  const browserMsArg = process.argv.find((arg) =>
    arg.startsWith("--browser-ms="),
  );
  const browserProofMs = browserMsArg
    ? Number(browserMsArg.split("=")[1])
    : null;
  const result = {
    schema: "anchorshield.benchmarks.v1",
    generated_at: new Date().toISOString(),
    node: [
      await measureNodeProof(
        "payment",
        "testdata/eligibility/input.valid.json",
      ),
      await measureNodeProof("rwa", "testdata/rwa/input.valid.json"),
    ],
    browser: {
      proof_ms: browserProofMs,
      source: browserProofMs
        ? "apps/web in-browser proof timer"
        : "run npm run m3:web, generate a payment proof in browser, then rerun with --browser-ms=<ms>",
    },
    soroban: sorobanFees(),
  };
  writeJson("docs/benchmarks/latest.json", result);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
