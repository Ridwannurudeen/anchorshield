const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repo = path.resolve(__dirname, "..");
const outDir = path.join(repo, ".m1", "eligibility");
const rwaOutDir = path.join(repo, ".m2", "rwa");
const buildDir = path.join(outDir, "build");
const snarkjs = path.join(repo, "node_modules", ".bin", "snarkjs");

const publicInputIndex = {
  issuer_id: 4,
  policy_id: 5,
  kyc_required: 6,
  sanctions_required: 7,
  allowed_country: 8,
  min_age: 9,
  min_investor_type: 10,
  action_type: 11,
  asset_id: 12,
  amount: 13,
  recipient: 14,
  action_id: 15,
  epoch: 16,
};

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repo,
    stdio: "inherit",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with ${result.status}`);
  }
}

function output(command, args) {
  const result = spawnSync(command, args, {
    cwd: repo,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    throw new Error(`${command} ${args.join(" ")} failed with ${result.status}`);
  }
  return `${result.stdout}${result.stderr}`;
}

function expectFail(label, command, args) {
  const result = spawnSync(command, args, {
    cwd: repo,
    encoding: "utf8",
  });
  if (result.status === 0) {
    throw new Error(`${label} unexpectedly passed`);
  }
  console.log(`${label}: rejected`);
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function paymentInput() {
  return {
    issuer_id: "101",
    policy_id: "202",
    kyc_required: "1",
    sanctions_required: "1",
    allowed_country: "566",
    min_age: "18",
    min_investor_type: "0",
    action_type: "0",
    asset_id: "9001",
    amount: "250",
    recipient: "7000001",
    action_id: "424242",
    epoch: "12",
    user_secret: "123456789",
    kyc_passed: "1",
    sanctions_clear: "1",
    country: "566",
    age: "33",
    investor_type: "1",
    tx_limit: "1000",
    issued_at: "1",
    expires_at: "99",
    merkle_index: "0",
    merkle_siblings: ["0", "0"],
    packet_originator: "1111",
    packet_beneficiary: "2222",
    packet_amount: "250",
    packet_corridor: "566",
    packet_action_id: "424242",
  };
}

function rwaInput() {
  return {
    ...paymentInput(),
    policy_id: "303",
    min_investor_type: "1",
    action_type: "1",
    asset_id: "9101",
    amount: "100",
    recipient: "8000001",
    action_id: "515151",
    packet_originator: "3333",
    packet_beneficiary: "4444",
    packet_amount: "100",
    packet_action_id: "515151",
  };
}

function paymentInvalidCases() {
  return [
    ["kyc_false", { kyc_passed: "0" }],
    ["sanctions_false", { sanctions_clear: "0" }],
    ["amount_over_limit", { amount: "1500", packet_amount: "1500" }],
    ["wrong_country", { country: "840" }],
    ["packet_amount_mismatch", { packet_amount: "251" }],
    ["expired", { epoch: "120" }],
  ];
}

function rwaInvalidCases() {
  return [
    ["kyc_false", { kyc_passed: "0" }],
    ["sanctions_false", { sanctions_clear: "0" }],
    ["investor_too_low", { investor_type: "0" }],
    ["wrong_country", { country: "840" }],
    ["packet_action_mismatch", { packet_action_id: "515152" }],
    ["expired", { epoch: "120" }],
  ];
}

const scenarios = [
  {
    label: "M1 payment",
    outDir,
    validInput: paymentInput(),
    invalidCases: paymentInvalidCases(),
    expected: {
      action_type: "0",
      amount: "250",
      recipient: "7000001",
      action_id: "424242",
    },
    wrongSignals: [
      ["action-binding wrong amount", "amount", "251"],
      ["action-binding wrong action", "action_id", "424243"],
    ],
  },
  {
    label: "M2 RWA",
    outDir: rwaOutDir,
    validInput: rwaInput(),
    invalidCases: rwaInvalidCases(),
    expected: {
      action_type: "1",
      amount: "100",
      recipient: "8000001",
      action_id: "515151",
    },
    wrongSignals: [
      ["rwa action-binding wrong action type", "action_type", "0"],
      ["rwa action-binding wrong recipient", "recipient", "8000002"],
    ],
  },
];

fs.rmSync(outDir, { recursive: true, force: true });
fs.rmSync(rwaOutDir, { recursive: true, force: true });
fs.mkdirSync(buildDir, { recursive: true });
fs.mkdirSync(rwaOutDir, { recursive: true });

run("circom", [
  "circuits/eligibility.circom",
  "--r1cs",
  "--wasm",
  "--sym",
  "--prime",
  "bls12381",
  "-l",
  "circuits",
  "-l",
  "circuits/components",
  "-l",
  "node_modules/circomlib/circuits",
  "-o",
  buildDir,
]);

const r1csInfo = output(snarkjs, ["r1cs", "info", path.join(buildDir, "eligibility.r1cs")]);
process.stdout.write(r1csInfo);
const constraintsMatch = r1csInfo.match(/# of Constraints:\s+(\d+)/);
if (!constraintsMatch) {
  throw new Error("could not parse r1cs constraint count");
}
const constraints = Number(constraintsMatch[1]);
const power = Math.max(12, Math.ceil(Math.log2(constraints + 1)));
if (power > 18) {
  throw new Error(`M1 circuit is too large for smoke setup: ${constraints} constraints`);
}

for (const scenario of scenarios) {
  writeJson(path.join(scenario.outDir, "input.valid.json"), scenario.validInput);

  for (const [name, patch] of scenario.invalidCases) {
    const invalidPath = path.join(scenario.outDir, `input.${name}.json`);
    writeJson(invalidPath, { ...scenario.validInput, ...patch });
    expectFail(
      `${scenario.label} invalid witness ${name}`,
      snarkjs,
      [
        "wtns",
        "calculate",
        path.join(buildDir, "eligibility_js", "eligibility.wasm"),
        invalidPath,
        path.join(scenario.outDir, `${name}.wtns`),
      ],
    );
  }
}

run(snarkjs, [
  "powersoftau",
  "new",
  "bls12381",
  String(power),
  path.join(outDir, "pot_0000.ptau"),
]);
run(snarkjs, [
  "powersoftau",
  "contribute",
  path.join(outDir, "pot_0000.ptau"),
  path.join(outDir, "pot_0001.ptau"),
  "--name=anchorshield-m1-smoke",
  "-e=anchorshield-m1-smoke",
]);
run(snarkjs, [
  "powersoftau",
  "prepare",
  "phase2",
  path.join(outDir, "pot_0001.ptau"),
  path.join(outDir, "pot_final.ptau"),
]);
run(snarkjs, [
  "groth16",
  "setup",
  path.join(buildDir, "eligibility.r1cs"),
  path.join(outDir, "pot_final.ptau"),
  path.join(outDir, "eligibility_0000.zkey"),
]);
run(snarkjs, [
  "zkey",
  "contribute",
  path.join(outDir, "eligibility_0000.zkey"),
  path.join(outDir, "eligibility_final.zkey"),
  "--name=anchorshield-m1-smoke",
  "-e=anchorshield-m1-smoke",
]);
run(snarkjs, [
  "zkv",
  path.join(buildDir, "eligibility.r1cs"),
  path.join(outDir, "pot_final.ptau"),
  path.join(outDir, "eligibility_final.zkey"),
]);
run(snarkjs, [
  "zkey",
  "export",
  "verificationkey",
  path.join(outDir, "eligibility_final.zkey"),
  path.join(outDir, "verification_key.json"),
]);

for (const scenario of scenarios) {
  if (scenario.outDir !== outDir) {
    fs.copyFileSync(
      path.join(outDir, "verification_key.json"),
      path.join(scenario.outDir, "verification_key.json"),
    );
  }

  run(snarkjs, [
    "groth16",
    "fullprove",
    path.join(scenario.outDir, "input.valid.json"),
    path.join(buildDir, "eligibility_js", "eligibility.wasm"),
    path.join(outDir, "eligibility_final.zkey"),
    path.join(scenario.outDir, "proof.json"),
    path.join(scenario.outDir, "public.json"),
  ]);
  run(snarkjs, [
    "groth16",
    "verify",
    path.join(scenario.outDir, "verification_key.json"),
    path.join(scenario.outDir, "public.json"),
    path.join(scenario.outDir, "proof.json"),
  ]);

  const publicSignals = JSON.parse(
    fs.readFileSync(path.join(scenario.outDir, "public.json"), "utf8"),
  );
  if (publicSignals.length !== 17) {
    throw new Error(`${scenario.label}: expected 17 public signals, got ${publicSignals.length}`);
  }

  for (const [name, expected] of Object.entries(scenario.expected)) {
    if (publicSignals[publicInputIndex[name]] !== expected) {
      throw new Error(`${scenario.label}: ${name} public-signal index is wrong`);
    }
  }

  for (const [label, signalName, wrongValue] of scenario.wrongSignals) {
    const wrongSignals = [...publicSignals];
    wrongSignals[publicInputIndex[signalName]] = wrongValue;
    const wrongPath = path.join(
      scenario.outDir,
      `public.${label.toLowerCase().replaceAll(" ", "-")}.json`,
    );
    writeJson(wrongPath, wrongSignals);
    expectFail(label, snarkjs, [
      "groth16",
      "verify",
      path.join(scenario.outDir, "verification_key.json"),
      wrongPath,
      path.join(scenario.outDir, "proof.json"),
    ]);
  }

  const summary = {
    constraints,
    power,
    public_signals: publicSignals,
  };
  writeJson(path.join(scenario.outDir, "summary.json"), summary);
  console.log(`${scenario.label} circuit smoke passed`);
}

console.log(`M1/M2 circuit smoke passed with ${constraints} constraints and ptau power ${power}`);
