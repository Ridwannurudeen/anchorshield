const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repo = path.resolve(__dirname, "..");
const outDir = path.join(repo, ".m1", "eligibility");
const rwaOutDir = path.join(repo, ".m2", "rwa");
const buildDir = path.join(outDir, "build");
const snarkjs = path.join(repo, "node_modules", "snarkjs", "build", "cli.cjs");
const cachedPtau = path.join(repo, ".ceremony", "pot_final.ptau");
const poseidonConstants = fs.readFileSync(
  path.join(repo, "circuits", "components", "poseidon255_constants.circom"),
  "utf8",
);

const FIELD_PRIME = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);
const TWO_248 = 1n << 248n;
const CREDENTIAL_DEPTH = 16;
const DENY_DEPTH = 20;
const REVOCATION_DEPTH = 20;
const partialRounds = [
  56, 56, 56, 56, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
];
const poseidonCache = new Map();

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
  sanctions_root: 17,
  revocation_root: 18,
};

function decimal(value) {
  return value.toString(10);
}

function mod(value) {
  const reduced = value % FIELD_PRIME;
  return reduced >= 0n ? reduced : reduced + FIELD_PRIME;
}

function circomReturnExpression(functionName, t) {
  const functionStart = poseidonConstants.indexOf(`function ${functionName}`);
  const branchStart = poseidonConstants.indexOf(`t == ${t}`, functionStart);
  const returnStart = poseidonConstants.indexOf("return", branchStart);
  const arrayStart = poseidonConstants.indexOf("[", returnStart);
  let depth = 0;

  for (let i = arrayStart; i < poseidonConstants.length; i++) {
    const char = poseidonConstants[i];
    if (char === "[") {
      depth += 1;
    } else if (char === "]") {
      depth -= 1;
      if (depth === 0) {
        return poseidonConstants.slice(arrayStart, i + 1);
      }
    }
  }

  throw new Error(`could not parse ${functionName}(${t})`);
}

function circomArray(functionName, t) {
  const expression = circomReturnExpression(functionName, t).replace(
    /0x[0-9a-f]+/gi,
    (value) => `${value}n`,
  );
  return Function(`return ${expression};`)();
}

function poseidonParams(t) {
  if (!poseidonCache.has(t)) {
    poseidonCache.set(t, {
      constants: circomArray("CONSTANTS", t),
      matrix: circomArray("MATRIX", t),
    });
  }
  return poseidonCache.get(t);
}

function pow5(value) {
  const square = mod(value * value);
  return mod(square * square * value);
}

function poseidon255(inputs) {
  const values = inputs.map((value) => BigInt(value));
  const t = values.length + 1;
  const nPartial = partialRounds[values.length - 1];
  const nFull = 8;
  const { constants, matrix } = poseidonParams(t);
  let state = [0n, ...values];

  for (let round = 0; round < nFull + nPartial; round++) {
    const arked = state.map((value, index) =>
      mod(value + constants[round * t + index]),
    );
    const sbox =
      round < nFull / 2 || round >= nFull / 2 + nPartial
        ? arked.map(pow5)
        : [pow5(arked[0]), ...arked.slice(1)];

    state = matrix.map((row) =>
      mod(
        row.reduce(
          (sum, coefficient, index) => sum + coefficient * sbox[index],
          0n,
        ),
      ),
    );
  }

  return state[0];
}

function foldHash(values) {
  let current = poseidon255([values[0], values[1]]);
  for (let i = 2; i < values.length; i++) {
    current = poseidon255([current, values[i]]);
  }
  return current;
}

function low248Hash(values) {
  return poseidon255(values) % TWO_248;
}

function merkleRoot(leaf, index, siblings) {
  let node = BigInt(leaf);
  let pathIndex = BigInt(index);
  for (const sibling of siblings) {
    const siblingValue = BigInt(sibling);
    node =
      pathIndex & 1n
        ? poseidon255([siblingValue, node])
        : poseidon255([node, siblingValue]);
    pathIndex >>= 1n;
  }
  return node;
}

function exclusionRoot(lowValue, lowNext, depth) {
  const leaf = poseidon255([lowValue, lowNext]);
  return merkleRoot(
    leaf,
    0n,
    Array.from({ length: depth }, () => 0n),
  );
}

function exclusionWitness(depth) {
  return {
    low_value: "0",
    low_next: "0",
    low_index: "0",
    low_siblings: Array.from({ length: depth }, () => "0"),
    root: decimal(exclusionRoot(0n, 0n, depth)),
  };
}

const emptySanctionsWitness = exclusionWitness(DENY_DEPTH);
const emptyRevocationWitness = exclusionWitness(REVOCATION_DEPTH);

function run(command, args, options = {}) {
  const child =
    command === snarkjs
      ? { command: process.execPath, args: [snarkjs, ...args] }
      : { command, args };
  const result = spawnSync(child.command, child.args, {
    cwd: repo,
    stdio: "inherit",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed with ${result.status}`,
    );
  }
}

function output(command, args) {
  const child =
    command === snarkjs
      ? { command: process.execPath, args: [snarkjs, ...args] }
      : { command, args };
  const result = spawnSync(child.command, child.args, {
    cwd: repo,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stdout.write(result.stdout || "");
    process.stderr.write(result.stderr || result.error?.message || "");
    throw new Error(
      `${command} ${args.join(" ")} failed with ${result.status}`,
    );
  }
  return `${result.stdout}${result.stderr}`;
}

function expectFail(label, command, args) {
  const child =
    command === snarkjs
      ? { command: process.execPath, args: [snarkjs, ...args] }
      : { command, args };
  const result = spawnSync(child.command, child.args, {
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
  const input = {
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
    sanctions_root: emptySanctionsWitness.root,
    revocation_root: emptyRevocationWitness.root,
    user_secret: "123456789",
    kyc_passed: "1",
    country: "566",
    age: "33",
    investor_type: "1",
    tx_limit: "1000",
    issued_at: "1",
    expires_at: "99",
    merkle_index: "0",
    merkle_siblings: Array.from({ length: CREDENTIAL_DEPTH }, () => "0"),
    packet_originator: "1111",
    packet_beneficiary: "2222",
    packet_amount: "250",
    packet_corridor: "566",
    packet_action_id: "424242",
    sanctions_low_value: emptySanctionsWitness.low_value,
    sanctions_low_next: emptySanctionsWitness.low_next,
    sanctions_low_index: emptySanctionsWitness.low_index,
    sanctions_low_siblings: emptySanctionsWitness.low_siblings,
    revocation_low_value: emptyRevocationWitness.low_value,
    revocation_low_next: emptyRevocationWitness.low_next,
    revocation_low_index: emptyRevocationWitness.low_index,
    revocation_low_siblings: emptyRevocationWitness.low_siblings,
  };
  input.user_commitment = decimal(userCommitment(input));
  return input;
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

function credentialHash(input) {
  return foldHash([
    userCommitment(input),
    input.issuer_id,
    input.kyc_passed,
    input.country,
    input.age,
    input.investor_type,
    input.tx_limit,
    input.issued_at,
    input.expires_at,
  ]);
}

function userCommitment(input) {
  if (input.user_commitment !== undefined && input.user_commitment !== null) {
    return BigInt(input.user_commitment);
  }
  return poseidon255([input.user_secret, input.issuer_id]);
}

function sanctionsKey(input) {
  return low248Hash([userCommitment(input), input.issuer_id]);
}

function revocationKey(input) {
  return low248Hash([credentialHash(input)]);
}

function sanctionsLeafPatch(lowValue, lowNext, depth = DENY_DEPTH) {
  return {
    sanctions_low_value: decimal(lowValue),
    sanctions_low_next: decimal(lowNext),
    sanctions_low_index: "0",
    sanctions_low_siblings: Array.from({ length: depth }, () => "0"),
    sanctions_root: decimal(exclusionRoot(lowValue, lowNext, depth)),
  };
}

function revocationLeafPatch(lowValue, lowNext, depth = REVOCATION_DEPTH) {
  return {
    revocation_low_value: decimal(lowValue),
    revocation_low_next: decimal(lowNext),
    revocation_low_index: "0",
    revocation_low_siblings: Array.from({ length: depth }, () => "0"),
    revocation_root: decimal(exclusionRoot(lowValue, lowNext, depth)),
  };
}

function rootMismatchPatch(prefix) {
  return prefix === "sanctions"
    ? { sanctions_low_value: "1", sanctions_low_next: "0" }
    : { revocation_low_value: "1", revocation_low_next: "0" };
}

function sentinelAbusePatch(prefix) {
  const honestRoot = decimal(exclusionRoot(0n, TWO_248 - 1n, DENY_DEPTH));
  return prefix === "sanctions"
    ? { sanctions_low_next: "0", sanctions_root: honestRoot }
    : { revocation_low_next: "0", revocation_root: honestRoot };
}

function untruncatedPatch(prefix) {
  return prefix === "sanctions"
    ? sanctionsLeafPatch(TWO_248, 0n)
    : revocationLeafPatch(TWO_248, 0n);
}

function paymentInvalidCases() {
  return [
    ["kyc_false", { kyc_passed: "0" }],
    ["amount_over_limit", { amount: "1500", packet_amount: "1500" }],
    ["wrong_country", { country: "840" }],
    ["commitment_mismatch", { user_commitment: "1" }],
    ["packet_amount_mismatch", { packet_amount: "251" }],
    ["expired", { epoch: "120" }],
    ["not_yet_issued", { issued_at: "20" }],
    [
      "sanctions_listed_key",
      (input) => sanctionsLeafPatch(sanctionsKey(input), 0n),
    ],
    ["sanctions_root_mismatch", () => rootMismatchPatch("sanctions")],
    [
      "sanctions_non_strict_low",
      (input) => sanctionsLeafPatch(sanctionsKey(input), 0n),
    ],
    [
      "sanctions_non_strict_next",
      (input) => sanctionsLeafPatch(0n, sanctionsKey(input)),
    ],
    ["sanctions_sentinel_abuse", () => sentinelAbusePatch("sanctions")],
    ["sanctions_untruncated_low", () => untruncatedPatch("sanctions")],
    [
      "revocation_listed_key",
      (input) => revocationLeafPatch(revocationKey(input), 0n),
    ],
    ["revocation_root_mismatch", () => rootMismatchPatch("revocation")],
    [
      "revocation_non_strict_low",
      (input) => revocationLeafPatch(revocationKey(input), 0n),
    ],
    [
      "revocation_non_strict_next",
      (input) => revocationLeafPatch(0n, revocationKey(input)),
    ],
    ["revocation_sentinel_abuse", () => sentinelAbusePatch("revocation")],
    ["revocation_untruncated_low", () => untruncatedPatch("revocation")],
  ];
}

function rwaInvalidCases() {
  return [
    ["kyc_false", { kyc_passed: "0" }],
    ["investor_too_low", { investor_type: "0" }],
    ["wrong_country", { country: "840" }],
    ["commitment_mismatch", { user_commitment: "1" }],
    ["packet_action_mismatch", { packet_action_id: "515152" }],
    ["expired", { epoch: "120" }],
    ["not_yet_issued", { issued_at: "20" }],
    [
      "sanctions_listed_key",
      (input) => sanctionsLeafPatch(sanctionsKey(input), 0n),
    ],
    ["sanctions_root_mismatch", () => rootMismatchPatch("sanctions")],
    [
      "sanctions_non_strict_low",
      (input) => sanctionsLeafPatch(sanctionsKey(input), 0n),
    ],
    [
      "sanctions_non_strict_next",
      (input) => sanctionsLeafPatch(0n, sanctionsKey(input)),
    ],
    ["sanctions_sentinel_abuse", () => sentinelAbusePatch("sanctions")],
    ["sanctions_untruncated_low", () => untruncatedPatch("sanctions")],
    [
      "revocation_listed_key",
      (input) => revocationLeafPatch(revocationKey(input), 0n),
    ],
    ["revocation_root_mismatch", () => rootMismatchPatch("revocation")],
    [
      "revocation_non_strict_low",
      (input) => revocationLeafPatch(revocationKey(input), 0n),
    ],
    [
      "revocation_non_strict_next",
      (input) => revocationLeafPatch(0n, revocationKey(input)),
    ],
    ["revocation_sentinel_abuse", () => sentinelAbusePatch("revocation")],
    ["revocation_untruncated_low", () => untruncatedPatch("revocation")],
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
      sanctions_root: emptySanctionsWitness.root,
      revocation_root: emptyRevocationWitness.root,
    },
    wrongSignals: [
      ["action-binding wrong amount", "amount", "251"],
      ["action-binding wrong action", "action_id", "424243"],
      ["wrong sanctions root", "sanctions_root", "1"],
      ["wrong revocation root", "revocation_root", "1"],
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
      sanctions_root: emptySanctionsWitness.root,
      revocation_root: emptyRevocationWitness.root,
    },
    wrongSignals: [
      ["rwa action-binding wrong action type", "action_type", "0"],
      ["rwa action-binding wrong recipient", "recipient", "8000002"],
      ["rwa wrong sanctions root", "sanctions_root", "1"],
      ["rwa wrong revocation root", "revocation_root", "1"],
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

const r1csInfo = output(snarkjs, [
  "r1cs",
  "info",
  path.join(buildDir, "eligibility.r1cs"),
]);
process.stdout.write(r1csInfo);
const constraintsMatch = r1csInfo.match(/# of Constraints:\s+(\d+)/);
if (!constraintsMatch) {
  throw new Error("could not parse r1cs constraint count");
}
const constraints = Number(constraintsMatch[1]);
const power = Math.max(12, Math.ceil(Math.log2(constraints + 1)));
if (power > 18) {
  throw new Error(
    `M1 circuit is too large for smoke setup: ${constraints} constraints`,
  );
}

for (const scenario of scenarios) {
  writeJson(
    path.join(scenario.outDir, "input.valid.json"),
    scenario.validInput,
  );

  for (const [name, patch] of scenario.invalidCases) {
    const resolvedPatch =
      typeof patch === "function" ? patch(scenario.validInput) : patch;
    const invalidPath = path.join(scenario.outDir, `input.${name}.json`);
    writeJson(invalidPath, { ...scenario.validInput, ...resolvedPatch });
    expectFail(`${scenario.label} invalid witness ${name}`, snarkjs, [
      "wtns",
      "calculate",
      path.join(buildDir, "eligibility_js", "eligibility.wasm"),
      invalidPath,
      path.join(scenario.outDir, `${name}.wtns`),
    ]);
  }
}

if (fs.existsSync(cachedPtau)) {
  fs.copyFileSync(cachedPtau, path.join(outDir, "pot_final.ptau"));
} else {
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
}
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
  if (publicSignals.length !== 19) {
    throw new Error(
      `${scenario.label}: expected 19 public signals, got ${publicSignals.length}`,
    );
  }

  for (const [name, expected] of Object.entries(scenario.expected)) {
    if (publicSignals[publicInputIndex[name]] !== expected) {
      throw new Error(
        `${scenario.label}: ${name} public-signal index is wrong`,
      );
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

console.log(
  `M1/M2 circuit smoke passed with ${constraints} constraints and ptau power ${power}`,
);
