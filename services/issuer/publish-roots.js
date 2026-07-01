const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");
const DEFAULT_REPORT_PATH = path.join(
  __dirname,
  "out",
  "root-publish-report.json",
);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function loadIssuance(
  issuancePath = path.join(__dirname, "out", "issuance.json"),
) {
  return readJson(issuancePath);
}

function loadCommands(
  issuancePath = path.join(__dirname, "out", "issuance.json"),
) {
  const issuance = loadIssuance(issuancePath);
  if (
    !Array.isArray(issuance.root_commands) ||
    issuance.root_commands.length !== 3
  ) {
    throw new Error("issuance file does not contain the three root commands");
  }
  return issuance.root_commands;
}

function splitCommand(command) {
  const parts = command.match(/"[^"]+"|\S+/g) || [];
  return parts.map((part) => part.replace(/^"|"$/g, ""));
}

function valueAfter(parts, flag) {
  const index = parts.indexOf(flag);
  return index === -1 ? null : parts[index + 1];
}

function parseRootCommand(command) {
  const parts = splitCommand(command);
  const separator = parts.indexOf("--");
  if (separator === -1 || !parts[separator + 1]) {
    throw new Error(`invalid stellar root command: ${command}`);
  }
  return {
    command,
    program: parts[0],
    args: parts.slice(1),
    contractId: valueAfter(parts, "--id"),
    source:
      valueAfter(parts, "--source") || valueAfter(parts, "--source-account"),
    network: valueAfter(parts, "--network"),
    fnName: parts[separator + 1],
    issuerId: valueAfter(parts, "--issuer_id"),
    root: valueAfter(parts, "--root"),
    memberCount: valueAfter(parts, "--member_count"),
  };
}

function decimalRootToHex(root) {
  const value = BigInt(root);
  if (value < 0n) {
    throw new Error(`root must be non-negative: ${root}`);
  }
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) {
    throw new Error(`root exceeds 32 bytes: ${root}`);
  }
  return hex;
}

function parseHexRootOutput(output) {
  const trimmed = String(output).trim();
  const parsed = trimmed.startsWith('"') ? JSON.parse(trimmed) : trimmed;
  const hex = String(parsed).replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`unexpected root getter output: ${trimmed}`);
  }
  return hex;
}

function parseDecimalOutput(output) {
  const trimmed = String(output).trim();
  const parsed = trimmed.startsWith('"') ? JSON.parse(trimmed) : trimmed;
  const value = String(parsed);
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`unexpected decimal getter output: ${trimmed}`);
  }
  return value;
}

function runCommand(program, args, { capture = false } = {}) {
  return spawnSync(program, args, {
    cwd: repo,
    encoding: capture ? "utf8" : undefined,
    stdio: capture ? "pipe" : "inherit",
    shell: false,
  });
}

function publicKeyOrIdentityAddress(source, runner = runCommand) {
  if (/^G[A-Z2-7]{55}$/.test(source)) {
    return source;
  }
  const result = runner("stellar", ["keys", "address", source], {
    capture: true,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `root publish blocked: import the deployed admin identity as '${source}' before execution`,
    );
  }
  return result.stdout.trim();
}

function assertPublishIdentity({ issuance, commands, runner }) {
  const admin = issuance.root_publish?.admin;
  const source = parseRootCommand(commands[0]).source;
  if (!admin || !source) {
    throw new Error(
      "issuance file is missing root_publish admin/source metadata",
    );
  }
  const sourceAddress = publicKeyOrIdentityAddress(source, runner);
  if (sourceAddress !== admin) {
    throw new Error(
      `root publish blocked: source '${source}' resolves to ${sourceAddress}, expected deployed admin ${admin}`,
    );
  }
  return { source, sourceAddress, admin };
}

function rootGetterCommands({ issuance, readSource }) {
  const parsed = issuance.root_commands.map(parseRootCommand);
  const first = parsed[0];
  const source = readSource || issuance.root_publish?.admin || first.source;
  const memberCount = String(issuance.active_member_count ?? first.memberCount);
  return [
    {
      name: "credential_root",
      format: "hex",
      expected: decimalRootToHex(issuance.roots.credential_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "root",
        "--issuer_id",
        String(issuance.issuer_id),
      ],
    },
    {
      name: "credential_member_count",
      format: "decimal",
      expected: memberCount,
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "member_count",
        "--issuer_id",
        String(issuance.issuer_id),
        "--root",
        decimalRootToHex(issuance.roots.credential_root),
      ],
    },
    {
      name: "sanctions_root",
      format: "hex",
      expected: decimalRootToHex(issuance.roots.sanctions_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "sanctions_root",
      ],
    },
    {
      name: "revocation_root",
      format: "hex",
      expected: decimalRootToHex(issuance.roots.revocation_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "revocation_root",
        "--issuer_id",
        String(issuance.issuer_id),
      ],
    },
  ];
}

function expectedPreviousRoots(issuance) {
  return (
    issuance.expected_previous_roots ||
    issuance.root_publish?.expected_previous_roots ||
    null
  );
}

function rootReconcileCommands({ issuance, readSource }) {
  const expected = expectedPreviousRoots(issuance);
  if (!expected) return [];
  const parsed = issuance.root_commands.map(parseRootCommand);
  const first = parsed[0];
  const source = readSource || issuance.root_publish?.admin || first.source;
  const checks = [
    {
      name: "previous_credential_root",
      format: "hex",
      expected: decimalRootToHex(expected.credential_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "root",
        "--issuer_id",
        String(issuance.issuer_id),
      ],
    },
    {
      name: "previous_sanctions_root",
      format: "hex",
      expected: decimalRootToHex(expected.sanctions_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "sanctions_root",
      ],
    },
    {
      name: "previous_revocation_root",
      format: "hex",
      expected: decimalRootToHex(expected.revocation_root),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "revocation_root",
        "--issuer_id",
        String(issuance.issuer_id),
      ],
    },
  ];
  if (expected.active_member_count !== undefined) {
    checks.splice(1, 0, {
      name: "previous_credential_member_count",
      format: "decimal",
      expected: String(expected.active_member_count),
      command: [
        "stellar",
        "contract",
        "invoke",
        "--id",
        first.contractId,
        "--source-account",
        source,
        "--network",
        first.network,
        "--send",
        "no",
        "--",
        "member_count",
        "--issuer_id",
        String(issuance.issuer_id),
        "--root",
        decimalRootToHex(expected.credential_root),
      ],
    });
  }
  return checks;
}

function runRootChecks(checks, runner) {
  return checks.map((check) => {
    const [program, ...args] = check.command;
    const result = runner(program, args, { capture: true });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error(
        `${check.command.join(" ")} failed: ${result.stderr || result.stdout}`,
      );
    }
    const actual =
      check.format === "decimal"
        ? parseDecimalOutput(result.stdout)
        : parseHexRootOutput(result.stdout);
    if (actual !== check.expected) {
      throw new Error(
        `${check.name} mismatch: on-chain ${actual}, expected ${check.expected}`,
      );
    }
    return {
      name: check.name,
      expected: check.expected,
      actual,
      command: check.command.join(" "),
    };
  });
}

function assertPublishExtendsOnChain({
  issuance,
  issuancePath,
  readSource,
  runner = runCommand,
} = {}) {
  const loadedIssuance = issuance || loadIssuance(issuancePath);
  const checks = rootReconcileCommands({
    issuance: loadedIssuance,
    readSource,
  });
  if (!checks.length) {
    return {
      checked: false,
      reason: "expected_previous_roots not configured",
    };
  }
  return {
    checked: true,
    checks: runRootChecks(checks, runner),
  };
}

function verifyPublishedRoots({
  issuance,
  issuancePath,
  readSource,
  runner = runCommand,
} = {}) {
  const loadedIssuance = issuance || loadIssuance(issuancePath);
  const checks = runRootChecks(
    rootGetterCommands({
      issuance: loadedIssuance,
      readSource,
    }),
    runner,
  );
  return {
    schema: "anchorshield.root_publish_report.v1",
    verified: true,
    generated_at: new Date().toISOString(),
    issuer_id: loadedIssuance.issuer_id,
    roots: loadedIssuance.roots,
    checks,
  };
}

function publishRoots({
  execute = false,
  approved = process.env.ANCHORSHIELD_ROOT_PUBLISH_APPROVED === "1",
  issuancePath,
  reportPath = DEFAULT_REPORT_PATH,
  verifyOnly = false,
  readSource = process.env.ANCHORSHIELD_ROOT_READ_SOURCE,
  runner = runCommand,
} = {}) {
  const issuance = loadIssuance(issuancePath);
  const commands = loadCommands(issuancePath);
  const verificationCommands = rootGetterCommands({ issuance, readSource }).map(
    (check) => check.command.join(" "),
  );
  if (verifyOnly) {
    const report = verifyPublishedRoots({ issuancePath, readSource, runner });
    writeJson(reportPath, report);
    return report;
  }
  if (!execute) {
    return {
      mode: "dry-run",
      commands,
      verification_commands: verificationCommands,
    };
  }
  if (!approved) {
    throw new Error(
      "root publish blocked: set ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 only after explicit approval",
    );
  }
  const identity = assertPublishIdentity({ issuance, commands, runner });
  const reconcile = assertPublishExtendsOnChain({
    issuance,
    readSource,
    runner,
  });

  for (const command of commands) {
    const parsed = parseRootCommand(command);
    const result = runner(parsed.program, parsed.args);
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error(`${command} failed with status ${result.status}`);
    }
  }

  const report = verifyPublishedRoots({ issuancePath, readSource, runner });
  const result = {
    ...report,
    mode: "executed",
    commands,
    identity,
    reconcile,
  };
  writeJson(reportPath, result);
  return result;
}

function main() {
  const execute = process.argv.includes("--execute");
  const verifyOnly = process.argv.includes("--verify");
  const result = publishRoots({ execute, verifyOnly });
  console.log(JSON.stringify(result, null, 2));
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

module.exports = {
  assertPublishIdentity,
  assertPublishExtendsOnChain,
  decimalRootToHex,
  expectedPreviousRoots,
  loadIssuance,
  loadCommands,
  parseHexRootOutput,
  parseDecimalOutput,
  parseRootCommand,
  publicKeyOrIdentityAddress,
  rootGetterCommands,
  rootReconcileCommands,
  splitCommand,
  publishRoots,
  verifyPublishedRoots,
};
