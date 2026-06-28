const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const repo = path.resolve(__dirname, "..", "..");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function loadCommands(
  issuancePath = path.join(__dirname, "out", "issuance.json"),
) {
  const issuance = readJson(issuancePath);
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

function publishRoots({
  execute = false,
  approved = process.env.ANCHORSHIELD_ROOT_PUBLISH_APPROVED === "1",
  issuancePath,
} = {}) {
  const commands = loadCommands(issuancePath);
  if (!execute) {
    return {
      mode: "dry-run",
      commands,
    };
  }
  if (!approved) {
    throw new Error(
      "root publish blocked: set ANCHORSHIELD_ROOT_PUBLISH_APPROVED=1 only after explicit approval",
    );
  }

  for (const command of commands) {
    const [program, ...args] = splitCommand(command);
    const result = spawnSync(program, args, {
      cwd: repo,
      stdio: "inherit",
      shell: false,
    });
    if (result.status !== 0) {
      throw new Error(`${command} failed with status ${result.status}`);
    }
  }

  return {
    mode: "executed",
    commands,
  };
}

function main() {
  const execute = process.argv.includes("--execute");
  const result = publishRoots({ execute });
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
  loadCommands,
  splitCommand,
  publishRoots,
};
