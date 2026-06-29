import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repo, relativePath), "utf8"));
}

function checkPackage(relativePath) {
  const pkg = readJson(path.join(relativePath, "package.json"));
  const blockers = [];
  if (pkg.private !== false) {
    blockers.push("package.json private must be false before publish");
  }
  if (!pkg.license || pkg.license === "UNLICENSED") {
    blockers.push("final publish license must be chosen before publish");
  }
  if (!pkg.version || pkg.version === "0.0.0") {
    blockers.push("package version must be a real semver version");
  }
  if (!pkg.repository?.url) {
    blockers.push("repository metadata is required");
  }
  if (!Array.isArray(pkg.files) || pkg.files.length === 0) {
    blockers.push("files allowlist is required");
  }
  return {
    name: pkg.name,
    version: pkg.version,
    path: relativePath,
    private: pkg.private,
    license: pkg.license,
    blockers,
  };
}

function runNpm(args) {
  if (process.platform === "win32") {
    for (const arg of args) {
      if (!/^[A-Za-z0-9@._:/=~-]+$/.test(arg)) {
        throw new Error(`unsafe npm argument: ${arg}`);
      }
    }
    return spawnSync(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", ["npm", ...args].join(" ")],
      {
        cwd: repo,
        encoding: "utf8",
        stdio: "pipe",
        shell: false,
      },
    );
  }
  return spawnSync("npm", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: "pipe",
    shell: false,
  });
}

function npmWhoami() {
  const result = runNpm(["whoami"]);
  if (result.status !== 0) {
    return null;
  }
  return result.stdout.trim();
}

function npmPublishedVersion(pkg) {
  const result = runNpm([
    "view",
    `${pkg.name}@${pkg.version}`,
    "version",
    "--json",
  ]);
  if (result.status === 0) {
    return {
      version: result.stdout.trim().replace(/^"|"$/g, ""),
      error: null,
    };
  }
  const output = `${result.stderr || ""}${result.stdout || ""}`;
  if (output.includes("E404") || output.includes("404 Not Found")) {
    return { version: null, error: null };
  }
  return {
    version: null,
    error: output.trim() || "npm view failed",
  };
}

function evaluatePublishPreflight() {
  const packages = [checkPackage("packages/sdk"), checkPackage("packages/cli")];
  const npmUser = npmWhoami();
  const blockers = [];
  if (!npmUser) {
    blockers.push("npm auth is required before publish");
  }
  for (const pkg of packages) {
    const published = npmPublishedVersion(pkg);
    pkg.published_version = published.version;
    if (published.error) {
      blockers.push(
        `${pkg.name}: unable to verify npm version: ${published.error}`,
      );
    }
    if (
      published.version &&
      process.env.ANCHORSHIELD_NPM_ALLOW_EXISTING_VERSION !== "1"
    ) {
      blockers.push(
        `${pkg.name}@${pkg.version}: version already exists on npm; bump package version before publishing`,
      );
    }
    for (const blocker of pkg.blockers) {
      blockers.push(`${pkg.name}: ${blocker}`);
    }
  }
  if (process.env.ANCHORSHIELD_NPM_PUBLISH_APPROVED !== "1") {
    blockers.push(
      "set ANCHORSHIELD_NPM_PUBLISH_APPROVED=1 only after explicit publish approval",
    );
  }
  return {
    schema: "anchorshield.publish_preflight.v1",
    npm_user: npmUser,
    packages,
    ready: blockers.length === 0,
    blockers,
  };
}

function main() {
  const result = evaluatePublishPreflight();
  console.log(JSON.stringify(result, null, 2));
  if (!result.ready) {
    process.exit(1);
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}

export { checkPackage, evaluatePublishPreflight };
