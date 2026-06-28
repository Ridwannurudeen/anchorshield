// Cross-platform command helper for AnchorShield npm scripts.
// JS-only steps run natively everywhere. Rust/circom/Stellar tools prefer the
// local toolchain and fall back to WSL on Windows when native build scripts are
// blocked or the MSVC linker is unavailable.
import { execSync } from "node:child_process";

const isWin = process.platform === "win32";
let hasMsvcLinker;

function toolEnv() {
  if (!isWin) {
    return process.env;
  }
  const prepend = [
    "C:\\Users\\gudma\\.cargo\\bin",
    "C:\\Program Files (x86)\\Stellar CLI",
  ].join(";");
  return {
    ...process.env,
    PATH: `${prepend};${process.env.PATH || ""}`,
  };
}

function wslRepoPath(subdir) {
  const p = process.cwd();
  const drive = p[0].toLowerCase();
  const rest = p.slice(2).replace(/\\/g, "/");
  const base = `/mnt/${drive}${rest}`;
  return subdir === "." ? base : `${base}/${subdir.replace(/\\/g, "/")}`;
}

function canUseMsvcCargo() {
  if (hasMsvcLinker === undefined) {
    try {
      execSync("where link.exe", { stdio: "ignore" });
      hasMsvcLinker = true;
    } catch {
      hasMsvcLinker = false;
    }
  }
  return hasMsvcLinker;
}

function runWsl(cmd, subdir) {
  const full = wslRepoPath(subdir);
  const inner = `cd '${full}' && ${cmd}`;
  console.log(`$ wsl: ${inner}`);
  execSync(`wsl -d Ubuntu-24.04 -- bash -lc "${inner.replace(/"/g, '\\"')}"`, {
    stdio: "inherit",
  });
}

// Native JS/node command (portable).
export function run(cmd) {
  console.log(`$ ${cmd}`);
  execSync(cmd, { stdio: "inherit" });
}

// Toolchain command (cargo/circom/snarkjs/stellar). `subdir` is relative to repo root.
export function tool(cmd, subdir = ".") {
  console.log(`$ (${subdir}) ${cmd}`);
  if (isWin && /^\s*cargo\b/.test(cmd) && !canUseMsvcCargo()) {
    runWsl(cmd, subdir);
    return;
  }
  try {
    execSync(cmd, {
      stdio: "inherit",
      cwd: subdir,
      env: toolEnv(),
      shell: isWin ? undefined : "/bin/bash",
    });
  } catch (error) {
    if (!isWin) {
      throw error;
    }
    runWsl(cmd, subdir);
  }
}
