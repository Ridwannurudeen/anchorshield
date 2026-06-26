// Cross-platform command helper for AnchorShield npm scripts.
// JS-only steps run natively everywhere. Steps needing the Rust/circom/snarkjs
// toolchain run natively on Linux/macOS (e.g. CI) and bridge to WSL on Windows,
// where that toolchain lives.
import { execSync } from "node:child_process";

const isWin = process.platform === "win32";

function wslRepoPath() {
  const p = process.cwd();
  const drive = p[0].toLowerCase();
  const rest = p.slice(2).replace(/\\/g, "/");
  return `/mnt/${drive}${rest}`;
}

// Native JS/node command (portable).
export function run(cmd) {
  console.log(`$ ${cmd}`);
  execSync(cmd, { stdio: "inherit" });
}

// Toolchain command (cargo/circom/snarkjs/stellar). `subdir` is relative to repo root.
export function tool(cmd, subdir = ".") {
  if (isWin) {
    const base = wslRepoPath();
    const full = subdir === "." ? base : `${base}/${subdir}`;
    const inner = `cd '${full}' && ${cmd}`;
    console.log(`$ wsl: ${inner}`);
    execSync(`wsl bash -lc "${inner.replace(/"/g, '\\"')}"`, { stdio: "inherit" });
  } else {
    console.log(`$ (${subdir}) ${cmd}`);
    execSync(cmd, { stdio: "inherit", cwd: subdir, shell: "/bin/bash" });
  }
}
