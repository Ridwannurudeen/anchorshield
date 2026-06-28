#!/usr/bin/env bash
# AnchorShield workspace test runner.
#
# Runs `cargo test --workspace` for the Soroban contracts. Must run inside
# WSL/Linux: the Windows host has no MSVC linker and Smart App Control (enforcement)
# blocks freshly-built test binaries; the windows-gnu toolchain links but the soroban
# cdylib artifacts overflow the PE 16-bit export-ordinal limit. Linux has none of these.
#
# CARGO_TARGET_DIR defaults to a WSL-native path because building into the /mnt/c
# source tree (DrvFs) is slow for the thousands of object files. Override it if needed.
#
# Run from repo root inside WSL/Linux:  bash scripts/test.sh [extra cargo args]
set -euo pipefail

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/as-target}"

# No args: run the whole workspace. With args: pass them straight through so
# `-p <crate>`, `--release`, `-- --nocapture`, etc. behave as expected.
if [ "$#" -eq 0 ]; then
  exec cargo test --workspace
else
  exec cargo test "$@"
fi
