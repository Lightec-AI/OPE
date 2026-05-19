#!/usr/bin/env bash
# Build libope_ffi for language bindings (run from repo root or bindings/).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo build -p ope-ffi --release
echo "Built: $ROOT/target/release/libope_ffi.$(case "$(uname -s)" in Darwin) echo dylib;; Linux) echo so;; *) echo dll;; esac)"
