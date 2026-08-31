#!/usr/bin/env bash
# Linux/WSL Zig archiver adapter for AArch64 musl cc-rs dependencies.

set -euo pipefail

zig_bin="${ZIG_EXE:-}"
if [[ -z "$zig_bin" ]]; then
    zig_bin="$(command -v zig || true)"
fi
if [[ -z "$zig_bin" || ! -x "$zig_bin" ]]; then
    echo "zig-ar-aarch64: set ZIG_EXE to an executable Zig 0.13.0 binary" >&2
    exit 127
fi

exec "$zig_bin" ar "$@"
