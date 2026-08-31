#!/usr/bin/env bash
# Linux/WSL Zig C-compiler adapter for cc-rs AArch64 musl dependencies.

set -euo pipefail

zig_bin="${ZIG_EXE:-}"
if [[ -z "$zig_bin" ]]; then
    zig_bin="$(command -v zig || true)"
fi
if [[ -z "$zig_bin" || ! -x "$zig_bin" ]]; then
    echo "zig-cc-aarch64: set ZIG_EXE to an executable Zig 0.13.0 binary" >&2
    exit 127
fi

args=()
for arg in "$@"; do
    case "$arg" in
        --target=*|-target=*|-march=*|-mcpu=*|-mfpu=*|-mfloat-abi=*) ;;
        *) args+=("$arg") ;;
    esac
done

exec "$zig_bin" cc -target aarch64-linux-musl -mcpu=cortex_a53 "${args[@]}"
