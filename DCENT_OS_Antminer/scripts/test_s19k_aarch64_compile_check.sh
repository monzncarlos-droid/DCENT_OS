#!/usr/bin/env bash

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
check="$script_dir/s19k_aarch64_compile_check.sh"
cc_wrapper="$script_dir/../dcentrald/zig-cc-aarch64.sh"
ar_wrapper="$script_dir/../dcentrald/zig-ar-aarch64.sh"

bash -n "$check" "$cc_wrapper" "$ar_wrapper"
grep -Fq 'readonly TARGET=aarch64-unknown-linux-musl' "$check"
grep -Fq 'readonly EXPECTED_ZIG_VERSION=0.13.0' "$check"
grep -Fq 'readonly EXPECTED_ZIG_SHA256=7f9e3a661e909d5188d1b8b14f082b98a19c323a30d43bfdd1b2893ed37273e0' "$check"
grep -Fq 'export CARGO_NET_OFFLINE=true' "$check"
grep -Fq 'cargo check --offline --locked --target "$TARGET"' "$check"
grep -Fq -- '-p dcentrald-common -p dcentrald-hal -p dcentrald' "$check"
grep -Fq 'cargo build --offline --locked --release --target "$TARGET"' "$check"
grep -Fq -- '-p dcentrald --bin dcentrald' "$check"
grep -Fq 'S19K_AARCH64_RELEASE_LINK_SMOKE_OK' "$check"
grep -Fq 'authority=none capsule_required=build-dcentrald.sh_amlogic' "$check"
grep -Fq 'release artifact reuses an older adopted-route binary' "$check"
if grep -Fq 's19k_native_build_verify.py" stage' "$check"; then
    echo "FAIL: mutable-checkout smoke path still mints a native build receipt" >&2
    exit 1
fi
grep -Fq 'capsule binds an immutable Git-object snapshot and complete Cargo graph' "$check"
grep -Fq -- '--release-link requires an explicit clean CARGO_TARGET_DIR' "$check"
grep -Fq 'CARGO_TARGET_DIR must be initially absent or empty' "$check"
grep -Fq 'CARGO_TARGET_DIR must not reuse a filesystem mount point' "$check"
grep -Fq 'CARGO_TARGET_DIR uses unsupported non-native filesystem type' "$check"
grep -Fq 'exec "$zig_bin" cc -target aarch64-linux-musl -mcpu=cortex_a53' "$cc_wrapper"
grep -Fq 'exec "$zig_bin" ar "$@"' "$ar_wrapper"

missing_output=$(mktemp)
fake_dir=$(mktemp -d)
trap 'rm -f "$missing_output"; rm -rf "$fake_dir"' EXIT HUP INT TERM

if bash "$check" --unknown >"$missing_output" 2>&1; then
    echo "FAIL: compile check accepted an unknown argument" >&2
    exit 1
fi
grep -Fq 'the only accepted argument is --release-link' "$missing_output"

if env -u ZIG_EXE bash "$check" >"$missing_output" 2>&1; then
    echo "FAIL: compile check accepted a missing ZIG_EXE" >&2
    exit 1
fi
grep -Fq 'ZIG_EXE must name the externally provisioned Zig 0.13.0 executable' \
    "$missing_output"

if env -u ZIG_EXE -u CARGO_TARGET_DIR bash "$check" --release-link \
    >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted a missing CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq -- '--release-link requires an explicit clean CARGO_TARGET_DIR' \
    "$missing_output"

if env -u ZIG_EXE CARGO_TARGET_DIR=relative-target bash "$check" --release-link \
    >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted a relative CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq 'CARGO_TARGET_DIR must be absolute for --release-link' "$missing_output"

mkdir "$fake_dir/populated-target"
printf 'stale\n' >"$fake_dir/populated-target/stale"
if env -u ZIG_EXE CARGO_TARGET_DIR="$fake_dir/populated-target" \
    bash "$check" --release-link >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted a populated CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq 'CARGO_TARGET_DIR must be initially absent or empty' "$missing_output"

if env -u ZIG_EXE CARGO_TARGET_DIR="$fake_dir/populated-target" \
    bash "$check" >"$missing_output" 2>&1; then
    echo "FAIL: ordinary check unexpectedly ran without ZIG_EXE" >&2
    exit 1
fi
grep -Fq 'ZIG_EXE must name the externally provisioned Zig 0.13.0 executable' \
    "$missing_output"

mkdir "$fake_dir/real-target"
ln -s "$fake_dir/real-target" "$fake_dir/symlink-target"
if env -u ZIG_EXE CARGO_TARGET_DIR="$fake_dir/symlink-target" \
    bash "$check" --release-link >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted a symlink CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq 'CARGO_TARGET_DIR must not be a symlink' "$missing_output"

if env -u ZIG_EXE CARGO_TARGET_DIR="$fake_dir/../$(basename "$fake_dir")/real-target" \
    bash "$check" --release-link >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted an ambiguous CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq 'CARGO_TARGET_DIR must be an unambiguous canonical path' "$missing_output"

if env -u ZIG_EXE CARGO_TARGET_DIR=/ bash "$check" --release-link \
    >"$missing_output" 2>&1; then
    echo "FAIL: release-link accepted a mount-point CARGO_TARGET_DIR" >&2
    exit 1
fi
grep -Fq 'CARGO_TARGET_DIR must not reuse a filesystem mount point' "$missing_output"

mkdir "$fake_dir/empty-target"
if env -u ZIG_EXE CARGO_TARGET_DIR="$fake_dir/empty-target" \
    bash "$check" --release-link >"$missing_output" 2>&1; then
    echo "FAIL: release-link unexpectedly reached a build without ZIG_EXE" >&2
    exit 1
fi
grep -Fq 'ZIG_EXE must name the externally provisioned Zig 0.13.0 executable' \
    "$missing_output"

absent_target="$fake_dir/absent-target"
if env -u ZIG_EXE CARGO_TARGET_DIR="$absent_target" \
    bash "$check" --release-link >"$missing_output" 2>&1; then
    echo "FAIL: release-link unexpectedly ran without ZIG_EXE" >&2
    exit 1
fi
grep -Fq 'ZIG_EXE must name the externally provisioned Zig 0.13.0 executable' \
    "$missing_output"
[ ! -e "$absent_target" ] || {
    echo "FAIL: release target admission created the absent target" >&2
    exit 1
}

if [ -d /mnt/c ] && [ "$(stat -f -c %T /mnt/c)" = v9fs ]; then
    v9fs_target=/mnt/c/dcent-s19k-release-target-must-not-exist
    if [ -e "$v9fs_target" ] || [ -L "$v9fs_target" ]; then
        echo "FAIL: reserved v9fs test target already exists" >&2
        exit 1
    fi
    if env -u ZIG_EXE CARGO_TARGET_DIR="$v9fs_target" \
        bash "$check" --release-link >"$missing_output" 2>&1; then
        echo "FAIL: release-link accepted a v9fs CARGO_TARGET_DIR" >&2
        exit 1
    fi
    grep -Fq 'unsupported non-native filesystem type: v9fs' "$missing_output"
fi

printf '#!/bin/sh\nprintf "0.13.0\\n"\n' >"$fake_dir/zig"
chmod 0700 "$fake_dir/zig"
if ZIG_EXE="$fake_dir/zig" bash "$check" >"$missing_output" 2>&1; then
    echo "FAIL: compile check accepted an unpinned Zig executable" >&2
    exit 1
fi
grep -Fq 'Zig executable SHA-256 is not the pinned Linux x86_64 0.13.0 identity' \
    "$missing_output"

echo "S19K_AARCH64_COMPILE_STATIC_OK"
