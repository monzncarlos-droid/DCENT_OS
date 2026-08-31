#!/usr/bin/env bash
# Offline cfg/type-check for the production S19k AArch64 daemon route.

set -euo pipefail

readonly TARGET=aarch64-unknown-linux-musl
readonly EXPECTED_ZIG_VERSION=0.13.0
readonly EXPECTED_ZIG_SHA256=7f9e3a661e909d5188d1b8b14f082b98a19c323a30d43bfdd1b2893ed37273e0

fail() {
    printf 'S19K_AARCH64_COMPILE_REFUSED: %s\n' "$1" >&2
    exit "${2:-1}"
}

admit_release_target() {
    if [ -z "${CARGO_TARGET_DIR:-}" ]; then
        fail "--release-link requires an explicit clean CARGO_TARGET_DIR" 64
    fi
    case "$CARGO_TARGET_DIR" in
        /*) ;;
        *) fail "CARGO_TARGET_DIR must be absolute for --release-link" 64 ;;
    esac

    command -v realpath >/dev/null 2>&1 || fail "realpath is required" 69
    command -v stat >/dev/null 2>&1 || fail "stat is required" 69
    command -v find >/dev/null 2>&1 || fail "find is required" 69
    command -v mountpoint >/dev/null 2>&1 || fail "mountpoint is required" 69

    target_root=$CARGO_TARGET_DIR
    if [ -L "$target_root" ]; then
        fail "CARGO_TARGET_DIR must not be a symlink" 65
    fi
    if [ -e "$target_root" ]; then
        [ -d "$target_root" ] \
            || fail "CARGO_TARGET_DIR exists but is not a directory" 65
        canonical_target=$(realpath -- "$target_root")
        [ "$canonical_target" = "$target_root" ] \
            || fail "CARGO_TARGET_DIR must be an unambiguous canonical path" 65
        if mountpoint -q -- "$target_root"; then
            fail "CARGO_TARGET_DIR must not reuse a filesystem mount point" 65
        fi
        if find "$target_root" -mindepth 1 -maxdepth 1 -print -quit \
            | grep -q .; then
            fail "CARGO_TARGET_DIR must be initially absent or empty" 65
        fi
        filesystem_probe=$target_root
    else
        target_parent=$(dirname -- "$target_root")
        target_leaf=$(basename -- "$target_root")
        [ -d "$target_parent" ] && [ ! -L "$target_parent" ] \
            || fail "CARGO_TARGET_DIR parent must be an existing non-symlink directory" 65
        canonical_parent=$(realpath -- "$target_parent")
        [ "$canonical_parent/$target_leaf" = "$target_root" ] \
            || fail "CARGO_TARGET_DIR must be an unambiguous canonical path" 65
        filesystem_probe=$canonical_parent
    fi

    target_filesystem=$(stat -f -c %T -- "$filesystem_probe")
    case "$target_filesystem" in
        9p|v9fs|drvfs|fuseblk|cifs|nfs|nfs4)
            fail "CARGO_TARGET_DIR uses unsupported non-native filesystem type: $target_filesystem" 65
            ;;
    esac
}

mode=check
case "$#" in
    0) ;;
    1)
        [ "$1" = "--release-link" ] \
            || fail "the only accepted argument is --release-link" 64
        mode=release-link
        ;;
    *) fail "the only accepted argument is --release-link" 64 ;;
esac

case "$(uname -s):$(uname -m)" in
    Linux:x86_64) ;;
    *) fail "the pinned Zig identity is for a Linux x86_64 verification host" 64 ;;
esac

if [ "$mode" = release-link ]; then
    admit_release_target
fi

if [ -z "${ZIG_EXE:-}" ]; then
    fail "ZIG_EXE must name the externally provisioned Zig 0.13.0 executable" 64
fi
case "$ZIG_EXE" in
    /*) ;;
    *) fail "ZIG_EXE must be an absolute path" 64 ;;
esac
if [ ! -f "$ZIG_EXE" ] || [ ! -x "$ZIG_EXE" ] || [ -L "$ZIG_EXE" ]; then
    fail "ZIG_EXE must be an executable regular non-symlink file" 64
fi
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required" 69
observed_zig_sha256=$(sha256sum "$ZIG_EXE" | awk '{print $1}')
if [ "$observed_zig_sha256" != "$EXPECTED_ZIG_SHA256" ]; then
    fail "Zig executable SHA-256 is not the pinned Linux x86_64 0.13.0 identity" 65
fi
observed_zig_version=$("$ZIG_EXE" version)
if [ "$observed_zig_version" != "$EXPECTED_ZIG_VERSION" ]; then
    fail "Zig version is not exactly $EXPECTED_ZIG_VERSION" 65
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
project_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
daemon_root="$project_root/dcentrald"
cc_wrapper="$daemon_root/zig-cc-aarch64.sh"
ar_wrapper="$daemon_root/zig-ar-aarch64.sh"
for wrapper in "$cc_wrapper" "$ar_wrapper"; do
    if [ ! -f "$wrapper" ] || [ -L "$wrapper" ]; then
        fail "cross wrapper is missing or unsafe: $wrapper" 66
    fi
    bash -n "$wrapper" || fail "cross wrapper has invalid shell syntax: $wrapper" 65
done

cd "$daemon_root"
command -v rustc >/dev/null 2>&1 || fail "rustc is required" 69
command -v cargo >/dev/null 2>&1 || fail "cargo is required" 69
command -v rustup >/dev/null 2>&1 || fail "rustup is required" 69
case "$(rustc --version)" in
    "rustc 1.90.0 "*) ;;
    *) fail "rustc must resolve to the repository-pinned 1.90.0 toolchain" 65 ;;
esac
rustup target list --installed | grep -Fxq "$TARGET" \
    || fail "Rust target $TARGET is not installed" 69

export CARGO_NET_OFFLINE=true
export CC_aarch64_unknown_linux_musl="$cc_wrapper"
export AR_aarch64_unknown_linux_musl="$ar_wrapper"

if [ "$mode" = release-link ]; then
    # Re-admit immediately before Cargo to catch pre-build path substitution or
    # population after the initial command-line admission.
    admit_release_target
    cargo build --offline --locked --release --target "$TARGET" \
        -p dcentrald --bin dcentrald
    artifact="$target_root/$TARGET/release/dcentrald"
    if [ ! -f "$artifact" ] || [ ! -x "$artifact" ] || [ -L "$artifact" ]; then
        fail "release artifact is missing or unsafe: $artifact" 66
    fi
    command -v readelf >/dev/null 2>&1 || fail "readelf is required" 69
    readelf -h "$artifact" | grep -F 'Class:                             ELF64' >/dev/null \
        || fail "release artifact is not ELF64" 65
    readelf -h "$artifact" | grep -F 'Machine:                           AArch64' >/dev/null \
        || fail "release artifact is not AArch64" 65
    artifact_sha256=$(sha256sum "$artifact" | awk '{print $1}')
    case "$artifact_sha256" in
        fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b|\
        9570a9fcd8e8a2cff6f3d21902f6354666c5b337b7b260641e5b0baf9260b4d6)
            fail "release artifact reuses an older adopted-route binary" 65
            ;;
    esac
    artifact_bytes=$(stat -c %s "$artifact")
    # This mutable-checkout path is a linker smoke test only.  A release-chain
    # receipt must come from build-dcentrald.sh amlogic, whose schema-v4 build
    # capsule binds an immutable Git-object snapshot and complete Cargo graph.
    printf 'S19K_AARCH64_RELEASE_LINK_SMOKE_OK target=%s profile=release sha256=%s bytes=%s authority=none capsule_required=build-dcentrald.sh_amlogic\n' \
        "$TARGET" "$artifact_sha256" "$artifact_bytes"
else
    cargo check --offline --locked --target "$TARGET" \
        -p dcentrald-common -p dcentrald-hal -p dcentrald
    printf 'S19K_AARCH64_COMPILE_OK target=%s rust=1.90.0 zig=%s zig_sha256=%s\n' \
        "$TARGET" "$EXPECTED_ZIG_VERSION" "$EXPECTED_ZIG_SHA256"
fi
