#!/bin/sh
set -eu

umask 077
export LC_ALL=C

fail() {
    printf '%s\n' "s19k-ptrace-kat build refused: $*" >&2
    exit 1
}

[ -z "${WSL_INTEROP-}" ] || fail "WSL execution is prohibited"
[ -z "${WSL_DISTRO_NAME-}" ] || fail "WSL execution is prohibited"
case "$(uname -r 2>&1)" in
    *[Mm]icrosoft*) fail "WSL execution is prohibited" ;;
esac
[ ! -e /.dockerenv ] || fail "Docker execution is prohibited"
[ ! -e /run/.containerenv ] || fail "container execution is prohibited"
case "$(uname -s 2>&1)" in
    MINGW64_NT-*) ;;
    *) fail "native Windows Git-Bash (MINGW64) is required" ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CDPATH= cd -- "$SCRIPT_DIR"
[ -f "$SCRIPT_DIR/Cargo.toml" ] || fail "package root is incomplete"
[ -f "$SCRIPT_DIR/Cargo.lock" ] || fail "locked dependency graph is absent"
[ -f "$SCRIPT_DIR/kat-manifest.json" ] || fail "KAT manifest is absent"
[ ! -e "$SCRIPT_DIR/dist" ] && [ ! -L "$SCRIPT_DIR/dist" ] \
    || fail "dist already exists; preserve it as immutable evidence or remove it manually"
[ ! -e "$SCRIPT_DIR/target-kat" ] && [ ! -L "$SCRIPT_DIR/target-kat" ] \
    || fail "target-kat already exists; preserve it or remove it manually before a new build"

for command_name in cargo rustc python sha256sum wc cp chmod mkdir grep sed find sort cygpath env; do
    command_path=$(command -v "$command_name" 2>&1) \
        || fail "required build command is absent: $command_name"
    [ -n "$command_path" ] || fail "empty command resolution for $command_name"
done

UNCONTROLLED_CARGO_ENV=$(env | sed -n '/^CARGO_/p')
[ -z "$UNCONTROLLED_CARGO_ENV" ] || fail "uncontrolled CARGO_* environment is present"
for uncontrolled_name in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER \
    RUSTC_WORKSPACE_WRAPPER RUSTUP_TOOLCHAIN \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS; do
    eval "uncontrolled_value=\${$uncontrolled_name-}"
    [ -z "$uncontrolled_value" ] \
        || fail "uncontrolled build environment is set: $uncontrolled_name"
done
[ ! -e "$HOME/.cargo/config" ] && [ ! -L "$HOME/.cargo/config" ] \
    || fail "unbound Cargo home config exists"
[ ! -e "$HOME/.cargo/config.toml" ] && [ ! -L "$HOME/.cargo/config.toml" ] \
    || fail "unbound Cargo home config.toml exists"
config_parent=$(dirname -- "$SCRIPT_DIR")
while [ "$config_parent" != / ] && [ "$config_parent" != . ]; do
    [ ! -e "$config_parent/.cargo/config" ] && [ ! -L "$config_parent/.cargo/config" ] \
        || fail "unbound ancestor Cargo config exists: $config_parent"
    [ ! -e "$config_parent/.cargo/config.toml" ] && [ ! -L "$config_parent/.cargo/config.toml" ] \
        || fail "unbound ancestor Cargo config.toml exists: $config_parent"
    next_parent=$(dirname -- "$config_parent")
    [ "$next_parent" != "$config_parent" ] || break
    config_parent=$next_parent
done

RUSTC_VERSION=$(rustc --version)
case "$RUSTC_VERSION" in
    'rustc 1.90.0 '*) ;;
    *) fail "unexpected rustc version: $RUSTC_VERSION" ;;
esac

RUSTC_VERBOSE=$(rustc -vV)
RUSTC_RELEASE=$(printf '%s\n' "$RUSTC_VERBOSE" | sed -n 's/^release: //p')
RUSTC_COMMIT=$(printf '%s\n' "$RUSTC_VERBOSE" | sed -n 's/^commit-hash: //p')
RUSTC_HOST=$(printf '%s\n' "$RUSTC_VERBOSE" | sed -n 's/^host: //p')
[ "$RUSTC_RELEASE" = 1.90.0 ] || fail "unexpected rustc release: $RUSTC_RELEASE"
[ "$RUSTC_HOST" = x86_64-pc-windows-msvc ] || fail "unexpected rustc host: $RUSTC_HOST"
case "$RUSTC_COMMIT" in *[!0-9a-f]*|'') fail "rustc commit hash is not canonical lowercase hex" ;; esac
[ "${#RUSTC_COMMIT}" -eq 40 ] || fail "rustc commit hash width mismatch"

CARGO_VERSION=$(cargo --version | sed -n 's/^cargo \([0-9][0-9.]*\) .*/\1/p')
[ "$CARGO_VERSION" = 1.90.0 ] || fail "unexpected Cargo version: $CARGO_VERSION"

RUSTC_SYSROOT_NATIVE=$(rustc --print sysroot)
RUSTC_SYSROOT=$(cygpath -u "$RUSTC_SYSROOT_NATIVE")
[ -d "$RUSTC_SYSROOT" ] && [ ! -L "$RUSTC_SYSROOT" ] || fail "rustc sysroot is not canonical"
RUST_LLD="$RUSTC_SYSROOT/lib/rustlib/$RUSTC_HOST/bin/rust-lld.exe"
[ -f "$RUST_LLD" ] && [ ! -L "$RUST_LLD" ] || fail "bundled rust-lld.exe is absent"
RUST_LLD_NATIVE=$(cygpath -w "$RUST_LLD")
RUST_LLD_SHA=$(sha256sum "$RUST_LLD" | sed 's/[[:space:]].*$//')
RUST_LLD_BYTES=$(wc -c <"$RUST_LLD" | sed 's/[[:space:]]//g')

ARM_STD_MANIFEST="$RUSTC_SYSROOT/lib/rustlib/manifest-rust-std-armv7-unknown-linux-musleabihf"
AARCH64_STD_MANIFEST="$RUSTC_SYSROOT/lib/rustlib/manifest-rust-std-aarch64-unknown-linux-musl"
[ -f "$ARM_STD_MANIFEST" ] && [ ! -L "$ARM_STD_MANIFEST" ] \
    || fail "ARMv7 rust-std component manifest is absent"
[ -f "$AARCH64_STD_MANIFEST" ] && [ ! -L "$AARCH64_STD_MANIFEST" ] \
    || fail "AArch64 rust-std component manifest is absent"
ARM_STD_MANIFEST_SHA=$(sha256sum "$ARM_STD_MANIFEST" | sed 's/[[:space:]].*$//')
AARCH64_STD_MANIFEST_SHA=$(sha256sum "$AARCH64_STD_MANIFEST" | sed 's/[[:space:]].*$//')

SOURCE_PATHS='.cargo/config.toml
Cargo.lock
Cargo.toml
README.md
build.sh
fixture/Cargo.toml
fixture/src/main.rs
kat-manifest.json
run-target.sh
rust-toolchain.toml
test_verify_elf.py
tracer/Cargo.toml
tracer/src/main.rs
verify_elf.py'
ACTUAL_SOURCE_PATHS=$(CDPATH= cd -- "$SCRIPT_DIR" && find . -type f -print \
    | sed 's#^\./##' | sort)
[ "$ACTUAL_SOURCE_PATHS" = "$SOURCE_PATHS" ] \
    || fail "source file universe differs from the canonical manifest"

SOURCE_ROWS=
SOURCE_COUNT=0
for source_relative in $SOURCE_PATHS; do
    source_path="$SCRIPT_DIR/$source_relative"
    [ -f "$source_path" ] && [ ! -L "$source_path" ] \
        || fail "source input is absent or a symlink: $source_relative"
    source_sha=$(sha256sum "$source_path" | sed 's/[[:space:]].*$//')
    source_bytes=$(wc -c <"$source_path" | sed 's/[[:space:]]//g')
    SOURCE_ROWS=$SOURCE_ROWS$source_sha'  '$source_bytes'  '$source_relative'
'
    SOURCE_COUNT=$((SOURCE_COUNT + 1))
done
SOURCE_MANIFEST_SHA=$(printf '%s' "$SOURCE_ROWS" | sha256sum | sed 's/[[:space:]].*$//')
SOURCE_MANIFEST_BYTES=$(printf '%s' "$SOURCE_ROWS" | wc -c | sed 's/[[:space:]]//g')
LOCK_SHA=$(sha256sum "$SCRIPT_DIR/Cargo.lock" | sed 's/[[:space:]].*$//')
VERIFIER_SHA=$(sha256sum "$SCRIPT_DIR/verify_elf.py" | sed 's/[[:space:]].*$//')
TOOLCHAIN_SHA=$(sha256sum "$SCRIPT_DIR/rust-toolchain.toml" | sed 's/[[:space:]].*$//')
CONFIG_SHA=$(sha256sum "$SCRIPT_DIR/.cargo/config.toml" | sed 's/[[:space:]].*$//')

for evidence_sha in "$RUST_LLD_SHA" "$ARM_STD_MANIFEST_SHA" "$AARCH64_STD_MANIFEST_SHA" \
    "$SOURCE_MANIFEST_SHA" "$LOCK_SHA" "$VERIFIER_SHA" "$TOOLCHAIN_SHA" "$CONFIG_SHA"; do
    case "$evidence_sha" in *[!0-9a-f]*|'') fail "non-canonical evidence SHA-256" ;; esac
    [ "${#evidence_sha}" -eq 64 ] || fail "evidence SHA-256 width mismatch"
done

TARGET_DIR="$SCRIPT_DIR/target-kat"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="$RUST_LLD_NATIVE"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$RUST_LLD_NATIVE"

cargo build \
    --manifest-path "$SCRIPT_DIR/Cargo.toml" \
    --offline --locked --release --target armv7-unknown-linux-musleabihf \
    --package s19k-ptrace-tracer
cargo build \
    --manifest-path "$SCRIPT_DIR/Cargo.toml" \
    --offline --locked --release --target aarch64-unknown-linux-musl \
    --package s19k-ptrace-fixture

TRACER_SOURCE="$TARGET_DIR/armv7-unknown-linux-musleabihf/release/s19k-ptrace-tracer"
FIXTURE_SOURCE="$TARGET_DIR/aarch64-unknown-linux-musl/release/s19k-ptrace-fixture"
[ -f "$TRACER_SOURCE" ] && [ ! -L "$TRACER_SOURCE" ] || fail "ARMv7 tracer output is absent"
[ -f "$FIXTURE_SOURCE" ] && [ ! -L "$FIXTURE_SOURCE" ] || fail "AArch64 fixture output is absent"

mkdir -m 700 "$SCRIPT_DIR/dist"
TRACER="$SCRIPT_DIR/dist/tracer-armv7-static"
FIXTURE="$SCRIPT_DIR/dist/fixture-aarch64-static"
cp "$TRACER_SOURCE" "$TRACER"
cp "$FIXTURE_SOURCE" "$FIXTURE"
chmod 500 "$TRACER" "$FIXTURE"

python "$SCRIPT_DIR/verify_elf.py" \
    --path "$TRACER" --elf-class 32 --machine 40 --label tracer \
    --receipt "$SCRIPT_DIR/dist/tracer.elf.receipt"
python "$SCRIPT_DIR/verify_elf.py" \
    --path "$FIXTURE" --elf-class 64 --machine 183 --label fixture \
    --receipt "$SCRIPT_DIR/dist/fixture.elf.receipt"

POST_SOURCE_ROWS=
for source_relative in $SOURCE_PATHS; do
    source_path="$SCRIPT_DIR/$source_relative"
    [ -f "$source_path" ] && [ ! -L "$source_path" ] \
        || fail "source input changed type during the build: $source_relative"
    source_sha=$(sha256sum "$source_path" | sed 's/[[:space:]].*$//')
    source_bytes=$(wc -c <"$source_path" | sed 's/[[:space:]]//g')
    POST_SOURCE_ROWS=$POST_SOURCE_ROWS$source_sha'  '$source_bytes'  '$source_relative'
'
done
[ "$POST_SOURCE_ROWS" = "$SOURCE_ROWS" ] \
    || fail "source inputs changed during the build"
POST_SOURCE_PATHS=$(CDPATH= cd -- "$SCRIPT_DIR" && find . \
    -path ./dist -prune -o -path ./target-kat -prune -o -type f -print \
    | sed 's#^\./##' | sort)
[ "$POST_SOURCE_PATHS" = "$SOURCE_PATHS" ] \
    || fail "source file universe changed during the build"
[ "$(sha256sum "$RUST_LLD" | sed 's/[[:space:]].*$//')" = "$RUST_LLD_SHA" ] \
    || fail "rust-lld changed during the build"
[ "$(sha256sum "$ARM_STD_MANIFEST" | sed 's/[[:space:]].*$//')" = "$ARM_STD_MANIFEST_SHA" ] \
    || fail "ARMv7 rust-std component manifest changed during the build"
[ "$(sha256sum "$AARCH64_STD_MANIFEST" | sed 's/[[:space:]].*$//')" = "$AARCH64_STD_MANIFEST_SHA" ] \
    || fail "AArch64 rust-std component manifest changed during the build"

printf '%s' "$SOURCE_ROWS" >"$SCRIPT_DIR/dist/source-inputs.sha256"
chmod 400 "$SCRIPT_DIR/dist/source-inputs.sha256"
[ "$(sha256sum "$SCRIPT_DIR/dist/source-inputs.sha256" | sed 's/[[:space:]].*$//')" \
    = "$SOURCE_MANIFEST_SHA" ] || fail "published source manifest hash mismatch"

TRACER_SHA=$(sha256sum "$TRACER" | sed 's/[[:space:]].*$//')
FIXTURE_SHA=$(sha256sum "$FIXTURE" | sed 's/[[:space:]].*$//')
MANIFEST_SHA=$(sha256sum "$SCRIPT_DIR/kat-manifest.json" | sed 's/[[:space:]].*$//')
TRACER_BYTES=$(wc -c <"$TRACER" | sed 's/[[:space:]]//g')
FIXTURE_BYTES=$(wc -c <"$FIXTURE" | sed 's/[[:space:]]//g')
TRACER_ELF_RECEIPT_SHA=$(sha256sum "$SCRIPT_DIR/dist/tracer.elf.receipt" | sed 's/[[:space:]].*$//')
FIXTURE_ELF_RECEIPT_SHA=$(sha256sum "$SCRIPT_DIR/dist/fixture.elf.receipt" | sed 's/[[:space:]].*$//')

case "$TRACER_SHA:$FIXTURE_SHA:$MANIFEST_SHA:$TRACER_ELF_RECEIPT_SHA:$FIXTURE_ELF_RECEIPT_SHA" in
    *[!0-9a-f:]*|*::*|:*) fail "non-canonical SHA-256 output" ;;
esac
[ "${#TRACER_SHA}" -eq 64 ] && [ "${#FIXTURE_SHA}" -eq 64 ] \
    && [ "${#MANIFEST_SHA}" -eq 64 ] && [ "${#TRACER_ELF_RECEIPT_SHA}" -eq 64 ] \
    && [ "${#FIXTURE_ELF_RECEIPT_SHA}" -eq 64 ] \
    || fail "unexpected SHA-256 width"

RECEIPT="$SCRIPT_DIR/dist/kat-build.receipt"
[ ! -e "$RECEIPT" ] && [ ! -L "$RECEIPT" ] || fail "build receipt already exists"
{
    printf '%s\n' 'schema=s19k-ptrace-kat-build-v1'
    printf '%s\n' 'status=source-built-not-target-validated'
    printf '%s\n' "host=$RUSTC_HOST"
    printf '%s\n' 'shell=MINGW64'
    printf '%s\n' "rustc_version=$RUSTC_RELEASE"
    printf '%s\n' "rustc_commit=$RUSTC_COMMIT"
    printf '%s\n' "cargo_version=$CARGO_VERSION"
    printf '%s\n' 'cargo_offline=true'
    printf '%s\n' 'cargo_locked=true'
    printf '%s\n' 'cargo_incremental=off'
    printf '%s\n' 'linker_resolution=explicit-target-env'
    printf '%s\n' "rust_lld_sha256=$RUST_LLD_SHA"
    printf '%s\n' "rust_lld_bytes=$RUST_LLD_BYTES"
    printf '%s\n' "arm_rust_std_manifest_sha256=$ARM_STD_MANIFEST_SHA"
    printf '%s\n' "aarch64_rust_std_manifest_sha256=$AARCH64_STD_MANIFEST_SHA"
    printf '%s\n' "source_count=$SOURCE_COUNT"
    printf '%s\n' 'source_manifest_file=source-inputs.sha256'
    printf '%s\n' "source_manifest_sha256=$SOURCE_MANIFEST_SHA"
    printf '%s\n' "source_manifest_bytes=$SOURCE_MANIFEST_BYTES"
    printf '%s\n' "cargo_lock_sha256=$LOCK_SHA"
    printf '%s\n' "elf_verifier_sha256=$VERIFIER_SHA"
    printf '%s\n' "rust_toolchain_sha256=$TOOLCHAIN_SHA"
    printf '%s\n' "cargo_config_sha256=$CONFIG_SHA"
    printf '%s\n' 'tracer_target=armv7-unknown-linux-musleabihf'
    printf '%s\n' "tracer_sha256=$TRACER_SHA"
    printf '%s\n' "tracer_bytes=$TRACER_BYTES"
    printf '%s\n' 'tracer_elf_receipt=tracer.elf.receipt'
    printf '%s\n' "tracer_elf_receipt_sha256=$TRACER_ELF_RECEIPT_SHA"
    printf '%s\n' 'fixture_target=aarch64-unknown-linux-musl'
    printf '%s\n' "fixture_sha256=$FIXTURE_SHA"
    printf '%s\n' "fixture_bytes=$FIXTURE_BYTES"
    printf '%s\n' 'fixture_elf_receipt=fixture.elf.receipt'
    printf '%s\n' "fixture_elf_receipt_sha256=$FIXTURE_ELF_RECEIPT_SHA"
    printf '%s\n' "manifest_sha256=$MANIFEST_SHA"
    printf '%s\n' 'elf_verification=stdlib-parser-pass'
    printf '%s\n' 'production_authority=false'
} >"$RECEIPT"
chmod 400 "$RECEIPT"

printf '%s\n' "build receipt: $RECEIPT"
printf '%s\n' "tracer sha256: $TRACER_SHA ($TRACER_BYTES bytes)"
printf '%s\n' "fixture sha256: $FIXTURE_SHA ($FIXTURE_BYTES bytes)"
