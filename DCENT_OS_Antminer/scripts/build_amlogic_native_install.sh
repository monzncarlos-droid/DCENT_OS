#!/usr/bin/env bash
#
# Extract a flashable Amlogic native-install rootfs image from an existing,
# validated Buildroot sysupgrade package. This helper does not build or publish
# packages. Destructive flashing remains operator-gated elsewhere.
#
# Usage:
#   scripts/build_amlogic_native_install.sh --variant s19jpro-aml
#   scripts/build_amlogic_native_install.sh --variant s19jproplus
#   scripts/build_amlogic_native_install.sh --variant s19kpro
# S19 XP / S19j XP / S21 XP are package-only and intentionally refused.
#   scripts/build_amlogic_native_install.sh --variant s21
#   scripts/build_amlogic_native_install.sh --variant s21pro
#   scripts/build_amlogic_native_install.sh --variant s21 --lab-unsigned
#
# The package must already exist under --output-dir (default: output/). Non-S9
# packaging has no authenticated capsule yet; this helper cannot create it.

set -euo pipefail

VARIANT=""
OUTPUT_DIR=""
LAB_UNSIGNED=0

usage() {
    echo "Usage: $(basename "$0") --variant s19jpro-aml|s19jproplus|s19kpro|s21|s21pro [--output-dir DIR] [--lab-unsigned]" >&2
    echo "       Extracts an existing validated sysupgrade tarball; does not build one." >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --variant)
            VARIANT="${2:-}"
            shift 2
            ;;
        --variant=*)
            VARIANT="${1#--variant=}"
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --output-dir=*)
            OUTPUT_DIR="${1#--output-dir=}"
            shift
            ;;
        --lab-unsigned)
            LAB_UNSIGNED=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown flag: $1" >&2
            usage
            exit 1
            ;;
    esac
done

[ -n "$VARIANT" ] || { echo "ERROR: missing --variant" >&2; usage; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
. "$SCRIPT_DIR/lib/am3_geometry.sh"
if [ -n "$OUTPUT_DIR" ]; then
    case "$OUTPUT_DIR" in
        /*|[A-Za-z]:*) ;;
        *) OUTPUT_DIR="$PROJECT_DIR/$OUTPUT_DIR" ;;
    esac
else
    OUTPUT_DIR="$PROJECT_DIR/output"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

case "$VARIANT" in
    s19jpro-aml|s19jpro|s19j)
        TARGET="am3-s19jpro-aml"
        BOARD_PKG_NAME="am3-s19jpro-aml"
        TAR_NAME="dcentos-sysupgrade-am3-s19jpro-aml.tar"
        ROOT_MEMBER="sysupgrade-am3-s19jpro-aml/root"
        BIN_NAME="dcentos-amlogic-s19jpro-aml.bin"
        ;;
    s19jproplus|s19j-pro-plus|s19jpro+)
        TARGET="am3-s19jproplus"
        BOARD_PKG_NAME="am3-s19jproplus"
        TAR_NAME="dcentos-sysupgrade-am3-s19jproplus.tar"
        ROOT_MEMBER="sysupgrade-am3-s19jproplus/root"
        BIN_NAME="dcentos-amlogic-s19jproplus.bin"
        ;;
    s19kpro|s19k)
        TARGET="am3-s19kpro"
        BOARD_PKG_NAME="am3-s19k"
        TAR_NAME="dcentos-sysupgrade-am3-s19kpro.tar"
        ROOT_MEMBER="sysupgrade-am3-s19k/root"
        BIN_NAME="dcentos-amlogic-s19kpro.bin"
        ;;
    s19xp|s19jxp|s19j-xp)
        echo "ERROR: S19 XP/S19j XP are NOT-IMPLEMENTED package-only targets; native install extraction is refused" >&2
        exit 2
        ;;
    s21)
        TARGET="am3-s21"
        BOARD_PKG_NAME="am3-s21"
        TAR_NAME="dcentos-sysupgrade-am3-s21.tar"
        ROOT_MEMBER="sysupgrade-am3-s21/root"
        BIN_NAME="dcentos-amlogic-s21.bin"
        ;;
    s21pro)
        TARGET="am3-s21pro"
        BOARD_PKG_NAME="am3-s21pro"
        TAR_NAME="dcentos-sysupgrade-am3-s21pro.tar"
        ROOT_MEMBER="sysupgrade-am3-s21pro/root"
        BIN_NAME="dcentos-amlogic-s21pro.bin"
        ;;
    *)
        echo "ERROR: unsupported Amlogic variant: $VARIANT (supported: s19jpro-aml, s19jproplus, s19kpro, s21, s21pro; S19 XP/S19j XP/S21 XP are package-only)" >&2
        exit 1
        ;;
esac

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

is_release_status() {
    case "${1:-release}" in
        release|production|stable) return 0 ;;
        *) return 1 ;;
    esac
}

if [ "$LAB_UNSIGNED" = "1" ]; then
    export DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1
    export DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-lab_unsigned}"
fi
DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}"
DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-release}"
if is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE" && is_release_status "$DCENT_PACKAGE_STATUS"; then
    echo "ERROR: DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 requires non-release DCENT_PACKAGE_STATUS (for example lab_unsigned)." >&2
    exit 1
fi
export DCENT_ALLOW_UNSIGNED_SYSUPGRADE DCENT_PACKAGE_STATUS

echo "=== DCENT_OS Amlogic native-install extraction ==="
echo "Variant: $VARIANT"
echo "Target:  $TARGET"
echo "Output:  $OUTPUT_DIR/$BIN_NAME"
echo ""

BIN_PATH="$OUTPUT_DIR/$BIN_NAME"
if [ -e "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
    echo "ERROR: refusing to replace existing native-image output: $BIN_PATH" >&2
    echo "       remove or relocate it explicitly after verifying it is not an alias" >&2
    exit 1
fi

TARBALL="$OUTPUT_DIR/$TAR_NAME"
[ -f "$TARBALL" ] || {
    echo "ERROR: expected existing tarball missing: $TARBALL" >&2
    echo "       this extractor does not invoke the disabled non-S9 packaging lane" >&2
    exit 2
}

DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}" \
DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-release}" \
DCENT_REQUIRE_INSTALLABLE_PACKAGE=1 \
    bash "$SCRIPT_DIR/pre_flash_validate.sh" --package-only "$TARBALL" "$BOARD_PKG_NAME"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

tar -xf "$TARBALL" -C "$TMPDIR" "$ROOT_MEMBER"
STAGED_ROOT="$TMPDIR/native-rootfs.bin"
cp "$TMPDIR/$ROOT_MEMBER" "$STAGED_ROOT"

ROOT_SIZE=$(stat -c%s "$STAGED_ROOT" 2>/dev/null || stat -f%z "$STAGED_ROOT")
case "$ROOT_SIZE" in
    ''|*[!0-9]*) echo "ERROR: extracted rootfs size is not numeric: $ROOT_SIZE" >&2; exit 1 ;;
esac
[ "$ROOT_SIZE" -le "$DCENT_AM3_ROOTFS_WINDOW_DEC" ] || {
    echo "ERROR: extracted rootfs exceeds Amlogic rootfs window: $ROOT_SIZE > $DCENT_AM3_ROOTFS_WINDOW_DEC" >&2
    exit 1
}
ROOT_MAGIC=$(od -An -N4 -tx1 "$STAGED_ROOT" 2>/dev/null | tr -d ' \n')
[ "$ROOT_MAGIC" = "27051956" ] || {
    echo "ERROR: extracted rootfs is not a uImage payload (magic=$ROOT_MAGIC)" >&2
    exit 1
}
ROOT_SHA=$(sha256sum "$STAGED_ROOT" | awk '{print $1}')

# Publish with a no-replace hard-link operation. Unlike cp/redirection, ln
# fails atomically if a regular file, hard link, or symlink appeared at the
# destination after the preflight check, so an alias can never be followed.
ln "$STAGED_ROOT" "$BIN_PATH" || {
    echo "ERROR: native-image output appeared during publication; refusing: $BIN_PATH" >&2
    exit 1
}

echo ""
echo "Flashable rootfs image:"
echo "  Path:   $BIN_PATH"
echo "  Size:   $ROOT_SIZE bytes"
echo "  Magic:  $ROOT_MAGIC"
echo "  SHA256: $ROOT_SHA"
echo ""
echo "Live NAND write is intentionally not performed by this build script."
echo "Operator-gated install still requires recovery path, physical access, readback, and reboot proof."
