#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_ROOT=${BUILD_ROOT:-$ROOT_DIR/build-matrix}
DIST_ROOT=${DIST_ROOT:-$ROOT_DIR/dist}
INCLUDE_INTERNAL_TARGETS=${INCLUDE_INTERNAL_TARGETS:-0}
PACKAGE_SCRIPT="$SCRIPT_DIR/package-firmware.sh"
TARGET_MATRIX_TOOL="$SCRIPT_DIR/target_matrix.py"
PYTHON=${PYTHON:-python}

export CC_xtensa_esp32s3_espidf=${CC_xtensa_esp32s3_espidf:-xtensa-esp32s3-elf-gcc}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct -- .)}
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*) printf '%s\n' "Unable to derive numeric SOURCE_DATE_EPOCH" >&2; exit 1 ;;
esac
export SOURCE_DATE_EPOCH

cd "$ROOT_DIR"
"$PYTHON" "$TARGET_MATRIX_TOOL" validate

build_one() {
    feature=$1
    board_target=$2
    flash_layout=$3
    cargo_target_dir="$BUILD_ROOT/$board_target"
    release_dir="$cargo_target_dir/xtensa-esp32s3-espidf/release"

    if [ "$flash_layout" = "n16r8" ]; then
        sdkconfig_defaults="sdkconfig.defaults;sdkconfig.defaults.16mb"
        partitions_csv="$ROOT_DIR/partitions-16mb.csv"
    else
        sdkconfig_defaults="sdkconfig.defaults"
        partitions_csv="$ROOT_DIR/partitions.csv"
    fi

    printf '%s\n' "==> Building $board_target ($feature, $flash_layout)"
    CARGO_TARGET_DIR="$cargo_target_dir" \
        ESP_IDF_SDKCONFIG_DEFAULTS="$sdkconfig_defaults" \
        cargo build --locked --release -p dcentaxe --no-default-features --features "$feature"

    printf '%s\n' "==> Packaging $board_target"
    TARGET_DIR="$release_dir" \
        BOARD_TARGET="$board_target" \
        OUT_DIR="$DIST_ROOT/$board_target" \
        PARTITIONS_CSV="$partitions_csv" \
        "$PACKAGE_SCRIPT"
}

build_scope() {
    scope=$1
    "$PYTHON" "$TARGET_MATRIX_TOOL" list --scope "$scope" --format tsv |
        while IFS="$(printf '\t')" read -r feature board_target _device_model flash_layout _package_policy; do
            build_one "$feature" "$board_target" "$flash_layout"
        done
}

build_scope public
if [ "$INCLUDE_INTERNAL_TARGETS" = "1" ]; then
    build_scope internal
fi
