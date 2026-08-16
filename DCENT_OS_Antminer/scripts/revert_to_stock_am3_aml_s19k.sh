#!/bin/sh
#
# revert_to_stock_am3_aml_s19k.sh — Revert an S19k Pro (Amlogic A113D,
# BM1366, BHB56902 hashboards) from DCENTos back to stock Bitmain
# firmware.
#
#  W12-B sibling of revert_to_stock_am3_aml_s21.sh. Same
# Amlogic uImage flash mechanism as S21, using scripts/lib/am3_geometry.sh. The
# difference (BM1366 + BHB56902 + APW121215f fw=0x76) is hashboard-side
# and doesn't change the flash primitives. Per
# .
#
# verified_revertable: false in PROFILE_TABLE.amlogic-a113d-bm1366 (W23 rename) —
# CODE-COMPLETE but NOT live-tested.  will run the full loop on
# the office S19k Pro before flipping that flag.
#
# Usage:
#   ./revert_to_stock_am3_aml_s19k.sh [--dry-run] <firmware_image.tar.gz> <sha256>

set -eu
# POSIX-sh (BusyBox ash) compatible.

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ ! -r "$SCRIPT_DIR/lib/am3_geometry.sh" ]; then
    echo "ERROR: missing shared AM3 geometry file: $SCRIPT_DIR/lib/am3_geometry.sh" >&2
    echo "Copy scripts/lib/am3_geometry.sh beside this revert helper before using it." >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/am3_geometry.sh"

DOWNLOAD_DIR="/tmp/stock_firmware_am3_aml_s19k"
MAX_EXTRACTED_KB="${DCENT_STOCK_REVERT_MAX_EXTRACTED_KB:-262144}"
ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ROOTFS_OFFSET="$DCENT_AM3_ROOTFS_OFFSET_HEX"
UIMAGE_MAGIC_HEX="27051956"
DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

# /242: firstboot-only is refused. Plan names recover_env.
# dry_run writes the plan before GPIO/nandwrite and exits 0.
write_revert_commit_plan() {
    _dry=$1
    _nand=$2
    REVERT_PLAN="/tmp/REVERT_COMMIT_PLAN.txt"
    {
        echo "schema=dcentos.amlogic-stock-image-revert/v1"
        echo "nandwrite_target=root"
        echo "rootfs_local=0x05100000"
        echo "rootfs_window=0x02800000"
        echo "commit=refused_firstboot_only"
        echo "bootcmd_reads_firstboot=false"
        echo "bootm_mtd2=false"
        echo "mix_flag_02=false"
        echo "uimage_write_is_not_recover_to_stock=true"
        echo "stock_return=recover_env_nandrecovery"
        echo "recover_env_source=nandrecovery_env.bin"
        echo "recover_env_ram=0x01060000"
        echo "nandrecovery_env_offset=0x0B000000"
        echo "env_size=0x10000"
        echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"
        echo "flag_02_helper=s19k_write_recovery_flag.sh"
        echo "does_not_arm_flag_02=true"
        echo "dry_run=$_dry"
        echo "nandwrite=$_nand"
        echo "gpio_write=$_nand"
        echo "execute=CLEAR_FOR_FLASH"
        echo "clear_for_flash=false"
    } > "$REVERT_PLAN"
    echo "  wrote $REVERT_PLAN dry_run=$_dry nandwrite=$_nand"
}

echo "==============================================================="
echo "  DCENTos -> Stock Bitmain Firmware Revert (S19k Pro / am3-aml)"
echo "==============================================================="
echo ""

CURRENT_SLOT=$(fw_printenv -n dcent_boot_slot 2>/dev/null || echo "1")
echo "Current dcent_boot_slot: $CURRENT_SLOT"
echo ""

FW_IMAGE="${1:-}"
EXPECTED_SHA256=$(printf '%s' "${2:-}" | tr 'A-F' 'a-f')
if [ -z "$FW_IMAGE" ]; then
    echo "ERROR: No firmware image specified."
    echo "Usage: $0 [--dry-run] /path/to/Antminer-S19k-Pro-merge-release-XXXXX.tar.gz <sha256>"
    exit 1
fi
if [ ${#EXPECTED_SHA256} -ne 64 ]; then
    echo "ERROR: stock revert requires expected SHA-256 (64 hex chars) as argv2" >&2
    exit 1
fi
case "$EXPECTED_SHA256" in
    *[!0-9a-f]*) echo "ERROR: expected SHA-256 is not hex" >&2; exit 1 ;;
esac

if [ ! -f "$FW_IMAGE" ]; then
    echo "ERROR: Firmware image not found: $FW_IMAGE"
    exit 1
fi

echo "Firmware image: $FW_IMAGE"
echo "Image size: $(ls -lh "$FW_IMAGE" | awk '{print $5}')"
echo ""

echo "Step 0: identity / geometry preflight (before REVERT prompt)..."
if [ -r /etc/dcentos/tmp_deploy ]; then
    echo "ERROR: /etc/dcentos/tmp_deploy leftover — refuse stock revert after /tmp bench deploy" >&2
    exit 1
fi
if [ ! -r /etc/dcentos/board_target ]; then
    echo "ERROR: missing live /etc/dcentos/board_target; refuse fail-open stock revert" >&2
    exit 1
fi
BT=$(tr -d ' \t\r\n' < /etc/dcentos/board_target)
case "$BT" in
    am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
    *)
        echo "ERROR: live board_target='$BT' is not am3-s19k; refuse fail-open stock revert" >&2
        exit 1
        ;;
esac
OFFSET_DEC=$((ROOTFS_OFFSET))
SIZE_SUM_WINDOW_DEC=$((0x05700000))
SIZE_SUM_FLAG_DEC=$((0x05300000))
SIZE_SUM_BASE_DEC=$((0x06100000))
ADMITTED_LOCAL_DEC=$((0x05100000))
if [ "$OFFSET_DEC" -eq "$SIZE_SUM_WINDOW_DEC" ] || [ "$OFFSET_DEC" -eq "$SIZE_SUM_FLAG_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is size-sum pairing 0x05700000/0x05300000; refuse as revert nandwrite base" >&2
    exit 1
fi
if [ "$OFFSET_DEC" -eq "$SIZE_SUM_BASE_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is size-sum 0x06100000 without the 6MiB hole; refuse as revert base" >&2
    exit 1
fi
if [ "$OFFSET_DEC" -ne "$ADMITTED_LOCAL_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is not admitted local 0x05100000 (nandrootfs − physical mtd5 0x06700000)" >&2
    exit 1
fi
echo "  identity=$BT tmp_deploy=absent rootfs_offset=$ROOTFS_OFFSET"

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum missing; refusing expected-SHA stock revert." >&2
    exit 1
fi
ACTUAL_SHA256=$(sha256sum "$FW_IMAGE" | awk '{print $1}' | tr 'A-F' 'a-f')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: firmware SHA-256 drift before extraction." >&2
    echo "  expected: $EXPECTED_SHA256" >&2
    echo "  actual:   $ACTUAL_SHA256" >&2
    exit 1
fi
echo "Firmware SHA-256 verified at extraction time."

echo "Step 1: Extracting firmware archive (classify before REVERT)..."
EXTRACT_DIR="/tmp/stock_extract"
trap 'rm -rf /tmp/stock_extract 2>/dev/null' EXIT
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
tar --no-same-owner --no-same-permissions --no-overwrite-dir \
    -xzf "$FW_IMAGE" -C "$EXTRACT_DIR"

EXTRACTED_KB=$(du -sk "$EXTRACT_DIR" | awk '{print $1}')
if [ "$EXTRACTED_KB" -gt "$MAX_EXTRACTED_KB" ]; then
    echo "ERROR: extracted firmware tree is ${EXTRACTED_KB} KiB, above cap ${MAX_EXTRACTED_KB} KiB"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
if find "$EXTRACT_DIR" -type f -links +1 -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: firmware archive contains hard-linked files; refusing destructive revert"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

UIMAGE=$(find "$EXTRACT_DIR" -type f \( -name 'rootfs_uImage*' -o -name '*uImage*' -o -name 'rootfs*.bin' \) | head -1)
if [ -z "$UIMAGE" ]; then
    echo "ERROR: No rootfs uImage found in firmware archive"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
UIMAGE_REAL=$(readlink -f "$UIMAGE")
case "$UIMAGE_REAL" in
    "$EXTRACT_DIR"/*) ;;
    *)
        echo "ERROR: uImage symlink escapes extract dir: $UIMAGE -> $UIMAGE_REAL"
        rm -rf "$EXTRACT_DIR"
        exit 1
        ;;
esac

HEAD8=$(head -c 8 "$UIMAGE_REAL" | od -An -tx1 | tr -d ' \n')
case "$HEAD8" in
    414e44524f494421*)
        echo "ERROR: ANDROID! boot.img is not an mtd5 uImage; refuse nandwrite" >&2
        rm -rf "$EXTRACT_DIR"
        exit 1
        ;;
esac
HEAD_HEX=$(printf '%s' "$HEAD8" | cut -c1-8)
if [ "$HEAD_HEX" != "$UIMAGE_MAGIC_HEX" ]; then
    echo "ERROR: rootfs payload lacks uImage magic 27051956 (got: $HEAD_HEX)"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
ARCH_HEX=$(dd if="$UIMAGE_REAL" bs=1 skip=29 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$ARCH_HEX" != "16" ]; then
    echo "ERROR: uImage IH_ARCH=$ARCH_HEX is not ARM64 (16); refuse nandwrite" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
UIMAGE_LEN=$(wc -c < "$UIMAGE_REAL" | tr -d ' \t\r\n')
if [ "$UIMAGE_LEN" -gt 41943040 ]; then
    echo "ERROR: uImage ${UIMAGE_LEN} B exceeds 0x02800000 window; refuse nandwrite" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
echo "  payload uImage IH_ARCH=ARM64 size=$UIMAGE_LEN admitted"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] writing REVERT_COMMIT_PLAN before GPIO/nandwrite..."
    echo "[DRY RUN] dry_run=true nandwrite=false gpio_write=false"
    write_revert_commit_plan true false
    echo "[DRY RUN] no GPIO write, no nandwrite; refusing firstboot-only"
    echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2."
    rm -rf "$EXTRACT_DIR" "$DOWNLOAD_DIR"
    exit 0
fi

echo "WARNING: This will write stock Bitmain firmware to $ROOTFS_MTD"
echo "         offset $ROOTFS_OFFSET (uImage rootfs). This nandwrite is"
echo "         NOT recover_to_stock / mtd2. firstboot-only commit is refused."
echo ""
printf "Type 'REVERT' to proceed: "
read CONFIRM
if [ "$CONFIRM" != "REVERT" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
# : firstboot-only is not a recover commit, and flag 0x02
# execute stays FLASH-gated. Do not GPIO/nandwrite then refuse.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "ERROR: CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/nandwrite/fw_setenv."
    write_revert_commit_plan false false
    echo "ERROR: refusing firstboot-only revert commit; .78 bootcmd never reads firstboot" >&2
    echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2." >&2
    echo "Stock-return is recover_to_stock (recover_env + nand erase.part nvdata)." >&2
    echo "This script does NOT arm flag 0x02 and does NOT fw_setenv firstboot." >&2
    echo "Use s19k_write_recovery_flag.sh --value 0x02 after CRC-admitting nandrecovery_env.bin." >&2
    rm -rf "$EXTRACT_DIR" "$DOWNLOAD_DIR"
    exit 1
fi

trap 'echo "INTERRUPTED -- forcing reboot via sysrq to recover into a clean boot state."; echo b > /proc/sysrq-trigger 2>/dev/null || reboot -f' INT TERM HUP
trap 'rm -rf /tmp/stock_extract 2>/dev/null' EXIT

echo "Step 1c: NAND/env tool preflight (before any NAND write)..."
if ! command -v nandwrite >/dev/null 2>&1; then
    echo "ERROR: nandwrite missing; refuse NAND write" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
if ! command -v fw_setenv >/dev/null 2>&1; then
    echo "ERROR: fw_setenv missing (Braiins L3); refuse NAND write before env-flip is possible" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
if ! command -v nanddump >/dev/null 2>&1; then
    echo "ERROR: nanddump missing; refuse NAND write without readback" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 1b: GPIO437 SafeOff (am3-s19k-active-low, value=1) before NAND write..."
PWR_GPIO=437
SYS=/sys/class/gpio
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "$PWR_GPIO" > "$SYS/export" 2>/dev/null || true
fi
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "ERROR: gpio437 missing after export — refusing stock revert NAND write" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
echo 0 > "$SYS/gpio$PWR_GPIO/active_low"
echo high > "$SYS/gpio$PWR_GPIO/direction"
echo 1 > "$SYS/gpio$PWR_GPIO/value"
VAL=$(cat "$SYS/gpio$PWR_GPIO/value")
if [ "$VAL" != "1" ]; then
    echo "ERROR: gpio437 value=$VAL after SafeOff (want 1 / DISABLE on am3-s19k)" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
echo "  gpio437 SafeOff OK polarity=am3-s19k-active-low value=$VAL"

echo "Step 2: Writing uImage to $ROOTFS_MTD offset $ROOTFS_OFFSET..."
if ! nandwrite -p -s "$ROOTFS_OFFSET" "$ROOTFS_MTD" "$UIMAGE_REAL"; then
    echo "ERROR: nandwrite failed -- rootfs slot may be partially overwritten."
    echo "DO NOT POWER CYCLE -- dcent_boot_slot has NOT been flipped."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 3: Post-write uImage magic readback..."
WROTE_HEX=$(nanddump -s "$ROOTFS_OFFSET" -l 4 "$ROOTFS_MTD" 2>/dev/null | tail -c 4 | od -An -tx1 | tr -d ' \n')
if [ "$WROTE_HEX" != "$UIMAGE_MAGIC_HEX" ]; then
    echo "ERROR: post-write readback at $ROOTFS_OFFSET lacks uImage magic 27051956 (got: $WROTE_HEX)"
    echo "DO NOT POWER CYCLE -- dcent_boot_slot has NOT been flipped."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 4: Revert commit plan (refusing firstboot-only)..."
# : .78 bootcmd never reads firstboot. Corpus stock-return is
# recover_to_stock = recover_env (nandrecovery_env @ 0x0B000000 → RAM
# 0x01060000, env import 0x10000) + nand erase.part nvdata, armed by
# flag 0x02 via s19k_write_recovery_flag.sh. This uImage nandwrite is
# NOT recover_to_stock and does NOT boot mtd2. Mixing firstboot+0x02 is
# refused. Execute of flag 0x02 stays CLEAR_FOR_FLASH=false.
write_revert_commit_plan false true
echo "ERROR: refusing firstboot-only revert commit; .78 bootcmd never reads firstboot" >&2
echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2." >&2
echo "Stock-return is recover_to_stock (recover_env + nand erase.part nvdata)." >&2
echo "This script does NOT arm flag 0x02 and does NOT fw_setenv firstboot." >&2
echo "Use s19k_write_recovery_flag.sh --value 0x02 after CRC-admitting nandrecovery_env.bin." >&2
rm -rf "$EXTRACT_DIR" "$DOWNLOAD_DIR"
exit 1
