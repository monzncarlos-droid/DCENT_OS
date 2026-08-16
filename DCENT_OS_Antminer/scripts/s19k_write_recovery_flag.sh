#!/bin/sh
#
# s19k_write_recovery_flag.sh — plan / host fixture / env-gated execute of
# the am3-s19k U-Boot recovery-flag byte.
#
# Values:
#   0x01 — verify-only InstallArm / FirstBosThenSetFlag2 plan + 128 KiB fixture.
#           Execute FLASH NOT_YET (not a NAND commit).
#   0x02 — U-Boot stock revert (recover_to_stock). Default.
#   0x03 — verify-only SuccessfulKeepBos / boot_bos plan + 128 KiB fixture.
#           Execute FLASH NOT_YET.
# 0x02 is NOT a direct bootm of mtd2 stock_system and NOT fw_setenv firstboot 1.
# 0x03 is NOT recover_to_stock and NOT a direct bootm of mtd2.
#
# Default is --verify-only.
# --fixture-in/--fixture-out rewrites a 128 KiB buffer on the host (no NAND).
# --execute requires DCENT_S19K_RECOVERY_FLAG_EXECUTE=1, CLEAR_FOR_FLASH=true,
# live /etc/dcentos/board_target (am3-s19k aliases), GPIO437 SafeOff=1, and
# an eraseblock-aligned flag (byte_in_block=0) using the S99upgrade
# flash_erase + one-byte nandwrite pattern.
#
# FLASH NOT_YET. Env=1 is not a NAND write. Braiins /tmp success is not stock GO.

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ ! -r "$SCRIPT_DIR/lib/am3_geometry.sh" ]; then
    echo "ERROR: missing $SCRIPT_DIR/lib/am3_geometry.sh" >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/am3_geometry.sh"

VALUE="$DCENT_AM3_RECOVERY_FLAG_STOCK_REVERT"
MTD5_BASE="0x06700000"
VERIFY_ONLY=true
EXECUTE=false
FIXTURE_IN=""
FIXTURE_OUT=""

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") [--value 0x02] [--mtd5-base 0x06700000|--proc-mtd FILE] [--verify-only|--execute] [--fixture-in FILE --fixture-out FILE]

  --value 0x01: verify-only InstallArm plan + 128 KiB fixture (execute FLASH NOT_YET).
  --value 0x02: U-Boot stock revert (default).
  --value 0x03: verify-only SuccessfulKeepBos plan + 128 KiB fixture (execute FLASH NOT_YET).
  --fixture-in/--fixture-out: rewrite a 131072-byte eraseblock buffer (host CI, 0x01/0x02/0x03).
  --execute is refused unless DCENT_S19K_RECOVERY_FLAG_EXECUTE=1 (0x02 only).
  FLASH-false, missing live board_target, and missing GPIO437 SafeOff also refuse.
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --value)
            [ $# -ge 2 ] || usage
            VALUE=$2
            shift 2
            ;;
        --mtd5-base)
            [ $# -ge 2 ] || usage
            MTD5_BASE=$2
            shift 2
            ;;
        --proc-mtd)
            [ $# -ge 2 ] || usage
            COMPUTED=$(dcent_am3_mtd5_base_from_proc_mtd "$2") || {
                echo "ERROR: cannot compute mtd5 base from $2" >&2
                exit 1
            }
            MTD5_BASE=$COMPUTED
            shift 2
            ;;
        --fixture-in)
            [ $# -ge 2 ] || usage
            FIXTURE_IN=$2
            shift 2
            ;;
        --fixture-out)
            [ $# -ge 2 ] || usage
            FIXTURE_OUT=$2
            shift 2
            ;;
        --verify-only)
            VERIFY_ONLY=true
            EXECUTE=false
            shift
            ;;
        --execute)
            EXECUTE=true
            VERIFY_ONLY=false
            shift
            ;;
        -h|--help) usage ;;
        *) echo "ERROR: unknown arg: $1" >&2; usage ;;
    esac
done

case "$VALUE" in
    0x02|2|02) VALUE=0x02 ;;
    0x03|3|03) VALUE=0x03 ;;
    0x01|1|01) VALUE=0x01 ;;
    *)
        echo "ERROR: refuse recovery flag $VALUE" >&2
        exit 1
        ;;
esac

if [ "$MTD5_BASE" = "0x06100000" ] || [ "$MTD5_BASE" = "0x6100000" ]; then
    echo "ERROR: 0x06100000 is sum(mtd0-4) without the 6MiB hole; refuse as physical mtd5" >&2
    exit 1
fi

BASE_DEC=$((MTD5_BASE))
GLOBAL_DEC=$((DCENT_AM3_RECOVERY_FLAG_GLOBAL))
if [ "$BASE_DEC" -eq 0 ] || [ "$BASE_DEC" -gt "$GLOBAL_DEC" ]; then
    echo "ERROR: mtd5 base $MTD5_BASE cannot produce a local flag offset" >&2
    exit 1
fi
LOCAL_DEC=$((GLOBAL_DEC - BASE_DEC))
LOCAL_HEX=$(printf '0x%08X' "$LOCAL_DEC")

ERASESIZE=${DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED:-131072}
EB_INDEX=$((LOCAL_DEC / ERASESIZE))
EB_START=$((EB_INDEX * ERASESIZE))
EB_OFF=$((LOCAL_DEC % ERASESIZE))
EB_START_HEX=$(printf '0x%08X' "$EB_START")
EB_OFF_HEX=$(printf '0x%X' "$EB_OFF")

# : one host fixture rewrite for 0x01 / 0x02 / 0x03.
# Does not write NAND. Caller prints plan fields first.
rewrite_recovery_flag_fixture() {
    if [ -z "$FIXTURE_IN" ] || [ -z "$FIXTURE_OUT" ]; then
        echo "ERROR: --fixture-in and --fixture-out must be used together" >&2
        exit 1
    fi
    if [ ! -f "$FIXTURE_IN" ]; then
        echo "ERROR: fixture-in missing: $FIXTURE_IN" >&2
        exit 1
    fi
    IN_LEN=$(wc -c < "$FIXTURE_IN" | tr -d ' \t')
    if [ "$IN_LEN" -ne "$ERASESIZE" ]; then
        echo "ERROR: fixture-in must be exactly $ERASESIZE bytes (got $IN_LEN)" >&2
        exit 1
    fi
    dd if="$FIXTURE_IN" of="$FIXTURE_OUT" bs="$ERASESIZE" count=1 conv=notrunc 2>/dev/null
    case "$VALUE" in
        0x01)
            printf '\001' | dd of="$FIXTURE_OUT" bs=1 seek="$EB_OFF" conv=notrunc 2>/dev/null
            echo "fixture_value=0x01"
            ;;
        0x02)
            printf '\002' | dd of="$FIXTURE_OUT" bs=1 seek="$EB_OFF" conv=notrunc 2>/dev/null
            echo "fixture_value=0x02"
            ;;
        0x03)
            printf '\003' | dd of="$FIXTURE_OUT" bs=1 seek="$EB_OFF" conv=notrunc 2>/dev/null
            echo "fixture_value=0x03"
            ;;
        *)
            echo "ERROR: refuse fixture rewrite for $VALUE" >&2
            exit 1
            ;;
    esac
    OUT_LEN=$(wc -c < "$FIXTURE_OUT" | tr -d ' \t')
    if [ "$OUT_LEN" -ne "$ERASESIZE" ]; then
        echo "ERROR: fixture-out length $OUT_LEN != $ERASESIZE" >&2
        exit 1
    fi
    echo "mode=fixture-rewrite"
    echo "fixture_out=$FIXTURE_OUT"
}

# : 0x03 is rust SuccessfulKeepBos / BootBos. Plan + fixture only.
if [ "$VALUE" = "0x03" ]; then
    if [ "$EXECUTE" = true ]; then
        echo "ERROR: recovery flag 0x03 execute is FLASH NOT_YET (SuccessfulKeepBos plan/fixture only)" >&2
        exit 1
    fi
    echo "schema=dcentos.amlogic-successful-flag/v1"
    echo "SUCCESSFUL_FLAG_PLAN=1"
    echo "intent=SuccessfulKeepBos"
    echo "value=0x03"
    echo "mtd5_base=$MTD5_BASE"
    echo "local_offset=$LOCAL_HEX"
    echo "target_mtd=5"
    echo "eraseblock_index=$EB_INDEX"
    echo "eraseblock_start=$EB_START_HEX"
    echo "byte_in_block=$EB_OFF_HEX"
    echo "erase_count=1"
    echo "rewriter=eraseblock_rewrite"
    echo "dry_flash_erase=flash_erase /dev/mtd5 $EB_START_HEX 1"
    echo "dry_nandwrite=printf '\\\\x03' | nandwrite -p -s $EB_START_HEX /dev/mtd5"
    echo "uboot_action=BootBos"
    echo "promote_from=0x02"
    echo "firstboot=S99_WAL_companion_only"
    echo "bootcmd_reads_firstboot=false"
    echo "bootm_mtd2=false"
    echo "recover_to_stock=false"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    if [ -n "$FIXTURE_IN" ] || [ -n "$FIXTURE_OUT" ]; then
        rewrite_recovery_flag_fixture
        exit 0
    fi
    echo "mode=verify-only"
    exit 0
fi

# : 0x01 is rust InstallArm / FirstBosThenSetFlag2. Plan + fixture
# only. --execute stays FLASH NOT_YET (not a NAND commit).
if [ "$VALUE" = "0x01" ]; then
    if [ "$EXECUTE" = true ]; then
        echo "ERROR: recovery flag 0x01 execute is FLASH NOT_YET (InstallArm plan/fixture only)" >&2
        exit 1
    fi
    echo "schema=dcentos.amlogic-install-commit/v1"
    echo "INSTALL_COMMIT_PLAN=1"
    echo "intent=InstallArm"
    echo "value=0x01"
    echo "mtd5_base=$MTD5_BASE"
    echo "local_offset=$LOCAL_HEX"
    echo "target_mtd=5"
    echo "eraseblock_index=$EB_INDEX"
    echo "eraseblock_start=$EB_START_HEX"
    echo "byte_in_block=$EB_OFF_HEX"
    echo "erase_count=1"
    echo "rewriter=eraseblock_rewrite"
    echo "dry_flash_erase=flash_erase /dev/mtd5 $EB_START_HEX 1"
    echo "dry_nandwrite=printf '\\\\x01' | nandwrite -p -s $EB_START_HEX /dev/mtd5"
    echo "uboot_action=FirstBosThenSetFlag2"
    echo "firstboot=S99_WAL_companion_only"
    echo "bootcmd_reads_firstboot=false"
    echo "bootm_mtd2=false"
    echo "recover_to_stock=false"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    if [ -n "$FIXTURE_IN" ] || [ -n "$FIXTURE_OUT" ]; then
        rewrite_recovery_flag_fixture
        exit 0
    fi
    echo "mode=verify-only"
    exit 0
fi

echo "schema=dcentos.amlogic-recovery-flag/v1"
echo "intent=UbootStockRevert"
echo "value=$VALUE"
echo "mtd5_base=$MTD5_BASE"
echo "local_offset=$LOCAL_HEX"
echo "target_mtd=5"
echo "eraseblock_index=$EB_INDEX"
echo "eraseblock_start=$EB_START_HEX"
echo "byte_in_block=$EB_OFF_HEX"
echo "erase_count=1"
echo "rewriter=eraseblock_rewrite"
echo "dry_flash_erase=flash_erase /dev/mtd5 $EB_START_HEX 1"
echo "dry_nandwrite=printf '\\\\x02' | nandwrite -p -s $EB_START_HEX /dev/mtd5"
echo "clear_for_flash=false"
echo "env_flip=false"
echo "recover_env_source=nandrecovery_env.bin"
echo "nand_env_bak_is_not_nandrecovery_env=true"
echo "nand_erase_part=nvdata"
echo "bootm_mtd2=false"
echo "recover_execute=refused"
echo "reason=CLEAR_FOR_FLASH"
echo "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
echo "fail=nand_erase_or_env_import_without_admit"
echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"

if [ -n "$FIXTURE_IN" ] || [ -n "$FIXTURE_OUT" ]; then
    rewrite_recovery_flag_fixture
    if [ "$EXECUTE" = false ]; then
        exit 0
    fi
fi

if [ "$VERIFY_ONLY" = true ]; then
    echo "mode=verify-only"
    exit 0
fi

if [ "${DCENT_S19K_RECOVERY_FLAG_EXECUTE:-0}" != 1 ]; then
    echo "ERROR: --execute refused (DCENT_S19K_RECOVERY_FLAG_EXECUTE!=1); NAND byte write not proven" >&2
    exit 1
fi

if [ "$EB_OFF" -ne 0 ]; then
    echo "ERROR: byte_in_block must be 0 for S99-style one-byte nandwrite after erase; unaligned needs a full 128 KiB rewrite" >&2
    exit 1
fi

if [ -n "$FIXTURE_OUT" ]; then
    echo "mode=fixture-execute-offline"
    echo "nand=skipped"
    exit 0
fi

if ! command -v flash_erase >/dev/null 2>&1 || ! command -v nandwrite >/dev/null 2>&1; then
    echo "ERROR: flash_erase/nandwrite missing; refuse on-device execute" >&2
    exit 1
fi
if [ ! -e /dev/mtd5 ]; then
    echo "ERROR: /dev/mtd5 missing; refuse on-device execute" >&2
    exit 1
fi

# : env=1 is not a NAND write. Do not flash_erase/nandwrite then refuse.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "ERROR: CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite."
    echo "schema=dcentos.amlogic-recovery-flag/v1"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "verify-only/fixture already host-safe; FLASH NOT_YET"
    exit 1
fi

if [ ! -r /etc/dcentos/board_target ]; then
    echo "ERROR: missing live /etc/dcentos/board_target; refuse fail-open recovery-flag write" >&2
    exit 1
fi
BT=$(tr -d ' \t\r\n' < /etc/dcentos/board_target)
case "$BT" in
    am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
    *)
        echo "ERROR: live board_target='$BT' is not am3-s19k; refuse fail-open recovery-flag write" >&2
        exit 1
        ;;
esac

echo "Step 1: gpio437 SafeOff (am3-s19k-active-low, value=1) before NAND write..."
PWR_GPIO=437
SYS=/sys/class/gpio
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "$PWR_GPIO" > "$SYS/export" 2>/dev/null || true
fi
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "ERROR: gpio437 missing after export — refusing recovery-flag NAND write" >&2
    exit 1
fi
echo 0 > "$SYS/gpio$PWR_GPIO/active_low"
echo high > "$SYS/gpio$PWR_GPIO/direction"
echo 1 > "$SYS/gpio$PWR_GPIO/value"
VAL=$(cat "$SYS/gpio$PWR_GPIO/value")
if [ "$VAL" != "1" ]; then
    echo "ERROR: gpio437 value=$VAL after SafeOff (want 1 / DISABLE on am3-s19k)" >&2
    exit 1
fi
echo "  gpio437 SafeOff OK polarity=am3-s19k-active-low value=$VAL"

sync
if ! flash_erase /dev/mtd5 "$EB_START_HEX" 1; then
    echo "ERROR: flash_erase /dev/mtd5 $EB_START_HEX failed" >&2
    exit 1
fi
if ! printf '\002' | nandwrite -p -s "$EB_START_HEX" /dev/mtd5; then
    echo "ERROR: nandwrite 0x02 at $EB_START_HEX failed" >&2
    exit 1
fi
if command -v nanddump >/dev/null 2>&1; then
    READBACK=$(nanddump -q -s "$LOCAL_HEX" -l 1 /dev/mtd5 | od -An -tx1 | tr -d ' \n')
    case "$READBACK" in
        02*) echo "readback=0x02" ;;
        *)
            echo "ERROR: nanddump readback=$READBACK expected 02" >&2
            exit 1
            ;;
    esac
fi
echo "mode=execute-eraseblock-rewrite"
echo "nand=erased+programmed"
echo "clear_for_flash=false"
