#!/bin/sh
#
# recover_amlogic_to_stock.sh — walk installer RECOVER_TO_STOCK_PLAN.txt.
#
# U-Boot recover_to_stock on .78 is:
#   run recover_env; nand erase.part nvdata; reset
# recover_env is:
#   nand read 01060000 ${nandrecovery_env_offset} ${env_size}
#   env default -a
#   env import -d -c 01060000 0x10000
#   env save
#
# nand_env.bak is /dev/nand_env and is NOT recover_env.
# Linux nandwrite / fw_setenv is NOT U-Boot recover_env.
# firstboot is NOT a stock-return path.
#
# Default is --dry-run (alias --verify-only): CRC-admit the sidecar,
# walk step0/1/2, write RECOVER_WALK.txt, refuse NAND.
# --execute still FLASH NOT_YET after typing RECOVER.
#
# Order on --execute:
#   Type 'RECOVER' < CLEAR_FOR_FLASH < live board_target
#   < GPIO437 SafeOff=1 < live /proc/mtd < nandwrite (never reached)

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ ! -r "$SCRIPT_DIR/lib/am3_geometry.sh" ]; then
    echo "ERROR: missing $SCRIPT_DIR/lib/am3_geometry.sh" >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/am3_geometry.sh"

ARTIFACT_DIR=""
DRY_RUN=true
VERIFY_ONLY=true
EXECUTE=false

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") --artifact-dir DIR [--dry-run|--verify-only|--execute]

  --artifact-dir DIR   RECOVER_TO_STOCK_PLAN.txt + nandrecovery_env.bin
  --dry-run            walk ImportNandrecoveryEnv / EraseNvdata / Reset (default)
  --verify-only        alias of --dry-run
  --execute            Type 'RECOVER' then refuse FLASH/NAND

nand_env.bak is not recover_env. clear_for_flash=false. FLASH NOT_YET.
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --artifact-dir)
            [ $# -ge 2 ] || usage
            ARTIFACT_DIR=$2
            shift 2
            ;;
        --dry-run|--verify-only)
            DRY_RUN=true
            VERIFY_ONLY=true
            EXECUTE=false
            shift
            ;;
        --execute)
            EXECUTE=true
            DRY_RUN=false
            VERIFY_ONLY=false
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "ERROR: unknown arg: $1" >&2
            usage
            ;;
    esac
done

[ -n "$ARTIFACT_DIR" ] || usage

PLAN="$ARTIFACT_DIR/RECOVER_TO_STOCK_PLAN.txt"
NANDRECOVERY_ENV="$ARTIFACT_DIR/nandrecovery_env.bin"
WALK="$ARTIFACT_DIR/RECOVER_WALK.txt"
REFUSE="$ARTIFACT_DIR/RECOVER_EXECUTE_REFUSE.txt"

[ -f "$PLAN" ] || {
    echo "ERROR: missing $PLAN" >&2
    exit 1
}
[ -f "$NANDRECOVERY_ENV" ] || {
    echo "ERROR: missing $NANDRECOVERY_ENV (nand_env.bak is not recover_env)" >&2
    exit 1
}

if [ ! -r "$SCRIPT_DIR/s19k_nand_env_crc.py" ]; then
    echo "ERROR: missing $SCRIPT_DIR/s19k_nand_env_crc.py" >&2
    exit 1
fi
if command -v py >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=py
elif command -v python3 >/dev/null 2>&1; then
    NAND_ENV_CRC_PY=python3
else
    echo "ERROR: py/python3 missing; cannot CRC-admit nandrecovery_env.bin" >&2
    exit 1
fi
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$NANDRECOVERY_ENV" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$NANDRECOVERY_ENV" \
    || { echo "ERROR: nandrecovery_env.bin CRC32 mismatch" >&2; exit 1; }

plan_get() {
    sed -n "s/^$1=//p" "$PLAN" | head -1 | tr -d '\r'
}

SCHEMA=$(plan_get schema)
INTENT=$(plan_get intent)
FLAG=$(plan_get flag_value)
SOURCE=$(plan_get recover_env_source)
STEP0=$(plan_get step0)
STEP1=$(plan_get step1)
STEP2=$(plan_get step2)
ERASE_PART=$(plan_get nand_erase_part)
BOOTM=$(plan_get bootm_mtd2)
CLEAR=$(plan_get clear_for_flash)
FLAG_LOCAL=$(plan_get flag_local)
ENV_LOCAL=$(plan_get nandrecovery_env_local)

[ "$SCHEMA" = "dcentos.amlogic-recover-to-stock/v1" ] || {
    echo "ERROR: RECOVER_TO_STOCK_PLAN schema is not dcentos.amlogic-recover-to-stock/v1" >&2
    exit 1
}
[ "$INTENT" = "UbootStockRevert" ] || {
    echo "ERROR: recover plan intent must be UbootStockRevert" >&2
    exit 1
}
[ "$FLAG" = "0x02" ] || {
    echo "ERROR: recover plan flag_value must be 0x02" >&2
    exit 1
}
[ "$SOURCE" = "nandrecovery_env.bin" ] || {
    echo "ERROR: nand_env.bak is not recover_env (got recover_env_source=$SOURCE)" >&2
    exit 1
}
[ "$STEP0" = "ImportNandrecoveryEnv" ] || {
    echo "ERROR: step0 must be ImportNandrecoveryEnv" >&2
    exit 1
}
[ "$STEP1" = "EraseNvdata" ] || {
    echo "ERROR: step1 must be EraseNvdata" >&2
    exit 1
}
[ "$STEP2" = "Reset" ] || {
    echo "ERROR: step2 must be Reset" >&2
    exit 1
}
[ "$ERASE_PART" = "nvdata" ] || {
    echo "ERROR: nand_erase_part must be nvdata" >&2
    exit 1
}
[ "$BOOTM" = "false" ] || {
    echo "ERROR: bootm_mtd2 must be false" >&2
    exit 1
}
[ "$CLEAR" = "false" ] || {
    echo "ERROR: RECOVER_TO_STOCK_PLAN must keep clear_for_flash=false" >&2
    exit 1
}

if [ -f "$ARTIFACT_DIR/nand_env.bak" ]; then
    rec_sha=""
    bak_sha=""
    if command -v sha256sum >/dev/null 2>&1; then
        rec_sha=$(sha256sum "$NANDRECOVERY_ENV" | awk '{print $1}' | tr 'A-F' 'a-f')
        bak_sha=$(sha256sum "$ARTIFACT_DIR/nand_env.bak" | awk '{print $1}' | tr 'A-F' 'a-f')
    elif command -v shasum >/dev/null 2>&1; then
        rec_sha=$(shasum -a 256 "$NANDRECOVERY_ENV" | awk '{print $1}' | tr 'A-F' 'a-f')
        bak_sha=$(shasum -a 256 "$ARTIFACT_DIR/nand_env.bak" | awk '{print $1}' | tr 'A-F' 'a-f')
    fi
    if [ -n "$rec_sha" ] && [ "$rec_sha" = "$bak_sha" ]; then
        echo "ERROR: nandrecovery_env.bin sha256 equals nand_env.bak; bak is not recover_env" >&2
        exit 1
    fi
fi

echo "[DRY RUN] walking RECOVER_TO_STOCK_PLAN before GPIO/nandwrite/fw_setenv/env import"
echo 'dry_step0=nand read 01060000 ${nandrecovery_env_offset} ${env_size}; env default -a; env import -d -c 01060000 0x10000; env save'
echo "dry_step1=nand erase.part nvdata"
echo "dry_step2=reset"

{
    echo "schema=dcentos.amlogic-recover-walk/v1"
    echo "plan_schema=dcentos.amlogic-recover-to-stock/v1"
    echo "mode=dry-run"
    echo "intent=UbootStockRevert"
    echo "flag_value=0x02"
    echo "flag_local=${FLAG_LOCAL:-0x04D00000}"
    echo "nandrecovery_env_local=${ENV_LOCAL:-0x04900000}"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "env_crc_ok=true"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo 'dry_step0=nand read 01060000 ${nandrecovery_env_offset} ${env_size}; env default -a; env import -d -c 01060000 0x10000; env save'
    echo "dry_step1=nand erase.part nvdata"
    echo "dry_step2=reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "fw_setenv=false"
    echo "env_import=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "dry_run=true nandwrite=false gpio_write=false"
    echo "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    echo "fail=nand_erase_or_env_import_without_admit"
} > "$WALK"

{
    echo "schema=dcentos.amlogic-recover-execute/v1"
    echo "execute=refused"
    echo "reason=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "flag_value=0x02"
    echo "flag_local=${FLAG_LOCAL:-0x04D00000}"
    echo "nandrecovery_env_local=${ENV_LOCAL:-0x04900000}"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "recover_env_ram=0x01060000"
    echo "env_import_size=0x10000"
    echo "nandrecovery_env_offset=0x0B000000"
    echo "env_size=0x10000"
    echo "step0=ImportNandrecoveryEnv"
    echo "step1=EraseNvdata"
    echo "step2=Reset"
    echo "nand_erase_part=nvdata"
    echo "bootm_mtd2=false"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "fw_setenv=false"
    echo "env_import=false"
    echo "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet"
    echo "fail=nand_erase_or_env_import_without_admit"
} > "$REFUSE"

echo "RECOVER_WALK.txt written (plan walked; FLASH/NAND still refused)"
echo "RECOVER_EXECUTE_REFUSE.txt written (execute=refused reason=CLEAR_FOR_FLASH)"

if [ "$DRY_RUN" = true ] || [ "$VERIFY_ONLY" = true ]; then
    echo "mode=dry-run"
    echo "verify-only: no NAND write"
    exit 0
fi

if [ "${DCENT_S19K_RECOVER_EXECUTE:-0}" != 1 ]; then
    echo "ERROR: --execute refused (DCENT_S19K_RECOVER_EXECUTE!=1); U-Boot recover_env not proven" >&2
    exit 1
fi

echo ""
echo "WARNING: this would enter U-Boot recover_to_stock (import nandrecovery_env, erase nvdata, reset)."
echo "         Linux nandwrite/fw_setenv is not recover_env. FLASH NOT_YET."
echo ""
printf "Type 'RECOVER' to proceed: "
read CONFIRM
if [ "$CONFIRM" != "RECOVER" ]; then
    echo "Aborted."
    exit 0
fi

# : plan/dry-run is host-safe. Execute is FLASH-gated.
# Do not gpio / flash_erase / nandwrite / fw_setenv / env import then refuse.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "ERROR: CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite."
    echo "schema=dcentos.amlogic-recover-execute/v1"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "fw_setenv=false"
    echo "env_import=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "dry-run already walked the plan; FLASH NOT_YET"
    exit 1
fi

if [ ! -r /etc/dcentos/board_target ]; then
    echo "ERROR: missing live /etc/dcentos/board_target; refuse fail-open recover-to-stock" >&2
    exit 1
fi
BT=$(tr -d ' \t\r\n' < /etc/dcentos/board_target)
case "$BT" in
    am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
    *)
        echo "ERROR: live board_target='$BT' is not am3-s19k; refuse fail-open recover-to-stock" >&2
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
    echo "ERROR: gpio437 missing after export — refusing recover-to-stock" >&2
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

if [ ! -r /proc/mtd ]; then
    echo "ERROR: missing live /proc/mtd; refuse geometry-blind recover-to-stock" >&2
    exit 1
fi

# Unreachable while CLEAR_FOR_FLASH=false.
# Linux nandwrite / fw_setenv is not U-Boot recover_env. Never invoke.
echo "ERROR: Linux nandwrite/fw_setenv is not U-Boot recover_to_stock" >&2
echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"
echo "nandwrite=false"
echo "fw_setenv=false"
echo "env_import=false"
echo "fail=nand_erase_or_env_import_without_admit"
# refused linux substitute: flash_erase /dev/mtd5 0 0
# refused linux substitute: nandwrite -p /dev/mtd5 "$NANDRECOVERY_ENV"
# refused linux substitute: fw_setenv
exit 1
