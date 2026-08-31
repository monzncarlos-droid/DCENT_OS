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
if [ ! -r "$SCRIPT_DIR/lib/amlogic_identity_guard.sh" ]; then
    echo "ERROR: missing $SCRIPT_DIR/lib/amlogic_identity_guard.sh" >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/amlogic_identity_guard.sh"

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
LEDGER="$ARTIFACT_DIR/BACKUP_LEDGER.txt"
IDENTITY_PROOF="$ARTIFACT_DIR/identity_tuple_pre.txt"
WALK="$ARTIFACT_DIR/RECOVER_WALK.txt"
REFUSE="$ARTIFACT_DIR/RECOVER_EXECUTE_REFUSE.txt"
WALK_TMP=
REFUSE_TMP=

cleanup() {
    [ -z "$WALK_TMP" ] || rm -f "$WALK_TMP"
    [ -z "$REFUSE_TMP" ] || rm -f "$REFUSE_TMP"
}

require_exact_live_s19k_identity() {
    LIVE_IDENTITY_ROOT=${1:-/etc/dcentos}
    if [ ! -r "$LIVE_IDENTITY_ROOT/platform" ] || [ ! -r "$LIVE_IDENTITY_ROOT/board_target" ]; then
        echo "ERROR: missing live canonical platform/board_target pair; refuse fail-open recover-to-stock" >&2
        return 1
    fi
    LIVE_PLATFORM=$(tr -d ' \t\r\n' < "$LIVE_IDENTITY_ROOT/platform")
    LIVE_BOARD_TARGET=$(tr -d ' \t\r\n' < "$LIVE_IDENTITY_ROOT/board_target")
    if [ "$LIVE_PLATFORM:$LIVE_BOARD_TARGET" != "am3-aml-s19k:am3-s19k" ]; then
        echo "ERROR: live platform:board_target='$LIVE_PLATFORM:$LIVE_BOARD_TARGET' is not exact am3-aml-s19k:am3-s19k; refuse recover-to-stock" >&2
        return 1
    fi
    return 0
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

[ -d "$ARTIFACT_DIR" ] && [ ! -L "$ARTIFACT_DIR" ] || {
    echo "ERROR: artifact directory must be a real non-symlink directory: $ARTIFACT_DIR" >&2
    exit 1
}

for REQUIRED_INPUT in "$PLAN" "$NANDRECOVERY_ENV" "$LEDGER" "$IDENTITY_PROOF"; do
    [ -f "$REQUIRED_INPUT" ] && [ ! -L "$REQUIRED_INPUT" ] || {
        echo "ERROR: recovery input must be a regular non-symlink file: $REQUIRED_INPUT" >&2
        exit 1
    }
done
for DERIVED_OUTPUT in "$WALK" "$REFUSE"; do
    if [ -e "$DERIVED_OUTPUT" ] || [ -L "$DERIVED_OUTPUT" ]; then
        [ -f "$DERIVED_OUTPUT" ] && [ ! -L "$DERIVED_OUTPUT" ] || {
            echo "ERROR: refusing unsafe recovery output path: $DERIVED_OUTPUT" >&2
            exit 1
        }
    fi
done

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

field_get_exact() {
    FIELD_FILE=$1
    FIELD_KEY=$2
    FIELD_LABEL=$3
    FIELD_COUNT=$(awk -F= -v key="$FIELD_KEY" '$1 == key { count++ } END { print count + 0 }' "$FIELD_FILE")
    [ "$FIELD_COUNT" -eq 1 ] || {
        echo "ERROR: $FIELD_LABEL must contain exactly one $FIELD_KEY= field (got $FIELD_COUNT)" >&2
        return 1
    }
    sed -n "s/^$FIELD_KEY=//p" "$FIELD_FILE" | tr -d '\r'
}

SCHEMA=$(field_get_exact "$PLAN" schema recover-plan)
INTENT=$(field_get_exact "$PLAN" intent recover-plan)
FLAG=$(field_get_exact "$PLAN" flag_value recover-plan)
SOURCE=$(field_get_exact "$PLAN" recover_env_source recover-plan)
STEP0=$(field_get_exact "$PLAN" step0 recover-plan)
STEP1=$(field_get_exact "$PLAN" step1 recover-plan)
STEP2=$(field_get_exact "$PLAN" step2 recover-plan)
ERASE_PART=$(field_get_exact "$PLAN" nand_erase_part recover-plan)
BOOTM=$(field_get_exact "$PLAN" bootm_mtd2 recover-plan)
CLEAR=$(field_get_exact "$PLAN" clear_for_flash recover-plan)
FLAG_LOCAL=$(field_get_exact "$PLAN" flag_local recover-plan)
ENV_LOCAL=$(field_get_exact "$PLAN" nandrecovery_env_local recover-plan)
LEDGER_SCHEMA=$(field_get_exact "$LEDGER" schema backup-ledger)
LEDGER_CLEAR=$(field_get_exact "$LEDGER" clear_for_flash backup-ledger)
LEDGER_ENV_LOCAL=$(field_get_exact "$LEDGER" nandrecovery_env_local backup-ledger)
LEDGER_ENV_SHA=$(field_get_exact "$LEDGER" nandrecovery_env_sha256 backup-ledger | tr 'A-F' 'a-f')
IDENTITY_PROOF_SCHEMA=$(field_get_exact "$LEDGER" identity_proof_schema backup-ledger)
IDENTITY_PROOF_VARIANT=$(field_get_exact "$LEDGER" identity_proof_variant backup-ledger)
IDENTITY_PROOF_FILE=$(field_get_exact "$LEDGER" identity_proof_file backup-ledger)
IDENTITY_PROOF_SHA=$(field_get_exact "$LEDGER" identity_proof_sha256 backup-ledger | tr 'A-F' 'a-f')
IDENTITY_PROOF_RECEIPT=$(field_get_exact "$LEDGER" identity_proof_receipt backup-ledger)
LEDGER_BT=$(field_get_exact "$LEDGER" board_target backup-ledger)
LEDGER_BT_SRC=$(field_get_exact "$LEDGER" board_target_source backup-ledger)
LEDGER_BT_PKG=$(field_get_exact "$LEDGER" board_target_package backup-ledger)

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
[ "$FLAG_LOCAL" = "0x04D00000" ] || {
    echo "ERROR: recover plan flag_local must be sealed .78 offset 0x04D00000" >&2
    exit 1
}
[ "$ENV_LOCAL" = "0x04900000" ] || {
    echo "ERROR: recover plan nandrecovery_env_local must be sealed .78 offset 0x04900000" >&2
    exit 1
}
[ "$LEDGER_SCHEMA" = "dcentos.amlogic-backup/v1" ] || {
    echo "ERROR: BACKUP_LEDGER schema is not dcentos.amlogic-backup/v1" >&2
    exit 1
}
[ "$LEDGER_CLEAR" = "false" ] || {
    echo "ERROR: BACKUP_LEDGER must keep clear_for_flash=false" >&2
    exit 1
}
[ "$LEDGER_ENV_LOCAL" = "$ENV_LOCAL" ] || {
    echo "ERROR: recover plan nandrecovery_env_local does not match BACKUP_LEDGER" >&2
    exit 1
}
[ "$IDENTITY_PROOF_SCHEMA" = "dcentos.amlogic-identity-tuple/v1" ] || {
    echo "ERROR: backup has no typed exact Amlogic identity-tuple proof" >&2
    exit 1
}
case "$IDENTITY_PROOF_VARIANT" in
    s19kpro|s19k) ;;
    *) echo "ERROR: identity proof variant '$IDENTITY_PROOF_VARIANT' is not exact S19k" >&2; exit 1 ;;
esac
[ "$IDENTITY_PROOF_FILE" = identity_tuple_pre.txt ] || {
    echo "ERROR: identity proof file must be exact artifact leaf identity_tuple_pre.txt" >&2
    exit 1
}
[ "$LEDGER_BT_PKG" = am3-s19k ] || {
    echo "ERROR: backup package target '${LEDGER_BT_PKG:-missing}' is not exact am3-s19k" >&2
    exit 1
}
case "$LEDGER_BT_SRC" in
    package)
        [ -z "$LEDGER_BT" ] || {
            echo "ERROR: package-sourced backup must not relabel a package target as a live board_target" >&2
            exit 1
        }
        ;;
    live)
        case "$LEDGER_BT" in
            am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
            *) echo "ERROR: live backup board_target '$LEDGER_BT' is not S19k" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "ERROR: backup board_target source '${LEDGER_BT_SRC:-missing}' is neither live nor tuple-proven package evidence" >&2
        exit 1
        ;;
esac
for IDENTITY_KEY in BOARD_TARGET MODEL HWID PCB BOS_MODEL DT_MODEL DT_COMPATIBLE CPU_SYSTEM; do
    IDENTITY_KEY_COUNT=$(grep -c "^$IDENTITY_KEY=" "$IDENTITY_PROOF" 2>/dev/null || true)
    [ "$IDENTITY_KEY_COUNT" -eq 1 ] || {
        echo "ERROR: identity proof must contain exactly one $IDENTITY_KEY= observation" >&2
        exit 1
    }
done
# 2026-08-30 dialect fields: absent (historical eight-field transcripts) or
# exactly once (current ten-field records).  The library re-admit below
# enforces the exact 8-vs-10 consistency.
for IDENTITY_KEY in PCB_OBSERVATION HASHBOARD_EEPROM; do
    IDENTITY_KEY_COUNT=$(grep -c "^$IDENTITY_KEY=" "$IDENTITY_PROOF" 2>/dev/null || true)
    [ "$IDENTITY_KEY_COUNT" -le 1 ] || {
        echo "ERROR: identity proof must not repeat the $IDENTITY_KEY= observation" >&2
        exit 1
    }
done
if grep -nEv '^(BOARD_TARGET|MODEL|HWID|PCB|BOS_MODEL|DT_MODEL|DT_COMPATIBLE|CPU_SYSTEM|PCB_OBSERVATION|HASHBOARD_EEPROM)=.*$' "$IDENTITY_PROOF" >/dev/null 2>&1; then
    echo "ERROR: identity proof contains an untyped observation line" >&2
    exit 1
fi
case "$LEDGER_ENV_SHA" in
    *[!0-9a-f]*|'') echo "ERROR: BACKUP_LEDGER nandrecovery_env_sha256 is not lowercase hex" >&2; exit 1 ;;
esac
[ "${#LEDGER_ENV_SHA}" -eq 64 ] || {
    echo "ERROR: BACKUP_LEDGER nandrecovery_env_sha256 is not 64 hex chars" >&2
    exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
    NANDRECOVERY_ENV_SHA=$(sha256sum "$NANDRECOVERY_ENV" | awk '{print $1}' | tr 'A-F' 'a-f')
    FILE_IDENTITY_PROOF_SHA=$(sha256sum "$IDENTITY_PROOF" | awk '{print $1}' | tr 'A-F' 'a-f')
elif command -v shasum >/dev/null 2>&1; then
    NANDRECOVERY_ENV_SHA=$(shasum -a 256 "$NANDRECOVERY_ENV" | awk '{print $1}' | tr 'A-F' 'a-f')
    FILE_IDENTITY_PROOF_SHA=$(shasum -a 256 "$IDENTITY_PROOF" | awk '{print $1}' | tr 'A-F' 'a-f')
else
    echo "ERROR: sha256sum/shasum missing; cannot bind nandrecovery_env.bin to BACKUP_LEDGER" >&2
    exit 1
fi
[ "$NANDRECOVERY_ENV_SHA" = "$LEDGER_ENV_SHA" ] || {
    echo "ERROR: nandrecovery_env.bin sha256 does not match BACKUP_LEDGER" >&2
    exit 1
}
case "$IDENTITY_PROOF_SHA" in
    *[!0-9a-f]*|'') echo "ERROR: BACKUP_LEDGER identity_proof_sha256 is not lowercase hex" >&2; exit 1 ;;
esac
[ "${#IDENTITY_PROOF_SHA}" -eq 64 ] || {
    echo "ERROR: BACKUP_LEDGER identity_proof_sha256 is not 64 hex chars" >&2
    exit 1
}
[ "$FILE_IDENTITY_PROOF_SHA" = "$IDENTITY_PROOF_SHA" ] || {
    echo "ERROR: identity_tuple_pre.txt sha256 does not match BACKUP_LEDGER" >&2
    exit 1
}
if ! RECOMPUTED_IDENTITY_RECEIPT=$(dcent_amlogic_identity_record_admit \
    "$IDENTITY_PROOF_VARIANT" "$(cat "$IDENTITY_PROOF")"); then
    echo "ERROR: stored identity transcript no longer admits the exact S19k model/SoC/PCB tuple" >&2
    exit 1
fi
[ -n "$IDENTITY_PROOF_RECEIPT" ] && \
[ "$RECOMPUTED_IDENTITY_RECEIPT" = "$IDENTITY_PROOF_RECEIPT" ] || {
    echo "ERROR: identity proof receipt does not match independently recomputed tuple admission" >&2
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

umask 077
WALK_TMP=$(mktemp "$ARTIFACT_DIR/.RECOVER_WALK.txt.tmp.XXXXXX") || {
    echo "ERROR: could not allocate private RECOVER_WALK transaction" >&2
    exit 1
}
{
    echo "schema=dcentos.amlogic-recover-walk/v1"
    echo "plan_schema=dcentos.amlogic-recover-to-stock/v1"
    echo "mode=dry-run"
    echo "intent=UbootStockRevert"
    echo "flag_value=0x02"
    echo "flag_local=$FLAG_LOCAL"
    echo "nandrecovery_env_local=$ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "nand_env_bak_is_not_nandrecovery_env=true"
    echo "env_crc_ok=true"
    echo "nandrecovery_env_sha256=$NANDRECOVERY_ENV_SHA"
    echo "nandrecovery_env_sha256_ok=true"
    echo "identity_proof_schema=$IDENTITY_PROOF_SCHEMA"
    echo "identity_proof_variant=$IDENTITY_PROOF_VARIANT"
    echo "identity_proof_sha256=$FILE_IDENTITY_PROOF_SHA"
    echo "identity_proof_receipt=$RECOMPUTED_IDENTITY_RECEIPT"
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
} > "$WALK_TMP"
chmod 0600 "$WALK_TMP"
mv -f "$WALK_TMP" "$WALK"
WALK_TMP=

REFUSE_TMP=$(mktemp "$ARTIFACT_DIR/.RECOVER_EXECUTE_REFUSE.txt.tmp.XXXXXX") || {
    echo "ERROR: could not allocate private RECOVER_EXECUTE_REFUSE transaction" >&2
    exit 1
}
{
    echo "schema=dcentos.amlogic-recover-execute/v1"
    echo "execute=refused"
    echo "reason=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "flag_value=0x02"
    echo "flag_local=$FLAG_LOCAL"
    echo "nandrecovery_env_local=$ENV_LOCAL"
    echo "recover_env_source=nandrecovery_env.bin"
    echo "nandrecovery_env_sha256=$NANDRECOVERY_ENV_SHA"
    echo "nandrecovery_env_sha256_ok=true"
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
} > "$REFUSE_TMP"
chmod 0600 "$REFUSE_TMP"
mv -f "$REFUSE_TMP" "$REFUSE"
REFUSE_TMP=

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

require_exact_live_s19k_identity /etc/dcentos || exit 1

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
