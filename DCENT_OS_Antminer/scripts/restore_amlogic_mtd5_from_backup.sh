#!/bin/sh
#
# restore_amlogic_mtd5_from_backup.sh — hash-verified restore of the
# installer `--backup-only` mtd5 nanddump.
#
# L3 / Braiins-without-fw_setenv: fw_setenv not required. This path does
# NOT flip U-Boot env and does NOT restore /dev/nand_env.
#
# CRITICAL: mtd5_pre_install.bin is a full `nanddump` of /dev/mtd5.
# nandwrite of that file at the uImage window 0x05700000 is refused
# (refuse window-offset): it would place mtd5[0] onto the rootfs window.
#
# Default is --verify-only (hash check + plan). --execute is on-device
# only, after typing RESTORE, with live /proc/mtd and gpio437 SafeOff first.
#
# CLEAR_FOR_FLASH stays false. Braiins /tmp success is not stock GO.

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ ! -r "$SCRIPT_DIR/lib/am3_geometry.sh" ]; then
    echo "ERROR: missing $SCRIPT_DIR/lib/am3_geometry.sh" >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/am3_geometry.sh"

ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ARTIFACT_DIR=""
EXECUTE=false
VERIFY_ONLY=true

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") --artifact-dir DIR [--verify-only|--execute]

  --artifact-dir DIR   BACKUP_LEDGER.txt + nand_env.bak + mtd5_pre_install.bin + nandrecovery_env.bin
  --verify-only        hash-check + print plan (default)
  --execute            on-device full-mtd5 restore after typing RESTORE

fw_setenv not required. Never writes mtd0/mtd1. clear_for_flash=false.
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
LEDGER="$ARTIFACT_DIR/BACKUP_LEDGER.txt"
NAND_ENV="$ARTIFACT_DIR/nand_env.bak"
MTD5="$ARTIFACT_DIR/mtd5_pre_install.bin"
NANDRECOVERY_ENV="$ARTIFACT_DIR/nandrecovery_env.bin"

[ -f "$LEDGER" ] || { echo "ERROR: missing $LEDGER" >&2; exit 1; }
[ -f "$NAND_ENV" ] || { echo "ERROR: missing $NAND_ENV" >&2; exit 1; }
[ -f "$MTD5" ] || { echo "ERROR: missing $MTD5" >&2; exit 1; }
[ -f "$NANDRECOVERY_ENV" ] || {
    echo "ERROR: missing $NANDRECOVERY_ENV (nand_env.bak is not recover_env)" >&2
    exit 1
}
# : recover_env imports this sidecar. CRC-admit it with the
# same ISO-HDLC helper the installer uses. Missing py/python3 is refuse,
# not skip. nand_env.bak is hashed above and CRC-checked here, but it
# is never recover_env_source.
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
"$NAND_ENV_CRC_PY" -3 "$SCRIPT_DIR/s19k_nand_env_crc.py" "$NAND_ENV" \
    || "$NAND_ENV_CRC_PY" "$SCRIPT_DIR/s19k_nand_env_crc.py" "$NAND_ENV" \
    || { echo "ERROR: nand_env.bak CRC32 mismatch" >&2; exit 1; }

ledger_get() {
    sed -n "s/^$1=//p" "$LEDGER" | head -1
}

SCHEMA=$(ledger_get schema)
CLEAR=$(ledger_get clear_for_flash)
NOT_GO=$(ledger_get braiins_success_is_not_stock_go)
LEDGER_NAND=$(ledger_get nand_env_sha256 | tr 'A-F' 'a-f')
LEDGER_MTD5=$(ledger_get mtd5_sha256 | tr 'A-F' 'a-f')
LEDGER_REC=$(ledger_get nandrecovery_env_sha256 | tr 'A-F' 'a-f')

[ "$SCHEMA" = "dcentos.amlogic-backup/v1" ] || {
    echo "ERROR: BACKUP_LEDGER schema is not dcentos.amlogic-backup/v1" >&2
    exit 1
}
[ "$CLEAR" = "false" ] || {
    echo "ERROR: BACKUP_LEDGER must keep clear_for_flash=false" >&2
    exit 1
}
[ "$NOT_GO" = "true" ] || {
    echo "ERROR: BACKUP_LEDGER must keep braiins_success_is_not_stock_go=true" >&2
    exit 1
}

hex64() {
    s=$1
    [ "${#s}" -eq 64 ] || return 1
    case $s in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

hex64 "$LEDGER_NAND" || { echo "ERROR: nand_env_sha256 is not 64 hex chars" >&2; exit 1; }
hex64 "$LEDGER_MTD5" || { echo "ERROR: mtd5_sha256 is not 64 hex chars" >&2; exit 1; }
[ -n "$LEDGER_REC" ] || {
    echo "ERROR: missing nandrecovery_env_sha256" >&2
    exit 1
}
hex64 "$LEDGER_REC" || { echo "ERROR: nandrecovery_env_sha256 is not 64 hex chars" >&2; exit 1; }
[ "$LEDGER_NAND" != "$LEDGER_MTD5" ] || {
    echo "ERROR: nand_env and mtd5 sha256 must not be identical" >&2
    exit 1
}
[ "$LEDGER_REC" != "$LEDGER_NAND" ] || {
    echo "ERROR: nandrecovery_env_sha256 must not equal nand_env_sha256" >&2
    exit 1
}

local_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}' | tr 'A-F' 'a-f'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}' | tr 'A-F' 'a-f'
    else
        echo ""
    fi
}

FILE_NAND=$(local_sha256 "$NAND_ENV")
FILE_MTD5=$(local_sha256 "$MTD5")
FILE_REC=$(local_sha256 "$NANDRECOVERY_ENV")
[ -n "$FILE_NAND" ] && [ -n "$FILE_MTD5" ] && [ -n "$FILE_REC" ] || {
    echo "ERROR: sha256sum/shasum missing" >&2
    exit 1
}
[ "$FILE_NAND" = "$LEDGER_NAND" ] || {
    echo "ERROR: nand_env.bak sha256 drift (ledger $LEDGER_NAND file $FILE_NAND)" >&2
    exit 1
}
[ "$FILE_MTD5" = "$LEDGER_MTD5" ] || {
    echo "ERROR: mtd5_pre_install.bin sha256 drift (ledger $LEDGER_MTD5 file $FILE_MTD5)" >&2
    exit 1
}
[ "$FILE_REC" = "$LEDGER_REC" ] || {
    echo "ERROR: nandrecovery_env.bin sha256 drift (ledger $LEDGER_REC file $FILE_REC)" >&2
    exit 1
}

LEDGER_BT=$(ledger_get board_target | tr -d ' \t\r\n')
LEDGER_BT_SRC=$(ledger_get board_target_source | tr -d ' \t\r\n')
LEDGER_BT_PKG=$(ledger_get board_target_package | tr -d ' \t\r\n')
if [ "$LEDGER_BT_SRC" = "package" ]; then
    echo "board_target_source=package (invented from --variant; verify-only may continue)"
    echo "board_target_package=${LEDGER_BT_PKG:-missing}"
elif [ -n "$LEDGER_BT" ]; then
    case "$LEDGER_BT" in
        am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
        *)
            echo "ERROR: admit ledger board_target='$LEDGER_BT' is not am3-s19k; refuse fail-open restore" >&2
            exit 1
            ;;
    esac
else
    echo "ERROR: admit ledger board_target='$LEDGER_BT' is not am3-s19k; refuse fail-open restore" >&2
    exit 1
fi
LEDGER_MTD5_LEN=$(ledger_get mtd5_len | tr -d ' \t\r\n')
FILE_MTD5_LEN=$(wc -c < "$MTD5" | tr -d ' \t\r\n')
[ -n "$LEDGER_MTD5_LEN" ] || {
    echo "ERROR: BACKUP_LEDGER missing mtd5_len" >&2
    exit 1
}
[ "$LEDGER_MTD5_LEN" = "$FILE_MTD5_LEN" ] || {
    echo "ERROR: mtd5_pre_install.bin length $FILE_MTD5_LEN != ledger mtd5_len $LEDGER_MTD5_LEN" >&2
    exit 1
}
LEDGER_PROC=$(ledger_get proc_mtd | tr -d '\r')
[ -n "$LEDGER_PROC" ] || {
    echo "ERROR: BACKUP_LEDGER missing proc_mtd; refuse geometry-blind restore" >&2
    exit 1
}
PROC_TMP="$ARTIFACT_DIR/.restore_proc_mtd.txt"
printf '%s\n' "$LEDGER_PROC" | tr '|' '\n' > "$PROC_TMP"
RECOMPUTED=$(dcent_am3_mtd5_base_from_proc_mtd "$PROC_TMP") || {
    echo "ERROR: ledger proc_mtd cannot compute mtd5 geometry" >&2
    rm -f "$PROC_TMP"
    exit 1
}
rm -f "$PROC_TMP"
LEDGER_BASE=$(ledger_get computed_mtd5_base | tr -d ' \t\r\n')
[ -n "$LEDGER_BASE" ] && [ "$LEDGER_BASE" != "unknown" ] || {
    echo "ERROR: ledger computed_mtd5_base unknown; refuse geometry-blind restore" >&2
    exit 1
}
if [ "$LEDGER_BASE" = "0x06100000" ] || [ "$LEDGER_BASE" = "0x6100000" ] || \
   [ "$RECOMPUTED" = "0x06100000" ]; then
    echo "ERROR: ledger computed_mtd5_base is size-sum without the 6MiB hole; refuse restore" >&2
    exit 1
fi
[ $((LEDGER_BASE)) -eq $((RECOMPUTED)) ] || {
    echo "ERROR: ledger computed_mtd5_base != recomputed from proc_mtd" >&2
    exit 1
}
dcent_am3_mtd5_covers_recovery "$FILE_MTD5_LEN" "$RECOMPUTED" || {
    echo "ERROR: mtd5 backup shorter than recovery-flag/nandrecovery_env window" >&2
    exit 1
}

# : CRC-valid nandrecovery_env.bin may still be a copied nand_env.bak.
# recover_env imports the mtd5 window, so the sidecar must be that slice.
SLICE="$ARTIFACT_DIR/.restore_nandrecovery_env.slice"
dcent_am3_extract_nandrecovery_env "$MTD5" "$RECOMPUTED" "$SLICE" || {
    echo "ERROR: cannot slice nandrecovery_env from mtd5_pre_install.bin" >&2
    rm -f "$SLICE"
    exit 1
}
cmp -s "$SLICE" "$NANDRECOVERY_ENV" || {
    echo "ERROR: nandrecovery_env.bin does not match mtd5 slice" >&2
    rm -f "$SLICE"
    exit 1
}
rm -f "$SLICE"

echo "schema=dcentos.amlogic-restore/v1"
echo "kind=PreInstallMtd5Nanddump"
echo "target_mtd=5"
echo "use_window_offset=false"
echo "restore_nand_env=false"
echo "nand_env_bak_is_not_nandrecovery_env=true"
echo "nandrecovery_env=nandrecovery_env.bin"
echo "recover_env_source=nandrecovery_env.bin"
echo "nandrecovery_env_crc_ok=true"
echo "nandrecovery_env_matches_mtd5_slice=true"
echo "nandrecovery_env_sha256_ok=true"
echo "nand_env_crc_ok=true"
echo "nandrecovery_env_local=0x04900000"
echo "recovery_flag_local=0x04D00000"
echo "recomputed_mtd5_base=$RECOMPUTED"
echo "covers_recovery=true"
echo "env_flip=false"
echo "clear_for_flash=false"
echo "braiins_success_is_not_stock_go=true"
echo "nand_env_sha256=$FILE_NAND"
echo "mtd5_sha256=$FILE_MTD5"
echo "rootfs_mtd=$ROOTFS_MTD"
echo "note=full nanddump restore; refuse window-offset 0x05700000"
echo "VERIFY_OK hashes match ledger"

if [ "$VERIFY_ONLY" = true ]; then
    echo "verify-only: no NAND write"
    exit 0
fi

[ -e "$ROOTFS_MTD" ] || {
    echo "ERROR: $ROOTFS_MTD missing — --execute is on-device only" >&2
    exit 1
}
command -v nandwrite >/dev/null 2>&1 || { echo "ERROR: nandwrite missing" >&2; exit 1; }
command -v nanddump >/dev/null 2>&1 || { echo "ERROR: nanddump missing" >&2; exit 1; }
command -v flash_erase >/dev/null 2>&1 || { echo "ERROR: flash_erase missing" >&2; exit 1; }

echo ""
echo "WARNING: this erases ALL of $ROOTFS_MTD then nandwrites the hashed nanddump."
echo "         fw_setenv not required. env is not flipped. nand_env is not written."
echo ""
printf "Type 'RESTORE' to proceed: "
read CONFIRM
if [ "$CONFIRM" != "RESTORE" ]; then
    echo "Aborted."
    exit 0
fi

# : plan/verify-only is L3 (no fw_setenv). Execute is FLASH-gated.
# Do not gpio/flash_erase/nandwrite then refuse.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "ERROR: CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite."
    echo "schema=dcentos.amlogic-restore/v1"
    echo "nandwrite=false"
    echo "gpio_write=false"
    echo "execute=CLEAR_FOR_FLASH"
    echo "clear_for_flash=false"
    echo "verify-only already proved hashes; FLASH NOT_YET"
    exit 1
fi

if [ -r /etc/dcentos/tmp_deploy ]; then
    echo "ERROR: /etc/dcentos/tmp_deploy leftover — refuse restore after /tmp bench deploy" >&2
    exit 1
fi
if [ "$LEDGER_BT_SRC" != "live" ]; then
    echo "ERROR: restore --execute refuses board_target_source=${LEDGER_BT_SRC:-missing} (invented from --variant)" >&2
    exit 1
fi
if [ ! -r /etc/dcentos/board_target ]; then
    echo "ERROR: missing live /etc/dcentos/board_target; refuse fail-open restore" >&2
    exit 1
fi
BT=$(tr -d ' \t\r\n' < /etc/dcentos/board_target)
[ "$BT" = "$LEDGER_BT" ] || {
    echo "ERROR: live board_target=$BT != ledger board_target=$LEDGER_BT; refuse restore" >&2
    exit 1
}
if [ ! -r /proc/mtd ]; then
    echo "ERROR: missing live /proc/mtd; refuse geometry-blind restore" >&2
    exit 1
fi
MTD_N=$(grep -c '^mtd' /proc/mtd || true)
if [ "$MTD_N" -ge 7 ]; then
    echo "ERROR: /proc/mtd has $MTD_N partitions (7-part map blocked); refuse restore" >&2
    exit 1
fi
LIVE_BASE=$(dcent_am3_mtd5_base_from_proc_mtd /proc/mtd) || {
    echo "ERROR: live /proc/mtd cannot compute mtd5 geometry" >&2
    exit 1
}
[ $((LIVE_BASE)) -eq $((RECOMPUTED)) ] || {
    echo "ERROR: live mtd5 base != backup ledger geometry" >&2
    exit 1
}

echo "Step 1: gpio437 SafeOff (am3-s19k-active-low, value=1) before NAND write..."
PWR_GPIO=437
SYS=/sys/class/gpio
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "$PWR_GPIO" > "$SYS/export" 2>/dev/null || true
fi
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "ERROR: gpio437 missing after export — refusing restore NAND write" >&2
    exit 1
fi
echo 0 > "$SYS/gpio$PWR_GPIO/active_low"
echo high > "$SYS/gpio$PWR_GPIO/direction"
echo 1 > "$SYS/gpio$PWR_GPIO/value"
VAL=$(cat "$SYS/gpio$PWR_GPIO/value")
if [ "$VAL" != "1" ]; then
    echo "ERROR: gpio437 value=$VAL after SafeOff (want 1)" >&2
    exit 1
fi
echo "  gpio437 SafeOff OK polarity=am3-s19k-active-low value=$VAL"

echo "Step 2: flash_erase $ROOTFS_MTD (whole partition; not the 0x05700000 window)..."
flash_erase "$ROOTFS_MTD" 0 0

echo "Step 3: nandwrite full nanddump to $ROOTFS_MTD..."
nandwrite -p "$ROOTFS_MTD" "$MTD5"

echo "Step 4: nanddump readback sha256..."
nanddump --bb=skipbad -f /tmp/mtd5_restore_readback.bin "$ROOTFS_MTD" >/dev/null 2>&1
READBACK=$(local_sha256 /tmp/mtd5_restore_readback.bin)
rm -f /tmp/mtd5_restore_readback.bin
if [ "$READBACK" != "$FILE_MTD5" ]; then
    echo "ERROR: post-write mtd5 sha256 drift (want $FILE_MTD5 got $READBACK)" >&2
    echo "DO NOT POWER CYCLE until this is understood. env was not flipped." >&2
    exit 1
fi

echo "RESTORE_OK mtd5 matches ledger sha256=$READBACK env_flip=false clear_for_flash=false"
exit 0
