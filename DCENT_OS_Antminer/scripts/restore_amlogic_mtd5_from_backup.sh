#!/bin/sh
#
# restore_amlogic_mtd5_from_backup.sh — hash-verified restore of the
# installer `--backup-only` mtd5 nanddump.
#
# L3 / Braiins-without-fw_setenv: fw_setenv not required. This path does
# NOT flip U-Boot env and does NOT restore /dev/nand_env.
#
# CRITICAL: mtd5_pre_install.bin is a full `nanddump` of /dev/mtd5.
# nandwrite of that file at the sealed `a lab unit` uImage window 0x05100000 is
# refused (refuse window-offset): it would place mtd5[0] onto the rootfs
# window. The older 0x05700000 value is independently refused as size-sum
# geometry that omitted the 6 MiB mtd0->mtd1 hole.
#
# Default is --verify-only (hash check + plan). --execute remains an
# unconditionally refused request; the unreachable future tail records the
# required live /proc/mtd, identity, and gpio437 SafeOff ordering.
#
# CLEAR_FOR_FLASH stays false. Braiins /tmp success is not stock GO.

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

ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ARTIFACT_DIR=""
EXECUTE=false
VERIFY_ONLY=true

usage() {
    cat >&2 <<USAGE
Usage: $(basename "$0") --artifact-dir DIR [--verify-only|--execute]

  --artifact-dir DIR   BACKUP_LEDGER.txt + nand_env.bak + mtd5_pre_install.bin + nandrecovery_env.bin
  --verify-only        hash-check + print plan (default)
  --execute            refused (future full-mtd5 restore contract only)

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
[ -d "$ARTIFACT_DIR" ] && [ ! -L "$ARTIFACT_DIR" ] || {
    echo "ERROR: artifact-dir must be a real directory, not a symlink: $ARTIFACT_DIR" >&2
    exit 1
}
LEDGER="$ARTIFACT_DIR/BACKUP_LEDGER.txt"
NAND_ENV="$ARTIFACT_DIR/nand_env.bak"
MTD5="$ARTIFACT_DIR/mtd5_pre_install.bin"
NANDRECOVERY_ENV="$ARTIFACT_DIR/nandrecovery_env.bin"

[ -f "$LEDGER" ] && [ ! -L "$LEDGER" ] || { echo "ERROR: missing or symlinked $LEDGER" >&2; exit 1; }
[ -f "$NAND_ENV" ] && [ ! -L "$NAND_ENV" ] || { echo "ERROR: missing or symlinked $NAND_ENV" >&2; exit 1; }
[ -f "$MTD5" ] && [ ! -L "$MTD5" ] || { echo "ERROR: missing or symlinked $MTD5" >&2; exit 1; }
[ -f "$NANDRECOVERY_ENV" ] && [ ! -L "$NANDRECOVERY_ENV" ] || {
    echo "ERROR: missing $NANDRECOVERY_ENV (nand_env.bak is not recover_env)" >&2
    exit 1
}
command -v mktemp >/dev/null 2>&1 || { echo "ERROR: mktemp missing" >&2; exit 1; }
umask 077
RESTORE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/dcent-amlogic-restore.XXXXXX") || {
    echo "ERROR: could not create private restore verification directory" >&2
    exit 1
}
cleanup_restore_tmp() {
    rm -f "$RESTORE_TMP/proc_mtd.txt" "$RESTORE_TMP/nandrecovery_env.slice" \
        "$RESTORE_TMP/mtd5_restore_readback.bin" 2>/dev/null || true
    rmdir "$RESTORE_TMP" 2>/dev/null || true
}

require_exact_live_s19k_identity() {
    LIVE_IDENTITY_ROOT=${1:-/etc/dcentos}
    if [ ! -r "$LIVE_IDENTITY_ROOT/platform" ] || [ ! -r "$LIVE_IDENTITY_ROOT/board_target" ]; then
        echo "ERROR: missing live canonical platform/board_target pair; refuse fail-open restore" >&2
        return 1
    fi
    LIVE_PLATFORM=$(tr -d ' \t\r\n' < "$LIVE_IDENTITY_ROOT/platform")
    LIVE_BOARD_TARGET=$(tr -d ' \t\r\n' < "$LIVE_IDENTITY_ROOT/board_target")
    if [ "$LIVE_PLATFORM:$LIVE_BOARD_TARGET" != "am3-aml-s19k:am3-s19k" ]; then
        echo "ERROR: live platform:board_target='$LIVE_PLATFORM:$LIVE_BOARD_TARGET' is not exact am3-aml-s19k:am3-s19k; refuse restore" >&2
        return 1
    fi
    return 0
}
trap cleanup_restore_tmp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
    KEY=$1
    COUNT=$(grep -c "^$KEY=" "$LEDGER" 2>/dev/null || true)
    [ "$COUNT" -le 1 ] || {
        echo "ERROR: BACKUP_LEDGER repeats authority field $KEY" >&2
        return 1
    }
    sed -n "s/^$KEY=//p" "$LEDGER"
}

if grep -nEv '^[A-Za-z0-9_][A-Za-z0-9_]*=.*$' "$LEDGER" >/dev/null 2>&1; then
    echo "ERROR: BACKUP_LEDGER contains malformed non-key=value lines" >&2
    exit 1
fi
LEDGER_DUPLICATE_KEYS=$(sed -n 's/^\([A-Za-z0-9_][A-Za-z0-9_]*\)=.*$/\1/p' "$LEDGER" | sort | uniq -d)
[ -z "$LEDGER_DUPLICATE_KEYS" ] || {
    echo "ERROR: BACKUP_LEDGER repeats authority field(s): $LEDGER_DUPLICATE_KEYS" >&2
    exit 1
}

SCHEMA=$(ledger_get schema)
CLEAR=$(ledger_get clear_for_flash)
NOT_GO=$(ledger_get braiins_success_is_not_stock_go)
LEDGER_NAND=$(ledger_get nand_env_sha256 | tr 'A-F' 'a-f')
LEDGER_MTD5=$(ledger_get mtd5_sha256 | tr 'A-F' 'a-f')
LEDGER_REC=$(ledger_get nandrecovery_env_sha256 | tr 'A-F' 'a-f')
LEDGER_BAD_BLOCKS=$(ledger_get mtd5_dump_bad_blocks | tr -d ' \t\r\n')
LEDGER_OOB=$(ledger_get mtd5_dump_oob | tr -d ' \t\r\n')
LEDGER_DUPLICATE=$(ledger_get mtd5_duplicate_read | tr -d ' \t\r\n')
LEDGER_BAD_COUNT_BEFORE=$(ledger_get mtd5_bad_block_count_before | tr -d ' \t\r\n')
LEDGER_BAD_COUNT_AFTER=$(ledger_get mtd5_bad_block_count_after | tr -d ' \t\r\n')
LEDGER_BAD_POLICY=$(ledger_get mtd5_restore_bad_block_policy | tr -d ' \t\r\n')
IDENTITY_PROOF_SCHEMA=$(ledger_get identity_proof_schema | tr -d ' \t\r\n')
IDENTITY_PROOF_VARIANT=$(ledger_get identity_proof_variant | tr -d ' \t\r\n')
IDENTITY_PROOF_FILE=$(ledger_get identity_proof_file | tr -d ' \t\r\n')
IDENTITY_PROOF_SHA=$(ledger_get identity_proof_sha256 | tr 'A-F' 'a-f' | tr -d ' \t\r\n')
IDENTITY_PROOF_RECEIPT=$(ledger_get identity_proof_receipt | tr -d '\r')

[ "$SCHEMA" = "dcentos.amlogic-backup/v1" ] || {
    echo "ERROR: BACKUP_LEDGER schema is not dcentos.amlogic-backup/v1" >&2
    exit 1
}
case "$LEDGER_BAD_COUNT_BEFORE:$LEDGER_BAD_COUNT_AFTER" in
    *[!0-9:]*|:*|*:)
        echo "ERROR: backup has no exact numeric before/after bad-block count; full padbad replay is refused" >&2
        exit 1
        ;;
esac
if [ "$LEDGER_BAD_COUNT_BEFORE" -ne 0 ] || [ "$LEDGER_BAD_COUNT_AFTER" -ne 0 ] || \
   [ "$LEDGER_BAD_POLICY" != zero-only-admitted ]; then
    echo "ERROR: full padbad restore is admitted only for a stable zero-bad-block backup" >&2
    echo "ERROR: backup bad blocks before/after=$LEDGER_BAD_COUNT_BEFORE/$LEDGER_BAD_COUNT_AFTER policy=${LEDGER_BAD_POLICY:-missing}; no proven padbad-to-skipbad replay transform exists" >&2
    exit 1
fi
[ "$CLEAR" = "false" ] || {
    echo "ERROR: BACKUP_LEDGER must keep clear_for_flash=false" >&2
    exit 1
}
[ "$NOT_GO" = "true" ] || {
    echo "ERROR: BACKUP_LEDGER must keep braiins_success_is_not_stock_go=true" >&2
    exit 1
}
[ "$LEDGER_BAD_BLOCKS" = "padbad" ] && [ "$LEDGER_OOB" = "omitted" ] && \
    [ "$LEDGER_DUPLICATE" = "true" ] || {
    echo "ERROR: backup is not offset-preserving padbad/omitoob with a matching duplicate read" >&2
    echo "ERROR: legacy skipbad or untyped mtd5 backups are non-restorable because bad blocks compact offsets" >&2
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
IDENTITY_PROOF="$ARTIFACT_DIR/$IDENTITY_PROOF_FILE"
[ -f "$IDENTITY_PROOF" ] && [ ! -L "$IDENTITY_PROOF" ] || {
    echo "ERROR: identity proof must be a regular non-symlink file: $IDENTITY_PROOF" >&2
    exit 1
}
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
hex64 "$IDENTITY_PROOF_SHA" || {
    echo "ERROR: identity_proof_sha256 is not 64 lowercase hex chars" >&2
    exit 1
}
FILE_IDENTITY_PROOF=$(local_sha256 "$IDENTITY_PROOF")
[ "$FILE_IDENTITY_PROOF" = "$IDENTITY_PROOF_SHA" ] || {
    echo "ERROR: identity_tuple_pre.txt sha256 drift" >&2
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
if [ "$LEDGER_BT_PKG" != am3-s19k ]; then
    echo "ERROR: backup package target '${LEDGER_BT_PKG:-missing}' is not exact am3-s19k" >&2
    exit 1
fi
if [ "$LEDGER_BT_SRC" = "package" ]; then
    [ -z "$LEDGER_BT" ] || {
        echo "ERROR: package-sourced backup must not relabel a package target as a live board_target" >&2
        exit 1
    }
    echo "board_target_source=package (not live; exact tuple proof independently re-admitted)"
    echo "board_target_package=$LEDGER_BT_PKG"
elif [ "$LEDGER_BT_SRC" = "live" ] && [ -n "$LEDGER_BT" ]; then
    case "$LEDGER_BT" in
        am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
        *)
            echo "ERROR: admit ledger board_target='$LEDGER_BT' is not am3-s19k; refuse fail-open restore" >&2
            exit 1
            ;;
    esac
else
    echo "ERROR: backup board_target source '${LEDGER_BT_SRC:-missing}' is neither live nor tuple-proven package evidence" >&2
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
PROC_TMP="$RESTORE_TMP/proc_mtd.txt"
printf '%s\n' "$LEDGER_PROC" | tr '|' '\n' > "$PROC_TMP"
dcent_am3_require_exact_s19k_mtd_map_file "$PROC_TMP" || {
    echo "ERROR: backup ledger geometry is not exact S19k .78" >&2
    exit 1
}
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
SLICE="$RESTORE_TMP/nandrecovery_env.slice"
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
echo "mtd5_dump_bad_blocks=$LEDGER_BAD_BLOCKS"
echo "mtd5_dump_oob=$LEDGER_OOB"
echo "mtd5_duplicate_read=$LEDGER_DUPLICATE"
echo "mtd5_bad_block_count_before=$LEDGER_BAD_COUNT_BEFORE"
echo "mtd5_bad_block_count_after=$LEDGER_BAD_COUNT_AFTER"
echo "mtd5_restore_bad_block_policy=$LEDGER_BAD_POLICY"
echo "identity_proof_schema=$IDENTITY_PROOF_SCHEMA"
echo "identity_proof_variant=$IDENTITY_PROOF_VARIANT"
echo "identity_proof_sha256=$FILE_IDENTITY_PROOF"
echo "identity_proof_receipt=$RECOMPUTED_IDENTITY_RECEIPT"
echo "rootfs_mtd=$ROOTFS_MTD"
echo "note=full nanddump restore; refuse any window-offset including current 0x05100000; stale 0x05700000 is size-sum geometry"
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

if [ ! -r /proc/mtd ]; then
    echo "ERROR: missing live /proc/mtd; refuse geometry-blind restore" >&2
    exit 1
fi
dcent_am3_require_exact_s19k_mtd_map_file /proc/mtd || {
    echo "ERROR: live geometry is not exact S19k .78; refuse restore" >&2
    exit 1
}
LIVE_BASE=$(dcent_am3_mtd5_base_from_proc_mtd /proc/mtd) || {
    echo "ERROR: live /proc/mtd cannot compute mtd5 geometry" >&2
    exit 1
}
[ $((LIVE_BASE)) -eq $((RECOMPUTED)) ] || {
    echo "ERROR: live mtd5 base != backup ledger geometry" >&2
    exit 1
}
if [ -r /etc/dcentos/tmp_deploy ]; then
    echo "ERROR: /etc/dcentos/tmp_deploy leftover — refuse restore after /tmp bench deploy" >&2
    exit 1
fi
require_exact_live_s19k_identity /etc/dcentos || exit 1
LIVE_BAD_BLOCKS=$(cat /sys/class/mtd/mtd5/bad_blocks 2>/dev/null || echo unknown)
LIVE_BAD_BLOCKS=$(printf '%s' "$LIVE_BAD_BLOCKS" | tr -d ' \t\r\n')
case "$LIVE_BAD_BLOCKS" in
    ''|*[!0-9]*)
        echo "ERROR: live mtd5 bad-block count is unavailable; refusing unproven full-image replay" >&2
        exit 1
        ;;
esac
[ "$LIVE_BAD_BLOCKS" -eq 0 ] || {
    echo "ERROR: live mtd5 has $LIVE_BAD_BLOCKS bad block(s); refusing padbad image through skip-bad nandwrite" >&2
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

echo "Step 2: flash_erase $ROOTFS_MTD (whole partition; not current 0x05100000 or stale 0x05700000 windows)..."
flash_erase "$ROOTFS_MTD" 0 0

echo "Step 3: nandwrite full nanddump to $ROOTFS_MTD..."
nandwrite -p "$ROOTFS_MTD" "$MTD5"

echo "Step 4: offset-preserving nanddump readback sha256..."
nanddump --bb=padbad --omitoob -f "$RESTORE_TMP/mtd5_restore_readback.bin" \
    "$ROOTFS_MTD" >/dev/null 2>&1
READBACK=$(local_sha256 "$RESTORE_TMP/mtd5_restore_readback.bin")
rm -f "$RESTORE_TMP/mtd5_restore_readback.bin"
if [ "$READBACK" != "$FILE_MTD5" ]; then
    echo "ERROR: post-write mtd5 sha256 drift (want $FILE_MTD5 got $READBACK)" >&2
    echo "DO NOT POWER CYCLE until this is understood. env was not flipped." >&2
    exit 1
fi

echo "RESTORE_OK mtd5 matches ledger sha256=$READBACK env_flip=false clear_for_flash=false"
exit 0
