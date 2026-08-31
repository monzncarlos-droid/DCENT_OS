#!/bin/sh
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
#
# DCENT_OS S19k Pro Amlogic first-install stage 1.
#
# This is the target-side transaction candidate packaged as
# transition/stage1.sh.  It owns no SSH transport and never reboots.  The
# current reviewed bytes intentionally keep live NAND execution unreachable:
# INTERNAL_CLEAR_FOR_FLASH=false.  A fixture-only backend exercises the exact
# orchestration and cut points without opening a device node; it cannot be
# redirected to /dev.
#
# Live contract, once a future separately reviewed script hash changes the
# internal gate:
#   1. exact request, script, rootfs, recovery inputs, S19k identity, source,
#      /proc/mtd, physical mtd5 base, zero-bad-block and GPIO437 SafeOff proof;
#   2. persist a pre-mutation receipt/state and revalidate;
#   3. erase/write/read back the complete mtd5 rootfs window payload;
#   4. revalidate all safety evidence and the still-original flag eraseblock;
#   5. erase/write/read back a separately content-bound full 128 KiB flag
#      eraseblock whose byte 0 is 0x01 and whose remaining bytes exactly match
#      the captured original; this is the final NAND operation (InstallArm);
#   6. publish installed_commit_verified_no_reboot.  Reboot is always external.
#
# Any failure after the first erase is indeterminate_restore_required.  Restore
# mode rewrites/readbacks only the separately captured full original 0x02 flag
# eraseblock and reports stock_recovery_armed_no_reboot; it cannot claim that
# stock cold-booted.

set -eu
umask 077

STAGE1_PROTOCOL_SCHEMA='dcentos.s19k-mtd5-rootfs-window-stage1/v1'
REQUEST_SCHEMA_EXPECTED='dcentos.s19k-stage1-request/v1'
RECEIPT_SCHEMA='dcentos.s19k-stage1-receipt/v1'
IMPLEMENTATION_ID='dcentos-s19k-aml-stage1-posix-v1'
AUTHORIZATION_SCHEMA_EXPECTED='dcentos.s19k-stage1-authorization/v1'
LIVE_AUTHORIZATION_PUBKEY_HEX='26985575eae77d56c490ceeb9054af012eab5ae59119cd20eaa70dd7e722df83'
LIVE_STAGE1_AUTHORIZER_NAME='s19k-stage1-authorizer'
LIVE_STAGE1_AUTHORIZER_SHA256='8a8d744a11490a30f5e821794ad3c6d12c55d940bdbce001369867c8212a6c53'
LIVE_STAGE1_AUTHORIZER_BYTES=467976
STAGE1_AUTHORIZER_MAX_BYTES=1048576
TMP_RESERVE_KIB=4096
LIVE_RUNTIME_EXTRA_MAX_BYTES=524288
# RFC 8032 vector public key, accepted only by the ordinary-file fixture
# backend.  It is explicitly forbidden as the live/release trust anchor.
FIXTURE_AUTHORIZATION_PUBKEY_HEX='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

# This literal is a release interlock.  Tests may use the fixture backend, but
# no environment variable, argv, request field, symlink or helper command can
# change this value or route fixture operations to a device.
INTERNAL_CLEAR_FOR_FLASH=false

MTD5='/dev/mtd5'
MTD5_BASE_HEX='0x06700000'
MTD5_LEN=160432128
MTD5_END_HEX='0x10000000'
ROOTFS_LOCAL_HEX='0x05100000'
ROOTFS_WINDOW_HEX='0x02800000'
ROOTFS_WINDOW_BYTES=41943040
ROOTFS_ERASE_COUNT=320
ERASEBLOCK_SIZE=131072
WRITESIZE=2048
RECOVERY_FLAG_LOCAL_HEX='0x04D00000'
RECOVERY_FLAG_INSTALLED=1
RECOVERY_FLAG_STOCK=2
GPIO_SAFE_OFF=437
GPIO_SAFE_OFF_VALUE=1
FLAG_TAIL_ALL_FF_SHA256='7d6d0bf52ce759862d4f62e20d038e0fca09df26dfb34ce2067efa0dc53558f0'

REQUEST_PATH=''
MODE='unknown'
WORKDIR=''
LOG_FILE=''
OPERATION_LOG=''
STATE_FILE=''
RECEIPT_FILE=''
MODE_RECEIPT_FILE=''
CLAIM_FILE=''
REQUEST_SHA256=''
SCOPE_ID=''
BOARD_TARGET=''
SOURCE_LAYOUT=''
IDENTITY_RECORD_SHA256=''
ROOTFS_SHA256=''
ROOTFS_BYTES=0
ROOTFS_READBACK_SHA256=''
ROOTFS_READBACK_BYTES=0
FLAG_ORIGINAL_SHA256=''
FLAG_CANDIDATE_SHA256=''
FLAG_READBACK_VALUE=0
AUTHORIZATION_SIGNATURE_SHA256=''
AUTHORIZATION_VERIFIED=false
AUTHORIZATION_VERIFIER='none'
STAGE1_AUTHORIZER_VERIFIED=false
STAGE1_AUTHORIZER_OBSERVED_SHA256=''
STAGE1_AUTHORIZER_OBSERVED_BYTES=0
STAGE1_AUTHORIZER_TARGET_KAT_VERIFIED=false
TMP_AVAILABLE_KIB=0
TMP_CAPACITY_VERIFIED=false
ROOTFS_READBACK_MODE='none'
TRANSFERS_VERIFIED=false
IDENTITY_VERIFIED=false
GEOMETRY_VERIFIED=false
ZERO_BAD_BLOCKS_VERIFIED=false
SAFEOFF_VERIFIED=false
MUTATION_STARTED=false
NAND_ERASE_PERFORMED=false
NAND_WRITE_PERFORMED=false
FIXTURE_MUTATION_PERFORMED=false
RESTORE_REQUIRED=false
POSTBOOT_PROOF_REQUIRED=false
INSTALL_COMMIT_VERIFIED=false
STOCK_RECOVERY_ARMED=false
LAST_COMPLETED_STEP='entry'
FAILURE_CODE=''
STOCK_PROCESS_STATE='unknown'
SIMULATION=false
RECEIPT_EMITTED=false
LOCK_HELD=false
TEST_ROOT=''

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

file_bytes() {
    wc -c < "$1" | tr -d ' \t\r\n'
}

is_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

is_safe_atom() {
    [ -n "$1" ] || return 1
    case "$1" in *[!A-Za-z0-9._:+/@-]*) return 1 ;; esac
    return 0
}

json_bool() {
    if [ "$1" = true ]; then printf true; else printf false; fi
}

operation_log_sha256() {
    if [ -n "$OPERATION_LOG" ] && [ -f "$OPERATION_LOG" ]; then
        sha256_file "$OPERATION_LOG" 2>/dev/null || printf ''
    else
        printf ''
    fi
}

# The live transaction deliberately forces each durable handoff to storage.
# The ordinary-file fixture has no durability claim and may live on a host
# filesystem (for example WSL drvfs) where a global sync is both unrelated to
# the proof and pathologically slow.  Keep the proof backend deterministic
# without weakening the live path.
durable_sync() {
    # The test-root environment can fail during request parsing before the
    # marker is admitted and SIMULATION flips true.  No mutation is reachable
    # on that path, so avoid a host-wide drvfs sync for those refusal receipts.
    if [ "$SIMULATION" = true ] || [ -n "${DCENT_S19K_STAGE1_TEST_ROOT:-}" ]; then
        return 0
    fi
    sync >/dev/null 2>&1 || true
}

# One exact flat canonical JSON object.  All interpolated strings are either
# constants, lowercase hashes or atoms admitted before mutation.
emit_receipt() {
    receipt_state=$1
    receipt_exit=$2
    receipt_failure=$3
    receipt_op_sha=$(operation_log_sha256)
    [ -n "$receipt_failure" ] || receipt_failure='none'
    [ -n "$REQUEST_SHA256" ] || REQUEST_SHA256='none'
    [ -n "$SCOPE_ID" ] || SCOPE_ID='none'
    [ -n "$BOARD_TARGET" ] || BOARD_TARGET='none'
    [ -n "$SOURCE_LAYOUT" ] || SOURCE_LAYOUT='none'
    [ -n "$IDENTITY_RECORD_SHA256" ] || IDENTITY_RECORD_SHA256='none'
    [ -n "$ROOTFS_SHA256" ] || ROOTFS_SHA256='none'
    [ -n "$ROOTFS_READBACK_SHA256" ] || ROOTFS_READBACK_SHA256='none'
    [ -n "$FLAG_ORIGINAL_SHA256" ] || FLAG_ORIGINAL_SHA256='none'
    [ -n "$FLAG_CANDIDATE_SHA256" ] || FLAG_CANDIDATE_SHA256='none'
    [ -n "$receipt_op_sha" ] || receipt_op_sha='none'
    [ -n "$LAST_COMPLETED_STEP" ] || LAST_COMPLETED_STEP='none'
    [ -n "$STOCK_PROCESS_STATE" ] || STOCK_PROCESS_STATE='unknown'

    WRITES_AUTHORIZED=false
    if [ "$MODE" != preflight ] && [ "$INTERNAL_CLEAR_FOR_FLASH" = true ] && \
       [ "$AUTHORIZATION_VERIFIED" = true ] && [ "$SIMULATION" != true ]; then
        WRITES_AUTHORIZED=true
    fi
    receipt_line=$(printf '%s' \
        "{\"authority_token_sha256\":\"${REQ_AUTHORITY_TOKEN_SHA256:-none}\",\"authorization_public_key_hex\":\"${REQ_AUTHORIZATION_PUBKEY_HEX:-none}\",\"authorization_schema\":\"${REQ_AUTHORIZATION_SCHEMA:-none}\",\"authorization_signature_sha256\":\"${AUTHORIZATION_SIGNATURE_SHA256:-none}\",\"authorization_verified\":$(json_bool "$AUTHORIZATION_VERIFIED"),\"authorization_verifier\":\"$AUTHORIZATION_VERIFIER\"," \
        "\"board_target\":\"$BOARD_TARGET\",\"capsule_sha256\":\"${REQ_CAPSULE_SHA256:-none}\",\"claim_file\":\"stage1-$MODE.claim\",\"clear_for_flash_internal\":$(json_bool "$INTERNAL_CLEAR_FOR_FLASH"),\"clear_for_flash_request\":$(json_bool "${REQ_CLEAR_FOR_FLASH:-false}")," \
        "\"exit_code\":$receipt_exit,\"failure_code\":\"$receipt_failure\",\"fixture_mutation_performed\":$(json_bool "$FIXTURE_MUTATION_PERFORMED"),\"geometry_verified\":$(json_bool "$GEOMETRY_VERIFIED"),\"identity_record_sha256\":\"$IDENTITY_RECORD_SHA256\",\"identity_verified\":$(json_bool "$IDENTITY_VERIFIED"),\"implementation_id\":\"$IMPLEMENTATION_ID\",\"install_commit_verified\":$(json_bool "$INSTALL_COMMIT_VERIFIED")," \
        "\"last_completed_step\":\"$LAST_COMPLETED_STEP\",\"latest_receipt_file\":\"stage1-receipt.json\",\"log_file\":\"stage1-$MODE.log\",\"mode\":\"$MODE\",\"mtd5_backup_sha256\":\"${REQ_MTD5_BACKUP_SHA256:-none}\",\"mtd5_base_hex\":\"$MTD5_BASE_HEX\",\"mutation_started\":$(json_bool "$MUTATION_STARTED")," \
        "\"nand_env_backup_sha256\":\"${REQ_NAND_ENV_BACKUP_SHA256:-none}\",\"nand_erase_performed\":$(json_bool "$NAND_ERASE_PERFORMED"),\"nand_write_performed\":$(json_bool "$NAND_WRITE_PERFORMED"),\"nandrecovery_env_sha256\":\"${REQ_NANDRECOVERY_ENV_SHA256:-none}\",\"operation_log_file\":\"stage1-$MODE-operations.log\",\"operation_log_sha256\":\"$receipt_op_sha\",\"original_recovery_flag\":${REQ_ORIGINAL_RECOVERY_FLAG:-0}," \
        "\"persistent_image_verification_id\":\"${REQ_PERSISTENT_IMAGE_ID:-none}\",\"postboot_proof_required\":$(json_bool "$POSTBOOT_PROOF_REQUIRED"),\"receipt_file\":\"stage1-$MODE-receipt.json\",\"recovery_flag_candidate_sha256\":\"$FLAG_CANDIDATE_SHA256\",\"recovery_flag_original_sha256\":\"$FLAG_ORIGINAL_SHA256\",\"recovery_flag_readback\":$FLAG_READBACK_VALUE,\"request_schema\":\"$REQUEST_SCHEMA_EXPECTED\",\"request_sha256\":\"$REQUEST_SHA256\"," \
        "\"restore_required\":$(json_bool "$RESTORE_REQUIRED"),\"rootfs_bytes\":$ROOTFS_BYTES,\"rootfs_readback_bytes\":$ROOTFS_READBACK_BYTES,\"rootfs_readback_mode\":\"$ROOTFS_READBACK_MODE\",\"rootfs_readback_sha256\":\"$ROOTFS_READBACK_SHA256\",\"rootfs_sha256\":\"$ROOTFS_SHA256\",\"safeoff_gpio\":$GPIO_SAFE_OFF,\"safeoff_value\":$GPIO_SAFE_OFF_VALUE,\"safeoff_verified\":$(json_bool "$SAFEOFF_VERIFIED"),\"schema\":\"$RECEIPT_SCHEMA\",\"scope_id\":\"$SCOPE_ID\",\"simulation\":$(json_bool "$SIMULATION"),\"source_layout\":\"$SOURCE_LAYOUT\"," \
        "\"stage1_authorizer_bytes\":${REQ_STAGE1_AUTHORIZER_BYTES:-0},\"stage1_authorizer_observed_bytes\":$STAGE1_AUTHORIZER_OBSERVED_BYTES,\"stage1_authorizer_observed_sha256\":\"${STAGE1_AUTHORIZER_OBSERVED_SHA256:-none}\",\"stage1_authorizer_pinned_bytes\":$LIVE_STAGE1_AUTHORIZER_BYTES,\"stage1_authorizer_pinned_sha256\":\"$LIVE_STAGE1_AUTHORIZER_SHA256\",\"stage1_authorizer_sha256\":\"${REQ_STAGE1_AUTHORIZER_SHA256:-none}\",\"stage1_authorizer_target_kat_verified\":$(json_bool "$STAGE1_AUTHORIZER_TARGET_KAT_VERIFIED"),\"stage1_authorizer_verified\":$(json_bool "$STAGE1_AUTHORIZER_VERIFIED")," \
        "\"stage1_bytes\":${REQ_STAGE1_BYTES:-0},\"stage1_protocol_schema\":\"$STAGE1_PROTOCOL_SCHEMA\",\"stage1_sha256\":\"${REQ_STAGE1_SHA256:-none}\",\"state\":\"$receipt_state\",\"state_file\":\"stage1-$MODE-state\",\"stock_process_state\":\"$STOCK_PROCESS_STATE\",\"stock_recovery_armed\":$(json_bool "$STOCK_RECOVERY_ARMED"),\"stock_recovery_device_id\":\"${REQ_STOCK_RECOVERY_DEVICE_ID:-none}\",\"stock_recovery_receipt_sha256\":\"${REQ_STOCK_RECOVERY_RECEIPT_SHA256:-none}\",\"stock_recovery_verification_id\":\"${REQ_STOCK_RECOVERY_ID:-none}\"," \
        "\"terminal\":true,\"tmp_available_kib\":$TMP_AVAILABLE_KIB,\"tmp_capacity_verified\":$(json_bool "$TMP_CAPACITY_VERIFIED"),\"tmp_reserve_kib\":$TMP_RESERVE_KIB,\"tmp_runtime_extra_max_bytes\":$LIVE_RUNTIME_EXTRA_MAX_BYTES,\"transferred_inputs_verified\":$(json_bool "$TRANSFERS_VERIFIED"),\"writes_authorized\":$(json_bool "$WRITES_AUTHORIZED"),\"zero_bad_blocks_verified\":$(json_bool "$ZERO_BAD_BLOCKS_VERIFIED")}")

    RECEIPT_EMITTED=true
    if [ -n "$RECEIPT_FILE" ]; then
        receipt_tmp="$RECEIPT_FILE.tmp.$$"
        if printf '%s\n' "$receipt_line" > "$receipt_tmp" 2>/dev/null; then
            durable_sync
            mv -f "$receipt_tmp" "$RECEIPT_FILE" 2>/dev/null || true
            durable_sync
        fi
    fi
    if [ -n "$MODE_RECEIPT_FILE" ] && [ ! -e "$MODE_RECEIPT_FILE" ] && [ ! -L "$MODE_RECEIPT_FILE" ]; then
        mode_receipt_tmp="$MODE_RECEIPT_FILE.tmp.$$"
        if printf '%s\n' "$receipt_line" > "$mode_receipt_tmp" 2>/dev/null; then
            durable_sync
            # A hard-link publication is atomic and fails if a terminal mode
            # receipt appeared concurrently; it can never replace evidence.
            if ln "$mode_receipt_tmp" "$MODE_RECEIPT_FILE" 2>/dev/null; then
                durable_sync
            fi
            rm -f "$mode_receipt_tmp" 2>/dev/null || true
        fi
    fi
    printf '%s\n' "$receipt_line"
}

finish() {
    finish_state=$1
    finish_exit=$2
    finish_failure=$3
    trap - EXIT HUP INT TERM
    emit_receipt "$finish_state" "$finish_exit" "$finish_failure"
    exit "$finish_exit"
}

fail_now() {
    fail_code=$1
    fail_exit=${2:-1}
    FAILURE_CODE=$fail_code
    if [ "$MUTATION_STARTED" = true ]; then
        RESTORE_REQUIRED=true
        finish indeterminate_restore_required "$fail_exit" "$fail_code"
    fi
    finish refused_pre_mutation "$fail_exit" "$fail_code"
}

on_exit() {
    unexpected_exit=$1
    [ "$RECEIPT_EMITTED" = true ] && return 0
    set +e
    if [ "$unexpected_exit" -eq 0 ]; then unexpected_exit=1; fi
    if [ "$MUTATION_STARTED" = true ]; then
        RESTORE_REQUIRED=true
        emit_receipt indeterminate_restore_required "$unexpected_exit" unexpected_exit
    else
        emit_receipt refused_pre_mutation "$unexpected_exit" unexpected_exit
    fi
    return 0
}

trap 'on_exit $?' EXIT
trap 'FAILURE_CODE=signal_hup; exit 129' HUP
trap 'FAILURE_CODE=signal_int; exit 130' INT
trap 'FAILURE_CODE=signal_term; exit 143' TERM

usage() {
    fail_now argv_invalid 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --request)
            [ "$#" -ge 2 ] || usage
            REQUEST_PATH=$2
            shift 2
            ;;
        --mode)
            [ "$#" -ge 2 ] || usage
            MODE=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

[ -n "$REQUEST_PATH" ] || usage
case "$MODE" in preflight|install|restore) ;; *) usage ;; esac
# A preflight success is only admission to the transition workflow, never the
# final production proof.  Every mode therefore tells the executor that an
# independent cold-boot witness remains required for campaign completion.
POSTBOOT_PROOF_REQUIRED=true

WORKDIR=$(pwd -P) || fail_now workdir_unavailable 2
LOG_FILE="$WORKDIR/stage1-$MODE.log"
OPERATION_LOG="$WORKDIR/stage1-$MODE-operations.log"
STATE_FILE="$WORKDIR/stage1-$MODE-state"
RECEIPT_FILE="$WORKDIR/stage1-receipt.json"
MODE_RECEIPT_FILE="$WORKDIR/stage1-$MODE-receipt.json"
CLAIM_FILE="$WORKDIR/stage1-$MODE.claim"
# Append-only launch diagnostics preserve evidence if a duplicate invocation is
# refused by the later O_EXCL claim.  The operation log is truncated only by
# the process that actually acquires that claim.
: >> "$LOG_FILE" || fail_now workdir_not_writable 2
exec 2>>"$LOG_FILE"
# Never inherit an interactive SSH stdin.  nohup may redirect it too; the
# explicit close makes the target-side contract independent of its launcher.
exec </dev/null

[ -f "$REQUEST_PATH" ] && [ ! -L "$REQUEST_PATH" ] || fail_now request_not_regular 2
# Bind every parsed and signed byte to one already-open inode.  Reopening the
# request pathname after parsing would let a path replacement verify different
# bytes than the fields that drive the transaction.
exec 4<"$REQUEST_PATH" || fail_now request_open_failed 2
REQUEST_FD=/proc/self/fd/4
REQUEST_BYTES=$(file_bytes "$REQUEST_FD") || fail_now request_size_failed 2
case "$REQUEST_BYTES" in ''|*[!0-9]*) fail_now request_size_invalid 2 ;; esac
[ "$REQUEST_BYTES" -gt 0 ] && [ "$REQUEST_BYTES" -le 32768 ] || fail_now request_size_invalid 2
NON_ASCII=$(LC_ALL=C tr -d '\11\12\15\40-\176' < "$REQUEST_FD" | wc -c | tr -d ' \t\r\n')
[ "$NON_ASCII" -eq 0 ] || fail_now request_not_ascii 2
REQUEST_SHA256=$(sha256_file "$REQUEST_FD") || fail_now request_hash_failed 2
is_sha256 "$REQUEST_SHA256" || fail_now request_hash_invalid 2

json_string() {
    json_key=$1
    json_count=$(grep -c "^[[:space:]]*\"$json_key\"[[:space:]]*:" "$REQUEST_FD" || true)
    [ "$json_count" -eq 1 ] || fail_now "request_${json_key}_cardinality" 2
    json_value=$(sed -n "s/^[[:space:]]*\"$json_key\"[[:space:]]*:[[:space:]]*\"\([^\"\\\\]*\)\"[[:space:]]*,\{0,1\}[[:space:]]*$/\\1/p" "$REQUEST_FD")
    [ -n "$json_value" ] || fail_now "request_${json_key}_invalid" 2
    printf '%s' "$json_value"
}

json_uint() {
    json_key=$1
    json_count=$(grep -c "^[[:space:]]*\"$json_key\"[[:space:]]*:" "$REQUEST_FD" || true)
    [ "$json_count" -eq 1 ] || fail_now "request_${json_key}_cardinality" 2
    json_value=$(sed -n "s/^[[:space:]]*\"$json_key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*,\{0,1\}[[:space:]]*$/\\1/p" "$REQUEST_FD")
    [ -n "$json_value" ] || fail_now "request_${json_key}_invalid" 2
    printf '%s' "$json_value"
}

json_boolean() {
    json_key=$1
    json_count=$(grep -c "^[[:space:]]*\"$json_key\"[[:space:]]*:" "$REQUEST_FD" || true)
    [ "$json_count" -eq 1 ] || fail_now "request_${json_key}_cardinality" 2
    json_value=$(sed -n "s/^[[:space:]]*\"$json_key\"[[:space:]]*:[[:space:]]*\(true\|false\)[[:space:]]*,\{0,1\}[[:space:]]*$/\\1/p" "$REQUEST_FD")
    [ -n "$json_value" ] || fail_now "request_${json_key}_invalid" 2
    printf '%s' "$json_value"
}

EXPECTED_KEYS='authority_token_sha256
authorization_public_key_hex
authorization_schema
board_target
capsule_sha256
clear_for_flash
eraseblock_size
identity_record_sha256
mode
mtd5_backup_sha256
mtd5_base_hex
mtd5_len
nand_env_backup_sha256
nandrecovery_env_sha256
original_recovery_flag
persistent_image_verification_id
recovery_flag_eraseblock_sha256
recovery_flag_install_candidate_sha256
recovery_flag_local_offset_hex
rootfs_bytes
rootfs_erase_count
rootfs_local_offset_hex
rootfs_mtd
rootfs_sha256
rootfs_window_hex
schema
scope_id
source_layout
stage1_authorizer_bytes
stage1_authorizer_sha256
stage1_bytes
stage1_sha256
stock_recovery_device_id
stock_recovery_receipt_sha256
stock_recovery_verification_id'

OBSERVED_KEYS=$(sed -n 's/^[[:space:]]*"\([a-z0-9_][a-z0-9_]*\)"[[:space:]]*:.*/\1/p' "$REQUEST_FD" | LC_ALL=C sort)
[ "$OBSERVED_KEYS" = "$EXPECTED_KEYS" ] || fail_now request_key_set_not_exact 2

REQ_SCHEMA=$(json_string schema)
REQ_MODE=$(json_string mode)
SCOPE_ID=$(json_string scope_id)
REQ_AUTHORITY_TOKEN_SHA256=$(json_string authority_token_sha256)
REQ_AUTHORIZATION_PUBKEY_HEX=$(json_string authorization_public_key_hex)
REQ_AUTHORIZATION_SCHEMA=$(json_string authorization_schema)
REQ_CAPSULE_SHA256=$(json_string capsule_sha256)
REQ_STAGE1_AUTHORIZER_SHA256=$(json_string stage1_authorizer_sha256)
REQ_STAGE1_AUTHORIZER_BYTES=$(json_uint stage1_authorizer_bytes)
REQ_STAGE1_SHA256=$(json_string stage1_sha256)
REQ_STAGE1_BYTES=$(json_uint stage1_bytes)
ROOTFS_SHA256=$(json_string rootfs_sha256)
ROOTFS_BYTES=$(json_uint rootfs_bytes)
REQ_PERSISTENT_IMAGE_ID=$(json_string persistent_image_verification_id)
REQ_STOCK_RECOVERY_ID=$(json_string stock_recovery_verification_id)
REQ_STOCK_RECOVERY_RECEIPT_SHA256=$(json_string stock_recovery_receipt_sha256)
REQ_STOCK_RECOVERY_DEVICE_ID=$(json_string stock_recovery_device_id)
BOARD_TARGET=$(json_string board_target)
SOURCE_LAYOUT=$(json_string source_layout)
IDENTITY_RECORD_SHA256=$(json_string identity_record_sha256)
REQ_MTD5_BACKUP_SHA256=$(json_string mtd5_backup_sha256)
REQ_NAND_ENV_BACKUP_SHA256=$(json_string nand_env_backup_sha256)
REQ_NANDRECOVERY_ENV_SHA256=$(json_string nandrecovery_env_sha256)
FLAG_ORIGINAL_SHA256=$(json_string recovery_flag_eraseblock_sha256)
FLAG_CANDIDATE_SHA256=$(json_string recovery_flag_install_candidate_sha256)
REQ_ORIGINAL_RECOVERY_FLAG=$(json_uint original_recovery_flag)
REQ_MTD5_BASE_HEX=$(json_string mtd5_base_hex)
REQ_MTD5_LEN=$(json_uint mtd5_len)
REQ_ROOTFS_MTD=$(json_string rootfs_mtd)
REQ_ROOTFS_LOCAL_HEX=$(json_string rootfs_local_offset_hex)
REQ_ROOTFS_WINDOW_HEX=$(json_string rootfs_window_hex)
REQ_ROOTFS_ERASE_COUNT=$(json_uint rootfs_erase_count)
REQ_ERASEBLOCK_SIZE=$(json_uint eraseblock_size)
REQ_RECOVERY_FLAG_LOCAL_HEX=$(json_string recovery_flag_local_offset_hex)
REQ_CLEAR_FOR_FLASH=$(json_boolean clear_for_flash)

[ "$REQ_SCHEMA" = "$REQUEST_SCHEMA_EXPECTED" ] || fail_now request_schema_mismatch 2
[ "$REQ_AUTHORIZATION_SCHEMA" = "$AUTHORIZATION_SCHEMA_EXPECTED" ] || fail_now authorization_schema_mismatch 2
[ "$REQ_MODE" = "$MODE" ] || fail_now request_mode_mismatch 2
for request_hash in \
    "$SCOPE_ID" "$REQ_AUTHORITY_TOKEN_SHA256" "$REQ_CAPSULE_SHA256" \
    "$REQ_STAGE1_AUTHORIZER_SHA256" "$REQ_STAGE1_SHA256" \
    "$ROOTFS_SHA256" "$REQ_PERSISTENT_IMAGE_ID" \
    "$REQ_STOCK_RECOVERY_ID" "$REQ_STOCK_RECOVERY_RECEIPT_SHA256" \
    "$IDENTITY_RECORD_SHA256" "$REQ_MTD5_BACKUP_SHA256" \
    "$REQ_NAND_ENV_BACKUP_SHA256" "$REQ_NANDRECOVERY_ENV_SHA256" \
    "$FLAG_ORIGINAL_SHA256" "$FLAG_CANDIDATE_SHA256"
do
    is_sha256 "$request_hash" || fail_now request_hash_field_invalid 2
done
is_safe_atom "$REQ_STOCK_RECOVERY_DEVICE_ID" || fail_now recovery_device_id_invalid 2
[ "${#REQ_STOCK_RECOVERY_DEVICE_ID}" -le 128 ] || fail_now recovery_device_id_invalid 2
[ "$BOARD_TARGET" = am3-s19kpro ] || fail_now board_target_not_exact_s19k 2
case "$SOURCE_LAYOUT" in braiins-aml-s19k|luxos-aml-s19k) ;; *) fail_now source_layout_invalid 2 ;; esac
[ "$REQ_MTD5_BASE_HEX" = "$MTD5_BASE_HEX" ] || fail_now mtd5_base_request_mismatch 2
[ "$REQ_MTD5_LEN" -eq "$MTD5_LEN" ] || fail_now mtd5_len_request_mismatch 2
[ "$REQ_ROOTFS_MTD" = "$MTD5" ] || fail_now rootfs_mtd_request_mismatch 2
[ "$REQ_ROOTFS_LOCAL_HEX" = "$ROOTFS_LOCAL_HEX" ] || fail_now rootfs_offset_request_mismatch 2
[ "$REQ_ROOTFS_WINDOW_HEX" = "$ROOTFS_WINDOW_HEX" ] || fail_now rootfs_window_request_mismatch 2
[ "$REQ_ROOTFS_ERASE_COUNT" -eq "$ROOTFS_ERASE_COUNT" ] || fail_now rootfs_erase_count_request_mismatch 2
[ "$REQ_ERASEBLOCK_SIZE" -eq "$ERASEBLOCK_SIZE" ] || fail_now eraseblock_request_mismatch 2
[ "$REQ_RECOVERY_FLAG_LOCAL_HEX" = "$RECOVERY_FLAG_LOCAL_HEX" ] || fail_now flag_offset_request_mismatch 2
[ "$REQ_ORIGINAL_RECOVERY_FLAG" -eq "$RECOVERY_FLAG_STOCK" ] || fail_now original_flag_not_stock_recovery 2
[ "$REQ_CLEAR_FOR_FLASH" = true ] || fail_now request_clear_for_flash_not_true 2
[ "$ROOTFS_BYTES" -gt 0 ] && [ "$ROOTFS_BYTES" -le "$ROOTFS_WINDOW_BYTES" ] || fail_now rootfs_bytes_out_of_window 2
[ "$REQ_STAGE1_AUTHORIZER_BYTES" -gt 0 ] && [ "$REQ_STAGE1_AUTHORIZER_BYTES" -le "$STAGE1_AUTHORIZER_MAX_BYTES" ] || fail_now stage1_authorizer_bytes_out_of_bounds 2
[ "$REQ_STAGE1_AUTHORIZER_BYTES" -eq "$LIVE_STAGE1_AUTHORIZER_BYTES" ] || fail_now stage1_authorizer_bytes_request_mismatch 2
[ "$REQ_STAGE1_AUTHORIZER_SHA256" = "$LIVE_STAGE1_AUTHORIZER_SHA256" ] || fail_now stage1_authorizer_hash_request_mismatch 2
[ "$REQ_STAGE1_BYTES" -gt 0 ] && [ "$REQ_STAGE1_BYTES" -le 4194304 ] || fail_now stage1_bytes_invalid 2

# Fixture mode is a distinct filesystem backend.  It never calls flash_erase,
# nandwrite or nanddump and every simulated NAND path is fixed below TEST_ROOT.
if [ -n "${DCENT_S19K_STAGE1_TEST_ROOT:-}" ]; then
    TEST_ROOT=$(CDPATH= cd "$DCENT_S19K_STAGE1_TEST_ROOT" 2>/dev/null && pwd -P) || fail_now fixture_root_invalid 2
    [ "$TEST_ROOT" != / ] || fail_now fixture_root_invalid 2
    case "$TEST_ROOT" in *'/../'*|*/..) fail_now fixture_root_invalid 2 ;; esac
    [ -f "$TEST_ROOT/.dcent-s19k-stage1-fixture" ] && [ ! -L "$TEST_ROOT/.dcent-s19k-stage1-fixture" ] || fail_now fixture_marker_missing 2
    [ "$(sed -n '1p' "$TEST_ROOT/.dcent-s19k-stage1-fixture")" = 'dcentos.s19k-stage1-fixture/v1' ] || fail_now fixture_marker_invalid 2
    case "$WORKDIR" in "$TEST_ROOT"/*) ;; *) fail_now fixture_workdir_outside_root 2 ;; esac
    SIMULATION=true
    [ "$REQ_AUTHORIZATION_PUBKEY_HEX" = "$FIXTURE_AUTHORIZATION_PUBKEY_HEX" ] || fail_now fixture_authorization_key_mismatch 2
else
    [ "$(id -u)" -eq 0 ] || fail_now root_required 2
    [ "$WORKDIR" = "/tmp/dcent-s19k-first-install/$SCOPE_ID" ] || fail_now live_workdir_not_scope_bound 2
    [ "$REQ_AUTHORIZATION_PUBKEY_HEX" = "$LIVE_AUTHORIZATION_PUBKEY_HEX" ] || fail_now live_authorization_key_mismatch 2
fi

[ -f "$0" ] && [ ! -L "$0" ] || fail_now stage1_not_regular 2
OBS_STAGE1_SHA=$(sha256_file "$0") || fail_now stage1_hash_failed 2
OBS_STAGE1_BYTES=$(file_bytes "$0") || fail_now stage1_size_failed 2
[ "$OBS_STAGE1_SHA" = "$REQ_STAGE1_SHA256" ] || fail_now stage1_hash_mismatch 2
[ "$OBS_STAGE1_BYTES" -eq "$REQ_STAGE1_BYTES" ] || fail_now stage1_size_mismatch 2

# Verify a one-shot Ed25519 authorization over the exact request bytes.  The
# live key is the pinned D-Central release trust anchor; fixture mode uses only
# the RFC test key and remains structurally unable to reach a device.  A
# request clear=true and a public token digest are never sufficient alone.
REQUEST_SIGNATURE_FILE="$REQUEST_PATH.sig"
[ -f "$REQUEST_SIGNATURE_FILE" ] && [ ! -L "$REQUEST_SIGNATURE_FILE" ] || fail_now authorization_signature_missing 2
exec 5<"$REQUEST_SIGNATURE_FILE" || fail_now authorization_signature_open_failed 2
REQUEST_SIGNATURE_FD=/proc/self/fd/5
[ "$(file_bytes "$REQUEST_SIGNATURE_FD")" -eq 64 ] || fail_now authorization_signature_size_mismatch 2
AUTHORIZATION_SIGNATURE_SHA256=$(sha256_file "$REQUEST_SIGNATURE_FD") || fail_now authorization_signature_hash_failed 2
is_sha256 "$AUTHORIZATION_SIGNATURE_SHA256" || fail_now authorization_signature_hash_invalid 2
if [ "$SIMULATION" = true ]; then
    # Host fixtures retain OpenSSL only as an isolated test oracle.  The live
    # branch below neither probes nor invokes OpenSSL.
    command -v openssl >/dev/null 2>&1 || fail_now fixture_openssl_missing 2
    AUTHORIZATION_PUB_DER="$WORKDIR/stage1-authorization-pubkey.der"
    printf '\060\052\060\005\006\003\053\145\160\003\041\000' > "$AUTHORIZATION_PUB_DER"
    printf '\327\132\230\001\202\261\012\267\325\113\376\323\311\144\007\072\016\341\162\363\332\246\043\045\257\002\032\150\367\007\121\032' >> "$AUTHORIZATION_PUB_DER"
    [ "$(file_bytes "$AUTHORIZATION_PUB_DER")" -eq 44 ] || fail_now authorization_public_key_der_size_mismatch 2
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$AUTHORIZATION_PUB_DER" \
        -rawin -in "$REQUEST_FD" -sigfile "$REQUEST_SIGNATURE_FD" \
        >/dev/null 2>&1 || fail_now authorization_signature_invalid 2
    AUTHORIZATION_VERIFIER=fixture-openssl-pkeyutl
else
    AUTHORIZER_FILE="$WORKDIR/$LIVE_STAGE1_AUTHORIZER_NAME"
    [ -f "$AUTHORIZER_FILE" ] && [ ! -L "$AUTHORIZER_FILE" ] || fail_now stage1_authorizer_not_regular 2
    [ -x "$AUTHORIZER_FILE" ] || fail_now stage1_authorizer_not_executable 2
    exec 8<"$AUTHORIZER_FILE" || fail_now stage1_authorizer_open_failed 2
    AUTHORIZER_FD=/proc/self/fd/8
    STAGE1_AUTHORIZER_OBSERVED_BYTES=$(file_bytes "$AUTHORIZER_FD") || fail_now stage1_authorizer_size_failed 2
    case "$STAGE1_AUTHORIZER_OBSERVED_BYTES" in ''|*[!0-9]*) fail_now stage1_authorizer_size_invalid 2 ;; esac
    [ "$STAGE1_AUTHORIZER_OBSERVED_BYTES" -gt 0 ] && [ "$STAGE1_AUTHORIZER_OBSERVED_BYTES" -le "$STAGE1_AUTHORIZER_MAX_BYTES" ] || fail_now stage1_authorizer_size_out_of_bounds 2
    [ "$STAGE1_AUTHORIZER_OBSERVED_BYTES" -eq "$LIVE_STAGE1_AUTHORIZER_BYTES" ] || fail_now stage1_authorizer_size_mismatch 2
    STAGE1_AUTHORIZER_OBSERVED_SHA256=$(sha256_file "$AUTHORIZER_FD") || fail_now stage1_authorizer_hash_failed 2
    [ "$STAGE1_AUTHORIZER_OBSERVED_SHA256" = "$LIVE_STAGE1_AUTHORIZER_SHA256" ] || fail_now stage1_authorizer_hash_mismatch 2
    "$AUTHORIZER_FD" \
        --public-key-hex "$REQ_AUTHORIZATION_PUBKEY_HEX" \
        --message-fd 4 --signature-fd 5 \
        >/dev/null 2>&1 || fail_now authorization_signature_invalid 2
    AUTHORIZATION_VERIFIER=$LIVE_STAGE1_AUTHORIZER_NAME
    STAGE1_AUTHORIZER_VERIFIED=true
fi
AUTHORIZATION_VERIFIED=true

# POSIX noclobber requires an O_EXCL-style create.  One mode request may start
# exactly once in a scope; a stale claim is evidence requiring operator/toolbox
# adjudication, never permission to silently restart a transaction.
if [ -e "$MODE_RECEIPT_FILE" ] || [ -L "$MODE_RECEIPT_FILE" ]; then
    # Preserve the earlier immutable terminal receipt.  The duplicate refusal
    # is returned on stdout/latest only and cannot replace that evidence.
    MODE_RECEIPT_FILE=''
    fail_now mode_receipt_already_exists 2
fi
if ! (
    set -C
    {
        printf 'schema=dcentos.s19k-stage1-claim/v1\n'
        printf 'pid=%s\n' "$$"
        printf 'scope_id=%s\n' "$SCOPE_ID"
        printf 'mode=%s\n' "$MODE"
        printf 'request_sha256=%s\n' "$REQUEST_SHA256"
        printf 'stage1_sha256=%s\n' "$OBS_STAGE1_SHA"
    } > "$CLAIM_FILE"
) 2>/dev/null; then
    # Another process owns (or owned) this mode.  Do not publish a competing
    # terminal mode receipt while the rightful owner may still be running.
    MODE_RECEIPT_FILE=''
    fail_now mode_claim_already_exists 2
fi
durable_sync

ROOTFS_FILE="$WORKDIR/dcent-rootfs.img"
FLAG_ORIGINAL_FILE="$WORKDIR/recovery_flag_eb.bin"
FLAG_CANDIDATE_FILE="$WORKDIR/recovery_flag_eb.0x01.bin"
for input_file in "$ROOTFS_FILE" "$FLAG_ORIGINAL_FILE" "$FLAG_CANDIDATE_FILE"; do
    [ -f "$input_file" ] && [ ! -L "$input_file" ] || fail_now input_not_regular 2
done

exec 3<"$ROOTFS_FILE" || fail_now rootfs_open_failed 2
OBS_ROOTFS_SHA=$(sha256_file /proc/self/fd/3) || fail_now rootfs_hash_failed 2
OBS_ROOTFS_BYTES=$(file_bytes /proc/self/fd/3) || fail_now rootfs_size_failed 2
[ "$OBS_ROOTFS_SHA" = "$ROOTFS_SHA256" ] || fail_now rootfs_hash_mismatch 2
[ "$OBS_ROOTFS_BYTES" -eq "$ROOTFS_BYTES" ] || fail_now rootfs_size_mismatch 2
exec 6<"$FLAG_ORIGINAL_FILE" || fail_now flag_original_open_failed 2
exec 7<"$FLAG_CANDIDATE_FILE" || fail_now flag_candidate_open_failed 2
FLAG_ORIGINAL_FD=/proc/self/fd/6
FLAG_CANDIDATE_FD=/proc/self/fd/7

verify_recovery_inputs() {
    [ "$(file_bytes "$FLAG_ORIGINAL_FD")" -eq "$ERASEBLOCK_SIZE" ] || fail_now flag_original_size_mismatch 2
    [ "$(file_bytes "$FLAG_CANDIDATE_FD")" -eq "$ERASEBLOCK_SIZE" ] || fail_now flag_candidate_size_mismatch 2
    [ "$(sha256_file "$FLAG_ORIGINAL_FD")" = "$FLAG_ORIGINAL_SHA256" ] || fail_now flag_original_hash_mismatch 2
    [ "$(sha256_file "$FLAG_CANDIDATE_FD")" = "$FLAG_CANDIDATE_SHA256" ] || fail_now flag_candidate_hash_mismatch 2
    original_byte=$(od -An -tu1 -N1 "$FLAG_ORIGINAL_FD" | tr -d ' \t\r\n')
    candidate_byte=$(od -An -tu1 -N1 "$FLAG_CANDIDATE_FD" | tr -d ' \t\r\n')
    [ "$original_byte" -eq "$RECOVERY_FLAG_STOCK" ] || fail_now flag_original_byte_not_02 2
    [ "$candidate_byte" -eq "$RECOVERY_FLAG_INSTALLED" ] || fail_now flag_candidate_byte_not_01 2
    # BusyBox tail can start at byte two without the 131071 one-byte reads
    # incurred by `dd bs=1 skip=1` on host-mounted audit fixtures.
    original_tail=$(tail -c +2 "$FLAG_ORIGINAL_FD" | sha256sum | awk '{print $1}')
    candidate_tail=$(tail -c +2 "$FLAG_CANDIDATE_FD" | sha256sum | awk '{print $1}')
    [ "$original_tail" = "$FLAG_TAIL_ALL_FF_SHA256" ] || fail_now flag_original_tail_not_erased 2
    [ "$candidate_tail" = "$original_tail" ] || fail_now flag_candidate_tail_differs 2
}
verify_recovery_inputs
TRANSFERS_VERIFIED=true

system_path() {
    case "$1" in /*) ;; *) return 1 ;; esac
    if [ "$SIMULATION" = true ]; then printf '%s%s' "$TEST_ROOT" "$1"; else printf '%s' "$1"; fi
}

read_first_or_empty() {
    read_path=$(system_path "$1") || return 1
    if [ -r "$read_path" ]; then sed -n '1p' "$read_path"; fi
}

normalize_signal() {
    # BusyBox tr supports explicit ASCII ranges, not GNU character classes.
    printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9'
}

capture_identity() {
    identity_out="$WORKDIR/identity.observed"
    # Keep this byte-for-byte convergent with install_amlogic_persistent.sh.
    # BusyBox tr does not implement GNU's `[:space:]` spelling; its literal
    # whitespace escape set is required or `am3-s19k` becomes `m3-19k`.
    board_target=$(read_first_or_empty /etc/dcentos/board_target | tr -d ' \t\r\n')
    model=$(read_first_or_empty /config/CONF_MINER_TYPE)
    hwid=$(read_first_or_empty /config/CONF_HARDWARE_ID)
    pcb=''
    for pcb_abs in /config/CONF_CONTROL_BOARD /config/CONF_CTRL_BOARD_TYPE /config/CONF_BOARD_TYPE /etc/dcentos/pcb; do
        pcb_path=$(system_path "$pcb_abs")
        if [ -r "$pcb_path" ]; then pcb=$(sed -n '1p' "$pcb_path"); break; fi
    done
    bos_path=$(system_path /etc/bosminer.toml)
    bos_model=''
    if [ -r "$bos_path" ]; then bos_model=$(grep '^model' "$bos_path" | sed -n '1p' || true); fi
    dt_model_path=$(system_path /proc/device-tree/model)
    dt_compatible_path=$(system_path /proc/device-tree/compatible)
    cpu_path=$(system_path /proc/cpuinfo)
    dt_model=''
    dt_compatible=''
    cpu_system=''
    if [ -r "$dt_model_path" ]; then dt_model=$(tr '\000' '\n' < "$dt_model_path" | sed -n '1p'); fi
    if [ -r "$dt_compatible_path" ]; then dt_compatible=$(tr '\000' '\n' < "$dt_compatible_path" | tr '\n' ' '); fi
    if [ -r "$cpu_path" ]; then
        cpu_system=$(sed -n 's/^Hardware[[:space:]]*:[[:space:]]*//p;s/^model name[[:space:]]*:[[:space:]]*//p' "$cpu_path" | sed -n '1,2p' | tr '\n' ' ')
    fi
    {
        printf 'BOARD_TARGET=%s\n' "$board_target"
        printf 'MODEL=%s\n' "$model"
        printf 'HWID=%s\n' "$hwid"
        printf 'PCB=%s\n' "$pcb"
        printf 'BOS_MODEL=%s\n' "$bos_model"
        printf 'DT_MODEL=%s\n' "$dt_model"
        printf 'DT_COMPATIBLE=%s\n' "$dt_compatible"
        printf 'CPU_SYSTEM=%s\n' "$cpu_system"
    } > "$identity_out"
    observed_identity_sha=$(sha256_file "$identity_out")
    [ "$observed_identity_sha" = "$IDENTITY_RECORD_SHA256" ] || fail_now identity_record_hash_mismatch 2

    identity_lower=$(tr 'A-Z' 'a-z' < "$identity_out")
    case "$identity_lower" in *s21*|*s19k\ pro+*|*s19kpro+*|*s19k\ pro\ plus*|*s19kproplus*|*s19kxp*|*hydro*|*immersion*) fail_now sibling_identity_refused 2 ;; esac
    board_norm=$(normalize_signal "$board_target")
    case "$board_norm" in ''|am3s19k|am3s19kpro|amlogics19k|amlogics19kpro) ;; *) fail_now observed_board_target_conflict 2 ;; esac
    model_norm=$(normalize_signal "$model")
    bos_value=${bos_model#*=}
    bos_norm=$(normalize_signal "$bos_value")
    case "$model_norm" in antminers19kpro|antminers19kpronopic) ;; *) fail_now exact_model_missing 2 ;; esac
    case "$bos_norm" in antminers19kpro|antminers19kpronopic) ;; *) fail_now exact_bos_model_missing 2 ;; esac
    pcb_tokens=$(printf '%s\n%s\n%s\n%s\n' "$pcb" "$hwid" "$dt_model" "$dt_compatible" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '\n')
    printf '%s\n' "$pcb_tokens" | grep -Eq '^(c81|c83)$' || fail_now exact_pcb_c81_c83_missing 2
    soc_tokens=$(printf '%s\n%s\n%s\n' "$dt_model" "$dt_compatible" "$cpu_system" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '\n')
    printf '%s\n' "$soc_tokens" | grep -Eq '^(a113d|axg)$' || fail_now exact_soc_a113d_axg_missing 2
    IDENTITY_VERIFIED=true
}

verify_mtd_geometry() {
    proc_mtd=$(system_path /proc/mtd)
    [ -r "$proc_mtd" ] || fail_now proc_mtd_missing 2
    actual_map=$(awk '/^mtd[0-9]+:/ { name=$4; gsub(/"/, "", name); print $1, $2, $3, name }' "$proc_mtd")
    expected_map='mtd0: 00200000 00020000 bootloader
mtd1: 00800000 00020000 tpl
mtd2: 03200000 00020000 stock_system
mtd3: 00500000 00020000 stock_config
mtd4: 02000000 00020000 overlay
mtd5: 09900000 00020000 system'
    [ "$actual_map" = "$expected_map" ] || fail_now proc_mtd_map_mismatch 2
    mtd_name=$(system_path /sys/class/mtd/mtd5/name)
    mtd_size=$(system_path /sys/class/mtd/mtd5/size)
    mtd_erase=$(system_path /sys/class/mtd/mtd5/erasesize)
    mtd_write=$(system_path /sys/class/mtd/mtd5/writesize)
    mtd_bad=$(system_path /sys/class/mtd/mtd5/bad_blocks)
    [ "$(tr -d ' \t\r\n' < "$mtd_name")" = system ] || fail_now mtd5_name_mismatch 2
    [ "$(tr -d ' \t\r\n' < "$mtd_size")" -eq "$MTD5_LEN" ] || fail_now mtd5_size_mismatch 2
    [ "$(tr -d ' \t\r\n' < "$mtd_erase")" -eq "$ERASEBLOCK_SIZE" ] || fail_now mtd5_erasesize_mismatch 2
    [ "$(tr -d ' \t\r\n' < "$mtd_write")" -eq "$WRITESIZE" ] || fail_now mtd5_writesize_mismatch 2
    [ "$(tr -d ' \t\r\n' < "$mtd_bad")" -eq 0 ] || fail_now mtd5_bad_blocks_nonzero 2
    if [ "$SIMULATION" = true ]; then
        dmesg_file="$TEST_ROOT/dmesg.txt"
        [ -r "$dmesg_file" ] || fail_now dmesg_evidence_missing 2
        grep -F '0x000006700000-0x000010000000 : "system"' "$dmesg_file" >/dev/null || fail_now physical_mtd5_base_not_observed 2
    else
        dmesg | grep -F '0x000006700000-0x000010000000 : "system"' >/dev/null || fail_now physical_mtd5_base_not_observed 2
    fi
    GEOMETRY_VERIFIED=true
    ZERO_BAD_BLOCKS_VERIFIED=true
}

verify_source_and_safeoff() {
    platform_path=$(system_path /etc/bos_platform)
    [ -r "$platform_path" ] || fail_now bos_platform_missing 2
    [ "$(tr -d ' \t\r\n' < "$platform_path")" = am3-aml ] || fail_now bos_platform_not_am3_aml 2
    if [ "$SOURCE_LAYOUT" = braiins-aml-s19k ]; then
        [ -r "$(system_path /etc/bosminer.toml)" ] || fail_now braiins_source_not_observed 2
    fi
    tmp_deploy=$(system_path /etc/dcentos/tmp_deploy)
    [ ! -e "$tmp_deploy" ] && [ ! -L "$tmp_deploy" ] || fail_now tmp_deploy_leftover_present 2
    gpio_dir=$(system_path /sys/class/gpio/gpio437)
    [ -d "$gpio_dir" ] && [ ! -L "$gpio_dir" ] || fail_now gpio437_not_exported 2
    [ "$(tr -d ' \t\r\n' < "$gpio_dir/active_low")" = 0 ] || fail_now gpio437_active_low_not_zero 2
    [ "$(tr -d ' \t\r\n' < "$gpio_dir/direction")" = out ] || fail_now gpio437_direction_not_out 2
    [ "$(tr -d ' \t\r\n' < "$gpio_dir/value")" = "$GPIO_SAFE_OFF_VALUE" ] || fail_now gpio437_not_safeoff_high 2
    if [ "$SIMULATION" = true ]; then
        process_list="$TEST_ROOT/process.list"
        [ -r "$process_list" ] || fail_now process_snapshot_missing 2
        process_blob=$(cat "$process_list")
    else
        process_blob=$(ps w)
    fi
    if printf '%s\n' "$process_blob" | grep -E '(^|[ /])(bosminer|boser|bos-tools|dcentrald)([ :]($|[0-9])|[ /]|$)' >/dev/null; then
        STOCK_PROCESS_STATE=present
        fail_now mining_process_still_live 2
    fi
    STOCK_PROCESS_STATE=absent
    SAFEOFF_VERIFIED=true
}

verify_live_tools_and_tmp_capacity() {
    if [ "$SIMULATION" = true ]; then
        TMP_AVAILABLE_KIB=0
        TMP_CAPACITY_VERIFIED=true
        return 0
    fi
    for required_tool in flash_erase nandwrite nanddump sha256sum mkfifo df; do
        command -v "$required_tool" >/dev/null 2>&1 || fail_now "required_tool_${required_tool}_missing" 2
    done
    tmp_available=$(df -Pk "$WORKDIR" | awk 'NR > 1 && $4 ~ /^[0-9]+$/ { print $4; exit }')
    case "$tmp_available" in ''|*[!0-9]*) fail_now tmp_available_kib_invalid 2 ;; esac
    TMP_AVAILABLE_KIB=$tmp_available
    [ "$TMP_AVAILABLE_KIB" -ge "$TMP_RESERVE_KIB" ] || fail_now tmp_capacity_reserve_not_met 2
    TMP_CAPACITY_VERIFIED=true
}

read_current_flag_eraseblock() {
    flag_out=$1
    if [ "$SIMULATION" = true ]; then
        cp "$TEST_ROOT/nand/flag-current.bin" "$flag_out" || return 1
    else
        nanddump --bb=skipbad --omitoob -q -s "$RECOVERY_FLAG_LOCAL_HEX" -l "$ERASEBLOCK_SIZE" -f "$flag_out" "$MTD5" >/dev/null 2>&1 || return 1
    fi
    [ "$(file_bytes "$flag_out")" -eq "$ERASEBLOCK_SIZE" ] || return 1
}

verify_current_flag_is_original() {
    current_flag="$WORKDIR/recovery_flag_eb.current.bin"
    read_current_flag_eraseblock "$current_flag" || fail_now current_flag_read_failed 2
    cmp -s "$current_flag" "$FLAG_ORIGINAL_FD" || fail_now current_flag_differs_from_backup 2
}

verify_current_flag_readable_for_restore() {
    current_flag="$WORKDIR/recovery_flag_eb.current.bin"
    read_current_flag_eraseblock "$current_flag" || fail_now current_flag_read_failed 2
}

record_operation() {
    op_name=$1
    printf '%s %s\n' "$(wc -l < "$OPERATION_LOG" 2>/dev/null || printf 0)" "$op_name" >> "$OPERATION_LOG"
    durable_sync
}

persist_state() {
    state_name=$1
    state_tmp="$STATE_FILE.tmp.$$"
    {
        printf 'schema=dcentos.s19k-stage1-state/v1\n'
        printf 'request_sha256=%s\n' "$REQUEST_SHA256"
        printf 'scope_id=%s\n' "$SCOPE_ID"
        printf 'mode=%s\n' "$MODE"
        printf 'state=%s\n' "$state_name"
        printf 'mutation_started=%s\n' "$MUTATION_STARTED"
        printf 'restore_required=%s\n' "$RESTORE_REQUIRED"
        printf 'last_completed_step=%s\n' "$LAST_COMPLETED_STEP"
    } > "$state_tmp"
    durable_sync
    mv -f "$state_tmp" "$STATE_FILE"
    durable_sync
}

full_revalidate() {
    capture_identity
    verify_mtd_geometry
    verify_source_and_safeoff
    verify_live_tools_and_tmp_capacity
    [ "$(sha256_file /proc/self/fd/3)" = "$ROOTFS_SHA256" ] || fail_now rootfs_fd_hash_drift 2
    [ "$(file_bytes /proc/self/fd/3)" -eq "$ROOTFS_BYTES" ] || fail_now rootfs_fd_size_drift 2
    verify_recovery_inputs
    if [ "$MODE" = restore ]; then
        verify_current_flag_readable_for_restore
    else
        verify_current_flag_is_original
    fi
}

cutpoint() {
    cut_name=$1
    if [ "$SIMULATION" = true ] && [ "${DCENT_S19K_STAGE1_TEST_CUTPOINT:-}" = "$cut_name" ]; then
        fail_now "test_cutpoint_$cut_name" 91
    fi
}

erase_rootfs_window() {
    if [ "$SIMULATION" = true ]; then
        : > "$TEST_ROOT/nand/rootfs-current.bin"
        FIXTURE_MUTATION_PERFORMED=true
    else
        # Mark the live primitive as invoked before it can partially mutate and
        # return nonzero.  The receipt must never mislabel such a failure as a
        # no-NAND-operation refusal.
        NAND_ERASE_PERFORMED=true
        flash_erase "$MTD5" "$ROOTFS_LOCAL_HEX" "$ROOTFS_ERASE_COUNT" >/dev/null 2>&1
    fi
}

write_rootfs() {
    if [ "$SIMULATION" = true ]; then
        cp /proc/self/fd/3 "$TEST_ROOT/nand/rootfs-current.bin"
        FIXTURE_MUTATION_PERFORMED=true
    else
        NAND_WRITE_PERFORMED=true
        nandwrite -p -s "$ROOTFS_LOCAL_HEX" "$MTD5" /proc/self/fd/3 >/dev/null 2>&1
    fi
}

readback_rootfs_fixture() {
    rb_file=$1
    [ "$SIMULATION" = true ] || return 1
    cp "$TEST_ROOT/nand/rootfs-current.bin" "$rb_file"
}

# Never materialize a second rootfs-sized file in the stock /tmp tmpfs.  Keep
# the nanddump producer and sha256 consumer as independently checked processes;
# a shell pipeline would mask a failed producer on BusyBox ash.
readback_rootfs_live_stream() {
    [ "$SIMULATION" != true ] || return 1
    ROOTFS_READBACK_MODE=named-fifo-sha256
    readback_fifo="$WORKDIR/rootfs.readback.fifo"
    readback_result="$WORKDIR/rootfs.readback.sha256"
    [ ! -e "$readback_fifo" ] && [ ! -L "$readback_fifo" ] || return 1
    [ ! -e "$readback_result" ] && [ ! -L "$readback_result" ] || return 1
    mkfifo "$readback_fifo" || return 1
    sha256sum < "$readback_fifo" > "$readback_result" &
    readback_consumer_pid=$!
    if nanddump --bb=skipbad --omitoob -q \
        -s "$ROOTFS_LOCAL_HEX" -l "$ROOTFS_BYTES" \
        -f "$readback_fifo" "$MTD5" >/dev/null 2>&1
    then
        readback_producer_rc=0
    else
        readback_producer_rc=$?
    fi
    # nanddump can fail before opening the FIFO (argument/device/tool error).
    # In that case the sha256sum child is still blocked in its FIFO open, so a
    # plain wait would hang forever.  Terminate and reap it before refusing.
    if [ "$readback_producer_rc" -ne 0 ]; then
        kill "$readback_consumer_pid" 2>/dev/null || true
        if wait "$readback_consumer_pid" 2>/dev/null; then
            readback_consumer_rc=0
        else
            readback_consumer_rc=$?
        fi
        rm -f "$readback_fifo" 2>/dev/null || true
        return 1
    fi
    if wait "$readback_consumer_pid"; then
        readback_consumer_rc=0
    else
        readback_consumer_rc=$?
    fi
    rm -f "$readback_fifo" 2>/dev/null || true
    [ "$readback_consumer_rc" -eq 0 ] || return 1
    [ -f "$readback_result" ] && [ ! -L "$readback_result" ] || return 1
    [ "$(wc -l < "$readback_result" | tr -d ' \t\r\n')" -eq 1 ] || return 1
    streamed_sha=$(awk 'NR == 1 { print $1 }' "$readback_result")
    is_sha256 "$streamed_sha" || return 1
    [ "$streamed_sha" = "$ROOTFS_SHA256" ] || return 1
    ROOTFS_READBACK_SHA256=$streamed_sha
    # nanddump returned success for exact -l ROOTFS_BYTES and the complete
    # stream matched the payload.  Only now may the receipt report full bytes.
    ROOTFS_READBACK_BYTES=$ROOTFS_BYTES
}

erase_flag_eraseblock() {
    if [ "$SIMULATION" = true ]; then
        : > "$TEST_ROOT/nand/flag-current.bin"
        FIXTURE_MUTATION_PERFORMED=true
    else
        NAND_ERASE_PERFORMED=true
        flash_erase "$MTD5" "$RECOVERY_FLAG_LOCAL_HEX" 1 >/dev/null 2>&1
    fi
}

write_flag_eraseblock() {
    flag_source=$1
    if [ "$SIMULATION" = true ]; then
        cp "$flag_source" "$TEST_ROOT/nand/flag-current.bin"
        FIXTURE_MUTATION_PERFORMED=true
    else
        NAND_WRITE_PERFORMED=true
        nandwrite -p -s "$RECOVERY_FLAG_LOCAL_HEX" "$MTD5" "$flag_source" >/dev/null 2>&1
    fi
}

: > "$OPERATION_LOG"
mkdir "$WORKDIR/.stage1-$MODE.lock" 2>/dev/null || fail_now stage1_lock_held 2
LOCK_HELD=true
LAST_COMPLETED_STEP=inputs_content_bound
record_operation preflight.inputs_content_bound
full_revalidate
LAST_COMPLETED_STEP=preflight_revalidated
record_operation preflight.identity_geometry_zero_badblocks_safeoff_flag_matched
persist_state preflight_verified_no_write

if [ "$MODE" = preflight ]; then
    finish preflight_verified_no_write 0 none
fi

if [ "$INTERNAL_CLEAR_FOR_FLASH" != true ] && [ "$SIMULATION" != true ]; then
    LAST_COMPLETED_STEP=preflight_revalidated
    finish refused_clear_for_flash_false 73 clear_for_flash_internal_false
fi

if [ "$MODE" = install ]; then
    POSTBOOT_PROOF_REQUIRED=true
    LAST_COMPLETED_STEP=pre_mutation_revalidated
    record_operation install.pre_mutation_revalidated
    persist_state pre_mutation_revalidated
    cutpoint before_rootfs_erase

    # Persist mutation intent before calling the first destructive primitive.
    MUTATION_STARTED=true
    RESTORE_REQUIRED=true
    LAST_COMPLETED_STEP=rootfs_erase_started
    persist_state rootfs_erase_started
    erase_rootfs_window || fail_now rootfs_erase_failed 74
    LAST_COMPLETED_STEP=rootfs_erased
    record_operation install.rootfs_erased
    persist_state rootfs_erased
    cutpoint after_rootfs_erase

    write_rootfs || fail_now rootfs_write_failed 75
    LAST_COMPLETED_STEP=rootfs_written
    record_operation install.rootfs_written_content_bound_fd
    persist_state rootfs_written
    cutpoint after_rootfs_write

    if [ "$SIMULATION" = true ]; then
        ROOTFS_READBACK_MODE=fixture-file
        ROOTFS_READBACK="$WORKDIR/rootfs.readback.bin"
        readback_rootfs_fixture "$ROOTFS_READBACK" || fail_now rootfs_readback_failed 76
        ROOTFS_READBACK_BYTES=$(file_bytes "$ROOTFS_READBACK")
        ROOTFS_READBACK_SHA256=$(sha256_file "$ROOTFS_READBACK")
        [ "$ROOTFS_READBACK_BYTES" -eq "$ROOTFS_BYTES" ] || fail_now rootfs_readback_size_mismatch 76
        [ "$ROOTFS_READBACK_SHA256" = "$ROOTFS_SHA256" ] || fail_now rootfs_readback_hash_mismatch 76
        cmp -s "$ROOTFS_READBACK" /proc/self/fd/3 || fail_now rootfs_readback_byte_mismatch 76
    else
        readback_rootfs_live_stream || fail_now rootfs_stream_readback_failed 76
    fi
    LAST_COMPLETED_STEP=rootfs_readback_verified
    record_operation install.rootfs_full_readback_verified
    persist_state rootfs_readback_verified
    cutpoint after_rootfs_readback

    # The commit candidate was uploaded and content-bound before rootfs erase.
    # Revalidate every live surface and prove the current full flag eraseblock
    # is still the separately captured original before the commit cutover.
    full_revalidate
    LAST_COMPLETED_STEP=pre_commit_revalidated
    record_operation install.pre_commit_all_surfaces_revalidated
    persist_state pre_commit_revalidated
    cutpoint before_flag_erase

    erase_flag_eraseblock || fail_now flag_erase_failed 77
    LAST_COMPLETED_STEP=flag_eraseblock_erased
    record_operation install.flag_eraseblock_erased_commit_last
    persist_state flag_eraseblock_erased
    cutpoint after_flag_erase

    write_flag_eraseblock "$FLAG_CANDIDATE_FD" || fail_now flag_candidate_write_failed 78
    LAST_COMPLETED_STEP=flag_candidate_written
    record_operation install.flag_full_eraseblock_candidate_written
    persist_state flag_candidate_written
    cutpoint after_flag_write

    FLAG_READBACK="$WORKDIR/recovery_flag_eb.readback.bin"
    read_current_flag_eraseblock "$FLAG_READBACK" || fail_now flag_readback_failed 79
    [ "$(sha256_file "$FLAG_READBACK")" = "$FLAG_CANDIDATE_SHA256" ] || fail_now flag_readback_hash_mismatch 79
    cmp -s "$FLAG_READBACK" "$FLAG_CANDIDATE_FD" || fail_now flag_readback_byte_mismatch 79
    FLAG_READBACK_VALUE=$(od -An -tu1 -N1 "$FLAG_READBACK" | tr -d ' \t\r\n')
    [ "$FLAG_READBACK_VALUE" -eq "$RECOVERY_FLAG_INSTALLED" ] || fail_now flag_readback_not_01 79
    cutpoint after_flag_readback

    INSTALL_COMMIT_VERIFIED=true
    RESTORE_REQUIRED=false
    LAST_COMPLETED_STEP=install_commit_full_readback_verified
    record_operation install.commit_0x01_full_eraseblock_readback_verified_no_reboot
    persist_state installed_commit_verified_no_reboot
    finish installed_commit_verified_no_reboot 0 none
fi

# Restore does not and cannot claim a cold boot.  It only restores the exact
# original full 0x02 flag eraseblock, arming U-Boot recover_to_stock for an
# externally witnessed reboot.  The rootfs and stock-recovery receipt remain
# content-bound in the request; full mtd5 replay is intentionally not attempted.
if [ "$MODE" = restore ]; then
    POSTBOOT_PROOF_REQUIRED=true
    LAST_COMPLETED_STEP=restore_pre_mutation_revalidated
    record_operation restore.pre_mutation_revalidated
    persist_state restore_pre_mutation_revalidated
    cutpoint before_restore_flag_erase

    MUTATION_STARTED=true
    RESTORE_REQUIRED=true
    LAST_COMPLETED_STEP=restore_flag_erase_started
    persist_state restore_flag_erase_started
    erase_flag_eraseblock || fail_now restore_flag_erase_failed 80
    LAST_COMPLETED_STEP=restore_flag_erased
    record_operation restore.flag_eraseblock_erased
    persist_state restore_flag_erased
    cutpoint after_restore_flag_erase

    write_flag_eraseblock "$FLAG_ORIGINAL_FD" || fail_now restore_flag_write_failed 81
    LAST_COMPLETED_STEP=restore_flag_written
    record_operation restore.original_full_eraseblock_written
    persist_state restore_flag_written
    cutpoint after_restore_flag_write

    RESTORE_READBACK="$WORKDIR/recovery_flag_eb.restore.readback.bin"
    read_current_flag_eraseblock "$RESTORE_READBACK" || fail_now restore_flag_readback_failed 82
    [ "$(sha256_file "$RESTORE_READBACK")" = "$FLAG_ORIGINAL_SHA256" ] || fail_now restore_flag_readback_hash_mismatch 82
    cmp -s "$RESTORE_READBACK" "$FLAG_ORIGINAL_FD" || fail_now restore_flag_readback_byte_mismatch 82
    FLAG_READBACK_VALUE=$(od -An -tu1 -N1 "$RESTORE_READBACK" | tr -d ' \t\r\n')
    [ "$FLAG_READBACK_VALUE" -eq "$RECOVERY_FLAG_STOCK" ] || fail_now restore_flag_readback_not_02 82
    STOCK_RECOVERY_ARMED=true
    RESTORE_REQUIRED=false
    LAST_COMPLETED_STEP=stock_recovery_0x02_full_readback_armed
    record_operation restore.stock_recovery_0x02_full_eraseblock_readback_armed_no_reboot
    persist_state stock_recovery_armed_no_reboot
    finish stock_recovery_armed_no_reboot 0 none
fi

fail_now mode_dispatch_unreachable 2
