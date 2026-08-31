#!/bin/sh
# Supervised, content-bound S19k /tmp Track-1 runner.
# This lane never writes persistent identity/state.  The TOML selects policy,
# while fresh process-independent Braiins/SoC/MTD/EEPROM evidence admits the
# physical S19k target.  Every receipt lives below the admitted /tmp dir.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

MODE=${1:-run}
TRIAL_DIR=${2:?trial_dir}
BOARD_TARGET=${3:-am3-s19k}
DEPLOY_MODE=${4:-}
BIN_SHA=${5:-}
BIN_BYTES=${6:-}
CFG_SHA=${7:-}
CFG_BYTES=${8:-}
RUNNER_SHA=${9:-}
RUNNER_BYTES=${10:-}
CUSTODY_SHA=${11:-}
CUSTODY_BYTES=${12:-}
STOCK_RESTART_HELPER_SHA=${13:-}
STOCK_RESTART_HELPER_BYTES=${14:-}
ENDURANCE_SEQUENCE=${15:-}
ENDURANCE_SEGMENT_SHA=${16:-}
ENDURANCE_SEGMENT_BYTES=${17:-}
ENDURANCE_PREDECESSOR_MANIFEST_SHA=${18:-}
ENDURANCE_MANIFEST_SHA=${19:-}
ENDURANCE_MANIFEST_BYTES=${20:-}
ENDURANCE_COLLECTOR_WALL_MS=${21:-}

PREFIX=/tmp/dcentrald_bench_t1_
WRAPPER_SCAN_PREFIX=$PREFIX
case "$TRIAL_DIR" in
    "$PREFIX"*) ;;
    *) echo "ERROR: trial_dir is outside the S19k /tmp namespace" >&2; exit 2 ;;
esac
SUFFIX=${TRIAL_DIR#"$PREFIX"}
case "$SUFFIX" in
    ''|*[!A-Za-z0-9._-]*|*/*)
        echo "ERROR: trial_dir must be one direct /tmp child with a safe suffix" >&2
        exit 2
        ;;
esac
[ "$TRIAL_DIR" = "$PREFIX$SUFFIX" ] && [ -d "$TRIAL_DIR" ] && [ ! -L "$TRIAL_DIR" ] || {
    echo "ERROR: trial_dir must be the exact real non-symlink direct child" >&2
    exit 2
}
TRIAL_LS=$(ls -ldn "$TRIAL_DIR" 2>/dev/null || true)
set -- $TRIAL_LS
[ "${1:-}" = drwx------ ] && [ "${3:-}" = 0 ] && [ "${4:-}" = 0 ] || {
    echo "ERROR: trial_dir must be a root-owned mode-0700 private directory" >&2
    exit 2
}
case "$BOARD_TARGET" in
    am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
    *) echo "ERROR: invalid S19k board_target" >&2; exit 2 ;;
esac

ACTIVE="$TRIAL_DIR/runtime_active"
STOCK_RETAINED_RECEIPT="$TRIAL_DIR/runtime_stock_owner_retained_closed"
TERMINAL_HANDOFF_RECEIPT="$TRIAL_DIR/runtime_terminal_safeoff"
PRE_SAFEOFF_ACTIVE="$TRIAL_DIR/runtime_active_pre_safeoff"
SAFEOFF_TERMINAL_RECEIPT="$TRIAL_DIR/runtime_safeoff_terminal_receipt"
NO_WORK_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_handoff_no_work_transcript"
INSTALL_CUSTODY_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_install_custody_transcript"
BOUNDED_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_bounded_work_transcript"
ENDURANCE_EVIDENCE_DIR="$TRIAL_DIR/endurance_evidence"
ENDURANCE_SEGMENT_DIR="$ENDURANCE_EVIDENCE_DIR/segments"
ENDURANCE_ACK_DIR="$ENDURANCE_EVIDENCE_DIR/acks"
ENDURANCE_DAEMON_TERMINAL="$ENDURANCE_EVIDENCE_DIR/daemon_terminal"
ENDURANCE_DAEMON_FAILURE="$ENDURANCE_EVIDENCE_DIR/daemon_failure"
ENDURANCE_FAILURE_RECEIPT="$TRIAL_DIR/runtime_endurance_failure_receipt"
STARTUP_J1="$TRIAL_DIR/runtime_startup_j1_daemon_blocked"
STARTUP_C1="$TRIAL_DIR/runtime_startup_c1_child_identity"
STARTUP_J2="$TRIAL_DIR/runtime_startup_j2_child_bound"
STARTUP_RELEASE="$TRIAL_DIR/runtime_startup_release"
STARTUP_PARENT_LOST="$TRIAL_DIR/runtime_startup_parent_lost"
STARTUP_RETIRE_TERMINAL="$TRIAL_DIR/runtime_startup_retired_terminal"
STARTUP_RETIRE_CLEANUP="$TRIAL_DIR/runtime_startup_retire_cleanup_commit"
STARTUP_PRESAFEOFF_SOURCE="$TRIAL_DIR/runtime_startup_prefix_pre_safeoff"
STARTUP_PRESAFEOFF_OWNER="$TRIAL_DIR/runtime_startup_owner_pre_safeoff"
STARTUP_PRESAFEOFF_ACTIVE="$TRIAL_DIR/runtime_startup_active_pre_safeoff"
STARTUP_RETIRE_CLEANUP_SOURCE=
STARTUP_FIFO=
STARTUP_J0_KEYS_SHA=ba209c68990f2906b0ede8f8ae8431e49ebc3dc7d5de9d8bbcf34b54fb95a8a4
STARTUP_C1_KEYS_SHA=56d18f3d5068a6b439da72c223b475897b558a3656657203b27929515582d0de
STARTUP_J1_J2_KEYS_SHA=0049174bcef8d732bc954251f24b8d47982491f820f9f225ee772ce38e6a4855
STARTUP_RELEASE_KEYS_SHA=5f24aa1f2dea5a6014860b0b2c1c7d6cc0c03132f1fa8ca6c463c8f69ba6d014
STARTUP_PARENT_LOST_KEYS_SHA=0c82824108262e2638d7c26833b431f1c4aeec9618627bde84c6170935f5f11c
STARTUP_RETIRE_TERMINAL_KEYS_SHA=858ed6920b9935628e58c2151ba9568ac2712892cf009a172ed513ed634d6eec
STARTUP_RETIRE_CLEANUP_KEYS_SHA=376809731ee2566a8dad80682b970b184e398ffc0965a0b2da8428e7ffa616d2
STARTUP_PRESAFEOFF_SOURCE_KEYS_SHA=b8d678f5f2c4396aa030b52027e84af511ff1cea489273013e700a102ba621df
STARTUP_PREFIX_PENDING_KEYS_SHA=381a0fc71b6f93eddee56017abee98cce1c937698da677af40c2ce976be4bea2
STARTUP_PREFIX_OWNER_KEYS_SHA=aa69f14cef4035b77ea7b13513bb6a221e6d8bcfb12c67bddcc8765fceeb910d
RETIRED_ACTIVE="$TRIAL_DIR/runtime_active.retired.stock-owner-retained"
RETIRED_OWNER="$TRIAL_DIR/runtime_lock_owner.retired.stock-owner-retained"
STARTUP_RETIRED_ACTIVE="$TRIAL_DIR/runtime_active.retired.startup-no-effect"
STARTUP_RETIRED_OWNER="$TRIAL_DIR/runtime_lock_owner.retired.startup-no-effect"
RUNTIME_LOCK=/tmp/dcent-s19k-track1-runtime-lock
RUNTIME_LOCK_OWNER="$RUNTIME_LOCK/owner"
TRIAL_BIN="$TRIAL_DIR/dcentrald"
TRIAL_CFG="$TRIAL_DIR/dcentrald_s19k.toml"
TRIAL_RUNNER="$TRIAL_DIR/run_trial"
TRIAL_CUSTODY="$TRIAL_DIR/supervisor_custody_observer"
TRIAL_STOCK_RESTART_HELPER="$TRIAL_DIR/stock_restart_helper"
LIVE_CPUINFO=/proc/cpuinfo
LIVE_UNAME=uname
LIVE_PROC_MTD=/proc/mtd
LIVE_BOS_PLATFORM=/etc/bos_platform
LIVE_BOS_MODE=/etc/bos_mode
LIVE_BOSMINER_MODEL=/etc/bosminer_model.json
LIVE_I2CGET=/usr/sbin/i2cget
CHILD_PID=0
CHILD_START=0
SELF_START=0
SUPERVISOR_PID=0
SUPERVISOR_START=0
SUPERVISOR_PPID=0
SUPERVISOR_PGRP=0
SUPERVISOR_SESSION=0
SUPERVISOR_EXE=
SUPERVISOR_CMDLINE_SHA=
SUPERVISOR_CMDLINE_BYTES=0
BOSMINER_PID=0
BOSMINER_START=0
BOSMINER_PPID=0
BOSMINER_PGRP=0
BOSMINER_SESSION=0
BOSMINER_EXE=
BOSMINER_CMDLINE_SHA=
BOSMINER_CMDLINE_BYTES=0
STOCK_PIDFILE_PATH=
STOCK_PIDFILE_SHA=
STOCK_PIDFILE_BYTES=0
BOUND_STOCK_PIDFILE_PATH=
BOUND_STOCK_PIDFILE_SHA=
BOUND_STOCK_PIDFILE_BYTES=0
LIVE_IDENTITY_SHA=
LIVE_IDENTITY_MODEL_SHA=
LIVE_IDENTITY_PROFILE=
LIVE_IDENTITY_BOARD_NAMES=
LIVE_IDENTITY_PHYSICAL_ADDRESSES=
LIVE_IDENTITY_EEPROM_SLOTS=
EXPECTED_LIVE_IDENTITY_SHA=
EXPECTED_LIVE_IDENTITY_PROFILE=

is_regular_nonsymlink() {
    [ -f "$1" ] && [ ! -L "$1" ]
}

runtime_lock_container_is_exact() {
    [ -d "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ] || return 1
    LOCK_LS=$(ls -ldn "$RUNTIME_LOCK" 2>/dev/null || true)
    set -- $LOCK_LS
    [ "${1:-}" = drwx------ ] \
        && [ "${3:-}" = 0 ] \
        && [ "${4:-}" = 0 ]
}

no_published_runtime_or_startup_evidence_exists() {
    for EVIDENCE_PATH in \
        "$ACTIVE" "$STOCK_RETAINED_RECEIPT" "$TERMINAL_HANDOFF_RECEIPT" \
        "$PRE_SAFEOFF_ACTIVE" "$SAFEOFF_TERMINAL_RECEIPT" \
        "$NO_WORK_TRANSCRIPT_RECEIPT" "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" "$BOUNDED_TRANSCRIPT_RECEIPT" \
        "$STARTUP_C1" "$STARTUP_J1" "$STARTUP_J2" "$STARTUP_RELEASE" \
        "$STARTUP_PARENT_LOST" "$STARTUP_RETIRE_TERMINAL" "$STARTUP_RETIRE_CLEANUP" \
        "$STARTUP_PRESAFEOFF_SOURCE" "$STARTUP_PRESAFEOFF_OWNER" "$STARTUP_PRESAFEOFF_ACTIVE" \
        "$STARTUP_RETIRE_CLEANUP_SOURCE" \
        "$RETIRED_ACTIVE" "$RETIRED_OWNER" \
        "$STARTUP_RETIRED_ACTIVE" "$STARTUP_RETIRED_OWNER"; do
        [ ! -e "$EVIDENCE_PATH" ] && [ ! -L "$EVIDENCE_PATH" ] || return 1
    done
}

# Admit only the complete, known preparation namespace from a wrapper lifetime
# that is now terminal.  The returned list contains literal direct-child paths;
# callers never pass the discovery globs to rm(1).
classify_exact_pre_j0_residues() {
    PRE_J0_RESIDUE_LIST=
    PRE_J0_RESIDUE_COUNT=0
    PRE_J0_RESIDUE_MANIFEST=
    for PRE_J0_RESIDUE in \
        "$TRIAL_DIR"/.startup_* \
        "$TRIAL_DIR"/.runtime_* \
        "$TRIAL_DIR"/.all_task_effect_snapshot.*; do
        [ -e "$PRE_J0_RESIDUE" ] || [ -L "$PRE_J0_RESIDUE" ] || continue
        if [ -n "${PRE_J0_EXCLUDED_PATHS:-}" ]; then
            PRE_J0_IS_EXCLUDED=false
            OLD_IFS=$IFS
            IFS='
'
            for PRE_J0_EXCLUDED in $PRE_J0_EXCLUDED_PATHS; do
                [ "$PRE_J0_RESIDUE" = "$PRE_J0_EXCLUDED" ] && PRE_J0_IS_EXCLUDED=true
            done
            IFS=$OLD_IFS
            [ "$PRE_J0_IS_EXCLUDED" = false ] || continue
        fi
        [ "${PRE_J0_RESIDUE%/*}" = "$TRIAL_DIR" ] || return 1
        PRE_J0_BASE=${PRE_J0_RESIDUE##*/}
        PRE_J0_KIND=
        PRE_J0_PID=
        PRE_J0_START=
        case "$PRE_J0_BASE" in
            .startup_fifo.*)
                PRE_J0_KIND=fifo
                PRE_J0_SUFFIX=${PRE_J0_BASE#.startup_fifo.}
                PRE_J0_PID=${PRE_J0_SUFFIX%%.*}
                PRE_J0_START=${PRE_J0_SUFFIX#*.}
                [ "$PRE_J0_START" != "$PRE_J0_SUFFIX" ] \
                    && [ "${PRE_J0_START#*.}" = "$PRE_J0_START" ] || return 1
                ;;
            .startup_daemon_argv.*|.startup_daemon_env.*|.startup_daemon_transcript.*)
                PRE_J0_KIND=regular
                case "$PRE_J0_BASE" in
                    .startup_daemon_argv.*) PRE_J0_SUFFIX=${PRE_J0_BASE#.startup_daemon_argv.} ;;
                    .startup_daemon_env.*) PRE_J0_SUFFIX=${PRE_J0_BASE#.startup_daemon_env.} ;;
                    .startup_daemon_transcript.*) PRE_J0_SUFFIX=${PRE_J0_BASE#.startup_daemon_transcript.} ;;
                esac
                PRE_J0_PID=${PRE_J0_SUFFIX%%.*}
                PRE_J0_START=${PRE_J0_SUFFIX#*.}
                [ "$PRE_J0_START" != "$PRE_J0_SUFFIX" ] \
                    && [ "${PRE_J0_START#*.}" = "$PRE_J0_START" ] || return 1
                ;;
            .runtime_startup_retire_cleanup_commit.source.*)
                PRE_J0_KIND=regular
                PRE_J0_SUFFIX=${PRE_J0_BASE#.runtime_startup_retire_cleanup_commit.source.}
                PRE_J0_PID=${PRE_J0_SUFFIX%%.*}
                PRE_J0_START=${PRE_J0_SUFFIX#*.}
                [ "$PRE_J0_START" != "$PRE_J0_SUFFIX" ] \
                    && [ "${PRE_J0_START#*.}" = "$PRE_J0_START" ] || return 1
                ;;
            .runtime_*.tmp.*|.runtime_*.claim.*|.runtime_*.completed.*)
                PRE_J0_KIND=regular
                case "$PRE_J0_BASE" in
                    .runtime_*.tmp.*) PRE_J0_SUFFIX=${PRE_J0_BASE##*.tmp.} ;;
                    .runtime_*.claim.*) PRE_J0_SUFFIX=${PRE_J0_BASE##*.claim.} ;;
                    .runtime_*.completed.*) PRE_J0_SUFFIX=${PRE_J0_BASE##*.completed.} ;;
                esac
                PRE_J0_PID=${PRE_J0_SUFFIX%%.*}
                PRE_J0_START=${PRE_J0_SUFFIX#*.}
                [ "$PRE_J0_START" != "$PRE_J0_SUFFIX" ] \
                    && [ "${PRE_J0_START#*.}" = "$PRE_J0_START" ] || return 1
                case "$PRE_J0_BASE" in
                    .runtime_active.tmp.*|.runtime_lock_owner.tmp.*|\
                    .runtime_owner_recovery.tmp.*|\
                    .runtime_owner_stock_restart_pending.tmp.*|\
                    .runtime_owner_stock_restart_pending_resume.tmp.*|\
                    .runtime_owner_receiptless_stock_restart_pending.tmp.*|\
                    .runtime_owner_receiptless_stock_restart_pending_resume.tmp.*|\
                    .runtime_safeoff_terminal_receipt.tmp.*|\
                    .runtime_safeoff_terminal_receipt_receiptless.tmp.*|\
                    .runtime_safeoff_terminal_receipt_startup_prefix.tmp.*|\
                    .runtime_handoff_no_work_transcript.tmp.*|\
                    .runtime_bounded_work_transcript.tmp.*|\
                    .runtime_active_stock_restart_pending.tmp.*|\
                    .runtime_active_receiptless_stock_restart_pending.tmp.*|\
                    .runtime_active_startup_prefix_stock_restart_pending.tmp.*|\
                    .runtime_owner_startup_prefix_stock_restart_pending.tmp.*|\
                    .runtime_owner_startup_prefix_stock_restart_pending_resume.tmp.*|\
                    .runtime_startup_prefix_pre_safeoff.tmp.*|\
                    .runtime_startup_prefix_pre_safeoff.claim.*|\
                    .runtime_safeoff_terminal_receipt.claim.*|\
                    .runtime_safeoff_terminal_receipt_receiptless.claim.*|\
                    .runtime_safeoff_terminal_receipt_startup_prefix.claim.*|\
                    .runtime_startup_prefix_pre_safeoff.completed.*|\
                    .runtime_safeoff_terminal_receipt.completed.*|\
                    .runtime_safeoff_terminal_receipt_receiptless.completed.*|\
                    .runtime_safeoff_terminal_receipt_startup_prefix.completed.*|\
                    .runtime_startup_tx.tmp.*|.runtime_startup_j0.tmp.*|\
                    .runtime_startup_c1.tmp.*|.runtime_startup_j1.tmp.*|\
                    .runtime_startup_j2.tmp.*|.runtime_startup_release.tmp.*|\
                    .runtime_startup_parent_lost.tmp.*|.runtime_startup_parent_lost_j0.tmp.*|\
                    .runtime_startup_retired_terminal.tmp.*|\
                    .runtime_stock_owner_retained_early.tmp.*|\
                    .runtime_stock_owner_retained_prewatchdog.tmp.*|\
                    .runtime_stock_owner_retained_closed.tmp.*|\
                    .runtime_terminal_safeoff.tmp.*) ;;
                    *) return 1 ;;
                esac
                ;;
            .all_task_effect_snapshot.*)
                PRE_J0_KIND=regular
                PRE_J0_SUFFIX=${PRE_J0_BASE#.all_task_effect_snapshot.}
                OLD_IFS=$IFS
                IFS=.
                set -- $PRE_J0_SUFFIX
                IFS=$OLD_IFS
                [ "$#" -eq 4 ] || return 1
                PRE_J0_PID=$1
                PRE_J0_START=$2
                valid_uint "$3" && [ "$3" -lt 3 ] || return 1
                case "$4" in one|two) ;; *) return 1 ;; esac
                ;;
            *) return 1 ;;
        esac
        valid_pid_start "$PRE_J0_PID" "$PRE_J0_START" \
            && ! process_matches "$PRE_J0_PID" "$PRE_J0_START" || return 1
        PRE_J0_LS=$(ls -ldn "$PRE_J0_RESIDUE" 2>/dev/null || true)
        set -- $PRE_J0_LS
        [ "${3:-}" = 0 ] && [ "${4:-}" = 0 ] || return 1
        case "$PRE_J0_KIND:${1:-}" in
            fifo:prw-------) [ -p "$PRE_J0_RESIDUE" ] && [ ! -L "$PRE_J0_RESIDUE" ] || return 1 ;;
            regular:-rw-------) is_regular_nonsymlink "$PRE_J0_RESIDUE" || return 1 ;;
            *) return 1 ;;
        esac
        PRE_J0_RESIDUE_LIST=${PRE_J0_RESIDUE_LIST}${PRE_J0_RESIDUE_LIST:+"
"}$PRE_J0_RESIDUE
        if [ "$PRE_J0_KIND" = fifo ]; then
            PRE_J0_ITEM_SHA=none
            PRE_J0_ITEM_BYTES=0
        else
            PRE_J0_ITEM_SHA=$(sha256sum "$PRE_J0_RESIDUE" | awk '{print $1}')
            PRE_J0_ITEM_BYTES=$(wc -c < "$PRE_J0_RESIDUE" | tr -d ' \t\r\n')
            valid_sha256 "$PRE_J0_ITEM_SHA" && valid_uint "$PRE_J0_ITEM_BYTES" || return 1
        fi
        PRE_J0_MANIFEST_LINE="$PRE_J0_BASE|$PRE_J0_KIND|$PRE_J0_PID|$PRE_J0_START|$PRE_J0_ITEM_SHA|$PRE_J0_ITEM_BYTES"
        PRE_J0_RESIDUE_MANIFEST=${PRE_J0_RESIDUE_MANIFEST}${PRE_J0_RESIDUE_MANIFEST:+"
"}$PRE_J0_MANIFEST_LINE
        PRE_J0_RESIDUE_COUNT=$((PRE_J0_RESIDUE_COUNT + 1))
    done
    if [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ]; then
        PRE_J0_RESIDUE_MANIFEST_SHA=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    else
        PRE_J0_RESIDUE_MANIFEST_SHA=$(printf '%s\n' "$PRE_J0_RESIDUE_MANIFEST" | sha256sum | awk '{print $1}')
        valid_sha256 "$PRE_J0_RESIDUE_MANIFEST_SHA" || return 1
    fi
}

remove_classified_pre_j0_residues() {
    EXPECTED_RESIDUE_LIST=$PRE_J0_RESIDUE_LIST
    EXPECTED_RESIDUE_COUNT=$PRE_J0_RESIDUE_COUNT
    EXPECTED_RESIDUE_MANIFEST=$PRE_J0_RESIDUE_MANIFEST
    EXPECTED_RESIDUE_MANIFEST_SHA=$PRE_J0_RESIDUE_MANIFEST_SHA
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_LIST" = "$EXPECTED_RESIDUE_LIST" ] \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq "$EXPECTED_RESIDUE_COUNT" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST" = "$EXPECTED_RESIDUE_MANIFEST" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST_SHA" = "$EXPECTED_RESIDUE_MANIFEST_SHA" ] || return 1
    OLD_IFS=$IFS
    IFS='
'
    for PRE_J0_LITERAL in $PRE_J0_RESIDUE_LIST; do
        [ -n "$PRE_J0_LITERAL" ] || continue
        rm -f "$PRE_J0_LITERAL" || { IFS=$OLD_IFS; return 1; }
        [ ! -e "$PRE_J0_LITERAL" ] && [ ! -L "$PRE_J0_LITERAL" ] \
            || { IFS=$OLD_IFS; return 1; }
    done
    IFS=$OLD_IFS
}

valid_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
}

valid_live_identity_profile() {
    case "$1" in
        live88_two_bhb56903_slots_2_3|held78_three_bhb56902_slots_1_2_3|\
        bhb56902-only:partial-logical-uarts-populated|\
        bhb56903-only:partial-logical-uarts-populated|\
        mixed-bhb56902-bhb56903:partial-logical-uarts-populated|\
        bhb56902-only:all-three-uarts-populated|\
        bhb56903-only:all-three-uarts-populated|\
        mixed-bhb56902-bhb56903:all-three-uarts-populated) return 0 ;;
        *) return 1 ;;
    esac
}

valid_size() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -gt 0 ]
}

valid_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
}

valid_trial_dir_value() {
    case "$1" in
        "$PREFIX"*) ;;
        *) return 1 ;;
    esac
    LOCK_TRIAL_SUFFIX=${1#"$PREFIX"}
    case "$LOCK_TRIAL_SUFFIX" in ''|*[!A-Za-z0-9._-]*|*/*) return 1 ;; esac
}

valid_pid_start() {
    case "$1" in ''|0|*[!0-9]*) return 1 ;; esac
    case "$2" in ''|0|*[!0-9]*) return 1 ;; esac
}

verify_bound_file() {
    PATHNAME=$1
    EXPECTED_SHA=$2
    EXPECTED_BYTES=$3
    LABEL=$4
    is_regular_nonsymlink "$PATHNAME" || {
        echo "ERROR: $LABEL is not a regular non-symlink file" >&2
        return 1
    }
    valid_sha256 "$EXPECTED_SHA" && valid_size "$EXPECTED_BYTES" || {
        echo "ERROR: $LABEL expected digest/size is malformed" >&2
        return 1
    }
    ACTUAL_SHA=$(sha256sum "$PATHNAME" 2>/dev/null | awk '{print $1}') || return 1
    ACTUAL_BYTES=$(wc -c < "$PATHNAME" | tr -d ' \t\r\n') || return 1
    [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] && [ "$ACTUAL_BYTES" = "$EXPECTED_BYTES" ] || {
        echo "ERROR: $LABEL changed after deploy (sha/bytes mismatch)" >&2
        return 1
    }
}

verify_all_bound_files() {
    verify_bound_file "$TRIAL_BIN" "$BIN_SHA" "$BIN_BYTES" dcentrald
    verify_bound_file "$TRIAL_CFG" "$CFG_SHA" "$CFG_BYTES" config
    verify_bound_file "$TRIAL_RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" runner
    verify_bound_file "$TRIAL_CUSTODY" "$CUSTODY_SHA" "$CUSTODY_BYTES" supervisor-custody-observer
    verify_bound_file "$TRIAL_STOCK_RESTART_HELPER" "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES" stock-restart-helper
}

# IMPLEMENTED_EXPERIMENTAL: classify an exact non-empty 902/903 population
# across the three controller-facing logical addresses.  The two historical
# .78/.88 labels remain stable compatibility names for their exact populations.
# This deliberately does not trust
# the staged TOML or a DCENT-managed identity marker.  The BOS model file is
# boot-generated from EEPROM but remains mutable, so its complete digest is
# continuity evidence, not immutable attestation.  A profile is selected only
# when its board count, exact SKU, physical addresses, and all three direct
# read-only EEPROM presence/preamble observations agree; fields are never
# admitted independently as a broad union.
capture_exact_live_s19k_identity() {
    [ "$($LIVE_UNAME -m 2>/dev/null || true)" = aarch64 ] || {
        echo "ERROR: live identity is not the held aarch64 AM3 control plane" >&2
        return 1
    }
    is_regular_nonsymlink "$LIVE_CPUINFO" || {
        echo "ERROR: live /proc/cpuinfo identity source is unavailable" >&2
        return 1
    }
    CPU_TUPLE=$(awk -F: '
        /^[[:space:]]*processor[[:space:]]*:/ { processors++ }
        /^[[:space:]]*CPU implementer[[:space:]]*:/ {
            value=$2; gsub(/[[:space:]]/, "", value)
            implementers++; if (value != "0x41") bad=1
        }
        /^[[:space:]]*CPU architecture[[:space:]]*:/ {
            value=$2; gsub(/[[:space:]]/, "", value)
            architectures++; if (value != "8") bad=1
        }
        /^[[:space:]]*CPU part[[:space:]]*:/ {
            value=$2; gsub(/[[:space:]]/, "", value)
            parts++; if (value != "0xd03") bad=1
        }
        /^[[:space:]]*Hardware[[:space:]]*:/ {
            value=$2; sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value)
            hardware++; if (value != "Amlogic") bad=1
        }
        END {
            if (!bad && processors == 4 && implementers == 4 && architectures == 4 && parts == 4 && hardware == 1)
                print "Amlogic:aarch64:4x0x41:arch8:part0xd03"
            else
                exit 1
        }
    ' "$LIVE_CPUINFO") || {
        echo "ERROR: live CPU tuple is not the held four-core Amlogic A113D tuple" >&2
        return 1
    }

    is_regular_nonsymlink "$LIVE_BOS_PLATFORM" \
        && [ "$(cat "$LIVE_BOS_PLATFORM" 2>/dev/null || true)" = am3-aml ] || {
        echo "ERROR: live Braiins platform is not exact am3-aml" >&2
        return 1
    }
    is_regular_nonsymlink "$LIVE_BOS_MODE" \
        && [ "$(cat "$LIVE_BOS_MODE" 2>/dev/null || true)" = nand ] || {
        echo "ERROR: live Braiins mode is not exact nand" >&2
        return 1
    }

    is_regular_nonsymlink "$LIVE_PROC_MTD" || {
        echo "ERROR: live /proc/mtd identity source is unavailable" >&2
        return 1
    }
    MTD_MAP=$(awk '
        BEGIN {
            count=0
            expected_size[0]="00200000"; expected_size[1]="00800000"; expected_size[2]="03200000"
            expected_size[3]="00500000"; expected_size[4]="02000000"; expected_size[5]="09900000"
            expected_name[0]="bootloader"; expected_name[1]="tpl"; expected_name[2]="stock_system"
            expected_name[3]="stock_config"; expected_name[4]="overlay"; expected_name[5]="system"
        }
        NR == 1 {
            if (NF != 4 || $1 != "dev:" || $2 != "size" || $3 != "erasesize" || $4 != "name") exit 1
            next
        }
        {
            if (NF != 4 || count >= 6) exit 1
            name=$4; gsub(/^"|"$/, "", name)
            expected_dev[count] = "mtd" count ":"
            if ($1 != expected_dev[count] || $2 != expected_size[count] || $3 != "00020000" || name != expected_name[count]) exit 1
            printf "%s %s %s %s\n", $1, $2, $3, name
            count++
        }
        END { if (count != 6) exit 1 }
    ' "$LIVE_PROC_MTD") || {
        echo "ERROR: live MTD map is not the exact held six-row Braiins AM3 layout" >&2
        return 1
    }

    is_regular_nonsymlink "$LIVE_BOSMINER_MODEL" || {
        echo "ERROR: boot-detected Braiins model descriptor is unavailable or unsafe" >&2
        return 1
    }
    LIVE_IDENTITY_MODEL_SHA=$(sha256sum "$LIVE_BOSMINER_MODEL" 2>/dev/null | awk '{print $1}') || return 1
    valid_sha256 "$LIVE_IDENTITY_MODEL_SHA" || return 1
    JSON_FIELDS=$(tr ',' '\n' < "$LIVE_BOSMINER_MODEL") || return 1
    MODEL_VALUES=$(printf '%s\n' "$JSON_FIELDS" | sed -n 's/^.*"model"[[:space:]]*:[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p')
    VENDOR_VALUES=$(printf '%s\n' "$JSON_FIELDS" | sed -n 's/^.*"vendor_name"[[:space:]]*:[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p')
    MODEL_KEY_COUNT=$(awk '{ key="\"model\""; line=$0; while ((at=index(line, key)) != 0) { count++; line=substr(line, at+length(key)) } } END { print count+0 }' "$LIVE_BOSMINER_MODEL")
    VENDOR_KEY_COUNT=$(awk '{ key="\"vendor_name\""; line=$0; while ((at=index(line, key)) != 0) { count++; line=substr(line, at+length(key)) } } END { print count+0 }' "$LIVE_BOSMINER_MODEL")
    [ "$MODEL_VALUES" = "Antminer S19K Pro NoPic" ] \
        && [ "$VENDOR_VALUES" = "Antminer S19k Pro" ] \
        && [ "$MODEL_KEY_COUNT" -eq 1 ] && [ "$VENDOR_KEY_COUNT" -eq 1 ] || {
        echo "ERROR: Braiins boot-detected model is not exact S19K Pro NoPic" >&2
        return 1
    }

    # Parse the hashboard array as objects rather than independent field bags.
    # The live `.88` descriptor has three objects: addr1 is the exact
    # undetected placeholder, while addr2/3 carry BHB56903 + serial_number.
    # Aggregating keys would incorrectly admit a descriptor that moved the
    # placeholder to addr3 and a populated board to addr1.
    HASHBOARD_ROWS=$(awk '
        function string_value(line, value) {
            value=line
            sub(/^.*:[[:space:]]*"/, "", value)
            sub(/"[[:space:]]*,?[[:space:]]*$/, "", value)
            if (value == line || value ~ /[\\"]/) exit 1
            return value
        }
        function scalar_value(line, value) {
            value=line
            sub(/^.*:[[:space:]]*/, "", value)
            sub(/[[:space:]]*,?[[:space:]]*$/, "", value)
            if (value == line) exit 1
            return value
        }
        /^[[:space:]]*"hashboards"[[:space:]]*:[[:space:]]*\[[[:space:]]*$/ {
            if (seen_array++) exit 1
            in_array=1
            next
        }
        in_array && /^[[:space:]]*\][[:space:]]*,?[[:space:]]*$/ {
            if (in_object) exit 1
            in_array=0
            completed=1
            next
        }
        in_array && /^[[:space:]]*\{[[:space:]]*$/ {
            if (in_object) exit 1
            in_object=1
            address=""; board=""; serial=0; note=""; hashrate=0
            next
        }
        in_array && /^[[:space:]]*\}[[:space:]]*,?[[:space:]]*$/ {
            if (!in_object || address == "" || hashrate != 1) exit 1
            if (address !~ /^[123]$/ || seen_address[address]++) exit 1
            rows[address]=sprintf("%s|%s|%d|%s", address, board, serial, note)
            in_object=0
            objects++
            next
        }
        in_array && in_object {
            if ($0 ~ /^[[:space:]]*"physical_address"[[:space:]]*:/) {
                if (address != "") exit 1
                address=scalar_value($0)
                if (address !~ /^[0-9]+$/) exit 1
            } else if ($0 ~ /^[[:space:]]*"hashrate_ths"[[:space:]]*:/) {
                if (hashrate++) exit 1
                if (scalar_value($0) != "46.12146") exit 1
            } else if ($0 ~ /^[[:space:]]*"serial_number"[[:space:]]*:/) {
                if (serial || string_value($0) == "") exit 1
                serial=1
            } else if ($0 ~ /^[[:space:]]*"board_name"[[:space:]]*:/) {
                if (board != "") exit 1
                board=string_value($0)
            } else if ($0 ~ /^[[:space:]]*"note"[[:space:]]*:/) {
                if (note != "") exit 1
                note=string_value($0)
            } else if ($0 !~ /^[[:space:]]*$/) {
                exit 1
            }
            next
        }
        END {
            if (in_array || in_object || !completed || seen_array != 1 || objects != 3) exit 1
            for (address=1; address<=3; address++) {
                if (!(address in rows)) exit 1
                print rows[address]
            }
        }
    ' "$LIVE_BOSMINER_MODEL") || {
        echo "ERROR: Braiins hashboard objects are not the exact held descriptor shape" >&2
        return 1
    }
    LIVE88_HASHBOARD_ROWS=$(printf '%s\n' \
        '1||0|HB not detected. Board name unknown. hashrate_ths is calculated.' \
        '2|BHB56903|1|' \
        '3|BHB56903|1|')
    HELD78_HASHBOARD_ROWS=$(printf '%s\n' \
        '1|BHB56902|1|' \
        '2|BHB56902|1|' \
        '3|BHB56902|1|')

    PROFILE_SUMMARY=$(printf '%s\n' "$HASHBOARD_ROWS" | awk -F '|' '
        BEGIN {
            absent_note="HB not detected. Board name unknown. hashrate_ths is calculated."
        }
        NF != 4 { invalid=1; next }
        {
            address=$1+0
            board=$2
            serial_present=$3
            note=$4
            if (address != NR || address < 1 || address > 3) {
                invalid=1
                next
            }
            if (board == "") {
                if (serial_present != "0" || note != absent_note) invalid=1
                mask=mask "0"
                next
            }
            if (serial_present != "1" || note != "" ||
                (board != "BHB56902" && board != "BHB56903")) {
                invalid=1
                next
            }
            mask=mask "1"
            count++
            if (board == "BHB56902") count902++
            if (board == "BHB56903") count903++
            # busybox awk 1.29.3 (on the target unit) cannot parse a comma
            # string literal inside a ternary inside concatenation; plain
            # if/else concatenation is equivalent and portable.
            if (names == "") names = board
            else names = names "," board
            if (addresses == "") addresses = address
            else addresses = addresses "," address
        }
        END {
            if (invalid || NR != 3 || count < 1 || length(mask) != 3) exit 1
            if (count902 && count903) sku="mixed-bhb56902-bhb56903"
            else if (count902) sku="bhb56902-only"
            else if (count903) sku="bhb56903-only"
            else exit 1
            population=(count == 3 ? "all-three-uarts-populated" : "partial-logical-uarts-populated")
            printf "%d|%s|%s|%s|%s|%s\n", count, names, addresses, mask, sku, population
        }
    ') || {
        echo "ERROR: Braiins model descriptor is not a supported BHB56902/BHB56903 population" >&2
        return 1
    }
    OLD_IFS=$IFS
    IFS='|'
    set -- $PROFILE_SUMMARY
    IFS=$OLD_IFS
    [ "$#" -eq 6 ] || {
        echo "ERROR: internal S19k population classification is malformed" >&2
        return 1
    }
    BOARD_COUNT=$1
    LIVE_IDENTITY_BOARD_NAMES=$2
    LIVE_IDENTITY_PHYSICAL_ADDRESSES=$3
    LIVE_IDENTITY_EXPECTED_MASK=$4
    LIVE_IDENTITY_PROFILE="$5:$6"
    if [ "$HASHBOARD_ROWS" = "$LIVE88_HASHBOARD_ROWS" ]; then
        LIVE_IDENTITY_PROFILE=live88_two_bhb56903_slots_2_3
    elif [ "$HASHBOARD_ROWS" = "$HELD78_HASHBOARD_ROWS" ]; then
        LIVE_IDENTITY_PROFILE=held78_three_bhb56902_slots_1_2_3
    else
        valid_live_identity_profile "$LIVE_IDENTITY_PROFILE" || return 1
    fi

    # The capture proves this exact absolute applet path, but not whether the
    # Buildroot installation is a regular binary, hardlink, or BusyBox symlink.
    [ -x "$LIVE_I2CGET" ] || {
        echo "ERROR: held Braiins /usr/sbin/i2cget evidence reader is unavailable" >&2
        return 1
    }
    EEPROM_PRESENT=0
    EEPROM_MASK=
    LIVE_IDENTITY_EEPROM_SLOTS=
    for SLOT_ADDR in 50 51 52; do
        EEPROM_0=$($LIVE_I2CGET -y 1 "0x$SLOT_ADDR" 0 b 2>/dev/null || true)
        if [ -z "$EEPROM_0" ]; then
            SLOT_VALUE=absent
            EEPROM_MASK="${EEPROM_MASK}0"
        else
            EEPROM_1=$($LIVE_I2CGET -y 1 "0x$SLOT_ADDR" 1 b 2>/dev/null || true)
            [ -n "$EEPROM_1" ] || {
                echo "ERROR: partial EEPROM identity read at 0x$SLOT_ADDR" >&2
                return 1
            }
            EEPROM_0=$(printf '%s' "$EEPROM_0" | tr 'A-F' 'a-f')
            EEPROM_1=$(printf '%s' "$EEPROM_1" | tr 'A-F' 'a-f')
            [ "$EEPROM_0:$EEPROM_1" = 0x05:0x11 ] || {
                echo "ERROR: live EEPROM at 0x$SLOT_ADDR is not held S19K preamble 05:11" >&2
                return 1
            }
            SLOT_VALUE=05:11
            EEPROM_PRESENT=$((EEPROM_PRESENT + 1))
            EEPROM_MASK="${EEPROM_MASK}1"
        fi
        if [ -n "$LIVE_IDENTITY_EEPROM_SLOTS" ]; then
            LIVE_IDENTITY_EEPROM_SLOTS="$LIVE_IDENTITY_EEPROM_SLOTS,"
        fi
        LIVE_IDENTITY_EEPROM_SLOTS="${LIVE_IDENTITY_EEPROM_SLOTS}0x${SLOT_ADDR}=${SLOT_VALUE}"
    done
    [ "$EEPROM_PRESENT" -eq "$BOARD_COUNT" ] \
        && [ "$EEPROM_MASK" = "$LIVE_IDENTITY_EXPECTED_MASK" ] || {
        echo "ERROR: direct EEPROM population contradicts the selected typed S19k profile" >&2
        return 1
    }

    IDENTITY_TRANSCRIPT=$(printf '%s\n' \
        'schema=dcentos.s19k-braiins-live-identity/v2' \
        "profile=$LIVE_IDENTITY_PROFILE" \
        "cpu=$CPU_TUPLE" \
        'bos_platform=am3-aml' \
        'bos_mode=nand' \
        "$MTD_MAP" \
        'model=Antminer S19K Pro NoPic' \
        'vendor=Antminer S19k Pro' \
        "model_sha256=$LIVE_IDENTITY_MODEL_SHA" \
        "board_count=$BOARD_COUNT" \
        "physical_addresses=$LIVE_IDENTITY_PHYSICAL_ADDRESSES" \
        "board_names=$LIVE_IDENTITY_BOARD_NAMES" \
        "eeprom=$LIVE_IDENTITY_EEPROM_SLOTS")
    LIVE_IDENTITY_SHA=$(printf '%s\n' "$IDENTITY_TRANSCRIPT" | sha256sum | awk '{print $1}') || return 1
    valid_sha256 "$LIVE_IDENTITY_SHA" || return 1
}

require_same_live_s19k_identity() {
    valid_live_identity_profile "$EXPECTED_LIVE_IDENTITY_PROFILE" \
        && valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" || {
        echo "ERROR: runtime receipt has no valid bound live-identity profile/digest" >&2
        return 1
    }
    capture_exact_live_s19k_identity || return 1
    [ "$LIVE_IDENTITY_PROFILE" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$LIVE_IDENTITY_SHA" = "$EXPECTED_LIVE_IDENTITY_SHA" ] || {
        echo "ERROR: live S19k identity profile/digest changed; refusing fixed-polarity recovery" >&2
        return 1
    }
}

process_start() {
    STAT_LINE=$(cat "/proc/$1/stat" 2>/dev/null || true)
    case "$STAT_LINE" in *') '*) ;; *) return 0 ;; esac
    STAT_REST=${STAT_LINE##*) }
    set -- $STAT_REST
    [ "$#" -ge 20 ] || return 0
    shift 19
    printf '%s\n' "$1"
}

process_ppid() {
    STAT_LINE=$(cat "/proc/$1/stat" 2>/dev/null || true)
    case "$STAT_LINE" in *') '*) ;; *) return 0 ;; esac
    STAT_REST=${STAT_LINE##*) }
    set -- $STAT_REST
    [ "$#" -ge 2 ] || return 0
    printf '%s\n' "$2"
}

process_matches() {
    PID=$1
    START=$2
    case "$PID:$START" in *[!0-9:]*) return 1 ;; 0:*|*:0|:*) return 1 ;; esac
    STAT_LINE=$(cat "/proc/$PID/stat" 2>/dev/null || true)
    case "$STAT_LINE" in *') '*) ;; *) return 1 ;; esac
    STAT_REST=${STAT_LINE##*) }
    set -- $STAT_REST
    [ "$#" -ge 20 ] || return 1
    STATE=$1
    shift 19
    LIVE_START=$1
    case "$STATE" in Z|X|x) return 1 ;; esac
    [ -n "$STATE" ] && [ -n "$LIVE_START" ] && [ "$LIVE_START" = "$START" ]
}

exact_dcentrald_child_matches() {
    PID=$1
    START=$2
    process_matches "$PID" "$START" || return 1
    [ "$(cat "/proc/$PID/comm" 2>/dev/null || true)" = dcentrald ] || return 1
    [ "$(readlink "/proc/$PID/exe" 2>/dev/null || true)" = "$TRIAL_BIN" ]
}

stock_observation_field() {
    KEY=$1
    COUNT=$(printf '%s\n' "$STOCK_OBSERVATION" | grep -c "^$KEY=" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    printf '%s\n' "$STOCK_OBSERVATION" | sed -n "s/^$KEY=//p"
}

capture_exact_stock_tree() {
    STOCK_OBSERVATION=$("$TRIAL_CUSTODY" capture /proc /var/run/bosminer.pid) || return 1
    [ "$(printf '%s\n' "$STOCK_OBSERVATION" | wc -l | tr -d ' \t\r\n')" -eq 23 ] \
        && [ "$(stock_observation_field schema)" = dcentos.s19k-braiins-supervisor-custody/v1 ] \
        && [ "$(stock_observation_field authority)" = read-only-process-tree-observation ] \
        && [ "$(stock_observation_field supervisor_state)" = nonterminal ] \
        && [ "$(stock_observation_field child_state)" = nonterminal ] \
        && [ "$(stock_observation_field pidfile)" = /var/run/bosminer.pid ] || {
            echo "ERROR: supervisor custody observer returned an inexact evidence record" >&2
            return 1
        }

    SUPERVISOR_PID=$(stock_observation_field supervisor_pid)
    SUPERVISOR_START=$(stock_observation_field supervisor_start)
    SUPERVISOR_PPID=$(stock_observation_field supervisor_ppid)
    SUPERVISOR_PGRP=$(stock_observation_field supervisor_pgrp)
    SUPERVISOR_SESSION=$(stock_observation_field supervisor_session)
    SUPERVISOR_EXE=$(stock_observation_field supervisor_exe)
    SUPERVISOR_CMDLINE_SHA=$(stock_observation_field supervisor_cmdline_sha256)
    SUPERVISOR_CMDLINE_BYTES=$(stock_observation_field supervisor_cmdline_bytes)
    BOSMINER_PID=$(stock_observation_field child_pid)
    BOSMINER_START=$(stock_observation_field child_start)
    BOSMINER_PPID=$(stock_observation_field child_ppid)
    BOSMINER_PGRP=$(stock_observation_field child_pgrp)
    BOSMINER_SESSION=$(stock_observation_field child_session)
    BOSMINER_EXE=$(stock_observation_field child_exe)
    BOSMINER_CMDLINE_SHA=$(stock_observation_field child_cmdline_sha256)
    BOSMINER_CMDLINE_BYTES=$(stock_observation_field child_cmdline_bytes)
    STOCK_PIDFILE_SHA=$(stock_observation_field pidfile_sha256)
    STOCK_PIDFILE_BYTES=$(stock_observation_field pidfile_bytes)
    STOCK_PIDFILE_PATH=$(stock_observation_field pidfile)

    valid_pid_start "$SUPERVISOR_PID" "$SUPERVISOR_START" \
        && valid_pid_start "$BOSMINER_PID" "$BOSMINER_START" \
        && [ "$SUPERVISOR_PPID" = 1 ] \
        && [ "$BOSMINER_PPID" = "$SUPERVISOR_PID" ] \
        && [ "$SUPERVISOR_PGRP" = "$BOSMINER_PGRP" ] \
        && [ "$SUPERVISOR_SESSION" = "$BOSMINER_SESSION" ] \
        && [ "$SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$BOSMINER_EXE" = /usr/bin/bosminer ] \
        && valid_sha256 "$SUPERVISOR_CMDLINE_SHA" \
        && valid_size "$SUPERVISOR_CMDLINE_BYTES" \
        && valid_sha256 "$BOSMINER_CMDLINE_SHA" \
        && valid_size "$BOSMINER_CMDLINE_BYTES" \
        && valid_sha256 "$STOCK_PIDFILE_SHA" \
        && valid_size "$STOCK_PIDFILE_BYTES" || {
            echo "ERROR: exact stock supervisor/child custody fields are malformed or inconsistent" >&2
            return 1
        }
}

bind_exact_stock_tree() {
    BOUND_SUPERVISOR_PID=$SUPERVISOR_PID
    BOUND_SUPERVISOR_START=$SUPERVISOR_START
    BOUND_SUPERVISOR_PPID=$SUPERVISOR_PPID
    BOUND_SUPERVISOR_PGRP=$SUPERVISOR_PGRP
    BOUND_SUPERVISOR_SESSION=$SUPERVISOR_SESSION
    BOUND_SUPERVISOR_EXE=$SUPERVISOR_EXE
    BOUND_SUPERVISOR_CMDLINE_SHA=$SUPERVISOR_CMDLINE_SHA
    BOUND_SUPERVISOR_CMDLINE_BYTES=$SUPERVISOR_CMDLINE_BYTES
    BOUND_BOSMINER_PID=$BOSMINER_PID
    BOUND_BOSMINER_START=$BOSMINER_START
    BOUND_BOSMINER_PPID=$BOSMINER_PPID
    BOUND_BOSMINER_PGRP=$BOSMINER_PGRP
    BOUND_BOSMINER_SESSION=$BOSMINER_SESSION
    BOUND_BOSMINER_EXE=$BOSMINER_EXE
    BOUND_BOSMINER_CMDLINE_SHA=$BOSMINER_CMDLINE_SHA
    BOUND_BOSMINER_CMDLINE_BYTES=$BOSMINER_CMDLINE_BYTES
    BOUND_STOCK_PIDFILE_SHA=$STOCK_PIDFILE_SHA
    BOUND_STOCK_PIDFILE_BYTES=$STOCK_PIDFILE_BYTES
    BOUND_STOCK_PIDFILE_PATH=$STOCK_PIDFILE_PATH
}

require_same_exact_stock_tree() {
    capture_exact_stock_tree || return 1
    [ "$SUPERVISOR_PID:$SUPERVISOR_START:$SUPERVISOR_PPID:$SUPERVISOR_PGRP:$SUPERVISOR_SESSION" = \
        "$BOUND_SUPERVISOR_PID:$BOUND_SUPERVISOR_START:$BOUND_SUPERVISOR_PPID:$BOUND_SUPERVISOR_PGRP:$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$SUPERVISOR_EXE:$SUPERVISOR_CMDLINE_SHA:$SUPERVISOR_CMDLINE_BYTES" = \
            "$BOUND_SUPERVISOR_EXE:$BOUND_SUPERVISOR_CMDLINE_SHA:$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$BOSMINER_PID:$BOSMINER_START:$BOSMINER_PPID:$BOSMINER_PGRP:$BOSMINER_SESSION" = \
            "$BOUND_BOSMINER_PID:$BOUND_BOSMINER_START:$BOUND_BOSMINER_PPID:$BOUND_BOSMINER_PGRP:$BOUND_BOSMINER_SESSION" ] \
        && [ "$BOSMINER_EXE:$BOSMINER_CMDLINE_SHA:$BOSMINER_CMDLINE_BYTES" = \
            "$BOUND_BOSMINER_EXE:$BOUND_BOSMINER_CMDLINE_SHA:$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$STOCK_PIDFILE_PATH:$STOCK_PIDFILE_SHA:$STOCK_PIDFILE_BYTES" = \
            "$BOUND_STOCK_PIDFILE_PATH:$BOUND_STOCK_PIDFILE_SHA:$BOUND_STOCK_PIDFILE_BYTES" ]
}

ensure_runtime_lock_for_recovery() {
    RECOVERY_LOCK_MODE=${1:-bound}
    case "$RECOVERY_LOCK_MODE" in
        bound|receiptless) ;;
        *) echo "ERROR: invalid recovery lock mode" >&2; return 1 ;;
    esac
    if mkdir "$RUNTIME_LOCK" 2>/dev/null; then
        chmod 700 "$RUNTIME_LOCK" || return 1
        write_runtime_lock_owner recovery || return 1
        admit_runtime_lock_owner
        return
    fi
    runtime_lock_container_is_exact || {
        echo "ERROR: runtime custody lock is not an exact directory" >&2
        return 1
    }
    if [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        another_trial_wrapper_is_live && {
            echo "ERROR: live Track-1 wrapper owns an unpublished global custody lock" >&2
            return 1
        }
        write_runtime_lock_owner recovery || return 1
        admit_runtime_lock_owner
        return
    fi
    admit_runtime_lock_owner_record || return 1
    if runtime_lock_owner_matches_current; then
        return 0
    fi
    [ "$RECOVERY_LOCK_MODE" = receiptless ] || {
        echo "ERROR: global custody lock owner does not match this exact trial/runner" >&2
        return 1
    }
    replace_runtime_lock_owner_for_receiptless_recovery
}

# Stable all-thread /proc snapshot for absence and FD claims. Linux does not
# expose non-leader TIDs through `/proc/[0-9]*` readdir, so leader-only scans can
# miss live workers after pthread_exit/zombie leadership. Enumerate every
# `/proc/TGID/task/TID`, parse starttime after the final `) ` delimiter, inspect
# every live TID image and shared FD table, and require two byte-identical
# snapshots. Any inaccessible/malformed/racing state refuses the absence claim.
collect_all_task_effect_snapshot() {
    EFFECT_PROC_ROOT=${1:-/proc}
    EFFECT_WRAPPER_PREFIX=${WRAPPER_SCAN_PREFIX:-/tmp/dcentrald_bench_t1_}
    [ -d "$EFFECT_PROC_ROOT" ] && [ ! -L "$EFFECT_PROC_ROOT" ] || return 1
    for TG_DIR in "$EFFECT_PROC_ROOT"/[0-9]*; do
        [ -d "$TG_DIR/task" ] || continue
        TGID=${TG_DIR#"$EFFECT_PROC_ROOT"/}
        for TID_DIR in "$TG_DIR"/task/[0-9]*; do
            [ -d "$TID_DIR" ] || continue
            TID=${TID_DIR##*/}
            STAT_LINE=$(cat "$TID_DIR/stat" 2>/dev/null) || {
                # A task may disappear between the task-directory glob and
                # the first read.  That is an ordinary procfs lifetime edge,
                # not evidence for or against custody.  Only skip when the
                # exact task directory is now gone; an extant unreadable or
                # malformed entry remains an ambiguity and fails closed.
                [ ! -d "$TID_DIR" ] && continue
                return 1
            }
            case "$STAT_LINE" in *') '*) ;; *) return 1 ;; esac
            STAT_REST=${STAT_LINE##*) }
            set -- $STAT_REST
            [ "$#" -ge 20 ] || return 1
            STATE=$1
            TASK_PPID=$2
            valid_uint "$TASK_PPID" || return 1
            shift 19
            TID_START=$1
            valid_uint "$TGID" && valid_uint "$TID" && valid_uint "$TID_START" || return 1
            COMM=$(cat "$TID_DIR/comm" 2>/dev/null) || {
                [ ! -d "$TID_DIR" ] && continue
                return 1
            }
            case "$COMM" in *'|'*) return 1 ;; esac
            COMM_CLEAN=$(printf '%s' "$COMM" | tr -d '\r\n')
            [ "$COMM" = "$COMM_CLEAN" ] || return 1
            EXE=$(readlink "$TID_DIR/exe" 2>/dev/null || true)
            case "$EXE" in *'|'*) return 1 ;; esac
            ARGV0=
            BOSMINER_ARG=false
            TRACK1_WRAPPER_ARG=false
            case "$STATE" in
                Z|X|x) EXE=terminal ;;
                *)
                    CMDLINE_BYTES=$(wc -c < "$TID_DIR/cmdline" 2>/dev/null | tr -d ' \t\r\n') || {
                        [ ! -d "$TID_DIR" ] && continue
                        return 1
                    }
                    valid_uint "$CMDLINE_BYTES" || return 1
                    if [ "$CMDLINE_BYTES" = 0 ]; then
                        [ -z "$EXE" ] || return 1
                        EXE=kernel-thread
                    else
                        [ -n "$EXE" ] || return 1
                        CMDLINE=$(tr '\000' '\n' < "$TID_DIR/cmdline" 2>/dev/null) || {
                            [ ! -d "$TID_DIR" ] && continue
                            return 1
                        }
                        OLD_IFS=$IFS
                        IFS='
'
                        # Cmdline bytes are process-controlled. Disable pathname
                        # expansion while newline-splitting so an argument such
                        # as '*' cannot enumerate or block on the wrapper cwd.
                        set -f
                        FIRST_ARG=true
                        for PROC_ARG in $CMDLINE; do
                            case "$PROC_ARG" in
                                *'|'*)
                                    [ "$FIRST_ARG" = false ] || {
                                        set +f
                                        IFS=$OLD_IFS
                                        return 1
                                    }
                                    PROC_ARG=$(printf '%s' "$PROC_ARG" | tr '|' ':')
                                    ;;
                            esac
                            case "$PROC_ARG" in *'|'**) IFS=$OLD_IFS; return 1 ;; esac
                            PROC_ARG_CLEAN=$(printf '%s' "$PROC_ARG" | tr -d '\r\n')
                            [ "$PROC_ARG" = "$PROC_ARG_CLEAN" ] || {
                                set +f
                                IFS=$OLD_IFS
                                return 1
                            }
                            if [ "$FIRST_ARG" = true ]; then
                                ARGV0=$PROC_ARG
                                FIRST_ARG=false
                            fi
                            [ "$PROC_ARG" = /usr/bin/bosminer ] && BOSMINER_ARG=true
                            case "$PROC_ARG" in
                                "$EFFECT_WRAPPER_PREFIX"*/run_trial) TRACK1_WRAPPER_ARG=true ;;
                            esac
                        done
                        set +f
                        IFS=$OLD_IFS
                        [ "$FIRST_ARG" = false ] || return 1
                    fi
                    ;;
            esac
            # A command-substitution fork of this wrapper keeps the wrapper's
            # own run_trial argv until exec; mid-enumeration it would read as
            # a second live wrapper and poison both snapshot stability and the
            # competing-wrapper fence. Direct children of $$ are our own
            # forks; a genuinely competing wrapper is launched by its own ssh
            # session and is never our child.
            [ "$TASK_PPID" = "$$" ] && TRACK1_WRAPPER_ARG=false
            printf 'T|%s|%s|%s|%s|comm=%s|exe=%s|argv0=%s|bosminer_arg=%s|track1_wrapper_arg=%s\n' \
                "$TGID" "$TID" "$STATE" "$TID_START" "$COMM" "$EXE" "$ARGV0" \
                "$BOSMINER_ARG" "$TRACK1_WRAPPER_ARG"
            for FD in "$TID_DIR"/fd/*; do
                # Procfs fd entries are symlinks. Test the link itself first so
                # custody enumeration never stats (and potentially blocks on)
                # an unrelated descriptor target such as NFS/FUSE/DrvFS.
                [ -L "$FD" ] || [ -e "$FD" ] || continue
                FD_TARGET=$(readlink "$FD" 2>/dev/null) || {
                    # Descriptor close and task exit are both legitimate
                    # between enumeration and readlink.  A still-present link
                    # that cannot be read is ambiguous and must fail closed.
                    [ ! -L "$FD" ] && [ ! -e "$FD" ] && continue
                    return 1
                }
                case "$FD_TARGET" in *'|'*) return 1 ;; esac
                printf 'F|%s|%s|%s|target=%s\n' "$TGID" "$TID" "${FD##*/}" "$FD_TARGET"
            done
        done
    done
}

filter_custody_relevant_task_effects() (
    set -f
    COMPLETE_SNAPSHOT=$1
    OLD_IFS=$IFS
    IFS='
'
    for EFFECT_LINE in $COMPLETE_SNAPSHOT; do
        case "$EFFECT_LINE" in
            T\|*'|comm=dcentrald|'*|T\|*'|exe='*/dcentrald'|'*|T\|*'|exe='*/dcentrald\ \(deleted\)'|'*|T\|*'|argv0='*/dcentrald'|'*|\
            T\|*'|comm=bosminer|'*|T\|*'|exe=/usr/bin/bosminer|'*|T\|*'|exe=/usr/bin/bosminer (deleted)|'*|T\|*'|argv0=/usr/bin/bosminer|'*|\
            T\|*'|comm=bos-tools|'*|T\|*'|exe=/usr/bin/bos-tools|'*|T\|*'|exe=/usr/bin/bos-tools (deleted)|'*|T\|*'|argv0=/usr/bin/bos-tools|'*|\
            T\|*'|track1_wrapper_arg=true'|F\|*'|target=/dev/watchdog'*)
                printf '%s\n' "$EFFECT_LINE"
                ;;
        esac
    done
    IFS=$OLD_IFS
)

stable_all_task_effect_snapshot() {
    EFFECT_PROC_ROOT=${1:-/proc}
    SNAP_TRIES=0
    while [ "$SNAP_TRIES" -lt 3 ]; do
        SNAPSHOT_ONE_FILE="$TRIAL_DIR/.all_task_effect_snapshot.$$.${SELF_START}.$SNAP_TRIES.one"
        SNAPSHOT_TWO_FILE="$TRIAL_DIR/.all_task_effect_snapshot.$$.${SELF_START}.$SNAP_TRIES.two"
        [ ! -e "$SNAPSHOT_ONE_FILE" ] && [ ! -L "$SNAPSHOT_ONE_FILE" ] \
            && [ ! -e "$SNAPSHOT_TWO_FILE" ] && [ ! -L "$SNAPSHOT_TWO_FILE" ] || return 1
        set -C
        if ! exec 7> "$SNAPSHOT_ONE_FILE"; then
            set +C
            return 1
        fi
        set +C
        if ! collect_all_task_effect_snapshot "$EFFECT_PROC_ROOT" >&7; then
            exec 7>&-
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            SNAP_TRIES=$((SNAP_TRIES + 1))
            continue
        fi
        exec 7>&-
        chmod 600 "$SNAPSHOT_ONE_FILE" || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            return 1
        }
        COMPLETE_SNAPSHOT_ONE=$(cat "$SNAPSHOT_ONE_FILE") || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            return 1
        }
        SNAP_ONE=$(filter_custody_relevant_task_effects "$COMPLETE_SNAPSHOT_ONE") || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            SNAP_TRIES=$((SNAP_TRIES + 1))
            continue
        }
        set -C
        if ! exec 7> "$SNAPSHOT_TWO_FILE"; then
            set +C
            rm -f "$SNAPSHOT_ONE_FILE"
            return 1
        fi
        set +C
        if ! collect_all_task_effect_snapshot "$EFFECT_PROC_ROOT" >&7; then
            exec 7>&-
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            SNAP_TRIES=$((SNAP_TRIES + 1))
            continue
        fi
        exec 7>&-
        chmod 600 "$SNAPSHOT_TWO_FILE" || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            return 1
        }
        COMPLETE_SNAPSHOT_TWO=$(cat "$SNAPSHOT_TWO_FILE") || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            return 1
        }
        SNAP_TWO=$(filter_custody_relevant_task_effects "$COMPLETE_SNAPSHOT_TWO") || {
            rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE"
            SNAP_TRIES=$((SNAP_TRIES + 1))
            continue
        }
        rm -f "$SNAPSHOT_ONE_FILE" "$SNAPSHOT_TWO_FILE" || return 1
        if [ "$SNAP_ONE" = "$SNAP_TWO" ]; then
            ALL_TASK_EFFECT_SNAPSHOT=$SNAP_TWO
            return 0
        fi
        SNAP_TRIES=$((SNAP_TRIES + 1))
    done
    return 1
}

all_task_snapshot_has_no_dcentrald() (
    set -f
    OLD_IFS=$IFS
    IFS='
'
    for TASK_LINE in $ALL_TASK_EFFECT_SNAPSHOT; do
        case "$TASK_LINE" in
            T\|*'|comm=dcentrald|'*|T\|*'|exe='*/dcentrald'|'*|T\|*'|exe='*/dcentrald\ \(deleted\)'|'*|T\|*'|argv0='*/dcentrald'|'*)
                echo "ERROR: all-thread dcentrald owner observation: $TASK_LINE" >&2
                IFS=$OLD_IFS
                return 1
                ;;
        esac
    done
    IFS=$OLD_IFS
    return 0
)

no_dcentrald_thread_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" \
        && all_task_snapshot_has_no_dcentrald
}

all_task_snapshot_has_stock_owner() (
    # Exact stock-custody matcher over the stable all-thread snapshot.
    # /usr/bin/bos-tools is a Braiins multi-call binary that also hosts
    # non-mining run-and-watch daemons (dnsmasq, boser, ...).  Those are not
    # stock mining custody, legitimately survive the stock handoff, and must
    # never satisfy this guard, so a bare bos-tools exe/comm/argv0 match is
    # forbidden here.  The stock custody owner is live only when
    #   (a) bosminer itself is live under any identity -- it must never be
    #       alive after the stock handoff,
    #   (b) a live task's argv carries the exact /usr/bin/bosminer path --
    #       the run-and-watch MINING supervisor, whatever its pid, or
    #   (c) a live thread-group leader still matches the pid + starttime +
    #       exe supervisor identity bound by the J0 runtime-lock owner
    #       record (supervisor_pid/supervisor_start/supervisor_exe).
    # Fail closed: once a global owner-record path is bound, a record that
    # is present but unreadable, non-regular, malformed, or of an unknown
    # schema proves nothing, and the stock owner counts as live/unknown;
    # a lost record inside an existing custody container is equally
    # live/unknown.  Only a fully unbound board (no container and no
    # record -- the receiptless entry after neutral-container retirement)
    # and the tuple-less launch/recovery/pending runtime-lock schemas
    # defer to the process-level tests above alone.
    set -f
    OLD_IFS=$IFS
    IFS='
'
    EXACT_SUP_PID=
    EXACT_SUP_START=
    EXACT_SUP_EXE=
    EXACT_SUP_HEAD=
    EXACT_OWNER_SCHEMA=unbound-board
    if [ -n "${RUNTIME_LOCK_OWNER:-}" ]; then
        if [ ! -f "$RUNTIME_LOCK_OWNER" ] || [ -L "$RUNTIME_LOCK_OWNER" ]; then
            if [ -e "$RUNTIME_LOCK_OWNER" ] || [ -L "$RUNTIME_LOCK_OWNER" ]; then
                IFS=$OLD_IFS
                return 0
            fi
            if [ -d "${RUNTIME_LOCK_OWNER%/*}" ]; then
                # An exact EMPTY container with no owner record is the
                # designed pre-J0-crash neutral state (a prior wrapper
                # died before the no-clobber owner hard-link); the
                # process-level custody tests stay authoritative there,
                # exactly like a fully unbound board.  A container that
                # is inexact or holds any entry stays live/unknown.
                NEUTRAL_CONTAINER_HAS_ENTRY=false
                # This matcher runs set -f so snapshot lines can never
                # filename-generate; the container-emptiness globs need it on.
                set +f
                for NEUTRAL_CONTAINER_ENTRY in "${RUNTIME_LOCK_OWNER%/*}"/* "${RUNTIME_LOCK_OWNER%/*}"/.[!.]* "${RUNTIME_LOCK_OWNER%/*}"/..?*; do
                    [ -e "$NEUTRAL_CONTAINER_ENTRY" ] && NEUTRAL_CONTAINER_HAS_ENTRY=true && break
                done
                set -f
                # The exactness helper field-splits ls(1) output and needs a
                # whitespace IFS; this matcher runs with a newline-only IFS.
                NEUTRAL_CONTAINER_IFS=$IFS
                IFS=" 	"
                if [ "$NEUTRAL_CONTAINER_HAS_ENTRY" = true ] \
                    || ! runtime_lock_container_is_exact; then
                    IFS=$NEUTRAL_CONTAINER_IFS
                    IFS=$OLD_IFS
                    return 0
                fi
                IFS=$NEUTRAL_CONTAINER_IFS
            fi
        else
            EXACT_OWNER_SCHEMA=$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" schema) || {
                IFS=$OLD_IFS
                return 0
            }
        fi
        case "$EXACT_OWNER_SCHEMA" in
            dcentos.s19k-startup-j0-prefork/v1)
                EXACT_SUP_PID=$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" supervisor_pid) || {
                    IFS=$OLD_IFS
                    return 0
                }
                EXACT_SUP_START=$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" supervisor_start) || {
                    IFS=$OLD_IFS
                    return 0
                }
                EXACT_SUP_EXE=$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" supervisor_exe) || {
                    IFS=$OLD_IFS
                    return 0
                }
                case "$EXACT_SUP_PID:$EXACT_SUP_START" in
                    *[!0-9:]*|0:*|*:0|:)
                        IFS=$OLD_IFS
                        return 0
                        ;;
                esac
                [ -n "$EXACT_SUP_EXE" ] || {
                    IFS=$OLD_IFS
                    return 0
                }
                EXACT_SUP_HEAD="T|$EXACT_SUP_PID|$EXACT_SUP_PID|"
                ;;
            dcentos.s19k-track1-runtime-lock/v6|dcentos.s19k-track1-runtime-lock/v7|dcentos.s19k-track1-runtime-lock/v8|dcentos.s19k-track1-runtime-lock/v9|dcentos.s19k-track1-runtime-lock/v10|unbound-board)
                ;;
            *)
                IFS=$OLD_IFS
                return 0
                ;;
        esac
    fi
    for TASK_LINE in $ALL_TASK_EFFECT_SNAPSHOT; do
        case "$TASK_LINE" in
            T\|*'|comm=bosminer|'*|T\|*'|exe=/usr/bin/bosminer|'*|T\|*'|exe=/usr/bin/bosminer (deleted)|'*|T\|*'|argv0=/usr/bin/bosminer|'*)
                IFS=$OLD_IFS
                return 0
                ;;
        esac
        case "$TASK_LINE" in
            T\|*'|bosminer_arg=true|'*)
                IFS=$OLD_IFS
                return 0
                ;;
        esac
        if [ -n "$EXACT_SUP_HEAD" ]; then
            case "$TASK_LINE" in
                "$EXACT_SUP_HEAD"*)
                    TASK_TAIL=${TASK_LINE#"$EXACT_SUP_HEAD"}
                    TASK_TAIL=${TASK_TAIL#*|}
                    case "$TASK_TAIL" in
                        "$EXACT_SUP_START"'|'*'|exe='"$EXACT_SUP_EXE"'|'*|"$EXACT_SUP_START"'|'*'|exe='"$EXACT_SUP_EXE"' (deleted)|'*)
                            IFS=$OLD_IFS
                            return 0
                            ;;
                    esac
                    ;;
            esac
        fi
    done
    IFS=$OLD_IFS
    return 1
)

bosminer_custody_owner_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" || return 0
    all_task_snapshot_has_stock_owner
}

all_task_snapshot_has_another_wrapper() (
    set -f
    OLD_IFS=$IFS
    IFS='
'
    for TASK_LINE in $ALL_TASK_EFFECT_SNAPSHOT; do
        case "$TASK_LINE" in
            T\|"$$"\|*) continue ;;
            T\|*'|track1_wrapper_arg=true') IFS=$OLD_IFS; return 0 ;;
        esac
    done
    IFS=$OLD_IFS
    return 1
)

another_trial_wrapper_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" || return 0
    all_task_snapshot_has_another_wrapper
}

runtime_lock_field_at() {
    OWNER_EVIDENCE=$1
    KEY=$2
    COUNT=$(grep -c "^$KEY=" "$OWNER_EVIDENCE" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$OWNER_EVIDENCE"
}

runtime_lock_field() {
    runtime_lock_field_at "$RUNTIME_LOCK_OWNER" "$1"
}

startup_fifo_matches_j0() {
    OWNER_EVIDENCE=$1
    J0_WRAPPER_PID=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid) || return 1
    J0_WRAPPER_START=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start) || return 1
    J0_FIFO=$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_path) || return 1
    [ "$J0_FIFO" = "$TRIAL_DIR/.startup_fifo.$J0_WRAPPER_PID.$J0_WRAPPER_START" ] || return 1
    exec 8<> "$J0_FIFO" || return 1
    FD_TARGET=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
    FIFO_LS=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
    set -- $FIFO_LS
    OBSERVED_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
    exec 8>&-
    [ "$FD_TARGET" = "$J0_FIFO" ] \
        && [ "${1:-}" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_inode)" ] \
        && [ "${2:-}" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mode)" ] \
        && [ "${4:-}" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_uid)" ] \
        && [ "${5:-}" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_gid)" ] \
        && [ "$OBSERVED_MNT_ID" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mnt_id)" ]
}

exact_current_wrapper_matches_j0() {
    OWNER_EVIDENCE=$1
    J0_WRAPPER_PID=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid) || return 1
    J0_WRAPPER_START=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start) || return 1
    [ "$J0_WRAPPER_PID" = "$$" ] \
        && [ "$J0_WRAPPER_START" = "$SELF_START" ] \
        && process_matches "$$" "$SELF_START" \
        && [ "$(cat "/proc/$$/comm" 2>/dev/null || true)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_comm)" ] \
        && [ "$(readlink "/proc/$$/exe" 2>/dev/null || true)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_exe)" ] \
        && [ "$(sha256sum "/proc/$$/cmdline" 2>/dev/null | awk '{print $1}')" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_sha256)" ] \
        && [ "$(wc -c < "/proc/$$/cmdline" 2>/dev/null | tr -d ' \t\r\n')" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_bytes)" ]
}

publish_no_clobber_journal_keep_source() {
    JOURNAL_SOURCE=$1
    JOURNAL_DESTINATION=$2
    is_regular_nonsymlink "$TRIAL_BIN" || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        DCENT_S19K_STARTUP_BOOTSTRAP=publisher-v1 \
        DCENT_S19K_STARTUP_WRAPPER_PID="$$" \
        DCENT_S19K_STARTUP_WRAPPER_START="$SELF_START" \
        "$TRIAL_BIN" \
        --s19k-track1-journal-source "$JOURNAL_SOURCE" \
        --s19k-track1-journal-destination "$JOURNAL_DESTINATION" \
        6>&- 9>&- </dev/null >/dev/null 2>&1 || return 1
}

publish_no_clobber_journal() {
    JOURNAL_SOURCE=$1
    JOURNAL_DESTINATION=$2
    publish_no_clobber_journal_keep_source "$JOURNAL_SOURCE" "$JOURNAL_DESTINATION" || return 1
    rm -f "$JOURNAL_SOURCE"
}

write_runtime_lock_owner() {
    LOCK_KIND=$1
    case "$LOCK_KIND" in launch|recovery) ;; *) return 1 ;; esac
    valid_trial_dir_value "$TRIAL_DIR" || return 1
    valid_sha256 "$RUNNER_SHA" && valid_size "$RUNNER_BYTES" \
        && valid_sha256 "$CUSTODY_SHA" && valid_size "$CUSTODY_BYTES" \
        && valid_sha256 "$STOCK_RESTART_HELPER_SHA" && valid_size "$STOCK_RESTART_HELPER_BYTES" \
        && valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" || return 1
    [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] || {
        echo "ERROR: refusing to overwrite an existing global custody owner record" >&2
        return 1
    }
    LOCK_TMP="$TRIAL_DIR/.runtime_lock_owner.tmp.$$.${SELF_START}"
    [ ! -e "$LOCK_TMP" ] && [ ! -L "$LOCK_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-track1-runtime-lock/v6\n'
        printf 'owner_kind=%s\n' "$LOCK_KIND"
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
    } > "$LOCK_TMP"
    chmod 600 "$LOCK_TMP"
    publish_no_clobber_journal "$LOCK_TMP" "$RUNTIME_LOCK_OWNER"
}

admit_runtime_lock_owner_record_at() {
    OWNER_EVIDENCE=$1
    is_regular_nonsymlink "$OWNER_EVIDENCE" || {
        echo "ERROR: global custody lock has no regular owner record" >&2
        return 1
    }
    OWNER_SCHEMA=$(runtime_lock_field_at "$OWNER_EVIDENCE" schema) || return 1
    if [ "$OWNER_SCHEMA" = dcentos.s19k-startup-j0-prefork/v1 ]; then
        [ "$(wc -l < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" -eq 79 ] \
            && startup_ordered_keys_are_exact "$OWNER_EVIDENCE" "$STARTUP_J0_KEYS_SHA" \
            && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" ordinal)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_schema)" = none ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_sha256)" = none ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_bytes)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" trial_dir)" = "$TRIAL_DIR" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_path)" = not-published ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_sha256)" = none ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_bytes)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_phase)" = not-published ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_owner_binding)" = self-hardlink ] \
            && startup_fifo_matches_j0 "$OWNER_EVIDENCE" \
            && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mnt_id)" \
            && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_inode)" \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mode)" = prw------- ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_uid)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_gid)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_role)" = wrapper ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_pid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_start)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" ] \
            && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" \
            && [ -n "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_comm)" ] \
            && [ -n "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_exe)" ] \
            && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_sha256)" \
            && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_bytes)" \
            && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_sha256)" \
            && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_bytes)" \
            && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_sha256)" \
            && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_bytes)" \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_count)" = 10 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_pid)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_start)" = 0 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_start)" = "$BOUND_BOSMINER_START" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = "$BOUND_STOCK_PIDFILE_PATH" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_sha256)" = "$BOUND_STOCK_PIDFILE_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_bytes)" = "$BOUND_STOCK_PIDFILE_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" binary_sha256)" = "$BIN_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" binary_bytes)" = "$BIN_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" config_sha256)" = "$CFG_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" config_bytes)" = "$CFG_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_sha256)" = "$RUNNER_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_bytes)" = "$RUNNER_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" watchdog_start_intent)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" watchdog_armed)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" signal_attempted)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" inherited_rails)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" route_or_uart_opened)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" hardware_opened)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" parent_release)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" persistent_mutation)" = false ] \
            && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" publication)" = no-clobber-hard-link-after-fsync ] || return 1
        LOCK_KIND=launch
        LOCK_TRIAL=$TRIAL_DIR
        LOCK_RUNNER_SHA=$RUNNER_SHA
        LOCK_RUNNER_BYTES=$RUNNER_BYTES
        LOCK_CUSTODY_SHA=$CUSTODY_SHA
        LOCK_CUSTODY_BYTES=$CUSTODY_BYTES
        LOCK_HELPER_SHA=$STOCK_RESTART_HELPER_SHA
        LOCK_HELPER_BYTES=$STOCK_RESTART_HELPER_BYTES
        LOCK_IDENTITY_SHA=$EXPECTED_LIVE_IDENTITY_SHA
        return 0
    fi
    [ "$(wc -l < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" -eq 10 ] || {
        echo "ERROR: global custody owner record has an inexact field set" >&2
        return 1
    }
    [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" schema)" = dcentos.s19k-track1-runtime-lock/v6 ] || return 1
    LOCK_KIND=$(runtime_lock_field_at "$OWNER_EVIDENCE" owner_kind)
    case "$LOCK_KIND" in launch|recovery) ;; *) return 1 ;; esac
    LOCK_TRIAL=$(runtime_lock_field_at "$OWNER_EVIDENCE" trial_dir)
    valid_trial_dir_value "$LOCK_TRIAL" || return 1
    LOCK_RUNNER_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_sha256)
    LOCK_RUNNER_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_bytes)
    LOCK_CUSTODY_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_sha256)
    LOCK_CUSTODY_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_bytes)
    LOCK_HELPER_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_sha256)
    LOCK_HELPER_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_bytes)
    LOCK_IDENTITY_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_sha256)
    valid_sha256 "$LOCK_RUNNER_SHA" && valid_size "$LOCK_RUNNER_BYTES" \
        && valid_sha256 "$LOCK_CUSTODY_SHA" && valid_size "$LOCK_CUSTODY_BYTES" \
        && valid_sha256 "$LOCK_HELPER_SHA" && valid_size "$LOCK_HELPER_BYTES" \
        && valid_sha256 "$LOCK_IDENTITY_SHA" || return 1
    [ "$LOCK_IDENTITY_SHA" = "$EXPECTED_LIVE_IDENTITY_SHA" ] || {
        echo "ERROR: global custody lock is bound to a different live identity" >&2
        return 1
    }
}

admit_runtime_lock_owner_record() {
    admit_runtime_lock_owner_record_at "$RUNTIME_LOCK_OWNER"
}

runtime_lock_owner_matches_current() {
    [ "$LOCK_TRIAL" = "$TRIAL_DIR" ] \
        && [ "$LOCK_RUNNER_SHA" = "$RUNNER_SHA" ] \
        && [ "$LOCK_RUNNER_BYTES" = "$RUNNER_BYTES" ] \
        && [ "$LOCK_CUSTODY_SHA" = "$CUSTODY_SHA" ] \
        && [ "$LOCK_CUSTODY_BYTES" = "$CUSTODY_BYTES" ] \
        && [ "$LOCK_HELPER_SHA" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$LOCK_HELPER_BYTES" = "$STOCK_RESTART_HELPER_BYTES" ]
}

admit_runtime_lock_owner() {
    admit_runtime_lock_owner_record || return 1
    runtime_lock_owner_matches_current || {
        echo "ERROR: global custody lock owner does not match this exact trial/runner" >&2
        return 1
    }
}

replace_runtime_lock_owner_for_receiptless_recovery() {
    # This path is reachable only after receiptless recovery has refused every
    # live bosminer, dcentrald, and Track-1 wrapper and captured the same exact
    # live board identity. Preserve the global lock directory while atomically
    # replacing a dead prior-version owner record with this recovery runner.
    admit_runtime_lock_owner_record || return 1
    runtime_lock_owner_matches_current && return 0
    another_trial_wrapper_is_live && {
        echo "ERROR: a Track-1 wrapper appeared before stale custody rebind" >&2
        return 1
    }
    if bosminer_custody_owner_is_live || ! no_dcentrald_thread_is_live; then
        echo "ERROR: a hardware owner appeared before stale custody rebind" >&2
        return 1
    fi
    STALE_OWNER_SHA=$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')
    valid_sha256 "$STALE_OWNER_SHA" || return 1
    REBIND_TMP="$TRIAL_DIR/.runtime_owner_recovery.tmp.$$.${SELF_START}"
    [ ! -e "$REBIND_TMP" ] && [ ! -L "$REBIND_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-track1-runtime-lock/v6\n'
        printf 'owner_kind=recovery\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
    } > "$REBIND_TMP"
    chmod 600 "$REBIND_TMP"
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" = "$STALE_OWNER_SHA" ] || {
        rm -f "$REBIND_TMP"
        echo "ERROR: global custody owner changed during receiptless recovery rebind" >&2
        return 1
    }
    mv -f "$REBIND_TMP" "$RUNTIME_LOCK_OWNER" || return 1
    admit_runtime_lock_owner
}

active_field_at() {
    ACTIVE_EVIDENCE=$1
    KEY=$2
    COUNT=$(grep -c "^$KEY=" "$ACTIVE_EVIDENCE" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$ACTIVE_EVIDENCE"
}

active_field() {
    active_field_at "$ACTIVE" "$1"
}

pre_active_field() {
    KEY=$1
    COUNT=$(grep -c "^$KEY=" "$PRE_SAFEOFF_ACTIVE" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$PRE_SAFEOFF_ACTIVE"
}

retained_stock_field() {
    KEY=$1
    COUNT=$(grep -c "^$KEY=" "$STOCK_RETAINED_RECEIPT" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$STOCK_RETAINED_RECEIPT"
}

valid_bool() {
    case "$1" in true|false) return 0 ;; *) return 1 ;; esac
}

valid_stock_lease_kind() {
    case "$1" in pidfd|legacy_exact_identity_experimental) return 0 ;; *) return 1 ;; esac
}

retained_watchdog_relation_is_exact() {
    SLA=$(retained_stock_field watchdog_sla_admitted)
    valid_bool "$SLA" || return 1
    if [ "$SLA" = true ]; then
        [ "$(retained_stock_field watchdog_requested_timeout_s)" = 30 ] \
            && [ "$(retained_stock_field watchdog_effective_timeout_s)" = 30 ] \
            && [ "$(retained_stock_field watchdog_kick_interval_s)" = 5 ]
    else
        valid_size "$(retained_stock_field watchdog_requested_timeout_s)" \
            && valid_size "$(retained_stock_field watchdog_effective_timeout_s)" \
            && valid_size "$(retained_stock_field watchdog_kick_interval_s)"
    fi
}

all_task_snapshot_has_no_watchdog_fd() (
    set -f
    OLD_IFS=$IFS
    IFS='
'
    for TASK_LINE in $ALL_TASK_EFFECT_SNAPSHOT; do
        case "$TASK_LINE" in F\|*\|target=/dev/watchdog*) IFS=$OLD_IFS; return 1 ;; esac
    done
    IFS=$OLD_IFS
    return 0
)

no_watchdog_fd_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" \
        && all_task_snapshot_has_no_watchdog_fd
}

no_stock_daemon_watchdog_or_competing_wrapper_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" \
        && ! all_task_snapshot_has_stock_owner \
        && all_task_snapshot_has_no_dcentrald \
        && all_task_snapshot_has_no_watchdog_fd \
        && ! all_task_snapshot_has_another_wrapper
}

no_daemon_watchdog_or_competing_wrapper_is_live() {
    EFFECT_PROC_ROOT=${1:-/proc}
    stable_all_task_effect_snapshot "$EFFECT_PROC_ROOT" \
        && all_task_snapshot_has_no_dcentrald \
        && all_task_snapshot_has_no_watchdog_fd \
        && ! all_task_snapshot_has_another_wrapper
}

gpio437_is_exact_engaged() {
    BASE=/sys/class/gpio/gpio437
    [ -d "$BASE" ] \
        && is_regular_nonsymlink "$BASE/direction" \
        && is_regular_nonsymlink "$BASE/active_low" \
        && is_regular_nonsymlink "$BASE/value" \
        && [ "$(cat "$BASE/direction")" = out ] \
        && [ "$(cat "$BASE/active_low")" = 0 ] \
        && [ "$(cat "$BASE/value")" = 0 ]
}

gpio_stock_baseline_is_exact() {
    for SPEC in 437:0 454:0 455:1 456:1; do
        GPIO=${SPEC%%:*}
        VALUE=${SPEC#*:}
        BASE=/sys/class/gpio/gpio$GPIO
        [ -d "$BASE" ] \
            && is_regular_nonsymlink "$BASE/direction" \
            && is_regular_nonsymlink "$BASE/active_low" \
            && is_regular_nonsymlink "$BASE/value" \
            && [ "$(cat "$BASE/direction")" = out ] \
            && [ "$(cat "$BASE/active_low")" = 0 ] \
            && [ "$(cat "$BASE/value")" = "$VALUE" ] || return 1
    done
}

gpio_safeoff_is_exact() {
    GPIO_SAFEOFF_SPECS='437:1 454:0 455:0 456:0'
    GPIO_SAFEOFF_MODE=$(safeoff_source_deploy_mode 2>/dev/null || true)
    if [ "$GPIO_SAFEOFF_MODE" = install-custody-safeoff ]; then
        # Install custody owns only the fixed-polarity GPIO437 cut. Do not
        # make its terminal proof depend on inspecting the three reset lines.
        GPIO_SAFEOFF_SPECS=437:1
    fi
    for SPEC in $GPIO_SAFEOFF_SPECS; do
        GPIO=${SPEC%%:*}
        VALUE=${SPEC#*:}
        BASE=/sys/class/gpio/gpio$GPIO
        [ -d "$BASE" ] \
            && is_regular_nonsymlink "$BASE/direction" \
            && is_regular_nonsymlink "$BASE/active_low" \
            && is_regular_nonsymlink "$BASE/value" \
            && [ "$(cat "$BASE/direction")" = out ] \
            && [ "$(cat "$BASE/active_low")" = 0 ] \
            && [ "$(cat "$BASE/value")" = "$VALUE" ] || return 1
    done
}

retained_magic_closed_receipt_is_exact() {
    ACTIVE_EVIDENCE=${1:-$ACTIVE}
    is_regular_nonsymlink "$STOCK_RETAINED_RECEIPT" \
        && is_regular_nonsymlink "$ACTIVE_EVIDENCE" \
        && [ "$(wc -l < "$STOCK_RETAINED_RECEIPT" | tr -d ' \t\r\n')" -eq 52 ] \
        && [ "$(retained_stock_field schema)" = dcentos.s19k-stock-owner-retained/v2 ] \
        && [ "$(retained_stock_field disposition)" = stock-owner-retained-closed ] \
        && [ "$(retained_stock_field runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(retained_stock_field runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(retained_stock_field signal_attempted)" = false ] \
        && [ "$(retained_stock_field supervisor_signal_attempted)" = false ] \
        && [ "$(retained_stock_field child_signal_attempted)" = false ] \
        && [ "$(retained_stock_field inherited_rails)" = false ] \
        && [ "$(retained_stock_field route_or_uart_opened)" = false ] \
        && [ "$(retained_stock_field watchdog_armed)" = true ] \
        && retained_watchdog_relation_is_exact \
        && [ "$(retained_stock_field watchdog_magic_close)" = true ] \
        && [ "$(retained_stock_field watchdog_worker_joined)" = true ] \
        && [ "$(retained_stock_field stock_tree_revalidated_after_close)" = true ] \
        && [ "$(retained_stock_field live_identity_revalidated_after_close)" = true ] \
        && [ "$(retained_stock_field gpio437_engaged_after_close)" = true ] \
        && [ "$(retained_stock_field supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(retained_stock_field supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(retained_stock_field supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
        && [ "$(retained_stock_field supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
        && [ "$(retained_stock_field supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$(retained_stock_field supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
        && [ "$(retained_stock_field supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(retained_stock_field bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(retained_stock_field bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
        && [ "$(retained_stock_field bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$(retained_stock_field bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$(retained_stock_field bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
        && [ "$(retained_stock_field bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(retained_stock_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(retained_stock_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(retained_stock_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(retained_stock_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(retained_stock_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(retained_stock_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(retained_stock_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(retained_stock_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(retained_stock_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(retained_stock_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(retained_stock_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(retained_stock_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(retained_stock_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(retained_stock_field gpio437)" = engaged-checked ] \
        && [ "$(retained_stock_field persistent_mutation)" = false ] \
        && [ "$(retained_stock_field publication)" = no-clobber-hard-link-after-fsync ]
}

retained_prewatchdog_receipt_is_exact() {
    ACTIVE_EVIDENCE=${1:-$ACTIVE}
    is_regular_nonsymlink "$STOCK_RETAINED_RECEIPT" \
        && is_regular_nonsymlink "$ACTIVE_EVIDENCE" \
        && [ "$(wc -l < "$STOCK_RETAINED_RECEIPT" | tr -d ' \t\r\n')" -eq 46 ] \
        && [ "$(retained_stock_field schema)" = dcentos.s19k-stock-owner-retained-prewatchdog/v1 ] \
        && [ "$(retained_stock_field disposition)" = stock-owner-retained-before-watchdog ] \
        && [ "$(retained_stock_field runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(retained_stock_field runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(retained_stock_field signal_attempted)" = false ] \
        && [ "$(retained_stock_field supervisor_signal_attempted)" = false ] \
        && [ "$(retained_stock_field child_signal_attempted)" = false ] \
        && [ "$(retained_stock_field inherited_rails)" = false ] \
        && [ "$(retained_stock_field route_or_uart_opened)" = false ] \
        && [ "$(retained_stock_field watchdog_started)" = false ] \
        && [ "$(retained_stock_field watchdog_fd)" = absent-checked ] \
        && [ "$(retained_stock_field stock_tree_revalidated)" = true ] \
        && [ "$(retained_stock_field live_identity_revalidated)" = true ] \
        && [ "$(retained_stock_field gpio437_engaged)" = true ] \
        && [ "$(retained_stock_field supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(retained_stock_field supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(retained_stock_field supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
        && [ "$(retained_stock_field supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
        && [ "$(retained_stock_field supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$(retained_stock_field supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
        && [ "$(retained_stock_field supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(retained_stock_field bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(retained_stock_field bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
        && [ "$(retained_stock_field bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$(retained_stock_field bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$(retained_stock_field bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
        && [ "$(retained_stock_field bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(retained_stock_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(retained_stock_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(retained_stock_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(retained_stock_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(retained_stock_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(retained_stock_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(retained_stock_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(retained_stock_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(retained_stock_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(retained_stock_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(retained_stock_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(retained_stock_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(retained_stock_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(retained_stock_field persistent_mutation)" = false ] \
        && [ "$(retained_stock_field publication)" = no-clobber-hard-link-after-fsync ]
}

retained_early_receipt_is_exact() {
    ACTIVE_EVIDENCE=${1:-$ACTIVE}
    SCHEMA=$(retained_stock_field schema) || return 1
    case "$SCHEMA" in
        dcentos.s19k-stock-owner-retained-runtime-binding-not-admitted/v1)
            [ "$(retained_stock_field disposition)" = stock-owner-retained-runtime-binding-not-admitted ] \
                && [ "$(retained_stock_field runtime_binding)" = not-admitted ] \
                && [ "$(retained_stock_field live_identity)" = not-observed ] || return 1
            ;;
        dcentos.s19k-stock-owner-retained-before-live-identity/v1)
            [ "$(retained_stock_field disposition)" = stock-owner-retained-before-live-identity ] \
                && [ "$(retained_stock_field runtime_binding)" = admitted ] \
                && [ "$(retained_stock_field live_identity)" = not-admitted ] || return 1
            ;;
        *) return 1 ;;
    esac
    is_regular_nonsymlink "$STOCK_RETAINED_RECEIPT" \
        && is_regular_nonsymlink "$ACTIVE_EVIDENCE" \
        && [ "$(wc -l < "$STOCK_RETAINED_RECEIPT" | tr -d ' \t\r\n')" -eq 47 ] \
        && [ "$(retained_stock_field runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(retained_stock_field runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(retained_stock_field signal_attempted)" = false ] \
        && [ "$(retained_stock_field supervisor_signal_attempted)" = false ] \
        && [ "$(retained_stock_field child_signal_attempted)" = false ] \
        && [ "$(retained_stock_field inherited_rails)" = false ] \
        && [ "$(retained_stock_field route_or_uart_opened)" = false ] \
        && [ "$(retained_stock_field watchdog_started)" = false ] \
        && [ "$(retained_stock_field watchdog_fd)" = absent-checked ] \
        && retained_early_daemon_relation_is_exact \
        && [ "$(retained_stock_field stock_tree_revalidated)" = true ] \
        && [ "$(retained_stock_field gpio437_engaged)" = true ] \
        && [ "$(retained_stock_field supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(retained_stock_field supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(retained_stock_field supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
        && [ "$(retained_stock_field supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
        && [ "$(retained_stock_field supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$(retained_stock_field supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
        && [ "$(retained_stock_field supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(retained_stock_field bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(retained_stock_field bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
        && [ "$(retained_stock_field bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$(retained_stock_field bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$(retained_stock_field bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
        && [ "$(retained_stock_field bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
        && [ "$(retained_stock_field bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$(retained_stock_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(retained_stock_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(retained_stock_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(retained_stock_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(retained_stock_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(retained_stock_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(retained_stock_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(retained_stock_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(retained_stock_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(retained_stock_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(retained_stock_field persistent_mutation)" = false ] \
        && [ "$(retained_stock_field publication)" = no-clobber-hard-link-after-fsync ]
}

retained_early_daemon_relation_is_exact() {
    EARLY_SCHEMA=$(retained_stock_field schema) || return 1
    DAEMON_PID=$(retained_stock_field daemon_pid) || return 1
    DAEMON_START=$(retained_stock_field daemon_start) || return 1
    DAEMON_PPID=$(retained_stock_field daemon_ppid) || return 1
    valid_pid_start "$DAEMON_PID" "$DAEMON_START" \
        && valid_uint "$DAEMON_PPID" \
        && [ "$(retained_stock_field daemon_exe)" = "$TRIAL_BIN" ] \
        && ! process_matches "$DAEMON_PID" "$DAEMON_START" || return 1
    case "$EARLY_SCHEMA" in
        dcentos.s19k-stock-owner-retained-runtime-binding-not-admitted/v1)
            [ "$DAEMON_PPID" = 1 ] \
                && [ "$CHILD_PID:$CHILD_START" = 0:0 ] \
                && ! process_matches "$WRAPPER_PID" "$WRAPPER_START"
            ;;
        dcentos.s19k-stock-owner-retained-before-live-identity/v1)
            [ "$DAEMON_PID" = "$CHILD_PID" ] \
                && [ "$DAEMON_START" = "$CHILD_START" ] || return 1
            if [ "$DAEMON_PPID" = 1 ]; then
                ! process_matches "$WRAPPER_PID" "$WRAPPER_START"
            else
                [ "$DAEMON_PPID" = "$WRAPPER_PID" ]
            fi
            ;;
        *) return 1 ;;
    esac
}

retained_stock_receipt_is_exact() {
    ACTIVE_EVIDENCE=${1:-$ACTIVE}
    SCHEMA=$(retained_stock_field schema) || return 1
    case "$SCHEMA" in
        dcentos.s19k-stock-owner-retained/v2)
            retained_magic_closed_receipt_is_exact "$ACTIVE_EVIDENCE"
            ;;
        dcentos.s19k-stock-owner-retained-prewatchdog/v1)
            retained_prewatchdog_receipt_is_exact "$ACTIVE_EVIDENCE"
            ;;
        dcentos.s19k-stock-owner-retained-runtime-binding-not-admitted/v1|dcentos.s19k-stock-owner-retained-before-live-identity/v1)
            retained_early_receipt_is_exact "$ACTIVE_EVIDENCE"
            ;;
        *) return 1 ;;
    esac
}

terminal_handoff_field() {
    KEY=$1
    COUNT=$(grep -c "^$KEY=" "$TERMINAL_HANDOFF_RECEIPT" 2>/dev/null || true)
    [ "$COUNT" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$TERMINAL_HANDOFF_RECEIPT"
}

terminal_handoff_receipt_is_exact() {
    ACTIVE_EVIDENCE=${1:-$ACTIVE}
    TERMINAL_DEPLOY_MODE=$(active_field_at "$ACTIVE_EVIDENCE" deploy_mode) || return 1
    case "$TERMINAL_DEPLOY_MODE" in
        install-custody-safeoff)
            EXPECTED_TERMINAL_HANDOFF_SCHEMA=dcentos.s19k-install-custody-terminal-safeoff/v1
            EXPECTED_TERMINAL_HANDOFF_DISPOSITION=install-custody-terminal-safeoff
            EXPECTED_TERMINAL_RESETS=not-attempted
            ;;
        mining-on-passthrough|handoff-no-work|bounded-work-proof|endurance-work-proof)
            EXPECTED_TERMINAL_HANDOFF_SCHEMA=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1
            EXPECTED_TERMINAL_HANDOFF_DISPOSITION=terminal-safeoff-partial-stock-owner
            EXPECTED_TERMINAL_RESETS=454:0,455:0,456:0
            ;;
        *) return 1 ;;
    esac
    is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && is_regular_nonsymlink "$ACTIVE_EVIDENCE" \
        && [ "$(wc -l < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')" -eq 53 ] \
        && [ "$(terminal_handoff_field schema)" = "$EXPECTED_TERMINAL_HANDOFF_SCHEMA" ] \
        && [ "$(terminal_handoff_field disposition)" = "$EXPECTED_TERMINAL_HANDOFF_DISPOSITION" ] \
        && [ "$(terminal_handoff_field runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(terminal_handoff_field runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(terminal_handoff_field terminal_safeoff)" = true ] \
        && [ "$(terminal_handoff_field watchdog_magic_close)" = true ] \
        && [ "$(terminal_handoff_field watchdog_worker_joined)" = true ] \
        && [ "$(terminal_handoff_field resets)" = "$EXPECTED_TERMINAL_RESETS" ] \
        && [ "$(terminal_handoff_field psu)" = 437:1 ] \
        && [ "$(terminal_handoff_field inherited_rails)" = true ] \
        && [ "$(terminal_handoff_field supervisor_signal_attempted)" = true ] \
        && valid_bool "$(terminal_handoff_field supervisor_gone)" \
        && valid_bool "$(terminal_handoff_field child_signal_attempted)" \
        && valid_bool "$(terminal_handoff_field child_gone)" \
        && valid_bool "$(terminal_handoff_field global_stock_absence)" \
        && valid_bool "$(terminal_handoff_field replacement_or_ambiguity)" \
        && [ "$(terminal_handoff_field remnant_authority)" = all-thread-ptrace-or-pidfd-recovery-only ] \
        && valid_stock_lease_kind "$(terminal_handoff_field supervisor_lease_kind)" \
        && valid_stock_lease_kind "$(terminal_handoff_field child_lease_kind)" \
        && [ "$(terminal_handoff_field supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(terminal_handoff_field supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(terminal_handoff_field supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
        && [ "$(terminal_handoff_field supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
        && [ "$(terminal_handoff_field supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$(terminal_handoff_field supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
        && [ "$(terminal_handoff_field supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(terminal_handoff_field supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(terminal_handoff_field bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(terminal_handoff_field bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(terminal_handoff_field bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
        && [ "$(terminal_handoff_field bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$(terminal_handoff_field bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$(terminal_handoff_field bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
        && [ "$(terminal_handoff_field bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
        && [ "$(terminal_handoff_field bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$(terminal_handoff_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(terminal_handoff_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(terminal_handoff_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(terminal_handoff_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(terminal_handoff_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(terminal_handoff_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(terminal_handoff_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(terminal_handoff_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(terminal_handoff_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(terminal_handoff_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(terminal_handoff_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(terminal_handoff_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(terminal_handoff_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(terminal_handoff_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(terminal_handoff_field persistent_mutation)" = false ] \
        && [ "$(terminal_handoff_field publication)" = no-clobber-hard-link-after-fsync ] \
        && terminal_handoff_leg_relation_is_exact
}

terminal_handoff_leg_relation_is_exact() {
    SUP_GONE=$(terminal_handoff_field supervisor_gone) || return 1
    CHILD_GONE=$(terminal_handoff_field child_gone) || return 1
    GLOBAL_ABSENT=$(terminal_handoff_field global_stock_absence) || return 1
    if [ "$SUP_GONE" = true ]; then
        [ "$(terminal_handoff_field supervisor_remnant)" = absent ] || return 1
    else
        case "$(terminal_handoff_field supervisor_remnant)" in
            ambiguous-do-not-signal|original-lifetime-outcome-unknown) ;;
            *) return 1 ;;
        esac
    fi
    if [ "$CHILD_GONE" = true ]; then
        [ "$(terminal_handoff_field child_remnant)" = absent ] || return 1
    else
        case "$(terminal_handoff_field child_remnant)" in
            ambiguous-do-not-signal|original-lifetime-outcome-unknown) ;;
            *) return 1 ;;
        esac
    fi
    [ "$GLOBAL_ABSENT" != true ] || {
        [ "$SUP_GONE" = true ] && [ "$CHILD_GONE" = true ] \
            && [ "$(terminal_handoff_field replacement_or_ambiguity)" = false ]
    }
}

admit_terminal_handoff_obligation() {
    verify_all_bound_files \
        && admit_runtime_lock_owner \
        && terminal_handoff_receipt_is_exact \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_dcentrald_thread_is_live \
        && no_watchdog_fd_is_live || {
            echo "ERROR: terminal partial-handoff obligation/state revalidation failed; custody remains" >&2
            return 1
        }
}

load_bound_runtime_active_static_from() {
    ACTIVE_EVIDENCE=$1
    is_regular_nonsymlink "$ACTIVE_EVIDENCE" \
        && [ "$(wc -l < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" -eq 40 ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" schema)" = dcentos.s19k-tmp-runtime/v5 ] || return 1
    RECEIPT_PHASE=$(active_field_at "$ACTIVE_EVIDENCE" phase) || return 1
    case "$RECEIPT_PHASE" in
        launch-pending-or-recovery-required|child-live-or-recovery-required) ;;
        *) return 1 ;;
    esac
    [ "$(active_field_at "$ACTIVE_EVIDENCE" persistent_mutation)" = false ] \
        && is_handoff_deploy_mode "$(active_field_at "$ACTIVE_EVIDENCE" deploy_mode)" \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(active_field_at "$ACTIVE_EVIDENCE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] || return 1
    WRAPPER_PID=$(active_field_at "$ACTIVE_EVIDENCE" wrapper_pid) || return 1
    WRAPPER_START=$(active_field_at "$ACTIVE_EVIDENCE" wrapper_start) || return 1
    CHILD_PID=$(active_field_at "$ACTIVE_EVIDENCE" child_pid) || return 1
    CHILD_START=$(active_field_at "$ACTIVE_EVIDENCE" child_start) || return 1
    BOUND_SUPERVISOR_PID=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_pid) || return 1
    BOUND_SUPERVISOR_START=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_start) || return 1
    BOUND_SUPERVISOR_PPID=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_ppid) || return 1
    BOUND_SUPERVISOR_PGRP=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_pgrp) || return 1
    BOUND_SUPERVISOR_SESSION=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_session) || return 1
    BOUND_SUPERVISOR_EXE=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_exe) || return 1
    BOUND_SUPERVISOR_CMDLINE_SHA=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_cmdline_sha256) || return 1
    BOUND_SUPERVISOR_CMDLINE_BYTES=$(active_field_at "$ACTIVE_EVIDENCE" supervisor_cmdline_bytes) || return 1
    BOUND_BOSMINER_PID=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_pid) || return 1
    BOUND_BOSMINER_START=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_start) || return 1
    BOUND_BOSMINER_PPID=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_ppid) || return 1
    BOUND_BOSMINER_PGRP=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_pgrp) || return 1
    BOUND_BOSMINER_SESSION=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_session) || return 1
    BOUND_BOSMINER_EXE=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_exe) || return 1
    BOUND_BOSMINER_CMDLINE_SHA=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_cmdline_sha256) || return 1
    BOUND_BOSMINER_CMDLINE_BYTES=$(active_field_at "$ACTIVE_EVIDENCE" bosminer_cmdline_bytes) || return 1
    BOUND_STOCK_PIDFILE_PATH=$(active_field_at "$ACTIVE_EVIDENCE" stock_pidfile_path) || return 1
    BOUND_STOCK_PIDFILE_SHA=$(active_field_at "$ACTIVE_EVIDENCE" stock_pidfile_sha256) || return 1
    BOUND_STOCK_PIDFILE_BYTES=$(active_field_at "$ACTIVE_EVIDENCE" stock_pidfile_bytes) || return 1
    EXPECTED_LIVE_IDENTITY_PROFILE=$(active_field_at "$ACTIVE_EVIDENCE" live_identity_profile) || return 1
    EXPECTED_LIVE_IDENTITY_SHA=$(active_field_at "$ACTIVE_EVIDENCE" live_identity_sha256) || return 1
    valid_pid_start "$WRAPPER_PID" "$WRAPPER_START" \
        && valid_pid_start "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" \
        && valid_pid_start "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" \
        && [ "$BOUND_SUPERVISOR_PPID" = 1 ] \
        && [ "$BOUND_BOSMINER_PPID" = "$BOUND_SUPERVISOR_PID" ] \
        && valid_uint "$BOUND_SUPERVISOR_PGRP" \
        && valid_uint "$BOUND_SUPERVISOR_SESSION" \
        && [ "$BOUND_SUPERVISOR_PGRP" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$BOUND_SUPERVISOR_SESSION" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$BOUND_SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$BOUND_BOSMINER_EXE" = /usr/bin/bosminer ] \
        && valid_sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA" \
        && valid_size "$BOUND_SUPERVISOR_CMDLINE_BYTES" \
        && valid_sha256 "$BOUND_BOSMINER_CMDLINE_SHA" \
        && valid_size "$BOUND_BOSMINER_CMDLINE_BYTES" \
        && [ "$BOUND_STOCK_PIDFILE_PATH" = /var/run/bosminer.pid ] \
        && valid_sha256 "$BOUND_STOCK_PIDFILE_SHA" \
        && valid_size "$BOUND_STOCK_PIDFILE_BYTES" \
        && valid_live_identity_profile "$EXPECTED_LIVE_IDENTITY_PROFILE" \
        && valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" || return 1
    case "$RECEIPT_PHASE" in
        launch-pending-or-recovery-required) [ "$CHILD_PID:$CHILD_START" = 0:0 ] ;;
        child-live-or-recovery-required) valid_pid_start "$CHILD_PID" "$CHILD_START" ;;
    esac
}

is_handoff_deploy_mode() {
    case "$1" in
        mining-on-passthrough|install-custody-safeoff|handoff-no-work|bounded-work-proof|endurance-work-proof) return 0 ;;
        *) return 1 ;;
    esac
}

endurance_private_directory_is_exact() {
    ENDURANCE_DIRECTORY=$1
    [ -d "$ENDURANCE_DIRECTORY" ] && [ ! -L "$ENDURANCE_DIRECTORY" ] || return 1
    ENDURANCE_DIRECTORY_LS=$(ls -ldn "$ENDURANCE_DIRECTORY" 2>/dev/null || true)
    set -- $ENDURANCE_DIRECTORY_LS
    [ "${1:-}" = drwx------ ] && [ "${3:-}" = 0 ] && [ "${4:-}" = 0 ]
}

endurance_sequence_is_valid() {
    case "$1" in ''|*[!0-9]*|0[0-9]*) return 1 ;; esac
    [ "$1" -le 1561 ]
}

endurance_segment_path() {
    ENDURANCE_SEGMENT_SUFFIX=$(printf '%06d' "$1") || return 1
    printf '%s/segment.%s.kv\n' "$ENDURANCE_SEGMENT_DIR" "$ENDURANCE_SEGMENT_SUFFIX"
}

endurance_ack_path() {
    ENDURANCE_ACK_SUFFIX=$(printf '%06d' "$1") || return 1
    printf '%s/ack.%s.kv\n' "$ENDURANCE_ACK_DIR" "$ENDURANCE_ACK_SUFFIX"
}

endurance_regular_evidence_is_exact() {
    ENDURANCE_FILE=$1
    ENDURANCE_MAX_BYTES=$2
    is_regular_nonsymlink "$ENDURANCE_FILE" || return 1
    ENDURANCE_FILE_LS=$(ls -lni "$ENDURANCE_FILE" 2>/dev/null || true)
    set -- $ENDURANCE_FILE_LS
    [ "${2:-}" = -rw------- ] && [ "${4:-}" = 0 ] && [ "${5:-}" = 0 ] \
        && valid_size "$(wc -c < "$ENDURANCE_FILE" | tr -d ' \t\r\n')" \
        && [ "$(wc -c < "$ENDURANCE_FILE" | tr -d ' \t\r\n')" -le "$ENDURANCE_MAX_BYTES" ]
}

endurance_runtime_source_is_exact() {
    if is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field_at "$ACTIVE" schema 2>/dev/null || true)" = dcentos.s19k-tmp-runtime/v5 ]; then
        ENDURANCE_ACTIVE_EVIDENCE=$ACTIVE
    elif is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" schema 2>/dev/null || true)" = dcentos.s19k-tmp-runtime/v5 ]; then
        ENDURANCE_ACTIVE_EVIDENCE=$PRE_SAFEOFF_ACTIVE
    else
        return 1
    fi
    load_bound_runtime_active_static_from "$ENDURANCE_ACTIVE_EVIDENCE" \
        && [ "$(active_field_at "$ENDURANCE_ACTIVE_EVIDENCE" deploy_mode)" = endurance-work-proof ]
}

endurance_collection_namespace_is_exact() {
    verify_all_bound_files \
        && endurance_runtime_source_is_exact \
        && endurance_private_directory_is_exact "$ENDURANCE_EVIDENCE_DIR" \
        && endurance_private_directory_is_exact "$ENDURANCE_SEGMENT_DIR" \
        && endurance_private_directory_is_exact "$ENDURANCE_ACK_DIR"
}

endurance_previous_manifest_sha() {
    ENDURANCE_CURRENT_SEQUENCE=$1
    if [ "$ENDURANCE_CURRENT_SEQUENCE" -eq 0 ]; then
        printf '%s\n' e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        return 0
    fi
    ENDURANCE_PREVIOUS_SEQUENCE=$((ENDURANCE_CURRENT_SEQUENCE - 1))
    ENDURANCE_PREVIOUS_ACK=$(endurance_ack_path "$ENDURANCE_PREVIOUS_SEQUENCE") || return 1
    endurance_regular_evidence_is_exact "$ENDURANCE_PREVIOUS_ACK" 4096 \
        && [ "$(wc -l < "$ENDURANCE_PREVIOUS_ACK" | tr -d ' \t\r\n')" -eq 9 ] \
        && [ "$(startup_field_at "$ENDURANCE_PREVIOUS_ACK" schema)" = dcentos.s19k-endurance-segment-ack/v1 ] \
        && [ "$(startup_field_at "$ENDURANCE_PREVIOUS_ACK" sequence)" = "$ENDURANCE_PREVIOUS_SEQUENCE" ] \
        && [ "$(startup_field_at "$ENDURANCE_PREVIOUS_ACK" publication)" = no-clobber-hard-link-after-fsync ] \
        || return 1
    ENDURANCE_PREVIOUS_MANIFEST=$(startup_field_at "$ENDURANCE_PREVIOUS_ACK" off_target_manifest_sha256) || return 1
    valid_sha256 "$ENDURANCE_PREVIOUS_MANIFEST" || return 1
    printf '%s\n' "$ENDURANCE_PREVIOUS_MANIFEST"
}

load_bound_runtime_active_from() {
    ACTIVE_EVIDENCE=$1
    load_bound_runtime_active_static_from "$ACTIVE_EVIDENCE" \
        && is_regular_nonsymlink "$BOUND_STOCK_PIDFILE_PATH" \
        && [ "$(sha256sum "$BOUND_STOCK_PIDFILE_PATH" | awk '{print $1}')" = "$BOUND_STOCK_PIDFILE_SHA" ] \
        && [ "$(wc -c < "$BOUND_STOCK_PIDFILE_PATH" | tr -d ' \t\r\n')" = "$BOUND_STOCK_PIDFILE_BYTES" ] \
        && [ "$(cat "$BOUND_STOCK_PIDFILE_PATH")" = "$BOUND_SUPERVISOR_PID" ]
}

retained_retirement_state_is_exact() {
    ACTIVE_EVIDENCE=$1
    OWNER_EVIDENCE=$2
    load_bound_runtime_active_from "$ACTIVE_EVIDENCE" \
        && admit_runtime_lock_owner_record_at "$OWNER_EVIDENCE" \
        && runtime_lock_owner_matches_current \
        && retained_stock_receipt_is_exact "$ACTIVE_EVIDENCE" \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && no_dcentrald_thread_is_live \
        && no_watchdog_fd_is_live
}

retire_stock_owner_retained_obligation() {
    if is_regular_nonsymlink "$ACTIVE" && [ ! -e "$RETIRED_ACTIVE" ] && [ ! -L "$RETIRED_ACTIVE" ]; then
        ACTIVE_EVIDENCE=$ACTIVE
    elif is_regular_nonsymlink "$RETIRED_ACTIVE" && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
        ACTIVE_EVIDENCE=$RETIRED_ACTIVE
    else
        echo "ERROR: retained-stock retirement ACTIVE phase is ambiguous" >&2
        return 1
    fi
    if is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" && [ ! -e "$RETIRED_OWNER" ] && [ ! -L "$RETIRED_OWNER" ]; then
        OWNER_EVIDENCE=$RUNTIME_LOCK_OWNER
    elif is_regular_nonsymlink "$RETIRED_OWNER" && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        OWNER_EVIDENCE=$RETIRED_OWNER
    else
        echo "ERROR: retained-stock retirement OWNER phase is ambiguous" >&2
        return 1
    fi
    retained_retirement_state_is_exact "$ACTIVE_EVIDENCE" "$OWNER_EVIDENCE" || {
        echo "ERROR: retained-stock retirement phase failed exact revalidation; custody remains" >&2
        return 1
    }
    if [ "$ACTIVE_EVIDENCE" = "$ACTIVE" ]; then
        mv "$ACTIVE" "$RETIRED_ACTIVE" || return 1
        ACTIVE_EVIDENCE=$RETIRED_ACTIVE
        retained_retirement_state_is_exact "$ACTIVE_EVIDENCE" "$OWNER_EVIDENCE" || return 1
    fi
    if [ "$OWNER_EVIDENCE" = "$RUNTIME_LOCK_OWNER" ]; then
        mv "$RUNTIME_LOCK_OWNER" "$RETIRED_OWNER" || return 1
        OWNER_EVIDENCE=$RETIRED_OWNER
        retained_retirement_state_is_exact "$ACTIVE_EVIDENCE" "$OWNER_EVIDENCE" || return 1
    fi
    if [ ! -e "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ]; then
        echo "S19k Track-1 retained-stock custody was already retired; immutable evidence revalidated"
        return 0
    fi
    [ -d "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ] || return 1
    # The only canonical child was moved above. Any hidden/extra entry is an
    # ambiguous crash state and deliberately prevents lock release.
    rmdir "$RUNTIME_LOCK" || return 1
    echo "S19k Track-1 retained-stock custody retired from active lock after exact typed receipt"
}

write_active_content() {
    ACTIVE_DEST=$1
    PHASE=$2
    case "$PHASE" in
        launch-pending-or-recovery-required|child-live-or-recovery-required) ;;
        *) echo "ERROR: invalid runtime receipt phase" >&2; return 1 ;;
    esac
    {
        printf 'schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'phase=%s\n' "$PHASE"
        printf 'wrapper_pid=%s\n' "$$"
        printf 'wrapper_start=%s\n' "$SELF_START"
        printf 'child_pid=%s\n' "$CHILD_PID"
        printf 'child_start=%s\n' "$CHILD_START"
        printf 'supervisor_pid=%s\n' "$BOUND_SUPERVISOR_PID"
        printf 'supervisor_start=%s\n' "$BOUND_SUPERVISOR_START"
        printf 'supervisor_ppid=%s\n' "$BOUND_SUPERVISOR_PPID"
        printf 'supervisor_pgrp=%s\n' "$BOUND_SUPERVISOR_PGRP"
        printf 'supervisor_session=%s\n' "$BOUND_SUPERVISOR_SESSION"
        printf 'supervisor_exe=%s\n' "$BOUND_SUPERVISOR_EXE"
        printf 'supervisor_cmdline_sha256=%s\n' "$BOUND_SUPERVISOR_CMDLINE_SHA"
        printf 'supervisor_cmdline_bytes=%s\n' "$BOUND_SUPERVISOR_CMDLINE_BYTES"
        printf 'bosminer_pid=%s\n' "$BOUND_BOSMINER_PID"
        printf 'bosminer_start=%s\n' "$BOUND_BOSMINER_START"
        printf 'bosminer_ppid=%s\n' "$BOUND_BOSMINER_PPID"
        printf 'bosminer_pgrp=%s\n' "$BOUND_BOSMINER_PGRP"
        printf 'bosminer_session=%s\n' "$BOUND_BOSMINER_SESSION"
        printf 'bosminer_exe=%s\n' "$BOUND_BOSMINER_EXE"
        printf 'bosminer_cmdline_sha256=%s\n' "$BOUND_BOSMINER_CMDLINE_SHA"
        printf 'bosminer_cmdline_bytes=%s\n' "$BOUND_BOSMINER_CMDLINE_BYTES"
        printf 'stock_pidfile_path=%s\n' "$BOUND_STOCK_PIDFILE_PATH"
        printf 'stock_pidfile_sha256=%s\n' "$BOUND_STOCK_PIDFILE_SHA"
        printf 'stock_pidfile_bytes=%s\n' "$BOUND_STOCK_PIDFILE_BYTES"
        printf 'binary_sha256=%s\n' "$BIN_SHA"
        printf 'binary_bytes=%s\n' "$BIN_BYTES"
        printf 'config_sha256=%s\n' "$CFG_SHA"
        printf 'config_bytes=%s\n' "$CFG_BYTES"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'deploy_mode=%s\n' "$DEPLOY_MODE"
        printf 'persistent_mutation=false\n'
    } > "$ACTIVE_DEST"
    chmod 600 "$ACTIVE_DEST"
}

write_active() {
    PHASE=$1
    TMP="$ACTIVE.tmp.$$.${SELF_START}"
    [ ! -e "$TMP" ] && [ ! -L "$TMP" ] || return 1
    write_active_content "$TMP" "$PHASE" || return 1
    mv -f "$TMP" "$ACTIVE"
}

write_startup_j0_owner_prefork() {
    [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] || return 1
    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || return 1
    valid_sha256 "$DAEMON_CMDLINE_SHA" && valid_size "$DAEMON_CMDLINE_BYTES" \
        && valid_sha256 "$DAEMON_ENVIRONMENT_SHA" \
        && valid_size "$DAEMON_ENVIRONMENT_BYTES" \
        && [ "$DAEMON_ENVIRONMENT_COUNT" -eq 10 ] || return 1
    WRAPPER_PPID=$(process_ppid "$$")
    valid_uint "$WRAPPER_PPID" || return 1
    WRAPPER_COMM=$(cat "/proc/$$/comm" 2>/dev/null || true)
    WRAPPER_EXE=$(readlink "/proc/$$/exe" 2>/dev/null || true)
    WRAPPER_CMDLINE_SHA=$(sha256sum "/proc/$$/cmdline" 2>/dev/null | awk '{print $1}')
    WRAPPER_CMDLINE_BYTES=$(wc -c < "/proc/$$/cmdline" 2>/dev/null | tr -d ' \t\r\n')
    [ -n "$WRAPPER_COMM" ] && [ -n "$WRAPPER_EXE" ] \
        && valid_sha256 "$WRAPPER_CMDLINE_SHA" \
        && valid_size "$WRAPPER_CMDLINE_BYTES" || return 1
    TX_PREIMAGE="$TRIAL_DIR/.runtime_startup_tx.tmp.$$.${SELF_START}"
    J0_SCRATCH="$TRIAL_DIR/.runtime_startup_j0.tmp.$$.${SELF_START}"
    [ ! -e "$TX_PREIMAGE" ] && [ ! -L "$TX_PREIMAGE" ] \
        && [ ! -e "$J0_SCRATCH" ] && [ ! -L "$J0_SCRATCH" ] || return 1
    {
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'wrapper=%s:%s:%s\n' "$$" "$SELF_START" "$WRAPPER_PPID"
        printf 'daemon_cmdline=%s:%s\n' "$DAEMON_CMDLINE_SHA" "$DAEMON_CMDLINE_BYTES"
        printf 'daemon_environment=%s:%s:%s\n' "$DAEMON_ENVIRONMENT_SHA" "$DAEMON_ENVIRONMENT_BYTES" "$DAEMON_ENVIRONMENT_COUNT"
        printf 'active=not-published\n'
        printf 'runner=%s:%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody=%s:%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'restart_helper=%s:%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity=%s:%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'stock_tree=%s:%s:%s:%s\n' "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START"
        printf 'gpio_raw=437:0,454:0,455:1,456:1\n'
    } > "$TX_PREIMAGE"
    chmod 600 "$TX_PREIMAGE"
    STARTUP_TX_ID=$(sha256sum "$TX_PREIMAGE" | awk '{print $1}')
    rm -f "$TX_PREIMAGE"
    valid_sha256 "$STARTUP_TX_ID" || return 1
    {
        printf 'schema=dcentos.s19k-startup-j0-prefork/v1\n'
        printf 'transaction_id=%s\n' "$STARTUP_TX_ID"
        printf 'ordinal=0\n'
        printf 'predecessor_schema=none\n'
        printf 'predecessor_sha256=none\n'
        printf 'predecessor_bytes=0\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runtime_active_path=not-published\n'
        printf 'runtime_active_sha256=none\n'
        printf 'runtime_active_bytes=0\n'
        printf 'runtime_active_phase=not-published\n'
        printf 'runtime_owner_path=%s\n' "$RUNTIME_LOCK_OWNER"
        printf 'runtime_owner_binding=self-hardlink\n'
        printf 'fifo_path=%s\n' "$STARTUP_FIFO"
        printf 'fifo_mnt_id=%s\n' "$FIFO_MNT_ID"
        printf 'fifo_inode=%s\n' "$FIFO_INODE"
        printf 'fifo_mode=%s\n' "$FIFO_MODE"
        printf 'fifo_uid=%s\n' "$FIFO_UID"
        printf 'fifo_gid=%s\n' "$FIFO_GID"
        printf 'writer_role=wrapper\n'
        printf 'writer_pid=%s\n' "$$"
        printf 'writer_start=%s\n' "$SELF_START"
        printf 'writer_ppid=%s\n' "$WRAPPER_PPID"
        printf 'daemon_pid=0\n'
        printf 'daemon_start=0\n'
        printf 'wrapper_pid=%s\n' "$$"
        printf 'wrapper_start=%s\n' "$SELF_START"
        printf 'wrapper_ppid=%s\n' "$WRAPPER_PPID"
        printf 'wrapper_comm=%s\n' "$WRAPPER_COMM"
        printf 'wrapper_exe=%s\n' "$WRAPPER_EXE"
        printf 'wrapper_cmdline_sha256=%s\n' "$WRAPPER_CMDLINE_SHA"
        printf 'wrapper_cmdline_bytes=%s\n' "$WRAPPER_CMDLINE_BYTES"
        printf 'expected_daemon_cmdline_sha256=%s\n' "$DAEMON_CMDLINE_SHA"
        printf 'expected_daemon_cmdline_bytes=%s\n' "$DAEMON_CMDLINE_BYTES"
        printf 'daemon_environment_sha256=%s\n' "$DAEMON_ENVIRONMENT_SHA"
        printf 'daemon_environment_bytes=%s\n' "$DAEMON_ENVIRONMENT_BYTES"
        printf 'daemon_environment_count=%s\n' "$DAEMON_ENVIRONMENT_COUNT"
        printf 'supervisor_pid=%s\n' "$BOUND_SUPERVISOR_PID"
        printf 'supervisor_start=%s\n' "$BOUND_SUPERVISOR_START"
        printf 'supervisor_ppid=%s\n' "$BOUND_SUPERVISOR_PPID"
        printf 'supervisor_pgrp=%s\n' "$BOUND_SUPERVISOR_PGRP"
        printf 'supervisor_session=%s\n' "$BOUND_SUPERVISOR_SESSION"
        printf 'supervisor_exe=%s\n' "$BOUND_SUPERVISOR_EXE"
        printf 'supervisor_cmdline_sha256=%s\n' "$BOUND_SUPERVISOR_CMDLINE_SHA"
        printf 'supervisor_cmdline_bytes=%s\n' "$BOUND_SUPERVISOR_CMDLINE_BYTES"
        printf 'bosminer_pid=%s\n' "$BOUND_BOSMINER_PID"
        printf 'bosminer_start=%s\n' "$BOUND_BOSMINER_START"
        printf 'bosminer_ppid=%s\n' "$BOUND_BOSMINER_PPID"
        printf 'bosminer_pgrp=%s\n' "$BOUND_BOSMINER_PGRP"
        printf 'bosminer_session=%s\n' "$BOUND_BOSMINER_SESSION"
        printf 'bosminer_exe=%s\n' "$BOUND_BOSMINER_EXE"
        printf 'bosminer_cmdline_sha256=%s\n' "$BOUND_BOSMINER_CMDLINE_SHA"
        printf 'bosminer_cmdline_bytes=%s\n' "$BOUND_BOSMINER_CMDLINE_BYTES"
        printf 'stock_pidfile_path=%s\n' "$BOUND_STOCK_PIDFILE_PATH"
        printf 'stock_pidfile_sha256=%s\n' "$BOUND_STOCK_PIDFILE_SHA"
        printf 'stock_pidfile_bytes=%s\n' "$BOUND_STOCK_PIDFILE_BYTES"
        printf 'binary_sha256=%s\n' "$BIN_SHA"
        printf 'binary_bytes=%s\n' "$BIN_BYTES"
        printf 'config_sha256=%s\n' "$CFG_SHA"
        printf 'config_bytes=%s\n' "$CFG_BYTES"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'gpio_raw=437:0,454:0,455:1,456:1\n'
        printf 'watchdog_start_intent=false\n'
        printf 'watchdog_armed=false\n'
        printf 'signal_attempted=false\n'
        printf 'inherited_rails=false\n'
        printf 'route_or_uart_opened=false\n'
        printf 'hardware_opened=false\n'
        printf 'parent_release=false\n'
        printf 'persistent_mutation=false\n'
        printf 'publication=no-clobber-hard-link-after-fsync\n'
    } > "$J0_SCRATCH"
    chmod 600 "$J0_SCRATCH"
    process_matches "$$" "$SELF_START" \
        && [ "$(process_ppid "$$")" = "$WRAPPER_PPID" ] \
        && [ "$(cat "/proc/$$/comm" 2>/dev/null || true)" = "$WRAPPER_COMM" ] \
        && [ "$(readlink "/proc/$$/exe" 2>/dev/null || true)" = "$WRAPPER_EXE" ] \
        && [ "$(sha256sum "/proc/$$/cmdline" 2>/dev/null | awk '{print $1}')" = "$WRAPPER_CMDLINE_SHA" ] \
        && [ "$(wc -c < "/proc/$$/cmdline" 2>/dev/null | tr -d ' \t\r\n')" = "$WRAPPER_CMDLINE_BYTES" ] || return 1
    publish_no_clobber_journal_keep_source "$J0_SCRATCH" "$RUNTIME_LOCK_OWNER" || return 1
    rm -f "$J0_SCRATCH"
    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]
}

startup_field_at() {
    STARTUP_FILE=$1
    STARTUP_KEY=$2
    STARTUP_COUNT=$(grep -c "^$STARTUP_KEY=" "$STARTUP_FILE" 2>/dev/null || true)
    [ "$STARTUP_COUNT" -eq 1 ] || return 1
    sed -n "s/^$STARTUP_KEY=//p" "$STARTUP_FILE"
}

startup_ordered_keys_are_exact() {
    STARTUP_FILE=$1
    EXPECTED_KEYS_SHA=$2
    [ "$(awk -F= '{print $1}' "$STARTUP_FILE" 2>/dev/null | sha256sum | awk '{print $1}')" = "$EXPECTED_KEYS_SHA" ]
}

require_startup_j1_for_child() {
    is_regular_nonsymlink "$STARTUP_C1" \
        && [ "$(wc -l < "$STARTUP_C1" | tr -d ' \t\r\n')" -eq 47 ] \
        && startup_ordered_keys_are_exact "$STARTUP_C1" "$STARTUP_C1_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_C1" schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transaction_id)" = "$STARTUP_TX_ID" ] \
        && [ "$(startup_field_at "$STARTUP_C1" ordinal)" = 1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_sha256)" = "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_bytes)" = "$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_sha256)" = "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_bytes)" = "$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_pid)" = "$CHILD_PID" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_start)" = "$CHILD_START" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_ppid)" = "$$" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_comm)" = "$(cat "/proc/$CHILD_PID/comm" 2>/dev/null || true)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_exe)" = "$(readlink "/proc/$CHILD_PID/exe" 2>/dev/null || true)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(sha256sum "/proc/$CHILD_PID/cmdline" 2>/dev/null | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(runtime_lock_field expected_daemon_cmdline_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_bytes)" = "$(wc -c < "/proc/$CHILD_PID/cmdline" 2>/dev/null | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_bytes)" = "$(runtime_lock_field expected_daemon_cmdline_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_sha256)" = "$(runtime_lock_field daemon_environment_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_bytes)" = "$(runtime_lock_field daemon_environment_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_count)" = 10 ] \
        && [ "$(startup_field_at "$STARTUP_C1" bootstrap_fd_set)" = stdio-only ] \
        && [ "$(startup_field_at "$STARTUP_C1" stdin_path)" = /dev/null ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && valid_uint "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" \
        && valid_uint "$(startup_field_at "$STARTUP_C1" transcript_inode)" \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_gid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_C1" pdeathsig_scope)" = process-lifetime ] \
        && is_regular_nonsymlink "$STARTUP_J1" \
        && [ "$(wc -l < "$STARTUP_J1" | tr -d ' \t\r\n')" -eq 87 ] \
        && startup_ordered_keys_are_exact "$STARTUP_J1" "$STARTUP_J1_J2_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_J1" schema)" = dcentos.s19k-startup-j1-daemon-blocked/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J1" transaction_id)" = "$STARTUP_TX_ID" ] \
        && [ "$(startup_field_at "$STARTUP_J1" ordinal)" = 2 ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_sha256)" = "$(sha256sum "$STARTUP_C1" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_bytes)" = "$(wc -c < "$STARTUP_C1" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_path)" = not-published ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_sha256)" = none ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_bytes)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_phase)" = not-published ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_sha256)" = "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_bytes)" = "$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_role)" = daemon-blocked ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_pid)" = "$CHILD_PID" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_start)" = "$CHILD_START" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_ppid)" = "$$" ] \
        && [ "$(startup_field_at "$STARTUP_J1" daemon_pid)" = "$CHILD_PID" ] \
        && [ "$(startup_field_at "$STARTUP_J1" daemon_start)" = "$CHILD_START" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_pid)" = "$$" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_start)" = "$SELF_START" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_ppid)" = "$(runtime_lock_field wrapper_ppid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_comm)" = "$(runtime_lock_field wrapper_comm)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_exe)" = "$(runtime_lock_field wrapper_exe)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_cmdline_sha256)" = "$(runtime_lock_field wrapper_cmdline_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_cmdline_bytes)" = "$(runtime_lock_field wrapper_cmdline_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_J1" pdeathsig_scope)" = process-lifetime ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_path)" = "$(runtime_lock_field fifo_path)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_mnt_id)" = "$(runtime_lock_field fifo_mnt_id)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_inode)" = "$(runtime_lock_field fifo_inode)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_mode)" = "$(runtime_lock_field fifo_mode)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_uid)" = "$(runtime_lock_field fifo_uid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_gid)" = "$(runtime_lock_field fifo_gid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_reader_held)" = true ] \
        && [ "$(startup_field_at "$STARTUP_J1" bootstrap_fd_set)" = stdio-plus-single-fifo ] \
        && valid_uint "$(startup_field_at "$STARTUP_J1" fifo_reader_fd)" \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_reader_fd)" -gt 2 ] \
        && [ "$(startup_field_at "$STARTUP_J1" stdin_path)" = "$(startup_field_at "$STARTUP_C1" stdin_path)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_path)" = "$(startup_field_at "$STARTUP_C1" transcript_path)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_mnt_id)" = "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_inode)" = "$(startup_field_at "$STARTUP_C1" transcript_inode)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_mode)" = "$(startup_field_at "$STARTUP_C1" transcript_mode)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_uid)" = "$(startup_field_at "$STARTUP_C1" transcript_uid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" transcript_gid)" = "$(startup_field_at "$STARTUP_C1" transcript_gid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(startup_field_at "$STARTUP_J1" supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(startup_field_at "$STARTUP_J1" bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(startup_field_at "$STARTUP_J1" bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(startup_field_at "$STARTUP_J1" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_J1" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_J1" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_J1" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_J1" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(startup_field_at "$STARTUP_J1" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(startup_field_at "$STARTUP_J1" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_J1" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(startup_field_at "$STARTUP_J1" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" parent_release)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" publication)" = no-clobber-hard-link-after-fsync ] \
        && exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START" || return 1
    for KEY in wrapper_pid wrapper_start wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes binary_sha256 binary_bytes; do
        [ "$(startup_field_at "$STARTUP_C1" "$KEY")" = "$(runtime_lock_field "$KEY")" ] || return 1
    done
    for KEY in watchdog_start_intent watchdog_armed signal_attempted inherited_rails route_or_uart_opened hardware_opened parent_release persistent_mutation; do
        [ "$(startup_field_at "$STARTUP_C1" "$KEY")" = false ] || return 1
    done
    [ "$(startup_field_at "$STARTUP_C1" publication)" = no-clobber-hard-link-after-fsync ]
}

write_startup_j2_and_release() {
    require_startup_j1_for_child || return 1
    exact_current_wrapper_matches_j0 "$RUNTIME_LOCK_OWNER" || return 1
    [ "$(active_field phase)" = child-live-or-recovery-required ] || return 1
    # Reparenting (parent exit) is kernel-controlled; J2's writer_ppid must
    # equal the J0/J1 journal value, not a post-orphan live ppid.
    WRAPPER_PPID=$(startup_field_at "$STARTUP_J1" wrapper_ppid)
    valid_uint "$WRAPPER_PPID" || return 1
    ACTIVE_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    ACTIVE_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    OWNER_SHA=$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')
    OWNER_BYTES=$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')
    J1_SHA=$(sha256sum "$STARTUP_J1" | awk '{print $1}')
    J1_BYTES=$(wc -c < "$STARTUP_J1" | tr -d ' \t\r\n')
    J2_SCRATCH="$TRIAL_DIR/.runtime_startup_j2.tmp.$$.${SELF_START}"
    RELEASE_SCRATCH="$TRIAL_DIR/.runtime_startup_release.tmp.$$.${SELF_START}"
    [ ! -e "$J2_SCRATCH" ] && [ ! -L "$J2_SCRATCH" ] \
        && [ ! -e "$RELEASE_SCRATCH" ] && [ ! -L "$RELEASE_SCRATCH" ] || return 1
    {
        printf 'schema=dcentos.s19k-startup-j2-child-bound/v1\n'
        printf 'transaction_id=%s\n' "$STARTUP_TX_ID"
        printf 'ordinal=3\n'
        printf 'predecessor_schema=dcentos.s19k-startup-j1-daemon-blocked/v1\n'
        printf 'predecessor_sha256=%s\n' "$J1_SHA"
        printf 'predecessor_bytes=%s\n' "$J1_BYTES"
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runtime_active_path=%s\n' "$ACTIVE"
        printf 'runtime_active_sha256=%s\n' "$ACTIVE_SHA"
        printf 'runtime_active_bytes=%s\n' "$ACTIVE_BYTES"
        printf 'runtime_active_phase=child-live-or-recovery-required\n'
        printf 'runtime_owner_path=%s\n' "$RUNTIME_LOCK_OWNER"
        printf 'runtime_owner_sha256=%s\n' "$OWNER_SHA"
        printf 'runtime_owner_bytes=%s\n' "$OWNER_BYTES"
        printf 'writer_role=wrapper\n'
        printf 'writer_pid=%s\n' "$$"
        printf 'writer_start=%s\n' "$SELF_START"
        printf 'writer_ppid=%s\n' "$WRAPPER_PPID"
        printf 'daemon_pid=%s\n' "$CHILD_PID"
        printf 'daemon_start=%s\n' "$CHILD_START"
        for KEY in wrapper_pid wrapper_start wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes pdeathsig pdeathsig_scope fifo_path fifo_mnt_id fifo_inode fifo_mode fifo_uid fifo_gid fifo_reader_held bootstrap_fd_set fifo_reader_fd stdin_path transcript_path transcript_mnt_id transcript_inode transcript_mode transcript_uid transcript_gid supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_schema live_identity_profile live_identity_sha256 gpio_raw; do
            printf '%s=%s\n' "$KEY" "$(startup_field_at "$STARTUP_J1" "$KEY")"
        done
        printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\ninherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\nparent_release=false\npersistent_mutation=false\n'
        printf 'publication=no-clobber-hard-link-after-fsync\n'
    } > "$J2_SCRATCH"
    chmod 600 "$J2_SCRATCH"
    publish_no_clobber_journal "$J2_SCRATCH" "$STARTUP_J2" || return 1
    J2_SHA=$(sha256sum "$STARTUP_J2" | awk '{print $1}')
    J2_BYTES=$(wc -c < "$STARTUP_J2" | tr -d ' \t\r\n')
    {
        printf 'schema=dcentos.s19k-startup-release/v1\n'
        printf 'transaction_id=%s\n' "$STARTUP_TX_ID"
        printf 'ordinal=3-release\n'
        printf 'predecessor_schema=dcentos.s19k-startup-j2-child-bound/v1\n'
        printf 'predecessor_sha256=%s\n' "$J2_SHA"
        printf 'predecessor_bytes=%s\n' "$J2_BYTES"
        printf 'runtime_active_sha256=%s\n' "$ACTIVE_SHA"
        printf 'runtime_active_bytes=%s\n' "$ACTIVE_BYTES"
        printf 'runtime_owner_sha256=%s\n' "$OWNER_SHA"
        printf 'runtime_owner_bytes=%s\n' "$OWNER_BYTES"
        printf 'daemon_pid=%s\n' "$CHILD_PID"
        printf 'daemon_start=%s\n' "$CHILD_START"
        printf 'wrapper_pid=%s\n' "$$"
        printf 'wrapper_start=%s\n' "$SELF_START"
        for KEY in wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes pdeathsig pdeathsig_scope; do
            printf '%s=%s\n' "$KEY" "$(startup_field_at "$STARTUP_J1" "$KEY")"
        done
        printf 'gpio_raw=437:0,454:0,455:1,456:1\n'
        printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\ninherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\n'
        printf 'parent_release=true\n'
        printf 'publication=no-clobber-hard-link-after-fsync\n'
    } > "$RELEASE_SCRATCH"
    chmod 600 "$RELEASE_SCRATCH"
    exact_current_wrapper_matches_j0 "$RUNTIME_LOCK_OWNER" \
        && exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START" || return 1
    publish_no_clobber_journal "$RELEASE_SCRATCH" "$STARTUP_RELEASE"
}

load_bound_startup_j0_static_from() {
    OWNER_EVIDENCE=$1
    is_regular_nonsymlink "$OWNER_EVIDENCE" \
        && [ "$(wc -l < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" -eq 79 ] \
        && startup_ordered_keys_are_exact "$OWNER_EVIDENCE" "$STARTUP_J0_KEYS_SHA" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" ordinal)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_schema)" = none ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_sha256)" = none ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" predecessor_bytes)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_path)" = not-published ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_sha256)" = none ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_bytes)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_active_phase)" = not-published ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" runtime_owner_binding)" = self-hardlink ] \
        && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mnt_id)" \
        && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_inode)" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mode)" = prw------- ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_uid)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_gid)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_role)" = wrapper ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_pid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_start)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" writer_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" ] \
        && valid_pid_start "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" \
        && valid_uint "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" \
        && [ -n "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_comm)" ] \
        && [ -n "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_exe)" ] \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_sha256)" \
        && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_bytes)" \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_sha256)" \
        && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_bytes)" \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_sha256)" \
        && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_bytes)" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_count)" = 10 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_pid)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_start)" = 0 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ] \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_sha256)" \
        && valid_size "$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_bytes)" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && valid_live_identity_profile "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_profile)" \
        && valid_sha256 "$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_sha256)" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" watchdog_start_intent)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" watchdog_armed)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" signal_attempted)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" inherited_rails)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" route_or_uart_opened)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" hardware_opened)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" parent_release)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" persistent_mutation)" = false ] \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    BOUND_SUPERVISOR_PID=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_pid) || return 1
    BOUND_SUPERVISOR_START=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_start) || return 1
    BOUND_SUPERVISOR_PPID=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_ppid) || return 1
    BOUND_SUPERVISOR_PGRP=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_pgrp) || return 1
    BOUND_SUPERVISOR_SESSION=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_session) || return 1
    BOUND_SUPERVISOR_EXE=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_exe) || return 1
    BOUND_SUPERVISOR_CMDLINE_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_cmdline_sha256) || return 1
    BOUND_SUPERVISOR_CMDLINE_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" supervisor_cmdline_bytes) || return 1
    BOUND_BOSMINER_PID=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_pid) || return 1
    BOUND_BOSMINER_START=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_start) || return 1
    BOUND_BOSMINER_PPID=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_ppid) || return 1
    BOUND_BOSMINER_PGRP=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_pgrp) || return 1
    BOUND_BOSMINER_SESSION=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_session) || return 1
    BOUND_BOSMINER_EXE=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_exe) || return 1
    BOUND_BOSMINER_CMDLINE_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_cmdline_sha256) || return 1
    BOUND_BOSMINER_CMDLINE_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" bosminer_cmdline_bytes) || return 1
    BOUND_STOCK_PIDFILE_PATH=$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_path) || return 1
    BOUND_STOCK_PIDFILE_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_sha256) || return 1
    BOUND_STOCK_PIDFILE_BYTES=$(runtime_lock_field_at "$OWNER_EVIDENCE" stock_pidfile_bytes) || return 1
    EXPECTED_LIVE_IDENTITY_PROFILE=$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_profile) || return 1
    EXPECTED_LIVE_IDENTITY_SHA=$(runtime_lock_field_at "$OWNER_EVIDENCE" live_identity_sha256) || return 1
    valid_pid_start "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" \
        && valid_pid_start "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" \
        && [ "$BOUND_BOSMINER_PPID" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$BOUND_SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$BOUND_BOSMINER_EXE" = /usr/bin/bosminer ] \
        && valid_sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA" \
        && valid_size "$BOUND_SUPERVISOR_CMDLINE_BYTES" \
        && valid_sha256 "$BOUND_BOSMINER_CMDLINE_SHA" \
        && valid_size "$BOUND_BOSMINER_CMDLINE_BYTES" \
        && valid_live_identity_profile "$EXPECTED_LIVE_IDENTITY_PROFILE" \
        && valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_path)" = "$TRIAL_DIR/.startup_fifo.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ]
}

load_bound_startup_j0_from() {
    OWNER_EVIDENCE=$1
    load_bound_startup_j0_static_from "$OWNER_EVIDENCE" \
        && admit_runtime_lock_owner_record_at "$OWNER_EVIDENCE" \
        && runtime_lock_owner_matches_current
}

startup_c1_is_exact_for_recovery() {
    OWNER_EVIDENCE=$1
    is_regular_nonsymlink "$STARTUP_C1" \
        && [ "$(wc -l < "$STARTUP_C1" | tr -d ' \t\r\n')" -eq 47 ] \
        && startup_ordered_keys_are_exact "$STARTUP_C1" "$STARTUP_C1_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_C1" schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" ordinal)" = 1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" predecessor_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_C1" runtime_owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && valid_pid_start "$(startup_field_at "$STARTUP_C1" child_pid)" "$(startup_field_at "$STARTUP_C1" child_start)" \
        && [ "$(startup_field_at "$STARTUP_C1" child_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_comm)" = dcentrald ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_exe)" = "$TRIAL_BIN" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_sha256)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_cmdline_bytes)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" expected_daemon_cmdline_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_sha256)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_bytes)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" daemon_environment_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_C1" child_environment_count)" = 10 ] \
        && [ "$(startup_field_at "$STARTUP_C1" bootstrap_fd_set)" = stdio-only ] \
        && [ "$(startup_field_at "$STARTUP_C1" stdin_path)" = /dev/null ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_path)" = "$TRIAL_DIR/.startup_daemon_transcript.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && valid_uint "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" \
        && valid_uint "$(startup_field_at "$STARTUP_C1" transcript_inode)" \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_gid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_C1" pdeathsig_scope)" = process-lifetime ] || return 1
    for KEY in wrapper_pid wrapper_start wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes binary_sha256 binary_bytes; do
        [ "$(startup_field_at "$STARTUP_C1" "$KEY")" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" "$KEY")" ] || return 1
    done
    for KEY in watchdog_start_intent watchdog_armed signal_attempted inherited_rails route_or_uart_opened hardware_opened parent_release persistent_mutation; do
        [ "$(startup_field_at "$STARTUP_C1" "$KEY")" = false ] || return 1
    done
    [ "$(startup_field_at "$STARTUP_C1" publication)" = no-clobber-hard-link-after-fsync ]
}

startup_j1_is_exact_for_recovery() {
    OWNER_EVIDENCE=$1
    startup_c1_is_exact_for_recovery "$OWNER_EVIDENCE" \
        && is_regular_nonsymlink "$STARTUP_J1" \
        && [ "$(wc -l < "$STARTUP_J1" | tr -d ' \t\r\n')" -eq 87 ] \
        && startup_ordered_keys_are_exact "$STARTUP_J1" "$STARTUP_J1_J2_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_J1" schema)" = dcentos.s19k-startup-j1-daemon-blocked/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J1" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" ordinal)" = 2 ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_sha256)" = "$(sha256sum "$STARTUP_C1" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" predecessor_bytes)" = "$(wc -c < "$STARTUP_C1" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_path)" = not-published ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_sha256)" = none ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_bytes)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_active_phase)" = not-published ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_path)" = "$RUNTIME_LOCK_OWNER" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" runtime_owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_role)" = daemon-blocked ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_pid)" = "$(startup_field_at "$STARTUP_J1" daemon_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_start)" = "$(startup_field_at "$STARTUP_J1" daemon_start)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" writer_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_pid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" wrapper_start)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && [ "$(startup_field_at "$STARTUP_J1" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_J1" pdeathsig_scope)" = process-lifetime ] \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_reader_held)" = true ] \
        && [ "$(startup_field_at "$STARTUP_J1" bootstrap_fd_set)" = stdio-plus-single-fifo ] \
        && valid_uint "$(startup_field_at "$STARTUP_J1" fifo_reader_fd)" \
        && [ "$(startup_field_at "$STARTUP_J1" fifo_reader_fd)" -gt 2 ] || return 1
    for KEY in stdin_path transcript_path transcript_mnt_id transcript_inode transcript_mode transcript_uid transcript_gid; do
        [ "$(startup_field_at "$STARTUP_J1" "$KEY")" = "$(startup_field_at "$STARTUP_C1" "$KEY")" ] || return 1
    done
    for KEY in wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes fifo_path fifo_mnt_id fifo_inode fifo_mode fifo_uid fifo_gid supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_schema live_identity_profile live_identity_sha256 gpio_raw; do
        [ "$(startup_field_at "$STARTUP_J1" "$KEY")" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" "$KEY")" ] || return 1
    done
    [ "$(startup_field_at "$STARTUP_J1" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" parent_release)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J1" publication)" = no-clobber-hard-link-after-fsync ]
}

startup_j2_is_exact_for_recovery() {
    OWNER_EVIDENCE=$1
    ACTIVE_EVIDENCE=$2
    startup_j1_is_exact_for_recovery "$OWNER_EVIDENCE" \
        && is_regular_nonsymlink "$STARTUP_J2" \
        && [ "$(wc -l < "$STARTUP_J2" | tr -d ' \t\r\n')" -eq 87 ] \
        && startup_ordered_keys_are_exact "$STARTUP_J2" "$STARTUP_J1_J2_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_J2" schema)" = dcentos.s19k-startup-j2-child-bound/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J2" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_J2" ordinal)" = 3 ] \
        && [ "$(startup_field_at "$STARTUP_J2" predecessor_schema)" = dcentos.s19k-startup-j1-daemon-blocked/v1 ] \
        && [ "$(startup_field_at "$STARTUP_J2" predecessor_sha256)" = "$(sha256sum "$STARTUP_J1" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" predecessor_bytes)" = "$(wc -c < "$STARTUP_J1" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_active_path)" = "$ACTIVE" ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_active_phase)" = child-live-or-recovery-required ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" runtime_owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_J2" writer_role)" = wrapper ] \
        && [ "$(startup_field_at "$STARTUP_J2" writer_pid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_J2" writer_start)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && [ "$(startup_field_at "$STARTUP_J2" writer_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" ] \
        && [ "$(startup_field_at "$STARTUP_J2" daemon_pid)" = "$(active_field_at "$ACTIVE_EVIDENCE" child_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_J2" daemon_start)" = "$(active_field_at "$ACTIVE_EVIDENCE" child_start)" ] || return 1
    for KEY in wrapper_pid wrapper_start wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 wrapper_cmdline_bytes pdeathsig pdeathsig_scope fifo_path fifo_mnt_id fifo_inode fifo_mode fifo_uid fifo_gid fifo_reader_held bootstrap_fd_set fifo_reader_fd stdin_path transcript_path transcript_mnt_id transcript_inode transcript_mode transcript_uid transcript_gid supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_schema live_identity_profile live_identity_sha256 gpio_raw; do
        [ "$(startup_field_at "$STARTUP_J2" "$KEY")" = "$(startup_field_at "$STARTUP_J1" "$KEY")" ] || return 1
    done
    [ "$(startup_field_at "$STARTUP_J2" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" parent_release)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$STARTUP_J2" publication)" = no-clobber-hard-link-after-fsync ]
}

startup_release_is_exact_for_recovery() {
    OWNER_EVIDENCE=$1
    ACTIVE_EVIDENCE=$2
    is_regular_nonsymlink "$STARTUP_RELEASE" \
        && [ "$(wc -l < "$STARTUP_RELEASE" | tr -d ' \t\r\n')" -eq 30 ] \
        && startup_ordered_keys_are_exact "$STARTUP_RELEASE" "$STARTUP_RELEASE_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_RELEASE" schema)" = dcentos.s19k-startup-release/v1 ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" ordinal)" = 3-release ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" predecessor_schema)" = dcentos.s19k-startup-j2-child-bound/v1 ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" predecessor_sha256)" = "$(sha256sum "$STARTUP_J2" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" predecessor_bytes)" = "$(wc -c < "$STARTUP_J2" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" runtime_active_sha256)" = "$(sha256sum "$ACTIVE_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" runtime_active_bytes)" = "$(wc -c < "$ACTIVE_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" runtime_owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" runtime_owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" daemon_pid)" = "$(active_field_at "$ACTIVE_EVIDENCE" child_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" daemon_start)" = "$(active_field_at "$ACTIVE_EVIDENCE" child_start)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_pid)" = "$(active_field_at "$ACTIVE_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_start)" = "$(active_field_at "$ACTIVE_EVIDENCE" wrapper_start)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_ppid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_ppid)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_comm)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_comm)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_exe)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_exe)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_cmdline_sha256)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_sha256)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" wrapper_cmdline_bytes)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_cmdline_bytes)" ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" pdeathsig_scope)" = process-lifetime ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" parent_release)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RELEASE" publication)" = no-clobber-hard-link-after-fsync ]
}

startup_parent_lost_j0_is_exact_for_recovery() {
    OWNER_EVIDENCE=$1
    is_regular_nonsymlink "$STARTUP_PARENT_LOST" \
        && [ "$(wc -l < "$STARTUP_PARENT_LOST" | tr -d ' \t\r\n')" -eq 27 ] \
        && startup_ordered_keys_are_exact "$STARTUP_PARENT_LOST" "$STARTUP_PARENT_LOST_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" schema)" = dcentos.s19k-startup-parent-lost/v2 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" highest_phase)" = j0 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" predecessor_schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" predecessor_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" predecessor_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" runtime_owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" runtime_owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && valid_pid_start "$(startup_field_at "$STARTUP_PARENT_LOST" daemon_pid)" "$(startup_field_at "$STARTUP_PARENT_LOST" daemon_start)" \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" daemon_ppid)" = 1 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" wrapper_pid)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" wrapper_start)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" pdeathsig)" = 9 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" pdeathsig_scope)" = process-lifetime ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" runtime_active)" = not-published ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" stock_tree_revalidated)" = true ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" gpio_stock_baseline_revalidated)" = true ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" gpio437_engaged)" = true ] \
        && [ "$(startup_field_at "$STARTUP_PARENT_LOST" publication)" = no-clobber-hard-link-after-fsync ]
}

startup_digest_or_none() {
    DIGEST_PATH=$1
    if [ -e "$DIGEST_PATH" ] || [ -L "$DIGEST_PATH" ]; then
        is_regular_nonsymlink "$DIGEST_PATH" || return 1
        STARTUP_DIGEST_SHA=$(sha256sum "$DIGEST_PATH" | awk '{print $1}')
        STARTUP_DIGEST_BYTES=$(wc -c < "$DIGEST_PATH" | tr -d ' \t\r\n')
        valid_sha256 "$STARTUP_DIGEST_SHA" && valid_size "$STARTUP_DIGEST_BYTES"
    else
        STARTUP_DIGEST_SHA=none
        STARTUP_DIGEST_BYTES=0
    fi
}

capture_startup_transcript_for_terminal() {
    OWNER_EVIDENCE=$1
    STARTUP_TRANSCRIPT_PATH="$TRIAL_DIR/.startup_daemon_transcript.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)"
    is_regular_nonsymlink "$STARTUP_TRANSCRIPT_PATH" || return 1
    exec 8<> "$STARTUP_TRANSCRIPT_PATH" || return 1
    STARTUP_TRANSCRIPT_TARGET_INITIAL=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
    STARTUP_TRANSCRIPT_LS_INITIAL=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
    set -- $STARTUP_TRANSCRIPT_LS_INITIAL
    STARTUP_TRANSCRIPT_INODE_INITIAL=${1:-}
    STARTUP_TRANSCRIPT_MODE_INITIAL=${2:-}
    STARTUP_TRANSCRIPT_UID_INITIAL=${4:-}
    STARTUP_TRANSCRIPT_GID_INITIAL=${5:-}
    STARTUP_TRANSCRIPT_MNT_ID_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
    STARTUP_TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/8" 2>/dev/null | awk '{print $1}')
    STARTUP_TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/8" 2>/dev/null | tr -d ' \t\r\n')
    STARTUP_TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
    STARTUP_TRANSCRIPT_LS=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
    set -- $STARTUP_TRANSCRIPT_LS
    STARTUP_TRANSCRIPT_INODE=${1:-}
    STARTUP_TRANSCRIPT_MODE=${2:-}
    STARTUP_TRANSCRIPT_UID=${4:-}
    STARTUP_TRANSCRIPT_GID=${5:-}
    STARTUP_TRANSCRIPT_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
    exec 8>&-
    [ "$STARTUP_TRANSCRIPT_TARGET_INITIAL" = "$STARTUP_TRANSCRIPT_PATH" ] \
        && [ "$STARTUP_TRANSCRIPT_TARGET" = "$STARTUP_TRANSCRIPT_TARGET_INITIAL" ] \
        && [ "$STARTUP_TRANSCRIPT_INODE" = "$STARTUP_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$STARTUP_TRANSCRIPT_MODE" = "$STARTUP_TRANSCRIPT_MODE_INITIAL" ] \
        && [ "$STARTUP_TRANSCRIPT_UID" = "$STARTUP_TRANSCRIPT_UID_INITIAL" ] \
        && [ "$STARTUP_TRANSCRIPT_GID" = "$STARTUP_TRANSCRIPT_GID_INITIAL" ] \
        && [ "$STARTUP_TRANSCRIPT_MNT_ID" = "$STARTUP_TRANSCRIPT_MNT_ID_INITIAL" ] \
        && valid_uint "$STARTUP_TRANSCRIPT_MNT_ID" \
        && valid_uint "$STARTUP_TRANSCRIPT_INODE" \
        && [ "$STARTUP_TRANSCRIPT_MODE" = -rw------- ] \
        && [ "$STARTUP_TRANSCRIPT_UID" = 0 ] \
        && [ "$STARTUP_TRANSCRIPT_GID" = 0 ] || return 1
    valid_sha256 "$STARTUP_TRANSCRIPT_SHA" && valid_uint "$STARTUP_TRANSCRIPT_BYTES" || return 1
    if is_regular_nonsymlink "$STARTUP_C1"; then
        [ "$(startup_field_at "$STARTUP_C1" transcript_path)" = "$STARTUP_TRANSCRIPT_PATH" ] \
            && [ "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" = "$STARTUP_TRANSCRIPT_MNT_ID" ] \
            && [ "$(startup_field_at "$STARTUP_C1" transcript_inode)" = "$STARTUP_TRANSCRIPT_INODE" ] \
            && [ "$(startup_field_at "$STARTUP_C1" transcript_mode)" = 0600 ] \
            && [ "$(startup_field_at "$STARTUP_C1" transcript_uid)" = 0 ] \
            && [ "$(startup_field_at "$STARTUP_C1" transcript_gid)" = 0 ] || return 1
    fi
}

publish_startup_retire_terminal() {
    OWNER_EVIDENCE=$1
    ACTIVE_EVIDENCE=$2
    STARTUP_HIGHEST_PHASE=$3
    OWNER_SHA=$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')
    OWNER_BYTES=$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')
    startup_digest_or_none "$STARTUP_C1" || return 1
    C1_SHA=$STARTUP_DIGEST_SHA; C1_BYTES=$STARTUP_DIGEST_BYTES
    startup_digest_or_none "$STARTUP_J1" || return 1
    J1_SHA=$STARTUP_DIGEST_SHA; J1_BYTES=$STARTUP_DIGEST_BYTES
    if [ -n "$ACTIVE_EVIDENCE" ]; then
        startup_digest_or_none "$ACTIVE_EVIDENCE" || return 1
    else
        STARTUP_DIGEST_SHA=none; STARTUP_DIGEST_BYTES=0
    fi
    TERMINAL_ACTIVE_SHA=$STARTUP_DIGEST_SHA; TERMINAL_ACTIVE_BYTES=$STARTUP_DIGEST_BYTES
    startup_digest_or_none "$STARTUP_J2" || return 1
    J2_SHA=$STARTUP_DIGEST_SHA; J2_BYTES=$STARTUP_DIGEST_BYTES
    startup_digest_or_none "$STARTUP_RELEASE" || return 1
    RELEASE_SHA=$STARTUP_DIGEST_SHA; RELEASE_BYTES=$STARTUP_DIGEST_BYTES
    startup_digest_or_none "$STARTUP_PARENT_LOST" || return 1
    PARENT_LOST_SHA=$STARTUP_DIGEST_SHA; PARENT_LOST_BYTES=$STARTUP_DIGEST_BYTES
    capture_startup_transcript_for_terminal "$OWNER_EVIDENCE" || return 1
    TERMINAL_TMP="$TRIAL_DIR/.runtime_startup_retired_terminal.tmp.$$.${SELF_START}"
    [ ! -e "$TERMINAL_TMP" ] && [ ! -L "$TERMINAL_TMP" ] \
        && [ ! -e "$STARTUP_RETIRE_TERMINAL" ] && [ ! -L "$STARTUP_RETIRE_TERMINAL" ] || return 1
    {
        printf 'schema=dcentos.s19k-startup-retired-terminal/v1\n'
        printf 'transaction_id=%s\n' "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)"
        printf 'phase=startup-no-effect-retired\n'
        printf 'highest_phase=%s\n' "$STARTUP_HIGHEST_PHASE"
        printf 'owner_sha256=%s\nowner_bytes=%s\n' "$OWNER_SHA" "$OWNER_BYTES"
        printf 'c1_sha256=%s\nc1_bytes=%s\n' "$C1_SHA" "$C1_BYTES"
        printf 'j1_sha256=%s\nj1_bytes=%s\n' "$J1_SHA" "$J1_BYTES"
        printf 'active_sha256=%s\nactive_bytes=%s\n' "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES"
        printf 'j2_sha256=%s\nj2_bytes=%s\n' "$J2_SHA" "$J2_BYTES"
        printf 'release_sha256=%s\nrelease_bytes=%s\n' "$RELEASE_SHA" "$RELEASE_BYTES"
        printf 'parent_lost_sha256=%s\nparent_lost_bytes=%s\n' "$PARENT_LOST_SHA" "$PARENT_LOST_BYTES"
        printf 'fifo_path=%s\n' "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_path)"
        printf 'fifo_mnt_id=%s\n' "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mnt_id)"
        printf 'fifo_inode=%s\n' "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_inode)"
        printf 'transcript_path=%s\ntranscript_mnt_id=%s\ntranscript_inode=%s\n' "$STARTUP_TRANSCRIPT_PATH" "$STARTUP_TRANSCRIPT_MNT_ID" "$STARTUP_TRANSCRIPT_INODE"
        printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\n'
        printf 'transcript_sha256=%s\ntranscript_bytes=%s\n' "$STARTUP_TRANSCRIPT_SHA" "$STARTUP_TRANSCRIPT_BYTES"
        printf 'supervisor_pid=%s\nsupervisor_start=%s\n' "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START"
        printf 'supervisor_ppid=%s\nsupervisor_pgrp=%s\nsupervisor_session=%s\n' "$BOUND_SUPERVISOR_PPID" "$BOUND_SUPERVISOR_PGRP" "$BOUND_SUPERVISOR_SESSION"
        printf 'supervisor_exe=%s\nsupervisor_cmdline_sha256=%s\nsupervisor_cmdline_bytes=%s\n' "$BOUND_SUPERVISOR_EXE" "$BOUND_SUPERVISOR_CMDLINE_SHA" "$BOUND_SUPERVISOR_CMDLINE_BYTES"
        printf 'bosminer_pid=%s\nbosminer_start=%s\n' "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START"
        printf 'bosminer_ppid=%s\nbosminer_pgrp=%s\nbosminer_session=%s\n' "$BOUND_BOSMINER_PPID" "$BOUND_BOSMINER_PGRP" "$BOUND_BOSMINER_SESSION"
        printf 'bosminer_exe=%s\nbosminer_cmdline_sha256=%s\nbosminer_cmdline_bytes=%s\n' "$BOUND_BOSMINER_EXE" "$BOUND_BOSMINER_CMDLINE_SHA" "$BOUND_BOSMINER_CMDLINE_BYTES"
        printf 'stock_pidfile_path=%s\nstock_pidfile_sha256=%s\nstock_pidfile_bytes=%s\n' "$BOUND_STOCK_PIDFILE_PATH" "$BOUND_STOCK_PIDFILE_SHA" "$BOUND_STOCK_PIDFILE_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_profile=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\ninherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\n'
        printf 'stock_tree_revalidated=true\nlive_identity_revalidated=true\n'
        printf 'gpio_raw=437:0,454:0,455:1,456:1\ngpio_stock_baseline_revalidated=true\ngpio437_engaged=true\n'
        printf 'dcentrald_all_threads_absent=true\nwatchdog_all_threads_absent=true\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$TERMINAL_TMP"
    chmod 600 "$TERMINAL_TMP"
    publish_no_clobber_journal "$TERMINAL_TMP" "$STARTUP_RETIRE_TERMINAL"
}

startup_prefix_pending_active_is_source_bound() {
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 47 ] \
        && startup_ordered_keys_are_exact "$ACTIVE" "$STARTUP_PREFIX_PENDING_KEYS_SHA" \
        && [ "$(active_field schema)" = dcentos.s19k-startup-prefix-stock-restart-pending/v1 ] \
        && [ "$(active_field phase)" = terminal-safeoff-stock-restart-pending ] \
        && [ "$(active_field terminal)" = true ] \
        && [ "$(active_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(active_field source_receipt_schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
        && [ "$(active_field source_receipt_path)" = "$STARTUP_PRESAFEOFF_SOURCE" ] \
        && is_regular_nonsymlink "$STARTUP_PRESAFEOFF_SOURCE" \
        && [ "$(active_field source_receipt_sha256)" = "$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')" ] \
        && [ "$(active_field source_receipt_bytes)" = "$(wc -c < "$STARTUP_PRESAFEOFF_SOURCE" | tr -d ' \t\r\n')" ] \
        && [ "$(active_field transaction_id)" = "$(startup_field_at "$STARTUP_PRESAFEOFF_SOURCE" transaction_id)" ] \
        && [ "$(active_field highest_phase)" = "$(startup_field_at "$STARTUP_PRESAFEOFF_SOURCE" highest_phase)" ]
}

historical_active_is_exact_at() {
    HISTORICAL_PATH=$1
    HISTORICAL_SHA=$2
    HISTORICAL_BYTES=$3
    is_regular_nonsymlink "$HISTORICAL_PATH" \
        && [ "$(sha256sum "$HISTORICAL_PATH" | awk '{print $1}')" = "$HISTORICAL_SHA" ] \
        && [ "$(wc -c < "$HISTORICAL_PATH" | tr -d ' \t\r\n')" = "$HISTORICAL_BYTES" ]
}

same_historical_active_inode() {
    HISTORICAL_ONE=$1
    HISTORICAL_TWO=$2
    HISTORICAL_SHA=$3
    HISTORICAL_BYTES=$4
    historical_active_is_exact_at "$HISTORICAL_ONE" "$HISTORICAL_SHA" "$HISTORICAL_BYTES" \
        && historical_active_is_exact_at "$HISTORICAL_TWO" "$HISTORICAL_SHA" "$HISTORICAL_BYTES" || return 1
    HISTORICAL_ONE_LS=$(ls -lniL "$HISTORICAL_ONE" 2>/dev/null || true)
    set -- $HISTORICAL_ONE_LS
    HISTORICAL_ONE_INODE=${1:-}
    HISTORICAL_TWO_LS=$(ls -lniL "$HISTORICAL_TWO" 2>/dev/null || true)
    set -- $HISTORICAL_TWO_LS
    HISTORICAL_TWO_INODE=${1:-}
    valid_uint "$HISTORICAL_ONE_INODE" \
        && [ "$HISTORICAL_TWO_INODE" = "$HISTORICAL_ONE_INODE" ]
}

startup_retire_terminal_is_exact() {
    OWNER_EVIDENCE=$1
    is_regular_nonsymlink "$STARTUP_RETIRE_TERMINAL" \
        && [ "$(wc -l < "$STARTUP_RETIRE_TERMINAL" | tr -d ' \t\r\n')" -eq 75 ] \
        && startup_ordered_keys_are_exact "$STARTUP_RETIRE_TERMINAL" "$STARTUP_RETIRE_TERMINAL_KEYS_SHA" \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" schema)" = dcentos.s19k-startup-retired-terminal/v1 ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transaction_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" phase)" = startup-no-effect-retired ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" owner_sha256)" = "$(sha256sum "$OWNER_EVIDENCE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" owner_bytes)" = "$(wc -c < "$OWNER_EVIDENCE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" fifo_path)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_path)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" fifo_mnt_id)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_mnt_id)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" fifo_inode)" = "$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_inode)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_pid)" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_start)" = "$BOUND_SUPERVISOR_START" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_ppid)" = "$BOUND_SUPERVISOR_PPID" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_pgrp)" = "$BOUND_SUPERVISOR_PGRP" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_session)" = "$BOUND_SUPERVISOR_SESSION" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_exe)" = "$BOUND_SUPERVISOR_EXE" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_cmdline_sha256)" = "$BOUND_SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" supervisor_cmdline_bytes)" = "$BOUND_SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_pid)" = "$BOUND_BOSMINER_PID" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_start)" = "$BOUND_BOSMINER_START" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_ppid)" = "$BOUND_BOSMINER_PPID" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_pgrp)" = "$BOUND_BOSMINER_PGRP" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_session)" = "$BOUND_BOSMINER_SESSION" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_exe)" = "$BOUND_BOSMINER_EXE" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_cmdline_sha256)" = "$BOUND_BOSMINER_CMDLINE_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" bosminer_cmdline_bytes)" = "$BOUND_BOSMINER_CMDLINE_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_pidfile_path)" = "$BOUND_STOCK_PIDFILE_PATH" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_pidfile_sha256)" = "$BOUND_STOCK_PIDFILE_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_pidfile_bytes)" = "$BOUND_STOCK_PIDFILE_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_path)" = "$TRIAL_DIR/.startup_daemon_transcript.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)" ] \
        && valid_uint "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_mnt_id)" \
        && valid_uint "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_inode)" \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_gid)" = 0 ] \
        && valid_sha256 "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_sha256)" \
        && valid_uint "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_bytes)" \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" stock_tree_revalidated)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" live_identity_revalidated)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" gpio_stock_baseline_revalidated)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" gpio437_engaged)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" dcentrald_all_threads_absent)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" watchdog_all_threads_absent)" = true ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    for PREFIX_KEY in c1 j1 active j2 release parent_lost; do
        PAIR_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "${PREFIX_KEY}_sha256") || return 1
        PAIR_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "${PREFIX_KEY}_bytes") || return 1
        if [ "$PAIR_SHA:$PAIR_BYTES" != none:0 ]; then
            valid_sha256 "$PAIR_SHA" && valid_size "$PAIR_BYTES" || return 1
        fi
    done
    HIGHEST=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" highest_phase) || return 1
    C1_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" c1_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" c1_bytes)
    J1_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" j1_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" j1_bytes)
    ACTIVE_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" active_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" active_bytes)
    J2_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" j2_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" j2_bytes)
    RELEASE_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" release_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" release_bytes)
    PL_PAIR=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" parent_lost_sha256):$(startup_field_at "$STARTUP_RETIRE_TERMINAL" parent_lost_bytes)
    case "$HIGHEST" in
        j0) [ "$C1_PAIR:$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0:none:0:none:0 ] ;;
        parent-lost-j0) [ "$C1_PAIR:$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR" = none:0:none:0:none:0:none:0:none:0 ] && [ "$PL_PAIR" != none:0 ] ;;
        c1) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0:none:0 ] ;;
        j1) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0 ] ;;
        active) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0 ] ;;
        j2) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR" != none:0 ] && [ "$RELEASE_PAIR:$PL_PAIR" = none:0:none:0 ] ;;
        release) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR" != none:0 ] && [ "$RELEASE_PAIR" != none:0 ] && [ "$PL_PAIR" = none:0 ] ;;
        *) return 1 ;;
    esac || return 1
    TERMINAL_PENDING_ACTIVE=false
    if [ -e "$ACTIVE" ] || [ -L "$ACTIVE" ]; then
        if startup_prefix_pending_active_is_source_bound; then
            TERMINAL_PENDING_ACTIVE=true
        elif ! is_regular_nonsymlink "$ACTIVE"; then
            return 1
        fi
    fi
    if [ "$ACTIVE_PAIR" != none:0 ]; then
        TERMINAL_ACTIVE_SHA=${ACTIVE_PAIR%%:*}
        TERMINAL_ACTIVE_BYTES=${ACTIVE_PAIR#*:}
        if [ "$TERMINAL_PENDING_ACTIVE" = true ]; then
            historical_active_is_exact_at "$STARTUP_PRESAFEOFF_ACTIVE" "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES" || return 1
            if [ -e "$STARTUP_RETIRED_ACTIVE" ] || [ -L "$STARTUP_RETIRED_ACTIVE" ]; then
                same_historical_active_inode "$STARTUP_PRESAFEOFF_ACTIVE" "$STARTUP_RETIRED_ACTIVE" \
                    "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES" || return 1
            fi
        else
            if historical_active_is_exact_at "$ACTIVE" "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES" \
                && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ]; then
                TERMINAL_ACTIVE_EVIDENCE=$ACTIVE
            elif historical_active_is_exact_at "$STARTUP_RETIRED_ACTIVE" "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES" \
                && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
                TERMINAL_ACTIVE_EVIDENCE=$STARTUP_RETIRED_ACTIVE
            else
                return 1
            fi
            if [ -e "$STARTUP_PRESAFEOFF_ACTIVE" ] || [ -L "$STARTUP_PRESAFEOFF_ACTIVE" ]; then
                same_historical_active_inode "$TERMINAL_ACTIVE_EVIDENCE" "$STARTUP_PRESAFEOFF_ACTIVE" \
                    "$TERMINAL_ACTIVE_SHA" "$TERMINAL_ACTIVE_BYTES" || return 1
            fi
        fi
    else
        [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ] \
            && [ ! -e "$STARTUP_PRESAFEOFF_ACTIVE" ] && [ ! -L "$STARTUP_PRESAFEOFF_ACTIVE" ] || return 1
        if [ "$TERMINAL_PENDING_ACTIVE" != true ]; then
            [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || return 1
        fi
    fi
}

consume_startup_companion_after_terminal() {
    COMPANION=$1
    SHA_KEY=$2
    BYTES_KEY=$3
    EXPECTED_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "$SHA_KEY") || return 1
    EXPECTED_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "$BYTES_KEY") || return 1
    if [ "$EXPECTED_SHA:$EXPECTED_BYTES" = none:0 ]; then
        [ ! -e "$COMPANION" ] && [ ! -L "$COMPANION" ]
        return
    fi
    if [ -e "$COMPANION" ] || [ -L "$COMPANION" ]; then
        is_regular_nonsymlink "$COMPANION" \
            && [ "$(sha256sum "$COMPANION" | awk '{print $1}')" = "$EXPECTED_SHA" ] \
            && [ "$(wc -c < "$COMPANION" | tr -d ' \t\r\n')" = "$EXPECTED_BYTES" ] \
            && rm -f "$COMPANION"
        return
    fi
    return 0
}

startup_cleanup_record_is_exact_at() {
    CLEANUP_EVIDENCE=$1
    is_regular_nonsymlink "$CLEANUP_EVIDENCE" \
        && [ "$(wc -l < "$CLEANUP_EVIDENCE" | tr -d ' \t\r\n')" -eq 64 ] \
        && startup_ordered_keys_are_exact "$CLEANUP_EVIDENCE" "$STARTUP_RETIRE_CLEANUP_KEYS_SHA" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" schema)" = dcentos.s19k-startup-retire-cleanup-commit/v1 ] \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" transaction_id)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" phase)" = startup-no-effect-cleanup-committed ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" terminal_schema)" = dcentos.s19k-startup-retired-terminal/v1 ] \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" terminal_sha256)" \
        && valid_size "$(startup_field_at "$CLEANUP_EVIDENCE" terminal_bytes)" \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" owner_sha256)" \
        && valid_size "$(startup_field_at "$CLEANUP_EVIDENCE" owner_bytes)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" residue_count)" = 0 ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" residue_manifest_sha256)" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" commit_source_path)" != '' ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" fifo_path)" != '' ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_path)" != '' ] \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_mnt_id)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_inode)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_gid)" = 0 ] \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_sha256)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" transcript_bytes)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_exe)" = /usr/bin/bos-tools ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_exe)" = /usr/bin/bosminer ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_ppid)" = "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_pid)" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)" = /var/run/bosminer.pid ] \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_sha256)" \
        && valid_size "$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_bytes)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && valid_live_identity_profile "$(startup_field_at "$CLEANUP_EVIDENCE" live_identity_profile)" \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" live_identity_sha256)" \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" watchdog_start_intent)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" watchdog_armed)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" signal_attempted)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" inherited_rails)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" route_or_uart_opened)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" hardware_opened)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$CLEANUP_EVIDENCE" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    case "$(startup_field_at "$CLEANUP_EVIDENCE" highest_phase)" in
        j0|parent-lost-j0|c1|j1|active|j2|release) ;;
        *) return 1 ;;
    esac
    valid_pid_start "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_pid)" "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_start)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_ppid)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_pgrp)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_session)" \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_cmdline_sha256)" \
        && valid_size "$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_cmdline_bytes)" \
        && valid_pid_start "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_pid)" "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_start)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_pgrp)" \
        && valid_uint "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_session)" \
        && valid_sha256 "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_cmdline_sha256)" \
        && valid_size "$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_cmdline_bytes)" || return 1
    CLEANUP_ACTIVE_PAIR=$(startup_field_at "$CLEANUP_EVIDENCE" active_sha256):$(startup_field_at "$CLEANUP_EVIDENCE" active_bytes)
    [ "$CLEANUP_ACTIVE_PAIR" = none:0 ] \
        || { valid_sha256 "${CLEANUP_ACTIVE_PAIR%%:*}" && valid_size "${CLEANUP_ACTIVE_PAIR#*:}"; }
}

load_bound_startup_cleanup_record() {
    CLEANUP_EVIDENCE=$1
    startup_cleanup_record_is_exact_at "$CLEANUP_EVIDENCE" || return 1
    BOUND_SUPERVISOR_PID=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_pid)
    BOUND_SUPERVISOR_START=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_start)
    BOUND_SUPERVISOR_PPID=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_ppid)
    BOUND_SUPERVISOR_PGRP=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_pgrp)
    BOUND_SUPERVISOR_SESSION=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_session)
    BOUND_SUPERVISOR_EXE=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_exe)
    BOUND_SUPERVISOR_CMDLINE_SHA=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_cmdline_sha256)
    BOUND_SUPERVISOR_CMDLINE_BYTES=$(startup_field_at "$CLEANUP_EVIDENCE" supervisor_cmdline_bytes)
    BOUND_BOSMINER_PID=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_pid)
    BOUND_BOSMINER_START=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_start)
    BOUND_BOSMINER_PPID=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_ppid)
    BOUND_BOSMINER_PGRP=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_pgrp)
    BOUND_BOSMINER_SESSION=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_session)
    BOUND_BOSMINER_EXE=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_exe)
    BOUND_BOSMINER_CMDLINE_SHA=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_cmdline_sha256)
    BOUND_BOSMINER_CMDLINE_BYTES=$(startup_field_at "$CLEANUP_EVIDENCE" bosminer_cmdline_bytes)
    BOUND_STOCK_PIDFILE_PATH=$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_path)
    BOUND_STOCK_PIDFILE_SHA=$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_sha256)
    BOUND_STOCK_PIDFILE_BYTES=$(startup_field_at "$CLEANUP_EVIDENCE" stock_pidfile_bytes)
    EXPECTED_LIVE_IDENTITY_PROFILE=$(startup_field_at "$CLEANUP_EVIDENCE" live_identity_profile)
    EXPECTED_LIVE_IDENTITY_SHA=$(startup_field_at "$CLEANUP_EVIDENCE" live_identity_sha256)
}

publish_startup_cleanup_commit() {
    OWNER_EVIDENCE=$1
    startup_retire_terminal_is_exact "$OWNER_EVIDENCE" || return 1
    TERMINAL_SHA=$(sha256sum "$STARTUP_RETIRE_TERMINAL" | awk '{print $1}')
    TERMINAL_BYTES=$(wc -c < "$STARTUP_RETIRE_TERMINAL" | tr -d ' \t\r\n')
    OWNER_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" owner_sha256)
    OWNER_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" owner_bytes)
    ACTIVE_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" active_sha256)
    ACTIVE_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" active_bytes)
    if [ ! -e "$STARTUP_RETIRE_CLEANUP_SOURCE" ] && [ ! -L "$STARTUP_RETIRE_CLEANUP_SOURCE" ]; then
        set -C
        if ! {
            printf 'schema=dcentos.s19k-startup-retire-cleanup-commit/v1\n'
            printf 'transaction_id=%s\n' "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transaction_id)"
            printf 'phase=startup-no-effect-cleanup-committed\n'
            printf 'highest_phase=%s\n' "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" highest_phase)"
            printf 'trial_dir=%s\n' "$TRIAL_DIR"
            printf 'terminal_schema=dcentos.s19k-startup-retired-terminal/v1\n'
            printf 'terminal_sha256=%s\nterminal_bytes=%s\n' "$TERMINAL_SHA" "$TERMINAL_BYTES"
            printf 'owner_sha256=%s\nowner_bytes=%s\n' "$OWNER_SHA" "$OWNER_BYTES"
            printf 'active_sha256=%s\nactive_bytes=%s\n' "$ACTIVE_SHA" "$ACTIVE_BYTES"
            printf 'fifo_path=%s\n' "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" fifo_path)"
            for KEY in transcript_path transcript_mnt_id transcript_inode transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes; do
                printf '%s=%s\n' "$KEY" "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "$KEY")"
            done
            printf 'residue_count=0\n'
            printf 'residue_manifest_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n'
            printf 'commit_source_path=%s\n' "$STARTUP_RETIRE_CLEANUP_SOURCE"
            for KEY in supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_profile live_identity_sha256 gpio_raw; do
                printf '%s=%s\n' "$KEY" "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "$KEY")"
            done
            printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\ninherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\npersistent_mutation=false\n'
            printf 'publication=no-clobber-hard-link-after-fsync\n'
        } > "$STARTUP_RETIRE_CLEANUP_SOURCE"; then
            set +C
            return 1
        fi
        set +C
        chmod 600 "$STARTUP_RETIRE_CLEANUP_SOURCE"
    fi
    startup_cleanup_record_is_exact_at "$STARTUP_RETIRE_CLEANUP_SOURCE" \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" transaction_id)" = "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transaction_id)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" highest_phase)" = "$(startup_field_at "$STARTUP_RETIRE_TERMINAL" highest_phase)" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" terminal_sha256)" = "$TERMINAL_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" terminal_bytes)" = "$TERMINAL_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" owner_sha256)" = "$OWNER_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" owner_bytes)" = "$OWNER_BYTES" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" active_sha256)" = "$ACTIVE_SHA" ] \
        && [ "$(startup_field_at "$STARTUP_RETIRE_CLEANUP_SOURCE" active_bytes)" = "$ACTIVE_BYTES" ] || return 1
    if [ ! -e "$STARTUP_RETIRE_CLEANUP" ] && [ ! -L "$STARTUP_RETIRE_CLEANUP" ]; then
        publish_no_clobber_journal_keep_source "$STARTUP_RETIRE_CLEANUP_SOURCE" "$STARTUP_RETIRE_CLEANUP" || return 1
    fi
    startup_cleanup_record_is_exact_at "$STARTUP_RETIRE_CLEANUP" \
        && [ "$(sha256sum "$STARTUP_RETIRE_CLEANUP_SOURCE" | awk '{print $1}')" = "$(sha256sum "$STARTUP_RETIRE_CLEANUP" | awk '{print $1}')" ] \
        && [ "$(wc -c < "$STARTUP_RETIRE_CLEANUP_SOURCE" | tr -d ' \t\r\n')" = "$(wc -c < "$STARTUP_RETIRE_CLEANUP" | tr -d ' \t\r\n')" ] \
        && rm -f "$STARTUP_RETIRE_CLEANUP_SOURCE"
}

startup_cleanup_suffix_is_exact() {
    load_bound_startup_cleanup_record "$STARTUP_RETIRE_CLEANUP" || return 1
    CLEANUP_SOURCE_BOUND=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" commit_source_path) || return 1
    CLEANUP_SOURCE_SUFFIX=${CLEANUP_SOURCE_BOUND##*.source.}
    CLEANUP_SOURCE_PID=${CLEANUP_SOURCE_SUFFIX%%.*}
    CLEANUP_SOURCE_START=${CLEANUP_SOURCE_SUFFIX#*.}
    [ "${CLEANUP_SOURCE_BOUND%/*}" = "$TRIAL_DIR" ] \
        && [ "$CLEANUP_SOURCE_BOUND" = "$TRIAL_DIR/.runtime_startup_retire_cleanup_commit.source.$CLEANUP_SOURCE_PID.$CLEANUP_SOURCE_START" ] \
        && valid_pid_start "$CLEANUP_SOURCE_PID" "$CLEANUP_SOURCE_START" || return 1
    if [ -e "$RUNTIME_LOCK" ] || [ -L "$RUNTIME_LOCK" ]; then
        runtime_lock_container_is_exact \
            && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] || return 1
    fi
    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && [ ! -e "$STARTUP_C1" ] && [ ! -L "$STARTUP_C1" ] \
        && [ ! -e "$STARTUP_J1" ] && [ ! -L "$STARTUP_J1" ] \
        && [ ! -e "$STARTUP_J2" ] && [ ! -L "$STARTUP_J2" ] \
        && [ ! -e "$STARTUP_RELEASE" ] && [ ! -L "$STARTUP_RELEASE" ] \
        && [ ! -e "$STARTUP_PARENT_LOST" ] && [ ! -L "$STARTUP_PARENT_LOST" ] \
        && [ ! -e "$STOCK_RETAINED_RECEIPT" ] && [ ! -L "$STOCK_RETAINED_RECEIPT" ] \
        && [ ! -e "$TERMINAL_HANDOFF_RECEIPT" ] && [ ! -L "$TERMINAL_HANDOFF_RECEIPT" ] \
        && [ ! -e "$PRE_SAFEOFF_ACTIVE" ] && [ ! -L "$PRE_SAFEOFF_ACTIVE" ] \
        && [ ! -e "$SAFEOFF_TERMINAL_RECEIPT" ] && [ ! -L "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && [ ! -e "$RETIRED_ACTIVE" ] && [ ! -L "$RETIRED_ACTIVE" ] \
        && [ ! -e "$RETIRED_OWNER" ] && [ ! -L "$RETIRED_OWNER" ] \
        && [ ! -e "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" fifo_path)" ] \
        && [ ! -L "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" fifo_path)" ] || return 1
    CLEANUP_TRANSCRIPT=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_path) || return 1
    if [ -e "$CLEANUP_TRANSCRIPT" ] || [ -L "$CLEANUP_TRANSCRIPT" ]; then
        is_regular_nonsymlink "$CLEANUP_TRANSCRIPT" \
            && [ "$(sha256sum "$CLEANUP_TRANSCRIPT" | awk '{print $1}')" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_sha256)" ] \
            && [ "$(wc -c < "$CLEANUP_TRANSCRIPT" | tr -d ' \t\r\n')" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_bytes)" ] || return 1
    fi
    for PAIR_SPEC in \
        "$STARTUP_RETIRE_TERMINAL:terminal_sha256:terminal_bytes" \
        "$STARTUP_RETIRED_OWNER:owner_sha256:owner_bytes" \
        "$STARTUP_RETIRED_ACTIVE:active_sha256:active_bytes"; do
        PAIR_PATH=${PAIR_SPEC%%:*}
        PAIR_REST=${PAIR_SPEC#*:}
        PAIR_SHA_KEY=${PAIR_REST%%:*}
        PAIR_BYTES_KEY=${PAIR_REST#*:}
        PAIR_SHA=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" "$PAIR_SHA_KEY")
        PAIR_BYTES=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" "$PAIR_BYTES_KEY")
        if [ "$PAIR_SHA:$PAIR_BYTES" = none:0 ]; then
            [ ! -e "$PAIR_PATH" ] && [ ! -L "$PAIR_PATH" ] || return 1
        elif [ -e "$PAIR_PATH" ] || [ -L "$PAIR_PATH" ]; then
            is_regular_nonsymlink "$PAIR_PATH" \
                && [ "$(sha256sum "$PAIR_PATH" | awk '{print $1}')" = "$PAIR_SHA" ] \
                && [ "$(wc -c < "$PAIR_PATH" | tr -d ' \t\r\n')" = "$PAIR_BYTES" ] || return 1
        fi
    done
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && no_daemon_watchdog_or_competing_wrapper_is_live
}

finalize_startup_cleanup_commit() {
    startup_cleanup_suffix_is_exact || return 1
    if [ -e "$RUNTIME_LOCK" ] || [ -L "$RUNTIME_LOCK" ]; then
        runtime_lock_container_is_exact && rmdir "$RUNTIME_LOCK" || return 1
        startup_cleanup_suffix_is_exact || return 1
    fi
    CLEANUP_SOURCE_BOUND=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" commit_source_path) || return 1
    if [ -e "$CLEANUP_SOURCE_BOUND" ] || [ -L "$CLEANUP_SOURCE_BOUND" ]; then
        is_regular_nonsymlink "$CLEANUP_SOURCE_BOUND" \
            && [ "$(sha256sum "$CLEANUP_SOURCE_BOUND" | awk '{print $1}')" = "$(sha256sum "$STARTUP_RETIRE_CLEANUP" | awk '{print $1}')" ] \
            && [ "$(wc -c < "$CLEANUP_SOURCE_BOUND" | tr -d ' \t\r\n')" = "$(wc -c < "$STARTUP_RETIRE_CLEANUP" | tr -d ' \t\r\n')" ] \
            && rm -f "$CLEANUP_SOURCE_BOUND" || return 1
    fi
    CLEANUP_TRANSCRIPT=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_path) || return 1
    if [ -e "$CLEANUP_TRANSCRIPT" ] || [ -L "$CLEANUP_TRANSCRIPT" ]; then
        is_regular_nonsymlink "$CLEANUP_TRANSCRIPT" \
            && [ "$(sha256sum "$CLEANUP_TRANSCRIPT" | awk '{print $1}')" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_sha256)" ] \
            && [ "$(wc -c < "$CLEANUP_TRANSCRIPT" | tr -d ' \t\r\n')" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_bytes)" ] \
            && rm -f "$CLEANUP_TRANSCRIPT" || return 1
        startup_cleanup_suffix_is_exact || return 1
    fi
    PRE_J0_EXCLUDED_PATHS=
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST_SHA" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] || return 1
    for CONSUMED_EVIDENCE in "$STARTUP_RETIRED_ACTIVE" "$STARTUP_RETIRED_OWNER" "$STARTUP_RETIRE_TERMINAL"; do
        if [ -e "$CONSUMED_EVIDENCE" ] || [ -L "$CONSUMED_EVIDENCE" ]; then
            rm -f "$CONSUMED_EVIDENCE" || return 1
            startup_cleanup_suffix_is_exact || return 1
        fi
    done
    startup_cleanup_suffix_is_exact || return 1
    rm -f "$STARTUP_RETIRE_CLEANUP" || return 1
    [ ! -e "$STARTUP_RETIRE_CLEANUP" ] && [ ! -L "$STARTUP_RETIRE_CLEANUP" ]
}

retire_startup_no_effect_obligation() {
    if [ -e "$STARTUP_RETIRE_CLEANUP" ] || [ -L "$STARTUP_RETIRE_CLEANUP" ]; then
        if [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
            finalize_startup_cleanup_commit || return 1
            echo "S19k pre-J3 startup cleanup suffix completed from its immutable commit"
            return 0
        fi
    fi
    if is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" && [ ! -e "$STARTUP_RETIRED_OWNER" ] && [ ! -L "$STARTUP_RETIRED_OWNER" ]; then
        OWNER_EVIDENCE=$RUNTIME_LOCK_OWNER
    elif is_regular_nonsymlink "$STARTUP_RETIRED_OWNER" && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        OWNER_EVIDENCE=$STARTUP_RETIRED_OWNER
    else
        echo "ERROR: startup retirement OWNER phase is ambiguous" >&2
        return 1
    fi
    if [ -e "$STARTUP_RETIRE_TERMINAL" ] || [ -L "$STARTUP_RETIRE_TERMINAL" ]; then
        load_bound_startup_j0_static_from "$OWNER_EVIDENCE" || return 1
        STARTUP_TERMINAL_PRESENT=true
    else
        load_bound_startup_j0_from "$OWNER_EVIDENCE" || return 1
        STARTUP_TERMINAL_PRESENT=false
    fi
    ORIGINAL_WRAPPER_PID=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid)
    ORIGINAL_WRAPPER_START=$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)
    if process_matches "$ORIGINAL_WRAPPER_PID" "$ORIGINAL_WRAPPER_START"; then
        [ "$ORIGINAL_WRAPPER_PID" = "$$" ] \
            && [ "$ORIGINAL_WRAPPER_START" = "$SELF_START" ] \
            && exact_current_wrapper_matches_j0 "$OWNER_EVIDENCE" || return 1
    fi
    if is_regular_nonsymlink "$ACTIVE" && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ]; then
        ACTIVE_EVIDENCE=$ACTIVE
    elif is_regular_nonsymlink "$STARTUP_RETIRED_ACTIVE" && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
        ACTIVE_EVIDENCE=$STARTUP_RETIRED_ACTIVE
    elif [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] \
        && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ]; then
        ACTIVE_EVIDENCE=
    else
        return 1
    fi
    STARTUP_HIGHEST_PHASE=j0
    if [ "$STARTUP_TERMINAL_PRESENT" = true ]; then
        startup_retire_terminal_is_exact "$OWNER_EVIDENCE" || return 1
        STARTUP_HIGHEST_PHASE=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" highest_phase)
        case "$STARTUP_HIGHEST_PHASE" in j0|parent-lost-j0|c1|j1|active|j2|release) ;; *) return 1 ;; esac
    elif [ -e "$STARTUP_PARENT_LOST" ] || [ -L "$STARTUP_PARENT_LOST" ]; then
        [ -z "$ACTIVE_EVIDENCE" ] \
            && [ ! -e "$STARTUP_C1" ] && [ ! -L "$STARTUP_C1" ] \
            && [ ! -e "$STARTUP_J1" ] && [ ! -L "$STARTUP_J1" ] \
            && [ ! -e "$STARTUP_J2" ] && [ ! -L "$STARTUP_J2" ] \
            && [ ! -e "$STARTUP_RELEASE" ] && [ ! -L "$STARTUP_RELEASE" ] \
            && startup_parent_lost_j0_is_exact_for_recovery "$OWNER_EVIDENCE" || return 1
        STARTUP_HIGHEST_PHASE=parent-lost-j0
    elif [ -e "$STARTUP_J2" ] || [ -L "$STARTUP_J2" ] \
        || [ -e "$STARTUP_RELEASE" ] || [ -L "$STARTUP_RELEASE" ]; then
        [ -n "$ACTIVE_EVIDENCE" ] \
            && load_bound_runtime_active_from "$ACTIVE_EVIDENCE" \
            && startup_j2_is_exact_for_recovery "$OWNER_EVIDENCE" "$ACTIVE_EVIDENCE" || return 1
        if [ -e "$STARTUP_RELEASE" ] || [ -L "$STARTUP_RELEASE" ]; then
            startup_release_is_exact_for_recovery "$OWNER_EVIDENCE" "$ACTIVE_EVIDENCE" || return 1
            STARTUP_HIGHEST_PHASE=release
        else
            STARTUP_HIGHEST_PHASE=j2
        fi
    else
        if [ -e "$STARTUP_J1" ] || [ -L "$STARTUP_J1" ]; then
            startup_j1_is_exact_for_recovery "$OWNER_EVIDENCE" || return 1
            if [ -n "$ACTIVE_EVIDENCE" ]; then
                load_bound_runtime_active_from "$ACTIVE_EVIDENCE" \
                    && [ "$RECEIPT_PHASE" = child-live-or-recovery-required ] \
                    && [ "$CHILD_PID" = "$(startup_field_at "$STARTUP_C1" child_pid)" ] \
                    && [ "$CHILD_START" = "$(startup_field_at "$STARTUP_C1" child_start)" ] || return 1
                STARTUP_HIGHEST_PHASE=active
            else
                STARTUP_HIGHEST_PHASE=j1
            fi
        elif [ -e "$STARTUP_C1" ] || [ -L "$STARTUP_C1" ]; then
            [ -z "$ACTIVE_EVIDENCE" ] \
                && startup_c1_is_exact_for_recovery "$OWNER_EVIDENCE" || return 1
            STARTUP_HIGHEST_PHASE=c1
        else
            [ -z "$ACTIVE_EVIDENCE" ] || return 1
        fi
    fi
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && no_dcentrald_thread_is_live \
        && no_watchdog_fd_is_live || return 1
    if [ "$STARTUP_TERMINAL_PRESENT" = false ]; then
        PRE_J0_EXCLUDED_PATHS=$(runtime_lock_field_at "$OWNER_EVIDENCE" fifo_path) || return 1
        PRE_J0_EXCLUDED_PATHS="$PRE_J0_EXCLUDED_PATHS
$TRIAL_DIR/.startup_daemon_transcript.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)"
        classify_exact_pre_j0_residues || return 1
        remove_classified_pre_j0_residues || return 1
        PRE_J0_EXCLUDED_PATHS=
        verify_all_bound_files \
            && require_same_live_s19k_identity \
            && require_same_exact_stock_tree \
            && gpio_stock_baseline_is_exact \
            && no_dcentrald_thread_is_live \
            && no_watchdog_fd_is_live || return 1
        publish_startup_retire_terminal "$OWNER_EVIDENCE" "$ACTIVE_EVIDENCE" "$STARTUP_HIGHEST_PHASE" || return 1
        STARTUP_TERMINAL_PRESENT=true
    fi
    startup_retire_terminal_is_exact "$OWNER_EVIDENCE" || return 1
    consume_startup_companion_after_terminal "$STARTUP_C1" c1_sha256 c1_bytes || return 1
    consume_startup_companion_after_terminal "$STARTUP_J1" j1_sha256 j1_bytes || return 1
    consume_startup_companion_after_terminal "$STARTUP_J2" j2_sha256 j2_bytes || return 1
    consume_startup_companion_after_terminal "$STARTUP_RELEASE" release_sha256 release_bytes || return 1
    consume_startup_companion_after_terminal "$STARTUP_PARENT_LOST" parent_lost_sha256 parent_lost_bytes || return 1
    BOUND_FIFO=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" fifo_path)
    if [ -e "$BOUND_FIFO" ] || [ -L "$BOUND_FIFO" ]; then
        startup_fifo_matches_j0 "$OWNER_EVIDENCE" && rm -f "$BOUND_FIFO" || return 1
    fi
    if [ -n "$ACTIVE_EVIDENCE" ] && [ "$ACTIVE_EVIDENCE" = "$ACTIVE" ]; then
        mv "$ACTIVE" "$STARTUP_RETIRED_ACTIVE" || return 1
        ACTIVE_EVIDENCE=$STARTUP_RETIRED_ACTIVE
        startup_retire_terminal_is_exact "$OWNER_EVIDENCE" || return 1
    fi
    # The transcript is named by the wrapper lifetime, not the stock
    # supervisor. Derive that immutable tuple from J0 when it remains present.
    PRE_J0_EXCLUDED_PATHS="$TRIAL_DIR/.startup_daemon_transcript.$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_pid).$(runtime_lock_field_at "$OWNER_EVIDENCE" wrapper_start)"
    classify_exact_pre_j0_residues || return 1
    remove_classified_pre_j0_residues || return 1
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && no_daemon_watchdog_or_competing_wrapper_is_live || return 1
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST_SHA" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] || return 1
    PRE_J0_EXCLUDED_PATHS=
    # Commit the self-sufficient cleanup authority while immutable J0 still
    # occupies the global owner path. From this point every deletion suffix is
    # recoverable without interpreting absence as evidence.
    publish_startup_cleanup_commit "$OWNER_EVIDENCE" || return 1
    if [ "$OWNER_EVIDENCE" = "$RUNTIME_LOCK_OWNER" ]; then
        mv "$RUNTIME_LOCK_OWNER" "$STARTUP_RETIRED_OWNER" || return 1
        OWNER_EVIDENCE=$STARTUP_RETIRED_OWNER
        startup_retire_terminal_is_exact "$OWNER_EVIDENCE" || return 1
    fi
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && no_daemon_watchdog_or_competing_wrapper_is_live || return 1
    if [ -e "$RUNTIME_LOCK" ] || [ -L "$RUNTIME_LOCK" ]; then
        runtime_lock_container_is_exact && rmdir "$RUNTIME_LOCK" || return 1
    fi
    [ ! -e "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ] || return 1
    finalize_startup_cleanup_commit || return 1
    echo "S19k pre-J3 startup custody retired and consumed without SafeOff or stock signaling"
}

retire_released_startup_after_child_exit() {
    # In this bounded slice, the only admitted post-release child outcome is a
    # typed prewatchdog refusal before J3. The startup journals independently
    # prove that no watchdog, stock signal, inherited rails, UART, or hardware
    # effect occurred. Validate the redundant daemon receipt before removing
    # it, so a crash after that removal remains recoverable solely from the
    # immutable J0->C1->J1->ACTIVE->J2->release prefix.
    OWNER_EVIDENCE=$RUNTIME_LOCK_OWNER
    is_regular_nonsymlink "$OWNER_EVIDENCE" \
        && [ "$(runtime_lock_field_at "$OWNER_EVIDENCE" schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && load_bound_startup_j0_static_from "$OWNER_EVIDENCE" \
        && load_bound_runtime_active_from "$ACTIVE" \
        && startup_j2_is_exact_for_recovery "$OWNER_EVIDENCE" "$ACTIVE" \
        && startup_release_is_exact_for_recovery "$OWNER_EVIDENCE" "$ACTIVE" || return 1
    if [ -e "$STOCK_RETAINED_RECEIPT" ] || [ -L "$STOCK_RETAINED_RECEIPT" ]; then
        retained_prewatchdog_receipt_is_exact "$ACTIVE" \
            && verify_all_bound_files \
            && require_same_live_s19k_identity \
            && require_same_exact_stock_tree \
            && gpio_stock_baseline_is_exact \
            && no_dcentrald_thread_is_live \
            && no_watchdog_fd_is_live || return 1
        rm -f "$STOCK_RETAINED_RECEIPT" || return 1
    fi
    retire_startup_no_effect_obligation
}

wait_for_exact_child_exit() {
    N=0
    while process_matches "$CHILD_PID" "$CHILD_START" && [ "$N" -lt 60 ]; do
        sleep 1
        N=$((N + 1))
    done
    ! process_matches "$CHILD_PID" "$CHILD_START"
}

# Attempt-10 hard-ceiling backstop (2026-08-28 lifecycle audit).  Live
# attempt 9 deadlocked 26+ minutes because the wrapper blocked on a daemon
# that had parked instead of exiting; the sealed salvage-v6 daemon now exits
# every one-shot Track-1 authority on a typed disposition, and this ceiling
# is the defense-in-depth bound for any residual hang class.  TRIAL_CEILING_
# DEADLINE is armed only for the one-shot trial deploy modes and only after
# the daemon fork is admitted; ordinary mining-on passthrough sessions keep
# the unmodified blocking wait.
trial_ceiling_expired() {
    [ -n "${TRIAL_CEILING_DEADLINE:-}" ] || return 1
    [ "$(date +%s)" -ge "$TRIAL_CEILING_DEADLINE" ]
}

enforce_trial_ceiling_exit() {
    # Expiry closeout: SIGKILL ONLY the identity-fenced daemon child; never
    # signal S99bosminer, bosminer, or any stock supervisor process.  Append
    # the typed ceiling marker to the daemon transcript, print (never
    # execute) the deployer-printed restore command, and exit non-zero so
    # the coordinator runs the proven human recovery path (attempt 9:
    # SIGKILL wrapper, then the exact printed restore).
    if process_matches "$CHILD_PID" "$CHILD_START"; then
        exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START" || {
            echo "ERROR: supervised child lifetime changed comm/exe identity at the trial ceiling; refusing to signal it and leaving the runtime receipt intact" >&2
            exit 1
        }
        kill -KILL "$CHILD_PID" 2>/dev/null || {
            process_matches "$CHILD_PID" "$CHILD_START" && {
                echo "ERROR: exact supervised dcentrald could not be SIGKILLed at the trial ceiling; leaving the runtime receipt intact" >&2
                exit 1
            }
        }
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    printf 'S19K_TMP_TRIAL_CEILING_EXCEEDED schema=dcentos.s19k-trial-ceiling/v1 ceiling_seconds=%s wrapper_pid=%s child_pid=%s child_start=%s utc_epoch=%s action=daemon-sigkill-restore-required\n' \
        "$TRIAL_CEILING_SECONDS" "$$" "$CHILD_PID" "$CHILD_START" "$(date +%s)" \
        >> "$STARTUP_DAEMON_TRANSCRIPT" 2>/dev/null \
        || echo "ERROR: trial ceiling marker could not be appended to the daemon transcript" >&2
    echo "ERROR: one-shot Track-1 trial exceeded the ${TRIAL_CEILING_SECONDS}s hard ceiling; the exact daemon child was SIGKILLed and custody remains for the printed restore" >&2
    echo "Stop/recover the orphaned temporary runtime after the ceiling kill:"
    echo "  $TRIAL_DIR/run_trial restore $TRIAL_DIR $BOARD_TARGET recovery $BIN_SHA $BIN_BYTES $CFG_SHA $CFG_BYTES $RUNNER_SHA $RUNNER_BYTES $CUSTODY_SHA $CUSTODY_BYTES $STOCK_RESTART_HELPER_SHA $STOCK_RESTART_HELPER_BYTES"
    exit 97
}

safeoff_source_deploy_mode() {
    case "$DEPLOY_MODE" in
        install-custody-safeoff|stage-only|mining-on-passthrough|handoff-no-work|bounded-work-proof|endurance-work-proof)
            printf '%s\n' "$DEPLOY_MODE"
            return 0
            ;;
        recovery)
            for SAFEOFF_MODE_SOURCE in "$PRE_SAFEOFF_ACTIVE" "$STARTUP_PRESAFEOFF_ACTIVE" "$ACTIVE"; do
                is_regular_nonsymlink "$SAFEOFF_MODE_SOURCE" || continue
                SAFEOFF_MODE=$(active_field_at "$SAFEOFF_MODE_SOURCE" deploy_mode 2>/dev/null || true)
                case "$SAFEOFF_MODE" in
                    install-custody-safeoff|stage-only|mining-on-passthrough|handoff-no-work|bounded-work-proof|endurance-work-proof)
                        printf '%s\n' "$SAFEOFF_MODE"
                        return 0
                        ;;
                esac
            done
            return 1
            ;;
        *) return 1 ;;
    esac
}

set_expected_safeoff_receipt() {
    SAFEOFF_SOURCE_MODE=$(safeoff_source_deploy_mode) || return 1
    if [ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]; then
        EXPECTED_SAFEOFF_SCHEMA=dcentos.s19k-install-custody-safeoff/v1
        EXPECTED_SAFEOFF_RESETS=not-attempted
        EXPECTED_SAFEOFF_GPIO_RAW=437:1
        EXPECTED_SAFEOFF_RECEIPT="DCENT_S19K_INSTALL_CUSTODY_SAFEOFF_RECEIPT schema=$EXPECTED_SAFEOFF_SCHEMA live_identity_sha256=$EXPECTED_LIVE_IDENTITY_SHA live_identity_profile=$EXPECTED_LIVE_IDENTITY_PROFILE live_identity_model_sha256=$LIVE_IDENTITY_MODEL_SHA live_identity_board_count=$BOARD_COUNT live_identity_physical_addresses=$LIVE_IDENTITY_PHYSICAL_ADDRESSES live_identity_board_names=$LIVE_IDENTITY_BOARD_NAMES live_identity_eeprom=$LIVE_IDENTITY_EEPROM_SLOTS resets=$EXPECTED_SAFEOFF_RESETS psu=437:1"
    else
        EXPECTED_SAFEOFF_SCHEMA=dcentos.s19k-track1-safeoff/v1
        EXPECTED_SAFEOFF_RESETS=454:0,455:0,456:0
        EXPECTED_SAFEOFF_GPIO_RAW=437:1,454:0,455:0,456:0
        EXPECTED_SAFEOFF_RECEIPT="DCENT_S19K_TRACK1_SAFEOFF_RECEIPT schema=$EXPECTED_SAFEOFF_SCHEMA live_identity_sha256=$EXPECTED_LIVE_IDENTITY_SHA live_identity_profile=$EXPECTED_LIVE_IDENTITY_PROFILE live_identity_model_sha256=$LIVE_IDENTITY_MODEL_SHA live_identity_board_count=$BOARD_COUNT live_identity_physical_addresses=$LIVE_IDENTITY_PHYSICAL_ADDRESSES live_identity_board_names=$LIVE_IDENTITY_BOARD_NAMES live_identity_eeprom=$LIVE_IDENTITY_EEPROM_SLOTS resets=$EXPECTED_SAFEOFF_RESETS psu=437:1"
    fi
}

run_checked_safeoff_command() {
    SAFEOFF_SOURCE_MODE=$(safeoff_source_deploy_mode) || {
        echo "ERROR: recovery source deploy mode is unavailable; refusing reset-capable SafeOff because install custody permits GPIO437-only custody" >&2
        return 1
    }
    if [ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]; then
        echo "ERROR: install custody forbids the reset-capable recovery SafeOff command; only its daemon-issued GPIO437-only terminal receipt is admissible" >&2
        return 1
    fi
    verify_all_bound_files || return 1
    require_same_live_s19k_identity || return 1
    if process_matches "${BOUND_SUPERVISOR_PID:-0}" "${BOUND_SUPERVISOR_START:-0}" \
        || process_matches "${BOUND_BOSMINER_PID:-0}" "${BOUND_BOSMINER_START:-0}" \
        || bosminer_custody_owner_is_live; then
        echo "ERROR: bosminer custody supervisor or child still owns hardware; refusing competing recovery SafeOff and retaining receipt" >&2
        return 1
    fi
    if ! no_dcentrald_thread_is_live; then
        echo "ERROR: a dcentrald process is still live; refusing concurrent recovery SafeOff" >&2
        return 1
    fi
    if another_trial_wrapper_is_live; then
        echo "ERROR: another Track-1 wrapper is still live; refusing concurrent recovery SafeOff" >&2
        return 1
    fi
    # The held Braiins AM3 rootfs exposes /usr/bin/env as BusyBox and its
    # `env -i` applet was exercised offline.  Do not inherit SSH/operator
    # DCENT_* experiment knobs into the recovery authority.
    SAFE_OUT=$(/usr/bin/env -i \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        DCENTOS_EPHEMERAL_RUNTIME=1 \
        DCENTOS_LOG_RING_DIR=/tmp/dcent/log \
        DCENT_S19K_LIVE_IDENTITY_SHA256="$EXPECTED_LIVE_IDENTITY_SHA" \
        "$TRIAL_BIN" --config "$TRIAL_CFG" --s19k-track1-recovery-safeoff 2>&1) || {
        printf '%s\n' "$SAFE_OUT" >&2
        echo "ERROR: checked S19k recovery SafeOff command failed; receipt retained" >&2
        return 1
    }
    printf '%s\n' "$SAFE_OUT"
    # Exact live `.88` kernel evidence (4.9.113, gpiochip bases 411/497)
    # publishes no gpio-line-names and exposes the prepared legacy reset lines
    # at 454/455/456.  The content-bound daemon's name-first resolver therefore
    # takes those explicit fallbacks.  472/473/474 are unexported on this unit
    # and must never be accepted as a successful reset receipt.
    set_expected_safeoff_receipt
    printf '%s\n' "$SAFE_OUT" | grep -Fxq "$EXPECTED_SAFEOFF_RECEIPT" || {
        echo "ERROR: recovery command returned no exact checked reset+cut receipt" >&2
        return 1
    }
}

perform_checked_safeoff() {
    runtime_lock_container_is_exact || {
        echo "ERROR: checked recovery requires the atomic runtime custody lock" >&2
        return 1
    }
    admit_runtime_lock_owner || return 1
    run_checked_safeoff_command
}

handoff_no_work_transcript_receipt_is_exact() {
    is_regular_nonsymlink "$NO_WORK_TRANSCRIPT_RECEIPT" \
        && [ "$(wc -l < "$NO_WORK_TRANSCRIPT_RECEIPT" | tr -d ' \t\r\n')" -eq 65 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" schema)" = dcentos.s19k-handoff-no-work-transcript/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" deploy_mode)" = handoff-no-work ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_mnt_id)" = "$NO_WORK_TRANSCRIPT_MNT_ID" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_inode)" = "$NO_WORK_TRANSCRIPT_INODE" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_gid)" = 0 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_sha256)" = "$NO_WORK_TRANSCRIPT_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" transcript_bytes)" = "$NO_WORK_TRANSCRIPT_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" source_runtime_active_schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" source_runtime_active_path)" = "$PRE_SAFEOFF_ACTIVE" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" source_runtime_active_sha256)" = "$NO_WORK_SOURCE_ACTIVE_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" source_runtime_active_bytes)" = "$NO_WORK_SOURCE_ACTIVE_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" pending_runtime_schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" pending_runtime_path)" = "$ACTIVE" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" pending_runtime_sha256)" = "$NO_WORK_PENDING_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" pending_runtime_bytes)" = "$NO_WORK_PENDING_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_schema)" = dcentos.s19k-terminal-safeoff-partial-stock-owner/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF_RECEIPT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_sha256)" = "$NO_WORK_TERMINAL_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_bytes)" = "$NO_WORK_TERMINAL_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" safeoff_receipt_schema)" = dcentos.s19k-track1-safeoff/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" safeoff_receipt_sha256)" = "$NO_WORK_SAFEOFF_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" safeoff_receipt_bytes)" = "$NO_WORK_SAFEOFF_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_c1_schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_c1_path)" = "$STARTUP_C1" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_c1_sha256)" = "$NO_WORK_C1_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_c1_bytes)" = "$NO_WORK_C1_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j1_schema)" = dcentos.s19k-startup-j1-daemon-blocked/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j1_path)" = "$STARTUP_J1" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j1_sha256)" = "$NO_WORK_J1_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j1_bytes)" = "$NO_WORK_J1_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j2_schema)" = dcentos.s19k-startup-j2-child-bound/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j2_path)" = "$STARTUP_J2" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j2_sha256)" = "$NO_WORK_J2_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_j2_bytes)" = "$NO_WORK_J2_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_release_schema)" = dcentos.s19k-startup-release/v1 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_release_path)" = "$STARTUP_RELEASE" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_release_sha256)" = "$NO_WORK_RELEASE_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" startup_release_bytes)" = "$NO_WORK_RELEASE_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" wrapper_exit_status)" = "$NO_WORK_WRAPPER_EXIT_STATUS" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" no_work_active_count)" = "$NO_WORK_ACTIVE_COUNT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" discarded_job_count)" = "$NO_WORK_DISCARDED_JOB_COUNT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" full_frame_count)" = "$NO_WORK_FULL_FRAME_COUNT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" bounded_tx_count)" = "$NO_WORK_BOUNDED_TX_COUNT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" dispatch_admitted_count)" = "$NO_WORK_DISPATCH_ADMITTED_COUNT" ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" semantic_verification)" = host-plus-independent-instruments-required ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$NO_WORK_TRANSCRIPT_RECEIPT" publication)" = no-clobber-hard-link-after-fsync ]
}

# Keep and hash the exact no-work daemon transcript inode only after the daemon
# is gone and checked SafeOff has become a typed stock-restart-pending
# obligation. The target binds bytes and marker counts; only the independent
# host verifier may combine them with the external rail/GPIO/UART captures.
publish_handoff_no_work_transcript_receipt() {
    NO_WORK_WRAPPER_EXIT_STATUS=$1
    [ "$DEPLOY_MODE" = handoff-no-work ] || return 0
    valid_uint "$NO_WORK_WRAPPER_EXIT_STATUS" \
        && [ "$NO_WORK_WRAPPER_EXIT_STATUS" -le 255 ] || return 1
    [ -e "/proc/$$/fd/6" ] \
        && ! process_matches "$CHILD_PID" "$CHILD_START" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" deploy_mode)" = handoff-no-work ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && [ "$(active_field source_runtime_active_sha256)" = "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" ] \
        && [ "$(active_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ] \
        && [ "$(active_field terminal_handoff_receipt_sha256)" = "$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')" ] || return 1

    NO_WORK_TRANSCRIPT_TARGET_INITIAL=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    NO_WORK_TRANSCRIPT_LS_INITIAL=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $NO_WORK_TRANSCRIPT_LS_INITIAL
    NO_WORK_TRANSCRIPT_INODE_INITIAL=${1:-}
    NO_WORK_TRANSCRIPT_MODE_INITIAL=${2:-}
    NO_WORK_TRANSCRIPT_UID_INITIAL=${4:-}
    NO_WORK_TRANSCRIPT_GID_INITIAL=${5:-}
    NO_WORK_TRANSCRIPT_MNT_ID_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    [ "$NO_WORK_TRANSCRIPT_TARGET_INITIAL" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$NO_WORK_TRANSCRIPT_MODE_INITIAL" = -rw------- ] \
        && [ "$NO_WORK_TRANSCRIPT_UID_INITIAL" = 0 ] \
        && [ "$NO_WORK_TRANSCRIPT_GID_INITIAL" = 0 ] \
        && valid_uint "$NO_WORK_TRANSCRIPT_INODE_INITIAL" \
        && valid_uint "$NO_WORK_TRANSCRIPT_MNT_ID_INITIAL" \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_inode)" = "$NO_WORK_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" = "$NO_WORK_TRANSCRIPT_MNT_ID_INITIAL" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_gid)" = 0 ] || return 1

    NO_WORK_TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/6" | awk '{print $1}')
    NO_WORK_TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/6" | tr -d ' \t\r\n')
    NO_WORK_TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    NO_WORK_TRANSCRIPT_LS=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $NO_WORK_TRANSCRIPT_LS
    NO_WORK_TRANSCRIPT_INODE=${1:-}
    NO_WORK_TRANSCRIPT_MODE=${2:-}
    NO_WORK_TRANSCRIPT_UID=${4:-}
    NO_WORK_TRANSCRIPT_GID=${5:-}
    NO_WORK_TRANSCRIPT_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    valid_sha256 "$NO_WORK_TRANSCRIPT_SHA" \
        && valid_size "$NO_WORK_TRANSCRIPT_BYTES" \
        && [ "$NO_WORK_TRANSCRIPT_TARGET" = "$NO_WORK_TRANSCRIPT_TARGET_INITIAL" ] \
        && [ "$NO_WORK_TRANSCRIPT_INODE" = "$NO_WORK_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$NO_WORK_TRANSCRIPT_MODE" = "$NO_WORK_TRANSCRIPT_MODE_INITIAL" ] \
        && [ "$NO_WORK_TRANSCRIPT_UID" = "$NO_WORK_TRANSCRIPT_UID_INITIAL" ] \
        && [ "$NO_WORK_TRANSCRIPT_GID" = "$NO_WORK_TRANSCRIPT_GID_INITIAL" ] \
        && [ "$NO_WORK_TRANSCRIPT_MNT_ID" = "$NO_WORK_TRANSCRIPT_MNT_ID_INITIAL" ] || return 1

    NO_WORK_SOURCE_ACTIVE_SHA=$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')
    NO_WORK_SOURCE_ACTIVE_BYTES=$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')
    NO_WORK_PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    NO_WORK_PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    NO_WORK_TERMINAL_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
    NO_WORK_TERMINAL_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
    NO_WORK_SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    NO_WORK_SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    for NO_WORK_STARTUP_FILE in "$STARTUP_C1" "$STARTUP_J1" "$STARTUP_J2" "$STARTUP_RELEASE"; do
        is_regular_nonsymlink "$NO_WORK_STARTUP_FILE" || return 1
    done
    NO_WORK_C1_SHA=$(sha256sum "$STARTUP_C1" | awk '{print $1}')
    NO_WORK_C1_BYTES=$(wc -c < "$STARTUP_C1" | tr -d ' \t\r\n')
    NO_WORK_J1_SHA=$(sha256sum "$STARTUP_J1" | awk '{print $1}')
    NO_WORK_J1_BYTES=$(wc -c < "$STARTUP_J1" | tr -d ' \t\r\n')
    NO_WORK_J2_SHA=$(sha256sum "$STARTUP_J2" | awk '{print $1}')
    NO_WORK_J2_BYTES=$(wc -c < "$STARTUP_J2" | tr -d ' \t\r\n')
    NO_WORK_RELEASE_SHA=$(sha256sum "$STARTUP_RELEASE" | awk '{print $1}')
    NO_WORK_RELEASE_BYTES=$(wc -c < "$STARTUP_RELEASE" | tr -d ' \t\r\n')
    for NO_WORK_STARTUP_VALUE in \
        "$NO_WORK_C1_SHA" "$NO_WORK_J1_SHA" "$NO_WORK_J2_SHA" "$NO_WORK_RELEASE_SHA"; do
        valid_sha256 "$NO_WORK_STARTUP_VALUE" || return 1
    done
    for NO_WORK_STARTUP_VALUE in \
        "$NO_WORK_C1_BYTES" "$NO_WORK_J1_BYTES" "$NO_WORK_J2_BYTES" "$NO_WORK_RELEASE_BYTES"; do
        valid_size "$NO_WORK_STARTUP_VALUE" || return 1
    done
    NO_WORK_ACTIVE_COUNT=$(grep -F -c 'S19k handoff-no-work active: jobs will be discarded and UART work is structurally refused' "/proc/$$/fd/6" || true)
    NO_WORK_DISCARDED_JOB_COUNT=$(grep -F -c 'S19k handoff-no-work discarded pool job before clean/work state' "/proc/$$/fd/6" || true)
    NO_WORK_FULL_FRAME_COUNT=$(grep -F -c 'FULL FRAME ON WIRE (' "/proc/$$/fd/6" || true)
    NO_WORK_BOUNDED_TX_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_TX_EVIDENCE' "/proc/$$/fd/6" || true)
    NO_WORK_DISPATCH_ADMITTED_COUNT=$(grep -F -c 'serial work-dispatch admission OK' "/proc/$$/fd/6" || true)
    for NO_WORK_COUNT in \
        "$NO_WORK_ACTIVE_COUNT" "$NO_WORK_DISCARDED_JOB_COUNT" \
        "$NO_WORK_FULL_FRAME_COUNT" "$NO_WORK_BOUNDED_TX_COUNT" \
        "$NO_WORK_DISPATCH_ADMITTED_COUNT"; do
        valid_uint "$NO_WORK_COUNT" || return 1
    done

    NO_WORK_TMP="$TRIAL_DIR/.runtime_handoff_no_work_transcript.tmp.$$.${SELF_START}"
    [ ! -e "$NO_WORK_TMP" ] && [ ! -L "$NO_WORK_TMP" ] \
        && [ ! -e "$NO_WORK_TRANSCRIPT_RECEIPT" ] && [ ! -L "$NO_WORK_TRANSCRIPT_RECEIPT" ] || return 1
    {
        printf 'schema=dcentos.s19k-handoff-no-work-transcript/v1\n'
        printf 'deploy_mode=handoff-no-work\n'
        printf 'transcript_path=%s\ntranscript_mnt_id=%s\ntranscript_inode=%s\n' \
            "$STARTUP_DAEMON_TRANSCRIPT" "$NO_WORK_TRANSCRIPT_MNT_ID" "$NO_WORK_TRANSCRIPT_INODE"
        printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\n'
        printf 'transcript_sha256=%s\ntranscript_bytes=%s\n' "$NO_WORK_TRANSCRIPT_SHA" "$NO_WORK_TRANSCRIPT_BYTES"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'source_runtime_active_path=%s\nsource_runtime_active_sha256=%s\nsource_runtime_active_bytes=%s\n' \
            "$PRE_SAFEOFF_ACTIVE" "$NO_WORK_SOURCE_ACTIVE_SHA" "$NO_WORK_SOURCE_ACTIVE_BYTES"
        printf 'pending_runtime_schema=dcentos.s19k-stock-restart-pending/v4\n'
        printf 'pending_runtime_path=%s\npending_runtime_sha256=%s\npending_runtime_bytes=%s\n' \
            "$ACTIVE" "$NO_WORK_PENDING_SHA" "$NO_WORK_PENDING_BYTES"
        printf 'terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1\n'
        printf 'terminal_handoff_receipt_path=%s\nterminal_handoff_receipt_sha256=%s\nterminal_handoff_receipt_bytes=%s\n' \
            "$TERMINAL_HANDOFF_RECEIPT" "$NO_WORK_TERMINAL_SHA" "$NO_WORK_TERMINAL_BYTES"
        printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
        printf 'safeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' \
            "$SAFEOFF_TERMINAL_RECEIPT" "$NO_WORK_SAFEOFF_SHA" "$NO_WORK_SAFEOFF_BYTES"
        printf 'startup_c1_schema=dcentos.s19k-startup-c1-child-identity/v1\n'
        printf 'startup_c1_path=%s\nstartup_c1_sha256=%s\nstartup_c1_bytes=%s\n' \
            "$STARTUP_C1" "$NO_WORK_C1_SHA" "$NO_WORK_C1_BYTES"
        printf 'startup_j1_schema=dcentos.s19k-startup-j1-daemon-blocked/v1\n'
        printf 'startup_j1_path=%s\nstartup_j1_sha256=%s\nstartup_j1_bytes=%s\n' \
            "$STARTUP_J1" "$NO_WORK_J1_SHA" "$NO_WORK_J1_BYTES"
        printf 'startup_j2_schema=dcentos.s19k-startup-j2-child-bound/v1\n'
        printf 'startup_j2_path=%s\nstartup_j2_sha256=%s\nstartup_j2_bytes=%s\n' \
            "$STARTUP_J2" "$NO_WORK_J2_SHA" "$NO_WORK_J2_BYTES"
        printf 'startup_release_schema=dcentos.s19k-startup-release/v1\n'
        printf 'startup_release_path=%s\nstartup_release_sha256=%s\nstartup_release_bytes=%s\n' \
            "$STARTUP_RELEASE" "$NO_WORK_RELEASE_SHA" "$NO_WORK_RELEASE_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\nlive_identity_sha256=%s\nlive_identity_model_sha256=%s\n' \
            "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA" "$LIVE_IDENTITY_MODEL_SHA"
        printf 'wrapper_exit_status=%s\n' "$NO_WORK_WRAPPER_EXIT_STATUS"
        printf 'no_work_active_count=%s\ndiscarded_job_count=%s\nfull_frame_count=%s\nbounded_tx_count=%s\ndispatch_admitted_count=%s\n' \
            "$NO_WORK_ACTIVE_COUNT" "$NO_WORK_DISCARDED_JOB_COUNT" \
            "$NO_WORK_FULL_FRAME_COUNT" "$NO_WORK_BOUNDED_TX_COUNT" \
            "$NO_WORK_DISPATCH_ADMITTED_COUNT"
        printf 'semantic_verification=host-plus-independent-instruments-required\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$NO_WORK_TMP"
    chmod 600 "$NO_WORK_TMP"
    publish_no_clobber_journal "$NO_WORK_TMP" "$NO_WORK_TRANSCRIPT_RECEIPT" \
        && handoff_no_work_transcript_receipt_is_exact
}

install_custody_transcript_receipt_is_exact() {
    is_regular_nonsymlink "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" \
        && [ "$(wc -l < "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" | tr -d ' \t\r\n')" -eq 77 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" schema)" = dcentos.s19k-install-custody-transcript/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" deploy_mode)" = install-custody-safeoff ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_mnt_id)" = "$INSTALL_TRANSCRIPT_MNT_ID" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_inode)" = "$INSTALL_TRANSCRIPT_INODE" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_gid)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_sha256)" = "$INSTALL_TRANSCRIPT_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" transcript_bytes)" = "$INSTALL_TRANSCRIPT_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" source_runtime_active_schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" source_runtime_active_path)" = "$PRE_SAFEOFF_ACTIVE" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" source_runtime_active_sha256)" = "$INSTALL_SOURCE_ACTIVE_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" source_runtime_active_bytes)" = "$INSTALL_SOURCE_ACTIVE_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" pending_runtime_schema)" = dcentos.s19k-install-custody-stock-restart-pending/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" pending_runtime_path)" = "$ACTIVE" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" pending_runtime_sha256)" = "$INSTALL_PENDING_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" pending_runtime_bytes)" = "$INSTALL_PENDING_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_schema)" = dcentos.s19k-install-custody-terminal-safeoff/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF_RECEIPT" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_sha256)" = "$INSTALL_TERMINAL_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_bytes)" = "$INSTALL_TERMINAL_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" safeoff_receipt_schema)" = dcentos.s19k-install-custody-safeoff/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" safeoff_receipt_sha256)" = "$INSTALL_SAFEOFF_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" safeoff_receipt_bytes)" = "$INSTALL_SAFEOFF_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_c1_schema)" = dcentos.s19k-startup-c1-child-identity/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_c1_path)" = "$STARTUP_C1" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_c1_sha256)" = "$INSTALL_C1_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_c1_bytes)" = "$INSTALL_C1_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j1_schema)" = dcentos.s19k-startup-j1-daemon-blocked/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j1_path)" = "$STARTUP_J1" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j1_sha256)" = "$INSTALL_J1_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j1_bytes)" = "$INSTALL_J1_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j2_schema)" = dcentos.s19k-startup-j2-child-bound/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j2_path)" = "$STARTUP_J2" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j2_sha256)" = "$INSTALL_J2_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_j2_bytes)" = "$INSTALL_J2_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_release_schema)" = dcentos.s19k-startup-release/v1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_release_path)" = "$STARTUP_RELEASE" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_release_sha256)" = "$INSTALL_RELEASE_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" startup_release_bytes)" = "$INSTALL_RELEASE_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" child_cmdline_sha256)" = "$INSTALL_CHILD_CMDLINE_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" child_cmdline_bytes)" = "$INSTALL_CHILD_CMDLINE_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" child_environment_sha256)" = "$INSTALL_CHILD_ENV_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" child_environment_bytes)" = "$INSTALL_CHILD_ENV_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" child_environment_count)" = 10 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" wrapper_exit_status)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" success_marker_count)" = 1 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" pool_connection_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" stratum_start_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" uart_open_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" full_frame_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" bounded_tx_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" dispatch_admitted_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" asic_work_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" reset_work_count)" = 0 ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" mining_config)" = disabled-and-route-free ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" uart_contract)" = not-opened ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" asic_contract)" = not-touched ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" reset_contract)" = not-attempted ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" publication)" = no-clobber-hard-link-after-fsync ]
}

publish_install_custody_transcript_receipt() {
    INSTALL_WRAPPER_EXIT_STATUS=$1
    [ "$DEPLOY_MODE" = install-custody-safeoff ] || return 0
    valid_uint "$INSTALL_WRAPPER_EXIT_STATUS" \
        && [ "$INSTALL_WRAPPER_EXIT_STATUS" -eq 0 ] \
        && [ -e "/proc/$$/fd/6" ] \
        && ! process_matches "$CHILD_PID" "$CHILD_START" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" deploy_mode)" = install-custody-safeoff ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema)" = dcentos.s19k-install-custody-stock-restart-pending/v1 ] \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(terminal_handoff_field resets)" = not-attempted ] \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] || return 1

    INSTALL_TRANSCRIPT_TARGET_INITIAL=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    INSTALL_TRANSCRIPT_LS_INITIAL=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $INSTALL_TRANSCRIPT_LS_INITIAL
    INSTALL_TRANSCRIPT_INODE_INITIAL=${1:-}
    INSTALL_TRANSCRIPT_MODE_INITIAL=${2:-}
    INSTALL_TRANSCRIPT_UID_INITIAL=${4:-}
    INSTALL_TRANSCRIPT_GID_INITIAL=${5:-}
    INSTALL_TRANSCRIPT_MNT_ID_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    [ "$INSTALL_TRANSCRIPT_TARGET_INITIAL" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$INSTALL_TRANSCRIPT_MODE_INITIAL" = -rw------- ] \
        && [ "$INSTALL_TRANSCRIPT_UID_INITIAL" = 0 ] \
        && [ "$INSTALL_TRANSCRIPT_GID_INITIAL" = 0 ] \
        && valid_uint "$INSTALL_TRANSCRIPT_INODE_INITIAL" \
        && valid_uint "$INSTALL_TRANSCRIPT_MNT_ID_INITIAL" \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_inode)" = "$INSTALL_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" = "$INSTALL_TRANSCRIPT_MNT_ID_INITIAL" ] || return 1

    INSTALL_TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/6" | awk '{print $1}')
    INSTALL_TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/6" | tr -d ' \t\r\n')
    INSTALL_TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    INSTALL_TRANSCRIPT_LS=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $INSTALL_TRANSCRIPT_LS
    INSTALL_TRANSCRIPT_INODE=${1:-}
    INSTALL_TRANSCRIPT_MODE=${2:-}
    INSTALL_TRANSCRIPT_UID=${4:-}
    INSTALL_TRANSCRIPT_GID=${5:-}
    INSTALL_TRANSCRIPT_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    valid_sha256 "$INSTALL_TRANSCRIPT_SHA" \
        && valid_size "$INSTALL_TRANSCRIPT_BYTES" \
        && [ "$INSTALL_TRANSCRIPT_TARGET" = "$INSTALL_TRANSCRIPT_TARGET_INITIAL" ] \
        && [ "$INSTALL_TRANSCRIPT_INODE" = "$INSTALL_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$INSTALL_TRANSCRIPT_MODE" = "$INSTALL_TRANSCRIPT_MODE_INITIAL" ] \
        && [ "$INSTALL_TRANSCRIPT_UID" = "$INSTALL_TRANSCRIPT_UID_INITIAL" ] \
        && [ "$INSTALL_TRANSCRIPT_GID" = "$INSTALL_TRANSCRIPT_GID_INITIAL" ] \
        && [ "$INSTALL_TRANSCRIPT_MNT_ID" = "$INSTALL_TRANSCRIPT_MNT_ID_INITIAL" ] || return 1

    INSTALL_SUCCESS_COUNT=$(grep -F -c 'S19k install-custody-safeoff complete: pool=not-configured UART=not-opened ASIC=not-touched reset=not-attempted GPIO437=checked-safeoff watchdog=closed' "/proc/$$/fd/6" || true)
    INSTALL_POOL_COUNT=$(grep -E -c 'Connecting to pool|pool connection (started|established)|mining\.(subscribe|authorize)' "/proc/$$/fd/6" || true)
    INSTALL_STRATUM_COUNT=$(grep -E -c 'Stratum (client|V1|V2).*start|starting Stratum|stratum handshake' "/proc/$$/fd/6" || true)
    INSTALL_UART_COUNT=$(grep -E -c 'opening ttyS1\+ttyS2|Failed to open required passthrough|ttyS3 discover open' "/proc/$$/fd/6" || true)
    INSTALL_FULL_FRAME_COUNT=$(grep -F -c 'FULL FRAME ON WIRE (' "/proc/$$/fd/6" || true)
    INSTALL_BOUNDED_TX_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_TX_EVIDENCE' "/proc/$$/fd/6" || true)
    INSTALL_DISPATCH_COUNT=$(grep -F -c 'serial work-dispatch admission OK' "/proc/$$/fd/6" || true)
    INSTALL_ASIC_COUNT=$(grep -E -c 'ASIC init|SetAddress|GetAddress|chip initialization|work dispatch admitted' "/proc/$$/fd/6" || true)
    INSTALL_RESET_COUNT=$(grep -E -c 'terminal hashboard reset asserted|reset-trio and GPIO437|native all resets' "/proc/$$/fd/6" || true)
    for INSTALL_COUNT in "$INSTALL_SUCCESS_COUNT" "$INSTALL_POOL_COUNT" "$INSTALL_STRATUM_COUNT" \
        "$INSTALL_UART_COUNT" "$INSTALL_FULL_FRAME_COUNT" "$INSTALL_BOUNDED_TX_COUNT" \
        "$INSTALL_DISPATCH_COUNT" "$INSTALL_ASIC_COUNT" "$INSTALL_RESET_COUNT"; do
        valid_uint "$INSTALL_COUNT" || return 1
    done
    [ "$INSTALL_SUCCESS_COUNT" -eq 1 ] \
        && [ "$INSTALL_POOL_COUNT" -eq 0 ] \
        && [ "$INSTALL_STRATUM_COUNT" -eq 0 ] \
        && [ "$INSTALL_UART_COUNT" -eq 0 ] \
        && [ "$INSTALL_FULL_FRAME_COUNT" -eq 0 ] \
        && [ "$INSTALL_BOUNDED_TX_COUNT" -eq 0 ] \
        && [ "$INSTALL_DISPATCH_COUNT" -eq 0 ] \
        && [ "$INSTALL_ASIC_COUNT" -eq 0 ] \
        && [ "$INSTALL_RESET_COUNT" -eq 0 ] || return 1

    INSTALL_SOURCE_ACTIVE_SHA=$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')
    INSTALL_SOURCE_ACTIVE_BYTES=$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')
    INSTALL_PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    INSTALL_PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    INSTALL_TERMINAL_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
    INSTALL_TERMINAL_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
    INSTALL_SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    INSTALL_SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    for INSTALL_STARTUP_FILE in "$STARTUP_C1" "$STARTUP_J1" "$STARTUP_J2" "$STARTUP_RELEASE"; do
        is_regular_nonsymlink "$INSTALL_STARTUP_FILE" || return 1
    done
    INSTALL_C1_SHA=$(sha256sum "$STARTUP_C1" | awk '{print $1}')
    INSTALL_C1_BYTES=$(wc -c < "$STARTUP_C1" | tr -d ' \t\r\n')
    INSTALL_J1_SHA=$(sha256sum "$STARTUP_J1" | awk '{print $1}')
    INSTALL_J1_BYTES=$(wc -c < "$STARTUP_J1" | tr -d ' \t\r\n')
    INSTALL_J2_SHA=$(sha256sum "$STARTUP_J2" | awk '{print $1}')
    INSTALL_J2_BYTES=$(wc -c < "$STARTUP_J2" | tr -d ' \t\r\n')
    INSTALL_RELEASE_SHA=$(sha256sum "$STARTUP_RELEASE" | awk '{print $1}')
    INSTALL_RELEASE_BYTES=$(wc -c < "$STARTUP_RELEASE" | tr -d ' \t\r\n')
    INSTALL_CHILD_CMDLINE_SHA=$(startup_field_at "$STARTUP_C1" child_cmdline_sha256) || return 1
    INSTALL_CHILD_CMDLINE_BYTES=$(startup_field_at "$STARTUP_C1" child_cmdline_bytes) || return 1
    INSTALL_CHILD_ENV_SHA=$(startup_field_at "$STARTUP_C1" child_environment_sha256) || return 1
    INSTALL_CHILD_ENV_BYTES=$(startup_field_at "$STARTUP_C1" child_environment_bytes) || return 1
    INSTALL_CHILD_ENV_COUNT=$(startup_field_at "$STARTUP_C1" child_environment_count) || return 1
    valid_sha256 "$INSTALL_CHILD_CMDLINE_SHA" && valid_size "$INSTALL_CHILD_CMDLINE_BYTES" \
        && valid_sha256 "$INSTALL_CHILD_ENV_SHA" && valid_size "$INSTALL_CHILD_ENV_BYTES" \
        && [ "$INSTALL_CHILD_ENV_COUNT" -eq 10 ] || return 1

    INSTALL_TMP="$TRIAL_DIR/.runtime_install_custody_transcript.tmp.$$.${SELF_START}"
    [ ! -e "$INSTALL_TMP" ] && [ ! -L "$INSTALL_TMP" ] \
        && [ ! -e "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" ] && [ ! -L "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" ] || return 1
    {
        printf 'schema=dcentos.s19k-install-custody-transcript/v1\ndeploy_mode=install-custody-safeoff\n'
        printf 'transcript_path=%s\ntranscript_mnt_id=%s\ntranscript_inode=%s\n' "$STARTUP_DAEMON_TRANSCRIPT" "$INSTALL_TRANSCRIPT_MNT_ID" "$INSTALL_TRANSCRIPT_INODE"
        printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\ntranscript_sha256=%s\ntranscript_bytes=%s\n' "$INSTALL_TRANSCRIPT_SHA" "$INSTALL_TRANSCRIPT_BYTES"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\nsource_runtime_active_path=%s\nsource_runtime_active_sha256=%s\nsource_runtime_active_bytes=%s\n' "$PRE_SAFEOFF_ACTIVE" "$INSTALL_SOURCE_ACTIVE_SHA" "$INSTALL_SOURCE_ACTIVE_BYTES"
        printf 'pending_runtime_schema=dcentos.s19k-install-custody-stock-restart-pending/v1\npending_runtime_path=%s\npending_runtime_sha256=%s\npending_runtime_bytes=%s\n' "$ACTIVE" "$INSTALL_PENDING_SHA" "$INSTALL_PENDING_BYTES"
        printf 'terminal_handoff_receipt_schema=dcentos.s19k-install-custody-terminal-safeoff/v1\nterminal_handoff_receipt_path=%s\nterminal_handoff_receipt_sha256=%s\nterminal_handoff_receipt_bytes=%s\n' "$TERMINAL_HANDOFF_RECEIPT" "$INSTALL_TERMINAL_SHA" "$INSTALL_TERMINAL_BYTES"
        printf 'safeoff_receipt_schema=dcentos.s19k-install-custody-safeoff/v1\nsafeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' "$SAFEOFF_TERMINAL_RECEIPT" "$INSTALL_SAFEOFF_SHA" "$INSTALL_SAFEOFF_BYTES"
        printf 'startup_c1_schema=dcentos.s19k-startup-c1-child-identity/v1\nstartup_c1_path=%s\nstartup_c1_sha256=%s\nstartup_c1_bytes=%s\n' "$STARTUP_C1" "$INSTALL_C1_SHA" "$INSTALL_C1_BYTES"
        printf 'startup_j1_schema=dcentos.s19k-startup-j1-daemon-blocked/v1\nstartup_j1_path=%s\nstartup_j1_sha256=%s\nstartup_j1_bytes=%s\n' "$STARTUP_J1" "$INSTALL_J1_SHA" "$INSTALL_J1_BYTES"
        printf 'startup_j2_schema=dcentos.s19k-startup-j2-child-bound/v1\nstartup_j2_path=%s\nstartup_j2_sha256=%s\nstartup_j2_bytes=%s\n' "$STARTUP_J2" "$INSTALL_J2_SHA" "$INSTALL_J2_BYTES"
        printf 'startup_release_schema=dcentos.s19k-startup-release/v1\nstartup_release_path=%s\nstartup_release_sha256=%s\nstartup_release_bytes=%s\n' "$STARTUP_RELEASE" "$INSTALL_RELEASE_SHA" "$INSTALL_RELEASE_BYTES"
        printf 'child_cmdline_sha256=%s\nchild_cmdline_bytes=%s\nchild_environment_sha256=%s\nchild_environment_bytes=%s\nchild_environment_count=%s\n' "$INSTALL_CHILD_CMDLINE_SHA" "$INSTALL_CHILD_CMDLINE_BYTES" "$INSTALL_CHILD_ENV_SHA" "$INSTALL_CHILD_ENV_BYTES" "$INSTALL_CHILD_ENV_COUNT"
        printf 'binary_sha256=%s\nbinary_bytes=%s\nconfig_sha256=%s\nconfig_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES" "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\ncustody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES" "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\nlive_identity_profile=%s\nlive_identity_sha256=%s\nlive_identity_model_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA" "$LIVE_IDENTITY_MODEL_SHA"
        printf 'wrapper_exit_status=%s\nsuccess_marker_count=%s\npool_connection_count=%s\nstratum_start_count=%s\nuart_open_count=%s\n' "$INSTALL_WRAPPER_EXIT_STATUS" "$INSTALL_SUCCESS_COUNT" "$INSTALL_POOL_COUNT" "$INSTALL_STRATUM_COUNT" "$INSTALL_UART_COUNT"
        printf 'full_frame_count=%s\nbounded_tx_count=%s\ndispatch_admitted_count=%s\nasic_work_count=%s\nreset_work_count=%s\n' "$INSTALL_FULL_FRAME_COUNT" "$INSTALL_BOUNDED_TX_COUNT" "$INSTALL_DISPATCH_COUNT" "$INSTALL_ASIC_COUNT" "$INSTALL_RESET_COUNT"
        printf 'mining_config=disabled-and-route-free\nuart_contract=not-opened\nasic_contract=not-touched\nreset_contract=not-attempted\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$INSTALL_TMP"
    chmod 600 "$INSTALL_TMP"
    publish_no_clobber_journal "$INSTALL_TMP" "$INSTALL_CUSTODY_TRANSCRIPT_RECEIPT" \
        && install_custody_transcript_receipt_is_exact
}

bounded_work_transcript_receipt_is_exact() {
    is_regular_nonsymlink "$BOUNDED_TRANSCRIPT_RECEIPT" \
        && [ "$(wc -l < "$BOUNDED_TRANSCRIPT_RECEIPT" | tr -d ' \t\r\n')" -eq 51 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" schema)" = dcentos.s19k-bounded-work-transcript/v1 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" deploy_mode)" = bounded-work-proof ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_mnt_id)" = "$BOUNDED_TRANSCRIPT_MNT_ID" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_inode)" = "$BOUNDED_TRANSCRIPT_INODE" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_gid)" = 0 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_sha256)" = "$BOUNDED_TRANSCRIPT_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" transcript_bytes)" = "$BOUNDED_TRANSCRIPT_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" source_runtime_active_schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" source_runtime_active_path)" = "$PRE_SAFEOFF_ACTIVE" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" source_runtime_active_sha256)" = "$BOUNDED_SOURCE_ACTIVE_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" source_runtime_active_bytes)" = "$BOUNDED_SOURCE_ACTIVE_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" pending_runtime_schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" pending_runtime_path)" = "$ACTIVE" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" pending_runtime_sha256)" = "$BOUNDED_PENDING_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" pending_runtime_bytes)" = "$BOUNDED_PENDING_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_schema)" = dcentos.s19k-terminal-safeoff-partial-stock-owner/v1 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF_RECEIPT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_sha256)" = "$BOUNDED_TERMINAL_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" terminal_handoff_receipt_bytes)" = "$BOUNDED_TERMINAL_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" safeoff_receipt_schema)" = dcentos.s19k-track1-safeoff/v1 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" safeoff_receipt_sha256)" = "$BOUNDED_SAFEOFF_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" safeoff_receipt_bytes)" = "$BOUNDED_SAFEOFF_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" wrapper_exit_status)" = "$BOUNDED_WRAPPER_EXIT_STATUS" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" started_count)" = "$BOUNDED_STARTED_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" tx_count)" = "$BOUNDED_TX_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" rx_count)" = "$BOUNDED_RX_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" attribution_count)" = "$BOUNDED_ATTRIBUTION_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" pool_result_count)" = "$BOUNDED_POOL_RESULT_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" complete_count)" = "$BOUNDED_COMPLETE_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" incomplete_count)" = "$BOUNDED_INCOMPLETE_COUNT" ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" semantic_verification)" = host-required ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" persistent_mutation)" = false ] \
        && [ "$(startup_field_at "$BOUNDED_TRANSCRIPT_RECEIPT" publication)" = no-clobber-hard-link-after-fsync ]
}

# Hash the exact transcript inode held by this wrapper only after the bounded
# daemon is gone and checked SafeOff has become a typed stock-restart-pending
# obligation.  The target does not claim semantic success here: the copied
# receipt deliberately requires the independent host verifier.
publish_bounded_work_transcript_receipt() {
    BOUNDED_WRAPPER_EXIT_STATUS=$1
    [ "$DEPLOY_MODE" = bounded-work-proof ] || return 0
    valid_uint "$BOUNDED_WRAPPER_EXIT_STATUS" \
        && [ "$BOUNDED_WRAPPER_EXIT_STATUS" -le 255 ] || return 1
    [ -e "/proc/$$/fd/6" ] \
        && ! process_matches "$CHILD_PID" "$CHILD_START" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" deploy_mode)" = bounded-work-proof ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && [ "$(active_field source_runtime_active_sha256)" = "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" ] \
        && [ "$(active_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ] \
        && [ "$(active_field terminal_handoff_receipt_sha256)" = "$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')" ] || return 1

    BOUNDED_TRANSCRIPT_TARGET_INITIAL=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    BOUNDED_TRANSCRIPT_LS_INITIAL=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $BOUNDED_TRANSCRIPT_LS_INITIAL
    BOUNDED_TRANSCRIPT_INODE_INITIAL=${1:-}
    BOUNDED_TRANSCRIPT_MODE_INITIAL=${2:-}
    BOUNDED_TRANSCRIPT_UID_INITIAL=${4:-}
    BOUNDED_TRANSCRIPT_GID_INITIAL=${5:-}
    BOUNDED_TRANSCRIPT_MNT_ID_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    [ "$BOUNDED_TRANSCRIPT_TARGET_INITIAL" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$BOUNDED_TRANSCRIPT_MODE_INITIAL" = -rw------- ] \
        && [ "$BOUNDED_TRANSCRIPT_UID_INITIAL" = 0 ] \
        && [ "$BOUNDED_TRANSCRIPT_GID_INITIAL" = 0 ] \
        && valid_uint "$BOUNDED_TRANSCRIPT_INODE_INITIAL" \
        && valid_uint "$BOUNDED_TRANSCRIPT_MNT_ID_INITIAL" \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_path)" = "$STARTUP_DAEMON_TRANSCRIPT" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_inode)" = "$BOUNDED_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mnt_id)" = "$BOUNDED_TRANSCRIPT_MNT_ID_INITIAL" ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_mode)" = 0600 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_uid)" = 0 ] \
        && [ "$(startup_field_at "$STARTUP_C1" transcript_gid)" = 0 ] || return 1

    BOUNDED_TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/6" | awk '{print $1}')
    BOUNDED_TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/6" | tr -d ' \t\r\n')
    BOUNDED_TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
    BOUNDED_TRANSCRIPT_LS=$(ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
    set -- $BOUNDED_TRANSCRIPT_LS
    BOUNDED_TRANSCRIPT_INODE=${1:-}
    BOUNDED_TRANSCRIPT_MODE=${2:-}
    BOUNDED_TRANSCRIPT_UID=${4:-}
    BOUNDED_TRANSCRIPT_GID=${5:-}
    BOUNDED_TRANSCRIPT_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
    valid_sha256 "$BOUNDED_TRANSCRIPT_SHA" \
        && valid_size "$BOUNDED_TRANSCRIPT_BYTES" \
        && [ "$BOUNDED_TRANSCRIPT_TARGET" = "$BOUNDED_TRANSCRIPT_TARGET_INITIAL" ] \
        && [ "$BOUNDED_TRANSCRIPT_INODE" = "$BOUNDED_TRANSCRIPT_INODE_INITIAL" ] \
        && [ "$BOUNDED_TRANSCRIPT_MODE" = "$BOUNDED_TRANSCRIPT_MODE_INITIAL" ] \
        && [ "$BOUNDED_TRANSCRIPT_UID" = "$BOUNDED_TRANSCRIPT_UID_INITIAL" ] \
        && [ "$BOUNDED_TRANSCRIPT_GID" = "$BOUNDED_TRANSCRIPT_GID_INITIAL" ] \
        && [ "$BOUNDED_TRANSCRIPT_MNT_ID" = "$BOUNDED_TRANSCRIPT_MNT_ID_INITIAL" ] || return 1

    BOUNDED_SOURCE_ACTIVE_SHA=$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')
    BOUNDED_SOURCE_ACTIVE_BYTES=$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')
    BOUNDED_PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    BOUNDED_PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    BOUNDED_TERMINAL_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
    BOUNDED_TERMINAL_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
    BOUNDED_SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    BOUNDED_SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    BOUNDED_STARTED_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_PROOF_STARTED' "/proc/$$/fd/6" || true)
    BOUNDED_TX_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_TX_EVIDENCE' "/proc/$$/fd/6" || true)
    BOUNDED_RX_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_RX_EVIDENCE' "/proc/$$/fd/6" || true)
    BOUNDED_ATTRIBUTION_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_RX_ATTRIBUTION_EVIDENCE' "/proc/$$/fd/6" || true)
    BOUNDED_POOL_RESULT_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_POOL_RESULT_EVIDENCE' "/proc/$$/fd/6" || true)
    BOUNDED_COMPLETE_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_PROOF_COMPLETE' "/proc/$$/fd/6" || true)
    BOUNDED_INCOMPLETE_COUNT=$(grep -F -c 'S19K_BOUNDED_WORK_PROOF_INCOMPLETE' "/proc/$$/fd/6" || true)
    for BOUNDED_COUNT in \
        "$BOUNDED_STARTED_COUNT" "$BOUNDED_TX_COUNT" "$BOUNDED_RX_COUNT" \
        "$BOUNDED_ATTRIBUTION_COUNT" "$BOUNDED_POOL_RESULT_COUNT" \
        "$BOUNDED_COMPLETE_COUNT" "$BOUNDED_INCOMPLETE_COUNT"; do
        valid_uint "$BOUNDED_COUNT" || return 1
    done

    BOUNDED_TMP="$TRIAL_DIR/.runtime_bounded_work_transcript.tmp.$$.${SELF_START}"
    [ ! -e "$BOUNDED_TMP" ] && [ ! -L "$BOUNDED_TMP" ] \
        && [ ! -e "$BOUNDED_TRANSCRIPT_RECEIPT" ] && [ ! -L "$BOUNDED_TRANSCRIPT_RECEIPT" ] || return 1
    {
        printf 'schema=dcentos.s19k-bounded-work-transcript/v1\n'
        printf 'deploy_mode=bounded-work-proof\n'
        printf 'transcript_path=%s\ntranscript_mnt_id=%s\ntranscript_inode=%s\n' \
            "$STARTUP_DAEMON_TRANSCRIPT" "$BOUNDED_TRANSCRIPT_MNT_ID" "$BOUNDED_TRANSCRIPT_INODE"
        printf 'transcript_mode=0600\ntranscript_uid=0\ntranscript_gid=0\n'
        printf 'transcript_sha256=%s\ntranscript_bytes=%s\n' "$BOUNDED_TRANSCRIPT_SHA" "$BOUNDED_TRANSCRIPT_BYTES"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'source_runtime_active_path=%s\nsource_runtime_active_sha256=%s\nsource_runtime_active_bytes=%s\n' \
            "$PRE_SAFEOFF_ACTIVE" "$BOUNDED_SOURCE_ACTIVE_SHA" "$BOUNDED_SOURCE_ACTIVE_BYTES"
        printf 'pending_runtime_schema=dcentos.s19k-stock-restart-pending/v4\n'
        printf 'pending_runtime_path=%s\npending_runtime_sha256=%s\npending_runtime_bytes=%s\n' \
            "$ACTIVE" "$BOUNDED_PENDING_SHA" "$BOUNDED_PENDING_BYTES"
        printf 'terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1\n'
        printf 'terminal_handoff_receipt_path=%s\nterminal_handoff_receipt_sha256=%s\nterminal_handoff_receipt_bytes=%s\n' \
            "$TERMINAL_HANDOFF_RECEIPT" "$BOUNDED_TERMINAL_SHA" "$BOUNDED_TERMINAL_BYTES"
        printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
        printf 'safeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' \
            "$SAFEOFF_TERMINAL_RECEIPT" "$BOUNDED_SAFEOFF_SHA" "$BOUNDED_SAFEOFF_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\nlive_identity_sha256=%s\nlive_identity_model_sha256=%s\n' \
            "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA" "$LIVE_IDENTITY_MODEL_SHA"
        printf 'wrapper_exit_status=%s\n' "$BOUNDED_WRAPPER_EXIT_STATUS"
        printf 'started_count=%s\ntx_count=%s\nrx_count=%s\nattribution_count=%s\npool_result_count=%s\ncomplete_count=%s\nincomplete_count=%s\n' \
            "$BOUNDED_STARTED_COUNT" "$BOUNDED_TX_COUNT" "$BOUNDED_RX_COUNT" \
            "$BOUNDED_ATTRIBUTION_COUNT" "$BOUNDED_POOL_RESULT_COUNT" \
            "$BOUNDED_COMPLETE_COUNT" "$BOUNDED_INCOMPLETE_COUNT"
        printf 'semantic_verification=host-required\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$BOUNDED_TMP"
    chmod 600 "$BOUNDED_TMP"
    publish_no_clobber_journal "$BOUNDED_TMP" "$BOUNDED_TRANSCRIPT_RECEIPT" \
        && bounded_work_transcript_receipt_is_exact
}

endurance_daemon_terminal_is_exact() {
    endurance_regular_evidence_is_exact "$ENDURANCE_DAEMON_TERMINAL" 4096 \
        && [ "$(wc -l < "$ENDURANCE_DAEMON_TERMINAL" | tr -d ' \t\r\n')" -eq 15 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" schema)" = dcentos.s19k-endurance-daemon-terminal/v1 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" outcome)" = pass-pending-runner-safeoff ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" minimum_s)" = 86400 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" maximum_s)" = 93600 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" acceptance_windows)" = 4x6h-per-required-uart ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    ENDURANCE_ELAPSED=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" elapsed_s) || return 1
    ENDURANCE_SEGMENT_COUNT=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" segment_count) || return 1
    ENDURANCE_TERMINAL_SEQUENCE=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" terminal_sequence) || return 1
    ENDURANCE_CHAIN_HEAD=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" segment_chain_head_sha256) || return 1
    ENDURANCE_OFF_TARGET_MANIFEST_SHA=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" off_target_manifest_sha256) || return 1
    ENDURANCE_OFF_TARGET_MANIFEST_BYTES=$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" off_target_manifest_bytes) || return 1
    valid_uint "$ENDURANCE_ELAPSED" && [ "$ENDURANCE_ELAPSED" -ge 86400 ] && [ "$ENDURANCE_ELAPSED" -lt 93600 ] \
        && valid_size "$ENDURANCE_SEGMENT_COUNT" && [ "$ENDURANCE_SEGMENT_COUNT" -le 1561 ] \
        && endurance_sequence_is_valid "$ENDURANCE_TERMINAL_SEQUENCE" \
        && [ "$ENDURANCE_SEGMENT_COUNT" -eq $((ENDURANCE_TERMINAL_SEQUENCE + 1)) ] \
        && valid_sha256 "$ENDURANCE_CHAIN_HEAD" \
        && valid_sha256 "$ENDURANCE_OFF_TARGET_MANIFEST_SHA" \
        && valid_size "$ENDURANCE_OFF_TARGET_MANIFEST_BYTES" \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" runtime_active_sha256)" = "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" runtime_active_bytes)" = "$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_TERMINAL" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] || return 1
    ENDURANCE_TERMINAL_SEGMENT=$(endurance_segment_path "$ENDURANCE_TERMINAL_SEQUENCE") || return 1
    ENDURANCE_TERMINAL_ACK=$(endurance_ack_path "$ENDURANCE_TERMINAL_SEQUENCE") || return 1
    endurance_regular_evidence_is_exact "$ENDURANCE_TERMINAL_SEGMENT" 65536 \
        && [ "$(sha256sum "$ENDURANCE_TERMINAL_SEGMENT" | awk '{print $1}')" = "$ENDURANCE_CHAIN_HEAD" ] \
        && endurance_regular_evidence_is_exact "$ENDURANCE_TERMINAL_ACK" 4096 \
        && [ "$(startup_field_at "$ENDURANCE_TERMINAL_ACK" segment_sha256)" = "$ENDURANCE_CHAIN_HEAD" ] \
        && [ "$(startup_field_at "$ENDURANCE_TERMINAL_ACK" off_target_manifest_sha256)" = "$ENDURANCE_OFF_TARGET_MANIFEST_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_TERMINAL_ACK" off_target_manifest_bytes)" = "$ENDURANCE_OFF_TARGET_MANIFEST_BYTES" ]
}

endurance_daemon_failure_is_exact() {
    endurance_regular_evidence_is_exact "$ENDURANCE_DAEMON_FAILURE" 65536 \
        && [ "$(wc -l < "$ENDURANCE_DAEMON_FAILURE" | tr -d ' \t\r\n')" -eq 16 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" schema)" = dcentos.s19k-endurance-daemon-failure/v1 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" outcome)" = fail-after-checked-safeoff ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" checked_safeoff)" = true ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    ENDURANCE_FAILURE_ELAPSED=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" elapsed_s) || return 1
    ENDURANCE_FAILURE_SEGMENT_COUNT=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" segment_count) || return 1
    ENDURANCE_FAILURE_ACKNOWLEDGED=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" acknowledged_segments) || return 1
    ENDURANCE_FAILURE_UNACKNOWLEDGED=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" unacknowledged_segments) || return 1
    ENDURANCE_FAILURE_UNACKNOWLEDGED_BYTES=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" unacknowledged_bytes) || return 1
    ENDURANCE_FAILURE_CHAIN_HEAD=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" segment_chain_head_sha256) || return 1
    ENDURANCE_FAILURE_MANIFEST_SHA=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" off_target_manifest_sha256) || return 1
    ENDURANCE_FAILURE_MANIFEST_BYTES=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" off_target_manifest_bytes) || return 1
    ENDURANCE_FAILURE_REASON_HEX=$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" failure_reason_utf8_hex) || return 1
    case "$ENDURANCE_FAILURE_REASON_HEX" in ''|*[!0-9a-f]*) return 1 ;; esac
    valid_uint "$ENDURANCE_FAILURE_ELAPSED" \
        && valid_uint "$ENDURANCE_FAILURE_SEGMENT_COUNT" \
        && [ "$ENDURANCE_FAILURE_SEGMENT_COUNT" -le 1561 ] \
        && valid_uint "$ENDURANCE_FAILURE_ACKNOWLEDGED" \
        && [ "$ENDURANCE_FAILURE_ACKNOWLEDGED" -le "$ENDURANCE_FAILURE_SEGMENT_COUNT" ] \
        && valid_uint "$ENDURANCE_FAILURE_UNACKNOWLEDGED" \
        && [ "$ENDURANCE_FAILURE_UNACKNOWLEDGED" -eq $((ENDURANCE_FAILURE_SEGMENT_COUNT - ENDURANCE_FAILURE_ACKNOWLEDGED)) ] \
        && valid_uint "$ENDURANCE_FAILURE_UNACKNOWLEDGED_BYTES" \
        && [ "$ENDURANCE_FAILURE_UNACKNOWLEDGED_BYTES" -le 524288 ] \
        && valid_sha256 "$ENDURANCE_FAILURE_CHAIN_HEAD" \
        && valid_sha256 "$ENDURANCE_FAILURE_MANIFEST_SHA" \
        && valid_uint "$ENDURANCE_FAILURE_MANIFEST_BYTES" \
        && [ "${#ENDURANCE_FAILURE_REASON_HEX}" -le 16384 ] \
        && [ $((${#ENDURANCE_FAILURE_REASON_HEX} % 2)) -eq 0 ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" runtime_active_sha256)" = "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" runtime_active_bytes)" = "$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')" ] \
        && [ "$(startup_field_at "$ENDURANCE_DAEMON_FAILURE" live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ]
}

publish_endurance_failure_receipt() {
    ENDURANCE_FAILURE_WRAPPER_STATUS=$1
    valid_uint "$ENDURANCE_FAILURE_WRAPPER_STATUS" \
        && [ "$ENDURANCE_FAILURE_WRAPPER_STATUS" -gt 0 ] \
        && [ "$ENDURANCE_FAILURE_WRAPPER_STATUS" -le 255 ] \
        && ! process_matches "$CHILD_PID" "$CHILD_START" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" deploy_mode)" = endurance-work-proof ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && endurance_daemon_failure_is_exact || return 1
    ENDURANCE_FAILURE_TMP="$TRIAL_DIR/.runtime_endurance_failure_receipt.tmp.$$.${SELF_START}"
    [ ! -e "$ENDURANCE_FAILURE_RECEIPT" ] && [ ! -L "$ENDURANCE_FAILURE_RECEIPT" ] \
        && [ ! -e "$ENDURANCE_FAILURE_TMP" ] && [ ! -L "$ENDURANCE_FAILURE_TMP" ] || return 1
    ENDURANCE_FAILURE_DAEMON_SHA=$(sha256sum "$ENDURANCE_DAEMON_FAILURE" | awk '{print $1}')
    ENDURANCE_FAILURE_DAEMON_BYTES=$(wc -c < "$ENDURANCE_DAEMON_FAILURE" | tr -d ' \t\r\n')
    ENDURANCE_FAILURE_SOURCE_SHA=$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')
    ENDURANCE_FAILURE_SOURCE_BYTES=$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')
    ENDURANCE_FAILURE_PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    ENDURANCE_FAILURE_PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    ENDURANCE_FAILURE_HANDOFF_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
    ENDURANCE_FAILURE_HANDOFF_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
    ENDURANCE_FAILURE_SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    ENDURANCE_FAILURE_SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    {
        printf 'schema=dcentos.s19k-endurance-failure-receipt/v1\n'
        printf 'deploy_mode=endurance-work-proof\noutcome=fail-after-checked-safeoff\n'
        printf 'daemon_failure_path=%s\ndaemon_failure_sha256=%s\ndaemon_failure_bytes=%s\n' \
            "$ENDURANCE_DAEMON_FAILURE" "$ENDURANCE_FAILURE_DAEMON_SHA" "$ENDURANCE_FAILURE_DAEMON_BYTES"
        printf 'elapsed_s=%s\nsegment_count=%s\nacknowledged_segments=%s\nunacknowledged_segments=%s\nunacknowledged_bytes=%s\n' \
            "$ENDURANCE_FAILURE_ELAPSED" "$ENDURANCE_FAILURE_SEGMENT_COUNT" \
            "$ENDURANCE_FAILURE_ACKNOWLEDGED" "$ENDURANCE_FAILURE_UNACKNOWLEDGED" \
            "$ENDURANCE_FAILURE_UNACKNOWLEDGED_BYTES"
        printf 'segment_chain_head_sha256=%s\noff_target_manifest_sha256=%s\noff_target_manifest_bytes=%s\n' \
            "$ENDURANCE_FAILURE_CHAIN_HEAD" "$ENDURANCE_FAILURE_MANIFEST_SHA" "$ENDURANCE_FAILURE_MANIFEST_BYTES"
        printf 'failure_reason_utf8_hex=%s\n' "$ENDURANCE_FAILURE_REASON_HEX"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'source_runtime_active_path=%s\nsource_runtime_active_sha256=%s\nsource_runtime_active_bytes=%s\n' \
            "$PRE_SAFEOFF_ACTIVE" "$ENDURANCE_FAILURE_SOURCE_SHA" "$ENDURANCE_FAILURE_SOURCE_BYTES"
        printf 'pending_runtime_schema=dcentos.s19k-stock-restart-pending/v4\n'
        printf 'pending_runtime_path=%s\npending_runtime_sha256=%s\npending_runtime_bytes=%s\n' \
            "$ACTIVE" "$ENDURANCE_FAILURE_PENDING_SHA" "$ENDURANCE_FAILURE_PENDING_BYTES"
        printf 'terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1\n'
        printf 'terminal_handoff_receipt_path=%s\nterminal_handoff_receipt_sha256=%s\nterminal_handoff_receipt_bytes=%s\n' \
            "$TERMINAL_HANDOFF_RECEIPT" "$ENDURANCE_FAILURE_HANDOFF_SHA" "$ENDURANCE_FAILURE_HANDOFF_BYTES"
        printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
        printf 'safeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' \
            "$SAFEOFF_TERMINAL_RECEIPT" "$ENDURANCE_FAILURE_SAFEOFF_SHA" "$ENDURANCE_FAILURE_SAFEOFF_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\nlive_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'wrapper_exit_status=%s\nsemantic_verification=host-required\n' "$ENDURANCE_FAILURE_WRAPPER_STATUS"
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$ENDURANCE_FAILURE_TMP"
    chmod 600 "$ENDURANCE_FAILURE_TMP"
    publish_no_clobber_journal "$ENDURANCE_FAILURE_TMP" "$ENDURANCE_FAILURE_RECEIPT" \
        && endurance_regular_evidence_is_exact "$ENDURANCE_FAILURE_RECEIPT" 65536 \
        && [ "$(wc -l < "$ENDURANCE_FAILURE_RECEIPT" | tr -d ' \t\r\n')" -eq 48 ] \
        && [ "$(startup_field_at "$ENDURANCE_FAILURE_RECEIPT" schema)" = dcentos.s19k-endurance-failure-receipt/v1 ] \
        && [ "$(startup_field_at "$ENDURANCE_FAILURE_RECEIPT" daemon_failure_sha256)" = "$ENDURANCE_FAILURE_DAEMON_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_FAILURE_RECEIPT" safeoff_receipt_sha256)" = "$ENDURANCE_FAILURE_SAFEOFF_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_FAILURE_RECEIPT" wrapper_exit_status)" = "$ENDURANCE_FAILURE_WRAPPER_STATUS" ] \
        && [ "$(startup_field_at "$ENDURANCE_FAILURE_RECEIPT" publication)" = no-clobber-hard-link-after-fsync ]
}

publish_endurance_work_receipt() {
    ENDURANCE_WRAPPER_EXIT_STATUS=$1
    [ "$DEPLOY_MODE" = endurance-work-proof ] || return 0
    valid_uint "$ENDURANCE_WRAPPER_EXIT_STATUS" \
        && [ "$ENDURANCE_WRAPPER_EXIT_STATUS" -le 255 ] || return 1
    if [ "$ENDURANCE_WRAPPER_EXIT_STATUS" -ne 0 ]; then
        publish_endurance_failure_receipt "$ENDURANCE_WRAPPER_EXIT_STATUS"
        return
    fi
    [ "$ENDURANCE_WRAPPER_EXIT_STATUS" = 0 ] \
        && ! process_matches "$CHILD_PID" "$CHILD_START" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field_at "$PRE_SAFEOFF_ACTIVE" deploy_mode)" = endurance-work-proof ] \
        && is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
        && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && endurance_daemon_terminal_is_exact || return 1
    ENDURANCE_RECEIPT="$TRIAL_DIR/runtime_endurance_work_receipt"
    ENDURANCE_RECEIPT_TMP="$TRIAL_DIR/.runtime_endurance_work_receipt.tmp.$$.${SELF_START}"
    [ ! -e "$ENDURANCE_RECEIPT" ] && [ ! -L "$ENDURANCE_RECEIPT" ] \
        && [ ! -e "$ENDURANCE_RECEIPT_TMP" ] && [ ! -L "$ENDURANCE_RECEIPT_TMP" ] || return 1
    ENDURANCE_DAEMON_SHA=$(sha256sum "$ENDURANCE_DAEMON_TERMINAL" | awk '{print $1}')
    ENDURANCE_DAEMON_BYTES=$(wc -c < "$ENDURANCE_DAEMON_TERMINAL" | tr -d ' \t\r\n')
    ENDURANCE_SOURCE_SHA=$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')
    ENDURANCE_SOURCE_BYTES=$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')
    ENDURANCE_PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    ENDURANCE_PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    ENDURANCE_TERMINAL_HANDOFF_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
    ENDURANCE_TERMINAL_HANDOFF_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
    ENDURANCE_SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    ENDURANCE_SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    {
        printf 'schema=dcentos.s19k-endurance-work-receipt/v1\n'
        printf 'deploy_mode=endurance-work-proof\n'
        printf 'daemon_terminal_path=%s\n' "$ENDURANCE_DAEMON_TERMINAL"
        printf 'daemon_terminal_sha256=%s\n' "$ENDURANCE_DAEMON_SHA"
        printf 'daemon_terminal_bytes=%s\n' "$ENDURANCE_DAEMON_BYTES"
        printf 'segment_count=%s\nterminal_sequence=%s\nsegment_chain_head_sha256=%s\n' \
            "$ENDURANCE_SEGMENT_COUNT" "$ENDURANCE_TERMINAL_SEQUENCE" "$ENDURANCE_CHAIN_HEAD"
        printf 'off_target_manifest_sha256=%s\noff_target_manifest_bytes=%s\n' \
            "$ENDURANCE_OFF_TARGET_MANIFEST_SHA" "$ENDURANCE_OFF_TARGET_MANIFEST_BYTES"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'source_runtime_active_path=%s\nsource_runtime_active_sha256=%s\nsource_runtime_active_bytes=%s\n' \
            "$PRE_SAFEOFF_ACTIVE" "$ENDURANCE_SOURCE_SHA" "$ENDURANCE_SOURCE_BYTES"
        printf 'pending_runtime_schema=dcentos.s19k-stock-restart-pending/v4\n'
        printf 'pending_runtime_path=%s\npending_runtime_sha256=%s\npending_runtime_bytes=%s\n' \
            "$ACTIVE" "$ENDURANCE_PENDING_SHA" "$ENDURANCE_PENDING_BYTES"
        printf 'terminal_handoff_receipt_schema=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1\n'
        printf 'terminal_handoff_receipt_path=%s\nterminal_handoff_receipt_sha256=%s\nterminal_handoff_receipt_bytes=%s\n' \
            "$TERMINAL_HANDOFF_RECEIPT" "$ENDURANCE_TERMINAL_HANDOFF_SHA" "$ENDURANCE_TERMINAL_HANDOFF_BYTES"
        printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
        printf 'safeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' \
            "$SAFEOFF_TERMINAL_RECEIPT" "$ENDURANCE_SAFEOFF_SHA" "$ENDURANCE_SAFEOFF_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\nlive_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'wrapper_exit_status=0\nsemantic_verification=host-required\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$ENDURANCE_RECEIPT_TMP"
    chmod 600 "$ENDURANCE_RECEIPT_TMP"
    publish_no_clobber_journal "$ENDURANCE_RECEIPT_TMP" "$ENDURANCE_RECEIPT" \
        && endurance_regular_evidence_is_exact "$ENDURANCE_RECEIPT" 65536 \
        && [ "$(wc -l < "$ENDURANCE_RECEIPT" | tr -d ' \t\r\n')" -eq 43 ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" schema)" = dcentos.s19k-endurance-work-receipt/v1 ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" daemon_terminal_sha256)" = "$ENDURANCE_DAEMON_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" off_target_manifest_sha256)" = "$ENDURANCE_OFF_TARGET_MANIFEST_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" safeoff_receipt_sha256)" = "$ENDURANCE_SAFEOFF_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" terminal_handoff_receipt_sha256)" = "$ENDURANCE_TERMINAL_HANDOFF_SHA" ] \
        && [ "$(startup_field_at "$ENDURANCE_RECEIPT" publication)" = no-clobber-hard-link-after-fsync ]
}

publish_mode_specific_receipts_after_safeoff() {
    MODE_WRAPPER_EXIT_STATUS=$1
    publish_install_custody_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS" || {
        echo "ERROR: install-custody transcript could not bind the pool/UART/ASIC/reset-free checked SafeOff; stock restart remains pending" >&2
        return 1
    }
    publish_handoff_no_work_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS" || {
        echo "ERROR: no-work transcript could not be bound after checked SafeOff; stock restart remains pending" >&2
        return 1
    }
    publish_bounded_work_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS" || {
        echo "ERROR: bounded-work transcript could not be bound after checked SafeOff; stock restart remains pending" >&2
        return 1
    }
    publish_endurance_work_receipt "$MODE_WRAPPER_EXIT_STATUS" || {
        echo "ERROR: endurance receipt could not bind the acknowledged segment chain and checked SafeOff; stock restart remains pending" >&2
        return 1
    }
    if [ "$DEPLOY_MODE" = install-custody-safeoff ] \
        || [ "$DEPLOY_MODE" = handoff-no-work ] \
        || [ "$DEPLOY_MODE" = bounded-work-proof ]; then
        exec 6>&-
    fi
}

startup_source_field() {
    startup_field_at "$STARTUP_PRESAFEOFF_SOURCE" "$1"
}

startup_source_optional_file_is_exact() {
    FIELD_PREFIX=$1
    EXPECTED_PATH=$2
    PRESENT=$(startup_source_field "${FIELD_PREFIX}_present") || return 1
    BOUND_PATH=$(startup_source_field "${FIELD_PREFIX}_path") || return 1
    BOUND_SHA=$(startup_source_field "${FIELD_PREFIX}_sha256") || return 1
    BOUND_BYTES=$(startup_source_field "${FIELD_PREFIX}_bytes") || return 1
    [ "$BOUND_PATH" = "$EXPECTED_PATH" ] || return 1
    case "$PRESENT:$BOUND_SHA:$BOUND_BYTES" in
        false:none:0) [ ! -e "$BOUND_PATH" ] && [ ! -L "$BOUND_PATH" ]; return $? ;;
        true:none:0) return 1 ;;
    esac
    valid_sha256 "$BOUND_SHA" && valid_size "$BOUND_BYTES" || return 1
    if [ "$PRESENT" = true ]; then
        is_regular_nonsymlink "$BOUND_PATH" \
            && [ "$(sha256sum "$BOUND_PATH" | awk '{print $1}')" = "$BOUND_SHA" ] \
            && [ "$(wc -c < "$BOUND_PATH" | tr -d ' \t\r\n')" = "$BOUND_BYTES" ]
    else
        [ "$PRESENT" = false ] \
            && [ ! -e "$BOUND_PATH" ] && [ ! -L "$BOUND_PATH" ]
    fi
}

startup_source_preserved_file_is_exact() {
    FIELD_PREFIX=$1
    EXPECTED_PATH=$2
    PRESENT=$(startup_source_field "${FIELD_PREFIX}_present") || return 1
    BOUND_PATH=$(startup_source_field "${FIELD_PREFIX}_path") || return 1
    BOUND_SHA=$(startup_source_field "${FIELD_PREFIX}_sha256") || return 1
    BOUND_BYTES=$(startup_source_field "${FIELD_PREFIX}_bytes") || return 1
    [ "$BOUND_PATH" = "$EXPECTED_PATH" ] || return 1
    case "$PRESENT" in
        false) [ "$BOUND_SHA:$BOUND_BYTES" = none:0 ] \
            && [ ! -e "$BOUND_PATH" ] && [ ! -L "$BOUND_PATH" ] ;;
        true) valid_sha256 "$BOUND_SHA" && valid_size "$BOUND_BYTES" \
            && is_regular_nonsymlink "$BOUND_PATH" \
            && [ "$(sha256sum "$BOUND_PATH" | awk '{print $1}')" = "$BOUND_SHA" ] \
            && [ "$(wc -c < "$BOUND_PATH" | tr -d ' \t\r\n')" = "$BOUND_BYTES" ] ;;
        *) return 1 ;;
    esac
}

startup_source_optional_pair_equals_record() {
    FIELD_PREFIX=$1
    RECORD=$2
    RECORD_PREFIX=$3
    [ "$(startup_source_field "${FIELD_PREFIX}_sha256")" = "$(startup_field_at "$RECORD" "${RECORD_PREFIX}_sha256")" ] \
        && [ "$(startup_source_field "${FIELD_PREFIX}_bytes")" = "$(startup_field_at "$RECORD" "${RECORD_PREFIX}_bytes")" ]
}

startup_source_optional_absent_pair_is_none() {
    FIELD_PREFIX=$1
    [ "$(startup_source_field "${FIELD_PREFIX}_present")" = false ] \
        && [ "$(startup_source_field "${FIELD_PREFIX}_sha256")" = none ] \
        && [ "$(startup_source_field "${FIELD_PREFIX}_bytes")" = 0 ]
}

startup_source_transcript_tuple_equals_record() {
    RECORD=$1
    for TRANSCRIPT_KEY in path mnt_id inode mode uid gid sha256 bytes; do
        [ "$(startup_source_field "transcript_${TRANSCRIPT_KEY}")" = "$(startup_field_at "$RECORD" "transcript_${TRANSCRIPT_KEY}")" ] || return 1
    done
}

startup_source_transcript_state_is_exact() {
    TRANSCRIPT_PRESENT=$(startup_source_field transcript_present) || return 1
    TRANSCRIPT_PATH=$(startup_source_field transcript_path) || return 1
    case "$TRANSCRIPT_PRESENT" in
        false)
            [ ! -e "$TRANSCRIPT_PATH" ] && [ ! -L "$TRANSCRIPT_PATH" ]
            ;;
        true)
            is_regular_nonsymlink "$TRANSCRIPT_PATH" || return 1
            exec 8< "$TRANSCRIPT_PATH" || return 1
            TRANSCRIPT_TARGET_INITIAL=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
            TRANSCRIPT_LS_INITIAL=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
            set -- $TRANSCRIPT_LS_INITIAL
            TRANSCRIPT_INODE_INITIAL=${1:-}
            TRANSCRIPT_MODE_INITIAL=${2:-}
            TRANSCRIPT_UID_INITIAL=${4:-}
            TRANSCRIPT_GID_INITIAL=${5:-}
            TRANSCRIPT_MNT_ID_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
            TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/8" 2>/dev/null | awk '{print $1}')
            TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/8" 2>/dev/null | tr -d ' \t\r\n')
            TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
            TRANSCRIPT_LS=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
            set -- $TRANSCRIPT_LS
            TRANSCRIPT_INODE=${1:-}
            TRANSCRIPT_MODE=${2:-}
            TRANSCRIPT_UID=${4:-}
            TRANSCRIPT_GID=${5:-}
            TRANSCRIPT_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
            exec 8>&-
            [ "$TRANSCRIPT_TARGET_INITIAL" = "$TRANSCRIPT_PATH" ] \
                && [ "$TRANSCRIPT_TARGET" = "$TRANSCRIPT_TARGET_INITIAL" ] \
                && [ "$TRANSCRIPT_INODE" = "$TRANSCRIPT_INODE_INITIAL" ] \
                && [ "$TRANSCRIPT_MODE" = "$TRANSCRIPT_MODE_INITIAL" ] \
                && [ "$TRANSCRIPT_UID" = "$TRANSCRIPT_UID_INITIAL" ] \
                && [ "$TRANSCRIPT_GID" = "$TRANSCRIPT_GID_INITIAL" ] \
                && [ "$TRANSCRIPT_MNT_ID" = "$TRANSCRIPT_MNT_ID_INITIAL" ] \
                && [ "$TRANSCRIPT_INODE" = "$(startup_source_field transcript_inode)" ] \
                && [ "$TRANSCRIPT_MODE" = -rw------- ] \
                && [ "$TRANSCRIPT_UID" = "$(startup_source_field transcript_uid)" ] \
                && [ "$TRANSCRIPT_GID" = "$(startup_source_field transcript_gid)" ] \
                && [ "$TRANSCRIPT_MNT_ID" = "$(startup_source_field transcript_mnt_id)" ] \
                && [ "$(startup_source_field transcript_mode)" = 0600 ] \
                && [ "$TRANSCRIPT_SHA" = "$(startup_source_field transcript_sha256)" ] \
                && [ "$TRANSCRIPT_BYTES" = "$(startup_source_field transcript_bytes)" ]
            ;;
        *) return 1 ;;
    esac
}

startup_source_runtime_v6_owner_is_exact() {
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq 10 ] \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v6 ] \
        && [ "$(runtime_lock_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(runtime_lock_field runner_sha256)" = "$(startup_source_field runner_sha256)" ] \
        && [ "$(runtime_lock_field runner_bytes)" = "$(startup_source_field runner_bytes)" ] \
        && [ "$(runtime_lock_field custody_observer_sha256)" = "$(startup_source_field custody_observer_sha256)" ] \
        && [ "$(runtime_lock_field custody_observer_bytes)" = "$(startup_source_field custody_observer_bytes)" ] \
        && [ "$(runtime_lock_field stock_restart_helper_sha256)" = "$(startup_source_field stock_restart_helper_sha256)" ] \
        && [ "$(runtime_lock_field stock_restart_helper_bytes)" = "$(startup_source_field stock_restart_helper_bytes)" ] \
        && [ "$(runtime_lock_field live_identity_sha256)" = "$(startup_source_field live_identity_sha256)" ] || return 1
    case "$(runtime_lock_field owner_kind)" in launch|recovery) ;; *) return 1 ;; esac
}

startup_source_runtime_v10_owner_is_exact() {
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq 16 ] \
        && startup_ordered_keys_are_exact "$RUNTIME_LOCK_OWNER" "$STARTUP_PREFIX_OWNER_KEYS_SHA" \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v10 ] \
        && [ "$(runtime_lock_field owner_kind)" = startup-prefix-stock-restart-pending ] \
        && [ "$(runtime_lock_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(runtime_lock_field runner_sha256)" = "$(startup_source_field runner_sha256)" ] \
        && [ "$(runtime_lock_field runner_bytes)" = "$(startup_source_field runner_bytes)" ] \
        && [ "$(runtime_lock_field custody_observer_sha256)" = "$(startup_source_field custody_observer_sha256)" ] \
        && [ "$(runtime_lock_field custody_observer_bytes)" = "$(startup_source_field custody_observer_bytes)" ] \
        && [ "$(runtime_lock_field stock_restart_helper_sha256)" = "$(startup_source_field stock_restart_helper_sha256)" ] \
        && [ "$(runtime_lock_field stock_restart_helper_bytes)" = "$(startup_source_field stock_restart_helper_bytes)" ] \
        && [ "$(runtime_lock_field live_identity_sha256)" = "$(startup_source_field live_identity_sha256)" ] \
        && startup_prefix_pending_active_is_source_bound \
        && [ "$(runtime_lock_field active_sha256)" = "$(sha256sum "$ACTIVE" | awk '{print $1}')" ] \
        && [ "$(runtime_lock_field active_bytes)" = "$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')" ] \
        && [ "$(runtime_lock_field transaction_id)" = "$(startup_source_field transaction_id)" ] \
        && [ "$(runtime_lock_field highest_phase)" = "$(startup_source_field highest_phase)" ] \
        && [ "$(runtime_lock_field source_receipt_sha256)" = "$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')" ] \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(runtime_lock_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ]
}

startup_source_canonical_owner_state_is_exact() {
    SOURCE_KIND_VALUE=$(startup_source_field source_kind) || return 1
    SOURCE_OWNER_PRESENT_VALUE=$(startup_source_field owner_present) || return 1
    SOURCE_OWNER_SHA_VALUE=$(startup_source_field owner_sha256) || return 1
    SOURCE_OWNER_BYTES_VALUE=$(startup_source_field owner_bytes) || return 1

    if [ -e "$STARTUP_RETIRED_OWNER" ] || [ -L "$STARTUP_RETIRED_OWNER" ]; then
        [ "$SOURCE_OWNER_PRESENT_VALUE" = true ] \
            && same_historical_active_inode "$STARTUP_PRESAFEOFF_OWNER" "$STARTUP_RETIRED_OWNER" \
                "$SOURCE_OWNER_SHA_VALUE" "$SOURCE_OWNER_BYTES_VALUE" || return 1
    fi

    if [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        return 0
    fi
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" || return 1
    case "$(runtime_lock_field schema 2>/dev/null || true)" in
        dcentos.s19k-startup-j0-prefork/v1)
            [ "$SOURCE_OWNER_PRESENT_VALUE" = true ] \
                && [ ! -e "$STARTUP_RETIRED_OWNER" ] && [ ! -L "$STARTUP_RETIRED_OWNER" ] \
                && same_historical_active_inode "$STARTUP_PRESAFEOFF_OWNER" "$RUNTIME_LOCK_OWNER" \
                    "$SOURCE_OWNER_SHA_VALUE" "$SOURCE_OWNER_BYTES_VALUE" \
                && load_bound_startup_j0_static_from "$RUNTIME_LOCK_OWNER"
            ;;
        dcentos.s19k-track1-runtime-lock/v6)
            startup_source_runtime_v6_owner_is_exact
            ;;
        dcentos.s19k-track1-runtime-lock/v10)
            startup_source_runtime_v10_owner_is_exact
            ;;
        *) return 1 ;;
    esac
}

startup_source_canonical_active_state_is_exact() {
    SOURCE_KIND_VALUE=$(startup_source_field source_kind) || return 1
    SOURCE_ACTIVE_PRESENT_VALUE=$(startup_source_field active_present) || return 1
    SOURCE_ACTIVE_SHA_VALUE=$(startup_source_field active_sha256) || return 1
    SOURCE_ACTIVE_BYTES_VALUE=$(startup_source_field active_bytes) || return 1
    CURRENT_ACTIVE_KIND=absent
    if [ -e "$ACTIVE" ] || [ -L "$ACTIVE" ]; then
        if startup_prefix_pending_active_is_source_bound; then
            CURRENT_ACTIVE_KIND=pending
        elif is_regular_nonsymlink "$ACTIVE"; then
            CURRENT_ACTIVE_KIND=historical
        else
            return 1
        fi
    fi

    if [ "$SOURCE_ACTIVE_PRESENT_VALUE" = true ]; then
        case "$CURRENT_ACTIVE_KIND" in
            historical)
                [ "$SOURCE_KIND_VALUE" = startup-prefix ] \
                    && same_historical_active_inode "$STARTUP_PRESAFEOFF_ACTIVE" "$ACTIVE" \
                        "$SOURCE_ACTIVE_SHA_VALUE" "$SOURCE_ACTIVE_BYTES_VALUE" || return 1
                ;;
            pending|absent) ;;
            *) return 1 ;;
        esac
        if [ -e "$STARTUP_RETIRED_ACTIVE" ] || [ -L "$STARTUP_RETIRED_ACTIVE" ]; then
            same_historical_active_inode "$STARTUP_PRESAFEOFF_ACTIVE" "$STARTUP_RETIRED_ACTIVE" \
                "$SOURCE_ACTIVE_SHA_VALUE" "$SOURCE_ACTIVE_BYTES_VALUE" || return 1
        fi
    else
        [ "$CURRENT_ACTIVE_KIND" != historical ] \
            && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ] || return 1
    fi
}

startup_prefix_safeoff_source_is_exact() {
    is_regular_nonsymlink "$STARTUP_PRESAFEOFF_SOURCE" \
        && [ "$(wc -l < "$STARTUP_PRESAFEOFF_SOURCE" | tr -d ' \t\r\n')" -eq 108 ] \
        && startup_ordered_keys_are_exact "$STARTUP_PRESAFEOFF_SOURCE" "$STARTUP_PRESAFEOFF_SOURCE_KEYS_SHA" \
        && [ "$(startup_source_field schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
        && valid_sha256 "$(startup_source_field transaction_id)" \
        && [ "$(startup_source_field phase)" = startup-prefix-stock-loss-admitted ] \
        && [ "$(startup_source_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(startup_source_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(startup_source_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(startup_source_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(startup_source_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(startup_source_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(startup_source_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(startup_source_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(startup_source_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(startup_source_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(startup_source_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(startup_source_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && valid_live_identity_profile "$(startup_source_field live_identity_profile)" \
        && valid_sha256 "$(startup_source_field live_identity_sha256)" \
        && [ "$(startup_source_field stock_supervisor)" = absent ] \
        && [ "$(startup_source_field stock_bosminer)" = absent ] \
        && [ "$(startup_source_field dcentrald)" = absent ] \
        && [ "$(startup_source_field watchdog_fd)" = absent ] \
        && [ "$(startup_source_field competing_wrapper)" = absent ] \
        && [ "$(startup_source_field watchdog_start_intent)" = false ] \
        && [ "$(startup_source_field watchdog_armed)" = false ] \
        && [ "$(startup_source_field signal_attempted)" = false ] \
        && [ "$(startup_source_field inherited_rails)" = false ] \
        && [ "$(startup_source_field route_or_uart_opened)" = false ] \
        && [ "$(startup_source_field hardware_opened)" = false ] \
        && [ "$(startup_source_field persistent_mutation)" = false ] \
        && [ "$(startup_source_field publication)" = no-clobber-hard-link-after-fsync ] || return 1
    case "$(startup_source_field source_kind)" in
        startup-prefix|startup-cleanup-commit) ;;
        *) return 1 ;;
    esac
    case "$(startup_source_field highest_phase)" in
        j0|parent-lost-j0|c1|j1|active|j2|release) ;;
        *) return 1 ;;
    esac
    startup_source_optional_file_is_exact c1 "$STARTUP_C1" \
        && startup_source_optional_file_is_exact j1 "$STARTUP_J1" \
        && startup_source_optional_file_is_exact j2 "$STARTUP_J2" \
        && startup_source_optional_file_is_exact release "$STARTUP_RELEASE" \
        && startup_source_optional_file_is_exact parent_lost "$STARTUP_PARENT_LOST" \
        && startup_source_optional_file_is_exact terminal "$STARTUP_RETIRE_TERMINAL" \
        && startup_source_optional_file_is_exact cleanup "$STARTUP_RETIRE_CLEANUP" \
        && startup_source_preserved_file_is_exact preserved_owner "$STARTUP_PRESAFEOFF_OWNER" \
        && startup_source_preserved_file_is_exact preserved_active "$STARTUP_PRESAFEOFF_ACTIVE" || return 1
    SOURCE_OWNER_PRESENT=$(startup_source_field owner_present) || return 1
    SOURCE_OWNER_SHA=$(startup_source_field owner_sha256) || return 1
    SOURCE_OWNER_BYTES=$(startup_source_field owner_bytes) || return 1
    SOURCE_PRESERVED_OWNER_PRESENT=$(startup_source_field preserved_owner_present) || return 1
    case "$SOURCE_OWNER_PRESENT:$SOURCE_PRESERVED_OWNER_PRESENT" in
        true:true) valid_sha256 "$SOURCE_OWNER_SHA" && valid_size "$SOURCE_OWNER_BYTES" \
            && [ "$(startup_source_field owner_path)" = "$STARTUP_PRESAFEOFF_OWNER" ] \
            && [ "$(startup_source_field preserved_owner_sha256)" = "$SOURCE_OWNER_SHA" ] \
            && [ "$(startup_source_field preserved_owner_bytes)" = "$SOURCE_OWNER_BYTES" ] ;;
        false:false) valid_sha256 "$SOURCE_OWNER_SHA" && valid_size "$SOURCE_OWNER_BYTES" \
            && [ "$(startup_source_field owner_path)" = none ] ;;
        *) return 1 ;;
    esac || return 1
    SOURCE_ACTIVE_PRESENT=$(startup_source_field active_present) || return 1
    SOURCE_ACTIVE_SHA=$(startup_source_field active_sha256) || return 1
    SOURCE_ACTIVE_BYTES=$(startup_source_field active_bytes) || return 1
    SOURCE_PRESERVED_ACTIVE_PRESENT=$(startup_source_field preserved_active_present) || return 1
    case "$SOURCE_ACTIVE_PRESENT:$SOURCE_PRESERVED_ACTIVE_PRESENT:$SOURCE_ACTIVE_SHA:$SOURCE_ACTIVE_BYTES" in
        true:true:*:*) valid_sha256 "$SOURCE_ACTIVE_SHA" && valid_size "$SOURCE_ACTIVE_BYTES" \
            && [ "$(startup_source_field active_path)" = "$STARTUP_PRESAFEOFF_ACTIVE" ] \
            && [ "$(startup_source_field preserved_active_sha256)" = "$SOURCE_ACTIVE_SHA" ] \
            && [ "$(startup_source_field preserved_active_bytes)" = "$SOURCE_ACTIVE_BYTES" ] ;;
        false:false:none:0) [ "$(startup_source_field active_path)" = none ] ;;
        false:false:*:*) [ "$(startup_source_field active_path)" = none ] \
            && valid_sha256 "$SOURCE_ACTIVE_SHA" && valid_size "$SOURCE_ACTIVE_BYTES" ;;
        *) return 1 ;;
    esac || return 1
    case "$(startup_source_field fifo_present)" in true|false) ;; *) return 1 ;; esac
    [ "$(startup_source_field fifo_path)" != '' ] || return 1
    case "$(startup_source_field source_kind)" in
        startup-prefix)
            valid_uint "$(startup_source_field fifo_mnt_id)" \
                && valid_uint "$(startup_source_field fifo_inode)" || return 1
            [ "$(startup_source_field preserved_owner_present)" = true ] \
                && [ "$(startup_source_field owner_present)" = true ] \
                && load_bound_startup_j0_static_from "$STARTUP_PRESAFEOFF_OWNER" \
                && [ "$(startup_source_field transaction_id)" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" transaction_id)" ] \
                && [ "$(startup_source_field owner_sha256)" = "$(sha256sum "$STARTUP_PRESAFEOFF_OWNER" | awk '{print $1}')" ] \
                && [ "$(startup_source_field owner_bytes)" = "$(wc -c < "$STARTUP_PRESAFEOFF_OWNER" | tr -d ' \t\r\n')" ] \
                && [ "$(startup_source_field fifo_path)" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" fifo_path)" ] \
                && [ "$(startup_source_field fifo_mnt_id)" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" fifo_mnt_id)" ] \
                && [ "$(startup_source_field fifo_inode)" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" fifo_inode)" ] || return 1
            case "$(startup_source_field active_present)" in
                true) [ "$(startup_source_field preserved_active_present)" = true ] || return 1 ;;
                false) [ "$(startup_source_field preserved_active_present)" = false ] \
                    && [ "$(startup_source_field active_path)" = none ] \
                    && [ "$(startup_source_field active_sha256)" = none ] \
                    && [ "$(startup_source_field active_bytes)" = 0 ] || return 1 ;;
            esac
            case "$(startup_source_field fifo_present)" in
                true) startup_fifo_matches_j0 "$STARTUP_PRESAFEOFF_OWNER" || return 1 ;;
                false) [ ! -e "$(startup_source_field fifo_path)" ] \
                    && [ ! -L "$(startup_source_field fifo_path)" ] || return 1 ;;
            esac
            for SOURCE_J0_KEY in supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_profile live_identity_sha256; do
                [ "$(startup_source_field "$SOURCE_J0_KEY")" = "$(runtime_lock_field_at "$STARTUP_PRESAFEOFF_OWNER" "$SOURCE_J0_KEY")" ] || return 1
            done
            startup_source_optional_absent_pair_is_none cleanup || return 1
            if [ "$(startup_source_field terminal_present)" = true ]; then
                startup_retire_terminal_is_exact "$STARTUP_PRESAFEOFF_OWNER" \
                    && startup_source_transcript_tuple_equals_record "$STARTUP_RETIRE_TERMINAL" || return 1
                for HISTORICAL_PREFIX in c1 j1 j2 release parent_lost; do
                    startup_source_optional_pair_equals_record "$HISTORICAL_PREFIX" "$STARTUP_RETIRE_TERMINAL" "$HISTORICAL_PREFIX" || return 1
                done
            else
                startup_source_optional_absent_pair_is_none terminal || return 1
                for HISTORICAL_PREFIX in c1 j1 j2 release parent_lost; do
                    if [ "$(startup_source_field "${HISTORICAL_PREFIX}_present")" = false ]; then
                        startup_source_optional_absent_pair_is_none "$HISTORICAL_PREFIX" || return 1
                    fi
                done
                capture_startup_transcript_for_terminal "$STARTUP_PRESAFEOFF_OWNER" || return 1
                [ "$(startup_source_field transcript_path)" = "$STARTUP_TRANSCRIPT_PATH" ] \
                    && [ "$(startup_source_field transcript_mnt_id)" = "$STARTUP_TRANSCRIPT_MNT_ID" ] \
                    && [ "$(startup_source_field transcript_inode)" = "$STARTUP_TRANSCRIPT_INODE" ] \
                    && [ "$(startup_source_field transcript_mode)" = 0600 ] \
                    && [ "$(startup_source_field transcript_uid)" = "$STARTUP_TRANSCRIPT_UID" ] \
                    && [ "$(startup_source_field transcript_gid)" = "$STARTUP_TRANSCRIPT_GID" ] \
                    && [ "$(startup_source_field transcript_sha256)" = "$STARTUP_TRANSCRIPT_SHA" ] \
                    && [ "$(startup_source_field transcript_bytes)" = "$STARTUP_TRANSCRIPT_BYTES" ] || return 1
            fi
            ;;
        startup-cleanup-commit)
            [ "$(startup_source_field fifo_present)" = false ] \
                && [ "$(startup_source_field fifo_path)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" fifo_path)" ] \
                && [ ! -e "$(startup_source_field fifo_path)" ] \
                && [ ! -L "$(startup_source_field fifo_path)" ] \
                && [ "$(startup_source_field fifo_mnt_id)" = none ] \
                && [ "$(startup_source_field fifo_inode)" = none ] || return 1
            load_bound_startup_cleanup_record "$STARTUP_RETIRE_CLEANUP" \
                && [ "$(startup_source_field transaction_id)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transaction_id)" ] \
                && [ "$(startup_source_field highest_phase)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" highest_phase)" ] \
                && [ "$(startup_source_field owner_sha256)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" owner_sha256)" ] \
                && [ "$(startup_source_field owner_bytes)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" owner_bytes)" ] \
                && [ "$(startup_source_field active_sha256)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" active_sha256)" ] \
                && [ "$(startup_source_field active_bytes)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" active_bytes)" ] \
                && [ "$(startup_source_field terminal_sha256)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" terminal_sha256)" ] \
                && [ "$(startup_source_field terminal_bytes)" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" terminal_bytes)" ] \
                && [ "$(startup_source_field cleanup_sha256)" = "$(sha256sum "$STARTUP_RETIRE_CLEANUP" | awk '{print $1}')" ] \
                && [ "$(startup_source_field cleanup_bytes)" = "$(wc -c < "$STARTUP_RETIRE_CLEANUP" | tr -d ' \t\r\n')" ] || return 1
            for SOURCE_CLEANUP_KEY in supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_profile live_identity_sha256 transcript_path transcript_mnt_id transcript_inode transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes; do
                [ "$(startup_source_field "$SOURCE_CLEANUP_KEY")" = "$(startup_field_at "$STARTUP_RETIRE_CLEANUP" "$SOURCE_CLEANUP_KEY")" ] || return 1
            done
            for HISTORICAL_PREFIX in c1 j1 j2 release parent_lost; do
                startup_source_optional_absent_pair_is_none "$HISTORICAL_PREFIX" || return 1
            done
            ;;
    esac
    startup_source_canonical_owner_state_is_exact \
        && startup_source_canonical_active_state_is_exact || return 1
    case "$(startup_source_field transcript_present)" in true|false) ;; *) return 1 ;; esac
    [ "$(startup_source_field transcript_path)" != '' ] \
        && valid_uint "$(startup_source_field transcript_mnt_id)" \
        && valid_uint "$(startup_source_field transcript_inode)" \
        && [ "$(startup_source_field transcript_mode)" = 0600 ] \
        && [ "$(startup_source_field transcript_uid)" = 0 ] \
        && [ "$(startup_source_field transcript_gid)" = 0 ] \
        && valid_sha256 "$(startup_source_field transcript_sha256)" \
        && valid_uint "$(startup_source_field transcript_bytes)" \
        && startup_source_transcript_state_is_exact || return 1
    C1_PAIR=$(startup_source_field c1_sha256):$(startup_source_field c1_bytes)
    J1_PAIR=$(startup_source_field j1_sha256):$(startup_source_field j1_bytes)
    ACTIVE_PAIR=$SOURCE_ACTIVE_SHA:$SOURCE_ACTIVE_BYTES
    J2_PAIR=$(startup_source_field j2_sha256):$(startup_source_field j2_bytes)
    RELEASE_PAIR=$(startup_source_field release_sha256):$(startup_source_field release_bytes)
    PL_PAIR=$(startup_source_field parent_lost_sha256):$(startup_source_field parent_lost_bytes)
    if [ "$(startup_source_field source_kind)" = startup-prefix ]; then
        case "$(startup_source_field highest_phase)" in
            j0) [ "$C1_PAIR:$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0:none:0:none:0 ] ;;
            parent-lost-j0) [ "$C1_PAIR:$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR" = none:0:none:0:none:0:none:0:none:0 ] && [ "$PL_PAIR" != none:0 ] ;;
            c1) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR:$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0:none:0 ] ;;
            j1) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR:$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0:none:0 ] ;;
            active) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR:$RELEASE_PAIR:$PL_PAIR" = none:0:none:0:none:0 ] ;;
            j2) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR" != none:0 ] && [ "$RELEASE_PAIR:$PL_PAIR" = none:0:none:0 ] ;;
            release) [ "$C1_PAIR" != none:0 ] && [ "$J1_PAIR" != none:0 ] && [ "$ACTIVE_PAIR" != none:0 ] && [ "$J2_PAIR" != none:0 ] && [ "$RELEASE_PAIR" != none:0 ] && [ "$PL_PAIR" = none:0 ] ;;
        esac || return 1
    else
        [ "$(startup_source_field cleanup_present)" = true ] \
            && valid_sha256 "$(startup_source_field cleanup_sha256)" \
            && valid_size "$(startup_source_field cleanup_bytes)" || return 1
    fi
    for STOCK_KEY in supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes; do
        [ -n "$(startup_source_field "$STOCK_KEY")" ] || return 1
    done
    BOUND_SUPERVISOR_PID=$(startup_source_field supervisor_pid)
    BOUND_SUPERVISOR_START=$(startup_source_field supervisor_start)
    BOUND_SUPERVISOR_PPID=$(startup_source_field supervisor_ppid)
    BOUND_SUPERVISOR_PGRP=$(startup_source_field supervisor_pgrp)
    BOUND_SUPERVISOR_SESSION=$(startup_source_field supervisor_session)
    BOUND_SUPERVISOR_EXE=$(startup_source_field supervisor_exe)
    BOUND_SUPERVISOR_CMDLINE_SHA=$(startup_source_field supervisor_cmdline_sha256)
    BOUND_SUPERVISOR_CMDLINE_BYTES=$(startup_source_field supervisor_cmdline_bytes)
    BOUND_BOSMINER_PID=$(startup_source_field bosminer_pid)
    BOUND_BOSMINER_START=$(startup_source_field bosminer_start)
    BOUND_BOSMINER_PPID=$(startup_source_field bosminer_ppid)
    BOUND_BOSMINER_PGRP=$(startup_source_field bosminer_pgrp)
    BOUND_BOSMINER_SESSION=$(startup_source_field bosminer_session)
    BOUND_BOSMINER_EXE=$(startup_source_field bosminer_exe)
    BOUND_BOSMINER_CMDLINE_SHA=$(startup_source_field bosminer_cmdline_sha256)
    BOUND_BOSMINER_CMDLINE_BYTES=$(startup_source_field bosminer_cmdline_bytes)
    BOUND_STOCK_PIDFILE_PATH=$(startup_source_field stock_pidfile_path)
    BOUND_STOCK_PIDFILE_SHA=$(startup_source_field stock_pidfile_sha256)
    BOUND_STOCK_PIDFILE_BYTES=$(startup_source_field stock_pidfile_bytes)
    EXPECTED_LIVE_IDENTITY_PROFILE=$(startup_source_field live_identity_profile)
    EXPECTED_LIVE_IDENTITY_SHA=$(startup_source_field live_identity_sha256)
    valid_pid_start "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" \
        && valid_pid_start "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" \
        && [ "$BOUND_SUPERVISOR_PPID" = 1 ] \
        && [ "$BOUND_BOSMINER_PPID" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$BOUND_SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$BOUND_BOSMINER_EXE" = /usr/bin/bosminer ] \
        && valid_sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA" \
        && valid_size "$BOUND_SUPERVISOR_CMDLINE_BYTES" \
        && valid_sha256 "$BOUND_BOSMINER_CMDLINE_SHA" \
        && valid_size "$BOUND_BOSMINER_CMDLINE_BYTES" \
        && [ "$BOUND_STOCK_PIDFILE_PATH" = /var/run/bosminer.pid ] \
        && valid_sha256 "$BOUND_STOCK_PIDFILE_SHA" \
        && valid_size "$BOUND_STOCK_PIDFILE_BYTES"
}

capture_optional_startup_source_file() {
    OPTIONAL_PATH=$1
    if [ -e "$OPTIONAL_PATH" ] || [ -L "$OPTIONAL_PATH" ]; then
        is_regular_nonsymlink "$OPTIONAL_PATH" || return 1
        OPTIONAL_PRESENT=true
        OPTIONAL_SHA=$(sha256sum "$OPTIONAL_PATH" | awk '{print $1}')
        OPTIONAL_BYTES=$(wc -c < "$OPTIONAL_PATH" | tr -d ' \t\r\n')
        valid_sha256 "$OPTIONAL_SHA" && valid_size "$OPTIONAL_BYTES"
    else
        OPTIONAL_PRESENT=false
        OPTIONAL_SHA=none
        OPTIONAL_BYTES=0
    fi
}

preserve_startup_source_file() {
    SOURCE_PATH=$1
    PRESERVED_PATH=$2
    EXPECTED_SHA=$3
    EXPECTED_BYTES=$4
    is_regular_nonsymlink "$SOURCE_PATH" \
        && valid_sha256 "$EXPECTED_SHA" && valid_size "$EXPECTED_BYTES" \
        && [ "$(sha256sum "$SOURCE_PATH" | awk '{print $1}')" = "$EXPECTED_SHA" ] \
        && [ "$(wc -c < "$SOURCE_PATH" | tr -d ' \t\r\n')" = "$EXPECTED_BYTES" ] || return 1
    if [ ! -e "$PRESERVED_PATH" ] && [ ! -L "$PRESERVED_PATH" ]; then
        ln "$SOURCE_PATH" "$PRESERVED_PATH" || return 1
    fi
    is_regular_nonsymlink "$PRESERVED_PATH" \
        && [ "$(sha256sum "$PRESERVED_PATH" | awk '{print $1}')" = "$EXPECTED_SHA" ] \
        && [ "$(wc -c < "$PRESERVED_PATH" | tr -d ' \t\r\n')" = "$EXPECTED_BYTES" ]
}

classify_startup_cleanup_for_safeoff() {
    load_bound_startup_cleanup_record "$STARTUP_RETIRE_CLEANUP" || return 1
    SOURCE_KIND=startup-cleanup-commit
    SOURCE_TRANSACTION_ID=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transaction_id)
    SOURCE_HIGHEST_PHASE=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" highest_phase)
    SOURCE_OWNER_SHA=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" owner_sha256)
    SOURCE_OWNER_BYTES=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" owner_bytes)
    valid_sha256 "$SOURCE_OWNER_SHA" && valid_size "$SOURCE_OWNER_BYTES" || return 1

    CLEANUP_CURRENT_OWNER=false
    CLEANUP_RETIRED_OWNER=false
    if [ -e "$RUNTIME_LOCK_OWNER" ] || [ -L "$RUNTIME_LOCK_OWNER" ]; then
        is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
            && [ "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" = "$SOURCE_OWNER_SHA" ] \
            && [ "$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" = "$SOURCE_OWNER_BYTES" ] \
            && load_bound_startup_j0_static_from "$RUNTIME_LOCK_OWNER" || return 1
        CLEANUP_CURRENT_OWNER=true
    fi
    if [ -e "$STARTUP_RETIRED_OWNER" ] || [ -L "$STARTUP_RETIRED_OWNER" ]; then
        is_regular_nonsymlink "$STARTUP_RETIRED_OWNER" \
            && [ "$(sha256sum "$STARTUP_RETIRED_OWNER" | awk '{print $1}')" = "$SOURCE_OWNER_SHA" ] \
            && [ "$(wc -c < "$STARTUP_RETIRED_OWNER" | tr -d ' \t\r\n')" = "$SOURCE_OWNER_BYTES" ] \
            && load_bound_startup_j0_static_from "$STARTUP_RETIRED_OWNER" || return 1
        CLEANUP_RETIRED_OWNER=true
    fi
    [ "$CLEANUP_CURRENT_OWNER:$CLEANUP_RETIRED_OWNER" != true:true ] || return 1
    if [ "$CLEANUP_CURRENT_OWNER" = true ]; then
        SOURCE_OWNER_PRESENT=true
        SOURCE_OWNER_PATH=$RUNTIME_LOCK_OWNER
    elif [ "$CLEANUP_RETIRED_OWNER" = true ]; then
        SOURCE_OWNER_PRESENT=true
        SOURCE_OWNER_PATH=$STARTUP_RETIRED_OWNER
    else
        SOURCE_OWNER_PRESENT=false
        SOURCE_OWNER_PATH=none
    fi

    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || return 1
    SOURCE_ACTIVE_SHA=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" active_sha256)
    SOURCE_ACTIVE_BYTES=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" active_bytes)
    SOURCE_ACTIVE_PRESENT=false
    SOURCE_ACTIVE_PATH=none
    if [ "$SOURCE_ACTIVE_SHA:$SOURCE_ACTIVE_BYTES" = none:0 ]; then
        [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ] || return 1
    else
        valid_sha256 "$SOURCE_ACTIVE_SHA" && valid_size "$SOURCE_ACTIVE_BYTES" || return 1
        if [ -e "$STARTUP_RETIRED_ACTIVE" ] || [ -L "$STARTUP_RETIRED_ACTIVE" ]; then
            is_regular_nonsymlink "$STARTUP_RETIRED_ACTIVE" \
                && [ "$(sha256sum "$STARTUP_RETIRED_ACTIVE" | awk '{print $1}')" = "$SOURCE_ACTIVE_SHA" ] \
                && [ "$(wc -c < "$STARTUP_RETIRED_ACTIVE" | tr -d ' \t\r\n')" = "$SOURCE_ACTIVE_BYTES" ] || return 1
            SOURCE_ACTIVE_PRESENT=true
            SOURCE_ACTIVE_PATH=$STARTUP_RETIRED_ACTIVE
        fi
    fi

    for SOURCE_NAME in c1 j1 j2 release parent_lost; do
        eval "SOURCE_${SOURCE_NAME}_PRESENT=false"
        eval "SOURCE_${SOURCE_NAME}_SHA=none"
        eval "SOURCE_${SOURCE_NAME}_BYTES=0"
    done
    SOURCE_terminal_PRESENT=false
    SOURCE_terminal_SHA=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" terminal_sha256)
    SOURCE_terminal_BYTES=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" terminal_bytes)
    if [ -e "$STARTUP_RETIRE_TERMINAL" ] || [ -L "$STARTUP_RETIRE_TERMINAL" ]; then
        is_regular_nonsymlink "$STARTUP_RETIRE_TERMINAL" \
            && [ "$(sha256sum "$STARTUP_RETIRE_TERMINAL" | awk '{print $1}')" = "$SOURCE_terminal_SHA" ] \
            && [ "$(wc -c < "$STARTUP_RETIRE_TERMINAL" | tr -d ' \t\r\n')" = "$SOURCE_terminal_BYTES" ] || return 1
        SOURCE_terminal_PRESENT=true
    fi
    SOURCE_cleanup_PRESENT=true
    SOURCE_cleanup_SHA=$(sha256sum "$STARTUP_RETIRE_CLEANUP" | awk '{print $1}')
    SOURCE_cleanup_BYTES=$(wc -c < "$STARTUP_RETIRE_CLEANUP" | tr -d ' \t\r\n')
    SOURCE_FIFO_PRESENT=false
    SOURCE_FIFO_PATH=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" fifo_path)
    [ ! -e "$SOURCE_FIFO_PATH" ] && [ ! -L "$SOURCE_FIFO_PATH" ] || return 1
    SOURCE_FIFO_MNT_ID=none
    SOURCE_FIFO_INODE=none
    SOURCE_TRANSCRIPT_PATH=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_path)
    SOURCE_TRANSCRIPT_MNT_ID=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_mnt_id)
    SOURCE_TRANSCRIPT_INODE=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_inode)
    SOURCE_TRANSCRIPT_MODE=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_mode)
    SOURCE_TRANSCRIPT_UID=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_uid)
    SOURCE_TRANSCRIPT_GID=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_gid)
    SOURCE_TRANSCRIPT_SHA=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_sha256)
    SOURCE_TRANSCRIPT_BYTES=$(startup_field_at "$STARTUP_RETIRE_CLEANUP" transcript_bytes)
    if [ -e "$SOURCE_TRANSCRIPT_PATH" ] || [ -L "$SOURCE_TRANSCRIPT_PATH" ]; then
        is_regular_nonsymlink "$SOURCE_TRANSCRIPT_PATH" \
            && [ "$(sha256sum "$SOURCE_TRANSCRIPT_PATH" | awk '{print $1}')" = "$SOURCE_TRANSCRIPT_SHA" ] \
            && [ "$(wc -c < "$SOURCE_TRANSCRIPT_PATH" | tr -d ' \t\r\n')" = "$SOURCE_TRANSCRIPT_BYTES" ] || return 1
        SOURCE_TRANSCRIPT_PRESENT=true
    else
        SOURCE_TRANSCRIPT_PRESENT=false
    fi
}

classify_startup_prefix_for_safeoff() {
    SOURCE_OWNER_EVIDENCE=
    SOURCE_ACTIVE_EVIDENCE=
    SOURCE_KIND=startup-prefix
    if [ -e "$STARTUP_RETIRE_CLEANUP" ] || [ -L "$STARTUP_RETIRE_CLEANUP" ]; then
        classify_startup_cleanup_for_safeoff
        return
    fi
    if is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" schema 2>/dev/null || true)" = dcentos.s19k-startup-j0-prefork/v1 ]; then
        [ ! -e "$STARTUP_RETIRED_OWNER" ] && [ ! -L "$STARTUP_RETIRED_OWNER" ] || return 1
        SOURCE_OWNER_EVIDENCE=$RUNTIME_LOCK_OWNER
    elif [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && is_regular_nonsymlink "$STARTUP_RETIRED_OWNER"; then
        SOURCE_OWNER_EVIDENCE=$STARTUP_RETIRED_OWNER
    elif [ -e "$RUNTIME_LOCK_OWNER" ] || [ -L "$RUNTIME_LOCK_OWNER" ]; then
        return 1
    elif [ -e "$STARTUP_RETIRED_OWNER" ] || [ -L "$STARTUP_RETIRED_OWNER" ]; then
        return 1
    else
        return 1
    fi

    if [ -n "$SOURCE_OWNER_EVIDENCE" ]; then
        load_bound_startup_j0_static_from "$SOURCE_OWNER_EVIDENCE" || return 1
        SOURCE_TRANSACTION_ID=$(runtime_lock_field_at "$SOURCE_OWNER_EVIDENCE" transaction_id)
        SOURCE_OWNER_PRESENT=true
        SOURCE_OWNER_PATH=$SOURCE_OWNER_EVIDENCE
        SOURCE_OWNER_SHA=$(sha256sum "$SOURCE_OWNER_EVIDENCE" | awk '{print $1}')
        SOURCE_OWNER_BYTES=$(wc -c < "$SOURCE_OWNER_EVIDENCE" | tr -d ' \t\r\n')
        if is_regular_nonsymlink "$ACTIVE" \
            && [ "$(active_field schema 2>/dev/null || true)" = dcentos.s19k-tmp-runtime/v5 ] \
            && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ]; then
            SOURCE_ACTIVE_EVIDENCE=$ACTIVE
        elif is_regular_nonsymlink "$STARTUP_RETIRED_ACTIVE" \
            && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
            SOURCE_ACTIVE_EVIDENCE=$STARTUP_RETIRED_ACTIVE
        elif [ -e "$ACTIVE" ] || [ -L "$ACTIVE" ] \
            || [ -e "$STARTUP_RETIRED_ACTIVE" ] || [ -L "$STARTUP_RETIRED_ACTIVE" ]; then
            return 1
        fi
        SOURCE_HIGHEST_PHASE=j0
        if [ -e "$STARTUP_RETIRE_TERMINAL" ] || [ -L "$STARTUP_RETIRE_TERMINAL" ]; then
            startup_retire_terminal_is_exact "$SOURCE_OWNER_EVIDENCE" || return 1
            SOURCE_HIGHEST_PHASE=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" highest_phase)
        elif [ -e "$STARTUP_PARENT_LOST" ] || [ -L "$STARTUP_PARENT_LOST" ]; then
            [ -z "$SOURCE_ACTIVE_EVIDENCE" ] \
                && [ ! -e "$STARTUP_C1" ] && [ ! -L "$STARTUP_C1" ] \
                && [ ! -e "$STARTUP_J1" ] && [ ! -L "$STARTUP_J1" ] \
                && [ ! -e "$STARTUP_J2" ] && [ ! -L "$STARTUP_J2" ] \
                && [ ! -e "$STARTUP_RELEASE" ] && [ ! -L "$STARTUP_RELEASE" ] \
                && startup_parent_lost_j0_is_exact_for_recovery "$SOURCE_OWNER_EVIDENCE" || return 1
            SOURCE_HIGHEST_PHASE=parent-lost-j0
        elif [ -e "$STARTUP_J2" ] || [ -L "$STARTUP_J2" ] \
            || [ -e "$STARTUP_RELEASE" ] || [ -L "$STARTUP_RELEASE" ]; then
            [ -n "$SOURCE_ACTIVE_EVIDENCE" ] \
                && load_bound_runtime_active_static_from "$SOURCE_ACTIVE_EVIDENCE" \
                && startup_j2_is_exact_for_recovery "$SOURCE_OWNER_EVIDENCE" "$SOURCE_ACTIVE_EVIDENCE" || return 1
            if [ -e "$STARTUP_RELEASE" ] || [ -L "$STARTUP_RELEASE" ]; then
                startup_release_is_exact_for_recovery "$SOURCE_OWNER_EVIDENCE" "$SOURCE_ACTIVE_EVIDENCE" || return 1
                SOURCE_HIGHEST_PHASE=release
            else
                SOURCE_HIGHEST_PHASE=j2
            fi
        elif [ -e "$STARTUP_J1" ] || [ -L "$STARTUP_J1" ]; then
            startup_j1_is_exact_for_recovery "$SOURCE_OWNER_EVIDENCE" || return 1
            if [ -n "$SOURCE_ACTIVE_EVIDENCE" ]; then
                load_bound_runtime_active_static_from "$SOURCE_ACTIVE_EVIDENCE" \
                    && [ "$RECEIPT_PHASE" = child-live-or-recovery-required ] || return 1
                SOURCE_HIGHEST_PHASE=active
            else
                SOURCE_HIGHEST_PHASE=j1
            fi
        elif [ -e "$STARTUP_C1" ] || [ -L "$STARTUP_C1" ]; then
            [ -z "$SOURCE_ACTIVE_EVIDENCE" ] \
                && startup_c1_is_exact_for_recovery "$SOURCE_OWNER_EVIDENCE" || return 1
            SOURCE_HIGHEST_PHASE=c1
        else
            [ -z "$SOURCE_ACTIVE_EVIDENCE" ] || return 1
        fi

        for SOURCE_SPEC in \
            "c1:$STARTUP_C1" "j1:$STARTUP_J1" "j2:$STARTUP_J2" \
            "release:$STARTUP_RELEASE" "parent_lost:$STARTUP_PARENT_LOST" \
            "terminal:$STARTUP_RETIRE_TERMINAL" "cleanup:$STARTUP_RETIRE_CLEANUP"; do
            SOURCE_NAME=${SOURCE_SPEC%%:*}
            SOURCE_PATH_VALUE=${SOURCE_SPEC#*:}
            capture_optional_startup_source_file "$SOURCE_PATH_VALUE" || return 1
            eval "SOURCE_${SOURCE_NAME}_PRESENT=\$OPTIONAL_PRESENT"
            eval "SOURCE_${SOURCE_NAME}_SHA=\$OPTIONAL_SHA"
            eval "SOURCE_${SOURCE_NAME}_BYTES=\$OPTIONAL_BYTES"
        done
        if is_regular_nonsymlink "$STARTUP_RETIRE_TERMINAL"; then
            for SOURCE_NAME in c1 j1 j2 release parent_lost; do
                HISTORICAL_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "${SOURCE_NAME}_sha256") || return 1
                HISTORICAL_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" "${SOURCE_NAME}_bytes") || return 1
                if [ "$HISTORICAL_SHA:$HISTORICAL_BYTES" != none:0 ]; then
                    valid_sha256 "$HISTORICAL_SHA" && valid_size "$HISTORICAL_BYTES" || return 1
                    eval "SOURCE_${SOURCE_NAME}_SHA=\$HISTORICAL_SHA"
                    eval "SOURCE_${SOURCE_NAME}_BYTES=\$HISTORICAL_BYTES"
                fi
            done
        fi
        if [ -n "$SOURCE_ACTIVE_EVIDENCE" ]; then
            SOURCE_ACTIVE_PRESENT=true
            SOURCE_ACTIVE_PATH=$SOURCE_ACTIVE_EVIDENCE
            SOURCE_ACTIVE_SHA=$(sha256sum "$SOURCE_ACTIVE_EVIDENCE" | awk '{print $1}')
            SOURCE_ACTIVE_BYTES=$(wc -c < "$SOURCE_ACTIVE_EVIDENCE" | tr -d ' \t\r\n')
        else
            SOURCE_ACTIVE_PRESENT=false
            SOURCE_ACTIVE_PATH=none
            SOURCE_ACTIVE_SHA=none
            SOURCE_ACTIVE_BYTES=0
        fi
        SOURCE_FIFO_PRESENT=false
        SOURCE_FIFO_PATH=$(runtime_lock_field_at "$SOURCE_OWNER_EVIDENCE" fifo_path)
        if [ -e "$SOURCE_FIFO_PATH" ] || [ -L "$SOURCE_FIFO_PATH" ]; then
            startup_fifo_matches_j0 "$SOURCE_OWNER_EVIDENCE" || return 1
            SOURCE_FIFO_PRESENT=true
        fi
        SOURCE_FIFO_MNT_ID=$(runtime_lock_field_at "$SOURCE_OWNER_EVIDENCE" fifo_mnt_id)
        SOURCE_FIFO_INODE=$(runtime_lock_field_at "$SOURCE_OWNER_EVIDENCE" fifo_inode)
        if is_regular_nonsymlink "$STARTUP_RETIRE_TERMINAL"; then
            SOURCE_TRANSCRIPT_PATH=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_path)
            SOURCE_TRANSCRIPT_MNT_ID=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_mnt_id)
            SOURCE_TRANSCRIPT_INODE=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_inode)
            SOURCE_TRANSCRIPT_MODE=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_mode)
            SOURCE_TRANSCRIPT_UID=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_uid)
            SOURCE_TRANSCRIPT_GID=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_gid)
            SOURCE_TRANSCRIPT_SHA=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_sha256)
            SOURCE_TRANSCRIPT_BYTES=$(startup_field_at "$STARTUP_RETIRE_TERMINAL" transcript_bytes)
        else
            capture_startup_transcript_for_terminal "$SOURCE_OWNER_EVIDENCE" || return 1
            SOURCE_TRANSCRIPT_PATH=$STARTUP_TRANSCRIPT_PATH
            SOURCE_TRANSCRIPT_MNT_ID=$STARTUP_TRANSCRIPT_MNT_ID
            SOURCE_TRANSCRIPT_INODE=$STARTUP_TRANSCRIPT_INODE
            SOURCE_TRANSCRIPT_MODE=0600
            SOURCE_TRANSCRIPT_UID=0
            SOURCE_TRANSCRIPT_GID=0
            SOURCE_TRANSCRIPT_SHA=$STARTUP_TRANSCRIPT_SHA
            SOURCE_TRANSCRIPT_BYTES=$STARTUP_TRANSCRIPT_BYTES
        fi
        if is_regular_nonsymlink "$SOURCE_TRANSCRIPT_PATH"; then
            SOURCE_TRANSCRIPT_PRESENT=true
            [ "$(sha256sum "$SOURCE_TRANSCRIPT_PATH" | awk '{print $1}')" = "$SOURCE_TRANSCRIPT_SHA" ] \
                && [ "$(wc -c < "$SOURCE_TRANSCRIPT_PATH" | tr -d ' \t\r\n')" = "$SOURCE_TRANSCRIPT_BYTES" ] || return 1
        else
            SOURCE_TRANSCRIPT_PRESENT=false
        fi
        return 0
    fi

    return 1
}

startup_prefix_source_scratch_is_complete() {
    SOURCE_SCRATCH=$1
    is_regular_nonsymlink "$SOURCE_SCRATCH" \
        && [ "$(wc -l < "$SOURCE_SCRATCH" | tr -d ' \t\r\n')" -eq 108 ] \
        && startup_ordered_keys_are_exact "$SOURCE_SCRATCH" "$STARTUP_PRESAFEOFF_SOURCE_KEYS_SHA" \
        && [ "$(startup_field_at "$SOURCE_SCRATCH" schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
        && [ "$(startup_field_at "$SOURCE_SCRATCH" publication)" = no-clobber-hard-link-after-fsync ]
}

retire_incomplete_startup_prefix_source_scratches() {
    [ ! -e "$STARTUP_PRESAFEOFF_SOURCE" ] && [ ! -L "$STARTUP_PRESAFEOFF_SOURCE" ] || return 1
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    PRE_J0_EXCLUDED_PATHS="$SOURCE_FIFO_PATH
$SOURCE_TRANSCRIPT_PATH"
    classify_exact_pre_j0_residues || return 1
    INCOMPLETE_SOURCE_LIST=
    OLD_IFS=$IFS
    IFS='
'
    for SOURCE_RESIDUE in $PRE_J0_RESIDUE_LIST; do
        SOURCE_RESIDUE_BASE=${SOURCE_RESIDUE##*/}
        case "$SOURCE_RESIDUE_BASE" in
            .runtime_startup_prefix_pre_safeoff.tmp.*)
                startup_prefix_source_scratch_is_complete "$SOURCE_RESIDUE" && {
                    IFS=$OLD_IFS
                    PRE_J0_EXCLUDED_PATHS=
                    return 1
                }
                INCOMPLETE_SOURCE_LIST=${INCOMPLETE_SOURCE_LIST}${INCOMPLETE_SOURCE_LIST:+"
"}$SOURCE_RESIDUE
                ;;
        esac
    done
    IFS=$OLD_IFS
    FIRST_SOURCE_RESIDUE_LIST=$PRE_J0_RESIDUE_LIST
    FIRST_SOURCE_RESIDUE_COUNT=$PRE_J0_RESIDUE_COUNT
    FIRST_SOURCE_RESIDUE_MANIFEST=$PRE_J0_RESIDUE_MANIFEST
    FIRST_SOURCE_RESIDUE_MANIFEST_SHA=$PRE_J0_RESIDUE_MANIFEST_SHA
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && [ ! -e "$STARTUP_PRESAFEOFF_SOURCE" ] && [ ! -L "$STARTUP_PRESAFEOFF_SOURCE" ] \
        && classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_LIST" = "$FIRST_SOURCE_RESIDUE_LIST" ] \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq "$FIRST_SOURCE_RESIDUE_COUNT" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST" = "$FIRST_SOURCE_RESIDUE_MANIFEST" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST_SHA" = "$FIRST_SOURCE_RESIDUE_MANIFEST_SHA" ] || {
            PRE_J0_EXCLUDED_PATHS=
            return 1
        }
    OLD_IFS=$IFS
    IFS='
'
    for SOURCE_RESIDUE in $INCOMPLETE_SOURCE_LIST; do
        [ -n "$SOURCE_RESIDUE" ] || continue
        rm -f "$SOURCE_RESIDUE" || {
            IFS=$OLD_IFS
            PRE_J0_EXCLUDED_PATHS=
            return 1
        }
        [ ! -e "$SOURCE_RESIDUE" ] && [ ! -L "$SOURCE_RESIDUE" ] || {
            IFS=$OLD_IFS
            PRE_J0_EXCLUDED_PATHS=
            return 1
        }
    done
    IFS=$OLD_IFS
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && [ ! -e "$STARTUP_PRESAFEOFF_SOURCE" ] && [ ! -L "$STARTUP_PRESAFEOFF_SOURCE" ] \
        && classify_exact_pre_j0_residues || {
            PRE_J0_EXCLUDED_PATHS=
            return 1
        }
    OLD_IFS=$IFS
    IFS='
'
    for SOURCE_RESIDUE in $PRE_J0_RESIDUE_LIST; do
        case "${SOURCE_RESIDUE##*/}" in
            .runtime_startup_prefix_pre_safeoff.tmp.*)
                IFS=$OLD_IFS
                PRE_J0_EXCLUDED_PATHS=
                return 1
                ;;
        esac
    done
    IFS=$OLD_IFS
    PRE_J0_EXCLUDED_PATHS=
}

publish_startup_prefix_safeoff_source() {
    if [ -e "$STARTUP_PRESAFEOFF_SOURCE" ] || [ -L "$STARTUP_PRESAFEOFF_SOURCE" ]; then
        startup_prefix_safeoff_source_is_exact
        return
    fi
    classify_startup_prefix_for_safeoff || return 1
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    retire_incomplete_startup_prefix_source_scratches || return 1
    if [ "$SOURCE_OWNER_PRESENT" = true ]; then
        preserve_startup_source_file "$SOURCE_OWNER_PATH" "$STARTUP_PRESAFEOFF_OWNER" \
            "$SOURCE_OWNER_SHA" "$SOURCE_OWNER_BYTES" || return 1
        SOURCE_OWNER_PATH=$STARTUP_PRESAFEOFF_OWNER
        PRESERVED_OWNER_PRESENT=true
        PRESERVED_OWNER_SHA=$SOURCE_OWNER_SHA
        PRESERVED_OWNER_BYTES=$SOURCE_OWNER_BYTES
    else
        [ ! -e "$STARTUP_PRESAFEOFF_OWNER" ] && [ ! -L "$STARTUP_PRESAFEOFF_OWNER" ] || return 1
        PRESERVED_OWNER_PRESENT=false
        PRESERVED_OWNER_SHA=none
        PRESERVED_OWNER_BYTES=0
    fi
    if [ "$SOURCE_ACTIVE_PRESENT" = true ]; then
        preserve_startup_source_file "$SOURCE_ACTIVE_PATH" "$STARTUP_PRESAFEOFF_ACTIVE" \
            "$SOURCE_ACTIVE_SHA" "$SOURCE_ACTIVE_BYTES" || return 1
        SOURCE_ACTIVE_PATH=$STARTUP_PRESAFEOFF_ACTIVE
        PRESERVED_ACTIVE_PRESENT=true
        PRESERVED_ACTIVE_SHA=$SOURCE_ACTIVE_SHA
        PRESERVED_ACTIVE_BYTES=$SOURCE_ACTIVE_BYTES
    else
        [ ! -e "$STARTUP_PRESAFEOFF_ACTIVE" ] && [ ! -L "$STARTUP_PRESAFEOFF_ACTIVE" ] || return 1
        PRESERVED_ACTIVE_PRESENT=false
        PRESERVED_ACTIVE_SHA=none
        PRESERVED_ACTIVE_BYTES=0
    fi
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1

    SOURCE_TMP="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.tmp.$$.${SELF_START}"
    [ ! -e "$SOURCE_TMP" ] && [ ! -L "$SOURCE_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-startup-prefix-safeoff-source/v1\n'
        printf 'transaction_id=%s\n' "$SOURCE_TRANSACTION_ID"
        printf 'phase=startup-prefix-stock-loss-admitted\n'
        printf 'highest_phase=%s\n' "$SOURCE_HIGHEST_PHASE"
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'source_kind=%s\n' "$SOURCE_KIND"
        printf 'owner_present=%s\nowner_path=%s\nowner_sha256=%s\nowner_bytes=%s\n' \
            "$SOURCE_OWNER_PRESENT" "$SOURCE_OWNER_PATH" "$SOURCE_OWNER_SHA" "$SOURCE_OWNER_BYTES"
        printf 'c1_present=%s\nc1_path=%s\nc1_sha256=%s\nc1_bytes=%s\n' \
            "$SOURCE_c1_PRESENT" "$STARTUP_C1" "$SOURCE_c1_SHA" "$SOURCE_c1_BYTES"
        printf 'j1_present=%s\nj1_path=%s\nj1_sha256=%s\nj1_bytes=%s\n' \
            "$SOURCE_j1_PRESENT" "$STARTUP_J1" "$SOURCE_j1_SHA" "$SOURCE_j1_BYTES"
        printf 'active_present=%s\nactive_path=%s\nactive_sha256=%s\nactive_bytes=%s\n' \
            "$SOURCE_ACTIVE_PRESENT" "$SOURCE_ACTIVE_PATH" "$SOURCE_ACTIVE_SHA" "$SOURCE_ACTIVE_BYTES"
        printf 'j2_present=%s\nj2_path=%s\nj2_sha256=%s\nj2_bytes=%s\n' \
            "$SOURCE_j2_PRESENT" "$STARTUP_J2" "$SOURCE_j2_SHA" "$SOURCE_j2_BYTES"
        printf 'release_present=%s\nrelease_path=%s\nrelease_sha256=%s\nrelease_bytes=%s\n' \
            "$SOURCE_release_PRESENT" "$STARTUP_RELEASE" "$SOURCE_release_SHA" "$SOURCE_release_BYTES"
        printf 'parent_lost_present=%s\nparent_lost_path=%s\nparent_lost_sha256=%s\nparent_lost_bytes=%s\n' \
            "$SOURCE_parent_lost_PRESENT" "$STARTUP_PARENT_LOST" "$SOURCE_parent_lost_SHA" "$SOURCE_parent_lost_BYTES"
        printf 'terminal_present=%s\nterminal_path=%s\nterminal_sha256=%s\nterminal_bytes=%s\n' \
            "$SOURCE_terminal_PRESENT" "$STARTUP_RETIRE_TERMINAL" "$SOURCE_terminal_SHA" "$SOURCE_terminal_BYTES"
        printf 'cleanup_present=%s\ncleanup_path=%s\ncleanup_sha256=%s\ncleanup_bytes=%s\n' \
            "$SOURCE_cleanup_PRESENT" "$STARTUP_RETIRE_CLEANUP" "$SOURCE_cleanup_SHA" "$SOURCE_cleanup_BYTES"
        printf 'preserved_owner_present=%s\npreserved_owner_path=%s\npreserved_owner_sha256=%s\npreserved_owner_bytes=%s\n' \
            "$PRESERVED_OWNER_PRESENT" "$STARTUP_PRESAFEOFF_OWNER" "$PRESERVED_OWNER_SHA" "$PRESERVED_OWNER_BYTES"
        printf 'preserved_active_present=%s\npreserved_active_path=%s\npreserved_active_sha256=%s\npreserved_active_bytes=%s\n' \
            "$PRESERVED_ACTIVE_PRESENT" "$STARTUP_PRESAFEOFF_ACTIVE" "$PRESERVED_ACTIVE_SHA" "$PRESERVED_ACTIVE_BYTES"
        printf 'fifo_present=%s\nfifo_path=%s\nfifo_mnt_id=%s\nfifo_inode=%s\n' \
            "$SOURCE_FIFO_PRESENT" "$SOURCE_FIFO_PATH" "$SOURCE_FIFO_MNT_ID" "$SOURCE_FIFO_INODE"
        printf 'transcript_present=%s\ntranscript_path=%s\ntranscript_mnt_id=%s\ntranscript_inode=%s\n' \
            "$SOURCE_TRANSCRIPT_PRESENT" "$SOURCE_TRANSCRIPT_PATH" "$SOURCE_TRANSCRIPT_MNT_ID" "$SOURCE_TRANSCRIPT_INODE"
        printf 'transcript_mode=%s\ntranscript_uid=%s\ntranscript_gid=%s\ntranscript_sha256=%s\ntranscript_bytes=%s\n' \
            "$SOURCE_TRANSCRIPT_MODE" "$SOURCE_TRANSCRIPT_UID" "$SOURCE_TRANSCRIPT_GID" "$SOURCE_TRANSCRIPT_SHA" "$SOURCE_TRANSCRIPT_BYTES"
        printf 'supervisor_pid=%s\nsupervisor_start=%s\nsupervisor_ppid=%s\nsupervisor_pgrp=%s\nsupervisor_session=%s\n' \
            "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" "$BOUND_SUPERVISOR_PPID" "$BOUND_SUPERVISOR_PGRP" "$BOUND_SUPERVISOR_SESSION"
        printf 'supervisor_exe=%s\nsupervisor_cmdline_sha256=%s\nsupervisor_cmdline_bytes=%s\n' \
            "$BOUND_SUPERVISOR_EXE" "$BOUND_SUPERVISOR_CMDLINE_SHA" "$BOUND_SUPERVISOR_CMDLINE_BYTES"
        printf 'bosminer_pid=%s\nbosminer_start=%s\nbosminer_ppid=%s\nbosminer_pgrp=%s\nbosminer_session=%s\n' \
            "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" "$BOUND_BOSMINER_PPID" "$BOUND_BOSMINER_PGRP" "$BOUND_BOSMINER_SESSION"
        printf 'bosminer_exe=%s\nbosminer_cmdline_sha256=%s\nbosminer_cmdline_bytes=%s\n' \
            "$BOUND_BOSMINER_EXE" "$BOUND_BOSMINER_CMDLINE_SHA" "$BOUND_BOSMINER_CMDLINE_BYTES"
        printf 'stock_pidfile_path=%s\nstock_pidfile_sha256=%s\nstock_pidfile_bytes=%s\n' \
            "$BOUND_STOCK_PIDFILE_PATH" "$BOUND_STOCK_PIDFILE_SHA" "$BOUND_STOCK_PIDFILE_BYTES"
        printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
        printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\nlive_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'stock_supervisor=absent\nstock_bosminer=absent\ndcentrald=absent\nwatchdog_fd=absent\ncompeting_wrapper=absent\n'
        printf 'watchdog_start_intent=false\nwatchdog_armed=false\nsignal_attempted=false\ninherited_rails=false\nroute_or_uart_opened=false\nhardware_opened=false\n'
        printf 'persistent_mutation=false\npublication=no-clobber-hard-link-after-fsync\n'
    } > "$SOURCE_TMP"
    chmod 600 "$SOURCE_TMP"
    [ "$(wc -l < "$SOURCE_TMP" | tr -d ' \t\r\n')" -eq 108 ] || return 1
    publish_no_clobber_journal "$SOURCE_TMP" "$STARTUP_PRESAFEOFF_SOURCE" || return 1
    startup_prefix_safeoff_source_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live
}

same_held_exact_regular_inode() {
    HELD_ONE=$1
    HELD_TWO=$2
    is_regular_nonsymlink "$HELD_ONE" && is_regular_nonsymlink "$HELD_TWO" || return 1
    exec 8< "$HELD_ONE" || return 1
    exec 9< "$HELD_TWO" || { exec 8>&-; return 1; }
    HELD_SAVED_IFS=$IFS
    IFS=' 	
'
    HELD_ONE_TARGET_INITIAL=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
    HELD_TWO_TARGET_INITIAL=$(readlink "/proc/$$/fd/9" 2>/dev/null || true)
    HELD_ONE_LS_INITIAL=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
    set -- $HELD_ONE_LS_INITIAL
    HELD_ONE_INODE_INITIAL=${1:-}
    HELD_ONE_MODE_INITIAL=${2:-}
    HELD_ONE_UID_INITIAL=${4:-}
    HELD_ONE_GID_INITIAL=${5:-}
    HELD_TWO_LS_INITIAL=$(ls -lniL "/proc/$$/fd/9" 2>/dev/null || true)
    set -- $HELD_TWO_LS_INITIAL
    HELD_TWO_INODE_INITIAL=${1:-}
    HELD_TWO_MODE_INITIAL=${2:-}
    HELD_TWO_UID_INITIAL=${4:-}
    HELD_TWO_GID_INITIAL=${5:-}
    HELD_ONE_MNT_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
    HELD_TWO_MNT_INITIAL=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/9" 2>/dev/null)
    HELD_ONE_SHA=$(sha256sum "/proc/$$/fd/8" 2>/dev/null | awk '{print $1}')
    HELD_TWO_SHA=$(sha256sum "/proc/$$/fd/9" 2>/dev/null | awk '{print $1}')
    HELD_ONE_BYTES=$(wc -c < "/proc/$$/fd/8" 2>/dev/null | tr -d ' \t\r\n')
    HELD_TWO_BYTES=$(wc -c < "/proc/$$/fd/9" 2>/dev/null | tr -d ' \t\r\n')
    HELD_ONE_TARGET=$(readlink "/proc/$$/fd/8" 2>/dev/null || true)
    HELD_TWO_TARGET=$(readlink "/proc/$$/fd/9" 2>/dev/null || true)
    HELD_ONE_LS=$(ls -lniL "/proc/$$/fd/8" 2>/dev/null || true)
    set -- $HELD_ONE_LS
    HELD_ONE_INODE=${1:-}
    HELD_ONE_MODE=${2:-}
    HELD_ONE_UID=${4:-}
    HELD_ONE_GID=${5:-}
    HELD_TWO_LS=$(ls -lniL "/proc/$$/fd/9" 2>/dev/null || true)
    set -- $HELD_TWO_LS
    HELD_TWO_INODE=${1:-}
    HELD_TWO_MODE=${2:-}
    HELD_TWO_UID=${4:-}
    HELD_TWO_GID=${5:-}
    HELD_ONE_MNT=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/8" 2>/dev/null)
    HELD_TWO_MNT=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/9" 2>/dev/null)
    IFS=$HELD_SAVED_IFS
    exec 9>&-
    exec 8>&-
    [ "$HELD_ONE_TARGET_INITIAL" = "$HELD_ONE" ] \
        && [ "$HELD_TWO_TARGET_INITIAL" = "$HELD_TWO" ] \
        && [ "$HELD_ONE_TARGET" = "$HELD_ONE_TARGET_INITIAL" ] \
        && [ "$HELD_TWO_TARGET" = "$HELD_TWO_TARGET_INITIAL" ] \
        && valid_uint "$HELD_ONE_INODE" \
        && [ "$HELD_ONE_INODE" = "$HELD_ONE_INODE_INITIAL" ] \
        && [ "$HELD_TWO_INODE" = "$HELD_TWO_INODE_INITIAL" ] \
        && [ "$HELD_ONE_INODE" = "$HELD_TWO_INODE" ] \
        && [ "$HELD_ONE_MODE" = "$HELD_ONE_MODE_INITIAL" ] \
        && [ "$HELD_TWO_MODE" = "$HELD_TWO_MODE_INITIAL" ] \
        && [ "$HELD_ONE_MODE" = -rw------- ] \
        && [ "$HELD_TWO_MODE" = "$HELD_ONE_MODE" ] \
        && [ "$HELD_ONE_UID" = "$HELD_ONE_UID_INITIAL" ] \
        && [ "$HELD_TWO_UID" = "$HELD_TWO_UID_INITIAL" ] \
        && [ "$HELD_ONE_UID" = 0 ] && [ "$HELD_TWO_UID" = 0 ] \
        && [ "$HELD_ONE_GID" = "$HELD_ONE_GID_INITIAL" ] \
        && [ "$HELD_TWO_GID" = "$HELD_TWO_GID_INITIAL" ] \
        && [ "$HELD_ONE_GID" = 0 ] && [ "$HELD_TWO_GID" = 0 ] \
        && valid_uint "$HELD_ONE_MNT" \
        && [ "$HELD_ONE_MNT" = "$HELD_ONE_MNT_INITIAL" ] \
        && [ "$HELD_TWO_MNT" = "$HELD_TWO_MNT_INITIAL" ] \
        && [ "$HELD_ONE_MNT" = "$HELD_TWO_MNT" ] \
        && valid_sha256 "$HELD_ONE_SHA" && [ "$HELD_ONE_SHA" = "$HELD_TWO_SHA" ] \
        && valid_uint "$HELD_ONE_BYTES" && [ "$HELD_ONE_BYTES" = "$HELD_TWO_BYTES" ]
}

guarded_unlink_transition_residue() {
    GUARDED_SCRATCH=$1
    GUARDED_CANONICAL=$2
    GUARDED_CLAIM=$3
    GUARDED_COMPLETION=$4
    is_regular_nonsymlink "$TRIAL_BIN" || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        DCENT_S19K_STARTUP_BOOTSTRAP=publisher-v1 \
        DCENT_S19K_STARTUP_WRAPPER_PID="$$" \
        DCENT_S19K_STARTUP_WRAPPER_START="$SELF_START" \
        "$TRIAL_BIN" \
        --s19k-track1-guarded-unlink-scratch "$GUARDED_SCRATCH" \
        --s19k-track1-guarded-unlink-canonical "$GUARDED_CANONICAL" \
        --s19k-track1-guarded-unlink-claim "$GUARDED_CLAIM" \
        --s19k-track1-guarded-unlink-completion "$GUARDED_COMPLETION" \
        6>&- 9>&- </dev/null >/dev/null 2>&1
}

consume_guarded_transition_completion() {
    GUARDED_COMPLETION=$1
    GUARDED_CANONICAL=$2
    startup_prefix_pending_is_exact \
        && startup_prefix_owner_v10_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        DCENT_S19K_STARTUP_BOOTSTRAP=publisher-v1 \
        DCENT_S19K_STARTUP_WRAPPER_PID="$$" \
        DCENT_S19K_STARTUP_WRAPPER_START="$SELF_START" \
        "$TRIAL_BIN" \
        --s19k-track1-consume-completion "$GUARDED_COMPLETION" \
        --s19k-track1-guarded-unlink-canonical "$GUARDED_CANONICAL" \
        6>&- 9>&- </dev/null >/dev/null 2>&1 || return 1
    startup_prefix_pending_is_exact \
        && startup_prefix_owner_v10_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live
}

durable_replace_startup_record() {
    DURABLE_SOURCE=$1
    DURABLE_DESTINATION=$2
    DURABLE_OLD_SHA=$3
    DURABLE_OLD_BYTES=$4
    DURABLE_NEW_SHA=$5
    DURABLE_NEW_BYTES=$6
    is_regular_nonsymlink "$TRIAL_BIN" \
        && { [ "$DURABLE_OLD_SHA:$DURABLE_OLD_BYTES" = none:0 ] \
            || { valid_sha256 "$DURABLE_OLD_SHA" && valid_size "$DURABLE_OLD_BYTES"; }; } \
        && valid_sha256 "$DURABLE_NEW_SHA" \
        && valid_size "$DURABLE_NEW_BYTES" || return 1
    /usr/bin/env -i \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        DCENT_S19K_STARTUP_BOOTSTRAP=publisher-v1 \
        DCENT_S19K_STARTUP_WRAPPER_PID="$$" \
        DCENT_S19K_STARTUP_WRAPPER_START="$SELF_START" \
        "$TRIAL_BIN" \
        --s19k-track1-durable-replace-source "$DURABLE_SOURCE" \
        --s19k-track1-durable-replace-destination "$DURABLE_DESTINATION" \
        --s19k-track1-durable-replace-old-sha256 "$DURABLE_OLD_SHA" \
        --s19k-track1-durable-replace-old-bytes "$DURABLE_OLD_BYTES" \
        --s19k-track1-durable-replace-new-sha256 "$DURABLE_NEW_SHA" \
        --s19k-track1-durable-replace-new-bytes "$DURABLE_NEW_BYTES" \
        6>&- 9>&- </dev/null >/dev/null 2>&1
}

retire_startup_prefix_transition_scratches() {
    startup_prefix_safeoff_source_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    PRE_J0_EXCLUDED_PATHS=$(startup_source_field fifo_path) || return 1
    PRE_J0_EXCLUDED_PATHS="$PRE_J0_EXCLUDED_PATHS
$(startup_source_field transcript_path)"
    TRANSITION_BASE_EXCLUDED_PATHS=$PRE_J0_EXCLUDED_PATHS
    STARTUP_TRANSITION_COMPLETION_LIST=
    classify_exact_pre_j0_residues || return 1
    FIRST_TRANSITION_RESIDUE_LIST=$PRE_J0_RESIDUE_LIST
    FIRST_TRANSITION_RESIDUE_COUNT=$PRE_J0_RESIDUE_COUNT
    OLD_IFS=$IFS
    IFS='
'
    for TRANSITION_RESIDUE in $FIRST_TRANSITION_RESIDUE_LIST; do
        TRANSITION_BASE=${TRANSITION_RESIDUE##*/}
        TRANSITION_DESTINATION=
        TRANSITION_SCRATCH=
        TRANSITION_CLAIM=
        TRANSITION_COMPLETION=
        case "$TRANSITION_BASE" in
            .runtime_startup_prefix_pre_safeoff.tmp.*)
                TRANSITION_DESTINATION=$STARTUP_PRESAFEOFF_SOURCE
                TRANSITION_SUFFIX=${TRANSITION_BASE#.runtime_startup_prefix_pre_safeoff.tmp.}
                TRANSITION_SCRATCH=$TRANSITION_RESIDUE
                TRANSITION_CLAIM="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.claim.$TRANSITION_SUFFIX"
                TRANSITION_COMPLETION="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.completed.$TRANSITION_SUFFIX"
                ;;
            .runtime_startup_prefix_pre_safeoff.claim.*)
                TRANSITION_DESTINATION=$STARTUP_PRESAFEOFF_SOURCE
                TRANSITION_SUFFIX=${TRANSITION_BASE#.runtime_startup_prefix_pre_safeoff.claim.}
                TRANSITION_SCRATCH="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.tmp.$TRANSITION_SUFFIX"
                TRANSITION_CLAIM=$TRANSITION_RESIDUE
                TRANSITION_COMPLETION="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.completed.$TRANSITION_SUFFIX"
                ;;
            .runtime_startup_prefix_pre_safeoff.completed.*)
                TRANSITION_DESTINATION=$STARTUP_PRESAFEOFF_SOURCE
                TRANSITION_SUFFIX=${TRANSITION_BASE#.runtime_startup_prefix_pre_safeoff.completed.}
                TRANSITION_SCRATCH="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.tmp.$TRANSITION_SUFFIX"
                TRANSITION_CLAIM="$TRIAL_DIR/.runtime_startup_prefix_pre_safeoff.claim.$TRANSITION_SUFFIX"
                TRANSITION_COMPLETION=$TRANSITION_RESIDUE
                ;;
            .runtime_safeoff_terminal_receipt.tmp.*|\
            .runtime_safeoff_terminal_receipt_receiptless.tmp.*|\
            .runtime_safeoff_terminal_receipt_startup_prefix.tmp.*)
                TRANSITION_DESTINATION=$SAFEOFF_TERMINAL_RECEIPT
                case "$TRANSITION_BASE" in
                    .runtime_safeoff_terminal_receipt.tmp.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt
                        ;;
                    .runtime_safeoff_terminal_receipt_receiptless.tmp.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_receiptless
                        ;;
                    .runtime_safeoff_terminal_receipt_startup_prefix.tmp.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_startup_prefix
                        ;;
                esac
                TRANSITION_SUFFIX=${TRANSITION_BASE#"$TRANSITION_PREFIX.tmp."}
                TRANSITION_SCRATCH=$TRANSITION_RESIDUE
                TRANSITION_CLAIM="$TRIAL_DIR/$TRANSITION_PREFIX.claim.$TRANSITION_SUFFIX"
                TRANSITION_COMPLETION="$TRIAL_DIR/$TRANSITION_PREFIX.completed.$TRANSITION_SUFFIX"
                ;;
            .runtime_safeoff_terminal_receipt.claim.*|\
            .runtime_safeoff_terminal_receipt_receiptless.claim.*|\
            .runtime_safeoff_terminal_receipt_startup_prefix.claim.*)
                TRANSITION_DESTINATION=$SAFEOFF_TERMINAL_RECEIPT
                case "$TRANSITION_BASE" in
                    .runtime_safeoff_terminal_receipt.claim.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt
                        ;;
                    .runtime_safeoff_terminal_receipt_receiptless.claim.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_receiptless
                        ;;
                    .runtime_safeoff_terminal_receipt_startup_prefix.claim.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_startup_prefix
                        ;;
                esac
                TRANSITION_SUFFIX=${TRANSITION_BASE#"$TRANSITION_PREFIX.claim."}
                TRANSITION_SCRATCH="$TRIAL_DIR/$TRANSITION_PREFIX.tmp.$TRANSITION_SUFFIX"
                TRANSITION_CLAIM=$TRANSITION_RESIDUE
                TRANSITION_COMPLETION="$TRIAL_DIR/$TRANSITION_PREFIX.completed.$TRANSITION_SUFFIX"
                ;;
            .runtime_safeoff_terminal_receipt.completed.*|\
            .runtime_safeoff_terminal_receipt_receiptless.completed.*|\
            .runtime_safeoff_terminal_receipt_startup_prefix.completed.*)
                TRANSITION_DESTINATION=$SAFEOFF_TERMINAL_RECEIPT
                case "$TRANSITION_BASE" in
                    .runtime_safeoff_terminal_receipt.completed.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt
                        ;;
                    .runtime_safeoff_terminal_receipt_receiptless.completed.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_receiptless
                        ;;
                    .runtime_safeoff_terminal_receipt_startup_prefix.completed.*)
                        TRANSITION_PREFIX=.runtime_safeoff_terminal_receipt_startup_prefix
                        ;;
                esac
                TRANSITION_SUFFIX=${TRANSITION_BASE#"$TRANSITION_PREFIX.completed."}
                TRANSITION_SCRATCH="$TRIAL_DIR/$TRANSITION_PREFIX.tmp.$TRANSITION_SUFFIX"
                TRANSITION_CLAIM="$TRIAL_DIR/$TRANSITION_PREFIX.claim.$TRANSITION_SUFFIX"
                TRANSITION_COMPLETION=$TRANSITION_RESIDUE
                ;;
            *) continue ;;
        esac
        guarded_unlink_transition_residue \
            "$TRANSITION_SCRATCH" "$TRANSITION_DESTINATION" "$TRANSITION_CLAIM" \
            "$TRANSITION_COMPLETION" || {
                IFS=$OLD_IFS
                return 1
            }
        STARTUP_TRANSITION_COMPLETION_LIST=${STARTUP_TRANSITION_COMPLETION_LIST}${STARTUP_TRANSITION_COMPLETION_LIST:+"
"}$TRANSITION_COMPLETION
    done
    IFS=$OLD_IFS
    PRE_J0_EXCLUDED_PATHS=$TRANSITION_BASE_EXCLUDED_PATHS
    if [ -n "$STARTUP_TRANSITION_COMPLETION_LIST" ]; then
        PRE_J0_EXCLUDED_PATHS="$PRE_J0_EXCLUDED_PATHS
$STARTUP_TRANSITION_COMPLETION_LIST"
    fi
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && startup_prefix_safeoff_source_is_exact || return 1
    classify_exact_pre_j0_residues || return 1
    FIRST_GENERIC_RESIDUE_LIST=$PRE_J0_RESIDUE_LIST
    FIRST_GENERIC_RESIDUE_COUNT=$PRE_J0_RESIDUE_COUNT
    FIRST_GENERIC_RESIDUE_MANIFEST=$PRE_J0_RESIDUE_MANIFEST
    FIRST_GENERIC_RESIDUE_MANIFEST_SHA=$PRE_J0_RESIDUE_MANIFEST_SHA
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && startup_prefix_safeoff_source_is_exact \
        && classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_LIST" = "$FIRST_GENERIC_RESIDUE_LIST" ] \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq "$FIRST_GENERIC_RESIDUE_COUNT" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST" = "$FIRST_GENERIC_RESIDUE_MANIFEST" ] \
        && [ "$PRE_J0_RESIDUE_MANIFEST_SHA" = "$FIRST_GENERIC_RESIDUE_MANIFEST_SHA" ] || return 1
    remove_classified_pre_j0_residues || return 1
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && startup_prefix_safeoff_source_is_exact \
        && classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] || return 1
    PRE_J0_EXCLUDED_PATHS=
}

consume_startup_transition_completions() {
    startup_prefix_pending_is_exact \
        && startup_prefix_owner_v10_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    CONSUME_COMPLETION_SAVED_IFS=$IFS
    CONSUME_COMPLETION_NEWLINE_IFS='
'
    IFS=$CONSUME_COMPLETION_NEWLINE_IFS
    for TRANSITION_COMPLETION in $STARTUP_TRANSITION_COMPLETION_LIST; do
        [ -n "$TRANSITION_COMPLETION" ] || continue
        # Nested exact validators use their own shared IFS scratch variable.
        # Restore the caller's parsing contract before entering any of them;
        # newline-only splitting is authority solely for selecting this list.
        IFS=$CONSUME_COMPLETION_SAVED_IFS
        case "${TRANSITION_COMPLETION##*/}" in
            .runtime_startup_prefix_pre_safeoff.completed.*)
                TRANSITION_CANONICAL=$STARTUP_PRESAFEOFF_SOURCE
                ;;
            .runtime_safeoff_terminal_receipt.completed.*|\
            .runtime_safeoff_terminal_receipt_receiptless.completed.*|\
            .runtime_safeoff_terminal_receipt_startup_prefix.completed.*)
                TRANSITION_CANONICAL=$SAFEOFF_TERMINAL_RECEIPT
                ;;
            *) IFS=$CONSUME_COMPLETION_SAVED_IFS; return 1 ;;
        esac
        consume_guarded_transition_completion \
            "$TRANSITION_COMPLETION" "$TRANSITION_CANONICAL" || {
                IFS=$CONSUME_COMPLETION_SAVED_IFS
                return 1
            }
        IFS=$CONSUME_COMPLETION_NEWLINE_IFS
    done
    IFS=$CONSUME_COMPLETION_SAVED_IFS
    startup_prefix_pending_is_exact \
        && startup_prefix_owner_v10_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    PRE_J0_EXCLUDED_PATHS=$(startup_source_field fifo_path) || return 1
    PRE_J0_EXCLUDED_PATHS="$PRE_J0_EXCLUDED_PATHS
$(startup_source_field transcript_path)"
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] || return 1
    PRE_J0_EXCLUDED_PATHS=
}

publish_startup_canonical_pre_safeoff_active() {
    startup_prefix_safeoff_source_is_exact \
        && [ "$(startup_source_field preserved_active_present)" = true ] \
        && [ "$(startup_source_field preserved_active_path)" = "$STARTUP_PRESAFEOFF_ACTIVE" ] \
        && is_regular_nonsymlink "$STARTUP_PRESAFEOFF_ACTIVE" \
        && [ "$(active_field_at "$STARTUP_PRESAFEOFF_ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field_at "$STARTUP_PRESAFEOFF_ACTIVE" deploy_mode)" = "$DEPLOY_MODE" ] \
        && [ "$(sha256sum "$STARTUP_PRESAFEOFF_ACTIVE" | awk '{print $1}')" = "$(startup_source_field preserved_active_sha256)" ] \
        && [ "$(wc -c < "$STARTUP_PRESAFEOFF_ACTIVE" | tr -d ' \t\r\n')" = "$(startup_source_field preserved_active_bytes)" ] || return 1
    if [ -e "$PRE_SAFEOFF_ACTIVE" ] || [ -L "$PRE_SAFEOFF_ACTIVE" ]; then
        is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
            && [ "$PRE_SAFEOFF_ACTIVE" -ef "$STARTUP_PRESAFEOFF_ACTIVE" ]
        return
    fi
    ln "$STARTUP_PRESAFEOFF_ACTIVE" "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$PRE_SAFEOFF_ACTIVE" -ef "$STARTUP_PRESAFEOFF_ACTIVE" ]
}

consume_startup_transition_completions_after_v4_pending() {
    is_regular_nonsymlink "$ACTIVE" \
        && { [ "$(active_field schema)" = dcentos.s19k-stock-restart-pending/v4 ] \
            || [ "$(active_field schema)" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; } \
        && is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v8 ] \
        && [ "$(runtime_lock_field active_sha256)" = "$(sha256sum "$ACTIVE" | awk '{print $1}')" ] \
        && [ "$(active_field source_runtime_active_path)" = "$PRE_SAFEOFF_ACTIVE" ] \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
        && terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
        && pending_terminal_binding_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    CONSUME_COMPLETION_SAVED_IFS=$IFS
    CONSUME_COMPLETION_NEWLINE_IFS='
'
    IFS=$CONSUME_COMPLETION_NEWLINE_IFS
    for TRANSITION_COMPLETION in $STARTUP_TRANSITION_COMPLETION_LIST; do
        [ -n "$TRANSITION_COMPLETION" ] || continue
        IFS=$CONSUME_COMPLETION_SAVED_IFS
        case "${TRANSITION_COMPLETION##*/}" in
            .runtime_startup_prefix_pre_safeoff.completed.*)
                TRANSITION_CANONICAL=$STARTUP_PRESAFEOFF_SOURCE
                ;;
            .runtime_safeoff_terminal_receipt.completed.*|\
            .runtime_safeoff_terminal_receipt_receiptless.completed.*|\
            .runtime_safeoff_terminal_receipt_startup_prefix.completed.*)
                TRANSITION_CANONICAL=$SAFEOFF_TERMINAL_RECEIPT
                ;;
            *) IFS=$CONSUME_COMPLETION_SAVED_IFS; return 1 ;;
        esac
        consume_guarded_transition_completion \
            "$TRANSITION_COMPLETION" "$TRANSITION_CANONICAL" || {
                IFS=$CONSUME_COMPLETION_SAVED_IFS
                return 1
            }
        IFS=$CONSUME_COMPLETION_NEWLINE_IFS
    done
    IFS=$CONSUME_COMPLETION_SAVED_IFS
    PRE_J0_EXCLUDED_PATHS=$(startup_source_field fifo_path) || return 1
    PRE_J0_EXCLUDED_PATHS="$PRE_J0_EXCLUDED_PATHS
$(startup_source_field transcript_path)"
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] || return 1
    PRE_J0_EXCLUDED_PATHS=
}

ensure_startup_prefix_safeoff_lock() {
    startup_prefix_safeoff_source_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    if is_regular_nonsymlink "$RUNTIME_LOCK_OWNER"; then
        CURRENT_SCHEMA=$(runtime_lock_field schema) || return 1
        case "$CURRENT_SCHEMA" in
            dcentos.s19k-startup-j0-prefork/v1)
                [ "$(startup_source_field preserved_owner_present)" = true ] \
                    && [ "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" = "$(startup_source_field preserved_owner_sha256)" ] \
                    && [ "$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" = "$(startup_source_field preserved_owner_bytes)" ] \
                    && load_bound_startup_j0_static_from "$RUNTIME_LOCK_OWNER" || return 1
                ;;
            dcentos.s19k-track1-runtime-lock/v6)
                admit_runtime_lock_owner || return 1
                ;;
            dcentos.s19k-track1-runtime-lock/v10)
                startup_prefix_pending_is_exact \
                    && startup_prefix_owner_v10_is_exact
                return
                ;;
            *) return 1 ;;
        esac
        return 0
    fi
    [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] || return 1
    if [ ! -e "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ]; then
        mkdir "$RUNTIME_LOCK" && chmod 700 "$RUNTIME_LOCK" || return 1
    fi
    runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] || return 1
    write_runtime_lock_owner recovery || return 1
    admit_runtime_lock_owner
}

publish_startup_prefix_safeoff_companion() {
    startup_prefix_safeoff_source_is_exact || return 1
    set_expected_safeoff_receipt
    ensure_startup_prefix_safeoff_lock \
        && require_same_live_s19k_identity || return 1
    if [ -e "$SAFEOFF_TERMINAL_RECEIPT" ] || [ -L "$SAFEOFF_TERMINAL_RECEIPT" ]; then
        is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
            && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
            && gpio_safeoff_is_exact \
            && no_stock_daemon_watchdog_or_competing_wrapper_is_live
        return
    fi
    if [ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]; then
        # GPIO437-only custody may never fall back to the reset-capable
        # recovery command. Require the daemon's immutable terminal receipt,
        # checked SafeOff GPIO, and complete stock absence before minting the
        # companion line.
        is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
            && terminal_handoff_receipt_is_exact "$STARTUP_PRESAFEOFF_ACTIVE" \
            && [ "$(terminal_handoff_field resets)" = not-attempted ] \
            && gpio_safeoff_is_exact \
            && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    else
        run_checked_safeoff_command || return 1
    fi
    gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    SAFE_TMP="$TRIAL_DIR/.runtime_safeoff_terminal_receipt_startup_prefix.tmp.$$.${SELF_START}"
    [ ! -e "$SAFE_TMP" ] && [ ! -L "$SAFE_TMP" ] || return 1
    printf '%s\n' "$EXPECTED_SAFEOFF_RECEIPT" > "$SAFE_TMP"
    chmod 600 "$SAFE_TMP"
    publish_no_clobber_journal "$SAFE_TMP" "$SAFEOFF_TERMINAL_RECEIPT" || return 1
    is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live
}

startup_prefix_pending_is_exact() {
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 47 ] \
        && startup_ordered_keys_are_exact "$ACTIVE" "$STARTUP_PREFIX_PENDING_KEYS_SHA" \
        && [ "$(active_field schema)" = dcentos.s19k-startup-prefix-stock-restart-pending/v1 ] \
        && [ "$(active_field phase)" = terminal-safeoff-stock-restart-pending ] \
        && [ "$(active_field terminal)" = true ] \
        && [ "$(active_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(active_field transaction_id)" = "$(startup_source_field transaction_id)" ] \
        && [ "$(active_field highest_phase)" = "$(startup_source_field highest_phase)" ] \
        && [ "$(active_field source_receipt_schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
        && [ "$(active_field source_receipt_path)" = "$STARTUP_PRESAFEOFF_SOURCE" ] \
        && [ "$(active_field source_receipt_sha256)" = "$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')" ] \
        && [ "$(active_field source_receipt_bytes)" = "$(wc -c < "$STARTUP_PRESAFEOFF_SOURCE" | tr -d ' \t\r\n')" ] \
        && [ "$(active_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(active_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(active_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(active_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(active_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(active_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(active_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(active_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(active_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(active_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(active_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(active_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(active_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(active_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(active_field live_identity_board_count)" = "$BOARD_COUNT" ] \
        && [ "$(active_field live_identity_physical_addresses)" = "$LIVE_IDENTITY_PHYSICAL_ADDRESSES" ] \
        && [ "$(active_field live_identity_board_names)" = "$LIVE_IDENTITY_BOARD_NAMES" ] \
        && [ "$(active_field live_identity_eeprom)" = "$LIVE_IDENTITY_EEPROM_SLOTS" ] \
        && [ "$(active_field safeoff_receipt_schema)" = dcentos.s19k-track1-safeoff/v1 ] \
        && [ "$(active_field safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && [ "$(active_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ] \
        && [ "$(active_field safeoff_receipt_bytes)" = "$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')" ] \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && [ "$(active_field resets)" = 454:0,455:0,456:0 ] \
        && [ "$(active_field psu)" = 437:1 ] \
        && [ "$(active_field gpio_raw)" = 437:1,454:0,455:0,456:0 ] \
        && [ "$(active_field dcentrald)" = absent ] \
        && [ "$(active_field wrapper_exit_required)" = true ] \
        && [ "$(active_field stock_supervisor)" = absent ] \
        && [ "$(active_field stock_bosminer)" = absent ] \
        && [ "$(active_field watchdog_fd)" = absent ] \
        && [ "$(active_field stock_init_path)" = /etc/init.d/S99bosminer ] \
        && [ "$(active_field stock_init_sha256)" = 6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9 ] \
        && [ "$(active_field stock_init_bytes)" = 1330 ] \
        && [ "$(active_field persistent_mutation)" = false ] \
        && [ "$(active_field next_authority)" = exact-stock-restart-helper-only ] || return 1
    WRITER_PID=$(active_field writer_wrapper_pid)
    WRITER_START=$(active_field writer_wrapper_start)
    valid_pid_start "$WRITER_PID" "$WRITER_START"
}

startup_prefix_owner_v10_is_exact() {
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq 16 ] \
        && startup_ordered_keys_are_exact "$RUNTIME_LOCK_OWNER" "$STARTUP_PREFIX_OWNER_KEYS_SHA" \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v10 ] \
        && [ "$(runtime_lock_field owner_kind)" = startup-prefix-stock-restart-pending ] \
        && [ "$(runtime_lock_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(runtime_lock_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(runtime_lock_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(runtime_lock_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(runtime_lock_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(runtime_lock_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(runtime_lock_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(runtime_lock_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(runtime_lock_field active_sha256)" = "$(sha256sum "$ACTIVE" | awk '{print $1}')" ] \
        && [ "$(runtime_lock_field active_bytes)" = "$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')" ] \
        && [ "$(runtime_lock_field transaction_id)" = "$(startup_source_field transaction_id)" ] \
        && [ "$(runtime_lock_field highest_phase)" = "$(startup_source_field highest_phase)" ] \
        && [ "$(runtime_lock_field source_receipt_sha256)" = "$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')" ] \
        && [ "$(runtime_lock_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ]
}

publish_startup_prefix_pending_after_safeoff() {
    startup_prefix_safeoff_source_is_exact \
        && ensure_startup_prefix_safeoff_lock \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    STOCK_INIT=/etc/init.d/S99bosminer
    STOCK_INIT_EXPECTED_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9
    STOCK_INIT_EXPECTED_BYTES=1330
    is_regular_nonsymlink "$STOCK_INIT" \
        && [ "$(sha256sum "$STOCK_INIT" | awk '{print $1}')" = "$STOCK_INIT_EXPECTED_SHA" ] \
        && [ "$(wc -c < "$STOCK_INIT" | tr -d ' \t\r\n')" = "$STOCK_INIT_EXPECTED_BYTES" ] || return 1
    PENDING_TMP="$TRIAL_DIR/.runtime_active_startup_prefix_stock_restart_pending.tmp.$$.${SELF_START}"
    if is_regular_nonsymlink "$ACTIVE" \
        && [ "$(active_field schema 2>/dev/null || true)" = dcentos.s19k-startup-prefix-stock-restart-pending/v1 ]; then
        startup_prefix_pending_is_exact || return 1
        PENDING_NEW_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
        PENDING_NEW_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
        durable_replace_startup_record \
            "$PENDING_TMP" "$ACTIVE" none 0 "$PENDING_NEW_SHA" "$PENDING_NEW_BYTES" || return 1
        startup_prefix_pending_is_exact || return 1
    else
        PENDING_OLD_SHA=none
        PENDING_OLD_BYTES=0
        if [ -e "$ACTIVE" ] || [ -L "$ACTIVE" ]; then
            [ "$(startup_source_field preserved_active_present)" = true ] \
                && [ "$(sha256sum "$ACTIVE" | awk '{print $1}')" = "$(startup_source_field preserved_active_sha256)" ] \
                && [ "$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')" = "$(startup_source_field preserved_active_bytes)" ] || return 1
            PENDING_OLD_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
            PENDING_OLD_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
        fi
        SOURCE_RECEIPT_SHA=$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')
        SOURCE_RECEIPT_BYTES=$(wc -c < "$STARTUP_PRESAFEOFF_SOURCE" | tr -d ' \t\r\n')
        SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
        SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
        [ ! -e "$PENDING_TMP" ] && [ ! -L "$PENDING_TMP" ] || return 1
        {
            printf 'schema=dcentos.s19k-startup-prefix-stock-restart-pending/v1\n'
            printf 'phase=terminal-safeoff-stock-restart-pending\nterminal=true\ntrial_dir=%s\n' "$TRIAL_DIR"
            printf 'transaction_id=%s\nhighest_phase=%s\n' "$(startup_source_field transaction_id)" "$(startup_source_field highest_phase)"
            printf 'source_receipt_schema=dcentos.s19k-startup-prefix-safeoff-source/v1\n'
            printf 'source_receipt_path=%s\nsource_receipt_sha256=%s\nsource_receipt_bytes=%s\n' "$STARTUP_PRESAFEOFF_SOURCE" "$SOURCE_RECEIPT_SHA" "$SOURCE_RECEIPT_BYTES"
            printf 'binary_sha256=%s\nbinary_bytes=%s\n' "$BIN_SHA" "$BIN_BYTES"
            printf 'config_sha256=%s\nconfig_bytes=%s\n' "$CFG_SHA" "$CFG_BYTES"
            printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
            printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
            printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
            printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
            printf 'live_identity_profile=%s\nlive_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE" "$EXPECTED_LIVE_IDENTITY_SHA"
            printf 'live_identity_model_sha256=%s\nlive_identity_board_count=%s\n' "$LIVE_IDENTITY_MODEL_SHA" "$BOARD_COUNT"
            printf 'live_identity_physical_addresses=%s\nlive_identity_board_names=%s\nlive_identity_eeprom=%s\n' "$LIVE_IDENTITY_PHYSICAL_ADDRESSES" "$LIVE_IDENTITY_BOARD_NAMES" "$LIVE_IDENTITY_EEPROM_SLOTS"
            printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
            printf 'safeoff_receipt_path=%s\nsafeoff_receipt_sha256=%s\nsafeoff_receipt_bytes=%s\n' "$SAFEOFF_TERMINAL_RECEIPT" "$SAFEOFF_SHA" "$SAFEOFF_BYTES"
            printf 'resets=454:0,455:0,456:0\npsu=437:1\ngpio_raw=437:1,454:0,455:0,456:0\n'
            printf 'dcentrald=absent\nwriter_wrapper_pid=%s\nwriter_wrapper_start=%s\nwrapper_exit_required=true\n' "$$" "$SELF_START"
            printf 'stock_supervisor=absent\nstock_bosminer=absent\nwatchdog_fd=absent\n'
            printf 'stock_init_path=%s\nstock_init_sha256=%s\nstock_init_bytes=%s\n' "$STOCK_INIT" "$STOCK_INIT_EXPECTED_SHA" "$STOCK_INIT_EXPECTED_BYTES"
            printf 'persistent_mutation=false\nnext_authority=exact-stock-restart-helper-only\n'
        } > "$PENDING_TMP"
        chmod 600 "$PENDING_TMP"
        [ "$(wc -l < "$PENDING_TMP" | tr -d ' \t\r\n')" -eq 47 ] || return 1
        PENDING_NEW_SHA=$(sha256sum "$PENDING_TMP" | awk '{print $1}')
        PENDING_NEW_BYTES=$(wc -c < "$PENDING_TMP" | tr -d ' \t\r\n')
        durable_replace_startup_record \
            "$PENDING_TMP" "$ACTIVE" "$PENDING_OLD_SHA" "$PENDING_OLD_BYTES" \
            "$PENDING_NEW_SHA" "$PENDING_NEW_BYTES" || return 1
        startup_prefix_pending_is_exact || return 1
    fi

    OWNER_TMP="$TRIAL_DIR/.runtime_owner_startup_prefix_stock_restart_pending.tmp.$$.${SELF_START}"
    if startup_prefix_owner_v10_is_exact; then
        OWNER_NEW_SHA=$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')
        OWNER_NEW_BYTES=$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')
        durable_replace_startup_record \
            "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" none 0 "$OWNER_NEW_SHA" "$OWNER_NEW_BYTES" \
            || return 1
        startup_prefix_owner_v10_is_exact \
            && startup_prefix_pending_is_exact || return 1
        return 0
    fi
    CURRENT_OWNER_SCHEMA=$(runtime_lock_field schema 2>/dev/null || true)
    case "$CURRENT_OWNER_SCHEMA" in
        dcentos.s19k-startup-j0-prefork/v1)
            [ "$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')" = "$(startup_source_field preserved_owner_sha256)" ] || return 1
            ;;
        dcentos.s19k-track1-runtime-lock/v6) admit_runtime_lock_owner || return 1 ;;
        *) return 1 ;;
    esac
    OWNER_OLD_SHA=$(sha256sum "$RUNTIME_LOCK_OWNER" | awk '{print $1}')
    OWNER_OLD_BYTES=$(wc -c < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')
    PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    SOURCE_RECEIPT_SHA=$(sha256sum "$STARTUP_PRESAFEOFF_SOURCE" | awk '{print $1}')
    SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    [ ! -e "$OWNER_TMP" ] && [ ! -L "$OWNER_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-track1-runtime-lock/v10\n'
        printf 'owner_kind=startup-prefix-stock-restart-pending\ntrial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\nrunner_bytes=%s\n' "$RUNNER_SHA" "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\ncustody_observer_bytes=%s\n' "$CUSTODY_SHA" "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\nstock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_SHA" "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\nactive_sha256=%s\nactive_bytes=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA" "$PENDING_SHA" "$PENDING_BYTES"
        printf 'transaction_id=%s\nhighest_phase=%s\n' "$(startup_source_field transaction_id)" "$(startup_source_field highest_phase)"
        printf 'source_receipt_sha256=%s\nsafeoff_receipt_sha256=%s\n' "$SOURCE_RECEIPT_SHA" "$SAFEOFF_SHA"
    } > "$OWNER_TMP"
    chmod 600 "$OWNER_TMP"
    OWNER_NEW_SHA=$(sha256sum "$OWNER_TMP" | awk '{print $1}')
    OWNER_NEW_BYTES=$(wc -c < "$OWNER_TMP" | tr -d ' \t\r\n')
    durable_replace_startup_record \
        "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" "$OWNER_OLD_SHA" "$OWNER_OLD_BYTES" \
        "$OWNER_NEW_SHA" "$OWNER_NEW_BYTES" || return 1
    startup_prefix_owner_v10_is_exact \
        && startup_prefix_pending_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live
}

transition_startup_stock_loss_to_pending() {
    publish_startup_prefix_safeoff_source || return 1
    startup_prefix_safeoff_source_is_exact || return 1
    EXPECTED_LIVE_IDENTITY_PROFILE=$(startup_source_field live_identity_profile)
    EXPECTED_LIVE_IDENTITY_SHA=$(startup_source_field live_identity_sha256)
    require_same_live_s19k_identity || return 1
    retire_startup_prefix_transition_scratches || return 1
    publish_startup_prefix_safeoff_companion || return 1
    if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
        is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
            && terminal_handoff_receipt_is_exact "$STARTUP_PRESAFEOFF_ACTIVE" \
            && publish_startup_canonical_pre_safeoff_active \
            && clear_runtime_obligation_after_safeoff \
            && consume_startup_transition_completions_after_v4_pending || return 1
        echo "S19k startup stock loss is SafeOff; canonical v4 stock restart and transcript publication remain pending"
        return 0
    fi
    publish_startup_prefix_pending_after_safeoff || return 1
    consume_startup_transition_completions || return 1
    echo "S19k startup stock loss is SafeOff; typed startup-prefix stock restart remains pending"
}

pending_terminal_binding_is_exact() {
    if [ "$PENDING_SCHEMA" = dcentos.s19k-stock-restart-pending/v4 ] \
        || [ "$PENDING_SCHEMA" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; then
        is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
            && [ "$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')" = "$TERMINAL_HANDOFF_SHA" ] \
            && [ "$(active_field terminal_handoff_receipt_schema)" = "$EXPECTED_TERMINAL_HANDOFF_SCHEMA" ] \
            && [ "$(active_field terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF_RECEIPT" ] \
            && [ "$(active_field terminal_handoff_receipt_sha256)" = "$TERMINAL_HANDOFF_SHA" ] \
            && [ "$(active_field terminal_handoff_receipt_bytes)" = "$TERMINAL_HANDOFF_BYTES" ] \
            && [ "$(runtime_lock_field terminal_handoff_receipt_sha256)" = "$TERMINAL_HANDOFF_SHA" ]
    else
        [ ! -e "$TERMINAL_HANDOFF_RECEIPT" ] && [ ! -L "$TERMINAL_HANDOFF_RECEIPT" ]
    fi
}

clear_runtime_obligation_after_safeoff() {
    # SafeOff is not stock recovery. Preserve the exact v4 predecessor and
    # checked SafeOff line, then atomically turn ACTIVE into the sole typed
    # stock-restart obligation. Keep the board-global lock held; only the
    # separately audited exact-stock-restart helper may consume it.
    set_expected_safeoff_receipt || return 1
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 40 ] \
        && [ "$(active_field schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(active_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(active_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(active_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(active_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(active_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(active_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(active_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(active_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(active_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(active_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(active_field persistent_mutation)" = false ] \
        && admit_runtime_lock_owner || {
            echo "ERROR: checked SafeOff cannot transition an inexact runtime obligation" >&2
            return 1
        }
    gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && process_matches "$$" "$SELF_START" \
        && verify_all_bound_files \
        && require_same_live_s19k_identity || {
            echo "ERROR: post-SafeOff owner/GPIO/artifact revalidation failed" >&2
            return 1
        }
    STOCK_INIT=/etc/init.d/S99bosminer
    STOCK_INIT_EXPECTED_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9
    STOCK_INIT_EXPECTED_BYTES=1330
    is_regular_nonsymlink "$STOCK_INIT" \
        && [ "$(sha256sum "$STOCK_INIT" | awk '{print $1}')" = "$STOCK_INIT_EXPECTED_SHA" ] \
        && [ "$(wc -c < "$STOCK_INIT" | tr -d ' \t\r\n')" = "$STOCK_INIT_EXPECTED_BYTES" ] || {
            echo "ERROR: live stock init script does not match held recovery authority" >&2
            return 1
        }

    SOURCE_ACTIVE_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    SOURCE_ACTIVE_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    valid_sha256 "$SOURCE_ACTIVE_SHA" && valid_size "$SOURCE_ACTIVE_BYTES" || return 1
    if [ -e "$PRE_SAFEOFF_ACTIVE" ] || [ -L "$PRE_SAFEOFF_ACTIVE" ]; then
        is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
            && [ "$ACTIVE" -ef "$PRE_SAFEOFF_ACTIVE" ] \
            && [ "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" = "$SOURCE_ACTIVE_SHA" ] \
            && [ "$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')" = "$SOURCE_ACTIVE_BYTES" ] || {
                echo "ERROR: existing pre-SafeOff companion is not the exact v4 ACTIVE inode/content" >&2
                return 1
            }
    else
        ln "$ACTIVE" "$PRE_SAFEOFF_ACTIVE" || return 1
    fi
    is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" = "$SOURCE_ACTIVE_SHA" ] \
        && [ "$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')" = "$SOURCE_ACTIVE_BYTES" ] || return 1

    if [ -e "$SAFEOFF_TERMINAL_RECEIPT" ] || [ -L "$SAFEOFF_TERMINAL_RECEIPT" ]; then
        is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
            && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] || {
                echo "ERROR: existing terminal SafeOff companion is not exact" >&2
                return 1
            }
    else
        SAFE_TMP="$TRIAL_DIR/.runtime_safeoff_terminal_receipt.tmp.$$.${SELF_START}"
        [ ! -e "$SAFE_TMP" ] && [ ! -L "$SAFE_TMP" ] || return 1
        printf '%s\n' "$EXPECTED_SAFEOFF_RECEIPT" > "$SAFE_TMP"
        chmod 600 "$SAFE_TMP"
        ln "$SAFE_TMP" "$SAFEOFF_TERMINAL_RECEIPT" || {
            rm -f "$SAFE_TMP"
            return 1
        }
        rm -f "$SAFE_TMP"
    fi
    is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] || return 1
    SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    valid_sha256 "$SAFEOFF_SHA" && valid_size "$SAFEOFF_BYTES" || return 1

    PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/v3
    PENDING_LINES=45
    OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v7
    OWNER_LINES=14
    TERMINAL_HANDOFF_SHA=
    TERMINAL_HANDOFF_BYTES=
    if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
        terminal_handoff_receipt_is_exact || return 1
        TERMINAL_HANDOFF_SHA=$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')
        TERMINAL_HANDOFF_BYTES=$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')
        valid_sha256 "$TERMINAL_HANDOFF_SHA" && valid_size "$TERMINAL_HANDOFF_BYTES" || return 1
        PENDING_SCHEMA=dcentos.s19k-stock-restart-pending/v4
        PENDING_LINES=49
        OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v8
        OWNER_LINES=15
        if [ "$SAFEOFF_SOURCE_MODE" = install-custody-safeoff ]; then
            PENDING_SCHEMA=dcentos.s19k-install-custody-stock-restart-pending/v1
        fi
    fi

    PENDING_TMP="$TRIAL_DIR/.runtime_active_stock_restart_pending.tmp.$$.${SELF_START}"
    [ ! -e "$PENDING_TMP" ] && [ ! -L "$PENDING_TMP" ] || return 1
    {
        printf 'schema=%s\n' "$PENDING_SCHEMA"
        printf 'phase=terminal-safeoff-stock-restart-pending\n'
        printf 'terminal=true\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'source_runtime_active_schema=dcentos.s19k-tmp-runtime/v5\n'
        printf 'source_runtime_active_path=%s\n' "$PRE_SAFEOFF_ACTIVE"
        printf 'source_runtime_active_sha256=%s\n' "$SOURCE_ACTIVE_SHA"
        printf 'source_runtime_active_bytes=%s\n' "$SOURCE_ACTIVE_BYTES"
        printf 'binary_sha256=%s\n' "$BIN_SHA"
        printf 'binary_bytes=%s\n' "$BIN_BYTES"
        printf 'config_sha256=%s\n' "$CFG_SHA"
        printf 'config_bytes=%s\n' "$CFG_BYTES"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'live_identity_model_sha256=%s\n' "$LIVE_IDENTITY_MODEL_SHA"
        printf 'live_identity_board_count=%s\n' "$BOARD_COUNT"
        printf 'live_identity_physical_addresses=%s\n' "$LIVE_IDENTITY_PHYSICAL_ADDRESSES"
        printf 'live_identity_board_names=%s\n' "$LIVE_IDENTITY_BOARD_NAMES"
        printf 'live_identity_eeprom=%s\n' "$LIVE_IDENTITY_EEPROM_SLOTS"
        printf 'safeoff_receipt_schema=%s\n' "$EXPECTED_SAFEOFF_SCHEMA"
        printf 'safeoff_receipt_path=%s\n' "$SAFEOFF_TERMINAL_RECEIPT"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
        printf 'safeoff_receipt_bytes=%s\n' "$SAFEOFF_BYTES"
        printf 'resets=%s\n' "$EXPECTED_SAFEOFF_RESETS"
        printf 'psu=437:1\n'
        printf 'gpio_raw=%s\n' "$EXPECTED_SAFEOFF_GPIO_RAW"
        printf 'dcentrald=absent\n'
        printf 'writer_wrapper_pid=%s\n' "$$"
        printf 'writer_wrapper_start=%s\n' "$SELF_START"
        printf 'wrapper_exit_required=true\n'
        printf 'stock_supervisor=absent\n'
        printf 'stock_bosminer=absent\n'
        printf 'watchdog_fd=absent\n'
        printf 'stock_init_path=/etc/init.d/S99bosminer\n'
        printf 'stock_init_sha256=%s\n' "$STOCK_INIT_EXPECTED_SHA"
        printf 'stock_init_bytes=%s\n' "$STOCK_INIT_EXPECTED_BYTES"
        printf 'persistent_mutation=false\n'
        printf 'next_authority=exact-stock-restart-helper-only\n'
        if [ "$PENDING_SCHEMA" = dcentos.s19k-stock-restart-pending/v4 ] \
            || [ "$PENDING_SCHEMA" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; then
            printf 'terminal_handoff_receipt_schema=%s\n' "$EXPECTED_TERMINAL_HANDOFF_SCHEMA"
            printf 'terminal_handoff_receipt_path=%s\n' "$TERMINAL_HANDOFF_RECEIPT"
            printf 'terminal_handoff_receipt_sha256=%s\n' "$TERMINAL_HANDOFF_SHA"
            printf 'terminal_handoff_receipt_bytes=%s\n' "$TERMINAL_HANDOFF_BYTES"
        fi
    } > "$PENDING_TMP"
    chmod 600 "$PENDING_TMP"
    [ "$(wc -l < "$PENDING_TMP" | tr -d ' \t\r\n')" -eq "$PENDING_LINES" ] || return 1
    mv -f "$PENDING_TMP" "$ACTIVE" || return 1
    PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    valid_sha256 "$PENDING_SHA" && valid_size "$PENDING_BYTES" || return 1

    OWNER_TMP="$TRIAL_DIR/.runtime_owner_stock_restart_pending.tmp.$$.${SELF_START}"
    [ ! -e "$OWNER_TMP" ] && [ ! -L "$OWNER_TMP" ] || return 1
    {
        printf 'schema=%s\n' "$OWNER_SCHEMA"
        printf 'owner_kind=stock-restart-pending\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'active_sha256=%s\n' "$PENDING_SHA"
        printf 'active_bytes=%s\n' "$PENDING_BYTES"
        printf 'source_runtime_active_sha256=%s\n' "$SOURCE_ACTIVE_SHA"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
        if [ "$PENDING_SCHEMA" = dcentos.s19k-stock-restart-pending/v4 ] \
            || [ "$PENDING_SCHEMA" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; then
            printf 'terminal_handoff_receipt_sha256=%s\n' "$TERMINAL_HANDOFF_SHA"
        fi
    } > "$OWNER_TMP"
    chmod 600 "$OWNER_TMP"
    mv -f "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" || return 1

    # Final fence after both atomic transitions. A crash or mismatch retains
    # the lock and all evidence; no generic restore may guess-repair it.
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq "$PENDING_LINES" ] \
        && [ "$(sha256sum "$ACTIVE" | awk '{print $1}')" = "$PENDING_SHA" ] \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" = "$SOURCE_ACTIVE_SHA" ] \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" = "$SAFEOFF_SHA" ] \
        && is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq "$OWNER_LINES" ] \
        && [ "$(runtime_lock_field schema)" = "$OWNER_SCHEMA" ] \
        && [ "$(runtime_lock_field owner_kind)" = stock-restart-pending ] \
        && [ "$(runtime_lock_field active_sha256)" = "$PENDING_SHA" ] \
        && [ "$(runtime_lock_field source_runtime_active_sha256)" = "$SOURCE_ACTIVE_SHA" ] \
        && [ "$(runtime_lock_field safeoff_receipt_sha256)" = "$SAFEOFF_SHA" ] \
        && pending_terminal_binding_is_exact \
        && verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live \
        && process_matches "$$" "$SELF_START" || {
            is_regular_nonsymlink "$ACTIVE" || echo "ERROR: pending final fence: ACTIVE type" >&2
            [ "$(wc -l < "$ACTIVE" 2>/dev/null | tr -d ' \t\r\n')" -eq "$PENDING_LINES" ] || echo "ERROR: pending final fence: ACTIVE field count" >&2
            is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" || echo "ERROR: pending final fence: OWNER type" >&2
            [ "$(wc -l < "$RUNTIME_LOCK_OWNER" 2>/dev/null | tr -d ' \t\r\n')" -eq "$OWNER_LINES" ] || echo "ERROR: pending final fence: OWNER field count" >&2
            pending_terminal_binding_is_exact || echo "ERROR: pending final fence: terminal binding" >&2
            verify_all_bound_files || echo "ERROR: pending final fence: artifact binding" >&2
            require_same_live_s19k_identity || echo "ERROR: pending final fence: live identity" >&2
            gpio_safeoff_is_exact || echo "ERROR: pending final fence: GPIO SafeOff" >&2
            no_stock_daemon_watchdog_or_competing_wrapper_is_live || echo "ERROR: pending final fence: custody process/watchdog state live or ambiguous" >&2
            process_matches "$$" "$SELF_START" || echo "ERROR: pending final fence: writer lifetime" >&2
            echo "ERROR: stock-restart-pending final fence failed; global custody lock retained" >&2
            return 1
        }
    echo "S19k checked SafeOff published; stock restart remains pending under global custody lock"
}

upgrade_interrupted_pending_owner_after_safeoff() {
    set_expected_safeoff_receipt || return 1
    PENDING_SCHEMA=$(active_field schema) || return 1
    case "$PENDING_SCHEMA" in
        dcentos.s19k-stock-restart-pending/v3)
            PENDING_LINES=45
            OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v7
            OWNER_LINES=14
            ;;
        dcentos.s19k-stock-restart-pending/v4)
            PENDING_LINES=49
            OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v8
            OWNER_LINES=15
            ;;
        dcentos.s19k-install-custody-stock-restart-pending/v1)
            PENDING_LINES=49
            OWNER_SCHEMA=dcentos.s19k-track1-runtime-lock/v8
            OWNER_LINES=15
            ;;
        *) return 1 ;;
    esac
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq "$PENDING_LINES" ] \
        && [ "$(active_field phase)" = terminal-safeoff-stock-restart-pending ] \
        && [ "$(active_field terminal)" = true ] \
        && [ "$(active_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(active_field source_runtime_active_schema)" = dcentos.s19k-tmp-runtime/v5 ] \
        && [ "$(active_field source_runtime_active_path)" = "$PRE_SAFEOFF_ACTIVE" ] \
        && is_regular_nonsymlink "$PRE_SAFEOFF_ACTIVE" \
        && [ "$(active_field source_runtime_active_sha256)" = "$(sha256sum "$PRE_SAFEOFF_ACTIVE" | awk '{print $1}')" ] \
        && [ "$(active_field source_runtime_active_bytes)" = "$(wc -c < "$PRE_SAFEOFF_ACTIVE" | tr -d ' \t\r\n')" ] \
        && [ "$(active_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(active_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(active_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(active_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(active_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(active_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(active_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(active_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(active_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(active_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(active_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(active_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(active_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(active_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(active_field live_identity_board_count)" = "$BOARD_COUNT" ] \
        && [ "$(active_field live_identity_physical_addresses)" = "$LIVE_IDENTITY_PHYSICAL_ADDRESSES" ] \
        && [ "$(active_field live_identity_board_names)" = "$LIVE_IDENTITY_BOARD_NAMES" ] \
        && [ "$(active_field live_identity_eeprom)" = "$LIVE_IDENTITY_EEPROM_SLOTS" ] \
        && [ "$(active_field safeoff_receipt_schema)" = "$EXPECTED_SAFEOFF_SCHEMA" ] \
        && [ "$(active_field safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(active_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ] \
        && [ "$(active_field safeoff_receipt_bytes)" = "$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')" ] \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && [ "$(active_field resets)" = "$EXPECTED_SAFEOFF_RESETS" ] \
        && [ "$(active_field psu)" = 437:1 ] \
        && [ "$(active_field gpio_raw)" = "$EXPECTED_SAFEOFF_GPIO_RAW" ] \
        && [ "$(active_field dcentrald)" = absent ] \
        && [ "$(active_field wrapper_exit_required)" = true ] \
        && [ "$(active_field stock_supervisor)" = absent ] \
        && [ "$(active_field stock_bosminer)" = absent ] \
        && [ "$(active_field watchdog_fd)" = absent ] \
        && [ "$(active_field stock_init_path)" = /etc/init.d/S99bosminer ] \
        && [ "$(active_field stock_init_sha256)" = 6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9 ] \
        && [ "$(active_field stock_init_bytes)" = 1330 ] \
        && [ "$(active_field persistent_mutation)" = false ] \
        && [ "$(active_field next_authority)" = exact-stock-restart-helper-only ] || return 1
    OLD_WRAPPER_PID=$(active_field writer_wrapper_pid)
    OLD_WRAPPER_START=$(active_field writer_wrapper_start)
    valid_pid_start "$OLD_WRAPPER_PID" "$OLD_WRAPPER_START" \
        && ! process_matches "$OLD_WRAPPER_PID" "$OLD_WRAPPER_START" || return 1
    BOUND_SUPERVISOR_PID=$(pre_active_field supervisor_pid)
    BOUND_SUPERVISOR_START=$(pre_active_field supervisor_start)
    BOUND_SUPERVISOR_PPID=$(pre_active_field supervisor_ppid)
    BOUND_SUPERVISOR_PGRP=$(pre_active_field supervisor_pgrp)
    BOUND_SUPERVISOR_SESSION=$(pre_active_field supervisor_session)
    BOUND_SUPERVISOR_EXE=$(pre_active_field supervisor_exe)
    BOUND_SUPERVISOR_CMDLINE_SHA=$(pre_active_field supervisor_cmdline_sha256)
    BOUND_SUPERVISOR_CMDLINE_BYTES=$(pre_active_field supervisor_cmdline_bytes)
    BOUND_BOSMINER_PID=$(pre_active_field bosminer_pid)
    BOUND_BOSMINER_START=$(pre_active_field bosminer_start)
    BOUND_BOSMINER_PPID=$(pre_active_field bosminer_ppid)
    BOUND_BOSMINER_PGRP=$(pre_active_field bosminer_pgrp)
    BOUND_BOSMINER_SESSION=$(pre_active_field bosminer_session)
    BOUND_BOSMINER_EXE=$(pre_active_field bosminer_exe)
    BOUND_BOSMINER_CMDLINE_SHA=$(pre_active_field bosminer_cmdline_sha256)
    BOUND_BOSMINER_CMDLINE_BYTES=$(pre_active_field bosminer_cmdline_bytes)
    valid_pid_start "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" \
        && valid_pid_start "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" \
        && [ "$BOUND_SUPERVISOR_PPID" = 1 ] \
        && [ "$BOUND_BOSMINER_PPID" = "$BOUND_SUPERVISOR_PID" ] \
        && [ "$BOUND_SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$BOUND_BOSMINER_EXE" = /usr/bin/bosminer ] || return 1
    if [ "$PENDING_SCHEMA" = dcentos.s19k-stock-restart-pending/v4 ] \
        || [ "$PENDING_SCHEMA" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; then
        TERMINAL_HANDOFF_SHA=$(active_field terminal_handoff_receipt_sha256)
        TERMINAL_HANDOFF_BYTES=$(active_field terminal_handoff_receipt_bytes)
        terminal_handoff_receipt_is_exact "$PRE_SAFEOFF_ACTIVE" \
            && [ "$(active_field terminal_handoff_receipt_schema)" = "$EXPECTED_TERMINAL_HANDOFF_SCHEMA" ] \
            && [ "$(active_field terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF_RECEIPT" ] \
            && is_regular_nonsymlink "$TERMINAL_HANDOFF_RECEIPT" \
            && [ "$(sha256sum "$TERMINAL_HANDOFF_RECEIPT" | awk '{print $1}')" = "$TERMINAL_HANDOFF_SHA" ] \
            && [ "$(wc -c < "$TERMINAL_HANDOFF_RECEIPT" | tr -d ' \t\r\n')" = "$TERMINAL_HANDOFF_BYTES" ] || return 1
    fi
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    SOURCE_ACTIVE_SHA=$(active_field source_runtime_active_sha256)
    SAFEOFF_SHA=$(active_field safeoff_receipt_sha256)
    OWNER_TMP="$TRIAL_DIR/.runtime_owner_stock_restart_pending_resume.tmp.$$.${SELF_START}"
    [ ! -e "$OWNER_TMP" ] && [ ! -L "$OWNER_TMP" ] || return 1
    {
        printf 'schema=%s\n' "$OWNER_SCHEMA"
        printf 'owner_kind=stock-restart-pending\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'active_sha256=%s\n' "$PENDING_SHA"
        printf 'active_bytes=%s\n' "$PENDING_BYTES"
        printf 'source_runtime_active_sha256=%s\n' "$SOURCE_ACTIVE_SHA"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
        if [ "$PENDING_SCHEMA" = dcentos.s19k-stock-restart-pending/v4 ] \
            || [ "$PENDING_SCHEMA" = dcentos.s19k-install-custody-stock-restart-pending/v1 ]; then
            printf 'terminal_handoff_receipt_sha256=%s\n' "$TERMINAL_HANDOFF_SHA"
        fi
    } > "$OWNER_TMP"
    chmod 600 "$OWNER_TMP"
    mv -f "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" || return 1
    is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq "$OWNER_LINES" ] \
        && [ "$(runtime_lock_field schema)" = "$OWNER_SCHEMA" ] \
        && [ "$(runtime_lock_field owner_kind)" = stock-restart-pending ] \
        && [ "$(runtime_lock_field active_sha256)" = "$PENDING_SHA" ] || return 1
    echo "S19k interrupted ACTIVE-first transition resumed to typed stock-restart-pending owner"
}

publish_receiptless_restart_pending_after_safeoff() {
    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || {
        echo "ERROR: receiptless pending publication found an unexpected ACTIVE" >&2
        return 1
    }
    admit_runtime_lock_owner || {
        echo "ERROR: receiptless pending publication lost the rebound global owner" >&2
        return 1
    }
    verify_all_bound_files || {
        echo "ERROR: receiptless pending publication lost an exact staged artifact" >&2
        return 1
    }
    require_same_live_s19k_identity || {
        echo "ERROR: receiptless pending publication lost the bound live identity" >&2
        return 1
    }
    gpio_safeoff_is_exact || {
        echo "ERROR: receiptless pending publication cannot reprove exact SafeOff GPIO" >&2
        return 1
    }
    no_stock_daemon_watchdog_or_competing_wrapper_is_live || {
        echo "ERROR: receiptless pending publication found a process/watchdog competitor" >&2
        return 1
    }
    process_matches "$$" "$SELF_START" || {
        echo "ERROR: receiptless pending publication lost the exact writer lifetime" >&2
        return 1
    }
    STOCK_INIT=/etc/init.d/S99bosminer
    STOCK_INIT_EXPECTED_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9
    STOCK_INIT_EXPECTED_BYTES=1330
    is_regular_nonsymlink "$STOCK_INIT" \
        && [ "$(sha256sum "$STOCK_INIT" | awk '{print $1}')" = "$STOCK_INIT_EXPECTED_SHA" ] \
        && [ "$(wc -c < "$STOCK_INIT" | tr -d ' \t\r\n')" = "$STOCK_INIT_EXPECTED_BYTES" ] || return 1
    if [ -e "$SAFEOFF_TERMINAL_RECEIPT" ] || [ -L "$SAFEOFF_TERMINAL_RECEIPT" ]; then
        is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
            && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] || return 1
    else
        SAFE_TMP="$TRIAL_DIR/.runtime_safeoff_terminal_receipt_receiptless.tmp.$$.${SELF_START}"
        [ ! -e "$SAFE_TMP" ] && [ ! -L "$SAFE_TMP" ] || return 1
        printf '%s\n' "$EXPECTED_SAFEOFF_RECEIPT" > "$SAFE_TMP"
        chmod 600 "$SAFE_TMP"
        ln "$SAFE_TMP" "$SAFEOFF_TERMINAL_RECEIPT" || {
            rm -f "$SAFE_TMP"
            return 1
        }
        rm -f "$SAFE_TMP"
    fi
    SAFEOFF_SHA=$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')
    SAFEOFF_BYTES=$(wc -c < "$SAFEOFF_TERMINAL_RECEIPT" | tr -d ' \t\r\n')
    PENDING_TMP="$TRIAL_DIR/.runtime_active_receiptless_stock_restart_pending.tmp.$$.${SELF_START}"
    [ ! -e "$PENDING_TMP" ] && [ ! -L "$PENDING_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-receiptless-stock-restart-pending/v2\n'
        printf 'phase=terminal-safeoff-stock-restart-pending\n'
        printf 'terminal=true\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'source=receiptless-recovery-no-v4-active\n'
        printf 'binary_sha256=%s\n' "$BIN_SHA"
        printf 'binary_bytes=%s\n' "$BIN_BYTES"
        printf 'config_sha256=%s\n' "$CFG_SHA"
        printf 'config_bytes=%s\n' "$CFG_BYTES"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
        printf 'live_identity_profile=%s\n' "$EXPECTED_LIVE_IDENTITY_PROFILE"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'live_identity_model_sha256=%s\n' "$LIVE_IDENTITY_MODEL_SHA"
        printf 'live_identity_board_count=%s\n' "$BOARD_COUNT"
        printf 'live_identity_physical_addresses=%s\n' "$LIVE_IDENTITY_PHYSICAL_ADDRESSES"
        printf 'live_identity_board_names=%s\n' "$LIVE_IDENTITY_BOARD_NAMES"
        printf 'live_identity_eeprom=%s\n' "$LIVE_IDENTITY_EEPROM_SLOTS"
        printf 'safeoff_receipt_schema=dcentos.s19k-track1-safeoff/v1\n'
        printf 'safeoff_receipt_path=%s\n' "$SAFEOFF_TERMINAL_RECEIPT"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
        printf 'safeoff_receipt_bytes=%s\n' "$SAFEOFF_BYTES"
        printf 'resets=454:0,455:0,456:0\n'
        printf 'psu=437:1\n'
        printf 'gpio_raw=437:1,454:0,455:0,456:0\n'
        printf 'dcentrald=absent\n'
        printf 'writer_wrapper_pid=%s\n' "$$"
        printf 'writer_wrapper_start=%s\n' "$SELF_START"
        printf 'wrapper_exit_required=true\n'
        printf 'stock_supervisor=absent\n'
        printf 'stock_bosminer=absent\n'
        printf 'watchdog_fd=absent\n'
        printf 'stock_init_path=/etc/init.d/S99bosminer\n'
        printf 'stock_init_sha256=%s\n' "$STOCK_INIT_EXPECTED_SHA"
        printf 'stock_init_bytes=%s\n' "$STOCK_INIT_EXPECTED_BYTES"
        printf 'persistent_mutation=false\n'
        printf 'next_authority=exact-stock-restart-helper-only\n'
    } > "$PENDING_TMP"
    chmod 600 "$PENDING_TMP"
    [ "$(wc -l < "$PENDING_TMP" | tr -d ' \t\r\n')" -eq 42 ] || return 1
    mv "$PENDING_TMP" "$ACTIVE" || return 1
    PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    OWNER_TMP="$TRIAL_DIR/.runtime_owner_receiptless_stock_restart_pending.tmp.$$.${SELF_START}"
    [ ! -e "$OWNER_TMP" ] && [ ! -L "$OWNER_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-track1-runtime-lock/v9\n'
        printf 'owner_kind=receiptless-stock-restart-pending\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'active_sha256=%s\n' "$PENDING_SHA"
        printf 'active_bytes=%s\n' "$PENDING_BYTES"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
    } > "$OWNER_TMP"
    chmod 600 "$OWNER_TMP"
    mv -f "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" || return 1
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(sha256sum "$ACTIVE" | awk '{print $1}')" = "$PENDING_SHA" ] \
        && is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq 13 ] \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v9 ] \
        && [ "$(runtime_lock_field active_sha256)" = "$PENDING_SHA" ] || {
            echo "ERROR: receiptless pending publication cannot re-admit final ACTIVE/OWNER" >&2
            return 1
        }
    gpio_safeoff_is_exact || {
        echo "ERROR: receiptless pending publication lost SafeOff after final owner commit" >&2
        return 1
    }
    no_stock_daemon_watchdog_or_competing_wrapper_is_live || {
        echo "ERROR: receiptless pending publication found a post-commit process/watchdog competitor" >&2
        return 1
    }
    echo "S19k receiptless checked SafeOff published as a distinct stock-restart-pending obligation"
}

upgrade_interrupted_receiptless_pending_owner_after_safeoff() {
    is_regular_nonsymlink "$ACTIVE" \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 42 ] \
        && [ "$(active_field schema)" = dcentos.s19k-receiptless-stock-restart-pending/v2 ] \
        && [ "$(active_field phase)" = terminal-safeoff-stock-restart-pending ] \
        && [ "$(active_field terminal)" = true ] \
        && [ "$(active_field trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(active_field source)" = receiptless-recovery-no-v4-active ] \
        && [ "$(active_field binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(active_field binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(active_field config_sha256)" = "$CFG_SHA" ] \
        && [ "$(active_field config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(active_field runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(active_field runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(active_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(active_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(active_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
        && [ "$(active_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
        && [ "$(active_field live_identity_profile)" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
        && [ "$(active_field live_identity_sha256)" = "$EXPECTED_LIVE_IDENTITY_SHA" ] \
        && [ "$(active_field live_identity_model_sha256)" = "$LIVE_IDENTITY_MODEL_SHA" ] \
        && [ "$(active_field safeoff_receipt_path)" = "$SAFEOFF_TERMINAL_RECEIPT" ] \
        && is_regular_nonsymlink "$SAFEOFF_TERMINAL_RECEIPT" \
        && [ "$(active_field safeoff_receipt_sha256)" = "$(sha256sum "$SAFEOFF_TERMINAL_RECEIPT" | awk '{print $1}')" ] \
        && [ "$(cat "$SAFEOFF_TERMINAL_RECEIPT")" = "$EXPECTED_SAFEOFF_RECEIPT" ] \
        && [ "$(active_field gpio_raw)" = 437:1,454:0,455:0,456:0 ] \
        && [ "$(active_field wrapper_exit_required)" = true ] \
        && [ "$(active_field persistent_mutation)" = false ] \
        && [ "$(active_field next_authority)" = exact-stock-restart-helper-only ] || return 1
    OLD_WRAPPER_PID=$(active_field writer_wrapper_pid)
    OLD_WRAPPER_START=$(active_field writer_wrapper_start)
    valid_pid_start "$OLD_WRAPPER_PID" "$OLD_WRAPPER_START" \
        && ! process_matches "$OLD_WRAPPER_PID" "$OLD_WRAPPER_START" || return 1
    verify_all_bound_files \
        && require_same_live_s19k_identity \
        && gpio_safeoff_is_exact \
        && no_stock_daemon_watchdog_or_competing_wrapper_is_live || return 1
    PENDING_SHA=$(sha256sum "$ACTIVE" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$ACTIVE" | tr -d ' \t\r\n')
    SAFEOFF_SHA=$(active_field safeoff_receipt_sha256)
    OWNER_TMP="$TRIAL_DIR/.runtime_owner_receiptless_stock_restart_pending_resume.tmp.$$.${SELF_START}"
    [ ! -e "$OWNER_TMP" ] && [ ! -L "$OWNER_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-track1-runtime-lock/v9\n'
        printf 'owner_kind=receiptless-stock-restart-pending\n'
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'runner_sha256=%s\n' "$RUNNER_SHA"
        printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
        printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
        printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
        printf 'stock_restart_helper_sha256=%s\n' "$STOCK_RESTART_HELPER_SHA"
        printf 'stock_restart_helper_bytes=%s\n' "$STOCK_RESTART_HELPER_BYTES"
        printf 'live_identity_sha256=%s\n' "$EXPECTED_LIVE_IDENTITY_SHA"
        printf 'active_sha256=%s\n' "$PENDING_SHA"
        printf 'active_bytes=%s\n' "$PENDING_BYTES"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFEOFF_SHA"
    } > "$OWNER_TMP"
    chmod 600 "$OWNER_TMP"
    mv -f "$OWNER_TMP" "$RUNTIME_LOCK_OWNER" || return 1
    [ "$(wc -l < "$RUNTIME_LOCK_OWNER" | tr -d ' \t\r\n')" -eq 13 ] \
        && [ "$(runtime_lock_field schema)" = dcentos.s19k-track1-runtime-lock/v9 ] \
        && [ "$(runtime_lock_field active_sha256)" = "$PENDING_SHA" ] || return 1
    echo "S19k interrupted receiptless ACTIVE-first transition resumed to typed pending owner"
}

retire_neutral_pre_j0_container_and_residue() {
    runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && no_published_runtime_or_startup_evidence_exists || return 1
    capture_exact_stock_tree || return 1
    bind_exact_stock_tree
    capture_exact_live_s19k_identity || return 1
    EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE
    EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA

    # First independent no-effect fence.  This is deliberately before residue
    # classification so an orphaned daemon or watchdog can never be explained
    # away by a plausible-looking scratch basename.
    verify_all_bound_files \
        && no_daemon_watchdog_or_competing_wrapper_is_live \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact || return 1
    classify_exact_pre_j0_residues || return 1
    FIRST_PRE_J0_RESIDUE_LIST=$PRE_J0_RESIDUE_LIST
    FIRST_PRE_J0_RESIDUE_COUNT=$PRE_J0_RESIDUE_COUNT

    # A second independently captured all-TID/process, identity, stock-tree,
    # and GPIO fence must see the same literal residue set.  Only then are the
    # already-classified direct children removed one by one.
    verify_all_bound_files \
        && no_daemon_watchdog_or_competing_wrapper_is_live \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && no_published_runtime_or_startup_evidence_exists || return 1
    classify_exact_pre_j0_residues || return 1
    [ "$PRE_J0_RESIDUE_COUNT" = "$FIRST_PRE_J0_RESIDUE_COUNT" ] \
        && [ "$PRE_J0_RESIDUE_LIST" = "$FIRST_PRE_J0_RESIDUE_LIST" ] || return 1
    remove_classified_pre_j0_residues || return 1

    # Final fence makes interruption idempotent: any crash before this point
    # leaves either the exact container or a strict suffix of the same residue
    # set for the next restore invocation.
    verify_all_bound_files \
        && no_daemon_watchdog_or_competing_wrapper_is_live \
        && require_same_live_s19k_identity \
        && require_same_exact_stock_tree \
        && gpio_stock_baseline_is_exact \
        && runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && no_published_runtime_or_startup_evidence_exists || return 1
    classify_exact_pre_j0_residues \
        && [ "$PRE_J0_RESIDUE_COUNT" -eq 0 ] || return 1
    rmdir "$RUNTIME_LOCK"
}

SELF_START=$(process_start "$$")
case "$SELF_START" in ''|*[!0-9]*) echo "ERROR: cannot bind wrapper identity" >&2; exit 1 ;; esac
STARTUP_FIFO="$TRIAL_DIR/.startup_fifo.$$.${SELF_START}"
STARTUP_DAEMON_TRANSCRIPT="$TRIAL_DIR/.startup_daemon_transcript.$$.${SELF_START}"
STARTUP_RETIRE_CLEANUP_SOURCE="$TRIAL_DIR/.runtime_startup_retire_cleanup_commit.source.$$.${SELF_START}"

if [ "$MODE" = endurance-read ]; then
    endurance_sequence_is_valid "$ENDURANCE_SEQUENCE" || {
        echo "ERROR: endurance-read requires one canonical segment sequence" >&2
        exit 2
    }
    endurance_collection_namespace_is_exact || {
        echo "ERROR: endurance collection namespace/runtime binding is inexact" >&2
        exit 1
    }
    ENDURANCE_SEGMENT=$(endurance_segment_path "$ENDURANCE_SEQUENCE") || exit 1
    if ! endurance_regular_evidence_is_exact "$ENDURANCE_SEGMENT" 65536; then
        [ ! -e "$ENDURANCE_SEGMENT" ] && [ ! -L "$ENDURANCE_SEGMENT" ] && exit 3
        echo "ERROR: endurance segment exists with an inexact type/owner/mode/size" >&2
        exit 1
    fi
    exec 7< "$ENDURANCE_SEGMENT"
    ENDURANCE_OBSERVED_SHA=$(sha256sum "/proc/$$/fd/7" | awk '{print $1}')
    ENDURANCE_OBSERVED_BYTES=$(wc -c < "/proc/$$/fd/7" | tr -d ' \t\r\n')
    valid_sha256 "$ENDURANCE_OBSERVED_SHA" && valid_size "$ENDURANCE_OBSERVED_BYTES" || exit 1
    cat <&7
    exit 0
fi

if [ "$MODE" = endurance-ack ]; then
    endurance_sequence_is_valid "$ENDURANCE_SEQUENCE" \
        && valid_sha256 "$ENDURANCE_SEGMENT_SHA" \
        && valid_size "$ENDURANCE_SEGMENT_BYTES" \
        && valid_sha256 "$ENDURANCE_PREDECESSOR_MANIFEST_SHA" \
        && valid_sha256 "$ENDURANCE_MANIFEST_SHA" \
        && valid_size "$ENDURANCE_MANIFEST_BYTES" \
        && valid_size "$ENDURANCE_COLLECTOR_WALL_MS" || {
            echo "ERROR: endurance-ack arguments are not canonical" >&2
            exit 2
        }
    endurance_collection_namespace_is_exact || {
        echo "ERROR: endurance collection namespace/runtime binding is inexact" >&2
        exit 1
    }
    ENDURANCE_SEGMENT=$(endurance_segment_path "$ENDURANCE_SEQUENCE") || exit 1
    endurance_regular_evidence_is_exact "$ENDURANCE_SEGMENT" 65536 \
        && [ "$(sha256sum "$ENDURANCE_SEGMENT" | awk '{print $1}')" = "$ENDURANCE_SEGMENT_SHA" ] \
        && [ "$(wc -c < "$ENDURANCE_SEGMENT" | tr -d ' \t\r\n')" = "$ENDURANCE_SEGMENT_BYTES" ] || {
            echo "ERROR: endurance-ack does not bind the exact sealed segment" >&2
            exit 1
        }
    ENDURANCE_EXPECTED_PREDECESSOR=$(endurance_previous_manifest_sha "$ENDURANCE_SEQUENCE") || {
        echo "ERROR: endurance-ack predecessor acknowledgement is missing or inexact" >&2
        exit 1
    }
    [ "$ENDURANCE_EXPECTED_PREDECESSOR" = "$ENDURANCE_PREDECESSOR_MANIFEST_SHA" ] || {
        echo "ERROR: endurance-ack manifest predecessor does not extend the acknowledged chain" >&2
        exit 1
    }
    ENDURANCE_ACK=$(endurance_ack_path "$ENDURANCE_SEQUENCE") || exit 1
    ENDURANCE_ACK_TMP="$ENDURANCE_ACK_DIR/.ack.$ENDURANCE_SEQUENCE.tmp.$$.${SELF_START}"
    [ ! -e "$ENDURANCE_ACK_TMP" ] && [ ! -L "$ENDURANCE_ACK_TMP" ] || exit 1
    {
        printf 'schema=dcentos.s19k-endurance-segment-ack/v1\n'
        printf 'sequence=%s\n' "$ENDURANCE_SEQUENCE"
        printf 'segment_sha256=%s\n' "$ENDURANCE_SEGMENT_SHA"
        printf 'segment_bytes=%s\n' "$ENDURANCE_SEGMENT_BYTES"
        printf 'predecessor_manifest_sha256=%s\n' "$ENDURANCE_PREDECESSOR_MANIFEST_SHA"
        printf 'off_target_manifest_sha256=%s\n' "$ENDURANCE_MANIFEST_SHA"
        printf 'off_target_manifest_bytes=%s\n' "$ENDURANCE_MANIFEST_BYTES"
        printf 'collector_wall_unix_ms=%s\n' "$ENDURANCE_COLLECTOR_WALL_MS"
        printf 'publication=no-clobber-hard-link-after-fsync\n'
    } > "$ENDURANCE_ACK_TMP"
    chmod 600 "$ENDURANCE_ACK_TMP"
    if [ -e "$ENDURANCE_ACK" ] || [ -L "$ENDURANCE_ACK" ]; then
        cmp -s "$ENDURANCE_ACK_TMP" "$ENDURANCE_ACK" \
            && endurance_regular_evidence_is_exact "$ENDURANCE_ACK" 4096 || {
                rm -f "$ENDURANCE_ACK_TMP"
                echo "ERROR: endurance acknowledgement already exists with different evidence" >&2
                exit 1
            }
        rm -f "$ENDURANCE_ACK_TMP"
    else
        publish_no_clobber_journal "$ENDURANCE_ACK_TMP" "$ENDURANCE_ACK" || {
            echo "ERROR: endurance acknowledgement publication failed" >&2
            exit 1
        }
    fi
    printf 'S19K_ENDURANCE_ACK_OK sequence=%s segment_sha256=%s manifest_sha256=%s\n' \
        "$ENDURANCE_SEQUENCE" "$ENDURANCE_SEGMENT_SHA" "$ENDURANCE_MANIFEST_SHA"
    exit 0
fi

if [ "$MODE" = endurance-final-read ]; then
    endurance_collection_namespace_is_exact || {
        echo "ERROR: endurance collection namespace/runtime binding is inexact" >&2
        exit 1
    }
    case "$ENDURANCE_SEQUENCE" in
        daemon_terminal) ENDURANCE_FINAL_FILE=$ENDURANCE_DAEMON_TERMINAL ;;
        daemon_failure) ENDURANCE_FINAL_FILE=$ENDURANCE_DAEMON_FAILURE ;;
        terminal_handoff) ENDURANCE_FINAL_FILE=$TERMINAL_HANDOFF_RECEIPT ;;
        safeoff) ENDURANCE_FINAL_FILE=$SAFEOFF_TERMINAL_RECEIPT ;;
        endurance_receipt) ENDURANCE_FINAL_FILE="$TRIAL_DIR/runtime_endurance_work_receipt" ;;
        endurance_failure_receipt) ENDURANCE_FINAL_FILE=$ENDURANCE_FAILURE_RECEIPT ;;
        runtime_active_pre_safeoff) ENDURANCE_FINAL_FILE=$PRE_SAFEOFF_ACTIVE ;;
        runtime_pending) ENDURANCE_FINAL_FILE=$ACTIVE ;;
        *) echo "ERROR: invalid endurance final receipt name" >&2; exit 2 ;;
    esac
    endurance_regular_evidence_is_exact "$ENDURANCE_FINAL_FILE" 65536 || {
        [ ! -e "$ENDURANCE_FINAL_FILE" ] && [ ! -L "$ENDURANCE_FINAL_FILE" ] && exit 3
        echo "ERROR: requested endurance final receipt is inexact" >&2
        exit 1
    }
    cat "$ENDURANCE_FINAL_FILE"
    exit 0
fi

if [ "$MODE" = identity ]; then
    case "$DEPLOY_MODE" in stage-only|mining-on-passthrough|install-custody-safeoff|handoff-no-work|bounded-work-proof|endurance-work-proof) ;; *) echo "ERROR: invalid identity probe mode" >&2; exit 2 ;; esac
    verify_all_bound_files
    capture_exact_live_s19k_identity
    printf 'DCENT_S19K_LIVE_IDENTITY schema=dcentos.s19k-braiins-live-identity/v2 profile=%s sha256=%s model_sha256=%s board_names=%s physical_addresses=%s eeprom=%s\n' \
        "$LIVE_IDENTITY_PROFILE" "$LIVE_IDENTITY_SHA" "$LIVE_IDENTITY_MODEL_SHA" \
        "$LIVE_IDENTITY_BOARD_NAMES" "$LIVE_IDENTITY_PHYSICAL_ADDRESSES" \
        "$LIVE_IDENTITY_EEPROM_SLOTS"
    exit 0
fi

if [ "$MODE" = restore ]; then
    [ "$DEPLOY_MODE" = recovery ] || { echo "ERROR: restore requires recovery mode token" >&2; exit 2; }
    verify_all_bound_files
    if [ -e "$STARTUP_PRESAFEOFF_SOURCE" ] || [ -L "$STARTUP_PRESAFEOFF_SOURCE" ]; then
        transition_startup_stock_loss_to_pending || {
            echo "ERROR: typed startup-prefix SafeOff transition could not resume; custody remains" >&2
            exit 1
        }
        echo "ERROR: startup-prefix stock restart is pending; use the exact stock-restart helper" >&2
        exit 1
    fi
    # A cleanup commit is a self-sufficient typed suffix.  Dispatch it before
    # the generic neutral-container classifier: after OWNER retirement but
    # before rmdir(2), the exact recoverable state is deliberately an empty
    # 0700 container plus this commit.
    if [ -e "$STARTUP_RETIRE_CLEANUP" ] || [ -L "$STARTUP_RETIRE_CLEANUP" ]; then
        if [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
            if ! finalize_startup_cleanup_commit; then
                transition_startup_stock_loss_to_pending || {
                    echo "ERROR: immutable startup cleanup suffix could neither finalize nor divert to typed SafeOff" >&2
                    exit 1
                }
                echo "ERROR: startup cleanup stock loss is SafeOff; exact stock-restart helper is required" >&2
                exit 1
            fi
            echo "S19k pre-J3 startup cleanup suffix completed; trial is reusable"
            exit 0
        fi
    fi
    # mkdir(2) only creates a neutral container; the complete immutable J0
    # hard-link is the custody acquisition.  A crash in that single pre-J0
    # window is retired without touching stock, GPIO, UART, or the watchdog,
    # but only after independently proving the exact empty/no-evidence state.
    if runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        retire_neutral_pre_j0_container_and_residue || {
            echo "ERROR: neutral pre-J0 container/residue failed exact double-fenced retirement" >&2
            exit 1
        }
        echo "S19k neutral pre-J0 lock container retired without SafeOff or stock signaling"
        exit 0
    fi
    STARTUP_OWNER_SCHEMA=$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" schema 2>/dev/null || true)
    if [ "$STARTUP_OWNER_SCHEMA" = dcentos.s19k-startup-j0-prefork/v1 ]; then
        if is_regular_nonsymlink "$STARTUP_C1"; then
            BLOCKED_DAEMON_PID=$(startup_field_at "$STARTUP_C1" child_pid)
            BLOCKED_DAEMON_START=$(startup_field_at "$STARTUP_C1" child_start)
            N=0
            while process_matches "$BLOCKED_DAEMON_PID" "$BLOCKED_DAEMON_START" && [ "$N" -lt 5 ]; do
                exact_dcentrald_child_matches "$BLOCKED_DAEMON_PID" "$BLOCKED_DAEMON_START" || {
                    echo "ERROR: startup-blocked daemon identity changed; refusing recovery" >&2
                    exit 1
                }
                sleep 1
                N=$((N + 1))
            done
            ! process_matches "$BLOCKED_DAEMON_PID" "$BLOCKED_DAEMON_START" || {
                echo "ERROR: startup-blocked daemon did not publish parent-lost and exit; custody remains" >&2
                exit 1
            }
        fi
        if [ -e "$STOCK_RETAINED_RECEIPT" ] || [ -L "$STOCK_RETAINED_RECEIPT" ]; then
            STARTUP_RETIRE_RESULT=0
            retire_released_startup_after_child_exit || STARTUP_RETIRE_RESULT=$?
        else
            STARTUP_RETIRE_RESULT=0
            retire_startup_no_effect_obligation || STARTUP_RETIRE_RESULT=$?
        fi
        if [ "$STARTUP_RETIRE_RESULT" -ne 0 ]; then
            transition_startup_stock_loss_to_pending || {
                echo "ERROR: explicit pre-J3 startup obligation could neither retire nor divert to typed SafeOff" >&2
                exit 1
            }
            echo "ERROR: startup stock loss is SafeOff; exact stock-restart helper is required" >&2
            exit 1
        fi
        exit 0
    fi
    if [ -e "$STARTUP_RETIRED_OWNER" ] || [ -L "$STARTUP_RETIRED_OWNER" ]; then
        if ! retire_startup_no_effect_obligation; then
            transition_startup_stock_loss_to_pending || exit 1
            echo "ERROR: startup retirement stock loss is SafeOff; exact stock-restart helper is required" >&2
            exit 1
        fi
        exit 0
    fi
    if [ -e "$RETIRED_ACTIVE" ] || [ -L "$RETIRED_ACTIVE" ] \
        || [ -e "$RETIRED_OWNER" ] || [ -L "$RETIRED_OWNER" ]; then
        retire_stock_owner_retained_obligation || {
            echo "ERROR: interrupted retained-stock retirement could not resume; custody remains" >&2
            exit 1
        }
        echo "S19k retained-stock retirement crash state completed without SafeOff or stock signaling"
        exit 0
    fi
    [ ! -L "$ACTIVE" ] || { echo "ERROR: runtime receipt is a symlink" >&2; exit 1; }
    if [ -e "$ACTIVE" ]; then
        is_regular_nonsymlink "$ACTIVE" || { echo "ERROR: runtime receipt is not regular" >&2; exit 1; }
        ACTIVE_SCHEMA=$(active_field schema)
        case "$ACTIVE_SCHEMA" in
            dcentos.s19k-startup-prefix-stock-restart-pending/v1)
                transition_startup_stock_loss_to_pending || {
                    echo "ERROR: startup-prefix pending ACTIVE/OWNER could not be re-admitted or completed" >&2
                    exit 1
                }
                echo "ERROR: startup-prefix stock restart is pending; use the exact stock-restart helper" >&2
                exit 1
                ;;
            dcentos.s19k-receiptless-stock-restart-pending/v2)
                [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 42 ] \
                    && [ "$(active_field phase)" = terminal-safeoff-stock-restart-pending ] \
                    && [ "$(active_field source)" = receiptless-recovery-no-v4-active ] \
                    && runtime_lock_container_is_exact \
                    && is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" || {
                        echo "ERROR: receiptless stock-restart-pending obligation is inexact; custody remains" >&2
                        exit 1
                    }
                EXPECTED_LIVE_IDENTITY_PROFILE=$(active_field live_identity_profile)
                EXPECTED_LIVE_IDENTITY_SHA=$(active_field live_identity_sha256)
                valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" || exit 1
                capture_exact_live_s19k_identity
                [ "$LIVE_IDENTITY_PROFILE" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
                    && [ "$LIVE_IDENTITY_SHA" = "$EXPECTED_LIVE_IDENTITY_SHA" ] || exit 1
                SELF_START=$(process_start "$$")
                valid_pid_start "$$" "$SELF_START" || exit 1
                CURRENT_OWNER_SCHEMA=$(runtime_lock_field schema)
                case "$CURRENT_OWNER_SCHEMA" in
                    dcentos.s19k-track1-runtime-lock/v9)
                        [ "$(runtime_lock_field owner_kind)" = receiptless-stock-restart-pending ] \
                            && [ "$(runtime_lock_field active_sha256)" = "$(sha256sum "$ACTIVE" | awk '{print $1}')" ] \
                            && gpio_safeoff_is_exact \
                            && ! bosminer_custody_owner_is_live \
                            && no_watchdog_fd_is_live || exit 1
                        ;;
                    dcentos.s19k-track1-runtime-lock/v6)
                        admit_runtime_lock_owner || exit 1
                        perform_checked_safeoff || exit 1
                        upgrade_interrupted_receiptless_pending_owner_after_safeoff || {
                            echo "ERROR: interrupted receiptless pending ACTIVE could not upgrade OWNER; custody remains" >&2
                            exit 1
                        }
                        ;;
                    *) echo "ERROR: receiptless pending ACTIVE has an unknown lock owner schema" >&2; exit 1 ;;
                esac
                echo "ERROR: receiptless stock restart is pending; use the exact stock-restart helper" >&2
                exit 1
                ;;
            dcentos.s19k-stock-restart-pending/v3|dcentos.s19k-stock-restart-pending/v4|dcentos.s19k-install-custody-stock-restart-pending/v1)
                EXPECTED_LIVE_IDENTITY_PROFILE=$(active_field live_identity_profile)
                EXPECTED_LIVE_IDENTITY_SHA=$(active_field live_identity_sha256)
                valid_sha256 "$EXPECTED_LIVE_IDENTITY_SHA" || exit 1
                capture_exact_live_s19k_identity
                [ "$LIVE_IDENTITY_PROFILE" = "$EXPECTED_LIVE_IDENTITY_PROFILE" ] \
                    && [ "$LIVE_IDENTITY_SHA" = "$EXPECTED_LIVE_IDENTITY_SHA" ] || {
                        echo "ERROR: pending stock-restart identity no longer matches this controller" >&2
                        exit 1
                    }
                SELF_START=$(process_start "$$")
                valid_pid_start "$$" "$SELF_START" || exit 1
                runtime_lock_container_is_exact \
                    && is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" || exit 1
                CURRENT_OWNER_SCHEMA=$(runtime_lock_field schema)
                case "$CURRENT_OWNER_SCHEMA" in
                    dcentos.s19k-track1-runtime-lock/v7|dcentos.s19k-track1-runtime-lock/v8)
                        echo "ERROR: stock restart is already pending under its final typed owner; use the exact stock-restart helper" >&2
                        exit 1
                        ;;
                    dcentos.s19k-track1-runtime-lock/v6) ;;
                    *) echo "ERROR: interrupted pending ACTIVE has an unknown lock owner schema" >&2; exit 1 ;;
                esac
                admit_runtime_lock_owner || exit 1
                perform_checked_safeoff || exit 1
                upgrade_interrupted_pending_owner_after_safeoff || {
                    echo "ERROR: interrupted pending ACTIVE could not upgrade OWNER; custody remains" >&2
                    exit 1
                }
                echo "ERROR: stock remains stopped after crash-resume; exact stock-restart helper is required" >&2
                exit 1
                ;;
        esac
        load_bound_runtime_active_from "$ACTIVE" || {
            echo "ERROR: runtime receipt failed exact v5 field/pidfile/artifact admission" >&2
            exit 1
        }
        [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 40 ] || {
            echo "ERROR: runtime receipt has an inexact field set" >&2
            exit 1
        }
        [ "$(active_field schema)" = dcentos.s19k-tmp-runtime/v5 ] || {
            echo "ERROR: unknown runtime receipt schema" >&2
            exit 1
        }
        RECEIPT_PHASE=$(active_field phase)
        case "$RECEIPT_PHASE" in
            launch-pending-or-recovery-required|child-live-or-recovery-required) ;;
            *) echo "ERROR: invalid runtime receipt phase" >&2; exit 1 ;;
        esac
        [ "$(active_field persistent_mutation)" = false ] || {
            echo "ERROR: runtime receipt claims persistent mutation; refusing guessed recovery" >&2
            exit 1
        }
        WRAPPER_PID=$(active_field wrapper_pid)
        WRAPPER_START=$(active_field wrapper_start)
        CHILD_PID=$(active_field child_pid)
        CHILD_START=$(active_field child_start)
        BOUND_SUPERVISOR_PID=$(active_field supervisor_pid)
        BOUND_SUPERVISOR_START=$(active_field supervisor_start)
        BOUND_SUPERVISOR_PPID=$(active_field supervisor_ppid)
        BOUND_SUPERVISOR_PGRP=$(active_field supervisor_pgrp)
        BOUND_SUPERVISOR_SESSION=$(active_field supervisor_session)
        BOUND_SUPERVISOR_EXE=$(active_field supervisor_exe)
        BOUND_SUPERVISOR_CMDLINE_SHA=$(active_field supervisor_cmdline_sha256)
        BOUND_SUPERVISOR_CMDLINE_BYTES=$(active_field supervisor_cmdline_bytes)
        BOUND_BOSMINER_PID=$(active_field bosminer_pid)
        BOUND_BOSMINER_START=$(active_field bosminer_start)
        BOUND_BOSMINER_PPID=$(active_field bosminer_ppid)
        BOUND_BOSMINER_PGRP=$(active_field bosminer_pgrp)
        BOUND_BOSMINER_SESSION=$(active_field bosminer_session)
        BOUND_BOSMINER_EXE=$(active_field bosminer_exe)
        BOUND_BOSMINER_CMDLINE_SHA=$(active_field bosminer_cmdline_sha256)
        BOUND_BOSMINER_CMDLINE_BYTES=$(active_field bosminer_cmdline_bytes)
        valid_pid_start "$WRAPPER_PID" "$WRAPPER_START" || {
            echo "ERROR: runtime receipt has an invalid wrapper lifetime" >&2
            exit 1
        }
        valid_pid_start "$BOUND_SUPERVISOR_PID" "$BOUND_SUPERVISOR_START" \
            && valid_pid_start "$BOUND_BOSMINER_PID" "$BOUND_BOSMINER_START" \
            && [ "$BOUND_SUPERVISOR_PPID" = 1 ] \
            && [ "$BOUND_BOSMINER_PPID" = "$BOUND_SUPERVISOR_PID" ] \
            && valid_uint "$BOUND_SUPERVISOR_PGRP" \
            && valid_uint "$BOUND_SUPERVISOR_SESSION" \
            && [ "$BOUND_SUPERVISOR_PGRP" = "$BOUND_BOSMINER_PGRP" ] \
            && [ "$BOUND_SUPERVISOR_SESSION" = "$BOUND_BOSMINER_SESSION" ] \
            && [ "$BOUND_SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
            && [ "$BOUND_BOSMINER_EXE" = /usr/bin/bosminer ] \
            && valid_sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA" \
            && valid_size "$BOUND_SUPERVISOR_CMDLINE_BYTES" \
            && valid_sha256 "$BOUND_BOSMINER_CMDLINE_SHA" \
            && valid_size "$BOUND_BOSMINER_CMDLINE_BYTES" || {
            echo "ERROR: runtime receipt has an invalid stock supervisor/child custody tree" >&2
            exit 1
        }
        case "$RECEIPT_PHASE" in
            launch-pending-or-recovery-required)
                [ "$CHILD_PID:$CHILD_START" = 0:0 ] || {
                    echo "ERROR: pending runtime receipt contains a child lifetime" >&2
                    exit 1
                }
                ;;
            child-live-or-recovery-required)
                valid_pid_start "$CHILD_PID" "$CHILD_START" || {
                    echo "ERROR: live runtime receipt has no valid child lifetime" >&2
                    exit 1
                }
                ;;
        esac
        [ "$(active_field live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] || {
            echo "ERROR: runtime receipt has unknown live-identity schema" >&2
            exit 1
        }
        EXPECTED_LIVE_IDENTITY_PROFILE=$(active_field live_identity_profile)
        EXPECTED_LIVE_IDENTITY_SHA=$(active_field live_identity_sha256)
        [ "$(active_field binary_sha256)" = "$BIN_SHA" ] \
            && [ "$(active_field binary_bytes)" = "$BIN_BYTES" ] \
            && [ "$(active_field config_sha256)" = "$CFG_SHA" ] \
            && [ "$(active_field config_bytes)" = "$CFG_BYTES" ] \
            && [ "$(active_field runner_sha256)" = "$RUNNER_SHA" ] \
            && [ "$(active_field runner_bytes)" = "$RUNNER_BYTES" ] \
            && [ "$(active_field custody_observer_sha256)" = "$CUSTODY_SHA" ] \
            && [ "$(active_field custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
            && [ "$(active_field stock_restart_helper_sha256)" = "$STOCK_RESTART_HELPER_SHA" ] \
            && [ "$(active_field stock_restart_helper_bytes)" = "$STOCK_RESTART_HELPER_BYTES" ] \
            && is_handoff_deploy_mode "$(active_field deploy_mode)" || {
                echo "ERROR: runtime receipt does not match the content-bound recovery command" >&2
                exit 1
            }
        require_same_live_s19k_identity
        if process_matches "$WRAPPER_PID" "$WRAPPER_START"; then
            echo "ERROR: trial wrapper pid $WRAPPER_PID is still live; signal the owner instead" >&2
            exit 1
        fi
        ensure_runtime_lock_for_recovery bound
        if process_matches "$CHILD_PID" "$CHILD_START"; then
            exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START" || {
                echo "ERROR: bound child lifetime no longer has the exact dcentrald comm/exe identity; refusing signal and retaining receipt" >&2
                exit 1
            }
            kill -TERM "$CHILD_PID" 2>/dev/null || {
                process_matches "$CHILD_PID" "$CHILD_START" && {
                    echo "ERROR: exact orphaned dcentrald could not be signaled; retaining receipt" >&2
                    exit 1
                }
            }
            wait_for_exact_child_exit || {
                echo "ERROR: orphaned dcentrald did not exit; leaving process and receipt intact" >&2
                exit 1
            }
        fi
        if ! no_dcentrald_thread_is_live; then
            echo "ERROR: dcentrald is live after exact child stop; refusing ambiguous recovery" >&2
            exit 1
        fi
        if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
            admit_terminal_handoff_obligation || exit 1
            if [ "$(terminal_handoff_field global_stock_absence)" != true ] \
                || bosminer_custody_owner_is_live; then
                echo "ERROR: terminal SafeOff is proven but a stock-process remnant is unresolved; only exact all-thread ptrace/pidfd recovery may continue" >&2
                exit 1
            fi
        fi
        if [ -e "$STOCK_RETAINED_RECEIPT" ] || [ -L "$STOCK_RETAINED_RECEIPT" ]; then
            retire_stock_owner_retained_obligation || {
                echo "ERROR: typed retained-stock obligation could not be retired; custody remains" >&2
                exit 1
            }
            echo "S19k temporary runtime refused before handoff; exact stock owner remains active"
            exit 0
        fi
        perform_checked_safeoff
    else
        # A missing tmpfs receipt is not proof that rails are safe.  It can
        # also mean the only recovery obligation was lost or removed after
        # both supervised processes died.  Refuse all live owners, establish
        # the exact board-scoped polarity tuple afresh, and require the same
        # checked reset+cut receipt as receipt-bound recovery.
        if bosminer_custody_owner_is_live; then
            echo "ERROR: a bosminer supervisor or child is live without a bound runtime receipt; refusing competing recovery" >&2
            exit 1
        fi
        if ! no_dcentrald_thread_is_live; then
            echo "ERROR: dcentrald is live without a bound runtime receipt; refusing ambiguous recovery" >&2
            exit 1
        fi
        if another_trial_wrapper_is_live; then
            echo "ERROR: another Track-1 wrapper is live without a bound runtime receipt; refusing ambiguous recovery" >&2
            exit 1
        fi
        capture_exact_live_s19k_identity
        EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE
        EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA
        SELF_START=$(process_start "$$")
        valid_pid_start "$$" "$SELF_START" || {
            echo "ERROR: cannot bind receiptless recovery wrapper lifetime" >&2
            exit 1
        }
        ensure_runtime_lock_for_recovery receiptless
        perform_checked_safeoff
        publish_receiptless_restart_pending_after_safeoff || {
            echo "ERROR: receiptless SafeOff completed but typed restart obligation publication failed; lock retained" >&2
            exit 1
        }
        echo "ERROR: stock remains stopped after receiptless recovery; exact stock-restart helper is required" >&2
        exit 1
    fi
    clear_runtime_obligation_after_safeoff || {
        echo "ERROR: checked SafeOff completed but the runtime obligation could not be cleared" >&2
        exit 1
    }
    echo "S19k temporary runtime is stopped; checked recovery receipt requirements are satisfied"
    exit 0
fi

[ "$MODE" = run ] || { echo "ERROR: mode must be run, identity, restore, endurance-read, endurance-ack, or endurance-final-read" >&2; exit 2; }
case "$DEPLOY_MODE" in
    stage-only|mining-on-passthrough|install-custody-safeoff|handoff-no-work|bounded-work-proof|endurance-work-proof) ;;
    *) echo "ERROR: invalid deploy mode" >&2; exit 2 ;;
esac
# Attempt-10 hard-ceiling backstop (2026-08-28 lifecycle audit): one-shot
# Track-1 trial modes get a host-side wall-clock ceiling so this wrapper can
# never block on a daemon that neither exits nor reaches a typed closeout
# (live attempt 9 parked 26+ minutes).  The default 900 s covers the 600 s
# bounded work deadline plus custody and closeout; the operator may raise it
# (endurance-work-proof runs MUST raise it above their 93600 s maximum) via
# S19K_TMP_TRIAL_CEILING_SECONDS.  Values below 120 s are refused, never
# clamped, so a typo cannot silently shorten a trial below its work
# authority; values above 2147483647 are likewise refused so the deadline
# arithmetic can never wrap into the past.  mining-on-passthrough sessions
# stay unbounded by design.
TRIAL_CEILING_SECONDS=
TRIAL_CEILING_DEADLINE=
case "$DEPLOY_MODE" in
    install-custody-safeoff|handoff-no-work|bounded-work-proof|endurance-work-proof)
        if [ -n "${S19K_TMP_TRIAL_CEILING_SECONDS:-}" ]; then
            case "$S19K_TMP_TRIAL_CEILING_SECONDS" in
                ''|*[!0-9]*|0|0[0-9]*)
                    echo "ERROR: S19K_TMP_TRIAL_CEILING_SECONDS must be a canonical decimal integer of at least 120" >&2
                    exit 2
                    ;;
            esac
            if [ "$S19K_TMP_TRIAL_CEILING_SECONDS" -lt 120 ]; then
                echo "ERROR: S19K_TMP_TRIAL_CEILING_SECONDS must be at least 120; refusing to shorten the one-shot trial hard ceiling" >&2
                exit 2
            fi
            if [ "$S19K_TMP_TRIAL_CEILING_SECONDS" -gt 2147483647 ]; then
                echo "ERROR: S19K_TMP_TRIAL_CEILING_SECONDS must be at most 2147483647; refusing values that would overflow the deadline arithmetic" >&2
                exit 2
            fi
            TRIAL_CEILING_SECONDS=$S19K_TMP_TRIAL_CEILING_SECONDS
        else
            TRIAL_CEILING_SECONDS=900
        fi
        ;;
esac
verify_all_bound_files
[ "$DEPLOY_MODE" != stage-only ] || {
    echo "S19k stage-only payload reverified; no persistent mutation or daemon launch performed"
    exit 0
}

if ! no_dcentrald_thread_is_live; then
    echo "ERROR: another dcentrald is already live; refusing Track-1 launch" >&2
    exit 1
fi
[ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || {
    echo "ERROR: stale temporary runtime receipt; use the content-bound restore command first" >&2
    exit 1
}
[ ! -e "$STOCK_RETAINED_RECEIPT" ] && [ ! -L "$STOCK_RETAINED_RECEIPT" ] || {
    echo "ERROR: retained-stock receipt path already exists; use its typed recovery path" >&2
    exit 1
}
[ ! -e "$TERMINAL_HANDOFF_RECEIPT" ] && [ ! -L "$TERMINAL_HANDOFF_RECEIPT" ] || {
    echo "ERROR: terminal partial-handoff receipt path already exists; use its typed recovery path" >&2
    exit 1
}
[ ! -e "$ENDURANCE_EVIDENCE_DIR" ] && [ ! -L "$ENDURANCE_EVIDENCE_DIR" ] || {
    echo "ERROR: stale endurance evidence namespace; use restore and a fresh trial directory" >&2
    exit 1
}
for STARTUP_RESIDUE in "$STARTUP_C1" "$STARTUP_J1" "$STARTUP_J2" "$STARTUP_RELEASE" \
    "$STARTUP_PARENT_LOST" "$STARTUP_RETIRE_TERMINAL" "$STARTUP_RETIRED_ACTIVE" \
    "$STARTUP_RETIRED_OWNER" "$STARTUP_RETIRE_CLEANUP" "$STARTUP_RETIRE_CLEANUP_SOURCE" \
    "$STARTUP_PRESAFEOFF_SOURCE" "$STARTUP_PRESAFEOFF_OWNER" "$STARTUP_PRESAFEOFF_ACTIVE"; do
    [ ! -e "$STARTUP_RESIDUE" ] && [ ! -L "$STARTUP_RESIDUE" ] || {
        echo "ERROR: prior startup transaction evidence remains; use restore or a fresh trial directory" >&2
        exit 1
    }
done
capture_exact_stock_tree
bind_exact_stock_tree
capture_exact_live_s19k_identity
EXPECTED_LIVE_IDENTITY_PROFILE=$LIVE_IDENTITY_PROFILE
EXPECTED_LIVE_IDENTITY_SHA=$LIVE_IDENTITY_SHA
gpio_stock_baseline_is_exact || {
    echo "ERROR: exact recovered-stock GPIO baseline is not present before J0 custody" >&2
    exit 1
}
no_watchdog_fd_is_live || {
    echo "ERROR: a watchdog descriptor is live before J0 custody" >&2
    exit 1
}
# A previous wrapper may have died before the atomic J0 owner link while the
# neutral container was itself absent.  Classify that exact lifetime-bound
# scratch universe before mkdir(2); if nonempty, create only a neutral 0700
# container, double-fence/retire the literal residues, then start acquisition
# from a residue-free namespace.
if [ ! -e "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ]; then
    classify_exact_pre_j0_residues || {
        echo "ERROR: pre-J0 residue namespace is ambiguous" >&2
        exit 1
    }
    if [ "$PRE_J0_RESIDUE_COUNT" -ne 0 ]; then
        mkdir "$RUNTIME_LOCK" && chmod 700 "$RUNTIME_LOCK" \
            && retire_neutral_pre_j0_container_and_residue || {
                echo "ERROR: lock-absent pre-J0 residue failed exact double-fenced retirement" >&2
                exit 1
            }
        [ ! -e "$RUNTIME_LOCK" ] && [ ! -L "$RUNTIME_LOCK" ] || exit 1
    fi
fi
# The root-owned lock directory is only a neutral container. The no-clobber
# hard-link of the complete immutable J0 record to LOCK/owner is the sole
# custody acquisition primitive; an empty exact container is safe to reuse.
if ! mkdir "$RUNTIME_LOCK" 2>/dev/null; then
    if runtime_lock_container_is_exact \
        && [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ] \
        && retire_neutral_pre_j0_container_and_residue \
        && mkdir "$RUNTIME_LOCK" 2>/dev/null \
        && chmod 700 "$RUNTIME_LOCK"; then
        echo "S19k neutral empty lock container from a pre-J0 crash was safely reacquired"
    else
        echo "ERROR: another version or interrupted Track-1 custody transaction holds the board-global runtime lock" >&2
        exit 1
    fi
fi
chmod 700 "$RUNTIME_LOCK" || exit 1
[ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || {
    echo "ERROR: runtime receipt appeared during custody acquisition" >&2
    exit 1
}
if another_trial_wrapper_is_live; then
    echo "ERROR: a competing Track-1 wrapper appeared during custody acquisition; retaining the runtime lock" >&2
    exit 1
fi
if ! no_dcentrald_thread_is_live; then
    echo "ERROR: a dcentrald owner appeared during custody acquisition; retaining the runtime lock" >&2
    exit 1
fi
require_same_exact_stock_tree || {
    echo "ERROR: stock supervisor/child tree changed during custody acquisition; retaining the runtime lock" >&2
    exit 1
}
gpio_stock_baseline_is_exact || {
    echo "ERROR: recovered-stock GPIO baseline changed during custody acquisition; retaining the neutral lock container" >&2
    exit 1
}

# Publish a self-sufficient immutable J0/global authority before fork. ACTIVE
# does not exist until the child has synchronously published C1 and J1 while
# holding the exact FIFO reader and permanent PDEATHSIG proof.
require_same_live_s19k_identity
if [ -e "$STARTUP_FIFO" ] || [ -L "$STARTUP_FIFO" ]; then
    echo "ERROR: startup FIFO path already exists; use recovery or a fresh trial directory" >&2
    exit 1
fi
mkfifo "$STARTUP_FIFO" || exit 1
chmod 600 "$STARTUP_FIFO"
exec 9<> "$STARTUP_FIFO"
FIFO_LS=$(ls -lni "$STARTUP_FIFO" 2>/dev/null || true)
set -- $FIFO_LS
FIFO_INODE=${1:-}
FIFO_MODE=${2:-}
FIFO_UID=${4:-}
FIFO_GID=${5:-}
FIFO_MNT_ID=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/9" 2>/dev/null)
exec 9>&-
valid_uint "$FIFO_INODE" && valid_uint "$FIFO_UID" && valid_uint "$FIFO_GID" \
    && valid_uint "$FIFO_MNT_ID" && [ "$FIFO_MODE" = prw------- ] || {
    rm -f "$STARTUP_FIFO"
    echo "ERROR: private startup FIFO identity/mode could not be proven" >&2
    exit 1
}

# Build the exact daemon argv once, bind its canonical NUL representation in
# J0, and execute this same positional vector after J0 commits. This prevents
# extra/missing authority flags from appearing between custody publication and
# exec. The environment is independently canonicalized in byte-sorted key
# order and the daemon admits that exact env-i set before C1.
set -- "$TRIAL_BIN" --config "$TRIAL_CFG" --serial-mining --allow-loud \
    --s19k-bos-tools-pid "$BOUND_SUPERVISOR_PID" \
    --s19k-bos-tools-start "$BOUND_SUPERVISOR_START" \
    --s19k-bos-tools-ppid "$BOUND_SUPERVISOR_PPID" \
    --s19k-bos-tools-pgrp "$BOUND_SUPERVISOR_PGRP" \
    --s19k-bos-tools-session "$BOUND_SUPERVISOR_SESSION" \
    --s19k-bos-tools-exe "$BOUND_SUPERVISOR_EXE" \
    --s19k-bos-tools-cmdline-sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA" \
    --s19k-bos-tools-cmdline-bytes "$BOUND_SUPERVISOR_CMDLINE_BYTES" \
    --s19k-bosminer-pid "$BOUND_BOSMINER_PID" \
    --s19k-bosminer-start "$BOUND_BOSMINER_START" \
    --s19k-bosminer-ppid "$BOUND_BOSMINER_PPID" \
    --s19k-bosminer-pgrp "$BOUND_BOSMINER_PGRP" \
    --s19k-bosminer-session "$BOUND_BOSMINER_SESSION" \
    --s19k-bosminer-exe "$BOUND_BOSMINER_EXE" \
    --s19k-bosminer-cmdline-sha256 "$BOUND_BOSMINER_CMDLINE_SHA" \
    --s19k-bosminer-cmdline-bytes "$BOUND_BOSMINER_CMDLINE_BYTES" \
    --s19k-track1-runtime-active "$ACTIVE" \
    --s19k-stock-owner-retained-receipt "$STOCK_RETAINED_RECEIPT"
if [ "$DEPLOY_MODE" = handoff-no-work ]; then
    # This exact flag is part of J0's canonical NUL argv digest. The daemon
    # independently requires it to agree with runtime_active.deploy_mode.
    set -- "$@" --s19k-track1-no-work
fi
if [ "$DEPLOY_MODE" = install-custody-safeoff ]; then
    # The exact flag is included in J0's canonical NUL argv and independently
    # matched against runtime_active.deploy_mode by the pre-runtime J3 lease.
    set -- "$@" --s19k-install-custody-safeoff
fi
if [ "$DEPLOY_MODE" = bounded-work-proof ]; then
    # This exact flag is part of J0's canonical NUL argv digest. The daemon
    # independently requires it to agree with runtime_active.deploy_mode.
    set -- "$@" --s19k-track1-bounded-work-proof
fi
if [ "$DEPLOY_MODE" = endurance-work-proof ]; then
    # The endurance authority is distinct from ordinary mining and the
    # Phase-3 bounded transcript. It is part of J0's canonical NUL argv.
    set -- "$@" --s19k-track1-endurance-work-proof
fi
DAEMON_ARGV_CANON="$TRIAL_DIR/.startup_daemon_argv.$$.${SELF_START}"
DAEMON_ENV_CANON="$TRIAL_DIR/.startup_daemon_env.$$.${SELF_START}"
[ ! -e "$DAEMON_ARGV_CANON" ] && [ ! -L "$DAEMON_ARGV_CANON" ] \
    && [ ! -e "$DAEMON_ENV_CANON" ] && [ ! -L "$DAEMON_ENV_CANON" ] || exit 1
umask 077
: > "$DAEMON_ARGV_CANON" || exit 1
for DAEMON_ARG in "$@"; do
    printf '%s\000' "$DAEMON_ARG" >> "$DAEMON_ARGV_CANON" || exit 1
done
{
    printf '%s\000' 'DCENTOS_EPHEMERAL_RUNTIME=1'
    printf '%s\000' 'DCENTOS_LOG_RING_DIR=/tmp/dcent/log'
    printf '%s\000' "DCENT_S19K_LIVE_IDENTITY_SHA256=$EXPECTED_LIVE_IDENTITY_SHA"
    printf '%s\000' 'DCENT_S19K_STARTUP_BOOTSTRAP=daemon-v1'
    printf '%s\000' "DCENT_S19K_STARTUP_FIFO=$STARTUP_FIFO"
    printf '%s\000' "DCENT_S19K_STARTUP_LOG=$STARTUP_DAEMON_TRANSCRIPT"
    printf '%s\000' "DCENT_S19K_STARTUP_WRAPPER_PID=$$"
    printf '%s\000' "DCENT_S19K_STARTUP_WRAPPER_START=$SELF_START"
    printf '%s\000' 'DCENT_S19K_TRACK1_STOP_SAFEOFF=1'
    printf '%s\000' 'PATH=/usr/bin:/bin:/usr/sbin:/sbin'
} > "$DAEMON_ENV_CANON" || exit 1
chmod 600 "$DAEMON_ARGV_CANON" "$DAEMON_ENV_CANON" || exit 1
DAEMON_CMDLINE_SHA=$(sha256sum "$DAEMON_ARGV_CANON" | awk '{print $1}')
DAEMON_CMDLINE_BYTES=$(wc -c < "$DAEMON_ARGV_CANON" | tr -d ' \t\r\n')
DAEMON_ENVIRONMENT_SHA=$(sha256sum "$DAEMON_ENV_CANON" | awk '{print $1}')
DAEMON_ENVIRONMENT_BYTES=$(wc -c < "$DAEMON_ENV_CANON" | tr -d ' \t\r\n')
DAEMON_ENVIRONMENT_COUNT=10
valid_sha256 "$DAEMON_CMDLINE_SHA" && valid_size "$DAEMON_CMDLINE_BYTES" \
    && valid_sha256 "$DAEMON_ENVIRONMENT_SHA" \
    && valid_size "$DAEMON_ENVIRONMENT_BYTES" || exit 1
rm -f "$DAEMON_ARGV_CANON" "$DAEMON_ENV_CANON" || exit 1
no_watchdog_fd_is_live || {
    echo "ERROR: a watchdog descriptor appeared immediately before J0; refusing custody" >&2
    exit 1
}
[ ! -e "$STARTUP_DAEMON_TRANSCRIPT" ] && [ ! -L "$STARTUP_DAEMON_TRANSCRIPT" ] || exit 1
set -C
: > "$STARTUP_DAEMON_TRANSCRIPT" || { set +C; exit 1; }
set +C
chmod 600 "$STARTUP_DAEMON_TRANSCRIPT" || exit 1
write_startup_j0_owner_prefork || {
    if is_regular_nonsymlink "$RUNTIME_LOCK_OWNER" \
        && admit_runtime_lock_owner_record \
        && runtime_lock_owner_matches_current; then
        echo "ERROR: J0 publication committed but final acknowledgement failed; retaining FIFO/J0 evidence" >&2
    elif [ ! -e "$RUNTIME_LOCK_OWNER" ] && [ ! -L "$RUNTIME_LOCK_OWNER" ]; then
        rm -f "$STARTUP_FIFO"
        rmdir "$RUNTIME_LOCK" 2>/dev/null || true
    else
        echo "ERROR: J0 publication outcome is ambiguous; retaining FIFO/J0 evidence" >&2
    fi
    echo "ERROR: could not atomically publish immutable J0/global custody authority; no child was forked" >&2
    exit 1
}

no_watchdog_fd_is_live || {
    echo "ERROR: a watchdog descriptor appeared after J0 and before fork; retiring no-effect custody" >&2
    retire_startup_no_effect_obligation || transition_startup_stock_loss_to_pending || true
    exit 1
}

# Keep one read-only descriptor to the original no-work/bounded transcript
# inode across the complete child lifetime. The child explicitly closes this
# wrapper descriptor; its own stdout/stderr binding remains the separately
# admitted C1 descriptor pair.
if [ "$DEPLOY_MODE" = install-custody-safeoff ] \
    || [ "$DEPLOY_MODE" = handoff-no-work ] \
    || [ "$DEPLOY_MODE" = bounded-work-proof ]; then
    exec 6< "$STARTUP_DAEMON_TRANSCRIPT" || {
        retire_startup_no_effect_obligation || transition_startup_stock_loss_to_pending || true
        echo "ERROR: no-work/work-proof wrapper could not retain the exact transcript inode" >&2
        exit 1
    }
fi

# The daemon completes C1/J1/J2/release, acquires the content-bound J3
# all-thread ptrace lease before Tokio, then freezes and terminates the exact
# stock tree only after watchdog/closeout authority is ready.
/usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    DCENTOS_EPHEMERAL_RUNTIME=1 \
    DCENTOS_LOG_RING_DIR=/tmp/dcent/log \
    DCENT_S19K_TRACK1_STOP_SAFEOFF=1 \
    DCENT_S19K_LIVE_IDENTITY_SHA256="$EXPECTED_LIVE_IDENTITY_SHA" \
    DCENT_S19K_STARTUP_BOOTSTRAP=daemon-v1 \
    DCENT_S19K_STARTUP_FIFO="$STARTUP_FIFO" \
    DCENT_S19K_STARTUP_LOG="$STARTUP_DAEMON_TRANSCRIPT" \
    DCENT_S19K_STARTUP_WRAPPER_PID="$$" \
    DCENT_S19K_STARTUP_WRAPPER_START="$SELF_START" \
    "$@" 6>&- 9>&- </dev/null >>"$STARTUP_DAEMON_TRANSCRIPT" 2>&1 &
CHILD_PID=$!
CHILD_START=$(process_start "$CHILD_PID")
case "$CHILD_START" in
    ''|*[!0-9]*)
        wait "$CHILD_PID" 2>/dev/null || true
        if ! bosminer_custody_owner_is_live; then
            transition_startup_stock_loss_to_pending || true
        fi
        echo "ERROR: launched dcentrald did not publish a stable process identity" >&2
        exit 1
        ;;
esac
# Arm the attempt-10 hard ceiling from the admitted daemon fork (the epoch
# that owns both the pre-J1 wait above and the final closeout wait below).
if [ -n "$TRIAL_CEILING_SECONDS" ]; then
    TRIAL_CEILING_DEADLINE=$(( $(date +%s) + TRIAL_CEILING_SECONDS ))
fi
while [ ! -e "$STARTUP_J1" ] && [ ! -L "$STARTUP_J1" ]; do
    if ! process_matches "$CHILD_PID" "$CHILD_START"; then
        wait "$CHILD_PID" 2>/dev/null || true
        echo "ERROR: dcentrald exited before publishing immutable J1; J0 custody remains" >&2
        exit 1
    fi
    # The attempt-10 hard ceiling also bounds the pre-J1 window: a daemon
    # that forks but never publishes J1 and never exits must not pin this
    # wrapper forever either.
    trial_ceiling_expired && enforce_trial_ceiling_exit
    sleep 1
done
require_startup_j1_for_child || {
    echo "ERROR: daemon J1 is not the exact blocked/no-WDT child phase; J0 custody remains" >&2
    exit 1
}
write_active child-live-or-recovery-required
write_startup_j2_and_release || {
    exec 9>&-
    echo "ERROR: parent could not publish exact J2/release; child remains blocked and J0 custody remains" >&2
    exit 1
}
J2_SHA=$(sha256sum "$STARTUP_J2" | awk '{print $1}')
RELEASE_SHA=$(sha256sum "$STARTUP_RELEASE" | awk '{print $1}')
RELEASE_TOKEN=$(printf '%s:%s:%s' "$STARTUP_TX_ID" "$J2_SHA" "$RELEASE_SHA" | sha256sum | awk '{print $1}')
valid_sha256 "$RELEASE_TOKEN" || exit 1
# Final parent edge: no external command runs with fd9 open, so no helper can
# inherit a hidden writer and defeat the child's bounded HUP/EOF proof.
exec 9<> "$STARTUP_FIFO" || exit 1
printf '%s' "$RELEASE_TOKEN" >&9 || {
    exec 9>&-
    exit 1
}
exec 9>&-

stop_child() {
    EXIT_CODE=$1
    trap - 1 2 15
    if process_matches "$CHILD_PID" "$CHILD_START"; then
        exact_dcentrald_child_matches "$CHILD_PID" "$CHILD_START" || {
            echo "ERROR: supervised child lifetime changed comm/exe identity; refusing signal and leaving runtime receipt intact" >&2
            exit "$EXIT_CODE"
        }
        kill -TERM "$CHILD_PID" 2>/dev/null || {
            process_matches "$CHILD_PID" "$CHILD_START" && {
                echo "ERROR: exact supervised dcentrald could not be signaled; leaving runtime receipt intact" >&2
                exit "$EXIT_CODE"
            }
        }
    fi
    wait_for_exact_child_exit || {
        echo "ERROR: dcentrald did not exit; leaving runtime receipt intact" >&2
        exit "$EXIT_CODE"
    }
    wait "$CHILD_PID" 2>/dev/null || true
    if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
        admit_terminal_handoff_obligation || exit 1
        if [ "$(terminal_handoff_field global_stock_absence)" != true ] \
            || bosminer_custody_owner_is_live; then
            echo "ERROR: terminal SafeOff is proven but a stock-process remnant is unresolved; custody retained for exact all-thread recovery" >&2
            exit 1
        fi
    fi
    if [ "$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" schema 2>/dev/null || true)" = dcentos.s19k-startup-j0-prefork/v1 ]; then
        # A published terminal-handoff receipt proves the J3 stock exit and
        # checked SafeOff: the live stock tree is gone by design, so the
        # live-tree retire is impossible and the typed stock-loss pending
        # transition is the only correct closeout.
        if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
            transition_startup_stock_loss_to_pending || exit 1
            publish_mode_specific_receipts_after_safeoff "$EXIT_CODE" || exit 1
        elif gpio_safeoff_is_exact && ! bosminer_custody_owner_is_live; then
            # Rails are physically checked-SafeOff and stock custody is
            # absent (a daemon-side terminal closeout, e.g. the
            # management-only park path, publishes no terminal-handoff
            # receipt). The live-tree retire is structurally impossible
            # here -- its pidfile fence must fail on the stale stock
            # pidfile -- so the typed stock-loss pending transition is the
            # only correct closeout.
            transition_startup_stock_loss_to_pending || exit 1
        elif ! retire_released_startup_after_child_exit; then
            transition_startup_stock_loss_to_pending || exit 1
        fi
        exit "$EXIT_CODE"
    fi
    if [ -e "$STOCK_RETAINED_RECEIPT" ] || [ -L "$STOCK_RETAINED_RECEIPT" ]; then
        retire_stock_owner_retained_obligation || exit 1
        exit "$EXIT_CODE"
    fi
    if perform_checked_safeoff; then
        clear_runtime_obligation_after_safeoff || exit 1
        publish_mode_specific_receipts_after_safeoff "$EXIT_CODE" || exit 1
    else
        exit 1
    fi
    exit "$EXIT_CODE"
}
trap 'stop_child 129' 1
trap 'stop_child 130' 2
trap 'stop_child 143' 15

# Attempt-10 hard-ceiling wait: for the one-shot trial modes the wrapper
# polls the exact child lifetime and enforces the wall ceiling instead of
# blocking in wait(2) without bound (attempt-9 deadlock class).  For every
# other deploy mode the original blocking wait is kept byte-for-byte.
if [ -n "$TRIAL_CEILING_DEADLINE" ]; then
    while process_matches "$CHILD_PID" "$CHILD_START"; do
        trial_ceiling_expired && enforce_trial_ceiling_exit
        sleep 1
    done
fi
if wait "$CHILD_PID"; then
    CHILD_STATUS=0
else
    CHILD_STATUS=$?
fi
if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
    admit_terminal_handoff_obligation || exit 1
    if [ "$(terminal_handoff_field global_stock_absence)" != true ] \
        || bosminer_custody_owner_is_live; then
        echo "ERROR: terminal SafeOff is proven but a stock-process remnant is unresolved; custody retained for exact all-thread recovery" >&2
        exit 1
    fi
fi
if [ "$(runtime_lock_field_at "$RUNTIME_LOCK_OWNER" schema 2>/dev/null || true)" = dcentos.s19k-startup-j0-prefork/v1 ]; then
    # Terminal handoff published: stock exited by design; the typed
    # stock-loss pending transition is the correct closeout.
    if [ -e "$TERMINAL_HANDOFF_RECEIPT" ] || [ -L "$TERMINAL_HANDOFF_RECEIPT" ]; then
        transition_startup_stock_loss_to_pending || exit 1
        publish_mode_specific_receipts_after_safeoff "$CHILD_STATUS" || exit 1
    elif gpio_safeoff_is_exact && ! bosminer_custody_owner_is_live; then
        # Rails are physically checked-SafeOff and stock custody is absent
        # (a daemon-side terminal closeout, e.g. the management-only park
        # path, publishes no terminal-handoff receipt). The live-tree
        # retire is structurally impossible here -- its pidfile fence must
        # fail on the stale stock pidfile -- so the typed stock-loss
        # pending transition is the only correct closeout.
        transition_startup_stock_loss_to_pending || exit 1
    elif ! retire_released_startup_after_child_exit; then
        transition_startup_stock_loss_to_pending || exit 1
    fi
    exit "$CHILD_STATUS"
fi
if [ -e "$STOCK_RETAINED_RECEIPT" ] || [ -L "$STOCK_RETAINED_RECEIPT" ]; then
    retire_stock_owner_retained_obligation || exit 1
    exit "$CHILD_STATUS"
fi
if perform_checked_safeoff; then
    clear_runtime_obligation_after_safeoff || exit 1
    publish_mode_specific_receipts_after_safeoff "$CHILD_STATUS" || exit 1
else
    exit 1
fi
exit "$CHILD_STATUS"
