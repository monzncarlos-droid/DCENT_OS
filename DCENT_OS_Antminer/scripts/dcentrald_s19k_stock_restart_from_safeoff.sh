#!/bin/sh
# Evidence-bound, one-shot Braiins stock restart after a terminal Track-1 SafeOff.
#
# This helper consumes only the helper-bound v3/v4, receiptless-v2, or
# startup-prefix-v1 pending contracts published by the content-bound Track-1 runner while its
# board-global custody lock remains held. It never signals a process, writes
# GPIO/NAND, or calls S99bosminer with
# stop/restart/reload. Once the durable claim says start-invocation-committed,
# every subsequent invocation is proof-only: stock start is never repeated.
# This is deliberately at-most-once, not exactly-once: a crash after durable
# intent but before exec is retained as an unresolved recovery obligation.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

MODE=${1:-}
TRIAL_DIR=${2:-}
EXPECTED_ACTIVE_SHA=${3:-}
EXPECTED_ACTIVE_BYTES=${4:-}
EXPECTED_HELPER_SHA=${5:-}
EXPECTED_HELPER_BYTES=${6:-}
EXECUTE=${7:-}

PREFIX=/tmp/dcentrald_bench_t1_
ACTIVE="$TRIAL_DIR/runtime_active"
PRE="$TRIAL_DIR/runtime_active_pre_safeoff"
SAFEOFF="$TRIAL_DIR/runtime_safeoff_terminal_receipt"
TERMINAL_HANDOFF="$TRIAL_DIR/runtime_terminal_safeoff"
STARTUP_SOURCE="$TRIAL_DIR/runtime_startup_prefix_pre_safeoff"
STARTUP_PRESERVED_OWNER="$TRIAL_DIR/runtime_startup_owner_pre_safeoff"
STARTUP_PRESERVED_ACTIVE="$TRIAL_DIR/runtime_startup_active_pre_safeoff"
STARTUP_C1="$TRIAL_DIR/runtime_startup_c1_child_identity"
STARTUP_J1="$TRIAL_DIR/runtime_startup_j1_daemon_blocked"
STARTUP_J2="$TRIAL_DIR/runtime_startup_j2_child_bound"
STARTUP_RELEASE="$TRIAL_DIR/runtime_startup_release"
STARTUP_PARENT_LOST="$TRIAL_DIR/runtime_startup_parent_lost"
STARTUP_RETIRE_TERMINAL="$TRIAL_DIR/runtime_startup_retired_terminal"
STARTUP_RETIRE_CLEANUP="$TRIAL_DIR/runtime_startup_retire_cleanup_commit"
STARTUP_RETIRED_OWNER="$TRIAL_DIR/runtime_lock_owner.retired.startup-no-effect"
STARTUP_RETIRED_ACTIVE="$TRIAL_DIR/runtime_active.retired.startup-no-effect"
CONSUMED="$TRIAL_DIR/runtime_stock_restart_pending.consumed"
TERMINAL="$TRIAL_DIR/runtime_stock_restart_complete"
UNRESOLVED="$TRIAL_DIR/runtime_stock_restart_unresolved"
UNRESOLVED_RETIRED="$TRIAL_DIR/runtime_stock_restart_unresolved.consumed"
STOCK_TREE_EVIDENCE="$TRIAL_DIR/runtime_stock_restart_stock_tree"
LOG_WINDOW_EVIDENCE="$TRIAL_DIR/runtime_stock_restart_log_window"
WATCHDOG_FD_EVIDENCE="$TRIAL_DIR/runtime_stock_restart_watchdog_fds"
LOCK=/tmp/dcent-s19k-track1-runtime-lock
OWNER="$LOCK/owner"
CLAIM_DIR="$LOCK/stock_restart_claim"
CLAIM="$CLAIM_DIR/owner"
INVOKE_LOCK=/tmp/dcent-s19k-stock-restart-helper-lock
INVOKE_OWNER="$INVOKE_LOCK/owner"
REQUIRE_NEUTRAL_MUTEX_MODE=true
BIN="$TRIAL_DIR/dcentrald"
CFG="$TRIAL_DIR/dcentrald_s19k.toml"
RUNNER="$TRIAL_DIR/run_trial"
CUSTODY="$TRIAL_DIR/supervisor_custody_observer"
HELPER="$TRIAL_DIR/stock_restart_helper"
PROC_ROOT=/proc
PIDFILE=/var/run/bosminer.pid
GPIO_ROOT=/sys/class/gpio
S99=/etc/init.d/S99bosminer
BOS_DEFAULTS=/lib/functions/bos-defaults.sh
STOCK_BOS_TOOLS=/usr/bin/bos-tools
STOCK_BOSMINER=/usr/bin/bosminer
LOG=/var/log/bosminer/bosminer.log
LOG_RESOLVED=/etc/log/bosminer/bosminer.log
LOG_MOUNT_ID=22
LOG_MOUNT_ROOT=/upper/etc
LOG_MOUNT_POINT=/etc
LOG_MOUNT_FS=ubifs
LOG_MOUNT_SOURCE=/dev/ubi0_0
WATCHDOG_NODE_ROOT=/dev
REQUIRE_EXACT_LOG_MOUNT=true
REQUIRE_EXACT_LOG_METADATA=true
REQUIRE_EXACT_STARTUP_OBJECT_METADATA=true
BUSYBOX=/bin/busybox
SHELL_INTERPRETER=/bin/sh
SHELL_INTERPRETER_LINK=busybox
START_STOP_DAEMON=/sbin/start-stop-daemon
START_STOP_DAEMON_LINK=../bin/busybox
BUSYBOX_LD_LINK=/lib/ld-linux-armhf.so.3
BUSYBOX_LD_TARGET=/lib/ld-2.19-2014.08-1-git.so
BUSYBOX_LIBM_LINK=/lib/libm.so.6
BUSYBOX_LIBM_TARGET=/lib/libm-2.19-2014.08-1-git.so
BUSYBOX_LIBC_LINK=/lib/libc.so.6
BUSYBOX_LIBC_TARGET=/lib/libc-2.19-2014.08-1-git.so
MAX_WAIT_SECONDS=300
STABILITY_WAIT_SECONDS=5
REQUIRE_EXACT_PIDFILE_METADATA=true

AUDITED_S99_SHA=6d9cce12caa49249396b48296101b0fbbcc6456cb3fa09bdbe2858bdcba948c9
AUDITED_S99_BYTES=1330
AUDITED_BOS_DEFAULTS_SHA=a5380fafcbd2cb4dc36c20b34353d40b97f5e2fcf3ed27f1741c55a2269ff85b
AUDITED_BOS_DEFAULTS_BYTES=434
AUDITED_STOCK_BOS_TOOLS_SHA=c597b12e1cd7ec614005b1007af0ce55058da888c9e83e5c11cf9fb5531bcad8
AUDITED_STOCK_BOS_TOOLS_BYTES=1061080
AUDITED_STOCK_BOSMINER_SHA=c5f9a28af02e7d6c318af955f746aaf43c6fa2502ecef09cd0ef209f394e4d22
AUDITED_STOCK_BOSMINER_BYTES=9113388
AUDITED_BUSYBOX_SHA=6f79b1c7794f14ed0334d88287eb85877aeed4f4a1a6c28f2b19c9d22bb7e98f
AUDITED_BUSYBOX_BYTES=384088
AUDITED_BUSYBOX_LD_SHA=b073c9de0008b6abc77a3860772f354252c346adc076ac15890425fc441dc0d5
AUDITED_BUSYBOX_LD_BYTES=123325
AUDITED_BUSYBOX_LIBM_SHA=4b135549c92b3e38e799313b6273582565477b238640581524c114d18d22550f
AUDITED_BUSYBOX_LIBM_BYTES=407060
AUDITED_BUSYBOX_LIBC_SHA=9e7cd88df51f7f236796e2d23bac2f57a767b89d0e7b11df79147d844e5afa6e
AUDITED_BUSYBOX_LIBC_BYTES=907032

case "$MODE:$EXECUTE" in
    start:START_STOCK_FROM_TERMINAL_SAFEOFF|prove:PROVE_STOCK_RESTART) ;;
    *)
        echo "ERROR: use start ... START_STOCK_FROM_TERMINAL_SAFEOFF or prove ... PROVE_STOCK_RESTART" >&2
        exit 2
        ;;
esac
case "$TRIAL_DIR" in "$PREFIX"*) ;; *) echo "ERROR: trial_dir outside Track-1 namespace" >&2; exit 2 ;; esac
SUFFIX=${TRIAL_DIR#"$PREFIX"}
case "$SUFFIX" in ''|*[!A-Za-z0-9._-]*|*/*) echo "ERROR: unsafe trial_dir" >&2; exit 2 ;; esac
[ "$TRIAL_DIR" = "$PREFIX$SUFFIX" ] && [ -d "$TRIAL_DIR" ] && [ ! -L "$TRIAL_DIR" ] || {
    echo "ERROR: trial_dir must be one exact non-symlink /tmp child" >&2
    exit 2
}
[ "$0" = "$HELPER" ] || {
    echo "ERROR: helper must be invoked through the exact staged trial path" >&2
    exit 2
}

regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
valid_sha() { [ "${#1}" -eq 64 ] && case "$1" in *[!0-9a-f]*) false ;; *) true ;; esac; }
valid_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
valid_positive() { valid_uint "$1" && [ "$1" -gt 0 ]; }
valid_bool() { case "$1" in true|false) return 0 ;; *) return 1 ;; esac; }
valid_stock_lease_kind() {
    case "$1" in pidfd|legacy_exact_identity_experimental) return 0 ;; *) return 1 ;; esac
}
field() {
    FIELD_FILE=$1 FIELD_KEY=$2
    [ "$(grep -c "^$FIELD_KEY=" "$FIELD_FILE" 2>/dev/null || true)" -eq 1 ] || return 1
    sed -n "s/^$FIELD_KEY=//p" "$FIELD_FILE"
}
require_ordered_keys() {
    ORDER_FILE=$1
    shift
    ORDER_LINE=1
    for ORDER_KEY in "$@"; do
        sed -n "${ORDER_LINE}p" "$ORDER_FILE" | grep -q "^${ORDER_KEY}=" || return 1
        ORDER_LINE=$((ORDER_LINE + 1))
    done
    [ "$(wc -l < "$ORDER_FILE" | tr -d ' \t\r\n')" -eq "$#" ]
}
verify_file() {
    VERIFY_PATH=$1 VERIFY_SHA=$2 VERIFY_BYTES=$3
    regular "$VERIFY_PATH" && valid_sha "$VERIFY_SHA" && valid_positive "$VERIFY_BYTES" || return 1
    [ "$(wc -c < "$VERIFY_PATH" | tr -d ' \t\r\n')" = "$VERIFY_BYTES" ] \
        && [ "$(sha256sum "$VERIFY_PATH" | awk '{print $1}')" = "$VERIFY_SHA" ]
}
launcher_runtime_is_exact() {
    verify_file "$BOS_DEFAULTS" "$AUDITED_BOS_DEFAULTS_SHA" "$AUDITED_BOS_DEFAULTS_BYTES" \
        && verify_file "$STOCK_BOS_TOOLS" "$AUDITED_STOCK_BOS_TOOLS_SHA" "$AUDITED_STOCK_BOS_TOOLS_BYTES" \
        && verify_file "$STOCK_BOSMINER" "$AUDITED_STOCK_BOSMINER_SHA" "$AUDITED_STOCK_BOSMINER_BYTES" \
        && verify_file "$BUSYBOX" "$AUDITED_BUSYBOX_SHA" "$AUDITED_BUSYBOX_BYTES" \
        && [ -L "$SHELL_INTERPRETER" ] \
        && [ "$(readlink "$SHELL_INTERPRETER" 2>/dev/null || true)" = "$SHELL_INTERPRETER_LINK" ] \
        && [ -L "$START_STOP_DAEMON" ] \
        && [ "$(readlink "$START_STOP_DAEMON" 2>/dev/null || true)" = "$START_STOP_DAEMON_LINK" ] \
        && [ -L "$BUSYBOX_LD_LINK" ] \
        && [ "$(readlink "$BUSYBOX_LD_LINK" 2>/dev/null || true)" = "${BUSYBOX_LD_TARGET##*/}" ] \
        && verify_file "$BUSYBOX_LD_TARGET" "$AUDITED_BUSYBOX_LD_SHA" "$AUDITED_BUSYBOX_LD_BYTES" \
        && [ -L "$BUSYBOX_LIBM_LINK" ] \
        && [ "$(readlink "$BUSYBOX_LIBM_LINK" 2>/dev/null || true)" = "${BUSYBOX_LIBM_TARGET##*/}" ] \
        && verify_file "$BUSYBOX_LIBM_TARGET" "$AUDITED_BUSYBOX_LIBM_SHA" "$AUDITED_BUSYBOX_LIBM_BYTES" \
        && [ -L "$BUSYBOX_LIBC_LINK" ] \
        && [ "$(readlink "$BUSYBOX_LIBC_LINK" 2>/dev/null || true)" = "${BUSYBOX_LIBC_TARGET##*/}" ] \
        && verify_file "$BUSYBOX_LIBC_TARGET" "$AUDITED_BUSYBOX_LIBC_SHA" "$AUDITED_BUSYBOX_LIBC_BYTES"
}
proc_state_start() {
    PROC_STAT=$(cat "$PROC_ROOT/$1/stat" 2>/dev/null || true)
    case "$PROC_STAT" in *') '*) ;; *) return 1 ;; esac
    # /proc/PID/stat comm may itself contain ") ".  Only the final delimiter
    # separates the parenthesized comm from state/start fields.
    PROC_REST=${PROC_STAT##*) }
    set -- $PROC_REST
    [ "$#" -ge 20 ] || return 1
    case "$1" in Z|X|x|'') return 1 ;; esac
    valid_positive "${20}" || return 1
    printf '%s:%s\n' "$1" "${20}"
}
process_matches() {
    PROCESS_OBS=$(proc_state_start "$1") || return 1
    [ "${PROCESS_OBS#*:}" = "$2" ]
}
live_process_matches_at() {
    LIVE_ROOT=$1 LIVE_PID=$2 LIVE_START=$3 LIVE_EXE=$4
    LIVE_STAT=$(cat "$LIVE_ROOT/$LIVE_PID/stat" 2>/dev/null || true)
    case "$LIVE_STAT" in *') '*) ;; *) return 1 ;; esac
    LIVE_REST=${LIVE_STAT##*) }
    set -- $LIVE_REST
    [ "$#" -ge 20 ] || return 1
    case "$1" in Z|X|x|'') return 1 ;; esac
    [ "${20}" = "$LIVE_START" ] \
        && [ "$(readlink "$LIVE_ROOT/$LIVE_PID/exe" 2>/dev/null)" = "$LIVE_EXE" ]
}

lifetime_is_gone_at() {
    LIFETIME_ROOT=$1 LIFETIME_PID=$2 LIFETIME_START=$3
    [ -d "$LIFETIME_ROOT/$LIFETIME_PID" ] || return 0
    LIFETIME_STAT=$(cat "$LIFETIME_ROOT/$LIFETIME_PID/stat" 2>/dev/null) || {
        [ ! -d "$LIFETIME_ROOT/$LIFETIME_PID" ] && return 0
        return 1
    }
    case "$LIFETIME_STAT" in *') '*) ;; *) return 1 ;; esac
    LIFETIME_REST=${LIFETIME_STAT##*) }
    set -- $LIFETIME_REST
    [ "$#" -ge 20 ] || return 1
    case "$1" in Z|X|x) return 0 ;; esac
    valid_positive "${20}" || return 1
    [ "${20}" != "$LIFETIME_START" ]
}

capture_single_dead_scratch() {
    SCRATCH_PREFIX=$1
    SCRATCH_PATH= SCRATCH_PID= SCRATCH_START= SCRATCH_SHA= SCRATCH_BYTES=
    for SCRATCH_CANDIDATE in "$SCRATCH_PREFIX"*; do
        [ -e "$SCRATCH_CANDIDATE" ] || [ -L "$SCRATCH_CANDIDATE" ] || continue
        [ -z "$SCRATCH_PATH" ] && regular "$SCRATCH_CANDIDATE" || return 1
        SCRATCH_SUFFIX=${SCRATCH_CANDIDATE#"$SCRATCH_PREFIX"}
        SCRATCH_PID=${SCRATCH_SUFFIX%%.*}
        SCRATCH_START=${SCRATCH_SUFFIX#*.}
        [ "$SCRATCH_CANDIDATE" = "$SCRATCH_PREFIX$SCRATCH_PID.$SCRATCH_START" ] \
            && [ "$SCRATCH_START" != "$SCRATCH_SUFFIX" ] \
            && valid_positive "$SCRATCH_PID" && valid_positive "$SCRATCH_START" \
            && lifetime_is_gone_at /proc "$SCRATCH_PID" "$SCRATCH_START" || return 1
        SCRATCH_SHA=$(sha256sum "$SCRATCH_CANDIDATE" | awk '{print $1}')
        SCRATCH_BYTES=$(wc -c < "$SCRATCH_CANDIDATE" | tr -d ' \t\r\n')
        valid_sha "$SCRATCH_SHA" && valid_uint "$SCRATCH_BYTES" || return 1
        SCRATCH_PATH=$SCRATCH_CANDIDATE
    done
}

captured_scratch_is_unchanged_and_dead() {
    [ -n "$SCRATCH_PATH" ] && regular "$SCRATCH_PATH" \
        && lifetime_is_gone_at /proc "$SCRATCH_PID" "$SCRATCH_START" \
        && [ "$(wc -c < "$SCRATCH_PATH" | tr -d ' \t\r\n')" = "$SCRATCH_BYTES" ] \
        && [ "$(sha256sum "$SCRATCH_PATH" | awk '{print $1}')" = "$SCRATCH_SHA" ]
}

same_regular_inode() {
    LEFT_PATH=$1 RIGHT_PATH=$2
    regular "$LEFT_PATH" && regular "$RIGHT_PATH" || return 1
    set -- $("$BUSYBOX" ls -liLnL "$LEFT_PATH" 2>/dev/null) || return 1
    LEFT_INODE=${1:-}
    set -- $("$BUSYBOX" ls -liLnL "$RIGHT_PATH" 2>/dev/null) || return 1
    [ -n "$LEFT_INODE" ] && [ "$LEFT_INODE" = "${1:-}" ]
}

transaction_scratches_absent() {
    for TRANSACTION_SCRATCH in \
        "$CLAIM_DIR"/.owner.* \
        "$CLAIM_DIR"/.stock_tree.* \
        "$CLAIM_DIR"/.watchdog_fds.* \
        "$CLAIM_DIR"/.log_window.* \
        "$TRIAL_DIR"/.runtime_stock_restart_unresolved.* \
        "$TRIAL_DIR"/.runtime_stock_restart_complete.*; do
        [ -e "$TRANSACTION_SCRATCH" ] || [ -L "$TRANSACTION_SCRATCH" ] || continue
        return 1
    done
}
cmdline_lines() { tr '\000' '\n' < "$1" 2>/dev/null || true; }

# Linux does not expose every non-leader TID through /proc/[0-9]*.  Every
# process/FD absence claim therefore comes from two byte-identical snapshots
# of /proc/TGID/task/TID.  Any extant unreadable or malformed task fails closed.
collect_all_task_effect_snapshot() {
    [ -d "$PROC_ROOT" ] && [ ! -L "$PROC_ROOT" ] || return 1
    for TG_DIR in "$PROC_ROOT"/[0-9]*; do
        [ -d "$TG_DIR" ] || continue
        if [ ! -d "$TG_DIR/task" ]; then
            [ ! -d "$TG_DIR" ] && continue
            return 1
        fi
        TGID=${TG_DIR#"$PROC_ROOT"/}
        valid_positive "$TGID" || return 1
        for TID_DIR in "$TG_DIR"/task/[0-9]*; do
            [ -d "$TID_DIR" ] || continue
            TID=${TID_DIR##*/}
            STAT_LINE=$(cat "$TID_DIR/stat" 2>/dev/null) || {
                [ ! -d "$TID_DIR" ] && continue
                return 1
            }
            case "$STAT_LINE" in *') '*) ;; *) return 1 ;; esac
            STAT_REST=${STAT_LINE##*) }
            set -- $STAT_REST
            [ "$#" -ge 20 ] || return 1
            STATE=$1
            shift 19
            TID_START=$1
            valid_positive "$TID" && valid_positive "$TID_START" || return 1
            EXE=$(readlink "$TID_DIR/exe" 2>/dev/null || true)
            ARGV0= BOSMINER_ARG=false PIDFILE_ARG=false SSD_START=false S99_START=false WRAPPER=false
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
                        CMDLINE=$(cmdline_lines "$TID_DIR/cmdline") || return 1
                        OLD_IFS=$IFS
                        IFS='
'
                        # Process argv is untrusted. Split with globbing disabled
                        # so wildcard bytes cannot enumerate the helper cwd.
                        set -f
                        FIRST_ARG=true
                        HAS_S=false
                        HAS_START=false
                        HAS_S99=false
                        HAS_BOS_TOOLS=false
                        for PROC_ARG in $CMDLINE; do
                            case "$PROC_ARG" in *'|'*|*'
') IFS=$OLD_IFS; return 1 ;; esac
                            if [ "$FIRST_ARG" = true ]; then ARGV0=$PROC_ARG; FIRST_ARG=false; fi
                            [ "$PROC_ARG" = /usr/bin/bosminer ] && BOSMINER_ARG=true
                            [ "$PROC_ARG" = /usr/bin/bos-tools ] && HAS_BOS_TOOLS=true
                            [ "$PROC_ARG" = "$PIDFILE" ] && PIDFILE_ARG=true
                            [ "$PROC_ARG" = -S ] && HAS_S=true
                            [ "$PROC_ARG" = start ] && HAS_START=true
                            [ "$PROC_ARG" = "$S99" ] && HAS_S99=true
                            case "$PROC_ARG" in "$PREFIX"*/run_trial) WRAPPER=true ;; esac
                        done
                        set +f
                        IFS=$OLD_IFS
                        [ "$FIRST_ARG" = false ] || return 1
                        [ "$HAS_S99:$HAS_START" = true:true ] && S99_START=true
                        [ "$HAS_S:$HAS_BOS_TOOLS:$BOSMINER_ARG:$PIDFILE_ARG" = true:true:true:true ] && SSD_START=true
                    fi
                    ;;
            esac
            printf 'T|%s|%s|%s|%s|exe=%s|argv0=%s|bosminer_arg=%s|ssd_start=%s|s99_start=%s|wrapper=%s\n' \
                "$TGID" "$TID" "$STATE" "$TID_START" "$EXE" "$ARGV0" "$BOSMINER_ARG" \
                "$SSD_START" "$S99_START" "$WRAPPER"
            for FD in "$TID_DIR"/fd/*; do
                # Do not dereference an fd target merely to establish that the
                # procfs descriptor link exists; the target filesystem may be
                # stalled while the procfs link and its text remain readable.
                [ -L "$FD" ] || [ -e "$FD" ] || continue
                FD_TARGET=$(readlink "$FD" 2>/dev/null) || {
                    [ ! -L "$FD" ] && [ ! -e "$FD" ] && continue
                    return 1
                }
                case "$FD_TARGET" in *'|'*) return 1 ;; esac
                # Dereferencing every process fd can block forever when an
                # unrelated open file lives on a stalled remote filesystem.
                # Production watchdog device nodes live in the already
                # validated WATCHDOG_NODE_ROOT namespace.  Use the procfs
                # link text as a non-dereferencing namespace gate, then use
                # rdev (not a basename) so alternate nodes inside /dev are
                # still detected.
                case "$FD_TARGET" in
                    "$WATCHDOG_NODE_ROOT"/*) ;;
                    *) continue ;;
                esac
                if fd_watchdog_rdev "$FD"; then
                    printf 'F|%s|%s|%s|rdev=%s|target=%s\n' \
                        "$TGID" "$TID" "${FD##*/}" "$FD_WATCHDOG_RDEV" "$FD_TARGET"
                else
                    FD_CLASS_RC=$?
                    if [ "$FD_CLASS_RC" -ne 1 ]; then
                        [ ! -L "$FD" ] && [ ! -e "$FD" ] && continue
                        return 1
                    fi
                fi
            done
        done
    done
}

filter_relevant_task_effects() (
    set -f
    OLD_IFS=$IFS
    IFS='
'
    for TASK_LINE in $1; do
        case "$TASK_LINE" in
            T\|*'|exe='*/dcentrald'|'*|T\|*'|argv0='*/dcentrald'|'*|\
            T\|*'|exe=/usr/bin/bosminer|'*|T\|*'|argv0=/usr/bin/bosminer|'*|\
            T\|*'|exe=/usr/bin/bos-tools|'*|T\|*'|argv0=/usr/bin/bos-tools|'*|\
            T\|*'|bosminer_arg=true|'*|T\|*'|ssd_start=true|'*|T\|*'|s99_start=true|'*|\
            T\|*'|wrapper=true'|F\|*) printf '%s\n' "$TASK_LINE" ;;
        esac
    done
    IFS=$OLD_IFS
)

stable_all_task_effect_snapshot() {
    SNAP_TRIES=0
    while [ "$SNAP_TRIES" -lt 3 ]; do
        COMPLETE_ONE=$(collect_all_task_effect_snapshot) || { SNAP_TRIES=$((SNAP_TRIES + 1)); continue; }
        SNAP_ONE=$(filter_relevant_task_effects "$COMPLETE_ONE") || return 1
        COMPLETE_TWO=$(collect_all_task_effect_snapshot) || { SNAP_TRIES=$((SNAP_TRIES + 1)); continue; }
        SNAP_TWO=$(filter_relevant_task_effects "$COMPLETE_TWO") || return 1
        if [ "$SNAP_ONE" = "$SNAP_TWO" ]; then
            ALL_TASK_EFFECT_SNAPSHOT=$SNAP_TWO
            return 0
        fi
        SNAP_TRIES=$((SNAP_TRIES + 1))
    done
    return 1
}

snapshot_has_pattern() { printf '%s\n' "$ALL_TASK_EFFECT_SNAPSHOT" | grep -Eq "$1"; }
any_track1_wrapper() { stable_all_task_effect_snapshot && snapshot_has_pattern '\|wrapper=true$'; }
any_dcentrald() { stable_all_task_effect_snapshot && snapshot_has_pattern '\|(exe|argv0)=[^|]*/dcentrald( \(deleted\))?\|'; }
stock_processes_absent() {
    stable_all_task_effect_snapshot || return 1
    ! snapshot_has_pattern '\|(exe|argv0)=/usr/bin/(bosminer|bos-tools)( \(deleted\))?\|' \
        && ! snapshot_has_pattern '\|bosminer_arg=true\|'
}
stock_start_launchers_absent() {
    stable_all_task_effect_snapshot || return 1
    ! snapshot_has_pattern '\|(ssd_start|s99_start)=true\|'
}
no_watchdog_fd() {
    watchdog_nodes_are_exact && stable_all_task_effect_snapshot \
        && ! snapshot_has_pattern '^F\|'
}
watchdog_fds_are_absent() {
    STOCK_SUPERVISOR_PID=$1 STOCK_CHILD_PID=$2
    valid_positive "$STOCK_SUPERVISOR_PID" && valid_positive "$STOCK_CHILD_PID" \
        && watchdog_nodes_are_exact && stable_all_task_effect_snapshot \
        && ! snapshot_has_pattern '^F\|' || return 1
    WATCHDOG_SNAPSHOT_SHA=$(printf '%s\n' "$ALL_TASK_EFFECT_SNAPSHOT" | sha256sum | awk '{print $1}')
    WATCHDOG_SNAPSHOT_BYTES=$(printf '%s\n' "$ALL_TASK_EFFECT_SNAPSHOT" | wc -c | tr -d ' \t\r\n')
    valid_sha "$WATCHDOG_SNAPSHOT_SHA" && valid_positive "$WATCHDOG_SNAPSHOT_BYTES"
}

# Stock `.88` did not own either hardware watchdog in ten read-only all-TID
# snapshots.  The verified /dev namespace is a safety gate against following
# unrelated descriptors on stalled filesystems, not the device authority:
# every held FD in that namespace is classified by character-device rdev, so
# alternate node names remain covered.  Inspection errors are a third state
# and fail closed rather than becoming absence.
fd_watchdog_rdev() {
    FD_CLASS_PATH=$1
    set -- $("$BUSYBOX" ls -liLnL "$FD_CLASS_PATH" 2>/dev/null) || return 2
    [ "$#" -ge 7 ] || return 2
    case "$2" in c*) ;; *) return 1 ;; esac
    FD_CLASS_MAJOR=${6%,}
    FD_CLASS_MINOR=$7
    valid_uint "$FD_CLASS_MAJOR" && valid_uint "$FD_CLASS_MINOR" || return 2
    FD_WATCHDOG_RDEV=$FD_CLASS_MAJOR:$FD_CLASS_MINOR
    case "$FD_WATCHDOG_RDEV" in 10:130|249:0) return 0 ;; *) return 1 ;; esac
}

watchdog_node_tuple() {
    WATCHDOG_NODE=$1
    [ -c "$WATCHDOG_NODE" ] && [ ! -L "$WATCHDOG_NODE" ] || return 1
    set -- $("$BUSYBOX" ls -liLnL "$WATCHDOG_NODE" 2>/dev/null) || return 1
    [ "$#" -ge 7 ] || return 1
    case "$2" in c*) ;; *) return 1 ;; esac
    WATCHDOG_MAJOR=${6%,}
    WATCHDOG_MINOR=$7
    valid_positive "$1" && valid_positive "$3" && valid_uint "$4" \
        && valid_uint "$5" && valid_uint "$WATCHDOG_MAJOR" \
        && valid_uint "$WATCHDOG_MINOR" || return 1
    printf '%s:%s:%s:%s:%s:%s\n' "$2" "$3" "$4" "$5" "$WATCHDOG_MAJOR" "$WATCHDOG_MINOR"
}

watchdog_nodes_are_exact() {
    WATCHDOG_NODE_TUPLE=$(watchdog_node_tuple "$WATCHDOG_NODE_ROOT/watchdog") || return 1
    WATCHDOG0_NODE_TUPLE=$(watchdog_node_tuple "$WATCHDOG_NODE_ROOT/watchdog0") || return 1
    [ "$WATCHDOG_NODE_TUPLE" = c---------:1:0:0:10:130 ] \
        && [ "$WATCHDOG0_NODE_TUPLE" = c---------:1:0:0:249:0 ]
}

build_watchdog_absence_evidence() {
    WATCHDOG_LOG_RECORD=${1:-}
    [ -n "$WATCHDOG_LOG_RECORD" ] || WATCHDOG_LOG_RECORD="$CLAIM_DIR/log_window"
    regular "$WATCHDOG_LOG_RECORD" || return 1
    watchdog_nodes_are_exact && [ -n "$WATCHDOG_SNAPSHOT_SHA" ] \
        && valid_sha "$WATCHDOG_SNAPSHOT_SHA" \
        && valid_positive "$WATCHDOG_SNAPSHOT_BYTES" || return 1
    WATCHDOG_TREE_SHA=$(printf '%s\n' "$STOCK_TREE" | sha256sum | awk '{print $1}')
    WATCHDOG_TREE_BYTES=$(printf '%s\n' "$STOCK_TREE" | wc -c | tr -d ' \t\r\n')
    WATCHDOG_LOG_SHA=$(sha256sum "$WATCHDOG_LOG_RECORD" | awk '{print $1}')
    WATCHDOG_LOG_BYTES=$(wc -c < "$WATCHDOG_LOG_RECORD" | tr -d ' \t\r\n')
    valid_sha "$WATCHDOG_TREE_SHA" && valid_positive "$WATCHDOG_TREE_BYTES" \
        && valid_sha "$WATCHDOG_LOG_SHA" && valid_positive "$WATCHDOG_LOG_BYTES" || return 1
    STOCK_WATCHDOG_EVIDENCE=$(printf '%s\n' \
        'schema=dcentos.s19k-stock-watchdog-absence/v1' \
        'authority=bounded-all-tid-hardware-watchdog-absence' \
        "node_watchdog=c---------:1:0:0:10:130" \
        "node_watchdog0=c---------:1:0:0:249:0" \
        'matching_watchdog_rdev_fd_count=0' \
        'matching_watchdog_rdev_fd_set_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
        'matching_watchdog_rdev_fd_set_bytes=0' \
        "all_tid_snapshot_sha256=$WATCHDOG_SNAPSHOT_SHA" \
        "all_tid_snapshot_bytes=$WATCHDOG_SNAPSHOT_BYTES" \
        "stock_supervisor=$STOCK_SUPERVISOR_PID:$(stock_tree_field supervisor_start)" \
        "stock_bosminer=$STOCK_CHILD_PID:$(stock_tree_field child_start)" \
        "stock_tree_sha256=$WATCHDOG_TREE_SHA" \
        "stock_tree_bytes=$WATCHDOG_TREE_BYTES" \
        "log_window_sha256=$WATCHDOG_LOG_SHA" \
        "log_window_bytes=$WATCHDOG_LOG_BYTES" \
        'internal_monitor_proof=chain2+chain3-temperature-watchdog-tasks+four-sensors+sane-temps' \
        'live_nonobservation_sha256=24676e15bb15f075345bd8f455a70a800c6c684db3d3fc7683cffc45193afa75' \
        'live_nonobservation_bytes=2889847') || return 1
    [ -n "$STOCK_WATCHDOG_EVIDENCE" ]
}
gpio_value() {
    GPIO_FILE="$GPIO_ROOT/gpio$1/value"
    regular "$GPIO_FILE" || return 1
    GPIO_VALUE=$(cat "$GPIO_FILE" 2>/dev/null || true)
    case "$GPIO_VALUE" in 0|1) printf '%s\n' "$GPIO_VALUE" ;; *) return 1 ;; esac
}
capture_gpio() {
    printf '437:%s,454:%s,455:%s,456:%s\n' \
        "$(gpio_value 437)" "$(gpio_value 454)" "$(gpio_value 455)" "$(gpio_value 456)"
}
capture_gpio437() {
    printf '437:%s\n' "$(gpio_value 437)"
}

admit_pending() {
    if regular "$ACTIVE" && [ ! -e "$CONSUMED" ] && [ ! -L "$CONSUMED" ]; then
        PENDING_RECORD=$ACTIVE
    elif regular "$CONSUMED" && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ]; then
        PENDING_RECORD=$CONSUMED
    else
        return 1
    fi
    PENDING_SCHEMA=$(field "$PENDING_RECORD" schema) || return 1
    case "$PENDING_SCHEMA" in
        dcentos.s19k-stock-restart-pending/v3)
            PENDING_VERSION=1
            ;;
        dcentos.s19k-stock-restart-pending/v4)
            PENDING_VERSION=2
            ;;
        dcentos.s19k-install-custody-stock-restart-pending/v1)
            PENDING_VERSION=install-custody
            ;;
        dcentos.s19k-receiptless-stock-restart-pending/v2)
            PENDING_VERSION=receiptless
            ;;
        dcentos.s19k-startup-prefix-stock-restart-pending/v1)
            PENDING_VERSION=startup-prefix
            ;;
        *) return 1 ;;
    esac
    if [ "$PENDING_VERSION" = startup-prefix ]; then
        require_ordered_keys "$PENDING_RECORD" schema phase terminal trial_dir transaction_id \
            highest_phase source_receipt_schema source_receipt_path source_receipt_sha256 \
            source_receipt_bytes binary_sha256 binary_bytes config_sha256 config_bytes \
            runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes \
            stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_schema \
            live_identity_profile live_identity_sha256 live_identity_model_sha256 \
            live_identity_board_count live_identity_physical_addresses live_identity_board_names \
            live_identity_eeprom safeoff_receipt_schema safeoff_receipt_path safeoff_receipt_sha256 \
            safeoff_receipt_bytes resets psu gpio_raw dcentrald writer_wrapper_pid \
            writer_wrapper_start wrapper_exit_required stock_supervisor stock_bosminer watchdog_fd \
            stock_init_path stock_init_sha256 stock_init_bytes persistent_mutation next_authority \
            || return 1
    elif [ "$PENDING_VERSION" = receiptless ]; then
        require_ordered_keys "$PENDING_RECORD" schema phase terminal trial_dir source binary_sha256 \
            binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 \
            custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes \
            live_identity_schema live_identity_profile live_identity_sha256 \
            live_identity_model_sha256 live_identity_board_count live_identity_physical_addresses \
            live_identity_board_names live_identity_eeprom safeoff_receipt_schema safeoff_receipt_path \
            safeoff_receipt_sha256 safeoff_receipt_bytes resets psu gpio_raw dcentrald \
            writer_wrapper_pid writer_wrapper_start wrapper_exit_required stock_supervisor \
            stock_bosminer watchdog_fd stock_init_path stock_init_sha256 stock_init_bytes \
            persistent_mutation next_authority || return 1
    else
        require_ordered_keys "$PENDING_RECORD" \
            schema phase terminal trial_dir source_runtime_active_schema source_runtime_active_path \
            source_runtime_active_sha256 source_runtime_active_bytes binary_sha256 binary_bytes \
            config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 \
            custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes \
            live_identity_schema live_identity_profile live_identity_sha256 \
            live_identity_model_sha256 live_identity_board_count live_identity_physical_addresses \
            live_identity_board_names live_identity_eeprom safeoff_receipt_schema safeoff_receipt_path \
            safeoff_receipt_sha256 safeoff_receipt_bytes resets psu gpio_raw dcentrald \
            writer_wrapper_pid writer_wrapper_start wrapper_exit_required stock_supervisor \
            stock_bosminer watchdog_fd stock_init_path stock_init_sha256 stock_init_bytes \
            persistent_mutation next_authority \
            $(case "$PENDING_VERSION" in 2|install-custody) printf '%s' 'terminal_handoff_receipt_schema terminal_handoff_receipt_path terminal_handoff_receipt_sha256 terminal_handoff_receipt_bytes' ;; esac) \
            || return 1
    fi
    [ "$(field "$PENDING_RECORD" phase)" = terminal-safeoff-stock-restart-pending ] \
        && [ "$(field "$PENDING_RECORD" terminal)" = true ] \
        && [ "$(field "$PENDING_RECORD" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$PENDING_RECORD" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(field "$PENDING_RECORD" safeoff_receipt_path)" = "$SAFEOFF" ] \
        && [ "$(field "$PENDING_RECORD" psu)" = 437:1 ] \
        && [ "$(field "$PENDING_RECORD" dcentrald)" = absent ] \
        && [ "$(field "$PENDING_RECORD" wrapper_exit_required)" = true ] \
        && [ "$(field "$PENDING_RECORD" stock_supervisor)" = absent ] \
        && [ "$(field "$PENDING_RECORD" stock_bosminer)" = absent ] \
        && [ "$(field "$PENDING_RECORD" watchdog_fd)" = absent ] \
        && [ "$(field "$PENDING_RECORD" stock_init_path)" = "$S99" ] \
        && [ "$(field "$PENDING_RECORD" stock_init_sha256)" = "$AUDITED_S99_SHA" ] \
        && [ "$(field "$PENDING_RECORD" stock_init_bytes)" = "$AUDITED_S99_BYTES" ] \
        && [ "$(field "$PENDING_RECORD" persistent_mutation)" = false ] \
        && [ "$(field "$PENDING_RECORD" next_authority)" = exact-stock-restart-helper-only ] || return 1
    if [ "$PENDING_VERSION" = install-custody ]; then
        [ "$(field "$PENDING_RECORD" safeoff_receipt_schema)" = dcentos.s19k-install-custody-safeoff/v1 ] \
            && [ "$(field "$PENDING_RECORD" resets)" = not-attempted ] \
            && [ "$(field "$PENDING_RECORD" gpio_raw)" = 437:1 ] || return 1
    else
        [ "$(field "$PENDING_RECORD" safeoff_receipt_schema)" = dcentos.s19k-track1-safeoff/v1 ] \
            && [ "$(field "$PENDING_RECORD" resets)" = 454:0,455:0,456:0 ] \
            && [ "$(field "$PENDING_RECORD" gpio_raw)" = 437:1,454:0,455:0,456:0 ] || return 1
    fi

    PENDING_SHA=$(sha256sum "$PENDING_RECORD" | awk '{print $1}')
    PENDING_BYTES=$(wc -c < "$PENDING_RECORD" | tr -d ' \t\r\n')
    valid_sha "$EXPECTED_ACTIVE_SHA" && valid_positive "$EXPECTED_ACTIVE_BYTES" \
        && [ "$PENDING_SHA:$PENDING_BYTES" = "$EXPECTED_ACTIVE_SHA:$EXPECTED_ACTIVE_BYTES" ] || return 1

    if [ "$PENDING_VERSION" = startup-prefix ]; then
        [ "$(field "$PENDING_RECORD" source_receipt_schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
            && [ "$(field "$PENDING_RECORD" source_receipt_path)" = "$STARTUP_SOURCE" ] || return 1
        SOURCE_SHA=$(field "$PENDING_RECORD" source_receipt_sha256)
        SOURCE_BYTES=$(field "$PENDING_RECORD" source_receipt_bytes)
        SOURCE_KIND=startup-prefix-safeoff-source-v1
        PRE_SHA=
        PRE_BYTES=
    elif [ "$PENDING_VERSION" = receiptless ]; then
        [ "$(field "$PENDING_RECORD" source)" = receiptless-recovery-no-v4-active ] \
            && [ ! -e "$PRE" ] && [ ! -L "$PRE" ] || return 1
        SOURCE_KIND=receiptless-recovery-no-v4-active
        SOURCE_SHA=absent
        SOURCE_BYTES=0
        PRE_SHA=
        PRE_BYTES=
    else
        [ "$(field "$PENDING_RECORD" source_runtime_active_schema)" = dcentos.s19k-tmp-runtime/v5 ] \
            && [ "$(field "$PENDING_RECORD" source_runtime_active_path)" = "$PRE" ] || return 1
        PRE_SHA=$(field "$PENDING_RECORD" source_runtime_active_sha256)
        PRE_BYTES=$(field "$PENDING_RECORD" source_runtime_active_bytes)
        SOURCE_KIND=runtime-active-v5
        SOURCE_SHA=$PRE_SHA
        SOURCE_BYTES=$PRE_BYTES
    fi
    SAFE_SHA=$(field "$PENDING_RECORD" safeoff_receipt_sha256)
    SAFE_BYTES=$(field "$PENDING_RECORD" safeoff_receipt_bytes)
    BIN_SHA=$(field "$PENDING_RECORD" binary_sha256); BIN_BYTES=$(field "$PENDING_RECORD" binary_bytes)
    CFG_SHA=$(field "$PENDING_RECORD" config_sha256); CFG_BYTES=$(field "$PENDING_RECORD" config_bytes)
    RUNNER_SHA=$(field "$PENDING_RECORD" runner_sha256); RUNNER_BYTES=$(field "$PENDING_RECORD" runner_bytes)
    CUSTODY_SHA=$(field "$PENDING_RECORD" custody_observer_sha256); CUSTODY_BYTES=$(field "$PENDING_RECORD" custody_observer_bytes)
    HELPER_SHA=$(field "$PENDING_RECORD" stock_restart_helper_sha256); HELPER_BYTES=$(field "$PENDING_RECORD" stock_restart_helper_bytes)
    IDENTITY_PROFILE=$(field "$PENDING_RECORD" live_identity_profile)
    IDENTITY_SHA=$(field "$PENDING_RECORD" live_identity_sha256)
    IDENTITY_MODEL_SHA=$(field "$PENDING_RECORD" live_identity_model_sha256)
    IDENTITY_BOARD_COUNT=$(field "$PENDING_RECORD" live_identity_board_count)
    IDENTITY_ADDRESSES=$(field "$PENDING_RECORD" live_identity_physical_addresses)
    IDENTITY_NAMES=$(field "$PENDING_RECORD" live_identity_board_names)
    IDENTITY_EEPROM=$(field "$PENDING_RECORD" live_identity_eeprom)
    WRITER_PID=$(field "$PENDING_RECORD" writer_wrapper_pid)
    WRITER_START=$(field "$PENDING_RECORD" writer_wrapper_start)
    [ "$PENDING_VERSION" = receiptless ] || [ "$PENDING_VERSION" = startup-prefix ] \
        || { valid_sha "$PRE_SHA" && valid_positive "$PRE_BYTES"; } || return 1
    valid_sha "$SAFE_SHA" && valid_positive "$SAFE_BYTES" \
        && valid_sha "$IDENTITY_SHA" && valid_sha "$IDENTITY_MODEL_SHA" \
        && valid_positive "$WRITER_PID" && valid_positive "$WRITER_START" || return 1
    case "$IDENTITY_PROFILE:$IDENTITY_BOARD_COUNT:$IDENTITY_ADDRESSES:$IDENTITY_NAMES:$IDENTITY_EEPROM" in
        live88_two_bhb56903_slots_2_3:2:2,3:BHB56903,BHB56903:0x50=absent,0x51=05:11,0x52=05:11) ;;
        *) return 1 ;;
    esac
    verify_file "$SAFEOFF" "$SAFE_SHA" "$SAFE_BYTES" \
        && verify_file "$BIN" "$BIN_SHA" "$BIN_BYTES" \
        && verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" \
        && verify_file "$RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" \
        && verify_file "$CUSTODY" "$CUSTODY_SHA" "$CUSTODY_BYTES" \
        && verify_file "$HELPER" "$HELPER_SHA" "$HELPER_BYTES" \
        && [ "$HELPER_SHA:$HELPER_BYTES" = "$EXPECTED_HELPER_SHA:$EXPECTED_HELPER_BYTES" ] || return 1

    if [ "$PENDING_VERSION" = startup-prefix ]; then
        admit_startup_source || return 1
    elif [ "$PENDING_VERSION" != receiptless ]; then
        verify_file "$PRE" "$PRE_SHA" "$PRE_BYTES" \
            && admit_runtime_active_v5_at "$PRE" || return 1
    fi

    if [ "$PENDING_VERSION" = install-custody ]; then
        EXPECTED_SAFEOFF="DCENT_S19K_INSTALL_CUSTODY_SAFEOFF_RECEIPT schema=dcentos.s19k-install-custody-safeoff/v1 live_identity_sha256=$IDENTITY_SHA live_identity_profile=$IDENTITY_PROFILE live_identity_model_sha256=$IDENTITY_MODEL_SHA live_identity_board_count=$IDENTITY_BOARD_COUNT live_identity_physical_addresses=$IDENTITY_ADDRESSES live_identity_board_names=$IDENTITY_NAMES live_identity_eeprom=$IDENTITY_EEPROM resets=not-attempted psu=437:1"
    else
        EXPECTED_SAFEOFF="DCENT_S19K_TRACK1_SAFEOFF_RECEIPT schema=dcentos.s19k-track1-safeoff/v1 live_identity_sha256=$IDENTITY_SHA live_identity_profile=$IDENTITY_PROFILE live_identity_model_sha256=$IDENTITY_MODEL_SHA live_identity_board_count=$IDENTITY_BOARD_COUNT live_identity_physical_addresses=$IDENTITY_ADDRESSES live_identity_board_names=$IDENTITY_NAMES live_identity_eeprom=$IDENTITY_EEPROM resets=454:0,455:0,456:0 psu=437:1"
    fi
    [ "$(wc -l < "$SAFEOFF" | tr -d ' \t\r\n')" -eq 1 ] \
        && [ "$(cat "$SAFEOFF")" = "$EXPECTED_SAFEOFF" ] || return 1
    if [ "$PENDING_VERSION" = 2 ] || [ "$PENDING_VERSION" = install-custody ]; then
        TERMINAL_HANDOFF_SHA=$(field "$PENDING_RECORD" terminal_handoff_receipt_sha256)
        TERMINAL_HANDOFF_BYTES=$(field "$PENDING_RECORD" terminal_handoff_receipt_bytes)
        EXPECTED_TERMINAL_SCHEMA=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1
        [ "$PENDING_VERSION" != install-custody ] \
            || EXPECTED_TERMINAL_SCHEMA=dcentos.s19k-install-custody-terminal-safeoff/v1
        [ "$(field "$PENDING_RECORD" terminal_handoff_receipt_schema)" = "$EXPECTED_TERMINAL_SCHEMA" ] \
            && [ "$(field "$PENDING_RECORD" terminal_handoff_receipt_path)" = "$TERMINAL_HANDOFF" ] \
            && verify_file "$TERMINAL_HANDOFF" "$TERMINAL_HANDOFF_SHA" "$TERMINAL_HANDOFF_BYTES" \
            && admit_terminal_handoff || return 1
    else
        TERMINAL_HANDOFF_SHA=
        TERMINAL_HANDOFF_BYTES=
        [ ! -e "$TERMINAL_HANDOFF" ] && [ ! -L "$TERMINAL_HANDOFF" ] || return 1
    fi
}

startup_pair() { printf '%s:%s\n' "$(field "$1" "${2}_sha256")" "$(field "$1" "${2}_bytes")"; }

startup_stock_tuple_is_sane_at() {
    STOCK_RECORD=$1
    STOCK_SUP_PID=$(field "$STOCK_RECORD" supervisor_pid) || return 1
    STOCK_SUP_START=$(field "$STOCK_RECORD" supervisor_start) || return 1
    STOCK_CHILD_PID=$(field "$STOCK_RECORD" bosminer_pid) || return 1
    STOCK_CHILD_START=$(field "$STOCK_RECORD" bosminer_start) || return 1
    valid_positive "$STOCK_SUP_PID" && valid_positive "$STOCK_SUP_START" \
        && valid_positive "$STOCK_CHILD_PID" && valid_positive "$STOCK_CHILD_START" \
        && [ "$(field "$STOCK_RECORD" supervisor_ppid)" = 1 ] \
        && valid_positive "$(field "$STOCK_RECORD" supervisor_pgrp)" \
        && [ "$(field "$STOCK_RECORD" supervisor_session)" = "$(field "$STOCK_RECORD" supervisor_pgrp)" ] \
        && [ "$(field "$STOCK_RECORD" supervisor_exe)" = /usr/bin/bos-tools ] \
        && valid_sha "$(field "$STOCK_RECORD" supervisor_cmdline_sha256)" \
        && valid_positive "$(field "$STOCK_RECORD" supervisor_cmdline_bytes)" \
        && [ "$(field "$STOCK_RECORD" bosminer_ppid)" = "$STOCK_SUP_PID" ] \
        && [ "$(field "$STOCK_RECORD" bosminer_pgrp):$(field "$STOCK_RECORD" bosminer_session)" = "$(field "$STOCK_RECORD" supervisor_pgrp):$(field "$STOCK_RECORD" supervisor_session)" ] \
        && [ "$(field "$STOCK_RECORD" bosminer_exe)" = /usr/bin/bosminer ] \
        && valid_sha "$(field "$STOCK_RECORD" bosminer_cmdline_sha256)" \
        && valid_positive "$(field "$STOCK_RECORD" bosminer_cmdline_bytes)" \
        && [ "$(field "$STOCK_RECORD" stock_pidfile_path)" = /var/run/bosminer.pid ] || return 1
    STOCK_PIDFILE_EXPECTED_SHA=$(printf '%s\n' "$STOCK_SUP_PID" | sha256sum | awk '{print $1}')
    STOCK_PIDFILE_EXPECTED_BYTES=$(printf '%s\n' "$STOCK_SUP_PID" | wc -c | tr -d ' \t\r\n')
    [ "$(field "$STOCK_RECORD" stock_pidfile_sha256):$(field "$STOCK_RECORD" stock_pidfile_bytes)" = "$STOCK_PIDFILE_EXPECTED_SHA:$STOCK_PIDFILE_EXPECTED_BYTES" ]
}

startup_stock_tuple_equals() {
    STOCK_LEFT=$1 STOCK_RIGHT=$2
    for STOCK_KEY in supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session \
        supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start \
        bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 \
        bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes; do
        [ "$(field "$STOCK_LEFT" "$STOCK_KEY")" = "$(field "$STOCK_RIGHT" "$STOCK_KEY")" ] || return 1
    done
}

admit_runtime_active_v5_at() {
    RUNTIME_RECORD=$1
    regular "$RUNTIME_RECORD" \
        && require_ordered_keys "$RUNTIME_RECORD" schema phase wrapper_pid wrapper_start child_pid \
            child_start supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp \
            supervisor_session supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes \
            bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe \
            bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 \
            stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 \
            runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
            stock_restart_helper_bytes live_identity_schema live_identity_profile live_identity_sha256 \
            deploy_mode persistent_mutation \
        && [ "$(field "$RUNTIME_RECORD" schema)" = dcentos.s19k-tmp-runtime/v5 ] || return 1
    RUNTIME_PHASE=$(field "$RUNTIME_RECORD" phase) || return 1
    case "$RUNTIME_PHASE" in
        launch-pending-or-recovery-required)
            [ "$(field "$RUNTIME_RECORD" child_pid):$(field "$RUNTIME_RECORD" child_start)" = 0:0 ]
            ;;
        child-live-or-recovery-required)
            valid_positive "$(field "$RUNTIME_RECORD" child_pid)" \
                && valid_positive "$(field "$RUNTIME_RECORD" child_start)"
            ;;
        *) return 1 ;;
    esac || return 1
    valid_positive "$(field "$RUNTIME_RECORD" wrapper_pid)" \
        && valid_positive "$(field "$RUNTIME_RECORD" wrapper_start)" \
        && [ "$(field "$RUNTIME_RECORD" wrapper_pid):$(field "$RUNTIME_RECORD" wrapper_start)" = "$WRITER_PID:$WRITER_START" ] \
        && startup_stock_tuple_is_sane_at "$RUNTIME_RECORD" \
        && [ "$(field "$RUNTIME_RECORD" binary_sha256):$(field "$RUNTIME_RECORD" binary_bytes)" = "$BIN_SHA:$BIN_BYTES" ] \
        && [ "$(field "$RUNTIME_RECORD" config_sha256):$(field "$RUNTIME_RECORD" config_bytes)" = "$CFG_SHA:$CFG_BYTES" ] \
        && [ "$(field "$RUNTIME_RECORD" runner_sha256):$(field "$RUNTIME_RECORD" runner_bytes)" = "$RUNNER_SHA:$RUNNER_BYTES" ] \
        && [ "$(field "$RUNTIME_RECORD" custody_observer_sha256):$(field "$RUNTIME_RECORD" custody_observer_bytes)" = "$CUSTODY_SHA:$CUSTODY_BYTES" ] \
        && [ "$(field "$RUNTIME_RECORD" stock_restart_helper_sha256):$(field "$RUNTIME_RECORD" stock_restart_helper_bytes)" = "$HELPER_SHA:$HELPER_BYTES" ] \
        && [ "$(field "$RUNTIME_RECORD" live_identity_schema):$(field "$RUNTIME_RECORD" live_identity_profile):$(field "$RUNTIME_RECORD" live_identity_sha256)" = "dcentos.s19k-braiins-live-identity/v2:$IDENTITY_PROFILE:$IDENTITY_SHA" ] \
        && [ "$(field "$RUNTIME_RECORD" persistent_mutation)" = false ] || return 1
    RUNTIME_DEPLOY_MODE=$(field "$RUNTIME_RECORD" deploy_mode) || return 1
    case "$RUNTIME_DEPLOY_MODE" in
        mining-on-passthrough|install-custody-safeoff|handoff-no-work|bounded-work-proof|endurance-work-proof) ;;
        *) return 1 ;;
    esac
}

admit_startup_preserved() {
    PRESERVED_PREFIX=$1 PRESERVED_PATH_EXPECTED=$2
    PRESERVED_PRESENT=$(field "$STARTUP_SOURCE" "${PRESERVED_PREFIX}_present") || return 1
    PRESERVED_PATH=$(field "$STARTUP_SOURCE" "${PRESERVED_PREFIX}_path") || return 1
    PRESERVED_SHA=$(field "$STARTUP_SOURCE" "${PRESERVED_PREFIX}_sha256") || return 1
    PRESERVED_BYTES=$(field "$STARTUP_SOURCE" "${PRESERVED_PREFIX}_bytes") || return 1
    [ "$PRESERVED_PATH" = "$PRESERVED_PATH_EXPECTED" ] || return 1
    case "$PRESERVED_PRESENT:$PRESERVED_SHA:$PRESERVED_BYTES" in
        true:none:0) return 1 ;;
        true:*:*) verify_file "$PRESERVED_PATH" "$PRESERVED_SHA" "$PRESERVED_BYTES" ;;
        false:none:0) [ ! -e "$PRESERVED_PATH" ] && [ ! -L "$PRESERVED_PATH" ] ;;
        *) return 1 ;;
    esac
}

admit_startup_j0() {
    verify_file "$STARTUP_PRESERVED_OWNER" \
            "$(field "$STARTUP_SOURCE" preserved_owner_sha256)" "$(field "$STARTUP_SOURCE" preserved_owner_bytes)" \
        && require_ordered_keys "$STARTUP_PRESERVED_OWNER" schema transaction_id ordinal \
            predecessor_schema predecessor_sha256 predecessor_bytes trial_dir runtime_active_path \
            runtime_active_sha256 runtime_active_bytes runtime_active_phase runtime_owner_path \
            runtime_owner_binding fifo_path fifo_mnt_id fifo_inode fifo_mode fifo_uid fifo_gid \
            writer_role writer_pid writer_start writer_ppid daemon_pid daemon_start wrapper_pid \
            wrapper_start wrapper_ppid wrapper_comm wrapper_exe wrapper_cmdline_sha256 \
            wrapper_cmdline_bytes expected_daemon_cmdline_sha256 expected_daemon_cmdline_bytes \
            daemon_environment_sha256 daemon_environment_bytes daemon_environment_count supervisor_pid \
            supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe \
            supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid \
            bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes \
            stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes \
            config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 \
            custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes \
            live_identity_schema live_identity_profile live_identity_sha256 gpio_raw \
            watchdog_start_intent watchdog_armed signal_attempted inherited_rails route_or_uart_opened \
            hardware_opened parent_release persistent_mutation publication \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" schema)" = dcentos.s19k-startup-j0-prefork/v1 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" transaction_id)" = "$(field "$STARTUP_SOURCE" transaction_id)" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" ordinal)" = 0 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" predecessor_schema):$(field "$STARTUP_PRESERVED_OWNER" predecessor_sha256):$(field "$STARTUP_PRESERVED_OWNER" predecessor_bytes)" = none:none:0 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" runtime_active_path):$(field "$STARTUP_PRESERVED_OWNER" runtime_active_sha256):$(field "$STARTUP_PRESERVED_OWNER" runtime_active_bytes):$(field "$STARTUP_PRESERVED_OWNER" runtime_active_phase)" = not-published:none:0:not-published ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" runtime_owner_path):$(field "$STARTUP_PRESERVED_OWNER" runtime_owner_binding)" = "$OWNER:self-hardlink" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" writer_role)" = wrapper ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" writer_pid):$(field "$STARTUP_PRESERVED_OWNER" writer_start)" = "$(field "$STARTUP_PRESERVED_OWNER" wrapper_pid):$(field "$STARTUP_PRESERVED_OWNER" wrapper_start)" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" writer_ppid)" = "$(field "$STARTUP_PRESERVED_OWNER" wrapper_ppid)" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" wrapper_pid):$(field "$STARTUP_PRESERVED_OWNER" wrapper_start)" = "$WRITER_PID:$WRITER_START" ] \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" wrapper_ppid)" \
        && [ -n "$(field "$STARTUP_PRESERVED_OWNER" wrapper_comm)" ] \
        && [ -n "$(field "$STARTUP_PRESERVED_OWNER" wrapper_exe)" ] \
        && valid_sha "$(field "$STARTUP_PRESERVED_OWNER" wrapper_cmdline_sha256)" \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" wrapper_cmdline_bytes)" \
        && valid_sha "$(field "$STARTUP_PRESERVED_OWNER" expected_daemon_cmdline_sha256)" \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" expected_daemon_cmdline_bytes)" \
        && valid_sha "$(field "$STARTUP_PRESERVED_OWNER" daemon_environment_sha256)" \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" daemon_environment_bytes)" \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" daemon_environment_count)" = 10 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" daemon_pid):$(field "$STARTUP_PRESERVED_OWNER" daemon_start)" = 0:0 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" fifo_mode):$(field "$STARTUP_PRESERVED_OWNER" fifo_uid):$(field "$STARTUP_PRESERVED_OWNER" fifo_gid)" = prw-------:0:0 ] \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" fifo_mnt_id)" \
        && valid_positive "$(field "$STARTUP_PRESERVED_OWNER" fifo_inode)" \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" binary_sha256):$(field "$STARTUP_PRESERVED_OWNER" binary_bytes)" = "$BIN_SHA:$BIN_BYTES" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" config_sha256):$(field "$STARTUP_PRESERVED_OWNER" config_bytes)" = "$CFG_SHA:$CFG_BYTES" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" runner_sha256):$(field "$STARTUP_PRESERVED_OWNER" runner_bytes)" = "$RUNNER_SHA:$RUNNER_BYTES" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" custody_observer_sha256):$(field "$STARTUP_PRESERVED_OWNER" custody_observer_bytes)" = "$CUSTODY_SHA:$CUSTODY_BYTES" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" stock_restart_helper_sha256):$(field "$STARTUP_PRESERVED_OWNER" stock_restart_helper_bytes)" = "$HELPER_SHA:$HELPER_BYTES" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" live_identity_schema):$(field "$STARTUP_PRESERVED_OWNER" live_identity_profile):$(field "$STARTUP_PRESERVED_OWNER" live_identity_sha256)" = "dcentos.s19k-braiins-live-identity/v2:$IDENTITY_PROFILE:$IDENTITY_SHA" ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" watchdog_start_intent):$(field "$STARTUP_PRESERVED_OWNER" watchdog_armed):$(field "$STARTUP_PRESERVED_OWNER" signal_attempted)" = false:false:false ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" inherited_rails):$(field "$STARTUP_PRESERVED_OWNER" route_or_uart_opened):$(field "$STARTUP_PRESERVED_OWNER" hardware_opened):$(field "$STARTUP_PRESERVED_OWNER" parent_release):$(field "$STARTUP_PRESERVED_OWNER" persistent_mutation)" = false:false:false:false:false ] \
        && [ "$(field "$STARTUP_PRESERVED_OWNER" publication)" = no-clobber-hard-link-after-fsync ] \
        && startup_stock_tuple_is_sane_at "$STARTUP_PRESERVED_OWNER"
}

startup_record_tuple_equals_source() {
    TUPLE_RECORD=$1
    startup_stock_tuple_equals "$TUPLE_RECORD" "$STARTUP_SOURCE" || return 1
    for TUPLE_KEY in binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 runner_bytes \
        custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
        stock_restart_helper_bytes live_identity_profile live_identity_sha256; do
        [ "$(field "$TUPLE_RECORD" "$TUPLE_KEY")" = "$(field "$STARTUP_SOURCE" "$TUPLE_KEY")" ] || return 1
    done
}

admit_startup_terminal_ancestor() {
    verify_file "$STARTUP_RETIRE_TERMINAL" \
            "$(field "$STARTUP_SOURCE" terminal_sha256)" "$(field "$STARTUP_SOURCE" terminal_bytes)" \
        && require_ordered_keys "$STARTUP_RETIRE_TERMINAL" schema transaction_id phase highest_phase \
            owner_sha256 owner_bytes c1_sha256 c1_bytes j1_sha256 j1_bytes active_sha256 active_bytes \
            j2_sha256 j2_bytes release_sha256 release_bytes parent_lost_sha256 parent_lost_bytes \
            fifo_path fifo_mnt_id fifo_inode transcript_path transcript_mnt_id transcript_inode \
            transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes \
            supervisor_pid supervisor_start supervisor_ppid supervisor_pgrp supervisor_session \
            supervisor_exe supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid \
            bosminer_start bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe \
            bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path stock_pidfile_sha256 \
            stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 \
            runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
            stock_restart_helper_bytes live_identity_profile live_identity_sha256 watchdog_start_intent \
            watchdog_armed signal_attempted inherited_rails route_or_uart_opened hardware_opened \
            stock_tree_revalidated live_identity_revalidated gpio_raw gpio_stock_baseline_revalidated \
            gpio437_engaged dcentrald_all_threads_absent watchdog_all_threads_absent persistent_mutation \
            publication \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" schema):$(field "$STARTUP_RETIRE_TERMINAL" phase)" = dcentos.s19k-startup-retired-terminal/v1:startup-no-effect-retired ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" transaction_id):$(field "$STARTUP_RETIRE_TERMINAL" highest_phase)" = "$(field "$STARTUP_SOURCE" transaction_id):$(field "$STARTUP_SOURCE" highest_phase)" ] \
        && [ "$(startup_pair "$STARTUP_RETIRE_TERMINAL" owner)" = "$(startup_pair "$STARTUP_SOURCE" owner)" ] \
        && [ "$(startup_pair "$STARTUP_RETIRE_TERMINAL" active)" = "$(startup_pair "$STARTUP_SOURCE" active)" ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" fifo_path):$(field "$STARTUP_RETIRE_TERMINAL" fifo_mnt_id):$(field "$STARTUP_RETIRE_TERMINAL" fifo_inode)" = "$(field "$STARTUP_SOURCE" fifo_path):$(field "$STARTUP_SOURCE" fifo_mnt_id):$(field "$STARTUP_SOURCE" fifo_inode)" ] \
        && valid_positive "$(field "$STARTUP_RETIRE_TERMINAL" transcript_mnt_id)" \
        && valid_positive "$(field "$STARTUP_RETIRE_TERMINAL" transcript_inode)" \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" transcript_mode):$(field "$STARTUP_RETIRE_TERMINAL" transcript_uid):$(field "$STARTUP_RETIRE_TERMINAL" transcript_gid)" = 0600:0:0 ] \
        && valid_sha "$(field "$STARTUP_RETIRE_TERMINAL" transcript_sha256)" \
        && valid_uint "$(field "$STARTUP_RETIRE_TERMINAL" transcript_bytes)" \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" transcript_path):$(field "$STARTUP_RETIRE_TERMINAL" transcript_mnt_id):$(field "$STARTUP_RETIRE_TERMINAL" transcript_inode):$(field "$STARTUP_RETIRE_TERMINAL" transcript_mode):$(field "$STARTUP_RETIRE_TERMINAL" transcript_uid):$(field "$STARTUP_RETIRE_TERMINAL" transcript_gid):$(field "$STARTUP_RETIRE_TERMINAL" transcript_sha256):$(field "$STARTUP_RETIRE_TERMINAL" transcript_bytes)" = "$(field "$STARTUP_SOURCE" transcript_path):$(field "$STARTUP_SOURCE" transcript_mnt_id):$(field "$STARTUP_SOURCE" transcript_inode):$(field "$STARTUP_SOURCE" transcript_mode):$(field "$STARTUP_SOURCE" transcript_uid):$(field "$STARTUP_SOURCE" transcript_gid):$(field "$STARTUP_SOURCE" transcript_sha256):$(field "$STARTUP_SOURCE" transcript_bytes)" ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" watchdog_start_intent):$(field "$STARTUP_RETIRE_TERMINAL" watchdog_armed):$(field "$STARTUP_RETIRE_TERMINAL" signal_attempted)" = false:false:false ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" inherited_rails):$(field "$STARTUP_RETIRE_TERMINAL" route_or_uart_opened):$(field "$STARTUP_RETIRE_TERMINAL" hardware_opened)" = false:false:false ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" stock_tree_revalidated):$(field "$STARTUP_RETIRE_TERMINAL" live_identity_revalidated)" = true:true ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" gpio_raw):$(field "$STARTUP_RETIRE_TERMINAL" gpio_stock_baseline_revalidated):$(field "$STARTUP_RETIRE_TERMINAL" gpio437_engaged)" = 437:0,454:0,455:1,456:1:true:true ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" dcentrald_all_threads_absent):$(field "$STARTUP_RETIRE_TERMINAL" watchdog_all_threads_absent):$(field "$STARTUP_RETIRE_TERMINAL" persistent_mutation)" = true:true:false ] \
        && [ "$(field "$STARTUP_RETIRE_TERMINAL" publication)" = no-clobber-hard-link-after-fsync ] \
        && startup_stock_tuple_is_sane_at "$STARTUP_RETIRE_TERMINAL" \
        && startup_record_tuple_equals_source "$STARTUP_RETIRE_TERMINAL"
}

admit_startup_cleanup_ancestor() {
    verify_file "$STARTUP_RETIRE_CLEANUP" \
            "$(field "$STARTUP_SOURCE" cleanup_sha256)" "$(field "$STARTUP_SOURCE" cleanup_bytes)" \
        && require_ordered_keys "$STARTUP_RETIRE_CLEANUP" schema transaction_id phase highest_phase \
            trial_dir terminal_schema terminal_sha256 terminal_bytes owner_sha256 owner_bytes \
            active_sha256 active_bytes fifo_path transcript_path transcript_mnt_id transcript_inode \
            transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes \
            residue_count residue_manifest_sha256 commit_source_path supervisor_pid supervisor_start \
            supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe supervisor_cmdline_sha256 \
            supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid bosminer_pgrp \
            bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes stock_pidfile_path \
            stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes config_sha256 config_bytes \
            runner_sha256 runner_bytes custody_observer_sha256 custody_observer_bytes \
            stock_restart_helper_sha256 stock_restart_helper_bytes live_identity_profile \
            live_identity_sha256 gpio_raw watchdog_start_intent watchdog_armed signal_attempted \
            inherited_rails route_or_uart_opened hardware_opened persistent_mutation publication \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" schema):$(field "$STARTUP_RETIRE_CLEANUP" phase)" = dcentos.s19k-startup-retire-cleanup-commit/v1:startup-no-effect-cleanup-committed ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" transaction_id):$(field "$STARTUP_RETIRE_CLEANUP" highest_phase):$(field "$STARTUP_RETIRE_CLEANUP" trial_dir)" = "$(field "$STARTUP_SOURCE" transaction_id):$(field "$STARTUP_SOURCE" highest_phase):$TRIAL_DIR" ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" terminal_schema)" = dcentos.s19k-startup-retired-terminal/v1 ] \
        && valid_sha "$(field "$STARTUP_RETIRE_CLEANUP" terminal_sha256)" \
        && valid_positive "$(field "$STARTUP_RETIRE_CLEANUP" terminal_bytes)" \
        && [ "$(startup_pair "$STARTUP_RETIRE_CLEANUP" owner)" = "$(startup_pair "$STARTUP_SOURCE" owner)" ] \
        && [ "$(startup_pair "$STARTUP_RETIRE_CLEANUP" active)" = "$(startup_pair "$STARTUP_SOURCE" active)" ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" fifo_path)" = "$(field "$STARTUP_SOURCE" fifo_path)" ] \
        && valid_positive "$(field "$STARTUP_RETIRE_CLEANUP" transcript_mnt_id)" \
        && valid_positive "$(field "$STARTUP_RETIRE_CLEANUP" transcript_inode)" \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" transcript_mode):$(field "$STARTUP_RETIRE_CLEANUP" transcript_uid):$(field "$STARTUP_RETIRE_CLEANUP" transcript_gid)" = 0600:0:0 ] \
        && valid_sha "$(field "$STARTUP_RETIRE_CLEANUP" transcript_sha256)" \
        && valid_uint "$(field "$STARTUP_RETIRE_CLEANUP" transcript_bytes)" \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" transcript_path):$(field "$STARTUP_RETIRE_CLEANUP" transcript_mnt_id):$(field "$STARTUP_RETIRE_CLEANUP" transcript_inode):$(field "$STARTUP_RETIRE_CLEANUP" transcript_mode):$(field "$STARTUP_RETIRE_CLEANUP" transcript_uid):$(field "$STARTUP_RETIRE_CLEANUP" transcript_gid):$(field "$STARTUP_RETIRE_CLEANUP" transcript_sha256):$(field "$STARTUP_RETIRE_CLEANUP" transcript_bytes)" = "$(field "$STARTUP_SOURCE" transcript_path):$(field "$STARTUP_SOURCE" transcript_mnt_id):$(field "$STARTUP_SOURCE" transcript_inode):$(field "$STARTUP_SOURCE" transcript_mode):$(field "$STARTUP_SOURCE" transcript_uid):$(field "$STARTUP_SOURCE" transcript_gid):$(field "$STARTUP_SOURCE" transcript_sha256):$(field "$STARTUP_SOURCE" transcript_bytes)" ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" residue_count):$(field "$STARTUP_RETIRE_CLEANUP" residue_manifest_sha256)" = 0:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] \
        && startup_cleanup_source_path_is_consumed \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" watchdog_start_intent):$(field "$STARTUP_RETIRE_CLEANUP" watchdog_armed):$(field "$STARTUP_RETIRE_CLEANUP" signal_attempted)" = false:false:false ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" inherited_rails):$(field "$STARTUP_RETIRE_CLEANUP" route_or_uart_opened):$(field "$STARTUP_RETIRE_CLEANUP" hardware_opened):$(field "$STARTUP_RETIRE_CLEANUP" persistent_mutation)" = false:false:false:false ] \
        && [ "$(field "$STARTUP_RETIRE_CLEANUP" publication)" = no-clobber-hard-link-after-fsync ] \
        && startup_stock_tuple_is_sane_at "$STARTUP_RETIRE_CLEANUP" \
        && startup_record_tuple_equals_source "$STARTUP_RETIRE_CLEANUP"
}

startup_cleanup_source_path_is_consumed() {
    CLEANUP_SOURCE_PATH=$(field "$STARTUP_RETIRE_CLEANUP" commit_source_path) || return 1
    CLEANUP_SOURCE_SUFFIX=${CLEANUP_SOURCE_PATH##*.source.}
    CLEANUP_SOURCE_PID=${CLEANUP_SOURCE_SUFFIX%%.*}
    CLEANUP_SOURCE_START=${CLEANUP_SOURCE_SUFFIX#*.}
    [ "${CLEANUP_SOURCE_PATH%/*}" = "$TRIAL_DIR" ] \
        && [ "$CLEANUP_SOURCE_PATH" = "$TRIAL_DIR/.runtime_startup_retire_cleanup_commit.source.$CLEANUP_SOURCE_PID.$CLEANUP_SOURCE_START" ] \
        && valid_positive "$CLEANUP_SOURCE_PID" \
        && valid_positive "$CLEANUP_SOURCE_START" \
        && [ ! -e "$CLEANUP_SOURCE_PATH" ] \
        && [ ! -L "$CLEANUP_SOURCE_PATH" ]
}

admit_startup_bound_optional() {
    STARTUP_PREFIX_FIELD=$1
    STARTUP_EXPECTED_PATH=$2
    STARTUP_PRESENT=$(field "$STARTUP_SOURCE" "${STARTUP_PREFIX_FIELD}_present") || return 1
    STARTUP_PATH=$(field "$STARTUP_SOURCE" "${STARTUP_PREFIX_FIELD}_path") || return 1
    STARTUP_SHA=$(field "$STARTUP_SOURCE" "${STARTUP_PREFIX_FIELD}_sha256") || return 1
    STARTUP_BYTES=$(field "$STARTUP_SOURCE" "${STARTUP_PREFIX_FIELD}_bytes") || return 1
    [ "$STARTUP_PATH" = "$STARTUP_EXPECTED_PATH" ] || return 1
    case "$STARTUP_PRESENT:$STARTUP_SHA:$STARTUP_BYTES" in
        true:none:0) return 1 ;;
        true:*:*) verify_file "$STARTUP_PATH" "$STARTUP_SHA" "$STARTUP_BYTES" ;;
        false:none:0) [ ! -e "$STARTUP_PATH" ] && [ ! -L "$STARTUP_PATH" ] ;;
        false:*:*)
            valid_sha "$STARTUP_SHA" && valid_positive "$STARTUP_BYTES" \
                && [ ! -e "$STARTUP_PATH" ] && [ ! -L "$STARTUP_PATH" ] || return 1
            case "$(field "$STARTUP_SOURCE" source_kind):$STARTUP_PREFIX_FIELD" in
                startup-prefix:c1|startup-prefix:j1|startup-prefix:j2|startup-prefix:release|startup-prefix:parent_lost)
                    [ "$(field "$STARTUP_SOURCE" terminal_present)" = true ] \
                        && admit_startup_terminal_ancestor \
                        && [ "$(field "$STARTUP_RETIRE_TERMINAL" "${STARTUP_PREFIX_FIELD}_sha256"):$(field "$STARTUP_RETIRE_TERMINAL" "${STARTUP_PREFIX_FIELD}_bytes")" = "$STARTUP_SHA:$STARTUP_BYTES" ]
                    ;;
                startup-cleanup-commit:terminal)
                    [ "$(field "$STARTUP_SOURCE" cleanup_present)" = true ] \
                        && admit_startup_cleanup_ancestor \
                        && [ "$(field "$STARTUP_RETIRE_CLEANUP" terminal_sha256):$(field "$STARTUP_RETIRE_CLEANUP" terminal_bytes)" = "$STARTUP_SHA:$STARTUP_BYTES" ]
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

admit_startup_fifo_state() {
    STARTUP_FIFO_PRESENT=$(field "$STARTUP_SOURCE" fifo_present) || return 1
    STARTUP_FIFO_PATH=$(field "$STARTUP_SOURCE" fifo_path) || return 1
    [ "$STARTUP_FIFO_PATH" = "$(field "$STARTUP_PRESERVED_OWNER" fifo_path)" ] || return 1
    case "$STARTUP_FIFO_PRESENT" in
        false) [ ! -e "$STARTUP_FIFO_PATH" ] && [ ! -L "$STARTUP_FIFO_PATH" ] ;;
        true)
            [ -p "$STARTUP_FIFO_PATH" ] && [ ! -L "$STARTUP_FIFO_PATH" ] || return 1
            exec 7<> "$STARTUP_FIFO_PATH" || return 1
            STARTUP_FIFO_TARGET=$(readlink "/proc/$$/fd/7" 2>/dev/null || true)
            STARTUP_FIFO_LS=$("$BUSYBOX" ls -lniL "/proc/$$/fd/7" 2>/dev/null || true)
            STARTUP_FIFO_MNT=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/7" 2>/dev/null)
            exec 7>&-
            set -- $STARTUP_FIFO_LS
            [ "$STARTUP_FIFO_TARGET" = "$STARTUP_FIFO_PATH" ] || return 1
            if [ "$REQUIRE_EXACT_STARTUP_OBJECT_METADATA" = true ]; then
                [ "${2:-}:${4:-}:${5:-}" = prw-------:0:0 ] \
                    && [ "${1:-}:$STARTUP_FIFO_MNT" = "$(field "$STARTUP_SOURCE" fifo_inode):$(field "$STARTUP_SOURCE" fifo_mnt_id)" ] || return 1
            fi
            [ -p "$STARTUP_FIFO_PATH" ] && [ ! -L "$STARTUP_FIFO_PATH" ]
            ;;
        *) return 1 ;;
    esac
}

admit_startup_transcript_state() {
    STARTUP_TRANSCRIPT_PRESENT=$(field "$STARTUP_SOURCE" transcript_present) || return 1
    STARTUP_TRANSCRIPT_PATH=$(field "$STARTUP_SOURCE" transcript_path) || return 1
    case "$STARTUP_TRANSCRIPT_PRESENT" in
        false) [ ! -e "$STARTUP_TRANSCRIPT_PATH" ] && [ ! -L "$STARTUP_TRANSCRIPT_PATH" ] ;;
        true)
            regular "$STARTUP_TRANSCRIPT_PATH" || return 1
            # fd8 is the stock log boundary authority for the whole transaction.
            # Keep startup evidence on a disjoint descriptor across revalidation.
            exec 6< "$STARTUP_TRANSCRIPT_PATH" || return 1
            STARTUP_TRANSCRIPT_TARGET=$(readlink "/proc/$$/fd/6" 2>/dev/null || true)
            STARTUP_TRANSCRIPT_LS=$("$BUSYBOX" ls -lniL "/proc/$$/fd/6" 2>/dev/null || true)
            STARTUP_TRANSCRIPT_MNT=$(sed -n 's/^mnt_id:[[:space:]]*//p' "/proc/$$/fdinfo/6" 2>/dev/null)
            STARTUP_TRANSCRIPT_SHA=$(sha256sum "/proc/$$/fd/6" | awk '{print $1}')
            STARTUP_TRANSCRIPT_BYTES=$(wc -c < "/proc/$$/fd/6" | tr -d ' \t\r\n')
            set -- $STARTUP_TRANSCRIPT_LS
            STARTUP_TRANSCRIPT_INODE=${1:-}
            STARTUP_TRANSCRIPT_MODE=${2:-}
            STARTUP_TRANSCRIPT_UID=${4:-}
            STARTUP_TRANSCRIPT_GID=${5:-}
            STARTUP_TRANSCRIPT_PATH_LS=$("$BUSYBOX" ls -lniL "$STARTUP_TRANSCRIPT_PATH" 2>/dev/null || true)
            set -- $STARTUP_TRANSCRIPT_PATH_LS
            exec 6>&-
            [ "$STARTUP_TRANSCRIPT_TARGET" = "$STARTUP_TRANSCRIPT_PATH" ] \
                && [ "${1:-}" = "$STARTUP_TRANSCRIPT_INODE" ] \
                && [ "$STARTUP_TRANSCRIPT_SHA:$STARTUP_TRANSCRIPT_BYTES" = "$(field "$STARTUP_SOURCE" transcript_sha256):$(field "$STARTUP_SOURCE" transcript_bytes)" ] || return 1
            if [ "$REQUIRE_EXACT_STARTUP_OBJECT_METADATA" = true ]; then
                [ "$STARTUP_TRANSCRIPT_MODE:$STARTUP_TRANSCRIPT_UID:$STARTUP_TRANSCRIPT_GID" = -rw-------:0:0 ] \
                    && [ "$STARTUP_TRANSCRIPT_INODE:$STARTUP_TRANSCRIPT_MNT" = "$(field "$STARTUP_SOURCE" transcript_inode):$(field "$STARTUP_SOURCE" transcript_mnt_id)" ] || return 1
            fi
            ;;
        *) return 1 ;;
    esac
}

admit_startup_source() {
    verify_file "$STARTUP_SOURCE" "$SOURCE_SHA" "$SOURCE_BYTES" \
        && require_ordered_keys "$STARTUP_SOURCE" schema transaction_id phase highest_phase trial_dir \
            source_kind owner_present owner_path owner_sha256 owner_bytes c1_present c1_path c1_sha256 \
            c1_bytes j1_present j1_path j1_sha256 j1_bytes active_present active_path active_sha256 \
            active_bytes j2_present j2_path j2_sha256 j2_bytes release_present release_path \
            release_sha256 release_bytes parent_lost_present parent_lost_path parent_lost_sha256 \
            parent_lost_bytes terminal_present terminal_path terminal_sha256 terminal_bytes \
            cleanup_present cleanup_path cleanup_sha256 cleanup_bytes preserved_owner_present \
            preserved_owner_path preserved_owner_sha256 preserved_owner_bytes preserved_active_present \
            preserved_active_path preserved_active_sha256 preserved_active_bytes fifo_present fifo_path \
            fifo_mnt_id fifo_inode transcript_present transcript_path transcript_mnt_id transcript_inode \
            transcript_mode transcript_uid transcript_gid transcript_sha256 transcript_bytes supervisor_pid \
            supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe \
            supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start bosminer_ppid \
            bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 bosminer_cmdline_bytes \
            stock_pidfile_path stock_pidfile_sha256 stock_pidfile_bytes binary_sha256 binary_bytes \
            config_sha256 config_bytes runner_sha256 runner_bytes custody_observer_sha256 \
            custody_observer_bytes stock_restart_helper_sha256 stock_restart_helper_bytes \
            live_identity_schema live_identity_profile live_identity_sha256 stock_supervisor stock_bosminer \
            dcentrald watchdog_fd competing_wrapper watchdog_start_intent watchdog_armed signal_attempted \
            inherited_rails route_or_uart_opened hardware_opened persistent_mutation publication \
        && [ "$(field "$STARTUP_SOURCE" schema)" = dcentos.s19k-startup-prefix-safeoff-source/v1 ] \
        && valid_sha "$(field "$STARTUP_SOURCE" transaction_id)" \
        && [ "$(field "$STARTUP_SOURCE" transaction_id)" = "$(field "$PENDING_RECORD" transaction_id)" ] \
        && [ "$(field "$STARTUP_SOURCE" phase)" = startup-prefix-stock-loss-admitted ] \
        && [ "$(field "$STARTUP_SOURCE" highest_phase)" = "$(field "$PENDING_RECORD" highest_phase)" ] \
        && [ "$(field "$STARTUP_SOURCE" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$STARTUP_SOURCE" binary_sha256):$(field "$STARTUP_SOURCE" binary_bytes)" = "$BIN_SHA:$BIN_BYTES" ] \
        && [ "$(field "$STARTUP_SOURCE" config_sha256):$(field "$STARTUP_SOURCE" config_bytes)" = "$CFG_SHA:$CFG_BYTES" ] \
        && [ "$(field "$STARTUP_SOURCE" runner_sha256):$(field "$STARTUP_SOURCE" runner_bytes)" = "$RUNNER_SHA:$RUNNER_BYTES" ] \
        && [ "$(field "$STARTUP_SOURCE" custody_observer_sha256):$(field "$STARTUP_SOURCE" custody_observer_bytes)" = "$CUSTODY_SHA:$CUSTODY_BYTES" ] \
        && [ "$(field "$STARTUP_SOURCE" stock_restart_helper_sha256):$(field "$STARTUP_SOURCE" stock_restart_helper_bytes)" = "$HELPER_SHA:$HELPER_BYTES" ] \
        && [ "$(field "$STARTUP_SOURCE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(field "$STARTUP_SOURCE" live_identity_profile)" = "$IDENTITY_PROFILE" ] \
        && [ "$(field "$STARTUP_SOURCE" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$STARTUP_SOURCE" stock_supervisor):$(field "$STARTUP_SOURCE" stock_bosminer)" = absent:absent ] \
        && [ "$(field "$STARTUP_SOURCE" dcentrald):$(field "$STARTUP_SOURCE" watchdog_fd):$(field "$STARTUP_SOURCE" competing_wrapper)" = absent:absent:absent ] \
        && [ "$(field "$STARTUP_SOURCE" watchdog_start_intent):$(field "$STARTUP_SOURCE" watchdog_armed):$(field "$STARTUP_SOURCE" signal_attempted)" = false:false:false ] \
        && [ "$(field "$STARTUP_SOURCE" inherited_rails):$(field "$STARTUP_SOURCE" route_or_uart_opened):$(field "$STARTUP_SOURCE" hardware_opened)" = false:false:false ] \
        && [ "$(field "$STARTUP_SOURCE" persistent_mutation)" = false ] \
        && [ "$(field "$STARTUP_SOURCE" publication)" = no-clobber-hard-link-after-fsync ] || return 1
    admit_startup_preserved preserved_owner "$STARTUP_PRESERVED_OWNER" \
        && admit_startup_preserved preserved_active "$STARTUP_PRESERVED_ACTIVE" \
        && admit_startup_bound_optional c1 "$STARTUP_C1" \
        && admit_startup_bound_optional j1 "$STARTUP_J1" \
        && admit_startup_bound_optional j2 "$STARTUP_J2" \
        && admit_startup_bound_optional release "$STARTUP_RELEASE" \
        && admit_startup_bound_optional parent_lost "$STARTUP_PARENT_LOST" \
        && admit_startup_bound_optional terminal "$STARTUP_RETIRE_TERMINAL" \
        && admit_startup_bound_optional cleanup "$STARTUP_RETIRE_CLEANUP" || return 1
    [ ! -e "$STARTUP_RETIRED_OWNER" ] && [ ! -L "$STARTUP_RETIRED_OWNER" ] \
        && [ ! -e "$STARTUP_RETIRED_ACTIVE" ] && [ ! -L "$STARTUP_RETIRED_ACTIVE" ] || return 1
    for STARTUP_RESIDUE in \
        "$TRIAL_DIR"/.runtime_startup_prefix_pre_safeoff.tmp.* \
        "$TRIAL_DIR"/.runtime_startup_prefix_pre_safeoff.claim.* \
        "$TRIAL_DIR"/.runtime_startup_prefix_pre_safeoff.completed.* \
        "$TRIAL_DIR"/.runtime_startup_*.tmp.* \
        "$TRIAL_DIR"/.runtime_startup_*.claim.* \
        "$TRIAL_DIR"/.runtime_startup_*.completed.* \
        "$TRIAL_DIR"/.runtime_stock_restart_pending.tmp.*; do
        [ -e "$STARTUP_RESIDUE" ] || [ -L "$STARTUP_RESIDUE" ] || continue
        return 1
    done
    STARTUP_SOURCE_KIND=$(field "$STARTUP_SOURCE" source_kind)
    case "$STARTUP_SOURCE_KIND" in startup-prefix|startup-cleanup-commit) ;; *) return 1 ;; esac
    STARTUP_ACTIVE_PRESENT=$(field "$STARTUP_SOURCE" active_present)
    STARTUP_ACTIVE_PATH=$(field "$STARTUP_SOURCE" active_path)
    STARTUP_ACTIVE_SHA=$(field "$STARTUP_SOURCE" active_sha256)
    STARTUP_ACTIVE_BYTES=$(field "$STARTUP_SOURCE" active_bytes)
    STARTUP_OWNER_PRESENT=$(field "$STARTUP_SOURCE" owner_present)
    STARTUP_OWNER_PATH=$(field "$STARTUP_SOURCE" owner_path)
    STARTUP_OWNER_PAIR=$(startup_pair "$STARTUP_SOURCE" owner)
    case "$STARTUP_SOURCE_KIND:$STARTUP_OWNER_PRESENT:$(field "$STARTUP_SOURCE" preserved_owner_present)" in
        startup-prefix:true:true)
            [ "$STARTUP_OWNER_PATH" = "$STARTUP_PRESERVED_OWNER" ] \
                && [ "$STARTUP_OWNER_PAIR" = "$(startup_pair "$STARTUP_SOURCE" preserved_owner)" ] \
                && admit_startup_j0 || return 1
            ;;
        startup-cleanup-commit:false:false)
            [ "$STARTUP_OWNER_PATH" = none ] && valid_sha "${STARTUP_OWNER_PAIR%%:*}" \
                && valid_positive "${STARTUP_OWNER_PAIR#*:}" || return 1
            ;;
        *) return 1 ;;
    esac
    case "$STARTUP_SOURCE_KIND:$STARTUP_ACTIVE_PRESENT:$(field "$STARTUP_SOURCE" preserved_active_present):$STARTUP_ACTIVE_SHA:$STARTUP_ACTIVE_BYTES" in
        startup-prefix:true:true:*:*)
            [ "$STARTUP_ACTIVE_PATH" = "$STARTUP_PRESERVED_ACTIVE" ] \
                && [ "$STARTUP_ACTIVE_SHA:$STARTUP_ACTIVE_BYTES" = "$(startup_pair "$STARTUP_SOURCE" preserved_active)" ] \
                && verify_file "$STARTUP_PRESERVED_ACTIVE" "$STARTUP_ACTIVE_SHA" "$STARTUP_ACTIVE_BYTES" \
                && admit_runtime_active_v5_at "$STARTUP_PRESERVED_ACTIVE" || return 1
            ;;
        startup-prefix:false:false:none:0) [ "$STARTUP_ACTIVE_PATH" = none ] || return 1 ;;
        startup-cleanup-commit:false:false:none:0) [ "$STARTUP_ACTIVE_PATH" = none ] || return 1 ;;
        startup-cleanup-commit:false:false:*:*)
            [ "$STARTUP_ACTIVE_PATH" = none ] && valid_sha "$STARTUP_ACTIVE_SHA" \
                && valid_positive "$STARTUP_ACTIVE_BYTES" || return 1
            ;;
        *) return 1 ;;
    esac
    startup_stock_tuple_is_sane_at "$STARTUP_SOURCE" \
        && valid_positive "$(field "$STARTUP_SOURCE" transcript_mnt_id)" \
        && valid_positive "$(field "$STARTUP_SOURCE" transcript_inode)" \
        && [ "$(field "$STARTUP_SOURCE" transcript_mode):$(field "$STARTUP_SOURCE" transcript_uid):$(field "$STARTUP_SOURCE" transcript_gid)" = 0600:0:0 ] \
        && valid_sha "$(field "$STARTUP_SOURCE" transcript_sha256)" \
        && valid_uint "$(field "$STARTUP_SOURCE" transcript_bytes)" \
        && admit_startup_transcript_state || return 1
    if [ "$STARTUP_SOURCE_KIND" = startup-prefix ]; then
        startup_stock_tuple_equals "$STARTUP_SOURCE" "$STARTUP_PRESERVED_OWNER" \
            && [ "$(field "$STARTUP_SOURCE" fifo_path):$(field "$STARTUP_SOURCE" fifo_mnt_id):$(field "$STARTUP_SOURCE" fifo_inode)" = "$(field "$STARTUP_PRESERVED_OWNER" fifo_path):$(field "$STARTUP_PRESERVED_OWNER" fifo_mnt_id):$(field "$STARTUP_PRESERVED_OWNER" fifo_inode)" ] \
            && admit_startup_fifo_state \
            && [ "$(field "$STARTUP_SOURCE" cleanup_present):$(startup_pair "$STARTUP_SOURCE" cleanup)" = false:none:0 ] || return 1
        if [ "$(field "$STARTUP_SOURCE" terminal_present)" = true ]; then
            admit_startup_terminal_ancestor || return 1
            for STARTUP_HISTORY in c1 j1 active j2 release parent_lost; do
                [ "$(startup_pair "$STARTUP_SOURCE" "$STARTUP_HISTORY")" = "$(startup_pair "$STARTUP_RETIRE_TERMINAL" "$STARTUP_HISTORY")" ] || return 1
            done
        else
            [ "$(startup_pair "$STARTUP_SOURCE" terminal)" = none:0 ] || return 1
            for STARTUP_HISTORY in c1 j1 j2 release parent_lost; do
                if [ "$(field "$STARTUP_SOURCE" "${STARTUP_HISTORY}_present")" = false ]; then
                    [ "$(startup_pair "$STARTUP_SOURCE" "$STARTUP_HISTORY")" = none:0 ] || return 1
                fi
            done
            [ "$(field "$STARTUP_SOURCE" transcript_path)" = "$TRIAL_DIR/.startup_daemon_transcript.$(field "$STARTUP_PRESERVED_OWNER" wrapper_pid).$(field "$STARTUP_PRESERVED_OWNER" wrapper_start)" ] || return 1
        fi
    else
        [ "$(field "$STARTUP_SOURCE" fifo_present):$(field "$STARTUP_SOURCE" fifo_mnt_id):$(field "$STARTUP_SOURCE" fifo_inode)" = false:none:none ] \
            && [ ! -e "$(field "$STARTUP_SOURCE" fifo_path)" ] \
            && [ ! -L "$(field "$STARTUP_SOURCE" fifo_path)" ] \
            && admit_startup_cleanup_ancestor \
            && [ "$STARTUP_OWNER_PAIR" = "$(startup_pair "$STARTUP_RETIRE_CLEANUP" owner)" ] \
            && [ "$STARTUP_ACTIVE_SHA:$STARTUP_ACTIVE_BYTES" = "$(startup_pair "$STARTUP_RETIRE_CLEANUP" active)" ] || return 1
        for STARTUP_HISTORY in c1 j1 j2 release parent_lost; do
            [ "$(field "$STARTUP_SOURCE" "${STARTUP_HISTORY}_present"):$(startup_pair "$STARTUP_SOURCE" "$STARTUP_HISTORY")" = false:none:0 ] || return 1
        done
        case "$(field "$STARTUP_SOURCE" terminal_present):$(startup_pair "$STARTUP_SOURCE" terminal)" in
            true:*) admit_startup_terminal_ancestor ;;
            false:*) [ "$(startup_pair "$STARTUP_SOURCE" terminal)" = "$(startup_pair "$STARTUP_RETIRE_CLEANUP" terminal)" ] ;;
            *) return 1 ;;
        esac || return 1
    fi
    STARTUP_C1_PAIR=$(field "$STARTUP_SOURCE" c1_sha256):$(field "$STARTUP_SOURCE" c1_bytes)
    STARTUP_J1_PAIR=$(field "$STARTUP_SOURCE" j1_sha256):$(field "$STARTUP_SOURCE" j1_bytes)
    STARTUP_ACTIVE_PAIR=$STARTUP_ACTIVE_SHA:$STARTUP_ACTIVE_BYTES
    STARTUP_J2_PAIR=$(field "$STARTUP_SOURCE" j2_sha256):$(field "$STARTUP_SOURCE" j2_bytes)
    STARTUP_RELEASE_PAIR=$(field "$STARTUP_SOURCE" release_sha256):$(field "$STARTUP_SOURCE" release_bytes)
    STARTUP_PARENT_LOST_PAIR=$(field "$STARTUP_SOURCE" parent_lost_sha256):$(field "$STARTUP_SOURCE" parent_lost_bytes)
    case "$(field "$STARTUP_SOURCE" source_kind):$(field "$STARTUP_SOURCE" highest_phase)" in
        startup-prefix:j0) [ "$STARTUP_C1_PAIR:$STARTUP_J1_PAIR:$STARTUP_ACTIVE_PAIR:$STARTUP_J2_PAIR:$STARTUP_RELEASE_PAIR:$STARTUP_PARENT_LOST_PAIR" = none:0:none:0:none:0:none:0:none:0:none:0 ] ;;
        startup-prefix:parent-lost-j0) [ "$STARTUP_C1_PAIR:$STARTUP_J1_PAIR:$STARTUP_ACTIVE_PAIR:$STARTUP_J2_PAIR:$STARTUP_RELEASE_PAIR" = none:0:none:0:none:0:none:0:none:0 ] && [ "$STARTUP_PARENT_LOST_PAIR" != none:0 ] ;;
        startup-prefix:c1) [ "$STARTUP_C1_PAIR" != none:0 ] && [ "$STARTUP_J1_PAIR:$STARTUP_ACTIVE_PAIR:$STARTUP_J2_PAIR:$STARTUP_RELEASE_PAIR:$STARTUP_PARENT_LOST_PAIR" = none:0:none:0:none:0:none:0:none:0 ] ;;
        startup-prefix:j1) [ "$STARTUP_C1_PAIR" != none:0 ] && [ "$STARTUP_J1_PAIR" != none:0 ] && [ "$STARTUP_ACTIVE_PAIR:$STARTUP_J2_PAIR:$STARTUP_RELEASE_PAIR:$STARTUP_PARENT_LOST_PAIR" = none:0:none:0:none:0:none:0 ] ;;
        startup-prefix:active) [ "$STARTUP_C1_PAIR" != none:0 ] && [ "$STARTUP_J1_PAIR" != none:0 ] && [ "$STARTUP_ACTIVE_PAIR" != none:0 ] && [ "$STARTUP_J2_PAIR:$STARTUP_RELEASE_PAIR:$STARTUP_PARENT_LOST_PAIR" = none:0:none:0:none:0 ] ;;
        startup-prefix:j2) [ "$STARTUP_C1_PAIR" != none:0 ] && [ "$STARTUP_J1_PAIR" != none:0 ] && [ "$STARTUP_ACTIVE_PAIR" != none:0 ] && [ "$STARTUP_J2_PAIR" != none:0 ] && [ "$STARTUP_RELEASE_PAIR:$STARTUP_PARENT_LOST_PAIR" = none:0:none:0 ] ;;
        startup-prefix:release) [ "$STARTUP_C1_PAIR" != none:0 ] && [ "$STARTUP_J1_PAIR" != none:0 ] && [ "$STARTUP_ACTIVE_PAIR" != none:0 ] && [ "$STARTUP_J2_PAIR" != none:0 ] && [ "$STARTUP_RELEASE_PAIR" != none:0 ] && [ "$STARTUP_PARENT_LOST_PAIR" = none:0 ] ;;
        startup-cleanup-commit:*) [ "$(field "$STARTUP_SOURCE" cleanup_present)" = true ] ;;
        *) return 1 ;;
    esac
}

admit_terminal_handoff() {
    require_ordered_keys "$TERMINAL_HANDOFF" schema disposition runtime_active_sha256 \
        runtime_active_bytes terminal_safeoff watchdog_magic_close watchdog_worker_joined resets psu \
        inherited_rails supervisor_signal_attempted supervisor_gone supervisor_remnant \
        supervisor_lease_kind child_signal_attempted child_gone child_remnant child_lease_kind \
        global_stock_absence replacement_or_ambiguity remnant_authority supervisor_pid \
        supervisor_start supervisor_ppid supervisor_pgrp supervisor_session supervisor_exe \
        supervisor_cmdline_sha256 supervisor_cmdline_bytes bosminer_pid bosminer_start \
        bosminer_ppid bosminer_pgrp bosminer_session bosminer_exe bosminer_cmdline_sha256 \
        bosminer_cmdline_bytes binary_sha256 binary_bytes config_sha256 config_bytes runner_sha256 \
        runner_bytes custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
        stock_restart_helper_bytes live_identity_schema \
        live_identity_profile live_identity_sha256 live_identity_model_sha256 persistent_mutation \
        publication || return 1
    EXPECTED_TERMINAL_SCHEMA=dcentos.s19k-terminal-safeoff-partial-stock-owner/v1
    EXPECTED_TERMINAL_DISPOSITION=terminal-safeoff-partial-stock-owner
    EXPECTED_TERMINAL_RESETS=454:0,455:0,456:0
    if [ "$PENDING_VERSION" = install-custody ]; then
        EXPECTED_TERMINAL_SCHEMA=dcentos.s19k-install-custody-terminal-safeoff/v1
        EXPECTED_TERMINAL_DISPOSITION=install-custody-terminal-safeoff
        EXPECTED_TERMINAL_RESETS=not-attempted
    fi
    [ "$(field "$TERMINAL_HANDOFF" schema)" = "$EXPECTED_TERMINAL_SCHEMA" ] \
        && [ "$(field "$TERMINAL_HANDOFF" disposition)" = "$EXPECTED_TERMINAL_DISPOSITION" ] \
        && [ "$(field "$TERMINAL_HANDOFF" runtime_active_sha256):$(field "$TERMINAL_HANDOFF" runtime_active_bytes)" = "$PRE_SHA:$PRE_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" terminal_safeoff)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" watchdog_magic_close)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" watchdog_worker_joined)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" resets)" = "$EXPECTED_TERMINAL_RESETS" ] \
        && [ "$(field "$TERMINAL_HANDOFF" psu)" = 437:1 ] \
        && [ "$(field "$TERMINAL_HANDOFF" inherited_rails)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_signal_attempted)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_gone)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_remnant)" = absent ] \
        && valid_stock_lease_kind "$(field "$TERMINAL_HANDOFF" supervisor_lease_kind)" \
        && valid_bool "$(field "$TERMINAL_HANDOFF" child_signal_attempted)" \
        && [ "$(field "$TERMINAL_HANDOFF" child_gone)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" child_remnant)" = absent ] \
        && valid_stock_lease_kind "$(field "$TERMINAL_HANDOFF" child_lease_kind)" \
        && [ "$(field "$TERMINAL_HANDOFF" global_stock_absence)" = true ] \
        && [ "$(field "$TERMINAL_HANDOFF" replacement_or_ambiguity)" = false ] \
        && [ "$(field "$TERMINAL_HANDOFF" remnant_authority)" = all-thread-ptrace-or-pidfd-recovery-only ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_pid):$(field "$TERMINAL_HANDOFF" supervisor_start)" = "$(field "$PRE" supervisor_pid):$(field "$PRE" supervisor_start)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_ppid):$(field "$TERMINAL_HANDOFF" supervisor_pgrp):$(field "$TERMINAL_HANDOFF" supervisor_session)" = "$(field "$PRE" supervisor_ppid):$(field "$PRE" supervisor_pgrp):$(field "$PRE" supervisor_session)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_exe)" = "$(field "$PRE" supervisor_exe)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" supervisor_cmdline_sha256):$(field "$TERMINAL_HANDOFF" supervisor_cmdline_bytes)" = "$(field "$PRE" supervisor_cmdline_sha256):$(field "$PRE" supervisor_cmdline_bytes)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" bosminer_pid):$(field "$TERMINAL_HANDOFF" bosminer_start)" = "$(field "$PRE" bosminer_pid):$(field "$PRE" bosminer_start)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" bosminer_ppid):$(field "$TERMINAL_HANDOFF" bosminer_pgrp):$(field "$TERMINAL_HANDOFF" bosminer_session)" = "$(field "$PRE" bosminer_ppid):$(field "$PRE" bosminer_pgrp):$(field "$PRE" bosminer_session)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" bosminer_exe)" = "$(field "$PRE" bosminer_exe)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" bosminer_cmdline_sha256):$(field "$TERMINAL_HANDOFF" bosminer_cmdline_bytes)" = "$(field "$PRE" bosminer_cmdline_sha256):$(field "$PRE" bosminer_cmdline_bytes)" ] \
        && [ "$(field "$TERMINAL_HANDOFF" binary_sha256):$(field "$TERMINAL_HANDOFF" binary_bytes)" = "$BIN_SHA:$BIN_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" config_sha256):$(field "$TERMINAL_HANDOFF" config_bytes)" = "$CFG_SHA:$CFG_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" runner_sha256):$(field "$TERMINAL_HANDOFF" runner_bytes)" = "$RUNNER_SHA:$RUNNER_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" custody_observer_sha256):$(field "$TERMINAL_HANDOFF" custody_observer_bytes)" = "$CUSTODY_SHA:$CUSTODY_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" stock_restart_helper_sha256):$(field "$TERMINAL_HANDOFF" stock_restart_helper_bytes)" = "$HELPER_SHA:$HELPER_BYTES" ] \
        && [ "$(field "$TERMINAL_HANDOFF" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(field "$TERMINAL_HANDOFF" live_identity_profile)" = "$IDENTITY_PROFILE" ] \
        && [ "$(field "$TERMINAL_HANDOFF" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$TERMINAL_HANDOFF" live_identity_model_sha256)" = "$IDENTITY_MODEL_SHA" ] \
        && [ "$(field "$TERMINAL_HANDOFF" persistent_mutation)" = false ] \
        && [ "$(field "$TERMINAL_HANDOFF" publication)" = no-clobber-hard-link-after-fsync ]
}

admit_lock_owner() {
    [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && regular "$OWNER" || return 1
    for GLOBAL_LOCK_ENTRY in "$LOCK"/.[!.]* "$LOCK"/..?* "$LOCK"/*; do
        [ -e "$GLOBAL_LOCK_ENTRY" ] || [ -L "$GLOBAL_LOCK_ENTRY" ] || continue
        case "$GLOBAL_LOCK_ENTRY" in
            "$OWNER") regular "$GLOBAL_LOCK_ENTRY" || return 1 ;;
            "$CLAIM_DIR") [ -d "$GLOBAL_LOCK_ENTRY" ] && [ ! -L "$GLOBAL_LOCK_ENTRY" ] || return 1 ;;
            *) return 1 ;;
        esac
    done
    OWNER_SCHEMA=$(field "$OWNER" schema) || return 1
    case "$PENDING_VERSION:$OWNER_SCHEMA" in
        1:dcentos.s19k-track1-runtime-lock/v7) ;;
        2:dcentos.s19k-track1-runtime-lock/v8) ;;
        install-custody:dcentos.s19k-track1-runtime-lock/v8) ;;
        receiptless:dcentos.s19k-track1-runtime-lock/v9) ;;
        startup-prefix:dcentos.s19k-track1-runtime-lock/v10) ;;
        *) return 1 ;;
    esac
    if [ "$PENDING_VERSION" = startup-prefix ]; then
        require_ordered_keys "$OWNER" schema owner_kind trial_dir runner_sha256 runner_bytes \
            custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
            stock_restart_helper_bytes live_identity_sha256 active_sha256 active_bytes \
            transaction_id highest_phase source_receipt_sha256 safeoff_receipt_sha256 || return 1
        [ "$(field "$OWNER" owner_kind)" = startup-prefix-stock-restart-pending ] \
            && [ "$(field "$OWNER" transaction_id)" = "$(field "$PENDING_RECORD" transaction_id)" ] \
            && [ "$(field "$OWNER" highest_phase)" = "$(field "$PENDING_RECORD" highest_phase)" ] \
            && [ "$(field "$OWNER" source_receipt_sha256)" = "$SOURCE_SHA" ] || return 1
    elif [ "$PENDING_VERSION" = receiptless ]; then
        require_ordered_keys "$OWNER" schema owner_kind trial_dir runner_sha256 runner_bytes \
            custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
            stock_restart_helper_bytes live_identity_sha256 active_sha256 \
            active_bytes safeoff_receipt_sha256 || return 1
        [ "$(field "$OWNER" owner_kind)" = receiptless-stock-restart-pending ] || return 1
    else
        require_ordered_keys "$OWNER" schema owner_kind trial_dir runner_sha256 runner_bytes \
            custody_observer_sha256 custody_observer_bytes stock_restart_helper_sha256 \
            stock_restart_helper_bytes live_identity_sha256 active_sha256 \
            active_bytes source_runtime_active_sha256 safeoff_receipt_sha256 \
            $(case "$PENDING_VERSION" in 2|install-custody) printf '%s' terminal_handoff_receipt_sha256 ;; esac) \
            || return 1
        [ "$(field "$OWNER" owner_kind)" = stock-restart-pending ] || return 1
    fi
    [ "$(field "$OWNER" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$OWNER" runner_sha256):$(field "$OWNER" runner_bytes)" = "$RUNNER_SHA:$RUNNER_BYTES" ] \
        && [ "$(field "$OWNER" custody_observer_sha256):$(field "$OWNER" custody_observer_bytes)" = "$CUSTODY_SHA:$CUSTODY_BYTES" ] \
        && [ "$(field "$OWNER" stock_restart_helper_sha256):$(field "$OWNER" stock_restart_helper_bytes)" = "$HELPER_SHA:$HELPER_BYTES" ] \
        && [ "$(field "$OWNER" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$OWNER" active_sha256):$(field "$OWNER" active_bytes)" = "$PENDING_SHA:$PENDING_BYTES" ] \
        && [ "$(field "$OWNER" safeoff_receipt_sha256)" = "$SAFE_SHA" ] || return 1
    [ "$PENDING_VERSION" = receiptless ] || [ "$PENDING_VERSION" = startup-prefix ] \
        || [ "$(field "$OWNER" source_runtime_active_sha256)" = "$PRE_SHA" ] || return 1
    [ "$PENDING_VERSION" != 2 ] && [ "$PENDING_VERSION" != install-custody ] \
        || [ "$(field "$OWNER" terminal_handoff_receipt_sha256)" = "$TERMINAL_HANDOFF_SHA" ]
}

fresh_identity_matches() {
    IDENTITY_DEPLOY_MODE=mining-on-passthrough
    [ "$PENDING_VERSION" != install-custody ] || IDENTITY_DEPLOY_MODE=install-custody-safeoff
    IDENTITY_OUT=$("$BUSYBOX" env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "$RUNNER" identity "$TRIAL_DIR" am3-s19k "$IDENTITY_DEPLOY_MODE" \
        "$BIN_SHA" "$BIN_BYTES" "$CFG_SHA" "$CFG_BYTES" \
        "$RUNNER_SHA" "$RUNNER_BYTES" "$CUSTODY_SHA" "$CUSTODY_BYTES" \
        "$HELPER_SHA" "$HELPER_BYTES" 2>/dev/null) || return 1
    EXPECTED_IDENTITY="DCENT_S19K_LIVE_IDENTITY schema=dcentos.s19k-braiins-live-identity/v2 profile=$IDENTITY_PROFILE sha256=$IDENTITY_SHA model_sha256=$IDENTITY_MODEL_SHA board_names=$IDENTITY_NAMES physical_addresses=$IDENTITY_ADDRESSES eeprom=$IDENTITY_EEPROM"
    [ "$IDENTITY_OUT" = "$EXPECTED_IDENTITY" ]
}

pending_gpio_safeoff_is_exact() {
    if [ "$PENDING_VERSION" = install-custody ]; then
        # The install contract neither asserts nor relies on reset GPIOs.
        [ "$(capture_gpio437)" = 437:1 ]
    else
        PENDING_GPIO=$(capture_gpio) || return 1
        [ "$PENDING_GPIO" = 437:1,454:0,455:0,456:0 ]
    fi
}

prestart_core_predicates() {
    admit_pending && admit_lock_owner \
        && verify_file "$HELPER" "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES" \
        && verify_file "$S99" "$AUDITED_S99_SHA" "$AUDITED_S99_BYTES" \
        && launcher_runtime_is_exact \
        && lifetime_is_gone_at "$PROC_ROOT" "$WRITER_PID" "$WRITER_START" \
        && ! any_track1_wrapper && ! any_dcentrald && stock_processes_absent \
        && stock_start_launchers_absent \
        && no_watchdog_fd && [ ! -e "$PIDFILE" ] && [ ! -L "$PIDFILE" ] \
        && pending_gpio_safeoff_is_exact \
        && fresh_identity_matches
}
prestart_predicates() {
    prestart_core_predicates && admit_current_invocation_owner
}

capture_log_boundary() {
    regular "$LOG" || return 1
    exec 8<> "$LOG" || return 1
    LOG_FD=/proc/$$/fd/8
    LOG_FDINFO=/proc/$$/fdinfo/8
    LOG_RESOLVED_NOW=$(readlink "$LOG_FD" 2>/dev/null) || return 1
    [ "$LOG_RESOLVED_NOW" = "$LOG_RESOLVED" ] || return 1
    LOG_MNT_ID_NOW=$(sed -n 's/^mnt_id:[ \t]*//p' "$LOG_FDINFO")
    valid_positive "$LOG_MNT_ID_NOW" || return 1
    if [ "$REQUIRE_EXACT_LOG_MOUNT" = true ]; then
        [ "$LOG_MNT_ID_NOW" = "$LOG_MOUNT_ID" ] \
            && "$BUSYBOX" awk -v id="$LOG_MOUNT_ID" -v root="$LOG_MOUNT_ROOT" \
                -v mount="$LOG_MOUNT_POINT" -v fs="$LOG_MOUNT_FS" -v source="$LOG_MOUNT_SOURCE" \
                '$1 == id && $4 == root && $5 == mount { for (i=6; i<=NF; i++) if ($i == "-" && $(i+1) == fs && $(i+2) == source) ok=1 } END { exit !ok }' \
                /proc/$$/mountinfo || return 1
    fi
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    [ "$#" -ge 6 ] || return 1
    LOG_INODE=$1 LOG_MODE=$2 LOG_NLINK=$3 LOG_UID=$4 LOG_GID=$5 LOG_BYTES_BEFORE=$6
    valid_positive "$LOG_INODE" && valid_positive "$LOG_NLINK" \
        && valid_uint "$LOG_UID" && valid_uint "$LOG_GID" \
        && valid_positive "$LOG_BYTES_BEFORE" || return 1
    [ "$REQUIRE_EXACT_LOG_METADATA" != true ] \
        || { [ "$LOG_MODE" = -rw------- ] && [ "$LOG_NLINK:$LOG_UID:$LOG_GID" = 1:0:0 ]; } \
        || return 1
    LAST_BYTE_SHA=$("$BUSYBOX" tail -c 1 "$LOG_FD" | "$BUSYBOX" sha256sum | "$BUSYBOX" awk '{print $1}')
    [ "$LAST_BYTE_SHA" = 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b ]
}
open_bound_log_fd() {
    exec 8<> "$LOG" || return 1
    LOG_FD=/proc/$$/fd/8
    LOG_FDINFO=/proc/$$/fdinfo/8
    log_fd_tuple_is_unchanged
}
log_fd_tuple_is_unchanged() {
    [ -e "$LOG_FD" ] || [ -L "$LOG_FD" ] || return 1
    [ "$(readlink "$LOG_FD" 2>/dev/null)" = "$LOG_RESOLVED" ] \
        && [ "$(sed -n 's/^mnt_id:[ \t]*//p' "$LOG_FDINFO")" = "$LOG_MNT_ID_NOW" ] || return 1
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    [ "$#" -ge 6 ] \
        && [ "$1:$2:$3:$4:$5" = "$LOG_INODE:$LOG_MODE:$LOG_NLINK:$LOG_UID:$LOG_GID" ]
}
log_boundary_unchanged() {
    log_fd_tuple_is_unchanged || return 1
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    [ "$6" = "$LOG_BYTES_BEFORE" ]
}

write_claim() {
    CLAIM_PHASE=$1
    CLAIM_TMP="$CLAIM_DIR/.owner.$SELF_PID.$SELF_START"
    [ ! -e "$CLAIM_TMP" ] && [ ! -L "$CLAIM_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-stock-restart-claim/v3\n'
        printf 'phase=%s\n' "$CLAIM_PHASE"
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'helper_sha256=%s\n' "$EXPECTED_HELPER_SHA"
        printf 'helper_bytes=%s\n' "$EXPECTED_HELPER_BYTES"
        printf 'pending_sha256=%s\n' "$PENDING_SHA"
        printf 'pending_bytes=%s\n' "$PENDING_BYTES"
        printf 'source_kind=%s\n' "$SOURCE_KIND"
        printf 'source_sha256=%s\n' "$SOURCE_SHA"
        printf 'source_bytes=%s\n' "$SOURCE_BYTES"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFE_SHA"
        printf 'live_identity_sha256=%s\n' "$IDENTITY_SHA"
        printf 'stock_init_sha256=%s\n' "$AUDITED_S99_SHA"
        printf 'stock_init_bytes=%s\n' "$AUDITED_S99_BYTES"
        printf 'log_resolved=%s\n' "$LOG_RESOLVED"
        printf 'log_mount_id=%s\n' "$LOG_MNT_ID_NOW"
        printf 'log_inode=%s\n' "$LOG_INODE"
        printf 'log_mode=%s\n' "$LOG_MODE"
        printf 'log_nlink=%s\n' "$LOG_NLINK"
        printf 'log_uid=%s\n' "$LOG_UID"
        printf 'log_gid=%s\n' "$LOG_GID"
        printf 'log_bytes_before=%s\n' "$LOG_BYTES_BEFORE"
        printf 'start_command=/etc/init.d/S99bosminer:start-only\n'
    } > "$CLAIM_TMP" || return 1
    chmod 600 "$CLAIM_TMP" || return 1
    "$BUSYBOX" sync -d "$CLAIM_TMP" || return 1
    mv -f "$CLAIM_TMP" "$CLAIM" || return 1
    "$BUSYBOX" sync -f "$CLAIM_DIR" || return 1
}
admit_claim() {
    regular "$CLAIM" || return 1
    require_ordered_keys "$CLAIM" schema phase trial_dir helper_sha256 helper_bytes pending_sha256 \
        pending_bytes source_kind source_sha256 source_bytes safeoff_receipt_sha256 live_identity_sha256 \
        stock_init_sha256 stock_init_bytes log_resolved log_mount_id log_inode log_mode log_nlink \
        log_uid log_gid log_bytes_before \
        start_command || return 1
    CLAIM_PHASE=$(field "$CLAIM" phase)
    case "$CLAIM_PHASE" in prestart-admitted|start-invocation-committed) ;; *) return 1 ;; esac
    [ "$(field "$CLAIM" schema)" = dcentos.s19k-stock-restart-claim/v3 ] \
        && [ "$(field "$CLAIM" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$CLAIM" helper_sha256):$(field "$CLAIM" helper_bytes)" = "$EXPECTED_HELPER_SHA:$EXPECTED_HELPER_BYTES" ] \
        && [ "$(field "$CLAIM" pending_sha256):$(field "$CLAIM" pending_bytes)" = "$PENDING_SHA:$PENDING_BYTES" ] \
        && [ "$(field "$CLAIM" source_kind):$(field "$CLAIM" source_sha256):$(field "$CLAIM" source_bytes)" = "$SOURCE_KIND:$SOURCE_SHA:$SOURCE_BYTES" ] \
        && [ "$(field "$CLAIM" safeoff_receipt_sha256)" = "$SAFE_SHA" ] \
        && [ "$(field "$CLAIM" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$CLAIM" stock_init_sha256):$(field "$CLAIM" stock_init_bytes)" = "$AUDITED_S99_SHA:$AUDITED_S99_BYTES" ] \
        && [ "$(field "$CLAIM" start_command)" = /etc/init.d/S99bosminer:start-only ] || return 1
    LOG_RESOLVED_CLAIM=$(field "$CLAIM" log_resolved)
    LOG_MNT_ID_NOW=$(field "$CLAIM" log_mount_id)
    LOG_INODE=$(field "$CLAIM" log_inode)
    LOG_MODE=$(field "$CLAIM" log_mode)
    LOG_NLINK=$(field "$CLAIM" log_nlink)
    LOG_UID=$(field "$CLAIM" log_uid)
    LOG_GID=$(field "$CLAIM" log_gid)
    LOG_BYTES_BEFORE=$(field "$CLAIM" log_bytes_before)
    [ "$LOG_RESOLVED_CLAIM" = "$LOG_RESOLVED" ] \
        && valid_positive "$LOG_MNT_ID_NOW" && valid_positive "$LOG_INODE" \
        && valid_positive "$LOG_NLINK" && valid_uint "$LOG_UID" && valid_uint "$LOG_GID" \
        && valid_positive "$LOG_BYTES_BEFORE" \
        && { [ "$REQUIRE_EXACT_LOG_METADATA" != true ] \
            || [ "$LOG_MODE:$LOG_NLINK:$LOG_UID:$LOG_GID" = -rw-------:1:0:0 ]; } \
        && open_bound_log_fd
}

preclaim_directory_is_recoverable() {
    [ -d "$CLAIM_DIR" ] && [ ! -L "$CLAIM_DIR" ] \
        && [ ! -e "$CLAIM" ] && [ ! -L "$CLAIM" ] || return 1
    PRECLAIM_SCRATCH=
    for PRECLAIM_ENTRY in "$CLAIM_DIR"/.[!.]* "$CLAIM_DIR"/..?* "$CLAIM_DIR"/*; do
        [ -e "$PRECLAIM_ENTRY" ] || [ -L "$PRECLAIM_ENTRY" ] || continue
        PRECLAIM_NAME=${PRECLAIM_ENTRY##*/}
        case "$PRECLAIM_NAME" in
            .owner.*)
                PRECLAIM_PID=${PRECLAIM_NAME#.owner.}
                valid_positive "$PRECLAIM_PID" && regular "$PRECLAIM_ENTRY" \
                    && [ -z "$PRECLAIM_SCRATCH" ] || return 1
                PRECLAIM_SCRATCH=$PRECLAIM_ENTRY
                ;;
            *) return 1 ;;
        esac
    done
}

recover_preclaim_directory() {
    preclaim_directory_is_recoverable \
        && [ "$PENDING_RECORD" = "$ACTIVE" ] \
        && [ ! -e "$TERMINAL" ] && [ ! -L "$TERMINAL" ] \
        && [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] \
        && [ ! -e "$STOCK_TREE_EVIDENCE" ] && [ ! -L "$STOCK_TREE_EVIDENCE" ] \
        && [ ! -e "$WATCHDOG_FD_EVIDENCE" ] && [ ! -L "$WATCHDOG_FD_EVIDENCE" ] \
        && [ ! -e "$LOG_WINDOW_EVIDENCE" ] && [ ! -L "$LOG_WINDOW_EVIDENCE" ] \
        && prestart_predicates || return 1
    if [ -n "$PRECLAIM_SCRATCH" ]; then
        rm -f "$PRECLAIM_SCRATCH" || return 1
    fi
    rmdir "$CLAIM_DIR" || return 1
    prestart_predicates
}

neutral_invoke_lock_is_exact() {
    [ -d "$INVOKE_LOCK" ] && [ ! -L "$INVOKE_LOCK" ] || return 1
    if [ "$REQUIRE_NEUTRAL_MUTEX_MODE" = true ]; then
        set -- $("$BUSYBOX" ls -ldn "$INVOKE_LOCK" 2>/dev/null) || return 1
        [ "$#" -ge 4 ] && [ "$1:$3:$4" = drwx------:0:0 ] || return 1
    fi
    for INVOKE_LOCK_ENTRY in "$INVOKE_LOCK"/.[!.]* "$INVOKE_LOCK"/..?* "$INVOKE_LOCK"/*; do
        [ -e "$INVOKE_LOCK_ENTRY" ] || [ -L "$INVOKE_LOCK_ENTRY" ] || continue
        [ "$INVOKE_LOCK_ENTRY" = "$INVOKE_OWNER" ] && regular "$INVOKE_LOCK_ENTRY" || return 1
    done
}

claim_metadata() {
    if regular "$CLAIM"; then
        admit_claim || return 1
        INVOKE_PREDECESSOR_SHA=$(sha256sum "$CLAIM" | awk '{print $1}')
        INVOKE_PREDECESSOR_BYTES=$(wc -c < "$CLAIM" | tr -d ' \t\r\n')
        INVOKE_PREDECESSOR_PHASE=$CLAIM_PHASE
    elif regular "$TERMINAL"; then
        INVOKE_PREDECESSOR_SHA=$(sha256sum "$TERMINAL" | awk '{print $1}')
        INVOKE_PREDECESSOR_BYTES=$(wc -c < "$TERMINAL" | tr -d ' \t\r\n')
        INVOKE_PREDECESSOR_PHASE=terminal-published
    elif [ ! -e "$CLAIM" ] && [ ! -L "$CLAIM" ]; then
        INVOKE_PREDECESSOR_SHA=absent
        INVOKE_PREDECESSOR_BYTES=0
        INVOKE_PREDECESSOR_PHASE=absent
    else
        return 1
    fi
    case "$INVOKE_PREDECESSOR_PHASE" in
        absent|prestart-admitted) INVOKE_EXECUTION_MODE=start-authorized ;;
        start-invocation-committed|terminal-published) INVOKE_EXECUTION_MODE=prove-only ;;
        *) return 1 ;;
    esac
}

write_invocation_owner_record() {
    INVOKE_RECORD_PATH=$1
    {
        printf 'schema=dcentos.s19k-stock-restart-helper-owner/v1\n'
        printf 'owner_pid=%s\nowner_start=%s\nowner_exe=%s\n' "$SELF_PID" "$SELF_START" "$SELF_EXE"
        printf 'trial_dir=%s\n' "$TRIAL_DIR"
        printf 'helper_sha256=%s\nhelper_bytes=%s\n' "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES"
        printf 'pending_sha256=%s\npending_bytes=%s\n' "$PENDING_SHA" "$PENDING_BYTES"
        printf 'predecessor_claim_sha256=%s\npredecessor_claim_bytes=%s\npredecessor_claim_phase=%s\n' \
            "$INVOKE_PREDECESSOR_SHA" "$INVOKE_PREDECESSOR_BYTES" "$INVOKE_PREDECESSOR_PHASE"
        printf 'execution_mode=%s\n' "$INVOKE_EXECUTION_MODE"
        printf 'publication=no-clobber-hard-link-after-busybox-sync-d\n'
    } > "$INVOKE_RECORD_PATH" || return 1
    chmod 600 "$INVOKE_RECORD_PATH" || return 1
    "$BUSYBOX" sync -d "$INVOKE_RECORD_PATH" || return 1
}

admit_invocation_owner_at() {
    INVOKE_RECORD=$1
    regular "$INVOKE_RECORD" \
        && require_ordered_keys "$INVOKE_RECORD" schema owner_pid owner_start owner_exe trial_dir \
            helper_sha256 helper_bytes pending_sha256 pending_bytes predecessor_claim_sha256 \
            predecessor_claim_bytes predecessor_claim_phase execution_mode publication \
        && [ "$(field "$INVOKE_RECORD" schema)" = dcentos.s19k-stock-restart-helper-owner/v1 ] \
        && valid_positive "$(field "$INVOKE_RECORD" owner_pid)" \
        && valid_positive "$(field "$INVOKE_RECORD" owner_start)" \
        && [ -n "$(field "$INVOKE_RECORD" owner_exe)" ] \
        && [ "$(field "$INVOKE_RECORD" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$INVOKE_RECORD" helper_sha256):$(field "$INVOKE_RECORD" helper_bytes)" = "$EXPECTED_HELPER_SHA:$EXPECTED_HELPER_BYTES" ] \
        && [ "$(field "$INVOKE_RECORD" pending_sha256):$(field "$INVOKE_RECORD" pending_bytes)" = "$PENDING_SHA:$PENDING_BYTES" ] \
        && [ "$(field "$INVOKE_RECORD" publication)" = no-clobber-hard-link-after-busybox-sync-d ] || return 1
    INVOKE_RECORD_PHASE=$(field "$INVOKE_RECORD" predecessor_claim_phase)
    INVOKE_RECORD_CLAIM_SHA=$(field "$INVOKE_RECORD" predecessor_claim_sha256)
    INVOKE_RECORD_CLAIM_BYTES=$(field "$INVOKE_RECORD" predecessor_claim_bytes)
    INVOKE_RECORD_MODE=$(field "$INVOKE_RECORD" execution_mode)
    case "$INVOKE_RECORD_PHASE:$INVOKE_RECORD_CLAIM_SHA:$INVOKE_RECORD_CLAIM_BYTES:$INVOKE_RECORD_MODE" in
        absent:absent:0:start-authorized) ;;
        prestart-admitted:*:*:start-authorized|start-invocation-committed:*:*:prove-only|terminal-published:*:*:prove-only)
            valid_sha "$INVOKE_RECORD_CLAIM_SHA" && valid_positive "$INVOKE_RECORD_CLAIM_BYTES" || return 1
            ;;
        *) return 1 ;;
    esac
}

admit_current_invocation_owner() {
    neutral_invoke_lock_is_exact && admit_invocation_owner_at "$INVOKE_OWNER" || return 1
    [ "$(field "$INVOKE_OWNER" owner_pid):$(field "$INVOKE_OWNER" owner_start):$(field "$INVOKE_OWNER" owner_exe)" \
        = "$SELF_PID:$SELF_START:$SELF_EXE" ] || return 1
    claim_metadata || return 1
    OWNER_PREDECESSOR_PHASE=$(field "$INVOKE_OWNER" predecessor_claim_phase)
    case "$OWNER_PREDECESSOR_PHASE:$INVOKE_PREDECESSOR_PHASE" in
        absent:absent|absent:prestart-admitted|absent:start-invocation-committed|absent:terminal-published|\
        prestart-admitted:prestart-admitted|prestart-admitted:start-invocation-committed|prestart-admitted:terminal-published|\
        start-invocation-committed:terminal-published) ;;
        start-invocation-committed:start-invocation-committed|terminal-published:terminal-published)
            [ "$(field "$INVOKE_OWNER" predecessor_claim_sha256):$(field "$INVOKE_OWNER" predecessor_claim_bytes)" \
                = "$INVOKE_PREDECESSOR_SHA:$INVOKE_PREDECESSOR_BYTES" ] || return 1
            ;;
        *) return 1 ;;
    esac
}

stale_invocation_record_is_dead() {
    STALE_RECORD=$1
    admit_invocation_owner_at "$STALE_RECORD" || return 1
    STALE_PID=$(field "$STALE_RECORD" owner_pid)
    STALE_START=$(field "$STALE_RECORD" owner_start)
    STALE_EXE=$(field "$STALE_RECORD" owner_exe)
    STALE_OBSERVATION_ONE=$(invocation_lifetime_observation "$STALE_PID" "$STALE_START" "$STALE_EXE") \
        || return 1
    STALE_OBSERVATION_TWO=$(invocation_lifetime_observation "$STALE_PID" "$STALE_START" "$STALE_EXE") \
        || return 1
    [ "$STALE_OBSERVATION_ONE" = "$STALE_OBSERVATION_TWO" ] || return 1
    case "$STALE_OBSERVATION_TWO" in
        absent|different-lifetime:*) return 0 ;;
        *) return 1 ;;
    esac
}

invocation_lifetime_observation() {
    OBS_PID=$1 OBS_START=$2 OBS_EXE=$3
    if [ ! -d "/proc/$OBS_PID" ]; then
        printf 'absent\n'
        return
    fi
    OBS_STAT=$(cat "/proc/$OBS_PID/stat" 2>/dev/null) || {
        [ ! -d "/proc/$OBS_PID" ] && { printf 'absent\n'; return; }
        return 1
    }
    case "$OBS_STAT" in *') '*) ;; *) return 1 ;; esac
    OBS_REST=${OBS_STAT##*) }
    set -- $OBS_REST
    [ "$#" -ge 20 ] && valid_positive "${20}" || return 1
    case "$1" in Z|X|x|'') return 1 ;; esac
    if [ "${20}" != "$OBS_START" ]; then
        printf 'different-lifetime:%s\n' "${20}"
        return
    fi
    OBSERVED_EXE=$(readlink "/proc/$OBS_PID/exe" 2>/dev/null) || return 1
    [ "$OBSERVED_EXE" = "$OBS_EXE" ] || return 1
    printf 'exact-live:%s:%s\n' "${20}" "$OBSERVED_EXE"
}

postcommit_takeover_predicates() {
    admit_pending && admit_lock_owner \
        && verify_file "$HELPER" "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES" \
        && verify_file "$S99" "$AUDITED_S99_SHA" "$AUDITED_S99_BYTES" \
        && launcher_runtime_is_exact \
        && lifetime_is_gone_at "$PROC_ROOT" "$WRITER_PID" "$WRITER_START" \
        && ! any_track1_wrapper && ! any_dcentrald && fresh_identity_matches
}

recover_or_refuse_invocation_residue() {
    INVOKE_SCRATCH=
    for INVOKE_ENTRY in "$TRIAL_DIR"/.stock_restart_invocation_owner.*; do
        [ -e "$INVOKE_ENTRY" ] || [ -L "$INVOKE_ENTRY" ] || continue
        regular "$INVOKE_ENTRY" && [ -z "$INVOKE_SCRATCH" ] || return 1
        INVOKE_SCRATCH=$INVOKE_ENTRY
    done
    [ -n "$INVOKE_SCRATCH" ] || return 0
    stale_invocation_record_is_dead "$INVOKE_SCRATCH" || return 1
    claim_metadata || return 1
    case "$INVOKE_PREDECESSOR_PHASE" in
        absent|prestart-admitted) prestart_core_predicates ;;
        start-invocation-committed) postcommit_takeover_predicates ;;
        terminal-published) terminal_takeover_predicates ;;
        *) return 1 ;;
    esac || return 1
    stale_invocation_record_is_dead "$INVOKE_SCRATCH" || return 1
    rm -f "$INVOKE_SCRATCH" || return 1
}

acquire_invocation_owner() {
    SELF_PID=$$
    SELF_STAT=$(cat /proc/$$/stat 2>/dev/null) || return 1
    case "$SELF_STAT" in *') '*) ;; *) return 1 ;; esac
    SELF_REST=${SELF_STAT##*) }
    set -- $SELF_REST
    [ "$#" -ge 20 ] && valid_positive "${20}" || return 1
    SELF_START=${20}
    SELF_EXE=$(readlink /proc/$$/exe 2>/dev/null) || return 1
    [ -n "$SELF_EXE" ] || return 1
    if [ -e "$INVOKE_OWNER" ] || [ -L "$INVOKE_OWNER" ]; then
        stale_invocation_record_is_dead "$INVOKE_OWNER" || return 1
        claim_metadata || return 1
        case "$INVOKE_PREDECESSOR_PHASE" in
            absent|prestart-admitted) prestart_core_predicates ;;
            start-invocation-committed) postcommit_takeover_predicates ;;
            terminal-published) terminal_takeover_predicates ;;
            *) return 1 ;;
        esac || return 1
        stale_invocation_record_is_dead "$INVOKE_OWNER" || return 1
        rm -f "$INVOKE_OWNER" || return 1
        rmdir "$INVOKE_LOCK" || return 1
    fi
    if [ ! -e "$INVOKE_LOCK" ] && [ ! -L "$INVOKE_LOCK" ]; then
        mkdir -m 700 "$INVOKE_LOCK" 2>/dev/null || true
    fi
    neutral_invoke_lock_is_exact || return 1
    recover_or_refuse_invocation_residue || return 1
    claim_metadata || return 1
    INVOKE_SCRATCH="$TRIAL_DIR/.stock_restart_invocation_owner.$SELF_PID.$SELF_START"
    [ ! -e "$INVOKE_SCRATCH" ] && [ ! -L "$INVOKE_SCRATCH" ] || return 1
    write_invocation_owner_record "$INVOKE_SCRATCH" || return 1
    ln "$INVOKE_SCRATCH" "$INVOKE_OWNER" 2>/dev/null || { rm -f "$INVOKE_SCRATCH"; return 1; }
    rm -f "$INVOKE_SCRATCH" || return 1
    "$BUSYBOX" sync -f "$INVOKE_LOCK" || return 1
    admit_current_invocation_owner \
        && live_process_matches_at /proc "$SELF_PID" "$SELF_START" "$SELF_EXE" \
        && admit_current_invocation_owner
}

capture_stock_tree() {
    "$BUSYBOX" env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "$CUSTODY" capture "$PROC_ROOT" "$PIDFILE" 2>/dev/null
}
stock_tree_field() {
    printf '%s\n' "$STOCK_TREE" | sed -n "s/^$1=//p"
}
process_stat_tuple() {
    PROCESS_PID=$1
    PROCESS_STAT=$(cat "$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/stat" 2>/dev/null) || return 1
    case "$PROCESS_STAT" in *') '*) ;; *) return 1 ;; esac
    PROCESS_REST=${PROCESS_STAT##*) }
    set -- $PROCESS_REST
    [ "$#" -ge 20 ] || return 1
    case "$1" in Z|X|x|'') return 1 ;; esac
    valid_positive "$2" && valid_positive "$3" && valid_positive "$4" && valid_positive "${20}" || return 1
    printf '%s:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" "${20}"
}
process_fd_stdio_is_null() {
    PROCESS_PID=$1
    for STD_FD in 0 1 2; do
        [ "$(readlink "$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/fd/$STD_FD" 2>/dev/null)" = /dev/null ] || return 1
    done
}
process_runtime_is_stock_shaped() {
    PROCESS_PID=$1 EXPECTED_EXE=$2
    [ "$(readlink "$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/exe" 2>/dev/null)" = "$EXPECTED_EXE" ] \
        && [ "$(readlink "$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/cwd" 2>/dev/null)" = / ] \
        && [ "$(grep -c '^Umask:[[:space:]]*0022$' "$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/status" 2>/dev/null || true)" -eq 1 ] \
        && process_fd_stdio_is_null "$PROCESS_PID"
}
process_env_has_exact_boot_stock_set() {
    PROCESS_PID=$1 PROCESS_KIND=$2
    PROCESS_ENV="$PROC_ROOT/$PROCESS_PID/task/$PROCESS_PID/environ"
    regular "$PROCESS_ENV" || return 1
    PROCESS_ENV_LINES=$(cmdline_lines "$PROCESS_ENV") || return 1
    case "$PROCESS_KIND" in
        supervisor) EXPECTED_ENV_COUNT=12 ;;
        bosminer) EXPECTED_ENV_COUNT=13 ;;
        *) return 1 ;;
    esac
    [ "$(printf '%s\n' "$PROCESS_ENV_LINES" | wc -l | tr -d ' \t\r\n')" = "$EXPECTED_ENV_COUNT" ] || return 1
    for EXPECTED_ENV in \
        CONSOLE=/dev/console HOME=/ INIT_VERSION=sysvinit-2.9n \
        PATH=/sbin:/usr/sbin:/bin:/usr/bin PREVLEVEL=N PWD=/ RUNLEVEL=3 \
        SHELL=/bin/sh SHLVL=3 TERM=linux jtag=disable \
        'logo=,loaded,androidboot.selinux=enforcing'; do
        [ "$(printf '%s\n' "$PROCESS_ENV_LINES" | grep -Fxc "$EXPECTED_ENV")" -eq 1 ] || return 1
    done
    if [ "$PROCESS_KIND" = bosminer ]; then
        [ "$(printf '%s\n' "$PROCESS_ENV_LINES" | grep -Fxc '   =/usr/bin/bos-tools')" -eq 1 ] || return 1
    fi
}
pidfile_matches_fresh_supervisor() {
    regular "$PIDFILE" || return 1
    set -- $("$BUSYBOX" ls -liLnL "$PIDFILE" 2>/dev/null) || return 1
    [ "$#" -ge 6 ] || return 1
    PIDFILE_INODE=$1 PIDFILE_MODE=$2 PIDFILE_NLINK=$3 PIDFILE_UID=$4 PIDFILE_GID=$5 PIDFILE_BYTES=$6
    { [ "$REQUIRE_EXACT_PIDFILE_METADATA" != true ] \
        || [ "$PIDFILE_MODE:$PIDFILE_NLINK:$PIDFILE_UID:$PIDFILE_GID" = -rw-r--r--:1:0:0 ]; } \
        && [ "$(cat "$PIDFILE" 2>/dev/null)" = "$STOCK_SUPERVISOR_PID" ] \
        && [ "$PIDFILE_BYTES" = "$((${#STOCK_SUPERVISOR_PID} + 1))" ] || return 1
    PIDFILE_SHA=$(sha256sum "$PIDFILE" | awk '{print $1}')
    [ "$PIDFILE_SHA" = "$(printf '%s\n' "$STOCK_SUPERVISOR_PID" | sha256sum | awk '{print $1}')" ]
}
poststart_stock_shape_is_exact() {
    SUPERVISOR_STAT=$(process_stat_tuple "$STOCK_SUPERVISOR_PID") || return 1
    CHILD_STAT=$(process_stat_tuple "$STOCK_CHILD_PID") || return 1
    OLD_IFS=$IFS; IFS=:
    set -- $SUPERVISOR_STAT
    IFS=$OLD_IFS
    SUP_STATE=$1 SUP_PPID=$2 SUP_PGRP=$3 SUP_SESSION=$4 SUP_START=$5
    OLD_IFS=$IFS; IFS=:
    set -- $CHILD_STAT
    IFS=$OLD_IFS
    CHILD_STATE=$1 CHILD_PPID=$2 CHILD_PGRP=$3 CHILD_SESSION=$4 CHILD_START=$5
    [ "$SUP_PPID" = 1 ] \
        && [ "$SUP_PGRP" = "$SUP_SESSION" ] \
        && [ "$SUP_PGRP" != "$STOCK_SUPERVISOR_PID" ] \
        && [ "$CHILD_PPID" = "$STOCK_SUPERVISOR_PID" ] \
        && [ "$CHILD_PGRP:$CHILD_SESSION" = "$SUP_PGRP:$SUP_SESSION" ] \
        && [ "$SUP_START" = "$(stock_tree_field supervisor_start)" ] \
        && [ "$CHILD_START" = "$(stock_tree_field child_start)" ] \
        && process_runtime_is_stock_shaped "$STOCK_SUPERVISOR_PID" /usr/bin/bos-tools \
        && process_runtime_is_stock_shaped "$STOCK_CHILD_PID" /usr/bin/bosminer \
        && process_env_has_exact_boot_stock_set "$STOCK_SUPERVISOR_PID" supervisor \
        && process_env_has_exact_boot_stock_set "$STOCK_CHILD_PID" bosminer \
        && pidfile_matches_fresh_supervisor
}
log_window_header_value() {
    LOG_RECORD=$1 LOG_LINE=$2 LOG_KEY=$3
    LOG_HEADER_LINE=$(sed -n "${LOG_LINE}p" "$LOG_RECORD") || return 1
    case "$LOG_HEADER_LINE" in "$LOG_KEY="*) printf '%s\n' "${LOG_HEADER_LINE#*=}" ;; *) return 1 ;; esac
}

admit_log_window_evidence() {
    LOG_RECORD=$1 LOG_SHA=$2 LOG_RECORD_BYTES=$3
    verify_file "$LOG_RECORD" "$LOG_SHA" "$LOG_RECORD_BYTES" || return 1
    [ "$(log_window_header_value "$LOG_RECORD" 1 schema)" = dcentos.s19k-stock-log-window/v1 ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 2 log_resolved)" = "$LOG_RESOLVED" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 3 log_mount_id)" = "$LOG_MNT_ID_NOW" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 4 log_inode)" = "$LOG_INODE" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 5 log_mode)" = "$LOG_MODE" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 6 log_nlink)" = "$LOG_NLINK" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 7 log_uid)" = "$LOG_UID" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 8 log_gid)" = "$LOG_GID" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 9 log_bytes_before)" = "$LOG_BYTES_BEFORE" ] \
        && [ "$(log_window_header_value "$LOG_RECORD" 12 payload_begin)" = exact-stock-log-bytes ] || return 1
    LOG_BYTES_AFTER=$(log_window_header_value "$LOG_RECORD" 10 log_bytes_after) || return 1
    LOG_PAYLOAD_BYTES=$(log_window_header_value "$LOG_RECORD" 11 payload_bytes) || return 1
    valid_positive "$LOG_BYTES_AFTER" && valid_positive "$LOG_PAYLOAD_BYTES" \
        && [ "$LOG_BYTES_AFTER" -gt "$LOG_BYTES_BEFORE" ] \
        && [ "$LOG_PAYLOAD_BYTES" -eq "$((LOG_BYTES_AFTER - LOG_BYTES_BEFORE))" ] || return 1
    LOG_HEADER_BYTES=$(sed -n '1,12p' "$LOG_RECORD" | wc -c | tr -d ' \t\r\n')
    valid_positive "$LOG_HEADER_BYTES" \
        && [ "$LOG_RECORD_BYTES" -eq "$((LOG_HEADER_BYTES + LOG_PAYLOAD_BYTES))" ]
}

publish_log_window_evidence() {
    CLAIM_LOG="$CLAIM_DIR/log_window"
    CLAIM_LOG_TMP="$CLAIM_DIR/.log_window.$SELF_PID.$SELF_START"
    if [ -e "$CLAIM_LOG" ] || [ -L "$CLAIM_LOG" ]; then
        LOG_RECORD_SHA=$(sha256sum "$CLAIM_LOG" | awk '{print $1}')
        LOG_RECORD_BYTES=$(wc -c < "$CLAIM_LOG" | tr -d ' \t\r\n')
        admit_log_window_evidence "$CLAIM_LOG" "$LOG_RECORD_SHA" "$LOG_RECORD_BYTES"
        return
    fi
    [ ! -e "$CLAIM_LOG_TMP" ] && [ ! -L "$CLAIM_LOG_TMP" ] || return 1
    log_fd_tuple_is_unchanged || return 1
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    LOG_BYTES_AFTER=$6
    valid_positive "$LOG_BYTES_AFTER" && [ "$LOG_BYTES_AFTER" -gt "$LOG_BYTES_BEFORE" ] || return 1
    LOG_PAYLOAD_BYTES=$((LOG_BYTES_AFTER - LOG_BYTES_BEFORE))
    {
        printf 'schema=dcentos.s19k-stock-log-window/v1\n'
        printf 'log_resolved=%s\n' "$LOG_RESOLVED"
        printf 'log_mount_id=%s\n' "$LOG_MNT_ID_NOW"
        printf 'log_inode=%s\n' "$LOG_INODE"
        printf 'log_mode=%s\n' "$LOG_MODE"
        printf 'log_nlink=%s\n' "$LOG_NLINK"
        printf 'log_uid=%s\n' "$LOG_UID"
        printf 'log_gid=%s\n' "$LOG_GID"
        printf 'log_bytes_before=%s\n' "$LOG_BYTES_BEFORE"
        printf 'log_bytes_after=%s\n' "$LOG_BYTES_AFTER"
        printf 'payload_bytes=%s\n' "$LOG_PAYLOAD_BYTES"
        printf 'payload_begin=exact-stock-log-bytes\n'
        "$BUSYBOX" dd if="$LOG_FD" bs=1 skip="$LOG_BYTES_BEFORE" count="$LOG_PAYLOAD_BYTES" 2>/dev/null
    } > "$CLAIM_LOG_TMP" || return 1
    chmod 600 "$CLAIM_LOG_TMP" || return 1
    "$BUSYBOX" sync -d "$CLAIM_LOG_TMP" || return 1
    LOG_RECORD_SHA=$(sha256sum "$CLAIM_LOG_TMP" | awk '{print $1}')
    LOG_RECORD_BYTES=$(wc -c < "$CLAIM_LOG_TMP" | tr -d ' \t\r\n')
    admit_log_window_evidence "$CLAIM_LOG_TMP" "$LOG_RECORD_SHA" "$LOG_RECORD_BYTES" || return 1
    ln "$CLAIM_LOG_TMP" "$CLAIM_LOG" || return 1
    "$BUSYBOX" sync -f "$CLAIM_DIR" || return 1
    same_regular_inode "$CLAIM_LOG_TMP" "$CLAIM_LOG" \
        && admit_log_window_evidence "$CLAIM_LOG" "$LOG_RECORD_SHA" "$LOG_RECORD_BYTES" || return 1
    rm -f "$CLAIM_LOG_TMP" || return 1
    [ ! -e "$CLAIM_LOG_TMP" ] && [ ! -L "$CLAIM_LOG_TMP" ]
}

fresh_log_window_is_recovered() {
    publish_log_window_evidence || return 1
    log_fd_tuple_is_unchanged || return 1
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    valid_uint "$6" && [ "$6" -ge "$LOG_BYTES_AFTER" ] || return 1
    grep -Fq 'CHAIN/2: Initializing hashchain' "$CLAIM_DIR/log_window" \
        && grep -Fq 'CHAIN/3: Initializing hashchain' "$CLAIM_DIR/log_window" \
        && grep -Fq 'PSU: Enable' "$CLAIM_DIR/log_window" \
        && grep -Fq -- '--- RESUME ---' "$CLAIM_DIR/log_window" \
        && grep -Fq 'Connected Stratum V1 to:' "$CLAIM_DIR/log_window" \
        && grep -Fq 'mode: FixedSpeed(Speed(100)), min_fans: 0, min_fan_rpm: 2000' "$CLAIM_DIR/log_window" \
        && grep -Fq 'dangerous_temp: 90.0' "$CLAIM_DIR/log_window" \
        && grep -Fq 'max_fans: 4' "$CLAIM_DIR/log_window" \
        && grep -Fq 'Using sensor hb2.73[Lm75BCCnCopy-0] for Inlet temperature monitoring' "$CLAIM_DIR/log_window" \
        && grep -Fq 'Using sensor hb2.77[Lm75BCCnCopy-0] for Outlet temperature monitoring' "$CLAIM_DIR/log_window" \
        && grep -Fq 'Using sensor hb3.74[Lm75BCCnCopy-0] for Inlet temperature monitoring' "$CLAIM_DIR/log_window" \
        && grep -Fq 'Using sensor hb3.78[Lm75BCCnCopy-0] for Outlet temperature monitoring' "$CLAIM_DIR/log_window" \
        && grep -Fq 'CHAIN/2: Monitor watchdog temperature task started' "$CLAIM_DIR/log_window" \
        && grep -Fq 'CHAIN/3: Monitor watchdog temperature task started' "$CLAIM_DIR/log_window" \
        && ! grep -Eq 'CHAIN/[23]: (Init|Start) failed:' "$CLAIM_DIR/log_window" || return 1
    for TEMP_DESCRIPTOR in 'CHAIN/2, address: 73, position: Inlet' \
        'CHAIN/2, address: 77, position: Outlet' \
        'CHAIN/3, address: 74, position: Inlet' \
        'CHAIN/3, address: 78, position: Outlet'; do
        TEMP_LINE=$(grep -F "$TEMP_DESCRIPTOR, temperature:" "$CLAIM_DIR/log_window" | tail -n 1) || return 1
        TEMP_VALUE=$(printf '%s\n' "$TEMP_LINE" | sed -n 's/.*temperature: \([-0-9.][0-9.]*\).*/\1/p')
        [ -n "$TEMP_VALUE" ] \
            && "$BUSYBOX" awk -v value="$TEMP_VALUE" 'BEGIN { exit !(value + 0 >= 0 && value + 0 < 90) }' \
            || return 1
    done
}
poststart_runtime_predicates() {
    admit_pending \
        && verify_file "$HELPER" "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES" \
        && verify_file "$S99" "$AUDITED_S99_SHA" "$AUDITED_S99_BYTES" \
        && launcher_runtime_is_exact \
        && lifetime_is_gone_at "$PROC_ROOT" "$WRITER_PID" "$WRITER_START" \
        && ! any_track1_wrapper && ! any_dcentrald \
        && fresh_identity_matches \
        && [ "$(capture_gpio)" = 437:0,454:0,455:1,456:1 ] || return 1
    STOCK_TREE=$(capture_stock_tree) || return 1
    STOCK_SUPERVISOR_PID=$(stock_tree_field supervisor_pid)
    STOCK_CHILD_PID=$(stock_tree_field child_pid)
    valid_positive "$STOCK_SUPERVISOR_PID" && valid_positive "$STOCK_CHILD_PID" \
        && poststart_stock_shape_is_exact \
        && watchdog_fds_are_absent "$STOCK_SUPERVISOR_PID" "$STOCK_CHILD_PID"
}

poststart_predicates() {
    admit_lock_owner && admit_claim && admit_current_invocation_owner \
        && [ "$CLAIM_PHASE" = start-invocation-committed ] \
        && poststart_runtime_predicates \
        && fresh_log_window_is_recovered \
        && build_watchdog_absence_evidence
}

admit_watchdog_absence_evidence() {
    WATCHDOG_RECORD=$1 WATCHDOG_RECORD_SHA=$2 WATCHDOG_RECORD_BYTES=$3
    EXPECT_WATCHDOG_TREE_SHA=$4 EXPECT_WATCHDOG_TREE_BYTES=$5
    EXPECT_WATCHDOG_LOG_SHA=$6 EXPECT_WATCHDOG_LOG_BYTES=$7
    EXPECT_WATCHDOG_SUPERVISOR=$8 EXPECT_WATCHDOG_BOSMINER=$9
    verify_file "$WATCHDOG_RECORD" "$WATCHDOG_RECORD_SHA" "$WATCHDOG_RECORD_BYTES" \
        && require_ordered_keys "$WATCHDOG_RECORD" schema authority node_watchdog node_watchdog0 \
            matching_watchdog_rdev_fd_count matching_watchdog_rdev_fd_set_sha256 \
            matching_watchdog_rdev_fd_set_bytes all_tid_snapshot_sha256 all_tid_snapshot_bytes \
            stock_supervisor stock_bosminer stock_tree_sha256 stock_tree_bytes \
            log_window_sha256 log_window_bytes internal_monitor_proof \
            live_nonobservation_sha256 live_nonobservation_bytes \
        && [ "$(field "$WATCHDOG_RECORD" schema)" = dcentos.s19k-stock-watchdog-absence/v1 ] \
        && [ "$(field "$WATCHDOG_RECORD" authority)" = bounded-all-tid-hardware-watchdog-absence ] \
        && [ "$(field "$WATCHDOG_RECORD" node_watchdog)" = c---------:1:0:0:10:130 ] \
        && [ "$(field "$WATCHDOG_RECORD" node_watchdog0)" = c---------:1:0:0:249:0 ] \
        && [ "$(field "$WATCHDOG_RECORD" matching_watchdog_rdev_fd_count)" = 0 ] \
        && [ "$(field "$WATCHDOG_RECORD" matching_watchdog_rdev_fd_set_sha256)" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] \
        && [ "$(field "$WATCHDOG_RECORD" matching_watchdog_rdev_fd_set_bytes)" = 0 ] \
        && valid_sha "$(field "$WATCHDOG_RECORD" all_tid_snapshot_sha256)" \
        && valid_positive "$(field "$WATCHDOG_RECORD" all_tid_snapshot_bytes)" \
        && [ "$(field "$WATCHDOG_RECORD" stock_supervisor)" = "$EXPECT_WATCHDOG_SUPERVISOR" ] \
        && [ "$(field "$WATCHDOG_RECORD" stock_bosminer)" = "$EXPECT_WATCHDOG_BOSMINER" ] \
        && [ "$(field "$WATCHDOG_RECORD" stock_tree_sha256):$(field "$WATCHDOG_RECORD" stock_tree_bytes)" = "$EXPECT_WATCHDOG_TREE_SHA:$EXPECT_WATCHDOG_TREE_BYTES" ] \
        && [ "$(field "$WATCHDOG_RECORD" log_window_sha256):$(field "$WATCHDOG_RECORD" log_window_bytes)" = "$EXPECT_WATCHDOG_LOG_SHA:$EXPECT_WATCHDOG_LOG_BYTES" ] \
        && [ "$(field "$WATCHDOG_RECORD" internal_monitor_proof)" = chain2+chain3-temperature-watchdog-tasks+four-sensors+sane-temps ] \
        && [ "$(field "$WATCHDOG_RECORD" live_nonobservation_sha256):$(field "$WATCHDOG_RECORD" live_nonobservation_bytes)" = 24676e15bb15f075345bd8f455a70a800c6c684db3d3fc7683cffc45193afa75:2889847 ]
}

admit_stock_tree_evidence() {
    TREE_FILE=$1 TREE_SHA=$2 TREE_BYTES=$3
    verify_file "$TREE_FILE" "$TREE_SHA" "$TREE_BYTES" \
        && require_ordered_keys "$TREE_FILE" schema authority supervisor_pid supervisor_start \
            supervisor_ppid supervisor_pgrp supervisor_session supervisor_state supervisor_exe \
            supervisor_cmdline_sha256 supervisor_cmdline_bytes child_pid child_start child_ppid \
            child_pgrp child_session child_state child_exe child_cmdline_sha256 child_cmdline_bytes \
            pidfile pidfile_sha256 pidfile_bytes \
        && [ "$(field "$TREE_FILE" schema)" = dcentos.s19k-braiins-supervisor-custody/v1 ] \
        && [ "$(field "$TREE_FILE" authority)" = read-only-process-tree-observation ] \
        && [ "$(field "$TREE_FILE" supervisor_exe)" = /usr/bin/bos-tools ] \
        && [ "$(field "$TREE_FILE" child_exe)" = /usr/bin/bosminer ] \
        && [ "$(field "$TREE_FILE" pidfile)" = "$PIDFILE" ]
}

unresolved_value() {
    if regular "$UNRESOLVED" && [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ]; then
        printf '%s:%s\n' \
            "$(sha256sum "$UNRESOLVED" | awk '{print $1}')" \
            "$(wc -c < "$UNRESOLVED" | tr -d ' \t\r\n')"
    elif regular "$UNRESOLVED_RETIRED" && [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ]; then
        printf '%s:%s\n' \
            "$(sha256sum "$UNRESOLVED_RETIRED" | awk '{print $1}')" \
            "$(wc -c < "$UNRESOLVED_RETIRED" | tr -d ' \t\r\n')"
    elif [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] \
            && [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ]; then
        printf 'absent\n'
    else
        return 1
    fi
}

admit_unresolved_content_at() {
    UNRESOLVED_RECORD=$1
    regular "$UNRESOLVED_RECORD" || return 1
    require_ordered_keys "$UNRESOLVED_RECORD" schema disposition pending_sha256 pending_bytes \
        helper_sha256 helper_bytes claim_sha256 claim_bytes live_identity_sha256 \
        stock_init_sha256 stock_init_bytes start_command start_retry recovery_obligation \
        next_authority dcent_direct_hardware_or_flash_writer stock_restart_mutation || return 1
    valid_sha "$(field "$UNRESOLVED_RECORD" claim_sha256)" \
        && valid_positive "$(field "$UNRESOLVED_RECORD" claim_bytes)" \
        && [ "$(field "$UNRESOLVED_RECORD" schema)" = dcentos.s19k-stock-restart-unresolved/v1 ] \
        && [ "$(field "$UNRESOLVED_RECORD" disposition)" = start-committed-proof-not-reached ] \
        && [ "$(field "$UNRESOLVED_RECORD" pending_sha256):$(field "$UNRESOLVED_RECORD" pending_bytes)" = "$PENDING_SHA:$PENDING_BYTES" ] \
        && [ "$(field "$UNRESOLVED_RECORD" helper_sha256):$(field "$UNRESOLVED_RECORD" helper_bytes)" = "$EXPECTED_HELPER_SHA:$EXPECTED_HELPER_BYTES" ] \
        && [ "$(field "$UNRESOLVED_RECORD" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$UNRESOLVED_RECORD" stock_init_sha256):$(field "$UNRESOLVED_RECORD" stock_init_bytes)" = "$AUDITED_S99_SHA:$AUDITED_S99_BYTES" ] \
        && [ "$(field "$UNRESOLVED_RECORD" start_command)" = /etc/init.d/S99bosminer:start-only ] \
        && [ "$(field "$UNRESOLVED_RECORD" start_retry)" = forbidden ] \
        && [ "$(field "$UNRESOLVED_RECORD" recovery_obligation)" = active+global-lock-retained ] \
        && [ "$(field "$UNRESOLVED_RECORD" next_authority)" = prove-only ] \
        && [ "$(field "$UNRESOLVED_RECORD" dcent_direct_hardware_or_flash_writer)" = false ] \
        && [ "$(field "$UNRESOLVED_RECORD" stock_restart_mutation)" = unknown-committed-stock-start-may-have-appended-persistent-ubifs-log ]
}

admit_unresolved() {
    admit_unresolved_content_at "$UNRESOLVED" || return 1
    CLAIM_SHA=$(sha256sum "$CLAIM" | awk '{print $1}')
    CLAIM_BYTES=$(wc -c < "$CLAIM" | tr -d ' \t\r\n')
    [ "$(field "$UNRESOLVED" claim_sha256):$(field "$UNRESOLVED" claim_bytes)" = "$CLAIM_SHA:$CLAIM_BYTES" ]
}

emit_unresolved_receipt() {
    printf 'schema=dcentos.s19k-stock-restart-unresolved/v1\n'
    printf 'disposition=start-committed-proof-not-reached\n'
    printf 'pending_sha256=%s\n' "$PENDING_SHA"
    printf 'pending_bytes=%s\n' "$PENDING_BYTES"
    printf 'helper_sha256=%s\n' "$EXPECTED_HELPER_SHA"
    printf 'helper_bytes=%s\n' "$EXPECTED_HELPER_BYTES"
    printf 'claim_sha256=%s\n' "$CLAIM_SHA"
    printf 'claim_bytes=%s\n' "$CLAIM_BYTES"
    printf 'live_identity_sha256=%s\n' "$IDENTITY_SHA"
    printf 'stock_init_sha256=%s\n' "$AUDITED_S99_SHA"
    printf 'stock_init_bytes=%s\n' "$AUDITED_S99_BYTES"
    printf 'start_command=/etc/init.d/S99bosminer:start-only\n'
    printf 'start_retry=forbidden\n'
    printf 'recovery_obligation=active+global-lock-retained\n'
    printf 'next_authority=prove-only\n'
    printf 'dcent_direct_hardware_or_flash_writer=false\n'
    printf 'stock_restart_mutation=unknown-committed-stock-start-may-have-appended-persistent-ubifs-log\n'
}

publish_unresolved() {
    if [ -e "$UNRESOLVED" ] || [ -L "$UNRESOLVED" ]; then
        admit_unresolved
        return
    fi
    CLAIM_SHA=$(sha256sum "$CLAIM" | awk '{print $1}')
    CLAIM_BYTES=$(wc -c < "$CLAIM" | tr -d ' \t\r\n')
    UNRESOLVED_TMP="$TRIAL_DIR/.runtime_stock_restart_unresolved.$SELF_PID.$SELF_START"
    [ ! -e "$UNRESOLVED_TMP" ] && [ ! -L "$UNRESOLVED_TMP" ] \
        && [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ] || return 1
    emit_unresolved_receipt > "$UNRESOLVED_TMP" || return 1
    chmod 600 "$UNRESOLVED_TMP" || return 1
    "$BUSYBOX" sync -d "$UNRESOLVED_TMP" || return 1
    ln "$UNRESOLVED_TMP" "$UNRESOLVED" || return 1
    "$BUSYBOX" sync -f "$TRIAL_DIR" || return 1
    same_regular_inode "$UNRESOLVED_TMP" "$UNRESOLVED" && admit_unresolved || return 1
    rm -f "$UNRESOLVED_TMP" || return 1
    transaction_scratches_absent && admit_unresolved
}

publish_terminal() {
    CLAIM_TREE="$CLAIM_DIR/stock_tree"
    CLAIM_TREE_TMP="$CLAIM_DIR/.stock_tree.$SELF_PID.$SELF_START"
    STOCK_TREE_SHA=$(printf '%s\n' "$STOCK_TREE" | sha256sum | awk '{print $1}')
    STOCK_TREE_BYTES=$(printf '%s\n' "$STOCK_TREE" | wc -c | tr -d ' \t\r\n')
    if [ -e "$CLAIM_TREE" ] || [ -L "$CLAIM_TREE" ]; then
        admit_stock_tree_evidence "$CLAIM_TREE" "$STOCK_TREE_SHA" "$STOCK_TREE_BYTES" || return 1
    else
        [ ! -e "$CLAIM_TREE_TMP" ] && [ ! -L "$CLAIM_TREE_TMP" ] || return 1
        printf '%s\n' "$STOCK_TREE" > "$CLAIM_TREE_TMP" || return 1
        chmod 600 "$CLAIM_TREE_TMP" || return 1
        "$BUSYBOX" sync -d "$CLAIM_TREE_TMP" || return 1
        ln "$CLAIM_TREE_TMP" "$CLAIM_TREE" || return 1
        "$BUSYBOX" sync -f "$CLAIM_DIR" || return 1
        admit_stock_tree_evidence "$CLAIM_TREE" "$STOCK_TREE_SHA" "$STOCK_TREE_BYTES" \
            && same_regular_inode "$CLAIM_TREE_TMP" "$CLAIM_TREE" || return 1
        rm -f "$CLAIM_TREE_TMP" || return 1
    fi
    CLAIM_WATCHDOG="$CLAIM_DIR/watchdog_fds"
    CLAIM_WATCHDOG_TMP="$CLAIM_DIR/.watchdog_fds.$SELF_PID.$SELF_START"
    [ -n "$STOCK_WATCHDOG_EVIDENCE" ] || return 1
    WATCHDOG_FD_SHA=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | sha256sum | awk '{print $1}')
    WATCHDOG_FD_BYTES=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | wc -c | tr -d ' \t\r\n')
    if [ -e "$CLAIM_WATCHDOG" ] || [ -L "$CLAIM_WATCHDOG" ]; then
        admit_watchdog_absence_evidence "$CLAIM_WATCHDOG" "$WATCHDOG_FD_SHA" "$WATCHDOG_FD_BYTES" \
            "$WATCHDOG_TREE_SHA" "$WATCHDOG_TREE_BYTES" "$WATCHDOG_LOG_SHA" "$WATCHDOG_LOG_BYTES" \
            "$STOCK_SUPERVISOR_PID:$(stock_tree_field supervisor_start)" \
            "$STOCK_CHILD_PID:$(stock_tree_field child_start)" || return 1
    else
        [ ! -e "$CLAIM_WATCHDOG_TMP" ] && [ ! -L "$CLAIM_WATCHDOG_TMP" ] || return 1
        printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" > "$CLAIM_WATCHDOG_TMP" || return 1
        chmod 600 "$CLAIM_WATCHDOG_TMP" || return 1
        "$BUSYBOX" sync -d "$CLAIM_WATCHDOG_TMP" || return 1
        ln "$CLAIM_WATCHDOG_TMP" "$CLAIM_WATCHDOG" || return 1
        "$BUSYBOX" sync -f "$CLAIM_DIR" || return 1
        admit_watchdog_absence_evidence "$CLAIM_WATCHDOG" "$WATCHDOG_FD_SHA" "$WATCHDOG_FD_BYTES" \
            "$WATCHDOG_TREE_SHA" "$WATCHDOG_TREE_BYTES" "$WATCHDOG_LOG_SHA" "$WATCHDOG_LOG_BYTES" \
            "$STOCK_SUPERVISOR_PID:$(stock_tree_field supervisor_start)" \
            "$STOCK_CHILD_PID:$(stock_tree_field child_start)" \
            && same_regular_inode "$CLAIM_WATCHDOG_TMP" "$CLAIM_WATCHDOG" || return 1
        rm -f "$CLAIM_WATCHDOG_TMP" || return 1
    fi
    LOG_WINDOW_SHA=$(sha256sum "$CLAIM_DIR/log_window" | awk '{print $1}')
    LOG_WINDOW_BYTES=$(wc -c < "$CLAIM_DIR/log_window" | tr -d ' \t\r\n')
    admit_log_window_evidence "$CLAIM_DIR/log_window" "$LOG_WINDOW_SHA" "$LOG_WINDOW_BYTES" \
        || return 1
    TERMINAL_TMP="$TRIAL_DIR/.runtime_stock_restart_complete.$SELF_PID.$SELF_START"
    [ ! -e "$TERMINAL" ] && [ ! -L "$TERMINAL" ] || return 1
    [ ! -e "$TERMINAL_TMP" ] && [ ! -L "$TERMINAL_TMP" ] || return 1
    {
        printf 'schema=dcentos.s19k-stock-restart-complete/v4\n'
        printf 'disposition=stock-restart-proven\n'
        printf 'pending_sha256=%s\n' "$PENDING_SHA"
        printf 'pending_bytes=%s\n' "$PENDING_BYTES"
        printf 'source_kind=%s\n' "$SOURCE_KIND"
        printf 'source_sha256=%s\n' "$SOURCE_SHA"
        printf 'source_bytes=%s\n' "$SOURCE_BYTES"
        printf 'safeoff_receipt_sha256=%s\n' "$SAFE_SHA"
        printf 'live_identity_sha256=%s\n' "$IDENTITY_SHA"
        printf 'helper_sha256=%s\n' "$EXPECTED_HELPER_SHA"
        printf 'helper_bytes=%s\n' "$EXPECTED_HELPER_BYTES"
        printf 'stock_init_sha256=%s\n' "$AUDITED_S99_SHA"
        printf 'stock_init_bytes=%s\n' "$AUDITED_S99_BYTES"
        printf 'stock_bos_tools_sha256=%s\n' "$AUDITED_STOCK_BOS_TOOLS_SHA"
        printf 'stock_bos_tools_bytes=%s\n' "$AUDITED_STOCK_BOS_TOOLS_BYTES"
        printf 'stock_bosminer_sha256=%s\n' "$AUDITED_STOCK_BOSMINER_SHA"
        printf 'stock_bosminer_bytes=%s\n' "$AUDITED_STOCK_BOSMINER_BYTES"
        printf 'supervisor_pid=%s\n' "$STOCK_SUPERVISOR_PID"
        printf 'supervisor_start=%s\n' "$(stock_tree_field supervisor_start)"
        printf 'child_pid=%s\n' "$STOCK_CHILD_PID"
        printf 'child_start=%s\n' "$(stock_tree_field child_start)"
        printf 'stock_tree_path=%s\n' "$STOCK_TREE_EVIDENCE"
        printf 'stock_tree_sha256=%s\n' "$STOCK_TREE_SHA"
        printf 'stock_tree_bytes=%s\n' "$STOCK_TREE_BYTES"
        printf 'watchdog_fd_path=%s\n' "$WATCHDOG_FD_EVIDENCE"
        printf 'watchdog_fd_sha256=%s\n' "$WATCHDOG_FD_SHA"
        printf 'watchdog_fd_bytes=%s\n' "$WATCHDOG_FD_BYTES"
        printf 'watchdog_fd_authority=bounded-all-tid-hardware-watchdog-absence\n'
        printf 'gpio_raw=437:0,454:0,455:1,456:1\n'
        printf 'log_resolved=%s\n' "$LOG_RESOLVED"
        printf 'log_mount_id=%s\n' "$LOG_MNT_ID_NOW"
        printf 'log_inode=%s\n' "$LOG_INODE"
        printf 'log_mode=%s\n' "$LOG_MODE"
        printf 'log_nlink=%s\n' "$LOG_NLINK"
        printf 'log_uid=%s\n' "$LOG_UID"
        printf 'log_gid=%s\n' "$LOG_GID"
        printf 'log_bytes_before=%s\n' "$LOG_BYTES_BEFORE"
        printf 'log_bytes_after=%s\n' "$LOG_BYTES_AFTER"
        printf 'log_window_path=%s\n' "$LOG_WINDOW_EVIDENCE"
        printf 'log_window_sha256=%s\n' "$LOG_WINDOW_SHA"
        printf 'log_window_bytes=%s\n' "$LOG_WINDOW_BYTES"
        printf 'chain_recovery=chain2+chain3-init+four-sensors+sane-temps+monitor-watchdogs-no-failure-stable-window\n'
        printf 'stratum_recovery=connected-v1+resume\n'
        printf 'cooling_recovery=configured-monitoring-only-physical-fan-rpm-not-proven-min_fans-0\n'
        printf 'prior_unresolved=%s\n' "$(unresolved_value)"
        printf 'dcent_direct_hardware_or_flash_writer=false\n'
        printf 'stock_restart_mutation=expected-tmpfs-pidfile+stock-daemon-state+persistent-ubifs-bosminer-log-append\n'
        printf 'next_authority=terminal-finalizer-only\n'
    } > "$TERMINAL_TMP" || return 1
    chmod 600 "$TERMINAL_TMP" || return 1
    "$BUSYBOX" sync -d "$TERMINAL_TMP" || return 1
    ln "$TERMINAL_TMP" "$TERMINAL" || { rm -f "$TERMINAL_TMP"; return 1; }
    "$BUSYBOX" sync -f "$TRIAL_DIR" || return 1
    same_regular_inode "$TERMINAL_TMP" "$TERMINAL" && admit_terminal || return 1
    rm -f "$TERMINAL_TMP" || return 1
    transaction_scratches_absent
}

terminal_evidence_file() {
    PERMANENT=$1 CLAIM_COPY=$2 SHA=$3 BYTES=$4
    if verify_file "$PERMANENT" "$SHA" "$BYTES"; then
        printf '%s\n' "$PERMANENT"
    elif verify_file "$CLAIM_COPY" "$SHA" "$BYTES"; then
        printf '%s\n' "$CLAIM_COPY"
    else
        return 1
    fi
}

admit_terminal() {
    regular "$TERMINAL" || return 1
    require_ordered_keys "$TERMINAL" schema disposition pending_sha256 pending_bytes \
        source_kind source_sha256 source_bytes safeoff_receipt_sha256 live_identity_sha256 helper_sha256 \
        helper_bytes stock_init_sha256 stock_init_bytes stock_bos_tools_sha256 stock_bos_tools_bytes \
        stock_bosminer_sha256 stock_bosminer_bytes supervisor_pid supervisor_start child_pid \
        child_start stock_tree_path stock_tree_sha256 stock_tree_bytes watchdog_fd_path \
        watchdog_fd_sha256 watchdog_fd_bytes watchdog_fd_authority gpio_raw log_resolved log_mount_id \
        log_inode log_mode log_nlink log_uid log_gid log_bytes_before log_bytes_after log_window_path \
        log_window_sha256 log_window_bytes chain_recovery stratum_recovery cooling_recovery \
        prior_unresolved dcent_direct_hardware_or_flash_writer stock_restart_mutation next_authority || return 1
    LOG_MNT_ID_NOW=$(field "$TERMINAL" log_mount_id) || return 1
    LOG_INODE=$(field "$TERMINAL" log_inode) || return 1
    LOG_MODE=$(field "$TERMINAL" log_mode) || return 1
    LOG_NLINK=$(field "$TERMINAL" log_nlink) || return 1
    LOG_UID=$(field "$TERMINAL" log_uid) || return 1
    LOG_GID=$(field "$TERMINAL" log_gid) || return 1
    LOG_BYTES_BEFORE=$(field "$TERMINAL" log_bytes_before) || return 1
    valid_positive "$LOG_MNT_ID_NOW" && valid_positive "$LOG_INODE" \
        && valid_positive "$LOG_NLINK" && valid_uint "$LOG_UID" && valid_uint "$LOG_GID" \
        && valid_positive "$LOG_BYTES_BEFORE" || return 1
    [ -n "$LOG_MODE" ] || return 1
    if [ "$REQUIRE_EXACT_LOG_METADATA" = true ]; then
        [ "$LOG_MODE:$LOG_NLINK:$LOG_UID:$LOG_GID" = -rw-------:1:0:0 ] || return 1
    fi
    [ "$(field "$TERMINAL" schema)" = dcentos.s19k-stock-restart-complete/v4 ] \
        && [ "$(field "$TERMINAL" disposition)" = stock-restart-proven ] \
        && [ "$(field "$TERMINAL" pending_sha256):$(field "$TERMINAL" pending_bytes)" = "$PENDING_SHA:$PENDING_BYTES" ] \
        && [ "$(field "$TERMINAL" source_kind):$(field "$TERMINAL" source_sha256):$(field "$TERMINAL" source_bytes)" = "$SOURCE_KIND:$SOURCE_SHA:$SOURCE_BYTES" ] \
        && [ "$(field "$TERMINAL" safeoff_receipt_sha256)" = "$SAFE_SHA" ] \
        && [ "$(field "$TERMINAL" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$TERMINAL" helper_sha256):$(field "$TERMINAL" helper_bytes)" = "$EXPECTED_HELPER_SHA:$EXPECTED_HELPER_BYTES" ] \
        && [ "$(field "$TERMINAL" stock_init_sha256):$(field "$TERMINAL" stock_init_bytes)" = "$AUDITED_S99_SHA:$AUDITED_S99_BYTES" ] \
        && [ "$(field "$TERMINAL" stock_bos_tools_sha256):$(field "$TERMINAL" stock_bos_tools_bytes)" = "$AUDITED_STOCK_BOS_TOOLS_SHA:$AUDITED_STOCK_BOS_TOOLS_BYTES" ] \
        && [ "$(field "$TERMINAL" stock_bosminer_sha256):$(field "$TERMINAL" stock_bosminer_bytes)" = "$AUDITED_STOCK_BOSMINER_SHA:$AUDITED_STOCK_BOSMINER_BYTES" ] \
        && [ "$(field "$TERMINAL" stock_tree_path)" = "$STOCK_TREE_EVIDENCE" ] \
        && [ "$(field "$TERMINAL" watchdog_fd_path)" = "$WATCHDOG_FD_EVIDENCE" ] \
        && [ "$(field "$TERMINAL" watchdog_fd_authority)" = bounded-all-tid-hardware-watchdog-absence ] \
        && [ "$(field "$TERMINAL" gpio_raw)" = 437:0,454:0,455:1,456:1 ] \
        && [ "$(field "$TERMINAL" log_window_path)" = "$LOG_WINDOW_EVIDENCE" ] \
        && [ "$(field "$TERMINAL" log_resolved)" = "$LOG_RESOLVED" ] \
        && [ "$(field "$TERMINAL" chain_recovery)" = chain2+chain3-init+four-sensors+sane-temps+monitor-watchdogs-no-failure-stable-window ] \
        && [ "$(field "$TERMINAL" stratum_recovery)" = connected-v1+resume ] \
        && [ "$(field "$TERMINAL" cooling_recovery)" = configured-monitoring-only-physical-fan-rpm-not-proven-min_fans-0 ] \
        && [ "$(field "$TERMINAL" dcent_direct_hardware_or_flash_writer)" = false ] \
        && [ "$(field "$TERMINAL" stock_restart_mutation)" = expected-tmpfs-pidfile+stock-daemon-state+persistent-ubifs-bosminer-log-append ] \
        && [ "$(field "$TERMINAL" next_authority)" = terminal-finalizer-only ] || return 1
    TERMINAL_TREE_SHA=$(field "$TERMINAL" stock_tree_sha256)
    TERMINAL_TREE_BYTES=$(field "$TERMINAL" stock_tree_bytes)
    TERMINAL_WATCHDOG_SHA=$(field "$TERMINAL" watchdog_fd_sha256)
    TERMINAL_WATCHDOG_BYTES=$(field "$TERMINAL" watchdog_fd_bytes)
    TERMINAL_LOG_SHA=$(field "$TERMINAL" log_window_sha256)
    TERMINAL_LOG_BYTES=$(field "$TERMINAL" log_window_bytes)
    TERMINAL_LOG_AFTER=$(field "$TERMINAL" log_bytes_after)
    valid_sha "$TERMINAL_TREE_SHA" && valid_positive "$TERMINAL_TREE_BYTES" \
        && valid_sha "$TERMINAL_WATCHDOG_SHA" && valid_positive "$TERMINAL_WATCHDOG_BYTES" \
        && valid_sha "$TERMINAL_LOG_SHA" && valid_positive "$TERMINAL_LOG_BYTES" \
        && valid_positive "$(field "$TERMINAL" supervisor_pid)" \
        && valid_positive "$(field "$TERMINAL" supervisor_start)" \
        && valid_positive "$(field "$TERMINAL" child_pid)" \
        && valid_positive "$(field "$TERMINAL" child_start)" \
        && valid_positive "$(field "$TERMINAL" log_bytes_before)" \
        && valid_positive "$TERMINAL_LOG_AFTER" \
        && [ "$TERMINAL_LOG_AFTER" -gt "$(field "$TERMINAL" log_bytes_before)" ] \
        && open_bound_log_fd || return 1
    TERMINAL_TREE_FILE=$(terminal_evidence_file "$STOCK_TREE_EVIDENCE" "$CLAIM_DIR/stock_tree" \
        "$TERMINAL_TREE_SHA" "$TERMINAL_TREE_BYTES") || return 1
    TERMINAL_LOG_FILE=$(terminal_evidence_file "$LOG_WINDOW_EVIDENCE" "$CLAIM_DIR/log_window" \
        "$TERMINAL_LOG_SHA" "$TERMINAL_LOG_BYTES") || return 1
    TERMINAL_WATCHDOG_FILE=$(terminal_evidence_file "$WATCHDOG_FD_EVIDENCE" "$CLAIM_DIR/watchdog_fds" \
        "$TERMINAL_WATCHDOG_SHA" "$TERMINAL_WATCHDOG_BYTES") || return 1
    admit_stock_tree_evidence "$TERMINAL_TREE_FILE" "$TERMINAL_TREE_SHA" "$TERMINAL_TREE_BYTES" \
        && [ "$(field "$TERMINAL_TREE_FILE" supervisor_pid):$(field "$TERMINAL_TREE_FILE" supervisor_start)" \
            = "$(field "$TERMINAL" supervisor_pid):$(field "$TERMINAL" supervisor_start)" ] \
        && [ "$(field "$TERMINAL_TREE_FILE" child_pid):$(field "$TERMINAL_TREE_FILE" child_start)" \
            = "$(field "$TERMINAL" child_pid):$(field "$TERMINAL" child_start)" ] \
        && admit_watchdog_absence_evidence "$TERMINAL_WATCHDOG_FILE" "$TERMINAL_WATCHDOG_SHA" "$TERMINAL_WATCHDOG_BYTES" \
            "$TERMINAL_TREE_SHA" "$TERMINAL_TREE_BYTES" "$TERMINAL_LOG_SHA" "$TERMINAL_LOG_BYTES" \
            "$(field "$TERMINAL" supervisor_pid):$(field "$TERMINAL" supervisor_start)" \
            "$(field "$TERMINAL" child_pid):$(field "$TERMINAL" child_start)" \
        && admit_log_window_evidence "$TERMINAL_LOG_FILE" "$TERMINAL_LOG_SHA" "$TERMINAL_LOG_BYTES" \
        && [ "$LOG_BYTES_AFTER" = "$TERMINAL_LOG_AFTER" ] \
        && [ "$(field "$TERMINAL" prior_unresolved)" = "$(unresolved_value)" ]
}

ensure_permanent_evidence() {
    for EVIDENCE_PAIR in \
        "$CLAIM_DIR/stock_tree:$STOCK_TREE_EVIDENCE:$TERMINAL_TREE_SHA:$TERMINAL_TREE_BYTES" \
        "$CLAIM_DIR/watchdog_fds:$WATCHDOG_FD_EVIDENCE:$TERMINAL_WATCHDOG_SHA:$TERMINAL_WATCHDOG_BYTES" \
        "$CLAIM_DIR/log_window:$LOG_WINDOW_EVIDENCE:$TERMINAL_LOG_SHA:$TERMINAL_LOG_BYTES"; do
        OLD_IFS=$IFS; IFS=:
        set -- $EVIDENCE_PAIR
        IFS=$OLD_IFS
        CLAIM_COPY=$1 PERMANENT_COPY=$2 COPY_SHA=$3 COPY_BYTES=$4
        if [ -e "$PERMANENT_COPY" ] || [ -L "$PERMANENT_COPY" ]; then
            verify_file "$PERMANENT_COPY" "$COPY_SHA" "$COPY_BYTES" || return 1
        else
            verify_file "$CLAIM_COPY" "$COPY_SHA" "$COPY_BYTES" \
                && ln "$CLAIM_COPY" "$PERMANENT_COPY" || return 1
        fi
    done
}

terminal_live_revalidate() {
    poststart_runtime_predicates \
        && [ -n "${TERMINAL_LOG_FILE:-}" ] \
        && build_watchdog_absence_evidence "$TERMINAL_LOG_FILE" || return 1
    CURRENT_TREE_SHA=$(printf '%s\n' "$STOCK_TREE" | sha256sum | awk '{print $1}')
    CURRENT_TREE_BYTES=$(printf '%s\n' "$STOCK_TREE" | wc -c | tr -d ' \t\r\n')
    CURRENT_WATCHDOG_SHA=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | sha256sum | awk '{print $1}')
    CURRENT_WATCHDOG_BYTES=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | wc -c | tr -d ' \t\r\n')
    set -- $("$BUSYBOX" ls -liLnL "$LOG_FD" 2>/dev/null) || return 1
    CURRENT_LOG_BYTES=$6
    valid_uint "$CURRENT_LOG_BYTES" \
        && [ "$CURRENT_TREE_SHA:$CURRENT_TREE_BYTES" = "$TERMINAL_TREE_SHA:$TERMINAL_TREE_BYTES" ] \
        && [ "$CURRENT_WATCHDOG_SHA:$CURRENT_WATCHDOG_BYTES" = "$TERMINAL_WATCHDOG_SHA:$TERMINAL_WATCHDOG_BYTES" ] \
        && log_fd_tuple_is_unchanged \
        && [ "$CURRENT_LOG_BYTES" -ge "$(field "$TERMINAL" log_bytes_after)" ]
}

terminal_takeover_predicates() {
    admit_pending && admit_terminal \
        && verify_file "$HELPER" "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES" \
        && terminal_live_revalidate
}

classify_unresolved_scratch() {
    captured_scratch_is_unchanged_and_dead || return 1
    CLAIM_SHA=$(sha256sum "$CLAIM" | awk '{print $1}')
    CLAIM_BYTES=$(wc -c < "$CLAIM" | tr -d ' \t\r\n')
    EXPECTED_UNRESOLVED_SHA=$(emit_unresolved_receipt | sha256sum | awk '{print $1}')
    EXPECTED_UNRESOLVED_BYTES=$(emit_unresolved_receipt | wc -c | tr -d ' \t\r\n')
    if [ "$SCRATCH_SHA:$SCRATCH_BYTES" = "$EXPECTED_UNRESOLVED_SHA:$EXPECTED_UNRESOLVED_BYTES" ]; then
        admit_unresolved_content_at "$SCRATCH_PATH" || return 1
        UNRESOLVED_SCRATCH_CLASS=complete
    elif [ "$SCRATCH_BYTES" -lt "$EXPECTED_UNRESOLVED_BYTES" ]; then
        EXPECTED_PREFIX_SHA=$(emit_unresolved_receipt \
            | "$BUSYBOX" dd bs=1 count="$SCRATCH_BYTES" 2>/dev/null \
            | sha256sum | awk '{print $1}')
        [ "$SCRATCH_SHA" = "$EXPECTED_PREFIX_SHA" ] || return 1
        UNRESOLVED_SCRATCH_CLASS=partial
    else
        return 1
    fi
}

recover_unresolved_scratch() {
    capture_single_dead_scratch "$TRIAL_DIR/.runtime_stock_restart_unresolved." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
        && postcommit_takeover_predicates && classify_unresolved_scratch || return 1
    if [ -e "$UNRESOLVED" ] || [ -L "$UNRESOLVED" ]; then
        [ "$UNRESOLVED_SCRATCH_CLASS" = complete ] \
            && same_regular_inode "$SCRATCH_PATH" "$UNRESOLVED" \
            && admit_unresolved || return 1
    else
        [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ] || return 1
    fi
    captured_scratch_is_unchanged_and_dead && postcommit_takeover_predicates || return 1
    rm -f "$SCRATCH_PATH" || return 1
    [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
        && postcommit_takeover_predicates
}

recover_log_window_scratch() {
    capture_single_dead_scratch "$CLAIM_DIR/.log_window." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
        && postcommit_takeover_predicates || return 1
    LOG_SCRATCH_CLASS=
    if [ "$SCRATCH_BYTES" = 0 ]; then
        LOG_SCRATCH_CLASS=partial
    else
        LOG_SCRATCH_SHA=$SCRATCH_SHA LOG_SCRATCH_BYTES=$SCRATCH_BYTES
        if admit_log_window_evidence "$SCRATCH_PATH" "$LOG_SCRATCH_SHA" "$LOG_SCRATCH_BYTES"; then
            LOG_SCRATCH_CLASS=complete
        else
            LOG_SCHEMA_PREFIX='schema=dcentos.s19k-stock-log-window/v1'
            [ "$SCRATCH_BYTES" -le "$((${#LOG_SCHEMA_PREFIX} + 1))" ] || return 1
            EXPECTED_LOG_PREFIX_SHA=$(printf '%s\n' "$LOG_SCHEMA_PREFIX" \
                | "$BUSYBOX" dd bs=1 count="$SCRATCH_BYTES" 2>/dev/null \
                | sha256sum | awk '{print $1}')
            [ "$SCRATCH_SHA" = "$EXPECTED_LOG_PREFIX_SHA" ] || return 1
            LOG_SCRATCH_CLASS=partial
        fi
    fi
    if [ -e "$CLAIM_DIR/log_window" ] || [ -L "$CLAIM_DIR/log_window" ]; then
        [ "$LOG_SCRATCH_CLASS" = complete ] \
            && same_regular_inode "$SCRATCH_PATH" "$CLAIM_DIR/log_window" \
            && admit_log_window_evidence "$CLAIM_DIR/log_window" "$SCRATCH_SHA" "$SCRATCH_BYTES" \
            || return 1
    elif [ "$LOG_SCRATCH_CLASS" = complete ]; then
        ln "$SCRATCH_PATH" "$CLAIM_DIR/log_window" || return 1
        same_regular_inode "$SCRATCH_PATH" "$CLAIM_DIR/log_window" \
            && admit_log_window_evidence "$CLAIM_DIR/log_window" "$SCRATCH_SHA" "$SCRATCH_BYTES" \
            || return 1
    fi
    captured_scratch_is_unchanged_and_dead && postcommit_takeover_predicates || return 1
    rm -f "$SCRATCH_PATH" || return 1
    [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
        && postcommit_takeover_predicates
}

recover_claim_scratch() {
    capture_single_dead_scratch "$CLAIM_DIR/.owner." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    if regular "$CLAIM"; then
        admit_claim && [ "$CLAIM_PHASE" = prestart-admitted ] || return 1
    else
        [ ! -e "$CLAIM" ] && [ ! -L "$CLAIM" ] || return 1
    fi
    prestart_predicates && captured_scratch_is_unchanged_and_dead || return 1
    rm -f "$SCRATCH_PATH" || return 1
    [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
        && prestart_predicates
}

recover_stock_tree_scratch() {
    capture_single_dead_scratch "$CLAIM_DIR/.stock_tree." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
        && poststart_predicates || return 1
    CURRENT_TREE_SHA=$(printf '%s\n' "$STOCK_TREE" | sha256sum | awk '{print $1}')
    CURRENT_TREE_BYTES=$(printf '%s\n' "$STOCK_TREE" | wc -c | tr -d ' \t\r\n')
    if [ -e "$CLAIM_DIR/stock_tree" ] || [ -L "$CLAIM_DIR/stock_tree" ]; then
        same_regular_inode "$SCRATCH_PATH" "$CLAIM_DIR/stock_tree" \
            && [ "$SCRATCH_SHA:$SCRATCH_BYTES" = "$CURRENT_TREE_SHA:$CURRENT_TREE_BYTES" ] \
            && admit_stock_tree_evidence "$CLAIM_DIR/stock_tree" "$SCRATCH_SHA" "$SCRATCH_BYTES" \
            || return 1
    else
        [ ! -e "$TERMINAL" ] && [ ! -L "$TERMINAL" ] || return 1
    fi
    captured_scratch_is_unchanged_and_dead && poststart_predicates || return 1
    rm -f "$SCRATCH_PATH" || return 1
    [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
        && poststart_predicates
}

recover_watchdog_scratch() {
    capture_single_dead_scratch "$CLAIM_DIR/.watchdog_fds." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
        && poststart_predicates || return 1
    CURRENT_WATCHDOG_SHA=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | sha256sum | awk '{print $1}')
    CURRENT_WATCHDOG_BYTES=$(printf '%s\n' "$STOCK_WATCHDOG_EVIDENCE" | wc -c | tr -d ' \t\r\n')
    if [ -e "$CLAIM_DIR/watchdog_fds" ] || [ -L "$CLAIM_DIR/watchdog_fds" ]; then
        same_regular_inode "$SCRATCH_PATH" "$CLAIM_DIR/watchdog_fds" \
            && [ "$SCRATCH_SHA:$SCRATCH_BYTES" = "$CURRENT_WATCHDOG_SHA:$CURRENT_WATCHDOG_BYTES" ] \
            && admit_watchdog_absence_evidence "$CLAIM_DIR/watchdog_fds" "$SCRATCH_SHA" "$SCRATCH_BYTES" \
                "$WATCHDOG_TREE_SHA" "$WATCHDOG_TREE_BYTES" "$WATCHDOG_LOG_SHA" "$WATCHDOG_LOG_BYTES" \
                "$STOCK_SUPERVISOR_PID:$(stock_tree_field supervisor_start)" \
                "$STOCK_CHILD_PID:$(stock_tree_field child_start)" \
            || return 1
    else
        [ ! -e "$TERMINAL" ] && [ ! -L "$TERMINAL" ] || return 1
    fi
    captured_scratch_is_unchanged_and_dead && poststart_predicates || return 1
    rm -f "$SCRATCH_PATH" || return 1
    [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
        && poststart_predicates
}

recover_terminal_scratch() {
    capture_single_dead_scratch "$TRIAL_DIR/.runtime_stock_restart_complete." || return 1
    [ -n "$SCRATCH_PATH" ] || return 0
    if [ -e "$TERMINAL" ] || [ -L "$TERMINAL" ]; then
        same_regular_inode "$SCRATCH_PATH" "$TERMINAL" \
            && admit_terminal && terminal_live_revalidate || return 1
        captured_scratch_is_unchanged_and_dead || return 1
        rm -f "$SCRATCH_PATH" || return 1
        [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
            && admit_terminal && terminal_live_revalidate
    else
        admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
            && poststart_predicates && captured_scratch_is_unchanged_and_dead || return 1
        rm -f "$SCRATCH_PATH" || return 1
        [ ! -e "$SCRATCH_PATH" ] && [ ! -L "$SCRATCH_PATH" ] \
            && poststart_predicates
    fi
}

recover_transaction_scratches() {
    recover_claim_scratch \
        && recover_unresolved_scratch \
        && recover_log_window_scratch \
        && recover_stock_tree_scratch \
        && recover_watchdog_scratch \
        && recover_terminal_scratch
}

retire_unresolved_for_terminal() {
    TERMINAL_UNRESOLVED=$(field "$TERMINAL" prior_unresolved) || return 1
    if [ "$TERMINAL_UNRESOLVED" = absent ]; then
        [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] \
            && [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ]
        return
    fi
    TERMINAL_UNRESOLVED_SHA=${TERMINAL_UNRESOLVED%%:*}
    TERMINAL_UNRESOLVED_BYTES=${TERMINAL_UNRESOLVED#*:}
    valid_sha "$TERMINAL_UNRESOLVED_SHA" && valid_positive "$TERMINAL_UNRESOLVED_BYTES" \
        && [ "$TERMINAL_UNRESOLVED_BYTES" != "$TERMINAL_UNRESOLVED" ] || return 1
    if [ -e "$UNRESOLVED" ] || [ -L "$UNRESOLVED" ]; then
        [ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ] \
            && admit_unresolved \
            && verify_file "$UNRESOLVED" "$TERMINAL_UNRESOLVED_SHA" "$TERMINAL_UNRESOLVED_BYTES" \
            || return 1
        mv "$UNRESOLVED" "$UNRESOLVED_RETIRED" || return 1
        "$BUSYBOX" sync -f "$TRIAL_DIR" || return 1
    fi
    [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] \
        && admit_unresolved_content_at "$UNRESOLVED_RETIRED" \
        && verify_file "$UNRESOLVED_RETIRED" "$TERMINAL_UNRESOLVED_SHA" "$TERMINAL_UNRESOLVED_BYTES"
}

finalize_terminal() {
    transaction_scratches_absent && admit_terminal || return 1
    if [ "$PENDING_RECORD" = "$ACTIVE" ]; then
        admit_lock_owner && admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
            && terminal_live_revalidate && ensure_permanent_evidence \
            && terminal_live_revalidate && retire_unresolved_for_terminal \
            && admit_terminal && terminal_live_revalidate || return 1
        mv "$ACTIVE" "$CONSUMED" || return 1
        admit_pending && [ "$PENDING_RECORD" = "$CONSUMED" ] && admit_terminal || return 1
    fi
    if [ -d "$CLAIM_DIR" ] || [ -L "$CLAIM_DIR" ]; then
        [ -d "$CLAIM_DIR" ] && [ ! -L "$CLAIM_DIR" ] && admit_lock_owner || return 1
        if regular "$CLAIM"; then
            admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] \
                && terminal_live_revalidate && ensure_permanent_evidence \
                && terminal_live_revalidate && retire_unresolved_for_terminal \
                && admit_terminal && terminal_live_revalidate || return 1
        else
            [ ! -e "$CLAIM" ] && [ ! -L "$CLAIM" ] \
                && [ "$PENDING_RECORD" = "$CONSUMED" ] \
                && admit_terminal || return 1
        fi
        rm -f "$CLAIM_DIR/log_window" "$CLAIM_DIR/stock_tree" "$CLAIM_DIR/watchdog_fds" \
            "$CLAIM_DIR/s99_start.stdout" "$CLAIM_DIR/s99_start.stderr" "$CLAIM" || return 1
        rmdir "$CLAIM_DIR" || return 1
    fi
    if [ -e "$OWNER" ] || [ -L "$OWNER" ]; then
        admit_lock_owner && admit_terminal || return 1
        rm -f "$OWNER" || return 1
    fi
    if [ -d "$LOCK" ] || [ -L "$LOCK" ]; then
        [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && rmdir "$LOCK" || return 1
    fi
    admit_pending && [ "$PENDING_RECORD" = "$CONSUMED" ] \
        && admit_terminal && [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] \
        && [ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] \
        && [ ! -e "$LOCK" ] && [ ! -L "$LOCK" ] || return 1
    admit_current_invocation_owner || return 1
    rm -f "$INVOKE_OWNER" || return 1
    rmdir "$INVOKE_LOCK" || return 1
    [ ! -e "$INVOKE_LOCK" ] && [ ! -L "$INVOKE_LOCK" ] || return 1
    echo "S19k stock restart proven; pending SafeOff obligation consumed"
}

valid_sha "$EXPECTED_HELPER_SHA" && valid_positive "$EXPECTED_HELPER_BYTES" || {
    echo "ERROR: independently supplied helper digest/size is malformed" >&2
    exit 2
}
verify_file "$HELPER" "$EXPECTED_HELPER_SHA" "$EXPECTED_HELPER_BYTES" || {
    echo "ERROR: executing stock-restart helper is not the independently supplied artifact" >&2
    exit 1
}
admit_pending || {
    echo "ERROR: exact stock-restart pending ACTIVE/lock contract not admitted" >&2
    exit 1
}
acquire_invocation_owner || {
    echo "ERROR: board-global stock-restart helper invocation authority is live or ambiguous" >&2
    exit 1
}
recover_transaction_scratches || {
    echo "ERROR: stock-restart transaction scratch is live, ambiguous, or not recoverable from its exact phase ancestor" >&2
    exit 1
}

if [ -e "$TERMINAL" ] || [ -L "$TERMINAL" ] || [ "$PENDING_RECORD" = "$CONSUMED" ]; then
    regular "$TERMINAL" && finalize_terminal && exit 0
    echo "ERROR: terminal stock-restart transaction suffix is not exactly resumable" >&2
    exit 1
fi
[ ! -e "$UNRESOLVED_RETIRED" ] && [ ! -L "$UNRESOLVED_RETIRED" ] || {
    echo "ERROR: consumed unresolved evidence exists without an exact terminal transaction" >&2
    exit 1
}
if [ -e "$UNRESOLVED" ] || [ -L "$UNRESOLVED" ]; then
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] && admit_unresolved || {
        echo "ERROR: stale or inexact unresolved obligation precedes terminal proof" >&2
        exit 1
    }
fi
[ ! -e "$STOCK_TREE_EVIDENCE" ] && [ ! -L "$STOCK_TREE_EVIDENCE" ] \
    && [ ! -e "$WATCHDOG_FD_EVIDENCE" ] && [ ! -L "$WATCHDOG_FD_EVIDENCE" ] \
    && [ ! -e "$LOG_WINDOW_EVIDENCE" ] && [ ! -L "$LOG_WINDOW_EVIDENCE" ] || {
    echo "ERROR: orphan stock-restart proof evidence retained" >&2
    exit 1
}
admit_lock_owner || {
    echo "ERROR: exact stock-restart lock owner not admitted" >&2
    exit 1
}

if { [ -d "$CLAIM_DIR" ] || [ -L "$CLAIM_DIR" ]; } \
    && { [ ! -e "$CLAIM" ] || [ -L "$CLAIM" ]; }; then
    recover_preclaim_directory || {
        echo "ERROR: inexact pre-claim crash residue retained" >&2
        exit 1
    }
fi

if [ -d "$CLAIM_DIR" ] || [ -L "$CLAIM_DIR" ]; then
    [ -d "$CLAIM_DIR" ] && [ ! -L "$CLAIM_DIR" ] && admit_claim || {
        echo "ERROR: ambiguous stock-restart claim retained" >&2
        exit 1
    }
else
    [ "$MODE" = start ] || { echo "ERROR: prove requires an existing committed claim" >&2; exit 1; }
    prestart_predicates && capture_log_boundary || {
        echo "ERROR: pre-start SafeOff/identity/owner/log admission failed" >&2
        exit 1
    }
    mkdir "$CLAIM_DIR" 2>/dev/null || {
        echo "ERROR: another stock-restart claimant exists" >&2
        exit 1
    }
    write_claim prestart-admitted || {
        echo "ERROR: pre-start claim publisher failed; obligation retained" >&2
        exit 1
    }
    admit_claim || { echo "ERROR: pre-start claim publication failed; obligation retained" >&2; exit 1; }
fi

if [ "$CLAIM_PHASE" = prestart-admitted ]; then
    [ "$MODE" = start ] || { echo "ERROR: prove cannot commit an uninvoked start" >&2; exit 1; }
    prestart_predicates && log_boundary_unchanged && admit_claim || {
        echo "ERROR: volatile admission changed before start; claim/obligation retained" >&2
        exit 1
    }
    write_claim start-invocation-committed || {
        echo "ERROR: start-intent claim publisher failed; refusing invocation" >&2
        exit 1
    }
    admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] || {
        echo "ERROR: start intent was not durably committed; refusing invocation" >&2
        exit 1
    }
    # Revalidate after the durable intent write, immediately before the sole
    # mutation. This remains at-most-once: a crash in this final gap is an
    # explicit prove-only unresolved state and never authorizes replay.
    prestart_predicates && log_boundary_unchanged \
        && admit_claim && [ "$CLAIM_PHASE" = start-invocation-committed ] || {
        publish_unresolved || true
        echo "ERROR: volatile admission changed after start intent; no invocation/retry authorized" >&2
        exit 1
    }
    verify_file "$S99" "$AUDITED_S99_SHA" "$AUDITED_S99_BYTES" \
        && launcher_runtime_is_exact || {
        publish_unresolved || true
        echo "ERROR: stock launcher changed at the invocation fence; no invocation/retry authorized" >&2
        exit 1
    }
    (
        exec 8>&-
        cd /
        umask 0022
        "$BUSYBOX" env -i \
            CONSOLE=/dev/console HOME=/ INIT_VERSION=sysvinit-2.9n \
            PATH=/sbin:/usr/sbin:/bin:/usr/bin PREVLEVEL=N PWD=/ RUNLEVEL=3 \
            SHELL=/bin/sh SHLVL=2 TERM=linux jtag=disable \
            'logo=,loaded,androidboot.selinux=enforcing' \
            "$SHELL_INTERPRETER" "$S99" start
    ) > "$CLAIM_DIR/s99_start.stdout" 2> "$CLAIM_DIR/s99_start.stderr" || {
        publish_unresolved || true
        echo "ERROR: exact S99bosminer start failed; committed obligation retained (no retry/fallback)" >&2
        exit 1
    }
fi

[ "$CLAIM_PHASE" = start-invocation-committed ] || {
    echo "ERROR: no durable start commitment; refusing proof" >&2
    exit 1
}
[ ! -e "$UNRESOLVED" ] && [ ! -L "$UNRESOLVED" ] || admit_unresolved || {
    echo "ERROR: malformed unresolved proof obligation retained" >&2
    exit 1
}
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT_SECONDS" ]; do
    if poststart_predicates; then
        FIRST_STOCK_TREE=$STOCK_TREE
        FIRST_STOCK_WATCHDOG_EVIDENCE=$STOCK_WATCHDOG_EVIDENCE
        sleep "$STABILITY_WAIT_SECONDS"
        if poststart_predicates && [ "$STOCK_TREE" = "$FIRST_STOCK_TREE" ] \
                && [ "$STOCK_WATCHDOG_EVIDENCE" = "$FIRST_STOCK_WATCHDOG_EVIDENCE" ]; then
            publish_terminal && finalize_terminal && exit 0
        fi
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
publish_unresolved || {
    echo "ERROR: proof failed and unresolved receipt could not be durably admitted; ACTIVE/lock retained" >&2
    exit 1
}
echo "ERROR: bounded stock recovery proof not reached; committed obligation retained without fallback" >&2
exit 1
