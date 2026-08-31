#!/bin/sh
set -eu

umask 077
export LC_ALL=C

SCHEMA=s19k-ptrace-kat-harness-v1
ROOT_PREFIX=/tmp/dcent-s19k-ptrace-kat.
ROOT=
TRACER_SHA=
FIXTURE_SHA=
RESULTS=
CURRENT_CASE=
CURRENT_NONCE=
LIVE_TRACER_PID=0
LIVE_TRACER_START=0
LIVE_TRACER_EXE=
LIVE_FIXTURE_PID=0
LIVE_FIXTURE_START=0
LIVE_FIXTURE_EXE=
LIVE_CHILD_PID=0
LIVE_CHILD_START=0

fail() {
    printf '%s\n' "s19k-ptrace-kat target refusal: $*" >&2
    exit 1
}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" = 0 ] || [ "${1#0}" = "$1" ] ;;
    esac
}

is_positive_uint() {
    is_uint "$1" && [ "$1" -gt 0 ]
}

is_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

monotonic_seconds() {
    IFS=' ' read -r monotonic_value monotonic_rest < /proc/uptime \
        || return 1
    monotonic_value=${monotonic_value%%.*}
    is_uint "$monotonic_value" || return 1
    printf '%s\n' "$monotonic_value"
}

wait_file() {
    wait_path=$1
    wait_deadline=$(($(monotonic_seconds) + 20))
    while :; do
        if [ -f "$wait_path" ] && [ ! -L "$wait_path" ]; then
            return 0
        fi
        [ "$(monotonic_seconds)" -lt "$wait_deadline" ] \
            || fail "timeout waiting for $wait_path"
        sleep 1
    done
}

proc_start() {
    proc_pid=$1
    IFS= read -r proc_line < "/proc/$proc_pid/stat" || return 1
    proc_rest=${proc_line##*) }
    [ "$proc_rest" != "$proc_line" ] || return 1
    set -- $proc_rest
    [ "$#" -ge 20 ] || return 1
    proc_index=1
    while [ "$proc_index" -lt 20 ]; do
        shift
        proc_index=$((proc_index + 1))
    done
    is_positive_uint "$1" || return 1
    printf '%s\n' "$1"
}

proc_state() {
    state_pid=$1
    IFS= read -r state_line < "/proc/$state_pid/stat" || return 1
    state_rest=${state_line##*) }
    [ "$state_rest" != "$state_line" ] || return 1
    set -- $state_rest
    [ "$#" -ge 20 ] || return 1
    case "$1" in
        [A-Z]) printf '%s\n' "$1" ;;
        *) return 1 ;;
    esac
}

wait_owned_terminal() {
    terminal_pid=$1
    terminal_start=$2
    terminal_label=$3
    terminal_deadline=$(($(monotonic_seconds) + 25))
    while :; do
        if [ ! -r "/proc/$terminal_pid/stat" ]; then
            return 0
        fi
        terminal_current=$(proc_start "$terminal_pid") \
            || fail "$terminal_label identity became unreadable"
        [ "$terminal_current" = "$terminal_start" ] \
            || return 0
        terminal_state=$(proc_state "$terminal_pid") \
            || fail "$terminal_label state became unreadable"
        [ "$terminal_state" = Z ] && return 0
        [ "$(monotonic_seconds)" -lt "$terminal_deadline" ] \
            || fail "$terminal_label did not reach a bounded terminal state"
        sleep 1
    done
}

status_value() {
    status_pid=$1
    status_key=$2
    status_result=$(sed -n "s/^$status_key:[[:space:]]*//p" "/proc/$status_pid/status") \
        || return 1
    is_uint "$status_result" || return 1
    printf '%s\n' "$status_result"
}

proc_owned() {
    owned_pid=$1
    owned_start=$2
    owned_exe=$3
    owned_case=$4
    owned_nonce=$5
    [ "$owned_pid" -gt 0 ] 2>"$RESULTS/numeric-check.log" \
        || return 1
    [ "$(proc_start "$owned_pid" 2>"$RESULTS/proc-check.log")" = "$owned_start" ] \
        || return 1
    [ "$(readlink "/proc/$owned_pid/exe" 2>"$RESULTS/readlink-check.log")" = "$owned_exe" ] \
        || return 1
    tr '\000' '\n' < "/proc/$owned_pid/cmdline" \
        | grep -Fqx "$owned_case" || return 1
    tr '\000' '\n' < "/proc/$owned_pid/cmdline" \
        | grep -Fqx "$owned_nonce" || return 1
    return 0
}

safe_kill_owned() {
    kill_pid=$1
    kill_start=$2
    kill_exe=$3
    if [ "$kill_pid" -gt 0 ] \
        && proc_owned "$kill_pid" "$kill_start" "$kill_exe" "$CURRENT_CASE" "$CURRENT_NONCE"; then
        kill -KILL "$kill_pid" 2>"$RESULTS/cleanup-kill.log" || :
    fi
}

cleanup() {
    cleanup_status=$?
    trap - 0 HUP INT TERM
    if [ "$cleanup_status" -ne 0 ] && [ -n "$RESULTS" ] && [ -d "$RESULTS" ]; then
        safe_kill_owned "$LIVE_TRACER_PID" "$LIVE_TRACER_START" "$LIVE_TRACER_EXE"
        safe_kill_owned "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START" "$LIVE_FIXTURE_EXE"
        safe_kill_owned "$LIVE_CHILD_PID" "$LIVE_CHILD_START" "$LIVE_FIXTURE_EXE"
        printf '%s\n' "schema=$SCHEMA" "status=failed" \
            "case=${CURRENT_CASE##*/}" "production_authority=false" \
            >"$RESULTS/failure.receipt"
    fi
    exit "$cleanup_status"
}

trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            [ -z "$ROOT" ] || fail "duplicate --root"
            [ "$#" -ge 2 ] || fail "missing --root value"
            ROOT=$2
            shift 2
            ;;
        --tracer-sha256)
            [ -z "$TRACER_SHA" ] || fail "duplicate --tracer-sha256"
            [ "$#" -ge 2 ] || fail "missing --tracer-sha256 value"
            TRACER_SHA=$2
            shift 2
            ;;
        --fixture-sha256)
            [ -z "$FIXTURE_SHA" ] || fail "duplicate --fixture-sha256"
            [ "$#" -ge 2 ] || fail "missing --fixture-sha256 value"
            FIXTURE_SHA=$2
            shift 2
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || fail "root uid is required"
[ -n "$ROOT" ] || fail "missing --root"
is_sha256 "$TRACER_SHA" || fail "tracer SHA-256 is not canonical lowercase hex"
is_sha256 "$FIXTURE_SHA" || fail "fixture SHA-256 is not canonical lowercase hex"
case "$ROOT" in
    "$ROOT_PREFIX"*) ;;
    *) fail "root is outside the private KAT prefix" ;;
esac
ROOT_SUFFIX=${ROOT#"$ROOT_PREFIX"}
case "$ROOT_SUFFIX" in
    ''|*[!A-Za-z0-9]*) fail "root suffix must be nonempty ASCII alphanumeric" ;;
esac
[ "${#ROOT_SUFFIX}" -le 32 ] || fail "root suffix is too long for exact case nonces"
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || fail "root must be a non-symlink directory"
[ "$(readlink -f "$ROOT")" = "$ROOT" ] || fail "root canonical path mismatch"
set -- $(ls -ldn "$ROOT")
[ "$1" = drwx------ ] && [ "$3" = 0 ] \
    || fail "root must be owned by uid 0 with mode 0700"

for required_command in base64 cp dd grep id kill ls mkdir readlink sed sha256sum sleep sort tr uname wc; do
    required_path=$(command -v "$required_command" 2>&1) \
        || fail "required target command is absent: $required_command"
    [ -n "$required_path" ] || fail "empty command resolution for $required_command"
done

[ "$(uname -m)" = aarch64 ] || fail "target machine is not aarch64"
[ "$(uname -r)" = 4.9.113 ] || fail "target kernel is not exactly 4.9.113"
[ ! -e /proc/sys/kernel/yama/ptrace_scope ] \
    && [ ! -L /proc/sys/kernel/yama/ptrace_scope ] \
    || fail "unexpected Yama ptrace_scope surface"
CAP_EFF=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
case "$CAP_EFF" in
    ''|*[!0-9a-fA-F]*) fail "CapEff is absent or malformed" ;;
esac
[ $((0x$CAP_EFF & 0x80000)) -ne 0 ] || fail "CAP_SYS_PTRACE is absent"

TRACER_SOURCE="$ROOT/tracer-armv7-static"
FIXTURE_SOURCE="$ROOT/fixture-aarch64-static"
SCRIPT_SOURCE="$ROOT/run-target.sh"
for source_path in "$TRACER_SOURCE" "$FIXTURE_SOURCE" "$SCRIPT_SOURCE"; do
    [ -f "$source_path" ] && [ ! -L "$source_path" ] \
        || fail "required regular non-symlink input is absent: $source_path"
    [ "$(readlink -f "$source_path")" = "$source_path" ] \
        || fail "input canonical path mismatch: $source_path"
done

hash_file() {
    hash_path=$1
    hash_result=$(sha256sum "$hash_path") || return 1
    hash_result=${hash_result%%[[:space:]]*}
    is_sha256 "$hash_result" || return 1
    printf '%s\n' "$hash_result"
}

[ "$(hash_file "$TRACER_SOURCE")" = "$TRACER_SHA" ] || fail "tracer SHA-256 mismatch"
[ "$(hash_file "$FIXTURE_SOURCE")" = "$FIXTURE_SHA" ] || fail "fixture SHA-256 mismatch"

RESULTS="$ROOT/results"
for residue in "$RESULTS" "$ROOT/case-rollback" "$ROOT/case-precommit" "$ROOT/case-commit"; do
    [ ! -e "$residue" ] && [ ! -L "$residue" ] \
        || fail "runtime residue exists; use a fresh private root: $residue"
done
mkdir -m 700 "$RESULTS"

elf_b64() {
    elf_path=$1
    elf_skip=$2
    elf_count=$3
    dd if="$elf_path" bs=1 skip="$elf_skip" count="$elf_count" \
        2>>"$RESULTS/elf-dd.log" | base64
}

[ "$(elf_b64 "$TRACER_SOURCE" 0 4)" = f0VMRg== ] || fail "tracer ELF magic mismatch"
[ "$(elf_b64 "$TRACER_SOURCE" 4 1)" = AQ== ] || fail "tracer is not ELF32"
[ "$(elf_b64 "$TRACER_SOURCE" 5 1)" = AQ== ] || fail "tracer is not little-endian"
[ "$(elf_b64 "$TRACER_SOURCE" 18 2)" = KAA= ] || fail "tracer machine is not ARM"
[ "$(elf_b64 "$FIXTURE_SOURCE" 0 4)" = f0VMRg== ] || fail "fixture ELF magic mismatch"
[ "$(elf_b64 "$FIXTURE_SOURCE" 4 1)" = Ag== ] || fail "fixture is not ELF64"
[ "$(elf_b64 "$FIXTURE_SOURCE" 5 1)" = AQ== ] || fail "fixture is not little-endian"
[ "$(elf_b64 "$FIXTURE_SOURCE" 18 2)" = twA= ] || fail "fixture machine is not AArch64"

expect_keyset() {
    receipt_path=$1
    expected_csv=$2
    [ -f "$receipt_path" ] && [ ! -L "$receipt_path" ] \
        || fail "receipt is absent or not regular: $receipt_path"
    if grep -Ev '^[a-z][a-z0-9_.-]*=[^=[:space:]][^=]*$' "$receipt_path" \
        >"$RESULTS/malformed-receipt-lines.log"; then
        fail "malformed receipt line in $receipt_path"
    fi
    actual_keys=$(sed 's/=.*$//' "$receipt_path" | sort)
    expected_keys=$(printf '%s\n' "$expected_csv" | tr ',' '\n' | sort)
    [ "$actual_keys" = "$expected_keys" ] || fail "receipt key-set mismatch: $receipt_path"
}

receipt_value() {
    receipt_path=$1
    receipt_key=$2
    receipt_result=$(sed -n "s/^$receipt_key=//p" "$receipt_path") || return 1
    [ -n "$receipt_result" ] || return 1
    printf '%s\n' "$receipt_result"
}

expect_value() {
    [ "$(receipt_value "$1" "$2")" = "$3" ] \
        || fail "receipt value mismatch for $2 in $1"
}

expect_positive_value() {
    positive_value=$(receipt_value "$1" "$2") || fail "missing receipt value $2"
    is_positive_uint "$positive_value" || fail "receipt value $2 is not positive decimal"
}

group_snapshot() {
    snapshot_tgid=$1
    snapshot_start=$2
    [ "$(proc_start "$snapshot_tgid")" = "$snapshot_start" ] || return 1
    snapshot_lines=
    for snapshot_task in "/proc/$snapshot_tgid/task/"[0-9]*; do
        [ -d "$snapshot_task" ] || return 1
        snapshot_tid=${snapshot_task##*/}
        is_positive_uint "$snapshot_tid" || return 1
        [ "$(status_value "$snapshot_tid" Tgid)" = "$snapshot_tgid" ] || return 1
        [ "$(status_value "$snapshot_tid" TracerPid)" = 0 ] || return 1
        snapshot_tid_start=$(proc_start "$snapshot_tid") || return 1
        snapshot_lines=$snapshot_lines$snapshot_tid:$snapshot_tid_start'
'
    done
    [ -n "$snapshot_lines" ] || return 1
    printf '%s' "$snapshot_lines" | sort
}

read_progress() {
    progress_path=$1
    progress_deadline=$(($(monotonic_seconds) + 10))
    while :; do
        if [ -f "$progress_path" ] && [ ! -L "$progress_path" ]; then
            progress_value=$(sed -n 'p' "$progress_path") || progress_value=
            if is_uint "$progress_value"; then
                printf '%s\n' "$progress_value"
                return 0
            fi
        fi
        [ "$(monotonic_seconds)" -lt "$progress_deadline" ] || return 1
        sleep 1
    done
}

wait_original_absent() {
    absent_pid=$1
    absent_start=$2
    absent_deadline=$(($(monotonic_seconds) + 20))
    while :; do
        if [ ! -r "/proc/$absent_pid/stat" ]; then
            return 0
        fi
        absent_current=$(proc_start "$absent_pid" 2>"$RESULTS/absence-proc.log") || return 0
        [ "$absent_current" = "$absent_start" ] \
            || return 0
        [ "$(monotonic_seconds)" -lt "$absent_deadline" ] \
            || fail "original PID:start remains live: $absent_pid:$absent_start"
        sleep 1
    done
}

prepare_case() {
    case_name=$1
    CURRENT_CASE="$ROOT/$case_name"
    CURRENT_NONCE=${ROOT_SUFFIX}${case_name#case-}
    case "$CURRENT_NONCE" in
        *[!A-Za-z0-9]*|'') fail "derived nonce is not canonical" ;;
    esac
    mkdir -m 700 "$CURRENT_CASE"
    cp "$TRACER_SOURCE" "$CURRENT_CASE/tracer-armv7-static"
    cp "$FIXTURE_SOURCE" "$CURRENT_CASE/fixture-aarch64-static"
    chmod 500 "$CURRENT_CASE/tracer-armv7-static" "$CURRENT_CASE/fixture-aarch64-static"
    [ "$(hash_file "$CURRENT_CASE/tracer-armv7-static")" = "$TRACER_SHA" ] \
        || fail "case tracer copy hash mismatch"
    [ "$(hash_file "$CURRENT_CASE/fixture-aarch64-static")" = "$FIXTURE_SHA" ] \
        || fail "case fixture copy hash mismatch"
    set -- $(ls -ldn "$CURRENT_CASE")
    [ "$1" = drwx------ ] && [ "$3" = 0 ] || fail "case root is not uid0 mode0700"
}

start_fixture() {
    LIVE_FIXTURE_EXE="$CURRENT_CASE/fixture-aarch64-static"
    "$LIVE_FIXTURE_EXE" supervisor --root "$CURRENT_CASE" --nonce "$CURRENT_NONCE" \
        >"$CURRENT_CASE/fixture.stdout" 2>"$CURRENT_CASE/fixture.stderr" &
    LIVE_FIXTURE_PID=$!
    LIVE_FIXTURE_START=$(proc_start "$LIVE_FIXTURE_PID") \
        || fail "cannot bind fixture supervisor PID:start"
    wait_file "$CURRENT_CASE/fixture.ready"
    wait_file "$CURRENT_CASE/fixture.meta"
    expect_keyset "$CURRENT_CASE/fixture.ready" 'nonce,schema'
    expect_value "$CURRENT_CASE/fixture.ready" schema s19k-ptrace-fixture-v1
    expect_value "$CURRENT_CASE/fixture.ready" nonce "$CURRENT_NONCE"
    expect_keyset "$CURRENT_CASE/fixture.meta" \
        'child_pid,child_start,fixture_dev,fixture_exe,fixture_ino,nonce,schema,supervisor_pid,supervisor_start'
    expect_value "$CURRENT_CASE/fixture.meta" schema s19k-ptrace-fixture-v1
    expect_value "$CURRENT_CASE/fixture.meta" nonce "$CURRENT_NONCE"
    expect_value "$CURRENT_CASE/fixture.meta" fixture_exe "$LIVE_FIXTURE_EXE"
    expect_value "$CURRENT_CASE/fixture.meta" supervisor_pid "$LIVE_FIXTURE_PID"
    expect_value "$CURRENT_CASE/fixture.meta" supervisor_start "$LIVE_FIXTURE_START"
    LIVE_CHILD_PID=$(receipt_value "$CURRENT_CASE/fixture.meta" child_pid) \
        || fail "missing fixture child PID"
    LIVE_CHILD_START=$(receipt_value "$CURRENT_CASE/fixture.meta" child_start) \
        || fail "missing fixture child start"
    is_positive_uint "$LIVE_CHILD_PID" && is_positive_uint "$LIVE_CHILD_START" \
        || fail "fixture child identity is not positive decimal"
    proc_owned "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START" "$LIVE_FIXTURE_EXE" \
        "$CURRENT_CASE" "$CURRENT_NONCE" || fail "fixture supervisor identity mismatch"
    proc_owned "$LIVE_CHILD_PID" "$LIVE_CHILD_START" "$LIVE_FIXTURE_EXE" \
        "$CURRENT_CASE" "$CURRENT_NONCE" || fail "fixture child identity mismatch"
}

start_tracer() {
    tracer_mode=$1
    LIVE_TRACER_EXE="$CURRENT_CASE/tracer-armv7-static"
    "$LIVE_TRACER_EXE" --mode "$tracer_mode" --root "$CURRENT_CASE" --nonce "$CURRENT_NONCE" \
        >"$CURRENT_CASE/tracer.stdout" 2>"$CURRENT_CASE/tracer.stderr" &
    LIVE_TRACER_PID=$!
    LIVE_TRACER_START=$(proc_start "$LIVE_TRACER_PID") \
        || fail "cannot bind ARMv7 tracer PID:start"
    proc_owned "$LIVE_TRACER_PID" "$LIVE_TRACER_START" "$LIVE_TRACER_EXE" \
        "$CURRENT_CASE" "$CURRENT_NONCE" || fail "tracer identity mismatch"
}

wait_tracer_success() {
    wait_owned_terminal "$LIVE_TRACER_PID" "$LIVE_TRACER_START" tracer
    if wait "$LIVE_TRACER_PID"; then
        :
    else
        tracer_status=$?
        fail "tracer exited unsuccessfully: $tracer_status"
    fi
    wait_original_absent "$LIVE_TRACER_PID" "$LIVE_TRACER_START"
    LIVE_TRACER_PID=0
    LIVE_TRACER_START=0
    LIVE_TRACER_EXE=
}

shutdown_fixture() {
    [ ! -e "$CURRENT_CASE/shutdown" ] && [ ! -L "$CURRENT_CASE/shutdown" ] \
        || fail "shutdown marker pre-exists"
    printf '%s\n' "schema=$SCHEMA" "nonce=$CURRENT_NONCE" >"$CURRENT_CASE/shutdown"
    wait_file "$CURRENT_CASE/fixture.stopped"
    wait_owned_terminal "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START" fixture
    if wait "$LIVE_FIXTURE_PID"; then
        :
    else
        fixture_status=$?
        fail "fixture did not shut down cleanly: $fixture_status"
    fi
    expect_keyset "$CURRENT_CASE/fixture.stopped" 'child_status,nonce,schema'
    expect_value "$CURRENT_CASE/fixture.stopped" schema s19k-ptrace-fixture-v1
    expect_value "$CURRENT_CASE/fixture.stopped" nonce "$CURRENT_NONCE"
    expect_value "$CURRENT_CASE/fixture.stopped" child_status 'exit status: 0'
    wait_original_absent "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START"
    wait_original_absent "$LIVE_CHILD_PID" "$LIVE_CHILD_START"
    LIVE_FIXTURE_PID=0
    LIVE_FIXTURE_START=0
    LIVE_CHILD_PID=0
    LIVE_CHILD_START=0
    LIVE_FIXTURE_EXE=
}

verify_untraced_progress() {
    verify_supervisor_before=$1
    verify_child_before=$2
    verify_snapshot_one_supervisor=$(group_snapshot "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START") \
        || fail "supervisor all-TID untraced snapshot failed"
    verify_snapshot_one_child=$(group_snapshot "$LIVE_CHILD_PID" "$LIVE_CHILD_START") \
        || fail "child all-TID untraced snapshot failed"
    sleep 1
    verify_snapshot_two_supervisor=$(group_snapshot "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START") \
        || fail "second supervisor all-TID untraced snapshot failed"
    verify_snapshot_two_child=$(group_snapshot "$LIVE_CHILD_PID" "$LIVE_CHILD_START") \
        || fail "second child all-TID untraced snapshot failed"
    [ "$verify_snapshot_one_supervisor" = "$verify_snapshot_two_supervisor" ] \
        || fail "supervisor TID:start roster is not stable after lease release"
    [ "$verify_snapshot_one_child" = "$verify_snapshot_two_child" ] \
        || fail "child TID:start roster is not stable after lease release"
    verify_supervisor_after=$(read_progress "$CURRENT_CASE/supervisor.progress") \
        || fail "supervisor progress unreadable"
    verify_child_after=$(read_progress "$CURRENT_CASE/child.progress") \
        || fail "child progress unreadable"
    [ "$verify_supervisor_after" -gt "$verify_supervisor_before" ] \
        || fail "supervisor did not progress after lease release"
    [ "$verify_child_after" -gt "$verify_child_before" ] \
        || fail "child did not progress after lease release"
    VERIFIED_SUPERVISOR_AFTER=$verify_supervisor_after
    VERIFIED_CHILD_AFTER=$verify_child_after
}

# Case 1: exercise all lifecycle events, freeze to an all-TID fixpoint, then detach and progress.
prepare_case case-rollback
start_fixture
ROLLBACK_SUPERVISOR_BEFORE=$(read_progress "$CURRENT_CASE/supervisor.progress") \
    || fail "rollback supervisor progress unreadable"
ROLLBACK_CHILD_BEFORE=$(read_progress "$CURRENT_CASE/child.progress") \
    || fail "rollback child progress unreadable"
start_tracer exercise-rollback
wait_tracer_success
ROLLBACK_RECEIPT="$CURRENT_CASE/case.events-rollback.receipt"
expect_keyset "$ROLLBACK_RECEIPT" \
    'child_clone,child_exec,child_exit,child_fork,child_vfork,clone,detach,detach_child_after,detach_child_before,detach_supervisor_after,detach_supervisor_before,exec,exit,exitkill,fork,frozen_tids,geteventmsg_bits,geteventmsg_calls,geteventmsg_canary,interrupt_stop,mode,nonce,options,progress,schema,seize_nonstop,supervisor_clone,supervisor_exec,supervisor_exit,supervisor_fork,supervisor_vfork,vfork'
expect_value "$ROLLBACK_RECEIPT" schema s19k-ptrace-kat-receipt-v1
expect_value "$ROLLBACK_RECEIPT" mode exercise-rollback
expect_value "$ROLLBACK_RECEIPT" nonce "$CURRENT_NONCE"
expect_value "$ROLLBACK_RECEIPT" exitkill absent
expect_value "$ROLLBACK_RECEIPT" options 0x5e
expect_value "$ROLLBACK_RECEIPT" seize_nonstop churn-completed-while-seized
expect_value "$ROLLBACK_RECEIPT" geteventmsg_canary intact
expect_value "$ROLLBACK_RECEIPT" detach complete
expect_value "$ROLLBACK_RECEIPT" progress resumed
for event_key in fork vfork clone exec exit \
    supervisor_fork supervisor_vfork supervisor_clone supervisor_exec supervisor_exit \
    child_fork child_vfork child_clone child_exec child_exit \
    interrupt_stop frozen_tids geteventmsg_calls; do
    expect_positive_value "$ROLLBACK_RECEIPT" "$event_key"
done
ROLLBACK_INTERRUPT_STOPS=$(receipt_value "$ROLLBACK_RECEIPT" interrupt_stop)
ROLLBACK_FROZEN_TIDS=$(receipt_value "$ROLLBACK_RECEIPT" frozen_tids)
[ "$ROLLBACK_INTERRUPT_STOPS" -ge "$ROLLBACK_FROZEN_TIDS" ] \
    || fail "not every frozen TID produced an explicit INTERRUPT stop"
ROLLBACK_DETACH_SUPERVISOR_BEFORE=$(receipt_value "$ROLLBACK_RECEIPT" detach_supervisor_before)
ROLLBACK_DETACH_SUPERVISOR_AFTER=$(receipt_value "$ROLLBACK_RECEIPT" detach_supervisor_after)
ROLLBACK_DETACH_CHILD_BEFORE=$(receipt_value "$ROLLBACK_RECEIPT" detach_child_before)
ROLLBACK_DETACH_CHILD_AFTER=$(receipt_value "$ROLLBACK_RECEIPT" detach_child_after)
is_uint "$ROLLBACK_DETACH_SUPERVISOR_BEFORE" \
    && is_uint "$ROLLBACK_DETACH_SUPERVISOR_AFTER" \
    && is_uint "$ROLLBACK_DETACH_CHILD_BEFORE" \
    && is_uint "$ROLLBACK_DETACH_CHILD_AFTER" \
    || fail "detach progress fields are not canonical decimal"
[ "$ROLLBACK_DETACH_SUPERVISOR_AFTER" -gt "$ROLLBACK_DETACH_SUPERVISOR_BEFORE" ] \
    || fail "receipt does not prove supervisor post-detach progress"
[ "$ROLLBACK_DETACH_CHILD_AFTER" -gt "$ROLLBACK_DETACH_CHILD_BEFORE" ] \
    || fail "receipt does not prove child post-detach progress"
ROLLBACK_BITS=$(receipt_value "$ROLLBACK_RECEIPT" geteventmsg_bits)
case "$ROLLBACK_BITS" in 32|64) ;; *) fail "unexpected GETEVENTMSG c_ulong width outcome" ;; esac
verify_untraced_progress "$ROLLBACK_SUPERVISOR_BEFORE" "$ROLLBACK_CHILD_BEFORE"
shutdown_fixture
printf '%s\n' \
    "schema=$SCHEMA" "case=events-freeze-detach-rollback-progress" \
    "nonce=$CURRENT_NONCE" "geteventmsg_bits=$ROLLBACK_BITS" \
    'all_tid_tracerpid=zero-double-stable' 'progress=increased' \
    'fixture=clean-terminal-absence' 'result=pass' 'production_authority=false' \
    >"$CURRENT_CASE/case.rollback.harness.receipt"

# Case 2: kill the uncommitted tracer; EXITKILL must be absent and both tracees must progress.
prepare_case case-precommit
start_fixture
start_tracer precommit-hold
PRECOMMIT_READY="$CURRENT_CASE/precommit.lease.ready"
wait_file "$PRECOMMIT_READY"
expect_keyset "$PRECOMMIT_READY" \
    'child_progress,exitkill,geteventmsg_bits,geteventmsg_canary,leased_tids,mode,nonce,options,schema,seize_nonstop,supervisor_progress'
expect_value "$PRECOMMIT_READY" schema s19k-ptrace-kat-receipt-v1
expect_value "$PRECOMMIT_READY" mode precommit-hold
expect_value "$PRECOMMIT_READY" nonce "$CURRENT_NONCE"
expect_value "$PRECOMMIT_READY" exitkill absent
expect_value "$PRECOMMIT_READY" options 0x5e
expect_value "$PRECOMMIT_READY" seize_nonstop progressed
expect_value "$PRECOMMIT_READY" geteventmsg_canary not-exercised
expect_positive_value "$PRECOMMIT_READY" leased_tids
PRECOMMIT_LEASED=$(receipt_value "$PRECOMMIT_READY" leased_tids)
[ "$PRECOMMIT_LEASED" -ge 10 ] || fail "precommit lease did not cover both five-TID groups"
PRECOMMIT_BITS=$(receipt_value "$PRECOMMIT_READY" geteventmsg_bits)
case "$PRECOMMIT_BITS" in 32|64) ;; *) fail "unexpected precommit GETEVENTMSG width outcome" ;; esac
[ "$PRECOMMIT_BITS" = "$ROLLBACK_BITS" ] || fail "GETEVENTMSG width changed between cases"
PRECOMMIT_SUPERVISOR_BEFORE=$(receipt_value "$PRECOMMIT_READY" supervisor_progress)
PRECOMMIT_CHILD_BEFORE=$(receipt_value "$PRECOMMIT_READY" child_progress)
is_uint "$PRECOMMIT_SUPERVISOR_BEFORE" && is_uint "$PRECOMMIT_CHILD_BEFORE" \
    || fail "precommit progress baselines are not canonical"
PRECOMMIT_TRACER_PID=$LIVE_TRACER_PID
PRECOMMIT_TRACER_START=$LIVE_TRACER_START
proc_owned "$LIVE_TRACER_PID" "$LIVE_TRACER_START" "$LIVE_TRACER_EXE" \
    "$CURRENT_CASE" "$CURRENT_NONCE" || fail "precommit tracer identity changed before SIGKILL"
kill -KILL "$LIVE_TRACER_PID"
wait_owned_terminal "$LIVE_TRACER_PID" "$LIVE_TRACER_START" precommit-tracer
if wait "$LIVE_TRACER_PID"; then
    fail "SIGKILLed precommit tracer returned success"
else
    PRECOMMIT_WAIT_STATUS=$?
fi
[ "$PRECOMMIT_WAIT_STATUS" -eq 137 ] || fail "precommit tracer wait status is not SIGKILL: $PRECOMMIT_WAIT_STATUS"
wait_original_absent "$PRECOMMIT_TRACER_PID" "$PRECOMMIT_TRACER_START"
LIVE_TRACER_PID=0
LIVE_TRACER_START=0
LIVE_TRACER_EXE=
verify_untraced_progress "$PRECOMMIT_SUPERVISOR_BEFORE" "$PRECOMMIT_CHILD_BEFORE"
printf '%s\n' \
    "schema=$SCHEMA" 'case=precommit-tracer-death-without-exitkill' \
    "nonce=$CURRENT_NONCE" "geteventmsg_bits=$PRECOMMIT_BITS" \
    "tracer_wait_status=$PRECOMMIT_WAIT_STATUS" \
    'exitkill=absent' 'all_tid_tracerpid=zero-double-stable' \
    "supervisor_progress=$VERIFIED_SUPERVISOR_AFTER" \
    "child_progress=$VERIFIED_CHILD_AFTER" 'result=pass' 'production_authority=false' \
    >"$CURRENT_CASE/case.precommit-death.harness.receipt"
shutdown_fixture

# Case 3: the tracer publishes commit authority, then kills/reaps supervisor before child.
prepare_case case-commit
start_fixture
COMMIT_SUPERVISOR_PID=$LIVE_FIXTURE_PID
COMMIT_SUPERVISOR_START=$LIVE_FIXTURE_START
COMMIT_CHILD_PID=$LIVE_CHILD_PID
COMMIT_CHILD_START=$LIVE_CHILD_START
start_tracer commit-kill
COMMIT_AUTHORITY="$CURRENT_CASE/commit.authority.receipt"
COMMIT_RECEIPT="$CURRENT_CASE/case.commit-kill.receipt"
wait_file "$COMMIT_AUTHORITY"
expect_keyset "$COMMIT_AUTHORITY" \
    'child_clone,child_exec,child_exit,child_fork,child_vfork,exitkill,frozen_tids,geteventmsg_bits,geteventmsg_calls,geteventmsg_canary,interrupt_stop,mode,nonce,options,order,schema,seize_nonstop,state,supervisor_clone,supervisor_exec,supervisor_exit,supervisor_fork,supervisor_vfork'
expect_value "$COMMIT_AUTHORITY" schema s19k-ptrace-kat-receipt-v1
expect_value "$COMMIT_AUTHORITY" mode commit-kill
expect_value "$COMMIT_AUTHORITY" nonce "$CURRENT_NONCE"
expect_value "$COMMIT_AUTHORITY" exitkill absent
expect_value "$COMMIT_AUTHORITY" options 0x5e
expect_value "$COMMIT_AUTHORITY" seize_nonstop churn-completed-while-seized
expect_value "$COMMIT_AUTHORITY" geteventmsg_canary intact
expect_value "$COMMIT_AUTHORITY" state committed
expect_value "$COMMIT_AUTHORITY" order supervisor-first
expect_positive_value "$COMMIT_AUTHORITY" frozen_tids
expect_positive_value "$COMMIT_AUTHORITY" geteventmsg_calls
expect_positive_value "$COMMIT_AUTHORITY" interrupt_stop
for event_key in supervisor_fork supervisor_vfork supervisor_clone supervisor_exec supervisor_exit \
    child_fork child_vfork child_clone child_exec child_exit; do
    expect_positive_value "$COMMIT_AUTHORITY" "$event_key"
done
COMMIT_FROZEN_TIDS=$(receipt_value "$COMMIT_AUTHORITY" frozen_tids)
COMMIT_INTERRUPT_STOPS=$(receipt_value "$COMMIT_AUTHORITY" interrupt_stop)
[ "$COMMIT_INTERRUPT_STOPS" -ge "$COMMIT_FROZEN_TIDS" ] \
    || fail "committed freeze lacks an explicit INTERRUPT stop for every TID"
COMMIT_BITS=$(receipt_value "$COMMIT_AUTHORITY" geteventmsg_bits)
[ "$COMMIT_BITS" = "$ROLLBACK_BITS" ] || fail "GETEVENTMSG width changed in committed case"
wait_owned_terminal "$LIVE_FIXTURE_PID" "$LIVE_FIXTURE_START" committed-supervisor
if wait "$LIVE_FIXTURE_PID"; then
    fail "committed fixture supervisor unexpectedly returned success"
else
    COMMIT_FIXTURE_STATUS=$?
fi
[ "$COMMIT_FIXTURE_STATUS" -eq 137 ] || fail "committed supervisor wait status is not SIGKILL: $COMMIT_FIXTURE_STATUS"
LIVE_FIXTURE_PID=0
LIVE_FIXTURE_START=0
wait_tracer_success
expect_keyset "$COMMIT_RECEIPT" \
    'child,commit,exit_events,mode,nonce,order,reap,schema,supervisor,terminal_waits'
expect_value "$COMMIT_RECEIPT" schema s19k-ptrace-kat-receipt-v1
expect_value "$COMMIT_RECEIPT" mode commit-kill
expect_value "$COMMIT_RECEIPT" nonce "$CURRENT_NONCE"
expect_value "$COMMIT_RECEIPT" commit published-before-terminal-action
expect_value "$COMMIT_RECEIPT" order supervisor-first
expect_value "$COMMIT_RECEIPT" supervisor terminal-absent
expect_value "$COMMIT_RECEIPT" child terminal-absent
expect_value "$COMMIT_RECEIPT" reap complete
expect_positive_value "$COMMIT_RECEIPT" exit_events
expect_positive_value "$COMMIT_RECEIPT" terminal_waits
wait_original_absent "$COMMIT_SUPERVISOR_PID" "$COMMIT_SUPERVISOR_START"
wait_original_absent "$COMMIT_CHILD_PID" "$COMMIT_CHILD_START"
LIVE_CHILD_PID=0
LIVE_CHILD_START=0
LIVE_FIXTURE_EXE=
printf '%s\n' \
    "schema=$SCHEMA" 'case=committed-supervisor-first-kill-exit-drain-reap' \
    "nonce=$CURRENT_NONCE" "fixture_wait_status=$COMMIT_FIXTURE_STATUS" \
    'commit=published-before-terminal-action' 'order=supervisor-first' \
    'supervisor=terminal-absent' 'child=terminal-absent' \
    'result=pass' 'production_authority=false' \
    >"$CURRENT_CASE/case.commit.harness.receipt"

printf '%s\n' \
    "schema=$SCHEMA" 'kernel=4.9.113' 'machine=aarch64' \
    "tracer_sha256=$TRACER_SHA" "fixture_sha256=$FIXTURE_SHA" \
    "geteventmsg_bits=$ROLLBACK_BITS" 'rollback=pass' 'precommit=pass' \
    'commit=pass' "cap_eff=$CAP_EFF" 'yama_ptrace_scope=absent' \
    'runtime_root=private-root0700-tmp-only' \
    'production_authority=false' >"$RESULTS/kat-summary.receipt"

CURRENT_CASE=
CURRENT_NONCE=
printf '%s\n' "KAT PASS: $RESULTS/kat-summary.receipt"
