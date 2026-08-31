#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
guard=$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-priority-guard
flag=$project_dir/stock-runtime-overlay/etc/dcentos/nano3-priority-guard.enabled
expected_hash=e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751

sh -n "$guard"
[ -f "$flag" ]
grep -Fqx "expected_btcminer_sha256=$expected_hash" "$guard"
grep -Fq '[ -f "$enable_flag" ] || exit 0' "$guard"
grep -Fq 'is_exact_mount "$run_root" tmpfs || exit 0' "$guard"
grep -Fq 'watchpool_threa)' "$guard"
! grep -qw 'watchpool_thread' "$guard"
grep -Fq 'busybox renice -n 0 -p "$correction_tid" >/dev/null 2>&1' "$guard"
grep -Fq 'pass_${pass_number}_all_targets_nice_zero=1' "$guard"
grep -Fq 'guard_initial_admission=success' "$guard"
grep -Fq 'guard_terminal=success' "$guard"

commands=$(sed '/^[[:space:]]*#/d' "$guard")
if printf '%s\n' "$commands" | grep -q 'cgminer_thread'; then
    echo 'guard mutates or selects the mining thread' >&2
    exit 1
fi
if printf '%s\n' "$commands" |
   grep -Eq '(^|[;&|[:space:]])(kill|pkill|killall|chrt|taskset|cpuset|cgroup|start-stop-daemon)([;&|[:space:]]|$)'; then
    echo 'guard contains a forbidden miner mutation or scheduler change' >&2
    exit 1
fi
if printf '%s\n' "$commands" | grep -Eq 'while :|while true'; then
    echo 'guard contains an unbounded loop' >&2
    exit 1
fi

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

make_stat() {
    nice_value=$1
    # /proc/<pid>/task/<tid>/stat field 19 is nice. Target comm values contain
    # no spaces, matching the real target names and the guard's bounded parser.
    printf '1 (thread) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %s 0 0 0 0 0\n' \
        "$nice_value"
}

make_fake_commands() {
    fakebin=$1
    mkdir -p "$fakebin"
    cp "$test_root/fake-pidof" "$fakebin/pidof"
    cp "$test_root/fake-busybox" "$fakebin/busybox"
    cp "$test_root/fake-sleep" "$fakebin/sleep"
    cp "$test_root/fake-logger" "$fakebin/logger"
    chmod 0755 "$fakebin"/*
}

cat > "$test_root/fake-pidof" <<'EOF'
#!/bin/sh
cat "$TEST_CASE_DIR/pidof.out"
EOF
cat > "$test_root/fake-busybox" <<'EOF'
#!/bin/sh
[ "$1" = renice ] && [ "$2" = -n ] && [ "$3" = 0 ] && [ "$4" = -p ] || exit 90
tid=$5
printf '%s\n' "$*" >> "$TEST_CASE_DIR/renice.log"
if [ "${TEST_FAIL_RENICE_TID:-}" = "$tid" ]; then
    exit 91
fi
if [ "${TEST_SKIP_POSTCHECK_TID:-}" != "$tid" ]; then
    stat_file=$TEST_PROC_ROOT/4242/task/$tid/stat
    awk '{$19 = 0; print}' "$stat_file" > "$stat_file.next"
    mv "$stat_file.next" "$stat_file"
fi
EOF
cat > "$test_root/fake-sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$test_root/fake-logger" <<'EOF'
#!/bin/sh
exit 0
EOF

prepare_case() {
    case_name=$1
    case_dir=$test_root/$case_name
    proc_dir=$case_dir/proc
    run_dir=$case_dir/run
    mnt_dir=$case_dir/mnt
    fakebin=$case_dir/fakebin
    mkdir -p "$proc_dir/4242/task" "$run_dir" "$mnt_dir"
    : > "$case_dir/enabled"
    : > "$case_dir/renice.log"
    printf '4242\n' > "$case_dir/pidof.out"
    printf 'none %s tmpfs rw 0 0\nnone %s ubifs rw 0 0\n' \
        "$run_dir" "$mnt_dir" > "$proc_dir/mounts"
    printf 'synthetic exact-binary input\n' > "$proc_dir/4242/exe"
    synthetic_hash=$(sha256sum "$proc_dir/4242/exe" | awk '{print $1}')
    make_fake_commands "$fakebin"

    case_guard=$case_dir/guard
    sed \
        -e "s|^enable_flag=/etc/dcentos/nano3-priority-guard.enabled$|enable_flag=$case_dir/enabled|" \
        -e "s|^proc_root=/proc$|proc_root=$proc_dir|" \
        -e "s|^run_root=/run$|run_root=$run_dir|" \
        -e "s|^mnt_mount=/mnt$|mnt_mount=$mnt_dir|" \
        -e "s|^expected_btcminer_sha256=.*$|expected_btcminer_sha256=$synthetic_hash|" \
        -e 's/^startup_attempt_limit=.*/startup_attempt_limit=1/' \
        -e 's/^startup_sleep_seconds=.*/startup_sleep_seconds=0/' \
        -e 's/^settle_sleep_seconds=.*/settle_sleep_seconds=0/' \
        -e 's/^guard_pass_limit=.*/guard_pass_limit=1/' \
        -e 's/^guard_pass_sleep_seconds=.*/guard_pass_sleep_seconds=0/' \
        "$guard" > "$case_guard"
    chmod 0755 "$case_guard"
}

add_task() {
    tid=$1
    name=$2
    nice_value=$3
    task_dir=$proc_dir/4242/task/$tid
    mkdir -p "$task_dir"
    printf '%s\n' "$name" > "$task_dir/comm"
    make_stat "$nice_value" > "$task_dir/stat"
}

run_case() {
    rm -rf -- "$run_dir/dcentos-priority-guard" \
        "$run_dir/dcentos-priority-guard.txt"
    TEST_CASE_DIR=$case_dir TEST_PROC_ROOT=$proc_dir \
        PATH=$fakebin:/usr/bin:/bin "$case_guard" start
    report=$run_dir/dcentos-priority-guard.txt
    spins=0
    while [ ! -f "$report" ] && [ "$spins" -lt 1000 ]; do
        spins=$((spins + 1))
    done
    [ -f "$report" ] || {
        echo "$case_name: guard report was not created" >&2
        exit 1
    }
    spins=0
    while ! grep -q '^guard_terminal=' "$report" 2>/dev/null &&
          [ "$spins" -lt 1000 ]; do
        spins=$((spins + 1))
    done
    grep -q '^guard_terminal=' "$report" || {
        echo "$case_name: guard did not reach a terminal result" >&2
        exit 1
    }
}

assert_zero_renice() {
    [ ! -s "$case_dir/renice.log" ] || {
        echo "$case_name: expected zero renice calls" >&2
        cat "$case_dir/renice.log" >&2
        exit 1
    }
}

assert_failure() {
    reason=$1
    grep -qx 'guard_terminal=failure' "$report"
    grep -qx 'all_targets_nice_zero=0' "$report"
    grep -qx "guard_failure_reason=$reason" "$report"
    ! grep -qx 'guard_terminal=success' "$report"
}

# Exact admitted binary + one of each target at nice 10: exactly three calls,
# stable post-checks, and the only terminal success sentinel.
prepare_case valid
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
run_case
[ "$(wc -l < "$case_dir/renice.log" | tr -d ' ')" -eq 3 ]
grep -qx 'renice -n 0 -p 101' "$case_dir/renice.log"
grep -qx 'renice -n 0 -p 102' "$case_dir/renice.log"
grep -qx 'renice -n 0 -p 103' "$case_dir/renice.log"
grep -qx "expected_btcminer_sha256=$synthetic_hash" "$report"
grep -qx "observed_btcminer_sha256=$synthetic_hash" "$report"
grep -qx 'btcminer_hash_admitted=1' "$report"
grep -qx 'pass_1_target_api_post_nice=0' "$report"
grep -qx 'pass_1_target_watchdog_thread_post_nice=0' "$report"
grep -qx 'pass_1_target_watchpool_threa_post_nice=0' "$report"
grep -qx "pass_1_observed_btcminer_sha256=$synthetic_hash" "$report"
grep -qx 'pass_1_btcminer_hash_admitted=1' "$report"
grep -qx 'all_targets_nice_zero=1' "$report"
grep -qx 'guard_initial_admission=success' "$report"
grep -qx 'guard_terminal=success' "$report"

# Already-corrected target state is admitted without lowering any priority.
prepare_case already_zero
add_task 101 API 0
add_task 102 watchdog_thread 0
add_task 103 watchpool_threa 0
run_case
assert_zero_renice
grep -qx 'guard_terminal=success' "$report"

# Hash mismatch: exact expected/observed values are reported and no mutation.
prepare_case hash_mismatch
sed "s|^expected_btcminer_sha256=.*$|expected_btcminer_sha256=$expected_hash|" \
    "$case_guard" > "$case_guard.next"
mv "$case_guard.next" "$case_guard"
chmod 0755 "$case_guard"
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
run_case
assert_zero_renice
assert_failure btcminer_hash_mismatch
grep -qx "expected_btcminer_sha256=$expected_hash" "$report"
grep -qx "observed_btcminer_sha256=$synthetic_hash" "$report"
grep -qx 'btcminer_hash_admitted=0' "$report"

# Multiple btcminer PIDs never reach hash admission or mutation.
prepare_case multiple_pid
printf '4242 4343\n' > "$case_dir/pidof.out"
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
run_case
assert_zero_renice
assert_failure multiple_btcminer_pids

# Missing and duplicate target sets both fail before the first renice.
prepare_case missing_target
add_task 101 API 10
add_task 102 watchdog_thread 10
run_case
assert_zero_renice
assert_failure missing_target_thread

# Linux TASK_COMM_LEN is 16 including NUL. The 16-character source/DWARF
# label is impossible in /proc and must not be accepted as the live comm.
prepare_case impossible_untruncated_comm
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_thread 10
run_case
assert_zero_renice
assert_failure missing_target_thread

prepare_case duplicate_target
add_task 101 API 10
add_task 104 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
run_case
assert_zero_renice
assert_failure duplicate_target_thread

# Any priority outside the exact evidenced {10,0} set causes zero mutation.
prepare_case unexpected_nice
add_task 101 API 10
add_task 102 watchdog_thread -10
add_task 103 watchpool_threa 10
run_case
assert_zero_renice
assert_failure unexpected_target_nice

# A renice error or a non-zero post-check is terminally non-passing and can
# never leave the final success sentinel in the report.
prepare_case renice_failure
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
TEST_FAIL_RENICE_TID=102 run_case
assert_failure renice_failed
[ "$(wc -l < "$case_dir/renice.log" | tr -d ' ')" -eq 2 ]
! grep -qx 'guard_initial_admission=success' "$report"
! grep -qx 'pass_1_all_targets_nice_zero=1' "$report"

prepare_case postcheck_failure
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
TEST_SKIP_POSTCHECK_TID=101 run_case
assert_failure renice_postcheck_failed
! grep -qx 'guard_initial_admission=success' "$report"

# Without an exact /run tmpfs record, there must be no report, lock, or renice.
prepare_case run_not_tmpfs
sed "s|$run_dir tmpfs|$run_dir ext4|" "$proc_dir/mounts" > "$proc_dir/mounts.next"
mv "$proc_dir/mounts.next" "$proc_dir/mounts"
add_task 101 API 10
add_task 102 watchdog_thread 10
add_task 103 watchpool_threa 10
TEST_CASE_DIR=$case_dir TEST_PROC_ROOT=$proc_dir \
    PATH=$fakebin:/usr/bin:/bin "$case_guard" start
[ ! -e "$run_dir/dcentos-priority-guard" ]
[ ! -e "$run_dir/dcentos-priority-guard.txt" ]
assert_zero_renice

echo 'Nano 3 priority guard behavior tests: PASS'
