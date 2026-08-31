#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
snapshot=$project_dir/stock-runtime-overlay/etc/dcentos/nano3-health-snapshot.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/nano3-health-test.XXXXXX")
trap 'rm -rf "$test_root"' 0 1 2 15

proc=$test_root/proc
run=$test_root/run
pid=211
mkdir -p "$proc/$pid/task/$pid" "$proc/$pid/fd" "$proc/sys/fs" "$run"
printf '%s\n' '123.00 100.00' >"$proc/uptime"
printf '%s\n' '1.00 0.50 0.25 1/50 211' >"$proc/loadavg"
printf '%s\n' 'MemTotal: 100 kB' 'MemFree: 20 kB' 'Cached: 10 kB' \
    >"$proc/meminfo"
printf '%s\n' 'Name: btcminer' 'State: R (running)' 'Pid: 211' 'Threads: 1' \
    >"$proc/$pid/status"
printf '%s\n' btcminer >"$proc/$pid/task/$pid/comm"
printf '%s\n' do_work >"$proc/$pid/task/$pid/wchan"
printf '%s\n' '211 (btcminer) R 1 2 3' >"$proc/$pid/task/$pid/stat"
# Exercise the behavioral task bound without spawning any target helpers.
task_id=300
while [ "$task_id" -le 428 ]; do
    mkdir "$proc/$pid/task/$task_id"
    printf '%s\n' worker >"$proc/$pid/task/$task_id/comm"
    printf '%s\n' futex_wait >"$proc/$pid/task/$task_id/wchan"
    printf '%s\n' "$task_id (worker) S 1 2 3" \
        >"$proc/$pid/task/$task_id/stat"
    task_id=$((task_id + 1))
done
printf '%s\n' '10 0 100' >"$proc/sys/fs/file-nr"
printf '%s\n' 'CPU0' '1: 10 timer' >"$proc/interrupts"
printf 'tmpfs %s tmpfs rw,nosuid,nodev 0 0\n' "$run" >"$proc/mounts"
printf '%s\n' 'watchdog: healthy' >"$test_root/dmesg"

DCENT_HEALTH_PROC_ROOT=$proc \
DCENT_HEALTH_RUN_ROOT=$run \
DCENT_HEALTH_INITIAL_DELAY=0 \
DCENT_HEALTH_INTERVAL=0 \
DCENT_HEALTH_SAMPLE_LIMIT=1 \
DCENT_HEALTH_TEST_MODE=1 \
DCENT_HEALTH_BTCMINER_PID=$pid \
DCENT_HEALTH_DMESG_FILE=$test_root/dmesg \
    sh "$snapshot"

output=$run/dcentos-health/snapshot-0.txt
grep -qx 'scope=bounded-read-only-proc-health' "$output"
grep -qx 'btcminer_pid=211' "$output"
grep -q 'tid=211 comm=btcminer .*wchan=do_work .*stat=211 (btcminer) R' "$output"
grep -qx 'watchdog: healthy' "$output"
grep -qx 'collector_complete=1' "$output"
grep -qx 'safety_heartbeat=0' "$output"
grep -qx 'thermal_custody_proven=0' "$output"
grep -qx 'tasks_truncated=1' "$output"
grep -qx 'collector_state=complete_not_safety' "$run/dcentos-health/state"
grep -q '\[ "$task_count" -ge 128 \]' "$snapshot"
grep -q '\[ "$fd_count" -ge 1024 \]' "$snapshot"

! grep -Eq '/cmdline|/environ|cgminer\.ini|systemcfg\.ini' "$snapshot"
grep -q '/bin/nice -n 19 "$health_snapshot"' \
    "$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-observer"
grep -q -- '--nano3-read-only-observer-once' \
    "$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-observer"
grep -Fq '/bin/nice -n 19 /usr/libexec/dcentos/dcentrald-avalon \' \
    "$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-observer"
grep -q 'explicitly omits timer5' \
    "$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-observer"
grep -q 'mkdir -m 0700 "$observer_lock"' \
    "$project_dir/stock-runtime-overlay/etc/init.d/S99dcent-observer"

# A repeated direct launch is refused by the boot-local singleton.
if DCENT_HEALTH_PROC_ROOT=$proc DCENT_HEALTH_RUN_ROOT=$run \
   DCENT_HEALTH_INITIAL_DELAY=0 DCENT_HEALTH_INTERVAL=0 \
   DCENT_HEALTH_SAMPLE_LIMIT=1 DCENT_HEALTH_TEST_MODE=1 \
   DCENT_HEALTH_BTCMINER_PID=$pid DCENT_HEALTH_DMESG_FILE=$test_root/dmesg \
       sh "$snapshot"; then
    echo 'duplicate collector unexpectedly succeeded' >&2
    exit 1
fi

# Production bounds reject an unbounded sample count before any output.
bounded_run=$test_root/bounded-run
mkdir "$bounded_run"
if DCENT_HEALTH_PROC_ROOT=$proc DCENT_HEALTH_RUN_ROOT=$bounded_run \
   DCENT_HEALTH_INITIAL_DELAY=0 DCENT_HEALTH_INTERVAL=10 \
   DCENT_HEALTH_SAMPLE_LIMIT=17 DCENT_HEALTH_TEST_MODE=0 \
       sh "$snapshot"; then
    echo 'unbounded collector configuration unexpectedly succeeded' >&2
    exit 1
fi
[ ! -e "$bounded_run/dcentos-health" ]

# A non-tmpfs output root fails closed and receives no diagnostic files.
unsafe_run=$test_root/unsafe-run
unsafe_proc=$test_root/unsafe-proc
mkdir "$unsafe_run" "$unsafe_proc"
printf 'rootfs %s ubifs rw 0 0\n' "$unsafe_run" >"$unsafe_proc/mounts"
if DCENT_HEALTH_PROC_ROOT=$unsafe_proc DCENT_HEALTH_RUN_ROOT=$unsafe_run \
   DCENT_HEALTH_INITIAL_DELAY=0 DCENT_HEALTH_INTERVAL=0 \
   DCENT_HEALTH_SAMPLE_LIMIT=1 DCENT_HEALTH_TEST_MODE=1 \
       sh "$snapshot"; then
    echo 'non-tmpfs collector unexpectedly succeeded' >&2
    exit 1
fi
[ ! -e "$unsafe_run/dcentos-health" ]

echo 'Nano 3 bounded health snapshot tests: PASS'
