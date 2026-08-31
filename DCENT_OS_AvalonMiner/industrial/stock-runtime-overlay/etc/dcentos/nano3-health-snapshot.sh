#!/bin/sh
# Bounded, boot-local diagnostics for the Nano 3 management-starvation soak.
# Never reads configuration, command lines, environments, devices, or IPC;
# never signals, renices, or otherwise mutates btcminer.
# Collector completion is not a thermal/fan/watchdog/rail safety heartbeat.

set -u

proc_root=${DCENT_HEALTH_PROC_ROOT:-/proc}
run_root=${DCENT_HEALTH_RUN_ROOT:-/run}
initial_delay=${DCENT_HEALTH_INITIAL_DELAY:-210}
interval=${DCENT_HEALTH_INTERVAL:-30}
sample_limit=${DCENT_HEALTH_SAMPLE_LIMIT:-7}
fixed_pid=${DCENT_HEALTH_BTCMINER_PID:-}
dmesg_file=${DCENT_HEALTH_DMESG_FILE:-}
output_dir=$run_root/dcentos-health
worker_lock=$run_root/dcentos-health-worker
test_mode=${DCENT_HEALTH_TEST_MODE:-0}

case "$initial_delay:$interval:$sample_limit" in
    *[!0-9:]*|:*|*::*|*:|*:*:0) exit 1 ;;
esac
[ "$initial_delay" -le 900 ] || exit 1
[ "$sample_limit" -le 16 ] || exit 1
case "$test_mode" in
    0)
        [ "$interval" -ge 10 ] && [ "$interval" -le 300 ] || exit 1
        ;;
    1)
        [ "$run_root" != /run ] && [ "$interval" -le 300 ] || exit 1
        ;;
    *) exit 1 ;;
esac

# Refuse a rootfs/UBIFS fallback. Diagnostics are allowed only on the boot-local
# tmpfs mounted by stock inittab/fstab before rcS.
run_is_tmpfs=0
while read -r _source mountpoint fstype _rest; do
    if [ "$mountpoint" = "$run_root" ] && [ "$fstype" = tmpfs ]; then
        run_is_tmpfs=1
        break
    fi
done <"$proc_root/mounts" 2>/dev/null
[ "$run_is_tmpfs" = 1 ] || exit 1

# Direct/manual invocation is also singleton, not only the S99 call site.
mkdir -m 0700 "$worker_lock" 2>/dev/null || exit 1

umask 077
if [ ! -e "$output_dir" ]; then
    mkdir -m 0700 "$output_dir" || exit 1
fi
[ -d "$output_dir" ] && [ ! -L "$output_dir" ] || exit 1
printf '%s\n' 'collector_state=armed_not_safety' >"$output_dir/state"

sleep "$initial_delay"
sample=0
while [ "$sample" -lt "$sample_limit" ]; do
    temporary=$output_dir/.snapshot-$sample.$$
    destination=$output_dir/snapshot-$sample.txt
    if [ -n "$fixed_pid" ]; then
        btcminer_pid=$fixed_pid
    else
        btcminer_pid=$(pidof btcminer 2>/dev/null | awk '{print $1}')
    fi

    {
        echo 'scope=bounded-read-only-proc-health'
        echo "sample=$sample"
        date '+captured_at=%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || true
        printf 'uptime='; cat "$proc_root/uptime" 2>/dev/null || echo unavailable
        printf 'loadavg='; cat "$proc_root/loadavg" 2>/dev/null || echo unavailable
        echo 'memory_begin'
        grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|Slab|SReclaimable|SUnreclaim):' \
            "$proc_root/meminfo" 2>/dev/null || true
        echo 'memory_end'
        echo "btcminer_pid=${btcminer_pid:-missing}"
        if [ -n "$btcminer_pid" ] &&
           [ -d "$proc_root/$btcminer_pid" ]; then
            echo 'btcminer_status_begin'
            grep -E '^(Name|State|Pid|PPid|Threads|VmPeak|VmSize|VmRSS|VmSwap|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' \
                "$proc_root/$btcminer_pid/status" 2>/dev/null || true
            echo 'btcminer_status_end'
            fd_count=0
            fd_truncated=0
            for fd_entry in "$proc_root/$btcminer_pid"/fd/*; do
                [ -e "$fd_entry" ] || [ -L "$fd_entry" ] || continue
                if [ "$fd_count" -ge 1024 ]; then
                    fd_truncated=1
                    break
                fi
                fd_count=$((fd_count + 1))
            done
            echo "btcminer_fd_count=$fd_count"
            echo "btcminer_fd_count_truncated=$fd_truncated"
            echo 'btcminer_tasks_begin'
            task_count=0
            for task_dir in "$proc_root/$btcminer_pid"/task/*; do
                [ -d "$task_dir" ] || continue
                if [ "$task_count" -ge 128 ]; then
                    echo 'tasks_truncated=1'
                    break
                fi
                task_id=${task_dir##*/}
                task_comm=unavailable
                task_wchan=unavailable
                task_stat=unavailable
                IFS= read -r task_comm <"$task_dir/comm" 2>/dev/null || true
                IFS= read -r task_wchan <"$task_dir/wchan" 2>/dev/null || true
                IFS= read -r task_stat <"$task_dir/stat" 2>/dev/null || true
                printf 'tid=%s comm=%s wchan=%s stat=%s\n' \
                    "$task_id" "$task_comm" "$task_wchan" "$task_stat"
                task_count=$((task_count + 1))
            done
            echo 'btcminer_tasks_end'
        fi
        printf 'file_nr='; cat "$proc_root/sys/fs/file-nr" 2>/dev/null || echo unavailable
        echo 'interrupts_begin'
        head -n 256 "$proc_root/interrupts" 2>/dev/null || true
        echo 'interrupts_end'
        echo 'kernel_faults_begin'
        if [ -n "$dmesg_file" ]; then
            cat "$dmesg_file" 2>/dev/null
        else
            dmesg 2>/dev/null
        fi | grep -Ei 'oom|out of memory|hung|soft lockup|watchdog|wlan|ubifs|error|fail' |
            tail -n 80 || true
        echo 'kernel_faults_end'
        echo 'collector_complete=1'
        echo 'safety_heartbeat=0'
        echo 'thermal_custody_proven=0'
    } >"$temporary" 2>&1 || {
        rm -f "$temporary"
        exit 1
    }
    mv -f "$temporary" "$destination" || exit 1
    sample=$((sample + 1))
    [ "$sample" -lt "$sample_limit" ] && sleep "$interval"
done

printf '%s\n' 'collector_state=complete_not_safety' >"$output_dir/state"
