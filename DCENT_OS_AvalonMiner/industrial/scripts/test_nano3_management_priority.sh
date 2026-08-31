#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
service=$project_dir/stock-rootfs-overlay/etc/init.d/S50dcent-firstlight
sshd_config=$project_dir/stock-rootfs-overlay/etc/ssh/sshd_config

sh -n "$service"

# Keep the reservation strictly between stock's held-binary values: the main
# cgminer thread calls nice(-10), while its API thread calls nice(+10).
grep -qx 'MANAGEMENT_NICE=-5' "$service"
grep -Fq '/bin/nice -n "$MANAGEMENT_NICE" /sbin/start-stop-daemon \' "$service"
grep -Fq -- '-S -q -p "$PIDFILE" -x "$DAEMON" -- -o PidFile="$PIDFILE"' \
    "$service"

# The elevated recovery plane is deliberately narrow: key-only one-user
# access, no forwarding/tunnels/compression, and bounded concurrency.
for required_sshd_line in \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'AllowUsers admin' \
    'AllowTcpForwarding no' \
    'AllowAgentForwarding no' \
    'X11Forwarding no' \
    'PermitTunnel no' \
    'Compression no' \
    'MaxSessions 2' \
    'MaxStartups 2'; do
    grep -Fqx "$required_sshd_line" "$sshd_config"
done

# The management reservation must never mutate or select the stock miner.  It
# is an sshd launch property, not a miner wrapper, renice, affinity, scheduler,
# cgroup, signal, or restart mechanism.
commands=$(sed '/^[[:space:]]*#/d' "$service")
if printf '%s\n' "$commands" |
   grep -Eq 'btcminer|renice|chrt|taskset|cpuset|cgroup|sched_(set|rr|fifo)'; then
    echo 'management service contains a forbidden miner/scheduler mutation' >&2
    exit 1
fi

# Positive nice is sufficient to exercise BusyBox/coreutils command syntax on
# an unprivileged host.  Lowering to -5 is separately enforced above and is
# performed by root during BusyBox init on the target.
observed=$(/bin/nice -n 5 /bin/sh -c \
    "awk '{ print \$19 }' /proc/self/stat")
[ "$observed" -ge 5 ] || {
    echo "nice launch did not propagate to child (observed $observed)" >&2
    exit 1
}

echo 'Nano 3 management priority tests: PASS'
