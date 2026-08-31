#!/usr/bin/env bash
# Offline verification for the Nano 3 rootfs-only stock-coexistence artifact.
# Run inside the dcent/k230-sdk image with /dcent and /toolbox mounted.

set -euo pipefail

DCENT_DIR="${DCENT_DIR:-/dcent}"
TOOLBOX_DIR="${TOOLBOX_DIR:-/toolbox}"
IMAGE="${IMAGE:-$DCENT_DIR/build/image/DCENT_NANO3_ROOTFS_COEXISTENCE.kdimg}"
DAEMON="${DAEMON:-$DCENT_DIR/dcentrald/target/riscv64gc-unknown-linux-musl/release/dcentrald-avalon}"
EXPECTED_RCS_SHA256=66b4cfc834793fdcab719a96605265872c82869ac61f2f0b5a095e09b4695f36
EXPECTED_BTCMINER_SHA256=e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751

[ -f "$IMAGE" ] || { echo "missing image: $IMAGE" >&2; exit 1; }
[ -f "$DAEMON" ] || { echo "missing daemon: $DAEMON" >&2; exit 1; }
/bin/sh "$DCENT_DIR/scripts/test_nano3_priority_guard.sh"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

PYTHONPATH="$TOOLBOX_DIR/src" python3 - "$IMAGE" "$work" <<'PY'
import sys
from pathlib import Path

from dcent_toolbox.core.kdimg import KdImage

image_path, out_dir = map(Path, sys.argv[1:])
image = KdImage(image_path.read_bytes())
image.verify_all()
expected = [
    ("rootfs_1", 0x01400000, 0x01800000),
    ("rootfs_2", 0x02C00000, 0x01800000),
]
actual = [(part.name, part.nand_offset, part.part_size) for part in image.partitions]
if actual != expected:
    raise SystemExit(f"unexpected partition set: {actual!r}")
for part in image.partitions:
    payload = image._data[part.content_offset : part.content_offset + part.content_size]
    (out_dir / f"{part.name}.ubi").write_bytes(payload)
PY

expected_daemon="$(sha256sum "$DAEMON" | awk '{print $1}')"
for slot in rootfs_1 rootfs_2; do
    ubireader_extract_files -k -o "$work/extract-$slot" "$work/$slot.ubi" >/dev/null
    root="$(find "$work/extract-$slot" -type d -name 'ubi_rootfs_part_*' -print -quit)"
    [ -n "$root" ] && [ -d "$root" ] || {
        echo "$slot: extracted rootfs volume missing" >&2
        exit 1
    }

    [ "$(sha256sum "$root/usr/libexec/dcentos/dcentrald-avalon" | awk '{print $1}')" = \
      "$expected_daemon" ] || {
        echo "$slot: staged daemon hash mismatch" >&2
        exit 1
    }
    [ "$(sha256sum "$root/etc/init.d/rcS" | awk '{print $1}')" = \
      "$EXPECTED_RCS_SHA256" ] || {
        echo "$slot: stock rcS changed" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/usr/libexec/dcentos/dcentrald-avalon")" = 755 ]
    [ "$(stat -c %u:%g "$root/usr/libexec/dcentos/dcentrald-avalon")" = 0:0 ]
    [ "$(stat -c %a "$root/etc/init.d/S98dcent-data")" = 755 ]
    cmp -s "$root/etc/init.d/S98dcent-data" \
        "$DCENT_DIR/stock-runtime-overlay/etc/init.d/S98dcent-data" || {
        echo "$slot: data init service differs from the reviewed overlay" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/etc/user_permission_chg.sh")" = 755 ]
    [ "$(stat -c %a "$root/etc/dcentos/dcent-data-migrate.sh")" = 644 ]
    cmp -s "$root/etc/dcentos/dcent-data-migrate.sh" \
        "$DCENT_DIR/stock-runtime-overlay/etc/dcentos/dcent-data-migrate.sh" || {
        echo "$slot: data migration library differs from the reviewed overlay" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/etc/dcentos/nano3-health-snapshot.sh")" = 755 ]
    [ "$(stat -c %a "$root/etc/dcentos/nano3-persistence-snapshot.sh")" = 755 ]
    cmp -s "$root/etc/dcentos/nano3-persistence-snapshot.sh" \
        "$DCENT_DIR/stock-runtime-overlay/etc/dcentos/nano3-persistence-snapshot.sh" || {
        echo "$slot: persistence snapshot differs from the reviewed overlay" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/etc/init.d/S99dcent-observer")" = 755 ]
    [ "$(stat -c %a "$root/etc/init.d/S99dcent-priority-guard")" = 755 ]
    cmp -s "$root/etc/init.d/S99dcent-priority-guard" \
        "$DCENT_DIR/stock-runtime-overlay/etc/init.d/S99dcent-priority-guard" || {
        echo "$slot: priority guard differs from the reviewed overlay" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/etc/dcentos/nano3-priority-guard.enabled")" = 644 ]
    cmp -s "$root/etc/dcentos/nano3-priority-guard.enabled" \
        "$DCENT_DIR/stock-runtime-overlay/etc/dcentos/nano3-priority-guard.enabled" || {
        echo "$slot: priority-guard enable flag differs from the reviewed overlay" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/README.md")" = 644 ]
    cmp -s "$root/README.md" \
        "$DCENT_DIR/stock-runtime-overlay/README.md" || {
        echo "$slot: staged overlay README differs from the reviewed source" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/etc/init.d/dcentrald")" = 755 ]
    [ "$(stat -c %a "$root/etc/init.d/S50dcent-firstlight")" = 755 ]
    [ "$(stat -c %a "$root/etc/dcentos/dcentrald-avalon.toml.example")" = 644 ]
    [ "$(stat -c %a "$root/etc")" = 755 ]
    [ "$(stat -c %a "$root/etc/sudoers.d")" = 750 ]
    [ -x "$root/bin/nice" ]

    authorized_keys="$root/home/admin/.ssh/authorized_keys"
    [ -f "$authorized_keys" ] || {
        echo "$slot: admin authorized_keys missing" >&2
        exit 1
    }
    [ "$(stat -c %a "$root/home/admin/.ssh")" = 700 ]
    [ "$(stat -c %a "$authorized_keys")" = 600 ]
    [ "$(awk 'NF { count++ } END { print count + 0 }' "$authorized_keys")" = 1 ]
    [ "$(awk 'NF { print $1; exit }' "$authorized_keys")" = ssh-ed25519 ]
    ssh-keygen -l -f "$authorized_keys" >/dev/null
    [ -z "$(find "$root/home" "$root/root" -type f \
        \( -name 'id_ed25519' -o -name 'id_rsa' -o -name 'id_ecdsa' \
           -o -name 'id_dsa' \) -print -quit 2>/dev/null)" ] || {
        echo "$slot: operator SSH private-key filename embedded" >&2
        exit 1
    }
    ! grep -RIlE 'BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY' \
        "$root/home" "$root/root" 2>/dev/null | grep -q . || {
        echo "$slot: operator SSH private-key marker embedded" >&2
        exit 1
    }
    [ -z "$(find "$root/etc/ssh" -maxdepth 1 -type f \
        -name 'ssh_host_*_key' -print -quit)" ] || {
        echo "$slot: reusable SSH host private key embedded" >&2
        exit 1
    }

    [ -z "$(find "$root/etc/init.d" -maxdepth 1 -type f \
        -name 'S*dcentrald*' -print -quit)" ] || {
        echo "$slot: an unsafe dcentrald autostart file exists" >&2
        exit 1
    }
    grep -qx 'profile=stock-coexistence' "$root/etc/dcentos/runtime-mode"
    grep -qx 'dcentrald_autostart=0' "$root/etc/dcentos/runtime-mode"
    grep -qx 'stock_owner=btcminer' "$root/etc/dcentos/runtime-mode"
    grep -q 'ubimkvol /dev/ubi2 -N ubi_data_part -m' \
        "$root/etc/init.d/S98dcent-data"
    grep -q 'dcent_prepare_stock_config_dir /data' \
        "$root/etc/init.d/S98dcent-data"
    grep -q 'init_lock=/run/dcentos-data-init-lock' \
        "$root/etc/init.d/S98dcent-data"
    grep -q 'dcent_cleanup_stale_seed_dirs /tmp' \
        "$root/etc/init.d/S98dcent-data"
    grep -q 'usrcon/systemcfg.ini usrcon/cgminer.ini' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q 'dcent_cleanup_stale_config_workdirs' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q 'dcent_prepare_stock_configs_for_launch /data' \
        "$root/etc/user_permission_chg.sh"
    grep -q 'dcent_block_stock_launch' \
        "$root/etc/user_permission_chg.sh"
    grep -q "grep -q '\^/dev/ubi2_0 /data ubifs ' /proc/mounts" \
        "$root/etc/user_permission_chg.sh"
    grep -q '\[ -d "$readiness_dir" \]' \
        "$root/etc/user_permission_chg.sh"
    grep -q 'mkdir -m 0700 "$readiness_dir"' \
        "$root/etc/init.d/S98dcent-data"
    grep -q "sync || log_refusal 'persistent data sync failed'" \
        "$root/etc/init.d/S98dcent-data"
    grep -q "sync || dcent_block_stock_launch 'configuration sync failed'" \
        "$root/etc/user_permission_chg.sh"
    ! grep -q 'mountpoint -q /data 2>/dev/null && exit 0' \
        "$root/etc/init.d/S98dcent-data"
    grep -qx '\[cgminercfg\]' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -qx 'standard = --lowmem --real-quiet' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    ! grep -q 'mv -f.*dcent_destination' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q 'mktemp -d' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q '\.dcentos-config-init\.XXXXXX' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q '\.dcentos-config-migrate\.XXXXXX' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    ! grep -q '\.dcentos-config-migrate\.\$\$' \
        "$root/etc/dcentos/dcent-data-migrate.sh"
    grep -q '\[ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 \]' \
        "$root/etc/init.d/S98dcent-data"
    grep -q '\[ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 \]' \
        "$root/etc/user_permission_chg.sh"
    grep -q 'chown root:root /data /data/usrcon' \
        "$root/etc/user_permission_chg.sh"
    grep -q 'chown root:root /data' "$root/etc/init.d/S98dcent-data"
    grep -q '8|9)' "$root/etc/init.d/S98dcent-data"
    grep -Fq '[ "$(cat /sys/class/ubi/ubi2_0/name 2>/dev/null)" = ubi_data_part ] &&' \
        "$root/etc/init.d/S98dcent-data"
    grep -q -- '--stock-observer-once' "$root/etc/init.d/S99dcent-observer"
    grep -q -- '--nano3-read-only-observer-once' \
        "$root/etc/init.d/S99dcent-observer"
    grep -Fq '/bin/nice -n 19 /usr/libexec/dcentos/dcentrald-avalon \' \
        "$root/etc/init.d/S99dcent-observer"
    grep -q '/bin/nice -n 19 "$health_snapshot"' \
        "$root/etc/init.d/S99dcent-observer"
    grep -qx 'MANAGEMENT_NICE=-5' \
        "$root/etc/init.d/S50dcent-firstlight"
    grep -Fq '/bin/nice -n "$MANAGEMENT_NICE" /sbin/start-stop-daemon \' \
        "$root/etc/init.d/S50dcent-firstlight"
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
        grep -Fqx "$required_sshd_line" "$root/etc/ssh/sshd_config"
    done
    grep -q 'mkdir -m 0700 "$observer_lock"' \
        "$root/etc/init.d/S99dcent-observer"
    # Priority guard: exact held-binary admission, a complete unique target
    # set, nice {10,0} pre-admission, per-target post-checks, structured final
    # success, and no /run writes before exact tmpfs admission. The behavioral
    # harness above exercises the success and fail-closed cases independently.
    grep -Fq '[ -f "$enable_flag" ] || exit 0' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fqx \
        "expected_btcminer_sha256=$EXPECTED_BTCMINER_SHA256" \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'is_exact_mount "$run_root" tmpfs || exit 0' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'api_count=$((api_count + 1))' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'watchdog_thread_count=$((watchdog_thread_count + 1))' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'watchpool_threa_count=$((watchpool_threa_count + 1))' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'watchpool_threa)' \
        "$root/etc/init.d/S99dcent-priority-guard"
    ! grep -qw 'watchpool_thread' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'if [ "$task_nice" != 10 ] && [ "$task_nice" != 0 ]' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'busybox renice -n 0 -p "$correction_tid" >/dev/null 2>&1' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'failure_reason=renice_postcheck_failed' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'pass_${pass_number}_all_targets_nice_zero=1' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'pass_${pass_number}_observed_btcminer_sha256=$observed_btcminer_sha256' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'pass_${pass_number}_btcminer_hash_admitted=1' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'guard_initial_admission=success' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fq 'guard_terminal=success' \
        "$root/etc/init.d/S99dcent-priority-guard"
    grep -Fqx 'guard_pass_limit=60' \
        "$root/etc/init.d/S99dcent-priority-guard"
    ! sed '/^[[:space:]]*#/d' \
        "$root/etc/init.d/S99dcent-priority-guard" | \
        grep -q 'cgminer_thread'
    ! sed '/^[[:space:]]*#/d' \
        "$root/etc/init.d/S99dcent-priority-guard" | \
        grep -Eq '(^|[;&|[:space:]])(kill|pkill|killall|chrt|taskset|cpuset|cgroup|start-stop-daemon)([;&|[:space:]]|$)'
    grep -q 'scope=bounded-read-only-proc-health' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    ! grep -Eq '/cmdline|/environ|cgminer\.ini|systemcfg\.ini' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    grep -q 'safety_heartbeat=0' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    grep -q 'thermal_custody_proven=0' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    grep -q '\[ "$task_count" -ge 128 \]' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    grep -q '\[ "$fd_count" -ge 1024 \]' \
        "$root/etc/dcentos/nano3-health-snapshot.sh"
    grep -q 'schema=dcent-nano3-persistence-snapshot-v1' \
        "$root/etc/dcentos/nano3-persistence-snapshot.sh"
    grep -q 'configuration_values_printed=false' \
        "$root/etc/dcentos/nano3-persistence-snapshot.sh"
    grep -q 'authorizes_reboot=false' \
        "$root/etc/dcentos/nano3-persistence-snapshot.sh"
    ! sed '/^[[:space:]]*#/d' \
        "$root/etc/dcentos/nano3-persistence-snapshot.sh" | \
        grep -Eq '(^|[;&|[:space:]])(reboot|poweroff|halt|kill|pkill|killall|ssh|scp|curl|wget)([;&|[:space:]]|$)'
    bash -n "$root/etc/user_permission_chg.sh" \
        "$root/etc/init.d/S98dcent-data" \
        "$root/etc/dcentos/dcent-data-migrate.sh" \
        "$root/etc/dcentos/nano3-health-snapshot.sh" \
        "$root/etc/dcentos/nano3-persistence-snapshot.sh" \
        "$root/etc/init.d/S99dcent-observer" \
        "$root/etc/init.d/S99dcent-priority-guard" \
        "$root/etc/init.d/S50dcent-firstlight" \
        "$root/etc/init.d/dcentrald"

    readelf -h "$root/usr/libexec/dcentos/dcentrald-avalon" |
        grep -q 'Machine:.*RISC-V'
    ! readelf -l "$root/usr/libexec/dcentos/dcentrald-avalon" |
        grep -q INTERP
    ! readelf -d "$root/usr/libexec/dcentos/dcentrald-avalon" 2>/dev/null |
        grep -q NEEDED
    strings "$root/usr/libexec/dcentos/dcentrald-avalon" |
        grep -F -- '--stock-observer-once' >/dev/null
    strings "$root/usr/libexec/dcentos/dcentrald-avalon" |
        grep -F -- '--nano3-read-only-observer-once' >/dev/null

    echo "$slot: verified"
done

echo "COEXISTENCE_ROOTFS_ROUNDTRIP_OK daemon_sha256=$expected_daemon"
