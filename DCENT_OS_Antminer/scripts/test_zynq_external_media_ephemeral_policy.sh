#!/bin/sh
# Host-only behavioral/static regression for the Zynq external-media posture.
# No block device, MTD/UBI node, network endpoint, or hardware is contacted.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
POLICY="$PROJECT_ROOT/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/zynq-external-media-ephemeral.sh"
EARLY_INIT="$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-early-init.sh"
PERSIST="$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S45persistent"
UPGRADE="$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99upgrade"
XIL25_SEED="$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/init.d/S81dcentos-xil25-seed"
S19J_OWNER="$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald"
S19PRO_OWNER="$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/init.d/S82dcentrald"
RC_START="$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/rcS"
RC_STOP="$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/rcK"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/dcent-zynq-external-policy.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

require_text() {
    file=$1
    pattern=$2
    grep -Fq "$pattern" "$file" || fail "$file lacks required policy token: $pattern"
}

require_order() {
    file=$1
    first=$2
    second=$3
    first_line=$(grep -nF "$first" "$file" | head -n 1 | cut -d: -f1)
    second_line=$(grep -nF "$second" "$file" | head -n 1 | cut -d: -f1)
    [ -n "$first_line" ] && [ -n "$second_line" ] \
        || fail "$file lacks ordered policy tokens"
    [ "$first_line" -lt "$second_line" ] \
        || fail "$file evaluates '$second' before '$first'"
}

# Exercise the real helper with a mount shim. All mount targets are confined to
# the temporary fixture; the shim records intent and synthesizes /proc/mounts.
mkdir -p "$WORK/bin" "$WORK/etc/dcentos" "$WORK/data" "$WORK/tmp" "$WORK/run"
: > "$WORK/etc/dcentos/external-media-ephemeral-root"
: > "$WORK/mounts"
cat > "$WORK/bin/mount" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_MOUNT_LOG"
case "$*" in
    "-t tmpfs -o size=16m,mode=0755,nosuid,nodev,noexec tmpfs $DCENTOS_EXTERNAL_MEDIA_DATA_DIR")
        printf 'tmpfs %s tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n' \
            "$DCENTOS_EXTERNAL_MEDIA_DATA_DIR" >> "$MOCK_MOUNTS_FILE"
        ;;
    "-t overlay overlay -o "*" $DCENTOS_EXTERNAL_MEDIA_ETC_DIR")
        ;;
    *)
        echo "unexpected mount command: $*" >&2
        exit 97
        ;;
esac
SH
chmod 0755 "$WORK/bin/mount"

export PATH="$WORK/bin:$PATH"
export MOCK_MOUNT_LOG="$WORK/mount.log"
export MOCK_MOUNTS_FILE="$WORK/mounts"
export DCENTOS_EXTERNAL_MEDIA_MARKER="$WORK/etc/dcentos/external-media-ephemeral-root"
export DCENTOS_EXTERNAL_MEDIA_DATA_DIR="$WORK/data"
export DCENTOS_EXTERNAL_MEDIA_ETC_DIR="$WORK/etc"
export DCENTOS_EXTERNAL_MEDIA_TMP_DIR="$WORK/tmp"
export DCENTOS_EXTERNAL_MEDIA_RUN_DIR="$WORK/run"
export DCENTOS_EXTERNAL_MEDIA_READY_FILE="$WORK/run/dcentos/external-media-ephemeral-ready"
export DCENTOS_MOUNTS_FILE="$WORK/mounts"

# shellcheck disable=SC1090
. "$POLICY"
dcent_external_media_prepare_ephemeral_root \
    || fail "real external-media helper refused the isolated tmpfs fixture"
[ -f "$DCENTOS_EXTERNAL_MEDIA_READY_FILE" ] || fail "helper did not publish readiness proof"
dcent_external_media_data_is_ephemeral || fail "helper did not prove exact tmpfs /data backing"
[ -d "$WORK/data/dcent" ] || fail "helper did not prepare volatile management state"
[ "$(wc -l < "$MOCK_MOUNT_LOG" | tr -d ' ')" -eq 2 ] \
    || fail "helper issued an unexpected number of mount operations"
if grep -Eiq 'mtd|ubi|nand|fw_setenv|flash|ubiformat|ubiupdate' "$MOCK_MOUNT_LOG"; then
    fail "helper attempted a persistent-storage operation"
fi

# A malformed marker must fail before the first mount and leave readiness absent.
rm -f "$DCENTOS_EXTERNAL_MEDIA_READY_FILE" "$MOCK_MOUNT_LOG"
rm -f "$DCENTOS_EXTERNAL_MEDIA_MARKER"
mkdir "$DCENTOS_EXTERNAL_MEDIA_MARKER"
if dcent_external_media_prepare_ephemeral_root >/dev/null 2>&1; then
    fail "directory marker was accepted as external-media authority"
fi
[ ! -e "$MOCK_MOUNT_LOG" ] || fail "malformed marker reached mount operation"
rmdir "$DCENTOS_EXTERNAL_MEDIA_MARKER"
: > "$DCENTOS_EXTERNAL_MEDIA_MARKER"

# S45 must accept only the exact volatile mount, and its stop path must never
# persist host keys or an entropy seed.
: > "$DCENTOS_EXTERNAL_MEDIA_READY_FILE"
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
DCENTOS_EXTERNAL_MEDIA_READY_FILE="$DCENTOS_EXTERNAL_MEDIA_READY_FILE" \
DCENTOS_EXTERNAL_MEDIA_DATA_DIR="$DCENTOS_EXTERNAL_MEDIA_DATA_DIR" \
DCENTOS_MOUNTS_FILE="$DCENTOS_MOUNTS_FILE" \
    "$PERSIST" start > "$WORK/persist-start.log" 2>&1 \
    || fail "S45 rejected exact external-media tmpfs backing"
require_text "$WORK/persist-start.log" "persistent save/restore disabled"
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
    "$PERSIST" stop > "$WORK/persist-stop.log" 2>&1 \
    || fail "S45 external-media stop was not a safe no-op"
require_text "$WORK/persist-stop.log" "refusing persistent SSH-key or entropy-seed writes"
printf 'ubi0:rootfs_data %s ubifs rw,relatime 0 0\n' "$DCENTOS_EXTERNAL_MEDIA_DATA_DIR" > "$WORK/bad-mounts"
if DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
    DCENTOS_EXTERNAL_MEDIA_READY_FILE="$DCENTOS_EXTERNAL_MEDIA_READY_FILE" \
    DCENTOS_EXTERNAL_MEDIA_DATA_DIR="$DCENTOS_EXTERNAL_MEDIA_DATA_DIR" \
    DCENTOS_MOUNTS_FILE="$WORK/bad-mounts" \
        "$PERSIST" start >/dev/null 2>&1; then
    fail "S45 accepted UBIFS as external-media /data"
fi

# The boot-commit service must exit before even probing fw_printenv/fw_setenv.
cat > "$WORK/bin/fw_printenv" <<'SH'
#!/bin/sh
echo fw_printenv >> "$FORBIDDEN_COMMAND_LOG"
exit 0
SH
cat > "$WORK/bin/fw_setenv" <<'SH'
#!/bin/sh
echo fw_setenv >> "$FORBIDDEN_COMMAND_LOG"
exit 0
SH
chmod 0755 "$WORK/bin/fw_printenv" "$WORK/bin/fw_setenv"
export FORBIDDEN_COMMAND_LOG="$WORK/forbidden.log"
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
DCENTOS_MTD4_NODE="$WORK/fake-mtd4" \
    "$UPGRADE" start > "$WORK/upgrade.log" 2>&1 \
    || fail "S99 external-media refusal did not exit cleanly"
require_text "$WORK/upgrade.log" "U-Boot environment commit is disabled"
[ ! -e "$FORBIDDEN_COMMAND_LOG" ] || fail "S99 invoked a boot-environment tool"

# The exact-unit seed and both AM2 owners must refuse before any mining/hardware
# owner admission. This leaves dashboard/network recovery services available.
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
    "$XIL25_SEED" start > "$WORK/seed.log" 2>&1 \
    || fail "XIL .25 external-media seed refusal failed"
require_text "$WORK/seed.log" "persistent mining seed is disabled"
for owner in "$S19J_OWNER" "$S19PRO_OWNER"; do
    DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
        "$owner" start > "$WORK/owner.log" 2>&1 \
        || fail "AM2 external-media owner refusal failed: $owner"
    require_text "$WORK/owner.log" "safe-idle/management-only"
done

# The runlevel dispatcher is the complete auto-start/auto-stop boundary. An
# unexpected executable service must not run merely because the required safe
# scripts and marker are also present.
mkdir -p "$WORK/init.d"
cat > "$WORK/init.d/S40network" <<'SH'
#!/bin/sh
echo "allowed-$1" >> "$RUNLEVEL_COMMAND_LOG"
SH
cat > "$WORK/init.d/S46evil" <<'SH'
#!/bin/sh
echo "evil-$1" >> "$RUNLEVEL_COMMAND_LOG"
fw_setenv firmware 2
ubiupdatevol /dev/ubi0_1 /evil
dcentrald --s19j-hybrid
SH
chmod 0755 "$WORK/init.d/S40network" "$WORK/init.d/S46evil"
export RUNLEVEL_COMMAND_LOG="$WORK/runlevel.log"
DCENTOS_INIT_DIR="$WORK/init.d" \
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
    "$RC_START" > "$WORK/rcs.log" 2>&1 \
    || fail "external-media rcS allowlist failed"
require_text "$WORK/rcs.log" "skipped init service: S46evil"
require_text "$RUNLEVEL_COMMAND_LOG" "allowed-start"
if grep -Fq "evil-" "$RUNLEVEL_COMMAND_LOG"; then
    fail "external-media rcS executed an unexpected init service"
fi
: > "$RUNLEVEL_COMMAND_LOG"
DCENTOS_INIT_DIR="$WORK/init.d" \
DCENTOS_EXTERNAL_MEDIA_MARKER="$DCENTOS_EXTERNAL_MEDIA_MARKER" \
    "$RC_STOP" > "$WORK/rck.log" 2>&1 \
    || fail "external-media rcK allowlist failed"
require_text "$RUNLEVEL_COMMAND_LOG" "allowed-stop"
if grep -Fq "evil-" "$RUNLEVEL_COMMAND_LOG"; then
    fail "external-media rcK executed an unexpected shutdown service"
fi

# Static ordering assertions bind the producer's marker to the early boot and
# automatic-commit control flow. Normal NAND boots remain on the existing else
# branch because they do not contain the marker.
require_text "$EARLY_INIT" "MTD/UBI device-node creation suppressed"
require_text "$EARLY_INIT" "dcent_external_media_prepare_ephemeral_root"
require_text "$EARLY_INIT" "External-media identity is absent or unsafe"
require_text "$EARLY_INIT" "hardware writes suppressed"
require_order "$EARLY_INIT" 'if [ "$EXTERNAL_MEDIA_EPHEMERAL" -eq 1 ]; then' 'for mtd in /sys/class/mtd/mtd*; do'
require_order "$EARLY_INIT" 'if [ "$EXTERNAL_MEDIA_EPHEMERAL" -eq 1 ]; then' 'elif mount -t ubifs ubi0:rootfs_data /data'
require_order "$EARLY_INIT" 'hardware writes suppressed' '# --- Export FPGA GPIO pins'
require_order "$UPGRADE" "U-Boot environment commit is disabled" 'case "$1" in'
require_order "$XIL25_SEED" "persistent mining seed is disabled" 'KNOWN_XIL25_MAC='
require_order "$S19J_OWNER" "safe-idle/management-only" '        dcent_acquire_fan_transition_lock || {'
require_order "$S19PRO_OWNER" "safe-idle/management-only" '        dcent_acquire_fan_transition_lock || {'
require_text "$RC_START" "DCENTOS_EXTERNAL_MEDIA_START_ALLOWLIST"
require_text "$RC_STOP" "DCENTOS_EXTERNAL_MEDIA_STOP_ALLOWLIST"

echo "PASS: Zynq external-media runtime is volatile, non-committing, and safe-idle"
