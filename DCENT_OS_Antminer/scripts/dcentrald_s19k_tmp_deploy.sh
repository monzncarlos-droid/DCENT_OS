#!/bin/sh
# Reproducible Braiins Track-1 /tmp deploy for S19k Pro (am3-s19k).
# Stages armv7 musleabihf dcentrald, observes GPIO437, does not flash.
#
# Usage:
#   ./scripts/dcentrald_s19k_tmp_deploy.sh [--dry-run] <miner_ip> <dcentrald_armv7_binary> [config.toml]
#
# Rails: this script does NOT stop bosminer. Operator must `kill -9` bosminer
# (keeps GPIO437=0). `/etc/init.d/S99bosminer stop` is FORBIDDEN here (437=1).
# Mining stays disabled in the default config. Dual ttyS1+ttyS2 is required.

set -eu
DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=true
  shift
fi
MINER_IP=${1:?miner_ip}
BIN=${2:?dcentrald_binary}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CFG=${3:-"$ROOT/dcentrald/dcentrald_s19k.toml"}
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

test -f "$BIN" || { echo "ERROR: binary not found: $BIN" >&2; exit 1; }
test -f "$CFG" || { echo "ERROR: config not found: $CFG" >&2; exit 1; }

case "$BIN" in
  *armv7-unknown-linux-musleabihf*) ;;
  *)
    echo "ERROR: binary path must contain armv7-unknown-linux-musleabihf" >&2
    exit 1
    ;;
esac
# L1: path triple is not enough — refuse ELF64 / AArch64 / non-ELF (admit_s19k_armhf_elf).
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v py >/dev/null 2>&1; then
  PY="py -3"
else
  echo "ERROR: python3/py required to admit ELF32 ARM header" >&2
  exit 1
fi
ADMIT_OUT=$($PY - "$BIN" <<'PY'
import sys
path = sys.argv[1]
try:
    blob = open(path, "rb").read()
except OSError as exc:
    print("ERROR: cannot read ELF:", exc, file=sys.stderr)
    sys.exit(1)
if len(blob) < 52 or blob[:4] != b"\x7fELF" or blob[4] != 1:
    print("ERROR: admit_s19k_armhf_elf refused — not ELF32 (Track 1 Braiins userspace is armhf)", file=sys.stderr)
    sys.exit(1)
if blob[5] != 1:
    print("ERROR: admit_s19k_armhf_musl_static refused — not LSB", file=sys.stderr)
    sys.exit(1)
machine = int.from_bytes(blob[18:20], "little")
if machine != 40:
    print("ERROR: admit_s19k_armhf_elf refused — e_machine=%s (want EM_ARM=40, not AArch64=183)" % machine, file=sys.stderr)
    sys.exit(1)
flags = int.from_bytes(blob[36:40], "little")
if flags & 0x400 == 0:
    print("ERROR: admit_s19k_armhf_musl_static refused — missing hard_float EF_ARM_ABI_FLOAT_HARD", file=sys.stderr)
    sys.exit(1)
phoff = int.from_bytes(blob[28:32], "little")
phentsize = int.from_bytes(blob[42:44], "little")
phnum = int.from_bytes(blob[44:46], "little")
interp = None
for i in range(phnum):
    off = phoff + i * phentsize
    if len(blob) < off + 20:
        print("ERROR: admit_s19k_armhf_musl_static refused — truncated program headers", file=sys.stderr)
        sys.exit(1)
    p_type = int.from_bytes(blob[off:off+4], "little")
    if p_type != 3:
        continue
    p_offset = int.from_bytes(blob[off+4:off+8], "little")
    p_filesz = int.from_bytes(blob[off+16:off+20], "little")
    raw = blob[p_offset:p_offset+p_filesz]
    interp = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
if interp:
    if "ld-linux" in interp:
        print("ERROR: admit_s19k_armhf_musl_static refused — glibc ld-linux interp", file=sys.stderr)
        sys.exit(1)
    print("ERROR: admit_s19k_armhf_musl_static refused — PT_INTERP=%s (static musl only)" % interp, file=sys.stderr)
    sys.exit(1)
import hashlib
print("SHA256=" + hashlib.sha256(blob).hexdigest())
print("BYTES=%d" % len(blob))
print("ELF32 ARM musl-static admitted (class=1 machine=40 hard_float=1 pt_interp=none)")
PY
)
echo "$ADMIT_OUT"
LOCAL_SHA=$(printf '%s\n' "$ADMIT_OUT" | sed -n 's/^SHA256=//p' | head -n 1)
LOCAL_BYTES=$(printf '%s\n' "$ADMIT_OUT" | sed -n 's/^BYTES=//p' | head -n 1)
case "$LOCAL_SHA" in
  [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*) ;;
  *)
    echo "ERROR: local SHA256 missing after ELF admit" >&2
    exit 1
    ;;
esac
test -n "$LOCAL_BYTES" && [ "$LOCAL_BYTES" -gt 0 ] || {
  echo "ERROR: local BYTES missing after ELF admit" >&2
  exit 1
}

grep -Eq '^target[[:space:]]*=[[:space:]]*"am3-aml-s19k"' "$CFG" || {
  echo "ERROR: [platform].target must be am3-aml-s19k" >&2
  exit 1
}
grep -Eq '^board_target[[:space:]]*=[[:space:]]*"(am3-s19k|am3-s19kpro|am3-aml-s19kpro)"' "$CFG" || {
  echo "ERROR: [platform].board_target must be a live S19k AML alias (admit_s19k_tmp_deploy_board_target)" >&2
  exit 1
}
CFG_BT=$(sed -n 's/^board_target[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n 1)
case "$CFG_BT" in
  am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
  *)
    echo "ERROR: extracted board_target '$CFG_BT' is not a live S19k AML alias" >&2
    exit 1
    ;;
esac
# Stage-only: mining.enabled=false. Mining-on: enabled=true AND passthrough=true.
# Native BM1366 cold-init (enabled + !passthrough) is refused.
# Match only assignment lines — a comment containing "enabled = true" must not flip mode.
mining_key() {
  key=$1
  want=$2
  awk -v key="$key" -v want="$want" '
    BEGIN { s=0 }
    /^\[mining\]/ { s=1; next }
    /^\[/ { s=0 }
    s && $0 ~ "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*" want "[[:space:]]*(#.*)?$" { found=1 }
    END { exit !found }
  ' "$CFG"
}
MINING_ON=0
mining_key enabled true && MINING_ON=1
if [ "$MINING_ON" -eq 1 ]; then
  mining_key passthrough true || {
    echo "ERROR: NativeMiningOn — mining.enabled=true requires passthrough=true (kill -9 Braiins handoff)" >&2
    exit 1
  }
else
  mining_key enabled false || {
    echo "ERROR: [mining].enabled must be false, or true with passthrough=true" >&2
    exit 1
  }
fi

STAMP=$(date +%Y%m%d%H%M%S)
if [ "$DRY_RUN" = true ]; then
  REMOTE_DIR="/tmp/dcentrald_bench_t1_DRYRUN"
else
  REMOTE_DIR="/tmp/dcentrald_bench_t1_${STAMP}_$$"
fi
REMOTE_BIN="$REMOTE_DIR/dcentrald"
REMOTE_CFG="$REMOTE_DIR/dcentrald_s19k.toml"
if [ "$MINING_ON" -eq 1 ]; then
  DEPLOY_MODE=mining-on-passthrough
else
  DEPLOY_MODE=stage-only
fi
TMP_DEPLOY_PLAN="./TMP_DEPLOY_PLAN.txt"
{
  echo "schema=dcentos.s19k-tmp-deploy/v2"
  echo "triple=armv7-unknown-linux-musleabihf"
  echo "elf_class=32"
  echo "e_machine=40"
  echo "hard_float=true"
  echo "pt_interp=none"
  echo "musl_static=true"
  echo "sha256=$LOCAL_SHA"
  echo "bytes=$LOCAL_BYTES"
  echo "post_scp=sha256sum"
  echo "re_admit=elf32_arm_musl_static"
  echo "remote_dir=$REMOTE_DIR"
  echo "remote_bin=$REMOTE_BIN"
  echo "launch=$REMOTE_BIN --config $REMOTE_CFG"
  echo "chmod=755"
  echo "ports=/dev/ttyS1,/dev/ttyS2"
  echo "baud=3000000"
  echo "keep_rails=kill -9"
  echo "forbidden_stop=/etc/init.d/S99bosminer stop"
  echo "mode=$DEPLOY_MODE"
  echo "native_bm1366=refused"
  echo "clear_for_flash=false"
  echo "execute=CLEAR_FOR_FLASH"
  echo "dry_run=$DRY_RUN"
  echo "miner_ip=$MINER_IP"
} > "$TMP_DEPLOY_PLAN"
echo "  wrote $TMP_DEPLOY_PLAN"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY RUN] writing TMP_DEPLOY_PLAN before SSH..."
  echo "[DRY RUN] no ssh, no scp, no chmod, no /etc/dcentos write"
  echo "Run: $REMOTE_BIN --config $REMOTE_CFG"
  echo "FLASH NOT_YET. Not mining-achieved. Not stock GO."
  exit 0
fi

ssh $SSH_OPTS "root@$MINER_IP" "mkdir -p '$REMOTE_DIR'"
scp -O $SSH_OPTS "$BIN" "root@$MINER_IP:$REMOTE_BIN"
scp -O $SSH_OPTS "$CFG" "root@$MINER_IP:$REMOTE_CFG"
REMOTE_SUM=$(ssh $SSH_OPTS "root@$MINER_IP" "sha256sum '$REMOTE_BIN' | awk '{print \$1}'")
REMOTE_BYTES=$(ssh $SSH_OPTS "root@$MINER_IP" "wc -c < '$REMOTE_BIN'" | tr -d ' \t\r\n')
if [ -z "$REMOTE_SUM" ] || [ "$REMOTE_SUM" != "$LOCAL_SHA" ] || [ "$REMOTE_BYTES" != "$LOCAL_BYTES" ]; then
  echo "ERROR: admit_s19k_tmp_deploy_post_scp refused — sha256/bytes mismatch (plan=$LOCAL_SHA/$LOCAL_BYTES remote=$REMOTE_SUM/$REMOTE_BYTES)" >&2
  exit 1
fi
ssh $SSH_OPTS "root@$MINER_IP" "chmod 755 '$REMOTE_BIN'"

# Identity markers for the daemon. Stamp tmp_deploy so restore cannot
# treat this Braiins /tmp bench as an installed DCENT rootfs.
ssh $SSH_OPTS "root@$MINER_IP" "sh -s" <<EOF
set -eu
mkdir -p /etc/dcentos
printf '%s\n' '$CFG_BT' > /etc/dcentos/board_target
printf '%s\n' 'am3-aml-s19k' > /etc/dcentos/platform
printf '%s\n' 'am3-aml-s19kpro' > /etc/dcentos/board_family
printf '%s\n' 'am3-aml-s19k' > /etc/dcentos-platform
printf '%s\n' '1' > /etc/dcentos/tmp_deploy
EOF

# Observe only. Do not write GPIO437. Do not S99 stop.
OBS=$(ssh $SSH_OPTS "root@$MINER_IP" 'sh -s' <<'OBS'
set -eu
G=/sys/class/gpio/gpio437/value
if [ -f "$G" ]; then
  echo "GPIO437=$(cat "$G")"
else
  echo "GPIO437=unexported"
fi
echo -n "BOSMINER="
pidof bosminer 2>/dev/null || echo none
ls -l /dev/ttyS1 /dev/ttyS2 /dev/uart_trans 2>/dev/null || true
if [ -e /dev/uart_trans ]; then
  echo "ERROR: /dev/uart_trans present — Braiins Track-1 refuses this node" >&2
  exit 1
fi
OBS
)
echo "$OBS"
echo "$OBS" | grep -q '/dev/ttyS1' || {
  echo "ERROR: /dev/ttyS1 missing — refuse S19k Track-1 /tmp deploy" >&2
  exit 1
}
echo "$OBS" | grep -q '/dev/ttyS2' || {
  echo "ERROR: /dev/ttyS2 missing — refuse single-port /tmp deploy" >&2
  exit 1
}
if echo "$OBS" | grep -q 'GPIO437=1'; then
  if [ "$MINING_ON" -eq 1 ]; then
    echo "ERROR: GPIO437=1 means PSU OFF on am3-s19k. Refuse mining-on /tmp deploy. kill -9 bosminer (keep 437=0); do not S99 stop." >&2
    exit 1
  fi
  echo "WARN: GPIO437=1 means PSU OFF on am3-s19k. kill -9 bosminer next time; do not S99 stop." >&2
fi
if [ "$MINING_ON" -eq 1 ] && ! echo "$OBS" | grep -q 'BOSMINER=none'; then
  echo "ERROR: bosminer still running — refuse mining-on (it holds ttyS). kill -9 bosminer; do not S99 stop." >&2
  exit 1
fi

echo "Staged $REMOTE_DIR"
echo "Required ports: /dev/ttyS1 /dev/ttyS2 @ 3000000 (leftover serial_device is a hint)"
echo "Expected first job prefix after mining-on: 55 AA 21 36"
echo "Keep rails: kill -9 bosminer   FORBIDDEN: /etc/init.d/S99bosminer stop"
if [ "$MINING_ON" -eq 1 ]; then
  echo "MODE=mining-on passthrough=true (native BM1366 still refused)"
else
  echo "MODE=stage-only mining.enabled=false"
fi
echo "Run: $REMOTE_BIN --config $REMOTE_CFG"
echo "FLASH NOT_YET. Not mining-achieved. Not stock GO."
