#!/bin/sh
# Host-driven /tmp trial launcher for Antminer S19k Pro (am3-s19k).
# Track 1 Braiins userspace is **armhf** (ld-linux-armhf / ld-musl-armhf).
# Kernel may report aarch64 — that is NOT the userspace ABI. Stage only
# armv7-unknown-linux-musleabihf (ARM 32-bit) binaries; reject aarch64 ELF.
# Near-term BETA path assumes BraiinsOS+ (root SSH). Stock Bitmain first-install
# is a separate harder gate — do not treat this script as the stock restore path.
# Does not flash, does not energize, does not enable mining.
# Track 1 /tmp skeleton does NOT use fw_setenv/fw_printenv (missing on Braiins).
#
# Usage (lab host with Braiins root SSH) — DCENT_Bench operates the unit:
#   ./scripts/dcentrald_s19k_tmp_trial.sh <miner_ip> <dcentrald_binary> [config.toml]
#
# Stages binary + config (default dcentrald/dcentrald_s19k.toml) under a unique
# /tmp/dcentrald_bench_t1_<stamp>_<pid>/ on the miner (not fixed /tmp/dcentrald),
# stages /etc/dcentos/board_target=am3-s19k (+ platform markers) and requires typed toml [platform],
# and prints the exact run command. Daemon admission/runtime stays carrier-neutral;
# only this trial transport is Braiins-SSH. Operator must confirm NoPic / BM1366
# identity before any experimental opt-in.

set -eu
MINER_IP=${1:?miner_ip}
BIN=${2:?dcentrald_binary}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CFG=${3:-"$ROOT/dcentrald/dcentrald_s19k.toml"}
test -f "$CFG" || { echo "ERROR: config not found: $CFG" >&2; exit 1; }
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

test -f "$BIN" || { echo "ERROR: binary not found: $BIN" >&2; exit 1; }

# Fail-closed: require armv7/armhf musleabihf — reject aarch64 before staging.
case "$BIN" in
  *armv7-unknown-linux-musleabihf*) ;;
  *)
    if command -v readelf >/dev/null 2>&1; then
      hdr=$(readelf -h "$BIN" 2>/dev/null || true)
      echo "$hdr" | grep -q 'Machine:[[:space:]]*ARM$' || {
        echo "ERROR: binary is not ARM (armhf/armv7). Refuse staging (Track 1 Braiins userspace is armhf; kernel aarch64 != userspace)." >&2
        echo "$hdr" | head -20 >&2 || true
        exit 1
      }
      echo "$hdr" | grep -Eq 'Class:[[:space:]]*ELF32' || {
        echo "ERROR: binary is not ELF32 (reject aarch64/ELF64 for .88 Track 1)." >&2
        exit 1
      }
    elif command -v file >/dev/null 2>&1; then
      ft=$(file -b "$BIN" 2>/dev/null || true)
      echo "$ft" | grep -Eqi 'ARM|armhf|armv7' || {
        echo "ERROR: file(1) does not look like ARM32: $ft" >&2
        exit 1
      }
      echo "$ft" | grep -Eqi 'aarch64|ARM aarch64|x86-64|ELF 64' && {
        echo "ERROR: refusing aarch64/64-bit binary for Track 1 armhf userspace: $ft" >&2
        exit 1
      }
    else
      echo "ERROR: binary path must contain armv7-unknown-linux-musleabihf (no readelf/file available)." >&2
      exit 1
    fi
    ;;
esac

grep -q 'model = "s19k"' "$CFG"
grep -q 'serial_chip_count = 77' "$CFG"
grep -q 'serial_chip_type = "BM1366"' "$CFG"
grep -q '\[autotuner\]' "$CFG"
# Typed identity-only [platform] REQUIRED (target + board_target). CE #1 banned
# phantom kitchen-sink safety flags, not this section. Also stage /etc/dcentos markers.
grep -q '^\[platform\]' "$CFG" || { echo "ERROR: $CFG missing typed [platform] identity section." >&2; exit 1; }
grep -Eq '^target[[:space:]]*=[[:space:]]*"am3-aml-s19k"' "$CFG" || { echo "ERROR: [platform].target must be am3-aml-s19k" >&2; exit 1; }
grep -Eq '^board_target[[:space:]]*=[[:space:]]*"(am3-s19k|am3-s19kpro|am3-aml-s19kpro)"' "$CFG" || { echo "ERROR: [platform].board_target must be a live S19k AML alias (admit_s19k_tmp_deploy_board_target)" >&2; exit 1; }
CFG_BT=$(sed -n 's/^board_target[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n 1)
case "$CFG_BT" in
  am3-s19k|am3-s19kpro|am3-aml-s19kpro) ;;
  *) echo "ERROR: extracted board_target '$CFG_BT' is not a live S19k AML alias" >&2; exit 1 ;;
esac
# Refuse kitchen-sink / safety keys under [platform] (CE #1).
awk '
  BEGIN{in_p=0}
  /^\[platform\]/{in_p=1; next}
  /^\[/{in_p=0}
  in_p && /^[[:space:]]*#/ {next}
  in_p && /^[[:space:]]*$/ {next}
  in_p {
    if ($0 ~ /^target[[:space:]]*=/ || $0 ~ /^board_target[[:space:]]*=/) next
    print "ERROR: forbidden [platform] key (identity-only: target/board_target): " $0 > "/dev/stderr"
    bad=1
  }
  END{exit bad+0}
' "$CFG"
grep -q 'am3-s19k' "$CFG"
# mining.enabled must be false in the mining section
awk 'BEGIN{s=0} /^\[mining\]/{s=1;next} /^\[/{s=0} s && /enabled = false/{found=1} END{exit !found}' "$CFG"

# Unique remote stage path avoids races if another agent scp's a stale /tmp/dcentrald.
STAMP=$(date +%Y%m%d%H%M%S)
REMOTE_DIR="/tmp/dcentrald_bench_t1_${STAMP}_$$"
REMOTE_BIN="$REMOTE_DIR/dcentrald"
REMOTE_CFG="$REMOTE_DIR/dcentrald_s19k.toml"

# -O: OpenSSH legacy SCP protocol (AML/Braiins dropbear/sftp quirks)
ssh $SSH_OPTS "root@$MINER_IP" "mkdir -p '$REMOTE_DIR'"
scp -O $SSH_OPTS "$BIN" "root@$MINER_IP:$REMOTE_BIN"
scp -O $SSH_OPTS "$CFG" "root@$MINER_IP:$REMOTE_CFG"
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v py >/dev/null 2>&1; then
  PY="py -3"
else
  echo "ERROR: python3/py required for admit_s19k_tmp_deploy_post_scp" >&2
  exit 1
fi
LOCAL_SHA=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$BIN")
LOCAL_BYTES=$($PY -c "import os,sys; print(os.path.getsize(sys.argv[1]))" "$BIN")
REMOTE_SUM=$(ssh $SSH_OPTS "root@$MINER_IP" "sha256sum '$REMOTE_BIN' | awk '{print \$1}'")
REMOTE_BYTES=$(ssh $SSH_OPTS "root@$MINER_IP" "wc -c < '$REMOTE_BIN'" | tr -d ' \t\r\n')
if [ -z "$REMOTE_SUM" ] || [ "$REMOTE_SUM" != "$LOCAL_SHA" ] || [ "$REMOTE_BYTES" != "$LOCAL_BYTES" ]; then
  echo "ERROR: admit_s19k_tmp_deploy_post_scp refused — sha256/bytes mismatch (plan=$LOCAL_SHA/$LOCAL_BYTES remote=$REMOTE_SUM/$REMOTE_BYTES)" >&2
  exit 1
fi
ssh $SSH_OPTS "root@$MINER_IP" "chmod 755 '$REMOTE_BIN'"

# Carry am3-s19k identity the supported way: /etc/dcentos/board_target (+ platform).
# Runtime prefers /etc/dcentos markers; typed toml [platform] fills gaps (identity-only).
# Daemon has no env override for board_target; refuse if /etc is not writable.
ssh $SSH_OPTS "root@$MINER_IP" "printf '%s\n' '$CFG_BT' > '$REMOTE_DIR/board_target' && printf '%s\n' 'am3-aml-s19k' > '$REMOTE_DIR/platform' && printf '%s\n' 'am3-aml-s19k' > '$REMOTE_DIR/dcentos-platform' && printf '%s\n' 'am3-aml-s19kpro' > '$REMOTE_DIR/board_family'"
ssh $SSH_OPTS "root@$MINER_IP" "sh -s" <<EOF
set -eu
if ! mkdir -p /etc/dcentos 2>/dev/null; then
  echo "ERROR: cannot mkdir /etc/dcentos (not writable). Daemon identity is /etc/dcentos/board_target — no env override exists; refusing trial." >&2
  exit 1
fi
cp '$REMOTE_DIR/board_target' /etc/dcentos/board_target
cp '$REMOTE_DIR/platform' /etc/dcentos/platform
cp '$REMOTE_DIR/board_family' /etc/dcentos/board_family
cp '$REMOTE_DIR/dcentos-platform' /etc/dcentos-platform
printf '%s\n' '1' > /etc/dcentos/tmp_deploy
# Confirm staged markers (fail-closed).
grep -qx '$CFG_BT' /etc/dcentos/board_target
grep -qx 'am3-aml-s19k' /etc/dcentos/platform
grep -qx 'am3-aml-s19kpro' /etc/dcentos/board_family
grep -qx 'am3-aml-s19k' /etc/dcentos-platform
echo "Staged identity markers: /etc/dcentos/board_target=$CFG_BT board_family=am3-aml-s19kpro platform=am3-aml-s19k (tmp_deploy stamped)"
EOF

echo "Staged under $REMOTE_DIR (not fixed /tmp/dcentrald — avoids cross-agent races)."
echo "On miner (mining remains disabled in config; engine runtime-try stays fail-closed):"
echo "  $REMOTE_BIN --config $REMOTE_CFG"
echo "Mining-off wire try (Bench). To KEEP rails: kill -9 bosminer (GPIO437 stays 0=ON)."
echo "Do NOT /etc/init.d/S99bosminer stop — that drives GPIO437=1 (OFF) on am3-s19k."
echo "  DCENT_S19K_BRAIINS_WIRE_TRY=1 $REMOTE_BIN --config $REMOTE_CFG"
echo "Shell-only two-frame probe (no daemon): scripts/s19k_braiins_wire_try.sh <miner_ip>"
echo "Do not set experimental BM1366 mining opt-in. Do not flip CURRENT.braiins_ttys_bench_go."
