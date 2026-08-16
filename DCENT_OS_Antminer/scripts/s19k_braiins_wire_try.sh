#!/bin/sh
# Braiins Track-1 mining-off wire try (host-driven).
# Exclusive: DCENT_Bench on the authorized Braiins unit. Do not flash.
# Does NOT enable mining. Does NOT write GPIO437. Does NOT use ttyS0.
# Does NOT load /dev/uart_trans. bosminer must already be stopped.
#
# Usage (lab host):
#   ./scripts/s19k_braiins_wire_try.sh <miner_ip>
#
# On-miner it exclusive-opens /dev/ttyS1 then /dev/ttyS2 (required) and
# /dev/ttyS3 (discover; missing is not fatal) @ 3_000_000 8N1
# and writes two CLOSED set_address frames (addr 0 and 2, interval=2).
# Full 77-address burst lives in dcentrald when DCENT_S19K_BRAIINS_WIRE_TRY=1.
#
# Success = exclusive open + TX + optional RX hex. Not mining-achieved.

set -eu
MINER_IP=${1:?miner_ip}
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

# Desk 11g CLOSED frames (userspace-complete, including 55 AA):
#   set_address(0) = 55 AA 40 05 00 00 1c
#   set_address(2) = 55 AA 40 05 02 00 01
ssh $SSH_OPTS "root@$MINER_IP" "sh -s" <<'REMOTE'
set -eu
echo "S19K_BRAIINS_WIRE_TRY_SH start"

if pidof bosminer >/dev/null 2>&1; then
  echo "REFUSE: bosminer still running — stop it first (/etc/init.d/S99bosminer stop)" >&2
  exit 1
fi
if [ -e /dev/uart_trans ]; then
  echo "REFUSE: /dev/uart_trans present — this helper is Track 1 raw ttyS only" >&2
  exit 1
fi
if [ -r /sys/class/gpio/gpio437/value ]; then
  g=$(cat /sys/class/gpio/gpio437/value | tr -d ' \t\r\n')
  echo "gpio437=$g (read-only; will not write; am3-s19k 0=ON 1=OFF; S21-class is the other way)"
else
  echo "gpio437=unexported (will not write)"
fi

classify_rx() {
  rx=$(printf '%s' "${1:-}" | tr -d ' \t\r\n')
  if [ -z "$rx" ] || [ "$rx" = "-" ]; then
    echo silence
    return
  fi
  case "$rx" in
    *aa55*) echo chip ;;
    *) echo echo ;;
  esac
}

S1_RX=-
S2_RX=-
S3_RX=-

probe() {
  path=$1
  if [ ! -e "$path" ]; then
    echo "MISSING $path"
    return 0
  fi
  if [ "$path" = /dev/ttyS0 ]; then
    echo "REFUSE: never ttyS0" >&2
    return 1
  fi
  echo "OPEN $path"
  stty -F "$path" 3000000 raw -echo -ixon -ixoff clocal cread cs8 -parenb -cstopb min 0 time 1
  # Flush RX.
  dd if="$path" of=/dev/null bs=256 count=1 2>/dev/null || true
  # addr 0 then addr 2 (interval=2). No job frames.
  printf '\x55\xAA\x40\x05\x00\x00\x1c' > "$path" || {
    echo "TX_FAIL $path addr0" >&2
    return 1
  }
  printf '\x55\xAA\x40\x05\x02\x00\x01' > "$path" || {
    echo "TX_FAIL $path addr2" >&2
    return 1
  }
  echo "TX_OK $path set_address 0,2"
  rx=$(dd if="$path" bs=1 count=64 2>/dev/null | hexdump -v -e '/1 "%02x "' || true)
  if [ -n "$rx" ]; then
    echo "RX $path $rx"
  else
    rx=-
    echo "RX $path -"
  fi
  case "$path" in
    /dev/ttyS1) S1_RX=$rx ;;
    /dev/ttyS2) S2_RX=$rx ;;
    /dev/ttyS3) S3_RX=$rx ;;
  esac
}

probe /dev/ttyS1
probe /dev/ttyS2
probe /dev/ttyS3
S1_TAG=$(classify_rx "$S1_RX")
S2_TAG=$(classify_rx "$S2_RX")
S3_TAG=$(classify_rx "$S3_RX")
REQ=0
[ "$S1_TAG" = chip ] && REQ=$((REQ + 1))
[ "$S2_TAG" = chip ] && REQ=$((REQ + 1))
echo "S19K_PORT_RX ttyS1=$S1_TAG ttyS2=$S2_TAG ttyS3=$S3_TAG required_answered=$REQ"
if [ "$REQ" = 1 ]; then
  echo "NOTE: one of ttyS1/ttyS2 answered; not dual-chain or 2-board proof"
fi
echo "S19K_BRAIINS_WIRE_TRY_SH done (no mining claim; restart bosminer when finished)"
REMOTE
