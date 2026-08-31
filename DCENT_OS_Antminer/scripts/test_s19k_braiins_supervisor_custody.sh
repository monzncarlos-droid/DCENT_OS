#!/bin/sh
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER="$SCRIPT_DIR/dcentrald_s19k_braiins_supervisor_custody.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

make_stat() {
    PID=$1 COMM=$2 PPID_VALUE=$3 PGRP=$4 SESSION=$5 START=$6
    # /proc/PID/stat through field 22 (starttime).
    printf '%s (%s) S %s %s %s 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %s\n' \
        "$PID" "$COMM" "$PPID_VALUE" "$PGRP" "$SESSION" "$START"
}

make_process() {
    ROOT=$1 PID=$2 COMM=$3 EXE=$4 PPID_VALUE=$5 PGRP=$6 SESSION=$7 START=$8
    shift 8
    mkdir -p "$ROOT/$PID"
    make_stat "$PID" "$COMM" "$PPID_VALUE" "$PGRP" "$SESSION" "$START" > "$ROOT/$PID/stat"
    printf '%s\n' "$COMM" > "$ROOT/$PID/comm"
    ln -s "$EXE" "$ROOT/$PID/exe"
    : > "$ROOT/$PID/cmdline"
    for ARG in "$@"; do printf '%s\000' "$ARG" >> "$ROOT/$PID/cmdline"; done
}

make_good_fixture() {
    FIXTURE_ROOT=$1
    mkdir -p "$FIXTURE_ROOT/proc" "$FIXTURE_ROOT/run"
    printf '1458\n' > "$FIXTURE_ROOT/run/bosminer.pid"
    make_process "$FIXTURE_ROOT/proc" 1458 bos-tools /usr/bin/bos-tools 1 1457 1457 1251 \
        /usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file
    make_process "$FIXTURE_ROOT/proc" 9495 bosminer /usr/bin/bosminer 1458 1457 1457 1044815 \
        /usr/bin/bosminer --log-to-file
}

GOOD="$TMP_ROOT/good"
make_good_fixture "$GOOD"
OUT=$("$HELPER" capture "$GOOD/proc" "$GOOD/run/bosminer.pid")
printf '%s\n' "$OUT" | grep -qx 'schema=dcentos.s19k-braiins-supervisor-custody/v1'
printf '%s\n' "$OUT" | grep -qx 'authority=read-only-process-tree-observation'
printf '%s\n' "$OUT" | grep -qx 'supervisor_pid=1458'
printf '%s\n' "$OUT" | grep -qx 'supervisor_start=1251'
printf '%s\n' "$OUT" | grep -qx 'supervisor_ppid=1'
printf '%s\n' "$OUT" | grep -qx 'supervisor_state=nonterminal'
printf '%s\n' "$OUT" | grep -qx 'child_pid=9495'
printf '%s\n' "$OUT" | grep -qx 'child_start=1044815'
printf '%s\n' "$OUT" | grep -qx 'child_ppid=1458'
printf '%s\n' "$OUT" | grep -qx 'child_state=nonterminal'
[ "$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')" -eq 23 ]

BAD_PPID="$TMP_ROOT/bad-ppid"
make_good_fixture "$BAD_PPID"
make_stat 9495 bosminer 7777 1457 1457 1044815 > "$BAD_PPID/proc/9495/stat"
if "$HELPER" capture "$BAD_PPID/proc" "$BAD_PPID/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: wrong child PPID admitted' >&2
    exit 1
fi

DUP="$TMP_ROOT/duplicate-supervisor"
make_good_fixture "$DUP"
make_process "$DUP/proc" 2222 bos-tools /usr/bin/bos-tools 1 2221 2221 777 \
    /usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file
if "$HELPER" capture "$DUP/proc" "$DUP/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: duplicate supervisor admitted' >&2
    exit 1
fi

BAD_ARGV="$TMP_ROOT/bad-child-argv"
make_good_fixture "$BAD_ARGV"
printf '/usr/bin/bosminer\000--different\000' > "$BAD_ARGV/proc/9495/cmdline"
if "$HELPER" capture "$BAD_ARGV/proc" "$BAD_ARGV/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: unexpected child argv admitted' >&2
    exit 1
fi

BAD_SUPERVISOR_ARGV="$TMP_ROOT/bad-supervisor-argv"
make_good_fixture "$BAD_SUPERVISOR_ARGV"
printf '/usr/bin/bos-tools\000run-and-watch\000--\000/usr/bin/bosminer\000--log-to-file\000--extra\000' \
    > "$BAD_SUPERVISOR_ARGV/proc/1458/cmdline"
if "$HELPER" capture "$BAD_SUPERVISOR_ARGV/proc" "$BAD_SUPERVISOR_ARGV/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: altered bosminer supervisor argv admitted' >&2
    exit 1
fi

BAD_SUPERVISOR_COMM="$TMP_ROOT/bad-supervisor-comm"
make_good_fixture "$BAD_SUPERVISOR_COMM"
printf 'disguised\n' > "$BAD_SUPERVISOR_COMM/proc/1458/comm"
if "$HELPER" capture "$BAD_SUPERVISOR_COMM/proc" "$BAD_SUPERVISOR_COMM/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: altered bosminer supervisor comm admitted' >&2
    exit 1
fi

BAD_CHILD_COMM="$TMP_ROOT/bad-child-comm"
make_good_fixture "$BAD_CHILD_COMM"
printf 'disguised\n' > "$BAD_CHILD_COMM/proc/9495/comm"
if "$HELPER" capture "$BAD_CHILD_COMM/proc" "$BAD_CHILD_COMM/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: altered bosminer child comm admitted' >&2
    exit 1
fi

BAD_PIDFILE="$TMP_ROOT/bad-pidfile"
make_good_fixture "$BAD_PIDFILE"
printf '9495\n' > "$BAD_PIDFILE/run/bosminer.pid"
if "$HELPER" capture "$BAD_PIDFILE/proc" "$BAD_PIDFILE/run/bosminer.pid" >/dev/null 2>&1; then
    echo 'FAIL: child PID in supervisor pidfile admitted' >&2
    exit 1
fi

if grep -Eq '(^|[[:space:]])(kill|gpio|reboot|poweroff|halt)([[:space:]]|$)' "$HELPER"; then
    echo 'FAIL: observation helper contains a mutation command' >&2
    exit 1
fi

echo 'S19K_BRAIINS_SUPERVISOR_CUSTODY_TESTS_OK'
