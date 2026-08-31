#!/bin/sh
# Prove that every Zynq updater converts asynchronous termination into a
# nonzero exit before its single EXIT cleanup path runs.

set -eu

PROJECT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$PROJECT_DIR"

tests=0
failures=0

ok()
{
    tests=$((tests + 1))
    printf 'ok %s - %s\n' "$tests" "$1"
}

not_ok()
{
    tests=$((tests + 1))
    failures=$((failures + 1))
    printf 'not ok %s - %s\n' "$tests" "$1" >&2
}

assert_exact_line()
{
    _file=$1
    _line=$2
    _label=$3
    if [ "$(grep -Fxc -- "$_line" "$_file")" -eq 1 ]; then
        ok "$_label"
    else
        not_ok "$_label"
    fi
}

assert_absent_line()
{
    _file=$1
    _line=$2
    _label=$3
    if ! grep -Fx -- "$_line" "$_file" >/dev/null 2>&1; then
        ok "$_label"
    else
        not_ok "$_label"
    fi
}

SYSUPGRADES='
br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade
br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade
br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade
br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade
'

for _file in $SYSUPGRADES; do
    _profile=$(dirname "$_file")
    assert_exact_line "$_file" 'trap cleanup_package EXIT' \
        "$_profile has one terminal cleanup path"
    assert_exact_line "$_file" "trap 'exit 129' HUP" \
        "$_profile translates HUP to status 129"
    assert_exact_line "$_file" "trap 'exit 130' INT" \
        "$_profile translates INT to status 130"
    assert_exact_line "$_file" "trap 'exit 143' TERM" \
        "$_profile translates TERM to status 143"
    assert_absent_line "$_file" 'trap cleanup_package EXIT HUP INT TERM' \
        "$_profile never passes an interrupted-command status to cleanup"
done

probe_signal_exit()
{
    _signal=$1
    _expected=$2
    set +e
    _output=$(
        /bin/sh -c '
            cleanup()
            {
                rc=$?
                trap - EXIT HUP INT TERM
                printf "cleanup=%s\n" "$rc"
                exit "$rc"
            }
            trap cleanup EXIT
            trap "exit $2" "$1"
            kill -s "$1" "$$"
        ' sysupgrade-signal-probe "$_signal" "$_expected" 2>&1
    )
    _actual=$?
    set -e

    if [ "$_actual" -eq "$_expected" ] && \
       [ "$_output" = "cleanup=$_expected" ]; then
        ok "POSIX shell $_signal runs cleanup once and exits $_expected"
    else
        not_ok "POSIX shell $_signal cleanup result (status=$_actual output=$_output)"
    fi
}

probe_signal_exit HUP 129
probe_signal_exit INT 130
probe_signal_exit TERM 143

printf '1..%s\n' "$tests"
[ "$failures" -eq 0 ]
