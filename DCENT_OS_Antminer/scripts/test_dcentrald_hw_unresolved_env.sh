#!/bin/sh
# Host-safe contract for the U-Boot `dcent_hw_unresolved` fw_setenv helper.
# Never invokes nandwrite/flash_erase; never needs a miner.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-hw-unresolved-env.sh"
FAILURES=0

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    printf 'PASS: %s\n' "$*"
}

if [ ! -f "$HELPER" ]; then
    printf 'FAIL: helper missing: %s\n' "$HELPER" >&2
    exit 1
fi
if ! sh -n "$HELPER"; then
    printf 'FAIL: helper is not POSIX-shell parseable\n' >&2
    exit 1
fi
pass 'helper is POSIX-shell parseable'

if grep -E '^[[:space:]]*(nandwrite|flash_erase)([[:space:]]|$)' "$HELPER" >/dev/null 2>&1; then
    fail 'helper has a command-position nandwrite/flash_erase'
else
    pass 'helper has no command-position nandwrite/flash_erase'
fi

if grep -Fq 'NEVER nandwrite' "$HELPER" \
    && grep -Fq 'fw_setenv --script' "$HELPER"; then
    pass 'helper documents fw_setenv --script and NEVER nandwrite mtd4'
else
    fail 'helper lost fw_setenv --script / NEVER nandwrite contract'
fi

SET_PAYLOAD=$(sh "$HELPER" print-set) || fail 'print-set exited non-zero'
CLEAR_PAYLOAD=$(sh "$HELPER" print-clear) || fail 'print-clear exited non-zero'
[ "$SET_PAYLOAD" = "dcent_hw_unresolved 1" ] \
    && pass 'print-set emits dcent_hw_unresolved 1' \
    || fail "print-set payload was '$SET_PAYLOAD'"
[ "$CLEAR_PAYLOAD" = "dcent_hw_unresolved" ] \
    && pass 'print-clear emits name-only delete form' \
    || fail "print-clear payload was '$CLEAR_PAYLOAD'"

if sh "$HELPER" self-test; then
    pass 'helper self-test'
else
    fail 'helper self-test failed'
fi

if [ "$FAILURES" -ne 0 ]; then
    printf '%s failure(s)\n' "$FAILURES" >&2
    exit 1
fi
printf 'dcentrald-hw-unresolved-env: all checks passed\n'
exit 0
