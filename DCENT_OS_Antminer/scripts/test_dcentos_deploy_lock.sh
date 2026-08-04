#!/bin/sh
# Native lifecycle tests for the kernel-backed deploy/admission command lock.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOURCE="$ROOT/br2_external_dcentos/packages/dcentos-deploy-lock/src/dcentos-deploy-lock.c"
PDEATH_CHILD="$ROOT/scripts/fixtures/dcentos_deploy_lock_pdeath_child.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-deploy-lock-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' 0
trap 'exit 1' 1 2 15
LOCK_FILE="$TEST_ROOT/deploy.lock"
LOCK_BIN="$TEST_ROOT/dcentos-deploy-lock"
PREEXEC_LOCK_BIN="$TEST_ROOT/dcentos-deploy-lock-preexec"
PDEATH_RACE_BIN="$TEST_ROOT/dcentos-deploy-lock-pdeath-race"
CC=${CC:-cc}

"$CC" -std=c11 -Wall -Wextra -Werror -O2 \
    -DDCENTOS_DEPLOY_LOCK_TEST_ALLOW_NONROOT=1 \
    "-DDCENTOS_DEPLOY_LOCK_PATH=\"$LOCK_FILE\"" \
    -o "$LOCK_BIN" "$SOURCE"

"$CC" -std=c11 -Wall -Wextra -Werror -O2 \
    -DDCENTOS_DEPLOY_LOCK_TEST_ALLOW_NONROOT=1 \
    -DDCENTOS_DEPLOY_LOCK_TEST_PRE_PDEATHSIG_USEC=500000 \
    "-DDCENTOS_DEPLOY_LOCK_PATH=\"$LOCK_FILE\"" \
    -o "$PREEXEC_LOCK_BIN" "$SOURCE"

"$CC" -std=c11 -Wall -Wextra -Werror -O2 \
    -DDCENTOS_DEPLOY_LOCK_TEST_ALLOW_NONROOT=1 \
    -DDCENTOS_DEPLOY_LOCK_TEST_PARENT_DEATH_PRECHECK_USEC=500000 \
    "-DDCENTOS_DEPLOY_LOCK_PATH=\"$LOCK_FILE\"" \
    -o "$PDEATH_RACE_BIN" "$SOURCE"

if "$LOCK_BIN" -- sh -c 'exit 23'; then
    echo "FAIL: child failure was reported as success" >&2
    exit 1
else
    status=$?
    [ "$status" -eq 23 ] || {
        echo "FAIL: child status $status was not propagated" >&2
        exit 1
    }
fi

ready="$TEST_ROOT/ready"
release="$TEST_ROOT/release"
"$LOCK_BIN" -- sh -c '
    : >"$1"
    while [ ! -e "$2" ]; do sleep 0.05; done
' sh "$ready" "$release" &
holder=$!
while [ ! -e "$ready" ]; do sleep 0.05; done
if "$LOCK_BIN" -- /bin/true; then
    echo "FAIL: concurrent command acquired the same kernel lock" >&2
    exit 1
else
    status=$?
    [ "$status" -eq 75 ] || exit 1
fi
: >"$release"
wait "$holder"

# Killing the coordinator cannot strand pathname ownership. The kernel drops
# its flock, and PR_SET_PDEATHSIG contains the direct child.
"$LOCK_BIN" -- sh -c 'while :; do sleep 1; done' &
holder=$!
sleep 0.1
kill -KILL "$holder"
wait "$holder" 2>/dev/null || true
acquired=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
    21 22 23 24 25 26 27 28 29 30; do
    if "$LOCK_BIN" -- /bin/true; then
        acquired=1
        break
    fi
    sleep 0.1
done
[ "$acquired" -eq 1 ] || {
    echo "FAIL: owner death stranded the kernel lock" >&2
    exit 1
}

# Parent death in the fork-to-prctl interval cannot be consumed by an
# inherited forwarding handler. The test build widens that interval while
# HUP/INT/TERM remain blocked; the child must notice reparenting and never
# execute the requested command.
preexec_marker="$TEST_ROOT/preexec-marker"
"$PREEXEC_LOCK_BIN" -- sh -c ': >"$1"' sh "$preexec_marker" &
preexec_holder=$!
sleep 0.1
kill -KILL "$preexec_holder"
wait "$preexec_holder" 2>/dev/null || true
sleep 0.6
[ ! -e "$preexec_marker" ] || {
    echo "FAIL: parent death allowed a pre-exec child to escape" >&2
    exit 1
}
"$LOCK_BIN" -- /bin/true

# The same compiled boundary gives a supervised hardware owner non-maskable
# containment if its shell supervisor disappears. Prove the relationship after
# exec with a command that deliberately handles TERM without exiting: the
# parent-death boundary must still kill it and must not invoke that handler.
pdeath_ready="$TEST_ROOT/pdeath-ready"
pdeath_received="$TEST_ROOT/pdeath-received"
pdeath_pid="$TEST_ROOT/pdeath.pid"
sh -c '
    "$1" --parent-death-signal "$$" -- sh "$2" "$3" "$4" "$5" &
    wait
' sh "$LOCK_BIN" "$PDEATH_CHILD" "$pdeath_ready" "$pdeath_received" \
    "$pdeath_pid" &
pdeath_parent=$!
while [ ! -e "$pdeath_ready" ]; do sleep 0.05; done
pdeath_child=$(cat "$pdeath_pid")
kill -KILL "$pdeath_parent"
wait "$pdeath_parent" 2>/dev/null || true
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    kill -0 "$pdeath_child" 2>/dev/null || break
    sleep 0.05
done
[ ! -e "$pdeath_received" ] || {
    echo "FAIL: supervisor loss used cooperative TERM instead of hard containment" >&2
    exit 1
}
if kill -0 "$pdeath_child" 2>/dev/null; then
    echo "FAIL: supervised child remained live after parent-death SIGKILL" >&2
    exit 1
fi

# The expected supervisor identity is captured before the asynchronous child
# can run. Widen the helper-start-to-first-getppid window, kill that exact
# supervisor, and prove the reparented helper never executes the command.
pdeath_race_marker="$TEST_ROOT/pdeath-race-marker"
pdeath_race_pidfile="$TEST_ROOT/pdeath-race.pid"
sh -c '
    "$1" --parent-death-signal "$$" -- sh -c '\''
        : >"$1"
        while :; do sleep 1; done
    '\'' sh "$2" &
    printf "%s\n" "$!" >"$3"
    wait
' sh "$PDEATH_RACE_BIN" "$pdeath_race_marker" "$pdeath_race_pidfile" &
pdeath_race_parent=$!
while [ ! -e "$pdeath_race_pidfile" ]; do sleep 0.05; done
pdeath_race_child=$(cat "$pdeath_race_pidfile")
kill -KILL "$pdeath_race_parent"
wait "$pdeath_race_parent" 2>/dev/null || true
sleep 0.6
[ ! -e "$pdeath_race_marker" ] || {
    echo "FAIL: reparented parent-death helper executed the supervised command" >&2
    exit 1
}
if kill -0 "$pdeath_race_child" 2>/dev/null; then
    echo "FAIL: reparented parent-death helper remained live" >&2
    exit 1
fi

# A coordinator can die while a detached descendant continues. Because the
# command tree inherits the same flocked open-file-description, wrapper death
# alone must not admit a successor.
escaped_ready="$TEST_ROOT/escaped-ready"
"$LOCK_BIN" -- sh -c '
    trap "" TERM
    (
        trap "" TERM
        : >"$1"
        sleep 1
    ) &
    wait
' sh "$escaped_ready" &
escaped_holder=$!
while [ ! -e "$escaped_ready" ]; do sleep 0.05; done
kill -KILL "$escaped_holder"
wait "$escaped_holder" 2>/dev/null || true
if "$LOCK_BIN" -- /bin/true; then
    echo "FAIL: wrapper death released exclusion under a live descendant" >&2
    exit 1
else
    status=$?
    [ "$status" -eq 75 ] || exit 1
fi
sleep 1.1
"$LOCK_BIN" -- /bin/true

# Handoff releases only after the admitted command explicitly publishes its
# ready edge. The command may remain alive afterward without retaining lock.
handoff_ready="$TEST_ROOT/handoff-ready"
"$LOCK_BIN" --handoff sh -c '
    "$1" --ready
    : >"$2"
    sleep 1
' sh "$LOCK_BIN" "$handoff_ready" &
handoff_holder=$!
while [ ! -e "$handoff_ready" ]; do sleep 0.05; done
"$LOCK_BIN" -- /bin/true
wait "$handoff_holder"

# If the initiating command dies without a ready edge, an inheriting delayed
# child keeps the pipe open and therefore keeps exclusion until it exits.
"$LOCK_BIN" --handoff sh -c 'sleep 1 &' &
ambiguous_holder=$!
sleep 0.1
if "$LOCK_BIN" -- /bin/true; then
    echo "FAIL: unready descendant did not retain fail-closed exclusion" >&2
    exit 1
else
    status=$?
    [ "$status" -eq 75 ] || exit 1
fi
wait "$ambiguous_holder"
"$LOCK_BIN" -- /bin/true

rm -f "$LOCK_FILE"
ln -s "$TEST_ROOT/missing" "$LOCK_FILE"
if "$LOCK_BIN" -- /bin/true >/dev/null 2>&1; then
    echo "FAIL: symlink lock path was accepted" >&2
    exit 1
fi

printf 'dcentos deploy lock lifecycle: passed\n'
