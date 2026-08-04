#!/bin/sh
# Behavioral contract for the shared PID/start-tick managed-stop library.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
IDENTITY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-process-identity.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentrald-identity.XXXXXX") || exit 1
FAILURES=0
CHECKED=0

cleanup() {
    for p in ${TEST_PIDS:-}; do
        kill -9 "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
    case "$TEST_ROOT" in
        "${TMPDIR:-/tmp}"/dcentrald-identity.*) rm -rf "$TEST_ROOT" ;;
    esac
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    printf 'PASS: %s\n' "$*"
}

if [ ! -f "$IDENTITY_HELPER" ] || ! sh -n "$IDENTITY_HELPER"; then
    printf 'FAIL: exact-process identity helper is missing or not POSIX shell\n' >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$IDENTITY_HELPER"

# The injected pidof command is a fixture capability, not an operator setting.
# Both flags without the supervisor-issued internal authority must fall through
# to production pidof; an explicitly authorized fixture must remain usable.
PIDOF_MARKER="$TEST_ROOT/injected-pidof.called"
printf '%s\n' '#!/bin/sh' \
    ': > "$DCENT_TEST_PIDOF_MARKER"' \
    'exit 1' > "$TEST_ROOT/injected-pidof"
chmod +x "$TEST_ROOT/injected-pidof"
export DCENT_TEST_PIDOF_MARKER="$PIDOF_MARKER"
DCENT_TEST_ONLY_PROCESS_IDENTITY=1
DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/injected-pidof"
DCENT_PROCESS_IDENTITY_TEST_AUTHORITY=0
CHECKED=$((CHECKED + 1))
dcent_pidof_dcentrald >/dev/null 2>&1 || true
if [ -e "$PIDOF_MARKER" ]; then
    fail 'operator-controlled test flags invoked the injected pidof without internal authority'
else
    DCENT_PROCESS_IDENTITY_TEST_AUTHORITY=1
    dcent_pidof_dcentrald >/dev/null 2>&1 || true
    if [ -e "$PIDOF_MARKER" ]; then
        pass 'pidof test seam requires explicit internal supervisor authority'
    else
        fail 'internally authorized pidof fixture was not invoked'
    fi
fi
unset DCENT_TEST_ONLY_PROCESS_IDENTITY DCENT_TEST_PIDOF_COMMAND \
    DCENT_PROCESS_IDENTITY_TEST_AUTHORITY DCENT_TEST_PIDOF_MARKER

cp /bin/sleep "$TEST_ROOT/dcentrald"
chmod +x "$TEST_ROOT/dcentrald"
SAFETY_SCRIPT="$TEST_ROOT/safety.sh"
SAFETY_JOURNAL="$TEST_ROOT/safety.journal"
printf '%s\n' '#!/bin/sh' \
    'state=$(awk '\''{print $3}'\'' "/proc/$DCENT_TEST_WATCH_PID/stat" 2>/dev/null || true)' \
    '[ -z "$state" ] || [ "$state" = Z ] || exit 91' \
    'printf "%s\n" "$1" >> "$DCENT_TEST_SAFETY_JOURNAL"' \
    'exit 0' > "$SAFETY_SCRIPT"
chmod +x "$SAFETY_SCRIPT"
export DCENT_TEST_WATCH_PID DCENT_TEST_SAFETY_JOURNAL="$SAFETY_JOURNAL"

# The exact two-field record authorizes TERM, but fallback safety cannot run
# until that same executable/start-tick identity is gone or zombie.
"$TEST_ROOT/dcentrald" 60 &
CHILD_PID=$!
TEST_PIDS="$CHILD_PID"
CHILD_TICKS=$(awk '{print $22}' "/proc/$CHILD_PID/stat")
printf '%s %s\n' "$CHILD_PID" "$CHILD_TICKS" > "$TEST_ROOT/child.pid"
DCENT_TEST_WATCH_PID=$CHILD_PID
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 2 1 0; then
    STATE=$(awk '{print $3}' "/proc/$CHILD_PID/stat" 2>/dev/null || true)
    if { [ -z "$STATE" ] || [ "$STATE" = Z ]; } \
        && grep -Fxq safety "$SAFETY_JOURNAL"; then
        pass 'two-field identity is terminated and observed dead before fallback safety'
    else
        fail 'managed stop returned before exact owner death or fallback safety'
    fi
else
    fail 'valid two-field identity failed managed stop'
fi
wait "$CHILD_PID" 2>/dev/null || true
TEST_PIDS=

# The current helper receipt is bound to session token + boot ID + exact child
# identity. It suppresses the fallback writer only after the child record is
# removed by the simulated serialized custodian.
rm -f "$SAFETY_JOURNAL" "$TEST_ROOT/crash-latch" "$TEST_ROOT/wrapper.pid"
"$TEST_ROOT/dcentrald" 60 &
CHILD_PID=$!
CHILD_TICKS=$(awk '{print $22}' "/proc/$CHILD_PID/stat")
SESSION_TOKEN=admission.test
BOOT_ID=11111111-2222-3333-4444-555555555555
printf '%s %s %s %s\n' "$CHILD_PID" "$CHILD_TICKS" "$SESSION_TOKEN" "$BOOT_ID" \
    > "$TEST_ROOT/child.pid"
DCENT_TEST_WATCH_PID=$CHILD_PID
(
    while :; do
        RECEIPT_STATE=$(awk '{print $3}' "/proc/$CHILD_PID/stat" 2>/dev/null || true)
        [ -z "$RECEIPT_STATE" ] || [ "$RECEIPT_STATE" = Z ] && break
    done
    printf 'crash-latched:session-%s-boot-%s-pid-%s-start-%s-expected-zero-awaiting-typed-disposition\n' \
        "$SESSION_TOKEN" "$BOOT_ID" "$CHILD_PID" "$CHILD_TICKS" > "$TEST_ROOT/crash-latch"
    rm -f "$TEST_ROOT/child.pid"
) &
RECEIPT_WRAPPER_PID=$!
TEST_PIDS="$CHILD_PID $RECEIPT_WRAPPER_PID"
printf '%s\n' "$RECEIPT_WRAPPER_PID" > "$TEST_ROOT/wrapper.pid"
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 2 1 2 \
    && [ ! -e "$SAFETY_JOURNAL" ]; then
    pass 'session/boot-bound helper receipt suppresses the fallback writer'
else
    fail 'current typed helper receipt was rejected or raced with fallback safety'
fi
wait "$CHILD_PID" 2>/dev/null || true
wait "$RECEIPT_WRAPPER_PID" 2>/dev/null || true
TEST_PIDS=

# Even identical PID/start-tick text is stale when its boot identity differs.
# With no live wrapper, that mismatch must take the checked fallback path.
rm -f "$SAFETY_JOURNAL" "$TEST_ROOT/crash-latch" "$TEST_ROOT/wrapper.pid"
"$TEST_ROOT/dcentrald" 60 &
CHILD_PID=$!
CHILD_TICKS=$(awk '{print $22}' "/proc/$CHILD_PID/stat")
printf '%s %s %s %s\n' "$CHILD_PID" "$CHILD_TICKS" "$SESSION_TOKEN" "$BOOT_ID" \
    > "$TEST_ROOT/child.pid"
DCENT_TEST_WATCH_PID=$CHILD_PID
(
    while :; do
        RECEIPT_STATE=$(awk '{print $3}' "/proc/$CHILD_PID/stat" 2>/dev/null || true)
        [ -z "$RECEIPT_STATE" ] || [ "$RECEIPT_STATE" = Z ] && break
    done
    printf 'crash-latched:session-%s-boot-wrong-boot-pid-%s-start-%s-expected-zero-awaiting-typed-disposition\n' \
        "$SESSION_TOKEN" "$CHILD_PID" "$CHILD_TICKS" > "$TEST_ROOT/crash-latch"
    rm -f "$TEST_ROOT/child.pid"
) &
STALE_WRITER_PID=$!
TEST_PIDS="$CHILD_PID $STALE_WRITER_PID"
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/missing-wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 2 1 2 \
    && grep -Fxq safety "$SAFETY_JOURNAL"; then
    pass 'cross-boot receipt collision cannot suppress checked fallback safety'
else
    fail 'cross-boot receipt collision was accepted as the current session'
fi
wait "$CHILD_PID" 2>/dev/null || true
wait "$STALE_WRITER_PID" 2>/dev/null || true
TEST_PIDS=

# A live dcentrald with the wrong start tick is possible PID reuse. It must not
# be signaled, have its custody files removed, or trigger a hardware writer.
rm -f "$SAFETY_JOURNAL" "$TEST_ROOT/stop.log" "$TEST_ROOT/crash-latch"
"$TEST_ROOT/dcentrald" 60 &
REUSED_PID=$!
TEST_PIDS="$REUSED_PID"
REUSED_TICKS=$(awk '{print $22}' "/proc/$REUSED_PID/stat")
printf '%s %s\n' "$REUSED_PID" "$((REUSED_TICKS + 1))" > "$TEST_ROOT/child.pid"
DCENT_TEST_WATCH_PID=$REUSED_PID
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 0 0 0; then
    fail 'PID-reuse identity mismatch returned success'
elif ! kill -0 "$REUSED_PID" 2>/dev/null; then
    fail 'PID-reuse identity mismatch signaled the unrelated live process'
elif [ -e "$SAFETY_JOURNAL" ]; then
    fail 'PID-reuse identity mismatch invoked a competing safety writer'
else
    pass 'PID-reuse mismatch preserves the live process and suppresses safety writes'
fi
kill -9 "$REUSED_PID" 2>/dev/null || true
wait "$REUSED_PID" 2>/dev/null || true
TEST_PIDS=

# A stale crash marker is not a current receipt without the exact child
# identity embedded by the session helper.
rm -f "$SAFETY_JOURNAL" "$TEST_ROOT/child.pid" "$TEST_ROOT/wrapper.pid"
printf 'crash-latched:session-old-pid-1-start-1-unexpected-exit\n' \
    > "$TEST_ROOT/crash-latch"
DCENT_TEST_WATCH_PID=999999
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 0 0 0 \
    && grep -Fxq safety "$SAFETY_JOURNAL"; then
    pass 'stale unbound crash marker cannot suppress fallback safety'
else
    fail 'stale unbound crash marker was accepted as current terminal receipt'
fi

# An observed wrapper blocks fallback even when child identity is missing: it
# may still be inside the serialized helper safety action.
rm -f "$SAFETY_JOURNAL" "$TEST_ROOT/child.pid" "$TEST_ROOT/crash-latch"
/bin/sleep 60 &
WRAPPER_PID=$!
TEST_PIDS="$WRAPPER_PID"
printf '%s\n' "$WRAPPER_PID" > "$TEST_ROOT/wrapper.pid"
CHECKED=$((CHECKED + 1))
if dcent_stop_managed_session "$TEST_ROOT/child.pid" "$TEST_ROOT/expected.pid" \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/wrapper.pid" "$TEST_ROOT/crash-latch" \
    "$SAFETY_SCRIPT" "$TEST_ROOT/stop.log" 0 0 0; then
    fail 'live session wrapper allowed a competing fallback writer'
elif [ -e "$SAFETY_JOURNAL" ]; then
    fail 'live session wrapper path invoked fallback safety'
else
    pass 'live session wrapper suppresses a concurrent fallback custodian'
fi
kill -9 "$WRAPPER_PID" 2>/dev/null || true
wait "$WRAPPER_PID" 2>/dev/null || true
TEST_PIDS=

if [ "$FAILURES" -ne 0 ]; then
    printf 'dcentrald process-identity contract failed: %s failure(s), %s case(s)\n' \
        "$FAILURES" "$CHECKED" >&2
    exit 1
fi
printf 'dcentrald process-identity contract passed across %s behavioral cases.\n' "$CHECKED"
