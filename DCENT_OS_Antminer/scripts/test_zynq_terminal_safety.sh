#!/bin/sh
# Offline terminal-safety contract for exact AM2 Zynq launchers.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
IDENTITY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-process-identity.sh"
FAN_CUSTODY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-fan-custody.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-zynq-safety.XXXXXX") || exit 1
FAILURES=0
CHECKED=0

cleanup() {
    if [ -r "$TEST_ROOT/fanhold.pid" ]; then
        HOLDER_PID=$(cat "$TEST_ROOT/fanhold.pid" 2>/dev/null || true)
        case "$HOLDER_PID" in
            ''|*[!0-9]*) ;;
            *) kill -9 "$HOLDER_PID" 2>/dev/null || true ;;
        esac
    fi
    case "$TEST_ROOT" in
        "${TMPDIR:-/tmp}"/dcentos-zynq-safety.*) rm -rf "$TEST_ROOT" ;;
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

mkdir -p "$TEST_ROOT/bin"
DAEMON="$TEST_ROOT/dcentrald"
POLARITY_JOURNAL="$TEST_ROOT/polarity.journal"
printf '%s\n' '#!/bin/sh' \
    'if [ "${1:-}" = --safe-off ]; then' \
    '    printf "%s:%s\n" "${DCENT_AM2_PWR_CONTROL_ACTIVE_LOW:-0}" "${DCENT_AM2_PWR_CONTROL_ACTIVE_HIGH:-0}" >> "$DCENT_TEST_POLARITY_JOURNAL"' \
    '    exit "${DCENT_TEST_DAEMON_RC:-0}"' \
    'fi' \
    'exit 64' > "$DAEMON"
chmod +x "$DAEMON"
FAN_CUSTODIAN_DAEMON="$TEST_ROOT/dcentrald-fan-custodian"
cp /bin/sh "$FAN_CUSTODIAN_DAEMON"
chmod +x "$FAN_CUSTODIAN_DAEMON"

printf '%s\n' '#!/bin/sh' \
    'pidfile=' \
    'hold_pwm=30' \
    'while [ "$#" -gt 0 ]; do' \
    '    case "$1" in' \
    '        -p) shift; pidfile=${1:-} ;;' \
    '        --hold-fan) shift; hold_pwm=${1:-30} ;;' \
    '    esac' \
    '    shift' \
    'done' \
    '[ "${DCENT_TEST_FAN_RC:-0}" -eq 0 ] || exit "$DCENT_TEST_FAN_RC"' \
    '"$DCENT_TEST_FAN_CUSTODIAN_DAEMON" -c '\''trap "exit 0" TERM INT; while :; do sleep 60; done'\'' fan-custodian --hold-fan "$hold_pwm" &' \
    'holder_pid=$!' \
    'printf "%s\n" "$holder_pid" > "$pidfile"' \
    'start_ticks=$(awk '\''{print $22}'\'' "/proc/$holder_pid/stat")' \
    'boot_id=$(cat /proc/sys/kernel/random/boot_id)' \
    'if [ "${DCENT_TEST_FAN_READY:-1}" -eq 1 ]; then' \
    '    printf "%s %s fan-custodian %s\n" "$holder_pid" "$start_ticks" "$boot_id" > "$DCENT_TEST_FANHOLD_READYFILE"' \
    'fi' \
    'exit 0' > "$TEST_ROOT/bin/start-stop-daemon"
chmod +x "$TEST_ROOT/bin/start-stop-daemon"
printf '%s\n' '#!/bin/sh' \
    '[ -z "${DCENT_TEST_PIDOF_OUTPUT:-}" ] || printf "%s\n" "$DCENT_TEST_PIDOF_OUTPUT"' \
    > "$TEST_ROOT/bin/pidof"
chmod +x "$TEST_ROOT/bin/pidof"

run_safety() {
    SUPERVISOR=$1
    TARGET=$2
    DAEMON_RC=$3
    FAN_RC=$4
    # The final concurrency case intentionally invokes this function twice.
    # Truncation avoids a check-then-unlink race in BusyBox rm while preserving
    # the shared-log conditions of two real init invocations.
    : > "$TEST_ROOT/output"
    : > "$TEST_ROOT/safety.log"
    DCENT_TEST_ONLY_ZYNQ_LAUNCHER=1 \
    DCENT_TEST_DAEMON="$DAEMON" \
    DCENT_TEST_LOGFILE="$TEST_ROOT/safety.log" \
    DCENT_TEST_PIDFILE="$TEST_ROOT/wrapper.pid" \
    DCENT_TEST_CHILD_PIDFILE="$TEST_ROOT/child.pid" \
    DCENT_TEST_EXPECTFILE="$TEST_ROOT/expected.pid" \
    DCENT_TEST_FANHOLD_PIDFILE="$TEST_ROOT/fanhold.pid" \
    DCENT_TEST_FANHOLD_READYFILE="$TEST_ROOT/fanhold.ready" \
    DCENT_TEST_PROCESS_IDENTITY_HELPER="$IDENTITY_HELPER" \
    DCENT_TEST_FAN_CUSTODY_HELPER="$FAN_CUSTODY_HELPER" \
    DCENT_TEST_START_STOP_DAEMON="$TEST_ROOT/bin/start-stop-daemon" \
    DCENT_TEST_FAN_CUSTODIAN_DAEMON="$FAN_CUSTODIAN_DAEMON" \
    DCENT_TEST_ONLY_PROCESS_IDENTITY=1 \
    DCENT_TEST_ONLY_FAN_INTERPRETER=1 \
    DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/bin/pidof" \
    DCENT_TEST_PIDOF_OUTPUT="${PIDOF_OUTPUT:-}" \
    DCENT_TEST_PLATFORM=zynq-bm3-am2 \
    DCENT_TEST_BOARD_TARGET="$TARGET" \
    DCENT_TEST_DAEMON_RC="$DAEMON_RC" \
    DCENT_TEST_FAN_RC="$FAN_RC" \
    DCENT_TEST_FAN_READY="${FAN_READY:-1}" \
    DCENT_TEST_FAN_READY_WAIT=1 \
    DCENT_TEST_FANHOLD_READYFILE="$TEST_ROOT/fanhold.ready" \
    DCENT_TEST_FAN_CUSTODIAN_DAEMON="$FAN_CUSTODIAN_DAEMON" \
    DCENT_TEST_POLARITY_JOURNAL="$POLARITY_JOURNAL" \
    DCENT_AM2_PWR_CONTROL_ACTIVE_LOW=1 \
        sh "$SUPERVISOR" safety > "$TEST_ROOT/output" 2>&1
}

for SPEC in \
    "am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald:am2-s17p:S17" \
    "am2-s19pro/rootfs-overlay/etc/init.d/S82dcentrald:am2-s19pro:S19Pro"; do
    RELATIVE=${SPEC%%:*}
    REMAINDER=${SPEC#*:}
    TARGET=${REMAINDER%%:*}
    LABEL=${REMAINDER#*:}
    SUPERVISOR="$PROJECT_DIR/br2_external_dcentos/board/zynq/$RELATIVE"

    CHECKED=$((CHECKED + 1))
    if run_safety "$SUPERVISOR" "$TARGET" 1 0; then
        fail "$LABEL fan success masked a failed gpio907 power cut"
    elif [ -e "$TEST_ROOT/fanhold.pid" ] \
        && grep -Fq 'fan-only fallback is not a power-cut receipt' "$TEST_ROOT/safety.log"; then
        pass "$LABEL preserves failed rail-cut status after best-effort fan fallback"
    else
        fail "$LABEL failed-cut path did not exercise successful fan fallback"
    fi

    CHECKED=$((CHECKED + 1))
    if run_safety "$SUPERVISOR" "$TARGET" 0 1; then
        fail "$LABEL returned success when persistent fan custody failed"
    else
        pass "$LABEL requires fan custody in addition to power-cut evidence"
    fi

    CHECKED=$((CHECKED + 1))
    FAN_READY=0
    if run_safety "$SUPERVISOR" "$TARGET" 0 0; then
        fail "$LABEL accepted a background launch without a readiness receipt"
    elif [ ! -e "$TEST_ROOT/fanhold.pid" ] \
        && [ ! -e "$TEST_ROOT/fanhold.ready" ] \
        && [ ! -e "$TEST_ROOT/fanhold.ready.pending" ] \
        && [ ! -e "$TEST_ROOT/fanhold.ready.lock" ]; then
        pass "$LABEL rejects and exactly reaps an unready background custodian"
    else
        LOCK_OWNER=$(cat "$TEST_ROOT/fanhold.ready.lock/owner" 2>/dev/null || true)
        fail "$LABEL left ambiguous custody after readiness timeout (lock_owner=$LOCK_OWNER)"
    fi
    FAN_READY=1

    CHECKED=$((CHECKED + 1))
    if run_safety "$SUPERVISOR" "$TARGET" 0 0; then
        pass "$LABEL accepts the combined power-cut and fan-custody receipt"
    else
        SAFETY_DIAGNOSTIC=$(tr '\n' ' ' < "$TEST_ROOT/output" 2>/dev/null || true)
        fail "$LABEL rejected a complete terminal safety receipt: $SAFETY_DIAGNOSTIC"
    fi

    PRIOR_HOLDER_PID=$(cat "$TEST_ROOT/fanhold.pid" 2>/dev/null || true)
    CHECKED=$((CHECKED + 1))
    if run_safety "$SUPERVISOR" "$TARGET" 0 0; then
        CURRENT_HOLDER_PID=$(cat "$TEST_ROOT/fanhold.pid" 2>/dev/null || true)
        PRIOR_STATE=$(awk '{print $3}' "/proc/$PRIOR_HOLDER_PID/stat" 2>/dev/null || true)
        if [ -n "$CURRENT_HOLDER_PID" ] \
            && [ "$CURRENT_HOLDER_PID" != "$PRIOR_HOLDER_PID" ] \
            && { [ -z "$PRIOR_STATE" ] || [ "$PRIOR_STATE" = Z ]; }; then
            pass "$LABEL rotates exact fan custody without leaving the prior owner live"
        else
            fail "$LABEL did not prove exact prior-custodian death before replacement"
        fi
    else
        SAFETY_DIAGNOSTIC=$(tr '\n' ' ' < "$TEST_ROOT/output" 2>/dev/null || true)
        fail "$LABEL rejected safe replacement of a verified prior custodian: $SAFETY_DIAGNOSTIC"
    fi

    POLARITY_LINES_BEFORE=$(wc -l < "$POLARITY_JOURNAL" 2>/dev/null || printf 0)
    CHECKED=$((CHECKED + 1))
    PIDOF_OUTPUT=123
    if run_safety "$SUPERVISOR" "$TARGET" 0 0; then
        fail "$LABEL admitted a competing terminal writer beside a live owner"
    else
        POLARITY_LINES_AFTER=$(wc -l < "$POLARITY_JOURNAL" 2>/dev/null || printf 0)
        if [ "$POLARITY_LINES_AFTER" -eq "$POLARITY_LINES_BEFORE" ] \
            && [ ! -e "$TEST_ROOT/fanhold.pid" ] \
            && [ ! -e "$TEST_ROOT/fanhold.ready" ]; then
            pass "$LABEL refuses a live artifact-free owner before power or fan writes"
        else
            fail "$LABEL live-owner refusal still touched terminal safety state"
        fi
    fi
    PIDOF_OUTPUT=
done

# A launcher PID can be reused by another role of the same executable before
# readiness. Even a deceptive command line containing the expected hold pair
# must not synthesize kill authority unless it is the exact three-argument
# custodian invocation.
REUSE_LAUNCHER="$TEST_ROOT/bin/reuse-launcher"
printf '%s\n' '#!/bin/sh' \
    'pidfile=' \
    'while [ "$#" -gt 0 ]; do' \
    '    [ "$1" = -p ] && { shift; pidfile=${1:-}; }' \
    '    shift' \
    'done' \
    'printf "%s\n" "$DCENT_TEST_REUSED_PID" > "$pidfile"' \
    'exit 0' > "$REUSE_LAUNCHER"
chmod +x "$REUSE_LAUNCHER"
"$FAN_CUSTODIAN_DAEMON" -c 'trap "exit 0" TERM INT; while :; do sleep 60; done' \
    main-role --hold-fan 30 --serial-mining &
REUSED_ROLE_PID=$!
CHECKED=$((CHECKED + 1))
if DCENT_PROCESS_IDENTITY_TEST_AUTHORITY=1 \
    DCENT_TEST_ONLY_PROCESS_IDENTITY=1 \
    DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/bin/pidof" \
    DCENT_TEST_PIDOF_OUTPUT= \
    DCENT_TEST_REUSED_PID="$REUSED_ROLE_PID" \
    sh -c '. "$1"; . "$2"; dcent_fan_custodian_start "$3" 30 "$4" "$5" "$6" "$7" 1' \
        fan-role-test "$IDENTITY_HELPER" "$FAN_CUSTODY_HELPER" \
        "$FAN_CUSTODIAN_DAEMON" "$TEST_ROOT/reused.pid" \
        "$TEST_ROOT/reused.ready" "$REUSE_LAUNCHER" "$TEST_ROOT/reused.log" \
        2> "$TEST_ROOT/reused.stderr"; then
    fail 'same-executable non-hold role was accepted as pending fan custody'
elif ! kill -0 "$REUSED_ROLE_PID" 2>/dev/null; then
    fail 'pending role validation signaled the same-executable non-hold process'
elif [ -e "$TEST_ROOT/reused.pid" ] || [ -e "$TEST_ROOT/reused.ready" ] \
    || [ -e "$TEST_ROOT/reused.ready.pending" ] \
    || [ -e "$TEST_ROOT/reused.ready.lock" ]; then
    fail 'pending role refusal left ambiguous fan custody artifacts'
elif ! grep -q 'did not publish a verified readiness receipt' \
    "$TEST_ROOT/reused.stderr"; then
    fail 'pending role refusal omitted its custody diagnostic'
else
    pass 'pending identity rejects same-executable PID reuse without signaling it'
fi
kill -9 "$REUSED_ROLE_PID" 2>/dev/null || true
wait "$REUSED_ROLE_PID" 2>/dev/null || true

# The transition lock itself must have no crash window with an ownerless mkdir.
# A visible lock is one complete typed record, and a killed owner is recoverable
# by exact PID/start/boot identity without operator deletion.
CHECKED=$((CHECKED + 1))
ATOMIC_LOCK="$TEST_ROOT/atomic.ready.lock"
ATOMIC_READY="$TEST_ROOT/atomic-lock.ready"
ATOMIC_JOURNAL="$TEST_ROOT/atomic-lock.journal"
sh -c '. "$1"; . "$2"; dcent_fan_lock_acquire "$3" 1 || exit 1; : > "$4"; while :; do sleep 1; done' \
    fan-lock-holder "$IDENTITY_HELPER" "$FAN_CUSTODY_HELPER" \
    "$ATOMIC_LOCK" "$ATOMIC_READY" &
ATOMIC_HOLDER_PID=$!
ATOMIC_WAITED=0
while [ ! -e "$ATOMIC_READY" ] && kill -0 "$ATOMIC_HOLDER_PID" 2>/dev/null \
    && [ "$ATOMIC_WAITED" -lt 5 ]; do
    sleep 1
    ATOMIC_WAITED=$((ATOMIC_WAITED + 1))
done
ATOMIC_RECORD_OK=0
if [ -f "$ATOMIC_LOCK" ] && awk '
    NF { rows++; fields += NF; if (NF == 4 && $3 == "fan-custody-lock") typed++ }
    END { exit !(rows == 1 && fields == 4 && typed == 1) }
' "$ATOMIC_LOCK"; then
    ATOMIC_RECORD_OK=1
fi
kill -9 "$ATOMIC_HOLDER_PID" 2>/dev/null || true
wait "$ATOMIC_HOLDER_PID" 2>/dev/null || true
sh -c '. "$1"; . "$2"; dcent_fan_lock_acquire "$3" 5 || exit 1; printf "enter %s\n" "$$" >> "$4"; sleep 2; printf "leave %s\n" "$$" >> "$4"; dcent_fan_lock_release "$3"' \
    fan-lock-recovery-a "$IDENTITY_HELPER" "$FAN_CUSTODY_HELPER" \
    "$ATOMIC_LOCK" "$ATOMIC_JOURNAL" &
ATOMIC_RECOVERY_A=$!
sh -c '. "$1"; . "$2"; dcent_fan_lock_acquire "$3" 5 || exit 1; printf "enter %s\n" "$$" >> "$4"; sleep 2; printf "leave %s\n" "$$" >> "$4"; dcent_fan_lock_release "$3"' \
    fan-lock-recovery-b "$IDENTITY_HELPER" "$FAN_CUSTODY_HELPER" \
    "$ATOMIC_LOCK" "$ATOMIC_JOURNAL" &
ATOMIC_RECOVERY_B=$!
ATOMIC_RECOVERY_A_RC=0
ATOMIC_RECOVERY_B_RC=0
wait "$ATOMIC_RECOVERY_A" || ATOMIC_RECOVERY_A_RC=$?
wait "$ATOMIC_RECOVERY_B" || ATOMIC_RECOVERY_B_RC=$?
if [ "$ATOMIC_RECORD_OK" -ne 1 ]; then
    fail 'fan transition lock became visible without one complete typed owner'
elif [ "$ATOMIC_RECOVERY_A_RC" -ne 0 ] || [ "$ATOMIC_RECOVERY_B_RC" -ne 0 ]; then
    fail 'typed fan transition lock was not recoverable by both serialized contenders'
elif ! awk '
    NR == 1 && $1 == "enter" { first = $2 }
    NR == 2 && $1 == "leave" && $2 == first { first_done = 1 }
    NR == 3 && $1 == "enter" && $2 != first { second = $2 }
    NR == 4 && $1 == "leave" && $2 == second { second_done = 1 }
    END { exit !(NR == 4 && first_done && second_done) }
' "$ATOMIC_JOURNAL"; then
    fail 'concurrent stale-lock recovery contenders overlapped their custody transitions'
elif [ -e "$ATOMIC_LOCK" ] \
    || [ -e "${ATOMIC_LOCK}.recovery" ] \
    || find "$TEST_ROOT" -maxdepth 1 -name 'atomic.ready.lock*.candidate.*' \
        -print | grep -q .; then
    fail 'fan transition lock recovery left lock, recovery, or candidate artifacts'
else
    pass 'typed stale-lock recovery serializes contenders without an ABA window'
fi

# Two simultaneous terminal requests share one transition lock. The second may
# rotate the first verified holder, but exactly one typed custodian may survive.
CHECKED=$((CHECKED + 1))
CONCURRENT_SUPERVISOR="$PROJECT_DIR/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald"
(run_safety "$CONCURRENT_SUPERVISOR" am2-s17p 0 0) &
FIRST_SAFETY_PID=$!
(run_safety "$CONCURRENT_SUPERVISOR" am2-s17p 0 0) &
SECOND_SAFETY_PID=$!
FIRST_SAFETY_RC=0
SECOND_SAFETY_RC=0
wait "$FIRST_SAFETY_PID" || FIRST_SAFETY_RC=$?
wait "$SECOND_SAFETY_PID" || SECOND_SAFETY_RC=$?
READY_PID=$(awk 'NF { print $1; exit }' "$TEST_ROOT/fanhold.ready" 2>/dev/null || true)
EXACT_HOLDER_COUNT=0
for PROC_EXE in /proc/[0-9]*/exe; do
    [ "$(readlink -f "$PROC_EXE" 2>/dev/null || true)" = "$FAN_CUSTODIAN_DAEMON" ] \
        && EXACT_HOLDER_COUNT=$((EXACT_HOLDER_COUNT + 1))
done
if [ "$FIRST_SAFETY_RC" -eq 0 ] && [ "$SECOND_SAFETY_RC" -eq 0 ] \
    && [ "$EXACT_HOLDER_COUNT" -eq 1 ] \
    && [ "$READY_PID" = "$(cat "$TEST_ROOT/fanhold.pid" 2>/dev/null || true)" ]; then
    pass 'concurrent terminal requests serialize to one typed fan custodian'
else
    fail "concurrent terminal requests left ambiguous custody (rc=$FIRST_SAFETY_RC/$SECOND_SAFETY_RC holders=$EXACT_HOLDER_COUNT)"
fi

# Every exact AM2 launcher must hand `dcentrald --safe-off` exactly one declared
# gpio907 polarity, and today that declaration is ACTIVE_HIGH (journal `0:1`).
#
# Read this literal as "what we currently ship", NOT as "what the hardware is".
# The factory jigs say the opposite: gpio907 is active-LOW (`0` = rail ON),
# model-exact on both the S17 Pro and S19 Pro jig binaries, where `power_on`
# writes "0" and `power_off` writes "1" under Bitmain's own symbols. The
# ACTIVE_HIGH export is retained deliberately, not by oversight — `fdb9de37`
# records that removing it made `--safe-off` refuse outright (an *inoperative*
# safe-off rather than a fail-closed one), which is strictly worse.
#
# So this assertion's job is to make the eventual operator-gated flip visible:
# it is a tripwire on the declaration, and whoever flips the polarity must
# change this literal to `1:0` in the same commit. Do not relax it to accept
# either value — that would let the flip land silently, or let a launcher ship
# with both markers set, which the daemon treats as unproven polarity.
if grep -Ev '^0:1$' "$POLARITY_JOURNAL" >/dev/null 2>&1; then
    fail 'exact AM2 launchers did not all declare the single currently-shipped active-HIGH gpio907 polarity'
fi

if [ "$FAILURES" -ne 0 ]; then
    printf 'Zynq terminal-safety contract failed: %s failure(s), %s case(s)\n' \
        "$FAILURES" "$CHECKED" >&2
    exit 1
fi
printf 'Zynq terminal-safety contract passed across %s behavioral cases.\n' "$CHECKED"
