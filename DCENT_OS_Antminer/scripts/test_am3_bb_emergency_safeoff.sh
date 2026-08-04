#!/bin/sh
# Behavioral contract for the AM3-BB emergency GPIO/PWM safe-off path.
# All actuation is redirected to disposable fixture trees; this test never
# writes to the host's /sys hierarchy.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SUPERVISOR="$PROJECT_DIR/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald"
BOARD_SETUP="$PROJECT_DIR/br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/init.d/S37board_setup"
HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
IDENTITY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-process-identity.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-am3-safeoff.XXXXXX") || exit 1
GPIO_ROOT="$TEST_ROOT/gpio"
PWM_ROOT="$TEST_ROOT/pwm"
LOGFILE="$TEST_ROOT/safety.log"
OUTPUT="$TEST_ROOT/output.log"
JOURNAL="$TEST_ROOT/write.journal"
FAIL_WRITE_PATH=
FAILURES=0
CHECKED=0

cleanup() {
    case "$TEST_ROOT" in
        "${TMPDIR:-/tmp}"/dcentos-am3-safeoff.*) rm -rf "$TEST_ROOT" ;;
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

reset_fixture() {
    case "$TEST_ROOT" in
        "${TMPDIR:-/tmp}"/dcentos-am3-safeoff.*) ;;
        *) printf 'unsafe test root: %s\n' "$TEST_ROOT" >&2; exit 1 ;;
    esac
    rm -rf "$GPIO_ROOT" "$PWM_ROOT"
    rm -f "$LOGFILE" "$OUTPUT" "$JOURNAL"
    FAIL_WRITE_PATH=
    mkdir -p "$GPIO_ROOT" "$PWM_ROOT"
    : > "$GPIO_ROOT/export"
}

make_gpio() {
    FIXTURE_GPIO="$GPIO_ROOT/gpio$1"
    mkdir -p "$FIXTURE_GPIO"
    printf '0\n' > "$FIXTURE_GPIO/active_low"
    printf 'in\n' > "$FIXTURE_GPIO/direction"
    printf '0\n' > "$FIXTURE_GPIO/value"
}

make_all_gpios() {
    for g in 49 60 27 22 59; do
        make_gpio "$g"
    done
}

make_modern_pwm_channel() {
    FIXTURE_PWM="$PWM_ROOT/pwmchip$1/pwm$2"
    mkdir -p "$FIXTURE_PWM"
    printf '0\n' > "$FIXTURE_PWM/period"
    printf '0\n' > "$FIXTURE_PWM/duty_cycle"
    printf '0\n' > "$FIXTURE_PWM/enable"
}

make_complete_modern_pwm() {
    make_modern_pwm_channel 0 1
    make_modern_pwm_channel 2 0
}

make_complete_legacy_pwm() {
    mkdir -p "$PWM_ROOT/pwm1" "$PWM_ROOT/pwm2"
    for p in "$PWM_ROOT/pwm1" "$PWM_ROOT/pwm2"; do
        printf '0\n' > "$p/period_ns"
        printf '0\n' > "$p/duty_ns"
        printf '0\n' > "$p/run"
    done
}

run_safety() {
    DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_FAIL_WRITE_PATH="$FAIL_WRITE_PATH" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    PLATFORM=beaglebone \
        sh "$SUPERVISOR" safety > "$OUTPUT" 2>&1
}

expect_failure() {
    CHECKED=$((CHECKED + 1))
    FAILURE_NAME="$1"
    EXPECTED_TERMINAL="$2"
    if run_safety; then
        fail "$FAILURE_NAME returned success"
        return
    fi
    if grep -Fq "SAFETY: $EXPECTED_TERMINAL" "$LOGFILE"; then
        pass "$FAILURE_NAME fails closed with the exact structured receipt"
    else
        fail "$FAILURE_NAME lacks terminal receipt: $EXPECTED_TERMINAL"
    fi
}

assert_value() {
    ASSERT_PATH="$1"
    ASSERT_EXPECTED="$2"
    ASSERT_ACTUAL=$(cat "$ASSERT_PATH" 2>/dev/null) || {
        fail "missing readback $ASSERT_PATH"
        return
    }
    [ "$ASSERT_ACTUAL" = "$ASSERT_EXPECTED" ] \
        || fail "$ASSERT_PATH expected $ASSERT_EXPECTED, got ${ASSERT_ACTUAL:-<empty>}"
}

assert_absent() {
    if [ -e "$1" ]; then
        fail "unexpected fixture artifact $1"
    fi
}

expect_start_failure_after_cut() {
    CHECKED=$((CHECKED + 1))
    START_NAME="$1"
    START_DAEMON="$2"
    START_CONFIG="$3"
    START_MGMT_CONFIG="$4"
    if PATH="$TEST_ROOT/bin:$PATH" \
        DCENT_TEST_PIDOF_OUTPUT= \
        DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/bin/pidof" \
        DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
        DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
        DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
        DCENT_TEST_LOGFILE="$LOGFILE" \
        DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
        DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
        DCENT_TEST_PLATFORM=beaglebone \
        DCENT_TEST_DAEMON="$START_DAEMON" \
        DCENT_TEST_CONFIG="$START_CONFIG" \
        DCENT_TEST_MGMT_ONLY_CONFIG="$START_MGMT_CONFIG" \
        DCENT_TEST_COLDBOOT_PROOF_MARKER="$TEST_ROOT/coldboot-proof-absent" \
            sh "$SUPERVISOR" start > "$OUTPUT" 2>&1; then
        fail "$START_NAME returned success"
        return
    fi
    if grep -Fq 'SAFETY: safeoff-verified gpio_cut=verified fan=verified' "$LOGFILE" \
        && [ "$(cat "$GPIO_ROOT/gpio59/value" 2>/dev/null)" = 0 ]; then
        pass "$START_NAME fails only after the verified monotonic load cut"
    else
        fail "$START_NAME did not produce a verified pre-artifact load cut"
    fi
}

run_helper_self_test() {
    HELPER_EXPECTATION="$1"
    DCENT_TEST_SAFETY_SCRIPT="$SUPERVISOR" \
    DCENT_TEST_EXPECT_SAFEOFF="$HELPER_EXPECTATION" \
    DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    PLATFORM=beaglebone \
        sh "$HELPER" self-test > "$OUTPUT" 2>&1
}

run_boot_setup() {
    printf 'am3-bb-s19jpro\n' > "$TEST_ROOT/board_target"
    DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    DCENT_TEST_BOARD_TARGET_FILE="$TEST_ROOT/board_target" \
    DCENT_TEST_SAFETY_SCRIPT="$SUPERVISOR" \
    PLATFORM=beaglebone \
        sh "$BOARD_SETUP" start > "$OUTPUT" 2>&1
}

if [ ! -f "$SUPERVISOR" ] || [ ! -f "$HELPER" ] \
    || [ ! -f "$IDENTITY_HELPER" ] || [ ! -f "$BOARD_SETUP" ]; then
    printf 'FAIL: AM3-BB supervisor or session helper is missing\n' >&2
    exit 1
fi
if ! sh -n "$SUPERVISOR" || ! sh -n "$HELPER" || ! sh -n "$BOARD_SETUP"; then
    printf 'FAIL: AM3-BB safety scripts are not POSIX-shell parseable\n' >&2
    exit 1
fi

reset_fixture
make_all_gpios
make_complete_modern_pwm
CHECKED=$((CHECKED + 1))
if DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=wrong-board \
    PLATFORM=beaglebone \
        sh "$SUPERVISOR" safety > "$OUTPUT" 2>&1; then
    fail 'wrong image identity returned safe-off success'
elif [ -s "$JOURNAL" ]; then
    fail 'wrong image identity emitted a fixed GPIO/PWM write'
else
    pass 'exact image identity gates all fixed AM3-BB mutations'
fi

# If the load-bearing board-enable cut cannot be verified, no reset or fan
# output may be touched. Start with enabled, non-target fan values so any
# disable/reconfiguration is observable.
reset_fixture
make_all_gpios
make_complete_modern_pwm
printf '1\n' > "$PWM_ROOT/pwmchip0/pwm1/enable"
printf '77777\n' > "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
printf '1\n' > "$PWM_ROOT/pwmchip2/pwm0/enable"
printf '88888\n' > "$PWM_ROOT/pwmchip2/pwm0/duty_cycle"
rm -f "$GPIO_ROOT/gpio59/active_low"
mkdir "$GPIO_ROOT/gpio59/active_low"
expect_failure 'unverifiable primary board-enable cut' \
    'safeoff-failed gpio_cut=failed fan=preserved'
assert_value "$PWM_ROOT/pwmchip0/pwm1/enable" 1
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 77777
assert_value "$PWM_ROOT/pwmchip2/pwm0/enable" 1
assert_value "$PWM_ROOT/pwmchip2/pwm0/duty_cycle" 88888
if grep -Fq "$PWM_ROOT/" "$JOURNAL" 2>/dev/null; then
    fail 'failed primary load cut emitted a PWM write'
fi

# Missing GPIO export is a failed load-cut receipt even if every other command
# succeeds. All three modern channels are present so the failure is unambiguous.
reset_fixture
for g in 60 27 22 59; do make_gpio "$g"; done
make_complete_modern_pwm
expect_failure 'GPIO export that never publishes gpio49' \
    'safeoff-failed gpio_cut=failed fan=verified'

# Polarity failure must short-circuit before any direction/value command reaches
# that pin. This guards against energizing a board through an unknown polarity.
reset_fixture
make_all_gpios
make_complete_modern_pwm
rm -f "$GPIO_ROOT/gpio49/active_low"
mkdir "$GPIO_ROOT/gpio49/active_low"
expect_failure 'unwritable GPIO active_low attribute' \
    'safeoff-failed gpio_cut=failed fan=verified'
assert_value "$GPIO_ROOT/gpio49/direction" in
assert_value "$GPIO_ROOT/gpio49/value" 0
assert_absent "$GPIO_ROOT/gpio49/direction_command"

reset_fixture
make_all_gpios
make_complete_modern_pwm
rm -f "$GPIO_ROOT/gpio60/value"
ln -s /dev/null "$GPIO_ROOT/gpio60/value"
expect_failure 'GPIO value with contradictory readback' \
    'safeoff-failed gpio_cut=failed fan=verified'

reset_fixture
make_all_gpios
make_complete_modern_pwm
rm -f "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
ln -s /dev/null "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
expect_failure 'one failed channel among complete modern fan PWMs' \
    'safeoff-failed gpio_cut=verified fan=failed'
if grep -Fq "$PWM_ROOT/" "$JOURNAL" 2>/dev/null; then
    fail 'invalid modern PWM preflight emitted a PWM write'
fi

reset_fixture
make_all_gpios
make_complete_modern_pwm
printf '100000\n' > "$PWM_ROOT/pwmchip0/pwm1/period"
printf '70000\n' > "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
printf '1\n' > "$PWM_ROOT/pwmchip0/pwm1/enable"
rm -f "$PWM_ROOT/pwmchip2/pwm0/period"
expect_failure 'modern fan PWM missing period evidence' \
    'safeoff-failed gpio_cut=verified fan=failed'
assert_value "$PWM_ROOT/pwmchip0/pwm1/period" 100000
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 70000
assert_value "$PWM_ROOT/pwmchip0/pwm1/enable" 1
if grep -Fq "$PWM_ROOT/" "$JOURNAL" 2>/dev/null; then
    fail 'incomplete two-channel PWM preflight emitted a PWM write'
fi

# A partial modern export must not mask the complete stock backend.
reset_fixture
make_all_gpios
make_modern_pwm_channel 0 1
printf '100000\n' > "$PWM_ROOT/pwmchip0/pwm1/period"
printf '65000\n' > "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
printf '1\n' > "$PWM_ROOT/pwmchip0/pwm1/enable"
make_complete_legacy_pwm
CHECKED=$((CHECKED + 1))
if run_safety; then
    pass 'partial modern PWM export falls back to the complete legacy backend'
else
    fail 'partial modern PWM export masked the complete legacy backend'
fi
assert_value "$PWM_ROOT/pwmchip0/pwm1/period" 100000
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 65000
assert_value "$PWM_ROOT/pwmchip0/pwm1/enable" 1
assert_value "$PWM_ROOT/pwm1/duty_ns" 30000
assert_value "$PWM_ROOT/pwm2/duty_ns" 30000

# A mid-transition write fault must restore the preflighted enabled tuple.
reset_fixture
make_all_gpios
make_complete_modern_pwm
printf '200000\n' > "$PWM_ROOT/pwmchip0/pwm1/period"
printf '75000\n' > "$PWM_ROOT/pwmchip0/pwm1/duty_cycle"
printf '1\n' > "$PWM_ROOT/pwmchip0/pwm1/enable"
FAIL_WRITE_PATH="$PWM_ROOT/pwmchip0/pwm1/period"
expect_failure 'mid-transition modern PWM write fault' \
    'safeoff-failed gpio_cut=verified fan=failed'
assert_value "$PWM_ROOT/pwmchip0/pwm1/period" 200000
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 75000
assert_value "$PWM_ROOT/pwmchip0/pwm1/enable" 1
if ! grep -Fq 'restored prior front-pwm1 tuple after transition failure' "$LOGFILE"; then
    fail 'mid-transition PWM failure lacks a verified restoration receipt'
fi

# Already-enabled 100us channels stay enabled throughout a duty-only update.
reset_fixture
make_all_gpios
make_complete_modern_pwm
for p in "$PWM_ROOT/pwmchip0/pwm1" "$PWM_ROOT/pwmchip2/pwm0"; do
    printf '100000\n' > "$p/period"
    printf '70000\n' > "$p/duty_cycle"
    printf '1\n' > "$p/enable"
done
CHECKED=$((CHECKED + 1))
if run_safety; then
    pass 'valid enabled PWM channels use a duty-only safety adjustment'
else
    fail 'valid enabled PWM channels failed duty-only adjustment'
fi
if grep -Eq '/(enable|period)=' "$JOURNAL" 2>/dev/null; then
    fail 'duty-only PWM adjustment rewrote enable or period'
fi
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 30000
assert_value "$PWM_ROOT/pwmchip2/pwm0/duty_cycle" 30000

reset_fixture
make_all_gpios
expect_failure 'missing AM3-BB fan PWM control' \
    'safeoff-failed gpio_cut=verified fan=failed'

# Stock BB exposes a complete legacy period/duty/run tuple on two channels.
reset_fixture
make_all_gpios
make_complete_legacy_pwm
CHECKED=$((CHECKED + 1))
if run_safety \
    && grep -Fq 'SAFETY: safeoff-verified gpio_cut=verified fan=verified' "$LOGFILE"; then
    pass 'complete stock legacy PWM tuple returns verified success'
else
    fail 'complete stock legacy PWM tuple did not verify'
fi
assert_value "$PWM_ROOT/pwm1/period_ns" 100000
assert_value "$PWM_ROOT/pwm1/duty_ns" 30000
assert_value "$PWM_ROOT/pwm1/run" 1
assert_value "$PWM_ROOT/pwm2/period_ns" 100000
assert_value "$PWM_ROOT/pwm2/duty_ns" 30000
assert_value "$PWM_ROOT/pwm2/run" 1

reset_fixture
make_all_gpios
make_complete_modern_pwm
CHECKED=$((CHECKED + 1))
if run_safety; then
    if grep -Fq 'SAFETY: safeoff-verified gpio_cut=verified fan=verified' "$LOGFILE"; then
        pass 'complete GPIO/PWM fixture returns the exact verified receipt'
    else
        fail 'successful safe-off lacks the exact structured receipt'
    fi
else
    fail 'complete GPIO/PWM fixture returned failure'
fi

for g in 49 60 27 22; do
    assert_value "$GPIO_ROOT/gpio$g/active_low" 1
    assert_value "$GPIO_ROOT/gpio$g/direction_command" low
    assert_value "$GPIO_ROOT/gpio$g/direction" out
    assert_value "$GPIO_ROOT/gpio$g/value" 1
done
assert_value "$GPIO_ROOT/gpio59/active_low" 0
assert_value "$GPIO_ROOT/gpio59/direction_command" low
assert_value "$GPIO_ROOT/gpio59/direction" out
assert_value "$GPIO_ROOT/gpio59/value" 0
for p in "$PWM_ROOT/pwmchip0/pwm1" \
         "$PWM_ROOT/pwmchip2/pwm0"; do
    assert_value "$p/period" 100000
    assert_value "$p/duty_cycle" 30000
    assert_value "$p/enable" 1
done
LOAD_CUT_LINE=$(grep -nF "$GPIO_ROOT/gpio59/direction=low" "$JOURNAL" | head -1 | cut -d: -f1)
FIRST_PWM_LINE=$(grep -nF "$PWM_ROOT/" "$JOURNAL" | head -1 | cut -d: -f1)
if [ -z "$LOAD_CUT_LINE" ] || [ -z "$FIRST_PWM_LINE" ] \
    || [ "$LOAD_CUT_LINE" -ge "$FIRST_PWM_LINE" ]; then
    fail 'write journal does not prove load-cut-before-fan ordering'
fi

# A fake pidof makes live-owner ordering deterministic without relying on host
# processes. Its output is controlled only by the explicit fixture variable.
mkdir -p "$TEST_ROOT/bin"
printf '%s\n' '#!/bin/sh' \
    'if [ -n "${DCENT_TEST_PIDOF_OUTPUT:-}" ]; then' \
    '    printf "%s\\n" "$DCENT_TEST_PIDOF_OUTPUT"' \
    'fi' > "$TEST_ROOT/bin/pidof"
chmod +x "$TEST_ROOT/bin/pidof"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$TEST_ROOT/dcentrald"
chmod +x "$TEST_ROOT/dcentrald"
printf '[daemon]\n' > "$TEST_ROOT/dcentrald.toml"
printf '[daemon]\n' > "$TEST_ROOT/management-only.toml"

reset_fixture
make_all_gpios
make_complete_modern_pwm
printf '1\n' > "$GPIO_ROOT/gpio59/value"
CHECKED=$((CHECKED + 1))
if PATH="$TEST_ROOT/bin:$PATH" \
    DCENT_TEST_PIDOF_OUTPUT=123 \
    DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/bin/pidof" \
    DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    DCENT_TEST_PLATFORM=beaglebone \
    DCENT_TEST_DAEMON="$TEST_ROOT/dcentrald" \
    DCENT_TEST_CONFIG="$TEST_ROOT/dcentrald.toml" \
    DCENT_TEST_MGMT_ONLY_CONFIG="$TEST_ROOT/management-only.toml" \
    DCENT_TEST_COLDBOOT_PROOF_MARKER="$TEST_ROOT/coldboot-proof-absent" \
        sh "$SUPERVISOR" start > "$OUTPUT" 2>&1; then
    fail 'live-owner start refusal returned success'
elif grep -Fq 'SAFETY: safeoff-' "$LOGFILE" 2>/dev/null \
    || [ "$(cat "$GPIO_ROOT/gpio59/value")" != 1 ] \
    || [ -e "$GPIO_ROOT/gpio59/direction_command" ]; then
    fail 'live-owner refusal touched hardware safety state'
else
    pass 'live-owner refusal precedes and suppresses all hardware writes'
fi

reset_fixture
make_all_gpios
make_complete_modern_pwm
expect_start_failure_after_cut 'missing daemon admission' \
    "$TEST_ROOT/missing-dcentrald" "$TEST_ROOT/dcentrald.toml" "$TEST_ROOT/management-only.toml"

reset_fixture
make_all_gpios
make_complete_modern_pwm
expect_start_failure_after_cut 'missing primary config admission' \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/missing.toml" "$TEST_ROOT/management-only.toml"

reset_fixture
make_all_gpios
make_complete_modern_pwm
expect_start_failure_after_cut 'missing management-only config admission' \
    "$TEST_ROOT/dcentrald" "$TEST_ROOT/dcentrald.toml" "$TEST_ROOT/missing-management.toml"

reset_fixture
make_all_gpios
CHECKED=$((CHECKED + 1))
if PATH="$TEST_ROOT/bin:$PATH" \
    DCENT_TEST_PIDOF_OUTPUT= \
    DCENT_TEST_PIDOF_COMMAND="$TEST_ROOT/bin/pidof" \
    DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    DCENT_TEST_PLATFORM=beaglebone \
    DCENT_TEST_DAEMON="$TEST_ROOT/dcentrald" \
    DCENT_TEST_CONFIG="$TEST_ROOT/dcentrald.toml" \
    DCENT_TEST_MGMT_ONLY_CONFIG="$TEST_ROOT/management-only.toml" \
    DCENT_TEST_COLDBOOT_PROOF_MARKER="$TEST_ROOT/coldboot-proof-absent" \
    DCENT_TEST_CREATE_PROOF_AFTER_SAFEOFF=1 \
        sh "$SUPERVISOR" start > "$OUTPUT" 2>&1; then
    fail 'management-only degraded auxiliary fixture unexpectedly started'
elif grep -Fq 'Persistent session or exact-process identity helper is missing' "$OUTPUT" \
    && grep -Fq 'MANAGEMENT-ONLY until cold-boot proof' "$OUTPUT" \
    && grep -Fq 'management-only-prestart load_cut=verified auxiliary=degraded' "$LOGFILE"; then
    pass 'degraded admission snapshots management-only posture despite a later proof marker'
else
    fail 'management-only degraded path did not advance past safe hardware admission'
fi

# The stop contract retains a compatibility path for a legacy two-field
# PID/start-tick identity. Current supervisors publish session/boot binding too.
# A real executable fixture proves it cannot report success until that exact
# owner has stopped executing; no raw wrapper PID is involved.
reset_fixture
make_all_gpios
make_complete_modern_pwm
cp /bin/sleep "$TEST_ROOT/dcentrald"
chmod +x "$TEST_ROOT/dcentrald"
"$TEST_ROOT/dcentrald" 60 &
STOP_CHILD_PID=$!
STOP_CHILD_TICKS=$(awk '{print $22}' "/proc/$STOP_CHILD_PID/stat")
printf '%s %s\n' "$STOP_CHILD_PID" "$STOP_CHILD_TICKS" > "$TEST_ROOT/child.pid"
CHECKED=$((CHECKED + 1))
if DCENT_TEST_ONLY_SYSFS_ROOTS=1 \
    DCENT_TEST_GPIO_SYSFS_ROOT="$GPIO_ROOT" \
    DCENT_TEST_PWM_SYSFS_ROOT="$PWM_ROOT" \
    DCENT_TEST_LOGFILE="$LOGFILE" \
    DCENT_TEST_WRITE_JOURNAL="$JOURNAL" \
    DCENT_TEST_BOARD_TARGET=am3-bb-s19jpro \
    DCENT_TEST_DAEMON="$TEST_ROOT/dcentrald" \
    DCENT_TEST_PROCESS_IDENTITY_HELPER="$IDENTITY_HELPER" \
    DCENT_TEST_PIDFILE="$TEST_ROOT/wrapper.pid" \
    DCENT_TEST_CHILD_PIDFILE="$TEST_ROOT/child.pid" \
    DCENT_TEST_EXPECTFILE="$TEST_ROOT/expected.pid" \
    PLATFORM=beaglebone \
        sh "$SUPERVISOR" stop > "$OUTPUT" 2>&1; then
    if kill -0 "$STOP_CHILD_PID" 2>/dev/null \
        && [ "$(awk '{print $3}' "/proc/$STOP_CHILD_PID/stat" 2>/dev/null)" != Z ]; then
        fail 'stop returned success while the verified child remained executable'
    else
        pass 'stop parses a legacy exact identity and observes owner death before safe-off'
    fi
else
    fail 'verified legacy exact-identity stop fixture returned failure'
fi
wait "$STOP_CHILD_PID" 2>/dev/null || true

# Exercise the real safety script through the post-exit session-latch path. The
# helper self-test inspects its crash marker reason, proving success omits and
# failure appends the stable safeoff-failed suffix.
reset_fixture
make_all_gpios
make_complete_modern_pwm
CHECKED=$((CHECKED + 1))
if run_helper_self_test success; then
    pass 'session latch accepts the real verified command/readback receipt'
else
    fail 'session latch did not propagate real safe-off success'
fi

reset_fixture
make_all_gpios
CHECKED=$((CHECKED + 1))
if run_helper_self_test failure; then
    pass 'session latch records the real safeoff-failed crash reason'
else
    fail 'session latch did not propagate real safe-off failure'
fi

reset_fixture
make_all_gpios
make_complete_modern_pwm
CHECKED=$((CHECKED + 1))
if run_boot_setup \
    && grep -Fq '[OK] AM335x BB boot-safe command/readback verified' "$OUTPUT"; then
    pass 'S37 delegates to the checked custodian and reports verified boot state'
else
    fail 'S37 checked boot-safe success path failed'
fi
assert_value "$PWM_ROOT/pwmchip0/pwm1/duty_cycle" 10000
assert_value "$PWM_ROOT/pwmchip2/pwm0/duty_cycle" 10000

reset_fixture
make_all_gpios
CHECKED=$((CHECKED + 1))
if run_boot_setup; then
    fail 'S37 returned success with missing PWM evidence'
elif grep -Fq '[OK]' "$OUTPUT"; then
    fail 'S37 printed a false OK after custodian failure'
else
    pass 'S37 propagates incomplete boot-safe state without a false OK'
fi

if [ "$FAILURES" -ne 0 ]; then
    printf 'AM3-BB emergency safe-off contract failed: %s failure(s), %s case(s)\n' \
        "$FAILURES" "$CHECKED" >&2
    exit 1
fi

printf 'AM3-BB emergency safe-off contract passed across %s behavioral cases.\n' "$CHECKED"
