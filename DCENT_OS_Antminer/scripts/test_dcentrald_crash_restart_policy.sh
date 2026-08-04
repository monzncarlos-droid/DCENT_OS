#!/bin/sh
# Offline contract for persistent dcentrald hardware-session admission.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BOARD_DIR="$PROJECT_DIR/br2_external_dcentos/board"
CONFIG_DIR="$PROJECT_DIR/br2_external_dcentos/configs"
HELPER="$BOARD_DIR/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
DEPLOY_LOCK_SOURCE="$PROJECT_DIR/br2_external_dcentos/packages/dcentos-deploy-lock/src/dcentos-deploy-lock.c"
DAEMON_MAIN_SOURCE="$PROJECT_DIR/dcentrald/dcentrald/src/main.rs"
IDENTITY_HELPER="$BOARD_DIR/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-process-identity.sh"
FAN_CUSTODY_HELPER="$BOARD_DIR/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-fan-custody.sh"
IDENTITY_TEST="$SCRIPT_DIR/test_dcentrald_process_identity.sh"
AM3_BB_SAFEOFF_TEST="$SCRIPT_DIR/test_am3_bb_emergency_safeoff.sh"
ZYNQ_SAFEOFF_TEST="$SCRIPT_DIR/test_zynq_terminal_safety.sh"
FAILURES=0
CHECKED=0
CONFIGS_CHECKED=0
SYSUPGRADES_CHECKED=0
SYSUPGRADE_SIGNAL_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcent-sysupgrade-signal.XXXXXX") || exit 1
SYSUPGRADE_SIGNAL_SHELLS=sh
BUSYBOX_SIGNAL_SHELL_STATUS=missing
if command -v busybox >/dev/null 2>&1; then
    ln -s "$(command -v busybox)" "$SYSUPGRADE_SIGNAL_ROOT/ash" || exit 1
    if "$SYSUPGRADE_SIGNAL_ROOT/ash" -c ':' 2>/dev/null; then
        SYSUPGRADE_SIGNAL_SHELLS="sh
$SYSUPGRADE_SIGNAL_ROOT/ash"
        BUSYBOX_SIGNAL_SHELL_STATUS=ready
    else
        rm -f "$SYSUPGRADE_SIGNAL_ROOT/ash"
    fi
fi
trap 'rm -rf "$SYSUPGRADE_SIGNAL_ROOT"' 0
trap 'exit 1' 1 2 15

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    printf 'PASS: %s\n' "$*"
}

[ "$BUSYBOX_SIGNAL_SHELL_STATUS" = ready ] \
    || fail 'BusyBox ash is required for target-shell sysupgrade signal coverage'

if [ ! -f "$HELPER" ]; then
    fail 'canonical hardware-session latch helper is missing'
elif ! sh -n "$HELPER"; then
    fail 'canonical hardware-session latch helper is not POSIX-shell parseable'
else
    pass 'canonical hardware-session latch helper is POSIX-shell parseable'
    if sh "$HELPER" self-test; then
        pass 'session-latch transition and persistence fixtures pass'
    else
        fail 'session-latch transition or persistence fixture failed'
    fi
    pdeath_start=$(grep -n '^static int exec_with_parent_death_signal' \
        "$DEPLOY_LOCK_SOURCE" | head -n 1 | cut -d: -f1)
    pdeath_end=$(awk -v start="$pdeath_start" \
        'NR > start && /^}/ { print NR; exit }' "$DEPLOY_LOCK_SOURCE")
    pdeath_reset=$(awk -v start="$pdeath_start" -v end="$pdeath_end" \
        'NR > start && NR < end && /reset_child_signal_handlers\(\) != 0/ { print NR; exit }' \
        "$DEPLOY_LOCK_SOURCE")
    pdeath_unblock=$(awk -v start="$pdeath_start" -v end="$pdeath_end" \
        'NR > start && NR < end && /unblock_child_signals\(\) != 0/ { print NR; exit }' \
        "$DEPLOY_LOCK_SOURCE")
    pdeath_arm=$(awk -v start="$pdeath_start" -v end="$pdeath_end" \
        'NR > start && NR < end && /prctl\(PR_SET_PDEATHSIG, SIGKILL\) != 0/ { print NR; exit }' \
        "$DEPLOY_LOCK_SOURCE")
    pdeath_parent_pre=$(awk -v start="$pdeath_start" -v end="$pdeath_end" \
        'NR > start && NR < end && /getppid\(\) != expected_parent/ { print NR; exit }' \
        "$DEPLOY_LOCK_SOURCE")
    pdeath_parent_post=$(awk -v start="$pdeath_start" -v end="$pdeath_end" \
        'NR > start && NR < end && /getppid\(\) != expected_parent/ { count++; if (count == 2) { print NR; exit } }' \
        "$DEPLOY_LOCK_SOURCE")
    if grep -Fq 'PARENT_DEATH_HELPER=/usr/libexec/dcentos/dcentos-deploy-lock' "$HELPER" \
        && grep -Fq '"$SUPERVISOR_PID" -- "$@"' "$HELPER" \
        && [ -n "$pdeath_start" ] && [ -n "$pdeath_end" ] \
        && [ -n "$pdeath_reset" ] && [ -n "$pdeath_unblock" ] \
        && [ -n "$pdeath_arm" ] && [ -n "$pdeath_parent_pre" ] \
        && [ -n "$pdeath_parent_post" ] \
        && [ "$pdeath_parent_pre" -le "$pdeath_reset" ] \
        && [ "$pdeath_reset" -lt "$pdeath_unblock" ] \
        && [ "$pdeath_unblock" -lt "$pdeath_arm" ] \
        && [ "$pdeath_arm" -lt "$pdeath_parent_post" ]; then
        pass 'canonical session latch arms non-maskable kernel supervisor-loss containment'
    else
        fail 'canonical session latch does not arm and bracket the compiled supervisor-loss boundary'
    fi
fi

run_main_start=$(grep -nF 'async fn run_main() -> Result<()> {' \
    "$DAEMON_MAIN_SOURCE" | head -n 1 | cut -d: -f1)
sigint_registration=$(awk -v start="$run_main_start" \
    'NR > start && /signal::unix::signal\(signal::unix::SignalKind::interrupt\(\)\)/ { print NR; exit }' \
    "$DAEMON_MAIN_SOURCE")
sigterm_registration=$(awk -v start="$run_main_start" \
    'NR > start && /signal::unix::signal\(signal::unix::SignalKind::terminate\(\)\)/ { print NR; exit }' \
    "$DAEMON_MAIN_SOURCE")
signal_handler_spawn=$(awk -v start="$sigterm_registration" \
    'NR > start && /tokio::spawn\(async move/ { print NR; exit }' "$DAEMON_MAIN_SOURCE")
signal_handler_end=$(awk -v start="$signal_handler_spawn" \
    'NR > start && /^    \}\);/ { print NR; exit }' "$DAEMON_MAIN_SOURCE")
sigint_recv=$(awk -v start="$signal_handler_spawn" -v end="$signal_handler_end" \
    'NR > start && NR < end && /sigint\.recv\(\)/ { print NR; exit }' "$DAEMON_MAIN_SOURCE")
sigterm_recv=$(awk -v start="$signal_handler_spawn" -v end="$signal_handler_end" \
    'NR > start && NR < end && /sigterm\.recv\(\)/ { print NR; exit }' "$DAEMON_MAIN_SOURCE")
signal_cancel=$(awk -v start="$signal_handler_spawn" -v end="$signal_handler_end" \
    'NR > start && NR < end && /shutdown_token_signal\.cancel\(\)/ { print NR; exit }' \
    "$DAEMON_MAIN_SOURCE")
hardware_route=$(awk -v start="$run_main_start" \
    'NR > start && /(S19jTapMiner|S19jHybridMiner|SerialMiner|StockMiner|Daemon)::new\(/ { print NR; exit }' \
    "$DAEMON_MAIN_SOURCE")
runtime_route_admission=$(grep -nF 'let runtime_dispatch = selected_runtime_dispatch(' \
    "$DAEMON_MAIN_SOURCE")
runtime_route_admission=${runtime_route_admission%%:*}
case "$run_main_start:$sigint_registration:$sigterm_registration:$signal_handler_spawn:$signal_handler_end:$sigint_recv:$sigterm_recv:$signal_cancel:$hardware_route" in
    :*|*::*|*:) fail 'daemon signal-registration, handler-task, or hardware-route anchor is missing' ;;
    *)
        if [ "$sigint_registration" -lt "$signal_handler_spawn" ] \
            && [ "$sigterm_registration" -lt "$signal_handler_spawn" ] \
            && [ "$signal_handler_spawn" -lt "$sigint_recv" ] \
            && [ "$signal_handler_spawn" -lt "$sigterm_recv" ] \
            && [ "$sigint_recv" -lt "$signal_handler_end" ] \
            && [ "$sigterm_recv" -lt "$signal_handler_end" ] \
            && [ "$sigint_recv" -lt "$signal_cancel" ] \
            && [ "$sigterm_recv" -lt "$signal_cancel" ] \
            && [ "$signal_cancel" -lt "$signal_handler_end" ] \
            && [ -n "$runtime_route_admission" ] \
            && [ "$signal_handler_end" -lt "$runtime_route_admission" ] \
            && [ "$signal_handler_end" -lt "$hardware_route" ] \
            && [ "$signal_handler_spawn" -lt "$hardware_route" ]; then
            pass 'SIGINT/SIGTERM ownership is established before hardware-route construction'
        else
            fail 'graceful shutdown signal ownership can race hardware initialization'
        fi
        ;;
esac

if [ ! -f "$ZYNQ_SAFEOFF_TEST" ]; then
    fail 'Zynq terminal-safety behavioral test is missing'
elif sh "$ZYNQ_SAFEOFF_TEST"; then
    pass 'Zynq terminal safety preserves power-cut and fan-custody failures'
else
    fail 'Zynq terminal-safety behavioral contract failed'
fi

if [ ! -f "$FAN_CUSTODY_HELPER" ]; then
    fail 'shared typed fan-custody helper is missing'
elif ! sh -n "$FAN_CUSTODY_HELPER"; then
    fail 'shared typed fan-custody helper is not POSIX-shell parseable'
else
    grep -Fq 'ln "$DCENT_FAN_PUBLISH_CANDIDATE" "$DCENT_FAN_PUBLISH_PATH"' \
        "$FAN_CUSTODY_HELPER" \
        || fail 'fan-custody lock publication can expose an ownerless transition'
    grep -Fq 'fan-custody-recovery' "$FAN_CUSTODY_HELPER" \
        || fail 'stale fan-lock deletion lacks a serialized recovery authority'
    grep -Fq 'END { exit !(NR == 3 && hold && pwm) }' "$FAN_CUSTODY_HELPER" \
        || fail 'production pending custody is not bound to the exact hold-fan argv role'
    grep -Fq 'fan-custodian-pending' "$FAN_CUSTODY_HELPER" \
        || fail 'fan custody lacks a typed pending-launch identity'
    grep -Fq 'Refusing fan-custodian launch while any dcentrald role may execute' \
        "$FAN_CUSTODY_HELPER" \
        || fail 'fan custody can launch beside another live dcentrald role'
    pass 'fan custody uses exact roles and atomically published typed transition locks'
fi

if [ ! -f "$IDENTITY_HELPER" ] || [ ! -f "$IDENTITY_TEST" ]; then
    fail 'shared exact-process identity library or behavioral test is missing'
elif sh "$IDENTITY_TEST"; then
    pass 'typed session/boot custody and legacy exact-process shutdown behavior pass'
else
    fail 'exact-process identity behavioral contract failed'
fi
grep -Fq 'DCENT_PROCESS_IDENTITY_TEST_AUTHORITY' "$IDENTITY_HELPER" \
    || fail 'injected pidof command is not gated by internal supervisor authority'

if [ ! -f "$AM3_BB_SAFEOFF_TEST" ]; then
    fail 'AM3-BB emergency safe-off behavioral test is missing'
elif sh "$AM3_BB_SAFEOFF_TEST"; then
    pass 'AM3-BB emergency safe-off propagates verified GPIO/PWM outcomes'
else
    fail 'AM3-BB emergency safe-off behavioral contract failed'
fi

if [ -f "$HELPER" ]; then
    grep -Fq 'No process exit status is accepted as a physical SafeOff receipt' "$HELPER" \
        || fail 'helper does not state that process exit is not physical disposition evidence'
    grep -Fq 'mkdir "$LOCK_DIR"' "$HELPER" \
        || fail 'helper lacks atomic cross-process admission serialization'
    grep -Fq 'sync_state' "$HELPER" \
        || fail 'helper lacks a persistence barrier'
    grep -Fq 'expected-zero-awaiting-typed-disposition' "$HELPER" \
        || fail 'helper does not retain expected zero exits as unresolved'
    grep -Fq 'admit_update_window()' "$HELPER" \
        || fail 'helper lacks serialized manual-resolution update admission'
    grep -Fq 'update_transaction_is_absent || return 1' "$HELPER" \
        || fail 'daemon admission does not refuse an active update transaction'
    if grep -Eq '^[[:space:]]*clean\)|mark_session_clean' "$HELPER"; then
        fail 'helper exposes exit-status-based session clearing'
    else
        pass 'helper exposes no exit-status-based session clearing'
    fi
fi

OLD_IFS_SYSUPGRADE=$IFS
IFS='
'
for sysupgrade in $(find "$BOARD_DIR/zynq" -type f -path '*/usr/sbin/sysupgrade' 2>/dev/null | sort); do
    SYSUPGRADES_CHECKED=$((SYSUPGRADES_CHECKED + 1))
    relative=${sysupgrade#"$PROJECT_DIR"/}
    sh -n "$sysupgrade" \
        || fail "$relative is not POSIX-shell parseable"
    grep -Fq 'SESSION_LATCH_HELPER="/usr/libexec/dcentos/dcentrald-session-latch.sh"' "$sysupgrade" \
        || fail "$relative does not bind hardware-session update admission"
    grep -Fq 'SYSUPGRADE_UPDATE_LOCK="/run/dcentos-sysupgrade.lock"' "$sysupgrade" \
        || fail "$relative does not publish the canonical update transaction"
    grep -Fq 'release_pre_mutation_update_lock()' "$sysupgrade" \
        || fail "$relative cannot retire a pre-mutation update transaction"
    grep -Fq 'release_pre_mutation_update_lock' "$sysupgrade" \
        || fail "$relative package cleanup omits pre-mutation update-lock retirement"
    grep -Fq 'trap cleanup_package EXIT' "$sysupgrade" \
        && grep -Fq "trap 'terminate_sysupgrade 130' INT" "$sysupgrade" \
        && grep -Fq "trap 'terminate_sysupgrade 143' TERM" "$sysupgrade" \
        || fail "$relative does not terminate explicitly on INT/TERM"
    function_fixture="$SYSUPGRADE_SIGNAL_ROOT/functions.$SYSUPGRADES_CHECKED"
    awk '
        /^release_pre_mutation_update_lock\(\)/ { copying = 1 }
        /^manifest_field\(\)/ { copying = 0 }
        copying { print }
    ' "$sysupgrade" >"$function_fixture"
    for signal_fixture_shell in $SYSUPGRADE_SIGNAL_SHELLS; do
    signal_shell_label=$(basename "$signal_fixture_shell")
    pre_root="$SYSUPGRADE_SIGNAL_ROOT/pre.$SYSUPGRADES_CHECKED.$signal_shell_label"
    post_root="$SYSUPGRADE_SIGNAL_ROOT/post.$SYSUPGRADES_CHECKED.$signal_shell_label"
    int_root="$SYSUPGRADE_SIGNAL_ROOT/int.$SYSUPGRADES_CHECKED.$signal_shell_label"
    kill_root="$SYSUPGRADE_SIGNAL_ROOT/kill.$SYSUPGRADES_CHECKED.$signal_shell_label"
    mkdir "$pre_root" "$post_root" "$int_root" "$kill_root" \
        "$pre_root/package" "$pre_root/update-lock" \
        "$post_root/package" "$post_root/update-lock" \
        "$int_root/package" "$int_root/update-lock" \
        "$kill_root/package" "$kill_root/update-lock"
    "$signal_fixture_shell" -c '
        . "$1"
        PACKAGE_DIR=$2
        SYSUPGRADE_UPDATE_LOCK=$3
        SYSUPGRADE_UPDATE_LOCK_OWNED=1
        SYSUPGRADE_MUTATION_STARTED=0
        trap cleanup_package EXIT
        trap "terminate_sysupgrade 130" INT
        trap "terminate_sysupgrade 143" TERM
        kill -TERM $$
        : >"$4"
    ' sh "$function_fixture" "$pre_root/package" "$pre_root/update-lock" \
        "$pre_root/resumed"
    pre_status=$?
    if [ "$pre_status" -eq 143 ] \
       && [ ! -e "$pre_root/update-lock" ] \
       && [ ! -e "$pre_root/package" ] \
       && [ ! -e "$pre_root/resumed" ]; then
        pass "$relative TERM exits and retires only its pre-mutation update lock under $signal_shell_label"
    else
        fail "$relative TERM can resume or retain invalid pre-mutation state"
    fi
    "$signal_fixture_shell" -c '
        . "$1"
        PACKAGE_DIR=$2
        SYSUPGRADE_UPDATE_LOCK=$3
        SYSUPGRADE_UPDATE_LOCK_OWNED=1
        SYSUPGRADE_MUTATION_STARTED=1
        trap cleanup_package EXIT
        trap "terminate_sysupgrade 130" INT
        trap "terminate_sysupgrade 143" TERM
        kill -TERM $$
        : >"$4"
    ' sh "$function_fixture" "$post_root/package" "$post_root/update-lock" \
        "$post_root/resumed"
    post_status=$?
    if [ "$post_status" -eq 143 ] \
       && [ -d "$post_root/update-lock" ] \
       && [ ! -e "$post_root/package" ] \
       && [ ! -e "$post_root/resumed" ]; then
        pass "$relative TERM exits and retains its post-mutation update lock under $signal_shell_label"
    else
        fail "$relative TERM can resume or release post-mutation admission evidence"
    fi
    "$signal_fixture_shell" -c '
        . "$1"
        PACKAGE_DIR=$2
        SYSUPGRADE_UPDATE_LOCK=$3
        SYSUPGRADE_UPDATE_LOCK_OWNED=1
        SYSUPGRADE_MUTATION_STARTED=0
        trap cleanup_package EXIT
        trap "terminate_sysupgrade 130" INT
        trap "terminate_sysupgrade 143" TERM
        kill -INT $$
        : >"$4"
    ' sh "$function_fixture" "$int_root/package" "$int_root/update-lock" \
        "$int_root/resumed"
    int_status=$?
    if [ "$int_status" -eq 130 ] \
       && [ ! -e "$int_root/update-lock" ] \
       && [ ! -e "$int_root/package" ] \
       && [ ! -e "$int_root/resumed" ]; then
        pass "$relative INT exits 130 without resuming into mutation under $signal_shell_label"
    else
        fail "$relative INT can resume or retain invalid pre-mutation state"
    fi
    "$signal_fixture_shell" -c '
        . "$1"
        PACKAGE_DIR=$2
        SYSUPGRADE_UPDATE_LOCK=$3
        SYSUPGRADE_UPDATE_LOCK_OWNED=1
        SYSUPGRADE_MUTATION_STARTED=0
        trap cleanup_package EXIT
        trap "terminate_sysupgrade 130" INT
        trap "terminate_sysupgrade 143" TERM
        : >"$4"
        while :; do sleep 1; done
        : >"$5"
    ' sh "$function_fixture" "$kill_root/package" "$kill_root/update-lock" \
        "$kill_root/ready" "$kill_root/resumed" &
    kill_fixture_pid=$!
    kill_ready=0
    kill_wait_attempt=0
    while [ "$kill_wait_attempt" -lt 500 ]; do
        if [ -e "$kill_root/ready" ]; then
            kill_ready=1
            break
        fi
        kill -0 "$kill_fixture_pid" 2>/dev/null || break
        kill_wait_attempt=$((kill_wait_attempt + 1))
        sleep 0.01
    done
    if [ "$kill_ready" -eq 1 ]; then
        kill -KILL "$kill_fixture_pid"
        wait "$kill_fixture_pid" 2>/dev/null
        kill_status=$?
    else
        kill -KILL "$kill_fixture_pid" 2>/dev/null || true
        wait "$kill_fixture_pid" 2>/dev/null || true
        kill_status=0
        fail "$relative SIGKILL fixture failed to reach bounded readiness under $signal_shell_label"
    fi
    if [ "$kill_status" -eq 137 ] \
       && [ -d "$kill_root/update-lock" ] \
       && [ -d "$kill_root/package" ] \
       && [ ! -e "$kill_root/resumed" ]; then
        pass "$relative SIGKILL retains fail-closed update evidence under $signal_shell_label"
    else
        fail "$relative SIGKILL did not preserve fail-closed update evidence"
    fi
    rm -f "$kill_root/ready"
    rmdir "$post_root/update-lock" "$kill_root/update-lock" \
        "$kill_root/package" "$pre_root" "$post_root" "$int_root" \
        "$kill_root" 2>/dev/null || true
    done
    ADMIT_LINE=$(grep -n '"$SESSION_LATCH_HELPER" admit-update' "$sysupgrade" | head -n 1 | cut -d: -f1)
    STEP_LINE=$(grep -n '^# --- Step 1:' "$sysupgrade" | head -n 1 | cut -d: -f1)
    MUTATION_MARK_LINE=$(grep -n '^[[:space:]]*SYSUPGRADE_MUTATION_STARTED=1' "$sysupgrade" | head -n 1 | cut -d: -f1)
    FIRST_NAND_WRITE_LINE=$(grep -En '^[[:space:]]*if ! (ubimkvol|ubiupdatevol)' "$sysupgrade" | head -n 1 | cut -d: -f1)
    INT_TRAP_LINE=$(grep -nF "trap 'terminate_sysupgrade 130' INT" "$sysupgrade" | head -n 1 | cut -d: -f1)
    TERM_TRAP_LINE=$(grep -nF "trap 'terminate_sysupgrade 143' TERM" "$sysupgrade" | head -n 1 | cut -d: -f1)
    if [ -n "$ADMIT_LINE" ] && [ -n "$STEP_LINE" ] \
       && [ "$ADMIT_LINE" -lt "$STEP_LINE" ]; then
        pass "$relative admits hardware-session disposition before inactive-slot access"
    else
        fail "$relative reaches inactive-slot access before hardware-session admission"
    fi
    if [ -n "$MUTATION_MARK_LINE" ] && [ -n "$FIRST_NAND_WRITE_LINE" ] \
       && [ "$MUTATION_MARK_LINE" -lt "$FIRST_NAND_WRITE_LINE" ]; then
        pass "$relative retains its update lock from the first NAND mutation"
    else
        fail "$relative can mutate NAND while its update lock is cleanup-eligible"
    fi
    if [ -n "$INT_TRAP_LINE" ] && [ -n "$TERM_TRAP_LINE" ] \
       && [ -n "$MUTATION_MARK_LINE" ] && [ -n "$FIRST_NAND_WRITE_LINE" ] \
       && [ "$INT_TRAP_LINE" -lt "$MUTATION_MARK_LINE" ] \
       && [ "$TERM_TRAP_LINE" -lt "$MUTATION_MARK_LINE" ] \
       && [ "$INT_TRAP_LINE" -lt "$FIRST_NAND_WRITE_LINE" ] \
       && [ "$TERM_TRAP_LINE" -lt "$FIRST_NAND_WRITE_LINE" ]; then
        pass "$relative owns INT/TERM before mutation admission and NAND writes"
    else
        fail "$relative can reach mutation before production INT/TERM traps are installed"
    fi
done
IFS=$OLD_IFS_SYSUPGRADE

for defconfig in "$CONFIG_DIR"/*_defconfig; do
    [ -f "$defconfig" ] || continue
    if ! grep -q '^BR2_ROOTFS_OVERLAY=' "$defconfig"; then
        continue
    fi
    CONFIGS_CHECKED=$((CONFIGS_CHECKED + 1))
    relative=${defconfig#"$PROJECT_DIR"/}
    if grep -Fq 'BR2_ROOTFS_OVERLAY="$(BR2_EXTERNAL_DCENTOS_PATH)/board/common/rootfs-overlay ' "$defconfig" \
        || grep -Fq 'BR2_ROOTFS_OVERLAY="$(BR2_EXTERNAL_DCENTOS_PATH)/board/common/rootfs-overlay"' "$defconfig"; then
        pass "$relative installs the canonical common overlay first"
    else
        fail "$relative does not install the canonical common overlay first"
    fi
done

OLD_IFS=$IFS
IFS='
'
for supervisor in $(find "$BOARD_DIR" -type f -name S82dcentrald 2>/dev/null | sort); do
    CHECKED=$((CHECKED + 1))
    relative=${supervisor#"$PROJECT_DIR"/}

    if sh -n "$supervisor"; then
        pass "$relative is POSIX-shell parseable"
    else
        fail "$relative is not POSIX-shell parseable"
    fi

    if grep -Eq 'MAX_CRASH_RESTARTS|RESTART_DELAY|CRASH_COUNT' "$supervisor"; then
        fail "$relative retains automatic crash-restart state"
    else
        pass "$relative has no automatic crash-restart state"
    fi

    if grep -Eq 'ORPHAN_PIDS|Killing orphaned|dcentrald exited cleanly|automatic restart disabled' "$supervisor"; then
        fail "$relative retains kill-and-replace or exit-status disposition logic"
    else
        pass "$relative has no kill-and-replace or exit-status disposition logic"
    fi

    # Some targets deliberately retain the historical init filename only as a
    # typed negative capability. They never acquire hardware ownership, create
    # a daemon log, or publish a process supervisor, so admission/latch rules
    # for an activating S82 do not apply.
    if grep -Fxq 'DCENT_RUNTIME_OWNER_POLICY=not-implemented-refusal' "$supervisor"; then
        grep -Fq 'runtime hardware ownership NOT IMPLEMENTED; daemon start refused' "$supervisor" \
            || fail "$relative marks refusal policy without the canonical operator-visible refusal"
        if grep -Fq 'SESSION_LATCH_HELPER=' "$supervisor" \
            || grep -Eq '^[[:space:]]*(exec[[:space:]]+)?(/usr/local/bin/)?dcentrald([[:space:]]|$)' "$supervisor"; then
            fail "$relative refusal policy can still bind or launch a hardware-owner supervisor"
        else
            pass "$relative is a typed non-activating runtime-owner refusal"
        fi
        continue
    fi

    grep -Fq 'EXPECTFILE="/var/run/dcentrald.expected_exit.pid"' "$supervisor" \
        || fail "$relative keeps expected-exit state outside protected runtime storage"
    grep -Fq 'SESSION_LATCH_HELPER="/usr/libexec/dcentos/dcentrald-session-latch.sh"' "$supervisor" \
        || fail "$relative does not bind the canonical session-latch helper"
    if grep -Fq 'PROCESS_IDENTITY_HELPER=' "$supervisor"; then
        grep -Fq 'readonly DCENT_PROCESS_IDENTITY_TEST_AUTHORITY' "$supervisor" \
            || fail "$relative lets environment grant common process-test authority"
    fi
    grep -Fq 'SESSION_TOKEN=$(/bin/sh "$SESSION_LATCH_HELPER" prepare' "$supervisor" \
        || fail "$relative does not synchronously prepare persistent admission"
    grep -Fq '"$SESSION_LATCH_HELPER" supervise "$SESSION_TOKEN"' "$supervisor" \
        || fail "$relative does not pass the serialized admission token to the common supervisor"
    grep -Fq '"$SESSION_LATCH_HELPER" abandon "$SESSION_TOKEN" supervisor-launch-failed' "$supervisor" \
        || fail "$relative does not latch failed supervisor publication"
    if ! grep -Fq '"$SESSION_LATCH_HELPER" latch forced-stop-timeout' "$supervisor" \
        && ! grep -Fq 'dcent_stop_managed_session' "$supervisor"; then
        fail "$relative does not persist forced-stop disposition through a typed stop path"
    fi
    if grep -Eq 'CHILD_PID=\$\(cat .*CHILD_PIDFILE' "$supervisor"; then
        fail "$relative consumes the structured child identity as an unparsed PID"
    fi
    if grep -Eq 'kill (-TERM|-9) "?\$WRAPPER_PID' "$supervisor"; then
        fail "$relative signals a wrapper without a persisted start-time identity"
    fi
    case "$relative" in
        br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald)
            grep -Fq 'restart is refused before stop' "$supervisor" \
                || fail "$relative can stop a healthy owner before refusing unsafe readmission"
            ;;
        *)
            grep -Fq '"$0" stop || exit $?' "$supervisor" \
                || fail "$relative restart does not propagate stop failure"
            grep -Fq 'exec "$0" start' "$supervisor" \
                || fail "$relative restart does not propagate start refusal"
            ;;
    esac

    RUNNING_LINE=$(grep -En 'RUNNING_PIDS=.*(pidof|PIDOF_COMMAND).*dcentrald' "$supervisor" | head -n 1 | cut -d: -f1)
    PREPARE_LINE=$(grep -n 'SESSION_TOKEN=$(/bin/sh "$SESSION_LATCH_HELPER" prepare' "$supervisor" | head -n 1 | cut -d: -f1)
    SUPERVISE_LINE=$(grep -n '"$SESSION_LATCH_HELPER" supervise "$SESSION_TOKEN"' "$supervisor" | head -n 1 | cut -d: -f1)
    if [ -n "$RUNNING_LINE" ] && [ -n "$PREPARE_LINE" ] && [ -n "$SUPERVISE_LINE" ] \
        && [ "$RUNNING_LINE" -lt "$PREPARE_LINE" ] && [ "$PREPARE_LINE" -lt "$SUPERVISE_LINE" ]; then
        pass "$relative refuses a live owner, persists admission, then publishes the supervisor"
    else
        fail "$relative admission ordering is not live-owner -> persistent marker -> supervisor"
    fi

    if grep -Fq 'FANHOLD_PIDFILE=' "$supervisor"; then
        grep -Fq 'FANHOLD_READYFILE="/var/run/dcentrald-fanhold.ready"' "$supervisor" \
            || fail "$relative lacks the canonical resident fan readiness receipt"
        grep -Fq 'FAN_CUSTODY_HELPER="/usr/libexec/dcentos/dcentrald-fan-custody.sh"' "$supervisor" \
            || fail "$relative does not bind shared exact fan custody"
        grep -Fq 'dcent_fan_custodian_start' "$supervisor" \
            || fail "$relative accepts background launch as fan readiness"
        grep -Fq 'readonly DCENT_PROCESS_IDENTITY_TEST_AUTHORITY' "$supervisor" \
            || fail "$relative lets persistent environment grant process-test authority"
        FAN_LOCK_LINE=$(grep -n '^[[:space:]]*dcent_acquire_fan_transition_lock || {' "$supervisor" | head -n 1 | cut -d: -f1)
        FAN_STOP_LINE=$(grep -n '^[[:space:]]*am2_stop_fan_custodian ||' "$supervisor" | head -n 1 | cut -d: -f1)
        if [ -n "$FAN_LOCK_LINE" ] && [ -n "$FAN_STOP_LINE" ] \
            && [ -n "$RUNNING_LINE" ] \
            && [ "$FAN_LOCK_LINE" -lt "$FAN_STOP_LINE" ] \
            && [ "$FAN_STOP_LINE" -lt "$RUNNING_LINE" ]; then
            pass "$relative serializes exact prior fan custody before broad owner refusal"
        else
            fail "$relative can race or deadlock admission behind resident fan custody"
        fi
    fi
done
IFS=$OLD_IFS

[ "$CONFIGS_CHECKED" -gt 0 ] || fail 'no Buildroot overlay defconfigs were discovered'
[ "$CHECKED" -gt 0 ] || fail 'no shipped S82dcentrald supervisors were discovered'
[ "$SYSUPGRADES_CHECKED" -eq 4 ] \
    || fail "expected 4 Zynq sysupgrade hardware-session callers, found $SYSUPGRADES_CHECKED"

for platform in zynq amlogic; do
    web_root="$BOARD_DIR/$platform/rootfs-overlay/root/web"
    server="$web_root/server.py"
    mcp="$web_root/mcp_server.py"
    recovery="$web_root/static/recovery.html"
    diagnostic="$web_root/static/diagnostic.html"

    grep -Fq 'result = subprocess.run(' "$mcp" \
        || fail "$platform MCP service control is not synchronous"
    grep -Fq '"returncode": result.returncode' "$mcp" \
        || fail "$platform MCP service control does not report the init result"
    if [ "$platform" = amlogic ]; then
        grep -Fq '"status": "manual_resolution_required"' "$server" \
            || fail 'amlogic dashboard does not expose the manual-resolution policy'
        grep -Fq '/etc/init.d/S37board_setup start' "$recovery" \
            || fail 'amlogic recovery does not re-establish the boot-safe baseline'
        if grep -Fq 'Run guarded restart' "$recovery" \
            || grep -Fq 'Run guarded restart' "$diagnostic" \
            || grep -Fq '["/etc/init.d/S82dcentrald", "restart"]' "$server"; then
            fail 'amlogic web recovery advertises or executes forbidden restart'
        fi
    else
        grep -Fq 'result = subprocess.run(' "$server" \
            || fail "$platform dashboard service control is not synchronous"
        grep -Fq 'if result.returncode != 0:' "$server" \
            || fail "$platform dashboard service control does not propagate init refusal"
        grep -Fq '"status": "restart_refused"' "$server" \
            || fail "$platform dashboard service control lacks a stable refusal result"
        grep -Fq 'Run guarded restart' "$recovery" \
            || fail "$platform recovery UI lacks guarded restart control"
        grep -Fq 'Run guarded restart' "$diagnostic" \
            || fail "$platform diagnostic UI lacks guarded restart control"
    fi
done

REST_RS="$PROJECT_DIR/dcentrald/dcentrald-api/src/rest.rs"
REST_LATE_RS="$PROJECT_DIR/dcentrald/dcentrald-api/src/rest/late.rs"
RESTART_RS="$PROJECT_DIR/dcentrald/dcentrald/src/restart.rs"
grep -Fq 'const DAEMON_RESTART_REFUSAL' "$REST_RS" \
    || fail 'in-daemon control planes lack the canonical restart refusal'
grep -Fq 'StatusCode::CONFLICT' "$REST_LATE_RS" \
    || fail 'REST restart does not report a conflict'
grep -Fq 'Automatic daemon restart refused' "$RESTART_RS" \
    || fail 'automatic recovery can still claim to schedule process replacement'
if find "$PROJECT_DIR/dcentrald/dcentrald-api/src" \
        "$PROJECT_DIR/dcentrald/dcentrald-api/tests" -type f \
        -exec grep -Eq 'trigger_daemon_restart|build_daemon_restart_command' {} \; \
        -print | grep -q .; then
    fail 'in-process restart implementation remains reachable'
else
    pass 'REST, gRPC, and CGMiner preserve the live owner and refuse unsafe replacement'
fi

if [ "$FAILURES" -ne 0 ]; then
    printf 'dcentrald persistent admission policy failed: %s failure(s), %s supervisor(s), %s defconfig(s)\n' \
        "$FAILURES" "$CHECKED" "$CONFIGS_CHECKED" >&2
    exit 1
fi

printf 'dcentrald persistent admission policy passed across %s supervisor(s) and %s defconfig(s).\n' \
    "$CHECKED" "$CONFIGS_CHECKED"
