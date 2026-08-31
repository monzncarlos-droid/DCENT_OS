#!/bin/sh
# ONE USE ONLY: retire the exact retained Track-1 custody transaction from the
# 2026-08-20 .88 run after stock recovered under the unchanged Braiins
# run-and-watch supervisor.
#
# This is deliberately not a generic recovery tool.  Every old receipt,
# artifact, process lifetime, argv, pidfile, GPIO baseline, and immutable host
# transcript is hard-bound below.  It performs no signal, watchdog, GPIO,
# UART, service, or persistent-storage operation.  A mismatch retains the
# active receipt and global lock.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

[ "$#" -eq 1 ] && [ "$1" = CLEAR_EXACT_20260820_STOCK_RECOVERED ] || {
    echo 'ERROR: exact one-use confirmation token required' >&2
    exit 2
}

TRIAL_DIR=/tmp/dcentrald_bench_t1_20260820130324_61373
ACTIVE="$TRIAL_DIR/runtime_active"
LOCK=/tmp/dcent-s19k-track1-runtime-lock
OWNER="$LOCK/owner"
BIN="$TRIAL_DIR/dcentrald"
CFG="$TRIAL_DIR/dcentrald_s19k.toml"
RUNNER="$TRIAL_DIR/run_trial"
CUSTODY="$TRIAL_DIR/supervisor_custody_observer"
RUN_EVIDENCE="$TRIAL_DIR/track1-run.evidence.log"
RECOVERY_EVIDENCE="$TRIAL_DIR/post-run-stock-recovery.evidence.log"
CLOSEOUT="$TRIAL_DIR/runtime_stock_recovered_after_dcent_safeoff.1044815"
RETIRED_ACTIVE="$TRIAL_DIR/runtime_active.retired.stock-recovered.1044815"
RETIRED_OWNER="$TRIAL_DIR/runtime_lock_owner.retired.stock-recovered.1044815"

ACTIVE_SHA=6c19d422d8a09004cad5909c3d4c92700715b30a4cd17938beb5241a24885fb3
OWNER_SHA=adb44027d9289a1faa220163053afe01bcb45ad09bbdbb48ee4c428787a76b88
BIN_SHA=0281cdf9e6cf5bce519d0c4fdd3e6500dfe3826abfed5a2c764873f0a9e01d88
BIN_BYTES=23667432
CFG_SHA=814dc35562e6b121b00acfd65c88aec7f1bcd2e293edfd1995c2d4ea26de8dad
CFG_BYTES=1517
RUNNER_SHA=b945c78b682f3cdfed745e79dd4a5e4c720cbadf6a2fbebdc2d5406c5e50f24d
RUNNER_BYTES=42519
CUSTODY_SHA=86645dca6827093d7d367b3cef3e15c0acbecb694d3dfb86fa13d2dcc53352dd
CUSTODY_BYTES=8331
# These are deterministic UTF-8/no-BOM transcodes of the immutable UTF-16LE
# host transcripts.  The text anchors below are therefore checked by the
# target's BusyBox grep without weakening the original evidence to hash-only.
RUN_EVIDENCE_SHA=b91ef6c69aaffcb3beb2f1d45e24388acdb56ee17e86ebaa56fdb0385029d8d2
RUN_EVIDENCE_BYTES=17850
RECOVERY_EVIDENCE_SHA=43d045945a196144d7aa3096e13b198278da80c282607e22da03c3349ad78649
RECOVERY_EVIDENCE_BYTES=9936
IDENTITY_SHA=6312939be8f192e34e38f78c8461169386cf1c60f43f10b970fda935971347c2
IDENTITY_PROFILE=live88_two_bhb56903_slots_2_3

WRAPPER_PID=8760
WRAPPER_START=1043943
DCENT_CHILD_PID=9474
DCENT_CHILD_START=1044497
ORIGINAL_BOSMINER_PID=1472
ORIGINAL_BOSMINER_START=1262
SUPERVISOR_PID=1458
SUPERVISOR_START=1251
SUPERVISOR_PGRP=1457
SUPERVISOR_SESSION=1457
SUPERVISOR_CMDLINE_SHA=2e8273fd19bccb1b1744b2f26f48825aae6de73e55be9919a472d0a953cfac52
SUPERVISOR_CMDLINE_BYTES=68
RECOVERED_CHILD_PID=9495
RECOVERED_CHILD_START=1044815
CHILD_CMDLINE_SHA=465804a74a48655761ec62edfd4e08659b6fcaf7486e475260c1e490f2e9d3d3
CHILD_CMDLINE_BYTES=32
PIDFILE_SHA=4574cce19d396d4f7936ee9604f4d8ac809067746a51c6a6ba40d81a592d336c
PIDFILE_BYTES=5

regular() {
    [ -f "$1" ] && [ ! -L "$1" ]
}

field() {
    FILE=$1
    KEY=$2
    [ "$(grep -c "^$KEY=" "$FILE" 2>/dev/null || true)" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$FILE"
}

verify_file() {
    FILE=$1 EXPECTED_SHA=$2 EXPECTED_BYTES=$3
    regular "$FILE" \
        && [ "$(sha256sum "$FILE" 2>/dev/null | awk '{print $1}')" = "$EXPECTED_SHA" ] \
        && [ "$(wc -c < "$FILE" | tr -d ' \t\r\n')" = "$EXPECTED_BYTES" ]
}

process_matches() {
    PID=$1 START=$2
    OBSERVED=$(awk '{print $3 ":" $22}' "/proc/$PID/stat" 2>/dev/null || true)
    STATE=${OBSERVED%%:*}
    LIVE_START=${OBSERVED#*:}
    case "$STATE" in Z|X|x|'') return 1 ;; esac
    [ "$LIVE_START" = "$START" ]
}

any_executable_or_comm() {
    BASENAME=$1
    for PROC_DIR in /proc/[0-9]*; do
        [ -d "$PROC_DIR" ] || continue
        EXE=$(readlink "$PROC_DIR/exe" 2>/dev/null || true)
        COMM=$(cat "$PROC_DIR/comm" 2>/dev/null || true)
        case "$EXE" in */"$BASENAME"|*/"$BASENAME"\ \(deleted\)) return 0 ;; esac
        [ "$COMM" = "$BASENAME" ] && return 0
    done
    return 1
}

any_track1_wrapper() {
    for PROC_DIR in /proc/[0-9]*; do
        [ -d "$PROC_DIR" ] || continue
        PROC_PID=${PROC_DIR#/proc/}
        [ "$PROC_PID" != "$$" ] || continue
        tr '\000' '\n' < "$PROC_DIR/cmdline" 2>/dev/null \
            | grep -Eq '^/tmp/dcentrald_bench_t1_[A-Za-z0-9._-]+/run_trial$' \
            && return 0
    done
    return 1
}

no_watchdog_fd() {
    for FD in /proc/[0-9]*/fd/*; do
        [ -L "$FD" ] || [ -e "$FD" ] || continue
        TARGET=$(readlink "$FD" 2>/dev/null || true)
        case "$TARGET" in /dev/watchdog*) return 1 ;; esac
    done
}

gpio_is_exact() {
    GPIO=$1 EXPECTED_VALUE=$2
    BASE="/sys/class/gpio/gpio$GPIO"
    [ -d "$BASE" ] \
        && regular "$BASE/direction" && regular "$BASE/active_low" && regular "$BASE/value" \
        && [ "$(cat "$BASE/direction")" = out ] \
        && [ "$(cat "$BASE/active_low")" = 0 ] \
        && [ "$(cat "$BASE/value")" = "$EXPECTED_VALUE" ]
}

active_is_exact() {
    verify_file "$ACTIVE" "$ACTIVE_SHA" 769 \
        && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 20 ] \
        && [ "$(field "$ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v3 ] \
        && [ "$(field "$ACTIVE" phase)" = child-live-or-recovery-required ] \
        && [ "$(field "$ACTIVE" wrapper_pid)" = "$WRAPPER_PID" ] \
        && [ "$(field "$ACTIVE" wrapper_start)" = "$WRAPPER_START" ] \
        && [ "$(field "$ACTIVE" child_pid)" = "$DCENT_CHILD_PID" ] \
        && [ "$(field "$ACTIVE" child_start)" = "$DCENT_CHILD_START" ] \
        && [ "$(field "$ACTIVE" bosminer_pid)" = "$ORIGINAL_BOSMINER_PID" ] \
        && [ "$(field "$ACTIVE" bosminer_start)" = "$ORIGINAL_BOSMINER_START" ] \
        && [ "$(field "$ACTIVE" bosminer_exe)" = /usr/bin/bosminer ] \
        && [ "$(field "$ACTIVE" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(field "$ACTIVE" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(field "$ACTIVE" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(field "$ACTIVE" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(field "$ACTIVE" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(field "$ACTIVE" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(field "$ACTIVE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(field "$ACTIVE" live_identity_profile)" = "$IDENTITY_PROFILE" ] \
        && [ "$(field "$ACTIVE" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$ACTIVE" deploy_mode)" = mining-on-passthrough ] \
        && [ "$(field "$ACTIVE" persistent_mutation)" = false ]
}

owner_is_exact() {
    [ -d "$LOCK" ] && [ ! -L "$LOCK" ] \
        && verify_file "$OWNER" "$OWNER_SHA" 300 \
        && [ "$(ls -A "$LOCK" 2>/dev/null)" = owner ] \
        && [ "$(wc -l < "$OWNER" | tr -d ' \t\r\n')" -eq 6 ] \
        && [ "$(field "$OWNER" schema)" = dcentos.s19k-track1-runtime-lock/v1 ] \
        && [ "$(field "$OWNER" owner_kind)" = launch ] \
        && [ "$(field "$OWNER" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$OWNER" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(field "$OWNER" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(field "$OWNER" live_identity_sha256)" = "$IDENTITY_SHA" ]
}

evidence_is_exact() {
    verify_file "$RUN_EVIDENCE" "$RUN_EVIDENCE_SHA" "$RUN_EVIDENCE_BYTES" \
        && verify_file "$RECOVERY_EVIDENCE" "$RECOVERY_EVIDENCE_SHA" "$RECOVERY_EVIDENCE_BYTES" \
        && grep -Fq 'S19k Track-1 assumed inherited rails after signal-lease-confirmed bosminer exit' "$RUN_EVIDENCE" \
        && grep -Fq 'PASSTHROUGH BM1366 — opening ttyS1+ttyS2 required, ttyS3 discover' "$RUN_EVIDENCE" \
        && grep -Fq 'Track-1 terminal hashboard reset asserted with checked readback' "$RUN_EVIDENCE" \
        && grep -Fq 'PSU GPIO 437 driven 1 and read back disengaged (am3-s19k T6 SafeOff)' "$RUN_EVIDENCE" \
        && grep -Fq 'Track-1 terminal GPIO437 SafeOff completed after reset attempts' "$RUN_EVIDENCE" \
        && grep -Fq '2026-08-20T17:08:11.688752Z  INFO bosminer_backend::miner: Cooldown temperature reached' "$RECOVERY_EVIDENCE" \
        && grep -Fq '2026-08-20T17:08:36.118090Z  INFO bosminer_backend::psu: PSU: Enable' "$RECOVERY_EVIDENCE" \
        && grep -Fq 'CHAIN/2: Discovered 77 chips (expected 77 chips)' "$RECOVERY_EVIDENCE" \
        && grep -Fq 'CHAIN/3: Discovered 77 chips (expected 77 chips)' "$RECOVERY_EVIDENCE" \
        && [ "$(grep -Fc 'Set baud rate @ requested: 3125000, actual: 3125000' "$RECOVERY_EVIDENCE")" -eq 2 ] \
        && grep -Fq '2026-08-20T17:10:14.779605Z  INFO bosminer::client::stratum_v2: log_message="Stratum: changing target' "$RECOVERY_EVIDENCE"
}

identity_is_exact() {
    IDENTITY_OUT=$("$RUNNER" identity "$TRIAL_DIR" am3-s19k mining-on-passthrough \
        "$BIN_SHA" "$BIN_BYTES" "$CFG_SHA" "$CFG_BYTES" "$RUNNER_SHA" "$RUNNER_BYTES") || return 1
    [ "$IDENTITY_OUT" = 'DCENT_S19K_LIVE_IDENTITY schema=dcentos.s19k-braiins-live-identity/v2 profile=live88_two_bhb56903_slots_2_3 sha256=6312939be8f192e34e38f78c8461169386cf1c60f43f10b970fda935971347c2 model_sha256=d0ea732385a9a3b32da131996e226f564aa05d0625af03f7e1d58fcfd717f6b0 board_names=BHB56903,BHB56903 physical_addresses=2,3 eeprom=0x50=absent,0x51=05:11,0x52=05:11' ]
}

custody_is_exact() {
    CUSTODY_OUT=$1
    regular "$CUSTODY_OUT" && [ "$(wc -l < "$CUSTODY_OUT" | tr -d ' \t\r\n')" -eq 23 ] \
        && [ "$(field "$CUSTODY_OUT" schema)" = dcentos.s19k-braiins-supervisor-custody/v1 ] \
        && [ "$(field "$CUSTODY_OUT" authority)" = read-only-process-tree-observation ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_pid)" = "$SUPERVISOR_PID" ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_start)" = "$SUPERVISOR_START" ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_ppid)" = 1 ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_pgrp)" = "$SUPERVISOR_PGRP" ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_session)" = "$SUPERVISOR_SESSION" ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_state)" = nonterminal ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_exe)" = /usr/bin/bos-tools ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_cmdline_sha256)" = "$SUPERVISOR_CMDLINE_SHA" ] \
        && [ "$(field "$CUSTODY_OUT" supervisor_cmdline_bytes)" = "$SUPERVISOR_CMDLINE_BYTES" ] \
        && [ "$(field "$CUSTODY_OUT" child_pid)" = "$RECOVERED_CHILD_PID" ] \
        && [ "$(field "$CUSTODY_OUT" child_start)" = "$RECOVERED_CHILD_START" ] \
        && [ "$(field "$CUSTODY_OUT" child_ppid)" = "$SUPERVISOR_PID" ] \
        && [ "$(field "$CUSTODY_OUT" child_pgrp)" = "$SUPERVISOR_PGRP" ] \
        && [ "$(field "$CUSTODY_OUT" child_session)" = "$SUPERVISOR_SESSION" ] \
        && [ "$(field "$CUSTODY_OUT" child_state)" = nonterminal ] \
        && [ "$(field "$CUSTODY_OUT" child_exe)" = /usr/bin/bosminer ] \
        && [ "$(field "$CUSTODY_OUT" child_cmdline_sha256)" = "$CHILD_CMDLINE_SHA" ] \
        && [ "$(field "$CUSTODY_OUT" child_cmdline_bytes)" = "$CHILD_CMDLINE_BYTES" ] \
        && [ "$(field "$CUSTODY_OUT" pidfile)" = /var/run/bosminer.pid ] \
        && [ "$(field "$CUSTODY_OUT" pidfile_sha256)" = "$PIDFILE_SHA" ] \
        && [ "$(field "$CUSTODY_OUT" pidfile_bytes)" = "$PIDFILE_BYTES" ]
}

closeout_is_exact() {
    FILE=$1
    regular "$FILE" && [ "$(wc -l < "$FILE" | tr -d ' \t\r\n')" -eq 30 ] \
        && [ "$(field "$FILE" schema)" = dcentos.s19k-track1-stock-recovered-after-safeoff/v1 ] \
        && [ "$(field "$FILE" disposition)" = stock-recovered-after-dcent-safeoff ] \
        && [ "$(field "$FILE" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$FILE" original_runtime_sha256)" = "$ACTIVE_SHA" ] \
        && [ "$(field "$FILE" original_lock_owner_sha256)" = "$OWNER_SHA" ] \
        && [ "$(field "$FILE" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(field "$FILE" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(field "$FILE" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(field "$FILE" custody_observer_sha256)" = "$CUSTODY_SHA" ] \
        && [ "$(field "$FILE" custody_observer_bytes)" = "$CUSTODY_BYTES" ] \
        && [ "$(field "$FILE" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$FILE" original_bosminer)" = "$ORIGINAL_BOSMINER_PID:$ORIGINAL_BOSMINER_START" ] \
        && [ "$(field "$FILE" dcentrald_child)" = "$DCENT_CHILD_PID:$DCENT_CHILD_START" ] \
        && [ "$(field "$FILE" stock_supervisor)" = "$SUPERVISOR_PID:$SUPERVISOR_START:/usr/bin/bos-tools" ] \
        && [ "$(field "$FILE" stock_replacement_child)" = "$RECOVERED_CHILD_PID:$RECOVERED_CHILD_START:/usr/bin/bosminer" ] \
        && [ "$(field "$FILE" stock_pidfile_sha256)" = "$PIDFILE_SHA" ] \
        && [ "$(field "$FILE" gpio_baseline)" = 437:out:0:0,454:out:0:0,455:out:0:1,456:out:0:1 ] \
        && [ "$(field "$FILE" run_evidence_sha256)" = "$RUN_EVIDENCE_SHA" ] \
        && [ "$(field "$FILE" run_evidence_bytes)" = "$RUN_EVIDENCE_BYTES" ] \
        && [ "$(field "$FILE" stock_recovery_evidence_sha256)" = "$RECOVERY_EVIDENCE_SHA" ] \
        && [ "$(field "$FILE" stock_recovery_evidence_bytes)" = "$RECOVERY_EVIDENCE_BYTES" ] \
        && [ "$(field "$FILE" handoff_reached)" = true ] \
        && [ "$(field "$FILE" uart_mutation_reached)" = true ] \
        && [ "$(field "$FILE" reset_gpio_mutation)" = true ] \
        && [ "$(field "$FILE" safeoff_gpio437)" = true ] \
        && [ "$(field "$FILE" stock_restart_by_unchanged_supervisor)" = true ] \
        && [ "$(field "$FILE" stock_recovery)" = cooldown+psu-enable+chains-2-3-77-at-3125000+stratum-target ] \
        && [ "$(field "$FILE" watchdog_fd_live)" = false ] \
        && [ "$(field "$FILE" persistent_mutation)" = false ] \
        && [ "$(field "$FILE" custody_release)" = exact-active-owner-lock-retired ]
}

volatile_state_is_exact() {
    CUSTODY_OUT=$1
    ! process_matches "$WRAPPER_PID" "$WRAPPER_START" \
        && ! process_matches "$DCENT_CHILD_PID" "$DCENT_CHILD_START" \
        && ! process_matches "$ORIGINAL_BOSMINER_PID" "$ORIGINAL_BOSMINER_START" \
        && ! any_executable_or_comm dcentrald \
        && ! any_track1_wrapper \
        && no_watchdog_fd \
        && gpio_is_exact 437 0 \
        && gpio_is_exact 454 0 \
        && gpio_is_exact 455 1 \
        && gpio_is_exact 456 1 \
        && "$CUSTODY" capture /proc /var/run/bosminer.pid > "$CUSTODY_OUT" \
        && custody_is_exact "$CUSTODY_OUT" \
        && identity_is_exact
}

[ -d "$TRIAL_DIR" ] && [ ! -L "$TRIAL_DIR" ] || { echo 'ERROR: exact trial missing' >&2; exit 1; }
[ ! -e "$CLOSEOUT" ] && [ ! -L "$CLOSEOUT" ] \
    && [ ! -e "$RETIRED_ACTIVE" ] && [ ! -L "$RETIRED_ACTIVE" ] \
    && [ ! -e "$RETIRED_OWNER" ] && [ ! -L "$RETIRED_OWNER" ] || {
        echo 'ERROR: one-use output path already exists' >&2
        exit 1
    }
verify_file "$BIN" "$BIN_SHA" "$BIN_BYTES" \
    && verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" \
    && verify_file "$RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" \
    && verify_file "$CUSTODY" "$CUSTODY_SHA" "$CUSTODY_BYTES" \
    && active_is_exact && owner_is_exact && evidence_is_exact || {
        echo 'ERROR: exact current transaction/artifact/evidence admission failed' >&2
        exit 1
    }

TMP_DIR="$TRIAL_DIR/.stock-recovered-closeout-tmp.$$"
[ ! -e "$TMP_DIR" ] && [ ! -L "$TMP_DIR" ] && mkdir "$TMP_DIR" || {
    echo 'ERROR: could not acquire private one-use scratch directory' >&2
    exit 1
}
CUSTODY_TMP="$TMP_DIR/custody"
RECEIPT_TMP="$TMP_DIR/receipt"
[ ! -e "$CUSTODY_TMP" ] && [ ! -L "$CUSTODY_TMP" ] \
    && [ ! -e "$RECEIPT_TMP" ] && [ ! -L "$RECEIPT_TMP" ] || {
        echo 'ERROR: private one-use scratch paths are not empty' >&2
        exit 1
    }
cleanup_tmp() {
    rm -f "$CUSTODY_TMP" "$RECEIPT_TMP"
    rmdir "$TMP_DIR" 2>/dev/null || true
}
trap cleanup_tmp EXIT HUP INT TERM
volatile_state_is_exact "$CUSTODY_TMP" || {
    echo 'ERROR: recovered stock volatile state is not exact; retaining custody' >&2
    exit 1
}

{
    printf 'schema=dcentos.s19k-track1-stock-recovered-after-safeoff/v1\n'
    printf 'disposition=stock-recovered-after-dcent-safeoff\n'
    printf 'trial_dir=%s\n' "$TRIAL_DIR"
    printf 'original_runtime_sha256=%s\n' "$ACTIVE_SHA"
    printf 'original_lock_owner_sha256=%s\n' "$OWNER_SHA"
    printf 'binary_sha256=%s\n' "$BIN_SHA"
    printf 'config_sha256=%s\n' "$CFG_SHA"
    printf 'runner_sha256=%s\n' "$RUNNER_SHA"
    printf 'custody_observer_sha256=%s\n' "$CUSTODY_SHA"
    printf 'custody_observer_bytes=%s\n' "$CUSTODY_BYTES"
    printf 'live_identity_sha256=%s\n' "$IDENTITY_SHA"
    printf 'original_bosminer=%s:%s\n' "$ORIGINAL_BOSMINER_PID" "$ORIGINAL_BOSMINER_START"
    printf 'dcentrald_child=%s:%s\n' "$DCENT_CHILD_PID" "$DCENT_CHILD_START"
    printf 'stock_supervisor=%s:%s:/usr/bin/bos-tools\n' "$SUPERVISOR_PID" "$SUPERVISOR_START"
    printf 'stock_replacement_child=%s:%s:/usr/bin/bosminer\n' "$RECOVERED_CHILD_PID" "$RECOVERED_CHILD_START"
    printf 'stock_pidfile_sha256=%s\n' "$PIDFILE_SHA"
    printf 'gpio_baseline=437:out:0:0,454:out:0:0,455:out:0:1,456:out:0:1\n'
    printf 'run_evidence_sha256=%s\n' "$RUN_EVIDENCE_SHA"
    printf 'run_evidence_bytes=%s\n' "$RUN_EVIDENCE_BYTES"
    printf 'stock_recovery_evidence_sha256=%s\n' "$RECOVERY_EVIDENCE_SHA"
    printf 'stock_recovery_evidence_bytes=%s\n' "$RECOVERY_EVIDENCE_BYTES"
    printf 'handoff_reached=true\n'
    printf 'uart_mutation_reached=true\n'
    printf 'reset_gpio_mutation=true\n'
    printf 'safeoff_gpio437=true\n'
    printf 'stock_restart_by_unchanged_supervisor=true\n'
    printf 'stock_recovery=cooldown+psu-enable+chains-2-3-77-at-3125000+stratum-target\n'
    printf 'watchdog_fd_live=false\n'
    printf 'persistent_mutation=false\n'
    printf 'custody_release=exact-active-owner-lock-retired\n'
} > "$RECEIPT_TMP"
chmod 600 "$RECEIPT_TMP"
closeout_is_exact "$RECEIPT_TMP" || { echo 'ERROR: typed closeout construction failed' >&2; exit 1; }

# Final full admission while the board-global lock is still held.
verify_file "$BIN" "$BIN_SHA" "$BIN_BYTES" \
    && verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" \
    && verify_file "$RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" \
    && verify_file "$CUSTODY" "$CUSTODY_SHA" "$CUSTODY_BYTES" \
    && active_is_exact && owner_is_exact && evidence_is_exact \
    && volatile_state_is_exact "$CUSTODY_TMP" || {
        echo 'ERROR: final full revalidation failed; retaining custody' >&2
        exit 1
    }

# Preserve the exact old records by atomic rename.  If the post-active volatile
# check fails, restore the active name before touching the global owner.
mv "$ACTIVE" "$RETIRED_ACTIVE"
volatile_state_is_exact "$CUSTODY_TMP" || {
    mv "$RETIRED_ACTIVE" "$ACTIVE"
    echo 'ERROR: stock state changed at release boundary; custody restored' >&2
    exit 1
}
mv "$OWNER" "$RETIRED_OWNER"
if ! rmdir "$LOCK"; then
    mv "$RETIRED_OWNER" "$OWNER" || true
    mv "$RETIRED_ACTIVE" "$ACTIVE" || true
    echo 'ERROR: global lock was not empty; custody restoration attempted' >&2
    exit 1
fi

# Publish only after exact active/owner removal and empty-lock retirement.
ln "$RECEIPT_TMP" "$CLOSEOUT" || {
    echo 'ERROR: custody retired but typed closeout publication failed; retained records remain in trial' >&2
    exit 1
}
closeout_is_exact "$CLOSEOUT" || {
    echo 'ERROR: published typed closeout failed exact verification' >&2
    exit 1
}
rm -f "$RECEIPT_TMP" "$CUSTODY_TMP"
rmdir "$TMP_DIR"
trap - EXIT HUP INT TERM
echo "DCENT_S19K_TRACK1_CLOSEOUT schema=dcentos.s19k-track1-stock-recovered-after-safeoff/v1 disposition=stock-recovered-after-dcent-safeoff receipt=$CLOSEOUT"
