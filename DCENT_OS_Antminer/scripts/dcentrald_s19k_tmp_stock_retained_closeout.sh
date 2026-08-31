#!/bin/sh
# Evidence-bounded cleanup for a stranded S19k Track-1 v3 receipt after the
# exact watchdog-disabled, pre-handoff failure. This helper never signals a
# process, opens the daemon recovery route, or writes GPIO/NAND. It removes
# only the exact runtime_active and board-global lock after publishing a typed
# append-only closeout receipt.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

TRIAL_DIR=${1:?trial_dir}
EXPECTED_BOSMINER_PID=${2:?expected_bosminer_pid}
EXPECTED_BOSMINER_START=${3:?expected_bosminer_start}
EXPECTED_BOSMINER_EXE=${4:?expected_bosminer_exe}
EXPECTED_CHILD_PID=${5:?expected_child_pid}
EXPECTED_CHILD_START=${6:?expected_child_start}
EXPECTED_GPIO_RAW=${7:?expected_gpio_raw}
EXPECTED_CFG_SHA=${8:?expected_config_sha256_from_host_plan}
EXPECTED_CFG_BYTES=${9:?expected_config_bytes_from_host_plan}
EXPECTED_RUNNER_SHA=${10:?expected_runner_sha256_from_host_plan}
EXPECTED_RUNNER_BYTES=${11:?expected_runner_bytes_from_host_plan}
EXPECTED_SOURCE_SNAPSHOT_ID=${12:?expected_source_snapshot_id}
EXPECTED_SOURCE_DESCRIPTOR_SHA=${13:?expected_source_descriptor_sha256}
EXPECTED_BUILD_RECEIPT_ID=${14:?expected_build_receipt_id}
EXPECTED_BUILD_RECEIPT_FILE_SHA=${15:?expected_build_receipt_file_sha256}
EXECUTE=${16:-}

AUDITED_BIN_SHA=19b846ffd82446212863e556fdb4ec12099732e90cfd64e2484b6793062a5752
AUDITED_BIN_BYTES=23656544
AUDITED_SOURCE_SNAPSHOT_ID=2ee6982acee0c61128698ab36e1a05e9e6e37a9efcc326f35b1cc1b6f63db703
AUDITED_SOURCE_DESCRIPTOR_SHA=ce94cac8677752fa26592444ce15ad05a2ff07ed8d694b1cca5ccb64685eafb0
AUDITED_BUILD_RECEIPT_ID=321dd6704881ac23681974af0b58469e766213c01a992e94912b17763318a199
AUDITED_BUILD_RECEIPT_FILE_SHA=be1bf2dc9de50e74c8e4bf43967a23557238b8f8936e4d4c2849825a1d5d69c6

[ "$EXECUTE" = CLEAR_STOCK_RETAINED ] || {
    echo "ERROR: final token must be CLEAR_STOCK_RETAINED" >&2
    exit 2
}
[ "$EXPECTED_GPIO_RAW" = 437:0,454:0,455:1,456:1 ] || {
    echo "ERROR: this historical closeout admits only the independently observed .88 raw GPIO tuple" >&2
    exit 2
}
[ "$EXPECTED_SOURCE_SNAPSHOT_ID:$EXPECTED_SOURCE_DESCRIPTOR_SHA:$EXPECTED_BUILD_RECEIPT_ID:$EXPECTED_BUILD_RECEIPT_FILE_SHA" = \
  "$AUDITED_SOURCE_SNAPSHOT_ID:$AUDITED_SOURCE_DESCRIPTOR_SHA:$AUDITED_BUILD_RECEIPT_ID:$AUDITED_BUILD_RECEIPT_FILE_SHA" ] || {
    echo "ERROR: independently trusted source/build receipt pins are not the audited tuple" >&2
    exit 2
}

PREFIX=/tmp/dcentrald_bench_t1_
case "$TRIAL_DIR" in "$PREFIX"*) ;; *) echo "ERROR: trial_dir outside Track-1 namespace" >&2; exit 2 ;; esac
SUFFIX=${TRIAL_DIR#"$PREFIX"}
case "$SUFFIX" in ''|*[!A-Za-z0-9._-]*|*/*) echo "ERROR: unsafe trial_dir" >&2; exit 2 ;; esac
[ "$TRIAL_DIR" = "$PREFIX$SUFFIX" ] && [ -d "$TRIAL_DIR" ] && [ ! -L "$TRIAL_DIR" ] || {
    echo "ERROR: trial_dir must be an exact non-symlink directory" >&2
    exit 2
}

ACTIVE="$TRIAL_DIR/runtime_active"
LOCK=/tmp/dcent-s19k-track1-runtime-lock
OWNER="$LOCK/owner"
BIN="$TRIAL_DIR/dcentrald"
CFG="$TRIAL_DIR/dcentrald_s19k.toml"
RUNNER="$TRIAL_DIR/run_trial"

regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
field() {
    FILE=$1 KEY=$2
    [ "$(grep -c "^$KEY=" "$FILE" 2>/dev/null || true)" -eq 1 ] || return 1
    sed -n "s/^$KEY=//p" "$FILE"
}
valid_sha() { [ "${#1}" -eq 64 ] && case "$1" in *[!0-9a-f]*) false ;; *) true ;; esac; }
valid_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -gt 0 ]; }
proc_state_start() {
    PROC_STAT=$(cat "/proc/$1/stat" 2>/dev/null || true)
    case "$PROC_STAT" in *') '*) ;; *) return 1 ;; esac
    REST=${PROC_STAT#*) }
    set -- $REST
    [ "$#" -ge 20 ] || return 1
    printf '%s:%s\n' "$1" "$20"
}
proc_matches() {
    OBS=$(proc_state_start "$1") || return 1
    STATE=${OBS%%:*} START=${OBS#*:}
    case "$STATE" in Z|X|x) return 1 ;; esac
    [ "$START" = "$2" ]
}
any_executable_basename() {
    WANT=$1
    for P in /proc/[0-9]*; do
        [ -d "$P" ] || continue
        E=$(readlink "$P/exe" 2>/dev/null || true)
        case "$E" in */"$WANT"|*/"$WANT"\ \(deleted\)) return 0 ;; esac
    done
    return 1
}
any_track1_wrapper() {
    for P in /proc/[0-9]*; do
        [ -r "$P/cmdline" ] || continue
        CMD=$(tr '\000' '\n' < "$P/cmdline" 2>/dev/null || true)
        printf '%s\n' "$CMD" | grep -Eq '^/tmp/dcentrald_bench_t1_[A-Za-z0-9._-]+/run_trial$' && return 0
    done
    return 1
}
verify_file() {
    FILE=$1 SHA=$2 BYTES=$3
    regular "$FILE" && valid_sha "$SHA" && valid_uint "$BYTES" || return 1
    [ "$(wc -c < "$FILE" | tr -d ' \t\r\n')" = "$BYTES" ] || return 1
    [ "$(sha256sum "$FILE" | awk '{print $1}')" = "$SHA" ]
}

regular "$ACTIVE" && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 20 ] || {
    echo "ERROR: exact v3 runtime receipt missing" >&2; exit 1;
}
[ "$(field "$ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v3 ] \
    && [ "$(field "$ACTIVE" phase)" = child-live-or-recovery-required ] \
    && [ "$(field "$ACTIVE" deploy_mode)" = mining-on-passthrough ] \
    && [ "$(field "$ACTIVE" persistent_mutation)" = false ] \
    && [ "$(field "$ACTIVE" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] || {
        echo "ERROR: receipt is not the exact stranded pre-handoff class" >&2; exit 1;
    }

WRAPPER_PID=$(field "$ACTIVE" wrapper_pid); WRAPPER_START=$(field "$ACTIVE" wrapper_start)
CHILD_PID=$(field "$ACTIVE" child_pid); CHILD_START=$(field "$ACTIVE" child_start)
BOSMINER_PID=$(field "$ACTIVE" bosminer_pid); BOSMINER_START=$(field "$ACTIVE" bosminer_start)
BOSMINER_EXE=$(field "$ACTIVE" bosminer_exe)
BIN_SHA=$(field "$ACTIVE" binary_sha256); BIN_BYTES=$(field "$ACTIVE" binary_bytes)
CFG_SHA=$(field "$ACTIVE" config_sha256); CFG_BYTES=$(field "$ACTIVE" config_bytes)
RUNNER_SHA=$(field "$ACTIVE" runner_sha256); RUNNER_BYTES=$(field "$ACTIVE" runner_bytes)
IDENTITY_PROFILE=$(field "$ACTIVE" live_identity_profile)
IDENTITY_SHA=$(field "$ACTIVE" live_identity_sha256)

[ "$BIN_SHA:$BIN_BYTES" = "$AUDITED_BIN_SHA:$AUDITED_BIN_BYTES" ] \
    && [ "$CFG_SHA:$CFG_BYTES" = "$EXPECTED_CFG_SHA:$EXPECTED_CFG_BYTES" ] \
    && [ "$RUNNER_SHA:$RUNNER_BYTES" = "$EXPECTED_RUNNER_SHA:$EXPECTED_RUNNER_BYTES" ] || {
        echo "ERROR: receipt content does not match independently preserved host/build pins" >&2; exit 1;
    }

[ "$BOSMINER_PID:$BOSMINER_START:$BOSMINER_EXE" = "$EXPECTED_BOSMINER_PID:$EXPECTED_BOSMINER_START:$EXPECTED_BOSMINER_EXE" ] \
    && [ "$CHILD_PID:$CHILD_START" = "$EXPECTED_CHILD_PID:$EXPECTED_CHILD_START" ] || {
        echo "ERROR: operator expectation does not match the immutable receipt" >&2; exit 1;
    }
valid_uint "$WRAPPER_PID" && valid_uint "$WRAPPER_START" \
    && valid_uint "$CHILD_PID" && valid_uint "$CHILD_START" \
    && valid_uint "$BOSMINER_PID" && valid_uint "$BOSMINER_START" \
    && valid_sha "$IDENTITY_SHA" || { echo "ERROR: invalid receipt lifetime/digest" >&2; exit 1; }
case "$BOSMINER_EXE" in /*/bosminer) ;; *) echo "ERROR: invalid bosminer exe" >&2; exit 1 ;; esac
case "$IDENTITY_PROFILE" in live88_two_bhb56903_slots_2_3) ;; *) echo "ERROR: historical helper is .88-profile-only" >&2; exit 1 ;; esac

verify_file "$BIN" "$BIN_SHA" "$BIN_BYTES" \
    && verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" \
    && verify_file "$RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" || {
        echo "ERROR: bound trial content changed" >&2; exit 1;
    }

require_bound_watchdog_disabled() {
    # Exact narrow cause: disabled configuration returns before the watchdog
    # worker/device exists. Duplicate/malformed watchdog authority is refused.
    verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" || return 1
    awk '
        BEGIN { section=""; tables=0; enabled=0; false_value=0; bad=0 }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        /^[[:space:]]*\[[^][]+\][[:space:]]*(#.*)?$/ {
            line=$0; sub(/^[[:space:]]*\[/,"",line); sub(/\][[:space:]]*(#.*)?$/,"",line)
            section=line; if (section == "watchdog") tables++; next
        }
        section == "watchdog" && /^[[:space:]]*enabled[[:space:]]*=/ {
            enabled++
            if ($0 ~ /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*false[[:space:]]*(#.*)?$/) false_value++
            else bad=1
        }
        END { exit !(tables == 1 && enabled == 1 && false_value == 1 && bad == 0) }
    ' "$CFG"
}
require_bound_watchdog_disabled || { echo "ERROR: bound config is not exact watchdog-disabled evidence" >&2; exit 1; }

[ -d "$LOCK" ] && [ ! -L "$LOCK" ] && regular "$OWNER" \
    && [ "$(wc -l < "$OWNER" | tr -d ' \t\r\n')" -eq 6 ] || {
        echo "ERROR: exact global custody lock/owner missing" >&2; exit 1;
    }
[ "$(field "$OWNER" schema)" = dcentos.s19k-track1-runtime-lock/v1 ] \
    && [ "$(field "$OWNER" owner_kind)" = launch ] \
    && [ "$(field "$OWNER" trial_dir)" = "$TRIAL_DIR" ] \
    && [ "$(field "$OWNER" runner_sha256)" = "$RUNNER_SHA" ] \
    && [ "$(field "$OWNER" runner_bytes)" = "$RUNNER_BYTES" ] \
    && [ "$(field "$OWNER" live_identity_sha256)" = "$IDENTITY_SHA" ] || {
        echo "ERROR: global custody owner is not bound to this exact receipt" >&2; exit 1;
    }

proc_matches "$WRAPPER_PID" "$WRAPPER_START" && { echo "ERROR: receipted wrapper is live" >&2; exit 1; }
proc_matches "$CHILD_PID" "$CHILD_START" && { echo "ERROR: receipted child is live" >&2; exit 1; }
if pidof dcentrald >/dev/null 2>&1 || any_executable_basename dcentrald; then echo "ERROR: dcentrald is live" >&2; exit 1; fi
if any_track1_wrapper; then echo "ERROR: a Track-1 wrapper is live" >&2; exit 1; fi

require_exact_stock_owner() {
    proc_matches "$BOSMINER_PID" "$BOSMINER_START" \
        && [ "$(cat "/proc/$BOSMINER_PID/comm" 2>/dev/null || true)" = bosminer ] \
        && [ "$(readlink "/proc/$BOSMINER_PID/exe" 2>/dev/null || true)" = "$BOSMINER_EXE" ] || return 1
    set -- $(pidof bosminer 2>/dev/null || true)
    [ "$#" -eq 1 ] && [ "$1" = "$BOSMINER_PID" ] || return 1
    COUNT=0
    for P in /proc/[0-9]*; do
        [ -d "$P" ] || continue
        E=$(readlink "$P/exe" 2>/dev/null || true)
        case "$E" in */bosminer|*/bosminer\ \(deleted\))
            [ "${P#/proc/}" = "$BOSMINER_PID" ] || return 1
            COUNT=$((COUNT + 1))
            ;;
        esac
    done
    [ "$COUNT" -eq 1 ]
}
require_exact_stock_owner || { echo "ERROR: original bosminer is not the exclusive exact lifetime" >&2; exit 1; }

# A disabled config proves this daemon never opened the descriptor. Refuse if
# any process nevertheless holds a watchdog device, including an unrelated or
# stale owner not represented by the receipt.
require_no_watchdog_fd() {
    for FD in /proc/[0-9]*/fd/*; do
        [ -L "$FD" ] || [ -e "$FD" ] || continue
        TARGET=$(readlink "$FD" 2>/dev/null || true)
        case "$TARGET" in /dev/watchdog|/dev/watchdog[0-9]*|/dev/watchdog\ \(deleted\)|/dev/watchdog[0-9]*\ \(deleted\))
            echo "ERROR: a watchdog device descriptor is live at $FD" >&2; return 1 ;;
        esac
    done
}
require_no_watchdog_fd || exit 1

read_gpio_tuple() {
    OUT=
    for N in 437 454 455 456; do
        V=$(cat "/sys/class/gpio/gpio$N/value" 2>/dev/null || true)
        case "$V" in 0|1) ;; *) return 1 ;; esac
        if [ -z "$OUT" ]; then OUT="$N:$V"; else OUT="$OUT,$N:$V"; fi
    done
    printf '%s\n' "$OUT"
}
[ "$(read_gpio_tuple)" = "$EXPECTED_GPIO_RAW" ] || {
    echo "ERROR: raw GPIO tuple changed from independently observed pre-handoff state" >&2; exit 1;
}

fresh_identity_matches() {
    IDENTITY_OUT=$("$RUNNER" identity "$TRIAL_DIR" am3-s19k mining-on-passthrough \
        "$BIN_SHA" "$BIN_BYTES" "$CFG_SHA" "$CFG_BYTES" "$RUNNER_SHA" "$RUNNER_BYTES") || return 1
    [ "$(printf '%s\n' "$IDENTITY_OUT" | wc -l | tr -d ' \t\r\n')" -eq 1 ] \
        && printf '%s\n' "$IDENTITY_OUT" | grep -Eq "^DCENT_S19K_LIVE_IDENTITY schema=dcentos\\.s19k-braiins-live-identity/v2 profile=$IDENTITY_PROFILE sha256=$IDENTITY_SHA model_sha256=[0-9a-f]{64} board_names=BHB56903,BHB56903 physical_addresses=2,3 eeprom=0x50=absent,0x51=05:11,0x52=05:11$"
}
fresh_identity_matches || {
    echo "ERROR: fresh old-runner identity does not match the receipt-bound .88 profile" >&2; exit 1;
}

# Recheck all volatile evidence immediately before publishing/clearing.
require_exact_stock_owner || { echo "ERROR: stock lifetime changed during evidence capture" >&2; exit 1; }
proc_matches "$CHILD_PID" "$CHILD_START" && { echo "ERROR: child lifetime reappeared" >&2; exit 1; }
if pidof dcentrald >/dev/null 2>&1 || any_executable_basename dcentrald; then echo "ERROR: dcentrald appeared during evidence capture" >&2; exit 1; fi
[ "$(read_gpio_tuple)" = "$EXPECTED_GPIO_RAW" ] || { echo "ERROR: GPIO tuple changed during evidence capture" >&2; exit 1; }
[ "$(field "$OWNER" live_identity_sha256)" = "$IDENTITY_SHA" ] || { echo "ERROR: lock owner changed" >&2; exit 1; }

active_is_unchanged() {
    regular "$ACTIVE" && [ "$(wc -l < "$ACTIVE" | tr -d ' \t\r\n')" -eq 20 ] \
        && [ "$(field "$ACTIVE" schema)" = dcentos.s19k-tmp-runtime/v3 ] \
        && [ "$(field "$ACTIVE" phase)" = child-live-or-recovery-required ] \
        && [ "$(field "$ACTIVE" wrapper_pid)" = "$WRAPPER_PID" ] \
        && [ "$(field "$ACTIVE" wrapper_start)" = "$WRAPPER_START" ] \
        && [ "$(field "$ACTIVE" child_pid)" = "$CHILD_PID" ] \
        && [ "$(field "$ACTIVE" child_start)" = "$CHILD_START" ] \
        && [ "$(field "$ACTIVE" bosminer_pid)" = "$BOSMINER_PID" ] \
        && [ "$(field "$ACTIVE" bosminer_start)" = "$BOSMINER_START" ] \
        && [ "$(field "$ACTIVE" bosminer_exe)" = "$BOSMINER_EXE" ] \
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

lock_is_unchanged() {
    [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && regular "$OWNER" \
        && [ "$(wc -l < "$OWNER" | tr -d ' \t\r\n')" -eq 6 ] \
        && [ "$(field "$OWNER" schema)" = dcentos.s19k-track1-runtime-lock/v1 ] \
        && [ "$(field "$OWNER" owner_kind)" = launch ] \
        && [ "$(field "$OWNER" trial_dir)" = "$TRIAL_DIR" ] \
        && [ "$(field "$OWNER" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(field "$OWNER" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(field "$OWNER" live_identity_sha256)" = "$IDENTITY_SHA" ]
}

CLOSEOUT="$TRIAL_DIR/runtime_stock_owner_retained.$CHILD_START"
[ ! -e "$CLOSEOUT" ] && [ ! -L "$CLOSEOUT" ] || { echo "ERROR: closeout receipt path exists" >&2; exit 1; }
TMP="$TRIAL_DIR/.runtime_stock_owner_retained.$CHILD_START.$$"
{
    printf 'schema=dcentos.s19k-track1-stock-owner-retained/v1\n'
    printf 'disposition=stock-owner-retained/no-handoff\n'
    printf 'reason=watchdog-disabled-by-bound-config\n'
    printf 'runtime_schema=dcentos.s19k-tmp-runtime/v3\n'
    printf 'runtime_phase=child-live-or-recovery-required\n'
    printf 'child_pid=%s\n' "$CHILD_PID"
    printf 'child_start=%s\n' "$CHILD_START"
    printf 'bosminer_pid=%s\n' "$BOSMINER_PID"
    printf 'bosminer_start=%s\n' "$BOSMINER_START"
    printf 'bosminer_exe=%s\n' "$BOSMINER_EXE"
    printf 'binary_sha256=%s\n' "$BIN_SHA"
    printf 'binary_bytes=%s\n' "$BIN_BYTES"
    printf 'config_sha256=%s\n' "$CFG_SHA"
    printf 'config_bytes=%s\n' "$CFG_BYTES"
    printf 'runner_sha256=%s\n' "$RUNNER_SHA"
    printf 'runner_bytes=%s\n' "$RUNNER_BYTES"
    printf 'live_identity_schema=dcentos.s19k-braiins-live-identity/v2\n'
    printf 'live_identity_profile=%s\n' "$IDENTITY_PROFILE"
    printf 'live_identity_sha256=%s\n' "$IDENTITY_SHA"
    printf 'audited_binary_sha256=%s\n' "$AUDITED_BIN_SHA"
    printf 'audited_source_snapshot_id=%s\n' "$AUDITED_SOURCE_SNAPSHOT_ID"
    printf 'audited_source_descriptor_sha256=%s\n' "$AUDITED_SOURCE_DESCRIPTOR_SHA"
    printf 'audited_build_receipt_id=%s\n' "$AUDITED_BUILD_RECEIPT_ID"
    printf 'audited_build_receipt_file_sha256=%s\n' "$AUDITED_BUILD_RECEIPT_FILE_SHA"
    printf 'daemon_boundary=watchdog-require-armed-before-route-claims-sigkill-reset-guard-uart\n'
    printf 'watchdog_device=not-opened-disabled-by-configuration\n'
    printf 'hashboard_mutation=not-reached\n'
    printf 'gpio_mutation=false\n'
    printf 'safeoff=false\n'
    printf 'persistent_mutation=false\n'
} > "$TMP"
chmod 600 "$TMP"
ln "$TMP" "$CLOSEOUT" || { rm -f "$TMP"; echo "ERROR: no-clobber closeout publish failed" >&2; exit 1; }
rm -f "$TMP"

closeout_is_exact() {
    regular "$CLOSEOUT" && [ "$(wc -l < "$CLOSEOUT" | tr -d ' \t\r\n')" -eq 30 ] \
        && [ "$(field "$CLOSEOUT" schema)" = dcentos.s19k-track1-stock-owner-retained/v1 ] \
        && [ "$(field "$CLOSEOUT" disposition)" = stock-owner-retained/no-handoff ] \
        && [ "$(field "$CLOSEOUT" reason)" = watchdog-disabled-by-bound-config ] \
        && [ "$(field "$CLOSEOUT" runtime_schema)" = dcentos.s19k-tmp-runtime/v3 ] \
        && [ "$(field "$CLOSEOUT" runtime_phase)" = child-live-or-recovery-required ] \
        && [ "$(field "$CLOSEOUT" child_pid)" = "$CHILD_PID" ] \
        && [ "$(field "$CLOSEOUT" child_start)" = "$CHILD_START" ] \
        && [ "$(field "$CLOSEOUT" bosminer_pid)" = "$BOSMINER_PID" ] \
        && [ "$(field "$CLOSEOUT" bosminer_start)" = "$BOSMINER_START" ] \
        && [ "$(field "$CLOSEOUT" bosminer_exe)" = "$BOSMINER_EXE" ] \
        && [ "$(field "$CLOSEOUT" binary_sha256)" = "$BIN_SHA" ] \
        && [ "$(field "$CLOSEOUT" binary_bytes)" = "$BIN_BYTES" ] \
        && [ "$(field "$CLOSEOUT" config_sha256)" = "$CFG_SHA" ] \
        && [ "$(field "$CLOSEOUT" config_bytes)" = "$CFG_BYTES" ] \
        && [ "$(field "$CLOSEOUT" runner_sha256)" = "$RUNNER_SHA" ] \
        && [ "$(field "$CLOSEOUT" runner_bytes)" = "$RUNNER_BYTES" ] \
        && [ "$(field "$CLOSEOUT" live_identity_schema)" = dcentos.s19k-braiins-live-identity/v2 ] \
        && [ "$(field "$CLOSEOUT" live_identity_profile)" = "$IDENTITY_PROFILE" ] \
        && [ "$(field "$CLOSEOUT" live_identity_sha256)" = "$IDENTITY_SHA" ] \
        && [ "$(field "$CLOSEOUT" audited_binary_sha256)" = "$AUDITED_BIN_SHA" ] \
        && [ "$(field "$CLOSEOUT" audited_source_snapshot_id)" = "$AUDITED_SOURCE_SNAPSHOT_ID" ] \
        && [ "$(field "$CLOSEOUT" audited_source_descriptor_sha256)" = "$AUDITED_SOURCE_DESCRIPTOR_SHA" ] \
        && [ "$(field "$CLOSEOUT" audited_build_receipt_id)" = "$AUDITED_BUILD_RECEIPT_ID" ] \
        && [ "$(field "$CLOSEOUT" audited_build_receipt_file_sha256)" = "$AUDITED_BUILD_RECEIPT_FILE_SHA" ] \
        && [ "$(field "$CLOSEOUT" daemon_boundary)" = watchdog-require-armed-before-route-claims-sigkill-reset-guard-uart ] \
        && [ "$(field "$CLOSEOUT" watchdog_device)" = not-opened-disabled-by-configuration ] \
        && [ "$(field "$CLOSEOUT" hashboard_mutation)" = not-reached ] \
        && [ "$(field "$CLOSEOUT" gpio_mutation)" = false ] \
        && [ "$(field "$CLOSEOUT" safeoff)" = false ] \
        && [ "$(field "$CLOSEOUT" persistent_mutation)" = false ]
}

# The hardlink receipt is not authority by itself. Re-run the complete
# volatile admission immediately before deleting any custody state.
closeout_is_exact \
    && active_is_unchanged \
    && verify_file "$BIN" "$BIN_SHA" "$BIN_BYTES" \
    && verify_file "$CFG" "$CFG_SHA" "$CFG_BYTES" \
    && verify_file "$RUNNER" "$RUNNER_SHA" "$RUNNER_BYTES" \
    && require_bound_watchdog_disabled \
    && lock_is_unchanged \
    && ! proc_matches "$WRAPPER_PID" "$WRAPPER_START" \
    && ! proc_matches "$CHILD_PID" "$CHILD_START" \
    && ! pidof dcentrald >/dev/null 2>&1 \
    && ! any_executable_basename dcentrald \
    && ! any_track1_wrapper \
    && require_exact_stock_owner \
    && require_no_watchdog_fd \
    && [ "$(read_gpio_tuple)" = "$EXPECTED_GPIO_RAW" ] \
    && fresh_identity_matches \
    && closeout_is_exact \
    && active_is_unchanged \
    && lock_is_unchanged || {
        echo "ERROR: complete post-publication revalidation failed; retaining custody" >&2
        exit 1
    }

# Crash order remains fail-closed: active is the final removed obligation.
rm -f "$OWNER"
rmdir "$LOCK"
regular "$ACTIVE" || { echo "ERROR: runtime receipt changed before final clear" >&2; exit 1; }
rm -f "$ACTIVE"
echo "DCENT_S19K_TRACK1_CLOSEOUT schema=dcentos.s19k-track1-stock-owner-retained/v1 disposition=stock-owner-retained/no-handoff reason=watchdog-disabled-by-bound-config gpio_mutation=false safeoff=false receipt=$CLOSEOUT"
