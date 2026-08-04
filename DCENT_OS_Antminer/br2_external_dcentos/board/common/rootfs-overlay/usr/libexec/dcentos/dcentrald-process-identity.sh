#!/bin/sh
# Shared exact-process identity and managed-stop contract for dcentrald init.
#
# This file is a sourced library. Current session supervisors publish
# "PID START_TICKS ADMISSION_TOKEN BOOT_ID" so terminal receipts are bound to
# both an exact process and an exact boot/session. Legacy two-field records are
# accepted only for exact-process shutdown and can never authorize a serialized
# helper receipt. No function treats signal delivery as process-death proof.

dcent_read_child_identity() {
    DCENT_CHILD_PID=
    DCENT_CHILD_START_TICKS=
    DCENT_CHILD_SESSION_TOKEN=
    DCENT_CHILD_BOOT_ID=
    [ -r "$1" ] || return 1

    DCENT_IDENTITY_RECORD=$(awk '
        NF {
            rows++
            fields += NF
            if (rows == 1 && (NF == 2 || NF == 4)) {
                if (NF == 2) print $1 " " $2
                else print $1 " " $2 " " $3 " " $4
            }
        }
        END { if (rows != 1 || (fields != 2 && fields != 4)) exit 1 }
    ' "$1" 2>/dev/null) || return 1
    DCENT_CHILD_PID=${DCENT_IDENTITY_RECORD%% *}
    DCENT_IDENTITY_REMAINDER=${DCENT_IDENTITY_RECORD#* }
    DCENT_CHILD_START_TICKS=${DCENT_IDENTITY_REMAINDER%% *}
    case "$DCENT_CHILD_PID:$DCENT_CHILD_START_TICKS" in
        *[!0-9:]*|:*)
            DCENT_CHILD_PID=
            DCENT_CHILD_START_TICKS=
            return 1
            ;;
    esac
    if [ "$DCENT_IDENTITY_REMAINDER" != "$DCENT_CHILD_START_TICKS" ]; then
        DCENT_IDENTITY_REMAINDER=${DCENT_IDENTITY_REMAINDER#* }
        DCENT_CHILD_SESSION_TOKEN=${DCENT_IDENTITY_REMAINDER%% *}
        DCENT_CHILD_BOOT_ID=${DCENT_IDENTITY_REMAINDER#* }
        case "$DCENT_CHILD_SESSION_TOKEN:$DCENT_CHILD_BOOT_ID" in
            *[!A-Za-z0-9._:-]*|:*|*:) return 1 ;;
        esac
    fi
    return 0
}

dcent_child_identity_matches() {
    DCENT_IDENTITY_PID=$1
    DCENT_IDENTITY_START_TICKS=$2
    DCENT_IDENTITY_DAEMON=$3
    case "$DCENT_IDENTITY_PID:$DCENT_IDENTITY_START_TICKS" in
        *[!0-9:]*|:*) return 1 ;;
    esac
    [ "$(awk '{print $22}' "/proc/$DCENT_IDENTITY_PID/stat" 2>/dev/null)" \
        = "$DCENT_IDENTITY_START_TICKS" ] || return 1
    DCENT_IDENTITY_ACTUAL_EXE=$(readlink -f "/proc/$DCENT_IDENTITY_PID/exe" 2>/dev/null) \
        || return 1
    DCENT_IDENTITY_EXPECTED_EXE=$(readlink -f "$DCENT_IDENTITY_DAEMON" 2>/dev/null) \
        || return 1
    [ "$DCENT_IDENTITY_ACTUAL_EXE" = "$DCENT_IDENTITY_EXPECTED_EXE" ]
}

dcent_child_identity_is_live() {
    dcent_child_identity_matches "$1" "$2" "$3" || return 1
    DCENT_IDENTITY_STATE=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null) || return 1
    [ "$DCENT_IDENTITY_STATE" != Z ]
}

dcent_pidof_dcentrald() {
    if [ "${DCENT_PROCESS_IDENTITY_TEST_AUTHORITY:-0}" = 1 ] \
        && [ "${DCENT_TEST_ONLY_PROCESS_IDENTITY:-0}" = 1 ] \
        && [ -n "${DCENT_TEST_PIDOF_COMMAND:-}" ]; then
        case "$DCENT_TEST_PIDOF_COMMAND" in
            /*) "$DCENT_TEST_PIDOF_COMMAND" dcentrald ;;
            *) return 1 ;;
        esac
        return
    fi
    pidof dcentrald
}

dcent_dcentrald_may_execute() {
    for DCENT_IDENTITY_PID in $(dcent_pidof_dcentrald 2>/dev/null || true); do
        case "$DCENT_IDENTITY_PID" in
            ''|*[!0-9]*) return 0 ;;
        esac
        DCENT_IDENTITY_STATE=$(awk '{print $3}' "/proc/$DCENT_IDENTITY_PID/stat" 2>/dev/null) \
            || return 0
        [ "$DCENT_IDENTITY_STATE" = Z ] || return 0
    done
    return 1
}

dcent_wait_child_identity_dead() {
    DCENT_IDENTITY_PID=$1
    DCENT_IDENTITY_START_TICKS=$2
    DCENT_IDENTITY_DAEMON=$3
    DCENT_IDENTITY_WAIT_LIMIT=$4
    DCENT_IDENTITY_WAITED=0
    while [ "$DCENT_IDENTITY_WAITED" -lt "$DCENT_IDENTITY_WAIT_LIMIT" ]; do
        dcent_child_identity_is_live "$DCENT_IDENTITY_PID" \
            "$DCENT_IDENTITY_START_TICKS" "$DCENT_IDENTITY_DAEMON" || return 0
        sleep 1
        DCENT_IDENTITY_WAITED=$((DCENT_IDENTITY_WAITED + 1))
    done
    ! dcent_child_identity_is_live "$DCENT_IDENTITY_PID" \
        "$DCENT_IDENTITY_START_TICKS" "$DCENT_IDENTITY_DAEMON"
}

dcent_wrapper_may_execute() {
    [ -e "$1" ] || return 1
    DCENT_WRAPPER_PID=$(cat "$1" 2>/dev/null) || return 0
    case "$DCENT_WRAPPER_PID" in
        ''|*[!0-9]*) return 0 ;;
    esac
    kill -0 "$DCENT_WRAPPER_PID" 2>/dev/null
}

# Stop one common-session-latch supervised owner.
#
# Arguments: child-pidfile expected-exit-file daemon wrapper-pidfile
#            crash-latch safety-script logfile [grace] [reap] [receipt]
dcent_stop_managed_session() {
    DCENT_STOP_CHILD_PIDFILE=$1
    DCENT_STOP_EXPECTFILE=$2
    DCENT_STOP_DAEMON=$3
    DCENT_STOP_WRAPPER_PIDFILE=$4
    DCENT_STOP_CRASH_LATCH=$5
    DCENT_STOP_SAFETY_SCRIPT=$6
    DCENT_STOP_LOGFILE=$7
    DCENT_STOP_GRACE=${8:-30}
    DCENT_STOP_REAP=${9:-5}
    DCENT_STOP_RECEIPT=${10:-30}
    DCENT_STOP_HAD_IDENTITY=0
    DCENT_STOP_TIMED_OUT=0
    DCENT_STOP_RECEIPT_PID=
    DCENT_STOP_RECEIPT_START_TICKS=
    DCENT_STOP_RECEIPT_SESSION_TOKEN=
    DCENT_STOP_RECEIPT_BOOT_ID=

    case "$DCENT_STOP_GRACE:$DCENT_STOP_REAP:$DCENT_STOP_RECEIPT" in
        *[!0-9:]*|:*)
            echo "  [FAIL] Invalid managed-stop timing contract" >&2
            return 1
            ;;
    esac

    if dcent_read_child_identity "$DCENT_STOP_CHILD_PIDFILE"; then
        DCENT_STOP_PID=$DCENT_CHILD_PID
        DCENT_STOP_START_TICKS=$DCENT_CHILD_START_TICKS
        DCENT_STOP_RECEIPT_PID=$DCENT_CHILD_PID
        DCENT_STOP_RECEIPT_START_TICKS=$DCENT_CHILD_START_TICKS
        DCENT_STOP_RECEIPT_SESSION_TOKEN=$DCENT_CHILD_SESSION_TOKEN
        DCENT_STOP_RECEIPT_BOOT_ID=$DCENT_CHILD_BOOT_ID
        DCENT_STOP_HAD_IDENTITY=1
    else
        DCENT_STOP_PID=
        DCENT_STOP_START_TICKS=
    fi

    if [ "$DCENT_STOP_HAD_IDENTITY" -eq 1 ] \
        && ! dcent_child_identity_matches "$DCENT_STOP_PID" \
            "$DCENT_STOP_START_TICKS" "$DCENT_STOP_DAEMON"; then
        if dcent_dcentrald_may_execute; then
            echo "  [FAIL] Refusing a live dcentrald with stale or mismatched child identity" >&2
            return 1
        fi
        echo "  [WARN] Ignoring stale child identity; no process will be signaled"
        DCENT_STOP_PID=
        DCENT_STOP_START_TICKS=
    fi
    if [ -z "$DCENT_STOP_PID" ] && dcent_dcentrald_may_execute; then
        echo "  [FAIL] A live dcentrald exists without a verified supervisor identity" >&2
        return 1
    fi

    if [ -n "$DCENT_STOP_PID" ]; then
        printf '%s requested-stop\n' "$DCENT_STOP_PID" > "$DCENT_STOP_EXPECTFILE" \
            || return 1
        dcent_child_identity_matches "$DCENT_STOP_PID" "$DCENT_STOP_START_TICKS" \
            "$DCENT_STOP_DAEMON" \
            && kill -TERM "$DCENT_STOP_PID" 2>/dev/null

        if ! dcent_wait_child_identity_dead "$DCENT_STOP_PID" \
            "$DCENT_STOP_START_TICKS" "$DCENT_STOP_DAEMON" "$DCENT_STOP_GRACE"; then
            echo "  [WARN] dcentrald did not exit in ${DCENT_STOP_GRACE}s; force killing"
            printf '%s forced-stop-timeout\n' "$DCENT_STOP_PID" > "$DCENT_STOP_EXPECTFILE" \
                || return 1
            DCENT_STOP_TIMED_OUT=1
            dcent_child_identity_matches "$DCENT_STOP_PID" "$DCENT_STOP_START_TICKS" \
                "$DCENT_STOP_DAEMON" \
                && kill -9 "$DCENT_STOP_PID" 2>/dev/null
        fi

        if ! dcent_wait_child_identity_dead "$DCENT_STOP_PID" \
            "$DCENT_STOP_START_TICKS" "$DCENT_STOP_DAEMON" "$DCENT_STOP_REAP"; then
            echo "  [FAIL] dcentrald PID $DCENT_STOP_PID remains live after SIGKILL" >&2
            return 1
        fi
    fi

    # The session helper removes child identity only after its safety action
    # and durable crash-marker promotion. Prefer that serialized receipt.
    DCENT_STOP_WAITED=0
    while [ -e "$DCENT_STOP_CHILD_PIDFILE" ] \
        && [ "$DCENT_STOP_WAITED" -lt "$DCENT_STOP_RECEIPT" ]; do
        sleep 1
        DCENT_STOP_WAITED=$((DCENT_STOP_WAITED + 1))
    done

    DCENT_STOP_RECEIPT_NEEDLE="session-$DCENT_STOP_RECEIPT_SESSION_TOKEN-boot-$DCENT_STOP_RECEIPT_BOOT_ID-pid-$DCENT_STOP_RECEIPT_PID-start-$DCENT_STOP_RECEIPT_START_TICKS-"
    if [ "$DCENT_STOP_HAD_IDENTITY" -eq 1 ] \
        && [ -n "$DCENT_STOP_RECEIPT_SESSION_TOKEN" ] \
        && [ -n "$DCENT_STOP_RECEIPT_BOOT_ID" ] \
        && [ ! -e "$DCENT_STOP_CHILD_PIDFILE" ] \
        && [ -f "$DCENT_STOP_CRASH_LATCH" ] \
        && grep -Fq "$DCENT_STOP_RECEIPT_NEEDLE" "$DCENT_STOP_CRASH_LATCH"; then
        if grep -Fq 'safeoff-failed' "$DCENT_STOP_CRASH_LATCH"; then
            echo "  [FAIL] Session helper recorded emergency safe-off failure" >&2
            return 1
        fi
        echo "  [OK] Serialized session-helper safety receipt observed; physical disposition remains unresolved"
    else
        if dcent_dcentrald_may_execute; then
            echo "  [FAIL] A dcentrald process remains executable; refusing fallback safety writes" >&2
            return 1
        fi
        if dcent_wrapper_may_execute "$DCENT_STOP_WRAPPER_PIDFILE"; then
            echo "  [FAIL] Session wrapper remains live or unverifiable; refusing a competing fallback writer" >&2
            return 1
        fi
        if ! "$DCENT_STOP_SAFETY_SCRIPT" safety >> "$DCENT_STOP_LOGFILE" 2>&1; then
            echo "  [FAIL] Fallback emergency safety action failed" >&2
            return 1
        fi
        echo "  [OK] Fallback safety action returned command/readback evidence; physical disposition remains unresolved"
    fi

    rm -f "$DCENT_STOP_WRAPPER_PIDFILE" "$DCENT_STOP_CHILD_PIDFILE" "$DCENT_STOP_EXPECTFILE"
    if [ "$DCENT_STOP_TIMED_OUT" -eq 1 ]; then
        echo "$(date): forced-stop-timeout: exact owner death observed before terminal safety receipt" \
            >> "$DCENT_STOP_LOGFILE"
    fi
    return 0
}
