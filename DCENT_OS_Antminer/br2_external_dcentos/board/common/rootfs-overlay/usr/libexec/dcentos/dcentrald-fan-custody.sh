#!/bin/sh
# Shared readiness and exact-process custody for resident dcentrald --hold-fan.
#
# Requires dcentrald-process-identity.sh to be sourced first. A launcher return
# is not readiness: success requires a live, exact executable/start-tick owner
# and a same-boot receipt published only after the initial PWM readback.

dcent_fan_custody_identity() {
    DCENT_FAN_CANDIDATE_FILE=$1
    DCENT_FAN_DAEMON=$2
    DCENT_FAN_EXPECTED_TOKEN=$3
    dcent_read_child_identity "$DCENT_FAN_CANDIDATE_FILE" || return 1
    [ "$DCENT_CHILD_SESSION_TOKEN" = "$DCENT_FAN_EXPECTED_TOKEN" ] || return 1
    DCENT_FAN_CURRENT_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 1
    [ -n "$DCENT_FAN_CURRENT_BOOT_ID" ] \
        && [ "$DCENT_CHILD_BOOT_ID" = "$DCENT_FAN_CURRENT_BOOT_ID" ] || return 1
    dcent_child_identity_is_live "$DCENT_CHILD_PID" "$DCENT_CHILD_START_TICKS" \
        "$DCENT_FAN_DAEMON"
}

dcent_fan_lock_try_publish() {
    DCENT_FAN_PUBLISH_PATH=$1
    DCENT_FAN_PUBLISH_TOKEN=$2
    DCENT_FAN_PUBLISH_TICKS=$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null) \
        || return 1
    DCENT_FAN_PUBLISH_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) \
        || return 1
    DCENT_FAN_PUBLISH_CANDIDATE="${DCENT_FAN_PUBLISH_PATH}.candidate.$$.$DCENT_FAN_PUBLISH_TICKS"
    [ ! -e "$DCENT_FAN_PUBLISH_CANDIDATE" ] \
        && [ ! -L "$DCENT_FAN_PUBLISH_CANDIDATE" ] || return 1
    (umask 077; set -C; printf '%s %s %s %s\n' \
        "$$" "$DCENT_FAN_PUBLISH_TICKS" "$DCENT_FAN_PUBLISH_TOKEN" \
        "$DCENT_FAN_PUBLISH_BOOT_ID" > "$DCENT_FAN_PUBLISH_CANDIDATE") \
        2>/dev/null || return 1

    # The hard link is the publication point: another process can observe
    # either no lock or one complete typed record, never a partially written
    # owner. Link failure leaves the existing owner untouched.
    ln "$DCENT_FAN_PUBLISH_CANDIDATE" "$DCENT_FAN_PUBLISH_PATH" 2>/dev/null
    DCENT_FAN_PUBLISH_RESULT=$?
    rm -f "$DCENT_FAN_PUBLISH_CANDIDATE"
    return "$DCENT_FAN_PUBLISH_RESULT"
}

dcent_fan_lock_path_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

dcent_fan_lock_owner_is_stale() {
    DCENT_FAN_STALE_PATH=$1
    DCENT_FAN_STALE_TOKEN=$2
    dcent_read_child_identity "$DCENT_FAN_STALE_PATH" || return 1
    [ "$DCENT_CHILD_SESSION_TOKEN" = "$DCENT_FAN_STALE_TOKEN" ] \
        && [ -n "$DCENT_CHILD_BOOT_ID" ] || return 1
    DCENT_FAN_STALE_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) \
        || return 1
    [ "$DCENT_CHILD_BOOT_ID" = "$DCENT_FAN_STALE_BOOT_ID" ] || return 0

    DCENT_FAN_STALE_STAT=$(awk '{print $22 " " $3}' \
        "/proc/$DCENT_CHILD_PID/stat" 2>/dev/null || true)
    if [ -n "$DCENT_FAN_STALE_STAT" ]; then
        DCENT_FAN_STALE_TICKS=${DCENT_FAN_STALE_STAT%% *}
        DCENT_FAN_STALE_STATE=${DCENT_FAN_STALE_STAT#* }
        [ "$DCENT_FAN_STALE_TICKS" != "$DCENT_CHILD_START_TICKS" ] \
            || [ "$DCENT_FAN_STALE_STATE" = Z ]
        return
    fi
    ! kill -0 "$DCENT_CHILD_PID" 2>/dev/null
}

dcent_fan_lock_release_typed() {
    DCENT_FAN_RELEASE_PATH=$1
    DCENT_FAN_RELEASE_TOKEN=$2
    dcent_read_child_identity "$DCENT_FAN_RELEASE_PATH" || return 1
    DCENT_FAN_RELEASE_TICKS=$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null) \
        || return 1
    DCENT_FAN_RELEASE_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) \
        || return 1
    [ "$DCENT_CHILD_PID" = "$$" ] \
        && [ "$DCENT_CHILD_START_TICKS" = "$DCENT_FAN_RELEASE_TICKS" ] \
        && [ "$DCENT_CHILD_SESSION_TOKEN" = "$DCENT_FAN_RELEASE_TOKEN" ] \
        && [ "$DCENT_CHILD_BOOT_ID" = "$DCENT_FAN_RELEASE_BOOT_ID" ] || return 1
    rm -f "$DCENT_FAN_RELEASE_PATH"
}

dcent_fan_lock_acquire() {
    DCENT_FAN_LOCK_DIR=$1
    DCENT_FAN_LOCK_WAIT=${2:-10}
    DCENT_FAN_RECOVERY_LOCK="${DCENT_FAN_LOCK_DIR}.recovery"
    case "$DCENT_FAN_LOCK_WAIT" in
        ''|*[!0-9]*) return 1 ;;
    esac

    DCENT_FAN_LOCK_WAITED=0
    while [ "$DCENT_FAN_LOCK_WAITED" -le "$DCENT_FAN_LOCK_WAIT" ]; do
        if ! dcent_fan_lock_path_exists "$DCENT_FAN_RECOVERY_LOCK" \
            && dcent_fan_lock_try_publish "$DCENT_FAN_LOCK_DIR" fan-custody-lock; then
            # A recovery contender can appear between the pre-check and link.
            # Relinquish our exact lock if it is already serializing stale-owner
            # adjudication. Otherwise the live typed owner is authoritative.
            if dcent_fan_lock_path_exists "$DCENT_FAN_RECOVERY_LOCK"; then
                dcent_fan_lock_release_typed "$DCENT_FAN_LOCK_DIR" \
                    fan-custody-lock || return 1
            else
                return 0
            fi
        fi

        if ! dcent_fan_lock_path_exists "$DCENT_FAN_RECOVERY_LOCK" \
            && dcent_fan_lock_owner_is_stale "$DCENT_FAN_LOCK_DIR" \
                fan-custody-lock \
            && dcent_fan_lock_try_publish "$DCENT_FAN_RECOVERY_LOCK" \
                fan-custody-recovery; then
            # The non-recovering recovery mutex closes the stale-lock ABA:
            # normal contenders check it both before and after publication, and
            # no second recovery actor can delete a replacement lock.
            if dcent_fan_lock_owner_is_stale "$DCENT_FAN_LOCK_DIR" \
                fan-custody-lock; then
                DCENT_FAN_STALE_LOCK_PID=$DCENT_CHILD_PID
                DCENT_FAN_STALE_LOCK_TICKS=$DCENT_CHILD_START_TICKS
                rm -f "$DCENT_FAN_LOCK_DIR" \
                    "${DCENT_FAN_LOCK_DIR}.candidate.$DCENT_FAN_STALE_LOCK_PID.$DCENT_FAN_STALE_LOCK_TICKS"
            fi
            dcent_fan_lock_release_typed "$DCENT_FAN_RECOVERY_LOCK" \
                fan-custody-recovery || return 1
            continue
        fi
        sleep 1
        DCENT_FAN_LOCK_WAITED=$((DCENT_FAN_LOCK_WAITED + 1))
    done
    echo "  [FAIL] Timed out acquiring serialized fan-custody transition; stale recovery remains fail-closed" >&2
    return 1
}

dcent_fan_lock_release() {
    dcent_fan_lock_release_typed "$1" fan-custody-lock
}

dcent_fan_cmdline_has_hold_role() {
    DCENT_FAN_ROLE_PID=$1
    DCENT_FAN_ROLE_PWM=$2
    if [ "${DCENT_PROCESS_IDENTITY_TEST_AUTHORITY:-0}" = 1 ] \
        && [ "${DCENT_TEST_ONLY_PROCESS_IDENTITY:-0}" = 1 ] \
        && [ "${DCENT_TEST_ONLY_FAN_INTERPRETER:-0}" = 1 ]; then
        tr '\000' '\n' < "/proc/$DCENT_FAN_ROLE_PID/cmdline" 2>/dev/null | awk \
            -v expected_pwm="$DCENT_FAN_ROLE_PWM" '
            NR == 2 && $0 == "-c" { interpreter = 1 }
            NR == 4 && $0 == "fan-custodian" { role = 1 }
            NR == 5 && $0 == "--hold-fan" { hold = 1 }
            NR == 6 && $0 == expected_pwm { pwm = 1 }
            END { exit !(NR == 6 && interpreter && role && hold && pwm) }
        '
        return
    fi
    tr '\000' '\n' < "/proc/$DCENT_FAN_ROLE_PID/cmdline" 2>/dev/null | awk \
        -v expected_pwm="$DCENT_FAN_ROLE_PWM" '
        NR == 2 && $0 == "--hold-fan" { hold = 1 }
        NR == 3 && $0 == expected_pwm { pwm = 1 }
        END { exit !(NR == 3 && hold && pwm) }
    '
}

dcent_fan_custodian_stop_locked() {
    DCENT_FAN_DAEMON=$1
    DCENT_FAN_PIDFILE=$2
    DCENT_FAN_READYFILE=$3
    DCENT_FAN_GRACE=${4:-5}
    DCENT_FAN_REAP=${5:-2}
    DCENT_FAN_PENDINGFILE="${DCENT_FAN_READYFILE}.pending"
    DCENT_FAN_IDENTITY_FILE=
    DCENT_FAN_EXPECTED_TOKEN=

    case "$DCENT_FAN_GRACE:$DCENT_FAN_REAP" in
        *[!0-9:]*|:*) return 1 ;;
    esac

    if dcent_fan_custody_identity "$DCENT_FAN_READYFILE" \
        "$DCENT_FAN_DAEMON" fan-custodian; then
        DCENT_FAN_IDENTITY_FILE=$DCENT_FAN_READYFILE
        DCENT_FAN_EXPECTED_TOKEN=fan-custodian
    elif dcent_fan_custody_identity "$DCENT_FAN_PENDINGFILE" \
        "$DCENT_FAN_DAEMON" fan-custodian-pending; then
        DCENT_FAN_IDENTITY_FILE=$DCENT_FAN_PENDINGFILE
        DCENT_FAN_EXPECTED_TOKEN=fan-custodian-pending
    fi

    if [ -z "$DCENT_FAN_IDENTITY_FILE" ]; then
        if [ ! -e "$DCENT_FAN_PIDFILE" ] \
            && [ ! -e "$DCENT_FAN_READYFILE" ] \
            && [ ! -e "$DCENT_FAN_PENDINGFILE" ]; then
            return 0
        fi
        if dcent_dcentrald_may_execute; then
            echo "  [FAIL] Fan-custodian artifacts are stale or unverifiable while dcentrald may execute" >&2
            return 1
        fi
        rm -f "$DCENT_FAN_PIDFILE" "$DCENT_FAN_READYFILE" "$DCENT_FAN_PENDINGFILE"
        return 0
    fi

    DCENT_FAN_PID=$DCENT_CHILD_PID
    DCENT_FAN_START_TICKS=$DCENT_CHILD_START_TICKS
    if [ -r "$DCENT_FAN_PIDFILE" ]; then
        DCENT_FAN_LAUNCHER_PID=$(awk 'NF { rows++; value=$1; fields+=NF } END { if (rows == 1 && fields == 1) print value; else exit 1 }' \
            "$DCENT_FAN_PIDFILE" 2>/dev/null) || return 1
        [ "$DCENT_FAN_LAUNCHER_PID" = "$DCENT_FAN_PID" ] || {
            echo "  [FAIL] Fan-custodian pidfile disagrees with the typed readiness identity" >&2
            return 1
        }
    fi

    dcent_child_identity_matches "$DCENT_FAN_PID" "$DCENT_FAN_START_TICKS" \
        "$DCENT_FAN_DAEMON" && kill -TERM "$DCENT_FAN_PID" 2>/dev/null
    if ! dcent_wait_child_identity_dead "$DCENT_FAN_PID" "$DCENT_FAN_START_TICKS" \
        "$DCENT_FAN_DAEMON" "$DCENT_FAN_GRACE"; then
        dcent_child_identity_matches "$DCENT_FAN_PID" "$DCENT_FAN_START_TICKS" \
            "$DCENT_FAN_DAEMON" && kill -9 "$DCENT_FAN_PID" 2>/dev/null
    fi
    if ! dcent_wait_child_identity_dead "$DCENT_FAN_PID" "$DCENT_FAN_START_TICKS" \
        "$DCENT_FAN_DAEMON" "$DCENT_FAN_REAP"; then
        echo "  [FAIL] Exact fan custodian remains live after SIGKILL" >&2
        return 1
    fi
    rm -f "$DCENT_FAN_PIDFILE" "$DCENT_FAN_READYFILE" "$DCENT_FAN_PENDINGFILE"
    return 0
}

dcent_fan_custodian_stop() {
    DCENT_FAN_LOCK_DIR="${3}.lock"
    dcent_fan_lock_acquire "$DCENT_FAN_LOCK_DIR" 10 || return 1
    dcent_fan_custodian_stop_locked "$@"
    DCENT_FAN_RESULT=$?
    dcent_fan_lock_release "$DCENT_FAN_LOCK_DIR" || return 1
    return "$DCENT_FAN_RESULT"
}

dcent_fan_custodian_start_locked() {
    DCENT_FAN_DAEMON=$1
    DCENT_FAN_PWM=$2
    DCENT_FAN_PIDFILE=$3
    DCENT_FAN_READYFILE=$4
    DCENT_FAN_LAUNCHER=$5
    DCENT_FAN_LOGFILE=$6
    DCENT_FAN_READY_WAIT=${7:-10}
    DCENT_FAN_PENDINGFILE="${DCENT_FAN_READYFILE}.pending"

    case "$DCENT_FAN_PWM:$DCENT_FAN_READY_WAIT" in
        *[!0-9:]*|:*) return 1 ;;
    esac
    [ "$DCENT_FAN_PWM" -le 30 ] || return 1
    dcent_fan_custodian_stop_locked "$DCENT_FAN_DAEMON" "$DCENT_FAN_PIDFILE" \
        "$DCENT_FAN_READYFILE" 5 2 || return 1
    if dcent_dcentrald_may_execute; then
        echo "  [FAIL] Refusing fan-custodian launch while any dcentrald role may execute" >&2
        return 1
    fi
    rm -f "$DCENT_FAN_PIDFILE" "$DCENT_FAN_READYFILE" "$DCENT_FAN_PENDINGFILE"

    "$DCENT_FAN_LAUNCHER" -S -b -m -p "$DCENT_FAN_PIDFILE" \
        -x "$DCENT_FAN_DAEMON" -- --hold-fan "$DCENT_FAN_PWM" \
        >> "$DCENT_FAN_LOGFILE" 2>&1 || return 1

    DCENT_FAN_WAITED=0
    while [ "$DCENT_FAN_WAITED" -lt "$DCENT_FAN_READY_WAIT" ]; do
        if dcent_fan_custody_identity "$DCENT_FAN_READYFILE" \
            "$DCENT_FAN_DAEMON" fan-custodian; then
            DCENT_FAN_READY_PID=$DCENT_CHILD_PID
            DCENT_FAN_LAUNCHER_PID=$(cat "$DCENT_FAN_PIDFILE" 2>/dev/null || true)
            if [ "$DCENT_FAN_LAUNCHER_PID" = "$DCENT_FAN_READY_PID" ]; then
                rm -f "$DCENT_FAN_PENDINGFILE"
                return 0
            fi
            echo "  [FAIL] Fan readiness PID disagrees with launcher custody" >&2
            break
        fi

        DCENT_FAN_LAUNCHER_PID=$(cat "$DCENT_FAN_PIDFILE" 2>/dev/null || true)
        case "$DCENT_FAN_LAUNCHER_PID" in
            ''|*[!0-9]*) ;;
            *)
                DCENT_FAN_START_TICKS=$(awk '{print $22}' "/proc/$DCENT_FAN_LAUNCHER_PID/stat" 2>/dev/null || true)
                DCENT_FAN_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
                if dcent_child_identity_is_live "$DCENT_FAN_LAUNCHER_PID" \
                    "$DCENT_FAN_START_TICKS" "$DCENT_FAN_DAEMON" \
                    && dcent_fan_cmdline_has_hold_role "$DCENT_FAN_LAUNCHER_PID" \
                        "$DCENT_FAN_PWM" \
                    && dcent_child_identity_is_live "$DCENT_FAN_LAUNCHER_PID" \
                        "$DCENT_FAN_START_TICKS" "$DCENT_FAN_DAEMON" \
                    && [ -n "$DCENT_FAN_BOOT_ID" ]; then
                    printf '%s %s fan-custodian-pending %s\n' \
                        "$DCENT_FAN_LAUNCHER_PID" "$DCENT_FAN_START_TICKS" "$DCENT_FAN_BOOT_ID" \
                        > "$DCENT_FAN_PENDINGFILE" || return 1
                fi
                ;;
        esac
        sleep 1
        DCENT_FAN_WAITED=$((DCENT_FAN_WAITED + 1))
    done

    echo "  [FAIL] Fan custodian did not publish a verified readiness receipt" >&2
    dcent_fan_custodian_stop_locked "$DCENT_FAN_DAEMON" "$DCENT_FAN_PIDFILE" \
        "$DCENT_FAN_READYFILE" 2 1 || true
    return 1
}

dcent_fan_custodian_start() {
    DCENT_FAN_LOCK_DIR="${4}.lock"
    dcent_fan_lock_acquire "$DCENT_FAN_LOCK_DIR" 10 || return 1
    dcent_fan_custodian_start_locked "$@"
    DCENT_FAN_RESULT=$?
    dcent_fan_lock_release "$DCENT_FAN_LOCK_DIR" || return 1
    return "$DCENT_FAN_RESULT"
}
