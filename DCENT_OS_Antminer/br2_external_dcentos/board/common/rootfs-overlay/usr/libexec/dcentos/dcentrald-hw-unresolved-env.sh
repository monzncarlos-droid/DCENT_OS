#!/bin/sh
# Stamp or clear the shared U-Boot env flag `dcent_hw_unresolved`.
#
# Journal v2 lives under the *active* image's `/data`. A U-Boot revert to
# the other A/B slot can see a clean `/data` and skip the latch. This flag
# lives in the shared NAND env so BOTH images see an unresolved hardware
# session. It is NOT VerifiedRailCut and does not authorize S82 start.
#
# NEVER nandwrite / flash_erase /dev/mtd4. Weak-ECC pl35x-nand env flips
# MUST use fw_setenv (libubootenv, redundant-copy-atomic). Recovery is
# also fw_setenv replay, never raw nandwrite.
#
# Usage:
#   dcentrald-hw-unresolved-env.sh print-set    # print fw_setenv --script payload
#   dcentrald-hw-unresolved-env.sh print-clear  # print the clear counterpart
#   dcentrald-hw-unresolved-env.sh set          # apply set (requires fw_setenv)
#   dcentrald-hw-unresolved-env.sh clear        # apply clear (requires fw_setenv)
#   dcentrald-hw-unresolved-env.sh self-test    # host-safe, never calls fw_setenv

set -u

PATH=/usr/bin:/bin:/usr/sbin:/sbin

ENV_NAME=dcent_hw_unresolved
ENV_SET_VALUE=1

log() {
    printf 'dcentrald-hw-unresolved-env: %s\n' "$*" >&2
}

usage() {
    log "usage: $0 print-set|print-clear|set|clear|self-test"
    return 1
}

# libubootenv `fw_setenv --script` form: `name value` sets; `name` with no
# value deletes. Matches revert_to_stock_s17.sh / AM2 sysupgrade.
print_set_script() {
    printf '%s %s\n' "$ENV_NAME" "$ENV_SET_VALUE"
}

print_clear_script() {
    printf '%s\n' "$ENV_NAME"
}

print_apply_command() {
    printf 'fw_setenv --script %s\n' "$1"
}

refuse_raw_mtd4() {
    # Defense in depth: this helper has no nandwrite/flash_erase path.
    # Fail closed if an operator alias tries to wrap us.
    case "${DCENT_FORCE_NANDWRITE_MTD4:-}" in
        '') return 0 ;;
        *)
            log "refusing: raw mtd4 mutation is forbidden (NEVER nandwrite mtd4)"
            return 1
            ;;
    esac
}

require_fw_setenv() {
    if ! command -v fw_setenv >/dev/null 2>&1; then
        log "fw_setenv missing; refusing env write (NEVER nandwrite mtd4)"
        return 1
    fi
    if ! command -v fw_printenv >/dev/null 2>&1; then
        log "fw_printenv missing; refusing env write that cannot be verified"
        return 1
    fi
    if [ ! -f /etc/fw_env.config ] || [ -L /etc/fw_env.config ]; then
        log "/etc/fw_env.config missing or symlink; refusing fw_setenv"
        return 1
    fi
    return 0
}

apply_script() {
    ACTION=$1
    refuse_raw_mtd4 || return 1
    require_fw_setenv || return 1

    SCRIPT=$(mktemp /tmp/dcent_hw_unresolved.XXXXXX.env) || {
        log "cannot create fw_setenv --script temp file"
        return 1
    }
    case "$ACTION" in
        set) print_set_script >"$SCRIPT" ;;
        clear) print_clear_script >"$SCRIPT" ;;
        *)
            rm -f "$SCRIPT"
            usage
            return 1
            ;;
    esac

    log "applying $(print_apply_command "$SCRIPT")"
    if ! fw_setenv --script "$SCRIPT"; then
        rm -f "$SCRIPT"
        log "fw_setenv --script failed; env not changed. NEVER nandwrite mtd4."
        return 1
    fi
    rm -f "$SCRIPT"

    GOT=$(fw_printenv "$ENV_NAME" 2>/dev/null || true)
    case "$ACTION" in
        set)
            case "$GOT" in
                "$ENV_NAME=$ENV_SET_VALUE") return 0 ;;
                *)
                    log "post-apply fw_printenv mismatch (got '${GOT:-<empty>}')"
                    return 1
                    ;;
            esac
            ;;
        clear)
            case "$GOT" in
                "$ENV_NAME="*|"$ENV_NAME "*)
                    log "post-clear fw_printenv still has $ENV_NAME"
                    return 1
                    ;;
                *) return 0 ;;
            esac
            ;;
    esac
}

self_test() {
    FAILURES=0
    SET_PAYLOAD=$(print_set_script)
    CLEAR_PAYLOAD=$(print_clear_script)
    [ "$SET_PAYLOAD" = "$ENV_NAME $ENV_SET_VALUE" ] || {
        log "self-test: print-set payload mismatch"
        FAILURES=$((FAILURES + 1))
    }
    [ "$CLEAR_PAYLOAD" = "$ENV_NAME" ] || {
        log "self-test: print-clear payload mismatch"
        FAILURES=$((FAILURES + 1))
    }
    APPLY_CMD=$(print_apply_command /tmp/example.env)
    case "$APPLY_CMD" in
        "fw_setenv --script /tmp/example.env") ;;
        *)
            log "self-test: apply command is not fw_setenv --script"
            FAILURES=$((FAILURES + 1))
            ;;
    esac

    # Apply without fw_setenv must fail closed (host/desk).
    if command -v fw_setenv >/dev/null 2>&1; then
        log "self-test: fw_setenv present on PATH; skip missing-tool apply refusal"
    else
        if apply_script set >/dev/null 2>&1; then
            log "self-test: apply succeeded without fw_setenv"
            FAILURES=$((FAILURES + 1))
        fi
    fi

    DCENT_FORCE_NANDWRITE_MTD4=1
    export DCENT_FORCE_NANDWRITE_MTD4
    if apply_script set >/dev/null 2>&1; then
        log "self-test: apply did not refuse forced nandwrite alias"
        FAILURES=$((FAILURES + 1))
    fi
    unset DCENT_FORCE_NANDWRITE_MTD4

    [ "$FAILURES" -eq 0 ]
}

case "${1:-}" in
    print-set)
        print_set_script
        ;;
    print-clear)
        print_clear_script
        ;;
    set)
        apply_script set
        ;;
    clear)
        apply_script clear
        ;;
    self-test)
        self_test
        ;;
    *)
        usage
        exit 1
        ;;
esac
