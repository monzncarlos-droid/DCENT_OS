#!/bin/sh
# Fail-closed capability reader for root-owned DCENTos mutation policy files.

dcent_mutation_policy_has() {
    policy_file=$1
    capability=$2
    [ -f "$policy_file" ] && [ ! -L "$policy_file" ] && [ -r "$policy_file" ] || return 1

    policy_uid=$(stat -c '%u' "$policy_file" 2>/dev/null) || return 1
    [ "$policy_uid" = 0 ] || return 1
    policy_mode=$(stat -c '%a' "$policy_file" 2>/dev/null) || return 1
    case "$policy_mode" in
        400|440|444|600|640|644) ;;
        *) return 1 ;;
    esac

    grep -F -x "$capability" "$policy_file" >/dev/null 2>&1 || \
        grep -F -x hardware-enabled "$policy_file" >/dev/null 2>&1
}
