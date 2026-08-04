#!/bin/sh
# Refuse slot transitions that could split or strand a persistent dev deploy.

dcent_deploy_upgrade_guard() {
    DCENT_DEPLOY_UPGRADE_BASE=${1:-/data/.dcent-deploy-recovery}
    DCENT_DEPLOY_UPGRADE_BINARY=${2:-/data/dcentrald}
    DCENT_DEPLOY_UPGRADE_MAINTENANCE=${3:-/run/dcentos-deploy-maintenance}

    if [ -e "$DCENT_DEPLOY_UPGRADE_MAINTENANCE" ] \
        || [ -L "$DCENT_DEPLOY_UPGRADE_MAINTENANCE" ]; then
        echo "Error: firmware transition blocked by active deploy maintenance" >&2
        return 1
    fi

    if [ -e "$DCENT_DEPLOY_UPGRADE_BASE" ] \
        || [ -L "$DCENT_DEPLOY_UPGRADE_BASE" ]; then
        [ -d "$DCENT_DEPLOY_UPGRADE_BASE" ] \
            && [ ! -L "$DCENT_DEPLOY_UPGRADE_BASE" ] || {
            echo "Error: firmware transition blocked by malformed deploy recovery base" >&2
            return 1
        }
        [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_UPGRADE_BASE" 2>/dev/null)" = "0:700" ] || {
            echo "Error: firmware transition blocked by unsafe deploy recovery base metadata" >&2
            return 1
        }
        if [ -e "$DCENT_DEPLOY_UPGRADE_BASE/.deploy-lease" ] \
            || [ -L "$DCENT_DEPLOY_UPGRADE_BASE/.deploy-lease" ]; then
            echo "Error: firmware transition blocked by active persistent deploy lease" >&2
            return 1
        fi
        set -- "$DCENT_DEPLOY_UPGRADE_BASE"/*/persistent-transaction.state
        if [ -e "$1" ] || [ -L "$1" ]; then
            echo "Error: firmware transition blocked by pending persistent deploy transaction" >&2
            return 1
        fi
    fi

    # The inactive-slot sync currently migrates operator config, not dev binary
    # and transaction evidence. Refuse that split-generation transition. A
    # future migration must copy and verify all three as one explicit schema.
    if [ -e "$DCENT_DEPLOY_UPGRADE_BINARY" ] \
        || [ -L "$DCENT_DEPLOY_UPGRADE_BINARY" ]; then
        echo "Error: firmware transition blocked by persistent dev binary override" >&2
        return 1
    fi
    return 0
}
