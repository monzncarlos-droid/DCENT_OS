#!/bin/sh
# Fail-closed resolver for interrupted persistent dev-deploy transactions.
#
# This file is sourced by S82dcentrald before it selects /data/dcentrald. A
# pending, durable transaction is either verified as a complete candidate or
# rolled back as one binary/config generation. Invalid or ambiguous evidence
# refuses daemon admission; no manifest value is evaluated as shell input.

DCENT_DEPLOY_PATH_HELPER=${DCENT_DEPLOY_PATH_HELPER:-/usr/libexec/dcentos/dcentos-deploy-path}
DCENT_DEPLOY_PATH_PROBE_DIR=${DCENT_DEPLOY_PATH_PROBE_DIR:-/data}

dcent_deploy_path_helper_ready() {
    DCENT_DEPLOY_PATH_EXPECTED_UID=${DCENT_DEPLOY_EXPECTED_UID:-0}
    [ -x "$DCENT_DEPLOY_PATH_HELPER" ] \
        && [ ! -L "$DCENT_DEPLOY_PATH_HELPER" ] \
        && [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_PATH_HELPER" 2>/dev/null)" \
            = "$DCENT_DEPLOY_PATH_EXPECTED_UID:755" ]
}

dcent_deploy_retire_path() {
    dcent_deploy_path_helper_ready || return 1
    "$DCENT_DEPLOY_PATH_HELPER" retire "$1" "$2"
}

dcent_deploy_restore_path_alias() {
    dcent_deploy_path_helper_ready || return 1
    "$DCENT_DEPLOY_PATH_HELPER" restore-link "$1" "$2"
}

dcent_deploy_print_capabilities() {
    dcent_deploy_path_helper_ready || return 1
    "$DCENT_DEPLOY_PATH_HELPER" probe "$DCENT_DEPLOY_PATH_PROBE_DIR" || return 1
    printf 'DCENT_DEPLOY_RECOVERY_SCHEMA_MIN=3\n'
    printf 'DCENT_DEPLOY_RECOVERY_SCHEMA_MAX=4\n'
}

dcent_deploy_state_value() {
    DCENT_DEPLOY_STATE_FILE=$1
    DCENT_DEPLOY_STATE_KEY=$2
    awk -v prefix="$DCENT_DEPLOY_STATE_KEY=" '
        index($0, prefix) == 1 {
            count++
            value = substr($0, length(prefix) + 1)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    ' "$DCENT_DEPLOY_STATE_FILE" 2>/dev/null
}

dcent_deploy_sha256() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    sha256sum "$1" 2>/dev/null | awk 'NF == 2 { print $1 }'
}

dcent_deploy_hash_is_sha256() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{64}$'
}

dcent_deploy_config_metadata_is_safe() {
    DCENT_DEPLOY_CONFIG_META=$(stat -c '%u:%g:%a' "$1" 2>/dev/null) || return 1
    case "$DCENT_DEPLOY_CONFIG_META" in
        "$DCENT_DEPLOY_EXPECTED_UID":0:[0-7][0145][0145]) ;;
        *) return 1 ;;
    esac
}

dcent_deploy_sync() {
    sync
}

dcent_deploy_path_is_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

dcent_deploy_classify_absent_original_config() {
    DCENT_DEPLOY_ABSENT_CONFIG_STATE=invalid
    if dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH"; then
        DCENT_DEPLOY_ABSENT_CONFIG_STATE=absent
        return 0
    fi
    [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_CONFIG_PATH")" \
        = "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_CONFIG_PATH" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:0:600" ] || return 1
    DCENT_DEPLOY_ABSENT_CONFIG_STATE=candidate
}

# Retire an absent-original candidate without a check-to-unlink race. The
# quarantine has one deterministic, transaction-owned pathname so recovery can
# reconcile a power cut after every individual rename/removal. It must be
# absent before any terminal transaction record can be published.
dcent_deploy_set_config_retirement_paths() {
    [ -n "${DCENT_DEPLOY_RUN_DIR:-}" ] || return 1
    DCENT_DEPLOY_QUARANTINE_DIR="$DCENT_DEPLOY_RUN_DIR/config-retirement"
    DCENT_DEPLOY_QUARANTINED_CONFIG="$DCENT_DEPLOY_QUARANTINE_DIR/observed"
}

dcent_deploy_validate_config_retirement_dir() {
    dcent_deploy_set_config_retirement_paths || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINE_DIR" && return 0
    [ -d "$DCENT_DEPLOY_QUARANTINE_DIR" ] \
        && [ ! -L "$DCENT_DEPLOY_QUARANTINE_DIR" ] || return 1
    [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_QUARANTINE_DIR" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ] || return 1
    DCENT_DEPLOY_QUARANTINE_ENTRY_COUNT=$(find "$DCENT_DEPLOY_QUARANTINE_DIR" \
        -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l) || return 1
    case "$DCENT_DEPLOY_QUARANTINE_ENTRY_COUNT" in
        0) ;;
        1)
            [ -e "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] \
                || [ -L "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] || return 1
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_restore_quarantined_config() {
    [ -e "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] \
        || [ -L "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH" || return 1
    dcent_deploy_restore_path_alias "$DCENT_DEPLOY_QUARANTINED_CONFIG" \
        "$DCENT_DEPLOY_CONFIG_PATH" || return 1
    ! dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINED_CONFIG" \
        && ! dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH"
}

dcent_deploy_remove_config_retirement_dir() {
    rm -f "$DCENT_DEPLOY_QUARANTINED_CONFIG" || return 1
    dcent_deploy_sync || return 1
    rmdir "$DCENT_DEPLOY_QUARANTINE_DIR" || return 1
    dcent_deploy_sync || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINE_DIR"
}

dcent_deploy_reconcile_config_retirement() {
    dcent_deploy_validate_config_retirement_dir || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINE_DIR" && return 0
    if [ "$DCENT_DEPLOY_QUARANTINE_ENTRY_COUNT" -eq 0 ]; then
        rmdir "$DCENT_DEPLOY_QUARANTINE_DIR" || return 1
        dcent_deploy_sync || return 1
        dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINE_DIR"
        return $?
    fi

    # Never delete either name when both exist. Older link-based recovery can
    # leave aliases, but inode comparison followed by unlink is itself racy;
    # retaining both objects is the only generally safe automatic action.
    if ! dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH"; then
        echo "  [FAIL] Live and quarantined config objects require manual recovery" >&2
        return 1
    fi

    if [ -f "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] \
        && [ ! -L "$DCENT_DEPLOY_QUARANTINED_CONFIG" ] \
        && [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_QUARANTINED_CONFIG")" \
            = "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" ] \
        && [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_QUARANTINED_CONFIG" 2>/dev/null)" \
            = "$DCENT_DEPLOY_EXPECTED_UID:0:600" ]; then
        dcent_deploy_remove_config_retirement_dir || return 1
        dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH"
        return $?
    fi

    if dcent_deploy_restore_quarantined_config; then
        dcent_deploy_sync || return 1
        echo "  [FAIL] Out-of-band config replacement was restored with a retained private alias; recovery remains blocked" >&2
    else
        echo "  [FAIL] Out-of-band config replacement retained at $DCENT_DEPLOY_QUARANTINED_CONFIG" >&2
    fi
    return 1
}

dcent_deploy_retire_absent_original_config() {
    dcent_deploy_reconcile_config_retirement || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_CONFIG_PATH" && return 0
    mkdir -m 700 "$DCENT_DEPLOY_QUARANTINE_DIR" || return 1
    dcent_deploy_sync || return 1
    if ! dcent_deploy_retire_path "$DCENT_DEPLOY_CONFIG_PATH" \
        "$DCENT_DEPLOY_QUARANTINED_CONFIG"; then
        rmdir "$DCENT_DEPLOY_QUARANTINE_DIR" 2>/dev/null || true
        dcent_deploy_sync || true
        return 1
    fi
    dcent_deploy_sync || return 1
    dcent_deploy_reconcile_config_retirement
}

dcent_deploy_set_resolved_binding() {
    case "$1:$2:$3" in
        data:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG":*|etc:"$DCENT_DEPLOY_EXPECTED_ETC_CONFIG":*)
            dcent_deploy_hash_is_sha256 "$3" || return 1
            ;;
        builtin:builtin:NONE) ;;
        *) return 1 ;;
    esac
    DCENT_DEPLOY_RESOLVED_CONFIG_SOURCE=$1
    DCENT_DEPLOY_RESOLVED_CONFIG_PATH=$2
    DCENT_DEPLOY_RESOLVED_CONFIG_SHA=$3
    DCENT_DEPLOY_RESOLVED_DATA_CONFIG=$DCENT_DEPLOY_EXPECTED_DATA_CONFIG
    DCENT_DEPLOY_RESOLVED_ETC_CONFIG=$DCENT_DEPLOY_EXPECTED_ETC_CONFIG
    DCENT_DEPLOY_CONFIG_BINDING_ACTIVE=1
}

dcent_verify_resolved_deploy_config() {
    case "${DCENT_DEPLOY_RESOLVED_CONFIG_SOURCE:-}" in
        "")
            return 0
            ;;
        data)
            [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_RESOLVED_CONFIG_PATH")" \
                = "$DCENT_DEPLOY_RESOLVED_CONFIG_SHA" ] \
                && dcent_deploy_config_metadata_is_safe \
                    "$DCENT_DEPLOY_RESOLVED_CONFIG_PATH"
            ;;
        etc)
            dcent_deploy_path_is_absent "$DCENT_DEPLOY_RESOLVED_DATA_CONFIG" \
                && [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_RESOLVED_CONFIG_PATH")" \
                    = "$DCENT_DEPLOY_RESOLVED_CONFIG_SHA" ] \
                && dcent_deploy_config_metadata_is_safe \
                    "$DCENT_DEPLOY_RESOLVED_CONFIG_PATH"
            ;;
        builtin)
            dcent_deploy_path_is_absent "$DCENT_DEPLOY_RESOLVED_DATA_CONFIG" \
                && dcent_deploy_path_is_absent "$DCENT_DEPLOY_RESOLVED_ETC_CONFIG"
            ;;
        *)
            return 1
            ;;
    esac
}

dcent_deploy_set_candidate_binary_binding() {
    DCENT_DEPLOY_RESOLVED_BINARY_SOURCE=data
    DCENT_DEPLOY_RESOLVED_BINARY_PATH=$DCENT_DEPLOY_BINARY_PATH
    DCENT_DEPLOY_RESOLVED_BINARY_SHA=$DCENT_DEPLOY_BINARY_CANDIDATE_SHA
}

dcent_deploy_set_prior_binary_binding() {
    if [ "$DCENT_DEPLOY_BINARY_ORIGINAL_STATUS" = present ] \
        && [ -x "$DCENT_DEPLOY_BINARY_PATH" ]; then
        DCENT_DEPLOY_RESOLVED_BINARY_SOURCE=data
        DCENT_DEPLOY_RESOLVED_BINARY_PATH=$DCENT_DEPLOY_BINARY_PATH
        DCENT_DEPLOY_RESOLVED_BINARY_SHA=$DCENT_DEPLOY_BINARY_ORIGINAL_SHA
    elif [ -x "$DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY" ]; then
        DCENT_DEPLOY_RESOLVED_BINARY_SOURCE=fallback
        DCENT_DEPLOY_RESOLVED_BINARY_PATH=$DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY
        DCENT_DEPLOY_RESOLVED_BINARY_SHA=$(dcent_deploy_sha256 \
            "$DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY") || return 1
        dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_RESOLVED_BINARY_SHA" || return 1
    else
        DCENT_DEPLOY_RESOLVED_BINARY_SOURCE=none
        DCENT_DEPLOY_RESOLVED_BINARY_PATH=$DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY
        DCENT_DEPLOY_RESOLVED_BINARY_SHA=NONE
    fi
}

dcent_verify_resolved_deploy_binary() {
    case "${DCENT_DEPLOY_RESOLVED_BINARY_SOURCE:-}" in
        "") return 0 ;;
        data)
            [ -x "$DCENT_DEPLOY_RESOLVED_BINARY_PATH" ] \
                && [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_RESOLVED_BINARY_PATH")" \
                = "$DCENT_DEPLOY_RESOLVED_BINARY_SHA" ]
            ;;
        fallback)
            [ ! -x "$DCENT_DEPLOY_EXPECTED_BINARY" ] \
                && [ -x "$DCENT_DEPLOY_RESOLVED_BINARY_PATH" ] \
                && [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_RESOLVED_BINARY_PATH")" \
                    = "$DCENT_DEPLOY_RESOLVED_BINARY_SHA" ]
            ;;
        none)
            [ ! -x "$DCENT_DEPLOY_EXPECTED_BINARY" ] \
                && [ ! -x "$DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY" ]
            ;;
        *) return 1 ;;
    esac
}

dcent_verify_resolved_deploy_generation() {
    dcent_verify_resolved_deploy_binary \
        && dcent_verify_resolved_deploy_config
}

dcent_verify_resolved_deploy_selection() {
    DCENT_DEPLOY_SELECTED_BINARY=$1
    DCENT_DEPLOY_SELECTED_CONFIG=$2
    [ "${DCENT_DEPLOY_CONFIG_BINDING_ACTIVE:-0}" -eq 1 ] || return 0
    [ "$DCENT_DEPLOY_SELECTED_BINARY" = "$DCENT_DEPLOY_RESOLVED_BINARY_PATH" ] || return 1
    case "$DCENT_DEPLOY_RESOLVED_CONFIG_SOURCE" in
        data|etc)
            [ "$DCENT_DEPLOY_SELECTED_CONFIG" = "$DCENT_DEPLOY_RESOLVED_CONFIG_PATH" ]
            ;;
        builtin)
            [ "$DCENT_DEPLOY_SELECTED_CONFIG" = "$DCENT_DEPLOY_EXPECTED_ETC_CONFIG" ]
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_set_candidate_binding() {
    case "$DCENT_DEPLOY_CONFIG_SOURCE:$DCENT_DEPLOY_CONFIG_PATH" in
        explicit:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG"|discovered:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG")
            dcent_deploy_set_resolved_binding data "$DCENT_DEPLOY_CONFIG_PATH" \
                "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA"
            ;;
        discovered:"$DCENT_DEPLOY_EXPECTED_ETC_CONFIG")
            dcent_deploy_set_resolved_binding etc "$DCENT_DEPLOY_CONFIG_PATH" \
                "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA"
            ;;
        builtin:builtin)
            dcent_deploy_set_resolved_binding builtin builtin NONE
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_set_rollback_binding() {
    dcent_deploy_set_resolved_binding "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE" \
        "$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH" "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA"
}

# Before rollback, an explicit /data candidate may already exist. Prove the
# independent old-generation selection without incorrectly requiring /data to
# be absent until that candidate has been removed.
dcent_deploy_validate_rollback_binding_before_restore() {
    case "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE" in
        data)
            if [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ]; then
                [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" = present ] || return 1
                [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_CONFIG_BACKUP")" \
                    = "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" ] || return 1
                [ "$DCENT_DEPLOY_SCHEMA" = dcent-persistent-tx-v3 ] \
                    || dcent_deploy_config_metadata_is_safe \
                        "$DCENT_DEPLOY_CONFIG_BACKUP" || return 1
            else
                [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH")" \
                    = "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" ] || return 1
                dcent_deploy_config_metadata_is_safe \
                    "$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH" || return 1
            fi
            ;;
        etc)
            [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH")" \
                = "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" ] || return 1
            dcent_deploy_config_metadata_is_safe \
                "$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH" || return 1
            [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] \
                || dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG" \
                || return 1
            ;;
        builtin)
            dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_ETC_CONFIG" \
                || return 1
            [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] \
                || dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG" \
                || return 1
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_validate_rollback_binding_live() {
    case "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE" in
        data)
            [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG")" \
                = "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" ] \
                && dcent_deploy_config_metadata_is_safe \
                    "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG"
            ;;
        etc)
            dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG" \
                && [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_EXPECTED_ETC_CONFIG")" \
                    = "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" ] \
                && dcent_deploy_config_metadata_is_safe \
                    "$DCENT_DEPLOY_EXPECTED_ETC_CONFIG"
            ;;
        builtin)
            dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_DATA_CONFIG" \
                && dcent_deploy_path_is_absent "$DCENT_DEPLOY_EXPECTED_ETC_CONFIG"
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_restore_copy() {
    DCENT_DEPLOY_RESTORE_LIVE=$1
    DCENT_DEPLOY_RESTORE_BACKUP=$2
    DCENT_DEPLOY_RESTORE_ID=$3
    DCENT_DEPLOY_RESTORE_SHA=$4
    DCENT_DEPLOY_RESTORE_METADATA=${5:-NONE}
    DCENT_DEPLOY_RESTORE_METADATA_POLICY=${6:-verify}
    DCENT_DEPLOY_RESTORE_TMP="${DCENT_DEPLOY_RESTORE_LIVE}.dcent-recover.${DCENT_DEPLOY_RESTORE_ID}"
    rm -f "$DCENT_DEPLOY_RESTORE_TMP" || return 1
    cp -p "$DCENT_DEPLOY_RESTORE_BACKUP" "$DCENT_DEPLOY_RESTORE_TMP" || return 1
    [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_RESTORE_TMP")" \
        = "$DCENT_DEPLOY_RESTORE_SHA" ] || return 1
    if [ "$DCENT_DEPLOY_RESTORE_METADATA_POLICY" = canonicalize ]; then
        [ "$DCENT_DEPLOY_RESTORE_METADATA" != NONE ] || return 1
        DCENT_DEPLOY_RESTORE_UID=${DCENT_DEPLOY_RESTORE_METADATA%%:*}
        DCENT_DEPLOY_RESTORE_MODE=${DCENT_DEPLOY_RESTORE_METADATA##*:}
        DCENT_DEPLOY_RESTORE_GID=${DCENT_DEPLOY_RESTORE_METADATA#*:}
        DCENT_DEPLOY_RESTORE_GID=${DCENT_DEPLOY_RESTORE_GID%:*}
        chown "$DCENT_DEPLOY_RESTORE_UID:$DCENT_DEPLOY_RESTORE_GID" \
            "$DCENT_DEPLOY_RESTORE_TMP" || return 1
        chmod "$DCENT_DEPLOY_RESTORE_MODE" "$DCENT_DEPLOY_RESTORE_TMP" || return 1
    elif [ "$DCENT_DEPLOY_RESTORE_METADATA_POLICY" != verify ]; then
        return 1
    fi
    [ "$DCENT_DEPLOY_RESTORE_METADATA" = NONE ] \
        || [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_RESTORE_TMP" 2>/dev/null)" \
            = "$DCENT_DEPLOY_RESTORE_METADATA" ] || return 1
    mv -f "$DCENT_DEPLOY_RESTORE_TMP" "$DCENT_DEPLOY_RESTORE_LIVE"
}

dcent_deploy_committed_matches_state() {
    awk '
        NR == FNR {
            expected[FNR] = $0
            expected_count = FNR
            next
        }
        {
            actual_count = FNR
            if (FNR == 3) {
                if ($0 != "PHASE=committed") bad = 1
            } else if ($0 != expected[FNR]) {
                bad = 1
            }
        }
        END {
            if (bad || actual_count != expected_count) exit 1
        }
    ' "$1" "$2"
}

# A power cut during committed-state revocation can leave a matching committed
# companion beside the authoritative pending state. Remove it only after the
# rollback terminal phase is durable, while that state still blocks admission.
dcent_deploy_remove_matching_committed() {
    DCENT_DEPLOY_STALE_COMMITTED="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.committed"
    [ -e "$DCENT_DEPLOY_STALE_COMMITTED" ] || return 0
    [ -f "$DCENT_DEPLOY_STALE_COMMITTED" ] \
        && [ ! -L "$DCENT_DEPLOY_STALE_COMMITTED" ] || return 1
    [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_STALE_COMMITTED" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ] || return 1
    dcent_deploy_committed_matches_state "$DCENT_DEPLOY_STATE" \
        "$DCENT_DEPLOY_STALE_COMMITTED" || return 1
    rm -f "$DCENT_DEPLOY_STALE_COMMITTED" || return 1
    dcent_deploy_sync
}

dcent_deploy_validate_prior_binary_live() {
    case "$DCENT_DEPLOY_BINARY_ORIGINAL_STATUS" in
        present)
            [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_BINARY_PATH")" \
                = "$DCENT_DEPLOY_BINARY_ORIGINAL_SHA" ] || return 1
            [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_BINARY_PATH" 2>/dev/null)" \
                = "$DCENT_DEPLOY_BINARY_ORIGINAL_METADATA" ] || return 1
            ;;
        absent)
            [ ! -e "$DCENT_DEPLOY_BINARY_PATH" ] || return 1
            ;;
        *) return 1 ;;
    esac
}

dcent_deploy_validate_prior_generation_live() {
    dcent_deploy_validate_prior_binary_live || return 1
    if [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] \
        && [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" = present ]; then
        [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" = NONE ] \
            || [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_CONFIG_PATH" 2>/dev/null)" \
                = "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" ] || return 1
    fi
    dcent_deploy_validate_rollback_binding_live
}

dcent_deploy_canonicalize_legacy_terminal_config() {
    [ "$DCENT_DEPLOY_SCHEMA" = dcent-persistent-tx-v3 ] || return 0
    [ "$DCENT_DEPLOY_CONFIG_MUTATED:$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" \
        = true:present ] || return 0
    [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_CONFIG_PATH")" \
        = "$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" ] || return 1
    if [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_CONFIG_PATH" 2>/dev/null)" \
        != "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" ]; then
        dcent_deploy_restore_copy "$DCENT_DEPLOY_CONFIG_PATH" \
            "$DCENT_DEPLOY_CONFIG_PATH" "$DCENT_DEPLOY_ID.legacy-v3" \
            "$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" \
            "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" canonicalize || return 1
        dcent_deploy_sync || return 1
    fi
}

# Publish a terminal record by hard-linking the already validated terminal
# state while that state still blocks admission. A failed final cleanup sync
# can only resurrect .state on reboot; the terminal name was already synced.
dcent_deploy_publish_terminal_copy() {
    DCENT_DEPLOY_PUBLISH_TARGET=$1
    DCENT_DEPLOY_PUBLISH_TMP="$DCENT_DEPLOY_PUBLISH_TARGET.new"
    DCENT_DEPLOY_PUBLISH_SHA=$(dcent_deploy_sha256 "$DCENT_DEPLOY_STATE") || return 1
    dcent_deploy_set_config_retirement_paths || return 1
    dcent_deploy_path_is_absent "$DCENT_DEPLOY_QUARANTINE_DIR" || return 1
    if ! dcent_deploy_path_is_absent "$DCENT_DEPLOY_PUBLISH_TARGET"; then
        [ -f "$DCENT_DEPLOY_PUBLISH_TARGET" ] \
            && [ ! -L "$DCENT_DEPLOY_PUBLISH_TARGET" ] || return 1
        cmp -s "$DCENT_DEPLOY_STATE" "$DCENT_DEPLOY_PUBLISH_TARGET" || return 1
    else
        ln -T "$DCENT_DEPLOY_STATE" "$DCENT_DEPLOY_PUBLISH_TARGET" || return 1
    fi
    [ -f "$DCENT_DEPLOY_PUBLISH_TARGET" ] \
        && [ ! -L "$DCENT_DEPLOY_PUBLISH_TARGET" ] || return 1
    cmp -s "$DCENT_DEPLOY_STATE" "$DCENT_DEPLOY_PUBLISH_TARGET" || return 1
    if [ "$(stat -c '%d:%i' "$DCENT_DEPLOY_STATE" 2>/dev/null)" \
        = "$(stat -c '%d:%i' "$DCENT_DEPLOY_PUBLISH_TARGET" 2>/dev/null)" ]; then
        [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_PUBLISH_TARGET" 2>/dev/null)" \
            = "$DCENT_DEPLOY_EXPECTED_UID:600:2" ] || return 1
    else
        [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_PUBLISH_TARGET" 2>/dev/null)" \
            = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ] || return 1
    fi
    dcent_deploy_sync || return 1
    # Legacy copy-first publication could leave an empty or partial `.new`.
    # Once the terminal target is durable, remove only a regular, private-dir
    # artifact; its contents are deliberately irrelevant to retry admission.
    if ! dcent_deploy_path_is_absent "$DCENT_DEPLOY_PUBLISH_TMP"; then
        [ -f "$DCENT_DEPLOY_PUBLISH_TMP" ] \
            && [ ! -L "$DCENT_DEPLOY_PUBLISH_TMP" ] || return 1
        case "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_PUBLISH_TMP" 2>/dev/null)" in
            "$DCENT_DEPLOY_EXPECTED_UID:600:1"|"$DCENT_DEPLOY_EXPECTED_UID:600:2") ;;
            *) return 1 ;;
        esac
        rm -f "$DCENT_DEPLOY_PUBLISH_TMP" || return 1
        dcent_deploy_sync || return 1
    fi
    rm -f "$DCENT_DEPLOY_STATE" || return 1
    # Failure here cannot erase the durable target. At worst .state reappears
    # after reboot and this idempotent path validates and removes it again.
    dcent_deploy_sync || true
    [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_PUBLISH_TARGET" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ] || return 1
    [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_PUBLISH_TARGET")" \
        = "$DCENT_DEPLOY_PUBLISH_SHA" ] || return 1
}

dcent_deploy_finish_terminal_state() {
    case "$DCENT_DEPLOY_PHASE" in
        recovered)
            DCENT_DEPLOY_TERMINAL="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.recovered"
            ;;
        rolled_back)
            DCENT_DEPLOY_TERMINAL="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.rolled-back"
            ;;
        *) return 1 ;;
    esac
    dcent_deploy_validate_prior_binary_live || return 1
    dcent_deploy_validate_rollback_binding_live || return 1
    dcent_deploy_canonicalize_legacy_terminal_config || return 1
    dcent_deploy_validate_prior_generation_live || return 1
    dcent_deploy_set_prior_binary_binding || return 1
    dcent_deploy_set_rollback_binding || return 1
    dcent_verify_resolved_deploy_generation || return 1
    dcent_deploy_remove_matching_committed || return 1
    dcent_deploy_publish_terminal_copy "$DCENT_DEPLOY_TERMINAL" || return 1
    dcent_deploy_release_matching_lease
}

dcent_deploy_validate_lease() {
    DCENT_DEPLOY_LEASE="$DCENT_DEPLOY_RECOVERY_BASE/.deploy-lease"
    DCENT_DEPLOY_LEASE_OWNER=
    [ -e "$DCENT_DEPLOY_LEASE" ] || [ -L "$DCENT_DEPLOY_LEASE" ] || return 0
    [ -d "$DCENT_DEPLOY_LEASE" ] && [ ! -L "$DCENT_DEPLOY_LEASE" ] || return 1
    [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_LEASE" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ] || return 1
    DCENT_DEPLOY_LEASE_OWNER_FILE="$DCENT_DEPLOY_LEASE/owner"
    [ -f "$DCENT_DEPLOY_LEASE_OWNER_FILE" ] \
        && [ ! -L "$DCENT_DEPLOY_LEASE_OWNER_FILE" ] || return 1
    [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_LEASE_OWNER_FILE" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ] || return 1
    DCENT_DEPLOY_LEASE_OWNER=$(cat "$DCENT_DEPLOY_LEASE_OWNER_FILE" 2>/dev/null) || return 1
    printf '%s\n' "$DCENT_DEPLOY_LEASE_OWNER" | grep -Eq '^[0-9a-f]{32}$' || return 1
}

dcent_deploy_synthesize_leased_terminal_state() {
    [ -n "$DCENT_DEPLOY_LEASE_OWNER" ] || return 1
    DCENT_DEPLOY_LEASE_RUN="$DCENT_DEPLOY_RECOVERY_BASE/$DCENT_DEPLOY_LEASE_OWNER"
    [ -d "$DCENT_DEPLOY_LEASE_RUN" ] && [ ! -L "$DCENT_DEPLOY_LEASE_RUN" ] || return 1
    [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_LEASE_RUN" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ] || return 1
    DCENT_DEPLOY_LEASE_TERMINAL=
    DCENT_DEPLOY_LEASE_TERMINAL_COUNT=0
    for DCENT_DEPLOY_LEASE_CANDIDATE in \
        "$DCENT_DEPLOY_LEASE_RUN/persistent-transaction.committed" \
        "$DCENT_DEPLOY_LEASE_RUN/persistent-transaction.recovered" \
        "$DCENT_DEPLOY_LEASE_RUN/persistent-transaction.rolled-back"
    do
        if [ -e "$DCENT_DEPLOY_LEASE_CANDIDATE" ] \
            || [ -L "$DCENT_DEPLOY_LEASE_CANDIDATE" ]; then
            [ -f "$DCENT_DEPLOY_LEASE_CANDIDATE" ] \
                && [ ! -L "$DCENT_DEPLOY_LEASE_CANDIDATE" ] || return 1
            DCENT_DEPLOY_LEASE_TERMINAL=$DCENT_DEPLOY_LEASE_CANDIDATE
            DCENT_DEPLOY_LEASE_TERMINAL_COUNT=$((DCENT_DEPLOY_LEASE_TERMINAL_COUNT + 1))
        fi
    done
    [ "$DCENT_DEPLOY_LEASE_TERMINAL_COUNT" -eq 1 ] || return 1
    [ "$(stat -c '%u:%a:%h' "$DCENT_DEPLOY_LEASE_TERMINAL" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ] || return 1
    DCENT_DEPLOY_LEASE_TERMINAL_LINES=$(wc -l < "$DCENT_DEPLOY_LEASE_TERMINAL" 2>/dev/null) || return 1
    DCENT_DEPLOY_LEASE_TERMINAL_SCHEMA=$(sed -n '1p' "$DCENT_DEPLOY_LEASE_TERMINAL") || return 1
    case "$DCENT_DEPLOY_LEASE_TERMINAL_SCHEMA:$DCENT_DEPLOY_LEASE_TERMINAL_LINES" in
        PERSISTENT_TX_STATE=dcent-persistent-tx-v3:19|PERSISTENT_TX_STATE=dcent-persistent-tx-v4:20) ;;
        *) return 1 ;;
    esac
    [ "$(sed -n '2p' "$DCENT_DEPLOY_LEASE_TERMINAL")" \
        = "DEPLOY_ID=$DCENT_DEPLOY_LEASE_OWNER" ] || return 1
    case "${DCENT_DEPLOY_LEASE_TERMINAL##*/}" in
        persistent-transaction.committed)
            DCENT_DEPLOY_LEASE_EXPECTED_PHASE=committed
            ;;
        persistent-transaction.recovered)
            DCENT_DEPLOY_LEASE_EXPECTED_PHASE=recovered
            ;;
        persistent-transaction.rolled-back)
            DCENT_DEPLOY_LEASE_EXPECTED_PHASE=rolled_back
            ;;
        *) return 1 ;;
    esac
    [ "$(sed -n '3p' "$DCENT_DEPLOY_LEASE_TERMINAL")" \
        = "PHASE=$DCENT_DEPLOY_LEASE_EXPECTED_PHASE" ] || return 1
    DCENT_DEPLOY_LEASE_STATE="$DCENT_DEPLOY_LEASE_RUN/persistent-transaction.state"
    DCENT_DEPLOY_LEASE_STATE_TMP="$DCENT_DEPLOY_LEASE_STATE.lease-recover.new"
    [ ! -e "$DCENT_DEPLOY_LEASE_STATE" ] && [ ! -L "$DCENT_DEPLOY_LEASE_STATE" ] || return 1
    rm -f "$DCENT_DEPLOY_LEASE_STATE_TMP" || return 1
    cp -p "$DCENT_DEPLOY_LEASE_TERMINAL" "$DCENT_DEPLOY_LEASE_STATE_TMP" || return 1
    chmod 600 "$DCENT_DEPLOY_LEASE_STATE_TMP" || return 1
    cmp -s "$DCENT_DEPLOY_LEASE_TERMINAL" "$DCENT_DEPLOY_LEASE_STATE_TMP" || return 1
    mv "$DCENT_DEPLOY_LEASE_STATE_TMP" "$DCENT_DEPLOY_LEASE_STATE" || return 1
    dcent_deploy_sync || return 1
}

dcent_deploy_release_matching_lease() {
    [ -n "${DCENT_DEPLOY_LEASE_OWNER:-}" ] || return 0
    [ "$DCENT_DEPLOY_LEASE_OWNER" = "$DCENT_DEPLOY_ID" ] || return 1
    [ "$(cat "$DCENT_DEPLOY_LEASE_OWNER_FILE" 2>/dev/null)" \
        = "$DCENT_DEPLOY_ID" ] || return 1
    DCENT_DEPLOY_RETIRED_LEASE="$DCENT_DEPLOY_RUN_DIR/deploy-lease.released"
    [ ! -e "$DCENT_DEPLOY_RETIRED_LEASE" ] \
        && [ ! -L "$DCENT_DEPLOY_RETIRED_LEASE" ] || return 1
    # Rename the complete lease directory on the same filesystem. A crash can
    # expose either the active lease or the retired audit marker, never an
    # ownerless active directory that blocks admission permanently.
    mv "$DCENT_DEPLOY_LEASE" "$DCENT_DEPLOY_RETIRED_LEASE" || return 1
    dcent_deploy_sync || return 1
    DCENT_DEPLOY_LEASE_OWNER=
}

dcent_recover_pending_deploy() {
    DCENT_DEPLOY_RECOVERY_BASE=$1
    DCENT_DEPLOY_EXPECTED_BINARY=$2
    DCENT_DEPLOY_EXPECTED_DATA_CONFIG=${3:-/data/dcentrald.toml}
    DCENT_DEPLOY_EXPECTED_ETC_CONFIG=${4:-/etc/dcentrald.toml}
    DCENT_DEPLOY_EXPECTED_FALLBACK_BINARY=${5:-/usr/local/bin/dcentrald}
    DCENT_DEPLOY_CONFIG_BINDING_ACTIVE=0

    [ -e "$DCENT_DEPLOY_RECOVERY_BASE" ] \
        || [ -L "$DCENT_DEPLOY_RECOVERY_BASE" ] || return 0
    [ -d "$DCENT_DEPLOY_RECOVERY_BASE" ] \
        && [ ! -L "$DCENT_DEPLOY_RECOVERY_BASE" ] || return 1
    DCENT_DEPLOY_EXPECTED_UID=$(id -u 2>/dev/null) || return 1
    [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_RECOVERY_BASE" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ] || return 1
    dcent_deploy_validate_lease || return 1
    set -- "$DCENT_DEPLOY_RECOVERY_BASE"/*/persistent-transaction.state
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        [ -n "$DCENT_DEPLOY_LEASE_OWNER" ] || return 0
        dcent_deploy_synthesize_leased_terminal_state || return 1
        set -- "$DCENT_DEPLOY_RECOVERY_BASE/$DCENT_DEPLOY_LEASE_OWNER/persistent-transaction.state"
    fi
    [ "$#" -eq 1 ] || {
        echo "  [FAIL] Multiple pending persistent deploy transactions require manual recovery" >&2
        return 1
    }
    DCENT_DEPLOY_STATE=$1
    if [ -n "$DCENT_DEPLOY_LEASE_OWNER" ]; then
        [ "${DCENT_DEPLOY_STATE%/persistent-transaction.state}" \
            = "$DCENT_DEPLOY_RECOVERY_BASE/$DCENT_DEPLOY_LEASE_OWNER" ] || return 1
    fi
    [ -f "$DCENT_DEPLOY_STATE" ] && [ ! -L "$DCENT_DEPLOY_STATE" ] || return 1
    DCENT_DEPLOY_STATE_METADATA=$(stat -c '%u:%a:%h' \
        "$DCENT_DEPLOY_STATE" 2>/dev/null) || return 1
    case "$DCENT_DEPLOY_STATE_METADATA" in
        "$DCENT_DEPLOY_EXPECTED_UID:600:1")
            DCENT_DEPLOY_STATE_NLINK=1
            ;;
        "$DCENT_DEPLOY_EXPECTED_UID:600:2")
            DCENT_DEPLOY_STATE_NLINK=2
            ;;
        *) return 1 ;;
    esac
    DCENT_DEPLOY_STATE_LINES=$(wc -l < "$DCENT_DEPLOY_STATE" 2>/dev/null) || return 1
    DCENT_DEPLOY_STATE_SCHEMA_LINE=$(sed -n '1p' "$DCENT_DEPLOY_STATE") || return 1
    case "$DCENT_DEPLOY_STATE_SCHEMA_LINE:$DCENT_DEPLOY_STATE_LINES" in
        PERSISTENT_TX_STATE=dcent-persistent-tx-v3:19) DCENT_DEPLOY_STATE_HAS_CONFIG_METADATA=false ;;
        PERSISTENT_TX_STATE=dcent-persistent-tx-v4:20) DCENT_DEPLOY_STATE_HAS_CONFIG_METADATA=true ;;
        *) return 1 ;;
    esac
    awk -F= -v expected_count="$DCENT_DEPLOY_STATE_LINES" '
        BEGIN {
            expected[1] = "PERSISTENT_TX_STATE"
            expected[2] = "DEPLOY_ID"
            expected[3] = "PHASE"
            expected[4] = "BINARY_PATH"
            expected[5] = "BINARY_ORIGINAL_STATUS"
            expected[6] = "BINARY_ORIGINAL_SHA256"
            expected[7] = "BINARY_BACKUP_PATH"
            expected[8] = "BINARY_CANDIDATE_SHA256"
            expected[9] = "CONFIG_MUTATED"
            expected[10] = "CONFIG_SOURCE"
            expected[11] = "CONFIG_PATH"
            expected[12] = "CONFIG_ORIGINAL_STATUS"
            expected[13] = "CONFIG_ORIGINAL_SHA256"
            expected[14] = "CONFIG_BACKUP_PATH"
            expected[15] = "CONFIG_CANDIDATE_SHA256"
            expected[16] = "ROLLBACK_CONFIG_SOURCE"
            expected[17] = "ROLLBACK_CONFIG_PATH"
            expected[18] = "ROLLBACK_CONFIG_SHA256"
            expected[19] = "BINARY_ORIGINAL_METADATA"
            expected[20] = "CONFIG_ORIGINAL_METADATA"
        }
        $1 != expected[NR] { exit 1 }
        END { if (NR != expected_count) exit 1 }
    ' "$DCENT_DEPLOY_STATE" || return 1

    DCENT_DEPLOY_SCHEMA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" PERSISTENT_TX_STATE) || return 1
    DCENT_DEPLOY_ID=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" DEPLOY_ID) || return 1
    DCENT_DEPLOY_PHASE=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" PHASE) || return 1
    DCENT_DEPLOY_BINARY_PATH=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_PATH) || return 1
    DCENT_DEPLOY_BINARY_ORIGINAL_STATUS=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_ORIGINAL_STATUS) || return 1
    DCENT_DEPLOY_BINARY_ORIGINAL_SHA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_ORIGINAL_SHA256) || return 1
    DCENT_DEPLOY_BINARY_BACKUP=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_BACKUP_PATH) || return 1
    DCENT_DEPLOY_BINARY_CANDIDATE_SHA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_CANDIDATE_SHA256) || return 1
    DCENT_DEPLOY_CONFIG_MUTATED=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_MUTATED) || return 1
    DCENT_DEPLOY_CONFIG_SOURCE=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_SOURCE) || return 1
    DCENT_DEPLOY_CONFIG_PATH=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_PATH) || return 1
    DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_ORIGINAL_STATUS) || return 1
    DCENT_DEPLOY_CONFIG_ORIGINAL_SHA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_ORIGINAL_SHA256) || return 1
    DCENT_DEPLOY_CONFIG_BACKUP=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_BACKUP_PATH) || return 1
    DCENT_DEPLOY_CONFIG_CANDIDATE_SHA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_CANDIDATE_SHA256) || return 1
    DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" ROLLBACK_CONFIG_SOURCE) || return 1
    DCENT_DEPLOY_ROLLBACK_CONFIG_PATH=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" ROLLBACK_CONFIG_PATH) || return 1
    DCENT_DEPLOY_ROLLBACK_CONFIG_SHA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" ROLLBACK_CONFIG_SHA256) || return 1
    DCENT_DEPLOY_BINARY_ORIGINAL_METADATA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" BINARY_ORIGINAL_METADATA) || return 1
    if [ "$DCENT_DEPLOY_STATE_HAS_CONFIG_METADATA" = true ]; then
        DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA=$(dcent_deploy_state_value "$DCENT_DEPLOY_STATE" CONFIG_ORIGINAL_METADATA) || return 1
    else
        case "$DCENT_DEPLOY_CONFIG_MUTATED:$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" in
            true:present)
                DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA="$DCENT_DEPLOY_EXPECTED_UID:0:600"
                ;;
            *) DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA=NONE ;;
        esac
    fi

    case "$DCENT_DEPLOY_SCHEMA:$DCENT_DEPLOY_STATE_HAS_CONFIG_METADATA" in
        dcent-persistent-tx-v3:false|dcent-persistent-tx-v4:true) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$DCENT_DEPLOY_ID" | grep -Eq '^[0-9a-f]{32}$' || return 1
    DCENT_DEPLOY_RUN_DIR=${DCENT_DEPLOY_STATE%/persistent-transaction.state}
    [ "$DCENT_DEPLOY_RUN_DIR" = "$DCENT_DEPLOY_RECOVERY_BASE/$DCENT_DEPLOY_ID" ] || return 1
    [ -d "$DCENT_DEPLOY_RUN_DIR" ] && [ ! -L "$DCENT_DEPLOY_RUN_DIR" ] || return 1
    [ "$(stat -c '%u:%a' "$DCENT_DEPLOY_RUN_DIR" 2>/dev/null)" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ] || return 1
    if [ "$DCENT_DEPLOY_STATE_NLINK" -eq 2 ]; then
        case "$DCENT_DEPLOY_PHASE" in
            committed)
                DCENT_DEPLOY_LINKED_TERMINAL="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.committed"
                ;;
            recovered)
                DCENT_DEPLOY_LINKED_TERMINAL="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.recovered"
                ;;
            rolled_back)
                DCENT_DEPLOY_LINKED_TERMINAL="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.rolled-back"
                ;;
            *) return 1 ;;
        esac
        [ -f "$DCENT_DEPLOY_LINKED_TERMINAL" ] \
            && [ ! -L "$DCENT_DEPLOY_LINKED_TERMINAL" ] || return 1
        DCENT_DEPLOY_STATE_IDENTITY=$(stat -c '%d:%i' \
            "$DCENT_DEPLOY_STATE" 2>/dev/null) || return 1
        [ "$(stat -c '%u:%a:%h:%d:%i' "$DCENT_DEPLOY_LINKED_TERMINAL" 2>/dev/null)" \
            = "$DCENT_DEPLOY_EXPECTED_UID:600:2:$DCENT_DEPLOY_STATE_IDENTITY" ] \
            || return 1
    fi
    [ "$DCENT_DEPLOY_BINARY_PATH" = "$DCENT_DEPLOY_EXPECTED_BINARY" ] || return 1
    [ "$DCENT_DEPLOY_BINARY_BACKUP" = "$DCENT_DEPLOY_RUN_DIR/dcentrald.backup" ] || return 1
    dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_BINARY_CANDIDATE_SHA" || return 1
    case "$DCENT_DEPLOY_PHASE" in
        prepared|mutating|installed|failed|rolling_back|committed|recovered|rolled_back) ;;
        *) return 1 ;;
    esac
    case "$DCENT_DEPLOY_BINARY_ORIGINAL_STATUS:$DCENT_DEPLOY_BINARY_ORIGINAL_SHA:$DCENT_DEPLOY_BINARY_ORIGINAL_METADATA" in
        present:*:*)
            dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_BINARY_ORIGINAL_SHA" || return 1
            printf '%s\n' "$DCENT_DEPLOY_BINARY_ORIGINAL_METADATA" \
                | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$' || return 1
            ;;
        absent:NONE:NONE) ;;
        *) return 1 ;;
    esac
    case "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE:$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH:$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" in
        data:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG":*|etc:"$DCENT_DEPLOY_EXPECTED_ETC_CONFIG":*)
            dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" || return 1
            ;;
        builtin:builtin:NONE) ;;
        *) return 1 ;;
    esac
    case "$DCENT_DEPLOY_CONFIG_SOURCE:$DCENT_DEPLOY_CONFIG_PATH:$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" in
        explicit:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG":*)
            [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] || return 1
            dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" || return 1
            ;;
        discovered:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG":*|discovered:"$DCENT_DEPLOY_EXPECTED_ETC_CONFIG":*)
            [ "$DCENT_DEPLOY_CONFIG_MUTATED" = false ] || return 1
            dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" || return 1
            ;;
        builtin:builtin:NONE)
            [ "$DCENT_DEPLOY_CONFIG_MUTATED" = false ] || return 1
            ;;
        *) return 1 ;;
    esac
    case "$DCENT_DEPLOY_CONFIG_MUTATED:$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS:$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA:$DCENT_DEPLOY_CONFIG_BACKUP" in
        true:present:*:"$DCENT_DEPLOY_RUN_DIR/dcentrald.toml.backup")
            dcent_deploy_hash_is_sha256 "$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" || return 1
            case "$DCENT_DEPLOY_SCHEMA:$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" in
                dcent-persistent-tx-v3:*)
                    [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" \
                        = "$DCENT_DEPLOY_EXPECTED_UID:0:600" ] || return 1
                    ;;
                dcent-persistent-tx-v4:*)
                    printf '%s\n' "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" \
                        | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$' || return 1
                    ;;
                *) return 1 ;;
            esac
            [ "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE:$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH:$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" \
                = "data:$DCENT_DEPLOY_EXPECTED_DATA_CONFIG:$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" ] || return 1
            ;;
        true:absent:NONE:NONE)
            [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" = NONE ] || return 1
            case "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE" in etc|builtin) ;; *) return 1 ;; esac
            ;;
        false:not_captured:NONE:NONE)
            [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" = NONE ] || return 1
            case "$DCENT_DEPLOY_CONFIG_SOURCE:$DCENT_DEPLOY_CONFIG_PATH:$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" in
                discovered:"$DCENT_DEPLOY_EXPECTED_DATA_CONFIG":*)
                    [ "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE:$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH:$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" \
                        = "data:$DCENT_DEPLOY_CONFIG_PATH:$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" ] || return 1
                    ;;
                discovered:"$DCENT_DEPLOY_EXPECTED_ETC_CONFIG":*)
                    [ "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE:$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH:$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" \
                        = "etc:$DCENT_DEPLOY_CONFIG_PATH:$DCENT_DEPLOY_CONFIG_CANDIDATE_SHA" ] || return 1
                    ;;
                builtin:builtin:NONE)
                    [ "$DCENT_DEPLOY_ROLLBACK_CONFIG_SOURCE:$DCENT_DEPLOY_ROLLBACK_CONFIG_PATH:$DCENT_DEPLOY_ROLLBACK_CONFIG_SHA" \
                        = builtin:builtin:NONE ] || return 1
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac

    if pidof dcentrald >/dev/null 2>&1; then
        echo "  [FAIL] Refusing persistent deploy recovery while dcentrald may execute" >&2
        return 1
    fi

    # A terminal state may be durable while its final filename is not. Validate
    # the fully restored generation and complete the rename idempotently.
    case "$DCENT_DEPLOY_PHASE" in
        recovered|rolled_back)
            dcent_deploy_finish_terminal_state
            return $?
            ;;
    esac

    # A committed phase may exist briefly if power failed between the phase
    # sync and the final state-file rename. Complete it forward only after
    # proving the entire candidate generation.
    if [ "$DCENT_DEPLOY_PHASE" = committed ]; then
        [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_BINARY_PATH")" \
            = "$DCENT_DEPLOY_BINARY_CANDIDATE_SHA" ] || return 1
        [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_BINARY_PATH" 2>/dev/null)" \
            = "$DCENT_DEPLOY_EXPECTED_UID:0:755" ] || return 1
        if [ "$DCENT_DEPLOY_CONFIG_SOURCE" = explicit ]; then
            [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_CONFIG_PATH" 2>/dev/null)" \
                = "$DCENT_DEPLOY_EXPECTED_UID:0:600" ] || return 1
        fi
        dcent_deploy_set_candidate_binary_binding || return 1
        dcent_deploy_set_candidate_binding || return 1
        dcent_verify_resolved_deploy_generation || return 1
        DCENT_DEPLOY_COMMITTED="$DCENT_DEPLOY_RUN_DIR/persistent-transaction.committed"
        dcent_deploy_publish_terminal_copy "$DCENT_DEPLOY_COMMITTED" || return 1
        dcent_deploy_release_matching_lease || return 1
        return 0
    fi

    # Validate every required recovery artifact and the effective old config
    # selection before changing either live path. A bad fallback or backup must
    # never cause a binary-only rollback.
    if [ "$DCENT_DEPLOY_BINARY_ORIGINAL_STATUS" = present ]; then
        [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_BINARY_BACKUP")" \
            = "$DCENT_DEPLOY_BINARY_ORIGINAL_SHA" ] || return 1
        [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_BINARY_BACKUP" 2>/dev/null)" \
            = "$DCENT_DEPLOY_BINARY_ORIGINAL_METADATA" ] || return 1
    fi
    if [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] \
        && [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" = present ]; then
        [ "$(dcent_deploy_sha256 "$DCENT_DEPLOY_CONFIG_BACKUP")" \
            = "$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" ] || return 1
        [ "$DCENT_DEPLOY_SCHEMA" = dcent-persistent-tx-v3 ] \
            || [ "$(stat -c '%u:%g:%a' "$DCENT_DEPLOY_CONFIG_BACKUP" 2>/dev/null)" \
                = "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" ] || return 1
    fi
    DCENT_DEPLOY_ABSENT_CONFIG_STATE=not_applicable
    if [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ] \
        && [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" = absent ]; then
        # Reconcile a prior crash after the deterministic config-retirement
        # rename before treating live-path absence as evidence. A foreign object
        # restored from quarantine deliberately keeps this transaction pending.
        dcent_deploy_reconcile_config_retirement || return 1
        dcent_deploy_classify_absent_original_config || return 1
    fi
    dcent_deploy_validate_rollback_binding_before_restore || return 1

    if [ "$DCENT_DEPLOY_BINARY_ORIGINAL_STATUS" = present ]; then
        dcent_deploy_restore_copy "$DCENT_DEPLOY_BINARY_PATH" \
            "$DCENT_DEPLOY_BINARY_BACKUP" "$DCENT_DEPLOY_ID" \
            "$DCENT_DEPLOY_BINARY_ORIGINAL_SHA" \
            "$DCENT_DEPLOY_BINARY_ORIGINAL_METADATA" || return 1
    else
        rm -f "$DCENT_DEPLOY_BINARY_PATH" || return 1
    fi
    if [ "$DCENT_DEPLOY_CONFIG_MUTATED" = true ]; then
        if [ "$DCENT_DEPLOY_CONFIG_ORIGINAL_STATUS" = present ]; then
            DCENT_DEPLOY_CONFIG_RESTORE_METADATA_POLICY=verify
            [ "$DCENT_DEPLOY_SCHEMA" != dcent-persistent-tx-v3 ] \
                || DCENT_DEPLOY_CONFIG_RESTORE_METADATA_POLICY=canonicalize
            dcent_deploy_restore_copy "$DCENT_DEPLOY_CONFIG_PATH" \
                "$DCENT_DEPLOY_CONFIG_BACKUP" "$DCENT_DEPLOY_ID" \
                "$DCENT_DEPLOY_CONFIG_ORIGINAL_SHA" \
                "$DCENT_DEPLOY_CONFIG_ORIGINAL_METADATA" \
                "$DCENT_DEPLOY_CONFIG_RESTORE_METADATA_POLICY" || return 1
        else
            case "$DCENT_DEPLOY_ABSENT_CONFIG_STATE" in
                absent|candidate)
                    dcent_deploy_retire_absent_original_config || return 1
                    ;;
                *) return 1 ;;
            esac
        fi
    fi
    dcent_deploy_validate_prior_generation_live || return 1
    dcent_deploy_sync || return 1

    DCENT_DEPLOY_TERMINAL_TMP="$DCENT_DEPLOY_STATE.recovered.new"
    rm -f "$DCENT_DEPLOY_TERMINAL_TMP" || return 1
    awk 'NR == 3 { print "PHASE=recovered"; next } { print }' \
        "$DCENT_DEPLOY_STATE" >"$DCENT_DEPLOY_TERMINAL_TMP" || return 1
    [ "$(wc -l < "$DCENT_DEPLOY_TERMINAL_TMP" 2>/dev/null)" \
        -eq "$DCENT_DEPLOY_STATE_LINES" ] || return 1
    chmod 600 "$DCENT_DEPLOY_TERMINAL_TMP" || return 1
    mv "$DCENT_DEPLOY_TERMINAL_TMP" "$DCENT_DEPLOY_STATE" || return 1
    dcent_deploy_sync || return 1
    DCENT_DEPLOY_PHASE=recovered
    dcent_deploy_finish_terminal_state || return 1
    echo "  [RECOVERED] Interrupted persistent deploy $DCENT_DEPLOY_ID restored as one generation"
}
