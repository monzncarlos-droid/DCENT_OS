#!/bin/sh
# Semantic tests for boot-time persistent binary/config generation recovery.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-deploy-recovery.sh"
DEPLOY_PATH_HELPER_SOURCE="$PROJECT_DIR/br2_external_dcentos/packages/dcentos-deploy-path/src/dcentos-deploy-path.c"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcent-deploy-recovery-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
DCENT_DEPLOY_PATH_HELPER="$TEST_ROOT/dcentos-deploy-path"
DCENT_DEPLOY_PATH_PROBE_DIR=$TEST_ROOT
cc -std=c11 -Wall -Wextra -Werror -O2 \
    -DDCENTOS_DEPLOY_PATH_TEST_FAILPOINTS "$DEPLOY_PATH_HELPER_SOURCE" \
    -o "$DCENT_DEPLOY_PATH_HELPER"
chmod 755 "$DCENT_DEPLOY_PATH_HELPER"

. "$HELPER"

PASS=0

sha() {
    sha256sum "$1" | awk '{ print $1 }'
}

assert_file_equals() {
    cmp -s "$1" "$2" || {
        echo "FAIL: $1 did not equal $2" >&2
        exit 1
    }
}

new_case() {
    CASE_NAME=$1
    DEPLOY_ID=$2
    CASE_ROOT="$TEST_ROOT/$CASE_NAME"
    RECOVERY_BASE="$CASE_ROOT/recovery"
    RUN_DIR="$RECOVERY_BASE/$DEPLOY_ID"
    DCENT_DEPLOY_RUN_DIR=$RUN_DIR
    LIVE_DIR="$CASE_ROOT/live"
    BINARY_PATH="$LIVE_DIR/dcentrald"
    CONFIG_PATH="$LIVE_DIR/dcentrald.toml"
    ETC_CONFIG_PATH="$LIVE_DIR/etc-dcentrald.toml"
    FALLBACK_BINARY="$LIVE_DIR/rootfs-dcentrald"
    mkdir -p "$RUN_DIR" "$LIVE_DIR"
    chmod 700 "$RECOVERY_BASE" "$RUN_DIR"
    printf 'rootfs-fallback-binary\n' >"$FALLBACK_BINARY"
    chmod 755 "$FALLBACK_BINARY"
}

write_manifest() {
    PHASE=$1
    BINARY_ORIGINAL_STATUS=$2
    BINARY_ORIGINAL_SHA=$3
    CONFIG_ORIGINAL_STATUS=$4
    CONFIG_ORIGINAL_SHA=$5
    CONFIG_BACKUP_PATH=$6
    BINARY_CANDIDATE_SHA=$7
    CONFIG_CANDIDATE_SHA=$8
    BINARY_MANIFEST_PATH=${9:-$BINARY_PATH}
    ROLLBACK_SOURCE=${10:-}
    ROLLBACK_PATH=${11:-}
    ROLLBACK_SHA=${12:-}
    if [ -z "$ROLLBACK_SOURCE" ]; then
        if [ "$CONFIG_ORIGINAL_STATUS" = present ]; then
            ROLLBACK_SOURCE=data
            ROLLBACK_PATH=$CONFIG_PATH
            ROLLBACK_SHA=$CONFIG_ORIGINAL_SHA
        else
            ROLLBACK_SOURCE=builtin
            ROLLBACK_PATH=builtin
            ROLLBACK_SHA=NONE
        fi
    fi
    if [ "$BINARY_ORIGINAL_STATUS" = present ]; then
        BINARY_ORIGINAL_METADATA=$(stat -c '%u:%g:%a' "$RUN_DIR/dcentrald.backup")
    else
        BINARY_ORIGINAL_METADATA=NONE
    fi
    if [ "$CONFIG_ORIGINAL_STATUS" = present ]; then
        CONFIG_ORIGINAL_METADATA=$(stat -c '%u:%g:%a' "$CONFIG_BACKUP_PATH")
    else
        CONFIG_ORIGINAL_METADATA=NONE
    fi
    if [ "$PHASE" = committed ] && [ -e "$CONFIG_PATH" ]; then
        chmod 600 "$CONFIG_PATH"
    fi
    cat >"$RUN_DIR/persistent-transaction.state" <<EOF
PERSISTENT_TX_STATE=dcent-persistent-tx-v4
DEPLOY_ID=$DEPLOY_ID
PHASE=$PHASE
BINARY_PATH=$BINARY_MANIFEST_PATH
BINARY_ORIGINAL_STATUS=$BINARY_ORIGINAL_STATUS
BINARY_ORIGINAL_SHA256=$BINARY_ORIGINAL_SHA
BINARY_BACKUP_PATH=$RUN_DIR/dcentrald.backup
BINARY_CANDIDATE_SHA256=$BINARY_CANDIDATE_SHA
CONFIG_MUTATED=true
CONFIG_SOURCE=explicit
CONFIG_PATH=$CONFIG_PATH
CONFIG_ORIGINAL_STATUS=$CONFIG_ORIGINAL_STATUS
CONFIG_ORIGINAL_SHA256=$CONFIG_ORIGINAL_SHA
CONFIG_BACKUP_PATH=$CONFIG_BACKUP_PATH
CONFIG_CANDIDATE_SHA256=$CONFIG_CANDIDATE_SHA
ROLLBACK_CONFIG_SOURCE=$ROLLBACK_SOURCE
ROLLBACK_CONFIG_PATH=$ROLLBACK_PATH
ROLLBACK_CONFIG_SHA256=$ROLLBACK_SHA
BINARY_ORIGINAL_METADATA=$BINARY_ORIGINAL_METADATA
CONFIG_ORIGINAL_METADATA=$CONFIG_ORIGINAL_METADATA
EOF
    chmod 600 "$RUN_DIR/persistent-transaction.state"
}

write_nonmutated_manifest() {
    PHASE=$1
    CONFIG_SOURCE=$2
    CONFIG_MANIFEST_PATH=$3
    CONFIG_CANDIDATE_SHA=$4
    case "$CONFIG_SOURCE:$CONFIG_MANIFEST_PATH" in
        discovered:"$CONFIG_PATH") ROLLBACK_SOURCE=data; ROLLBACK_PATH=$CONFIG_PATH; ROLLBACK_SHA=$CONFIG_CANDIDATE_SHA ;;
        discovered:"$ETC_CONFIG_PATH") ROLLBACK_SOURCE=etc; ROLLBACK_PATH=$ETC_CONFIG_PATH; ROLLBACK_SHA=$CONFIG_CANDIDATE_SHA ;;
        builtin:builtin) ROLLBACK_SOURCE=builtin; ROLLBACK_PATH=builtin; ROLLBACK_SHA=NONE ;;
        *) echo "invalid nonmutated test binding" >&2; exit 1 ;;
    esac
    cat >"$RUN_DIR/persistent-transaction.state" <<EOF
PERSISTENT_TX_STATE=dcent-persistent-tx-v4
DEPLOY_ID=$DEPLOY_ID
PHASE=$PHASE
BINARY_PATH=$BINARY_PATH
BINARY_ORIGINAL_STATUS=present
BINARY_ORIGINAL_SHA256=$(sha "$RUN_DIR/dcentrald.backup")
BINARY_BACKUP_PATH=$RUN_DIR/dcentrald.backup
BINARY_CANDIDATE_SHA256=$(sha "$BINARY_PATH")
CONFIG_MUTATED=false
CONFIG_SOURCE=$CONFIG_SOURCE
CONFIG_PATH=$CONFIG_MANIFEST_PATH
CONFIG_ORIGINAL_STATUS=not_captured
CONFIG_ORIGINAL_SHA256=NONE
CONFIG_BACKUP_PATH=NONE
CONFIG_CANDIDATE_SHA256=$CONFIG_CANDIDATE_SHA
ROLLBACK_CONFIG_SOURCE=$ROLLBACK_SOURCE
ROLLBACK_CONFIG_PATH=$ROLLBACK_PATH
ROLLBACK_CONFIG_SHA256=$ROLLBACK_SHA
BINARY_ORIGINAL_METADATA=$(stat -c '%u:%g:%a' "$RUN_DIR/dcentrald.backup")
CONFIG_ORIGINAL_METADATA=NONE
EOF
    chmod 600 "$RUN_DIR/persistent-transaction.state"
}

recover() {
    dcent_recover_pending_deploy "$RECOVERY_BASE" "$BINARY_PATH" \
        "$CONFIG_PATH" "$ETC_CONFIG_PATH" "$FALLBACK_BINARY"
}

write_lease() {
    LEASE_OWNER=$1
    mkdir "$RECOVERY_BASE/.deploy-lease"
    chmod 700 "$RECOVERY_BASE/.deploy-lease"
    printf '%s\n' "$LEASE_OWNER" >"$RECOVERY_BASE/.deploy-lease/owner"
    chmod 600 "$RECOVERY_BASE/.deploy-lease/owner"
}

test_deploy_path_helper_proves_target_primitives() {
    HELPER_CASE="$TEST_ROOT/deploy-path-helper"
    LIVE_CASE="$HELPER_CASE/live"
    PRIVATE_CASE="$HELPER_CASE/private"
    mkdir -p "$LIVE_CASE" "$PRIVATE_CASE"
    chmod 700 "$PRIVATE_CASE"
    DCENT_DEPLOY_EXPECTED_UID=$(stat -c '%u' "$DCENT_DEPLOY_PATH_HELPER")
    CAPABILITIES=$(dcent_deploy_print_capabilities)
    [ "$(printf '%s\n' "$CAPABILITIES" | sed -n '1p')" \
        = "DCENT_DEPLOY_RECOVERY_SCHEMA_MIN=3" ]
    [ "$(printf '%s\n' "$CAPABILITIES" | sed -n '2p')" \
        = "DCENT_DEPLOY_RECOVERY_SCHEMA_MAX=4" ]
    [ "$(printf '%s\n' "$CAPABILITIES" | awk 'END { print NR }')" -eq 2 ]
    PROBE_NAMESPACE="$TEST_ROOT/.dcent-deploy-path-probe"
    [ -d "$PROBE_NAMESPACE" ] && [ ! -L "$PROBE_NAMESPACE" ]
    [ "$(stat -c '%u:%a' "$PROBE_NAMESPACE")" \
        = "$DCENT_DEPLOY_EXPECTED_UID:700" ]
    [ -f "$PROBE_NAMESPACE/lock" ] && [ ! -L "$PROBE_NAMESPACE/lock" ]
    [ "$(stat -c '%u:%a:%h' "$PROBE_NAMESPACE/lock")" \
        = "$DCENT_DEPLOY_EXPECTED_UID:600:1" ]
    [ "$(find "$PROBE_NAMESPACE" -mindepth 1 -maxdepth 1 -print | wc -l)" \
        -eq 1 ]
    "$DCENT_DEPLOY_PATH_HELPER" probe "$HELPER_CASE"
    HELPER_PROBE_NAMESPACE="$HELPER_CASE/.dcent-deploy-path-probe"
    KILL_READY="$TEST_ROOT/probe-kill-ready"
    DCENTOS_DEPLOY_PATH_TEST_PAUSE_AFTER_SYNC="$KILL_READY" \
        "$DCENT_DEPLOY_PATH_HELPER" probe "$HELPER_CASE" &
    PROBE_PID=$!
    PROBE_READY=false
    for _probe_wait in $(seq 1 100); do
        if [ -f "$KILL_READY" ]; then
            PROBE_READY=true
            break
        fi
        sleep 0.01
    done
    if [ "$PROBE_READY" != true ]; then
        kill -9 "$PROBE_PID" 2>/dev/null || true
        wait "$PROBE_PID" 2>/dev/null || true
        echo "FAIL: deploy path helper did not reach the post-sync kill point" >&2
        exit 1
    fi
    if "$DCENT_DEPLOY_PATH_HELPER" probe "$HELPER_CASE" 2>/dev/null; then
        kill -9 "$PROBE_PID" 2>/dev/null || true
        wait "$PROBE_PID" 2>/dev/null || true
        echo "FAIL: concurrent deploy path probe bypassed the namespace lock" >&2
        exit 1
    fi
    kill -9 "$PROBE_PID"
    if wait "$PROBE_PID" 2>/dev/null; then
        echo "FAIL: SIGKILLed deploy path probe returned success" >&2
        exit 1
    fi
    [ -d "$HELPER_PROBE_NAMESPACE/live" ]
    [ -d "$HELPER_PROBE_NAMESPACE/private" ]
    "$DCENT_DEPLOY_PATH_HELPER" probe "$HELPER_CASE"
    [ "$(find "$HELPER_PROBE_NAMESPACE" -mindepth 1 -maxdepth 1 -print | wc -l)" \
        -eq 1 ]
    [ -f "$HELPER_PROBE_NAMESPACE/lock" ]
    printf 'source\n' >"$LIVE_CASE/source"
    printf 'destination\n' >"$PRIVATE_CASE/destination"
    if "$DCENT_DEPLOY_PATH_HELPER" retire "$LIVE_CASE/source" \
        "$PRIVATE_CASE/destination" 2>/dev/null; then
        echo "FAIL: deploy path helper clobbered an existing retirement destination" >&2
        exit 1
    fi
    grep -Fqx source "$LIVE_CASE/source"
    grep -Fqx destination "$PRIVATE_CASE/destination"
    rm "$PRIVATE_CASE/destination"
    "$DCENT_DEPLOY_PATH_HELPER" retire "$LIVE_CASE/source" \
        "$PRIVATE_CASE/destination"
    [ ! -e "$LIVE_CASE/source" ]
    grep -Fqx source "$PRIVATE_CASE/destination"
    "$DCENT_DEPLOY_PATH_HELPER" restore-link "$PRIVATE_CASE/destination" \
        "$LIVE_CASE/restored"
    grep -Fqx source "$PRIVATE_CASE/destination"
    grep -Fqx source "$LIVE_CASE/restored"
    [ "$(stat -c '%d:%i' "$PRIVATE_CASE/destination")" \
        = "$(stat -c '%d:%i' "$LIVE_CASE/restored")" ]
    mkdir "$LIVE_CASE/source-directory"
    if "$DCENT_DEPLOY_PATH_HELPER" retire "$LIVE_CASE/source-directory" \
        "$PRIVATE_CASE/renamed-directory" 2>/dev/null; then
        echo "FAIL: deploy path helper accepted a directory source" >&2
        exit 1
    fi
    [ -d "$LIVE_CASE/source-directory" ]
    PASS=$((PASS + 1))
}

test_mixed_generation_rolls_back_together() {
    new_case mixed 11111111111111111111111111111111
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    printf 'old-binary\n' >"$CASE_ROOT/expected-binary"
    printf 'old-config\n' >"$CASE_ROOT/expected-config"
    write_manifest mutating present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"

    recover
    assert_file_equals "$BINARY_PATH" "$CASE_ROOT/expected-binary"
    assert_file_equals "$CONFIG_PATH" "$CASE_ROOT/expected-config"
    [ "$(stat -c '%d:%i' "$BINARY_PATH")" != "$(stat -c '%d:%i' "$RUN_DIR/dcentrald.backup")" ]
    [ "$(stat -c '%d:%i' "$CONFIG_PATH")" != "$(stat -c '%d:%i' "$RUN_DIR/dcentrald.toml.backup")" ]
    dcent_verify_resolved_deploy_config
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    grep -Fqx 'PHASE=recovered' "$RUN_DIR/persistent-transaction.recovered"
    PASS=$((PASS + 1))
}

test_prior_absence_removes_both_candidates() {
    new_case absent 22222222222222222222222222222222
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    write_manifest mutating absent NONE absent NONE NONE \
        "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"

    recover
    [ ! -e "$BINARY_PATH" ]
    [ ! -e "$CONFIG_PATH" ]
    dcent_verify_resolved_deploy_config
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_prior_etc_fallback_is_restored_and_admitted() {
    new_case etc_fallback 23232323232323232323232323232323
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-data-config\n' >"$CONFIG_PATH"
    printf 'old-etc-config\n' >"$ETC_CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    ETC_SHA=$(sha "$ETC_CONFIG_PATH")
    write_manifest installed absent NONE absent NONE NONE \
        "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")" "$BINARY_PATH" \
        etc "$ETC_CONFIG_PATH" "$ETC_SHA"

    recover
    [ ! -e "$BINARY_PATH" ]
    [ ! -e "$CONFIG_PATH" ]
    [ "$(sha "$ETC_CONFIG_PATH")" = "$ETC_SHA" ]
    [ "$DCENT_DEPLOY_RESOLVED_CONFIG_SOURCE" = etc ]
    dcent_verify_resolved_deploy_config
    PASS=$((PASS + 1))
}

test_bad_config_backup_is_zero_mutation_failure() {
    new_case bad_backup 33333333333333333333333333333333
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'corrupt-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    BEFORE_CONFIG=$(sha "$CONFIG_PATH")
    EXPECTED_CONFIG_SHA=$(printf 'expected-old-config\n' | sha256sum | awk '{ print $1 }')
    write_manifest mutating present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$EXPECTED_CONFIG_SHA" "$RUN_DIR/dcentrald.toml.backup" \
        "$BEFORE_BINARY" "$BEFORE_CONFIG"

    if recover; then
        echo "FAIL: corrupt config backup was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ "$(sha "$CONFIG_PATH")" = "$BEFORE_CONFIG" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_committed_candidate_completes_forward() {
    new_case committed 44444444444444444444444444444444
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    NEW_BINARY_SHA=$(sha "$BINARY_PATH")
    NEW_CONFIG_SHA=$(sha "$CONFIG_PATH")
    chmod 755 "$BINARY_PATH"
    write_manifest committed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$NEW_BINARY_SHA" "$NEW_CONFIG_SHA"

    recover
    [ "$(sha "$BINARY_PATH")" = "$NEW_BINARY_SHA" ]
    [ "$(sha "$CONFIG_PATH")" = "$NEW_CONFIG_SHA" ]
    [ "$DCENT_DEPLOY_RESOLVED_CONFIG_SOURCE" = data ]
    dcent_verify_resolved_deploy_config
    [ -f "$RUN_DIR/persistent-transaction.committed" ]
    PASS=$((PASS + 1))
}

test_committed_config_drift_fails_closed() {
    new_case committed_drift 45454545454545454545454545454545
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 755 "$BINARY_PATH"
    NEW_CONFIG_SHA=$(sha "$CONFIG_PATH")
    write_manifest committed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$NEW_CONFIG_SHA"
    printf 'drifted-config\n' >"$CONFIG_PATH"
    if recover; then
        echo "FAIL: committed candidate config drift was accepted" >&2
        exit 1
    fi
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_multiple_pending_transactions_fail_closed() {
    new_case multiple 55555555555555555555555555555555
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest mutating present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    mkdir "$RECOVERY_BASE/66666666666666666666666666666666"
    chmod 700 "$RECOVERY_BASE/66666666666666666666666666666666"
    cp "$RUN_DIR/persistent-transaction.state" \
        "$RECOVERY_BASE/66666666666666666666666666666666/persistent-transaction.state"
    chmod 600 "$RECOVERY_BASE/66666666666666666666666666666666/persistent-transaction.state"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    BEFORE_CONFIG=$(sha "$CONFIG_PATH")

    if recover; then
        echo "FAIL: multiple pending transactions were accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ "$(sha "$CONFIG_PATH")" = "$BEFORE_CONFIG" ]
    PASS=$((PASS + 1))
}

test_tampered_path_fails_closed() {
    new_case tampered 77777777777777777777777777777777
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    BEFORE_CONFIG=$(sha "$CONFIG_PATH")
    write_manifest mutating present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$BEFORE_BINARY" "$BEFORE_CONFIG" \
        "$LIVE_DIR/not-the-daemon"

    if recover; then
        echo "FAIL: tampered binary path was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ "$(sha "$CONFIG_PATH")" = "$BEFORE_CONFIG" ]
    PASS=$((PASS + 1))
}

test_every_nonterminal_phase_rolls_back() {
    for phase_and_id in \
        prepared:88888888888888888888888888888888 \
        installed:99999999999999999999999999999999 \
        failed:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        rolling_back:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    do
        PHASE_NAME=${phase_and_id%%:*}
        PHASE_ID=${phase_and_id#*:}
        new_case "phase-$PHASE_NAME" "$PHASE_ID"
        printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
        printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
        printf 'new-binary\n' >"$BINARY_PATH"
        printf 'new-config\n' >"$CONFIG_PATH"
        write_manifest "$PHASE_NAME" present "$(sha "$RUN_DIR/dcentrald.backup")" \
            present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
            "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
        recover
        [ "$(cat "$BINARY_PATH")" = old-binary ]
        [ "$(cat "$CONFIG_PATH")" = old-config ]
        grep -Fqx 'PHASE=recovered' "$RUN_DIR/persistent-transaction.recovered"
        PASS=$((PASS + 1))
    done
}

test_discovered_config_drift_blocks_binary_restore() {
    new_case discovered_drift cccccccccccccccccccccccccccccccc
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'bound-config\n' >"$CONFIG_PATH"
    BOUND_SHA=$(sha "$CONFIG_PATH")
    write_nonmutated_manifest installed discovered "$CONFIG_PATH" "$BOUND_SHA"
    printf 'drifted-config\n' >"$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: discovered config drift was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_builtin_config_appearance_blocks_binary_restore() {
    new_case builtin_drift dddddddddddddddddddddddddddddddd
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    write_nonmutated_manifest installed builtin builtin NONE
    printf 'appeared-config\n' >"$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: config appearance after builtin binding was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_dangling_builtin_config_blocks_binary_restore() {
    new_case builtin_dangling deeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    write_nonmutated_manifest installed builtin builtin NONE
    ln -s "$CASE_ROOT/missing-config" "$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: dangling config after builtin binding was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -L "$CONFIG_PATH" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_dangling_explicit_candidate_is_preserved_before_binary_restore() {
    new_case explicit_absent_dangling dfeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        absent NONE NONE "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    rm -f "$CONFIG_PATH"
    ln -s "$CASE_ROOT/missing-replacement" "$CONFIG_PATH"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: dangling replacement of an absent-original explicit config was erased" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -L "$CONFIG_PATH" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_absent_original_retirement_restores_racing_regular_file() {
    new_case retire_regular_race df111111111111111111111111111111
    printf 'foreign-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    BEFORE_SHA=$(sha "$CONFIG_PATH")
    BEFORE_INODE=$(stat -c '%d:%i' "$CONFIG_PATH")
    DCENT_DEPLOY_CONFIG_PATH=$CONFIG_PATH
    DCENT_DEPLOY_CONFIG_CANDIDATE_SHA=$(printf 'candidate\n' | sha256sum | awk '{ print $1 }')
    DCENT_DEPLOY_ID=$DEPLOY_ID
    DCENT_DEPLOY_EXPECTED_UID=$(stat -c '%u' "$CONFIG_PATH")
    if dcent_deploy_retire_absent_original_config; then
        echo "FAIL: racing foreign regular config was retired as the candidate" >&2
        exit 1
    fi
    [ "$(sha "$CONFIG_PATH")" = "$BEFORE_SHA" ]
    [ "$(stat -c '%d:%i' "$CONFIG_PATH")" = "$BEFORE_INODE" ]
    [ -f "$RUN_DIR/config-retirement/observed" ]
    [ "$(stat -c '%d:%i' "$RUN_DIR/config-retirement/observed")" \
        = "$BEFORE_INODE" ]
    PASS=$((PASS + 1))
}

test_absent_original_retirement_restores_racing_dangling_symlink() {
    new_case retire_symlink_race df222222222222222222222222222222
    LINK_TARGET="$CASE_ROOT/missing-foreign-target"
    ln -s "$LINK_TARGET" "$CONFIG_PATH"
    DCENT_DEPLOY_CONFIG_PATH=$CONFIG_PATH
    DCENT_DEPLOY_CONFIG_CANDIDATE_SHA=$(printf 'candidate\n' | sha256sum | awk '{ print $1 }')
    DCENT_DEPLOY_ID=$DEPLOY_ID
    DCENT_DEPLOY_EXPECTED_UID=$(stat -c '%u' "$LIVE_DIR")
    if dcent_deploy_retire_absent_original_config; then
        echo "FAIL: racing dangling config was retired as the candidate" >&2
        exit 1
    fi
    [ -L "$CONFIG_PATH" ]
    [ "$(readlink "$CONFIG_PATH")" = "$LINK_TARGET" ]
    [ -L "$RUN_DIR/config-retirement/observed" ]
    [ "$(readlink "$RUN_DIR/config-retirement/observed")" = "$LINK_TARGET" ]
    [ "$(stat -c '%d:%i' "$RUN_DIR/config-retirement/observed")" \
        = "$(stat -c '%d:%i' "$CONFIG_PATH")" ]
    PASS=$((PASS + 1))
}

test_interrupted_candidate_quarantine_reconciles_before_absence() {
    new_case retire_candidate_interrupted df333333333333333333333333333333
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    chmod 755 "$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    printf 'candidate-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    CANDIDATE_SHA=$(sha "$CONFIG_PATH")
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        absent NONE NONE "$(sha "$BINARY_PATH")" "$CANDIDATE_SHA"
    mkdir -m 700 "$RUN_DIR/config-retirement"
    mv "$CONFIG_PATH" "$RUN_DIR/config-retirement/observed"

    recover
    [ ! -e "$RUN_DIR/config-retirement" ]
    [ ! -L "$RUN_DIR/config-retirement" ]
    [ ! -e "$CONFIG_PATH" ]
    assert_file_equals "$BINARY_PATH" "$RUN_DIR/dcentrald.backup"
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_interrupted_foreign_quarantine_restores_and_stays_pending() {
    new_case retire_foreign_interrupted df444444444444444444444444444444
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    chmod 755 "$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    printf 'candidate-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    CANDIDATE_SHA=$(sha "$CONFIG_PATH")
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        absent NONE NONE "$(sha "$BINARY_PATH")" "$CANDIDATE_SHA"
    printf 'foreign-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    FOREIGN_SHA=$(sha "$CONFIG_PATH")
    mkdir -m 700 "$RUN_DIR/config-retirement"
    mv "$CONFIG_PATH" "$RUN_DIR/config-retirement/observed"
    BEFORE_BINARY=$(sha "$BINARY_PATH")

    if recover; then
        echo "FAIL: interrupted foreign quarantine was accepted as candidate absence" >&2
        exit 1
    fi
    [ "$(sha "$CONFIG_PATH")" = "$FOREIGN_SHA" ]
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -f "$RUN_DIR/config-retirement/observed" ]
    [ "$(stat -c '%d:%i' "$RUN_DIR/config-retirement/observed")" \
        = "$(stat -c '%d:%i' "$CONFIG_PATH")" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    if recover; then
        echo "FAIL: retry accepted restored foreign config as prior absence" >&2
        exit 1
    fi
    [ "$(sha "$CONFIG_PATH")" = "$FOREIGN_SHA" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_exact_destination_links_never_mutate_directory_targets() {
    command -v busybox >/dev/null 2>&1 || {
        echo "FAIL: BusyBox is required to pin target ln -T/-sT semantics" >&2
        exit 1
    }
    new_case exact_link_destination df555555555555555555555555555555
    printf 'foreign-config\n' >"$RUN_DIR/foreign-config"
    mkdir "$CONFIG_PATH"
    if busybox ln -T "$RUN_DIR/foreign-config" "$CONFIG_PATH" 2>/dev/null; then
        echo "FAIL: BusyBox ln -T accepted a directory destination" >&2
        exit 1
    fi
    [ ! -e "$CONFIG_PATH/foreign-config" ]
    rmdir "$CONFIG_PATH"
    mkdir "$LIVE_DIR/destination-directory"
    ln -s "$LIVE_DIR/destination-directory" "$CONFIG_PATH"
    if busybox ln -T "$RUN_DIR/foreign-config" "$CONFIG_PATH" 2>/dev/null; then
        echo "FAIL: BusyBox ln -T followed a symlink-to-directory destination" >&2
        exit 1
    fi
    [ ! -e "$LIVE_DIR/destination-directory/foreign-config" ]
    rm -f "$CONFIG_PATH"
    busybox ln -sT -- target "$CONFIG_PATH"
    [ -L "$CONFIG_PATH" ] && [ "$(readlink "$CONFIG_PATH")" = target ]
    PASS=$((PASS + 1))
}

test_sync_failure_leaves_retryable_terminal_state() {
    new_case sync_failure eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest mutating present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    dcent_deploy_sync() { return 1; }
    if recover; then
        echo "FAIL: failed sync was accepted as durable recovery" >&2
        exit 1
    fi
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    [ ! -e "$RUN_DIR/persistent-transaction.recovered" ]
    dcent_deploy_sync() { sync; }
    recover
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_recovered_state_completes_idempotently() {
    new_case recovered_state ffffffffffffffffffffffffffffffff
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.backup" "$BINARY_PATH"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    CANDIDATE_BINARY_SHA=$(printf 'candidate-binary\n' | sha256sum | awk '{ print $1 }')
    CANDIDATE_CONFIG_SHA=$(printf 'candidate-config\n' | sha256sum | awk '{ print $1 }')
    write_manifest recovered present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$CANDIDATE_BINARY_SHA" "$CANDIDATE_CONFIG_SHA"
    recover
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    dcent_verify_resolved_deploy_config
    PASS=$((PASS + 1))
}

test_rolled_back_state_removes_matching_stale_commit() {
    new_case rolled_back_state 0123456789abcdef0123456789abcdef
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.backup" "$BINARY_PATH"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    CANDIDATE_BINARY_SHA=$(printf 'candidate-binary\n' | sha256sum | awk '{ print $1 }')
    CANDIDATE_CONFIG_SHA=$(printf 'candidate-config\n' | sha256sum | awk '{ print $1 }')
    write_manifest rolled_back present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$CANDIDATE_BINARY_SHA" "$CANDIDATE_CONFIG_SHA"
    awk 'NR == 3 { print "PHASE=committed"; next } { print }' \
        "$RUN_DIR/persistent-transaction.state" >"$RUN_DIR/persistent-transaction.committed"
    chmod 600 "$RUN_DIR/persistent-transaction.committed"
    recover
    [ -f "$RUN_DIR/persistent-transaction.rolled-back" ]
    [ ! -e "$RUN_DIR/persistent-transaction.committed" ]
    dcent_verify_resolved_deploy_config
    PASS=$((PASS + 1))
}

test_matching_committed_pair_completes_forward() {
    new_case committed_pair 10101010101010101010101010101010
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 755 "$BINARY_PATH"
    write_manifest committed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    cp "$RUN_DIR/persistent-transaction.state" "$RUN_DIR/persistent-transaction.committed"
    chmod 600 "$RUN_DIR/persistent-transaction.committed"
    recover
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ -f "$RUN_DIR/persistent-transaction.committed" ]
    dcent_verify_resolved_deploy_config
    PASS=$((PASS + 1))
}

test_terminal_publication_sync_failure_is_retryable() {
    new_case terminal_publish_sync 12121212121212121212121212121212
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    SYNC_CALLS=0
    dcent_deploy_sync() {
        SYNC_CALLS=$((SYNC_CALLS + 1))
        [ "$SYNC_CALLS" -ne 3 ] || return 1
        sync
    }
    if recover; then
        echo "FAIL: terminal copy with failed durability sync was accepted" >&2
        exit 1
    fi
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    grep -Fqx 'PHASE=recovered' "$RUN_DIR/persistent-transaction.state"
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    dcent_deploy_sync() { sync; }
    recover
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_partial_legacy_terminal_temp_does_not_poison_retry() {
    new_case partial_terminal_temp 12121212121212121212121212121213
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    chmod 755 "$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    write_nonmutated_manifest installed builtin builtin NONE
    : >"$RUN_DIR/persistent-transaction.recovered.new"
    chmod 600 "$RUN_DIR/persistent-transaction.recovered.new"

    recover
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ ! -e "$RUN_DIR/persistent-transaction.recovered.new" ]
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_same_bytes_restore_original_metadata_and_independence() {
    new_case same_bytes_metadata 13131313131313131313131313131313
    printf 'same-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'same-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    chmod 644 "$RUN_DIR/dcentrald.backup"
    chmod 400 "$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.backup" "$BINARY_PATH"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    chmod 755 "$BINARY_PATH"
    chmod 600 "$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    recover
    [ "$(stat -c '%a' "$BINARY_PATH")" = 644 ]
    [ "$(stat -c '%a' "$CONFIG_PATH")" = 400 ]
    [ "$(stat -c '%d:%i' "$BINARY_PATH")" != "$(stat -c '%d:%i' "$RUN_DIR/dcentrald.backup")" ]
    [ "$(stat -c '%d:%i' "$CONFIG_PATH")" != "$(stat -c '%d:%i' "$RUN_DIR/dcentrald.toml.backup")" ]
    [ "$DCENT_DEPLOY_RESOLVED_BINARY_SOURCE" = fallback ]
    dcent_verify_resolved_deploy_generation
    chmod 755 "$BINARY_PATH"
    if dcent_verify_resolved_deploy_generation; then
        echo "FAIL: execute-bit shadow of resolved fallback binary was accepted" >&2
        exit 1
    fi
    PASS=$((PASS + 1))
}

test_resolved_binary_drift_is_rejected() {
    new_case binary_binding 14141414141414141414141414141414
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    recover
    dcent_verify_resolved_deploy_generation
    printf 'unmanifested-executable\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    if dcent_verify_resolved_deploy_generation; then
        echo "FAIL: resolved binary drift was accepted" >&2
        exit 1
    fi
    PASS=$((PASS + 1))
}

test_resolved_etc_config_shadow_is_rejected() {
    new_case etc_shadow 15151515151515151515151515151515
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'bound-etc-config\n' >"$ETC_CONFIG_PATH"
    write_nonmutated_manifest installed discovered "$ETC_CONFIG_PATH" \
        "$(sha "$ETC_CONFIG_PATH")"
    recover
    dcent_verify_resolved_deploy_generation
    printf 'shadow-data-config\n' >"$CONFIG_PATH"
    if dcent_verify_resolved_deploy_generation; then
        echo "FAIL: /data shadow of resolved /etc config was accepted" >&2
        exit 1
    fi
    PASS=$((PASS + 1))
}

test_binary_backup_metadata_drift_blocks_restore() {
    new_case backup_metadata_drift 16161616161616161616161616161616
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    chmod 644 "$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    chmod 755 "$RUN_DIR/dcentrald.backup"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: binary backup metadata drift was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_config_backup_metadata_drift_is_zero_mutation_failure() {
    new_case config_metadata_drift 24242424242424242424242424242424
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    chmod 640 "$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    chmod 400 "$RUN_DIR/dcentrald.toml.backup"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    BEFORE_CONFIG=$(sha "$CONFIG_PATH")
    BEFORE_CONFIG_MODE=$(stat -c '%a' "$CONFIG_PATH")
    if recover; then
        echo "FAIL: config backup metadata drift was accepted" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    [ "$(sha "$CONFIG_PATH")" = "$BEFORE_CONFIG" ]
    [ "$(stat -c '%a' "$CONFIG_PATH")" = "$BEFORE_CONFIG_MODE" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_legacy_v3_pending_transaction_recovers_during_upgrade() {
    new_case legacy_v3 25252525252525252525252525252525
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    chmod 640 "$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest installed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    sed -i '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' \
        "$RUN_DIR/persistent-transaction.state"
    sed -i '$d' "$RUN_DIR/persistent-transaction.state"
    recover
    [ "$(sha "$BINARY_PATH")" = "$(sha "$RUN_DIR/dcentrald.backup")" ]
    [ "$(sha "$CONFIG_PATH")" = "$(sha "$RUN_DIR/dcentrald.toml.backup")" ]
    [ "$(stat -c '%u:%g:%a' "$CONFIG_PATH")" = "$(id -u):0:600" ]
    [ "$(wc -l <"$RUN_DIR/persistent-transaction.recovered")" -eq 19 ]
    grep -Fqx 'PERSISTENT_TX_STATE=dcent-persistent-tx-v3' \
        "$RUN_DIR/persistent-transaction.recovered"
    PASS=$((PASS + 1))
}

test_legacy_v3_terminal_state_canonicalizes_before_completion() {
    new_case legacy_v3_terminal 26262626262626262626262626262626
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    cp "$RUN_DIR/dcentrald.backup" "$BINARY_PATH"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    chmod 640 "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    write_manifest recovered present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    sed -i '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' \
        "$RUN_DIR/persistent-transaction.state"
    sed -i '$d' "$RUN_DIR/persistent-transaction.state"
    write_lease "$DEPLOY_ID"
    recover
    [ "$(stat -c '%u:%g:%a' "$CONFIG_PATH")" = "$(id -u):0:600" ]
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    [ ! -e "$RECOVERY_BASE/.deploy-lease" ]
    PASS=$((PASS + 1))
}

test_legacy_v3_terminal_validates_generation_before_canonicalization() {
    new_case legacy_v3_terminal_bad_binary 27272727272727272727272727272727
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'corrupt-live-binary\n' >"$BINARY_PATH"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    chmod 640 "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    write_manifest recovered present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    sed -i '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' \
        "$RUN_DIR/persistent-transaction.state"
    sed -i '$d' "$RUN_DIR/persistent-transaction.state"
    write_lease "$DEPLOY_ID"
    BEFORE_CONFIG_INODE=$(stat -c '%d:%i' "$CONFIG_PATH")
    if recover; then
        echo "FAIL: legacy terminal canonicalized before validating corrupt binary" >&2
        exit 1
    fi
    [ "$(stat -c '%u:%g:%a' "$CONFIG_PATH")" = "$(id -u):0:640" ]
    [ "$(stat -c '%d:%i' "$CONFIG_PATH")" = "$BEFORE_CONFIG_INODE" ]
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    [ -d "$RECOVERY_BASE/.deploy-lease" ]
    PASS=$((PASS + 1))
}

test_legacy_v3_leased_terminal_synthesizes_and_canonicalizes() {
    new_case legacy_v3_leased_terminal 28282828282828282828282828282828
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    cp "$RUN_DIR/dcentrald.backup" "$BINARY_PATH"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    cp "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    chmod 640 "$RUN_DIR/dcentrald.toml.backup" "$CONFIG_PATH"
    write_manifest recovered present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    sed -i '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' \
        "$RUN_DIR/persistent-transaction.state"
    sed -i '$d' "$RUN_DIR/persistent-transaction.state"
    mv "$RUN_DIR/persistent-transaction.state" \
        "$RUN_DIR/persistent-transaction.recovered"
    write_lease "$DEPLOY_ID"
    recover
    [ "$(stat -c '%u:%g:%a' "$CONFIG_PATH")" = "$(id -u):0:600" ]
    [ ! -e "$RECOVERY_BASE/.deploy-lease" ]
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_recovery_parent_metadata_drift_fails_before_mutation() {
    for drift in base run; do
        new_case "parent_metadata_$drift" 29292929292929292929292929292929
        printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
        printf 'new-binary\n' >"$BINARY_PATH"
        write_nonmutated_manifest installed builtin builtin NONE
        BEFORE_BINARY=$(sha "$BINARY_PATH")
        if [ "$drift" = base ]; then
            chmod 777 "$RECOVERY_BASE"
        else
            chmod 777 "$RUN_DIR"
        fi
        if recover; then
            echo "FAIL: recovery accepted $drift directory metadata drift" >&2
            exit 1
        fi
        [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
        [ -f "$RUN_DIR/persistent-transaction.state" ]
        PASS=$((PASS + 1))
    done
}

test_prior_no_executable_daemon_terminalizes_as_none() {
    new_case no_daemon 17171717171717171717171717171717
    chmod 644 "$FALLBACK_BINARY"
    printf 'new-binary\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    write_manifest installed absent NONE absent NONE NONE \
        "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    recover
    [ ! -e "$BINARY_PATH" ]
    [ "$DCENT_DEPLOY_RESOLVED_BINARY_SOURCE" = none ]
    dcent_verify_resolved_deploy_generation
    dcent_verify_resolved_deploy_selection "$FALLBACK_BINARY" "$ETC_CONFIG_PATH"
    [ -f "$RUN_DIR/persistent-transaction.recovered" ]
    PASS=$((PASS + 1))
}

test_dangling_state_symlink_blocks_admission() {
    new_case dangling_state 18181818181818181818181818181818
    ln -s "$RUN_DIR/missing-state-target" "$RUN_DIR/persistent-transaction.state"
    if recover; then
        echo "FAIL: dangling transaction-state symlink was ignored" >&2
        exit 1
    fi
    PASS=$((PASS + 1))
}

test_dangling_state_cannot_mask_valid_pending_state() {
    new_case dangling_first 19191919191919191919191919191919
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    write_nonmutated_manifest installed builtin builtin NONE
    DANGLING_DIR="$RECOVERY_BASE/00000000000000000000000000000000"
    mkdir "$DANGLING_DIR"
    ln -s "$DANGLING_DIR/missing" "$DANGLING_DIR/persistent-transaction.state"
    BEFORE_BINARY=$(sha "$BINARY_PATH")
    if recover; then
        echo "FAIL: dangling first state masked a valid pending transaction" >&2
        exit 1
    fi
    [ "$(sha "$BINARY_PATH")" = "$BEFORE_BINARY" ]
    PASS=$((PASS + 1))
}

test_dangling_recovery_base_blocks_admission() {
    CASE_ROOT="$TEST_ROOT/dangling_base"
    LIVE_DIR="$CASE_ROOT/live"
    mkdir -p "$LIVE_DIR"
    RECOVERY_BASE="$CASE_ROOT/recovery"
    BINARY_PATH="$LIVE_DIR/dcentrald"
    CONFIG_PATH="$LIVE_DIR/dcentrald.toml"
    ETC_CONFIG_PATH="$LIVE_DIR/etc-dcentrald.toml"
    FALLBACK_BINARY="$LIVE_DIR/rootfs-dcentrald"
    printf 'fallback\n' >"$FALLBACK_BINARY"
    chmod 755 "$FALLBACK_BINARY"
    ln -s "$CASE_ROOT/missing-recovery-target" "$RECOVERY_BASE"
    if recover; then
        echo "FAIL: dangling recovery-base symlink was ignored" >&2
        exit 1
    fi
    PASS=$((PASS + 1))
}

test_leased_committed_terminal_recovers_host_crash() {
    new_case leased_terminal 20202020202020202020202020202020
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'old-config\n' >"$RUN_DIR/dcentrald.toml.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    printf 'new-config\n' >"$CONFIG_PATH"
    write_manifest committed present "$(sha "$RUN_DIR/dcentrald.backup")" \
        present "$(sha "$RUN_DIR/dcentrald.toml.backup")" \
        "$RUN_DIR/dcentrald.toml.backup" "$(sha "$BINARY_PATH")" "$(sha "$CONFIG_PATH")"
    mv "$RUN_DIR/persistent-transaction.state" "$RUN_DIR/persistent-transaction.committed"
    write_lease "$DEPLOY_ID"
    recover
    [ -f "$RUN_DIR/persistent-transaction.committed" ]
    [ ! -e "$RUN_DIR/persistent-transaction.state" ]
    [ ! -e "$RECOVERY_BASE/.deploy-lease" ]
    [ -d "$RUN_DIR/deploy-lease.released" ]
    [ "$(cat "$RUN_DIR/deploy-lease.released/owner")" = "$DEPLOY_ID" ]
    dcent_verify_resolved_deploy_generation
    PASS=$((PASS + 1))
}

test_leased_terminal_synthesis_rejects_ambiguous_evidence() {
    for corruption in filename_phase metadata schema deploy_id; do
        case "$corruption" in
            filename_phase) case_id=24242424242424242424242424242420 ;;
            metadata) case_id=25252525252525252525252525252520 ;;
            schema) case_id=26262626262626262626262626262620 ;;
            deploy_id) case_id=27272727272727272727272727272720 ;;
        esac
        new_case "leased_terminal_$corruption" "$case_id"
        printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
        chmod 755 "$RUN_DIR/dcentrald.backup"
        printf 'new-binary\n' >"$BINARY_PATH"
        chmod 755 "$BINARY_PATH"
        write_nonmutated_manifest committed builtin builtin NONE
        terminal="$RUN_DIR/persistent-transaction.committed"
        mv "$RUN_DIR/persistent-transaction.state" "$terminal"
        case "$corruption" in
            filename_phase)
                mv "$terminal" "$RUN_DIR/persistent-transaction.recovered"
                ;;
            metadata)
                chmod 644 "$terminal"
                ;;
            schema)
                sed -i '1s/dcent-persistent-tx-v4/dcent-persistent-tx-v3/' "$terminal"
                ;;
            deploy_id)
                sed -i '2s/.*/DEPLOY_ID=ffffffffffffffffffffffffffffffff/' "$terminal"
                ;;
        esac
        write_lease "$DEPLOY_ID"
        if recover; then
            echo "FAIL: leased terminal synthesis accepted $corruption ambiguity" >&2
            exit 1
        fi
        [ ! -e "$RUN_DIR/persistent-transaction.state" ]
        [ -d "$RECOVERY_BASE/.deploy-lease" ]
    done
    PASS=$((PASS + 1))
}

test_mismatched_lease_and_pending_state_fail_closed() {
    new_case lease_mismatch 21212121212121212121212121212121
    printf 'old-binary\n' >"$RUN_DIR/dcentrald.backup"
    printf 'new-binary\n' >"$BINARY_PATH"
    write_nonmutated_manifest installed builtin builtin NONE
    write_lease 22222222222222222222222222222220
    if recover; then
        echo "FAIL: mismatched deploy lease and pending state were accepted" >&2
        exit 1
    fi
    [ -f "$RUN_DIR/persistent-transaction.state" ]
    PASS=$((PASS + 1))
}

test_abandoned_pre_manifest_lease_blocks_admission() {
    new_case abandoned_lease 23232323232323232323232323232320
    write_lease "$DEPLOY_ID"
    if recover; then
        echo "FAIL: abandoned lease without transaction evidence was ignored" >&2
        exit 1
    fi
    [ -d "$RECOVERY_BASE/.deploy-lease" ]
    PASS=$((PASS + 1))
}

test_deploy_path_helper_proves_target_primitives
test_mixed_generation_rolls_back_together
test_prior_absence_removes_both_candidates
test_prior_etc_fallback_is_restored_and_admitted
test_bad_config_backup_is_zero_mutation_failure
test_committed_candidate_completes_forward
test_committed_config_drift_fails_closed
test_multiple_pending_transactions_fail_closed
test_tampered_path_fails_closed
test_every_nonterminal_phase_rolls_back
test_discovered_config_drift_blocks_binary_restore
test_builtin_config_appearance_blocks_binary_restore
test_dangling_builtin_config_blocks_binary_restore
test_dangling_explicit_candidate_is_preserved_before_binary_restore
test_absent_original_retirement_restores_racing_regular_file
test_absent_original_retirement_restores_racing_dangling_symlink
test_interrupted_candidate_quarantine_reconciles_before_absence
test_interrupted_foreign_quarantine_restores_and_stays_pending
test_exact_destination_links_never_mutate_directory_targets
test_sync_failure_leaves_retryable_terminal_state
test_recovered_state_completes_idempotently
test_rolled_back_state_removes_matching_stale_commit
test_matching_committed_pair_completes_forward
test_terminal_publication_sync_failure_is_retryable
test_partial_legacy_terminal_temp_does_not_poison_retry
test_same_bytes_restore_original_metadata_and_independence
test_resolved_binary_drift_is_rejected
test_resolved_etc_config_shadow_is_rejected
test_binary_backup_metadata_drift_blocks_restore
test_config_backup_metadata_drift_is_zero_mutation_failure
test_legacy_v3_pending_transaction_recovers_during_upgrade
test_legacy_v3_terminal_state_canonicalizes_before_completion
test_legacy_v3_terminal_validates_generation_before_canonicalization
test_legacy_v3_leased_terminal_synthesizes_and_canonicalizes
test_recovery_parent_metadata_drift_fails_before_mutation
test_prior_no_executable_daemon_terminalizes_as_none
test_dangling_state_symlink_blocks_admission
test_dangling_state_cannot_mask_valid_pending_state
test_dangling_recovery_base_blocks_admission
test_leased_committed_terminal_recovers_host_crash
test_leased_terminal_synthesis_rejects_ambiguous_evidence
test_mismatched_lease_and_pending_state_fail_closed
test_abandoned_pre_manifest_lease_blocks_admission

printf 'dcentrald deploy recovery: %s/47 scenarios passed\n' "$PASS"
