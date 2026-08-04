#!/bin/bash
# DCENTos — Platform-Aware Dev Deploy Script
# D-Central Technologies, 2026
#
# Safe default behavior by board family:
#   - AM1 / S9: persistent deploy to /data/dcentrald
#   - AM2 / am2-s17: runtime-only deploy to /tmp (no NAND/rootfs mutation)
#   - Amlogic: runtime-only deploy to /tmp with --serial-mining
#
# Wave B (2026-05-19): the --passthrough CLI flag was removed. The
# [mining].passthrough = true knob in /data/dcentrald.toml is the canonical
# way to request passthrough mode; the S82 init script reads it. See
#  G-T8-1.
#
# This script is for rapid iteration without flashing NAND. It is intentionally
# conservative on experimental boards so runtime validation does not become an
# accidental install path.

set -euo pipefail

MINER_IP="${1:?Usage: $0 <miner_ip> [--skip-build] [--config FILE] [--verify] [--tail] [--rollback-on-fail] [--runtime-only] [--json] [--output FILE] [--dashboard-only]}"
shift

SKIP_BUILD=false
CONFIG_FILE=""
VERIFY=false
TAIL=false
ROLLBACK_ON_FAIL=false
JSON_OUTPUT=false
JSON_OUTPUT_FILE=""
DASHBOARD_ONLY=false
FORCE_RUNTIME_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)       SKIP_BUILD=true ;;
        --config)           CONFIG_FILE="${2:?--config requires a file argument}"; shift ;;
        --verify)           VERIFY=true ;;
        --tail)             TAIL=true ;;
        --rollback-on-fail) ROLLBACK_ON_FAIL=true ;;
        # Force every board family, including AM1/S9, onto /tmp. Acceptance
        # uses this so a diagnostic first-light run cannot inherit this
        # helper's normal AM1 /data deployment policy.
        --runtime-only)     FORCE_RUNTIME_ONLY=true ;;
        --json)             JSON_OUTPUT=true ;;
        --output)           JSON_OUTPUT_FILE="${2:?--output requires a file argument}"; shift ;;
        --output=*)         JSON_OUTPUT_FILE="${1#--output=}" ;;
        # W5.1 (2026-05-07): dashboard-only deploys skip the Rust rebuild
        # entirely. The SPA is now served by server.py from
        # /usr/share/dcentos-dashboard/index.html (no longer compiled
        # into dcentrald via include_str!), so a dashboard tweak is a
        # ~30-second scp instead of a ~10-minute cargo build cycle.
        --dashboard-only)   DASHBOARD_ONLY=true ;;
        *)                  echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

if [ "$FORCE_RUNTIME_ONLY" = true ] && [ "$DASHBOARD_ONLY" = true ]; then
    echo "ERROR: --runtime-only cannot be combined with --dashboard-only" >&2
    exit 2
fi

case "$MINER_IP" in
    ""|*[!A-Za-z0-9:._-]*)
        echo "ERROR: miner host contains unsupported characters" >&2
        exit 2
        ;;
esac

if [ -n "$JSON_OUTPUT_FILE" ]; then
    if [ -L "$JSON_OUTPUT_FILE" ] || { [ -e "$JSON_OUTPUT_FILE" ] && [ ! -f "$JSON_OUTPUT_FILE" ]; }; then
        echo "ERROR: JSON output destination must be a regular file or absent: $JSON_OUTPUT_FILE" >&2
        exit 2
    fi
    JSON_OUTPUT_DIR=$(dirname "$JSON_OUTPUT_FILE")
    mkdir -p "$JSON_OUTPUT_DIR" || {
        echo "ERROR: cannot create output directory: $JSON_OUTPUT_DIR" >&2
        exit 2
    }
    # Invalidate a prior receipt before this invocation can fail. A stale
    # success record must never be mistaken for evidence from the current run.
    rm -f -- "$JSON_OUTPUT_FILE"
    if ! sync -f "$JSON_OUTPUT_DIR" 2>/dev/null; then
        echo "ERROR: cannot durably invalidate stale JSON output: $JSON_OUTPUT_FILE" >&2
        exit 2
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE_DIR="$PROJECT_DIR/dcentrald"

SSH_TRANSPORT="openssh"
if [ -n "${DCENT_SSH_KNOWN_HOSTS:-}" ]; then
    [ -r "$DCENT_SSH_KNOWN_HOSTS" ] && [ -s "$DCENT_SSH_KNOWN_HOSTS" ] || {
        echo "ERROR: DCENT_SSH_KNOWN_HOSTS must name a readable non-empty pinned known_hosts file" >&2
        exit 2
    }
    case "$DCENT_SSH_KNOWN_HOSTS" in
        *[!A-Za-z0-9_./:-]*)
            echo "ERROR: DCENT_SSH_KNOWN_HOSTS contains unsupported characters" >&2
            exit 2
            ;;
    esac
    SSH_OPTS="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$DCENT_SSH_KNOWN_HOSTS -o ConnectTimeout=10"
else
    SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
fi

# Windows developer path: when password auth is needed and PuTTY tools are
# available, use plink/pscp for noninteractive deploys. This avoids raw ssh/scp
# hanging on password prompts under Git Bash / PowerShell launched sessions.
if [ -z "${DCENT_SSH_KNOWN_HOSTS:-}" ] && [ -n "${DCENT_PASSWORD:-}" ] && command -v plink.exe >/dev/null 2>&1 && command -v pscp.exe >/dev/null 2>&1; then
    SSH_TRANSPORT="putty"
fi

DEPLOY_START=$(date +%s)
DEPLOY_ID=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]') || DEPLOY_ID=""
case "$DEPLOY_ID" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) echo "ERROR: could not generate deploy identity" >&2; exit 2 ;;
esac

TARGET=""
BINARY=""
DEPLOY_MODE=""
PLATFORM_FAMILY=""
PLATFORM_DESC=""
DEPLOY_PATH=""
BACKUP_PATH=""
STAGING_PATH=""
CONFIG_REMOTE=""
CONFIG_BIND_SHA256=""
CONFIG_BIND_SOURCE="unresolved"
CONFIG_BIND_METADATA="NONE"
CONFIG_EXPECTED_BUILTIN=false
CONFIG_USED="unknown"
BINARY_SHA256=""
RUNTIME_CONFIG_DIR=""
REMOTE_RUN_DIR=""
LOG_PATH="/tmp/dcentrald.log"
EXPECTFILE="/var/run/dcentrald.expected_exit.pid"
VERIFY_TIMEOUT=15
HAS_PERSISTENT_SUPERVISOR=false
DEPLOY_DIR=""
DEPLOY_EXISTING_SIZE=0
CONFIG_UPLOAD_SIZE=0
CONFIG_EXISTING_SIZE=0
TMP_FREE_BYTES=0
DEPLOY_FREE_BYTES=0
DEPLOY_FREE_INODES=0
PERSISTENT_MIN_FREE_RESERVE_BYTES=1048576
PERSISTENT_MIN_FREE_INODES=16
API_PORT=80
API_VERIFICATION_STATUS="not_requested"
LAUNCHED_PID=""
LAUNCHED_START_TICKS=""
LAUNCHED_EXE=""
RUNTIME_LAUNCH_ATTEMPTED=false
RUNTIME_LAUNCH_COMMITTED=false
LAUNCH_ID=""
PERSISTENT_MUTATION_STARTED=false
PERSISTENT_CONFIG_MUTATION_STARTED=false
PERSISTENT_LAUNCH_COMMITTED=false
PERSISTENT_BACKUP_STATUS="not_required"
PERSISTENT_CONFIG_BACKUP_STATUS="not_required"
PERSISTENT_ROLLBACK_STATUS="not_required"
PERSISTENT_CONFIG_STAGE_PATH=""
PERSISTENT_CONFIG_BACKUP_PATH=""
PERSISTENT_CONFIG_ORIGINAL_EXISTS=false
PERSISTENT_CONFIG_ORIGINAL_SHA256=""
PERSISTENT_CONFIG_ORIGINAL_METADATA=""
DEPLOY_EXISTING_SHA256=""
DEPLOY_EXISTING_METADATA=""
DEPLOY_EXISTING_STATUS="not_captured"
PERSISTENT_CONFIG_ORIGINAL_STATUS="not_captured"
ROLLBACK_CONFIG_SOURCE="unresolved"
ROLLBACK_CONFIG_PATH=""
ROLLBACK_CONFIG_SHA256=""
PERSISTENT_TX_STATE_PATH=""
PERSISTENT_TX_STATUS="not_required"
PERSISTENT_TX_PUBLISH_ATTEMPTED=false
PERSISTENT_TX_SCHEMA="not_applicable"
PERSISTENT_TX_IDENTITY_SHA256=""
PERSISTENT_TX_TERMINAL_PATH=""
PERSISTENT_RECOVERY_SCHEMA_MIN=""
PERSISTENT_RECOVERY_SCHEMA_MAX=""
PERSISTENT_DEPLOY_LEASE_ACQUIRED=false
PERSISTENT_DEPLOY_LEASE_STATUS="not_acquired"
PERSISTENT_DEPLOY_LEASE_AMBIGUITY_STAGE="none"
PERSISTENT_DEPLOY_LEASE_PATH="/data/.dcent-deploy-recovery/.deploy-lease"
DEPLOY_MAINTENANCE_ACQUIRED=false
DEPLOY_MAINTENANCE_STATUS="not_acquired"
DEPLOY_MAINTENANCE_PATH="/run/dcentos-deploy-maintenance"
DEPLOY_LOCK_HELPER="/usr/libexec/dcentos/dcentos-deploy-lock"

BOSMINER_PID="NONE"
BOSTOOLS_PID="NONE"
BOSER_PID="NONE"
BOS_OWNER_IDENTITIES=""
BOS_OWNER_UNVERIFIABLE=""
DCENTRALD_PID="NONE"
DCENTRALD_IDENTITIES=""
DCENTRALD_UNVERIFIABLE=""
OS_VER="NONE"
BOS_VER="NONE"
ARCH="unknown"
SOC="unknown"
MODEL=""
HWID=""
UIO_COUNT=0

log() {
    if [ "$JSON_OUTPUT" = false ]; then
        echo "$@"
    fi
}

log_step() {
    log ""
    log "=== $1 ==="
}

json_string() {
    # Use one standards implementation for quoting rather than maintaining a
    # second JSON encoder in shell. This escapes every C0 control and rejects
    # invalid surrogate/text edge cases consistently with the receipt tests.
    python3 -c 'import json, sys; print(json.dumps(sys.argv[1], ensure_ascii=False), end="")' "$1"
}

write_json_payload() {
    local payload="$1"
    if [ -n "$JSON_OUTPUT_FILE" ]; then
        local output_dir output_tmp
        if [ -L "$JSON_OUTPUT_FILE" ] || { [ -e "$JSON_OUTPUT_FILE" ] && [ ! -f "$JSON_OUTPUT_FILE" ]; }; then
            echo "ERROR: JSON output destination must be a regular file or absent: $JSON_OUTPUT_FILE" >&2
            return 1
        fi
        output_dir="$(dirname "$JSON_OUTPUT_FILE")"
        if ! mkdir -p "$output_dir"; then
            echo "ERROR: cannot create output directory: $output_dir" >&2
            return 1
        fi
        output_tmp=$(mktemp "$output_dir/.dcent-deploy.XXXXXX") || {
            echo "ERROR: cannot create temporary JSON output in: $output_dir" >&2
            return 1
        }
        if ! printf '%s\n' "$payload" > "$output_tmp"; then
            rm -f "$output_tmp"
            echo "ERROR: cannot write JSON output: $JSON_OUTPUT_FILE" >&2
            return 1
        fi
        if ! sync -f "$output_tmp" 2>/dev/null; then
            rm -f "$output_tmp"
            echo "ERROR: cannot durably flush JSON output: $JSON_OUTPUT_FILE" >&2
            return 1
        fi
        # -T gives the destination path file semantics: an existing directory
        # must fail instead of accepting the receipt as a child entry.
        if ! mv -fT -- "$output_tmp" "$JSON_OUTPUT_FILE"; then
            rm -f "$output_tmp"
            echo "ERROR: cannot publish JSON output: $JSON_OUTPUT_FILE" >&2
            return 1
        fi
        if ! sync -f "$output_dir" 2>/dev/null; then
            # The file itself is durable and the rename is already visible,
            # but directory-entry persistence is uncertain. Withdrawing it
            # would create a second uncertain rename and can leave a visible
            # success receipt while later cleanup changes the target. Preserve
            # the truthful receipt and return a distinct no-rollback status.
            echo "ERROR: JSON output is visible but directory durability is unproven: $JSON_OUTPUT_FILE" >&2
            return 2
        fi
    fi
    if [ "$JSON_OUTPUT" = true ]; then
        printf '%s\n' "$payload"
    fi
}

build_receipt_payload() {
    local success="$1"
    local pid="$2"
    local binary_size="$3"
    local api_healthy="$4"
    local message="$5"
    local cleanup_status="$6"
    local deploy_end deploy_time
    local json_start_ticks json_exe json_launch_id json_cleanup_status
    local json_miner_ip json_platform_family json_deploy_mode json_message json_deploy_id
    local json_config json_remote_path
    local json_recovery_path json_backup_status json_config_backup_status json_rollback_status
    local json_binary_sha256 json_config_sha256 json_api_verification_status
    local json_config_bind_source json_original_binary_status json_original_binary_sha256
    local json_original_binary_metadata
    local json_original_config_status json_original_config_sha256 json_original_config_metadata
    local json_persistent_tx_schema json_persistent_tx_identity_sha256
    local json_persistent_tx_state_path json_persistent_tx_terminal_path
    local json_persistent_tx_status
    local json_rollback_config_source json_rollback_config_path json_rollback_config_sha256
    local json_deploy_lease_status json_maintenance_status

    case "$success" in true|false) ;; *) success=false ;; esac
    case "$pid" in null) ;; ""|*[!0-9]*) pid=null ;; esac
    case "$binary_size" in ""|*[!0-9]*) binary_size=0 ;; esac
    case "$api_healthy" in true|false) ;; *) api_healthy=false ;; esac
    deploy_end=$(date +%s)
    deploy_time=$((deploy_end - DEPLOY_START))

    json_start_ticks=$(json_string "${LAUNCHED_START_TICKS:-}")
    json_exe=$(json_string "${LAUNCHED_EXE:-}")
    json_launch_id=$(json_string "${LAUNCH_ID:-}")
    json_cleanup_status=$(json_string "$cleanup_status")
    json_miner_ip=$(json_string "$MINER_IP")
    json_platform_family=$(json_string "$PLATFORM_FAMILY")
    json_deploy_mode=$(json_string "$DEPLOY_MODE")
    json_message=$(json_string "$message")
    json_deploy_id=$(json_string "$DEPLOY_ID")
    json_config=$(json_string "$CONFIG_USED")
    json_remote_path=$(json_string "$DEPLOY_PATH")
    json_recovery_path=$(json_string "${REMOTE_RUN_DIR:-}")
    json_backup_status=$(json_string "$PERSISTENT_BACKUP_STATUS")
    json_config_backup_status=$(json_string "$PERSISTENT_CONFIG_BACKUP_STATUS")
    json_rollback_status=$(json_string "$PERSISTENT_ROLLBACK_STATUS")
    json_binary_sha256=$(json_string "${BINARY_SHA256:-}")
    json_config_sha256=$(json_string "${CONFIG_BIND_SHA256:-}")
    json_api_verification_status=$(json_string "$API_VERIFICATION_STATUS")
    json_config_bind_source=$(json_string "$CONFIG_BIND_SOURCE")
    json_original_binary_status=$(json_string "$DEPLOY_EXISTING_STATUS")
    json_original_binary_sha256=$(json_string "$DEPLOY_EXISTING_SHA256")
    json_original_binary_metadata=$(json_string "$DEPLOY_EXISTING_METADATA")
    json_original_config_status=$(json_string "$PERSISTENT_CONFIG_ORIGINAL_STATUS")
    json_original_config_sha256=$(json_string "$PERSISTENT_CONFIG_ORIGINAL_SHA256")
    json_original_config_metadata=$(json_string "$PERSISTENT_CONFIG_ORIGINAL_METADATA")
    json_persistent_tx_schema=$(json_string "$PERSISTENT_TX_SCHEMA")
    json_persistent_tx_identity_sha256=$(json_string "$PERSISTENT_TX_IDENTITY_SHA256")
    json_persistent_tx_state_path=$(json_string "$PERSISTENT_TX_STATE_PATH")
    json_persistent_tx_terminal_path=$(json_string "$PERSISTENT_TX_TERMINAL_PATH")
    json_persistent_tx_status=$(json_string "$PERSISTENT_TX_STATUS")
    json_rollback_config_source=$(json_string "$ROLLBACK_CONFIG_SOURCE")
    json_rollback_config_path=$(json_string "$ROLLBACK_CONFIG_PATH")
    json_rollback_config_sha256=$(json_string "${ROLLBACK_CONFIG_SHA256:-NONE}")
    json_deploy_lease_status=$(json_string "$PERSISTENT_DEPLOY_LEASE_STATUS")
    json_maintenance_status=$(json_string "$DEPLOY_MAINTENANCE_STATUS")

    cat <<ENDJSON
{
  "receipt_schema": "dcent-dev-deploy-v3",
  "deploy_id": $json_deploy_id,
  "success": $success,
  "pid": $pid,
  "start_ticks": $json_start_ticks,
  "exe": $json_exe,
  "launch_id": $json_launch_id,
  "cleanup_status": $json_cleanup_status,
  "recovery_artifact_path": $json_recovery_path,
  "backup_status": $json_backup_status,
  "config_backup_status": $json_config_backup_status,
  "rollback_status": $json_rollback_status,
  "binary_size": $binary_size,
  "binary_sha256": $json_binary_sha256,
  "config_sha256": $json_config_sha256,
  "config_binding_source": $json_config_bind_source,
  "original_binary_status": $json_original_binary_status,
  "original_binary_sha256": $json_original_binary_sha256,
  "original_binary_metadata": $json_original_binary_metadata,
  "original_config_status": $json_original_config_status,
  "original_config_sha256": $json_original_config_sha256,
  "original_config_metadata": $json_original_config_metadata,
  "persistent_transaction_schema": $json_persistent_tx_schema,
  "persistent_transaction_identity_sha256": $json_persistent_tx_identity_sha256,
  "persistent_transaction_state_path": $json_persistent_tx_state_path,
  "persistent_transaction_terminal_path": $json_persistent_tx_terminal_path,
  "persistent_transaction_status": $json_persistent_tx_status,
  "deploy_lease_status_at_receipt_publication": $json_deploy_lease_status,
  "maintenance_exclusion_at_receipt_publication": $json_maintenance_status,
  "rollback_config_source": $json_rollback_config_source,
  "rollback_config_path": $json_rollback_config_path,
  "rollback_config_sha256": $json_rollback_config_sha256,
  "deploy_time_seconds": $deploy_time,
  "api_healthy": $api_healthy,
  "api_verification_status": $json_api_verification_status,
  "miner_ip": $json_miner_ip,
  "platform_family": $json_platform_family,
  "deploy_mode": $json_deploy_mode,
  "config": $json_config,
  "remote_path": $json_remote_path,
  "sha256": $json_binary_sha256,
  "message": $json_message
}
ENDJSON
}

cleanup_remote_run_dir() {
    [ -n "$REMOTE_RUN_DIR" ] || return 0
    if ssh_run "rm -f '$REMOTE_RUN_DIR/dcentrald.new' '$REMOTE_RUN_DIR/dcentrald.backup' '$REMOTE_RUN_DIR/dcentrald.toml.new' '$REMOTE_RUN_DIR/dcentrald.toml.backup' '$REMOTE_RUN_DIR/expected-exit.pid' '$REMOTE_RUN_DIR/runtime-launch.authorized' '$REMOTE_RUN_DIR/runtime-launch.starting' '$REMOTE_RUN_DIR/runtime-launch.started.new' '$REMOTE_RUN_DIR/runtime-launch.started' '$REMOTE_RUN_DIR/runtime-launch.cancelled'; rmdir '$REMOTE_RUN_DIR'" >/dev/null 2>&1; then
        REMOTE_RUN_DIR=""
        return 0
    fi
    return 1
}

acquire_deploy_maintenance() {
    local result observation
    result=$(ssh_run '
set -e
umask 077
gate='"'"$DEPLOY_MAINTENANCE_PATH"'"'
owner="$gate/owner"
lock_helper='"'"$DEPLOY_LOCK_HELPER"'"'
[ -x "$lock_helper" ]
[ ! -e "$gate" ] && [ ! -L "$gate" ]
mkdir "$gate"
chmod 700 "$gate"
printf "%s\n" '"'"$DEPLOY_ID"'"' >"$owner"
chmod 600 "$owner"
if ! "$lock_helper" -- /bin/true; then
    [ "$(cat "$owner" 2>/dev/null)" = '"'"$DEPLOY_ID"'"' ] || exit 1
    rm -f "$owner"
    rmdir "$gate"
    exit 1
fi
printf "DEPLOY_MAINTENANCE_READY=true\n"
' 2>/dev/null) || result=""
    if [ "$result" = "DEPLOY_MAINTENANCE_READY=true" ]; then
        DEPLOY_MAINTENANCE_ACQUIRED=true
        DEPLOY_MAINTENANCE_STATUS="held"
        return 0
    fi

    # The target may have published the nonce-bound gate and completed its
    # kernel-lock exclusion check before the SSH reply was lost. Re-run the
    # exclusion check behind that exact gate and adopt only fully validated
    # evidence; the marker blocks every new S82 admission while this resolves.
    observation=$(ssh_run '
set -e
gate='"'"$DEPLOY_MAINTENANCE_PATH"'"'
owner="$gate/owner"
lock_helper='"'"$DEPLOY_LOCK_HELPER"'"'
[ -x "$lock_helper" ]
[ -d "$gate" ] && [ ! -L "$gate" ]
[ "$(stat -c "%u:%a" "$gate" 2>/dev/null)" = "0:700" ]
[ -f "$owner" ] && [ ! -L "$owner" ]
[ "$(stat -c "%u:%a:%h" "$owner" 2>/dev/null)" = "0:600:1" ]
[ "$(cat "$owner")" = '"'"$DEPLOY_ID"'"' ]
entry_count=0
for entry in "$gate"/* "$gate"/.[!.]* "$gate"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    [ "$entry" = "$owner" ]
    entry_count=$((entry_count + 1))
done
[ "$entry_count" -eq 1 ]
"$lock_helper" -- /bin/true
printf "DEPLOY_MAINTENANCE_OBSERVED=held\n"
' 2>/dev/null) || observation=""
    if [ "$observation" = "DEPLOY_MAINTENANCE_OBSERVED=held" ]; then
        DEPLOY_MAINTENANCE_ACQUIRED=true
        DEPLOY_MAINTENANCE_STATUS="held"
        return 0
    fi
    DEPLOY_MAINTENANCE_STATUS="ambiguous"
    return 1
}

release_deploy_maintenance() {
    [ "$DEPLOY_MAINTENANCE_ACQUIRED" = true ] || return 0
    local result observation
    result=$(ssh_run '
set -e
gate='"'"$DEPLOY_MAINTENANCE_PATH"'"'
owner="$gate/owner"
[ -d "$gate" ] && [ ! -L "$gate" ]
[ "$(stat -c "%u:%a" "$gate" 2>/dev/null)" = "0:700" ]
[ -f "$owner" ] && [ ! -L "$owner" ]
[ "$(stat -c "%u:%a:%h" "$owner" 2>/dev/null)" = "0:600:1" ]
[ "$(cat "$owner")" = '"'"$DEPLOY_ID"'"' ]
rm -f "$owner"
rmdir "$gate"
printf "DEPLOY_MAINTENANCE_RELEASED=true\n"
' 2>/dev/null) || result=""
    if [ "$result" = "DEPLOY_MAINTENANCE_RELEASED=true" ]; then
        DEPLOY_MAINTENANCE_ACQUIRED=false
        DEPLOY_MAINTENANCE_STATUS="released"
        return 0
    fi
    observation=$(ssh_run '
gate='"'"$DEPLOY_MAINTENANCE_PATH"'"'
if [ ! -e "$gate" ] && [ ! -L "$gate" ]; then
    printf "DEPLOY_MAINTENANCE_OBSERVED=released\n"
elif [ -d "$gate" ] && [ ! -L "$gate" ] \
    && [ -f "$gate/owner" ] && [ ! -L "$gate/owner" ] \
    && [ "$(cat "$gate/owner" 2>/dev/null)" = '"'"$DEPLOY_ID"'"' ]; then
    printf "DEPLOY_MAINTENANCE_OBSERVED=held\n"
else
    printf "DEPLOY_MAINTENANCE_OBSERVED=released-or-replaced\n"
fi
' 2>/dev/null) || observation=""
    case "$observation" in
        DEPLOY_MAINTENANCE_OBSERVED=released|DEPLOY_MAINTENANCE_OBSERVED=released-or-replaced)
            DEPLOY_MAINTENANCE_ACQUIRED=false
            DEPLOY_MAINTENANCE_STATUS="released"
            return 0
            ;;
        DEPLOY_MAINTENANCE_OBSERVED=held)
            DEPLOY_MAINTENANCE_STATUS="held"
            return 1
            ;;
        *)
            DEPLOY_MAINTENANCE_ACQUIRED=false
            DEPLOY_MAINTENANCE_STATUS="ambiguous"
            return 1
            ;;
    esac
}

probe_persistent_recovery_capability() {
    local result schema_min schema_max
    result=$(ssh_run '
set -e
init=/etc/init.d/S82dcentrald
[ -x "$init" ] && [ ! -L "$init" ]
"$init" deploy-recovery-capabilities
' 2>/dev/null) || result=""
    [ "$(printf '%s\n' "$result" | awk 'END { print NR }')" -eq 2 ] || return 1
    case "$(printf '%s\n' "$result" | sed -n '1p')" in
        DCENT_DEPLOY_RECOVERY_SCHEMA_MIN=*) ;;
        *) return 1 ;;
    esac
    case "$(printf '%s\n' "$result" | sed -n '2p')" in
        DCENT_DEPLOY_RECOVERY_SCHEMA_MAX=*) ;;
        *) return 1 ;;
    esac
    schema_min=$(single_assignment_value "$result" DCENT_DEPLOY_RECOVERY_SCHEMA_MIN 2>/dev/null) || return 1
    schema_max=$(single_assignment_value "$result" DCENT_DEPLOY_RECOVERY_SCHEMA_MAX 2>/dev/null) || return 1
    case "$schema_min:$schema_max" in
        *[!0-9:]*|:*|*:) return 1 ;;
    esac
    [ "$schema_min" -le 4 ] && [ "$schema_max" -ge 4 ] || return 1
    PERSISTENT_RECOVERY_SCHEMA_MIN=$schema_min
    PERSISTENT_RECOVERY_SCHEMA_MAX=$schema_max
}

release_persistent_deploy_lease() {
    [ "$DEPLOY_MODE" = persistent ] || return 0
    [ "$PERSISTENT_DEPLOY_LEASE_ACQUIRED" = true ] || return 0
    local release_result release_probe
    release_result=$(ssh_run '
set -e
lease='"'"$PERSISTENT_DEPLOY_LEASE_PATH"'"'
owner="$lease/owner"
retired='"'"$REMOTE_RUN_DIR/deploy-lease.released"'"'
[ -d "$lease" ] && [ ! -L "$lease" ]
[ -f "$owner" ] && [ ! -L "$owner" ]
[ "$(cat "$owner")" = '"'"$DEPLOY_ID"'"' ]
[ ! -e "$retired" ] && [ ! -L "$retired" ]
mv "$lease" "$retired"
sync
printf "PERSISTENT_DEPLOY_LEASE_RELEASED=true\n"
' 2>/dev/null) || release_result=""
    if [ "$release_result" = "PERSISTENT_DEPLOY_LEASE_RELEASED=true" ]; then
        PERSISTENT_DEPLOY_LEASE_ACQUIRED=false
        PERSISTENT_DEPLOY_LEASE_STATUS="released"
        return 0
    fi

    # A lost SSH response after rename must never trigger rollback across a
    # successor deploy. Re-observe the nonce-bound retired marker and make the
    # rename durable before deciding whether exclusion was surrendered.
    release_probe=$(ssh_run '
set -e
lease='"'"$PERSISTENT_DEPLOY_LEASE_PATH"'"'
retired='"'"$REMOTE_RUN_DIR/deploy-lease.released"'"'
if [ -d "$retired" ] && [ ! -L "$retired" ] \
    && [ "$(stat -c "%u:%a" "$retired" 2>/dev/null)" = "0:700" ] \
    && [ -f "$retired/owner" ] && [ ! -L "$retired/owner" ] \
    && [ "$(stat -c "%u:%a:%h" "$retired/owner" 2>/dev/null)" = "0:600:1" ] \
    && [ "$(cat "$retired/owner")" = '"'"$DEPLOY_ID"'"' ]; then
    sync
    printf "PERSISTENT_DEPLOY_LEASE_OBSERVED=released\n"
elif [ -d "$lease" ] && [ ! -L "$lease" ] \
    && [ -f "$lease/owner" ] && [ ! -L "$lease/owner" ] \
    && [ "$(cat "$lease/owner")" = '"'"$DEPLOY_ID"'"' ] \
    && [ ! -e "$retired" ] && [ ! -L "$retired" ]; then
    printf "PERSISTENT_DEPLOY_LEASE_OBSERVED=held\n"
else
    printf "PERSISTENT_DEPLOY_LEASE_OBSERVED=ambiguous\n"
    exit 1
fi
' 2>/dev/null) || release_probe=""
    case "$release_probe" in
        PERSISTENT_DEPLOY_LEASE_OBSERVED=released)
            PERSISTENT_DEPLOY_LEASE_ACQUIRED=false
            PERSISTENT_DEPLOY_LEASE_STATUS="released"
            return 0
            ;;
        PERSISTENT_DEPLOY_LEASE_OBSERVED=held)
            PERSISTENT_DEPLOY_LEASE_STATUS="held"
            return 1
            ;;
        *)
            PERSISTENT_DEPLOY_LEASE_ACQUIRED=false
            PERSISTENT_DEPLOY_LEASE_STATUS="ambiguous"
            PERSISTENT_DEPLOY_LEASE_AMBIGUITY_STAGE="release"
            return 1
            ;;
    esac
}

json_exit() {
    local success="$1"
    local pid="${2:-null}"
    local binary_size="${3:-0}"
    local api_healthy="${4:-false}"
    local message="${5:-}"
    local cleanup_status="not_required"
    local runtime_cleanup_ok=true
    case "$success" in true|false) ;; *) success=false ;; esac
    case "$pid" in null) ;; ""|*[!0-9]*) pid=null ;; esac
    case "$binary_size" in ""|*[!0-9]*) binary_size=0 ;; esac
    case "$api_healthy" in true|false) ;; *) api_healthy=false ;; esac
    if [ "$success" != "true" ]; then
        cleanup_status="complete"
        if [ "$DEPLOY_MODE" = "persistent" ] \
            && [ "$PERSISTENT_DEPLOY_LEASE_STATUS" = "ambiguous" ]; then
            cleanup_status="incomplete"
            if [ "$PERSISTENT_DEPLOY_LEASE_AMBIGUITY_STAGE" = "acquisition" ]; then
                # Acquisition failed before a transaction manifest or candidate
                # mutation. The target may nevertheless hold our lease, so keep
                # maintenance exclusion fail-closed without claiming a commit.
                PERSISTENT_ROLLBACK_STATUS="refused_lease_acquisition_unproven_no_candidate_mutation"
                PERSISTENT_TX_STATUS="lease_acquisition_ambiguous_no_transaction"
            else
                # The active lease may already have been atomically retired and
                # a successor may own the target. Never stop or restore bytes
                # without exclusion; publish only the unresolved evidence state.
                PERSISTENT_ROLLBACK_STATUS="refused_lease_ownership_unproven_candidate_retained"
                PERSISTENT_TX_STATUS="lease_release_ambiguous_candidate_committed"
            fi
        elif [ "$DEPLOY_MODE" = "persistent" ] &&
           { [ "$PERSISTENT_MUTATION_STARTED" = true ] ||
             [ "$PERSISTENT_TX_PUBLISH_ATTEMPTED" = true ]; }; then
            cleanup_status="recovery_artifacts_retained"
            persistent_owner_cleanup_ok=true
            cleanup_persistent_launch || {
                persistent_owner_cleanup_ok=false
                cleanup_status="incomplete"
            }
            if [ "$PERSISTENT_MUTATION_STARTED" != true ]; then
                PERSISTENT_ROLLBACK_STATUS="not_applicable_manifest_publication_ambiguous"
                PERSISTENT_TX_STATUS="publication_ambiguous_recovery_artifacts_retained"
            elif [ "$ROLLBACK_ON_FAIL" = true ]; then
                if [ "$persistent_owner_cleanup_ok" != true ]; then
                    PERSISTENT_ROLLBACK_STATUS="refused_owner_unproven_recovery_artifacts_retained"
                elif rollback_persistent_files; then
                    PERSISTENT_ROLLBACK_STATUS="files_restored_launch_stopped_ownership_unverified"
                else
                    PERSISTENT_ROLLBACK_STATUS="failed_recovery_artifacts_retained"
                    cleanup_status="incomplete"
                fi
            else
                PERSISTENT_ROLLBACK_STATUS="not_requested_recovery_artifacts_retained"
            fi
            if [ "$PERSISTENT_MUTATION_STARTED" = true ] &&
               [ "$PERSISTENT_TX_STATUS" != "rolled_back_prior_generation" ]; then
                mark_persistent_transaction_failed || cleanup_status="incomplete"
            fi
        else
            if ! cleanup_runtime_launch; then
                cleanup_status="incomplete"
                runtime_cleanup_ok=false
            fi
            if [ "$runtime_cleanup_ok" = true ]; then
                cleanup_remote_run_dir || cleanup_status="incomplete"
            else
                log "  Preserving private remote launch state for manual recovery: $REMOTE_RUN_DIR"
            fi
        fi
    fi
    if [ "$success" != true ] && [ "$DEPLOY_MODE" = persistent ] \
        && [ "$PERSISTENT_DEPLOY_LEASE_ACQUIRED" = true ]; then
        release_persistent_deploy_lease || cleanup_status="incomplete"
    fi
    if [ "$success" != true ] && [ "$cleanup_status" != incomplete ] \
        && [ "$DEPLOY_MAINTENANCE_ACQUIRED" = true ]; then
        release_deploy_maintenance || cleanup_status="incomplete"
    fi

    # Failure callers may not have received the launch stdout. If recovery
    # established an exact identity, preserve that identity in the receipt
    # even though the process has now been stopped (or stop proof failed).
    if [ "$pid" = "null" ] && [ -n "${LAUNCHED_PID:-}" ]; then
        pid=$LAUNCHED_PID
    fi

    local payload
    payload=$(build_receipt_payload \
        "$success" "$pid" "$binary_size" "$api_healthy" \
        "$message" "$cleanup_status") || exit 1
    if write_json_payload "$payload"; then
        receipt_publication_status=0
    else
        receipt_publication_status=$?
        # A successful runtime launch without its local identity receipt is not
        # an acceptable success. Reclaim the exact PID/start/exe triple before
        # reporting the evidence-publication failure. A return of 2 means the
        # fsynced receipt is already visible but its directory entry could not
        # be proven durable; keep target state unchanged so that visible
        # evidence never contradicts a compensating rollback.
        if [ "$success" = "true" ] \
            && [ "$receipt_publication_status" -ne 2 ]; then
            cleanup_runtime_launch || true
        fi
        trap - EXIT INT TERM HUP
        exit 1
    fi

    # json_exit owns all failure cleanup. Disable the generic EXIT retry so the
    # published cleanup_status remains the final observed result.
    trap - EXIT INT TERM HUP
    if [ "$success" = "true" ]; then
        exit 0
    else
        exit 1
    fi
}

remote_file_exists() {
    local path="$1"
    ssh_run "[ -f '$path' ] && echo yes || echo no" 2>/dev/null
}

compute_sha256_local() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        return 1
    fi
}

single_assignment_value() {
    local payload="$1"
    local key="$2"
    printf '%s\n' "$payload" | awk -v prefix="$key=" '
        index($0, prefix) == 1 {
            count++
            value = substr($0, length(prefix) + 1)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    '
}

ssh_run() {
    local remote_cmd="$1"
    if [ "$SSH_TRANSPORT" = "putty" ]; then
        if [ -n "${DCENT_HOSTKEY:-}" ]; then
            plink.exe -batch -pw "${DCENT_PASSWORD}" -hostkey "${DCENT_HOSTKEY}" "root@${MINER_IP}" "$remote_cmd"
        else
            plink.exe -batch -pw "${DCENT_PASSWORD}" "root@${MINER_IP}" "$remote_cmd"
        fi
    else
        ssh $SSH_OPTS "root@${MINER_IP}" "$remote_cmd"
    fi
}

# Revalidate PID, start ticks, executable, and launch nonce before every signal
# to narrow PID-reuse exposure. POSIX kill(2) still addresses a numeric PID, so
# a residual check-to-signal race remains until the target supports pidfds.
# The caller decides whether stopping that launch is policy-appropriate.
stop_exact_launched_process() {
    case "$LAUNCHED_PID:$LAUNCHED_START_TICKS" in
        *[!0-9:]*|:*|*:) return 1 ;;
    esac
    [ -n "$LAUNCHED_EXE" ] || return 1

    ssh_run '
pid='"$LAUNCHED_PID"'
expected_start='"$LAUNCHED_START_TICKS"'
expected_exe='"'"$LAUNCHED_EXE"'"'
expected_launch_id='"'"$LAUNCH_ID"'"'
expectfile='"'"$EXPECTFILE"'"'
identity_matches() {
    [ -r "/proc/$pid/stat" ] || return 1
    current_start=$(sed "s/^[^)]*) //" "/proc/$pid/stat" 2>/dev/null | awk "{print \$20}")
    current_exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    [ "$current_start" = "$expected_start" ] && [ "$current_exe" = "$expected_exe" ] || return 1
    [ -z "$expected_launch_id" ] || tr "\000" "\n" <"/proc/$pid/environ" 2>/dev/null | grep -Fqx "DCENT_DEPLOY_LAUNCH_ID=$expected_launch_id"
}
if identity_matches; then
    printf "%s\n" "$pid" >"$expectfile" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 30); do
        identity_matches || break
        sleep 1
    done
    if identity_matches; then
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$expectfile"
fi
identity_matches && exit 1
exit 0' >/dev/null 2>&1
}

# Recover a launch whose SSH output was lost. The deploy path was
# proven owner-free before the start command. A one-shot remote authorization
# is atomically claimed by the start script or cancelled by cleanup; only a
# cancelled/finished state can turn a zero-process scan into positive absence.
recover_runtime_launch_identity() {
    case "$DEPLOY_MODE" in runtime-only|persistent) ;; *) return 1 ;; esac
    [ "$RUNTIME_LAUNCH_ATTEMPTED" = "true" ] || return 1
    [ -z "$LAUNCHED_PID" ] || return 0

    local discovery status recovered_pid recovered_start recovered_exe
    local expected_config_path expected_config_sha
    if [ -n "$CONFIG_BIND_SHA256" ]; then
        expected_config_path=$CONFIG_REMOTE
        expected_config_sha=$CONFIG_BIND_SHA256
    else
        expected_config_path=builtin
        expected_config_sha=NONE
    fi
    discovery=$(ssh_run '
expected_exe='"'"$DEPLOY_PATH"'"'
expected_launch_id='"'"$LAUNCH_ID"'"'
expected_config_source='"'"$CONFIG_BIND_SOURCE"'"'
expected_config_path='"'"$expected_config_path"'"'
expected_config_sha='"'"$expected_config_sha"'"'
authorized='"$REMOTE_RUN_DIR/runtime-launch.authorized"'
starting='"$REMOTE_RUN_DIR/runtime-launch.starting"'
started='"$REMOTE_RUN_DIR/runtime-launch.started"'
cancelled='"$REMOTE_RUN_DIR/runtime-launch.cancelled"'
assignment_value() {
    key=$1
    awk -v prefix="$key=" '\''
        index($0, prefix) == 1 {
            count++
            value = substr($0, length(prefix) + 1)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    '\'' "$started"
}
if [ -f "$authorized" ]; then
    [ "$(cat "$authorized" 2>/dev/null)" = "$expected_launch_id" ] || {
        printf "RUNTIME_DISCOVERY=ambiguous\n"
        exit 0
    }
    mv "$authorized" "$cancelled" 2>/dev/null || true
fi
for attempt in $(seq 1 30); do
    matches=0
    matched_pid=""
    matched_start=""
    for proc in /proc/[0-9]*; do
        current_exe=$(readlink "$proc/exe" 2>/dev/null || true)
        [ "$current_exe" = "$expected_exe" ] || continue
        tr "\000" "\n" <"$proc/environ" 2>/dev/null | grep -Fqx "DCENT_DEPLOY_LAUNCH_ID=$expected_launch_id" || continue
        pid=${proc##*/}
        start=$(sed "s/^[^)]*) //" "$proc/stat" 2>/dev/null | awk "{print \$20}")
        case "$pid:$start" in *[!0-9:]*|:*|*:) printf "RUNTIME_DISCOVERY=ambiguous\n"; exit 0 ;; esac
        matches=$((matches + 1))
        matched_pid=$pid
        matched_start=$start
    done
    case "$matches" in
        1)
            printf "RUNTIME_DISCOVERY=exact\nRUNTIME_PID=%s\nRUNTIME_START_TICKS=%s\nRUNTIME_EXE=%s\n" \
                "$matched_pid" "$matched_start" "$expected_exe"
            exit 0
            ;;
        0) ;;
        *) printf "RUNTIME_DISCOVERY=ambiguous\n"; exit 0 ;;
    esac
    if [ -f "$cancelled" ]; then
        [ "$(cat "$cancelled" 2>/dev/null)" = "$expected_launch_id" ] || {
            printf "RUNTIME_DISCOVERY=ambiguous\n"
            exit 0
        }
        printf "RUNTIME_DISCOVERY=none\n"
        exit 0
    fi
    if [ -f "$started" ]; then
        [ "$(wc -l <"$started" 2>/dev/null)" -eq 8 ] || {
            printf "RUNTIME_DISCOVERY=ambiguous\n"
            exit 0
        }
        started_schema=$(assignment_value RUNTIME_LAUNCH_STATE 2>/dev/null) || started_schema=""
        started_launch_id=$(assignment_value LAUNCH_ID 2>/dev/null) || started_launch_id=""
        started_pid=$(assignment_value PID 2>/dev/null) || started_pid=""
        started_start=$(assignment_value START_TICKS 2>/dev/null) || started_start=""
        started_exe=$(assignment_value EXE 2>/dev/null) || started_exe=""
        started_config_source=$(assignment_value CONFIG_SOURCE 2>/dev/null) || started_config_source=""
        started_config_path=$(assignment_value CONFIG_PATH 2>/dev/null) || started_config_path=""
        started_config_sha=$(assignment_value CONFIG_SHA256 2>/dev/null) || started_config_sha=""
        case "$started_pid:$started_start" in *[!0-9:]*|:*|*:) started_schema="" ;; esac
        if [ "$started_schema" != "dcent-runtime-launch-v2" ] ||
           [ "$started_launch_id" != "$expected_launch_id" ] ||
           [ "$started_exe" != "$expected_exe" ] ||
           [ "$started_config_source" != "$expected_config_source" ] ||
           [ "$started_config_path" != "$expected_config_path" ] ||
           [ "$started_config_sha" != "$expected_config_sha" ]; then
            printf "RUNTIME_DISCOVERY=ambiguous\n"
            exit 0
        fi
        printf "RUNTIME_DISCOVERY=none\n"
        exit 0
    fi
    [ -f "$starting" ] && [ "$(cat "$starting" 2>/dev/null)" = "$expected_launch_id" ] || {
        printf "RUNTIME_DISCOVERY=ambiguous\n"
        exit 0
    }
    sleep 1
done
printf "RUNTIME_DISCOVERY=ambiguous\n"' 2>/dev/null) || return 1
    status=$(single_assignment_value "$discovery" RUNTIME_DISCOVERY 2>/dev/null) || return 1
    [ "$status" != "none" ] || return 0
    [ "$status" = "exact" ] || return 1
    recovered_pid=$(single_assignment_value "$discovery" RUNTIME_PID 2>/dev/null) || return 1
    recovered_start=$(single_assignment_value "$discovery" RUNTIME_START_TICKS 2>/dev/null) || return 1
    recovered_exe=$(single_assignment_value "$discovery" RUNTIME_EXE 2>/dev/null) || return 1
    case "$recovered_pid:$recovered_start" in *[!0-9:]*|:*|*:) return 1 ;; esac
    [ "$recovered_exe" = "$DEPLOY_PATH" ] || return 1
    LAUNCHED_PID=$recovered_pid
    LAUNCHED_START_TICKS=$recovered_start
    LAUNCHED_EXE=$recovered_exe
    log "  Recovered lost runtime launch identity PID=$LAUNCHED_PID start=$LAUNCHED_START_TICKS"
}

# Prove that the remote journal is a complete, immutable description of the
# launch before success can rely on it for crash recovery. A live process alone
# is insufficient: the launcher may have emitted its PID and then failed while
# committing runtime-launch.started.
verify_committed_launch_state() {
    local expected_config_path expected_config_sha state_result
    if [ -n "$CONFIG_BIND_SHA256" ]; then
        expected_config_path=$CONFIG_REMOTE
        expected_config_sha=$CONFIG_BIND_SHA256
    else
        expected_config_path=builtin
        expected_config_sha=NONE
    fi
    state_result=$(ssh_run '
started='"$REMOTE_RUN_DIR/runtime-launch.started"'
authorized='"$REMOTE_RUN_DIR/runtime-launch.authorized"'
starting='"$REMOTE_RUN_DIR/runtime-launch.starting"'
started_new='"$REMOTE_RUN_DIR/runtime-launch.started.new"'
[ -f "$started" ] && [ ! -L "$started" ]
[ "$(stat -c "%u:%a:%h" "$started" 2>/dev/null)" = "0:600:1" ]
[ ! -e "$authorized" ] && [ ! -e "$starting" ] && [ ! -e "$started_new" ]
[ "$(wc -l <"$started" 2>/dev/null)" -eq 8 ]
[ "$(sed -n "1p" "$started")" = "RUNTIME_LAUNCH_STATE=dcent-runtime-launch-v2" ]
[ "$(sed -n "2p" "$started")" = "LAUNCH_ID='"$LAUNCH_ID"'" ]
[ "$(sed -n "3p" "$started")" = "PID='"$LAUNCHED_PID"'" ]
[ "$(sed -n "4p" "$started")" = "START_TICKS='"$LAUNCHED_START_TICKS"'" ]
[ "$(sed -n "5p" "$started")" = "EXE='"$LAUNCHED_EXE"'" ]
[ "$(sed -n "6p" "$started")" = "CONFIG_SOURCE='"$CONFIG_BIND_SOURCE"'" ]
[ "$(sed -n "7p" "$started")" = "CONFIG_PATH='"$expected_config_path"'" ]
[ "$(sed -n "8p" "$started")" = "CONFIG_SHA256='"$expected_config_sha"'" ]
printf "LAUNCH_STATE=committed\n"' 2>/dev/null) || return 1
    [ "$state_result" = "LAUNCH_STATE=committed" ]
}

# Runtime-only failures must not strand a hardware-owning daemon.
cleanup_runtime_launch() {
    [ "$DEPLOY_MODE" = "runtime-only" ] || return 0
    [ "$RUNTIME_LAUNCH_COMMITTED" != "true" ] || return 0
    local cleanup_ok=true
    if [ -z "$LAUNCHED_PID" ] && [ "$RUNTIME_LAUNCH_ATTEMPTED" = "true" ]; then
        if ! recover_runtime_launch_identity; then
            log "ERROR: runtime launch outcome is ambiguous; refusing unbound cleanup and preserving its config"
            return 1
        fi
    fi
    if [ -n "$LAUNCHED_PID" ]; then
        log "  Cleaning up failed runtime-only launch PID=$LAUNCHED_PID"
        if ! stop_exact_launched_process; then
            log "ERROR: exact runtime launch stop was not proven; preserving its immutable config"
            return 1
        fi
    fi
    if [ -n "$RUNTIME_CONFIG_DIR" ]; then
        ssh_run "rm -f '$RUNTIME_CONFIG_DIR/dcentrald.toml' '$RUNTIME_CONFIG_DIR/dcentrald.toml.new' && rmdir '$RUNTIME_CONFIG_DIR'" >/dev/null 2>&1 || cleanup_ok=false
    fi
    [ "$cleanup_ok" = true ]
}

cleanup_persistent_launch() {
    [ "$DEPLOY_MODE" = "persistent" ] || return 0
    [ "$PERSISTENT_LAUNCH_COMMITTED" != "true" ] || return 0
    if [ -z "$LAUNCHED_PID" ] && [ "$RUNTIME_LAUNCH_ATTEMPTED" = "true" ]; then
        if ! recover_runtime_launch_identity; then
            log "ERROR: persistent launch outcome is ambiguous; preserving recovery artifacts and refusing byte rollback"
            return 1
        fi
    fi
    if [ -n "$LAUNCHED_PID" ]; then
        log "  Stopping exact failed persistent launch PID=$LAUNCHED_PID"
        stop_exact_launched_process || return 1
    fi
    return 0
}

# Convert an installed/committed transaction back into an explicit pending
# recovery record. This is used whenever launch, final ownership arbitration,
# or local receipt publication fails. The boot resolver will then refuse to
# admit dcentrald until the whole prior generation is restored.
mark_persistent_transaction_failed() {
    [ "$DEPLOY_MODE" = "persistent" ] || return 0
    [ "$PERSISTENT_MUTATION_STARTED" = true ] || return 0
    [ -n "$PERSISTENT_TX_STATE_PATH" ] || return 1
    # A failure transition may revoke a previously verified committed marker.
    # Until the remote transition is re-admitted, no terminal path is proven.
    PERSISTENT_TX_TERMINAL_PATH=""
    if ssh_run '
set -e
state='"'"$PERSISTENT_TX_STATE_PATH"'"'
committed='"'"$REMOTE_RUN_DIR/persistent-transaction.committed"'"'
rolled_back='"'"$REMOTE_RUN_DIR/persistent-transaction.rolled-back"'"'
recovered='"'"$REMOTE_RUN_DIR/persistent-transaction.recovered"'"'
expected_tx_identity='"'"$PERSISTENT_TX_IDENTITY_SHA256"'"'
if [ -f "$committed" ] && [ ! -L "$committed" ]; then
    [ ! -e "$state" ]
    [ "$(wc -l <"$committed")" -eq 20 ]
    [ "$(sed -n "1p" "$committed")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
    [ "$(sed -n "2p" "$committed")" = "DEPLOY_ID='"$DEPLOY_ID"'" ]
    [ "$(sed -n "3p" "$committed")" = "PHASE=committed" ]
    actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$committed" | sha256sum | awk "{print \$1}")
    [ "$actual_identity" = "$expected_tx_identity" ]
    revoke_tmp="$state.failed.new"
    rm -f "$revoke_tmp"
    awk '\''NR == 3 { print "PHASE=failed"; next } { print }'\'' "$committed" >"$revoke_tmp"
    [ "$(wc -l <"$revoke_tmp")" -eq 20 ]
    actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$revoke_tmp" | sha256sum | awk "{print \$1}")
    [ "$actual_identity" = "$expected_tx_identity" ]
    chmod 600 "$revoke_tmp"
    mv "$revoke_tmp" "$state"
    sync
    rm -f "$committed"
    sync
fi
if [ ! -e "$state" ]; then
    [ -f "$rolled_back" ] || [ -f "$recovered" ]
    exit $?
fi
[ -f "$state" ] && [ ! -L "$state" ]
[ "$(wc -l <"$state")" -eq 20 ]
[ "$(sed -n "1p" "$state")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
[ "$(sed -n "2p" "$state")" = "DEPLOY_ID='"$DEPLOY_ID"'" ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$state" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
tmp="$state.failed.new"
rm -f "$tmp"
awk '\''NR == 3 { print "PHASE=failed"; next } { print }'\'' "$state" >"$tmp"
[ "$(wc -l <"$tmp")" -eq 20 ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$tmp" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
chmod 600 "$tmp"
mv -f "$tmp" "$state"
sync
' >/dev/null 2>&1; then
        PERSISTENT_TX_STATUS="failed_pending_boot_recovery"
        return 0
    fi
    PERSISTENT_TX_STATUS="failure_state_unverified"
    return 1
}

# Commit a persistent generation only after its launch journal (and optional
# API health) has been proven. The final ownership scan deliberately runs
# after this function, so it remains the last remote observation before the
# local receipt is published.
finalize_persistent_transaction() {
    [ "$DEPLOY_MODE" = "persistent" ] || return 0
    local expected_config_path expected_config_sha result
    PERSISTENT_TX_TERMINAL_PATH=""
    if [ -n "$CONFIG_BIND_SHA256" ]; then
        expected_config_path=$CONFIG_REMOTE
        expected_config_sha=$CONFIG_BIND_SHA256
    else
        expected_config_path=builtin
        expected_config_sha=NONE
    fi
    result=$(ssh_run '
set -e
state='"'"$PERSISTENT_TX_STATE_PATH"'"'
committed='"'"$REMOTE_RUN_DIR/persistent-transaction.committed"'"'
expected_tx_identity='"'"$PERSISTENT_TX_IDENTITY_SHA256"'"'
[ -f "$state" ] && [ ! -L "$state" ] && [ ! -e "$committed" ]
[ "$(stat -c "%u:%a:%h" "$state")" = "0:600:1" ]
    [ "$(wc -l <"$state")" -eq 20 ]
    [ "$(sed -n "1p" "$state")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
[ "$(sed -n "2p" "$state")" = "DEPLOY_ID='"$DEPLOY_ID"'" ]
[ "$(sed -n "3p" "$state")" = "PHASE=installed" ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$state" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
[ '"$DEPLOY_EXISTING_STATUS"' != present ] || {
    [ "$(sha256sum '"$BACKUP_PATH"' | awk "{print \$1}")" = '"$DEPLOY_EXISTING_SHA256"' ]
    [ "$(stat -c "%u:%g:%a" '"$BACKUP_PATH"')" = '"$DEPLOY_EXISTING_METADATA"' ]
}
[ '"$PERSISTENT_CONFIG_ORIGINAL_STATUS"' != present ] || {
    [ "$(sha256sum '"$PERSISTENT_CONFIG_BACKUP_PATH"' | awk "{print \$1}")" = '"$PERSISTENT_CONFIG_ORIGINAL_SHA256"' ]
    [ "$(stat -c "%u:%g:%a" '"$PERSISTENT_CONFIG_BACKUP_PATH"')" = '"$PERSISTENT_CONFIG_ORIGINAL_METADATA"' ]
}
[ "$(sha256sum '"'"$DEPLOY_PATH"'"' | awk "{print \$1}")" = '"'"$BINARY_SHA256"'"' ]
[ "$(stat -c "%u:%g:%a" '"'"$DEPLOY_PATH"'"')" = "0:0:755" ]
case '"'"$CONFIG_BIND_SOURCE"'"' in
    explicit)
        [ '"'"$expected_config_path"'"' != builtin ]
        [ "$(sha256sum '"'"$expected_config_path"'"' | awk "{print \$1}")" = '"'"$expected_config_sha"'"' ]
        [ "$(stat -c "%u:%g:%a" '"'"$expected_config_path"'"')" = "0:0:600" ]
        ;;
    discovered)
        [ '"'"$expected_config_path"'"' != builtin ]
        [ "$(sha256sum '"'"$expected_config_path"'"' | awk "{print \$1}")" = '"'"$expected_config_sha"'"' ]
        case "$(stat -c "%u:%g:%a" '"'"$expected_config_path"'"')" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        ;;
    builtin)
        [ '"'"$expected_config_path"'"' = builtin ] && [ '"'"$expected_config_sha"'"' = NONE ]
        [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ] \
            && [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        ;;
    *) exit 1 ;;
esac
tmp="$state.committed.new"
awk '\''NR == 3 { print "PHASE=committed"; next } { print }'\'' "$state" >"$tmp"
[ "$(wc -l <"$tmp")" -eq 20 ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$tmp" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
chmod 600 "$tmp"
mv -f "$tmp" "$state"
sync
# Make the terminal record durable while .state still blocks boot admission.
# Removing .state afterward is cleanup: if its deletion is not durable, boot
# recovery sees the matching committed pair and completes it idempotently.
terminal_tmp="$committed.new"
terminal_sha=$(sha256sum "$state" 2>/dev/null | awk "{print \$1}")
if [ -e "$committed" ] || [ -L "$committed" ]; then
    [ -f "$committed" ] && [ ! -L "$committed" ]
    cmp -s "$state" "$committed"
else
    ln -T "$state" "$committed"
fi
[ -f "$committed" ] && [ ! -L "$committed" ]
cmp -s "$state" "$committed"
if [ "$(stat -c "%d:%i" "$state" 2>/dev/null)" \
        = "$(stat -c "%d:%i" "$committed" 2>/dev/null)" ]; then
    [ "$(stat -c "%u:%a:%h" "$committed" 2>/dev/null)" = "0:600:2" ]
else
    [ "$(stat -c "%u:%a:%h" "$committed" 2>/dev/null)" = "0:600:1" ]
fi
sync
if [ -e "$terminal_tmp" ] || [ -L "$terminal_tmp" ]; then
    [ -f "$terminal_tmp" ] && [ ! -L "$terminal_tmp" ]
    case "$(stat -c "%u:%a:%h" "$terminal_tmp" 2>/dev/null)" in
        0:600:1|0:600:2) ;;
        *) exit 1 ;;
    esac
    rm -f "$terminal_tmp"
    sync
fi
rm -f "$state"
sync || true
[ "$(stat -c "%u:%a:%h" "$committed" 2>/dev/null)" = "0:600:1" ]
[ "$(sha256sum "$committed" 2>/dev/null | awk "{print \$1}")" = "$terminal_sha" ]
printf "PERSISTENT_TX_COMMIT=verified\n"
' 2>/dev/null) || result=""
    [ "$result" = "PERSISTENT_TX_COMMIT=verified" ] || {
        PERSISTENT_TX_STATUS="commit_unverified"
        return 1
    }
    PERSISTENT_TX_STATUS="committed_candidate_generation"
    PERSISTENT_TX_TERMINAL_PATH="$REMOTE_RUN_DIR/persistent-transaction.committed"
}

# Restore only the prior persistent bytes, never an unverified service owner.
# A successful result follows a proven exact-launch stop and restores bytes;
# competing/vendor ownership remains unverified and owner readmission is a
# separate operation with its own process-identity proof.
rollback_persistent_files() {
    [ "$DEPLOY_MODE" = "persistent" ] || return 1
    [ "$PERSISTENT_MUTATION_STARTED" = true ] || return 1
    # Reopening a committed generation removes its terminal marker before byte
    # restoration. Publish a terminal path only after the new marker verifies.
    PERSISTENT_TX_TERMINAL_PATH=""

    if ssh_run '
set -e
deploy_path='"$DEPLOY_PATH"'
backup_path='"$BACKUP_PATH"'
existing_status='"$DEPLOY_EXISTING_STATUS"'
existing_size='"$DEPLOY_EXISTING_SIZE"'
existing_sha='"$DEPLOY_EXISTING_SHA256"'
existing_metadata='"$DEPLOY_EXISTING_METADATA"'
config_mutated='"$PERSISTENT_CONFIG_MUTATION_STARTED"'
config_path='"$CONFIG_REMOTE"'
config_backup='"$PERSISTENT_CONFIG_BACKUP_PATH"'
config_existed='"$PERSISTENT_CONFIG_ORIGINAL_EXISTS"'
config_sha='"$PERSISTENT_CONFIG_ORIGINAL_SHA256"'
config_metadata='"$PERSISTENT_CONFIG_ORIGINAL_METADATA"'
config_candidate_sha='"${CONFIG_BIND_SHA256:-NONE}"'
rollback_config_source='"$ROLLBACK_CONFIG_SOURCE"'
rollback_config_path='"$ROLLBACK_CONFIG_PATH"'
rollback_config_sha='"${ROLLBACK_CONFIG_SHA256:-NONE}"'
deploy_id='"$DEPLOY_ID"'
state='"$PERSISTENT_TX_STATE_PATH"'
committed='"$REMOTE_RUN_DIR/persistent-transaction.committed"'
rolled_back='"$REMOTE_RUN_DIR/persistent-transaction.rolled-back"'
quarantine_dir='"$REMOTE_RUN_DIR/config-retirement"'
deploy_path_helper=/usr/libexec/dcentos/dcentos-deploy-path
expected_tx_identity='"$PERSISTENT_TX_IDENTITY_SHA256"'
[ -x "$deploy_path_helper" ] && [ ! -L "$deploy_path_helper" ]
[ "$(stat -c "%u:%a" "$deploy_path_helper" 2>/dev/null)" = "0:755" ]
if [ -f "$committed" ] && [ ! -L "$committed" ]; then
    [ ! -e "$state" ]
    [ "$(wc -l <"$committed")" -eq 20 ]
    [ "$(sed -n "1p" "$committed")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
    [ "$(sed -n "2p" "$committed")" = "DEPLOY_ID=$deploy_id" ]
    [ "$(sed -n "3p" "$committed")" = "PHASE=committed" ]
    actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$committed" | sha256sum | awk "{print \$1}")
    [ "$actual_identity" = "$expected_tx_identity" ]
    revoke_tmp="$state.rolling-back.new"
    rm -f "$revoke_tmp"
    awk '\''NR == 3 { print "PHASE=rolling_back"; next } { print }'\'' "$committed" >"$revoke_tmp"
    [ "$(wc -l <"$revoke_tmp")" -eq 20 ]
    actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$revoke_tmp" | sha256sum | awk "{print \$1}")
    [ "$actual_identity" = "$expected_tx_identity" ]
    chmod 600 "$revoke_tmp"
    mv "$revoke_tmp" "$state"
    sync
    rm -f "$committed"
    sync
fi
[ -f "$state" ] && [ ! -L "$state" ]
[ "$(wc -l <"$state")" -eq 20 ]
[ "$(sed -n "1p" "$state")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
[ "$(sed -n "2p" "$state")" = "DEPLOY_ID=$deploy_id" ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$state" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
phase=$(sed -n "3s/^PHASE=//p" "$state")
case "$phase" in prepared|mutating|installed|failed|committed|rolling_back) ;; *) exit 1 ;; esac
if [ "$phase" != rolling_back ]; then
    phase_tmp="$state.rolling-back.new"
    awk '\''NR == 3 { print "PHASE=rolling_back"; next } { print }'\'' "$state" >"$phase_tmp"
    [ "$(wc -l <"$phase_tmp")" -eq 20 ]
    actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$phase_tmp" | sha256sum | awk "{print \$1}")
    [ "$actual_identity" = "$expected_tx_identity" ]
    chmod 600 "$phase_tmp"
    mv -f "$phase_tmp" "$state"
    sync
fi

path_is_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

retire_path() {
    "$deploy_path_helper" retire "$1" "$2"
}

restore_path_alias() {
    "$deploy_path_helper" restore-link "$1" "$2"
}

validate_config_retirement_dir() {
    quarantined_config="$quarantine_dir/observed"
    path_is_absent "$quarantine_dir" && return 0
    [ -d "$quarantine_dir" ] && [ ! -L "$quarantine_dir" ] || return 1
    [ "$(stat -c "%u:%a" "$quarantine_dir" 2>/dev/null)" = "0:700" ] || return 1
    quarantine_entry_count=$(find "$quarantine_dir" -mindepth 1 -maxdepth 1 \
        -print 2>/dev/null | wc -l) || return 1
    case "$quarantine_entry_count" in
        0) ;;
        1) [ -e "$quarantined_config" ] || [ -L "$quarantined_config" ] || return 1 ;;
        *) return 1 ;;
    esac
}

restore_quarantined_config() {
    [ -e "$quarantined_config" ] || [ -L "$quarantined_config" ] || return 1
    path_is_absent "$config_path" || return 1
    restore_path_alias "$quarantined_config" "$config_path" || return 1
    ! path_is_absent "$quarantined_config" && ! path_is_absent "$config_path"
}

remove_config_retirement_dir() {
    rm -f "$quarantined_config" || return 1
    sync || return 1
    rmdir "$quarantine_dir" || return 1
    sync || return 1
    path_is_absent "$quarantine_dir"
}

reconcile_config_retirement() {
    validate_config_retirement_dir || return 1
    path_is_absent "$quarantine_dir" && return 0
    if [ "$quarantine_entry_count" -eq 0 ]; then
        rmdir "$quarantine_dir" || return 1
        sync || return 1
        path_is_absent "$quarantine_dir"
        return $?
    fi
    if ! path_is_absent "$config_path"; then
        echo "live and quarantined config objects require manual recovery" >&2
        return 1
    fi
    if [ -f "$quarantined_config" ] && [ ! -L "$quarantined_config" ] \
        && [ "$(sha256sum "$quarantined_config" 2>/dev/null | awk "{print \$1}")" \
            = "$config_candidate_sha" ] \
        && [ "$(stat -c "%u:%g:%a" "$quarantined_config" 2>/dev/null)" \
            = "0:0:600" ]; then
        remove_config_retirement_dir || return 1
        path_is_absent "$config_path"
        return $?
    fi
    if restore_quarantined_config; then
        sync || return 1
        echo "out-of-band config replacement was restored with a retained private alias; rollback remains blocked" >&2
    else
        echo "out-of-band config replacement retained at $quarantined_config" >&2
    fi
    return 1
}

retire_absent_original_config() {
    reconcile_config_retirement || return 1
    path_is_absent "$config_path" && return 0
    mkdir -m 700 "$quarantine_dir" || return 1
    sync || return 1
    quarantined_config="$quarantine_dir/observed"
    if ! retire_path "$config_path" "$quarantined_config"; then
        rmdir "$quarantine_dir" 2>/dev/null || true
        sync || true
        return 1
    fi
    sync || return 1
    reconcile_config_retirement
}

# Validate every required recovery artifact before changing either live path.
if [ "$existing_status" = present ]; then
    [ "$(sha256sum "$backup_path" 2>/dev/null | awk "{print \$1}")" = "$existing_sha" ]
    [ "$(stat -c '%u:%g:%a' "$backup_path" 2>/dev/null)" = "$existing_metadata" ]
fi
if [ "$config_mutated" = true ] && [ "$config_existed" = true ]; then
    [ "$(sha256sum "$config_backup" 2>/dev/null | awk "{print \$1}")" = "$config_sha" ]
    [ "$(stat -c '%u:%g:%a' "$config_backup" 2>/dev/null)" = "$config_metadata" ]
fi
config_absent_rollback_state=not_applicable
if [ "$config_mutated" = true ] && [ "$config_existed" = false ]; then
    reconcile_config_retirement
    if [ ! -e "$config_path" ] && [ ! -L "$config_path" ]; then
        config_absent_rollback_state=absent
    else
        [ -f "$config_path" ] && [ ! -L "$config_path" ]
        [ "$(sha256sum "$config_path" 2>/dev/null | awk "{print \$1}")" = "$config_candidate_sha" ]
        [ "$(stat -c '%u:%g:%a' "$config_path" 2>/dev/null)" = "0:0:600" ]
        config_absent_rollback_state=candidate
    fi
fi
case "$rollback_config_source:$rollback_config_path" in
    data:/data/dcentrald.toml)
        if [ "$config_mutated" = true ]; then
            [ "$config_existed" = true ]
            [ "$(sha256sum "$config_backup" 2>/dev/null | awk "{print \$1}")" = "$rollback_config_sha" ]
            case "$(stat -c '%u:%g:%a' "$config_backup" 2>/dev/null)" in
                0:0:[0-7][0145][0145]) ;;
                *) exit 1 ;;
            esac
        else
            [ "$(sha256sum "$rollback_config_path" 2>/dev/null | awk "{print \$1}")" = "$rollback_config_sha" ]
            case "$(stat -c '%u:%g:%a' "$rollback_config_path" 2>/dev/null)" in
                0:0:[0-7][0145][0145]) ;;
                *) exit 1 ;;
            esac
        fi
        ;;
    etc:/etc/dcentrald.toml)
        [ "$(sha256sum "$rollback_config_path" 2>/dev/null | awk "{print \$1}")" = "$rollback_config_sha" ]
        case "$(stat -c '%u:%g:%a' "$rollback_config_path" 2>/dev/null)" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        [ "$config_mutated" = true ] \
            || { [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ]; }
        ;;
    builtin:builtin)
        [ "$rollback_config_sha" = NONE ]
        [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        [ "$config_mutated" = true ] \
            || { [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ]; }
        ;;
    *) exit 1 ;;
esac

if [ "$existing_status" = present ]; then
    restore_tmp="$deploy_path.dcent-restore.$deploy_id"
    rm -f "$restore_tmp"
    cp -p "$backup_path" "$restore_tmp"
    [ "$(sha256sum "$restore_tmp" 2>/dev/null | awk "{print \$1}")" = "$existing_sha" ]
    [ "$(stat -c '%u:%g:%a' "$restore_tmp" 2>/dev/null)" = "$existing_metadata" ]
    mv -f "$restore_tmp" "$deploy_path"
    [ "$(sha256sum "$deploy_path" 2>/dev/null | awk "{print \$1}")" = "$existing_sha" ]
    [ "$(stat -c '%u:%g:%a' "$deploy_path" 2>/dev/null)" = "$existing_metadata" ]
else
    rm -f "$deploy_path"
    [ ! -e "$deploy_path" ]
fi
if [ "$config_mutated" = true ]; then
    if [ "$config_existed" = true ]; then
        restore_tmp="$config_path.dcent-restore.$deploy_id"
        rm -f "$restore_tmp"
        cp -p "$config_backup" "$restore_tmp"
        [ "$(sha256sum "$restore_tmp" 2>/dev/null | awk "{print \$1}")" = "$config_sha" ]
        [ "$(stat -c '%u:%g:%a' "$restore_tmp" 2>/dev/null)" = "$config_metadata" ]
        mv -f "$restore_tmp" "$config_path"
        [ "$(sha256sum "$config_path" 2>/dev/null | awk "{print \$1}")" = "$config_sha" ]
        [ "$(stat -c '%u:%g:%a' "$config_path" 2>/dev/null)" = "$config_metadata" ]
    else
        case "$config_absent_rollback_state" in
            absent|candidate)
                retire_absent_original_config
                ;;
            *) exit 1 ;;
        esac
    fi
fi
case "$rollback_config_source:$rollback_config_path" in
    data:/data/dcentrald.toml)
        [ "$(sha256sum "$rollback_config_path" 2>/dev/null | awk "{print \$1}")" = "$rollback_config_sha" ]
        case "$(stat -c '%u:%g:%a' "$rollback_config_path" 2>/dev/null)" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        ;;
    etc:/etc/dcentrald.toml)
        [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ]
        [ "$(sha256sum "$rollback_config_path" 2>/dev/null | awk "{print \$1}")" = "$rollback_config_sha" ]
        case "$(stat -c '%u:%g:%a' "$rollback_config_path" 2>/dev/null)" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        ;;
    builtin:builtin)
        [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ] \
            && [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        ;;
esac
sync
[ ! -e "$quarantine_dir" ] && [ ! -L "$quarantine_dir" ]
phase_tmp="$state.rolled-back.new"
awk '\''NR == 3 { print "PHASE=rolled_back"; next } { print }'\'' "$state" >"$phase_tmp"
[ "$(wc -l <"$phase_tmp")" -eq 20 ]
actual_identity=$(awk '\''NR == 3 { print "PHASE=CANONICAL"; next } { print }'\'' "$phase_tmp" | sha256sum | awk "{print \$1}")
[ "$actual_identity" = "$expected_tx_identity" ]
chmod 600 "$phase_tmp"
mv -f "$phase_tmp" "$state"
sync
terminal_tmp="$rolled_back.new"
terminal_sha=$(sha256sum "$state" 2>/dev/null | awk "{print \$1}")
if [ -e "$rolled_back" ] || [ -L "$rolled_back" ]; then
    [ -f "$rolled_back" ] && [ ! -L "$rolled_back" ]
    cmp -s "$state" "$rolled_back"
else
    ln -T "$state" "$rolled_back"
fi
[ -f "$rolled_back" ] && [ ! -L "$rolled_back" ]
cmp -s "$state" "$rolled_back"
if [ "$(stat -c "%d:%i" "$state" 2>/dev/null)" \
        = "$(stat -c "%d:%i" "$rolled_back" 2>/dev/null)" ]; then
    [ "$(stat -c "%u:%a:%h" "$rolled_back" 2>/dev/null)" = "0:600:2" ]
else
    [ "$(stat -c "%u:%a:%h" "$rolled_back" 2>/dev/null)" = "0:600:1" ]
fi
sync
if [ -e "$terminal_tmp" ] || [ -L "$terminal_tmp" ]; then
    [ -f "$terminal_tmp" ] && [ ! -L "$terminal_tmp" ]
    case "$(stat -c "%u:%a:%h" "$terminal_tmp" 2>/dev/null)" in
        0:600:1|0:600:2) ;;
        *) exit 1 ;;
    esac
    rm -f "$terminal_tmp"
    sync
fi
rm -f "$state"
sync || true
[ "$(stat -c "%u:%a:%h" "$rolled_back" 2>/dev/null)" = "0:600:1" ]
[ "$(sha256sum "$rolled_back" 2>/dev/null | awk "{print \$1}")" = "$terminal_sha" ]
printf "PERSISTENT_ROLLBACK=files_restored_launch_stopped_ownership_unverified\n"' 2>/dev/null |
        grep -Fqx 'PERSISTENT_ROLLBACK=files_restored_launch_stopped_ownership_unverified'; then
        PERSISTENT_TX_STATUS="rolled_back_prior_generation"
        PERSISTENT_TX_TERMINAL_PATH="$REMOTE_RUN_DIR/persistent-transaction.rolled-back"
        return 0
    fi
    return 1
}

cleanup_uncommitted_runtime_on_exit() {
    local exit_status=$?
    local exit_cleanup_ok=true
    trap - EXIT INT TERM HUP
    if [ "$DEPLOY_MODE" = "persistent" ] \
       && [ "$PERSISTENT_LAUNCH_COMMITTED" != "true" ] &&
       { [ "$PERSISTENT_MUTATION_STARTED" = true ] ||
         [ "$PERSISTENT_TX_PUBLISH_ATTEMPTED" = true ]; }; then
        if ! cleanup_persistent_launch; then
            exit_cleanup_ok=false
        elif [ "$PERSISTENT_MUTATION_STARTED" = true ] \
            && [ "$ROLLBACK_ON_FAIL" = true ]; then
            rollback_persistent_files || exit_cleanup_ok=false
        fi
        if [ "$PERSISTENT_MUTATION_STARTED" = true ]; then
            mark_persistent_transaction_failed || exit_cleanup_ok=false
        fi
    else
        cleanup_runtime_launch || exit_cleanup_ok=false
    fi
    if [ "$exit_cleanup_ok" = true ]; then
        release_deploy_maintenance || true
    fi
    exit "$exit_status"
}

# Once a runtime daemon has an exact PID/start/exe identity, every local error,
# interrupt, or lost-output path must reclaim that same process until the
# atomic success receipt is published. Publication is not power-loss durability;
# the handler is harmless before launch and
# for persistent/dashboard deploys.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap cleanup_uncommitted_runtime_on_exit EXIT

scp_put() {
    local local_path="$1"
    local remote_path="$2"
    if [ "$SSH_TRANSPORT" = "putty" ]; then
        if [ -n "${DCENT_HOSTKEY:-}" ]; then
            pscp.exe -scp -batch -pw "${DCENT_PASSWORD}" -hostkey "${DCENT_HOSTKEY}" "$local_path" "$remote_path"
        else
            pscp.exe -scp -batch -pw "${DCENT_PASSWORD}" "$local_path" "$remote_path"
        fi
    else
        scp -O $SSH_OPTS "$local_path" "$remote_path"
    fi
}

log_step "Connecting to $MINER_IP"
if ! ssh_run "echo OK" >/dev/null 2>&1; then
    log "ERROR: Cannot SSH to root@$MINER_IP"
    json_exit false null 0 false "SSH connection failed"
fi
log "  SSH OK"
log "  SSH transport: $SSH_TRANSPORT"

if [ -n "${DCENT_EXPECTED_MAC:-}" ]; then
    EXPECTED_MAC_NORMALIZED=$(printf '%s' "$DCENT_EXPECTED_MAC" | tr 'A-F' 'a-f')
    if ! printf '%s' "$EXPECTED_MAC_NORMALIZED" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
        log "ERROR: DCENT_EXPECTED_MAC must be xx:xx:xx:xx:xx:xx"
        json_exit false null 0 false "Invalid expected MAC"
    fi
    OBSERVED_MAC=$(ssh_run 'tr "A-F" "a-f" </sys/class/net/eth0/address 2>/dev/null | tr -d "\r\n"' 2>/dev/null) || OBSERVED_MAC=""
    if [ "$OBSERVED_MAC" != "$EXPECTED_MAC_NORMALIZED" ]; then
        log "ERROR: eth0 identity mismatch ($OBSERVED_MAC != $EXPECTED_MAC_NORMALIZED)"
        json_exit false null 0 false "Physical unit identity mismatch"
    fi
    log "  eth0 MAC: $OBSERVED_MAC (exact operator-record match)"
fi

# W5.1 (2026-05-07): --dashboard-only fast path. The dashboard SPA was
# decoupled from dcentrald (`include_str!` retired, build.rs deleted) and
# now ships as a static asset served by server.py from
# /usr/share/dcentos-dashboard/index.html. We can refresh just that file
# without touching the daemon — no Rust rebuild, no binary swap, no
# /etc/init.d/S82dcentrald restart, no risk of corrupting hardware.
#
# This block is platform-agnostic on purpose: every supported platform
# (zynq, am2, amlogic, beaglebone) ships server.py and the same install
# path, so the deploy is identical. Skips all the platform-detect and
# binary-deploy machinery below.
if [ "$DASHBOARD_ONLY" = true ]; then
    DEPLOY_MODE="dashboard-only"
    PLATFORM_FAMILY="any"
    DEPLOY_PATH="/usr/share/dcentos-dashboard/index.html"
    CONFIG_USED="not_applicable"
    CONFIG_BIND_SOURCE="not_applicable"
    DEPLOY_EXISTING_STATUS="not_applicable"
    PERSISTENT_CONFIG_ORIGINAL_STATUS="not_applicable"
    ROLLBACK_CONFIG_SOURCE="not_applicable"
    API_VERIFICATION_STATUS="not_performed"
    log_step "Dashboard-only deploy"
    LOCAL_DASHBOARD="${DCENT_DEV_DEPLOY_DASHBOARD_OVERRIDE:-$PROJECT_DIR/dashboard/dist/index.html}"
    LOCAL_DASHBOARD_GZ="$LOCAL_DASHBOARD.gz"
    LOCAL_DASHBOARD_SHA="$LOCAL_DASHBOARD.sha256"
    if [ ! -f "$LOCAL_DASHBOARD" ]; then
        log "ERROR: dashboard not found at $LOCAL_DASHBOARD"
        log "  Run: cd DCENT_OS_Antminer/dashboard && npm run build"
        json_exit false null 0 false "dashboard/dist/index.html missing — run npm run build"
    fi
    DASHBOARD_BYTES=$(stat -c%s "$LOCAL_DASHBOARD" 2>/dev/null || stat -f%z "$LOCAL_DASHBOARD" 2>/dev/null || echo 0)
    if [ "${DASHBOARD_BYTES:-0}" -lt 100000 ]; then
        log "ERROR: dashboard appears truncated ($DASHBOARD_BYTES bytes < 100 KB floor)"
        log "  Real vite-plugin-singlefile builds are several hundred KB."
        log "  Did 'npm run build' fail? Re-run and re-check dist/index.html."
        json_exit false null "$DASHBOARD_BYTES" false "dashboard truncated"
    fi
    LOCAL_SHA=$(compute_sha256_local "$LOCAL_DASHBOARD" 2>/dev/null || echo "")
    if [ -z "$LOCAL_SHA" ]; then
        log "ERROR: could not compute sha256 for $LOCAL_DASHBOARD"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard sha256 sidecar failed"
    fi
    # Always regenerate both companions from the bytes being deployed. Mtime is
    # not an integrity relation and may preserve a stale, newer sidecar.
    LOCAL_DASHBOARD_GZ_NEW="$LOCAL_DASHBOARD_GZ.new.$$"
    LOCAL_DASHBOARD_SHA_NEW="$LOCAL_DASHBOARD_SHA.new.$$"
    rm -f "$LOCAL_DASHBOARD_GZ_NEW" "$LOCAL_DASHBOARD_SHA_NEW"
    log "  Regenerating bound gzip + SHA256 sidecars"
    if ! gzip -9 -c "$LOCAL_DASHBOARD" > "$LOCAL_DASHBOARD_GZ_NEW"; then
        rm -f "$LOCAL_DASHBOARD_GZ_NEW" "$LOCAL_DASHBOARD_SHA_NEW"
        log "ERROR: could not generate $LOCAL_DASHBOARD_GZ"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard gzip sidecar failed"
    fi
    printf '%s\n' "$LOCAL_SHA" > "$LOCAL_DASHBOARD_SHA_NEW"
    LOCAL_GZ_CONTENT_SHA=$(gzip -cd "$LOCAL_DASHBOARD_GZ_NEW" 2>/dev/null | compute_sha256_local /dev/stdin 2>/dev/null || echo "")
    if [ "$LOCAL_GZ_CONTENT_SHA" != "$LOCAL_SHA" ]; then
        rm -f "$LOCAL_DASHBOARD_GZ_NEW" "$LOCAL_DASHBOARD_SHA_NEW"
        log "ERROR: generated gzip sidecar did not decode to the dashboard bytes"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard gzip sidecar verification failed"
    fi
    mv -f "$LOCAL_DASHBOARD_GZ_NEW" "$LOCAL_DASHBOARD_GZ"
    mv -f "$LOCAL_DASHBOARD_SHA_NEW" "$LOCAL_DASHBOARD_SHA"
    log "  Local:  $LOCAL_DASHBOARD ($DASHBOARD_BYTES bytes)"

    REMOTE_DIR="/usr/share/dcentos-dashboard"
    REMOTE_INDEX="$REMOTE_DIR/index.html"
    REMOTE_GZ="$REMOTE_DIR/index.html.gz"
    REMOTE_SHA_FILE="$REMOTE_DIR/index.html.sha256"
    REMOTE_STAGE="$REMOTE_DIR/.index.html.$DEPLOY_ID.new"
    REMOTE_GZ_STAGE="$REMOTE_DIR/.index.html.gz.$DEPLOY_ID.new"
    REMOTE_SHA_STAGE="$REMOTE_DIR/.index.html.sha256.$DEPLOY_ID.new"

    # Pre-create the directory + ensure it's writable. On older overlays
    # /usr/share/dcentos-dashboard may not exist yet (pre-W5.1 image).
    if ! ssh_run "set -e; mkdir -p '$REMOTE_DIR'; [ -d '$REMOTE_DIR' ] && [ ! -L '$REMOTE_DIR' ]"; then
        json_exit false null "$DASHBOARD_BYTES" false "dashboard destination preparation failed"
    fi

    log "  Uploading to $REMOTE_STAGE"
    if ! scp_put "$LOCAL_DASHBOARD" "root@${MINER_IP}:$REMOTE_STAGE"; then
        log "ERROR: scp upload failed"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard scp failed"
    fi
    if ! scp_put "$LOCAL_DASHBOARD_GZ" "root@${MINER_IP}:$REMOTE_GZ_STAGE"; then
        log "ERROR: gzip sidecar scp upload failed"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard gzip scp failed"
    fi
    if ! scp_put "$LOCAL_DASHBOARD_SHA" "root@${MINER_IP}:$REMOTE_SHA_STAGE"; then
        log "ERROR: sha256 sidecar scp upload failed"
        json_exit false null "$DASHBOARD_BYTES" false "dashboard sha256 scp failed"
    fi

    # Transactional three-file swap with exact rollback. index.html moves last
    # as the commit file; no daemon restart is needed.
    log "  Atomic swap → $REMOTE_INDEX"
    DASHBOARD_SWAP_RESULT=$(ssh_run '
set -e
index='"$REMOTE_INDEX"'
gzip_file='"$REMOTE_GZ"'
sha_file='"$REMOTE_SHA_FILE"'
index_stage='"$REMOTE_STAGE"'
gzip_stage='"$REMOTE_GZ_STAGE"'
sha_stage='"$REMOTE_SHA_STAGE"'
expected_sha='"$LOCAL_SHA"'
suffix='"$DEPLOY_ID"'
index_backup="$index.backup.$suffix"
gzip_backup="$gzip_file.backup.$suffix"
sha_backup="$sha_file.backup.$suffix"
index_present=false
gzip_present=false
sha_present=false
swap_started=false
committed=false
restore_one() {
    live=$1
    backup=$2
    present=$3
    if [ "$present" = true ]; then
        restore="$live.restore.$suffix"
        rm -f "$restore"
        ln "$backup" "$restore"
        mv -f "$restore" "$live"
    else
        rm -f "$live"
    fi
}
rollback() {
    [ "$committed" = false ] || return 0
    if [ "$swap_started" = true ]; then
        restore_one "$index" "$index_backup" "$index_present"
        restore_one "$gzip_file" "$gzip_backup" "$gzip_present"
        restore_one "$sha_file" "$sha_backup" "$sha_present"
        sync
    fi
    rm -f "$index_stage" "$gzip_stage" "$sha_stage" \
        "$index_backup" "$gzip_backup" "$sha_backup"
}
trap rollback EXIT HUP INT TERM
for staged in "$index_stage" "$gzip_stage" "$sha_stage"; do
    [ -f "$staged" ] && [ ! -L "$staged" ]
done
[ "$(sha256sum "$index_stage" | awk "{print \$1}")" = "$expected_sha" ]
[ "$(gzip -cd "$gzip_stage" | sha256sum | awk "{print \$1}")" = "$expected_sha" ]
[ "$(wc -l <"$sha_stage")" -eq 1 ]
[ "$(cat "$sha_stage")" = "$expected_sha" ]
for spec in "$index:$index_backup:index_present" \
            "$gzip_file:$gzip_backup:gzip_present" \
            "$sha_file:$sha_backup:sha_present"; do
    live=${spec%%:*}
    rest=${spec#*:}
    backup=${rest%%:*}
    flag=${rest##*:}
    rm -f "$backup"
    if [ -e "$live" ]; then
        [ -f "$live" ] && [ ! -L "$live" ]
        ln "$live" "$backup"
        case "$flag" in
            index_present) index_present=true ;;
            gzip_present) gzip_present=true ;;
            sha_present) sha_present=true ;;
        esac
    fi
done
sync
swap_started=true
chmod 644 "$index_stage" "$gzip_stage" "$sha_stage"
mv -f "$gzip_stage" "$gzip_file"
mv -f "$sha_stage" "$sha_file"
mv -f "$index_stage" "$index"
[ "$(sha256sum "$index" | awk "{print \$1}")" = "$expected_sha" ]
[ "$(gzip -cd "$gzip_file" | sha256sum | awk "{print \$1}")" = "$expected_sha" ]
[ "$(wc -l <"$sha_file")" -eq 1 ]
[ "$(cat "$sha_file")" = "$expected_sha" ]
sync
committed=true
trap - EXIT HUP INT TERM
rm -f "$index_backup" "$gzip_backup" "$sha_backup"
sync
printf "DASHBOARD_SWAP_SHA256=%s\n" "$expected_sha"' 2>/dev/null) || DASHBOARD_SWAP_RESULT=""
    REMOTE_SHA=$(single_assignment_value "$DASHBOARD_SWAP_RESULT" DASHBOARD_SWAP_SHA256 2>/dev/null) || REMOTE_SHA=""
    if [ "$REMOTE_SHA" != "$LOCAL_SHA" ]; then
        log "ERROR: dashboard artifact-set transaction failed (local=$LOCAL_SHA remote=$REMOTE_SHA)"
        json_exit false null "$DASHBOARD_BYTES" false "Dashboard remote SHA256 verification failed"
    fi
    log "  SHA256 match: $LOCAL_SHA"

    log ""
    log "=== Dashboard-only deploy complete ==="
    log "  Target:      root@$MINER_IP:$REMOTE_INDEX"
    log "  Bytes:       $DASHBOARD_BYTES"
    DEPLOY_END=$(date +%s)
    DEPLOY_TIME=$((DEPLOY_END - DEPLOY_START))
    log "  Deploy time: ${DEPLOY_TIME}s (no Rust rebuild, no daemon restart)"
    log "  Verify:      curl -s http://$MINER_IP/api/dashboard/version"
    BINARY_SHA256=$LOCAL_SHA
    DEPLOY_PATH=$REMOTE_INDEX
    json_exit true null "$DASHBOARD_BYTES" false "Dashboard-only deploy successful"
fi

# Pre-deploy /tmp hygiene + read-only /data inventory.
# /tmp on S9 is a 64 MB tmpfs. Stale dcentrald.log* and old sysupgrade
# tarballs accumulate across deploys and can starve the staging step.
# /data is the canonical staging surface for sysupgrade tarballs (per
# ). Inventory its free space without the
# former touch/rm probe: even a temporary probe is a persistent write and made
# runtime-only acceptance claims false. A persistent copy reports its own
# failure later if the mount is not writable.
log_step "Pre-deploy /tmp cleanup + read-only /data inventory"
PRE_DEPLOY_INFO=$(ssh_run "
    rm -f /tmp/dcentrald.log* /tmp/*.tar 2>/dev/null
    TMP_FREE_KB=\$(df -Pk /tmp 2>/dev/null | awk 'NR==2 {print \$4}')
    DATA_FREE_KB=\$(df -Pk /data 2>/dev/null | awk 'NR==2 {print \$4}')
    echo TMP_FREE_KB=\${TMP_FREE_KB:-0}
    echo DATA_FREE_KB=\${DATA_FREE_KB:-0}
" 2>/dev/null) || true
TMP_FREE_KB=$(single_assignment_value "$PRE_DEPLOY_INFO" TMP_FREE_KB 2>/dev/null) || TMP_FREE_KB=0
DATA_FREE_KB=$(single_assignment_value "$PRE_DEPLOY_INFO" DATA_FREE_KB 2>/dev/null) || DATA_FREE_KB=0
case "$TMP_FREE_KB" in ""|*[!0-9]*) TMP_FREE_KB=0 ;; esac
case "$DATA_FREE_KB" in ""|*[!0-9]*) DATA_FREE_KB=0 ;; esac
log "  /tmp free after cleanup:  $((TMP_FREE_KB / 1024)) MB"
log "  /data free:               $((DATA_FREE_KB / 1024)) MB"
log "  /data writable:           not probed (persistent-write-free preflight)"

# Serialize before owner inventory: otherwise S82 could complete admission
# after an empty snapshot and before this deploy begins its stop/mutate path.
# The /run marker spans this script's many SSH commands; the kernel-lock
# handshake drains any S82 already inside recovery-to-child-exec admission.
if ! acquire_deploy_maintenance; then
    log "ERROR: Could not acquire dcentrald deploy/admission exclusion"
    json_exit false null 0 false "Deploy admission exclusion failed"
fi

log_step "Detecting miner platform"
if ! MINER_INFO=$(ssh_run '
    printf "SNAPSHOT_SCHEMA=dcent-miner-info-v1\n"
    echo "BOSMINER_PID=$(pidof bosminer 2>/dev/null || echo NONE)"
    echo "BOSTOOLS_PID=$(pidof bos-tools 2>/dev/null || echo NONE)"
    echo "BOSER_PID=$(pidof boser 2>/dev/null || echo NONE)"
    DCENTRALD_PIDS=""
    DCENTRALD_IDENTITIES=""
    DCENTRALD_UNVERIFIABLE=""
    for proc in /proc/[0-9]*; do
        exe=$(readlink "$proc/exe" 2>/dev/null || true)
        base=${exe##*/}
        base=${base% (deleted)}
        cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
        cmdbase=${cmd0##*/}
        case "$base,$cmdbase" in
            dcentrald,*|dcentrald_runtime,*|*,dcentrald|*,dcentrald_runtime)
                pid=${proc##*/}
                start=$(sed "s/^[^)]*) //" "$proc/stat" 2>/dev/null | awk "{print \$20}")
                case "$start" in
                    ""|*[!0-9]*)
                        DCENTRALD_UNVERIFIABLE="$DCENTRALD_UNVERIFIABLE $pid"
                        continue
                        ;;
                esac
                if [ -z "$exe" ]; then
                    DCENTRALD_UNVERIFIABLE="$DCENTRALD_UNVERIFIABLE $pid"
                    continue
                fi
                case "$exe" in /*) ;; *) DCENTRALD_UNVERIFIABLE="$DCENTRALD_UNVERIFIABLE $pid"; continue ;; esac
                case "$exe" in
                    *[!A-Za-z0-9_./+-]*) DCENTRALD_UNVERIFIABLE="$DCENTRALD_UNVERIFIABLE $pid"; continue ;;
                esac
                DCENTRALD_PIDS="$DCENTRALD_PIDS $pid"
                record="$pid:$start:$exe"
                if [ -n "$DCENTRALD_IDENTITIES" ]; then
                    DCENTRALD_IDENTITIES="$DCENTRALD_IDENTITIES,$record"
                else
                    DCENTRALD_IDENTITIES="$record"
                fi
                ;;
        esac
    done
    DCENTRALD_PIDS=${DCENTRALD_PIDS# }
    DCENTRALD_UNVERIFIABLE=${DCENTRALD_UNVERIFIABLE# }
    printf "DCENTRALD_PID=%s\n" "${DCENTRALD_PIDS:-NONE}"
    printf "DCENTRALD_IDENTITIES=%s\n" "$DCENTRALD_IDENTITIES"
    printf "DCENTRALD_UNVERIFIABLE=%s\n" "$DCENTRALD_UNVERIFIABLE"
    echo "OS_VER=$(cat /etc/dcentos-version 2>/dev/null || echo NONE)"
    echo "BOS_VER=$(cat /etc/bos_version 2>/dev/null | head -1 || echo NONE)"
    echo "BOS_PLATFORM=$(cat /etc/bos_platform 2>/dev/null | head -1 || echo NONE)"
    echo "ARCH=$(uname -m 2>/dev/null || echo unknown)"
    if [ -f /sys/devices/soc0/soc_id ]; then
        echo "SOC=$(cat /sys/devices/soc0/soc_id 2>/dev/null)"
    elif grep -q zynq /proc/cpuinfo 2>/dev/null; then
        echo "SOC=zynq"
    else
        echo "SOC=unknown"
    fi
    MODEL="$(cat /config/CONF_MINER_TYPE 2>/dev/null || cat /proc/device-tree/model 2>/dev/null || echo)"
    echo "MODEL=$MODEL"
    HWID="$(cat /config/CONF_HARDWARE_ID 2>/dev/null || echo)"
    echo "HWID=$HWID"
    echo "UIO_COUNT=$(find /sys/class/uio -maxdepth 1 -name "uio*" 2>/dev/null | wc -l)"
    printf "SNAPSHOT_COMPLETE=dcent-miner-info-v1\n"
    ' 2>/dev/null); then
    log "ERROR: miner platform snapshot transport failed"
    json_exit false null 0 false "Miner platform snapshot transport failed"
fi

if [ "$(printf '%s\n' "$MINER_INFO" | sed -n '1p')" != "SNAPSHOT_SCHEMA=dcent-miner-info-v1" ] ||
   [ "$(printf '%s\n' "$MINER_INFO" | sed -n '$p')" != "SNAPSHOT_COMPLETE=dcent-miner-info-v1" ] ||
   [ "$(printf '%s\n' "$MINER_INFO" | awk 'END { print NR }')" -ne 16 ]; then
    log "ERROR: miner platform snapshot was truncated, reordered, or unframed"
    json_exit false null 0 false "Miner platform snapshot was incomplete"
fi

snapshot_line_number=0
for snapshot_key in \
    SNAPSHOT_SCHEMA BOSMINER_PID BOSTOOLS_PID BOSER_PID DCENTRALD_PID \
    DCENTRALD_IDENTITIES DCENTRALD_UNVERIFIABLE OS_VER BOS_VER BOS_PLATFORM \
    ARCH SOC MODEL HWID UIO_COUNT SNAPSHOT_COMPLETE
do
    snapshot_line_number=$((snapshot_line_number + 1))
    snapshot_line=$(printf '%s\n' "$MINER_INFO" | sed -n "${snapshot_line_number}p")
    case "$snapshot_line" in
        "$snapshot_key="*) ;;
        *)
            log "ERROR: miner platform snapshot field order differed at $snapshot_key"
            json_exit false null 0 false "Miner platform snapshot schema was invalid"
            ;;
    esac
    snapshot_value=$(single_assignment_value "$MINER_INFO" "$snapshot_key" 2>/dev/null) || {
        log "ERROR: miner platform snapshot field $snapshot_key is missing or duplicated"
        json_exit false null 0 false "Miner platform snapshot schema was invalid"
    }
    printf -v "$snapshot_key" '%s' "$snapshot_value"
done
if [ "$SNAPSHOT_SCHEMA" != "dcent-miner-info-v1" ] ||
   [ "$SNAPSHOT_COMPLETE" != "dcent-miner-info-v1" ]; then
    log "ERROR: miner platform snapshot schema marker mismatch"
    json_exit false null 0 false "Miner platform snapshot schema was invalid"
fi
case "$UIO_COUNT" in ""|*[!0-9]*)
    log "ERROR: miner platform snapshot UIO_COUNT is not an unsigned integer"
    json_exit false null 0 false "Miner platform snapshot schema was invalid"
    ;;
esac

if [ -n "${DCENTRALD_UNVERIFIABLE:-}" ]; then
    log "ERROR: recognized dcentrald owner(s) lack a revalidatable PID/start/exe identity: $DCENTRALD_UNVERIFIABLE"
    json_exit false null 0 false "Existing dcentrald ownership could not be proven"
fi

SOC_LC=$(printf '%s' "$SOC" | tr '[:upper:]' '[:lower:]')
MODEL_LC=$(printf '%s' "$MODEL" | tr '[:upper:]' '[:lower:]')
HWID_LC=$(printf '%s' "$HWID" | tr '[:upper:]' '[:lower:]')
BOS_PLATFORM_LC=$(printf '%s' "${BOS_PLATFORM:-}" | tr '[:upper:]' '[:lower:]')

# Primary signal: /etc/bos_platform (most reliable). BraiinsOS ships it on
# every am1/am2 board and it cannot drift from the real hardware.
#   zynq-am1-s9       → am1
#   zynq-bm3-am2      → am2 (S17 / S19 / S19j Pro early / T17 / T19)
#   aarch64 variants  → amlogic (handled via ARCH below)
if [[ "$BOS_PLATFORM_LC" == "zynq-bm3-am2" ]]; then
    PLATFORM_FAMILY="am2"
    PLATFORM_DESC="AM2 runtime-only (detected via /etc/bos_platform)"
    TARGET="armv7-unknown-linux-musleabihf"
    DEPLOY_MODE="runtime-only"
    DEPLOY_PATH="/tmp/dcentrald_runtime"
    STAGING_PATH="/tmp/dcentrald_runtime.new"
    CONFIG_REMOTE="/tmp/dcentrald.runtime.toml"
    VERIFY_TIMEOUT=30
elif [[ "$BOS_PLATFORM_LC" == "zynq-am1-s9" ]]; then
    PLATFORM_FAMILY="am1"
    PLATFORM_DESC="AM1 persistent (detected via /etc/bos_platform)"
    TARGET="armv7-unknown-linux-musleabihf"
    DEPLOY_MODE="persistent"
    DEPLOY_PATH="/data/dcentrald"
    BACKUP_PATH="/tmp/dcentrald_backup"
    STAGING_PATH="/tmp/dcentrald_new"
    CONFIG_REMOTE="/data/dcentrald.toml"
    HAS_PERSISTENT_SUPERVISOR=true
elif [[ "$ARCH" == "aarch64" ]] || [[ "$SOC_LC" == *"amlogic"* ]] || [[ "$MODEL_LC" == *"amlogic"* ]]; then
    PLATFORM_FAMILY="amlogic"
    PLATFORM_DESC="Amlogic runtime-only"
    TARGET="aarch64-unknown-linux-musl"
    DEPLOY_MODE="runtime-only"
    DEPLOY_PATH="/tmp/dcentrald_runtime"
    STAGING_PATH="/tmp/dcentrald_runtime.new"
    CONFIG_REMOTE="/tmp/dcentrald.runtime.toml"
    VERIFY_TIMEOUT=30
elif [ "${UIO_COUNT:-0}" -ge 19 ] || [[ "$HWID_LC" == *"am2"* ]] || [[ "$MODEL_LC" == *"s17"* ]] || [[ "$MODEL_LC" == *"s19"* ]] || [[ "$MODEL_LC" == *"t17"* ]] || [[ "$MODEL_LC" == *"t19"* ]]; then
    # Fallback heuristic when /etc/bos_platform is unavailable (stock Bitmain
    # firmware, degraded boot, or non-BraiinsOS baseline).
    PLATFORM_FAMILY="am2"
    PLATFORM_DESC="AM2 runtime-only (UIO/HWID heuristic)"
    TARGET="armv7-unknown-linux-musleabihf"
    DEPLOY_MODE="runtime-only"
    DEPLOY_PATH="/tmp/dcentrald_runtime"
    STAGING_PATH="/tmp/dcentrald_runtime.new"
    CONFIG_REMOTE="/tmp/dcentrald.runtime.toml"
    VERIFY_TIMEOUT=30
else
    PLATFORM_FAMILY="am1"
    PLATFORM_DESC="AM1 persistent"
    TARGET="armv7-unknown-linux-musleabihf"
    DEPLOY_MODE="persistent"
    DEPLOY_PATH="/data/dcentrald"
    BACKUP_PATH="/tmp/dcentrald_backup"
    STAGING_PATH="/tmp/dcentrald_new"
    CONFIG_REMOTE="/data/dcentrald.toml"
    HAS_PERSISTENT_SUPERVISOR=true
fi

if [ "$FORCE_RUNTIME_ONLY" = true ]; then
    DEPLOY_MODE="runtime-only"
    DEPLOY_PATH="/tmp/dcentrald_runtime"
    STAGING_PATH="/tmp/dcentrald_runtime.new"
    CONFIG_REMOTE="/tmp/dcentrald.runtime.toml"
    BACKUP_PATH=""
    HAS_PERSISTENT_SUPERVISOR=false
    PLATFORM_DESC="$PLATFORM_DESC; forced /tmp-only by operator"
    VERIFY_TIMEOUT=30
fi

if [ "$DEPLOY_MODE" = "persistent" ]; then
    PERSISTENT_TX_SCHEMA="dcent-persistent-tx-v4"
fi

DEPLOY_DIR="$(dirname "$DEPLOY_PATH")"

if [ "$DEPLOY_MODE" = "runtime-only" ] && [ -z "$CONFIG_FILE" ]; then
    log "ERROR: $PLATFORM_FAMILY runtime-only deploy requires an explicit --config so the launched process can be bound to immutable content."
    json_exit false null 0 false "Explicit config required for runtime-only $PLATFORM_FAMILY deploy"
fi
if [ "$DEPLOY_MODE" = "persistent" ] && [ -z "$JSON_OUTPUT_FILE" ]; then
    log "ERROR: persistent deployment requires --output FILE so the mutation has a retained transaction receipt"
    json_exit false null 0 false "Persistent deploy requires a receipt output file"
fi
if [ "$DEPLOY_MODE" = "persistent" ] && ! probe_persistent_recovery_capability; then
    log "ERROR: target boot recovery does not explicitly support persistent transaction schema v4"
    json_exit false null 0 false "Persistent recovery schema v4 is unsupported by target"
fi

log "  Platform:    $PLATFORM_DESC"
log "  Arch:        $ARCH"
log "  SoC:         $SOC"
log "  bos_platform: ${BOS_PLATFORM:-NONE}"
log "  Model:       ${MODEL:-unknown}"
log "  HWID:        ${HWID:-unknown}"
log "  UIO count:   ${UIO_COUNT:-0}"
log "  BraiinsOS:   $BOS_VER"
log "  DCENTos:     $OS_VER"
log "  bosminer:    PID=$BOSMINER_PID"
log "  bos-tools:   PID=$BOSTOOLS_PID"
log "  boser:       PID=$BOSER_PID"
log "  dcentrald:   PID=$DCENTRALD_PID"

if [ "$MINER_IP" = "203.0.113.109" ] || [[ "${CONFIG_FILE:-}" == *"dcentrald_s19jpro_xil.toml"* ]]; then
    log "ERROR: XIL is a home-quiet target. Generic dev_deploy.sh uses raw bosminer stop/kill paths and is blocked for this unit."
    log "See the home-quiet handoff procedure in the project documentation."
    json_exit false null 0 false "XIL requires guarded quiet handoff; generic dev_deploy blocked"
fi

BINARY="$WORKSPACE_DIR/target/$TARGET/release/dcentrald"
if [ -n "${DCENT_DEV_DEPLOY_BINARY_OVERRIDE:-}" ]; then
    if [ "$SKIP_BUILD" != true ]; then
        log "ERROR: DCENT_DEV_DEPLOY_BINARY_OVERRIDE is valid only with --skip-build"
        json_exit false null 0 false "Binary override requires --skip-build"
    fi
    BINARY=$DCENT_DEV_DEPLOY_BINARY_OVERRIDE
fi

if [ "$SKIP_BUILD" = false ]; then
    log_step "Building dcentrald (release, $TARGET)"
    cd "$WORKSPACE_DIR"

    # Export zig-cc wrappers for crates with build.rs (ring, secp256k1-sys,
    # reqwest, rumqttc) when the caller hasn't set their own cross-compiler.
    # rust-lld links; the CC crate needs an actual C cross-compiler. Without
    # these, cargo fails with `failed to find tool 'arm-linux-musleabihf-gcc'`.
    # See dcentrald/.cargo/config.toml for why we don't default this via
    # cargo's [env] block on Windows.
    case "$TARGET" in
        armv7-unknown-linux-musleabihf)
            : "${CC_armv7_unknown_linux_musleabihf:=$WORKSPACE_DIR/zig-cc-arm.bat}"
            : "${AR_armv7_unknown_linux_musleabihf:=$WORKSPACE_DIR/zig-ar-arm.bat}"
            export CC_armv7_unknown_linux_musleabihf AR_armv7_unknown_linux_musleabihf
            log "  CC_armv7_unknown_linux_musleabihf=$CC_armv7_unknown_linux_musleabihf"
            ;;
        aarch64-unknown-linux-musl)
            : "${CC_aarch64_unknown_linux_musl:=$WORKSPACE_DIR/zig-cc-aarch64.bat}"
            : "${AR_aarch64_unknown_linux_musl:=$WORKSPACE_DIR/zig-ar-aarch64.bat}"
            export CC_aarch64_unknown_linux_musl AR_aarch64_unknown_linux_musl
            log "  CC_aarch64_unknown_linux_musl=$CC_aarch64_unknown_linux_musl"
            ;;
    esac

    if ! cargo build --release --target "$TARGET" 2>&1 | while IFS= read -r line; do log "  $line"; done; then
        log "ERROR: Build failed"
        json_exit false null 0 false "Build failed"
    fi
    log "  Build complete."
else
    log_step "Skipping build (--skip-build)"
fi

if [ ! -f "$BINARY" ]; then
    log "ERROR: Binary not found at $BINARY"
    log "Run without --skip-build to compile first."
    json_exit false null 0 false "Binary not found at $BINARY"
fi

BINARY_SIZE=$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY" 2>/dev/null || echo 0)
BINARY_MB=$(( BINARY_SIZE / 1024 / 1024 ))
BINARY_SHA256=$(compute_sha256_local "$BINARY") || {
    log "ERROR: Could not compute SHA256 for $BINARY"
    json_exit false null "$BINARY_SIZE" false "Could not compute local binary SHA256"
}
log "  Binary: $BINARY_SIZE bytes (${BINARY_MB} MB)"
log "  SHA256: $BINARY_SHA256"

if [ -n "$CONFIG_FILE" ]; then
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR: Config file not found: $CONFIG_FILE"
        json_exit false null "$BINARY_SIZE" false "Config file not found: $CONFIG_FILE"
    fi
    CONFIG_UPLOAD_SIZE=$(stat -c%s "$CONFIG_FILE" 2>/dev/null || stat -f%z "$CONFIG_FILE" 2>/dev/null || echo 0)
    case "$CONFIG_UPLOAD_SIZE" in ""|*[!0-9]*) CONFIG_UPLOAD_SIZE=0 ;; esac
fi

if [ "$DEPLOY_MODE" = "persistent" ]; then
    log_step "Preflight space check"
    REMOTE_SPACE_INFO=$(ssh_run "
        TMP_FREE_KB=\$(df -k /tmp 2>/dev/null | awk 'NR==2 {print \$4}')
        DEPLOY_FREE_KB=\$(df -k '$DEPLOY_DIR' 2>/dev/null | awk 'NR==2 {print \$4}')
        DEPLOY_FREE_INODES=\$(df -Pi '$DEPLOY_DIR' 2>/dev/null | awk 'NR==2 {print \$4}')
        EXISTING_STATUS=absent
        EXISTING_SIZE=0
        EXISTING_SHA256=NONE
        EXISTING_METADATA=NONE
        CONFIG_EXISTING_SIZE=0
        if [ -e '$DEPLOY_PATH' ] || [ -L '$DEPLOY_PATH' ]; then
            EXISTING_STATUS=present
            [ -f '$DEPLOY_PATH' ] && [ ! -L '$DEPLOY_PATH' ] || EXISTING_STATUS=invalid
        fi
        if [ "\$EXISTING_STATUS" = present ]; then
            EXISTING_SIZE=\$(wc -c < '$DEPLOY_PATH' 2>/dev/null || echo 0)
            EXISTING_SHA256=\$(sha256sum '$DEPLOY_PATH' 2>/dev/null | awk '{print \$1}')
            EXISTING_METADATA=\$(stat -c '%u:%g:%a' '$DEPLOY_PATH' 2>/dev/null)
        fi
        if [ -f /data/dcentrald.toml ]; then
            CONFIG_EXISTING_SIZE=\$(wc -c < /data/dcentrald.toml 2>/dev/null || echo 0)
        fi
        echo TMP_FREE_BYTES=\$((\${TMP_FREE_KB:-0} * 1024))
        echo DEPLOY_FREE_BYTES=\$((\${DEPLOY_FREE_KB:-0} * 1024))
        echo DEPLOY_FREE_INODES=\${DEPLOY_FREE_INODES:-0}
        echo DEPLOY_EXISTING_STATUS=\${EXISTING_STATUS:-invalid}
        echo DEPLOY_EXISTING_SIZE=\${EXISTING_SIZE:-0}
        echo DEPLOY_EXISTING_SHA256=\${EXISTING_SHA256:-NONE}
        echo DEPLOY_EXISTING_METADATA=\${EXISTING_METADATA:-NONE}
        echo CONFIG_EXISTING_SIZE=\${CONFIG_EXISTING_SIZE:-0}
    " 2>/dev/null) || true

    TMP_FREE_BYTES=$(single_assignment_value "$REMOTE_SPACE_INFO" TMP_FREE_BYTES 2>/dev/null) || TMP_FREE_BYTES=0
    DEPLOY_FREE_BYTES=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_FREE_BYTES 2>/dev/null) || DEPLOY_FREE_BYTES=0
    DEPLOY_FREE_INODES=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_FREE_INODES 2>/dev/null) || DEPLOY_FREE_INODES=0
    DEPLOY_EXISTING_STATUS=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_EXISTING_STATUS 2>/dev/null) || DEPLOY_EXISTING_STATUS=unavailable
    DEPLOY_EXISTING_SIZE=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_EXISTING_SIZE 2>/dev/null) || DEPLOY_EXISTING_SIZE=0
    DEPLOY_EXISTING_SHA256=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_EXISTING_SHA256 2>/dev/null) || DEPLOY_EXISTING_SHA256=""
    DEPLOY_EXISTING_METADATA=$(single_assignment_value "$REMOTE_SPACE_INFO" DEPLOY_EXISTING_METADATA 2>/dev/null) || DEPLOY_EXISTING_METADATA=""
    CONFIG_EXISTING_SIZE=$(single_assignment_value "$REMOTE_SPACE_INFO" CONFIG_EXISTING_SIZE 2>/dev/null) || CONFIG_EXISTING_SIZE=0
    case "$TMP_FREE_BYTES" in ""|*[!0-9]*) TMP_FREE_BYTES=0 ;; esac
    case "$DEPLOY_FREE_BYTES" in ""|*[!0-9]*) DEPLOY_FREE_BYTES=0 ;; esac
    case "$DEPLOY_FREE_INODES" in ""|*[!0-9]*) DEPLOY_FREE_INODES=0 ;; esac
    case "$CONFIG_EXISTING_SIZE" in ""|*[!0-9]*) CONFIG_EXISTING_SIZE=0 ;; esac
    if [ "$DEPLOY_EXISTING_STATUS" = present ]; then
        case "$DEPLOY_EXISTING_SIZE" in
            ""|*[!0-9]*)
                log "ERROR: existing persistent binary size could not be captured exactly"
                json_exit false null "$BINARY_SIZE" false "Existing persistent binary size was unavailable"
                ;;
        esac
        if ! printf '%s\n' "$DEPLOY_EXISTING_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
            log "ERROR: existing persistent binary hash could not be captured exactly"
            json_exit false null "$BINARY_SIZE" false "Existing persistent binary hash was unavailable"
        fi
        if ! printf '%s\n' "$DEPLOY_EXISTING_METADATA" | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$'; then
            log "ERROR: existing persistent binary metadata could not be captured exactly"
            json_exit false null "$BINARY_SIZE" false "Existing persistent binary metadata was unavailable"
        fi
    elif [ "$DEPLOY_EXISTING_STATUS" = absent ] \
        && [ "$DEPLOY_EXISTING_SIZE" = 0 ] \
        && [ "$DEPLOY_EXISTING_SHA256" = NONE ] \
        && [ "$DEPLOY_EXISTING_METADATA" = NONE ]; then
        DEPLOY_EXISTING_SHA256=""
        DEPLOY_EXISTING_METADATA="NONE"
    else
        log "ERROR: persistent binary inventory was internally inconsistent"
        json_exit false null "$BINARY_SIZE" false "Existing persistent binary inventory was inconsistent"
    fi

    # Persistent staging, independent recovery copies, and installation all
    # live on the target filesystem. Block-rounded candidate + backup usage
    # and an explicit free-space reserve are accounted before any write.
    BINARY_ALLOCATED_BYTES=$((((BINARY_SIZE + 4095) / 4096) * 4096))
    CONFIG_ALLOCATED_BYTES=$((((CONFIG_UPLOAD_SIZE + 4095) / 4096) * 4096))
    BINARY_BACKUP_ALLOCATED_BYTES=$((((DEPLOY_EXISTING_SIZE + 4095) / 4096) * 4096))
    CONFIG_BACKUP_ALLOCATED_BYTES=0
    if [ -n "$CONFIG_FILE" ]; then
        CONFIG_BACKUP_ALLOCATED_BYTES=$((((CONFIG_EXISTING_SIZE + 4095) / 4096) * 4096))
    fi
    DEPLOY_REQUIRED_BYTES=$((BINARY_ALLOCATED_BYTES + CONFIG_ALLOCATED_BYTES + BINARY_BACKUP_ALLOCATED_BYTES + CONFIG_BACKUP_ALLOCATED_BYTES + PERSISTENT_MIN_FREE_RESERVE_BYTES))

    log "  /tmp free:            $TMP_FREE_BYTES bytes"
    log "  $DEPLOY_DIR free:     $DEPLOY_FREE_BYTES bytes"
    log "  $DEPLOY_DIR inodes:   $DEPLOY_FREE_INODES free"
    log "  Existing binary size: $DEPLOY_EXISTING_SIZE bytes"

    if [ "$DEPLOY_FREE_BYTES" -lt "$DEPLOY_REQUIRED_BYTES" ]; then
        log "ERROR: Not enough $DEPLOY_DIR space for block-rounded staging plus reserve (need $DEPLOY_REQUIRED_BYTES bytes)"
        json_exit false null "$BINARY_SIZE" false "Insufficient persistent storage space for durable staging"
    fi
    if [ "$DEPLOY_FREE_INODES" -lt "$PERSISTENT_MIN_FREE_INODES" ]; then
        log "ERROR: Not enough $DEPLOY_DIR inodes for a recoverable transaction (need $PERSISTENT_MIN_FREE_INODES free)"
        json_exit false null "$BINARY_SIZE" false "Insufficient persistent storage inodes for durable staging"
    fi
fi

# All root-written binary staging and backup files live beneath a fresh 0700
# directory. Persistent transactions use the target filesystem so independent
# recovery copies and atomic renames remain power-loss recoverable across reboot.
if [ "$DEPLOY_MODE" = "persistent" ]; then
    REMOTE_RUN_DIR="/data/.dcent-deploy-recovery/$DEPLOY_ID"
    REMOTE_RUN_INFO=$(ssh_run '
set -e
umask 077
base=/data/.dcent-deploy-recovery
run_dir='"'"$REMOTE_RUN_DIR"'"'
lease="$base/.deploy-lease"
if [ -e "$base" ]; then
    [ -d "$base" ] && [ ! -L "$base" ]
else
    mkdir "$base"
fi
chmod 700 "$base"
base_meta=$(stat -c "%u:%a:%h" "$base" 2>/dev/null)
case "$base_meta" in 0:700:[2-9]|0:700:[1-9][0-9]*) ;; *) exit 1 ;; esac
[ "$(stat -c "%d" "$base" 2>/dev/null)" = "$(stat -c "%d" /data 2>/dev/null)" ]
set -- "$base"/*/persistent-transaction.state
if [ -e "$1" ] || [ -L "$1" ]; then
    exit 1
fi
[ ! -e "$lease" ] && [ ! -L "$lease" ]
mkdir "$lease"
chmod 700 "$lease"
printf "%s\n" '"'"$DEPLOY_ID"'"' >"$lease/owner.pending"
chmod 600 "$lease/owner.pending"
sync
mkdir "$run_dir"
run_meta=$(stat -c "%u:%a:%h" "$run_dir" 2>/dev/null)
case "$run_meta" in 0:700:[2-9]|0:700:[1-9][0-9]*) ;; *) rmdir "$run_dir"; exit 1 ;; esac
sync
mv "$lease/owner.pending" "$lease/owner"
sync
printf "REMOTE_RUN_DIR_READY=true\n"' 2>/dev/null) || REMOTE_RUN_INFO=""
    if [ "$REMOTE_RUN_INFO" != "REMOTE_RUN_DIR_READY=true" ]; then
        LEASE_ACQUIRE_PROBE=$(ssh_run '
set -e
base=/data/.dcent-deploy-recovery
lease="$base/.deploy-lease"
run_dir='"'"$REMOTE_RUN_DIR"'"'
owner="$lease/owner"
pending="$lease/owner.pending"
[ -d "$lease" ] && [ ! -L "$lease" ]
[ "$(stat -c "%u:%a" "$lease" 2>/dev/null)" = "0:700" ]
[ -d "$run_dir" ] && [ ! -L "$run_dir" ]
run_meta=$(stat -c "%u:%a:%h" "$run_dir" 2>/dev/null)
case "$run_meta" in 0:700:[2-9]|0:700:[1-9][0-9]*) ;; *) exit 1 ;; esac
if [ -f "$pending" ] && [ ! -L "$pending" ] \
    && [ ! -e "$owner" ] && [ ! -L "$owner" ] \
    && [ "$(stat -c "%u:%a:%h" "$pending" 2>/dev/null)" = "0:600:1" ] \
    && [ "$(cat "$pending")" = '"'"$DEPLOY_ID"'"' ]; then
    mv "$pending" "$owner"
fi
[ -f "$owner" ] && [ ! -L "$owner" ]
[ "$(stat -c "%u:%a:%h" "$owner" 2>/dev/null)" = "0:600:1" ]
[ "$(cat "$owner")" = '"'"$DEPLOY_ID"'"' ]
entry_count=0
for entry in "$lease"/* "$lease"/.[!.]* "$lease"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    [ "$entry" = "$owner" ]
    entry_count=$((entry_count + 1))
done
[ "$entry_count" -eq 1 ]
sync
printf "PERSISTENT_DEPLOY_LEASE_OBSERVED=held\n"
' 2>/dev/null) || LEASE_ACQUIRE_PROBE=""
        if [ "$LEASE_ACQUIRE_PROBE" = "PERSISTENT_DEPLOY_LEASE_OBSERVED=held" ]; then
            PERSISTENT_DEPLOY_LEASE_ACQUIRED=true
            PERSISTENT_DEPLOY_LEASE_STATUS="held"
        else
            PERSISTENT_DEPLOY_LEASE_STATUS="ambiguous"
            PERSISTENT_DEPLOY_LEASE_AMBIGUITY_STAGE="acquisition"
            log "ERROR: Persistent recovery-directory acquisition is ambiguous on the target"
            json_exit false null "$BINARY_SIZE" false "Persistent recovery directory acquisition is ambiguous"
        fi
    else
        PERSISTENT_DEPLOY_LEASE_ACQUIRED=true
        PERSISTENT_DEPLOY_LEASE_STATUS="held"
    fi
else
    REMOTE_RUN_INFO=$(ssh_run '
        umask 077
        run_dir=$(mktemp -d /tmp/dcent-deploy.XXXXXX) || exit 1
        metadata=$(stat -c "%u:%a:%h" "$run_dir" 2>/dev/null || true)
        case "$metadata" in 0:700:[2-9]|0:700:[1-9][0-9]*) ;; *) rmdir "$run_dir"; exit 1 ;; esac
        printf "REMOTE_RUN_DIR=%s\n" "$run_dir"
    ' 2>/dev/null) || REMOTE_RUN_INFO=""
    REMOTE_RUN_DIR=$(single_assignment_value "$REMOTE_RUN_INFO" REMOTE_RUN_DIR 2>/dev/null) || REMOTE_RUN_DIR=""
    case "$REMOTE_RUN_DIR" in
        /tmp/dcent-deploy.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
        *)
            REMOTE_RUN_DIR=""
            log "ERROR: Could not create and validate a fresh private remote deploy directory"
            json_exit false null "$BINARY_SIZE" false "Private remote deploy directory creation failed"
            ;;
    esac
fi
STAGING_PATH="$REMOTE_RUN_DIR/dcentrald.new"
if [ "$DEPLOY_MODE" = "persistent" ]; then
    BACKUP_PATH="$REMOTE_RUN_DIR/dcentrald.backup"
    PERSISTENT_TX_STATE_PATH="$REMOTE_RUN_DIR/persistent-transaction.state"
fi
LAUNCH_ID=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]') || LAUNCH_ID=""
if ! printf '%s\n' "$LAUNCH_ID" | grep -Eq '^[0-9a-f]{32}$'; then
    log "ERROR: Could not generate a strong launch identity"
    json_exit false null "$BINARY_SIZE" false "Launch identity generation failed"
fi

if [ -n "$CONFIG_FILE" ]; then
    log_step "Uploading config: $CONFIG_FILE"
    CONFIG_BIND_SHA256=$(compute_sha256_local "$CONFIG_FILE") || {
        log "ERROR: Could not compute SHA256 for config $CONFIG_FILE"
        json_exit false null "$BINARY_SIZE" false "Could not hash explicit config"
    }
    CONFIG_BIND_SOURCE="explicit"
    if [ "$DEPLOY_MODE" = "runtime-only" ]; then
        RUNTIME_CONFIG_DIR="/tmp/dcentrald-runtime.${CONFIG_BIND_SHA256}.${DEPLOY_START}.$$"
        CONFIG_REMOTE="$RUNTIME_CONFIG_DIR/dcentrald.toml"
        if ! ssh_run "umask 077; mkdir '$RUNTIME_CONFIG_DIR'" >/dev/null 2>&1; then
            log "ERROR: Could not create a fresh private runtime-config directory"
            json_exit false null "$BINARY_SIZE" false "Private runtime config directory creation failed"
        fi
        if ! scp_put "$CONFIG_FILE" "root@$MINER_IP:$CONFIG_REMOTE.new"; then
            log "ERROR: Runtime config upload failed"
            json_exit false null "$BINARY_SIZE" false "Runtime config upload failed"
        fi
        if ! ssh_run "set -e; [ -f '$CONFIG_REMOTE.new' ] && [ ! -L '$CONFIG_REMOTE.new' ]; ACTUAL=\$(sha256sum '$CONFIG_REMOTE.new' | awk '{print \$1}'); [ \"\$ACTUAL\" = '$CONFIG_BIND_SHA256' ]; chmod 400 '$CONFIG_REMOTE.new'; mv '$CONFIG_REMOTE.new' '$CONFIG_REMOTE'; META=\$(stat -c '%u:%a:%h' '$CONFIG_REMOTE'); [ \"\$META\" = '0:400:1' ]" >/dev/null 2>&1; then
            log "ERROR: Runtime config could not be sealed as a root-owned, single-link, mode-0400 file"
            json_exit false null "$BINARY_SIZE" false "Runtime config sealing failed"
        fi
        CONFIG_CANDIDATE_REMOTE="$CONFIG_REMOTE"
    else
        PERSISTENT_CONFIG_STAGE_PATH="$REMOTE_RUN_DIR/dcentrald.toml.new"
        if ! scp_put "$CONFIG_FILE" "root@$MINER_IP:$PERSISTENT_CONFIG_STAGE_PATH"; then
            log "ERROR: Persistent config staging upload failed"
            json_exit false null "$BINARY_SIZE" false "Persistent config staging upload failed"
        fi
        CONFIG_CANDIDATE_REMOTE="$PERSISTENT_CONFIG_STAGE_PATH"
    fi
    REMOTE_CONFIG_SHA256=$(ssh_run "sha256sum '$CONFIG_CANDIDATE_REMOTE' 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || REMOTE_CONFIG_SHA256=""
    if [ "$REMOTE_CONFIG_SHA256" != "$CONFIG_BIND_SHA256" ]; then
        log "ERROR: Explicit config hash mismatch on miner"
        ssh_run "rm -f '$CONFIG_CANDIDATE_REMOTE'" 2>/dev/null || true
        json_exit false null "$BINARY_SIZE" false "Uploaded config hash mismatch"
    fi
    log "  Staged immutable config candidate at $CONFIG_CANDIDATE_REMOTE (SHA256=$CONFIG_BIND_SHA256)"
elif [ "$DEPLOY_MODE" = "persistent" ]; then
    # Bind an inherited persistent config to the exact bytes observed, or bind
    # the deliberate absence of both supported config paths. The start script
    # revalidates this selection immediately before exec.
    INHERITED_CONFIG_INFO=$(ssh_run '
set -e
for candidate in /data/dcentrald.toml /etc/dcentrald.toml; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        [ -f "$candidate" ] && [ ! -L "$candidate" ]
        digest=$(sha256sum "$candidate" | awk "{print \$1}")
        metadata=$(stat -c "%u:%g:%a" "$candidate")
        case "$metadata" in 0:0:[0-7][0145][0145]) ;; *) exit 1 ;; esac
        printf "CONFIG_BIND_SOURCE=discovered\nCONFIG_BIND_PATH=%s\nCONFIG_BIND_SHA256=%s\nCONFIG_BIND_METADATA=%s\n" \
            "$candidate" "$digest" "$metadata"
        exit 0
    fi
done
printf "CONFIG_BIND_SOURCE=builtin\nCONFIG_BIND_PATH=builtin\nCONFIG_BIND_SHA256=NONE\nCONFIG_BIND_METADATA=NONE\n"' 2>/dev/null) || INHERITED_CONFIG_INFO=""
    CONFIG_BIND_SOURCE=$(single_assignment_value "$INHERITED_CONFIG_INFO" CONFIG_BIND_SOURCE 2>/dev/null) || CONFIG_BIND_SOURCE=""
    INHERITED_CONFIG_PATH=$(single_assignment_value "$INHERITED_CONFIG_INFO" CONFIG_BIND_PATH 2>/dev/null) || INHERITED_CONFIG_PATH=""
    CONFIG_BIND_SHA256=$(single_assignment_value "$INHERITED_CONFIG_INFO" CONFIG_BIND_SHA256 2>/dev/null) || CONFIG_BIND_SHA256=""
    CONFIG_BIND_METADATA=$(single_assignment_value "$INHERITED_CONFIG_INFO" CONFIG_BIND_METADATA 2>/dev/null) || CONFIG_BIND_METADATA=""
    case "$CONFIG_BIND_SOURCE:$INHERITED_CONFIG_PATH:$CONFIG_BIND_SHA256" in
        discovered:/data/dcentrald.toml:[0-9a-f]*|discovered:/etc/dcentrald.toml:[0-9a-f]*)
            if ! printf '%s\n' "$CONFIG_BIND_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
                log "ERROR: inherited persistent config hash was malformed"
                json_exit false null "$BINARY_SIZE" false "Inherited persistent config binding failed"
            fi
            case "$CONFIG_BIND_METADATA" in
                0:0:[0-7][0145][0145]) ;;
                *)
                    log "ERROR: inherited persistent config is not root-owned and non-writable by group/other"
                    json_exit false null "$BINARY_SIZE" false "Inherited persistent config metadata was unsafe"
                    ;;
            esac
            CONFIG_REMOTE="$INHERITED_CONFIG_PATH"
            case "$CONFIG_REMOTE" in
                /data/dcentrald.toml) ROLLBACK_CONFIG_SOURCE=data ;;
                /etc/dcentrald.toml) ROLLBACK_CONFIG_SOURCE=etc ;;
                *)
                    log "ERROR: inherited persistent config path was not supported"
                    json_exit false null "$BINARY_SIZE" false "Inherited persistent config binding failed"
                    ;;
            esac
            ROLLBACK_CONFIG_PATH=$CONFIG_REMOTE
            ROLLBACK_CONFIG_SHA256=$CONFIG_BIND_SHA256
            log "  Bound inherited config $CONFIG_REMOTE (SHA256=$CONFIG_BIND_SHA256)"
            ;;
        builtin:builtin:NONE)
            CONFIG_BIND_SHA256=""
            [ "$CONFIG_BIND_METADATA" = NONE ] || {
                log "ERROR: builtin config binding unexpectedly carried metadata"
                json_exit false null "$BINARY_SIZE" false "Inherited persistent config binding failed"
            }
            CONFIG_EXPECTED_BUILTIN=true
            ROLLBACK_CONFIG_SOURCE=builtin
            ROLLBACK_CONFIG_PATH=builtin
            ROLLBACK_CONFIG_SHA256=""
            log "  Bound config selection to builtin defaults (no persistent config present)"
            ;;
        *)
            log "ERROR: inherited persistent config could not be captured exactly"
            json_exit false null "$BINARY_SIZE" false "Inherited persistent config binding failed"
            ;;
    esac
fi

log_step "Stopping daemons"

if [ -n "$DCENTRALD_IDENTITIES" ]; then
    log "  Stopping exact dcentrald process identity set (PID $DCENTRALD_PID) — SIGTERM for graceful shutdown..."
    STOP_RESULT=$(ssh_run '
identities='"'"$DCENTRALD_IDENTITIES"'"'
expectfile='"'"$EXPECTFILE"'"'
identity_matches() {
    [ -r "/proc/$pid/stat" ] || return 1
    current_start=$(sed "s/^[^)]*) //" "/proc/$pid/stat" 2>/dev/null | awk "{print \$20}")
    current_exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    [ "$current_start" = "$expected_start" ] && [ "$current_exe" = "$expected_exe" ]
}
old_ifs=$IFS
IFS=,
for record in $identities; do
    pid=${record%%:*}
    rest=${record#*:}
    expected_start=${rest%%:*}
    expected_exe=${rest#*:}
    case "$pid:$expected_start" in *[!0-9:]*|:*|*:) continue ;; esac
    identity_matches || continue
    printf "%s\n" "$pid" >"$expectfile" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 30); do
        identity_matches || break
        sleep 1
    done
    if identity_matches; then
        kill -9 "$pid" 2>/dev/null || true
        for i in $(seq 1 10); do
            identity_matches || break
            sleep 1
        done
    fi
    rm -f "$expectfile"
done
IFS=$old_ifs
remaining=""
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    base=${exe##*/}; base=${base% (deleted)}
    cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
    cmdbase=${cmd0##*/}
    case "$base,$cmdbase" in
        dcentrald,*|dcentrald_runtime,*|*,dcentrald|*,dcentrald_runtime)
            remaining="$remaining ${proc##*/}" ;;
    esac
done
remaining=${remaining# }
printf "STOP_RESULT=%s\n" "${remaining:-OK}"' 2>/dev/null) || STOP_RESULT="STOP_RESULT=UNKNOWN"
    case "$STOP_RESULT" in
        STOP_RESULT=OK) log "  Exact dcentrald process identity set stopped" ;;
        *)
            log "ERROR: dcentrald stop was not proven; refusing to deploy over remaining or changed owner ($STOP_RESULT)"
            json_exit false null "$BINARY_SIZE" false "Existing dcentrald ownership changed or did not terminate"
            ;;
    esac
fi

VENDOR_OWNER_INFO=$(ssh_run '
identities=""
unverifiable=""
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    base=${exe##*/}; base=${base% (deleted)}
    cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
    cmdbase=${cmd0##*/}
    case "$base,$cmdbase" in
        bosminer,*|*,bosminer|bos-tools,*|*,bos-tools|boser,*|*,boser)
            pid=${proc##*/}
            start=$(sed "s/^[^)]*) //" "$proc/stat" 2>/dev/null | awk "{print \$20}")
            case "$pid:$start" in *[!0-9:]*|:*|*:) unverifiable="$unverifiable $pid"; continue ;; esac
            [ -n "$exe" ] || { unverifiable="$unverifiable $pid"; continue; }
            case "$exe" in /*) ;; *) unverifiable="$unverifiable $pid"; continue ;; esac
            case "$exe" in
                *[!A-Za-z0-9_./+-]*) unverifiable="$unverifiable $pid"; continue ;;
            esac
            record="$pid:$start:$exe"
            if [ -n "$identities" ]; then identities="$identities,$record"; else identities="$record"; fi
            ;;
    esac
done
printf "BOS_OWNER_IDENTITIES=%s\nBOS_OWNER_UNVERIFIABLE=%s\n" "$identities" "${unverifiable# }"' 2>/dev/null) || VENDOR_OWNER_INFO="BOS_OWNER_UNVERIFIABLE=snapshot-failed"
if ! printf '%s\n' "$VENDOR_OWNER_INFO" | awk '
    NR == 1 && index($0, "BOS_OWNER_IDENTITIES=") == 1 { identities = 1; next }
    NR == 2 && index($0, "BOS_OWNER_UNVERIFIABLE=") == 1 { unverifiable = 1; next }
    { malformed = 1 }
    END { exit !(NR == 2 && identities && unverifiable && !malformed) }
' >/dev/null 2>&1; then
    BOS_OWNER_IDENTITIES=""
    BOS_OWNER_UNVERIFIABLE="snapshot-invalid"
else
    BOS_OWNER_IDENTITIES=$(printf '%s\n' "$VENDOR_OWNER_INFO" | sed -n '1s/^BOS_OWNER_IDENTITIES=//p')
    BOS_OWNER_UNVERIFIABLE=$(printf '%s\n' "$VENDOR_OWNER_INFO" | sed -n '2s/^BOS_OWNER_UNVERIFIABLE=//p')
fi

if [ -n "${BOS_OWNER_UNVERIFIABLE:-}" ]; then
    log "ERROR: vendor miner owner(s) lack a revalidatable PID/start/exe identity: $BOS_OWNER_UNVERIFIABLE"
    json_exit false null "$BINARY_SIZE" false "Vendor miner ownership could not be proven"
fi

if [ -n "${BOS_OWNER_IDENTITIES:-}" ]; then
    if [ "$PLATFORM_FAMILY" = "amlogic" ]; then
        VENDOR_STOP_MODE="immediate"
        log "  Amlogic warm-takeover: stopping the freshly captured exact bosminer/bos-tools/boser identity set..."
    else
        VENDOR_STOP_MODE="graceful"
        log "  Stopping the freshly captured exact bosminer/bos-tools/boser identity set..."
    fi
    VENDOR_STOP_RESULT=$(ssh_run '
identities='"'"$BOS_OWNER_IDENTITIES"'"'
mode='"'"$VENDOR_STOP_MODE"'"'
identity_matches() {
    [ -r "/proc/$pid/stat" ] || return 1
    current_start=$(sed "s/^[^)]*) //" "/proc/$pid/stat" 2>/dev/null | awk "{print \$20}")
    current_exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    [ "$current_start" = "$expected_start" ] && [ "$current_exe" = "$expected_exe" ]
}
signal_exact_set() {
    requested_signal=$1
    old_ifs=$IFS; IFS=,
    for record in $identities; do
        pid=${record%%:*}; rest=${record#*:}
        expected_start=${rest%%:*}; expected_exe=${rest#*:}
        case "$pid:$expected_start" in *[!0-9:]*|:*|*:) continue ;; esac
        identity_matches && kill "$requested_signal" "$pid" 2>/dev/null || true
    done
    IFS=$old_ifs
}
if [ "$mode" = graceful ]; then
    signal_exact_set -TERM
    for i in $(seq 1 10); do
        any=false
        old_ifs=$IFS; IFS=,
        for record in $identities; do
            pid=${record%%:*}; rest=${record#*:}
            expected_start=${rest%%:*}; expected_exe=${rest#*:}
            identity_matches && any=true
        done
        IFS=$old_ifs
        [ "$any" = false ] && break
        sleep 1
    done
fi
signal_exact_set -KILL
sleep 1
remaining=""
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    base=${exe##*/}; base=${base% (deleted)}
    cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
    cmdbase=${cmd0##*/}
    case "$base,$cmdbase" in
        bosminer,*|*,bosminer|bos-tools,*|*,bos-tools|boser,*|*,boser) remaining="$remaining ${proc##*/}" ;;
    esac
done
printf "VENDOR_STOP_RESULT=%s\n" "${remaining# }"
' 2>/dev/null) || VENDOR_STOP_RESULT="VENDOR_STOP_RESULT=UNKNOWN"
    case "$VENDOR_STOP_RESULT" in
        VENDOR_STOP_RESULT=) log "  Exact vendor miner identity set stopped" ;;
        *)
            log "ERROR: vendor miner stop was not proven; refusing launch ($VENDOR_STOP_RESULT)"
            json_exit false null "$BINARY_SIZE" false "Vendor miner ownership changed or did not terminate"
            ;;
    esac
fi

if [ "$DCENTRALD_PID" = "NONE" ] && [ "$BOSMINER_PID" = "NONE" ]; then
    log "  No daemons running."
fi

log_step "Deploying binary"
if [ "$DEPLOY_MODE" = "persistent" ]; then
    if [ "$DEPLOY_EXISTING_STATUS" = present ]; then
        BACKUP_SHA256=$(ssh_run "set -e; [ -f '$DEPLOY_PATH' ] && [ ! -L '$DEPLOY_PATH' ]; [ \"\$(stat -c '%u:%g:%a' '$DEPLOY_PATH')\" = '$DEPLOY_EXISTING_METADATA' ]; rm -f '$BACKUP_PATH'; cp -p '$DEPLOY_PATH' '$BACKUP_PATH'; [ \"\$(stat -c '%d:%i' '$DEPLOY_PATH')\" != \"\$(stat -c '%d:%i' '$BACKUP_PATH')\" ]; [ \"\$(stat -c '%u:%g:%a' '$BACKUP_PATH')\" = '$DEPLOY_EXISTING_METADATA' ]; digest=\$(sha256sum '$BACKUP_PATH' | awk '{print \$1}'); sync; printf '%s\n' \"\$digest\"" 2>/dev/null) || BACKUP_SHA256=""
        if [ "$BACKUP_SHA256" != "$DEPLOY_EXISTING_SHA256" ]; then
            log "ERROR: persistent binary backup hash did not match the captured original"
            json_exit false null "$BINARY_SIZE" false "Persistent binary backup verification failed"
        fi
        PERSISTENT_BACKUP_STATUS="verified_durable_retained"
        log "  Verified durable independent backup $DEPLOY_PATH -> $BACKUP_PATH (SHA256=$BACKUP_SHA256)"
    else
        ssh_run "rm -f '$BACKUP_PATH'" 2>/dev/null || true
        PERSISTENT_BACKUP_STATUS="original_absent"
        log "  No existing persistent binary to back up"
    fi
    if [ -n "$PERSISTENT_CONFIG_STAGE_PATH" ]; then
        PERSISTENT_CONFIG_BACKUP_PATH="$REMOTE_RUN_DIR/dcentrald.toml.backup"
        CONFIG_ORIGINAL_INFO=$(ssh_run "
            set -e
            if [ -e '$CONFIG_REMOTE' ] || [ -L '$CONFIG_REMOTE' ]; then
                [ -f '$CONFIG_REMOTE' ] && [ ! -L '$CONFIG_REMOTE' ]
                CONFIG_ORIGINAL_SHA256=\$(sha256sum '$CONFIG_REMOTE' | awk '{print \$1}')
                CONFIG_ORIGINAL_METADATA=\$(stat -c '%u:%g:%a' '$CONFIG_REMOTE')
                case \"\$CONFIG_ORIGINAL_METADATA\" in 0:0:[0-7][0145][0145]) ;; *) exit 1 ;; esac
                rm -f '$PERSISTENT_CONFIG_BACKUP_PATH'
                cp -p '$CONFIG_REMOTE' '$PERSISTENT_CONFIG_BACKUP_PATH'
                [ \"\$(stat -c '%d:%i' '$CONFIG_REMOTE')\" != \"\$(stat -c '%d:%i' '$PERSISTENT_CONFIG_BACKUP_PATH')\" ]
                [ \"\$(sha256sum '$PERSISTENT_CONFIG_BACKUP_PATH' | awk '{print \$1}')\" = \"\$CONFIG_ORIGINAL_SHA256\" ]
                [ \"\$(stat -c '%u:%g:%a' '$PERSISTENT_CONFIG_BACKUP_PATH')\" = \"\$CONFIG_ORIGINAL_METADATA\" ]
                sync
                printf 'CONFIG_ORIGINAL_EXISTS=true\nCONFIG_ORIGINAL_SHA256=%s\nCONFIG_ORIGINAL_METADATA=%s\nROLLBACK_CONFIG_SOURCE=data\nROLLBACK_CONFIG_PATH=/data/dcentrald.toml\nROLLBACK_CONFIG_SHA256=%s\n' \
                    \"\$CONFIG_ORIGINAL_SHA256\" \"\$CONFIG_ORIGINAL_METADATA\" \"\$CONFIG_ORIGINAL_SHA256\"
            else
                if [ -e /etc/dcentrald.toml ] || [ -L /etc/dcentrald.toml ]; then
                    [ -f /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
                    case \"\$(stat -c '%u:%g:%a' /etc/dcentrald.toml)\" in
                        0:0:[0-7][0145][0145]) ;;
                        *) exit 1 ;;
                    esac
                    ROLLBACK_CONFIG_SHA256=\$(sha256sum /etc/dcentrald.toml | awk '{print \$1}')
                    printf 'CONFIG_ORIGINAL_EXISTS=false\nCONFIG_ORIGINAL_SHA256=NONE\nCONFIG_ORIGINAL_METADATA=NONE\nROLLBACK_CONFIG_SOURCE=etc\nROLLBACK_CONFIG_PATH=/etc/dcentrald.toml\nROLLBACK_CONFIG_SHA256=%s\n' \
                        \"\$ROLLBACK_CONFIG_SHA256\"
                else
                    printf 'CONFIG_ORIGINAL_EXISTS=false\nCONFIG_ORIGINAL_SHA256=NONE\nCONFIG_ORIGINAL_METADATA=NONE\nROLLBACK_CONFIG_SOURCE=builtin\nROLLBACK_CONFIG_PATH=builtin\nROLLBACK_CONFIG_SHA256=NONE\n'
                fi
            fi
        " 2>/dev/null) || CONFIG_ORIGINAL_INFO=""
        PERSISTENT_CONFIG_ORIGINAL_EXISTS=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" CONFIG_ORIGINAL_EXISTS 2>/dev/null) || PERSISTENT_CONFIG_ORIGINAL_EXISTS=""
        PERSISTENT_CONFIG_ORIGINAL_SHA256=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" CONFIG_ORIGINAL_SHA256 2>/dev/null) || PERSISTENT_CONFIG_ORIGINAL_SHA256=""
        PERSISTENT_CONFIG_ORIGINAL_METADATA=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" CONFIG_ORIGINAL_METADATA 2>/dev/null) || PERSISTENT_CONFIG_ORIGINAL_METADATA=""
        ROLLBACK_CONFIG_SOURCE=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" ROLLBACK_CONFIG_SOURCE 2>/dev/null) || ROLLBACK_CONFIG_SOURCE=""
        ROLLBACK_CONFIG_PATH=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" ROLLBACK_CONFIG_PATH 2>/dev/null) || ROLLBACK_CONFIG_PATH=""
        ROLLBACK_CONFIG_SHA256=$(single_assignment_value "$CONFIG_ORIGINAL_INFO" ROLLBACK_CONFIG_SHA256 2>/dev/null) || ROLLBACK_CONFIG_SHA256=""
        case "$PERSISTENT_CONFIG_ORIGINAL_EXISTS:$PERSISTENT_CONFIG_ORIGINAL_SHA256:$ROLLBACK_CONFIG_SOURCE:$ROLLBACK_CONFIG_PATH" in
            true:[0-9a-f][0-9a-f]*:data:/data/dcentrald.toml)
                if ! printf '%s\n' "$PERSISTENT_CONFIG_ORIGINAL_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
                    log "ERROR: prior persistent config backup hash was malformed"
                    json_exit false null "$BINARY_SIZE" false "Persistent config backup verification failed"
                fi
                if ! printf '%s\n' "$PERSISTENT_CONFIG_ORIGINAL_METADATA" | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$'; then
                    log "ERROR: prior persistent config backup metadata was malformed"
                    json_exit false null "$BINARY_SIZE" false "Persistent config backup metadata verification failed"
                fi
                case "$PERSISTENT_CONFIG_ORIGINAL_METADATA" in
                    0:0:[0-7][0145][0145]) ;;
                    *)
                        log "ERROR: prior persistent config metadata permits unsafe mutation"
                        json_exit false null "$BINARY_SIZE" false "Persistent config backup metadata was unsafe"
                        ;;
                esac
                PERSISTENT_CONFIG_BACKUP_STATUS="verified_durable_retained"
                PERSISTENT_CONFIG_ORIGINAL_STATUS="present"
                if [ "$ROLLBACK_CONFIG_SHA256" != "$PERSISTENT_CONFIG_ORIGINAL_SHA256" ]; then
                    log "ERROR: prior persistent config rollback binding did not match its backup"
                    json_exit false null "$BINARY_SIZE" false "Persistent config rollback binding failed"
                fi
                ;;
            false:NONE:etc:/etc/dcentrald.toml)
                [ "$PERSISTENT_CONFIG_ORIGINAL_METADATA" = NONE ] || {
                    log "ERROR: absent prior persistent config carried metadata"
                    json_exit false null "$BINARY_SIZE" false "Persistent config backup metadata verification failed"
                }
                if ! printf '%s\n' "$ROLLBACK_CONFIG_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
                    log "ERROR: fallback /etc config rollback hash was malformed"
                    json_exit false null "$BINARY_SIZE" false "Persistent config rollback binding failed"
                fi
                PERSISTENT_CONFIG_ORIGINAL_SHA256=""
                PERSISTENT_CONFIG_ORIGINAL_METADATA=""
                PERSISTENT_CONFIG_BACKUP_STATUS="original_absent"
                PERSISTENT_CONFIG_ORIGINAL_STATUS="absent"
                ;;
            false:NONE:builtin:builtin)
                [ "$PERSISTENT_CONFIG_ORIGINAL_METADATA" = NONE ] || {
                    log "ERROR: absent prior persistent config carried metadata"
                    json_exit false null "$BINARY_SIZE" false "Persistent config backup metadata verification failed"
                }
                [ "$ROLLBACK_CONFIG_SHA256" = NONE ] || {
                    log "ERROR: builtin rollback binding was malformed"
                    json_exit false null "$BINARY_SIZE" false "Persistent config rollback binding failed"
                }
                PERSISTENT_CONFIG_ORIGINAL_SHA256=""
                PERSISTENT_CONFIG_ORIGINAL_METADATA=""
                PERSISTENT_CONFIG_BACKUP_STATUS="original_absent"
                PERSISTENT_CONFIG_ORIGINAL_STATUS="absent"
                ;;
            *)
                log "ERROR: prior persistent config could not be captured and verified"
                json_exit false null "$BINARY_SIZE" false "Persistent config backup verification failed"
                ;;
        esac
    fi
else
    log "  Runtime-only mode — persistent system binary will not be modified"
fi

log "  Uploading binary ($BINARY_SIZE bytes)..."
if ! scp_put "$BINARY" "root@$MINER_IP:$STAGING_PATH"; then
    json_exit false null "$BINARY_SIZE" false "Binary staging upload failed"
fi
REMOTE_STAGE_SHA256=$(ssh_run "sha256sum '$STAGING_PATH' 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || REMOTE_STAGE_SHA256=""
if [ "$REMOTE_STAGE_SHA256" != "$BINARY_SHA256" ]; then
    log "ERROR: Staging hash mismatch on miner ($REMOTE_STAGE_SHA256 != $BINARY_SHA256)"
    ssh_run "rm -f '$STAGING_PATH'" 2>/dev/null || true
    json_exit false null "$BINARY_SIZE" false "Uploaded staging binary hash mismatch"
fi
log "  Staging SHA256 verified"

if [ "$DEPLOY_MODE" = "persistent" ]; then
    BINARY_ORIGINAL_SHA_FIELD=${DEPLOY_EXISTING_SHA256:-NONE}
    [ "$DEPLOY_EXISTING_STATUS" = present ] || BINARY_ORIGINAL_SHA_FIELD=NONE
    TX_CONFIG_MUTATED=false
    TX_CONFIG_PATH=${CONFIG_REMOTE:-builtin}
    TX_CONFIG_ORIGINAL_STATUS=not_captured
    TX_CONFIG_ORIGINAL_SHA=NONE
    TX_CONFIG_ORIGINAL_METADATA=NONE
    TX_CONFIG_BACKUP=NONE
    TX_CONFIG_CANDIDATE_SHA=${CONFIG_BIND_SHA256:-NONE}
    if [ -n "$PERSISTENT_CONFIG_STAGE_PATH" ]; then
        TX_CONFIG_MUTATED=true
        TX_CONFIG_ORIGINAL_STATUS=$PERSISTENT_CONFIG_ORIGINAL_STATUS
        TX_CONFIG_ORIGINAL_SHA=${PERSISTENT_CONFIG_ORIGINAL_SHA256:-NONE}
        TX_CONFIG_ORIGINAL_METADATA=${PERSISTENT_CONFIG_ORIGINAL_METADATA:-NONE}
        if [ "$PERSISTENT_CONFIG_ORIGINAL_STATUS" = present ]; then
            TX_CONFIG_BACKUP=$PERSISTENT_CONFIG_BACKUP_PATH
        fi
    elif [ "$CONFIG_BIND_SOURCE" = builtin ]; then
        TX_CONFIG_PATH=builtin
        TX_CONFIG_CANDIDATE_SHA=NONE
    fi
    TX_ROLLBACK_CONFIG_SHA=${ROLLBACK_CONFIG_SHA256:-NONE}
    PERSISTENT_TX_MANIFEST=$(cat <<EOF
PERSISTENT_TX_STATE=dcent-persistent-tx-v4
DEPLOY_ID=$DEPLOY_ID
PHASE=prepared
BINARY_PATH=$DEPLOY_PATH
BINARY_ORIGINAL_STATUS=$DEPLOY_EXISTING_STATUS
BINARY_ORIGINAL_SHA256=$BINARY_ORIGINAL_SHA_FIELD
BINARY_BACKUP_PATH=$BACKUP_PATH
BINARY_CANDIDATE_SHA256=$BINARY_SHA256
CONFIG_MUTATED=$TX_CONFIG_MUTATED
CONFIG_SOURCE=$CONFIG_BIND_SOURCE
CONFIG_PATH=$TX_CONFIG_PATH
CONFIG_ORIGINAL_STATUS=$TX_CONFIG_ORIGINAL_STATUS
CONFIG_ORIGINAL_SHA256=$TX_CONFIG_ORIGINAL_SHA
CONFIG_BACKUP_PATH=$TX_CONFIG_BACKUP
CONFIG_CANDIDATE_SHA256=$TX_CONFIG_CANDIDATE_SHA
ROLLBACK_CONFIG_SOURCE=$ROLLBACK_CONFIG_SOURCE
ROLLBACK_CONFIG_PATH=$ROLLBACK_CONFIG_PATH
ROLLBACK_CONFIG_SHA256=$TX_ROLLBACK_CONFIG_SHA
BINARY_ORIGINAL_METADATA=$DEPLOY_EXISTING_METADATA
CONFIG_ORIGINAL_METADATA=$TX_CONFIG_ORIGINAL_METADATA
EOF
)
    PERSISTENT_TX_IDENTITY_SHA256=$(printf '%s\n' "$PERSISTENT_TX_MANIFEST" \
        | awk 'NR == 3 { print "PHASE=CANONICAL"; next } { print }' \
        | sha256sum | awk '{ print $1 }')
    if ! printf '%s\n' "$PERSISTENT_TX_IDENTITY_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
        log "ERROR: persistent transaction identity could not be computed"
        json_exit false null "$BINARY_SIZE" false "Persistent transaction identity failed"
    fi
    PERSISTENT_TX_PUBLISH_ATTEMPTED=true
    PERSISTENT_TX_PUBLISH_RESULT=$(ssh_run "
set -e
umask 077
state='$PERSISTENT_TX_STATE_PATH'
tmp=\"\$state.prepared.new\"
[ ! -e \"\$state\" ] && [ ! -e \"\$tmp\" ]
printf '%s\n' '$PERSISTENT_TX_MANIFEST' >\"\$tmp\"
    [ \"\$(wc -l <\"\$tmp\")\" -eq 20 ]
    [ \"\$(sed -n '1p' \"\$tmp\")\" = 'PERSISTENT_TX_STATE=dcent-persistent-tx-v4' ]
    [ \"\$(sed -n '2p' \"\$tmp\")\" = 'DEPLOY_ID=$DEPLOY_ID' ]
    [ \"\$(sed -n '3p' \"\$tmp\")\" = 'PHASE=prepared' ]
    TX_MANIFEST_IDENTITY=\$(awk 'NR == 3 { print \"PHASE=CANONICAL\"; next } { print }' \"\$tmp\" | sha256sum | awk '{print \$1}')
    [ \"\$TX_MANIFEST_IDENTITY\" = '$PERSISTENT_TX_IDENTITY_SHA256' ]
chmod 600 \"\$tmp\"
[ \"\$(stat -c '%u:%a:%h' \"\$tmp\")\" = '0:600:1' ]
mv \"\$tmp\" \"\$state\"
sync
[ -f \"\$state\" ] && [ ! -L \"\$state\" ]
printf 'PERSISTENT_TX_PREPARED=verified\n'
" 2>/dev/null) || PERSISTENT_TX_PUBLISH_RESULT=""
    if [ "$PERSISTENT_TX_PUBLISH_RESULT" != "PERSISTENT_TX_PREPARED=verified" ]; then
        log "ERROR: durable persistent transaction manifest could not be published"
        json_exit false null "$BINARY_SIZE" false "Persistent transaction manifest publication failed"
    fi
    PERSISTENT_TX_STATUS="prepared_durable"

    # Candidate and independent backup share the target filesystem, so live
    # replacement is atomic while an already-open writer on the old inode
    # cannot mutate the recovery copy.
    PERSISTENT_MUTATION_STARTED=true
    PERSISTENT_INSTALL_SCRIPT=$(cat <<EOF
set -e
deploy_path='$DEPLOY_PATH'
staging_path='$STAGING_PATH'
backup_path='$BACKUP_PATH'
existing_status='$DEPLOY_EXISTING_STATUS'
existing_size='$DEPLOY_EXISTING_SIZE'
existing_sha='$DEPLOY_EXISTING_SHA256'
existing_metadata='$DEPLOY_EXISTING_METADATA'
config_stage='$PERSISTENT_CONFIG_STAGE_PATH'
config_path='$CONFIG_REMOTE'
config_backup='$PERSISTENT_CONFIG_BACKUP_PATH'
config_original_exists='$PERSISTENT_CONFIG_ORIGINAL_EXISTS'
config_original_sha='$PERSISTENT_CONFIG_ORIGINAL_SHA256'
config_original_metadata='$PERSISTENT_CONFIG_ORIGINAL_METADATA'
config_source='$CONFIG_BIND_SOURCE'
bound_config_path='${CONFIG_REMOTE:-builtin}'
bound_config_sha='${CONFIG_BIND_SHA256:-NONE}'
rollback_config_source='$ROLLBACK_CONFIG_SOURCE'
rollback_config_path='$ROLLBACK_CONFIG_PATH'
rollback_config_sha='${ROLLBACK_CONFIG_SHA256:-NONE}'
state='$PERSISTENT_TX_STATE_PATH'
deploy_id='$DEPLOY_ID'
expected_tx_identity='$PERSISTENT_TX_IDENTITY_SHA256'

tx_set_phase() {
    expected=\$1
    next=\$2
    [ -f "\$state" ] && [ ! -L "\$state" ]
    [ "\$(wc -l <"\$state")" -eq 20 ]
    [ "\$(sed -n "1p" "\$state")" = "PERSISTENT_TX_STATE=dcent-persistent-tx-v4" ]
    [ "\$(sed -n "2p" "\$state")" = "DEPLOY_ID=\$deploy_id" ]
    [ "\$(sed -n "3p" "\$state")" = "PHASE=\$expected" ]
    actual_identity=\$(awk 'NR == 3 { print "PHASE=CANONICAL"; next } { print }' "\$state" | sha256sum | awk '{print \$1}')
    [ "\$actual_identity" = "\$expected_tx_identity" ]
    tmp="\$state.\$next.new"
    rm -f "\$tmp"
    awk -v phase="\$next" 'NR == 3 { print "PHASE=" phase; next } { print }' "\$state" >"\$tmp"
    [ "\$(wc -l <"\$tmp")" -eq 20 ]
    actual_identity=\$(awk 'NR == 3 { print "PHASE=CANONICAL"; next } { print }' "\$tmp" | sha256sum | awk '{print \$1}')
    [ "\$actual_identity" = "\$expected_tx_identity" ]
    chmod 600 "\$tmp"
    mv -f "\$tmp" "\$state"
    sync
}

# Revalidate both staged and live bytes in the same remote shell that begins
# mutation. The shared deploy-admission lock and maintenance marker exclude
# cooperating writers. Absent-original config publication additionally uses an
# atomic no-clobber link, so an out-of-band pathname cannot be overwritten.
[ -f "\$staging_path" ] && [ ! -L "\$staging_path" ]
[ "\$(sha256sum "\$staging_path" | awk '{print \$1}')" = '$BINARY_SHA256' ]
if [ "\$existing_status" = present ]; then
    [ -f "\$deploy_path" ] && [ ! -L "\$deploy_path" ]
    [ -f "\$backup_path" ] && [ ! -L "\$backup_path" ]
    [ "\$(stat -c '%d:%i' "\$deploy_path")" != "\$(stat -c '%d:%i' "\$backup_path")" ]
    [ "\$(wc -c <"\$deploy_path")" = "\$existing_size" ]
    [ "\$(sha256sum "\$deploy_path" | awk '{print \$1}')" = "\$existing_sha" ]
    [ "\$(sha256sum "\$backup_path" | awk '{print \$1}')" = "\$existing_sha" ]
    [ "\$(stat -c '%u:%g:%a' "\$deploy_path")" = "\$existing_metadata" ]
    [ "\$(stat -c '%u:%g:%a' "\$backup_path")" = "\$existing_metadata" ]
else
    [ ! -e "\$deploy_path" ]
fi
if [ -n "\$config_stage" ]; then
    [ -f "\$config_stage" ] && [ ! -L "\$config_stage" ]
    [ "\$(sha256sum "\$config_stage" | awk '{print \$1}')" = '$CONFIG_BIND_SHA256' ]
    if [ "\$config_original_exists" = true ]; then
        [ -f "\$config_path" ] && [ ! -L "\$config_path" ]
        [ -f "\$config_backup" ] && [ ! -L "\$config_backup" ]
        [ "\$(stat -c '%d:%i' "\$config_path")" != "\$(stat -c '%d:%i' "\$config_backup")" ]
        [ "\$(sha256sum "\$config_path" | awk '{print \$1}')" = "\$config_original_sha" ]
        [ "\$(sha256sum "\$config_backup" | awk '{print \$1}')" = "\$config_original_sha" ]
        [ "\$(stat -c '%u:%g:%a' "\$config_path")" = "\$config_original_metadata" ]
        [ "\$(stat -c '%u:%g:%a' "\$config_backup")" = "\$config_original_metadata" ]
    else
        [ ! -e "\$config_path" ] && [ ! -L "\$config_path" ]
    fi
fi

# Prove the complete rollback config selection before changing either live
# path. An explicit /data candidate may coexist with a prior /etc fallback, so
# the candidate and rollback bindings are deliberately independent.
case "\$rollback_config_source:\$rollback_config_path" in
    data:/data/dcentrald.toml)
        if [ "\$config_original_exists" = true ]; then
            [ "\$(sha256sum "\$config_backup" | awk '{print \$1}')" = "\$rollback_config_sha" ]
            case "\$(stat -c '%u:%g:%a' "\$config_backup")" in
                0:0:[0-7][0145][0145]) ;;
                *) exit 1 ;;
            esac
        else
            [ "\$(sha256sum "\$rollback_config_path" | awk '{print \$1}')" = "\$rollback_config_sha" ]
            case "\$(stat -c '%u:%g:%a' "\$rollback_config_path")" in
                0:0:[0-7][0145][0145]) ;;
                *) exit 1 ;;
            esac
        fi
        ;;
    etc:/etc/dcentrald.toml)
        [ "\$(sha256sum "\$rollback_config_path" | awk '{print \$1}')" = "\$rollback_config_sha" ]
        case "\$(stat -c '%u:%g:%a' "\$rollback_config_path")" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        [ -n "\$config_stage" ] \
            || { [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ]; }
        ;;
    builtin:builtin)
        [ "\$rollback_config_sha" = NONE ]
        [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        [ -n "\$config_stage" ] \
            || { [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ]; }
        ;;
    *) exit 1 ;;
esac

case "\$config_source" in
    explicit)
        [ -n "\$config_stage" ] && [ "\$bound_config_path" = "\$config_path" ]
        ;;
    discovered)
        [ -z "\$config_stage" ]
        [ -f "\$bound_config_path" ] && [ ! -L "\$bound_config_path" ]
        [ "\$(sha256sum "\$bound_config_path" | awk '{print \$1}')" = "\$bound_config_sha" ]
        case "\$(stat -c '%u:%g:%a' "\$bound_config_path")" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        ;;
    builtin)
        [ -z "\$config_stage" ] && [ "\$bound_config_path" = builtin ] && [ "\$bound_config_sha" = NONE ]
        [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ] \
            && [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        ;;
    *) exit 1 ;;
esac

tx_set_phase prepared mutating
chmod 755 "\$staging_path"
mv -f "\$staging_path" "\$deploy_path"
if [ -n "\$config_stage" ]; then
    chmod 600 "\$config_stage"
    if [ "\$config_original_exists" = true ]; then
        mv -f "\$config_stage" "\$config_path"
    else
        # Hard-link publication is atomic and no-clobber on the same /data
        # filesystem. A pathname that appears after admission makes the
        # transaction fail closed instead of being overwritten by mv -f.
        ln -T "\$config_stage" "\$config_path"
        [ "\$(stat -c '%d:%i' "\$config_stage")" \
            = "\$(stat -c '%d:%i' "\$config_path")" ]
        rm -f "\$config_stage"
    fi
fi
sync
[ "\$(sha256sum "\$deploy_path" | awk '{print \$1}')" = '$BINARY_SHA256' ]
[ "\$(stat -c '%u:%g:%a' "\$deploy_path")" = '0:0:755' ]
case "\$config_source" in
    explicit)
        [ "\$(sha256sum "\$bound_config_path" | awk '{print \$1}')" = "\$bound_config_sha" ]
        [ "\$(stat -c '%u:%g:%a' "\$bound_config_path")" = "0:0:600" ]
        ;;
    discovered)
        [ "\$(sha256sum "\$bound_config_path" | awk '{print \$1}')" = "\$bound_config_sha" ]
        case "\$(stat -c '%u:%g:%a' "\$bound_config_path")" in
            0:0:[0-7][0145][0145]) ;;
            *) exit 1 ;;
        esac
        ;;
    builtin)
        [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ] \
            && [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ]
        ;;
esac
tx_set_phase mutating installed
EOF
)
    if [ -n "$PERSISTENT_CONFIG_STAGE_PATH" ]; then
        PERSISTENT_CONFIG_MUTATION_STARTED=true
    fi
    if ! ssh_run "$PERSISTENT_INSTALL_SCRIPT" >/dev/null 2>&1; then
        log "ERROR: persistent binary/config transaction failed; verified recovery artifacts are retained"
        json_exit false null "$BINARY_SIZE" false "Persistent binary/config installation failed"
    fi
else
    if ! ssh_run "chmod +x $STAGING_PATH && mv $STAGING_PATH $DEPLOY_PATH" >/dev/null 2>&1; then
        json_exit false null "$BINARY_SIZE" false "Runtime binary installation failed"
    fi
fi

if [ "$DEPLOY_MODE" = "persistent" ] && [ -n "$PERSISTENT_CONFIG_STAGE_PATH" ]; then
    REMOTE_INSTALLED_CONFIG_SHA256=$(ssh_run "sha256sum '$CONFIG_REMOTE' 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || REMOTE_INSTALLED_CONFIG_SHA256=""
    if [ "$REMOTE_INSTALLED_CONFIG_SHA256" != "$CONFIG_BIND_SHA256" ]; then
        log "ERROR: installed persistent config hash mismatch"
        json_exit false null "$BINARY_SIZE" false "Installed persistent config hash mismatch"
    fi
fi

REMOTE_DEPLOY_SHA256=$(ssh_run "sha256sum '$DEPLOY_PATH' 2>/dev/null | awk '{print \$1}'" 2>/dev/null) || REMOTE_DEPLOY_SHA256=""
if [ "$REMOTE_DEPLOY_SHA256" != "$BINARY_SHA256" ]; then
    log "ERROR: Installed binary hash mismatch on miner ($REMOTE_DEPLOY_SHA256 != $BINARY_SHA256)"
    json_exit false null "$BINARY_SIZE" false "Installed binary hash mismatch"
fi
log "  Installed SHA256 verified"

log "  Deployed to $DEPLOY_PATH"

log_step "Starting dcentrald"

if [ -n "$CONFIG_BIND_SHA256" ]; then
    JOURNAL_CONFIG_PATH=$CONFIG_REMOTE
    JOURNAL_CONFIG_SHA256=$CONFIG_BIND_SHA256
else
    JOURNAL_CONFIG_PATH=builtin
    JOURNAL_CONFIG_SHA256=NONE
fi

if ! ssh_run "umask 077; (set -C; printf '%s\n' '$LAUNCH_ID' >'$REMOTE_RUN_DIR/runtime-launch.authorized')" >/dev/null 2>&1; then
    log "ERROR: Could not publish the one-shot launch authorization"
    json_exit false null "$BINARY_SIZE" false "Launch authorization failed"
fi
RUNTIME_LAUNCH_ATTEMPTED=true

START_SCRIPT=$(cat <<EOF
CONFIG=""
if [ -n "$CONFIG_BIND_SHA256" ]; then
    [ -f "$CONFIG_REMOTE" ] && [ ! -L "$CONFIG_REMOTE" ] || {
        echo "START_ERROR=bound_config_type_changed"
        exit 1
    }
    if [ "$DEPLOY_MODE" = "runtime-only" ]; then
        CONFIG_META=\$(stat -c '%u:%a:%h' "$CONFIG_REMOTE" 2>/dev/null || true)
        if [ "\$CONFIG_META" != "0:400:1" ]; then
            echo "START_ERROR=explicit_config_metadata_changed"
            exit 1
        fi
    elif [ "$CONFIG_BIND_SOURCE" = explicit ]; then
        [ "\$(stat -c '%u:%g:%a' "$CONFIG_REMOTE" 2>/dev/null)" = "0:0:600" ] || {
            echo "START_ERROR=explicit_config_metadata_changed"
            exit 1
        }
    else
        case "\$(stat -c '%u:%g:%a' "$CONFIG_REMOTE" 2>/dev/null)" in
            0:0:[0-7][0145][0145]) ;;
            *)
                echo "START_ERROR=discovered_config_metadata_unsafe"
                exit 1
                ;;
        esac
    fi
    ACTUAL_CONFIG_SHA256=\$(sha256sum "$CONFIG_REMOTE" 2>/dev/null | awk '{print \$1}')
    if [ "\$ACTUAL_CONFIG_SHA256" != "$CONFIG_BIND_SHA256" ]; then
        echo "START_ERROR=explicit_config_hash_changed"
        exit 1
    fi
    CONFIG="--config $CONFIG_REMOTE"
    echo "CONFIG_USED=$CONFIG_REMOTE"
elif [ "$CONFIG_EXPECTED_BUILTIN" = true ]; then
    [ ! -e /data/dcentrald.toml ] && [ ! -L /data/dcentrald.toml ] \
        && [ ! -e /etc/dcentrald.toml ] && [ ! -L /etc/dcentrald.toml ] || {
        echo "START_ERROR=builtin_config_selection_changed"
        exit 1
    }
    echo "CONFIG_USED=builtin"
else
    echo "START_ERROR=config_binding_unresolved"
    exit 1
fi

EXTRA_ARGS=""
if [ "$PLATFORM_FAMILY" = "amlogic" ]; then
    EXTRA_ARGS="--serial-mining"
fi
if [ "$PLATFORM_FAMILY" = "am2" ]; then
    # am2 (S19j Pro / S17 / S19 / T17 / T19) requires the hybrid serial-init +
    # FPGA work-dispatch path. main.rs auto-detects this from /etc/bos_platform,
    # but passing the flag explicitly is belt-and-suspenders in case the
    # platform file is unreadable on degraded boots.
    EXTRA_ARGS="--s19j-hybrid"
fi

launch_authorized="$REMOTE_RUN_DIR/runtime-launch.authorized"
launch_starting="$REMOTE_RUN_DIR/runtime-launch.starting"
[ "\$(cat "\$launch_authorized" 2>/dev/null)" = "$LAUNCH_ID" ] || {
    echo "START_ERROR=launch_authorization_missing"
    exit 1
}
mv "\$launch_authorized" "\$launch_starting" || {
    echo "START_ERROR=launch_authorization_claim_failed"
    exit 1
}
if [ "$DEPLOY_MODE" = "runtime-only" ]; then
    # This is a process policy, not merely a binary location. It makes the
    # daemon redirect history/metrics/audit/recovery state to tmpfs, suppress
    # persistent capability publication, and expose observation-only APIs.
    nohup env DCENTOS_EPHEMERAL_RUNTIME=1 \
        DCENT_DEPLOY_LAUNCH_ID=$LAUNCH_ID \
        DCENTOS_AUDIT_LOG_PATH=/tmp/dcent/audit.log \
        DCENTOS_METRICS_DIR=/tmp/dcent/metrics \
        DCENTOS_LOG_RING_DIR=/tmp/dcent/log \
        $DEPLOY_PATH \$CONFIG \$EXTRA_ARGS >$LOG_PATH 2>&1 &
else
    nohup env DCENT_DEPLOY_LAUNCH_ID=$LAUNCH_ID \
        $DEPLOY_PATH \$CONFIG \$EXTRA_ARGS >$LOG_PATH 2>&1 &
fi
NEW_PID=\$!
echo "NEW_PID=\${NEW_PID:-}"
case "\${NEW_PID:-}" in
    ""|*[!0-9]*) ;;
    *)
        for i in \$(seq 1 5); do
            NEW_EXE=\$(readlink "/proc/\$NEW_PID/exe" 2>/dev/null || true)
            [ "\$NEW_EXE" = "$DEPLOY_PATH" ] && break
            sleep 1
        done
        NEW_START_TICKS=\$(sed "s/^[^)]*) //" "/proc/\$NEW_PID/stat" 2>/dev/null | awk '{print \$20}')
        printf "NEW_START_TICKS=%s\nNEW_EXE=%s\n" "\$NEW_START_TICKS" "\$NEW_EXE"
        ;;
esac
case "\${NEW_PID:-}:\${NEW_START_TICKS:-}" in
    *[!0-9:]*|:*|*:)
        echo "START_ERROR=launch_identity_invalid"
        exit 1
        ;;
esac
[ "\${NEW_EXE:-}" = "$DEPLOY_PATH" ] || {
    echo "START_ERROR=launch_executable_unobserved"
    exit 1
}
launch_started_new="$REMOTE_RUN_DIR/runtime-launch.started.new"
(set -C; printf 'RUNTIME_LAUNCH_STATE=dcent-runtime-launch-v2\nLAUNCH_ID=%s\nPID=%s\nSTART_TICKS=%s\nEXE=%s\nCONFIG_SOURCE=%s\nCONFIG_PATH=%s\nCONFIG_SHA256=%s\n' \
    "$LAUNCH_ID" "\$NEW_PID" "\$NEW_START_TICKS" "\$NEW_EXE" \
    "$CONFIG_BIND_SOURCE" "$JOURNAL_CONFIG_PATH" "$JOURNAL_CONFIG_SHA256" \
    >"\$launch_started_new") || {
    echo "START_ERROR=launch_state_prepare_failed"
    exit 1
}
mv "\$launch_started_new" "$REMOTE_RUN_DIR/runtime-launch.started" || {
    echo "START_ERROR=launch_state_commit_failed"
    exit 1
}
rm -f "$REMOTE_RUN_DIR/runtime-launch.starting"
sync
EOF
)

START_OUTPUT=$(ssh_run "$START_SCRIPT" 2>/dev/null) || true
CONFIG_USED=$(single_assignment_value "$START_OUTPUT" CONFIG_USED 2>/dev/null) || CONFIG_USED=unknown
NEW_PID=$(single_assignment_value "$START_OUTPUT" NEW_PID 2>/dev/null) || NEW_PID=null
NEW_START_TICKS=$(single_assignment_value "$START_OUTPUT" NEW_START_TICKS 2>/dev/null) || NEW_START_TICKS=""
NEW_EXE=$(single_assignment_value "$START_OUTPUT" NEW_EXE 2>/dev/null) || NEW_EXE=""
case "$NEW_PID:$NEW_START_TICKS" in
    *[!0-9:]*|:*|*:)
        LAUNCHED_PID=""
        LAUNCHED_START_TICKS=""
        LAUNCHED_EXE=""
        ;;
    *)
        if [ "$NEW_EXE" = "$DEPLOY_PATH" ]; then
            LAUNCHED_PID="$NEW_PID"
            LAUNCHED_START_TICKS="$NEW_START_TICKS"
            LAUNCHED_EXE="$NEW_EXE"
        else
            LAUNCHED_PID=""
            LAUNCHED_START_TICKS=""
            LAUNCHED_EXE=""
        fi
        ;;
esac
if [ "$CONFIG_USED" != "builtin" ] && [ "$CONFIG_USED" != "unknown" ]; then
    REMOTE_API_PORT=$(ssh_run "awk '
        BEGIN { in_api = 0 }
        /^\[api\]/ { in_api = 1; next }
        /^\[/ { in_api = 0 }
        in_api && \$1 == \"http_port\" {
            gsub(/[^0-9]/, \"\", \$3)
            print \$3
            exit
        }
    ' '$CONFIG_USED' 2>/dev/null" 2>/dev/null) || REMOTE_API_PORT=""
    if [ -n "$REMOTE_API_PORT" ]; then
        API_PORT="$REMOTE_API_PORT"
    fi
fi

log "  Config: $CONFIG_USED"
log "  PID: $NEW_PID"
if [ "$PLATFORM_FAMILY" = "amlogic" ]; then
    log "  Mode: serial-mining runtime-only"
elif [ "$DEPLOY_MODE" = "runtime-only" ]; then
    log "  Mode: runtime-only cold-init"
fi

sleep 1

RUNNING_PID=$(ssh_run '
expected_pid='"$NEW_PID"'
expected_exe='"$DEPLOY_PATH"'
expected_start='"$NEW_START_TICKS"'
expected_launch_id='"$LAUNCH_ID"'
case "$expected_pid" in ""|*[!0-9]*) exit 1 ;; esac
case "$expected_start" in ""|*[!0-9]*) exit 1 ;; esac
[ -r "/proc/$expected_pid/exe" ] || exit 1
[ "$(readlink "/proc/$expected_pid/exe" 2>/dev/null)" = "$expected_exe" ] || exit 1
[ "$(sed "s/^[^)]*) //" "/proc/$expected_pid/stat" 2>/dev/null | awk "{print \$20}")" = "$expected_start" ] || exit 1
if [ -n "$expected_launch_id" ]; then
    tr "\000" "\n" <"/proc/$expected_pid/environ" 2>/dev/null | grep -Fqx "DCENT_DEPLOY_LAUNCH_ID=$expected_launch_id" || exit 1
fi
matches=0
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    base=${exe##*/}; base=${base% (deleted)}
    cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
    cmdbase=${cmd0##*/}
    case "$base,$cmdbase" in
        dcentrald,*|dcentrald_runtime,*|*,dcentrald|*,dcentrald_runtime)
            matches=$((matches + 1))
            [ "${proc##*/}" = "$expected_pid" ] || exit 1
            ;;
    esac
done
[ "$matches" -eq 1 ] || exit 1
printf "%s\n" "$expected_pid"' 2>/dev/null) || RUNNING_PID="NONE"
case "$RUNNING_PID" in ""|*[!0-9]*) RUNNING_PID="NONE" ;; esac
if [ "$RUNNING_PID" = "NONE" ]; then
    log "  WARNING: dcentrald exited immediately!"
    log "  Last 20 lines of log:"
    if [ "$JSON_OUTPUT" = false ]; then
        ssh_run "tail -20 $LOG_PATH 2>/dev/null" 2>/dev/null || true
    fi

    if [ "$ROLLBACK_ON_FAIL" = true ] && [ "$DEPLOY_MODE" = "runtime-only" ] &&
       [ "$OS_VER" != "NONE" ] && [ "$HAS_PERSISTENT_SUPERVISOR" = true ]; then
        ssh_run "[ -x /etc/init.d/S82dcentrald ] && /etc/init.d/S82dcentrald start || true" 2>/dev/null || true
    fi

    json_exit false null "$BINARY_SIZE" false "dcentrald exited immediately"
fi

NEW_PID="$RUNNING_PID"
# The post-start verification above proves the complete launch identity even
# when SSH delivered only a prefix of START_OUTPUT. Rehydrate the canonical
# local identity from that proof so final arbitration, cleanup, and the receipt
# never depend on a truncated remote stdout stream.
NEW_START_TICKS="${LAUNCHED_START_TICKS:-$NEW_START_TICKS}"
NEW_EXE="$DEPLOY_PATH"
LAUNCHED_PID="$NEW_PID"
LAUNCHED_START_TICKS="$NEW_START_TICKS"
LAUNCHED_EXE="$NEW_EXE"
if ! verify_committed_launch_state; then
    log "ERROR: launch process is live but its exact recovery journal was not committed"
    json_exit false "$NEW_PID" "$BINARY_SIZE" false "Launch recovery journal commit was not proven"
fi
API_HEALTHY=false

if [ "$VERIFY" = true ]; then
    log_step "Verifying API health (polling for ${VERIFY_TIMEOUT}s)"
    API_VERIFICATION_STATUS="attempted"
    VERIFY_DEADLINE=$(($(date +%s) + VERIFY_TIMEOUT))

    while [ "$(date +%s)" -lt "$VERIFY_DEADLINE" ]; do
        HTTP_CODE=$(ssh_run "wget -q -O /dev/null -S http://127.0.0.1:$API_PORT/api/status 2>&1 | grep 'HTTP/' | tail -1 | awk '{print \$2}'" 2>/dev/null) || HTTP_CODE=""

        if [ "$HTTP_CODE" = "200" ]; then
            API_HEALTHY=true
            API_VERIFICATION_STATUS="healthy"
            log "  API healthy (HTTP 200)"
            break
        fi

        log "  Waiting... (HTTP=$HTTP_CODE)"
        sleep 2
    done

if [ "$API_HEALTHY" = false ]; then
        API_VERIFICATION_STATUS="failed"
        log "  WARNING: API did not respond with 200 within ${VERIFY_TIMEOUT}s"

        json_exit false "$NEW_PID" "$BINARY_SIZE" false "API health check failed"
    fi
fi

if [ "$DEPLOY_MODE" = "persistent" ]; then
    if ! finalize_persistent_transaction; then
        log "ERROR: installed persistent generation could not be durably committed"
        json_exit false "$NEW_PID" "$BINARY_SIZE" false "Persistent transaction commit was not proven"
    fi
    log "  Persistent binary/config generation committed durably"
fi

# The private launch journal is intentionally retained for both modes. Removing
# it before receipt publication creates a distributed-transaction hole: a local
# write failure could otherwise leave a daemon running without either a receipt
# or its remote recovery identity. The next deploy/recovery tooling may safely
# reclaim journals using their nonce-bound PID/start/exe record.
if [ "$DEPLOY_MODE" = "persistent" ]; then
    SUCCESS_CLEANUP_STATUS=recovery_artifacts_retained
    PERSISTENT_ROLLBACK_STATUS=artifact_restore_available_requires_owner_readmission
    log "  Recovery artifacts retained in $REMOTE_RUN_DIR"
else
    SUCCESS_CLEANUP_STATUS=launch_recovery_state_retained
    log "  Launch recovery state retained in $REMOTE_RUN_DIR"
fi

# Re-arbitrate immediately before success publication. Vendor supervisors may
# restart after the earlier stop scan, and the launched daemon may exit during
# API polling or cleanup; neither can be accepted from a stale ownership
# observation. The only later remote operation retires the matching deploy
# lease; it cannot mutate the observed daemon/config generation.
FINAL_OWNERSHIP=$(ssh_run '
expected_pid='"$NEW_PID"'
expected_start='"$NEW_START_TICKS"'
expected_exe='"$NEW_EXE"'
expected_launch_id='"$LAUNCH_ID"'
case "$expected_pid:$expected_start" in *[!0-9:]*|:*|*:) exit 1 ;; esac
[ "$(readlink "/proc/$expected_pid/exe" 2>/dev/null)" = "$expected_exe" ] || exit 1
[ "$(sed "s/^[^)]*) //" "/proc/$expected_pid/stat" 2>/dev/null | awk "{print \$20}")" = "$expected_start" ] || exit 1
if [ -n "$expected_launch_id" ]; then
    tr "\000" "\n" <"/proc/$expected_pid/environ" 2>/dev/null | grep -Fqx "DCENT_DEPLOY_LAUNCH_ID=$expected_launch_id" || exit 1
fi
dcentral_matches=0
vendor_matches=0
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    base=${exe##*/}; base=${base% (deleted)}
    cmd0=$(tr "\000" "\n" <"$proc/cmdline" 2>/dev/null | sed -n "1p")
    cmdbase=${cmd0##*/}
    case "$base,$cmdbase" in
        dcentrald,*|dcentrald_runtime,*|*,dcentrald|*,dcentrald_runtime)
            dcentral_matches=$((dcentral_matches + 1))
            [ "${proc##*/}" = "$expected_pid" ] || exit 1
            ;;
        bosminer,*|*,bosminer|bos-tools,*|*,bos-tools|boser,*|*,boser)
            vendor_matches=$((vendor_matches + 1))
            ;;
    esac
done
[ "$dcentral_matches" -eq 1 ] && [ "$vendor_matches" -eq 0 ] || exit 1
printf "FINAL_OWNERSHIP=OK\n"' 2>/dev/null) || FINAL_OWNERSHIP=""
if [ "$FINAL_OWNERSHIP" != "FINAL_OWNERSHIP=OK" ]; then
    log "ERROR: final daemon/vendor ownership arbitration failed"
    json_exit false "$NEW_PID" "$BINARY_SIZE" false "Final hardware ownership arbitration failed"
fi
DEPLOY_END=$(date +%s)
DEPLOY_TIME=$((DEPLOY_END - DEPLOY_START))

log_step "Deploy Complete"
log "  Target:      root@$MINER_IP"
log "  Platform:    $PLATFORM_DESC"
log "  Mode:        $DEPLOY_MODE"
log "  Binary:      $DEPLOY_PATH ($BINARY_SIZE bytes)"
log "  Config:      $CONFIG_USED"
log "  PID:         $NEW_PID"
log "  API health:  $API_HEALTHY"
log "  Deploy time: ${DEPLOY_TIME}s"
log ""
log "  Log:       ssh root@$MINER_IP 'tail -f $LOG_PATH'"
log "  REST API:  http://$MINER_IP:$API_PORT/"
log "  CGMiner:   http://$MINER_IP:4028/"
log ""

DEPLOY_JSON=$(build_receipt_payload \
    true "$NEW_PID" "$BINARY_SIZE" "$API_HEALTHY" \
    "Deploy successful" "$SUCCESS_CLEANUP_STATUS") || exit 1
# Receipt publication and the in-memory commit bit form one local critical
# section. Do not let a catchable termination signal publish success and then
# run the uncommitted-launch cleanup trap before the bit is set.
trap '' INT TERM HUP
if write_json_payload "$DEPLOY_JSON"; then
    receipt_publication_status=0
else
    receipt_publication_status=$?
    if [ "$receipt_publication_status" -ne 2 ]; then
        if [ "$DEPLOY_MODE" = "persistent" ]; then
            persistent_receipt_cleanup_ok=true
            cleanup_persistent_launch || persistent_receipt_cleanup_ok=false
            if [ "$ROLLBACK_ON_FAIL" = true ] &&
               [ "$persistent_receipt_cleanup_ok" = true ]; then
                rollback_persistent_files || true
            fi
        else
            cleanup_runtime_launch || true
        fi
    else
        # The success receipt is already visible and its file contents were
        # fsynced. Treat target state as committed before leaving nonzero, then
        # retire only the post-commit exclusion markers. The generic EXIT trap
        # must not reinterpret directory-durability uncertainty as permission
        # to stop or roll back the proven generation.
        RUNTIME_LAUNCH_COMMITTED=true
        PERSISTENT_LAUNCH_COMMITTED=true
        if [ "$DEPLOY_MODE" = persistent ]; then
            release_persistent_deploy_lease || true
        fi
        release_deploy_maintenance || true
        trap - EXIT INT TERM HUP
    fi
    exit 1
fi
RUNTIME_LAUNCH_COMMITTED=true
PERSISTENT_LAUNCH_COMMITTED=true
# Receipt publication is the local commit point and occurred while this deploy
# still held exclusive mutation authority. Lease retirement is post-commit
# maintenance: a failure may block a successor, but must never emit a second,
# contradictory receipt or roll back the generation already proven above.
if [ "$DEPLOY_MODE" = persistent ] && ! release_persistent_deploy_lease; then
    log "  WARNING: persistent deploy lease retirement is $PERSISTENT_DEPLOY_LEASE_STATUS; boot recovery or an administrator must resolve it before the next deploy"
fi
if ! release_deploy_maintenance; then
    log "  WARNING: deploy/admission exclusion retirement is $DEPLOY_MAINTENANCE_STATUS; reboot is required before another deploy or daemon admission"
fi
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [ "$TAIL" = true ]; then
    log "=== Tailing log (Ctrl+C to stop) ==="
    ssh_run "tail -f $LOG_PATH"
fi
