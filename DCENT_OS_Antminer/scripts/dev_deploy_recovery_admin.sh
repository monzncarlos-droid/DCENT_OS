#!/bin/bash
# Inspect or safely prune terminal AM1 persistent dev-deploy transactions.

set -euo pipefail

MINER_HOST="${1:?Usage: $0 <miner_host> {list|prune-terminal|prune-orphans} [--keep N] [--min-age-hours N]}"
ACTION="${2:-list}"
shift 2 || true
KEEP=4
MIN_AGE_HOURS=24

while [ "$#" -gt 0 ]; do
    case "$1" in
        --keep)
            KEEP="${2:?--keep requires a value}"
            shift
            ;;
        --min-age-hours)
            MIN_AGE_HOURS="${2:?--min-age-hours requires a value}"
            shift
            ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

case "$MINER_HOST" in
    ""|*[!A-Za-z0-9:._-]*) echo "ERROR: unsupported miner host" >&2; exit 2 ;;
esac
case "$ACTION" in list|prune-terminal|prune-orphans) ;; *) echo "ERROR: invalid recovery action" >&2; exit 2 ;; esac
case "$KEEP" in ""|*[!0-9]*) echo "ERROR: --keep must be an integer" >&2; exit 2 ;; esac
[ "$KEEP" -ge 1 ] && [ "$KEEP" -le 100 ] || {
    echo "ERROR: --keep must be between 1 and 100" >&2
    exit 2
}
case "$MIN_AGE_HOURS" in ""|*[!0-9]*) echo "ERROR: --min-age-hours must be an integer" >&2; exit 2 ;; esac
[ "$MIN_AGE_HOURS" -ge 1 ] && [ "$MIN_AGE_HOURS" -le 8760 ] || {
    echo "ERROR: --min-age-hours must be between 1 and 8760" >&2
    exit 2
}

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
if [ -n "${DCENT_SSH_KNOWN_HOSTS:-}" ]; then
    [ -r "$DCENT_SSH_KNOWN_HOSTS" ] && [ -s "$DCENT_SSH_KNOWN_HOSTS" ] || {
        echo "ERROR: DCENT_SSH_KNOWN_HOSTS must be readable and non-empty" >&2
        exit 2
    }
    SSH_OPTS+=(
        -o StrictHostKeyChecking=yes
        -o "UserKnownHostsFile=$DCENT_SSH_KNOWN_HOSTS"
    )
else
    SSH_OPTS+=(-o StrictHostKeyChecking=no)
fi

REMOTE_SCRIPT=$(cat <<'EOF'
set -eu
base=${DCENT_DEPLOY_RECOVERY_BASE:-/data/.dcent-deploy-recovery}
action=$1
keep=$2
min_age_hours=$3

[ -e "$base" ] || [ -L "$base" ] || exit 0
[ -d "$base" ] && [ ! -L "$base" ] || {
    echo "ERROR: recovery base is not a real directory" >&2
    exit 1
}
[ "$(stat -c '%u:%a' "$base" 2>/dev/null)" = "0:700" ] || {
    echo "ERROR: recovery base metadata is not root:0700" >&2
    exit 1
}

valid_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "0:700" ] || return 1
    name=${1##*/}
    printf '%s\n' "$name" | grep -Eq '^[0-9a-f]{32}$'
}

maintenance_gate=/run/dcentos-deploy-maintenance
lock_helper=/usr/libexec/dcentos/dcentos-deploy-lock
if [ "${DCENT_DEPLOY_ADMIN_TEST_AUTHORITY:-0}" = 1 ]; then
    maintenance_gate=${DCENT_DEPLOY_MAINTENANCE_PATH:-$maintenance_gate}
    lock_helper=${DCENT_DEPLOY_LOCK_HELPER:-$lock_helper}
fi
admin_owner="admin.$$"
release_admin_gate() {
    [ "$(cat "$maintenance_gate/owner" 2>/dev/null)" = "$admin_owner" ] || return 0
    rm -f "$maintenance_gate/owner" 2>/dev/null || return 1
    rmdir "$maintenance_gate" 2>/dev/null || return 1
}
trap 'release_admin_gate || true' 0
# On interruption, a foreground deletion may outlive this shell. Preserve the
# marker so admission cannot reopen until reboot/manual adjudication.
trap 'trap - 0; exit 1' 1 2 15
[ -x "$lock_helper" ] || {
    echo "ERROR: deploy/admission lock helper is missing" >&2
    exit 1
}
[ ! -e "$maintenance_gate" ] && [ ! -L "$maintenance_gate" ] || {
    echo "ERROR: deploy maintenance is already active" >&2
    exit 1
}
mkdir "$maintenance_gate"
chmod 700 "$maintenance_gate"
printf '%s\n' "$admin_owner" >"$maintenance_gate/owner"
chmod 600 "$maintenance_gate/owner"
if ! "$lock_helper" -- /bin/true; then
    echo "ERROR: daemon admission is already active" >&2
    exit 1
fi

lease="$base/.deploy-lease"
lease_owner=unknown
valid_active_lease() {
    [ -d "$lease" ] && [ ! -L "$lease" ] || return 1
    [ "$(stat -c '%u:%a' "$lease" 2>/dev/null)" = "0:700" ] || return 1
    [ -f "$lease/owner" ] && [ ! -L "$lease/owner" ] || return 1
    [ "$(stat -c '%u:%a:%h' "$lease/owner" 2>/dev/null)" = "0:600:1" ] \
        || return 1
    lease_owner=$(cat "$lease/owner" 2>/dev/null) || return 1
    printf '%s\n' "$lease_owner" | grep -Eq '^[0-9a-f]{32}$' || return 1
    lease_entries=0
    for lease_entry in "$lease"/* "$lease"/.[!.]* "$lease"/..?*; do
        [ -e "$lease_entry" ] || [ -L "$lease_entry" ] || continue
        [ "$lease_entry" = "$lease/owner" ] || return 1
        lease_entries=$((lease_entries + 1))
    done
    [ "$lease_entries" -eq 1 ]
}

if [ -e "$lease" ] || [ -L "$lease" ]; then
    if valid_active_lease; then
        if [ "$action" = list ]; then
            printf 'LEASE\tactive:%s\n' "$lease_owner"
        else
            echo "ERROR: pruning is blocked by active deploy lease $lease_owner" >&2
            exit 1
        fi
    elif [ "$action" = list ]; then
        printf 'LEASE\tinvalid\n'
    else
        echo "ERROR: pruning is blocked by invalid deploy lease evidence" >&2
        exit 1
    fi
fi

valid_terminal_manifest() {
    marker=$1
    deploy_id=$2
    expected_phase=$3
    [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
    [ "$(stat -c '%u:%a:%h' "$marker" 2>/dev/null)" = "0:600:1" ] || return 1
    marker_lines=$(wc -l <"$marker" 2>/dev/null) || return 1
    marker_schema=$(sed -n '1p' "$marker") || return 1
    case "$marker_schema:$marker_lines" in
        PERSISTENT_TX_STATE=dcent-persistent-tx-v3:19) has_config_metadata=false ;;
        PERSISTENT_TX_STATE=dcent-persistent-tx-v4:20) has_config_metadata=true ;;
        *) return 1 ;;
    esac
    [ "$(sed -n '2p' "$marker")" = "DEPLOY_ID=$deploy_id" ] || return 1
    [ "$(sed -n '3p' "$marker")" = "PHASE=$expected_phase" ] || return 1
    awk -F= -v expected_count="$marker_lines" '
        BEGIN {
            expected[1] = "PERSISTENT_TX_STATE"; expected[2] = "DEPLOY_ID"
            expected[3] = "PHASE"; expected[4] = "BINARY_PATH"
            expected[5] = "BINARY_ORIGINAL_STATUS"
            expected[6] = "BINARY_ORIGINAL_SHA256"
            expected[7] = "BINARY_BACKUP_PATH"
            expected[8] = "BINARY_CANDIDATE_SHA256"
            expected[9] = "CONFIG_MUTATED"; expected[10] = "CONFIG_SOURCE"
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
    ' "$marker" || return 1

    dir=${marker%/persistent-transaction.*}
    hash_pattern='^[0-9a-f]{64}$'
    binary_path=$(sed -n '4s/^BINARY_PATH=//p' "$marker")
    binary_original_status=$(sed -n '5s/^BINARY_ORIGINAL_STATUS=//p' "$marker")
    binary_original_sha=$(sed -n '6s/^BINARY_ORIGINAL_SHA256=//p' "$marker")
    binary_backup=$(sed -n '7s/^BINARY_BACKUP_PATH=//p' "$marker")
    binary_candidate_sha=$(sed -n '8s/^BINARY_CANDIDATE_SHA256=//p' "$marker")
    config_mutated=$(sed -n '9s/^CONFIG_MUTATED=//p' "$marker")
    config_source=$(sed -n '10s/^CONFIG_SOURCE=//p' "$marker")
    config_path=$(sed -n '11s/^CONFIG_PATH=//p' "$marker")
    config_original_status=$(sed -n '12s/^CONFIG_ORIGINAL_STATUS=//p' "$marker")
    config_original_sha=$(sed -n '13s/^CONFIG_ORIGINAL_SHA256=//p' "$marker")
    config_backup=$(sed -n '14s/^CONFIG_BACKUP_PATH=//p' "$marker")
    config_candidate_sha=$(sed -n '15s/^CONFIG_CANDIDATE_SHA256=//p' "$marker")
    rollback_source=$(sed -n '16s/^ROLLBACK_CONFIG_SOURCE=//p' "$marker")
    rollback_path=$(sed -n '17s/^ROLLBACK_CONFIG_PATH=//p' "$marker")
    rollback_sha=$(sed -n '18s/^ROLLBACK_CONFIG_SHA256=//p' "$marker")
    binary_original_metadata=$(sed -n '19s/^BINARY_ORIGINAL_METADATA=//p' "$marker")
    if [ "$has_config_metadata" = true ]; then
        config_original_metadata=$(sed -n '20s/^CONFIG_ORIGINAL_METADATA=//p' "$marker")
    elif [ "$config_mutated:$config_original_status" = true:present ]; then
        config_original_metadata=0:0:600
    else
        config_original_metadata=NONE
    fi

    [ "$binary_path" = /data/dcentrald ] || return 1
    [ "$binary_backup" = "$dir/dcentrald.backup" ] || return 1
    printf '%s\n' "$binary_candidate_sha" | grep -Eq "$hash_pattern" || return 1
    case "$binary_original_status:$binary_original_sha:$binary_original_metadata" in
        present:*:*)
            printf '%s\n' "$binary_original_sha" | grep -Eq "$hash_pattern" || return 1
            printf '%s\n' "$binary_original_metadata" | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$' || return 1
            ;;
        absent:NONE:NONE) ;;
        *) return 1 ;;
    esac
    case "$rollback_source:$rollback_path:$rollback_sha" in
        data:/data/dcentrald.toml:*|etc:/etc/dcentrald.toml:*)
            printf '%s\n' "$rollback_sha" | grep -Eq "$hash_pattern" || return 1
            ;;
        builtin:builtin:NONE) ;;
        *) return 1 ;;
    esac
    case "$config_source:$config_path:$config_candidate_sha" in
        explicit:/data/dcentrald.toml:*)
            [ "$config_mutated" = true ] || return 1
            printf '%s\n' "$config_candidate_sha" | grep -Eq "$hash_pattern" || return 1
            ;;
        discovered:/data/dcentrald.toml:*|discovered:/etc/dcentrald.toml:*)
            [ "$config_mutated" = false ] || return 1
            printf '%s\n' "$config_candidate_sha" | grep -Eq "$hash_pattern" || return 1
            ;;
        builtin:builtin:NONE)
            [ "$config_mutated" = false ] || return 1
            ;;
        *) return 1 ;;
    esac
    case "$config_mutated:$config_original_status:$config_original_sha:$config_backup" in
        true:present:*:"$dir/dcentrald.toml.backup")
            printf '%s\n' "$config_original_sha" | grep -Eq "$hash_pattern" || return 1
            case "$marker_schema:$config_original_metadata" in
                PERSISTENT_TX_STATE=dcent-persistent-tx-v3:0:0:600) ;;
                PERSISTENT_TX_STATE=dcent-persistent-tx-v4:*)
                    printf '%s\n' "$config_original_metadata" | grep -Eq '^[0-9]+:[0-9]+:[0-7]{3,4}$' || return 1
                    ;;
                *) return 1 ;;
            esac
            [ "$rollback_source:$rollback_path:$rollback_sha" \
                = "data:/data/dcentrald.toml:$config_original_sha" ] || return 1
            ;;
        true:absent:NONE:NONE)
            [ "$config_original_metadata" = NONE ] || return 1
            case "$rollback_source" in etc|builtin) ;; *) return 1 ;; esac
            ;;
        false:not_captured:NONE:NONE)
            [ "$config_original_metadata" = NONE ] || return 1
            case "$config_source:$config_path:$config_candidate_sha" in
                discovered:/data/dcentrald.toml:*)
                    [ "$rollback_source:$rollback_path:$rollback_sha" \
                        = "data:$config_path:$config_candidate_sha" ] || return 1
                    ;;
                discovered:/etc/dcentrald.toml:*)
                    [ "$rollback_source:$rollback_path:$rollback_sha" \
                        = "etc:$config_path:$config_candidate_sha" ] || return 1
                    ;;
                builtin:builtin:NONE)
                    [ "$rollback_source:$rollback_path:$rollback_sha" = builtin:builtin:NONE ] || return 1
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

terminal_directory_shape() {
    dir=$1
    for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "${entry##*/}" in
            deploy-lease.released)
                [ -d "$entry" ] && [ ! -L "$entry" ] || return 1
                [ "$(stat -c '%u:%a' "$entry" 2>/dev/null)" = "0:700" ] || return 1
                [ -f "$entry/owner" ] && [ ! -L "$entry/owner" ] || return 1
                [ "$(stat -c '%u:%a:%h' "$entry/owner" 2>/dev/null)" \
                    = "0:600:1" ] || return 1
                [ "$(cat "$entry/owner" 2>/dev/null)" = "${dir##*/}" ] || return 1
                released_count=0
                for released_entry in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
                    [ -e "$released_entry" ] || [ -L "$released_entry" ] || continue
                    [ "$released_entry" = "$entry/owner" ] || return 1
                    released_count=$((released_count + 1))
                done
                [ "$released_count" -eq 1 ] || return 1
                continue
                ;;
            dcentrald.new|dcentrald.backup|dcentrald.toml.new|dcentrald.toml.backup|expected-exit.pid|runtime-launch.authorized|runtime-launch.starting|runtime-launch.started|runtime-launch.cancelled|persistent-transaction.committed|persistent-transaction.rolled-back|persistent-transaction.recovered)
                [ -f "$entry" ] && [ ! -L "$entry" ] || return 1
                ;;
            *) return 1 ;;
        esac
    done
}

terminal_status() {
    dir=$1
    [ ! -e "$dir/persistent-transaction.state" ] \
        && [ ! -L "$dir/persistent-transaction.state" ] || return 1
    count=0
    status=
    for candidate in committed rolled-back recovered; do
        marker="$dir/persistent-transaction.$candidate"
        if [ -e "$marker" ] || [ -L "$marker" ]; then
            [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
            case "$candidate" in
                committed) expected_phase=committed ;;
                rolled-back) expected_phase=rolled_back ;;
                recovered) expected_phase=recovered ;;
            esac
            valid_terminal_manifest "$marker" "${dir##*/}" "$expected_phase" || return 1
            count=$((count + 1))
            status=$candidate
        fi
    done
    [ "$count" -eq 1 ] || return 1
    printf '%s\n' "$status"
}

terminal_old_enough() {
    modified=$(stat -c '%Y' "$1" 2>/dev/null) || return 1
    now=$(date +%s) || return 1
    age=$((now - modified))
    [ "$age" -ge 0 ] \
        && [ "$age" -ge $((min_age_hours * 3600)) ]
}

if [ "$action" = list ]; then
    for dir in "$base"/*; do
        [ -e "$dir" ] || [ -L "$dir" ] || continue
        valid_dir "$dir" || {
            printf 'INVALID\t%s\n' "$dir"
            continue
        }
        name=${dir##*/}
        if [ -f "$dir/persistent-transaction.state" ] \
            && [ ! -L "$dir/persistent-transaction.state" ]; then
            status=$(sed -n '3s/^PHASE=//p' "$dir/persistent-transaction.state")
            case "$status" in
                prepared|mutating|installed|failed|rolling_back|committed|recovered|rolled_back)
                    if valid_terminal_manifest \
                        "$dir/persistent-transaction.state" "$name" "$status"; then
                        printf '%s\tpending:%s\n' "$name" "$status"
                    else
                        printf '%s\tpending:invalid\n' "$name"
                    fi
                    ;;
                *) printf '%s\tpending:invalid\n' "$name" ;;
            esac
        elif status=$(terminal_status "$dir"); then
            printf '%s\tterminal:%s\n' "$name" "$status"
        else
            printf '%s\tretained:launch-or-invalid\n' "$name"
        fi
    done
    exit 0
fi

# ls -dt is safe here because every accepted basename is exactly 32 hex
# characters. Pending, ambiguous, symlinked, and launch-only directories are
# never deletion candidates. At least the newest terminal generation is kept.
if [ "$action" = prune-terminal ]; then
    terminal_seen=0
    for dir in $(ls -1dt "$base"/* 2>/dev/null || true); do
        valid_dir "$dir" || continue
        status=$(terminal_status "$dir") || continue
        terminal_seen=$((terminal_seen + 1))
        if [ "$terminal_seen" -le "$keep" ]; then
            printf 'KEEP\t%s\t%s\n' "${dir##*/}" "$status"
            continue
        fi
        case "$dir" in "$base"/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 1 ;; esac
        valid_dir "$dir" && status=$(terminal_status "$dir") || exit 1
        terminal_directory_shape "$dir" || exit 1
        if ! terminal_old_enough "$dir"; then
            printf 'KEEP\t%s\t%s:younger-than-min-age\n' "${dir##*/}" "$status"
            continue
        fi
        rm -rf -- "$dir"
        sync
        printf 'PRUNED\t%s\t%s\n' "${dir##*/}" "$status"
    done
fi

orphan_candidate() {
    dir=$1
    valid_dir "$dir" || return 1
    found=false
    # Hidden files are evidence too. Ignoring them would let an apparently
    # known-shape directory carry an unvalidated active/temporary marker into
    # recursive deletion.
    for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        [ -f "$entry" ] && [ ! -L "$entry" ] || return 1
        case "${entry##*/}" in
            dcentrald.new|dcentrald.backup|dcentrald.toml.new|dcentrald.toml.backup)
                found=true
                ;;
            *) return 1 ;;
        esac
    done
    [ "$found" = true ] || return 1
    modified=$(stat -c '%Y' "$dir" 2>/dev/null) || return 1
    now=$(date +%s)
    age=$((now - modified))
    [ "$age" -ge $((min_age_hours * 3600)) ]
}

if [ "$action" = prune-orphans ]; then
    for dir in "$base"/*; do
        [ -e "$dir" ] || [ -L "$dir" ] || continue
        orphan_candidate "$dir" || continue
        case "$dir" in "$base"/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 1 ;; esac
        orphan_candidate "$dir" || exit 1
        rm -rf -- "$dir"
        sync
        printf 'PRUNED\t%s\torphan-no-manifest\n' "${dir##*/}"
    done
fi
EOF
)

ssh "${SSH_OPTS[@]}" "root@$MINER_HOST" \
    "sh -s -- '$ACTION' '$KEEP' '$MIN_AGE_HOURS'" <<<"$REMOTE_SCRIPT"
