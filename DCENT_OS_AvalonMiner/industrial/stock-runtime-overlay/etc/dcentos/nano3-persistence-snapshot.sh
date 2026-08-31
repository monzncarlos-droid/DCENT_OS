#!/bin/sh
# Secret-safe, read-only Nano 3 persistence snapshot.
#
# Reads only the exact data-volume identity, boot ID, readiness marker, and two
# stock configuration files. It emits fixed metadata and digests, never values.
# It does not contact a network, signal a process, reboot, mount, sync, or write.

set -u
set -f
LC_ALL=C
export LC_ALL

fail() {
    echo "Nano 3 persistence snapshot refused: $*" >&2
    exit 2
}

[ "$#" -eq 2 ] || fail 'expected PHASE and 64-hex RUN_ID'
phase=$1
run_id=$2

case "$phase" in
    pre-reboot|post-reboot) ;;
    *) fail 'phase must be pre-reboot or post-reboot' ;;
esac
[ "${#run_id}" -eq 64 ] || fail 'run ID must contain exactly 64 hex characters'
case "$run_id" in
    *[!0-9a-f]*) fail 'run ID must be lowercase hexadecimal' ;;
esac

test_mode=${DCENT_PERSIST_TEST_MODE:-0}
case "$test_mode" in
    0)
        proc_root=/proc
        sys_root=/sys
        data_root=/data
        run_root=/run
        ;;
    1)
        proc_root=${DCENT_PERSIST_PROC_ROOT:-}
        sys_root=${DCENT_PERSIST_SYS_ROOT:-}
        data_root=${DCENT_PERSIST_DATA_ROOT:-}
        run_root=${DCENT_PERSIST_RUN_ROOT:-}
        for test_root in "$proc_root" "$sys_root" "$data_root" "$run_root"; do
            [ -n "$test_root" ] && [ "$test_root" != / ] ||
                fail 'test roots must be explicit and non-root'
        done
        ;;
    *) fail 'test mode must be 0 or 1' ;;
esac

for command_name in awk sha256sum stat wc; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "required command is unavailable: $command_name"
done

mount_identity=$(awk -v target="$data_root" '
    $2 == target {
        at_target++
        if ($1 == "/dev/ubi2_0" && $3 == "ubifs") exact++
    }
    END {
        if (at_target == 1 && exact == 1) print "ubi2_0:ubifs"
        else exit 1
    }
' "$proc_root/mounts" 2>/dev/null) || fail 'data mount identity is not exact'

mtd_num_file=$sys_root/class/ubi/ubi2/mtd_num
volume_name_file=$sys_root/class/ubi/ubi2_0/name
[ -r "$mtd_num_file" ] && [ ! -L "$mtd_num_file" ] ||
    fail 'UBI MTD identity is unavailable or indirect'
[ -r "$volume_name_file" ] && [ ! -L "$volume_name_file" ] ||
    fail 'UBI volume identity is unavailable or indirect'
IFS= read -r mtd_num <"$mtd_num_file" || fail 'could not read UBI MTD identity'
IFS= read -r volume_name <"$volume_name_file" ||
    fail 'could not read UBI volume identity'
[ "$mtd_num" = 12 ] || fail 'ubi2 is not attached to mtd12'
[ "$volume_name" = ubi_data_part ] || fail 'ubi2_0 is not ubi_data_part'

readiness_dir=$run_root/dcentos-data-ready
[ -d "$readiness_dir" ] && [ ! -L "$readiness_dir" ] ||
    fail 'boot-local data readiness marker is absent or indirect'

boot_id_file=$proc_root/sys/kernel/random/boot_id
[ -r "$boot_id_file" ] && [ ! -L "$boot_id_file" ] ||
    fail 'boot ID is unavailable or indirect'
IFS= read -r boot_id <"$boot_id_file" || fail 'could not read boot ID'
[ "${#boot_id}" -eq 36 ] || fail 'boot ID length is invalid'
case "$boot_id" in
    ????????-????-????-????-????????????) ;;
    *) fail 'boot ID shape is invalid' ;;
esac
case "$boot_id" in
    *[!0-9a-f-]*) fail 'boot ID must be lowercase hexadecimal UUID text' ;;
esac

inspect_config() {
    config_file=$1
    [ -f "$config_file" ] && [ ! -L "$config_file" ] || return 1

    config_stat_before=$(stat -c '%d:%i:%s:%Y:%a:%u:%g' "$config_file" \
        2>/dev/null) || return 1
    config_bytes=$(wc -c <"$config_file" 2>/dev/null) || return 1
    case "$config_bytes" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$config_bytes" -gt 0 ] && [ "$config_bytes" -le 65536 ] || return 1

    config_mode=$(stat -c '%a' "$config_file" 2>/dev/null) || return 1
    config_owner=$(stat -c '%u:%g' "$config_file" 2>/dev/null) || return 1
    case "$config_mode" in
        [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
        *) return 1 ;;
    esac
    case "$config_owner" in
        *[!0-9:]*|:*|*:|*:*:*) return 1 ;;
    esac

    config_sha256=$(sha256sum "$config_file" 2>/dev/null | awk '{print $1}') ||
        return 1
    [ "${#config_sha256}" -eq 64 ] || return 1
    case "$config_sha256" in
        *[!0-9a-f]*) return 1 ;;
    esac

    # Validate a bounded INI shape and hash only section/key names. Values are
    # neither emitted nor passed to the host verifier. Command substitution is
    # bounded by the 64 KiB file ceiling above.
    config_structure=$(awk '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            return value
        }
        {
            line = $0
            sub(/\r$/, "", line)
            if (length(line) > 4096) exit 2
            clean = trim(line)
            if (clean == "" || clean ~ /^[#;]/) next
            if (substr(clean, 1, 1) == "[" &&
                substr(clean, length(clean), 1) == "]") {
                section = trim(substr(clean, 2, length(clean) - 2))
                if (section == "") exit 2
                sections++
                printf "S%d:%s\n", length(section), section
                next
            }
            separator = index(line, "=")
            if (separator == 0 || section == "") exit 2
            key = trim(substr(line, 1, separator - 1))
            if (key == "") exit 2
            keys++
            printf "K%d:%s/%d:%s\n", length(section), section, length(key), key
        }
        END {
            if (sections == 0 || keys == 0) exit 2
        }
    ' "$config_file" 2>/dev/null) || return 1
    config_structure_sha256=$(printf '%s' "$config_structure" | sha256sum |
        awk '{print $1}') || return 1
    [ "${#config_structure_sha256}" -eq 64 ] || return 1
    case "$config_structure_sha256" in
        *[!0-9a-f]*) return 1 ;;
    esac

    # Hash twice and compare inode/size/mtime/mode/owner metadata around the
    # reads. A concurrent stock save is refused instead of producing a mixed
    # acceptance record.
    config_sha256_after=$(sha256sum "$config_file" 2>/dev/null |
        awk '{print $1}') || return 1
    config_stat_after=$(stat -c '%d:%i:%s:%Y:%a:%u:%g' "$config_file" \
        2>/dev/null) || return 1
    [ "$config_sha256_after" = "$config_sha256" ] || return 1
    [ "$config_stat_after" = "$config_stat_before" ] || return 1

    printf '%s|%s|%s|%s|%s\n' "$config_bytes" "$config_sha256" \
        "$config_structure_sha256" "$config_mode" "$config_owner"
}

systemcfg_meta=$(inspect_config "$data_root/usrcon/systemcfg.ini") ||
    fail 'system configuration is not one bounded regular nonempty INI file'
old_ifs=$IFS
IFS='|'
set -- $systemcfg_meta
IFS=$old_ifs
[ "$#" -eq 5 ] || fail 'system configuration metadata is malformed'
systemcfg_bytes=$1
systemcfg_sha256=$2
systemcfg_structure_sha256=$3
systemcfg_mode=$4
systemcfg_owner=$5

cgminer_meta=$(inspect_config "$data_root/usrcon/cgminer.ini") ||
    fail 'miner configuration is not one bounded regular nonempty INI file'
IFS='|'
set -- $cgminer_meta
IFS=$old_ifs
[ "$#" -eq 5 ] || fail 'miner configuration metadata is malformed'
cgminer_bytes=$1
cgminer_sha256=$2
cgminer_structure_sha256=$3
cgminer_mode=$4
cgminer_owner=$5

# Emit only this fixed schema after every input has passed. No config value can
# enter stdout or an error message.
printf '%s\n' \
    'schema=dcent-nano3-persistence-snapshot-v1' \
    'scope=read-only-structure-and-digest' \
    "phase=$phase" \
    "run_id=$run_id" \
    "boot_id=$boot_id" \
    'data_mount_device=/dev/ubi2_0' \
    'data_mount_type=ubifs' \
    "data_mount_identity=$mount_identity" \
    "data_mtd_num=$mtd_num" \
    "data_volume_name=$volume_name" \
    'readiness_marker=exact-directory' \
    "systemcfg_bytes=$systemcfg_bytes" \
    "systemcfg_sha256=$systemcfg_sha256" \
    "systemcfg_structure_sha256=$systemcfg_structure_sha256" \
    "systemcfg_mode=$systemcfg_mode" \
    "systemcfg_owner=$systemcfg_owner" \
    "cgminer_bytes=$cgminer_bytes" \
    "cgminer_sha256=$cgminer_sha256" \
    "cgminer_structure_sha256=$cgminer_structure_sha256" \
    "cgminer_mode=$cgminer_mode" \
    "cgminer_owner=$cgminer_owner" \
    'configuration_values_printed=false' \
    'snapshot_complete=1' \
    'authorizes_device=false' \
    'authorizes_reboot=false' \
    'authorizes_transmit=false' \
    'authorizes_energization=false'
