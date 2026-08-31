#!/bin/sh
# Admit the one canonical Zynq redundant U-Boot environment before mutation.
#
# Public API:
#   dcent_zynq_uboot_env_admit FW_ENV_CONFIG PROC_MTD SYSFS_MTD_ROOT MTD4_DEVICE
#
# Production callers bind these evidence sources to /etc/fw_env.config,
# /proc/mtd, /sys/class/mtd, and /dev/mtd4.  Keeping paths explicit lets the
# marker-guarded offline nandsim harness supply faithful proc/sysfs fixtures;
# expected identities and geometry remain immutable inside this helper.
# Sysupgrade must prove that fw_printenv/fw_setenv will address the audited
# mtd4 redundant-copy layout, not merely that their config exists.
# Underscored validators are side-effect-free test seams; they do not alter the
# production paths or weaken the public admission contract.

dcent_uboot_env_fail()
{
    printf '%s\n' "uboot-env-admission: ERROR: $*" >&2
    return 1
}

_dcent_uboot_env_uint()
{
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

_dcent_uboot_env_hex()
{
    case "$1" in
        ''|*[!0-9A-Fa-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

_dcent_uboot_env_stat()
{
    stat -c "$1" -- "$2" 2>/dev/null
}

_dcent_uboot_env_validate_config_metadata()
{
    [ "$#" -eq 7 ] || return 1
    _dcent_env_regular=$1
    _dcent_env_symlink=$2
    _dcent_env_ancestor_symlink=$3
    _dcent_env_uid=$4
    _dcent_env_gid=$5
    _dcent_env_mode=$6
    _dcent_env_nlink=$7

    [ "$_dcent_env_regular" = 1 ] && [ "$_dcent_env_symlink" = 0 ] &&
        [ "$_dcent_env_ancestor_symlink" = 0 ] &&
        [ "$_dcent_env_uid" = 0 ] && [ "$_dcent_env_gid" = 0 ] &&
        [ "$_dcent_env_mode" = 644 ] && [ "$_dcent_env_nlink" = 1 ]
}

_dcent_uboot_env_validate_config_content()
{
    [ "$#" -eq 4 ] || return 1
    [ "$1" = '/dev/mtd4 0x00000 0x20000 0x20000 1' ] &&
        [ "$2" = '/dev/mtd4 0x20000 0x20000 0x20000 1' ] &&
        [ "$3" = 2 ] && [ "$4" = 72 ]
}

_dcent_uboot_env_validate_ascii_path()
{
    [ "$#" -eq 1 ] || return 1
    [ -r "$1" ] || return 1
    # The config grammar permits horizontal tab, LF, and printable US-ASCII.
    # LC_ALL=C makes the octet ranges deterministic; CR, NUL, C1 bytes, and
    # UTF-8 multibyte input all survive tr and therefore cause refusal.
    _dcent_env_non_ascii_bytes=$(LC_ALL=C tr -d '\011\012\040-\176' <"$1" 2>/dev/null |
        wc -c | tr -d '[:space:]') || return 1
    [ "$_dcent_env_non_ascii_bytes" = 0 ]
}

_dcent_uboot_env_validate_config_content_path()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_env_config_path=$1
    [ -r "$_dcent_env_config_path" ] || return 1
    _dcent_uboot_env_validate_ascii_path "$_dcent_env_config_path" || return 1

    _dcent_env_line_count=$(wc -l <"$_dcent_env_config_path" 2>/dev/null |
        tr -d '[:space:]') || return 1
    _dcent_env_byte_count=$(wc -c <"$_dcent_env_config_path" 2>/dev/null |
        tr -d '[:space:]') || return 1
    _dcent_env_line_one=$(sed -n '1p' "$_dcent_env_config_path" 2>/dev/null) || return 1
    _dcent_env_line_two=$(sed -n '2p' "$_dcent_env_config_path" 2>/dev/null) || return 1

    _dcent_uboot_env_validate_config_content \
        "$_dcent_env_line_one" "$_dcent_env_line_two" \
        "$_dcent_env_line_count" "$_dcent_env_byte_count"
}

_dcent_uboot_env_validate_proc_record()
{
    [ "$#" -eq 5 ] || return 1
    [ "$1" = 1 ] && [ "$2" = 4 ] &&
        [ "$3" = 00080000 ] && [ "$4" = 00020000 ] &&
        [ "$5" = '"uboot_env"' ]
}

_dcent_uboot_env_validate_proc_mtd_path()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_env_proc_path=$1
    [ -r "$_dcent_env_proc_path" ] || return 1

    _dcent_env_proc_record=$(awk '
        $1 == "mtd4:" {
            count++
            if (count == 1) {
                fields = NF
                size = $2
                erase = $3
                name = $4
            }
        }
        END {
            printf "%d|%d|%s|%s|%s\n", count, fields, size, erase, name
        }
    ' "$_dcent_env_proc_path" 2>/dev/null) || return 1

    _dcent_env_old_ifs=$IFS
    IFS='|'
    # Intentional field splitting of the delimiter-only kernel record.
    # shellcheck disable=SC2086
    set -- $_dcent_env_proc_record
    IFS=$_dcent_env_old_ifs
    [ "$#" -eq 5 ] || return 1
    _dcent_uboot_env_validate_proc_record "$1" "$2" "$3" "$4" "$5"
}

_dcent_uboot_env_validate_sysfs_identity()
{
    [ "$#" -eq 4 ] || return 1
    [ "$1" = uboot_env ] && [ "$2" = 524288 ] &&
        [ "$3" = 131072 ]
    _dcent_env_sysfs_result=$?
    [ "$_dcent_env_sysfs_result" -eq 0 ] || return 1

    _dcent_env_sysfs_dev=$4
    case "$_dcent_env_sysfs_dev" in
        *:*) ;;
        *) return 1 ;;
    esac
    _dcent_env_sysfs_major=${_dcent_env_sysfs_dev%%:*}
    _dcent_env_sysfs_minor=${_dcent_env_sysfs_dev#*:}
    [ "$_dcent_env_sysfs_dev" = "$_dcent_env_sysfs_major:$_dcent_env_sysfs_minor" ] ||
        return 1
    _dcent_uboot_env_uint "$_dcent_env_sysfs_major" &&
        _dcent_uboot_env_uint "$_dcent_env_sysfs_minor"
}

_dcent_uboot_env_validate_device_metadata()
{
    [ "$#" -eq 9 ] || return 1
    _dcent_env_character=$1
    _dcent_env_symlink=$2
    _dcent_env_uid=$3
    _dcent_env_gid=$4
    _dcent_env_mode=$5
    _dcent_env_nlink=$6
    _dcent_env_major_hex=$7
    _dcent_env_minor_hex=$8
    _dcent_env_expected_dev=$9

    [ "$_dcent_env_character" = 1 ] && [ "$_dcent_env_symlink" = 0 ] &&
        [ "$_dcent_env_uid" = 0 ] && [ "$_dcent_env_gid" = 0 ] &&
        [ "$_dcent_env_mode" = 600 ] && [ "$_dcent_env_nlink" = 1 ] ||
        return 1
    _dcent_uboot_env_hex "$_dcent_env_major_hex" || return 1
    _dcent_uboot_env_hex "$_dcent_env_minor_hex" || return 1

    _dcent_env_major_dec=$(printf '%d' "0x$_dcent_env_major_hex" 2>/dev/null) ||
        return 1
    _dcent_env_minor_dec=$(printf '%d' "0x$_dcent_env_minor_hex" 2>/dev/null) ||
        return 1
    [ "$_dcent_env_major_dec:$_dcent_env_minor_dec" = "$_dcent_env_expected_dev" ]
}

_dcent_uboot_env_validate_evidence_paths()
{
    [ "$#" -eq 4 ] || return 1
    for _dcent_env_evidence_path in "$1" "$2" "$3" "$4"
    do
        case "$_dcent_env_evidence_path" in
            /*) ;;
            *) return 1 ;;
        esac
    done
    [ "$1" != / ] && [ "$2" != / ] && [ "$3" != / ] && [ "$4" != / ]
}

_dcent_uboot_env_read_sysfs_attr()
{
    [ "$#" -eq 2 ] || return 1
    _dcent_env_attr=$1
    _dcent_env_attr_label=$2
    [ -r "$_dcent_env_attr" ] || {
        dcent_uboot_env_fail "cannot read $_dcent_env_attr_label"
        return 1
    }
    _dcent_env_attr_lines=$(wc -l <"$_dcent_env_attr" 2>/dev/null |
        tr -d '[:space:]') || {
        dcent_uboot_env_fail "cannot count $_dcent_env_attr_label lines"
        return 1
    }
    [ "$_dcent_env_attr_lines" = 1 ] || {
        dcent_uboot_env_fail "$_dcent_env_attr_label must contain exactly one line"
        return 1
    }
    _dcent_env_attr_value=$(cat "$_dcent_env_attr" 2>/dev/null) || {
        dcent_uboot_env_fail "cannot read $_dcent_env_attr_label"
        return 1
    }
    [ -n "$_dcent_env_attr_value" ] || {
        dcent_uboot_env_fail "$_dcent_env_attr_label is empty"
        return 1
    }
    case "$_dcent_env_attr_value" in
        *'
'*)
            dcent_uboot_env_fail "$_dcent_env_attr_label contains embedded newlines"
            return 1
            ;;
    esac
    printf '%s\n' "$_dcent_env_attr_value"
}

_dcent_uboot_env_admit_config()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_env_config=$1
    [ -f "$_dcent_env_config" ] && [ ! -L "$_dcent_env_config" ] &&
        [ "${_dcent_env_config%/*}" != "$_dcent_env_config" ] || {
        dcent_uboot_env_fail "fw_env config must be an absolute non-symlink regular file"
        return 1
    }
    _dcent_env_config_parent=${_dcent_env_config%/*}
    [ -n "$_dcent_env_config_parent" ] || _dcent_env_config_parent=/
    _dcent_env_config_parent_real=$(CDPATH='' cd -P \
        "$_dcent_env_config_parent" 2>/dev/null && pwd -P) || {
        dcent_uboot_env_fail "cannot resolve fw_env config parent"
        return 1
    }
    [ "$_dcent_env_config_parent_real" = "$_dcent_env_config_parent" ] || {
        dcent_uboot_env_fail "fw_env config contains a symlinked or non-canonical ancestor"
        return 1
    }

    _dcent_env_config_before=$(_dcent_uboot_env_stat \
        '%d:%i:%u:%g:%a:%h' "$_dcent_env_config") || {
        dcent_uboot_env_fail "cannot inspect fw_env config metadata"
        return 1
    }
    _dcent_env_old_ifs=$IFS
    IFS=':'
    # stat fields are numeric and cannot contain the delimiter.
    # shellcheck disable=SC2086
    set -- $_dcent_env_config_before
    IFS=$_dcent_env_old_ifs
    [ "$#" -eq 6 ] || {
        dcent_uboot_env_fail "unexpected fw_env config metadata"
        return 1
    }
    _dcent_uboot_env_validate_config_metadata 1 0 0 "$3" "$4" "$5" "$6" || {
        dcent_uboot_env_fail "fw_env config must be root:root 0644 with one link"
        return 1
    }
    _dcent_uboot_env_validate_config_content_path "$_dcent_env_config" || {
        dcent_uboot_env_fail "fw_env config is not the exact two-copy mtd4 geometry"
        return 1
    }
    _dcent_env_config_after=$(_dcent_uboot_env_stat \
        '%d:%i:%u:%g:%a:%h' "$_dcent_env_config") || return 1
    [ "$_dcent_env_config_before" = "$_dcent_env_config_after" ] || {
        dcent_uboot_env_fail "fw_env config changed during admission"
        return 1
    }
}

dcent_zynq_uboot_env_admit()
{
    [ "$#" -eq 4 ] || {
        dcent_uboot_env_fail "admission requires FW_ENV_CONFIG PROC_MTD SYSFS_MTD_ROOT MTD4_DEVICE"
        return 1
    }
    _dcent_uboot_env_validate_evidence_paths "$1" "$2" "$3" "$4" || {
        dcent_uboot_env_fail "all evidence-source paths must be absolute and cannot be filesystem root"
        return 1
    }
    _dcent_env_config=$1
    _dcent_env_proc_mtd=$2
    _dcent_env_sysfs_root=$3
    _dcent_env_device=$4

    [ "$(id -u 2>/dev/null)" = 0 ] || {
        dcent_uboot_env_fail "U-Boot environment admission requires uid 0"
        return 1
    }

    _dcent_uboot_env_admit_config "$_dcent_env_config" || return 1

    [ -r "$_dcent_env_proc_mtd" ] && [ ! -L "$_dcent_env_proc_mtd" ] || {
        dcent_uboot_env_fail "proc MTD evidence is missing or symlinked"
        return 1
    }
    _dcent_uboot_env_validate_proc_mtd_path "$_dcent_env_proc_mtd" || {
        dcent_uboot_env_fail "proc MTD evidence does not expose exactly mtd4 size=00080000 erase=00020000 name=uboot_env"
        return 1
    }

    [ -d "$_dcent_env_sysfs_root" ] && [ ! -L "$_dcent_env_sysfs_root" ] || {
        dcent_uboot_env_fail "sysfs MTD root is missing or symlinked"
        return 1
    }
    _dcent_env_sysfs_mtd4=$_dcent_env_sysfs_root/mtd4
    [ -d "$_dcent_env_sysfs_mtd4" ] || {
        dcent_uboot_env_fail "mtd4 sysfs identity is missing"
        return 1
    }
    _dcent_env_sys_name=$(_dcent_uboot_env_read_sysfs_attr \
        "$_dcent_env_sysfs_mtd4/name" mtd4/name) || return 1
    _dcent_env_sys_size=$(_dcent_uboot_env_read_sysfs_attr \
        "$_dcent_env_sysfs_mtd4/size" mtd4/size) || return 1
    _dcent_env_sys_erase=$(_dcent_uboot_env_read_sysfs_attr \
        "$_dcent_env_sysfs_mtd4/erasesize" mtd4/erasesize) || return 1
    _dcent_env_sys_dev=$(_dcent_uboot_env_read_sysfs_attr \
        "$_dcent_env_sysfs_mtd4/dev" mtd4/dev) || return 1
    _dcent_uboot_env_validate_sysfs_identity \
        "$_dcent_env_sys_name" "$_dcent_env_sys_size" \
        "$_dcent_env_sys_erase" "$_dcent_env_sys_dev" || {
        dcent_uboot_env_fail "mtd4 sysfs identity does not match the canonical U-Boot environment"
        return 1
    }

    [ -c "$_dcent_env_device" ] && [ ! -L "$_dcent_env_device" ] || {
        dcent_uboot_env_fail "mtd4 device must be a non-symlink character device"
        return 1
    }
    _dcent_env_device_before=$(_dcent_uboot_env_stat \
        '%d:%i:%u:%g:%a:%h:%t:%T' "$_dcent_env_device") || {
        dcent_uboot_env_fail "cannot inspect mtd4 device metadata"
        return 1
    }
    _dcent_env_old_ifs=$IFS
    IFS=':'
    # stat fields are numeric/hexadecimal and cannot contain the delimiter.
    # shellcheck disable=SC2086
    set -- $_dcent_env_device_before
    IFS=$_dcent_env_old_ifs
    [ "$#" -eq 8 ] || {
        dcent_uboot_env_fail "unexpected mtd4 device metadata"
        return 1
    }
    _dcent_uboot_env_validate_device_metadata \
        1 0 "$3" "$4" "$5" "$6" "$7" "$8" "$_dcent_env_sys_dev" || {
        dcent_uboot_env_fail "mtd4 device must be root:root 0600, one-link, and match the sysfs device number"
        return 1
    }
    _dcent_env_device_after=$(_dcent_uboot_env_stat \
        '%d:%i:%u:%g:%a:%h:%t:%T' "$_dcent_env_device") || return 1
    [ "$_dcent_env_device_before" = "$_dcent_env_device_after" ] || {
        dcent_uboot_env_fail "mtd4 device changed during admission"
        return 1
    }

    return 0
}
