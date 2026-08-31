#!/bin/sh
# Admit an attached Zynq inactive UBI device by immutable sysfs identity.
#
# Public API:
#   dcent_ubi_attachment_require_absent SYSFS_UBI_ROOT UBI_NUM EXPECTED_MTD
#   dcent_ubi_identity_admit SYSFS_UBI_ROOT UBI_NUM EXPECTED_MTD \
#       EXPECTED_VOLUME_COUNT KERNEL_TYPE ROOTFS_TYPE ROOTFS_DATA_TYPE
#
# This helper owns no attach, detach, provisioning, geometry, write, or boot
# environment operation.  Callers retain those responsibilities and must call
# this after any factory-blank provisioning, immediately before the first
# ubiupdatevol-capable phase.  The semantic volume IDs are deliberately fixed:
#   0=kernel, 1=rootfs, 2=rootfs_data

dcent_ubi_identity_fail()
{
    printf '%s\n' "ubi-identity: ERROR: $*" >&2
    return 1
}

dcent_ubi_identity_uint()
{
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

dcent_ubi_identity_canonical_uint()
{
    case "$1" in
        ''|*[!0-9]*|0[0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

dcent_ubi_identity_prepare_root()
{
    _dcent_ubi_sysfs=$1
    case "$_dcent_ubi_sysfs" in
        /*) ;;
        *) dcent_ubi_identity_fail "sysfs UBI root must be an absolute path"; return 1 ;;
    esac
    [ -d "$_dcent_ubi_sysfs" ] && [ ! -L "$_dcent_ubi_sysfs" ] || {
        dcent_ubi_identity_fail "sysfs UBI root must be a non-symlink directory"
        return 1
    }
    _dcent_ubi_sysfs_real=$(CDPATH='' cd -P "$_dcent_ubi_sysfs" 2>/dev/null && pwd -P) || {
        dcent_ubi_identity_fail "cannot resolve sysfs UBI root"
        return 1
    }
    [ "$_dcent_ubi_sysfs_real" != / ] || {
        dcent_ubi_identity_fail "refusing filesystem root as sysfs UBI root"
        return 1
    }
}

dcent_ubi_attachment_require_absent()
{
    [ "$#" -eq 3 ] || {
        dcent_ubi_identity_fail "attachment absence admission requires exactly three arguments"
        return 1
    }
    dcent_ubi_identity_prepare_root "$1" || return 1
    _dcent_ubi_absent_num=$2
    _dcent_ubi_absent_mtd=$3
    dcent_ubi_identity_canonical_uint "$_dcent_ubi_absent_num" || {
        dcent_ubi_identity_fail "desired UBI device number is not canonical decimal"
        return 1
    }
    dcent_ubi_identity_canonical_uint "$_dcent_ubi_absent_mtd" || {
        dcent_ubi_identity_fail "inactive MTD number is not canonical decimal"
        return 1
    }

    # Prove both allocation domains are free: the desired UBI number must not
    # exist, and the inactive MTD must not already be attached under any other
    # number.  A caller may then issue one explicit `ubiattach -d`; it must
    # never detach or adopt an object that has no matching ownership receipt.
    for _dcent_ubi_entry in "$_dcent_ubi_sysfs_real"/ubi*; do
        [ -e "$_dcent_ubi_entry" ] || [ -L "$_dcent_ubi_entry" ] || continue
        _dcent_ubi_entry_name=${_dcent_ubi_entry##*/}
        _dcent_ubi_entry_suffix=${_dcent_ubi_entry_name#ubi}
        case "$_dcent_ubi_entry_suffix" in
            *_*)
                _dcent_ubi_parent_num=${_dcent_ubi_entry_suffix%%_*}
                _dcent_ubi_volume_num=${_dcent_ubi_entry_suffix#*_}
                dcent_ubi_identity_canonical_uint "$_dcent_ubi_parent_num" &&
                    dcent_ubi_identity_canonical_uint "$_dcent_ubi_volume_num" || {
                    dcent_ubi_identity_fail "unexpected UBI class entry: $_dcent_ubi_entry_name"
                    return 1
                }
                [ -d "$_dcent_ubi_sysfs_real/ubi$_dcent_ubi_parent_num" ] || {
                    dcent_ubi_identity_fail "orphan UBI volume class entry: $_dcent_ubi_entry_name"
                    return 1
                }
                [ "$_dcent_ubi_parent_num" != "$_dcent_ubi_absent_num" ] || {
                    dcent_ubi_identity_fail "desired UBI device number has residual volume entries"
                    return 1
                }
                continue
                ;;
        esac
        dcent_ubi_identity_canonical_uint "$_dcent_ubi_entry_suffix" || {
            dcent_ubi_identity_fail "unexpected UBI class entry: $_dcent_ubi_entry_name"
            return 1
        }
        [ -d "$_dcent_ubi_entry" ] || {
            dcent_ubi_identity_fail "UBI device class entry is not a directory: $_dcent_ubi_entry_name"
            return 1
        }
        [ "$_dcent_ubi_entry_suffix" != "$_dcent_ubi_absent_num" ] || {
            dcent_ubi_identity_fail "desired UBI device number is already allocated"
            return 1
        }
        _dcent_ubi_attached_mtd=$(dcent_ubi_identity_read_attr \
            "$_dcent_ubi_entry/mtd_num" "$_dcent_ubi_entry_name/mtd_num") || return 1
        dcent_ubi_identity_canonical_uint "$_dcent_ubi_attached_mtd" || {
            dcent_ubi_identity_fail "attached UBI MTD identity is not canonical decimal"
            return 1
        }
        [ "$_dcent_ubi_attached_mtd" != "$_dcent_ubi_absent_mtd" ] || {
            dcent_ubi_identity_fail "inactive MTD is already attached as $_dcent_ubi_entry_name"
            return 1
        }
    done
    return 0
}

dcent_ubi_identity_read_attr()
{
    _dcent_ubi_attr=$1
    _dcent_ubi_label=$2

    [ -r "$_dcent_ubi_attr" ] && [ -f "$_dcent_ubi_attr" ] && \
        [ ! -L "$_dcent_ubi_attr" ] || {
        dcent_ubi_identity_fail "$_dcent_ubi_label is not a readable non-symlink attribute"
        return 1
    }
    _dcent_ubi_lines=$(wc -l <"$_dcent_ubi_attr" 2>/dev/null | tr -d '[:space:]') || {
        dcent_ubi_identity_fail "cannot count lines in $_dcent_ubi_label"
        return 1
    }
    [ "$_dcent_ubi_lines" = 1 ] || {
        dcent_ubi_identity_fail "$_dcent_ubi_label must contain exactly one line"
        return 1
    }
    _dcent_ubi_value=$(cat "$_dcent_ubi_attr" 2>/dev/null) || {
        dcent_ubi_identity_fail "cannot read $_dcent_ubi_label"
        return 1
    }
    [ -n "$_dcent_ubi_value" ] || {
        dcent_ubi_identity_fail "$_dcent_ubi_label is empty"
        return 1
    }
    case "$_dcent_ubi_value" in
        *'
'*)
            dcent_ubi_identity_fail "$_dcent_ubi_label contains embedded newlines"
            return 1
            ;;
    esac
    printf '%s\n' "$_dcent_ubi_value"
}

dcent_ubi_identity_check_volume()
{
    _dcent_ubi_root=$1
    _dcent_ubi_num=$2
    _dcent_ubi_id=$3
    _dcent_ubi_expected_name=$4
    _dcent_ubi_expected_type=$5
    _dcent_ubi_volume=$_dcent_ubi_root/ubi${_dcent_ubi_num}_${_dcent_ubi_id}

    [ -d "$_dcent_ubi_volume" ] || {
        dcent_ubi_identity_fail "missing UBI volume ID $_dcent_ubi_id ($_dcent_ubi_expected_name)"
        return 1
    }
    _dcent_ubi_name=$(dcent_ubi_identity_read_attr \
        "$_dcent_ubi_volume/name" "ubi${_dcent_ubi_num}_${_dcent_ubi_id}/name") || return 1
    [ "$_dcent_ubi_name" = "$_dcent_ubi_expected_name" ] || {
        dcent_ubi_identity_fail "UBI volume ID $_dcent_ubi_id is named '$_dcent_ubi_name', expected '$_dcent_ubi_expected_name'"
        return 1
    }
    _dcent_ubi_type=$(dcent_ubi_identity_read_attr \
        "$_dcent_ubi_volume/type" "ubi${_dcent_ubi_num}_${_dcent_ubi_id}/type") || return 1
    case "$_dcent_ubi_type" in
        dynamic|static) ;;
        *)
            dcent_ubi_identity_fail "UBI volume ID $_dcent_ubi_id has unrecognized type '$_dcent_ubi_type'"
            return 1
            ;;
    esac
    [ "$_dcent_ubi_type" = "$_dcent_ubi_expected_type" ] || {
        dcent_ubi_identity_fail "UBI volume ID $_dcent_ubi_id has type '$_dcent_ubi_type', expected '$_dcent_ubi_expected_type'"
        return 1
    }
    return 0
}

dcent_ubi_identity_admit()
{
    [ "$#" -eq 7 ] || {
        dcent_ubi_identity_fail "identity admission requires exactly seven arguments"
        return 1
    }
    _dcent_ubi_sysfs=$1
    _dcent_ubi_num=$2
    _dcent_ubi_expected_mtd=$3
    _dcent_ubi_expected_count=$4
    _dcent_ubi_kernel_type=$5
    _dcent_ubi_rootfs_type=$6
    _dcent_ubi_data_type=$7

    dcent_ubi_identity_prepare_root "$_dcent_ubi_sysfs" || return 1

    dcent_ubi_identity_uint "$_dcent_ubi_num" || {
        dcent_ubi_identity_fail "UBI device number is not an unsigned integer"
        return 1
    }
    dcent_ubi_identity_uint "$_dcent_ubi_expected_mtd" || {
        dcent_ubi_identity_fail "expected MTD number is not an unsigned integer"
        return 1
    }
    dcent_ubi_identity_uint "$_dcent_ubi_expected_count" || {
        dcent_ubi_identity_fail "expected volume count is not an unsigned integer"
        return 1
    }
    [ "$_dcent_ubi_expected_count" = 3 ] || {
        dcent_ubi_identity_fail "the Zynq sysupgrade semantic layout requires exactly three volumes"
        return 1
    }
    for _dcent_ubi_expected_type in \
        "$_dcent_ubi_kernel_type" "$_dcent_ubi_rootfs_type" "$_dcent_ubi_data_type"
    do
        case "$_dcent_ubi_expected_type" in
            dynamic|static) ;;
            *)
                dcent_ubi_identity_fail "expected volume type '$_dcent_ubi_expected_type' is not recognized"
                return 1
                ;;
        esac
    done

    _dcent_ubi_device=$_dcent_ubi_sysfs_real/ubi$_dcent_ubi_num
    [ -d "$_dcent_ubi_device" ] || {
        dcent_ubi_identity_fail "attached UBI device ubi$_dcent_ubi_num is missing"
        return 1
    }
    _dcent_ubi_mtd=$(dcent_ubi_identity_read_attr \
        "$_dcent_ubi_device/mtd_num" "ubi$_dcent_ubi_num/mtd_num") || return 1
    dcent_ubi_identity_uint "$_dcent_ubi_mtd" || {
        dcent_ubi_identity_fail "attached UBI MTD identity is not an unsigned integer"
        return 1
    }
    [ "$_dcent_ubi_mtd" = "$_dcent_ubi_expected_mtd" ] || {
        dcent_ubi_identity_fail "ubi$_dcent_ubi_num is attached to mtd$_dcent_ubi_mtd, expected mtd$_dcent_ubi_expected_mtd"
        return 1
    }

    _dcent_ubi_count=$(dcent_ubi_identity_read_attr \
        "$_dcent_ubi_device/volumes_count" "ubi$_dcent_ubi_num/volumes_count") || return 1
    dcent_ubi_identity_uint "$_dcent_ubi_count" || {
        dcent_ubi_identity_fail "attached UBI volume count is not an unsigned integer"
        return 1
    }
    [ "$_dcent_ubi_count" = "$_dcent_ubi_expected_count" ] || {
        dcent_ubi_identity_fail "ubi$_dcent_ubi_num reports $_dcent_ubi_count volumes, expected $_dcent_ubi_expected_count"
        return 1
    }

    _dcent_ubi_seen=0
    for _dcent_ubi_entry in "$_dcent_ubi_sysfs_real/ubi${_dcent_ubi_num}_"*
    do
        [ -e "$_dcent_ubi_entry" ] || [ -L "$_dcent_ubi_entry" ] || continue
        [ -d "$_dcent_ubi_entry" ] || {
            dcent_ubi_identity_fail "unexpected non-directory UBI volume entry: ${_dcent_ubi_entry##*/}"
            return 1
        }
        _dcent_ubi_entry_id=${_dcent_ubi_entry##*/}
        _dcent_ubi_entry_id=${_dcent_ubi_entry_id#ubi"${_dcent_ubi_num}"_}
        dcent_ubi_identity_uint "$_dcent_ubi_entry_id" || {
            dcent_ubi_identity_fail "unexpected UBI volume entry: ${_dcent_ubi_entry##*/}"
            return 1
        }
        [ "$_dcent_ubi_entry_id" -lt "$_dcent_ubi_expected_count" ] || {
            dcent_ubi_identity_fail "unexpected extra UBI volume ID $_dcent_ubi_entry_id"
            return 1
        }
        _dcent_ubi_seen=$((_dcent_ubi_seen + 1))
    done
    [ "$_dcent_ubi_seen" = "$_dcent_ubi_expected_count" ] || {
        dcent_ubi_identity_fail "sysfs exposes $_dcent_ubi_seen volume entries, expected $_dcent_ubi_expected_count"
        return 1
    }

    dcent_ubi_identity_check_volume "$_dcent_ubi_sysfs_real" \
        "$_dcent_ubi_num" 0 kernel "$_dcent_ubi_kernel_type" || return 1
    dcent_ubi_identity_check_volume "$_dcent_ubi_sysfs_real" \
        "$_dcent_ubi_num" 1 rootfs "$_dcent_ubi_rootfs_type" || return 1
    dcent_ubi_identity_check_volume "$_dcent_ubi_sysfs_real" \
        "$_dcent_ubi_num" 2 rootfs_data "$_dcent_ubi_data_type" || return 1

    return 0
}
