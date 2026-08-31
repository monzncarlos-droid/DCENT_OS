#!/bin/sh
# Admit or create one UBI character-device node from an exact sysfs authority.
#
# Public API:
#   dcent_ubi_node_admit SYSFS_DEV_ATTR DEV_ROOT NODE_NAME
#   dcent_ubi_node_ensure SYSFS_DEV_ATTR DEV_ROOT NODE_NAME
#
# Existing filesystem objects are validation-only: this helper never repairs,
# replaces, chmods, or chowns them.  dcent_ubi_node_ensure creates a missing
# node as root:root 0600 and then performs the same admission.  On success it
# exports DCENT_UBI_NODE_CREATED as 1 for a node created by that call, otherwise
# 0.  Transaction ownership and cleanup remain the caller's responsibility.

dcent_ubi_node_fail()
{
    printf '%s\n' "ubi-node: ERROR: $*" >&2
    return 1
}

dcent_ubi_node_uint()
{
    case "$1" in
        ''|*[!0-9]*|0[0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

dcent_ubi_node_read_authority()
{
    _dcent_ubi_node_attr=$1

    case "$_dcent_ubi_node_attr" in
        /*/dev) ;;
        *) dcent_ubi_node_fail "sysfs dev authority must be an absolute */dev path"; return 1 ;;
    esac
    [ -r "$_dcent_ubi_node_attr" ] && [ -f "$_dcent_ubi_node_attr" ] && \
        [ ! -L "$_dcent_ubi_node_attr" ] || {
        dcent_ubi_node_fail "sysfs dev authority is not a readable non-symlink file"
        return 1
    }
    _dcent_ubi_node_lines=$(wc -l <"$_dcent_ubi_node_attr" 2>/dev/null | tr -d '[:space:]') || {
        dcent_ubi_node_fail "cannot count sysfs dev authority lines"
        return 1
    }
    [ "$_dcent_ubi_node_lines" = 1 ] || {
        dcent_ubi_node_fail "sysfs dev authority must contain exactly one line"
        return 1
    }
    _dcent_ubi_node_dev=$(cat "$_dcent_ubi_node_attr" 2>/dev/null) || {
        dcent_ubi_node_fail "cannot read sysfs dev authority"
        return 1
    }
    case "$_dcent_ubi_node_dev" in
        *:*:*) dcent_ubi_node_fail "sysfs dev authority contains multiple separators"; return 1 ;;
        *:*) ;;
        *) dcent_ubi_node_fail "sysfs dev authority is not MAJOR:MINOR"; return 1 ;;
    esac
    _dcent_ubi_node_major=${_dcent_ubi_node_dev%%:*}
    _dcent_ubi_node_minor=${_dcent_ubi_node_dev#*:}
    dcent_ubi_node_uint "$_dcent_ubi_node_major" && \
        dcent_ubi_node_uint "$_dcent_ubi_node_minor" || {
        dcent_ubi_node_fail "sysfs dev authority is not decimal MAJOR:MINOR"
        return 1
    }
    [ "$_dcent_ubi_node_major" -le 4095 ] && \
        [ "$_dcent_ubi_node_minor" -le 1048575 ] || {
        dcent_ubi_node_fail "sysfs dev authority exceeds Linux device-number bounds"
        return 1
    }
    _dcent_ubi_node_major_hex=$(printf '%x' "$_dcent_ubi_node_major" 2>/dev/null) || return 1
    _dcent_ubi_node_minor_hex=$(printf '%x' "$_dcent_ubi_node_minor" 2>/dev/null) || return 1
    return 0
}

dcent_ubi_node_prepare_target()
{
    _dcent_ubi_node_root=$1
    _dcent_ubi_node_name=$2

    case "$_dcent_ubi_node_root" in
        /*) ;;
        *) dcent_ubi_node_fail "device root must be absolute"; return 1 ;;
    esac
    [ -d "$_dcent_ubi_node_root" ] && [ ! -L "$_dcent_ubi_node_root" ] || {
        dcent_ubi_node_fail "device root must be a non-symlink directory"
        return 1
    }
    _dcent_ubi_node_root_real=$(CDPATH='' cd -P "$_dcent_ubi_node_root" 2>/dev/null && pwd -P) || {
        dcent_ubi_node_fail "cannot resolve device root"
        return 1
    }
    [ "$_dcent_ubi_node_root_real" != / ] || {
        dcent_ubi_node_fail "refusing filesystem root as device root"
        return 1
    }
    if [ "$_dcent_ubi_node_name" != ubi_ctrl ]; then
        case "$_dcent_ubi_node_name" in
            ubi*) _dcent_ubi_node_suffix=${_dcent_ubi_node_name#ubi} ;;
            *) dcent_ubi_node_fail "device-node name is not an exact UBI node name"; return 1 ;;
        esac
        case "$_dcent_ubi_node_suffix" in
            *_*_*) dcent_ubi_node_fail "device-node name has multiple volume separators"; return 1 ;;
            *_*)
                _dcent_ubi_node_device_num=${_dcent_ubi_node_suffix%%_*}
                _dcent_ubi_node_volume_num=${_dcent_ubi_node_suffix#*_}
                dcent_ubi_node_uint "$_dcent_ubi_node_device_num" && \
                    dcent_ubi_node_uint "$_dcent_ubi_node_volume_num" || {
                    dcent_ubi_node_fail "device-node name has a non-decimal UBI number"
                    return 1
                }
                ;;
            *)
                dcent_ubi_node_uint "$_dcent_ubi_node_suffix" || {
                    dcent_ubi_node_fail "device-node name has a non-decimal UBI number"
                    return 1
                }
                ;;
        esac
    fi
    _dcent_ubi_node_sysfs_name=${_dcent_ubi_node_attr%/dev}
    _dcent_ubi_node_sysfs_name=${_dcent_ubi_node_sysfs_name##*/}
    [ "$_dcent_ubi_node_sysfs_name" = "$_dcent_ubi_node_name" ] || {
        dcent_ubi_node_fail "sysfs authority and device-node names differ"
        return 1
    }
    _dcent_ubi_node_target=$_dcent_ubi_node_root_real/$_dcent_ubi_node_name
    return 0
}

dcent_ubi_node_admit()
{
    [ "$#" -eq 3 ] || {
        dcent_ubi_node_fail "node admission requires exactly three arguments"
        return 1
    }
    dcent_ubi_node_read_authority "$1" || return 1
    dcent_ubi_node_prepare_target "$2" "$3" || return 1

    [ -e "$_dcent_ubi_node_target" ] || [ -L "$_dcent_ubi_node_target" ] || {
        dcent_ubi_node_fail "device node is missing: $_dcent_ubi_node_name"
        return 1
    }
    [ ! -L "$_dcent_ubi_node_target" ] && [ -c "$_dcent_ubi_node_target" ] || {
        dcent_ubi_node_fail "existing object is not a non-symlink character device"
        return 1
    }
    # Capture the filesystem identity in one stat snapshot.  Separate owner,
    # mode, link-count, and rdev calls could otherwise describe different
    # inodes if a privileged actor replaced the path between commands.
    _dcent_ubi_node_metadata=$(stat -c '%u:%g:%a:%h:%t:%T' \
        "$_dcent_ubi_node_target" 2>/dev/null | tr 'A-F' 'a-f') || {
        dcent_ubi_node_fail "cannot read device-node metadata"
        return 1
    }
    _dcent_ubi_node_old_ifs=$IFS
    IFS=:
    read -r \
        _dcent_ubi_node_uid \
        _dcent_ubi_node_gid \
        _dcent_ubi_node_mode \
        _dcent_ubi_node_links \
        _dcent_ubi_node_major_stat \
        _dcent_ubi_node_minor_stat <<EOF
$_dcent_ubi_node_metadata
EOF
    _dcent_ubi_node_read_rc=$?
    IFS=$_dcent_ubi_node_old_ifs
    [ "$_dcent_ubi_node_read_rc" -eq 0 ] || {
        dcent_ubi_node_fail "cannot parse device-node metadata"
        return 1
    }
    [ "$_dcent_ubi_node_links" = 1 ] || {
        dcent_ubi_node_fail "device node has a hard-link alias"
        return 1
    }
    [ "$_dcent_ubi_node_uid:$_dcent_ubi_node_gid" = 0:0 ] || {
        dcent_ubi_node_fail "device node is not owned by root:root"
        return 1
    }
    [ "$_dcent_ubi_node_mode" = 600 ] || {
        dcent_ubi_node_fail "device node mode is not 0600"
        return 1
    }
    _dcent_ubi_node_rdev=$_dcent_ubi_node_major_stat:$_dcent_ubi_node_minor_stat
    # Re-read the authority after all filesystem metadata.  UBI device
    # numbers are dynamic, so a detach/reattach race must not admit a node
    # using an authority snapshot that changed while stat(1) was running.
    dcent_ubi_node_read_authority "$1" || return 1
    [ "$_dcent_ubi_node_rdev" = "$_dcent_ubi_node_major_hex:$_dcent_ubi_node_minor_hex" ] || {
        dcent_ubi_node_fail "device node does not match its sysfs major:minor authority"
        return 1
    }
    return 0
}

dcent_ubi_node_ensure()
{
    DCENT_UBI_NODE_CREATED=0
    export DCENT_UBI_NODE_CREATED
    [ "$#" -eq 3 ] || {
        dcent_ubi_node_fail "node ensure requires exactly three arguments"
        return 1
    }
    dcent_ubi_node_read_authority "$1" || return 1
    dcent_ubi_node_prepare_target "$2" "$3" || return 1

    if [ -e "$_dcent_ubi_node_target" ] || [ -L "$_dcent_ubi_node_target" ]; then
        dcent_ubi_node_admit "$1" "$2" "$3"
        return $?
    fi
    [ "$(id -u 2>/dev/null)" = 0 ] || {
        dcent_ubi_node_fail "creating a missing UBI node requires UID 0"
        return 1
    }
    (umask 077 && mknod -m 600 "$_dcent_ubi_node_target" c \
        "$_dcent_ubi_node_major" "$_dcent_ubi_node_minor") || {
        dcent_ubi_node_fail "could not create missing UBI device node"
        return 1
    }
    DCENT_UBI_NODE_CREATED=1
    export DCENT_UBI_NODE_CREATED
    if ! dcent_ubi_node_admit "$1" "$2" "$3"; then
        dcent_ubi_node_fail "new UBI device node failed post-create admission"
        return 1
    fi
    return 0
}
