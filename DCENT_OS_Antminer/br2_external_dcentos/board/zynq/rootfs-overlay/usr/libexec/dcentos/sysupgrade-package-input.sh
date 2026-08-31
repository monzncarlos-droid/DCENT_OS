#!/bin/sh
# Stable package-input admission for one Zynq sysupgrade transaction.
#
# Public API:
#   dcent_sysupgrade_input_open ABSOLUTE_PACKAGE_PATH
#   dcent_sysupgrade_input_verify_unchanged
#   dcent_sysupgrade_input_close
#
# A successful open publishes DCENT_SYSUPGRADE_INPUT_FD_PATH as
# /proc/self/fd/9.  Callers must use that path for every tar, hash, size,
# magic, extraction, and raw-image read.  Do not invoke input_open in command
# substitution: POSIX shells run command substitutions in a subshell, so the
# descriptor would not remain open in the sysupgrade process.
#
# This abstraction pins one inode without copying a 20--30 MiB upload into the
# 64 MiB Zynq /tmp tmpfs.  Renaming, replacing, or unlinking the original path
# cannot redirect descriptor-backed reads to a different inode.  The before /
# after identity and SHA-256 checks also fail closed on observed truncation or
# content changes.
#
# Linux caveat: a read-only descriptor is not a sealed immutable file.  A
# writer that already has this same inode open can still mutate it.  Requiring
# a root-owned, one-link, non-group/other-writable input excludes ordinary
# unprivileged opens, and checkpoint hashes detect observed mutation, but only
# trusted intake provenance can rule out a writable descriptor or mapping that
# predates admission.  Browser intake can satisfy that stronger provenance by
# creating a new root-owned file in a root-owned, non-writable staging
# directory and closing its upload descriptor before launching sysupgrade.
# The helper deliberately does not overclaim protection from a compromised
# root.  A concurrent privileged writer can also race immediately after any
# checkpoint; descriptor pinning plus re-hashing detects observed changes, but
# it is not an atomic byte seal.

DCENT_SYSUPGRADE_INPUT_PATH=
DCENT_SYSUPGRADE_INPUT_FD_PATH=
DCENT_SYSUPGRADE_INPUT_ID=
DCENT_SYSUPGRADE_INPUT_METADATA=
DCENT_SYSUPGRADE_INPUT_PARENT=
DCENT_SYSUPGRADE_INPUT_PARENT_METADATA=
DCENT_SYSUPGRADE_INPUT_SIZE=
DCENT_SYSUPGRADE_INPUT_SHA256=
DCENT_SYSUPGRADE_INPUT_OPEN=0

dcent_sysupgrade_input_fail()
{
    printf '%s\n' "sysupgrade-package-input: ERROR: $*" >&2
    return 1
}

# Pure policy seams let the mount-free host suite exercise the descriptor
# lifecycle as an unprivileged uid without weakening deployed admission.
dcent_sysupgrade_input_expected_uid()
{
    printf '%s\n' 0
}

dcent_sysupgrade_input_expected_gid()
{
    printf '%s\n' 0
}

_dcent_sysupgrade_input_stat_path()
{
    LC_ALL=C stat -c "$1" -- "$2" 2>/dev/null
}

_dcent_sysupgrade_input_stat_fd()
{
    # /proc/self/fd/N is a magic symlink.  -L inspects its pinned target.
    LC_ALL=C stat -Lc "$1" -- "$2" 2>/dev/null
}

_dcent_sysupgrade_input_validate_metadata()
{
    [ "$#" -eq 6 ] || return 1
    _dcent_input_uid=$1
    _dcent_input_gid=$2
    _dcent_input_mode=$3
    _dcent_input_nlink=$4
    _dcent_input_size=$5
    _dcent_input_type=$6

    [ "$_dcent_input_uid" = "$(dcent_sysupgrade_input_expected_uid)" ] &&
        [ "$_dcent_input_gid" = "$(dcent_sysupgrade_input_expected_gid)" ] &&
        [ "$_dcent_input_nlink" = 1 ] &&
        [ "$_dcent_input_type" = 'regular file' ] || return 1

    # Packages are data, never executables.  Owner-write is admitted because
    # the trusted root upload/administration paths naturally create 0600/0644
    # files; group/other write is never admitted.
    case "$_dcent_input_mode" in
        400|440|444|600|640|644) ;;
        *) return 1 ;;
    esac
    case "$_dcent_input_size" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    return 0
}

_dcent_sysupgrade_input_validate_directory_metadata()
{
    [ "$#" -eq 4 ] || return 1
    _dcent_input_dir_uid=$1
    _dcent_input_dir_gid=$2
    _dcent_input_dir_mode=$3
    _dcent_input_dir_type=$4
    [ "$_dcent_input_dir_type" = directory ] || return 1

    if [ "$_dcent_input_dir_uid" = "$(dcent_sysupgrade_input_expected_uid)" ]; then
        [ "$_dcent_input_dir_gid" = "$(dcent_sysupgrade_input_expected_gid)" ] ||
            return 1
    else
        # Host tests may run as an unprivileged uid below root-owned /tmp and
        # /.  In production expected uid/gid are already 0, so this branch
        # cannot widen the deployed owner policy.
        [ "$_dcent_input_dir_uid" = 0 ] && [ "$_dcent_input_dir_gid" = 0 ] ||
            return 1
    fi

    # The only admitted writable ancestor is the conventional root-owned
    # sticky scratch root.  All other ancestors must deny group/other write.
    [ "$_dcent_input_dir_mode" = 1777 ] &&
        [ "$_dcent_input_dir_uid" = 0 ] && return 0
    case "$_dcent_input_dir_mode" in
        ''|*[!0-9]*|[0-9][0-9][0-9][0-9]*) return 1 ;;
    esac
    _dcent_input_dir_user=$(( _dcent_input_dir_mode / 100 ))
    _dcent_input_dir_group=$(( (_dcent_input_dir_mode / 10) % 10 ))
    _dcent_input_dir_other=$(( _dcent_input_dir_mode % 10 ))
    case "$_dcent_input_dir_user" in 5|7) ;; *) return 1 ;; esac
    case "$_dcent_input_dir_group" in 0|1|4|5) ;; *) return 1 ;; esac
    case "$_dcent_input_dir_other" in 0|1|4|5) ;; *) return 1 ;; esac
    return 0
}

_dcent_sysupgrade_input_validate_ancestors()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_input_dir=$1
    while :
    do
        [ -d "$_dcent_input_dir" ] && [ ! -L "$_dcent_input_dir" ] || return 1
        _dcent_input_dir_meta=$(_dcent_sysupgrade_input_stat_path \
            '%u:%g:%a:%F' "$_dcent_input_dir") || return 1
        _dcent_input_old_ifs=$IFS
        IFS=':'
        # Directory metadata is delimiter-free.
        # shellcheck disable=SC2086
        set -- $_dcent_input_dir_meta
        IFS=$_dcent_input_old_ifs
        [ "$#" -eq 4 ] || return 1
        _dcent_sysupgrade_input_validate_directory_metadata \
            "$1" "$2" "$3" "$4" || return 1
        [ "$_dcent_input_dir" = / ] && break
        _dcent_input_dir=${_dcent_input_dir%/*}
        [ -n "$_dcent_input_dir" ] || _dcent_input_dir=/
    done
    return 0
}

_dcent_sysupgrade_input_validate_printable_path()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_input_nonprint=$(printf '%s' "$1" |
        LC_ALL=C tr -d '\040-\176' | wc -c | tr -d '[:space:]') || return 1
    [ "$_dcent_input_nonprint" = 0 ]
}

_dcent_sysupgrade_input_validate_path()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_input_path=$1
    case "$_dcent_input_path" in
        /*) ;;
        *) dcent_sysupgrade_input_fail "package path must be absolute"; return 1 ;;
    esac
    [ "$_dcent_input_path" != / ] || {
        dcent_sysupgrade_input_fail "filesystem root cannot be a package input"
        return 1
    }
    _dcent_sysupgrade_input_validate_printable_path "$_dcent_input_path" || {
        dcent_sysupgrade_input_fail "package path contains non-printable bytes"
        return 1
    }
    _dcent_input_leaf=${_dcent_input_path##*/}
    case "$_dcent_input_leaf" in
        ''|.|..)
            dcent_sysupgrade_input_fail "package path has no regular filename"
            return 1
            ;;
    esac
    [ -f "$_dcent_input_path" ] && [ ! -L "$_dcent_input_path" ] || {
        dcent_sysupgrade_input_fail "package input must be a non-symlink regular file"
        return 1
    }

    _dcent_input_parent=${_dcent_input_path%/*}
    [ -n "$_dcent_input_parent" ] || _dcent_input_parent=/
    _dcent_input_parent_real=$(CDPATH='' cd -P -- "$_dcent_input_parent" 2>/dev/null &&
        pwd -P) || {
        dcent_sysupgrade_input_fail "cannot canonicalize package parent directory"
        return 1
    }
    [ "$_dcent_input_parent_real" = "$_dcent_input_parent" ] || {
        dcent_sysupgrade_input_fail \
            "package path contains a symlinked or non-canonical ancestor"
        return 1
    }
    _dcent_sysupgrade_input_validate_ancestors "$_dcent_input_parent" || {
        dcent_sysupgrade_input_fail \
            "package ancestors must be canonical, trusted-owner directories without non-sticky group/other write"
        return 1
    }
    return 0
}

_dcent_sysupgrade_input_hash_fd()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_input_hash=$(sha256sum "$1" 2>/dev/null |
        awk 'NR == 1 { print tolower($1) }') || return 1
    case "$_dcent_input_hash" in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "$(printf '%s' "$_dcent_input_hash" | wc -c | tr -d '[:space:]')" = 64 ] ||
        return 1
    printf '%s\n' "$_dcent_input_hash"
}

_dcent_sysupgrade_input_clear_state()
{
    DCENT_SYSUPGRADE_INPUT_PATH=
    DCENT_SYSUPGRADE_INPUT_FD_PATH=
    DCENT_SYSUPGRADE_INPUT_ID=
    DCENT_SYSUPGRADE_INPUT_METADATA=
    DCENT_SYSUPGRADE_INPUT_PARENT=
    DCENT_SYSUPGRADE_INPUT_PARENT_METADATA=
    DCENT_SYSUPGRADE_INPUT_SIZE=
    DCENT_SYSUPGRADE_INPUT_SHA256=
    DCENT_SYSUPGRADE_INPUT_OPEN=0
}

dcent_sysupgrade_input_open()
{
    [ "$#" -eq 1 ] || {
        dcent_sysupgrade_input_fail "open requires ABSOLUTE_PACKAGE_PATH"
        return 1
    }
    [ "$DCENT_SYSUPGRADE_INPUT_OPEN" = 0 ] || {
        dcent_sysupgrade_input_fail "a package input is already open"
        return 1
    }
    [ "$(id -u 2>/dev/null)" = "$(dcent_sysupgrade_input_expected_uid)" ] || {
        dcent_sysupgrade_input_fail "caller uid is not admitted for package input"
        return 1
    }
    [ "$(id -g 2>/dev/null)" = "$(dcent_sysupgrade_input_expected_gid)" ] || {
        dcent_sysupgrade_input_fail "caller gid is not admitted for package input"
        return 1
    }
    if [ -e /proc/self/fd/9 ] || [ -L /proc/self/fd/9 ]; then
        dcent_sysupgrade_input_fail "reserved descriptor 9 is already in use"
        return 1
    fi

    _dcent_input_path=$1
    _dcent_sysupgrade_input_validate_path "$_dcent_input_path" || return 1
    _dcent_input_parent=${_dcent_input_path%/*}
    [ -n "$_dcent_input_parent" ] || _dcent_input_parent=/
    _dcent_input_parent_before=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%F' "$_dcent_input_parent") || {
        dcent_sysupgrade_input_fail "cannot inspect package parent identity"
        return 1
    }
    _dcent_input_before=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$_dcent_input_path") || {
        dcent_sysupgrade_input_fail "cannot inspect package input metadata"
        return 1
    }
    _dcent_input_old_ifs=$IFS
    IFS=':'
    # stat fields are numeric except the fixed, delimiter-free type label.
    # shellcheck disable=SC2086
    set -- $_dcent_input_before
    IFS=$_dcent_input_old_ifs
    [ "$#" -eq 8 ] || {
        dcent_sysupgrade_input_fail "unexpected package input metadata"
        return 1
    }
    _dcent_sysupgrade_input_validate_metadata "$3" "$4" "$5" "$6" "$7" "$8" || {
        dcent_sysupgrade_input_fail \
            "package must be expected-owner/group, regular, non-executable, one-link, and not group/other writable"
        return 1
    }

    # POSIX exec-with-redirection changes the current shell, so FD 9 remains
    # inherited by BusyBox tar/sha256sum even after pathname replacement.
    if ! exec 9< "$_dcent_input_path"; then
        dcent_sysupgrade_input_fail "cannot open package input on descriptor 9"
        return 1
    fi
    _dcent_input_fd_path=/proc/self/fd/9
    _dcent_input_fd=$(_dcent_sysupgrade_input_stat_fd \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$_dcent_input_fd_path") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "cannot inspect pinned package descriptor"
        return 1
    }
    _dcent_input_after=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$_dcent_input_path") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "package path disappeared during admission"
        return 1
    }
    if [ "$_dcent_input_before" != "$_dcent_input_fd" ] ||
       [ "$_dcent_input_before" != "$_dcent_input_after" ]; then
        exec 9<&-
        dcent_sysupgrade_input_fail "package identity changed while descriptor 9 was opened"
        return 1
    fi

    _dcent_input_sha=$(_dcent_sysupgrade_input_hash_fd "$_dcent_input_fd_path") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "cannot hash pinned package input"
        return 1
    }
    _dcent_input_fd_after=$(_dcent_sysupgrade_input_stat_fd \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$_dcent_input_fd_path") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "cannot re-inspect pinned package descriptor"
        return 1
    }
    _dcent_input_path_after=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$_dcent_input_path") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "package path disappeared while hashing"
        return 1
    }
    _dcent_input_parent_after=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%F' "$_dcent_input_parent") || {
        exec 9<&-
        dcent_sysupgrade_input_fail "package parent disappeared while hashing"
        return 1
    }
    if [ "$_dcent_input_fd_after" != "$_dcent_input_before" ] ||
       [ "$_dcent_input_path_after" != "$_dcent_input_before" ] ||
       [ "$_dcent_input_parent_after" != "$_dcent_input_parent_before" ]; then
        exec 9<&-
        dcent_sysupgrade_input_fail "package metadata changed while hashing"
        return 1
    fi

    DCENT_SYSUPGRADE_INPUT_PATH=$_dcent_input_path
    DCENT_SYSUPGRADE_INPUT_FD_PATH=$_dcent_input_fd_path
    DCENT_SYSUPGRADE_INPUT_ID=${_dcent_input_before%%:*}
    _dcent_input_rest=${_dcent_input_before#*:}
    DCENT_SYSUPGRADE_INPUT_ID=$DCENT_SYSUPGRADE_INPUT_ID:${_dcent_input_rest%%:*}
    DCENT_SYSUPGRADE_INPUT_METADATA=$_dcent_input_before
    DCENT_SYSUPGRADE_INPUT_PARENT=$_dcent_input_parent
    DCENT_SYSUPGRADE_INPUT_PARENT_METADATA=$_dcent_input_parent_before
    # Public state is consumed by the sysupgrade caller after this sourced
    # helper returns.
    # shellcheck disable=SC2034
    DCENT_SYSUPGRADE_INPUT_SIZE=$7
    DCENT_SYSUPGRADE_INPUT_SHA256=$_dcent_input_sha
    DCENT_SYSUPGRADE_INPUT_OPEN=1
    return 0
}

dcent_sysupgrade_input_verify_unchanged()
{
    [ "$#" -eq 0 ] || return 1
    [ "$DCENT_SYSUPGRADE_INPUT_OPEN" = 1 ] &&
        [ "$DCENT_SYSUPGRADE_INPUT_FD_PATH" = /proc/self/fd/9 ] || {
        dcent_sysupgrade_input_fail "no package input is open"
        return 1
    }
    _dcent_sysupgrade_input_validate_path "$DCENT_SYSUPGRADE_INPUT_PATH" || return 1

    _dcent_input_fd_before=$(_dcent_sysupgrade_input_stat_fd \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$DCENT_SYSUPGRADE_INPUT_FD_PATH") || {
        dcent_sysupgrade_input_fail "pinned package descriptor is unavailable"
        return 1
    }
    [ -f "$DCENT_SYSUPGRADE_INPUT_PATH" ] &&
        [ ! -L "$DCENT_SYSUPGRADE_INPUT_PATH" ] || {
        dcent_sysupgrade_input_fail "original package path was removed or substituted"
        return 1
    }
    _dcent_input_path_before=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$DCENT_SYSUPGRADE_INPUT_PATH") || return 1
    _dcent_input_parent_before=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%F' "$DCENT_SYSUPGRADE_INPUT_PARENT") || return 1
    if [ "$_dcent_input_fd_before" != "$DCENT_SYSUPGRADE_INPUT_METADATA" ] ||
       [ "$_dcent_input_path_before" != "$DCENT_SYSUPGRADE_INPUT_METADATA" ] ||
       [ "$_dcent_input_parent_before" != "$DCENT_SYSUPGRADE_INPUT_PARENT_METADATA" ]; then
        dcent_sysupgrade_input_fail "package path or descriptor metadata changed"
        return 1
    fi

    _dcent_input_sha=$(_dcent_sysupgrade_input_hash_fd \
        "$DCENT_SYSUPGRADE_INPUT_FD_PATH") || {
        dcent_sysupgrade_input_fail "cannot re-hash pinned package input"
        return 1
    }
    [ "$_dcent_input_sha" = "$DCENT_SYSUPGRADE_INPUT_SHA256" ] || {
        dcent_sysupgrade_input_fail "package content changed after admission"
        return 1
    }

    _dcent_input_fd_after=$(_dcent_sysupgrade_input_stat_fd \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$DCENT_SYSUPGRADE_INPUT_FD_PATH") || return 1
    _dcent_input_path_after=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%h:%s:%F' "$DCENT_SYSUPGRADE_INPUT_PATH") || return 1
    _dcent_input_parent_after=$(_dcent_sysupgrade_input_stat_path \
        '%d:%i:%u:%g:%a:%F' "$DCENT_SYSUPGRADE_INPUT_PARENT") || return 1
    if [ "$_dcent_input_fd_after" != "$DCENT_SYSUPGRADE_INPUT_METADATA" ] ||
       [ "$_dcent_input_path_after" != "$DCENT_SYSUPGRADE_INPUT_METADATA" ] ||
       [ "$_dcent_input_parent_after" != "$DCENT_SYSUPGRADE_INPUT_PARENT_METADATA" ]; then
        dcent_sysupgrade_input_fail "package metadata changed while re-hashing"
        return 1
    fi
    return 0
}

dcent_sysupgrade_input_close()
{
    [ "$#" -eq 0 ] || return 1
    if [ "$DCENT_SYSUPGRADE_INPUT_OPEN" = 1 ]; then
        exec 9<&-
    fi
    _dcent_sysupgrade_input_clear_state
    return 0
}
