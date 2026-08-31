#!/bin/sh
# Private scratch-space ownership for one Zynq sysupgrade transaction.
#
# Public API:
#   dcent_sysupgrade_workspace_create SCRATCH_ROOT
#   dcent_sysupgrade_workspace_path LEAF
#   dcent_sysupgrade_workspace_require_absent PATH
#   dcent_sysupgrade_workspace_cleanup PROC_MOUNTS
#
# The workspace is intentionally separate from the transaction-lock directory:
# the current lock receipt admits exactly one owner entry. The lock stays in
# /run, but the workspace lives below validated /tmp: Zynq
# deliberately caps /run at 1 MiB while signed package extraction needs tens
# of MiB. Cleanup verifies the workspace's original device/inode identity and
# refuses to cross a live mount boundary.
#
# REMAINING P0 (not hidden by this abstraction): pin mutable package input to
# a validated descriptor before tar inspection/extraction; validate every
# /dev/ubi* node against its sysfs major/minor identity; reconcile
# transaction-owned UBI attachments and mounts after signal/process death
# instead of relying on best-effort cleanup.

DCENT_SYSUPGRADE_WORKSPACE=
DCENT_SYSUPGRADE_WORKSPACE_ROOT=
DCENT_SYSUPGRADE_WORKSPACE_ID=
DCENT_SYSUPGRADE_WORKSPACE_OWNED=0

dcent_sysupgrade_workspace_fail()
{
    printf '%s\n' "sysupgrade-workspace: ERROR: $*" >&2
    return 1
}

# Kept as a pure predicate boundary so the mount-free host suite can exercise
# the complete lifecycle as an unprivileged CI user. Deployed callers source
# this definition unchanged, so their admitted uid remains exactly zero.
dcent_sysupgrade_workspace_expected_uid()
{
    printf '%s\n' 0
}

dcent_sysupgrade_workspace_owner_is_expected()
{
    [ "$#" -eq 1 ] || return 1
    [ "$1" = "$(dcent_sysupgrade_workspace_expected_uid)" ]
}

dcent_sysupgrade_workspace_stat()
{
    stat -c "$1" -- "$2" 2>/dev/null
}

dcent_sysupgrade_workspace_validate_root()
{
    [ "$#" -eq 1 ] || return 1
    _dcent_ws_root=$1
    case "$_dcent_ws_root" in
        /*) ;;
        *) dcent_sysupgrade_workspace_fail "workspace root must be absolute"; return 1 ;;
    esac
    [ "$_dcent_ws_root" != / ] || {
        dcent_sysupgrade_workspace_fail "filesystem root cannot be a workspace root"
        return 1
    }
    if [ ! -d "$_dcent_ws_root" ] || [ -L "$_dcent_ws_root" ]; then
        dcent_sysupgrade_workspace_fail "workspace root is absent or is a symlink"
        return 1
    fi
    _dcent_ws_real=$(CDPATH='' cd -P -- "$_dcent_ws_root" 2>/dev/null && pwd -P) || {
        dcent_sysupgrade_workspace_fail "cannot canonicalize workspace root"
        return 1
    }
    [ "$_dcent_ws_real" = "$_dcent_ws_root" ] || {
        dcent_sysupgrade_workspace_fail "workspace root contains a symlink or non-canonical component"
        return 1
    }
    _dcent_ws_uid=$(dcent_sysupgrade_workspace_stat %u "$_dcent_ws_root") || {
        dcent_sysupgrade_workspace_fail "cannot inspect workspace-root owner"
        return 1
    }
    dcent_sysupgrade_workspace_owner_is_expected "$_dcent_ws_uid" || {
        dcent_sysupgrade_workspace_fail "workspace root has the wrong owner"
        return 1
    }
    _dcent_ws_mode=$(dcent_sysupgrade_workspace_stat %a "$_dcent_ws_root") || {
        dcent_sysupgrade_workspace_fail "cannot inspect workspace-root mode"
        return 1
    }
    [ "$_dcent_ws_mode" = 1777 ] || {
        dcent_sysupgrade_workspace_fail \
            "scratch root must have exact sticky mode 1777 (mode=$_dcent_ws_mode)"
        return 1
    }
    printf '%s\n' "$_dcent_ws_real"
}

dcent_sysupgrade_workspace_is_empty()
{
    _dcent_ws_dir=$1
    _dcent_ws_entries=0
    for _dcent_ws_entry in "$_dcent_ws_dir"/* \
        "$_dcent_ws_dir"/.[!.]* "$_dcent_ws_dir"/..?*; do
        [ -e "$_dcent_ws_entry" ] || [ -L "$_dcent_ws_entry" ] || continue
        _dcent_ws_entries=$((_dcent_ws_entries + 1))
    done
    [ "$_dcent_ws_entries" -eq 0 ]
}

dcent_sysupgrade_workspace_verify_owned()
{
    [ "$DCENT_SYSUPGRADE_WORKSPACE_OWNED" = 1 ] || return 1
    [ -n "$DCENT_SYSUPGRADE_WORKSPACE" ] || return 1
    [ -d "$DCENT_SYSUPGRADE_WORKSPACE" ] && \
        [ ! -L "$DCENT_SYSUPGRADE_WORKSPACE" ] || return 1
    case "$DCENT_SYSUPGRADE_WORKSPACE" in
        "$DCENT_SYSUPGRADE_WORKSPACE_ROOT"/dcentos-sysupgrade.*) ;;
        *) return 1 ;;
    esac
    dcent_sysupgrade_workspace_owner_is_expected \
        "$(dcent_sysupgrade_workspace_stat %u "$DCENT_SYSUPGRADE_WORKSPACE")" || return 1
    [ "$(dcent_sysupgrade_workspace_stat %a "$DCENT_SYSUPGRADE_WORKSPACE")" = 700 ] || return 1
    _dcent_ws_current_id=$(dcent_sysupgrade_workspace_stat '%d:%i' \
        "$DCENT_SYSUPGRADE_WORKSPACE") || return 1
    [ "$_dcent_ws_current_id" = "$DCENT_SYSUPGRADE_WORKSPACE_ID" ]
}

dcent_sysupgrade_workspace_create()
{
    [ "$#" -eq 1 ] || {
        dcent_sysupgrade_workspace_fail "create requires SCRATCH_ROOT"
        return 1
    }
    [ "$DCENT_SYSUPGRADE_WORKSPACE_OWNED" = 0 ] || {
        dcent_sysupgrade_workspace_fail "this process already owns a workspace"
        return 1
    }
    dcent_sysupgrade_workspace_owner_is_expected "$(id -u 2>/dev/null)" || {
        dcent_sysupgrade_workspace_fail "caller uid is not admitted for workspace ownership"
        return 1
    }
    _dcent_ws_root=$(dcent_sysupgrade_workspace_validate_root "$1") || return 1

    # Do not save or restore a permissive inherited umask.  Everything created
    # after update admission remains private for the rest of the transaction.
    umask 077
    _dcent_ws_new=$(mktemp -d "$_dcent_ws_root/dcentos-sysupgrade.XXXXXX" 2>/dev/null) || {
        dcent_sysupgrade_workspace_fail "cannot create private workspace beneath $_dcent_ws_root"
        return 1
    }
    case "$_dcent_ws_new" in
        "$_dcent_ws_root"/dcentos-sysupgrade.*) ;;
        *)
            dcent_sysupgrade_workspace_fail "mktemp returned a workspace outside the admitted root"
            return 1
            ;;
    esac
    if [ ! -d "$_dcent_ws_new" ] || [ -L "$_dcent_ws_new" ]; then
        dcent_sysupgrade_workspace_fail "new workspace is not a real directory"
        return 1
    fi
    dcent_sysupgrade_workspace_owner_is_expected \
        "$(dcent_sysupgrade_workspace_stat %u "$_dcent_ws_new")" || {
        dcent_sysupgrade_workspace_fail "new workspace has the wrong owner"
        return 1
    }
    [ "$(dcent_sysupgrade_workspace_stat %a "$_dcent_ws_new")" = 700 ] || {
        dcent_sysupgrade_workspace_fail "new workspace mode is not 0700"
        return 1
    }
    dcent_sysupgrade_workspace_is_empty "$_dcent_ws_new" || {
        dcent_sysupgrade_workspace_fail "new workspace contains preexisting children"
        return 1
    }
    _dcent_ws_id=$(dcent_sysupgrade_workspace_stat '%d:%i' "$_dcent_ws_new") || {
        dcent_sysupgrade_workspace_fail "cannot capture new workspace identity"
        return 1
    }

    DCENT_SYSUPGRADE_WORKSPACE=$_dcent_ws_new
    DCENT_SYSUPGRADE_WORKSPACE_ROOT=$_dcent_ws_root
    DCENT_SYSUPGRADE_WORKSPACE_ID=$_dcent_ws_id
    DCENT_SYSUPGRADE_WORKSPACE_OWNED=1
    return 0
}

dcent_sysupgrade_workspace_path()
{
    [ "$#" -eq 1 ] || return 1
    dcent_sysupgrade_workspace_verify_owned || {
        dcent_sysupgrade_workspace_fail "cannot allocate a path without workspace ownership"
        return 1
    }
    _dcent_ws_leaf=$1
    case "$_dcent_ws_leaf" in
        ''|.|..|*[!A-Za-z0-9._-]*|*/*)
            dcent_sysupgrade_workspace_fail "unsafe workspace leaf: $_dcent_ws_leaf"
            return 1
            ;;
    esac
    printf '%s/%s\n' "$DCENT_SYSUPGRADE_WORKSPACE" "$_dcent_ws_leaf"
}

dcent_sysupgrade_workspace_require_absent()
{
    [ "$#" -eq 1 ] || return 1
    dcent_sysupgrade_workspace_verify_owned || return 1
    _dcent_ws_path=$1
    case "$_dcent_ws_path" in
        "$DCENT_SYSUPGRADE_WORKSPACE"/*) ;;
        *) dcent_sysupgrade_workspace_fail "path is outside the owned workspace"; return 1 ;;
    esac
    _dcent_ws_relative=${_dcent_ws_path#"$DCENT_SYSUPGRADE_WORKSPACE"/}
    case "$_dcent_ws_relative" in
        ''|.|..|*/*) dcent_sysupgrade_workspace_fail "path is not a direct workspace child"; return 1 ;;
    esac
    if [ -e "$_dcent_ws_path" ] || [ -L "$_dcent_ws_path" ]; then
        dcent_sysupgrade_workspace_fail "workspace child already exists: $_dcent_ws_relative"
        return 1
    fi
}

dcent_sysupgrade_workspace_has_mount()
{
    _dcent_ws_mounts=$1
    [ -r "$_dcent_ws_mounts" ] || return 0
    awk -v workspace="$DCENT_SYSUPGRADE_WORKSPACE" '
        $2 == workspace || index($2, workspace "/") == 1 { found=1 }
        END { exit found ? 0 : 1 }
    ' "$_dcent_ws_mounts"
}

dcent_sysupgrade_workspace_cleanup()
{
    [ "$#" -eq 1 ] || {
        dcent_sysupgrade_workspace_fail "cleanup requires PROC_MOUNTS"
        return 1
    }
    [ "$DCENT_SYSUPGRADE_WORKSPACE_OWNED" = 1 ] || return 0
    dcent_sysupgrade_workspace_verify_owned || {
        dcent_sysupgrade_workspace_fail "workspace identity changed; refusing broad cleanup"
        return 1
    }
    if dcent_sysupgrade_workspace_has_mount "$1"; then
        dcent_sysupgrade_workspace_fail \
            "workspace contains a live mount; cleanup ownership must be reconciled"
        return 1
    fi
    rm -rf -- "$DCENT_SYSUPGRADE_WORKSPACE" || {
        dcent_sysupgrade_workspace_fail "cannot remove the exact owned workspace"
        return 1
    }
    if [ -e "$DCENT_SYSUPGRADE_WORKSPACE" ] || [ -L "$DCENT_SYSUPGRADE_WORKSPACE" ]; then
        dcent_sysupgrade_workspace_fail "workspace remains after cleanup"
        return 1
    fi
    DCENT_SYSUPGRADE_WORKSPACE=
    DCENT_SYSUPGRADE_WORKSPACE_ROOT=
    DCENT_SYSUPGRADE_WORKSPACE_ID=
    DCENT_SYSUPGRADE_WORKSPACE_OWNED=0
    return 0
}
