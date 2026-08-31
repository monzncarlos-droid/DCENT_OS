#!/bin/sh
# Cross-process ownership for the complete Zynq sysupgrade transaction.
#
# Public API:
#   dcent_sysupgrade_lock_acquire LOCK_DIR PROC_ROOT BOOT_ID_PATH
#   dcent_sysupgrade_lock_arm_env_commit
#   dcent_sysupgrade_lock_abort_env_commit
#   dcent_sysupgrade_lock_require_cleanup
#   dcent_sysupgrade_lock_preserve
#   dcent_sysupgrade_lock_release
#   dcent_sysupgrade_lock_ledger_path
#
# The lock is an atomic transaction directory containing a boot-id + PID +
# /proc starttime receipt.  Schema v2 reserves exactly one optional `ledger`
# child for the separately validated resource ledger.  The lock helper never
# creates, interprets, reconciles, or removes that child.  Its presence is a
# containment boundary: stale acquisition and normal active-phase release must
# preserve the complete directory until the resource owner reconciles it.
#
# A live matching owner is never displaced. A dead/PID-reused owner is removed
# only after the receipt is complete, internally consistent, and the directory
# contains no ledger or unexpected entry. Malformed or ambiguous state fails
# closed for manual inspection.

DCENT_SYSUPGRADE_LOCK_HELD=0
DCENT_SYSUPGRADE_LOCK_PRESERVE=0
DCENT_SYSUPGRADE_LOCK_DIR=
DCENT_SYSUPGRADE_LOCK_BOOT_ID=
DCENT_SYSUPGRADE_LOCK_PID=
DCENT_SYSUPGRADE_LOCK_STARTTIME=
DCENT_SYSUPGRADE_LOCK_PROC_ROOT=
DCENT_SYSUPGRADE_LOCK_PHASE=
DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT=0

dcent_sysupgrade_lock_fail()
{
    printf '%s\n' "sysupgrade-lock: ERROR: $*" >&2
    return 1
}

dcent_sysupgrade_lock_uuid_valid()
{
    _dcent_uuid_value=$1
    case "$_dcent_uuid_value" in
        ''|*[!0-9a-f-]*) return 1 ;;
    esac
    [ "${#_dcent_uuid_value}" -eq 36 ] || return 1

    _dcent_uuid_old_ifs=$IFS
    IFS=-
    # UUID input has already been restricted to lowercase hexadecimal and
    # hyphens, so field splitting cannot expand pathnames or shell syntax.
    set -- $_dcent_uuid_value
    IFS=$_dcent_uuid_old_ifs
    [ "$#" -eq 5 ] &&
        [ "${#1}" -eq 8 ] && [ "${#2}" -eq 4 ] &&
        [ "${#3}" -eq 4 ] && [ "${#4}" -eq 4 ] &&
        [ "${#5}" -eq 12 ]
}

dcent_sysupgrade_lock_uint_valid()
{
    _dcent_uint_value=$1
    _dcent_uint_maximum=$2
    case "$_dcent_uint_value" in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#_dcent_uint_value}" -le "${#_dcent_uint_maximum}" ] || return 1
    if [ "${#_dcent_uint_value}" -eq "${#_dcent_uint_maximum}" ]; then
        LC_ALL=C awk -v value="$_dcent_uint_value" \
            -v maximum="$_dcent_uint_maximum" \
            'BEGIN { exit !("x" value <= "x" maximum) }' </dev/null || return 1
    fi
    return 0
}

# Print a process starttime and return 0 only for a stable, admitted procfs
# record. Return 1 only when PID absence was observed twice under the same
# proc-root inode. Return 2 for every malformed, unreadable, or racy state.
# Callers must never collapse return 2 into proven process death.
dcent_sysupgrade_lock_parse_proc_stat_stream()
{
    _dcent_proc_parse_pid=$1
    _dcent_proc_parse_line=
    _dcent_proc_parse_extra=
    IFS= read -r _dcent_proc_parse_line || return 1
    if IFS= read -r _dcent_proc_parse_extra || [ -n "$_dcent_proc_parse_extra" ]; then
        return 1
    fi
    _dcent_proc_parse_tail=$(printf '%s\n' "$_dcent_proc_parse_line" |
        sed -n "s/^$_dcent_proc_parse_pid (.*) //p") || return 1
    [ -n "$_dcent_proc_parse_tail" ] || return 1
    _dcent_proc_start=$(printf '%s\n' "$_dcent_proc_parse_tail" |
        awk 'NR == 1 && NF >= 20 { print $20 }') || return 1
    dcent_sysupgrade_lock_uint_valid "$_dcent_proc_start" \
        18446744073709551615
}

dcent_sysupgrade_lock_process_starttime()
{
    _dcent_proc_root=$1
    _dcent_proc_pid=$2
    dcent_sysupgrade_lock_uint_valid "$_dcent_proc_pid" 2147483647 || return 2
    [ -d "$_dcent_proc_root" ] && [ ! -L "$_dcent_proc_root" ] || return 2

    _dcent_proc_root_before=$(dcent_sysupgrade_lock_stat '%d:%i' \
        "$_dcent_proc_root") || return 2
    _dcent_proc_pid_dir=$_dcent_proc_root/$_dcent_proc_pid
    if [ ! -e "$_dcent_proc_pid_dir" ] && [ ! -L "$_dcent_proc_pid_dir" ]; then
        _dcent_proc_root_after=$(dcent_sysupgrade_lock_stat '%d:%i' \
            "$_dcent_proc_root") || return 2
        [ "$_dcent_proc_root_before" = "$_dcent_proc_root_after" ] &&
            [ ! -e "$_dcent_proc_pid_dir" ] && [ ! -L "$_dcent_proc_pid_dir" ] ||
            return 2
        return 1
    fi
    [ -d "$_dcent_proc_pid_dir" ] && [ ! -L "$_dcent_proc_pid_dir" ] || return 2

    _dcent_proc_stat=$_dcent_proc_pid_dir/stat
    [ -r "$_dcent_proc_stat" ] && [ -f "$_dcent_proc_stat" ] &&
        [ ! -L "$_dcent_proc_stat" ] || return 2
    _dcent_proc_dir_before=$(dcent_sysupgrade_lock_stat '%d:%i' \
        "$_dcent_proc_pid_dir") || return 2
    _dcent_proc_stat_before=$(dcent_sysupgrade_lock_stat '%d:%i:%h' \
        "$_dcent_proc_stat") || return 2
    [ "${_dcent_proc_stat_before##*:}" = 1 ] || return 2

    dcent_sysupgrade_lock_parse_proc_stat_stream "$_dcent_proc_pid" \
        <"$_dcent_proc_stat" || return 2

    _dcent_proc_stat_after=$(dcent_sysupgrade_lock_stat '%d:%i:%h' \
        "$_dcent_proc_stat") || return 2
    _dcent_proc_dir_after=$(dcent_sysupgrade_lock_stat '%d:%i' \
        "$_dcent_proc_pid_dir") || return 2
    _dcent_proc_root_after=$(dcent_sysupgrade_lock_stat '%d:%i' \
        "$_dcent_proc_root") || return 2
    [ "$_dcent_proc_root_before" = "$_dcent_proc_root_after" ] &&
        [ "$_dcent_proc_dir_before" = "$_dcent_proc_dir_after" ] &&
        [ "$_dcent_proc_stat_before" = "$_dcent_proc_stat_after" ] &&
        [ -d "$_dcent_proc_pid_dir" ] && [ ! -L "$_dcent_proc_pid_dir" ] &&
        [ -f "$_dcent_proc_stat" ] && [ ! -L "$_dcent_proc_stat" ] || return 2
    printf '%s\n' "$_dcent_proc_start"
}

dcent_sysupgrade_lock_parse_receipt_stream()
{
    _dcent_receipt_line1=
    _dcent_receipt_line2=
    _dcent_receipt_line3=
    _dcent_receipt_line4=
    _dcent_receipt_line5=
    _dcent_receipt_line6=
    _dcent_receipt_extra=
    IFS= read -r _dcent_receipt_line1 || return 1
    IFS= read -r _dcent_receipt_line2 || return 1
    IFS= read -r _dcent_receipt_line3 || return 1
    IFS= read -r _dcent_receipt_line4 || return 1
    IFS= read -r _dcent_receipt_line5 || return 1
    IFS= read -r _dcent_receipt_line6 || return 1
    if IFS= read -r _dcent_receipt_extra || [ -n "$_dcent_receipt_extra" ]; then
        return 1
    fi

    [ "$_dcent_receipt_line1" = schema=dcentos-sysupgrade-lock-v2 ] || return 1
    case "$_dcent_receipt_line2" in boot_id=*) ;; *) return 1 ;; esac
    case "$_dcent_receipt_line3" in pid=*) ;; *) return 1 ;; esac
    case "$_dcent_receipt_line4" in starttime=*) ;; *) return 1 ;; esac
    case "$_dcent_receipt_line5" in phase=*) ;; *) return 1 ;; esac
    [ "$_dcent_receipt_line6" = owner=zynq-sysupgrade ] || return 1

    _dcent_lock_owner_boot=${_dcent_receipt_line2#boot_id=}
    _dcent_lock_owner_pid=${_dcent_receipt_line3#pid=}
    _dcent_lock_owner_start=${_dcent_receipt_line4#starttime=}
    _dcent_lock_owner_phase=${_dcent_receipt_line5#phase=}
    dcent_sysupgrade_lock_uuid_valid "$_dcent_lock_owner_boot" || return 1
    dcent_sysupgrade_lock_uint_valid "$_dcent_lock_owner_pid" 2147483647 || return 1
    dcent_sysupgrade_lock_uint_valid "$_dcent_lock_owner_start" \
        18446744073709551615 || return 1
    case "$_dcent_lock_owner_phase" in
        active|cleanup-required|env-commit-armed|env-committed) ;;
        *) return 1 ;;
    esac
    return 0
}

dcent_sysupgrade_lock_stat()
{
    stat -c "$1" -- "$2" 2>/dev/null
}

dcent_sysupgrade_lock_validate_lock_dir()
{
    _dcent_validate_dir=$1
    _dcent_validate_parent=${_dcent_validate_dir%/*}
    [ -n "$_dcent_validate_parent" ] || _dcent_validate_parent=/
    [ -d "$_dcent_validate_parent" ] && [ ! -L "$_dcent_validate_parent" ] &&
        [ -d "$_dcent_validate_dir" ] && [ ! -L "$_dcent_validate_dir" ] || return 1
    _dcent_validate_parent_meta=$(dcent_sysupgrade_lock_stat '%u:%g:%d' \
        "$_dcent_validate_parent") || return 1
    _dcent_validate_dir_meta=$(dcent_sysupgrade_lock_stat '%u:%g:%a:%d:%h' \
        "$_dcent_validate_dir") || return 1
    _dcent_validate_expected=${_dcent_validate_parent_meta%:*}:700:${_dcent_validate_parent_meta##*:}
    case "$_dcent_validate_dir_meta" in
        "$_dcent_validate_expected:2"|"$_dcent_validate_expected:3") return 0 ;;
        *) return 1 ;;
    esac
}

dcent_sysupgrade_lock_read_receipt()
{
    _dcent_read_receipt=$1
    _dcent_read_dir=${_dcent_read_receipt%/*}
    [ "$_dcent_read_receipt" = "$_dcent_read_dir/owner" ] || return 1
    dcent_sysupgrade_lock_validate_lock_dir "$_dcent_read_dir" || return 1
    [ -r "$_dcent_read_receipt" ] && [ -f "$_dcent_read_receipt" ] &&
        [ ! -L "$_dcent_read_receipt" ] || return 1

    _dcent_read_dir_meta=$(dcent_sysupgrade_lock_stat '%u:%g:%d' \
        "$_dcent_read_dir") || return 1
    _dcent_read_before=$(dcent_sysupgrade_lock_stat '%u:%g:%a:%d:%h:%i' \
        "$_dcent_read_receipt") || return 1
    _dcent_read_expected=${_dcent_read_dir_meta%:*}:600:${_dcent_read_dir_meta##*:}:1
    case "$_dcent_read_before" in
        "$_dcent_read_expected:"*) ;;
        *) return 1 ;;
    esac
    dcent_sysupgrade_lock_parse_receipt_stream <"$_dcent_read_receipt" || return 1
    _dcent_read_after=$(dcent_sysupgrade_lock_stat '%u:%g:%a:%d:%h:%i' \
        "$_dcent_read_receipt") || return 1
    [ "$_dcent_read_before" = "$_dcent_read_after" ] &&
        [ -f "$_dcent_read_receipt" ] && [ ! -L "$_dcent_read_receipt" ]
}

dcent_sysupgrade_lock_parse_boot_id_stream()
{
    _dcent_boot_line=
    _dcent_boot_extra=
    IFS= read -r _dcent_boot_line || return 1
    if IFS= read -r _dcent_boot_extra || [ -n "$_dcent_boot_extra" ]; then
        return 1
    fi
    dcent_sysupgrade_lock_uuid_valid "$_dcent_boot_line" || return 1
    _dcent_lock_boot_id=$_dcent_boot_line
}

dcent_sysupgrade_lock_read_boot_id()
{
    _dcent_boot_path=$1
    [ -r "$_dcent_boot_path" ] && [ -f "$_dcent_boot_path" ] &&
        [ ! -L "$_dcent_boot_path" ] || return 1
    _dcent_boot_before=$(dcent_sysupgrade_lock_stat '%d:%i:%h' \
        "$_dcent_boot_path") || return 1
    [ "${_dcent_boot_before##*:}" = 1 ] || return 1
    dcent_sysupgrade_lock_parse_boot_id_stream <"$_dcent_boot_path" || return 1
    _dcent_boot_after=$(dcent_sysupgrade_lock_stat '%d:%i:%h' \
        "$_dcent_boot_path") || return 1
    [ "$_dcent_boot_before" = "$_dcent_boot_after" ] &&
        [ -f "$_dcent_boot_path" ] && [ ! -L "$_dcent_boot_path" ]
}

dcent_sysupgrade_lock_validate_ledger()
{
    _dcent_lock_ledger_dir=$1
    _dcent_lock_ledger=$2
    [ "$_dcent_lock_ledger" = "$_dcent_lock_ledger_dir/ledger" ] || return 1
    [ -d "$_dcent_lock_ledger" ] && [ ! -L "$_dcent_lock_ledger" ] || return 1

    # The ledger implementation owns its internal schema.  The transaction
    # lock owns only this containment boundary: a private, same-owner,
    # same-filesystem directory at the one canonical child name.  Mount
    # identity is outside this shell helper and must be admitted separately by
    # any future mutation authority; st_dev alone cannot detect same-superblock
    # bind mounts.
    _dcent_lock_dir_meta=$(dcent_sysupgrade_lock_stat '%u:%g:%d' \
        "$_dcent_lock_ledger_dir") || return 1
    _dcent_lock_ledger_meta=$(dcent_sysupgrade_lock_stat '%u:%g:%a:%d' \
        "$_dcent_lock_ledger") || return 1
    _dcent_lock_expected_ledger_meta=${_dcent_lock_dir_meta%:*}:700:${_dcent_lock_dir_meta##*:}
    [ "$_dcent_lock_ledger_meta" = "$_dcent_lock_expected_ledger_meta" ]
}

dcent_sysupgrade_lock_inspect_entries()
{
    _dcent_lock_inspect_dir=$1
    dcent_sysupgrade_lock_validate_lock_dir "$_dcent_lock_inspect_dir" || return 1
    _dcent_lock_owner_path=$_dcent_lock_inspect_dir/owner
    _dcent_lock_entry_count=0
    _dcent_lock_owner_count=0
    DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT=0

    for _dcent_lock_entry in "$_dcent_lock_inspect_dir"/* \
        "$_dcent_lock_inspect_dir"/.[!.]* "$_dcent_lock_inspect_dir"/..?*; do
        [ -e "$_dcent_lock_entry" ] || [ -L "$_dcent_lock_entry" ] || continue
        _dcent_lock_entry_count=$((_dcent_lock_entry_count + 1))
        case "$_dcent_lock_entry" in
            "$_dcent_lock_owner_path")
                _dcent_lock_owner_count=$((_dcent_lock_owner_count + 1))
                ;;
            "$_dcent_lock_inspect_dir/ledger")
                [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 0 ] || return 1
                dcent_sysupgrade_lock_validate_ledger \
                    "$_dcent_lock_inspect_dir" "$_dcent_lock_entry" || return 1
                DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT=1
                ;;
            *)
                return 1
                ;;
        esac
    done
    [ "$_dcent_lock_owner_count" -eq 1 ] || return 1
    if [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 1 ]; then
        [ "$_dcent_lock_entry_count" -eq 2 ] || return 1
        _dcent_lock_expected_links=3
    else
        [ "$_dcent_lock_entry_count" -eq 1 ] || return 1
        _dcent_lock_expected_links=2
    fi
    [ "$(dcent_sysupgrade_lock_stat '%h' "$_dcent_lock_inspect_dir")" = \
        "$_dcent_lock_expected_links" ] || return 1
    return 0
}

dcent_sysupgrade_lock_ledger_path()
{
    [ "$#" -eq 0 ] || {
        dcent_sysupgrade_lock_fail "ledger-path lookup takes no arguments"
        return 1
    }
    [ "$DCENT_SYSUPGRADE_LOCK_HELD" = 1 ] && \
        [ -n "$DCENT_SYSUPGRADE_LOCK_DIR" ] || {
        dcent_sysupgrade_lock_fail "cannot resolve ledger path without lock ownership"
        return 1
    }
    printf '%s/ledger\n' "$DCENT_SYSUPGRADE_LOCK_DIR"
}

dcent_sysupgrade_lock_write_phase()
{
    _dcent_lock_new_phase=$1
    case "$_dcent_lock_new_phase" in
        active|cleanup-required|env-commit-armed|env-committed) ;;
        *) dcent_sysupgrade_lock_fail "invalid transaction phase"; return 1 ;;
    esac
    [ "$DCENT_SYSUPGRADE_LOCK_HELD" = 1 ] || {
        dcent_sysupgrade_lock_fail "cannot change phase without lock ownership"
        return 1
    }
    dcent_sysupgrade_lock_inspect_entries "$DCENT_SYSUPGRADE_LOCK_DIR" || {
        dcent_sysupgrade_lock_fail \
            "transaction directory contains malformed or unexpected state"
        return 1
    }
    _dcent_lock_new_receipt=$DCENT_SYSUPGRADE_LOCK_DIR/.owner.new.$$
    rm -f "$_dcent_lock_new_receipt" || return 1
    if ! (umask 077; printf '%s\n' \
        'schema=dcentos-sysupgrade-lock-v2' \
        "boot_id=$DCENT_SYSUPGRADE_LOCK_BOOT_ID" \
        "pid=$DCENT_SYSUPGRADE_LOCK_PID" \
        "starttime=$DCENT_SYSUPGRADE_LOCK_STARTTIME" \
        "phase=$_dcent_lock_new_phase" \
        'owner=zynq-sysupgrade' >"$_dcent_lock_new_receipt"); then
        rm -f "$_dcent_lock_new_receipt"
        dcent_sysupgrade_lock_fail "cannot write the replacement phase receipt"
        return 1
    fi
    chmod 600 "$_dcent_lock_new_receipt" || {
        rm -f "$_dcent_lock_new_receipt"
        dcent_sysupgrade_lock_fail "cannot secure the replacement phase receipt"
        return 1
    }
    mv -f "$_dcent_lock_new_receipt" "$DCENT_SYSUPGRADE_LOCK_DIR/owner" || {
        rm -f "$_dcent_lock_new_receipt"
        dcent_sysupgrade_lock_fail "cannot publish the replacement phase receipt"
        return 1
    }
    if ! dcent_sysupgrade_lock_read_receipt "$DCENT_SYSUPGRADE_LOCK_DIR/owner" || \
       [ "$_dcent_lock_owner_boot" != "$DCENT_SYSUPGRADE_LOCK_BOOT_ID" ] || \
       [ "$_dcent_lock_owner_pid" != "$DCENT_SYSUPGRADE_LOCK_PID" ] || \
       [ "$_dcent_lock_owner_start" != "$DCENT_SYSUPGRADE_LOCK_STARTTIME" ] || \
       [ "$_dcent_lock_owner_phase" != "$_dcent_lock_new_phase" ]; then
        dcent_sysupgrade_lock_fail "replacement phase receipt did not read back exactly"
        return 1
    fi
    DCENT_SYSUPGRADE_LOCK_PHASE=$_dcent_lock_new_phase
    return 0
}

dcent_sysupgrade_lock_receipt_matches()
{
    [ "$_dcent_lock_owner_boot" = "$1" ] &&
        [ "$_dcent_lock_owner_pid" = "$2" ] &&
        [ "$_dcent_lock_owner_start" = "$3" ] &&
        [ "$_dcent_lock_owner_phase" = "$4" ]
}

dcent_sysupgrade_lock_remove_exact()
{
    _dcent_remove_dir=$1
    _dcent_remove_proc_root=$2
    _dcent_remove_current_boot=$3
    _dcent_remove_expected_boot=$4
    _dcent_remove_expected_pid=$5
    _dcent_remove_expected_start=$6
    _dcent_remove_expected_phase=$7
    _dcent_remove_disposition=$8
    _dcent_remove_receipt=$_dcent_remove_dir/owner
    case "$_dcent_remove_disposition" in
        stale|owned) ;;
        *) return 1 ;;
    esac

    # Re-read and re-inspect rather than trusting the caller's earlier path
    # observations. A changed receipt, a ledger, or an unexpected entry keeps
    # the complete tree present for manual reconciliation.
    dcent_sysupgrade_lock_read_receipt "$_dcent_remove_receipt" || return 1
    dcent_sysupgrade_lock_receipt_matches \
        "$_dcent_remove_expected_boot" "$_dcent_remove_expected_pid" \
        "$_dcent_remove_expected_start" "$_dcent_remove_expected_phase" || return 1
    dcent_sysupgrade_lock_inspect_entries "$_dcent_remove_dir" || return 1
    [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 0 ] || return 1

    if [ "$_dcent_remove_expected_boot" = "$_dcent_remove_current_boot" ]; then
        _dcent_remove_live_start=
        if _dcent_remove_live_start=$(dcent_sysupgrade_lock_process_starttime \
            "$_dcent_remove_proc_root" "$_dcent_remove_expected_pid" 2>/dev/null); then
            _dcent_remove_liveness=0
        else
            _dcent_remove_liveness=$?
        fi
        case "$_dcent_remove_disposition:$_dcent_remove_liveness" in
            owned:0)
                [ "$_dcent_remove_live_start" = "$_dcent_remove_expected_start" ] ||
                    return 1
                ;;
            stale:0)
                [ "$_dcent_remove_live_start" != "$_dcent_remove_expected_start" ] ||
                    return 1
                ;;
            stale:1) ;;
            *) return 1 ;;
        esac
    else
        [ "$_dcent_remove_disposition" = stale ] || return 1
    fi

    # Re-admit after process observation. This closes the ordinary race where
    # a cooperative writer changes receipt state while liveness is inspected.
    dcent_sysupgrade_lock_read_receipt "$_dcent_remove_receipt" || return 1
    dcent_sysupgrade_lock_receipt_matches \
        "$_dcent_remove_expected_boot" "$_dcent_remove_expected_pid" \
        "$_dcent_remove_expected_start" "$_dcent_remove_expected_phase" || return 1
    dcent_sysupgrade_lock_inspect_entries "$_dcent_remove_dir" || return 1
    [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 0 ] || return 1
    rm -f "$_dcent_remove_receipt" || return 1
    # rmdir, never rm -rf: an unexpected entry or concurrent substitution
    # converts cleanup into a refusal rather than broad deletion.
    rmdir "$_dcent_remove_dir" || return 1
}

dcent_sysupgrade_lock_acquire()
{
    [ "$#" -eq 3 ] || {
        dcent_sysupgrade_lock_fail \
            "acquire requires LOCK_DIR PROC_ROOT BOOT_ID_PATH"
        return 1
    }
    [ "$DCENT_SYSUPGRADE_LOCK_HELD" = 0 ] || {
        dcent_sysupgrade_lock_fail "this process already owns the transaction lock"
        return 1
    }
    _dcent_lock_dir=$1
    _dcent_lock_proc_root=$2
    _dcent_lock_boot_path=$3
    case "$_dcent_lock_dir" in
        /*) ;;
        *) dcent_sysupgrade_lock_fail "lock path must be absolute"; return 1 ;;
    esac
    [ "$_dcent_lock_dir" != / ] || {
        dcent_sysupgrade_lock_fail "filesystem root cannot be a lock directory"
        return 1
    }
    _dcent_lock_parent=${_dcent_lock_dir%/*}
    [ -n "$_dcent_lock_parent" ] || _dcent_lock_parent=/
    [ -d "$_dcent_lock_parent" ] && [ ! -L "$_dcent_lock_parent" ] || {
        dcent_sysupgrade_lock_fail "lock parent is absent or unsafe"
        return 1
    }
    [ -d "$_dcent_lock_proc_root" ] && [ ! -L "$_dcent_lock_proc_root" ] || {
        dcent_sysupgrade_lock_fail "proc root is absent or unsafe"
        return 1
    }
    [ -r "$_dcent_lock_boot_path" ] && [ -f "$_dcent_lock_boot_path" ] &&
        [ ! -L "$_dcent_lock_boot_path" ] || {
        dcent_sysupgrade_lock_fail "boot-id path is absent or unsafe"
        return 1
    }
    dcent_sysupgrade_lock_read_boot_id "$_dcent_lock_boot_path" || {
        dcent_sysupgrade_lock_fail "boot-id is malformed or unstable"
        return 1
    }
    _dcent_lock_pid=$$
    _dcent_lock_start=$(dcent_sysupgrade_lock_process_starttime \
        "$_dcent_lock_proc_root" "$_dcent_lock_pid") || {
        dcent_sysupgrade_lock_fail "cannot prove this process starttime"
        return 1
    }

    _dcent_lock_attempt=1
    while [ "$_dcent_lock_attempt" -le 2 ]; do
        if (umask 077; mkdir "$_dcent_lock_dir" 2>/dev/null); then
            chmod 700 "$_dcent_lock_dir" || {
                rmdir "$_dcent_lock_dir" 2>/dev/null || true
                dcent_sysupgrade_lock_fail "cannot secure the new lock directory"
                return 1
            }
            if ! (umask 077; printf '%s\n' \
                'schema=dcentos-sysupgrade-lock-v2' \
                "boot_id=$_dcent_lock_boot_id" \
                "pid=$_dcent_lock_pid" \
                "starttime=$_dcent_lock_start" \
                'phase=active' \
                'owner=zynq-sysupgrade' >"$_dcent_lock_dir/owner"); then
                rm -f "$_dcent_lock_dir/owner"
                rmdir "$_dcent_lock_dir" 2>/dev/null || true
                dcent_sysupgrade_lock_fail "cannot publish the lock receipt"
                return 1
            fi
            chmod 600 "$_dcent_lock_dir/owner" || {
                rm -f "$_dcent_lock_dir/owner"
                rmdir "$_dcent_lock_dir" 2>/dev/null || true
                dcent_sysupgrade_lock_fail "cannot secure the lock receipt"
                return 1
            }
            DCENT_SYSUPGRADE_LOCK_HELD=1
            DCENT_SYSUPGRADE_LOCK_PRESERVE=0
            DCENT_SYSUPGRADE_LOCK_DIR=$_dcent_lock_dir
            DCENT_SYSUPGRADE_LOCK_BOOT_ID=$_dcent_lock_boot_id
            DCENT_SYSUPGRADE_LOCK_PID=$_dcent_lock_pid
            DCENT_SYSUPGRADE_LOCK_STARTTIME=$_dcent_lock_start
            DCENT_SYSUPGRADE_LOCK_PROC_ROOT=$_dcent_lock_proc_root
            DCENT_SYSUPGRADE_LOCK_PHASE=active
            DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT=0
            return 0
        fi

        [ -d "$_dcent_lock_dir" ] && [ ! -L "$_dcent_lock_dir" ] || {
            dcent_sysupgrade_lock_fail "existing lock path is not a real directory"
            return 1
        }
        if ! dcent_sysupgrade_lock_read_receipt "$_dcent_lock_dir/owner"; then
            dcent_sysupgrade_lock_fail \
                "existing lock receipt is malformed or incomplete; manual inspection required"
            return 1
        fi
        if ! dcent_sysupgrade_lock_inspect_entries "$_dcent_lock_dir"; then
            dcent_sysupgrade_lock_fail \
                "transaction directory contains a malformed ledger or unexpected entry; manual inspection required"
            return 1
        fi
        if [ "$_dcent_lock_owner_boot" = "$_dcent_lock_boot_id" ]; then
            case "$_dcent_lock_owner_phase" in
                cleanup-required|env-commit-armed|env-committed)
                    dcent_sysupgrade_lock_fail \
                        "a same-boot boot-environment transaction is $_dcent_lock_owner_phase; reboot or recovery is required"
                    return 1
                    ;;
            esac
            _dcent_lock_live_start=
            if _dcent_lock_live_start=$(dcent_sysupgrade_lock_process_starttime \
                "$_dcent_lock_proc_root" "$_dcent_lock_owner_pid" 2>/dev/null); then
                _dcent_lock_liveness=0
            else
                _dcent_lock_liveness=$?
            fi
            case "$_dcent_lock_liveness" in
                0)
                    if [ "$_dcent_lock_live_start" = "$_dcent_lock_owner_start" ]; then
                        dcent_sysupgrade_lock_fail \
                            "another sysupgrade transaction is active (pid=$_dcent_lock_owner_pid)"
                        return 1
                    fi
                    ;;
                1) ;;
                *)
                    dcent_sysupgrade_lock_fail \
                        "owner liveness is ambiguous; manual inspection required"
                    return 1
                    ;;
            esac
        fi
        if [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 1 ]; then
            dcent_sysupgrade_lock_fail \
                "a stale transaction retains a resource ledger; reconciliation is required before acquisition"
            return 1
        fi
        _dcent_lock_stale_boot=$_dcent_lock_owner_boot
        _dcent_lock_stale_pid=$_dcent_lock_owner_pid
        _dcent_lock_stale_start=$_dcent_lock_owner_start
        _dcent_lock_stale_phase=$_dcent_lock_owner_phase
        dcent_sysupgrade_lock_remove_exact \
            "$_dcent_lock_dir" "$_dcent_lock_proc_root" "$_dcent_lock_boot_id" \
            "$_dcent_lock_stale_boot" "$_dcent_lock_stale_pid" \
            "$_dcent_lock_stale_start" "$_dcent_lock_stale_phase" stale || {
            dcent_sysupgrade_lock_fail \
                "proven-stale lock could not be removed without broad deletion"
            return 1
        }
        _dcent_lock_attempt=$((_dcent_lock_attempt + 1))
    done

    dcent_sysupgrade_lock_fail "transaction lock acquisition lost a concurrent race"
    return 1
}

dcent_sysupgrade_lock_arm_env_commit()
{
    [ "$DCENT_SYSUPGRADE_LOCK_PHASE" = active ] || {
        dcent_sysupgrade_lock_fail "boot-environment commit can only arm from active phase"
        return 1
    }
    dcent_sysupgrade_lock_write_phase env-commit-armed
}

dcent_sysupgrade_lock_abort_env_commit()
{
    [ "$DCENT_SYSUPGRADE_LOCK_PHASE" = env-commit-armed ] || {
        dcent_sysupgrade_lock_fail "only an armed boot-environment commit can abort"
        return 1
    }
    dcent_sysupgrade_lock_write_phase active
}

dcent_sysupgrade_lock_require_cleanup()
{
    [ "$DCENT_SYSUPGRADE_LOCK_PHASE" = active ] || {
        dcent_sysupgrade_lock_fail \
            "cleanup-required can only be published from the active phase"
        return 1
    }
    dcent_sysupgrade_lock_write_phase cleanup-required || return 1
    DCENT_SYSUPGRADE_LOCK_PRESERVE=1
    return 0
}

dcent_sysupgrade_lock_preserve()
{
    [ "$DCENT_SYSUPGRADE_LOCK_HELD" = 1 ] || {
        dcent_sysupgrade_lock_fail "cannot preserve an unowned transaction lock"
        return 1
    }
    case "$DCENT_SYSUPGRADE_LOCK_PHASE" in
        env-commit-armed) ;;
        *)
            dcent_sysupgrade_lock_fail \
                "verified boot-environment commit can only publish from armed phase"
            return 1
            ;;
    esac
    dcent_sysupgrade_lock_write_phase env-committed || return 1
    DCENT_SYSUPGRADE_LOCK_PRESERVE=1
    return 0
}

dcent_sysupgrade_lock_release()
{
    [ "$DCENT_SYSUPGRADE_LOCK_HELD" = 1 ] || return 0
    [ "$DCENT_SYSUPGRADE_LOCK_PRESERVE" = 0 ] || return 0
    if ! dcent_sysupgrade_lock_read_receipt "$DCENT_SYSUPGRADE_LOCK_DIR/owner" || \
       [ "$_dcent_lock_owner_boot" != "$DCENT_SYSUPGRADE_LOCK_BOOT_ID" ] || \
       [ "$_dcent_lock_owner_pid" != "$DCENT_SYSUPGRADE_LOCK_PID" ] || \
       [ "$_dcent_lock_owner_start" != "$DCENT_SYSUPGRADE_LOCK_STARTTIME" ] || \
       [ "$_dcent_lock_owner_phase" != "$DCENT_SYSUPGRADE_LOCK_PHASE" ]; then
        dcent_sysupgrade_lock_fail \
            "lock ownership changed; refusing cleanup for manual inspection"
        return 1
    fi
    if ! dcent_sysupgrade_lock_inspect_entries "$DCENT_SYSUPGRADE_LOCK_DIR"; then
        dcent_sysupgrade_lock_fail \
            "transaction directory contains a malformed ledger or unexpected entry; refusing release"
        return 1
    fi
    case "$DCENT_SYSUPGRADE_LOCK_PHASE" in
        active)
            if [ "$DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT" = 1 ]; then
                dcent_sysupgrade_lock_fail \
                    "resource ledger remains; reconciliation is required before release"
                return 1
            fi
            ;;
        *)
            # Armed/committed receipts survive process exit. A later same-boot
            # writer must not infer boot-env state from process liveness.
            return 0
            ;;
    esac
    dcent_sysupgrade_lock_remove_exact \
        "$DCENT_SYSUPGRADE_LOCK_DIR" "$DCENT_SYSUPGRADE_LOCK_PROC_ROOT" \
        "$DCENT_SYSUPGRADE_LOCK_BOOT_ID" "$DCENT_SYSUPGRADE_LOCK_BOOT_ID" \
        "$DCENT_SYSUPGRADE_LOCK_PID" "$DCENT_SYSUPGRADE_LOCK_STARTTIME" \
        "$DCENT_SYSUPGRADE_LOCK_PHASE" owned || {
        dcent_sysupgrade_lock_fail "cannot release transaction lock safely"
        return 1
    }
    DCENT_SYSUPGRADE_LOCK_HELD=0
    DCENT_SYSUPGRADE_LOCK_DIR=
    DCENT_SYSUPGRADE_LOCK_PHASE=
    DCENT_SYSUPGRADE_LOCK_LEDGER_PRESENT=0
    return 0
}
