#!/bin/sh
# Read-only, exact process-tree admission for the Braiins S19k stock miner.
#
# The held S19k S99bosminer script launches:
#   /usr/bin/bos-tools run-and-watch -- /usr/bin/bosminer --log-to-file
# and stores the *bos-tools supervisor* PID in /var/run/bosminer.pid.  Killing
# only its bosminer child is not a handoff: run-and-watch restarts that child.
# This helper performs no signals, GPIO operations, or persistent writes.  It
# emits observation evidence for the runner/daemon custody transaction.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

MODE=${1:-capture}
PROC_ROOT=${2:-/proc}
PIDFILE=${3:-/var/run/bosminer.pid}

case "$PROC_ROOT" in
    /*) ;;
    *) echo "ERROR: proc root must be absolute" >&2; exit 2 ;;
esac
case "$PIDFILE" in
    /*) ;;
    *) echo "ERROR: pidfile must be absolute" >&2; exit 2 ;;
esac
case "$MODE" in capture) ;; *) echo "ERROR: mode must be capture" >&2; exit 2 ;; esac

regular_nonsymlink() {
    [ -f "$1" ] && [ ! -L "$1" ]
}

valid_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
}

proc_stat_fields() {
    STAT_FILE=$1
    regular_nonsymlink "$STAT_FILE" || return 1
    STAT_LINE=$(cat "$STAT_FILE" 2>/dev/null) || return 1
    # Linux /proc/PID/stat fields after the final ") ": state, ppid, pgrp,
    # session, ...; starttime is the twentieth field of this suffix.
    STAT_REST=${STAT_LINE##*) }
    set -- $STAT_REST
    [ "$#" -ge 20 ] || return 1
    STATE=$1
    PPID_VALUE=$2
    PGRP_VALUE=$3
    SESSION_VALUE=$4
    START_VALUE=${20}
    case "$STATE" in Z|X|x|'') return 1 ;; esac
    valid_uint "$PPID_VALUE" && valid_uint "$PGRP_VALUE" \
        && valid_uint "$SESSION_VALUE" && valid_uint "$START_VALUE" \
        && [ "$START_VALUE" -gt 0 ] || return 1
    printf '%s:%s:%s:%s:%s\n' \
        "$STATE" "$PPID_VALUE" "$PGRP_VALUE" "$SESSION_VALUE" "$START_VALUE"
}

cmdline_field() {
    CMDLINE=$1
    INDEX=$2
    regular_nonsymlink "$CMDLINE" || return 1
    tr '\000' '\n' < "$CMDLINE" | sed -n "${INDEX}p"
}

cmdline_count() {
    regular_nonsymlink "$1" || return 1
    tr '\000' '\n' < "$1" | wc -l | tr -d ' \t\r\n'
}

cmdline_is_supervisor() {
    CMDLINE=$1
    [ "$(cmdline_count "$CMDLINE")" = 5 ] \
        && [ "$(cmdline_field "$CMDLINE" 1)" = /usr/bin/bos-tools ] \
        && [ "$(cmdline_field "$CMDLINE" 2)" = run-and-watch ] \
        && [ "$(cmdline_field "$CMDLINE" 3)" = -- ] \
        && [ "$(cmdline_field "$CMDLINE" 4)" = /usr/bin/bosminer ] \
        && [ "$(cmdline_field "$CMDLINE" 5)" = --log-to-file ]
}

cmdline_is_child() {
    CMDLINE=$1
    [ "$(cmdline_count "$CMDLINE")" = 2 ] \
        && [ "$(cmdline_field "$CMDLINE" 1)" = /usr/bin/bosminer ] \
        && [ "$(cmdline_field "$CMDLINE" 2)" = --log-to-file ]
}

cmdline_mentions_bosminer() {
    regular_nonsymlink "$1" || return 1
    tr '\000' '\n' < "$1" | grep -Fx /usr/bin/bosminer >/dev/null 2>&1
}

hash_file() {
    regular_nonsymlink "$1" || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

size_file() {
    regular_nonsymlink "$1" || return 1
    wc -c < "$1" | tr -d ' \t\r\n'
}

capture_once() {
    regular_nonsymlink "$PIDFILE" || {
        echo "ERROR: Braiins bosminer pidfile is not a regular non-symlink" >&2
        return 1
    }
    SUPERVISOR_PID=$(tr -d ' \t\r\n' < "$PIDFILE")
    valid_uint "$SUPERVISOR_PID" && [ "$SUPERVISOR_PID" -gt 1 ] || {
        echo "ERROR: Braiins bosminer pidfile has no valid supervisor PID" >&2
        return 1
    }
    [ -d "$PROC_ROOT/$SUPERVISOR_PID" ] || {
        echo "ERROR: pidfile supervisor process is absent" >&2
        return 1
    }
    SUPERVISOR_EXE=$(readlink "$PROC_ROOT/$SUPERVISOR_PID/exe" 2>/dev/null || true)
    [ "$SUPERVISOR_EXE" = /usr/bin/bos-tools ] \
        && [ "$(cat "$PROC_ROOT/$SUPERVISOR_PID/comm" 2>/dev/null || true)" = bos-tools ] \
        && cmdline_is_supervisor "$PROC_ROOT/$SUPERVISOR_PID/cmdline" || {
            echo "ERROR: pidfile process is not the exact bos-tools run-and-watch supervisor" >&2
            return 1
        }
    SUPERVISOR_STAT=$(proc_stat_fields "$PROC_ROOT/$SUPERVISOR_PID/stat") || return 1
    OLD_IFS=$IFS
    IFS=:
    set -- $SUPERVISOR_STAT
    IFS=$OLD_IFS
    SUPERVISOR_STATE=$1
    SUPERVISOR_PPID=$2
    SUPERVISOR_PGRP=$3
    SUPERVISOR_SESSION=$4
    SUPERVISOR_START=$5
    [ "$SUPERVISOR_PPID" = 1 ] || {
        echo "ERROR: exact stock supervisor is not reparented to init" >&2
        return 1
    }

    SUPERVISOR_MATCHES=0
    BOSMINER_MATCHES=0
    CHILD_PID=
    for PROC_DIR in "$PROC_ROOT"/[0-9]*; do
        [ -d "$PROC_DIR" ] || continue
        PID=${PROC_DIR##*/}
        EXE=$(readlink "$PROC_DIR/exe" 2>/dev/null || true)
        COMM=$(cat "$PROC_DIR/comm" 2>/dev/null || true)
        if cmdline_is_supervisor "$PROC_DIR/cmdline"; then
            [ "$EXE" = /usr/bin/bos-tools ] && [ "$COMM" = bos-tools ] || {
                echo "ERROR: exact bosminer supervisor argv has a disguised executable or comm" >&2
                return 1
            }
            SUPERVISOR_MATCHES=$((SUPERVISOR_MATCHES + 1))
            [ "$PID" = "$SUPERVISOR_PID" ] || {
                echo "ERROR: a second exact bosminer run-and-watch supervisor exists" >&2
                return 1
            }
        elif { [ "$EXE" = /usr/bin/bos-tools ] || [ "$COMM" = bos-tools ]; } \
            && cmdline_mentions_bosminer "$PROC_DIR/cmdline"; then
            # Other held stock services legitimately use bos-tools
            # run-and-watch too.  Only a bos-tools command line mentioning
            # the hardware-owning bosminer belongs to this custody domain.
            echo "ERROR: a bos-tools process mentions bosminer but has an unexpected custody argv" >&2
            return 1
        fi
        if [ "$EXE" = /usr/bin/bosminer ] || [ "$COMM" = bosminer ]; then
            BOSMINER_MATCHES=$((BOSMINER_MATCHES + 1))
            [ "$EXE" = /usr/bin/bosminer ] && [ "$COMM" = bosminer ] \
                && cmdline_is_child "$PROC_DIR/cmdline" || {
                echo "ERROR: a bosminer process has an unexpected executable, comm, or argv" >&2
                return 1
            }
            CHILD_PID=$PID
        fi
    done
    [ "$SUPERVISOR_MATCHES" -eq 1 ] && [ "$BOSMINER_MATCHES" -eq 1 ] \
        && valid_uint "$CHILD_PID" && [ "$CHILD_PID" -gt 1 ] || {
            echo "ERROR: exact stock supervisor/child process tree is not globally unique" >&2
            return 1
        }
    CHILD_STAT=$(proc_stat_fields "$PROC_ROOT/$CHILD_PID/stat") || return 1
    IFS=:
    set -- $CHILD_STAT
    IFS=$OLD_IFS
    CHILD_STATE=$1
    CHILD_PPID=$2
    CHILD_PGRP=$3
    CHILD_SESSION=$4
    CHILD_START=$5
    [ "$CHILD_PPID" = "$SUPERVISOR_PID" ] \
        && [ "$CHILD_PGRP" = "$SUPERVISOR_PGRP" ] \
        && [ "$CHILD_SESSION" = "$SUPERVISOR_SESSION" ] || {
            echo "ERROR: bosminer is not the exact child in the supervisor process group/session" >&2
            return 1
        }

    SUPERVISOR_CMDLINE_SHA256=$(hash_file "$PROC_ROOT/$SUPERVISOR_PID/cmdline")
    SUPERVISOR_CMDLINE_BYTES=$(size_file "$PROC_ROOT/$SUPERVISOR_PID/cmdline")
    CHILD_CMDLINE_SHA256=$(hash_file "$PROC_ROOT/$CHILD_PID/cmdline")
    CHILD_CMDLINE_BYTES=$(size_file "$PROC_ROOT/$CHILD_PID/cmdline")
    PIDFILE_SHA256=$(hash_file "$PIDFILE")
    PIDFILE_BYTES=$(size_file "$PIDFILE")

    cat <<EOF
schema=dcentos.s19k-braiins-supervisor-custody/v1
authority=read-only-process-tree-observation
supervisor_pid=$SUPERVISOR_PID
supervisor_start=$SUPERVISOR_START
supervisor_ppid=$SUPERVISOR_PPID
supervisor_pgrp=$SUPERVISOR_PGRP
supervisor_session=$SUPERVISOR_SESSION
supervisor_state=nonterminal
supervisor_exe=$SUPERVISOR_EXE
supervisor_cmdline_sha256=$SUPERVISOR_CMDLINE_SHA256
supervisor_cmdline_bytes=$SUPERVISOR_CMDLINE_BYTES
child_pid=$CHILD_PID
child_start=$CHILD_START
child_ppid=$CHILD_PPID
child_pgrp=$CHILD_PGRP
child_session=$CHILD_SESSION
child_state=nonterminal
child_exe=/usr/bin/bosminer
child_cmdline_sha256=$CHILD_CMDLINE_SHA256
child_cmdline_bytes=$CHILD_CMDLINE_BYTES
pidfile=$PIDFILE
pidfile_sha256=$PIDFILE_SHA256
pidfile_bytes=$PIDFILE_BYTES
EOF
}

FIRST=$(capture_once)
SECOND=$(capture_once)
[ "$FIRST" = "$SECOND" ] || {
    echo "ERROR: stock supervisor/child identity changed across double capture" >&2
    exit 1
}
printf '%s\n' "$FIRST"
