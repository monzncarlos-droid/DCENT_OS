#!/bin/sh
# Additive-only migration for Nano 3 configuration hidden by the /data mount.
# This file is sourced by S98dcent-data and is intentionally POSIX/BusyBox ash.

DCENT_KNOWN_DATA_CONFIGS="usrcon/systemcfg.ini usrcon/cgminer.ini"

# Stock Nano 3 btcminer opens both configuration paths directly with "w+".
# It cannot persist defaults or UI changes when the parent is absent, even if
# there is no pre-mount configuration to migrate.  Create only that exact
# directory; never replace a symlink/non-directory or rewrite existing mode or
# ownership metadata.
dcent_prepare_stock_config_dir() {
    dcent_data=$1
    dcent_data_usrcon=$dcent_data/usrcon

    [ -d "$dcent_data" ] && [ ! -L "$dcent_data" ] || return 1
    [ ! -L "$dcent_data_usrcon" ] || return 1
    if [ ! -e "$dcent_data_usrcon" ]; then
        mkdir -m 0755 "$dcent_data_usrcon" 2>/dev/null || {
            [ -d "$dcent_data_usrcon" ] && [ ! -L "$dcent_data_usrcon" ] ||
                return 1
        }
    fi
    [ -d "$dcent_data_usrcon" ] && [ ! -L "$dcent_data_usrcon" ] || return 1
}

# Remove only private work directories that can be left by a power loss between
# temporary-file creation, hard-link publication, and cleanup. Refuse an
# indirect directory, indirect file, or any unexpected entry instead of
# treating a broad prefix as disposable scratch space. Callers hold the exact
# /data and /data/usrcon root lock while this runs.
dcent_cleanup_stale_config_workdirs() {
    dcent_data=$1
    dcent_data_usrcon=$dcent_data/usrcon

    [ -d "$dcent_data_usrcon" ] && [ ! -L "$dcent_data_usrcon" ] || return 1
    for dcent_work in \
        "$dcent_data_usrcon"/.dcentos-config-init.* \
        "$dcent_data_usrcon"/.dcentos-config-migrate.*; do
        [ -e "$dcent_work" ] || [ -L "$dcent_work" ] || continue
        [ -d "$dcent_work" ] && [ ! -L "$dcent_work" ] || return 1

        for dcent_entry in \
            "$dcent_work"/* "$dcent_work"/.[!.]* "$dcent_work"/..?*; do
            [ -e "$dcent_entry" ] || [ -L "$dcent_entry" ] || continue
            case "$dcent_entry" in
                "$dcent_work/systemcfg.ini"|"$dcent_work/cgminer.ini") ;;
                *) return 1 ;;
            esac
            [ -f "$dcent_entry" ] && [ ! -L "$dcent_entry" ] || return 1
        done

        rm -f "$dcent_work/systemcfg.ini" "$dcent_work/cgminer.ini" ||
            return 1
        rmdir "$dcent_work" || return 1
    done
}

# A reset before the data volume mounts can strand the narrow pre-mount seed in
# /tmp. Admit only the exact seed layout this library creates. Empty seeds and
# a partially created usrcon directory are valid interruption states; any
# unexpected or indirect content fails closed without broad deletion.
dcent_cleanup_stale_seed_dirs() {
    dcent_seed_parent=$1

    [ -d "$dcent_seed_parent" ] && [ ! -L "$dcent_seed_parent" ] || return 1
    for dcent_seed in "$dcent_seed_parent"/dcentos-data-seed.*; do
        [ -e "$dcent_seed" ] || [ -L "$dcent_seed" ] || continue
        [ -d "$dcent_seed" ] && [ ! -L "$dcent_seed" ] || return 1

        for dcent_entry in \
            "$dcent_seed"/* "$dcent_seed"/.[!.]* "$dcent_seed"/..?*; do
            [ -e "$dcent_entry" ] || [ -L "$dcent_entry" ] || continue
            [ "$dcent_entry" = "$dcent_seed/usrcon" ] || return 1
            [ -d "$dcent_entry" ] && [ ! -L "$dcent_entry" ] || return 1
        done

        dcent_seed_usrcon=$dcent_seed/usrcon
        if [ -e "$dcent_seed_usrcon" ] || [ -L "$dcent_seed_usrcon" ]; then
            [ -d "$dcent_seed_usrcon" ] && [ ! -L "$dcent_seed_usrcon" ] ||
                return 1
            for dcent_entry in \
                "$dcent_seed_usrcon"/* \
                "$dcent_seed_usrcon"/.[!.]* \
                "$dcent_seed_usrcon"/..?*; do
                [ -e "$dcent_entry" ] || [ -L "$dcent_entry" ] || continue
                case "$dcent_entry" in
                    "$dcent_seed_usrcon/systemcfg.ini"|\
                    "$dcent_seed_usrcon/cgminer.ini") ;;
                    *) return 1 ;;
                esac
                [ -f "$dcent_entry" ] && [ ! -L "$dcent_entry" ] || return 1
            done
            rm -f "$dcent_seed_usrcon/systemcfg.ini" \
                "$dcent_seed_usrcon/cgminer.ini" || return 1
            rmdir "$dcent_seed_usrcon" || return 1
        fi
        rmdir "$dcent_seed" || return 1
    done
}

# The held Nano 3 btcminer cannot add keys to a missing/null iniparser
# dictionary. Its web handler nevertheless marks that dictionary dirty and
# later opens cgminer.ini with "w+", so the first UI save becomes a silent
# zero-byte truncation unless this section exists before btcminer starts.
dcent_write_empty_cgminer_config() {
    dcent_destination=$1

    [ ! -L "$dcent_destination" ] || return 1
    if [ -e "$dcent_destination" ]; then
        [ -f "$dcent_destination" ] || return 1
        [ ! -s "$dcent_destination" ] || return 0
    fi

    dcent_parent=${dcent_destination%/*}
    dcent_work="$(umask 077; mktemp -d \
        "$dcent_parent/.dcentos-config-init.XXXXXX" 2>/dev/null)" || return 1
    [ -d "$dcent_work" ] && [ ! -L "$dcent_work" ] || return 1
    dcent_temporary=$dcent_work/cgminer.ini

    (umask 077 && cat >"$dcent_temporary" <<'EOF'
[cgminercfg]
url0 =
user0 =
pass0 =
url1 =
user1 =
pass1 =
url2 =
user2 =
pass2 =
standard = --lowmem --real-quiet
EOF
    ) || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }
    chmod 0600 "$dcent_temporary" || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }

    dcent_publish_missing_or_zero "$dcent_temporary" "$dcent_destination" || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }
    rm -f "$dcent_temporary"
    rmdir "$dcent_work" || return 1
}

dcent_restore_zero_or_missing_file() {
    dcent_source=$1
    dcent_destination=$2

    [ -f "$dcent_source" ] && [ ! -L "$dcent_source" ] || return 1
    [ ! -L "$dcent_destination" ] || return 1
    if [ -e "$dcent_destination" ]; then
        [ -f "$dcent_destination" ] || return 1
        [ ! -s "$dcent_destination" ] || return 0
    fi

    dcent_parent=${dcent_destination%/*}
    dcent_work="$(umask 077; mktemp -d \
        "$dcent_parent/.dcentos-config-init.XXXXXX" 2>/dev/null)" || return 1
    [ -d "$dcent_work" ] && [ ! -L "$dcent_work" ] || return 1
    dcent_temporary=$dcent_work/systemcfg.ini

    (umask 077 && cat "$dcent_source" >"$dcent_temporary") || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }
    [ -s "$dcent_temporary" ] || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }
    chmod 0600 "$dcent_temporary" || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }

    dcent_publish_missing_or_zero "$dcent_temporary" "$dcent_destination" || {
        rm -f "$dcent_temporary"
        rmdir "$dcent_work" 2>/dev/null
        return 1
    }
    rm -f "$dcent_temporary"
    rmdir "$dcent_work" || return 1
}

# Publish a prepared regular file without following a destination symlink or
# overwriting a racing nonempty config. The caller's mode-0700 work directory
# makes the source immune to unprivileged substitution.
dcent_publish_missing_or_zero() {
    dcent_source=$1
    dcent_destination=$2

    [ -f "$dcent_source" ] && [ ! -L "$dcent_source" ] || return 1
    [ ! -L "$dcent_destination" ] || return 1
    if [ -e "$dcent_destination" ]; then
        [ -f "$dcent_destination" ] || return 1
        [ ! -s "$dcent_destination" ] || return 0
        rm -f "$dcent_destination" || return 1
    fi

    if ln "$dcent_source" "$dcent_destination" 2>/dev/null; then
        return 0
    fi
    # A racing nonempty regular file always wins. Anything else fails closed.
    [ -f "$dcent_destination" ] && [ ! -L "$dcent_destination" ] &&
        [ -s "$dcent_destination" ]
}

# Called synchronously by stock's post-mount, pre-btcminer permission hook.
# It repairs only absent/zero known configs and preserves every nonempty file.
dcent_prepare_stock_configs_for_launch() {
    dcent_data=$1
    dcent_systemcfg_fallback=$2
    dcent_data_usrcon=$dcent_data/usrcon

    dcent_prepare_stock_config_dir "$dcent_data" || return 1
    dcent_cleanup_stale_config_workdirs "$dcent_data" || return 1
    dcent_restore_zero_or_missing_file "$dcent_systemcfg_fallback" \
        "$dcent_data_usrcon/systemcfg.ini" || return 1
    dcent_write_empty_cgminer_config \
        "$dcent_data_usrcon/cgminer.ini" || return 1
}

dcent_stage_known_configs() {
    dcent_underlay=$1
    dcent_seed=$2
    dcent_seed_created=0
    dcent_underlay_usrcon=$dcent_underlay/usrcon

    [ ! -L "$dcent_underlay_usrcon" ] || return 1
    if [ ! -e "$dcent_underlay_usrcon" ]; then
        return 0
    fi
    [ -d "$dcent_underlay_usrcon" ] || return 1

    for dcent_relative in $DCENT_KNOWN_DATA_CONFIGS; do
        dcent_source=$dcent_underlay/$dcent_relative
        [ -f "$dcent_source" ] && [ ! -L "$dcent_source" ] || continue

        if [ "$dcent_seed_created" = 0 ]; then
            (umask 077 && mkdir "$dcent_seed") || return 1
            (umask 077 && mkdir "$dcent_seed/usrcon") || {
                rmdir "$dcent_seed" 2>/dev/null
                return 1
            }
            dcent_seed_created=1
        fi
        (umask 077 && cat "$dcent_source" >"$dcent_seed/$dcent_relative") ||
            return 1
        chmod 0600 "$dcent_seed/$dcent_relative" || return 1
    done
    return 0
}

dcent_restore_missing_configs() {
    dcent_seed=$1
    dcent_data=$2
    dcent_have_seed=0
    dcent_seed_usrcon=$dcent_seed/usrcon
    dcent_data_usrcon=$dcent_data/usrcon

    [ -d "$dcent_data" ] && [ ! -L "$dcent_data" ] || return 1
    [ ! -L "$dcent_seed_usrcon" ] || return 1
    [ -d "$dcent_seed_usrcon" ] || return 0
    for dcent_relative in $DCENT_KNOWN_DATA_CONFIGS; do
        dcent_source=$dcent_seed/$dcent_relative
        if [ -f "$dcent_source" ] && [ ! -L "$dcent_source" ]; then
            dcent_have_seed=1
            break
        fi
    done
    [ "$dcent_have_seed" = 1 ] || return 0

    dcent_prepare_stock_config_dir "$dcent_data" || return 1
    dcent_cleanup_stale_config_workdirs "$dcent_data" || return 1

    dcent_work="$(umask 077; mktemp -d \
        "$dcent_data_usrcon/.dcentos-config-migrate.XXXXXX" 2>/dev/null)" ||
        return 1
    [ -d "$dcent_work" ] && [ ! -L "$dcent_work" ] || return 1

    for dcent_relative in $DCENT_KNOWN_DATA_CONFIGS; do
        dcent_name=${dcent_relative##*/}
        dcent_source=$dcent_seed/$dcent_relative
        dcent_destination=$dcent_data/$dcent_relative
        [ -f "$dcent_source" ] && [ ! -L "$dcent_source" ] || continue

        if [ -e "$dcent_destination" ] || [ -L "$dcent_destination" ]; then
            echo "Nano 3 data migration preserved existing $dcent_name"
            continue
        fi

        dcent_temporary=$dcent_work/$dcent_name
        (umask 077 && cat "$dcent_source" >"$dcent_temporary") || {
            rm -f "$dcent_temporary"
            rmdir "$dcent_work" 2>/dev/null
            return 1
        }
        chmod 0600 "$dcent_temporary" || {
            rm -f "$dcent_temporary"
            rmdir "$dcent_work" 2>/dev/null
            return 1
        }

        # A hard link is the BusyBox-safe no-clobber primitive: it atomically
        # fails with EEXIST if stock creates the config after the check above.
        if ln "$dcent_temporary" "$dcent_destination" 2>/dev/null; then
            echo "Nano 3 data migration restored missing $dcent_name"
        elif [ -e "$dcent_destination" ] || [ -L "$dcent_destination" ]; then
            echo "Nano 3 data migration preserved racing $dcent_name"
        else
            rm -f "$dcent_temporary"
            rmdir "$dcent_work" 2>/dev/null
            return 1
        fi
        rm -f "$dcent_temporary"
    done

    rmdir "$dcent_work" || return 1
    return 0
}

dcent_remove_seed() {
    dcent_seed=$1
    for dcent_relative in $DCENT_KNOWN_DATA_CONFIGS; do
        rm -f "$dcent_seed/$dcent_relative"
    done
    rmdir "$dcent_seed/usrcon" 2>/dev/null || true
    rmdir "$dcent_seed" 2>/dev/null || true
}
