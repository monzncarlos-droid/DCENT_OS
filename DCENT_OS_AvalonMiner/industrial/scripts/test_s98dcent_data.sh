#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
migration_lib=$project_dir/stock-runtime-overlay/etc/dcentos/dcent-data-migrate.sh
init_script=$project_dir/stock-runtime-overlay/etc/init.d/S98dcent-data
launch_hook=$project_dir/stock-runtime-overlay/etc/user_permission_chg.sh

# shellcheck source=/dev/null
. "$migration_lib"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-data-test.XXXXXX")
cleanup() {
    rm -rf "$test_root"
}
trap cleanup 0 1 2 15

underlay=$test_root/underlay
seed=$test_root/seed
persistent=$test_root/persistent
mkdir "$underlay" "$persistent" "$underlay/usrcon" "$persistent/usrcon"

printf '%s\n' 'wifi=underlay-secret' >"$underlay/usrcon/systemcfg.ini"
printf '%s\n' 'pool=underlay-pool' >"$underlay/usrcon/cgminer.ini"
printf '%s\n' 'must-not-migrate' >"$underlay/unrelated.ini"
printf '%s\n' 'must-not-migrate' >"$underlay/usrcon/unrelated.ini"
printf '%s\n' 'pool=persistent-credential' >"$persistent/usrcon/cgminer.ini"

dcent_stage_known_configs "$underlay" "$seed"
[ -f "$seed/usrcon/systemcfg.ini" ]
[ -f "$seed/usrcon/cgminer.ini" ]
[ ! -e "$seed/unrelated.ini" ]
[ ! -e "$seed/usrcon/unrelated.ini" ]

# A factory-empty data volume has no staged files.  Its stock save directory
# must still exist before btcminer starts so direct fopen("w+") saves work.
empty_data=$test_root/empty-data
mkdir "$empty_data"
dcent_prepare_stock_config_dir "$empty_data"
[ -d "$empty_data/usrcon" ]
[ ! -L "$empty_data/usrcon" ]
[ "$(stat -c '%a' "$empty_data/usrcon")" = 755 ]
printf '%s\n' 'pool=stock-direct-save' >"$empty_data/usrcon/cgminer.ini"
grep -qx 'pool=stock-direct-save' "$empty_data/usrcon/cgminer.ini"
dcent_prepare_stock_config_dir "$empty_data"
grep -qx 'pool=stock-direct-save' "$empty_data/usrcon/cgminer.ini"

# The pre-btcminer barrier must create valid no-secret dictionaries for absent
# or zero files, while every nonempty user configuration remains byte-exact.
launch_data=$test_root/launch-data
mkdir "$launch_data"
dcent_prepare_stock_configs_for_launch "$launch_data" \
    "$underlay/usrcon/systemcfg.ini"
grep -qx '\[cgminercfg\]' "$launch_data/usrcon/cgminer.ini"
grep -qx 'standard = --lowmem --real-quiet' \
    "$launch_data/usrcon/cgminer.ini"
[ -s "$launch_data/usrcon/systemcfg.ini" ]
printf '%s\n' 'pool=user-owned' >"$launch_data/usrcon/cgminer.ini"
printf '%s\n' 'wifi=user-owned' >"$launch_data/usrcon/systemcfg.ini"
dcent_prepare_stock_configs_for_launch "$launch_data" \
    "$underlay/usrcon/systemcfg.ini"
grep -qx 'pool=user-owned' "$launch_data/usrcon/cgminer.ini"
grep -qx 'wifi=user-owned' "$launch_data/usrcon/systemcfg.ini"
[ -z "$(find "$launch_data/usrcon" -maxdepth 1 \
    -name '.dcentos-config-init.*' -print)" ]
: >"$launch_data/usrcon/cgminer.ini"
: >"$launch_data/usrcon/systemcfg.ini"
dcent_prepare_stock_configs_for_launch "$launch_data" \
    "$underlay/usrcon/systemcfg.ini"
grep -qx '\[cgminercfg\]' "$launch_data/usrcon/cgminer.ini"
grep -qx 'wifi=underlay-secret' "$launch_data/usrcon/systemcfg.ini"

dcent_restore_missing_configs "$seed" "$persistent"
grep -qx 'wifi=underlay-secret' "$persistent/usrcon/systemcfg.ini"
grep -qx 'pool=persistent-credential' "$persistent/usrcon/cgminer.ini"
[ ! -e "$persistent/unrelated.ini" ]
[ ! -e "$persistent/usrcon/unrelated.ini" ]
[ -z "$(find "$persistent/usrcon" -maxdepth 1 -name '.dcentos-config-migrate.*' -print)" ]

# A second pass is idempotent and cannot replace credentials/configuration.
printf '%s\n' 'wifi=persistent-newer' >"$persistent/usrcon/systemcfg.ini"
dcent_restore_missing_configs "$seed" "$persistent"
grep -qx 'wifi=persistent-newer' "$persistent/usrcon/systemcfg.ini"
grep -qx 'pool=persistent-credential' "$persistent/usrcon/cgminer.ini"

# A broken or valid symlink is an existing destination and must not be followed.
symlink_data=$test_root/symlink-data
mkdir "$symlink_data" "$symlink_data/usrcon"
printf '%s\n' 'outside=unchanged' >"$test_root/outside.ini"
ln -s "$test_root/outside.ini" "$symlink_data/usrcon/systemcfg.ini"
dcent_restore_missing_configs "$seed" "$symlink_data"
[ -L "$symlink_data/usrcon/systemcfg.ini" ]
grep -qx 'outside=unchanged' "$test_root/outside.ini"

# A missing usrcon directory is created, but a symlink/non-directory parent is
# refused before any known config can be copied through it.
missing_parent_data=$test_root/missing-parent-data
mkdir "$missing_parent_data"
dcent_restore_missing_configs "$seed" "$missing_parent_data"
[ -d "$missing_parent_data/usrcon" ]
grep -qx 'wifi=underlay-secret' "$missing_parent_data/usrcon/systemcfg.ini"
grep -qx 'pool=underlay-pool' "$missing_parent_data/usrcon/cgminer.ini"

symlink_parent_data=$test_root/symlink-parent-data
outside_dir=$test_root/outside-dir
mkdir "$symlink_parent_data" "$outside_dir"
ln -s "$outside_dir" "$symlink_parent_data/usrcon"
if dcent_restore_missing_configs "$seed" "$symlink_parent_data"; then
    echo 'usrcon symlink parent was not refused' >&2
    exit 1
fi
[ -z "$(find "$outside_dir" -mindepth 1 -print)" ]

nondir_parent_data=$test_root/nondir-parent-data
mkdir "$nondir_parent_data"
printf '%s\n' 'not-a-directory' >"$nondir_parent_data/usrcon"
if dcent_restore_missing_configs "$seed" "$nondir_parent_data"; then
    echo 'usrcon non-directory parent was not refused' >&2
    exit 1
fi
grep -qx 'not-a-directory' "$nondir_parent_data/usrcon"

# Pin the production safety boundary: create is allowed only for a proven-empty
# UBI, but formatting, volume deletion/resizing and generic underlay copies are not.
grep -q 'ubimkvol /dev/ubi2 -N ubi_data_part -m' "$init_script"
! grep -Eq 'ubiformat|ubirmvol|ubirsvol' "$init_script"
! grep -Eq 'cp -a /data|cp -R /data|cp -r /data' "$init_script"
grep -q 'dcent_stage_known_configs /data' "$init_script"
grep -q 'dcent_prepare_stock_config_dir /data' "$init_script"
grep -q 'dcent_restore_missing_configs.* /data' "$init_script"
grep -q 'usrcon/systemcfg.ini usrcon/cgminer.ini' "$migration_lib"
grep -q 'dcent_prepare_stock_configs_for_launch /data' "$launch_hook"
grep -q 'dcent_block_stock_launch' "$launch_hook"
! grep -q 'dcent_prepare_stock_configs_for_launch.*&' "$launch_hook"
grep -q "grep -q '\^/dev/ubi2_0 /data ubifs ' /proc/mounts" "$launch_hook"
grep -q '\[ -d "$readiness_dir" \]' "$launch_hook"
grep -q 'mkdir -m 0700 "$readiness_dir"' "$init_script"
grep -q "grep -q '\^/dev/ubi2_0 /data ubifs ' /proc/mounts" "$init_script"
grep -q "sync || log_refusal 'persistent data sync failed'" "$init_script"
grep -q "sync || dcent_block_stock_launch 'configuration sync failed'" \
    "$launch_hook"
! grep -q 'mountpoint -q /data 2>/dev/null && exit 0' "$init_script"
! grep -q 'mv -f.*dcent_destination' "$migration_lib"
grep -q 'ln "$dcent_source" "$dcent_destination"' "$migration_lib"
grep -q 'mktemp -d' "$migration_lib"
grep -q '\.dcentos-config-init\.XXXXXX' "$migration_lib"
grep -q '\.dcentos-config-migrate\.XXXXXX' "$migration_lib"
grep -q 'dcent_cleanup_stale_config_workdirs' "$migration_lib"
grep -q 'dcent_cleanup_stale_seed_dirs' "$migration_lib"
grep -q '"$dcent_data_usrcon"/.dcentos-config-init.\*' "$migration_lib"
grep -q '"$dcent_data_usrcon"/.dcentos-config-migrate.\*' "$migration_lib"
grep -q '"$dcent_seed_parent"/dcentos-data-seed.\*' "$migration_lib"
! grep -q '\.dcentos-config-migrate\.\$\$' "$migration_lib"
grep -q 'init_lock=/run/dcentos-data-init-lock' "$init_script"
grep -q 'mkdir -m 0700 "$init_lock"' "$init_script"
grep -q 'dcent_cleanup_stale_seed_dirs /tmp' "$init_script"
grep -q 'cleanup_init_lock.*could not release data initialization lock' \
    "$init_script"
! grep -Eq 'rm -rf .*(dcentos-data-seed|dcentos-config)' \
    "$init_script" "$migration_lib"
grep -q '\[ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 \]' \
    "$init_script"
grep -q '\[ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 \]' \
    "$launch_hook"
grep -q 'chown root:root /data /data/usrcon' "$launch_hook"
grep -q 'chmod 0700 /data /data/usrcon' "$launch_hook"
grep -q 'chmod 0755 /data/usrcon' "$launch_hook"
grep -q '8|9)' "$init_script"
grep -Fq '[ "$(cat /sys/class/ubi/ubi2_0/name 2>/dev/null)" = ubi_data_part ] &&' \
    "$init_script"
grep -q 'chown root:root /data' "$init_script"
grep -q 'chmod 0700 /data' "$init_script"
lock_line=$(grep -n 'chown root:root /data' "$init_script" | head -n 1 | cut -d: -f1)
restore_line=$(grep -n 'dcent_restore_missing_configs' "$init_script" | tail -n 1 | cut -d: -f1)
[ "$lock_line" -lt "$restore_line" ]

echo 'S98dcent-data host migration tests: PASS'
