#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
migration_lib=$project_dir/stock-runtime-overlay/etc/dcentos/dcent-data-migrate.sh

# shellcheck source=/dev/null
. "$migration_lib"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/dcent-data-fault-test.XXXXXX")
cleanup() {
    rm -rf "$test_root"
}
trap cleanup 0 1 2 15

seed=$test_root/seed
mkdir -p "$seed/usrcon"
printf '%s\n' '[systemcfg]' 'ssid = synthetic-recovery-network' \
    >"$seed/usrcon/systemcfg.ini"
printf '%s\n' '[cgminercfg]' 'url0 = synthetic-recovery-pool' \
    >"$seed/usrcon/cgminer.ini"
chmod 0600 "$seed/usrcon/systemcfg.ini" "$seed/usrcon/cgminer.ini"
fallback=$seed/usrcon/systemcfg.ini

# Pre-mount seed cleanup admits the exact narrow layout, including cuts after
# only the outer or usrcon directory was created. Complete staged copies are
# removed without examining or emitting their values.
seed_parent=$test_root/stale-seed-parent
mkdir -p "$seed_parent/dcentos-data-seed.100" \
    "$seed_parent/dcentos-data-seed.101/usrcon" \
    "$seed_parent/dcentos-data-seed.102/usrcon"
cp "$seed/usrcon/systemcfg.ini" \
    "$seed_parent/dcentos-data-seed.102/usrcon/systemcfg.ini"
cp "$seed/usrcon/cgminer.ini" \
    "$seed_parent/dcentos-data-seed.102/usrcon/cgminer.ini"
dcent_cleanup_stale_seed_dirs "$seed_parent"
[ -z "$(find "$seed_parent" -mindepth 1 -print)" ]

hostile_seed_parent=$test_root/hostile-seed-parent
mkdir -p "$hostile_seed_parent/dcentos-data-seed.200/usrcon"
printf '%s\n' 'unexpected-staged-content' \
    >"$hostile_seed_parent/dcentos-data-seed.200/unexpected"
if dcent_cleanup_stale_seed_dirs "$hostile_seed_parent"; then
    echo 'unexpected stale seed content was not refused' >&2
    exit 1
fi
grep -qx 'unexpected-staged-content' \
    "$hostile_seed_parent/dcentos-data-seed.200/unexpected"

indirect_seed_parent=$test_root/indirect-seed-parent
outside_seed=$test_root/outside-seed
mkdir "$indirect_seed_parent" "$outside_seed"
printf '%s\n' 'outside-seed-unchanged' >"$outside_seed/systemcfg.ini"
ln -s "$outside_seed" "$indirect_seed_parent/dcentos-data-seed.300"
if dcent_cleanup_stale_seed_dirs "$indirect_seed_parent"; then
    echo 'indirect stale seed directory was not refused' >&2
    exit 1
fi
grep -qx 'outside-seed-unchanged' "$outside_seed/systemcfg.ini"

assert_no_workdirs() {
    data=$1
    if find "$data/usrcon" -mindepth 1 -maxdepth 1 \
        \( -name '.dcentos-config-init.*' \
           -o -name '.dcentos-config-migrate.*' \) -print | grep -q .; then
        echo 'stale configuration work directory survived recovery' >&2
        exit 1
    fi
}

# Power loss before publication can leave only a private init directory and a
# partial temporary file. The next launch removes it, then reconstructs both
# canonical configs from admitted sources.
before_publish=$test_root/init-before-publish
mkdir -p "$before_publish/usrcon/.dcentos-config-init.ABCDEF"
printf '%s' 'partial' \
    >"$before_publish/usrcon/.dcentos-config-init.ABCDEF/systemcfg.ini"
dcent_prepare_stock_configs_for_launch "$before_publish" "$fallback"
cmp -s "$fallback" "$before_publish/usrcon/systemcfg.ini"
grep -qx '\[cgminercfg\]' "$before_publish/usrcon/cgminer.ini"
assert_no_workdirs "$before_publish"

# Power loss after atomic hard-link publication but before temp cleanup leaves
# two names for the same complete inode. Cleanup removes only the private name;
# the published nonempty config remains byte-exact.
after_publish=$test_root/init-after-publish
work=$after_publish/usrcon/.dcentos-config-init.BCDEFG
mkdir -p "$work"
printf '%s\n' '[cgminercfg]' 'url0 = synthetic-published-before-cut' \
    >"$work/cgminer.ini"
chmod 0600 "$work/cgminer.ini"
ln "$work/cgminer.ini" "$after_publish/usrcon/cgminer.ini"
published_hash=$(sha256sum "$after_publish/usrcon/cgminer.ini" | awk '{print $1}')
dcent_prepare_stock_configs_for_launch "$after_publish" "$fallback"
[ "$(sha256sum "$after_publish/usrcon/cgminer.ini" | awk '{print $1}')" = \
    "$published_hash" ]
cmp -s "$fallback" "$after_publish/usrcon/systemcfg.ini"
assert_no_workdirs "$after_publish"

# An interrupted pre-mount migration with no published destination is
# discarded. The next pass restores the seed, not the abandoned partial bytes.
migrate_before=$test_root/migrate-before-publish
work=$migrate_before/usrcon/.dcentos-config-migrate.CDEFGH
mkdir -p "$work"
printf '%s' 'partial' >"$work/systemcfg.ini"
dcent_restore_missing_configs "$seed" "$migrate_before"
cmp -s "$seed/usrcon/systemcfg.ini" "$migrate_before/usrcon/systemcfg.ini"
cmp -s "$seed/usrcon/cgminer.ini" "$migrate_before/usrcon/cgminer.ini"
assert_no_workdirs "$migrate_before"

# If one migration file was published before the cut, it wins as an existing
# nonempty config while the other missing file is restored on the next pass.
migrate_after=$test_root/migrate-after-one-publish
work=$migrate_after/usrcon/.dcentos-config-migrate.DEFGHI
mkdir -p "$work"
cp "$seed/usrcon/systemcfg.ini" "$work/systemcfg.ini"
printf '%s' 'partial' >"$work/cgminer.ini"
ln "$work/systemcfg.ini" "$migrate_after/usrcon/systemcfg.ini"
dcent_restore_missing_configs "$seed" "$migrate_after"
cmp -s "$seed/usrcon/systemcfg.ini" "$migrate_after/usrcon/systemcfg.ini"
cmp -s "$seed/usrcon/cgminer.ini" "$migrate_after/usrcon/cgminer.ini"
assert_no_workdirs "$migrate_after"

# Recovery is idempotent and never replaces later user-owned nonempty bytes.
printf '%s\n' 'user-owned-after-recovery' \
    >"$migrate_after/usrcon/cgminer.ini"
dcent_restore_missing_configs "$seed" "$migrate_after"
dcent_prepare_stock_configs_for_launch "$migrate_after" "$fallback"
grep -qx 'user-owned-after-recovery' "$migrate_after/usrcon/cgminer.ini"
assert_no_workdirs "$migrate_after"

# A prefix match is not deletion authority. Unexpected content or an indirect
# work directory refuses recovery without changing either canonical config.
hostile=$test_root/hostile-stale-dir
mkdir -p "$hostile/usrcon/.dcentos-config-init.EFGHIJ"
printf '%s\n' 'user-system-unchanged' >"$hostile/usrcon/systemcfg.ini"
printf '%s\n' 'user-miner-unchanged' >"$hostile/usrcon/cgminer.ini"
printf '%s\n' 'not-owned-scratch' \
    >"$hostile/usrcon/.dcentos-config-init.EFGHIJ/unexpected"
if dcent_prepare_stock_configs_for_launch "$hostile" "$fallback"; then
    echo 'unexpected stale work content was not refused' >&2
    exit 1
fi
grep -qx 'user-system-unchanged' "$hostile/usrcon/systemcfg.ini"
grep -qx 'user-miner-unchanged' "$hostile/usrcon/cgminer.ini"
grep -qx 'not-owned-scratch' \
    "$hostile/usrcon/.dcentos-config-init.EFGHIJ/unexpected"

indirect=$test_root/indirect-stale-dir
outside=$test_root/outside-stale-dir
mkdir -p "$indirect/usrcon" "$outside"
printf '%s\n' 'outside-unchanged' >"$outside/cgminer.ini"
ln -s "$outside" "$indirect/usrcon/.dcentos-config-migrate.FGHIJK"
if dcent_restore_missing_configs "$seed" "$indirect"; then
    echo 'indirect stale work directory was not refused' >&2
    exit 1
fi
grep -qx 'outside-unchanged' "$outside/cgminer.ini"
[ ! -e "$indirect/usrcon/systemcfg.ini" ]
[ ! -e "$indirect/usrcon/cgminer.ini" ]

echo 'Nano 3 interrupted data initialization recovery tests: PASS'
