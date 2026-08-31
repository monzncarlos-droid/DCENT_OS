#!/bin/sh
# Stock calls this after mounting app/data and immediately before btcminer.
# Keep its original permissions policy, but first make configuration readiness
# synchronous so btcminer can never initialize a null iniparser dictionary.

ROOT_PATH=/
MIGRATION_LIB=/etc/dcentos/dcent-data-migrate.sh

dcent_block_stock_launch() {
    logger -t dcentos "Nano 3 stock launch blocked: $*"
    # rcS ignores this helper's exit status. Blocking is the only fail-closed
    # result that prevents it from continuing into btcminer with unsafe state.
    while :; do
        sleep 60
    done
}

readiness_dir=/run/dcentos-data-ready
attempts=0
while :; do
    if [ -d "$readiness_dir" ] && [ ! -L "$readiness_dir" ] &&
       grep -q '^/dev/ubi2_0 /data ubifs ' /proc/mounts 2>/dev/null &&
       [ -r /sys/class/ubi/ubi2/mtd_num ] &&
       [ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 ] &&
       [ -r /sys/class/ubi/ubi2_0/name ] &&
       [ "$(cat /sys/class/ubi/ubi2_0/name 2>/dev/null)" = ubi_data_part ]; then
        break
    fi
    attempts=$((attempts + 1))
    if [ $((attempts % 60)) -eq 0 ]; then
        logger -t dcentos 'Nano 3 stock launch waiting for data migration'
    fi
    sleep 1
done
grep -q '^/dev/ubi2_0 /data ubifs ' /proc/mounts 2>/dev/null ||
    dcent_block_stock_launch '/data mount source or type is invalid'
[ -r /sys/class/ubi/ubi2/mtd_num ] &&
    [ "$(cat /sys/class/ubi/ubi2/mtd_num 2>/dev/null)" = 12 ] ||
    dcent_block_stock_launch 'ubi2 is not attached to mtd12'
[ -r /sys/class/ubi/ubi2_0/name ] &&
    [ "$(cat /sys/class/ubi/ubi2_0/name 2>/dev/null)" = ubi_data_part ] ||
    dcent_block_stock_launch '/data is not ubi2_0:ubi_data_part'

[ -r "$MIGRATION_LIB" ] ||
    dcent_block_stock_launch 'configuration migration library is missing'
. "$MIGRATION_LIB" ||
    dcent_block_stock_launch 'configuration migration library could not load'
dcent_prepare_stock_config_dir /data ||
    dcent_block_stock_launch 'configuration directory preparation failed'
# Retain the worker's whole-path root lock through the only zero-file
# replacement window. Stock's original recursive chown below restores admin
# ownership, and its final chmod restores /data mode 0755.
chown root:root /data /data/usrcon ||
    dcent_block_stock_launch 'configuration path ownership lock failed'
chmod 0700 /data /data/usrcon ||
    dcent_block_stock_launch 'configuration path mode lock failed'
dcent_prepare_stock_configs_for_launch /data \
    /mnt/heater/confiles/usrcon/systemcfg_bak.ini ||
    dcent_block_stock_launch 'configuration bootstrap failed'
chmod 0755 /data/usrcon ||
    dcent_block_stock_launch 'configuration directory mode restore failed'
sync || dcent_block_stock_launch 'configuration sync failed'

# Original Canaan policy follows byte-for-byte in effect.
chown admin:admin ${ROOT_PATH}/home/admin
chown nano:nano ${ROOT_PATH}/home/nano
chown -R admin:admin ${ROOT_PATH}/mnt/heater
chown -R admin:admin ${ROOT_PATH}/data

chmod 755 ${ROOT_PATH}/home
chmod 754 ${ROOT_PATH}/home/admin
chmod 755 ${ROOT_PATH}/home/nano
chmod 750 ${ROOT_PATH}/mnt/heater
chmod 755 ${ROOT_PATH}/data
