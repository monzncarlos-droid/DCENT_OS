#!/bin/sh
#
# Shared AM3 NAND/rootfs geometry constants.
#
# Host-side tools source this file so install, lab, and revert workflows agree
# on the same rootfs window. These values are evidence-scoped to the am3-aml
# S19K/S21 Amlogic layout; AM335x BB NAND remains unvalidated and must not use
# these constants.

DCENT_AM3_ROOTFS_MTD="${DCENT_AM3_ROOTFS_MTD:-/dev/mtd5}"
# Physical mtd5 = size-sum(mtd0-4) + 6MiB hole (system.sh / .78 dmesg).
# Locals = U-Boot global − 0x06700000 → rootfs 0x05100000, flag 0x04D00000.
DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1="${DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1:-0x600000}"
DCENT_AM3_ROOTFS_OFFSET_HEX="${DCENT_AM3_ROOTFS_OFFSET_HEX:-0x05100000}"
DCENT_AM3_ROOTFS_WINDOW_HEX="${DCENT_AM3_ROOTFS_WINDOW_HEX:-0x02800000}"
DCENT_AM3_ROOTFS_ERASE_COUNT="${DCENT_AM3_ROOTFS_ERASE_COUNT:-320}"
DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED="${DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED:-131072}"
DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX="${DCENT_AM3_RECOVERY_FLAG_OFFSET_HEX:-0x04D00000}"
# .78 U-Boot globals. Local = global − observed mtd5 base.
DCENT_AM3_NANDROOTFS_GLOBAL="${DCENT_AM3_NANDROOTFS_GLOBAL:-0x0B800000}"
DCENT_AM3_RECOVERY_FLAG_GLOBAL="${DCENT_AM3_RECOVERY_FLAG_GLOBAL:-0x0B400000}"
DCENT_AM3_NANDRECOVERY_ENV_GLOBAL="${DCENT_AM3_NANDRECOVERY_ENV_GLOBAL:-0x0B000000}"
DCENT_AM3_NANDRECOVERY_ENV_LEN="${DCENT_AM3_NANDRECOVERY_ENV_LEN:-0x10000}"
DCENT_AM3_RECOVERY_FLAG_STOCK_REVERT="${DCENT_AM3_RECOVERY_FLAG_STOCK_REVERT:-0x02}"

dcent_am3_geometry_init() {
    DCENT_AM3_ROOTFS_OFFSET_DEC=$((DCENT_AM3_ROOTFS_OFFSET_HEX))
    DCENT_AM3_ROOTFS_WINDOW_DEC=$((DCENT_AM3_ROOTFS_WINDOW_HEX))
    DCENT_AM3_ROOTFS_END_DEC=$((DCENT_AM3_ROOTFS_OFFSET_DEC + DCENT_AM3_ROOTFS_WINDOW_DEC))
}

# Admit only the exact six-row S19k .78 MTD tuple used by the rootfs/recovery
# offsets below.  A size sum is not identity: foreign names, erasesizes, row
# counts, or an mtd5 of another size must fail even if mtd0..4 add to the same
# base.  The caller supplies a regular proc_mtd-shaped file.
dcent_am3_require_exact_s19k_mtd_map_file() {
    _map_file=$1
    [ -n "$_map_file" ] && [ -r "$_map_file" ] || return 1
    _actual_map=$(awk '
        /^mtd[0-9]+:/ {
            name=$4
            gsub(/"/, "", name)
            print $1, $2, $3, name
        }
    ' "$_map_file")
    _expected_map='mtd0: 00200000 00020000 bootloader
mtd1: 00800000 00020000 tpl
mtd2: 03200000 00020000 stock_system
mtd3: 00500000 00020000 stock_config
mtd4: 02000000 00020000 overlay
mtd5: 09900000 00020000 system'
    [ "$_actual_map" = "$_expected_map" ] || {
        printf '%s\n' 'ERROR: S19k /proc/mtd does not match the exact six-part .78 map' >&2
        printf '%s\n' "$_actual_map" >&2
        return 1
    }
    return 0
}

# Physical mtd5 = sum(mtd0..mtd4 sizes) + 6MiB hole. Accepts newlines or '|'.
# Prints 0xHHHHHHHH on success. Matches rust mtd5_base_from_proc_mtd.
dcent_am3_mtd5_base_from_proc_mtd() {
    _src=$1
    [ -n "$_src" ] && [ -r "$_src" ] || return 1
    _sum=0
    _saw=0
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            ''|dev:*) continue ;;
        esac
        set -- $_line
        _dev=$1
        _size=$2
        [ -n "$_dev" ] && [ -n "$_size" ] || continue
        if [ "$_dev" = "mtd5:" ]; then
            _saw=1
            break
        fi
        case "$_dev" in
            mtd[0-4]:)
                _size_dec=$(printf '%d' "0x${_size#0x}")
                _sum=$((_sum + _size_dec))
                ;;
        esac
    done <<EOF
$(tr '|' '\n' < "$_src")
EOF
    [ "$_saw" -eq 1 ] && [ "$_sum" -gt 0 ] || return 1
    _hole=$((DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1))
    printf '0x%08X' $((_sum + _hole))
}

# Full mtd5 nanddump must cover U-Boot nandrecovery_env and the flag byte.
# Args: mtd5_len_decimal mtd5_base_hex (e.g. 160432128 0x06700000)
dcent_am3_mtd5_covers_recovery() {
    _len=$1
    _base_hex=$2
    [ -n "$_len" ] && [ -n "$_base_hex" ] || return 1
    _base=$((_base_hex))
    _flag_g=$((DCENT_AM3_RECOVERY_FLAG_GLOBAL))
    _env_g=$((DCENT_AM3_NANDRECOVERY_ENV_GLOBAL))
    _env_l=$((DCENT_AM3_NANDRECOVERY_ENV_LEN))
    [ "$_base" -gt 0 ] && [ "$_base" -le "$_flag_g" ] && [ "$_base" -le "$_env_g" ] || return 1
    _flag_local=$((_flag_g - _base))
    _env_local=$((_env_g - _base))
    [ "$_len" -gt "$_flag_local" ] || return 1
    [ "$_len" -ge $((_env_local + _env_l)) ] || return 1
    return 0
}

# Slice nandrecovery_env from a full mtd5 nanddump (host-side, no NAND write).
# Args: mtd5_file mtd5_base_hex out_file
# .78: base 0x06700000 → skip 0x04900000, count 0x10000 (4KiB aligned).
dcent_am3_extract_nandrecovery_env() {
    _in=$1
    _base_hex=$2
    _out=$3
    [ -n "$_in" ] && [ -n "$_base_hex" ] && [ -n "$_out" ] || return 1
    [ -f "$_in" ] || return 1
    _base=$((_base_hex))
    _env_g=$((DCENT_AM3_NANDRECOVERY_ENV_GLOBAL))
    _env_l=$((DCENT_AM3_NANDRECOVERY_ENV_LEN))
    [ "$_base" -gt 0 ] && [ "$_base" -le "$_env_g" ] || return 1
    _skip=$((_env_g - _base))
    [ $((_skip % 4096)) -eq 0 ] || return 1
    [ $((_env_l % 4096)) -eq 0 ] || return 1
    dd if="$_in" of="$_out" bs=4096 skip=$((_skip / 4096)) count=$((_env_l / 4096)) status=none || return 1
    return 0
}

# Slice the 128 KiB recovery-flag eraseblock from a full mtd5 nanddump.
# Args: mtd5_file mtd5_base_hex out_file
# .78: local 0x04D00000 is eraseblock-aligned (131072 * 616).
dcent_am3_extract_recovery_flag_eraseblock() {
    _in=$1
    _base_hex=$2
    _out=$3
    [ -n "$_in" ] && [ -n "$_base_hex" ] && [ -n "$_out" ] || return 1
    [ -f "$_in" ] || return 1
    _base=$((_base_hex))
    _flag_g=$((DCENT_AM3_RECOVERY_FLAG_GLOBAL))
    _es=$((DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED))
    [ "$_base" -gt 0 ] && [ "$_base" -le "$_flag_g" ] || return 1
    [ "$_es" -gt 0 ] || return 1
    _flag_local=$((_flag_g - _base))
    _eb_start=$(( (_flag_local / _es) * _es ))
    [ $((_eb_start % 4096)) -eq 0 ] || return 1
    [ $((_es % 4096)) -eq 0 ] || return 1
    dd if="$_in" of="$_out" bs=4096 skip=$((_eb_start / 4096)) count=$((_es / 4096)) status=none || return 1
    _out_len=$(wc -c < "$_out" | tr -d ' \t')
    [ "$_out_len" -eq "$_es" ] || return 1
    return 0
}

# Prove that the stock U-Boot one-byte recovery_set_flag implementation cannot
# destroy meaningful adjacent bytes. Held .78 recovery_set_flag erases one
# complete 0x20000 block and writes only byte 0, so installation is admissible
# only when the other 131071 bytes are already erased (0xFF).
# Args: recovery_flag_eraseblock_file
dcent_am3_admit_recovery_flag_eraseblock_exclusive() {
    _flag_eb=$1
    [ -n "$_flag_eb" ] && [ -f "$_flag_eb" ] && [ ! -L "$_flag_eb" ] || return 1
    _flag_eb_len=$(wc -c < "$_flag_eb" | tr -d ' \t')
    [ "$_flag_eb_len" -eq "$DCENT_AM3_ROOTFS_ERASESIZE_EXPECTED" ] || return 1
    _flag_eb_value=$(od -An -tx1 -N1 "$_flag_eb" | tr -d ' \t\r\n')
    case "$_flag_eb_value" in
        01|02|03) ;;
        *) return 1 ;;
    esac
    _flag_eb_tail_sha=$(dd if="$_flag_eb" bs=1 skip=1 2>/dev/null | sha256sum | awk '{print $1}')
    [ "$_flag_eb_tail_sha" = "7d6d0bf52ce759862d4f62e20d038e0fca09df26dfb34ce2067efa0dc53558f0" ] || return 1
    return 0
}

dcent_am3_geometry_init
