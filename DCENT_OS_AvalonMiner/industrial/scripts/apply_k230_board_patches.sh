#!/usr/bin/env bash
# Apply the per-model board deltas to the public k230_linux_sdk checkout.
#
# The public SDK's EVB SPI-NAND boot map (k230_board_common.h) is
#   uboot@0x80000  rtt@0x200000  linux@0xA00000
# and its k230_evb_nand_defconfig keeps a single env at 0x1e0000. The
# stock Avalon maps (held firmware-archive evidence) are:
#
#   Nano 3S (USB_UP.AUP build 2026-04-02):
#     uboot@0x100000 (+0x300000)  env@0x500000 (+0x580000, single-copy
#     read)  rtt@0x600000  linux@0xA00000  rootfs@0x1200000  app@0x4200000
#
#   Nano 3 (heater_nano3_master_image.img):
#     uboot@0x100000/0x200000 (1 MiB pair)  env@0x300000/0x380000
#     (REDUNDANT pair - CRC-valid env_t blobs, flags=1, ENV_SIZE 0x10000)
#     linux@0x400000/0xC00000  rootfs@0x1400000/0x2C00000  app@0x4400000/
#     0x5400000 - NO rtt partition
#
# Model switching is enforced-state: every sed sets the model's exact
# value regardless of what the tree currently carries, so nano3s ->
# nano3 -> nano3s round-trips cleanly. Re-running for the same model is
# a no-op. The tree stays dirty in the vendor clone's git status - that
# is the audit trail.
#
# After patching (switch models or first patch):  make <CONF>          (re-
# stage .config)   make CONF=<CONF> uboot-dirclean   make CONF=<CONF>
# (uboot rebuild only; linux/rootfs state is reused)

set -euo pipefail

MODEL="${1:-nano3s}"
SDK_DIR="${SDK_DIR:-/sdk}"
BOARD_H="$SDK_DIR/buildroot-overlay/boot/uboot/u-boot-2022.10-overlay/board/canaan/common/k230_board_common.h"
EVBNAND_CFG="$SDK_DIR/buildroot-overlay/boot/uboot/u-boot-2022.10-overlay/configs/k230_evb_nand_defconfig"

[ -f "$BOARD_H" ] || { echo "patches: missing $BOARD_H" >&2; exit 1; }
[ -f "$EVBNAND_CFG" ] || { echo "patches: missing $EVBNAND_CFG" >&2; exit 1; }

case "$MODEL" in
    nano3s)
        UBOOT_OFF=0x100000
        RTT_OFF=0x00600000
        LINUX_OFF=0x00a00000
        ENV_OFF=0x500000
        ROOTFS_MTD=rootfs
        ;;
    nano3)
        UBOOT_OFF=0x100000
        # No rtt partition on this model: k230_boot spinand rtt is never
        # reachable from the DCENT env, so the macro is left untouched.
        RTT_OFF=""
        LINUX_OFF=0x00400000
        ENV_OFF=0x300000
        ROOTFS_MTD=rootfs_ubi_a
        ;;
    *)
        echo "patches: unknown model '$MODEL' (nano3s|nano3)" >&2
        exit 1
        ;;
esac

# 1. boot-map offsets (k230_img.c reads these macros). Enforce the exact
#    value so the script also switches models, not just first-patches.
enforce_define() {
    local name="$1" value="$2" file="$3"
    if grep -q "#define $name $value" "$file"; then
        return 0
    fi
    sed -i "s/#define $name 0x[0-9a-fA-F][0-9a-fA-F]*/#define $name $value/" "$file"
    grep -q "#define $name $value" "$file" || {
        echo "patches: could not set $name=$value in $file" >&2; exit 1;
    }
    echo "patches: $name -> $value"
}
enforce_define UBOOT_SYS_IN_SPI_NAND_OFF "$UBOOT_OFF" "$BOARD_H"
enforce_define LINUX_SYS_IN_SPI_NAND_OFF "$LINUX_OFF" "$BOARD_H"
if [ -n "$RTT_OFF" ]; then
    enforce_define RTT_SYS_IN_SPI_NAND_OFF "$RTT_OFF" "$BOARD_H"
fi

# 2. U-Boot environment location. The nano3 stock uboot runs a REDUNDANT
#    env pair (0x300000/0x380000, flags byte present); the nano3s DCENT
#    build reads a single copy at 0x500000 (as shipped 2026-08-15).
sed -i "s/^CONFIG_ENV_OFFSET=.*/CONFIG_ENV_OFFSET=$ENV_OFF/" "$EVBNAND_CFG"
echo "patches: CONFIG_ENV_OFFSET -> $ENV_OFF"
if [ "$MODEL" = nano3 ]; then
    ensure_cfg() {
        local line="$1"
        grep -q "^$line" "$EVBNAND_CFG" || \
            sed -i "/^CONFIG_ENV_OFFSET=/a $line" "$EVBNAND_CFG"
    }
    # env/spinand.c #errors without SAVEENV+MTD when REDUND is set;
    # SYS_REDUNDAND_ENVIRONMENT puts the flags byte in env_t.
    ensure_cfg "CONFIG_ENV_OFFSET_REDUND=0x380000"
    ensure_cfg "CONFIG_SYS_REDUNDAND_ENVIRONMENT=y"
    ensure_cfg "CONFIG_CMD_SAVEENV=y"
    echo "patches: redundant env pair 0x300000/0x380000 enabled"
else
    sed -i \
        -e '/^CONFIG_ENV_OFFSET_REDUND=/d' \
        -e '/^CONFIG_SYS_REDUNDAND_ENVIRONMENT=/d' \
        -e '/^CONFIG_CMD_SAVEENV=/d' \
        "$EVBNAND_CFG"
fi

# 3. Bootargs address rootfs by the exact model DT label. Nano 3 retains the
#    factory partition order and label so factory U-Boot's mtd8/mtd9 slot
#    logic and custom U-Boot agree on the same physical rootfs-A partition.
IMG_C="$SDK_DIR/buildroot-overlay/boot/uboot/u-boot-2022.10-overlay/board/canaan/common/k230_img.c"
if [ -f "$IMG_C" ]; then
    sed -i -E \
        "s#ubi.mtd=[^ ]+ rootfstype=ubifs rw root=[^ \";]+#ubi.mtd=$ROOTFS_MTD rootfstype=ubifs rw root=ubi0:rootfs#g" \
        "$IMG_C"
    grep -q "ubi.mtd=$ROOTFS_MTD rootfstype=ubifs rw root=ubi0:rootfs" "$IMG_C" || {
        echo "patches: could not set rootfs bootargs in $IMG_C" >&2
        exit 1
    }
    echo "patches: k230_img.c rootfs bootargs -> ubi.mtd=$ROOTFS_MTD"
fi

# 4. DDR init: both home models are K230D SiPs (integrated 128 MiB LPDDR4).
#    The public k230_evb_nand defconfig selects LPDDR3_2133 — the EVB's
#    DISCRETE DDR (512 MiB, wrong type/timings) — and U-Boot hangs in DDR
#    init on the miner (live bench 2026-08-21: three silent first-light
#    boots). Select the SiP LPDDR4 2667 init (the k230d_canmv default);
#    DDR_SIZE then defaults to 0x08000000 via arch/riscv/cpu/k230/Kconfig.
UBOOT_OVERLAY="$SDK_DIR/buildroot-overlay/boot/uboot/u-boot-2022.10-overlay"
EVB_KCONFIG="$UBOOT_OVERLAY/board/canaan/k230_evb/Kconfig"
if [ -f "$EVB_KCONFIG" ]; then
    if ! grep -q '^config SIPLP4_2667' "$EVB_KCONFIG"; then
        sed -i 's/^\tdefault LPDDR3_800/\tdefault SIPLP4_2667/' "$EVB_KCONFIG"
        sed -i '/^endchoice/i\
config SIPLP4_2667\
\tbool "k230d sip lpddr4 2667"\
' "$EVB_KCONFIG"
        echo "patches: k230_evb/Kconfig DDR choice gains SIPLP4_2667 (default)"
    fi
    # The choice is set explicitly by the defconfig - flip it there too.
    sed -i -e 's/^CONFIG_LPDDR3_[0-9]*=y/CONFIG_SIPLP4_2667=y/' \
           -e '/^CONFIG_LPDDR3_[0-9]*=y/d' "$EVBNAND_CFG"
    grep -q '^CONFIG_SIPLP4_2667=y' "$EVBNAND_CFG" || \
        sed -i '0,/^CONFIG_LPDDR3_800\|^CONFIG_SYS_LOAD_ADDR/s//CONFIG_SIPLP4_2667=y\n&/' "$EVBNAND_CFG"
    grep -q '^CONFIG_SIPLP4_2667=y' "$EVBNAND_CFG" || {
        echo "patches: could not set CONFIG_SIPLP4_2667 in $EVBNAND_CFG" >&2; exit 1;
    }
    echo "patches: k230_evb_nand_defconfig DDR -> SIPLP4_2667 (K230D SiP LPDDR4)"
else
    echo "patches: WARN $EVB_KCONFIG missing - DDR init NOT switched" >&2
fi

echo "patches: $MODEL board deltas applied (or already present)."
