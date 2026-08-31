#!/usr/bin/env bash
# DCENT K230 SDK build driver — runs INSIDE the dcent/k230-sdk container.
#
# Host-side invocation (Git Bash, repo root):
#   bash DCENT_OS_AvalonMiner/scripts/run_k230_docker.sh \
#       bash /dcent/scripts/build_k230_in_docker.sh
#
# What it does:
#   1. stages the DCENT defconfig + kernel fragment + board patches (+ the
#      cross-built dcentrald binary + init script, when present) into the
#      SDK checkout's buildroot overlay
#   2. syncs the SDK checkout into the /work volume (a real Linux fs —
#      Windows bind mounts break buildroot's cpio extraction timestamps)
#      while preserving /work/output and /work/dl across runs
#   3. installs the Xuantie toolchain into /opt/toolchain on first use
#   4. runs the full SDK build (buildroot 2025.02.1: uboot 2022.10
#      k230_evb_nand + linux 6.6 xuantie + opensbi 1.4 + lean rootfs)
#
# Outputs land in /work/output/k230_dcent_defconfig/images/ :
#   uboot/swap_fn_u-boot-spl.bin  BROM SPL, K230 container (endian-swapped)
#   uboot/fn_ug_u-boot.bin        proper U-Boot (k230-gzip+mkimage+container)
#   uboot/env.env                 64 KiB default environment blob
#   fw_payload.bin, *.dtb         opensbi+linux payload, device trees
#   boot.ext4 / sysimage-*        vendor SD-card artifacts (not our target)
#   rootfs.tar                    DCENT rootfs — ubinize'd for NAND at assembly

set -euo pipefail

SDK_DIR="${SDK_DIR:-/sdk}"
DCENT_DIR="${DCENT_DIR:-/dcent}"
WORK_DIR="${WORK_DIR:-/work}"
CONF="${CONF:-k230_dcent_defconfig}"
# nano3s | nano3 — which board's boot map the patched U-Boot carries
# (env location + linux read offset; see apply_k230_board_patches.sh).
MODEL="${MODEL:-nano3s}"

[ -f "$SDK_DIR/Makefile" ] || {
    echo "build: $SDK_DIR does not look like the k230_linux_sdk checkout" >&2
    exit 1
}

# ---- 1. stage DCENT files into the vendor overlay (idempotent)
cp "$DCENT_DIR/buildroot/$CONF" "$SDK_DIR/buildroot-overlay/configs/$CONF"
cp "$DCENT_DIR/buildroot/fragment/linux.dcent.fragment" \
   "$SDK_DIR/buildroot-overlay/board/canaan/k230-soc/fragment/linux.dcent.fragment"
cp "$DCENT_DIR"/patches/*.patch "$SDK_DIR/buildroot-overlay/linux/"
bash "$DCENT_DIR/scripts/apply_k230_board_patches.sh" "$MODEL"

OVERLAY="$SDK_DIR/buildroot-overlay/board/canaan/k230-soc/rootfs_overlay"
mkdir -p "$OVERLAY/usr/bin" "$OVERLAY/etc/init.d" "$OVERLAY/etc/default"
rm -f "$OVERLAY/etc/init.d/S41adb_mtp" \
      "$OVERLAY/etc/init.d/S50telnet" \
      "$OVERLAY/etc/init.d/S97dcentgadget"
cp "$DCENT_DIR/buildroot/rootfs-overlay/etc/init.d/S98dcentrald" \
   "$OVERLAY/etc/init.d/S98dcentrald"
chmod +x "$OVERLAY/etc/init.d/S98dcentrald"
cp "$DCENT_DIR/buildroot/rootfs-overlay/etc/init.d/S10dcentgadget" \
   "$OVERLAY/etc/init.d/S10dcentgadget"
chmod +x "$OVERLAY/etc/init.d/S10dcentgadget"
cp "$DCENT_DIR/buildroot/rootfs-overlay/etc/default/dropbear" \
   "$OVERLAY/etc/default/dropbear"
DCENTD="$DCENT_DIR/dcentrald/target/riscv64gc-unknown-linux-musl/release/dcentrald-avalon"
if [ -f "$DCENTD" ]; then
    install -m 0755 "$DCENTD" "$OVERLAY/usr/bin/dcentrald"
    echo "build: staged dcentrald ($(stat -c%s "$DCENTD") bytes) into the rootfs overlay"
else
    echo "build: no dcentrald binary at $DCENTD — building without the daemon"
fi

# ---- 2. sync the checkout into the /work volume (keeps output/ and dl/)
if [ ! -f "$WORK_DIR/Makefile" ]; then
    echo "build: initial sync $SDK_DIR -> $WORK_DIR"
    rsync -a "$SDK_DIR"/ "$WORK_DIR"/ --exclude output --exclude dl
else
    # fast path: only source + overlay files can change
    rsync -a "$SDK_DIR"/ "$WORK_DIR"/ \
        --exclude output --exclude dl \
        --exclude .git
fi
mkdir -p "$WORK_DIR/output" "$WORK_DIR/dl"
# The SDK-to-work rsync also intentionally omits --delete.  Keep removed
# services removed in this second persistent overlay copy as well.
WORK_OVERLAY_INIT="$WORK_DIR/buildroot-overlay/board/canaan/k230-soc/rootfs_overlay/etc/init.d"
rm -f "$WORK_OVERLAY_INIT/S41adb_mtp" \
      "$WORK_OVERLAY_INIT/S50telnet" \
      "$WORK_OVERLAY_INIT/S97dcentgadget"

# ---- 3. toolchain (cached across builds via the /opt/toolchain bind mount)
TOOLCHAIN_ROOT="/opt/toolchain/Xuantie-900-gcc-linux-6.6.0-glibc-x86_64-V3.0.2"
if [ ! -x "$TOOLCHAIN_ROOT/bin/riscv64-unknown-linux-gnu-gcc" ]; then
    echo "build: installing Xuantie toolchain into /opt/toolchain ..."
    mkdir -p /opt/toolchain
    cd /opt/toolchain
    GCC_FILE=Xuantie-900-gcc-linux-6.6.0-glibc-x86_64-V3.0.2-20250410
    if curl --output /dev/null --silent --head --fail \
            https://ai.b-bug.org/k230/downloads/dl/gcc; then
        DOWN_URI="https://ai.b-bug.org/k230/downloads/dl/gcc"
    else
        DOWN_URI="https://download.kendryte.com/k230/downloads/dl/gcc"
    fi
    wget --progress=dot:giga "$DOWN_URI/$GCC_FILE.tar.gz" -O "$GCC_FILE.tar.gz"
    echo "8cefc7e94f760eaecc3620ffb238bf4a  $GCC_FILE.tar.gz" | md5sum -c -
    tar -xf "$GCC_FILE.tar.gz" -C /opt/toolchain
    rm -f "$GCC_FILE.tar.gz"
    cd "$WORK_DIR"
fi

# ---- 4. full build
cd "$WORK_DIR"
# Re-stage .config from the (possibly updated) defconfig: the goal form
# `make <CONF>` re-runs the SDK sync + buildroot defconfig against the
# existing output dir, so a defconfig edit (e.g. the DTS list) reaches
# the build without wiping linux/rootfs build state.
make "$CONF"
# `make <CONF>` performs a third non-deleting sync into Buildroot's versioned
# source copy. Purge the removed services there before Buildroot copies its
# rootfs overlay into the target tree.
for SYNCED_INIT in \
    "$WORK_DIR"/output/buildroot-*/board/canaan/k230-soc/rootfs_overlay/etc/init.d; do
    [ -d "$SYNCED_INIT" ] || continue
    rm -f "$SYNCED_INIT/S41adb_mtp" \
          "$SYNCED_INIT/S50telnet" \
          "$SYNCED_INIT/S97dcentgadget"
done
# Model switches change the uboot source overlay: force a uboot rebuild.
# opensbi embeds the kernel payload — dirclean it when linux relinks.
# A NEW kernel patch only applies at extract time, so K230_FORCE_LINUX=1
# (full kernel rebuild) is needed after adding one to patches/.
if [ "${K230_FORCE_UBOOT:-1}" = 1 ]; then
    make "CONF=$CONF" uboot-dirclean || make -C "output/$CONF" uboot-dirclean
    make "CONF=$CONF" opensbi-dirclean || true
fi
if [ "${K230_FORCE_LINUX:-0}" = 1 ]; then
    make "CONF=$CONF" linux-dirclean || make -C "output/$CONF" linux-dirclean
fi
# Buildroot copies overlays with rsync -a and does not delete files that were
# removed or renamed in the overlay.  Purge the known conflicting first-light
# services from the persistent target tree before finalization so a clean
# source overlay cannot still package an old ADB/telnet/gadget owner.
TARGET_INIT="$WORK_DIR/output/$CONF/target/etc/init.d"
rm -f "$TARGET_INIT/S41adb_mtp" \
      "$TARGET_INIT/S50telnet" \
      "$TARGET_INIT/S97dcentgadget"
echo "build: starting make CONF=$CONF in $WORK_DIR (model=$MODEL)"
make "CONF=$CONF"
echo "build: complete — images in $WORK_DIR/output/$CONF/images/"
