#!/usr/bin/env bash
# Assemble the first DCENT .kdimg for an Avalon K230 home model (Nano 3S
# or Nano 3) — runs INSIDE the dcent/k230-sdk container after
# build_k230_in_docker.sh with the matching MODEL.
#
# Inputs  (from the SDK build):
#   /work/output/<CONF>/images/uboot/swap_fn_u-boot-spl.bin  BROM SPL (swapped)
#   /work/output/<CONF>/images/uboot/fn_ug_u-boot.bin        proper U-Boot
#   /work/output/<CONF>/images/fw_payload.bin                opensbi+linux
#   /work/output/<CONF>/images/k230-<model>.dtb              device tree
#   /work/output/<CONF>/target/                              rootfs directory
#
# Per-model facts (evidence in the firmware archive):
#   nano3s  env pair @0x500000/0x580000, single-copy read, plain env_t blob
#   nano3   env pair @0x300000/0x380000, REDUNDANT read — the blob carries
#           the flags byte (mkenvimage -r), matching the stock master
#
# Steps:
#   1. SPL + U-Boot containers copied verbatim (the SDK's post-image.sh
#      already wrapped them in K230 type-0 containers);
#   2. env blob: mkenvimage over buildroot/dcent-$MODEL.env;
#   3. linux: k230-gzip fw_payload -> mkimage multi -> firmware_gen -n
#      (replica of the SDK post-image.sh gen_linux_bin, which the SD-only
#      flow disables);
#   4. rootfs: mkfs.ubifs + ubinize over the Buildroot target directory
#      (NAND geometry: 2 KiB pages / 128 KiB PEB; max LEB count derived
#      from the model's rootfs slot in the toolbox image map —
#      BENCH-TUNABLE against the real chip, see roadmap M1);
#   5. wrap everything via the toolbox k230_image_build builder (stdlib-only
#      import) -> DCENT_<MODEL>_FIRSTLIGHT.kdimg + describe-$MODEL.json
#
# Optional:  K230_STOCK_RTT=/path/to/stock/rtt.bin embeds the stock RT blob
# verbatim (lab-only; on-chip decrypt semantics with a custom U-Boot are
# unproven — default is a blank rtt partition and bootcmd=k230_boot spinand
# linux, which does not touch it). The nano3 map has no rtt part, so the
# blob is ignored for that model.

set -euo pipefail

CONF="${CONF:-k230_dcent_defconfig}"
SDK_DIR="${SDK_DIR:-/work}"
DCENT_DIR="${DCENT_DIR:-/dcent}"
OUT_DIR="${OUT_DIR:-$DCENT_DIR/build/image}"
MODEL="${MODEL:-nano3s}"

IMG="$SDK_DIR/output/$CONF/images"
UBOOT_BUILD="$SDK_DIR/output/$CONF/build/uboot-2022.10"
TARGET_DIR="$SDK_DIR/output/$CONF/target"
SDK_TOOLS="$SDK_DIR/tools"

for f in "$IMG/uboot/swap_fn_u-boot-spl.bin" "$IMG/uboot/fn_ug_u-boot.bin" \
         "$IMG/fw_payload.bin"; do
    [ -f "$f" ] || { echo "assemble: missing SDK artifact $f (run the build first)" >&2; exit 1; }
done

case "$MODEL" in
    nano3s) DTB_CANDS="k230-nano3s.dtb k230-evb.dtb" ;;
    nano3)  DTB_CANDS="k230-nano3.dtb k230-nano3s.dtb k230-evb.dtb" ;;
    *) echo "assemble: unknown model '$MODEL' (nano3s|nano3)" >&2; exit 1 ;;
esac
DTB=""
for cand in $DTB_CANDS; do
    [ -f "$IMG/$cand" ] && DTB="$IMG/$cand" && break
done
[ -n "$DTB" ] || { echo "assemble: no known .dtb in $IMG" >&2; exit 1; }
echo "assemble: model=$MODEL dtb=$(basename "$DTB")"

# Fail closed on the two Nano 3 DT properties whose absence made the V2-V5
# images unbootable under the factory chain: the exact 128 MiB memory window
# and the stock MTD ordering/name for rootfs A.
if [ "$MODEL" = nano3 ]; then
    FDTGET="$(command -v fdtget || true)"
    if [ -z "$FDTGET" ]; then
        FDTGET="$SDK_DIR/output/$CONF/host/bin/fdtget"
    fi
    [ -x "$FDTGET" ] || {
        echo "assemble: missing fdtget (install device-tree-compiler)" >&2
        exit 1
    }
    MEMORY_REG="$($FDTGET -t x "$DTB" /memory@0 reg)"
    [ "$MEMORY_REG" = "0 200000 0 7dfe000" ] || {
        echo "assemble: bad Nano 3 /memory@0 reg: $MEMORY_REG" >&2
        exit 1
    }
    ROOTFS_LABEL="$($FDTGET -t s "$DTB" \
        /soc/spi@91584000/spi-nand@0/partitions/partition@1400000 label)"
    [ "$ROOTFS_LABEL" = rootfs_ubi_a ] || {
        echo "assemble: bad Nano 3 rootfs-A label: $ROOTFS_LABEL" >&2
        exit 1
    }

    # The ACM service must be the only USB owner in the custom rootfs, and
    # every module it loads must be present for the built kernel release.
    [ -x "$TARGET_DIR/etc/init.d/S10dcentgadget" ] || {
        echo "assemble: Nano 3 S10dcentgadget is absent or not executable" >&2
        exit 1
    }
    grep -q '^UDC=91500000\.usb$' \
        "$TARGET_DIR/etc/init.d/S10dcentgadget" || {
        echo "assemble: Nano 3 gadget does not pin the evidenced USB0 UDC" >&2
        exit 1
    }
    for stale in S41adb_mtp S50telnet S97dcentgadget; do
        [ ! -e "$TARGET_DIR/etc/init.d/$stale" ] || {
            echo "assemble: conflicting Nano 3 init service remains: $stale" >&2
            exit 1
        }
    done
    MODULE_ROOTS="$(find "$TARGET_DIR/lib/modules" -mindepth 1 -maxdepth 1 \
        -type d -print)"
    [ "$(printf '%s\n' "$MODULE_ROOTS" | sed '/^$/d' | wc -l)" -eq 1 ] || {
        echo "assemble: Nano 3 rootfs must contain exactly one kernel module tree" >&2
        exit 1
    }
    [ -s "$MODULE_ROOTS/modules.dep" ] || {
        echo "assemble: Nano 3 rootfs has no modules.dep" >&2
        exit 1
    }
    KERNEL_RELEASE_FILES="$(find "$SDK_DIR/output/$CONF/build" \
        -mindepth 4 -maxdepth 4 -type f \
        -path '*/linux-*/include/config/kernel.release' -print)"
    [ "$(printf '%s\n' "$KERNEL_RELEASE_FILES" | sed '/^$/d' | wc -l)" -eq 1 ] || {
        echo "assemble: expected exactly one Nano 3 Linux build directory" >&2
        exit 1
    }
    LINUX_BUILD="${KERNEL_RELEASE_FILES%/include/config/kernel.release}"
    KERNEL_RELEASE="$(cat "$KERNEL_RELEASE_FILES")"
    [ "$(basename "$MODULE_ROOTS")" = "$KERNEL_RELEASE" ] || {
        echo "assemble: kernel/rootfs module release mismatch: " \
            "$KERNEL_RELEASE vs $(basename "$MODULE_ROOTS")" >&2
        exit 1
    }
    for symbol in \
        CONFIG_USB=y \
        CONFIG_USB_DWC2=y \
        CONFIG_USB_DWC2_DUAL_ROLE=y \
        CONFIG_USB_GADGET=y \
        CONFIG_CONFIGFS_FS=m \
        CONFIG_USB_LIBCOMPOSITE=m \
        CONFIG_USB_U_SERIAL=m \
        CONFIG_USB_F_ACM=m \
        CONFIG_USB_CONFIGFS=m \
        CONFIG_USB_CONFIGFS_ACM=y; do
        grep -qx "$symbol" "$LINUX_BUILD/.config" || {
            echo "assemble: Nano 3 final kernel config lacks $symbol" >&2
            exit 1
        }
    done
    for module in configfs libcomposite u_serial usb_f_acm; do
        find "$MODULE_ROOTS" -type f \
            \( -name "$module.ko" -o -name "$module.ko.xz" \
               -o -name "$module.ko.gz" \) -print -quit | grep -q . || {
            echo "assemble: Nano 3 rootfs lacks $module kernel module" >&2
            exit 1
        }
    done
fi

rm -rf "$OUT_DIR/parts-$MODEL"
mkdir -p "$OUT_DIR/parts-$MODEL"
cd "$OUT_DIR/parts-$MODEL"

# ---- 1. SPL + U-Boot (SDK post-image output, verbatim)
cp "$IMG/uboot/swap_fn_u-boot-spl.bin" spl.bin
cp "$IMG/uboot/fn_ug_u-boot.bin" uboot.bin

# ---- 2. env blob (redundant header for nano3, plain for nano3s)
ENV_FLAGS="-s 0x10000"
[ "$MODEL" = nano3 ] && ENV_FLAGS="-s 0x10000 -r"
"$UBOOT_BUILD/tools/mkenvimage" $ENV_FLAGS -o env.bin \
    "$DCENT_DIR/buildroot/dcent-$MODEL.env"

# ---- 3. linux container (gen_linux_bin replica)
k230_gzip() {
    local f="$1"
    "$SDK_TOOLS/k230_priv_gzip" -n8 -f -k "$f" \
        || "$SDK_TOOLS/k230_priv_gzip" -n9 -f -k "$f" \
        || "$SDK_TOOLS/k230_priv_gzip" -n7 -f -k "$f" \
        || "$SDK_TOOLS/k230_priv_gzip" -n6 -f -k "$f"
    sed -i -e "1s/\x08/\x09/" "$f.gz"
}

CONFIG_MEM_LINUX_SYS_BASE="$(grep CONFIG_MEM_LINUX_SYS_BASE \
    "$UBOOT_BUILD/board/canaan/common/sdk_autoconf.h" | awk '{print $3}')"
cp "$IMG/fw_payload.bin" .
cp "$DTB" .
ln -sf "$(basename "$DTB")" k.dtb
k230_gzip fw_payload.bin
echo a > rd
"$UBOOT_BUILD/tools/mkimage" -A riscv -O linux -T multi -C gzip \
    -a "$CONFIG_MEM_LINUX_SYS_BASE" -e "$CONFIG_MEM_LINUX_SYS_BASE" \
    -n linux -d fw_payload.bin.gz:rd:k.dtb ulinux.bin
python3 "$UBOOT_BUILD/tools/firmware_gen_no_securiy.py" -i ulinux.bin -o fn_ulinux.bin -n
mv fn_ulinux.bin linux.bin
rm -f fw_payload.bin fw_payload.bin.gz ulinux.bin rd k.dtb

# ---- 4. rootfs UBI (2 KiB page, 128 KiB PEB; partition size from the
#        model's map in the toolbox — single source of truth)
#      LEB = 128 KiB - 2*2 KiB = 124 KiB (126976); max LEB count from slot
MAX_LEB="$(PYTHONPATH=/toolbox/src python3 -c '
import sys
from dcent_toolbox.core.k230_image_build import image_map_for
rootfs = next(p for p in image_map_for(sys.argv[1]) if p.name == "rootfs")
print(rootfs.slots[0].size // 126976)' "$MODEL")"
echo "assemble: rootfs max LEB count $MAX_LEB (map-derived)"
mkfs.ubifs -r "$TARGET_DIR" -o rootfs.ubifs -m 2048 -e 126976 -c "$MAX_LEB"
cat > ubinize.cfg <<'EOF'
[rootfs]
mode=ubi
vol_id=0
vol_type=dynamic
vol_name=rootfs
vol_alignment=1
image=rootfs.ubifs
EOF
ubinize -o rootfs.ubi -m 2048 -p 128KiB ubinize.cfg
rm -f rootfs.ubifs ubinize.cfg

# ---- 5. optional stock RT blob (lab-only, off by default)
if [ -n "${K230_STOCK_RTT:-}" ]; then
    [ -f "$K230_STOCK_RTT" ] || { echo "assemble: K230_STOCK_RTT not found: $K230_STOCK_RTT" >&2; exit 1; }
    cp "$K230_STOCK_RTT" rtt.bin
    echo "assemble: embedding stock RT blob (lab-only)"
else
    # Blank rtt: on nano3s the kdimg still declares the partition (map
    # visibility) but zero content means the flasher never writes it — the
    # region keeps whatever was there (stock bytes on a converted unit,
    # erase state on a fresh chip). On nano3 the map has no rtt part and
    # the blob is ignored. bootcmd=k230_boot spinand linux never touches
    # it either way.
    : > rtt.bin
fi

# ---- 6. wrap into .kdimg via the toolbox builder (stdlib-only path)
PYTHONPATH="/toolbox/src" python3 - "$MODEL" "$OUT_DIR" <<'EOF'
import json, sys
from pathlib import Path
from dcent_toolbox.core.k230_image_build import build_dcent_k230_kdimg
from dcent_toolbox.core.k230_nano3_gate import build_nano3_linux_rootfs_gate

model, out_dir = sys.argv[1], Path(sys.argv[2])
parts_dir = out_dir / f"parts-{model}"
FILEMAP = {
    "spl": "spl.bin",
    "uboot": "uboot.bin",
    "uboot_env": "env.bin",
    "rtt": "rtt.bin",  # nano3 map has no rtt part; extra key is ignored
    "linux": "linux.bin",
    "rootfs": "rootfs.ubi",
}
parts = {
    key: (parts_dir / name).read_bytes()
    for key, name in FILEMAP.items()
    if (parts_dir / name).exists()
}
result = build_dcent_k230_kdimg(model, parts)
kdimg = out_dir / f"DCENT_{model.upper()}_FIRSTLIGHT.kdimg"
kdimg.write_bytes(result.data)
(out_dir / f"describe-{model}.json").write_text(
    json.dumps(result.image.describe(), indent=2))
desc = result.image.describe()
print(f"assemble: wrote {kdimg} ({kdimg.stat().st_size} bytes)")
print(f"assemble: partitions: {[p['name'] for p in desc['partitions']]}")

if model == "nano3":
    gate, evidence = build_nano3_linux_rootfs_gate(
        parts["linux"], parts["rootfs"]
    )
    gate_path = out_dir / "DCENT_NANO3_LINUX_ROOTFS_GATE.kdimg"
    gate_path.write_bytes(gate.data)
    gate.image.verify_all()
    digest = __import__("hashlib").sha256(gate.data).hexdigest()
    (out_dir / "DCENT_NANO3_LINUX_ROOTFS_GATE.kdimg.sha256").write_text(
        f"{digest}  {gate_path.name}\n"
    )
    (out_dir / "verify-nano3-linux-rootfs-gate.json").write_text(
        json.dumps(evidence, indent=2)
    )
    print(f"assemble: wrote {gate_path} ({gate_path.stat().st_size} bytes)")
    print(f"assemble: custom-Linux gate sha256 {digest}")
    print(
        "assemble: custom-Linux gate writes "
        f"{[p.name for p in gate.image.partitions]}"
    )
EOF

echo "assemble: done."
