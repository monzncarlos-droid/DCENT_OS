#!/bin/sh
#
# DCENTos post-image script — am1-s9se (Antminer S9 SE, Zynq am1 family)
# D-Central Technologies, 2026.
#
# 2026-08-29 S9k/S9 SE packaging-lane wave — the 2026-08-28 full-line
# campaign's missing S9 SE install artifact body. The held S9 SE stock
# image's devicetree is xlnx,zynq-7000 (the am1-s9 board family), so this
# lane reuses the proven am1-s9 SoC boot inputs (vendor/soc-boot/s9) and
# the shared Zynq packaging helpers.
#
# ## PACKAGE-ONLY / INSTALL DENIED ############################################
# The BoardDesc row (am1-s9se, BM1393, Ctrl_C43-class carrier) stays
# fail-closed: install authorization Denied, the BM1393 scaffold driver
# refuses every mutating operation, and the raw ASIC reply width is
# FPGA-bitstream-owned (desk-exhausted 2026-08-29). This artifact is a
# research/diagnostic shell payload ONLY — no Toolbox install/update route
# is emitted, and promotion to Experimental-install tier requires the
# operator-gated route-policy review binding this exact artifact.
#
# Model: board/zynq/am2-t17/post-image.sh (the package-only Zynq pattern),
# minus the S17-specific donor-admission chain: the boot inputs here are
# the am1-s9 vendor SoC boot files (kernel + S9-family DTB), fail-closed
# when absent — same sources the proven am1-s9 lane consumes.
#############################################################################

set -e

BOARD_DIR="$(dirname "$0")"
BINARIES_DIR="${BINARIES_DIR:-${BASE_DIR}/images}"

BOARD_NAME="am1-s9se"
BOARD_FAMILY="am1"
OUTPUT_TAR="${BINARIES_DIR}/dcentos-sysupgrade-am1-s9se.tar"

echo "=== DCENTos Post-Image Builder (am1-s9se) ==="
echo "    am1 Zynq S9-family boot inputs; package-only/install-denied."
echo ""

# -----------------------------------------------------------------------------
# Locate the rootfs produced by Buildroot
# -----------------------------------------------------------------------------
ROOTFS="${BINARIES_DIR}/rootfs.squashfs"
if [ ! -f "$ROOTFS" ]; then
    echo "ERROR: rootfs.squashfs not found in ${BINARIES_DIR}" >&2
    echo "  Enable BR2_TARGET_ROOTFS_SQUASHFS=y in the am1-s9se defconfig." >&2
    exit 1
fi
ROOTFS_SIZE=$(stat -c%s "$ROOTFS")
ROOTFS_SHA256=$(sha256sum "$ROOTFS" | awk '{print $1}')
echo "Rootfs:  rootfs.squashfs ($((ROOTFS_SIZE / 1024)) KB)"
echo "  SHA256: ${ROOTFS_SHA256}"

PROJECT_ROOT="$(cd "${BR2_EXTERNAL_DCENTOS_PATH}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_package_common.sh"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_archive_admission.sh"

# NOTE (deliberate): no dcent_zynq_geometry_require_payload_fit call — the
# geometry helper has no am1-s9se profile, and a package-only-denied
# artifact makes no partition-fit claim. Geometry admission lands together
# with a same-unit receipt if this target is ever promoted.

read_first_nonempty_line() {
    sed -n 's/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}' "$1"
}

infer_package_version() {
    if [ -n "${DCENT_PACKAGE_VERSION:-}" ]; then
        printf '%s\n' "${DCENT_PACKAGE_VERSION}"
        return 0
    fi
    for candidate in \
        "${TARGET_DIR:-}/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/zynq/am1-s9se/rootfs-overlay/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
    do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            value=$(read_first_nonempty_line "$candidate")
            if [ -n "$value" ]; then
                printf '%s\n' "$value"
                return 0
            fi
        fi
    done
    return 1
}

PACKAGE_VERSION=$(infer_package_version || true)
if [ -z "$PACKAGE_VERSION" ]; then
    echo "ERROR: unable to infer package version; set DCENT_PACKAGE_VERSION or ship /etc/dcentos-version" >&2
    exit 1
fi
case "$PACKAGE_VERSION" in
    *[!A-Za-z0-9._+:-]*)
        echo "ERROR: package version contains unsupported characters: $PACKAGE_VERSION" >&2
        exit 1
        ;;
esac
echo "Version: ${PACKAGE_VERSION}"

# -----------------------------------------------------------------------------
# SoC boot inputs: the am1-s9 vendor set (fail-closed when absent).
# -----------------------------------------------------------------------------
VENDOR_S9="${DCENT_VENDOR_SOC_BOOT:-$PROJECT_ROOT/vendor/soc-boot}/s9"
if [ -n "${DCENT_EXTRACTIONS_DIR:-}" ] && [ -d "$DCENT_EXTRACTIONS_DIR" ]; then
    EXTRACTIONS_DIR="$DCENT_EXTRACTIONS_DIR"
elif [ -d "$VENDOR_S9" ]; then
    EXTRACTIONS_DIR="$VENDOR_S9"
elif [ -d "$REPO_ROOT/knowledge-base/extractions/s9" ]; then
    echo "WARN: using private lab knowledge-base/extractions/s9 (not a public build input)." >&2
    EXTRACTIONS_DIR="$REPO_ROOT/knowledge-base/extractions/s9"
else
    echo "ERROR: No SoC boot inputs for am1-s9se. Set \$DCENT_EXTRACTIONS_DIR or populate vendor/soc-boot/s9/ (see vendor/soc-boot/README.md)." >&2
    exit 1
fi

KERNEL=""
for candidate in "$EXTRACTIONS_DIR/kernel.bin" "$EXTRACTIONS_DIR/uImage"; do
    if [ -f "$candidate" ]; then
        KERNEL="$candidate"
        break
    fi
done
[ -n "$KERNEL" ] || {
    echo "ERROR: no kernel input (kernel.bin/uImage) in $EXTRACTIONS_DIR" >&2
    exit 1
}
DTB=""
for candidate in "$EXTRACTIONS_DIR/s9_devicetree.dtb" "$EXTRACTIONS_DIR/devicetree.dtb"; do
    if [ -f "$candidate" ]; then
        DTB="$candidate"
        break
    fi
done
[ -n "$DTB" ] || {
    echo "ERROR: no device tree input (s9_devicetree.dtb/devicetree.dtb) in $EXTRACTIONS_DIR" >&2
    exit 1
}

MKIMAGE=""
if [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/mkimage" ]; then
    MKIMAGE="${HOST_DIR}/bin/mkimage"
else
    MKIMAGE=$(command -v mkimage || true)
fi
[ -n "$MKIMAGE" ] && [ -x "$MKIMAGE" ] || {
    echo "ERROR: host mkimage with FIT support is required" >&2
    exit 1
}

FIT_WORKDIR=$(mktemp -d)
trap 'rm -rf "$FIT_WORKDIR"' EXIT HUP INT TERM
cp "$KERNEL" "$FIT_WORKDIR/kernel.bin"
cp "$DTB" "$FIT_WORKDIR/board.dtb"
cat > "$FIT_WORKDIR/s9se-kernel.its" << 'EOF'
/dts-v1/;

/ {
    description = "DCENT_OS S9 SE research-shell kernel FIT";
    #address-cells = <1>;

    images {
        kernel@1 {
            description = "DCENT_OS S9 SE kernel";
            data = /incbin/("kernel.bin");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "none";
            load = <0x00008000>;
            entry = <0x00008000>;
            hash@1 { algo = "crc32"; };
            hash@2 { algo = "sha1"; };
        };

        fdt@1 {
            description = "Antminer S9-family device tree";
            data = /incbin/("board.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1 { algo = "crc32"; };
            hash@2 { algo = "sha1"; };
        };
    };

    configurations {
        default = "config@1";
        config@1 {
            description = "DCENT_OS S9 SE research shell";
            kernel = "kernel@1";
            fdt = "fdt@1";
        };
    };
};
EOF
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1740171698}" "$MKIMAGE" \
    -f "$FIT_WORKDIR/s9se-kernel.its" "$FIT_WORKDIR/kernel" >/dev/null
KERNEL_FILE="$FIT_WORKDIR/kernel"

KERNEL_SIZE=$(stat -c%s "$KERNEL_FILE")
KERNEL_SHA256=$(sha256sum "$KERNEL_FILE" | awk '{print $1}')
echo "Kernel:  kernel ($((KERNEL_SIZE / 1024)) KB) from am1-s9 vendor SoC boot inputs"
echo "  SHA256: ${KERNEL_SHA256}"

# -----------------------------------------------------------------------------
# Stage sysupgrade-am1-s9se/ and build tarball
# -----------------------------------------------------------------------------
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING" "$FIT_WORKDIR"' EXIT HUP INT TERM
SUP_DIR="$STAGING/sysupgrade-${BOARD_NAME}"
mkdir -p "$SUP_DIR"

cp "$KERNEL_FILE" "$SUP_DIR/kernel"
cp "$ROOTFS"       "$SUP_DIR/root"

cat > "$SUP_DIR/METADATA" << EOF
DCENT_OS
D-Central Technologies
Build: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board: ${BOARD_NAME}
Kernel: am1-s9 vendor SoC boot inputs + S9-family DTB FIT — RESEARCH SHELL
Rootfs: DCENTos (Buildroot)
EOF
METADATA_SHA256=$(sha256sum "$SUP_DIR/METADATA" | awk '{print $1}')

{
    echo "${KERNEL_SHA256}  kernel"
    echo "${ROOTFS_SHA256}  root"
    echo "${METADATA_SHA256}  METADATA"
} > "$SUP_DIR/SHA256SUMS"

cat > "$SUP_DIR/MANIFEST.json" << EOF
{
  "schema": 1,
  "product": "DCENT_OS",
  "family": "antminer",
  "package_type": "sysupgrade",
  "board_family": "${BOARD_FAMILY}",
  "board": "${BOARD_NAME}",
  "board_target": "${BOARD_NAME}",
  "version": "${PACKAGE_VERSION}",
  "created_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "payloads": {
    "kernel": {
      "path": "sysupgrade-${BOARD_NAME}/kernel",
      "size": ${KERNEL_SIZE},
      "sha256": "${KERNEL_SHA256}"
    },
    "rootfs": {
      "path": "sysupgrade-${BOARD_NAME}/root",
      "size": ${ROOTFS_SIZE},
      "sha256": "${ROOTFS_SHA256}"
    },
    "metadata": {
      "path": "sysupgrade-${BOARD_NAME}/METADATA",
      "sha256": "${METADATA_SHA256}"
    }
  },
  "toolbox": {
    "install_command": null,
    "update_command": null,
    "upload_endpoint": null,
    "board_target_header": null,
    "requires_inactive_slot": true
  }
}
EOF

# Final manifest/signature rewrite through the shared helper. This is a
# package-validation artifact only: no Toolbox install/update route is emitted.
DCENT_TOOLBOX_INSTALL_COMMAND=""
DCENT_TOOLBOX_UPDATE_COMMAND=""
DCENT_TOOLBOX_REQUIRES_INACTIVE_SLOT=true
DCENT_TOOLBOX_INSTALL_MODE=package_only_denied
DCENT_TARGET_SIDE_SYSUPGRADE=true
DCENT_PACKAGE_INSTALLABLE=false
DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-unvalidated_target_sysupgrade}"
dcent_stage_release_key
dcent_write_sysupgrade_manifest
dcent_sign_sysupgrade_manifest

(cd "$STAGING" && tar cf "$OUTPUT_TAR" "sysupgrade-${BOARD_NAME}/")
dcent_sysupgrade_archive_admit "$OUTPUT_TAR" "$BOARD_NAME" "$STAGING" || {
    echo "ERROR: generated sysupgrade archive failed canonical admission" >&2
    exit 1
}
OUTPUT_SIZE=$(stat -c%s "$OUTPUT_TAR")
OUTPUT_SHA256=$(sha256sum "$OUTPUT_TAR" | awk '{print $1}')

echo ""
echo "Sysupgrade tarball:"
echo "  Path:   ${OUTPUT_TAR}"
echo "  Size:   $((OUTPUT_SIZE / 1024)) KB"
echo "  SHA256: ${OUTPUT_SHA256}"
echo ""
tar tf "$OUTPUT_TAR" | sed 's/^/  /'

cat > "${BINARIES_DIR}/BUILD_INFO.txt" << EOF
=== DCENTos am1-s9se Build Info (RESEARCH SHELL package) ===
Build date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board:      ${BOARD_NAME} (Antminer S9 SE, Zynq am1 family)
Board family: ${BOARD_FAMILY}
Status:     Package-only artifact. The BoardDesc row stays fail-closed
            (install authorization Denied; BM1393 scaffold refuses every
            mutating operation; raw ASIC reply width FPGA-owned). Stock
            first-install and all Toolbox install/update routing remain
            denied. Promotion requires the operator-gated route-policy
            review binding this exact artifact.

Sysupgrade tarball:
  File:   $(basename "${OUTPUT_TAR}")
  Size:   ${OUTPUT_SIZE} bytes
  SHA256: ${OUTPUT_SHA256}

Target fleet:
  (none — no live S9 SE unit)
EOF

echo ""
echo "=== Build Complete (am1-s9se — RESEARCH SHELL package, install denied) ==="
