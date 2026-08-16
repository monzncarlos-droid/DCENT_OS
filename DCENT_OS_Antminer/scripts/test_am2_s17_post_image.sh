#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_ROOT=$(CDPATH= cd -- "$PROJECT_ROOT/../.." && pwd)
POST_IMAGE="$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s17pro/post-image.sh"
ADMISSION="$PROJECT_ROOT/scripts/extract_am2_s17_kernel.py"
DONOR="$WORKSPACE_ROOT/knowledge-base/firmware-archive/braiins-os_am2-s17_sd.img"

if [ ! -f "$DONOR" ]; then
    echo "SKIP: exact held Braiins AM2 S17 SD donor is absent"
    exit 0
fi
if ! command -v mkimage >/dev/null 2>&1; then
    echo "SKIP: mkimage with FIT support is absent"
    exit 0
fi

TMP_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TMP_ROOT"' EXIT HUP INT TERM
GOOD_DIR="$TMP_ROOT/good"
mkdir "$GOOD_DIR"
printf 'hsqs\000\000\000\000' > "$GOOD_DIR/rootfs.squashfs"

if ! BASE_DIR="$GOOD_DIR" \
     BINARIES_DIR="$GOOD_DIR" \
     BR2_EXTERNAL_DCENTOS_PATH="$PROJECT_ROOT/br2_external_dcentos" \
     DCENT_AM2_S17_BRAIINS_SD_IMAGE="$DONOR" \
     DCENT_PACKAGE_STATUS=lab_unsigned \
     DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 \
     DCENT_PACKAGE_VERSION=test-s17-donor-fit \
     sh "$POST_IMAGE" >"$GOOD_DIR/post-image.log" 2>&1; then
    cat "$GOOD_DIR/post-image.log" >&2
    exit 1
fi

PACKAGE="$GOOD_DIR/dcentos-sysupgrade-am2-s17pro.tar"
[ -f "$PACKAGE" ]
[ -f "$GOOD_DIR/kernel" ]
[ -f "$GOOD_DIR/am2-s17-donor-admission.json" ]
[ -f "$GOOD_DIR/am2-s17-fit-admission.json" ]

python3 "$ADMISSION" verify-fit --fit "$GOOD_DIR/kernel" > "$GOOD_DIR/recheck.json"
python3 - "$GOOD_DIR" "$PACKAGE" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1])
package = Path(sys.argv[2])
donor = json.loads((root / "am2-s17-donor-admission.json").read_text("ascii"))
fit = json.loads((root / "am2-s17-fit-admission.json").read_text("ascii"))
recheck = json.loads((root / "recheck.json").read_text("ascii"))

assert donor["donor"]["sha256"] == "b0444ad2a5e9b9e2b021ec756a40cb1448128545a42c77bdabb4363617d03579"
assert donor["source_fit"]["sha256"] == "e3e0f8ae80175235aef1d9b210f4345da3723a6fe472e491f91ffc561aaf4d67"
assert donor["source_fit"]["kernel"]["sha256"] == "205b9fb13cae3152e2d8ac94f34fd6105aa0260cf9229abe2bc14f86512a24c1"
assert donor["source_fit"]["dtb"]["sha256"] == "51f4d224271b0e2bd4c1bf4f62f88373f50caaa5f184571817f32fa30841ff3b"
assert donor["source_fit"]["dtb"]["model"] == "Antminer S17 Miner Control Board"
assert donor["authorization"]["stock_first_install"] is False
assert donor["authorization"]["flash"] is False

assert fit == recheck
assert fit["geometry"]["kernel_volume_lebs"] == 23
assert fit["geometry"]["usable_leb_size"] == 126_976
assert fit["geometry"]["kernel_capacity_bytes"] == 23 * 126_976 == 2_920_448
assert fit["geometry"]["fit_bytes"] == (root / "kernel").stat().st_size == 2_845_580
assert fit["fit"]["sha256"] == "3e0cebd3f0461722b3f9e21b84e0700d215e9a928459a951660849547aff5749"
assert fit["geometry"]["margin_bytes"] == 2_920_448 - 2_845_580 == 74_868
assert fit["geometry"]["fits"] is True
assert fit["authorization"]["stock_first_install"] is False
assert fit["authorization"]["flash"] is False

with tarfile.open(package, "r:") as archive:
    names = set(archive.getnames())
    expected = {
        "sysupgrade-am2-s17p",
        "sysupgrade-am2-s17p/kernel",
        "sysupgrade-am2-s17p/root",
        "sysupgrade-am2-s17p/METADATA",
        "sysupgrade-am2-s17p/SHA256SUMS",
        "sysupgrade-am2-s17p/MANIFEST.json",
    }
    assert names == expected, names
    member = archive.extractfile("sysupgrade-am2-s17p/MANIFEST.json")
    assert member is not None
    manifest = json.load(member)
    packaged_kernel = archive.extractfile("sysupgrade-am2-s17p/kernel").read()

assert manifest["installable"] is False
assert manifest["toolbox"]["install_command"] is None
assert manifest["toolbox"]["update_command"] is None
assert manifest["toolbox"]["install_mode"] == "package_only_denied"
assert manifest["target_side_sysupgrade"] is True
assert manifest["payloads"]["kernel"]["sha256"] == hashlib.sha256(packaged_kernel).hexdigest()
assert packaged_kernel == (root / "kernel").read_bytes()
PY

# The exact donor produces a reproducible kernel FIT even when package metadata
# dates differ; its timestamp is bound to the donor source FIT epoch.
REPEAT_DIR="$TMP_ROOT/repeat"
mkdir "$REPEAT_DIR"
cp "$GOOD_DIR/rootfs.squashfs" "$REPEAT_DIR/rootfs.squashfs"
BASE_DIR="$REPEAT_DIR" \
BINARIES_DIR="$REPEAT_DIR" \
BR2_EXTERNAL_DCENTOS_PATH="$PROJECT_ROOT/br2_external_dcentos" \
DCENT_AM2_S17_BRAIINS_SD_IMAGE="$DONOR" \
DCENT_PACKAGE_STATUS=lab_unsigned \
DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 \
DCENT_PACKAGE_VERSION=test-s17-donor-fit \
sh "$POST_IMAGE" >"$REPEAT_DIR/post-image.log" 2>&1
cmp "$GOOD_DIR/kernel" "$REPEAT_DIR/kernel"

# No donor, a wrong donor, and every old stock/kernel override route fail closed.
for CASE in no-donor wrong-donor old-override; do
    CASE_DIR="$TMP_ROOT/$CASE"
    mkdir "$CASE_DIR"
    cp "$GOOD_DIR/rootfs.squashfs" "$CASE_DIR/rootfs.squashfs"
    case "$CASE" in
        no-donor)
            DONOR_ENV=""
            EXTRA_ENV=""
            ;;
        wrong-donor)
            printf 'wrong-donor-hash' > "$CASE_DIR/wrong.img"
            DONOR_ENV="$CASE_DIR/wrong.img"
            EXTRA_ENV=""
            ;;
        old-override)
            DONOR_ENV="$DONOR"
            printf 'untrusted-kernel' > "$CASE_DIR/kernel-override"
            EXTRA_ENV="$CASE_DIR/kernel-override"
            ;;
    esac
    if BASE_DIR="$CASE_DIR" \
       BINARIES_DIR="$CASE_DIR" \
       BR2_EXTERNAL_DCENTOS_PATH="$PROJECT_ROOT/br2_external_dcentos" \
       DCENT_AM2_S17_BRAIINS_SD_IMAGE="$DONOR_ENV" \
       DCENT_AM2_S17_KERNEL="$EXTRA_ENV" \
       DCENT_PACKAGE_STATUS=lab_unsigned \
       DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 \
       DCENT_PACKAGE_VERSION=test-s17-refusal \
       sh "$POST_IMAGE" >"$CASE_DIR/post-image.log" 2>&1; then
        echo "FAIL: $CASE produced an S17 package" >&2
        exit 1
    fi
    [ ! -e "$CASE_DIR/dcentos-sysupgrade-am2-s17pro.tar" ]
done

echo "AM2_S17_EXACT_DONOR_MODEL_BOUND_FIT_PACKAGE_ONLY_OK"
