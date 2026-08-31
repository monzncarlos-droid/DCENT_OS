#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Plan/packaging helper for the DCENT ramdisk-swap route on stock BM1397
17-series units whose boot-chain eFuse is LOCKED (VNish model, A2 section 1).

CAMPAIGN:  (agent B2), DESK ONLY.

MODEL (A2_VNISH_BRAIINS_SUMMARY.md, verdict HIGH):
  * VNish on eFuse-locked boards swaps ONLY the ramdisk on the intact stock
    boot chain: uramdisk -> mtd1@0x0 AND mtd4@0x0. mtd0 (BOOT.bin / dtb /
    uImage) is never touched -- the S17/T17 packages ship uramdisk ONLY; the
    S17+/T17+ packages re-pin byte-identical-to-stock BOOT.bin/dtb/uImage
    (net effect: only the ramdisk changes).
  * The signed stock chain keeps booting, so the per-unit eFuse lock
    (EFUSE_STATUS 0xF800D010 bit 0x400, unlock word 0xDF0D at 0xF800D004 --
    A2 section 3 model 4) is irrelevant to this route BY CONSTRUCTION.

WHAT THIS TOOL DOES (desk, plan/packaging only):
  * Admits a DCENT rootfs.squashfs and wraps it as a legacy uImage ramdisk
    (`mkimage -A arm -O linux -T ramdisk -C none`) when a working `mkimage`
    is on PATH; otherwise it emits the exact command for the operator.
  * Refuses (fail closed) unless the operator supplies the target's actual
    ramdisk-partition window via --mtd1-max-bytes: NO live stock 17-series
    mtd dump is held, so this tool must NEVER guess the window. The value is
    read on-unit from /proc/mtd before any lab install.
  * Emits a signed-shape plan JSON: payload SHA256/size, uImage header
    overhead (64-byte legacy header), per-partition write plan (mtd1, mtd4),
    the never-touch list (mtd0 sub-partitions: BOOT.bin@0x0, dtb@0x1A00000,
    uImage@0x2000000), the backup-first requirement, and the stock-restore
    path (re-flash the backed-up stock uramdisk to mtd1+mtd4).

WHAT THIS TOOL NEVER DOES:
  * Contacts a miner, opens SSH, or writes any MTD. Live execution is a
    LAB-GATED operator step with a pre-write full NAND backup; the toolbox
    route that consumes this plan stays planner_outcome=evidence-gap.

Usage:
  build_am2_s17_ramdisk_swap.py plan --rootfs rootfs.squashfs \
      --board-target am2-s17p --mtd1-max-bytes <bytes> --output-dir out/
  build_am2_s17_ramdisk_swap.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

# Legacy uImage header is a fixed 64-byte structure (mkimage doc); the payload
# the stock u-boot boots is header + raw squashfs.
UIMAGE_LEGACY_HEADER_BYTES = 64

# Exact targets this route may ever plan for (B1's admitted set).
RAMDISK_SWAP_TARGETS = ("am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus")

# VNish write map (A2 section 1): uramdisk to BOTH ramdisk partitions.
RAMDISK_PARTITIONS = ("mtd1", "mtd4")

# NEVER-TOUCH list: the stock boot chain on mtd0 (A1 section V5 offsets).
NEVER_TOUCH = (
    "mtd0@0x0 (stock BOOT.bin)",
    "mtd0@0x1A00000 (stock dtb)",
    "mtd0@0x2000000 (stock uImage)",
)

ROUTE_ID = "ramdisk-swap-stock-am2-s17-lab"
EVIDENCE = (
    "",
    "",
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_window(mtd1_max_bytes: int) -> None:
    """The ramdisk window must come from the unit, never from a guess."""
    if mtd1_max_bytes <= 0:
        raise SystemExit(
            "refusing: --mtd1-max-bytes must be a positive on-unit /proc/mtd "
            "value; no live stock 17-series ramdisk-partition size is held"
        )
    if mtd1_max_bytes % 1024 != 0:
        raise SystemExit("refusing: ramdisk partition size must be KiB-aligned")


def plan_payload(
    rootfs: pathlib.Path,
    board_target: str,
    mtd1_max_bytes: int,
) -> dict:
    """Pure plan computation (host-testable; no I/O beyond reading the file)."""
    if board_target not in RAMDISK_SWAP_TARGETS:
        raise SystemExit(
            f"refusing: board target {board_target!r} is outside the admitted "
            f"BM1397 17-series set {RAMDISK_SWAP_TARGETS}"
        )
    validate_window(mtd1_max_bytes)
    if not rootfs.is_file() or rootfs.is_symlink():
        raise SystemExit(f"refusing: rootfs must be a regular non-symlink file: {rootfs}")
    with rootfs.open("rb") as handle:
        magic = handle.read(4)
    if magic != b"hsqs":
        raise SystemExit(
            f"refusing: {rootfs} is not a squashfs image (magic {magic!r}, want hsqs)"
        )
    rootfs_size = rootfs.stat().st_size
    wrapped_size = rootfs_size + UIMAGE_LEGACY_HEADER_BYTES
    fits = wrapped_size <= mtd1_max_bytes
    return {
        "route_id": ROUTE_ID,
        "board_target": board_target,
        "mechanism": "stock-boot-chain ramdisk swap (VNish model; mtd0 untouched)",
        "rootfs": {
            "path": str(rootfs),
            "size_bytes": rootfs_size,
            "sha256": sha256_file(rootfs),
        },
        "uimage": {
            "type": "legacy ramdisk",
            "header_bytes": UIMAGE_LEGACY_HEADER_BYTES,
            "wrapped_size_bytes": wrapped_size,
            "build_command": (
                f"mkimage -A arm -O linux -T ramdisk -C none "
                f"-n 'DCENT_OS {board_target} ramdisk' -d {rootfs} uramdisk"
            ),
        },
        "write_plan": [
            {"partition": part, "offset": "0x0", "payload": "uramdisk"}
            for part in RAMDISK_PARTITIONS
        ],
        "never_touch": list(NEVER_TOUCH),
        "window": {
            "mtd1_max_bytes": mtd1_max_bytes,
            "wrapped_fits": fits,
        },
        "lab_gates": [
            "full NAND backup of mtd1 and mtd4 BEFORE any write (backup-first)",
            "on-unit /proc/mtd window re-read immediately before the write",
            "operator confirmation of the physical chassis model",
            "stock restore = re-flash the backed-up stock uramdisk to mtd1+mtd4",
        ],
        "maturity": "lab-gated plan-only (desk-validated; no live unit proof)",
        "evidence": list(EVIDENCE),
    }


def build_uramdisk(plan: dict, output_dir: pathlib.Path) -> pathlib.Path | None:
    """Optionally wrap the payload with a host mkimage; else return None."""
    mkimage = shutil.which("mkimage")
    if mkimage is None:
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "uramdisk"
    subprocess.run(
        [mkimage, "-A", "arm", "-O", "linux", "-T", "ramdisk", "-C", "none",
         "-n", f"DCENT_OS {plan['board_target']} ramdisk", "-d", plan["rootfs"]["path"], str(out)],
        check=True,
    )
    actual = out.stat().st_size
    expected = plan["uimage"]["wrapped_size_bytes"]
    if actual != expected:
        raise SystemExit(
            f"refusing: mkimage output is {actual} bytes, plan expected {expected}"
        )
    return out


class _SelfTest(unittest.TestCase):
    """Host tests (also run by scripts/test_am2_s17_ramdisk_swap.py)."""

    def test_window_is_mandatory_and_aligned(self) -> None:
        for bad in (0, -1, 4095):
            with self.assertRaises(SystemExit):
                validate_window(bad)
        validate_window(4096)

    def test_target_set_is_exact(self) -> None:
        self.assertEqual(
            RAMDISK_SWAP_TARGETS, ("am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus")
        )
        self.assertEqual(RAMDISK_PARTITIONS, ("mtd1", "mtd4"))

    def test_never_touch_pins_the_stock_boot_chain(self) -> None:
        joined = " ".join(NEVER_TOUCH)
        self.assertIn("BOOT.bin", joined)
        self.assertIn("dtb", joined)
        self.assertIn("uImage", joined)
        self.assertIn("mtd0", joined)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    plan_p = sub.add_parser("plan", help="emit a lab-gated ramdisk-swap plan")
    plan_p.add_argument("--rootfs", required=True, type=pathlib.Path)
    plan_p.add_argument("--board-target", required=True)
    plan_p.add_argument("--mtd1-max-bytes", required=True, type=int)
    plan_p.add_argument("--output-dir", required=True, type=pathlib.Path)
    plan_p.add_argument(
        "--wrap", action="store_true",
        help="also run host mkimage to produce uramdisk when available",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        unittest.main(argv=[sys.argv[0], "-v"], exit=False)
        return 0
    if args.cmd != "plan":
        parser.print_help()
        return 2
    plan = plan_payload(args.rootfs, args.board_target, args.mtd1_max_bytes)
    if not plan["window"]["wrapped_fits"]:
        raise SystemExit(
            f"refusing: wrapped ramdisk {plan['uimage']['wrapped_size_bytes']} bytes "
            f"exceeds the on-unit window {args.mtd1_max_bytes} bytes"
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.wrap:
        built = build_uramdisk(plan, args.output_dir)
        plan["uimage"]["built"] = str(built) if built else "not-built (no host mkimage)"
    plan_path = args.output_dir / "ramdisk-swap-plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"plan written: {plan_path}")
    print("LAB-GATED: this tool never contacts a miner or writes any MTD.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
