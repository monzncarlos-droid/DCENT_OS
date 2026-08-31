#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Offline tests for scripts/build_am2_s17_ramdisk_swap.py (2026-08-27 armada).

Behavioral, host-only: builds synthetic squashfs fixtures in a tempdir and
exercises the plan path — the fail-closed window requirement, the exact
target set, the mtd1/mtd4 write map, the mtd0 never-touch list, and the
fit-vs-refuse boundary. The packager itself NEVER contacts a miner.
"""

from __future__ import annotations

import pathlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build_am2_s17_ramdisk_swap as rss  # noqa: E402


def _synthetic_squashfs(directory: pathlib.Path, name: str, size: int) -> pathlib.Path:
    path = directory / name
    payload = bytearray(b"\x00" * size)
    payload[0:4] = b"hsqs"  # squashfs magic (little-endian "sqsh" read back)
    path.write_bytes(bytes(payload))
    return path


class RamdiskSwapPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)
        self.rootfs = _synthetic_squashfs(self.dir, "rootfs.squashfs", 4096)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _plan(self, target: str = "am2-s17p", window: int = 1 << 20) -> dict:
        return rss.plan_payload(self.rootfs, target, window)

    def test_window_is_mandatory_and_aligned(self) -> None:
        for bad in (0, -1, 4095):
            with self.assertRaises(SystemExit):
                rss.validate_window(bad)
        rss.validate_window(4096)

    def test_exact_target_set(self) -> None:
        self.assertEqual(
            rss.RAMDISK_SWAP_TARGETS,
            ("am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"),
        )
        with self.assertRaises(SystemExit):
            self._plan(target="am2-s19pro")

    def test_plan_maps_mtd1_and_mtd4_only(self) -> None:
        plan = self._plan()
        parts = [entry["partition"] for entry in plan["write_plan"]]
        self.assertEqual(parts, ["mtd1", "mtd4"])
        for entry in plan["write_plan"]:
            self.assertEqual(entry["offset"], "0x0")

    def test_plan_pins_the_never_touch_boot_chain(self) -> None:
        joined = " ".join(self._plan()["never_touch"])
        self.assertIn("mtd0@0x0 (stock BOOT.bin)", joined)
        self.assertIn("mtd0@0x1A00000 (stock dtb)", joined)
        self.assertIn("mtd0@0x2000000 (stock uImage)", joined)

    def test_wrapped_size_includes_the_legacy_header(self) -> None:
        plan = self._plan()
        self.assertEqual(rss.UIMAGE_LEGACY_HEADER_BYTES, 64)
        self.assertEqual(
            plan["uimage"]["wrapped_size_bytes"],
            self.rootfs.stat().st_size + 64,
        )

    def test_fit_boundary(self) -> None:
        # wrapped = 4096 + 64 = 4160 bytes; windows must be KiB-aligned, so
        # an 8 KiB window fits while a 4 KiB window (4096 < 4160) refuses.
        wrapped = self.rootfs.stat().st_size + rss.UIMAGE_LEGACY_HEADER_BYTES
        self.assertGreater(wrapped, 4096)
        self.assertTrue(self._plan(window=8192)["window"]["wrapped_fits"])
        self.assertFalse(self._plan(window=4096)["window"]["wrapped_fits"])

    def test_non_squashfs_input_is_refused(self) -> None:
        plain = self.dir / "plain.bin"
        plain.write_bytes(b"\x00" * 4096)
        with self.assertRaises(SystemExit):
            rss.plan_payload(plain, "am2-s17p", 1 << 20)

    def test_lab_gates_list_backup_first_and_stock_restore(self) -> None:
        gates = " ".join(self._plan()["lab_gates"]).lower()
        self.assertIn("backup", gates)
        self.assertIn("/proc/mtd", gates)
        self.assertIn("stock restore", gates)

    def test_maturity_is_lab_gated_plan_only(self) -> None:
        self.assertIn("lab-gated", self._plan()["maturity"])
        self.assertIn("plan-only", self._plan()["maturity"])


if __name__ == "__main__":
    unittest.main()
