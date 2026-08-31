#!/usr/bin/env python3
"""Offline tests for the exact S19k AML factory recovery plan."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("s19k_aml_stock_recovery_plan.py")
SPEC = importlib.util.spec_from_file_location("s19k_aml_stock_recovery_plan", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class S19kAmlStockRecoveryPlanTests(unittest.TestCase):
    def _toc(self) -> bytes:
        toc = bytearray(MODULE.TOC_BYTES)
        struct.pack_into(
            "<IIIQII",
            toc,
            0,
            MODULE.AML_IMAGE_HEADER["crc"],
            MODULE.AML_IMAGE_HEADER["version"],
            MODULE.AML_IMAGE_HEADER["magic"],
            MODULE.AML_IMAGE_HEADER["image_bytes"],
            MODULE.AML_IMAGE_HEADER["item_align"],
            MODULE.AML_IMAGE_HEADER["item_count"],
        )
        return bytes(toc)

    def test_contract_pins_exact_archive_and_three_members(self) -> None:
        self.assertEqual(MODULE.ARCHIVE_BYTES, 23_470_887)
        self.assertEqual(
            MODULE.ARCHIVE_SHA256,
            "46214d02b3c246ad4f98bcbe50b83705392a23a9fa5007120cb21d033e98dcf4",
        )
        self.assertEqual(
            MODULE.MEMBERS,
            (
                "aml_sdc_burn.ini",
                "aml_sdc_burn.UBOOT.ENC",
                "aml_upgrade_package_enc.img",
            ),
        )

    def test_ini_parser_rejects_duplicates_conflicts_and_wrong_sections(self) -> None:
        good = b"""; held comments\n[common]\nerase_bootloader =1\nerase_flash=1\nreboot=1\n[burn_ex]\npackage=aml_upgrade_package_enc.img\n;media=\n"""
        parsed = MODULE._parse_exact_ini(good)
        self.assertEqual(parsed["common.erase_bootloader"], "1")
        bad = (
            good.replace(b"erase_bootloader =1", b"erase_bootloader =1\nerase_bootloader=0"),
            good.replace(b"reboot=1", b"reboot=0"),
            good.replace(b"[burn_ex]\npackage", b"package"),
            good.replace(b"[burn_ex]", b"[other]"),
            good.replace(b"erase_flash=1", b"erase_flash=1\nunknown=1"),
        )
        for malformed in bad:
            with self.assertRaises(MODULE.RecoveryMediaError):
                MODULE._parse_exact_ini(malformed)

    def test_toc_parser_requires_exact_semantics_and_hash(self) -> None:
        # A structurally correct synthetic TOC is still rejected because the
        # complete held 11008-byte TOC hash is part of identity.
        with self.assertRaisesRegex(MODULE.RecoveryMediaError, "TOC hash"):
            MODULE._parse_exact_aml_header(self._toc())
        mutated = bytearray(self._toc())
        struct.pack_into("<I", mutated, 8, 0xDEADBEEF)
        with self.assertRaisesRegex(MODULE.RecoveryMediaError, "header"):
            MODULE._parse_exact_aml_header(bytes(mutated))

    def test_wrong_archive_never_yields_a_plan(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            candidate = Path(raw_temp) / MODULE.ARCHIVE_NAME
            with zipfile.ZipFile(candidate, "w") as archive:
                for member in MODULE.MEMBERS:
                    archive.writestr(member, b"wrong")
            with self.assertRaisesRegex(MODULE.RecoveryMediaError, "byte length"):
                MODULE.validate_archive(candidate)

    def test_plan_is_irreversibly_offline_and_not_raw_restore(self) -> None:
        plan = MODULE.render_plan(
            Path(MODULE.ARCHIVE_NAME),
            {"archive_sha256": MODULE.ARCHIVE_SHA256, "members": list(MODULE.MEMBERS)},
        )
        self.assertFalse(plan["execute"])
        self.assertFalse(plan["clear_for_flash"])
        self.assertFalse(plan["linux_raw_restore_equivalent"])
        self.assertEqual(plan["transport"], "physical-amlogic-sd-burn")
        self.assertIn("full-logical-rescue/v1", plan["required_preburn_backup"])
        self.assertIn("FULL_RESCUE_LEDGER.txt", plan["bench_sequence"][0])
        self.assertIn("stable-badblock-counts", plan["required_preburn_backup"])
        self.assertIn("boot-nand-transcript", plan["required_preburn_backup"])
        self.assertFalse(plan["preburn_backup_is_physical_replay"])
        self.assertIn("calibration-import", plan["required_unit_state_restore"])
        self.assertNotIn("empty-badmap", plan["required_preburn_backup"])
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("paramiko", "subprocess", "nandwrite", "flash_erase", "gpio437"):
            self.assertNotIn(forbidden, source)

    def test_held_archive_if_present(self) -> None:
        held = (
            SCRIPT.parents[3]
            / "knowledge-base"
            / "firmware-archive"
            / "vnish-farm-2026-05-01"
            / "stock"
            / "x19"
            / "s19kpro"
            / MODULE.ARCHIVE_NAME
        )
        if not held.is_file():
            self.skipTest("optional held firmware corpus is absent")
        evidence = MODULE.validate_archive(held)
        plan = MODULE.render_plan(held, evidence)
        self.assertEqual(plan["archive_sha256"], MODULE.ARCHIVE_SHA256)
        self.assertEqual(plan["classification"], "vendor-encrypted-amlogic-sd-full-erase-stock-return")


if __name__ == "__main__":
    unittest.main()
