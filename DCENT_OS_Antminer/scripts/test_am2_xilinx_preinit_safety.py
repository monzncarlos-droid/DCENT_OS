#!/usr/bin/env python3
"""Focused tests for the host-only AM2 Xilinx pre-init analyzer."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
ANALYZER = SCRIPT_DIR / "analyze_am2_xilinx_preinit_safety.py"
SPEC = importlib.util.spec_from_file_location("am2_xilinx_preinit_safety", ANALYZER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Am2XilinxPreinitSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.s19j = MODULE.analyze(WORKSPACE_ROOT, "am2-s19j")
        cls.s19pro = MODULE.analyze(WORKSPACE_ROOT, "am2-s19pro")

    def test_exact_targets_have_narrow_proof_and_no_authority(self) -> None:
        for result in (self.s19j, self.s19pro):
            with self.subTest(target=result["target"]):
                self.assertEqual(result["schema"], MODULE.SCHEMA)
                self.assertEqual(
                    result["state"],
                    "resident-bundle-lineage-proven-whole-preinit-safety-blocked",
                )
                facets = result["proof_facets"]
                self.assertTrue(facets["exact_donor_media_and_members_verified"])
                self.assertTrue(facets["donor_handoff_no_persistent_writes_proven"])
                self.assertFalse(
                    facets["resident_pre_handoff_no_persistent_writes_proven"]
                )
                self.assertTrue(
                    facets[
                        "resident_bootgen_fsbl_uboot_bound_to_model_named_stock_package"
                    ]
                )
                self.assertFalse(facets["resident_bootrom_configuration_bound_to_target"])
                self.assertFalse(
                    facets[
                        "donor_handoff_invoked_by_identity_bound_resident_environment"
                    ]
                )
                self.assertFalse(facets["whole_pre_init_no_persistent_writes_proven"])
                self.assertFalse(facets["cold_boot_witnessed"])
                self.assertTrue(
                    all(value is False for value in result["authority"].values())
                )
                self.assertEqual(result["device_contact"], "none")
                self.assertEqual(result["network_contact"], "none")
                self.assertEqual(result["subprocess_execution"], "none")

    def test_targets_bind_different_boot_and_ramdisk_windows(self) -> None:
        j_loader = self.s19j["donor_execution_contract"]["loader"]
        p_loader = self.s19pro["donor_execution_contract"]["loader"]
        self.assertEqual(j_loader["target_marker_hex"], "6cb9dd")
        self.assertEqual(p_loader["target_marker_hex"], "419ddd")
        self.assertNotEqual(j_loader["encoded_sha256"], p_loader["encoded_sha256"])
        self.assertNotEqual(j_loader["decoded_sha256"], p_loader["decoded_sha256"])
        self.assertEqual(
            j_loader["normalized_decoded_sha256"],
            p_loader["normalized_decoded_sha256"],
        )
        j_update = next(
            item
            for item in self.s19j["donor_media"]["members"]
            if item["name"] == "update.image.gz"
        )
        p_update = next(
            item
            for item in self.s19pro["donor_media"]["members"]
            if item["name"] == "update.image.gz"
        )
        self.assertEqual(j_update["size"], 12_876_990)
        self.assertEqual(p_update["size"], 12_867_731)
        self.assertNotEqual(j_update["sha256"], p_update["sha256"])

    def test_loader_contract_is_exact_and_persistent_tokens_are_absent(self) -> None:
        loader = self.s19j["donor_execution_contract"]["loader"]
        self.assertEqual(
            loader["exact_commands"],
            [
                "fatload mmc 0 0x2000000 uImage",
                "fatload mmc 0 0x4000000 update.image.gz",
                "fatload mmc 0 0x3000000 devicetree.dtb",
                "bootm 0x2000000 0x4000000 0x3000000",
            ],
        )
        self.assertTrue(loader["rsa_locator_and_memory_patch_precede_load_and_boot"])
        self.assertTrue(loader["persistent_write_tokens_absent"])
        self.assertIn("saveenv", loader["persistent_write_tokens_checked"])
        self.assertIn("nand erase", loader["persistent_write_tokens_checked"])

    def test_related_resident_capture_exposes_exact_write_reachability(self) -> None:
        related = self.s19j["related_resident_evidence"]
        self.assertIn(".139", related["lineage"])
        self.assertIn("identity-bound S19j Pro .25", related["lineage"])
        environment = related["environment_partition"]
        self.assertEqual(environment["bootcmd"], "run $modeboot")
        self.assertFalse(environment["modeboot_present"])
        self.assertFalse(environment["uenvcmd_present"])
        self.assertFalse(environment["sd_uenvcmd_present"])
        self.assertEqual(len(environment["banks"]), 2)
        self.assertEqual(
            {item["operation"] for item in related["pre_init_access_ledger"]},
            {
                "saveenv",
                "nand erase.part uboot_env",
                "setenv; env set",
                "env import -t",
                "nand read",
                "ubi part",
                "ubi read",
            },
        )
        blockers = {item["id"]: item for item in self.s19j["blocker_ledger"]}
        self.assertEqual(
            blockers["persistent-environment-state-dependent-writes"]["state"],
            "reachable-write-branches-observed",
        )
        self.assertIn("sd_uenvcmd", blockers["compiled-default-versus-persisted-selector-drift"]["detail"])
        self.assertEqual(
            blockers["resident-ubi-attach-side-effects"]["state"], "unproven"
        )

    def test_shared_stock_bootgen_lineage_is_exact(self) -> None:
        lineage = self.s19j["resident_boot_bundle_lineage"]
        packages = lineage["stock_packages"]
        self.assertEqual(
            [(item["physical_model"], item["firmware_epoch"]) for item in packages],
            [
                ("Antminer S19j Pro", "2021-05-15"),
                ("Antminer S19 Pro", "2020-06-01"),
                ("Antminer S19 Pro", "2022-12-26"),
            ],
        )
        self.assertEqual(
            {item["first_component_sha256"] for item in packages},
            {MODULE.STOCK_BOOTGEN_SHA256},
        )
        self.assertTrue(lineage["all_stock_package_components_byte_identical"])
        self.assertTrue(lineage["s19jpro_25_nand_prefix_byte_identical"])
        bootgen = lineage["bootgen_component"]
        self.assertEqual(bootgen["size"], 2_788_160)
        self.assertEqual(bootgen["sha256"], MODULE.STOCK_BOOTGEN_SHA256)
        self.assertEqual(
            [item["sha256"] for item in bootgen["partitions"]],
            [
                "42b1bcb12a018a7fea3d8f58ae8d9465765d960803b4c29f656ed6c8ab3ba257",
                "ba99e606632de9523a64c15bb6ef65faa5020ad1279dc5e29a32b9aafd1e8bff",
                "f547e56d1c6b0b7562acec789e797708e1f54b240250871f4544b56c0ca825cd",
            ],
        )
        self.assertTrue(
            all(
                item["rsa_authentication_certificate_flag_present"]
                for item in bootgen["partitions"]
            )
        )
        self.assertIn("not cryptographically verified", lineage["proof_scope"])

    def test_identity_bound_live_25_environment_refutes_donor_hook(self) -> None:
        live = self.s19j["identity_bound_s19jpro_25"]
        self.assertEqual(live["identity"]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(
            live["identity"]["disk_board_target"], "am2-s19jpro-xil"
        )
        environment = live["environment_partition"]
        self.assertEqual(
            [item["redundancy_flag"] for item in environment["banks"]],
            [151, 152],
        )
        self.assertEqual(environment["differing_keys"], ["firmware"])
        self.assertEqual(environment["observed_selected_firmware"], "2")
        self.assertEqual(environment["modeboot"], "nandboot")
        self.assertFalse(environment["sd_boot_present"])
        self.assertFalse(environment["uenvcmd_present"])
        self.assertFalse(environment["sd_uenvcmd_present"])
        self.assertTrue(environment["sdboot_invokes_only_sd_uenvcmd"])
        self.assertFalse(live["donor_uenv_invoked_by_persisted_selector"])
        blockers = {item["id"]: item for item in self.s19j["blocker_ledger"]}
        self.assertIn(
            "defines only uenvcmd",
            blockers["compiled-default-versus-persisted-selector-drift"]["detail"],
        )

    def test_s19pro_package_lineage_does_not_invent_live_environment(self) -> None:
        facets = self.s19pro["proof_facets"]
        self.assertFalse(facets["resident_environment_bound_to_target"])
        blockers = {item["id"]: item for item in self.s19pro["blocker_ledger"]}
        self.assertEqual(
            blockers["s19pro-active-environment-not-held"]["state"],
            "exact-capture-absent",
        )
        exhaustion = self.s19pro["evidence_exhaustion"]
        self.assertFalse(exhaustion["s19pro_identity_bound_environment_found"])
        self.assertFalse(exhaustion["cold_boot_uart_trace_found"])

    def test_stock_bmu_component_tamper_is_refused(self) -> None:
        package = MODULE.STOCK_PACKAGES[0]
        raw = bytearray((WORKSPACE_ROOT / package.path).read_bytes())
        raw[MODULE.BMU_HEADER_SIZE + 0x1700] ^= 1
        with self.assertRaisesRegex(MODULE.EvidenceError, "BOOT.bin digest"):
            MODULE._extract_single_bmu_boot(bytes(raw), package)

    def test_live_25_unexpected_environment_divergence_is_refused(self) -> None:
        raw = bytearray((WORKSPACE_ROOT / MODULE.LIVE_25_ENV_PATH).read_bytes())
        # The held banks differ only in firmware. Requiring identity must fail closed.
        with self.assertRaisesRegex(MODULE.EvidenceError, "banks disagree"):
            MODULE._parse_redundant_environment(bytes(raw))

    def test_environment_crc_tamper_is_refused(self) -> None:
        raw = bytearray(
            (
                WORKSPACE_ROOT
                / ""
            ).read_bytes()
        )
        raw[100] ^= 1
        with self.assertRaisesRegex(MODULE.EvidenceError, "CRC mismatch"):
            MODULE._parse_redundant_environment(bytes(raw))

    def test_loader_tamper_is_refused_before_semantic_claim(self) -> None:
        image = (
            WORKSPACE_ROOT / MODULE.PROFILES["am2-s19j"].source_path
        ).read_bytes()
        members, _layout = MODULE._parse_fat16(image, MODULE.PROFILES["am2-s19j"])
        boot = bytearray(members["BOOT.BIN"])
        boot[-1] ^= 1
        with self.assertRaisesRegex(MODULE.EvidenceError, "BOOT.BIN mismatch"):
            MODULE._decode_and_verify_loader(bytes(boot), MODULE.PROFILES["am2-s19j"])

    def test_hardlink_evidence_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            source.write_bytes(b"held evidence")
            alias = root / "alias.bin"
            os.link(source, alias)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaisesRegex(MODULE.EvidenceError, "exactly one hard link"):
                MODULE._read_regular_once(
                    root,
                    Path("source.bin"),
                    expected_size=source.stat().st_size,
                    expected_sha256=digest,
                    maximum_size=1024,
                )

    def test_symlink_evidence_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            source.write_bytes(b"held evidence")
            alias = root / "alias.bin"
            try:
                alias.symlink_to(source)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(MODULE.EvidenceError, "must not traverse a link"):
                MODULE._read_regular_once(
                    root,
                    Path("alias.bin"),
                    expected_size=source.stat().st_size,
                    expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                    maximum_size=1024,
                )

    def test_device_namespace_is_refused(self) -> None:
        for value in (Path("/dev/sda"), Path("/proc/self/mem"), Path("/sys/block")):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE._reject_device_or_remote_path(value, label="test")

    def test_analysis_performs_no_network_or_subprocess_contact(self) -> None:
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
            mock.patch.object(subprocess, "run", side_effect=AssertionError("process")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        ):
            result = MODULE.analyze(WORKSPACE_ROOT, "am2-s19pro")
        self.assertEqual(result["device_contact"], "none")

    def test_cli_emits_typed_json_without_output_path(self) -> None:
        output = io.StringIO()
        with mock.patch.object(sys, "stdout", output):
            status = MODULE.main(
                [
                    "--workspace-root",
                    os.fspath(WORKSPACE_ROOT),
                    "--target",
                    "am2-s19j",
                ]
            )
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["schema"], MODULE.SCHEMA)
        self.assertFalse(result["authority"]["operator_boot_authorized"])


if __name__ == "__main__":
    unittest.main()
