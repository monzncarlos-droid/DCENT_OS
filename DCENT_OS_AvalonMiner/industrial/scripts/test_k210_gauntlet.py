#!/usr/bin/env python3
"""Host-only tests for the Avalon K210 production-readiness gauntlet."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_gauntlet.py")
SPEC = importlib.util.spec_from_file_location("k210_gauntlet", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gauntlet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gauntlet)


def synthetic_aup() -> bytes:
    app = bytes(range(64))
    body_prefix = b"\x01" + struct.pack("<I", len(app)) + app
    payload = body_prefix + hashlib.sha256(body_prefix).digest()
    header = bytearray(200)
    header[:16] = gauntlet.AUP_MAGIC
    struct.pack_into("<I", header, 0x10, 2)
    struct.pack_into("<I", header, 0x14, len(payload))
    header[0x18 : 0x18 + len(b"test_firmware")] = b"test_firmware"
    struct.pack_into("<I", header, 0x58, zlib.crc32(payload) & 0xFFFFFFFF)
    struct.pack_into("<I", header, 0x5C, 1)
    struct.pack_into("<I", header, 0x60, 2)
    header[0x64 : 0x64 + len(b"MM_TEST_X3")] = b"MM_TEST_X3"
    header[0x84 : 0x84 + len(b"MM_TEST")] = b"MM_TEST"
    header[0xA4 : 0xA4 + len(b"MM_TEST_OOW")] = b"MM_TEST_OOW"
    struct.pack_into("<I", header, 196, zlib.crc32(header[:196]) & 0xFFFFFFFF)
    return bytes(header) + payload


def synthetic_photo_png(width: int = 640, height: int = 480) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    scanline = b"\x00" + b"\x60\x90\xc0" * width
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanline * height))
        + chunk(b"IEND", b"")
    )


class K210GauntletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = gauntlet.load_manifest()

    def test_manifest_has_dynamic_target_and_profile_coverage(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(len(self.manifest["targets"]), 21)
        self.assertEqual(len(self.manifest["firmware_profiles"]), 12)
        transport = self.manifest["update_transport_contract"]
        self.assertEqual(transport["state"], "verified_offline_reference")
        self.assertEqual(transport["default_page_bytes"], 888)
        self.assertIn("0,upgrade", transport["api_command"])
        runtime = self.manifest["runtime_contract"]
        self.assertEqual(runtime["state"], "no_std_policy_core_and_safe_idle_pipeline")
        self.assertEqual(runtime["freestanding_target"], "riscv64gc-unknown-none-elf")
        runtime_result = gauntlet.verify_runtime_contract(self.manifest)
        self.assertEqual(runtime_result["state"], "verified")
        self.assertEqual(
            runtime_result["gate_ids"],
            [gate["id"] for gate in self.manifest["production_gates"]],
        )
        self.assertFalse(runtime_result["mutation_allow_variant"])
        self.assertEqual(
            runtime_result["safety_supervisor"], runtime["safety_supervisor"]
        )
        discovery_result = gauntlet.verify_discovery_contract(self.manifest)
        self.assertEqual(discovery_result["state"], "verified_schema_no_trust_anchor")
        self.assertFalse(discovery_result["receipt_admission_enabled"])
        self.assertIsNone(discovery_result["observer_key_id_sha256"])
        recovery_result = gauntlet.verify_recovery_contract(self.manifest)
        self.assertEqual(recovery_result["state"], "verified_schema_no_trust_anchors")
        self.assertFalse(recovery_result["receipt_admission_enabled"])
        self.assertIsNone(recovery_result["operator_key_id_sha256"])
        boot_policy_result = gauntlet.verify_boot_policy_contract(self.manifest)
        self.assertEqual(
            boot_policy_result["state"], "verified_schema_no_trust_anchors"
        )
        self.assertFalse(boot_policy_result["receipt_admission_enabled"])
        self.assertIsNone(boot_policy_result["operator_key_id_sha256"])
        matrix = gauntlet.matrix_payload(self.manifest)
        self.assertEqual(len(matrix["include"]), len(self.manifest["targets"]))
        self.assertEqual(
            {row["model"] for row in matrix["include"]},
            {row["id"] for row in self.manifest["targets"]},
        )

    def test_every_held_profile_is_assigned_and_every_target_is_fail_closed(
        self,
    ) -> None:
        profile_ids = {row["id"] for row in self.manifest["firmware_profiles"]}
        assigned = {
            row["stock_profile"]
            for row in self.manifest["targets"]
            if row["stock_profile"]
        }
        self.assertEqual(assigned, profile_ids)
        report = gauntlet.build_report(self.manifest, corpus_policy="skip")
        self.assertEqual(report["counts"]["production_ready"], 0)
        self.assertEqual(report["counts"]["verified_discovery_receipts"], 0)
        self.assertEqual(report["counts"]["verified_recovery_receipts"], 0)
        self.assertEqual(report["counts"]["verified_boot_policy_receipts"], 0)
        self.assertEqual(
            report["update_transport_contract"]["state"], "verified_offline_reference"
        )
        self.assertEqual(
            report["runtime_contract"]["state"],
            "no_std_policy_core_and_safe_idle_pipeline",
        )
        self.assertTrue(
            all(
                model["gates"]["replacement_firmware"]["state"]
                == "packaged_safe_idle_pipeline_sentinel_only"
                for model in report["models"]
            )
        )
        self.assertTrue(
            all(
                model["gates"]["thermal_power_safety"]["state"]
                == "generic_fail_closed_supervisor_only"
                for model in report["models"]
            )
        )
        self.assertTrue(
            all(
                model["gates"]["asic_control"]["state"] == "not_implemented"
                for model in report["models"]
            )
        )
        self.assertTrue(
            all(not model["production_ready"] for model in report["models"])
        )
        for model in report["models"]:
            self.assertEqual(
                model["runtime_contract"],
                "generic_safety_supervisor_and_packaged_safe_idle_pipeline_not_hardware_authority",
            )
            self.assertEqual(
                list(model["gates"]),
                [gate["id"] for gate in self.manifest["production_gates"]],
            )
            self.assertTrue(
                all(not gate["qualifies"] for gate in model["gates"].values())
            )

    def test_signed_discovery_advances_only_exact_identity(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.skipTest("OpenSSH ssh-keygen is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_root = root / "source-evidence"
            evidence_root.mkdir()
            capture = gauntlet.discovery._template(self.manifest, "a1246")
            capture["observer_id"] = "gauntlet-test-observer"
            capture["capture_session_id"] = "7b624544-cb80-4bd1-9e58-c97a9d8d1559"
            capture["unit_label"] = "a1246-unit-001"
            capture["authorization"]["operator_reference"] = (
                "test-read-only-authorization-001"
            )
            profile = next(
                row
                for row in self.manifest["firmware_profiles"]
                if row["id"] == "a1246-a3201-2hash"
            )
            capture["identity"] = {
                "asic_family": "A3201-Plus",
                "controller_board_model": "MM3v2",
                "controller_board_revision": "rev-2.1",
                "controller_serial": "controller-001",
                "controller_soc": "K210",
                "cooling_class": "air",
                "cooling_controller": "stock-fan-controller",
                "fan_or_pump_count": 4,
                "hashboard_count": 2,
                "hashboard_identifiers": ["hashboard-001", "hashboard-002"],
                "manufacturer": "Canaan",
                "marketing_model": "AvalonMiner A1246",
                "miner_serial": "miner-a1246-001",
                "psu_model": "P3600W",
                "psu_rated_watts": 3600,
                "psu_serial": "psu-001",
                "stock_dna": "dna-a1246-001",
                "stock_firmware_version": profile["firmware_version"],
                "stock_hwtype": profile["hw_list"][0],
                "stock_swtype": profile["sw_list"][0],
            }
            for item in capture["evidence"]:
                if item["kind"] in gauntlet.discovery.PHOTO_KINDS:
                    item["media_type"] = "image/png"
                    item["path"] = item["path"].removesuffix(".jpg") + ".png"
                    content = synthetic_photo_png()
                elif item["kind"] == "stock_version_response":
                    content = json.dumps(
                        {
                            "STATUS": [{"Status": "S"}],
                            "VERSION": [
                                {
                                    "VERSION": profile["firmware_version"],
                                    "HWTYPE": profile["hw_list"][0],
                                    "SWTYPE": profile["sw_list"][0],
                                    "PROD": "AvalonMiner A1246",
                                    "DNA": "dna-a1246-001",
                                    "MAC": "02:00:00:00:00:01",
                                    "UPAPI": 5,
                                }
                            ],
                        }
                    ).encode("ascii")
                elif item["kind"] == "stock_stats_response":
                    content = json.dumps(
                        {
                            "STATUS": [{"Status": "S"}],
                            "STATS": [
                                {
                                    "MM Count": 2,
                                    "MM ID0": "module-0",
                                    "MM ID1": "module-1",
                                }
                            ],
                        }
                    ).encode("ascii")
                elif item["kind"] == "hashboard_topology_record":
                    content = json.dumps(
                        {
                            "hashboard_count": 2,
                            "hashboard_identifiers": [
                                "hashboard-001",
                                "hashboard-002",
                            ],
                        }
                    ).encode("ascii")
                else:
                    content = json.dumps(
                        {
                            "session": "gauntlet test read-only discovery",
                            "operator": "gauntlet-test-operator",
                            "authorization_reference": "test-read-only-authorization-001",
                            "events": [
                                {
                                    "time_utc": "2026-01-01T00:05:00Z",
                                    "event": "completed deenergized_visual_inspection_power_down, visual_identity_inspection, closed_chassis_stock_power_restoration, and stock_read_only_management_queries",
                                }
                            ],
                            "stopped_reason": None,
                            "anomalies": [],
                        }
                    ).encode("ascii")
                source = evidence_root / item["path"]
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(content)
            capture_path = root / "capture.json"
            capture_path.write_text(json.dumps(capture), encoding="ascii")

            private_key = root / "observer"
            key_process = subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "gauntlet-test@invalid",
                    "-f",
                    str(private_key),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(
                key_process.returncode,
                0,
                key_process.stderr.decode(errors="replace"),
            )
            public_key = Path(f"{private_key}.pub")
            bundle = root / "bundle"
            gauntlet.discovery.create_bundle(
                self.manifest,
                capture_path,
                evidence_root,
                private_key,
                bundle,
            )

            repository = root / "repository"
            verifier = repository / self.manifest["discovery_contract"]["verifier"]
            verifier.parent.mkdir(parents=True)
            shutil.copyfile(gauntlet.discovery.__file__, verifier)
            pinned_key = repository / "trust" / "k210-observer.pub"
            pinned_key.parent.mkdir()
            shutil.copyfile(public_key, pinned_key)
            key_id = gauntlet.discovery.inspect_public_key(pinned_key)["key_id_sha256"]
            manifest = deepcopy(self.manifest)
            manifest["discovery_contract"]["state"] = (
                "signed_read_only_receipt_admission"
            )
            manifest["discovery_contract"]["trust_anchor"] = {
                "key_id_sha256": key_id,
                "path": "trust/k210-observer.pub",
                "role": gauntlet.discovery.SIGNER_ROLE,
            }
            gauntlet.validate_manifest(manifest)
            results = gauntlet.verify_discovery_bundles(manifest, [bundle], repository)
            self.assertEqual(set(results), {"a1246"})

            profiles = gauntlet.verify_profiles(manifest, corpus_policy="skip")
            target = next(row for row in manifest["targets"] if row["id"] == "a1246")
            model = gauntlet.evaluate_target(
                manifest, target, profiles, results["a1246"]
            )
            self.assertTrue(model["gates"]["exact_model_identity"]["qualifies"])
            self.assertEqual(
                model["gates"]["exact_model_identity"]["state"],
                "signed_exact_unit_discovery",
            )
            self.assertEqual(model["first_blocker"], "stock_restore")
            self.assertEqual(model["stock_profile"], "a1246-a3201-2hash")
            self.assertIn(
                "variant-profile:a1246-a3201-2hash",
                model["gates"]["exact_model_identity"]["evidence"],
            )
            self.assertFalse(model["production_ready"])
            self.assertTrue(
                all(
                    not gate["qualifies"]
                    for gate_id, gate in model["gates"].items()
                    if gate_id != "exact_model_identity"
                )
            )
            self.assertFalse(model["unit_discovery"]["authority_granted"])

    def test_unanchored_manifest_rejects_supplied_discovery_bundle(self) -> None:
        with self.assertRaisesRegex(gauntlet.GauntletError, "observer key is pinned"):
            gauntlet.verify_discovery_bundles(self.manifest, [Path("untrusted-bundle")])

    def test_unanchored_manifest_rejects_supplied_recovery_bundle(self) -> None:
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "operator and witness keys are pinned"
        ):
            gauntlet.verify_recovery_bundles(
                self.manifest, [Path("untrusted-bundle")], {}
            )

    def test_unanchored_manifest_rejects_supplied_rollback_bundle(self) -> None:
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "operator and witness keys are pinned"
        ):
            gauntlet.verify_rollback_bundles(
                self.manifest, [Path("untrusted-bundle")], {}, {}, {}, {}
            )

    def test_unanchored_manifest_rejects_supplied_bench_endurance_bundle(
        self,
    ) -> None:
        with self.assertRaisesRegex(gauntlet.GauntletError, "all seven stage keys"):
            gauntlet.verify_bench_endurance_bundles(
                self.manifest,
                [Path("untrusted-first-light")],
                [],
                [],
                {},
                {},
                {},
                {},
                {},
                {},
                {},
            )

    def test_unanchored_manifest_rejects_supplied_release_preauthorization(
        self,
    ) -> None:
        with self.assertRaisesRegex(gauntlet.GauntletError, "all four release keys"):
            gauntlet.verify_release_preauthorization_bundles(
                self.manifest, [Path("untrusted-preauthorization")], {}
            )

    def test_rollback_receipt_advances_only_rollback_gate(self) -> None:
        target = next(row for row in self.manifest["targets"] if row["id"] == "a1346")
        profiles = gauntlet.verify_profiles(self.manifest, corpus_policy="skip")

        def sha(character: str) -> str:
            return character * 64

        discovery_result = {
            "authority_granted": False,
            "identity_gate_eligible": True,
            "observer_key_id_sha256": sha("a"),
            "receipt_id": sha("1"),
            "state": "verified_signed_exact_unit_discovery",
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("2"),
            "unit_label": "unit-a1346-1",
        }
        recovery_result = {
            "authority_granted": False,
            "discovery_receipt_id": sha("1"),
            "operator_key_id_sha256": sha("b"),
            "receipt_id": sha("3"),
            "state": "verified_signed_stock_recovery",
            "stock_backup_set_sha256": sha("4"),
            "stock_restore_gate_eligible": True,
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("2"),
            "witness_key_id_sha256": sha("c"),
        }
        boot_result = {
            "authority_granted": False,
            "boot_policy_gate_eligible": True,
            "candidate_load_contract_compatible": True,
            "discovery_receipt_id": sha("1"),
            "flash_policy_sha256": sha("5"),
            "force_decrypt_state": "disabled",
            "jtag_state": "locked",
            "plaintext_boot_supported": True,
            "plaintext_probe_performed": True,
            "plaintext_probe_result": "booted",
            "receipt_id": sha("6"),
            "recovery_receipt_id": sha("3"),
            "rom_isp_state": "locked",
            "state": "verified_signed_boot_policy_measurement",
            "stock_backup_set_sha256": sha("4"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("2"),
        }
        replacement_result = {
            "artifact_set_sha256": sha("7"),
            "authority_granted": False,
            "boot_policy_receipt_id": sha("6"),
            "builder_key_id_sha256": sha("d"),
            "discovery_receipt_id": sha("1"),
            "interface_qualification_sha256": sha("8"),
            "receipt_id": sha("9"),
            "recovery_receipt_id": sha("3"),
            "replacement_firmware_gate_eligible": True,
            "reviewer_key_id_sha256": sha("e"),
            "route_adjudication_sha256": sha("f"),
            "selected_route": "native_aes0_flash",
            "state": "verified_signed_route_replacement_firmware",
            "stock_backup_set_sha256": sha("4"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("2"),
        }
        rollback_result = {
            "artifact_set_sha256": sha("7"),
            "authority_granted": False,
            "boot_policy_receipt_id": sha("6"),
            "discovery_receipt_id": sha("1"),
            "interface_qualification_sha256": sha("8"),
            "no_clobber_sha256": sha("6"),
            "operator_key_id_sha256": sha("0"),
            "receipt_id": sha("a"),
            "recovery_receipt_id": sha("3"),
            "route_replacement_receipt_id": sha("9"),
            "rollback_recovery_gate_eligible": True,
            "route_adjudication_sha256": sha("f"),
            "selected_route": "native_aes0_flash",
            "state": "verified_signed_route_rollback",
            "stock_backup_set_sha256": sha("4"),
            "stock_restoration_sha256": sha("c"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("2"),
            "witness_key_id_sha256": sha("d"),
        }
        model = gauntlet.evaluate_target(
            self.manifest,
            target,
            profiles,
            discovery_result=discovery_result,
            recovery_result=recovery_result,
            boot_policy_result=boot_result,
            replacement_result=replacement_result,
            rollback_result=rollback_result,
        )
        self.assertTrue(model["gates"]["rollback_recovery"]["qualifies"])
        self.assertFalse(model["gates"]["asic_control"]["qualifies"])
        self.assertFalse(model["production_ready"])

    def test_staged_receipts_advance_asic_safety_bench_and_endurance_gates(
        self,
    ) -> None:
        target = next(row for row in self.manifest["targets"] if row["id"] == "a1346")
        profiles = gauntlet.verify_profiles(self.manifest, corpus_policy="skip")

        def sha(character: str) -> str:
            return character * 64

        discovery_result = {
            "authority_granted": False,
            "identity_gate_eligible": True,
            "observer_key_id_sha256": sha("1"),
            "receipt_id": sha("2"),
            "state": "verified_signed_exact_unit_discovery",
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "unit_label": "unit-a1346-stage",
        }
        fixture_result = {
            "authority_granted": False,
            "controller_board_revision": "revision-a",
            "discovery_receipt_id": sha("2"),
            "fixture_evidence_set_sha256": sha("4"),
            "fixture_qualification_eligible": True,
            "receipt_id": sha("5"),
            "state": "verified_signed_fixture_qualification",
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "variant_profile_id": "a1346-v1",
        }
        capture_result = {
            "authority_granted": False,
            "capture_set_sha256": sha("6"),
            "discovery_receipt_id": sha("2"),
            "fixture_evidence_set_sha256": sha("4"),
            "fixture_receipt_id": sha("5"),
            "p1_capture_admission_eligible": True,
            "receipt_id": sha("7"),
            "state": "verified_signed_p1_passive_capture",
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "wire_contract_claimed": False,
        }
        recovery_result = {
            "authority_granted": False,
            "discovery_receipt_id": sha("2"),
            "operator_key_id_sha256": sha("4"),
            "receipt_id": sha("8"),
            "state": "verified_signed_stock_recovery",
            "stock_backup_set_sha256": sha("9"),
            "stock_restore_gate_eligible": True,
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "witness_key_id_sha256": sha("5"),
        }
        boot_result = {
            "authority_granted": False,
            "boot_policy_gate_eligible": True,
            "candidate_load_contract_compatible": True,
            "discovery_receipt_id": sha("2"),
            "flash_policy_sha256": sha("a"),
            "force_decrypt_state": "disabled",
            "jtag_state": "locked",
            "operator_key_id_sha256": sha("6"),
            "plaintext_boot_supported": True,
            "plaintext_probe_performed": True,
            "plaintext_probe_result": "booted",
            "receipt_id": sha("b"),
            "recovery_receipt_id": sha("8"),
            "rom_isp_state": "locked",
            "state": "verified_signed_boot_policy_measurement",
            "stock_backup_set_sha256": sha("9"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "witness_key_id_sha256": sha("7"),
        }
        replacement_result = {
            "artifact_set_sha256": sha("c"),
            "authority_granted": False,
            "boot_policy_receipt_id": sha("b"),
            "builder_key_id_sha256": sha("1"),
            "discovery_receipt_id": sha("2"),
            "installed_artifact_sha256": sha("d"),
            "interface_qualification_sha256": sha("e"),
            "receipt_id": sha("f"),
            "recovery_receipt_id": sha("8"),
            "replacement_firmware_gate_eligible": True,
            "replacement_firmware_version": "20260824_dcent_stage",
            "reviewer_key_id_sha256": sha("2"),
            "route_adjudication_sha256": sha("0"),
            "selected_route": "native_aes0_flash",
            "state": "verified_signed_route_replacement_firmware",
            "stock_backup_set_sha256": sha("9"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
        }
        rollback_result = {
            "artifact_set_sha256": sha("c"),
            "authority_granted": False,
            "boot_policy_receipt_id": sha("b"),
            "discovery_receipt_id": sha("2"),
            "interface_qualification_sha256": sha("e"),
            "no_clobber_sha256": sha("1"),
            "operator_key_id_sha256": sha("3"),
            "receipt_id": sha("a"),
            "recovery_receipt_id": sha("8"),
            "rollback_recovery_gate_eligible": True,
            "route_adjudication_sha256": sha("0"),
            "route_replacement_receipt_id": sha("f"),
            "selected_route": "native_aes0_flash",
            "state": "verified_signed_route_rollback",
            "stock_backup_set_sha256": sha("9"),
            "stock_restoration_sha256": sha("2"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "witness_key_id_sha256": sha("4"),
        }
        common_stage = {
            "artifact_set_sha256": sha("c"),
            "authority_granted": False,
            "boot_policy_receipt_id": sha("b"),
            "capture_receipt_id": sha("7"),
            "capture_set_sha256": sha("6"),
            "controller_board_revision": "revision-a",
            "discovery_receipt_id": sha("2"),
            "installed_artifact_sha256": sha("d"),
            "interface_qualification_sha256": sha("e"),
            "no_clobber_sha256": sha("1"),
            "outcome": "passed",
            "recovery_receipt_id": sha("8"),
            "replacement_firmware_version": "20260824_dcent_stage",
            "route_adjudication_sha256": sha("0"),
            "route_replacement_receipt_id": sha("f"),
            "route_rollback_receipt_id": sha("a"),
            "selected_route": "native_aes0_flash",
            "stock_backup_set_sha256": sha("9"),
            "stock_restoration_sha256": sha("2"),
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "unit_label": "unit-a1346-stage",
            "variant_profile_id": "a1346-v1",
            "fixture_receipt_id": sha("5"),
            "fixture_evidence_set_sha256": sha("4"),
        }
        first_light_result = {
            **common_stage,
            "bench_mining_gate_eligible": False,
            "endurance_faults_gate_eligible": False,
            "evidence_set_sha256": sha("3"),
            "first_light_gate_eligible": True,
            "operator_key_id_sha256": sha("4"),
            "prior_stage_evidence_set_sha256": None,
            "prior_stage_receipt_id": None,
            "protocol_reviewer_key_id_sha256": sha("5"),
            "qualification_class": "first_light",
            "receipt_id": sha("4"),
            "safety_reviewer_key_id_sha256": sha("6"),
            "state": "verified_staged_first_light",
            "witness_key_id_sha256": None,
        }
        bench_result = {
            **common_stage,
            "bench_mining_gate_eligible": True,
            "endurance_faults_gate_eligible": False,
            "evidence_set_sha256": sha("5"),
            "first_light_gate_eligible": True,
            "operator_key_id_sha256": sha("7"),
            "prior_stage_evidence_set_sha256": sha("3"),
            "prior_stage_receipt_id": sha("4"),
            "protocol_reviewer_key_id_sha256": None,
            "qualification_class": "bounded_bench_mining",
            "receipt_id": sha("5"),
            "safety_reviewer_key_id_sha256": None,
            "state": "verified_bounded_first_light_and_bench_mining",
            "witness_key_id_sha256": sha("8"),
        }
        endurance_result = {
            **common_stage,
            "bench_mining_gate_eligible": True,
            "endurance_faults_gate_eligible": True,
            "evidence_set_sha256": sha("6"),
            "first_light_gate_eligible": True,
            "operator_key_id_sha256": sha("9"),
            "prior_stage_evidence_set_sha256": sha("5"),
            "prior_stage_receipt_id": sha("5"),
            "protocol_reviewer_key_id_sha256": None,
            "qualification_class": "fault_endurance",
            "receipt_id": sha("6"),
            "safety_reviewer_key_id_sha256": None,
            "state": "verified_fault_and_endurance_qualification",
            "witness_key_id_sha256": sha("a"),
        }
        arguments = {
            "discovery_result": discovery_result,
            "fixture_result": fixture_result,
            "capture_result": capture_result,
            "recovery_result": recovery_result,
            "boot_policy_result": boot_result,
            "replacement_result": replacement_result,
            "rollback_result": rollback_result,
            "first_light_result": first_light_result,
            "bench_result": bench_result,
            "endurance_result": endurance_result,
        }
        model = gauntlet.evaluate_target(self.manifest, target, profiles, **arguments)
        for gate_id in (
            "asic_control",
            "thermal_power_safety",
            "bench_mining",
            "endurance_faults",
        ):
            self.assertTrue(model["gates"][gate_id]["qualifies"])
        self.assertFalse(model["gates"]["release_authority"]["qualifies"])
        self.assertFalse(model["production_ready"])

        preauthorization_result = {
            "artifact_set_sha256": sha("c"),
            "authority_granted": False,
            "endurance_evidence_set_sha256": sha("6"),
            "endurance_receipt_id": sha("6"),
            "firmware_version": "20260824_dcent_stage",
            "generic_future_authority_granted": False,
            "hardware_revision": "revision-a",
            "install_authority_scope_eligible": True,
            "installed_artifact_sha256": sha("d"),
            "interface_qualification_sha256": sha("e"),
            "no_clobber_sha256": sha("1"),
            "preauthorization_id": sha("7"),
            "preauthorization_sha256": sha("8"),
            "release_scope_sha256": sha("9"),
            "route_adjudication_sha256": sha("0"),
            "route_replacement_receipt_id": sha("f"),
            "selected_route": "native_aes0_flash",
            "state": "verified_exact_scope_preauthorization",
            "target_id": "a1346",
            "unit_fingerprint_sha256": sha("3"),
            "unit_label": "unit-a1346-stage",
            "variant_profile_id": "a1346-v1",
        }
        release_result = {
            **common_stage,
            "controller_board_revision": "revision-a",
            "endurance_evidence_set_sha256": sha("6"),
            "endurance_receipt_id": sha("6"),
            "evidence_set_sha256": sha("8"),
            "exact_scope_release_admitted": True,
            "firmware_version": "20260824_dcent_stage",
            "generic_future_authority_granted": False,
            "installer_key_id_sha256": sha("b"),
            "preauthorization_id": sha("7"),
            "preauthorization_sha256": sha("8"),
            "preauthorizer_key_id_sha256": sha("c"),
            "prior_bench_evidence_set_sha256": sha("5"),
            "prior_bench_receipt_id": sha("5"),
            "receipt_id": sha("7"),
            "release_authority_gate_eligible": True,
            "release_scope_sha256": sha("9"),
            "reviewer_key_id_sha256": sha("d"),
            "state": "verified_exact_scope_release_capstone",
            "witness_key_id_sha256": sha("e"),
        }
        arguments["release_preauthorization_result"] = preauthorization_result
        arguments["release_result"] = release_result
        released = gauntlet.evaluate_target(
            self.manifest, target, profiles, **arguments
        )
        self.assertTrue(released["gates"]["release_authority"]["qualifies"])
        self.assertTrue(released["production_ready"])
        self.assertEqual(released["first_blocker"], "none")

        spliced = dict(endurance_result)
        spliced["prior_stage_receipt_id"] = sha("7")
        arguments["endurance_result"] = spliced
        with self.assertRaisesRegex(gauntlet.GauntletError, "prior stage"):
            gauntlet.evaluate_target(self.manifest, target, profiles, **arguments)

    def test_held_corpus_is_all_verified_or_all_absent(self) -> None:
        results = gauntlet.verify_profiles(self.manifest, corpus_policy="auto")
        states = {result["state"] for result in results.values()}
        self.assertIn(states, ({"verified"}, {"absent"}))
        if states == {"verified"}:
            self.assertTrue(
                all(result["held_bytes_verified"] for result in results.values())
            )

    def test_auto_mode_allows_a_clean_checkout_without_the_ignored_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = gauntlet.verify_profiles(
                self.manifest, repo_root=Path(directory), corpus_policy="auto"
            )
        self.assertEqual({result["state"] for result in results.values()}, {"absent"})
        self.assertTrue(
            all(not result["held_bytes_verified"] for result in results.values())
        )

    def test_synthetic_aup_verifies_all_integrity_layers(self) -> None:
        observed = gauntlet.inspect_aup_bytes(synthetic_aup())
        self.assertEqual(observed["fmt_ver"], 2)
        self.assertEqual(observed["firmware_version"], "test_firmware")
        self.assertEqual(observed["hw_list"], ["MM_TEST_X3"])
        self.assertEqual(observed["sw_list"], ["MM_TEST", "MM_TEST_OOW"])
        self.assertEqual(observed["aes_enable"], 1)
        self.assertEqual(observed["k210_app_size"], 64)

    def test_plain_candidate_package_is_deterministic_and_self_verifying(self) -> None:
        app = bytes(range(251)) * 3
        first, receipt = gauntlet.build_candidate_package(
            self.manifest, "a1346", app, "20260823_dcent_safe-idle"
        )
        second, second_receipt = gauntlet.build_candidate_package(
            self.manifest, "a1346", app, "20260823_dcent_safe-idle"
        )
        self.assertEqual(first, second)
        self.assertEqual(receipt, second_receipt)
        observed = gauntlet.inspect_aup_bytes(first)
        self.assertEqual(observed["aes_enable"], 0)
        self.assertEqual(observed["k210_app_size"], len(app))
        self.assertEqual(observed["header_size"], 200)
        self.assertEqual(observed["hw_list"], ["MM4v1_X3"])
        self.assertEqual(observed["sw_list"], ["MM317", "MM317_OOW"])
        self.assertEqual(
            receipt["disposition"], "offline_candidate_not_authorized_for_install"
        )
        self.assertEqual(receipt["aup_sha256"], hashlib.sha256(first).hexdigest())

    def test_candidate_builder_rejects_nonphysical_or_unprofiled_rows(self) -> None:
        with self.assertRaisesRegex(gauntlet.GauntletError, "physical-model row"):
            gauntlet.build_candidate_package(
                self.manifest, "a14xi", b"app", "20260823_dcent_test"
            )
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "no held compatibility profile"
        ):
            gauntlet.build_candidate_package(
                self.manifest, "a1047", b"app", "20260823_dcent_test"
            )

    def test_candidate_builder_rejects_bad_version_and_oversized_app(self) -> None:
        with self.assertRaisesRegex(gauntlet.GauntletError, "firmware version"):
            gauntlet.build_candidate_package(self.manifest, "a1346", b"app", "latest")
        with self.assertRaisesRegex(gauntlet.GauntletError, "desk limit"):
            gauntlet.build_candidate_package(
                self.manifest,
                "a1346",
                b"x" * (gauntlet.CANDIDATE_MAX_APP_BYTES + 1),
                "20260823_dcent_test",
            )

    def test_candidate_cli_requires_explicit_aes0_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app.bin"
            app.write_bytes(b"candidate")
            code = gauntlet.main(
                [
                    "candidate",
                    "--model",
                    "a1346",
                    "--app-bin",
                    str(app),
                    "--firmware-version",
                    "20260823_dcent_test",
                    "--aup-out",
                    str(root / "candidate.aup"),
                    "--receipt-out",
                    str(root / "candidate.json"),
                ]
            )
            self.assertEqual(code, 2)
            self.assertFalse((root / "candidate.aup").exists())

    def test_aup_payload_corruption_is_rejected(self) -> None:
        corrupt = bytearray(synthetic_aup())
        corrupt[-33] ^= 0x01
        with self.assertRaisesRegex(gauntlet.GauntletError, "payload CRC mismatch"):
            gauntlet.inspect_aup_bytes(bytes(corrupt))

    def test_aup_header_corruption_is_rejected(self) -> None:
        corrupt = bytearray(synthetic_aup())
        corrupt[0x30] ^= 0x01
        with self.assertRaisesRegex(gauntlet.GauntletError, "header CRC mismatch"):
            gauntlet.inspect_aup_bytes(bytes(corrupt))

    def test_production_requirement_is_expected_red(self) -> None:
        code = gauntlet.main(
            [
                "--manifest",
                str(gauntlet.MANIFEST_PATH),
                "check",
                "--model",
                "a1346",
                "--corpus",
                "skip",
                "--require-production",
            ]
        )
        self.assertEqual(code, 3)

    def test_manifest_round_trips_as_strict_json(self) -> None:
        encoded = json.dumps(self.manifest, sort_keys=True)
        gauntlet.validate_manifest(json.loads(encoded))

    def test_manifest_rejects_unknown_top_level_contracts(self) -> None:
        manifest = deepcopy(self.manifest)
        manifest["shadow_release_contract"] = {}
        with self.assertRaisesRegex(gauntlet.GauntletError, "top-level fields"):
            gauntlet.validate_manifest(manifest)

    def test_manifest_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(gauntlet.GauntletError, "duplicate JSON key"):
                gauntlet.load_manifest(path)

    def test_manifest_rejects_cross_contract_anchor_reuse(self) -> None:
        anchors = {
            "alpha_contract": {
                "trust_anchor": {
                    "key_id_sha256": "1" * 64,
                    "path": "trust/alpha.pub",
                    "role": "alpha_signer",
                }
            },
            "beta_contract": {
                "trust_anchors": {
                    "reviewer": {
                        "key_id_sha256": "1" * 64,
                        "path": "trust/beta.pub",
                        "role": "beta_reviewer",
                    }
                }
            },
        }
        with self.assertRaisesRegex(gauntlet.GauntletError, "reuse key_id_sha256"):
            gauntlet._validate_global_anchor_separation(anchors)


if __name__ == "__main__":
    unittest.main()
