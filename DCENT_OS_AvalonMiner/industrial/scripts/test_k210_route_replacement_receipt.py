#!/usr/bin/env python3
"""Tests for route-discriminated K210 replacement artifact receipts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_route_replacement_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_route_replacement_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
route_replacement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(route_replacement)

BOOT_TEST_SCRIPT = Path(__file__).with_name("test_k210_boot_policy_receipt.py")
BOOT_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_boot_fixture_for_route_replacement", BOOT_TEST_SCRIPT
)
assert BOOT_TEST_SPEC is not None and BOOT_TEST_SPEC.loader is not None
boot_test = importlib.util.module_from_spec(BOOT_TEST_SPEC)
BOOT_TEST_SPEC.loader.exec_module(boot_test)


def synthetic_elf(raw: bytes, load_address: int) -> bytes:
    data = bytearray(120 + len(raw))
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, route_replacement.v1.ELF_MACHINE_RISCV, 1)
    struct.pack_into("<QQQ", data, 24, load_address, 64, 0)
    struct.pack_into("<HHHHHH", data, 52, 64, 56, 1, 0, 0, 0)
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        route_replacement.v1.ELF_PT_LOAD,
        5,
        120,
        load_address,
        load_address,
        len(raw),
        len(raw),
        8,
    )
    data[120:] = raw
    return bytes(data)


class K210RouteReplacementReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        boot_test.K210BootPolicyReceiptTests.setUpClass()

    def setUp(self) -> None:
        self.fixture = boot_test.K210BootPolicyReceiptTests(methodName="runTest")
        self.fixture.setUp()
        self.fixture._make_positive()
        self.root = self.fixture.root
        self.manifest = self.fixture.manifest
        self.recovery_fixture = self.fixture.fixture
        self.builder_private, self.builder_public = self.recovery_fixture._new_key(
            "route-builder"
        )
        self.reviewer_private, self.reviewer_public = self.recovery_fixture._new_key(
            "route-reviewer"
        )
        self.evidence_root = self.root / "route-replacement-evidence"
        self.evidence_root.mkdir()
        self.descriptor_path = self.root / "route-replacement-descriptor.json"

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _configure_boot_route(self, route: str) -> None:
        if route == "rom_isp_sram_bootstrap":
            self.fixture.descriptor["rom_isp_policy"].update(
                {
                    "erase_capable": True,
                    "existing_flash_independent": True,
                    "read_capable": True,
                    "state": "accessible",
                    "write_capable": True,
                }
            )
        elif route == "jtag_sram_bootstrap":
            self.fixture.descriptor["jtag_policy"].update(
                {
                    "halt_capable": True,
                    "idcode": "0x04e4796b",
                    "read_memory_capable": True,
                    "state": "accessible",
                    "write_memory_capable": True,
                }
            )

    def _add(
        self,
        evidence: list[dict[str, object]],
        evidence_id: str,
        kind: str,
        path: str,
        content: bytes,
    ) -> None:
        destination = self.evidence_root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        evidence.append(
            {
                "acquired_at_utc": "2026-08-24T17:00:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": (
                    "application/octet-stream"
                    if kind
                    in {
                        "controller_firmware_artifact",
                        "firmware_aup",
                        "firmware_elf",
                        "firmware_raw",
                        "source_archive",
                        "sram_execution_trace",
                    }
                    else "application/json"
                ),
                "method": route_replacement._method_for_kind(kind),
                "path": path,
                "redaction": "none",
            }
        )

    def _case(self, route: str) -> None:
        self._configure_boot_route(route)
        self.boot_bundle = self.fixture._bundle()
        self.boot_receipt = json.loads(
            (self.boot_bundle / route_replacement.boot.RECEIPT_NAME).read_text(
                encoding="ascii"
            )
        )
        self.recovery_bundle = self.fixture.recovery_bundle
        self.recovery_receipt = json.loads(
            (self.recovery_bundle / route_replacement.recovery.RECEIPT_NAME).read_text(
                encoding="ascii"
            )
        )
        self.discovery_bundle = self.recovery_fixture.discovery_bundle
        self.discovery_receipt = json.loads(
            (
                self.discovery_bundle / route_replacement.discovery.RECEIPT_NAME
            ).read_text(encoding="ascii")
        )
        verified = route_replacement.boot.verify_bundle(
            self.manifest,
            self.boot_bundle,
            self.fixture.operator_public,
            self.fixture.witness_public,
        )
        self.route_record = route_replacement.boot_route.adjudicate(verified)
        candidates = route_replacement._candidate_routes(self.route_record)
        self.raw = b"route-bound-safe-idle"
        self.source = b"clean route replacement source\n"
        source_sha = hashlib.sha256(self.source).hexdigest()
        evidence: list[dict[str, object]] = []
        copies = (
            (
                "discovery-receipt",
                "discovery_receipt_copy",
                "predecessors/discovery.json",
                route_replacement.canonical_json_bytes(self.discovery_receipt),
            ),
            (
                "recovery-receipt",
                "recovery_receipt_copy",
                "predecessors/recovery.json",
                route_replacement.canonical_json_bytes(self.recovery_receipt),
            ),
            (
                "boot-policy-receipt",
                "boot_policy_receipt_copy",
                "predecessors/boot-policy.json",
                route_replacement.canonical_json_bytes(self.boot_receipt),
            ),
            (
                "route-adjudication",
                "boot_route_adjudication_copy",
                "predecessors/route.json",
                route_replacement.canonical_json_bytes(self.route_record),
            ),
        )
        for item in copies:
            self._add(evidence, *item)
        common = (
            ("source-archive", "source_archive", "source/source.tar", self.source),
            (
                "source-manifest",
                "source_manifest",
                "source/manifest.json",
                b'{"clean":true}',
            ),
            ("sbom", "sbom", "reviews/sbom.json", b'{"spdxVersion":"SPDX-2.3"}'),
            (
                "license-review",
                "license_review",
                "reviews/license.json",
                b'{"passed":true}',
            ),
            (
                "clean-room-review",
                "clean_room_review",
                "reviews/clean-room.json",
                b'{"passed":true}',
            ),
        )
        for item in common:
            self._add(evidence, *item)

        load_address = self.boot_receipt["flash_policy"]["measured_boot_load_address"]
        elf = synthetic_elf(self.raw, load_address)
        profile = route_replacement.v1._profile_for_target(self.manifest, "a1246")
        builds = []
        for index, suffix in enumerate(("a", "b")):
            self._add(
                evidence,
                f"build-{suffix}-log",
                "reproducibility_log",
                f"build/{suffix}.json",
                json.dumps({"build": suffix, "complete": True}).encode("ascii"),
            )
            self._add(
                evidence,
                f"build-{suffix}-toolchain",
                "toolchain_manifest",
                f"build/{suffix}-toolchain.json",
                json.dumps({"rust": "1.90.0", "runner": suffix}).encode("ascii"),
            )
            if route == "native_aes0_flash":
                aup = boot_test.gauntlet.build_aup_v2(
                    boot_test.gauntlet.build_k210_plain_boot_image(self.raw),
                    "2.0.0-test",
                    profile["hw_list"],
                    profile["sw_list"],
                )
                artifacts = {
                    "aup": f"build-{suffix}-aup",
                    "elf": f"build-{suffix}-elf",
                    "raw": f"build-{suffix}-raw",
                }
                self._add(
                    evidence,
                    artifacts["aup"],
                    "firmware_aup",
                    f"artifacts/{suffix}.aup",
                    aup,
                )
                self._add(
                    evidence,
                    artifacts["elf"],
                    "firmware_elf",
                    f"artifacts/{suffix}.elf",
                    elf,
                )
                self._add(
                    evidence,
                    artifacts["raw"],
                    "firmware_raw",
                    f"artifacts/{suffix}.bin",
                    self.raw,
                )
            elif route in route_replacement.SRAM_ROUTES:
                artifacts = {
                    "elf": f"build-{suffix}-elf",
                    "raw": f"build-{suffix}-raw",
                }
                self._add(
                    evidence,
                    artifacts["elf"],
                    "firmware_elf",
                    f"artifacts/{suffix}.elf",
                    elf,
                )
                self._add(
                    evidence,
                    artifacts["raw"],
                    "firmware_raw",
                    f"artifacts/{suffix}.bin",
                    self.raw,
                )
            else:
                artifacts = {"controller": f"build-{suffix}-controller"}
                self._add(
                    evidence,
                    artifacts["controller"],
                    "controller_firmware_artifact",
                    f"artifacts/{suffix}-controller.bin",
                    self.raw,
                )
            builds.append(
                {
                    "artifacts": artifacts,
                    "build_log_evidence_id": f"build-{suffix}-log",
                    "completed_at_utc": f"2026-08-24T16:2{index}:00Z",
                    "environment_sha256": str(index + 1) * 64,
                    "host_id": f"build-host-{suffix}",
                    "id": f"build-{suffix}",
                    "source_archive_sha256": source_sha,
                    "started_at_utc": f"2026-08-24T16:1{index}:00Z",
                    "toolchain_manifest_evidence_id": f"build-{suffix}-toolchain",
                    "workspace_id": f"workspace-{suffix}",
                }
            )

        if route == "native_aes0_flash":
            self._add(
                evidence,
                "board-profile",
                "board_profile_record",
                "route/board-profile.json",
                b'{"route":"native_aes0_flash"}',
            )
            flash = self.boot_receipt["flash_policy"]
            route_contract = {
                "aup_hw_list": profile["hw_list"],
                "aup_sw_list": profile["sw_list"],
                "board_profile_evidence_id": "board-profile",
                "boot_flash_device_id": flash["boot_flash_device_id"],
                "boot_image_capacity_bytes": flash["boot_image_length_bytes"],
                "boot_image_offset_bytes": flash["boot_image_offset_bytes"],
                "load_address": load_address,
                "route_id": route,
            }
        elif route in route_replacement.SRAM_ROUTES:
            trace = b"qualified execution trace"
            self._add(
                evidence,
                "execution-trace",
                "sram_execution_trace",
                "route/execution-trace.bin",
                trace,
            )
            qualification = {
                "authority_granted": False,
                "entry_address": load_address,
                "executable_image_size_bytes": len(self.raw),
                "execution_started": True,
                "hash_power_physically_disconnected": True,
                "independent_cutoff_asserted": True,
                "kind": "dcent_k210_sram_execution_qualification",
                "load_address": load_address,
                "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
                "route_id": route,
                "safe_idle_observed": True,
                "stock_restored_after_probe": True,
                "target_id": "a1246",
                "trace_bytes": len(trace),
                "trace_sha256": hashlib.sha256(trace).hexdigest(),
                "unit_fingerprint_sha256": self.discovery_receipt[
                    "unit_fingerprint_sha256"
                ],
            }
            self._add(
                evidence,
                "execution-qualification",
                "sram_execution_qualification",
                "route/execution-qualification.json",
                route_replacement.canonical_json_bytes(qualification),
            )
            route_contract = {
                "entry_address": load_address,
                "executable_image_size_bytes": len(self.raw),
                "execution_qualification_evidence_id": "execution-qualification",
                "execution_trace_evidence_id": "execution-trace",
                "load_address": load_address,
                "maximum_image_size_bytes": 6 * 1024 * 1024,
                "route_id": route,
            }
        else:
            components = (
                ("connector", "connector_map_qualification"),
                ("signal", "signal_map_qualification"),
                ("power", "power_interface_qualification"),
                ("cooling", "cooling_interface_qualification"),
                ("cutoff", "cutoff_interface_qualification"),
                ("recovery", "recovery_interface_qualification"),
            )
            component_records = {}
            for name, kind in components:
                evidence_id = f"{name}-qualification"
                content = json.dumps({"qualified": True, "surface": name}).encode(
                    "ascii"
                )
                self._add(
                    evidence,
                    evidence_id,
                    kind,
                    f"route/{name}.json",
                    content,
                )
                component_records[name] = {
                    "bytes": len(content),
                    "evidence_id": evidence_id,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            interface = {
                "artifact_format": "raw-binary",
                "artifact_sha256": hashlib.sha256(self.raw).hexdigest(),
                "asic_interface_qualified": True,
                "authority_granted": False,
                "components": component_records,
                "connector_mapping_complete": True,
                "controller_target": "dcent-controller-v1",
                "cooling_custody_qualified": True,
                "independent_cutoff_qualified": True,
                "kind": "dcent_k210_replacement_controller_interface_qualification",
                "power_envelope_qualified": True,
                "recovery_interface_qualified": True,
                "route_id": route,
                "signal_levels_qualified": True,
                "target_id": "a1246",
                "unit_fingerprint_sha256": self.discovery_receipt[
                    "unit_fingerprint_sha256"
                ],
            }
            self._add(
                evidence,
                "interface-qualification",
                "controller_interface_qualification",
                "route/interface.json",
                route_replacement.canonical_json_bytes(interface),
            )
            route_contract = {
                "artifact_format": "raw-binary",
                "connector_evidence_id": "connector-qualification",
                "controller_target": "dcent-controller-v1",
                "cooling_evidence_id": "cooling-qualification",
                "cutoff_evidence_id": "cutoff-qualification",
                "interface_qualification_evidence_id": "interface-qualification",
                "power_evidence_id": "power-qualification",
                "recovery_evidence_id": "recovery-qualification",
                "route_id": route,
                "signal_evidence_id": "signal-qualification",
            }

        self.descriptor = {
            "boot_policy_receipt_id": self.boot_receipt["receipt_id"],
            "builder_id": "route-test-builder",
            "builds": builds,
            "completed_at_utc": "2026-08-24T17:00:00Z",
            "discovery_receipt_id": self.discovery_receipt["receipt_id"],
            "evidence": evidence,
            "firmware": {
                "clean_room_review_evidence_id": "clean-room-review",
                "firmware_class": "target_bound_safe_idle_runtime",
                "firmware_version": "2.0.0-test",
                "license_review_evidence_id": "license-review",
                "restricted_vendor_code_included": False,
                "sbom_evidence_id": "sbom",
                "source_archive_evidence_id": "source-archive",
                "source_archive_sha256": source_sha,
                "source_commit": "1" * 40,
                "source_dirty": False,
                "source_license": "GPL-3.0-only",
                "source_manifest_evidence_id": "source-manifest",
                "third_party_license_review_passed": True,
                "vendor_binary_blob_included": False,
            },
            "kind": route_replacement.DESCRIPTOR_KIND,
            "recovery_receipt_id": self.recovery_receipt["receipt_id"],
            "reviewer_id": "route-test-reviewer",
            "route_contract": route_contract,
            "route_selection": {
                "adjudicated_candidate_routes": candidates,
                "adjudication_sha256": self.route_record["adjudication_sha256"],
                "automatic_priority_selection_used": False,
                "builder_approved": True,
                "review_basis": f"explicit test review selected {route}",
                "reviewer_approved": True,
                "selected_route": route,
            },
            "schema_version": route_replacement.SCHEMA_VERSION,
            "scope": route_replacement.SCOPE,
            "stock_backup_set_sha256": self.recovery_receipt["stock_backup_set_sha256"],
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
            "unit_label": self.discovery_receipt["unit_label"],
        }

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "route-replacement-bundle"
        route_replacement.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.builder_private,
            self.reviewer_private,
            bundle,
        )
        return bundle

    def _verify(self) -> dict[str, object]:
        return route_replacement.verify_bundle(
            self.manifest,
            self._bundle(),
            self.builder_public,
            self.reviewer_public,
        )

    def test_aes0_round_trip_requires_elf_raw_aup_and_positive_boot(self) -> None:
        self._case("native_aes0_flash")
        result = self._verify()
        self.assertEqual(result["selected_route"], "native_aes0_flash")
        self.assertTrue(result["replacement_firmware_gate_eligible"])
        self.assertFalse(result["authority_granted"])

    def test_rom_isp_round_trip_uses_explicit_choice_and_execution_proof(self) -> None:
        self._case("rom_isp_sram_bootstrap")
        self.assertEqual(self.route_record["selected_route"], "native_aes0_flash")
        result = self._verify()
        self.assertEqual(result["selected_route"], "rom_isp_sram_bootstrap")

    def test_jtag_round_trip_requires_route_specific_execution_proof(self) -> None:
        self._case("jtag_sram_bootstrap")
        result = self._verify()
        self.assertEqual(result["selected_route"], "jtag_sram_bootstrap")

    def test_replacement_controller_round_trip_requires_complete_interface(
        self,
    ) -> None:
        self._case("clean_replacement_controller")
        result = self._verify()
        self.assertEqual(result["selected_route"], "clean_replacement_controller")
        self.assertRegex(result["interface_qualification_sha256"], r"^[0-9a-f]{64}$")

    def test_route_tamper_auto_priority_and_predecessor_splice_are_rejected(
        self,
    ) -> None:
        self._case("rom_isp_sram_bootstrap")
        self.descriptor["route_selection"]["automatic_priority_selection_used"] = True
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "automatic route priority"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        self.descriptor["route_selection"]["automatic_priority_selection_used"] = False
        route_path = self.evidence_root / "predecessors/route.json"
        tampered_route = json.loads(route_path.read_text(encoding="ascii"))
        tampered_route["selected_route"] = "jtag_sram_bootstrap"
        route_path.write_bytes(route_replacement.canonical_json_bytes(tampered_route))
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "does not reproduce"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        route_path.write_bytes(
            route_replacement.canonical_json_bytes(self.route_record)
        )
        self.descriptor["boot_policy_receipt_id"] = "0" * 64
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "does not match replacement"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_cross_route_artifacts_and_missing_execution_proof_are_rejected(
        self,
    ) -> None:
        self._case("rom_isp_sram_bootstrap")
        self.descriptor["builds"][0]["artifacts"]["aup"] = "build-a-raw"
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "artifacts keys invalid"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        del self.descriptor["builds"][0]["artifacts"]["aup"]
        qualification = self.evidence_root / "route/execution-qualification.json"
        qualification.write_bytes(b'{"execution_started":true}')
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "execution qualification"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_missing_controller_interface_signer_and_path_attacks_are_rejected(
        self,
    ) -> None:
        self._case("clean_replacement_controller")
        interface = self.evidence_root / "route/interface.json"
        payload = json.loads(interface.read_text(encoding="ascii"))
        payload["independent_cutoff_qualified"] = False
        interface.write_bytes(route_replacement.canonical_json_bytes(payload))
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "interface qualification"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        payload["independent_cutoff_qualified"] = True
        interface.write_bytes(route_replacement.canonical_json_bytes(payload))
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "keys must be distinct"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.builder_private,
            )
        self.descriptor["evidence"][0]["path"] = "../escape.json"
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "unsafe segment"
        ):
            route_replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_tamper_and_extra_bundle_members_are_rejected(self) -> None:
        self._case("native_aes0_flash")
        bundle = self._bundle()
        raw_item = next(
            item
            for item in self.descriptor["evidence"]
            if item["kind"] == "firmware_raw"
        )
        raw_path = bundle / route_replacement.EVIDENCE_DIRECTORY / raw_item["path"]
        raw_path.write_bytes(raw_path.read_bytes() + b"tamper")
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "digest or size mismatch"
        ):
            route_replacement.verify_bundle(
                self.manifest,
                bundle,
                self.builder_public,
                self.reviewer_public,
            )
        shutil.rmtree(bundle)
        bundle = self._bundle()
        (bundle / "unsigned.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(
            route_replacement.RouteReplacementError, "member set is not exact"
        ):
            route_replacement.verify_bundle(
                self.manifest,
                bundle,
                self.builder_public,
                self.reviewer_public,
            )


if __name__ == "__main__":
    unittest.main()
