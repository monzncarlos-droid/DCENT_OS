#!/usr/bin/env python3
"""Host-only tests for signed Avalon K210 boot-policy measurements."""

from __future__ import annotations

import importlib.util
import json
import shutil
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_boot_policy_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_boot_policy_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)

RECOVERY_TEST_SCRIPT = Path(__file__).with_name("test_k210_recovery_receipt.py")
RECOVERY_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_recovery_receipt_test_fixture", RECOVERY_TEST_SCRIPT
)
assert RECOVERY_TEST_SPEC is not None and RECOVERY_TEST_SPEC.loader is not None
recovery_test = importlib.util.module_from_spec(RECOVERY_TEST_SPEC)
RECOVERY_TEST_SPEC.loader.exec_module(recovery_test)

GAUNTLET_SCRIPT = Path(__file__).with_name("k210_gauntlet.py")
GAUNTLET_SPEC = importlib.util.spec_from_file_location(
    "k210_gauntlet_for_boot_policy_test", GAUNTLET_SCRIPT
)
assert GAUNTLET_SPEC is not None and GAUNTLET_SPEC.loader is not None
gauntlet = importlib.util.module_from_spec(GAUNTLET_SPEC)
GAUNTLET_SPEC.loader.exec_module(gauntlet)


class K210BootPolicyReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        recovery_test.K210RecoveryReceiptTests.setUpClass()

    def setUp(self) -> None:
        self.fixture = recovery_test.K210RecoveryReceiptTests(methodName="runTest")
        self.fixture.setUp()
        self.root = self.fixture.root
        self.manifest = self.fixture.manifest
        self.recovery_bundle = self.fixture._bundle()
        self.recovery_receipt = json.loads(
            (self.recovery_bundle / boot.recovery.RECEIPT_NAME).read_text(
                encoding="ascii"
            )
        )
        self.operator_private, self.operator_public = self.fixture._new_key(
            "boot-operator"
        )
        self.witness_private, self.witness_public = self.fixture._new_key(
            "boot-witness"
        )
        self.evidence_root = self.root / "boot-policy-evidence"
        self.evidence_root.mkdir()
        self.descriptor = self._descriptor()
        self.descriptor_path = self.root / "boot-policy-descriptor.json"

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _add_evidence(
        self,
        evidence: list[dict[str, object]],
        evidence_id: str,
        kind: str,
        path: str,
        content: bytes,
    ) -> None:
        source = self.evidence_root / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(content)
        evidence.append(
            {
                "acquired_at_utc": "2026-08-23T16:50:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": (
                    "application/octet-stream"
                    if kind == "plaintext_probe_artifact"
                    else "application/json"
                ),
                "method": (
                    "offline_artifact"
                    if kind == "recovery_receipt_copy"
                    else "authorized_boot_policy_measurement"
                ),
                "path": path,
                "redaction": "none",
            }
        )

    def _descriptor(self) -> dict[str, object]:
        evidence: list[dict[str, object]] = []
        records = (
            (
                "recovery-receipt",
                "recovery_receipt_copy",
                "identity/recovery-receipt.json",
                boot.canonical_json_bytes(self.recovery_receipt),
            ),
            (
                "safety-isolation",
                "safety_isolation_record",
                "records/safety-isolation.json",
                b'{"controller_only":true}\n',
            ),
            (
                "flash-map",
                "flash_map_record",
                "records/flash-map.json",
                b'{"full_coverage":true}\n',
            ),
            (
                "efuse",
                "efuse_record",
                "records/efuse.json",
                b'{"force_decrypt":"enabled"}\n',
            ),
            (
                "rom-isp",
                "rom_isp_record",
                "records/rom-isp.json",
                b'{"accessible":true}\n',
            ),
            (
                "jtag",
                "jtag_record",
                "records/jtag.json",
                b'{"state":"locked"}\n',
            ),
            (
                "load-address",
                "load_address_record",
                "records/load-address.json",
                b'{"address":2147483648}\n',
            ),
            (
                "plaintext-probe",
                "plaintext_probe_record",
                "records/plaintext-probe.json",
                b'{"performed":false}\n',
            ),
            (
                "stock-preboot",
                "stock_preboot_record",
                "records/stock-preboot.json",
                b'{"stock_booted":true}\n',
            ),
            (
                "stock-postboot",
                "stock_postboot_record",
                "records/stock-postboot.json",
                b'{"stock_booted":true,"identity_matched":true}\n',
            ),
        )
        for record in records:
            self._add_evidence(evidence, *record)
        devices = []
        for recovered in self.recovery_receipt["flash_devices"]:
            devices.append(
                {
                    "capacity_bytes": recovered["capacity_bytes"],
                    "id": recovered["id"],
                    "manufacturer": recovered["manufacturer"],
                    "model": recovered["model"],
                    "regions": [
                        {
                            "label": "stock-k210-boot-image",
                            "length_bytes": recovered["capacity_bytes"],
                            "offset_bytes": 0,
                            "role": "boot_image",
                        }
                    ],
                    "technology": recovered["technology"],
                }
            )
        boot_device = devices[0]
        return {
            "actions_performed": {
                **boot.BASE_ACTIONS_PERFORMED,
                "controlled_aes0_boot_probe_performed": False,
                "custom_firmware_written": False,
                "stock_flash_restored_after_measurement": False,
            },
            "authorization": {
                "authorized_actions": sorted(boot.BOOT_POLICY_ACTIONS),
                "operator_reference": "boot-policy-test-authorization-001",
                "valid_from_utc": "2026-08-23T16:30:00Z",
                "valid_until_utc": "2026-08-23T17:00:00Z",
            },
            "completed_at_utc": "2026-08-23T16:55:00Z",
            "discovery_receipt_id": self.recovery_receipt["discovery_receipt_id"],
            "evidence": evidence,
            "flash_policy": {
                "boot_flash_device_id": boot_device["id"],
                "boot_image_length_bytes": boot_device["capacity_bytes"],
                "boot_image_offset_bytes": 0,
                "candidate_load_address": boot.K210_CANDIDATE_LOAD_ADDRESS,
                "candidate_load_contract_compatible": True,
                "devices": devices,
                "flash_map_evidence_id": "flash-map",
                "load_address_evidence_id": "load-address",
                "measured_boot_load_address": boot.K210_CANDIDATE_LOAD_ADDRESS,
            },
            "jtag_policy": {
                "evidence_id": "jtag",
                "halt_capable": False,
                "idcode": None,
                "read_memory_capable": False,
                "state": "locked",
                "transport": "measured-board-pads",
                "write_memory_capable": False,
            },
            "kind": boot.DESCRIPTOR_KIND,
            "operator_id": "boot-policy-test-operator",
            "plaintext_probe": {
                "aes_enable": 0,
                "artifact_evidence_id": None,
                "delivery": "not_performed",
                "evidence_id": "plaintext-probe",
                "observation_method": "direct_policy",
                "performed": False,
                "plaintext_boot_supported": False,
                "result": "not_run_force_decrypt_enabled",
                "stock_flash_restored_after_measurement": False,
                "stock_identity_matched_after_measurement": True,
                "stock_postboot_evidence_id": "stock-postboot",
                "stock_preboot_evidence_id": "stock-preboot",
                "stock_state_verified_after_measurement": True,
            },
            "recovery_receipt_id": self.recovery_receipt["receipt_id"],
            "rom_isp_policy": {
                "erase_capable": True,
                "evidence_id": "rom-isp",
                "existing_flash_independent": True,
                "read_capable": True,
                "state": "accessible",
                "transport": "k210-rom-isp",
                "write_capable": True,
            },
            "safety_isolation": {
                "controller_only_power": True,
                "cooling_safe_for_controller_only": True,
                "evidence_id": "safety-isolation",
                "hash_power_physical_disconnect_verified": True,
                "independent_hash_power_cutoff_asserted": True,
            },
            "schema_version": boot.SCHEMA_VERSION,
            "scope": boot.SCOPE,
            "security_policy": {
                "evidence_id": "efuse",
                "force_decrypt_state": "enabled",
                "measurement_method": "direct_efuse_read",
                "otp_boot_key_state": "not_directly_readable",
            },
            "started_at_utc": "2026-08-23T16:35:00Z",
            "stock_backup_set_sha256": self.recovery_receipt["stock_backup_set_sha256"],
            "stock_identity": dict(self.recovery_receipt["stock_identity"]),
            "target_id": self.recovery_receipt["target_id"],
            "unit_fingerprint_sha256": self.recovery_receipt["unit_fingerprint_sha256"],
            "unit_label": self.recovery_receipt["unit_label"],
            "witness_id": "boot-policy-test-witness",
        }

    def _make_positive(self) -> None:
        self.descriptor["actions_performed"]["controlled_aes0_boot_probe_performed"] = (
            True
        )
        self.descriptor["actions_performed"]["custom_firmware_written"] = True
        self.descriptor["actions_performed"][
            "stock_flash_restored_after_measurement"
        ] = True
        self.descriptor["security_policy"].update(
            {
                "force_decrypt_state": "disabled",
                "measurement_method": "controlled_plaintext_probe",
                "otp_boot_key_state": "not_provisioned",
            }
        )
        self.descriptor["plaintext_probe"].update(
            {
                "artifact_evidence_id": "plaintext-artifact",
                "delivery": "direct_external_memory_restore",
                "observation_method": "uart_beacon",
                "performed": True,
                "plaintext_boot_supported": True,
                "result": "booted",
                "stock_flash_restored_after_measurement": True,
            }
        )
        self._add_evidence(
            self.descriptor["evidence"],
            "plaintext-artifact",
            "plaintext_probe_artifact",
            "images/plaintext-probe.bin",
            b"synthetic AES0 test image",
        )

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "boot-policy-bundle"
        boot.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.witness_private,
            bundle,
        )
        return bundle

    def test_negative_measurement_round_trip_is_gate_eligible(self) -> None:
        bundle = self._bundle()
        result = boot.verify_bundle(
            self.manifest, bundle, self.operator_public, self.witness_public
        )
        self.assertEqual(result["state"], "verified_signed_boot_policy_measurement")
        self.assertTrue(result["boot_policy_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["force_decrypt_state"], "enabled")
        self.assertEqual(
            result["rom_isp_capabilities"],
            {
                "erase_capable": True,
                "existing_flash_independent": True,
                "read_capable": True,
                "write_capable": True,
            },
        )
        self.assertEqual(
            result["jtag_capabilities"],
            {
                "halt_capable": False,
                "read_memory_capable": False,
                "write_memory_capable": False,
            },
        )
        self.assertFalse(result["plaintext_boot_supported"])
        receipt = json.loads((bundle / boot.RECEIPT_NAME).read_text(encoding="ascii"))
        self.assertEqual(receipt["authority_ceiling"], boot.AUTHORITY_CEILING)

    def test_template_is_bound_to_recovery_and_defaults_to_no_write(self) -> None:
        descriptor = boot._template(
            self.manifest,
            self.recovery_bundle / boot.recovery.RECEIPT_NAME,
        )
        self.assertEqual(
            descriptor["recovery_receipt_id"], self.recovery_receipt["receipt_id"]
        )
        self.assertEqual(
            descriptor["stock_backup_set_sha256"],
            self.recovery_receipt["stock_backup_set_sha256"],
        )
        self.assertFalse(descriptor["plaintext_probe"]["performed"])
        self.assertFalse(descriptor["actions_performed"]["custom_firmware_written"])

    def test_positive_plaintext_measurement_round_trip(self) -> None:
        self._make_positive()
        result = boot.verify_bundle(
            self.manifest,
            self._bundle(),
            self.operator_public,
            self.witness_public,
        )
        self.assertEqual(result["force_decrypt_state"], "disabled")
        self.assertTrue(result["plaintext_boot_supported"])
        self.assertTrue(result["candidate_load_contract_compatible"])

    def test_flash_regions_must_cover_recovery_device_exactly(self) -> None:
        self.descriptor["flash_policy"]["devices"][0]["regions"][0]["length_bytes"] -= 1
        with self.assertRaisesRegex(boot.BootPolicyError, "full device"):
            boot.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_recovery_link_and_flash_identity_are_exact(self) -> None:
        self.descriptor["recovery_receipt_id"] = "0" * 64
        with self.assertRaisesRegex(boot.BootPolicyError, "does not match"):
            boot.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["recovery_receipt_id"] = self.recovery_receipt["receipt_id"]
        self.descriptor["flash_policy"]["devices"][0]["model"] = "wrong-flash"
        with self.assertRaisesRegex(boot.BootPolicyError, "does not match recovery"):
            boot.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_tamper_and_wrong_witness_key_are_rejected(self) -> None:
        with self.assertRaisesRegex(boot.BootPolicyError, "keys must be distinct"):
            boot.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )
        bundle = self._bundle()
        _, wrong_public = self.fixture._new_key("wrong-boot-witness")
        with self.assertRaisesRegex(
            boot.BootPolicyError, "witness signer is not trusted"
        ):
            boot.verify_bundle(
                self.manifest, bundle, self.operator_public, wrong_public
            )
        evidence = bundle / boot.EVIDENCE_DIRECTORY / "records" / "jtag.json"
        evidence.write_bytes(b'{"tampered":true}\n')
        with self.assertRaisesRegex(boot.BootPolicyError, "digest or size mismatch"):
            boot.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )
        evidence.write_bytes(b'{"state":"locked"}\n')
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(boot.BootPolicyError, "member set is not exact"):
            boot.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )

    def test_gauntlet_advances_measurement_not_replacement(self) -> None:
        self._make_positive()
        bundle = self._bundle()
        repository = self.root / "repository"
        for relative, source in (
            (gauntlet.DISCOVERY_VERIFIER, boot.discovery.__file__),
            (gauntlet.RECOVERY_VERIFIER, boot.recovery.__file__),
            (gauntlet.BOOT_POLICY_VERIFIER, boot.__file__),
        ):
            destination = repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        trust = repository / "trust"
        trust.mkdir()
        keys = {
            "discovery": self.fixture.discovery_public,
            "recovery-operator": self.fixture.operator_public,
            "recovery-witness": self.fixture.witness_public,
            "boot-operator": self.operator_public,
            "boot-witness": self.witness_public,
        }
        key_ids = {}
        for name, source in keys.items():
            destination = trust / f"{name}.pub"
            shutil.copyfile(source, destination)
            key_ids[name] = boot.discovery.inspect_public_key(destination)[
                "key_id_sha256"
            ]
        manifest = deepcopy(self.manifest)
        manifest["discovery_contract"].update(
            {
                "state": "signed_read_only_receipt_admission",
                "trust_anchor": {
                    "key_id_sha256": key_ids["discovery"],
                    "path": "trust/discovery.pub",
                    "role": boot.discovery.SIGNER_ROLE,
                },
            }
        )
        manifest["recovery_contract"].update(
            {
                "state": "dual_signed_stock_recovery_admission",
                "trust_anchors": {
                    "operator": {
                        "key_id_sha256": key_ids["recovery-operator"],
                        "path": "trust/recovery-operator.pub",
                        "role": boot.recovery.OPERATOR_ROLE,
                    },
                    "witness": {
                        "key_id_sha256": key_ids["recovery-witness"],
                        "path": "trust/recovery-witness.pub",
                        "role": boot.recovery.WITNESS_ROLE,
                    },
                },
            }
        )
        manifest["boot_policy_contract"].update(
            {
                "state": "dual_signed_boot_policy_admission",
                "trust_anchors": {
                    "operator": {
                        "key_id_sha256": key_ids["boot-operator"],
                        "path": "trust/boot-operator.pub",
                        "role": boot.OPERATOR_ROLE,
                    },
                    "witness": {
                        "key_id_sha256": key_ids["boot-witness"],
                        "path": "trust/boot-witness.pub",
                        "role": boot.WITNESS_ROLE,
                    },
                },
            }
        )
        gauntlet.validate_manifest(manifest)
        discoveries = gauntlet.verify_discovery_bundles(
            manifest, [self.fixture.discovery_bundle], repository
        )
        recoveries = gauntlet.verify_recovery_bundles(
            manifest, [self.recovery_bundle], discoveries, repository
        )
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "no admitted recovery receipt"
        ):
            gauntlet.verify_boot_policy_bundles(
                manifest, [bundle], discoveries, {}, repository
            )
        measurements = gauntlet.verify_boot_policy_bundles(
            manifest, [bundle], discoveries, recoveries, repository
        )
        target = next(row for row in manifest["targets"] if row["id"] == "a1246")
        profiles = gauntlet.verify_profiles(manifest, corpus_policy="skip")
        model = gauntlet.evaluate_target(
            manifest,
            target,
            profiles,
            discoveries["a1246"],
            recoveries["a1246"],
            measurements["a1246"],
        )
        self.assertTrue(model["gates"]["exact_model_identity"]["qualifies"])
        self.assertTrue(model["gates"]["stock_restore"]["qualifies"])
        self.assertTrue(model["gates"]["boot_policy"]["qualifies"])
        self.assertFalse(model["gates"]["replacement_firmware"]["qualifies"])
        self.assertEqual(model["first_blocker"], "replacement_firmware")
        self.assertFalse(model["production_ready"])

    def test_default_manifest_has_no_boot_policy_admission_key(self) -> None:
        bundle = self._bundle()
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "until operator and witness keys are pinned"
        ):
            gauntlet.verify_boot_policy_bundles(
                self.manifest,
                [bundle],
                {},
                {},
                gauntlet.REPO_ROOT,
            )


if __name__ == "__main__":
    unittest.main()
