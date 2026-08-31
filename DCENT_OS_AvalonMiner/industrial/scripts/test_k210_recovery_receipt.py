#!/usr/bin/env python3
"""Host-only tests for signed Avalon K210 stock-recovery evidence."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_recovery_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_recovery_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
discovery = recovery.discovery
GAUNTLET_SCRIPT = Path(__file__).with_name("k210_gauntlet.py")
GAUNTLET_SPEC = importlib.util.spec_from_file_location(
    "k210_gauntlet_for_recovery_test", GAUNTLET_SCRIPT
)
assert GAUNTLET_SPEC is not None and GAUNTLET_SPEC.loader is not None
gauntlet = importlib.util.module_from_spec(GAUNTLET_SPEC)
GAUNTLET_SPEC.loader.exec_module(gauntlet)
MANIFEST = SCRIPT.parent.parent / "gauntlet" / "k210_models.json"
DISCOVERY_TEST_SCRIPT = Path(__file__).with_name("test_k210_discovery_receipt.py")
DISCOVERY_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_discovery_fixture_for_recovery_test", DISCOVERY_TEST_SCRIPT
)
assert DISCOVERY_TEST_SPEC is not None and DISCOVERY_TEST_SPEC.loader is not None
discovery_test = importlib.util.module_from_spec(DISCOVERY_TEST_SPEC)
DISCOVERY_TEST_SPEC.loader.exec_module(discovery_test)


class K210RecoveryReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_root = self.root / "recovery-evidence"
        self.evidence_root.mkdir()
        self.discovery_private, self.discovery_public = self._new_key("discovery")
        self.operator_private, self.operator_public = self._new_key("operator")
        self.witness_private, self.witness_public = self._new_key("witness")
        self.discovery_receipt = self._discovery_receipt()
        self.descriptor = self._descriptor()
        self.descriptor_path = self.root / "recovery-descriptor.json"
        self._write_descriptor()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _new_key(self, name: str) -> tuple[Path, Path]:
        private_key = self.root / name
        process = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"{name}@test.invalid",
                "-f",
                str(private_key),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        return private_key, Path(f"{private_key}.pub")

    def _discovery_receipt(self) -> dict[str, object]:
        evidence_root = self.root / "discovery-evidence"
        evidence_root.mkdir()
        capture = discovery_test.semantic_capture_fixture(
            self.manifest, evidence_root, "a1246"
        )
        capture_path = self.root / "discovery-capture.json"
        capture_path.write_text(json.dumps(capture), encoding="ascii")
        self.discovery_bundle = self.root / "discovery-bundle"
        receipt = discovery.create_bundle(
            self.manifest,
            capture_path,
            evidence_root,
            self.discovery_private,
            self.discovery_bundle,
        )
        discovery_copy = self.evidence_root / "identity" / "discovery-receipt.json"
        discovery_copy.parent.mkdir(parents=True)
        discovery_copy.write_bytes(discovery.canonical_json_bytes(receipt))
        return receipt

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
        media_type = (
            "application/octet-stream"
            if kind in {"stock_backup_image", "full_readback_image"}
            else "application/json"
        )
        evidence.append(
            {
                "acquired_at_utc": "2026-08-23T16:20:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": media_type,
                "method": (
                    "offline_artifact"
                    if kind in {"discovery_receipt_copy", "safety_record"}
                    else "authorized_recovery_execution"
                ),
                "path": path,
                "redaction": "none",
            }
        )

    def _descriptor(self) -> dict[str, object]:
        stock = bytes(range(64))
        evidence: list[dict[str, object]] = []
        self._add_evidence(
            evidence,
            "discovery-receipt",
            "discovery_receipt_copy",
            "identity/discovery-receipt.json",
            discovery.canonical_json_bytes(self.discovery_receipt),
        )
        records = (
            ("safety", "safety_record", "records/safety.json", b'{"safe":true}\n'),
            (
                "geometry",
                "flash_geometry_record",
                "records/geometry.json",
                b'{"capacity":32}\n',
            ),
            ("backup-a", "stock_backup_image", "images/backup-a.bin", stock),
            (
                "backup-a-log",
                "backup_log",
                "records/backup-a.json",
                b'{"complete":true}\n',
            ),
            ("backup-b", "stock_backup_image", "images/backup-b.bin", stock),
            (
                "backup-b-log",
                "backup_log",
                "records/backup-b.json",
                b'{"complete":true}\n',
            ),
            (
                "restore-a-log",
                "restore_log",
                "records/restore-a.json",
                b'{"complete":true}\n',
            ),
            (
                "restore-a-readback",
                "full_readback_image",
                "images/restore-a-readback.bin",
                stock,
            ),
            (
                "restore-a-boot",
                "stock_cold_boot_record",
                "records/restore-a-boot.json",
                b'{"booted":true}\n',
            ),
            (
                "restore-a-identity",
                "stock_identity_record",
                "records/restore-a-identity.json",
                b'{"matched":true}\n',
            ),
            (
                "restore-b-log",
                "restore_log",
                "records/restore-b.json",
                b'{"complete":true}\n',
            ),
            (
                "restore-b-readback",
                "full_readback_image",
                "images/restore-b-readback.bin",
                stock,
            ),
            (
                "restore-b-boot",
                "stock_cold_boot_record",
                "records/restore-b-boot.json",
                b'{"booted":true}\n',
            ),
            (
                "restore-b-identity",
                "stock_identity_record",
                "records/restore-b-identity.json",
                b'{"matched":true}\n',
            ),
            (
                "interruption-log",
                "interruption_log",
                "records/interruption.json",
                b'{"interrupted":true}\n',
            ),
            (
                "interruption-readback",
                "full_readback_image",
                "images/interruption-readback.bin",
                stock,
            ),
            (
                "interruption-boot",
                "stock_cold_boot_record",
                "records/interruption-boot.json",
                b'{"booted":true}\n',
            ),
            (
                "interruption-identity",
                "stock_identity_record",
                "records/interruption-identity.json",
                b'{"matched":true}\n',
            ),
        )
        for record in records:
            self._add_evidence(evidence, *record)
        return {
            "actions_performed": dict(recovery.ACTIONS_PERFORMED),
            "authorization": {
                "authorized_actions": sorted(recovery.RECOVERY_ACTIONS),
                "operator_reference": "recovery-test-authorization-001",
                "valid_from_utc": "2026-08-23T16:00:00Z",
                "valid_until_utc": "2026-08-23T17:00:00Z",
            },
            "completed_at_utc": "2026-08-23T16:30:00Z",
            "discovery_receipt_id": self.discovery_receipt["receipt_id"],
            "evidence": evidence,
            "flash_devices": [
                {
                    "backup_reads": [
                        {
                            "artifact_evidence_id": "backup-a",
                            "log_evidence_id": "backup-a-log",
                            "mechanism_class": "external_memory_programmer",
                            "tool": "test-spi-programmer",
                            "tool_serial": "spi-test-001",
                            "tool_version": "1.0",
                        },
                        {
                            "artifact_evidence_id": "backup-b",
                            "log_evidence_id": "backup-b-log",
                            "mechanism_class": "k210_rom_isp",
                            "tool": "test-k210-isp",
                            "tool_serial": "isp-test-001",
                            "tool_version": "1.0",
                        },
                    ],
                    "capacity_bytes": len(stock),
                    "geometry_evidence_id": "geometry",
                    "id": "controller-flash-0",
                    "manufacturer": "test-manufacturer",
                    "model": "test-spi-nor",
                    "technology": "spi_nor",
                }
            ],
            "interruption_drill": {
                "attempted_restore_path_id": "external-programmer",
                "cold_boot_evidence_id": "interruption-boot",
                "interrupted_after_bytes": 8,
                "interruption_kind": "power_loss",
                "log_evidence_id": "interruption-log",
                "passed": True,
                "recovered_by_restore_path_id": "k210-rom-isp",
                "recovery_readbacks": [
                    {
                        "flash_device_id": "controller-flash-0",
                        "readback_evidence_id": "interruption-readback",
                    }
                ],
                "stock_booted": True,
                "stock_identity_evidence_id": "interruption-identity",
                "stock_identity_matched": True,
            },
            "kind": recovery.DESCRIPTOR_KIND,
            "operator_id": "recovery-test-operator",
            "restore_paths": [
                self._restore_path(
                    "external-programmer",
                    "external_memory_programmer",
                    "test-spi-programmer",
                    "spi-test-001",
                    "backup-a",
                    "restore-a",
                    "2026-08-23T16:05:00Z",
                    "2026-08-23T16:10:00Z",
                ),
                self._restore_path(
                    "k210-rom-isp",
                    "k210_rom_isp",
                    "test-k210-isp",
                    "isp-test-001",
                    "backup-b",
                    "restore-b",
                    "2026-08-23T16:12:00Z",
                    "2026-08-23T16:17:00Z",
                ),
            ],
            "schema_version": recovery.SCHEMA_VERSION,
            "scope": recovery.SCOPE,
            "started_at_utc": "2026-08-23T16:01:00Z",
            "stock_identity": {
                key: self.discovery_receipt["identity"][key]
                for key in (
                    "stock_dna",
                    "stock_firmware_version",
                    "stock_hwtype",
                    "stock_swtype",
                )
            },
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
            "unit_label": self.discovery_receipt["unit_label"],
            "witness_id": "recovery-test-witness",
        }

    @staticmethod
    def _restore_path(
        path_id: str,
        mechanism: str,
        tool: str,
        serial: str,
        backup: str,
        prefix: str,
        started: str,
        completed: str,
    ) -> dict[str, object]:
        return {
            "cold_boot_evidence_id": f"{prefix}-boot",
            "completed_at_utc": completed,
            "device_results": [
                {
                    "flash_device_id": "controller-flash-0",
                    "full_write_completed": True,
                    "readback_evidence_id": f"{prefix}-readback",
                    "readback_matches": True,
                    "source_backup_evidence_id": backup,
                }
            ],
            "existing_flash_independent": True,
            "id": path_id,
            "log_evidence_id": f"{prefix}-log",
            "mechanism_class": mechanism,
            "started_at_utc": started,
            "stock_booted": True,
            "stock_identity_evidence_id": f"{prefix}-identity",
            "stock_identity_matched": True,
            "tool": tool,
            "tool_serial": serial,
            "tool_version": "1.0",
        }

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "recovery-bundle"
        recovery.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.witness_private,
            bundle,
        )
        return bundle

    def test_round_trip_is_dual_signed_exact_unit_and_non_authorizing(self) -> None:
        bundle = self._bundle()
        result = recovery.verify_bundle(
            self.manifest, bundle, self.operator_public, self.witness_public
        )
        self.assertEqual(result["state"], "verified_signed_stock_recovery")
        self.assertTrue(result["stock_restore_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["target_id"], "a1246")
        self.assertEqual(
            result["discovery_receipt_id"], self.discovery_receipt["receipt_id"]
        )
        receipt_path = bundle / recovery.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        self.assertEqual(
            receipt_path.read_bytes(), recovery.canonical_json_bytes(receipt)
        )
        self.assertEqual(receipt["authority_ceiling"], recovery.AUTHORITY_CEILING)

    def test_template_is_bound_to_the_discovery_receipt(self) -> None:
        descriptor = recovery._template(
            self.manifest,
            self.discovery_bundle / discovery.RECEIPT_NAME,
        )
        self.assertEqual(descriptor["target_id"], "a1246")
        self.assertEqual(
            descriptor["discovery_receipt_id"],
            self.discovery_receipt["receipt_id"],
        )
        self.assertEqual(
            descriptor["unit_fingerprint_sha256"],
            self.discovery_receipt["unit_fingerprint_sha256"],
        )
        recovery._validate_core(descriptor, self.manifest, receipt=False)

    def test_tampered_evidence_and_extra_members_are_rejected(self) -> None:
        bundle = self._bundle()
        readback = (
            bundle / recovery.EVIDENCE_DIRECTORY / "images" / "restore-a-readback.bin"
        )
        readback.write_bytes(readback.read_bytes() + b"tamper")
        with self.assertRaisesRegex(recovery.RecoveryError, "digest or size mismatch"):
            recovery.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )
        readback.write_bytes(bytes(range(64)))
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(recovery.RecoveryError, "member set is not exact"):
            recovery.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )

    def test_wrong_witness_key_and_same_signing_key_are_rejected(self) -> None:
        bundle = self._bundle()
        _, wrong_public = self._new_key("wrong-witness")
        with self.assertRaisesRegex(
            recovery.RecoveryError, "witness signer is not trusted"
        ):
            recovery.verify_bundle(
                self.manifest, bundle, self.operator_public, wrong_public
            )
        with self.assertRaisesRegex(recovery.RecoveryError, "keys must be distinct"):
            recovery.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )

    def test_readback_mismatch_is_rejected(self) -> None:
        mismatch = self.evidence_root / "images" / "restore-b-readback.bin"
        mismatch.write_bytes(b"x" * 64)
        with self.assertRaisesRegex(
            recovery.RecoveryError, "readback bytes do not match"
        ):
            recovery.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_restore_paths_must_be_independent(self) -> None:
        second = self.descriptor["restore_paths"][1]
        second["mechanism_class"] = "external_memory_programmer"
        with self.assertRaisesRegex(recovery.RecoveryError, "not independent"):
            recovery.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_discovery_receipt_link_is_exact(self) -> None:
        self.descriptor["unit_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(recovery.RecoveryError, "does not match recovery"):
            recovery.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_interruption_must_recover_through_other_path(self) -> None:
        self.descriptor["interruption_drill"]["recovered_by_restore_path_id"] = (
            "external-programmer"
        )
        with self.assertRaisesRegex(recovery.RecoveryError, "other admitted path"):
            recovery.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_gauntlet_advances_only_identity_and_stock_restore(self) -> None:
        bundle = self._bundle()
        repository = self.root / "repository"
        discovery_verifier = repository / gauntlet.DISCOVERY_VERIFIER
        recovery_verifier = repository / gauntlet.RECOVERY_VERIFIER
        discovery_verifier.parent.mkdir(parents=True)
        shutil.copyfile(discovery.__file__, discovery_verifier)
        shutil.copyfile(recovery.__file__, recovery_verifier)
        trust = repository / "trust"
        trust.mkdir()
        keys = {
            "discovery": (self.discovery_public, trust / "discovery.pub"),
            "operator": (self.operator_public, trust / "operator.pub"),
            "witness": (self.witness_public, trust / "witness.pub"),
        }
        key_ids = {}
        for name, (source, destination) in keys.items():
            shutil.copyfile(source, destination)
            key_ids[name] = discovery.inspect_public_key(destination)["key_id_sha256"]
        manifest = deepcopy(self.manifest)
        manifest["discovery_contract"]["state"] = "signed_read_only_receipt_admission"
        manifest["discovery_contract"]["trust_anchor"] = {
            "key_id_sha256": key_ids["discovery"],
            "path": "trust/discovery.pub",
            "role": discovery.SIGNER_ROLE,
        }
        manifest["recovery_contract"]["state"] = "dual_signed_stock_recovery_admission"
        manifest["recovery_contract"]["trust_anchors"] = {
            "operator": {
                "key_id_sha256": key_ids["operator"],
                "path": "trust/operator.pub",
                "role": recovery.OPERATOR_ROLE,
            },
            "witness": {
                "key_id_sha256": key_ids["witness"],
                "path": "trust/witness.pub",
                "role": recovery.WITNESS_ROLE,
            },
        }
        gauntlet.validate_manifest(manifest)
        discoveries = gauntlet.verify_discovery_bundles(
            manifest, [self.discovery_bundle], repository
        )
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "no admitted discovery receipt"
        ):
            gauntlet.verify_recovery_bundles(manifest, [bundle], {}, repository)
        recoveries = gauntlet.verify_recovery_bundles(
            manifest, [bundle], discoveries, repository
        )
        target = next(row for row in manifest["targets"] if row["id"] == "a1246")
        profiles = gauntlet.verify_profiles(manifest, corpus_policy="skip")
        model = gauntlet.evaluate_target(
            manifest,
            target,
            profiles,
            discoveries["a1246"],
            recoveries["a1246"],
        )
        self.assertTrue(model["gates"]["exact_model_identity"]["qualifies"])
        self.assertTrue(model["gates"]["stock_restore"]["qualifies"])
        self.assertEqual(
            model["gates"]["stock_restore"]["state"],
            "dual_path_stock_recovery_verified",
        )
        self.assertEqual(model["first_blocker"], "boot_policy")
        self.assertFalse(model["production_ready"])
        self.assertTrue(
            all(
                not gate["qualifies"]
                for gate_id, gate in model["gates"].items()
                if gate_id not in {"exact_model_identity", "stock_restore"}
            )
        )


if __name__ == "__main__":
    unittest.main()
