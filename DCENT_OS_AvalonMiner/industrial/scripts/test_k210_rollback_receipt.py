#!/usr/bin/env python3
"""Host-only tests for signed exact-route K210 rollback evidence."""

from __future__ import annotations

import importlib.util
import json
import shutil
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_rollback_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_rollback_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rollback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rollback)

REPLACEMENT_TEST_SCRIPT = Path(__file__).with_name("test_k210_replacement_receipt.py")
REPLACEMENT_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_replacement_receipt_fixture_for_rollback_test",
    REPLACEMENT_TEST_SCRIPT,
)
assert REPLACEMENT_TEST_SPEC is not None and REPLACEMENT_TEST_SPEC.loader is not None
replacement_test = importlib.util.module_from_spec(REPLACEMENT_TEST_SPEC)
REPLACEMENT_TEST_SPEC.loader.exec_module(replacement_test)


class K210RollbackReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        replacement_test.K210ReplacementReceiptTests.setUpClass()

    def setUp(self) -> None:
        self.fixture = replacement_test.K210ReplacementReceiptTests(
            methodName="runTest"
        )
        self.fixture.setUp()
        self.replacement_bundle = self.fixture._bundle()
        self.boot_fixture = self.fixture.fixture
        self.recovery_fixture = self.boot_fixture.fixture
        self.root = self.fixture.root
        self.manifest = self.fixture.manifest
        self.discovery_bundle = self.recovery_fixture.discovery_bundle
        self.recovery_bundle = self.boot_fixture.recovery_bundle
        self.boot_bundle = self.fixture.boot_bundle
        self.discovery_receipt_path = (
            self.discovery_bundle / rollback.discovery.RECEIPT_NAME
        )
        self.recovery_receipt_path = (
            self.recovery_bundle / rollback.recovery.RECEIPT_NAME
        )
        self.boot_receipt_path = self.boot_bundle / rollback.boot.RECEIPT_NAME
        self.replacement_receipt_path = (
            self.replacement_bundle / rollback.replacement.RECEIPT_NAME
        )
        self.discovery_receipt = self._read(self.discovery_receipt_path)
        self.recovery_receipt = self._read(self.recovery_receipt_path)
        self.boot_receipt = self._read(self.boot_receipt_path)
        self.replacement_receipt = self._read(self.replacement_receipt_path)

        verified_boot = rollback.boot.verify_bundle(
            self.manifest,
            self.boot_bundle,
            self.boot_fixture.operator_public,
            self.boot_fixture.witness_public,
        )
        self.route_record = rollback.boot_route.adjudicate(verified_boot)
        self.route_path = self.root / "route.json"
        self.route_path.write_bytes(rollback.canonical_json_bytes(self.route_record))
        self.operator_private, self.operator_public = self.recovery_fixture._new_key(
            "rollback-operator"
        )
        self.witness_private, self.witness_public = self.recovery_fixture._new_key(
            "rollback-witness"
        )
        self.evidence_root = self.root / "rollback-evidence"
        self.evidence_root.mkdir()
        self.descriptor = rollback._template(
            self.manifest,
            self.discovery_receipt_path,
            self.recovery_receipt_path,
            self.boot_receipt_path,
            self.replacement_receipt_path,
            self.route_path,
        )
        self.descriptor["operator_id"] = "rollback-test-operator"
        self.descriptor["witness_id"] = "rollback-test-witness"
        self.descriptor_path = self.root / "rollback-descriptor.json"
        self._populate_evidence()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    @staticmethod
    def _read(path: Path) -> dict[str, object]:
        return json.loads(path.read_text(encoding="ascii"))

    def _item(self, evidence_id: str) -> dict[str, object]:
        return next(
            item for item in self.descriptor["evidence"] if item["id"] == evidence_id
        )

    def _write_evidence(self, evidence_id: str, content: bytes) -> None:
        destination = self.evidence_root / self._item(evidence_id)["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    def _write_json_evidence(self, evidence_id: str, value: object) -> None:
        self._write_evidence(evidence_id, rollback.canonical_json_bytes(value))

    def _populate_evidence(self) -> None:
        copies = {
            "discovery-receipt": self.discovery_receipt,
            "recovery-receipt": self.recovery_receipt,
            "boot-policy-receipt": self.boot_receipt,
            "replacement-receipt": self.replacement_receipt,
            "route-adjudication": self.route_record,
        }
        for evidence_id, value in copies.items():
            self._write_json_evidence(evidence_id, value)

        common = {
            "authority_granted": False,
            "target_id": self.descriptor["target_id"],
            "unit_fingerprint_sha256": self.descriptor["unit_fingerprint_sha256"],
        }
        self._write_json_evidence(
            "pre-rollback-artifact",
            {
                **common,
                "artifact_set_sha256": self.replacement_receipt["artifact_set_sha256"],
                "kind": "dcent_k210_pre_rollback_artifact_observation",
                "replacement_firmware_receipt_id": self.descriptor[
                    "replacement_firmware_receipt_id"
                ],
                "selected_route": self.descriptor["selected_route"],
                "verified_running_before_rollback": True,
            },
        )
        execution = self.descriptor["rollback_execution"]
        self._write_json_evidence(
            "rollback-log",
            {
                **common,
                "completed": True,
                "faults": [],
                "kind": "dcent_k210_rollback_execution_log",
                "restore_path_id": execution["restore_path_id"],
                "route_adjudication_sha256": self.descriptor[
                    "route_adjudication_sha256"
                ],
                "selected_route": self.descriptor["selected_route"],
                "stops": [],
            },
        )
        interruption = self.descriptor["interruption_drill"]
        self._write_json_evidence(
            "interruption-log",
            {
                **common,
                "attempted_restore_path_id": interruption["attempted_restore_path_id"],
                "interrupted_after_bytes": interruption["interrupted_after_bytes"],
                "interruption_kind": interruption["interruption_kind"],
                "interruption_observed": True,
                "kind": "dcent_k210_rollback_interruption_log",
                "recovered_by_restore_path_id": interruption[
                    "recovered_by_restore_path_id"
                ],
            },
        )
        boot_record = {
            **common,
            "kind": "dcent_k210_stock_cold_boot_observation",
            "production_hashing_commanded": False,
            "stock_booted": True,
        }
        identity_record = {
            **common,
            "identity": self.descriptor["stock_identity"],
            "kind": "dcent_k210_stock_identity_observation",
            "stock_identity_matched": True,
        }
        for evidence_id in ("rollback-boot", "interruption-boot"):
            self._write_json_evidence(evidence_id, boot_record)
        for evidence_id in ("rollback-identity", "interruption-identity"):
            self._write_json_evidence(evidence_id, identity_record)

        recovery_evidence = {
            item["id"]: item for item in self.recovery_receipt["evidence"]
        }
        for section in ("rollback_execution", "interruption_drill"):
            for result in self.descriptor[section]["readbacks"]:
                baseline = recovery_evidence[result["baseline_backup_evidence_id"]]
                source = (
                    self.recovery_bundle
                    / rollback.recovery.EVIDENCE_DIRECTORY
                    / baseline["path"]
                )
                self._write_evidence(
                    result["readback_evidence_id"], source.read_bytes()
                )

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "rollback-bundle"
        rollback.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.witness_private,
            bundle,
        )
        return bundle

    def test_round_trip_is_exact_route_dual_signed_and_non_authorizing(self) -> None:
        bundle = self._bundle()
        result = rollback.verify_bundle(
            self.manifest, bundle, self.operator_public, self.witness_public
        )
        self.assertEqual(result["state"], "verified_signed_exact_route_rollback")
        self.assertTrue(result["rollback_recovery_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["selected_route"], "native_aes0_flash")
        self.assertEqual(
            result["replacement_firmware_receipt_id"],
            self.replacement_receipt["receipt_id"],
        )
        receipt = self._read(bundle / rollback.RECEIPT_NAME)
        self.assertEqual(receipt["authority_ceiling"], rollback.AUTHORITY_CEILING)
        self.assertEqual(
            (bundle / rollback.RECEIPT_NAME).read_bytes(),
            rollback.canonical_json_bytes(receipt),
        )

    def test_template_exact_joins_every_predecessor_and_selected_route(self) -> None:
        self.assertEqual(
            self.descriptor["discovery_receipt_id"],
            self.discovery_receipt["receipt_id"],
        )
        self.assertEqual(
            self.descriptor["recovery_receipt_id"], self.recovery_receipt["receipt_id"]
        )
        self.assertEqual(
            self.descriptor["boot_policy_receipt_id"], self.boot_receipt["receipt_id"]
        )
        self.assertEqual(
            self.descriptor["replacement_firmware_receipt_id"],
            self.replacement_receipt["receipt_id"],
        )
        self.assertEqual(
            self.descriptor["route_adjudication_sha256"],
            self.route_record["adjudication_sha256"],
        )
        self.assertEqual(self.descriptor["selected_route"], "native_aes0_flash")

    def test_stock_readback_must_match_admitted_recovery_backup(self) -> None:
        evidence_id = self.descriptor["rollback_execution"]["readbacks"][0][
            "readback_evidence_id"
        ]
        path = self.evidence_root / self._item(evidence_id)["path"]
        path.write_bytes(b"wrong" + path.read_bytes())
        with self.assertRaisesRegex(
            rollback.RollbackError, "readback bytes do not match admitted stock"
        ):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_route_record_must_reproduce_and_match_replacement_chain(self) -> None:
        tampered = deepcopy(self.route_record)
        tampered["selected_route"] = "jtag_sram_bootstrap"
        self._write_json_evidence("route-adjudication", tampered)
        with self.assertRaisesRegex(
            rollback.RollbackError, "does not reproduce from boot evidence"
        ):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_predecessor_splice_and_schema_v1_route_downgrade_are_rejected(
        self,
    ) -> None:
        self.descriptor["replacement_firmware_receipt_id"] = "0" * 64
        with self.assertRaisesRegex(rollback.RollbackError, "does not match rollback"):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["replacement_firmware_receipt_id"] = self.replacement_receipt[
            "receipt_id"
        ]
        self.descriptor["selected_route"] = "clean_replacement_controller"
        with self.assertRaisesRegex(rollback.RollbackError, "supports only"):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_interruption_requires_other_path_and_complete_stock_recovery(self) -> None:
        drill = self.descriptor["interruption_drill"]
        drill["recovered_by_restore_path_id"] = drill["attempted_restore_path_id"]
        with self.assertRaisesRegex(rollback.RollbackError, "other admitted path"):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        paths = sorted(item["id"] for item in self.recovery_receipt["restore_paths"])
        drill["recovered_by_restore_path_id"] = paths[1]
        drill["stock_booted"] = False
        with self.assertRaisesRegex(
            rollback.RollbackError, "stock_booted must be true"
        ):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_signer_separation_tamper_and_extra_member_are_rejected(self) -> None:
        with self.assertRaisesRegex(rollback.RollbackError, "keys must be distinct"):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )
        bundle = self._bundle()
        readback = next(
            item
            for item in self.descriptor["evidence"]
            if item["kind"] == "full_readback_image"
        )
        path = bundle / rollback.EVIDENCE_DIRECTORY / readback["path"]
        path.write_bytes(path.read_bytes() + b"tamper")
        with self.assertRaisesRegex(rollback.RollbackError, "digest or size mismatch"):
            rollback.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )

        # Rebuild because a signed bundle is immutable after a failed verification.
        shutil.rmtree(bundle)
        bundle = self._bundle()
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(rollback.RollbackError, "member set is not exact"):
            rollback.verify_bundle(
                self.manifest, bundle, self.operator_public, self.witness_public
            )

    def test_semantic_records_cannot_be_arbitrary_hashed_sentinels(self) -> None:
        self._write_json_evidence("rollback-log", {"completed": True})
        with self.assertRaisesRegex(rollback.RollbackError, "semantics do not match"):
            rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )


if __name__ == "__main__":
    unittest.main()
