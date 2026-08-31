#!/usr/bin/env python3
"""Regression tests for non-publishable exact-binary promotion candidates."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from promotion_candidate import (  # noqa: E402
    CandidateError,
    admitted_manifest,
    candidate_id,
    create_descriptor,
    proposed_registry_row,
    validate_descriptor,
)
from target_matrix import MANIFEST_PATH, find_target, load_manifest  # noqa: E402
from hardware_evidence import sha256_file  # noqa: E402


class PromotionCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = load_manifest()
        cls.target = find_target(cls.matrix, "lucky-lv08")
        cls.receipt_id = "lucky-lv08-unit-a-20260823"
        cls.commit = "a" * 40
        cls.epoch = "1786482223"
        cls.version = "0.3.0"
        cls.registry_sha = sha256_file(MANIFEST_PATH)

    def descriptor(self) -> dict:
        return create_descriptor(
            self.matrix,
            self.target,
            self.receipt_id,
            self.commit,
            self.epoch,
            self.registry_sha,
            self.version,
        )

    def test_candidate_is_final_policy_but_explicitly_not_publishable(self) -> None:
        value = self.descriptor()
        self.assertFalse(value["publishable"])
        self.assertEqual(value["disposition"], "qualification-only-not-publishable")
        row = value["registry_row"]
        self.assertEqual(row["support_tier"], "production")
        self.assertEqual(row["evidence_level"], "sustained-soak")
        self.assertEqual(row["install_policy"], "production")
        self.assertEqual(row["blockers"], [])
        self.assertEqual(row["promotion_receipt_id"], self.receipt_id)
        self.assertEqual(value["source"]["firmware_version"], self.version)
        self.assertFalse(value["source"]["git_dirty"])
        self.assertEqual(
            validate_descriptor(value, self.matrix, self.registry_sha), []
        )

    def test_candidate_id_detects_any_descriptor_tampering(self) -> None:
        value = self.descriptor()
        value["registry_row"]["device_model"] = "forged"
        errors = validate_descriptor(value, self.matrix, self.registry_sha)
        self.assertTrue(any("candidate_id" in error for error in errors))
        self.assertTrue(any("immutable hardware field device_model" in error for error in errors))

    def test_candidate_refuses_a_dirty_source_declaration(self) -> None:
        value = self.descriptor()
        value["source"]["git_dirty"] = True
        value["candidate_id"] = candidate_id(value)
        errors = validate_descriptor(value, self.matrix, self.registry_sha)
        self.assertTrue(any("git_dirty" in error for error in errors))

    def test_candidate_refuses_stale_source_or_build_epoch(self) -> None:
        value = self.descriptor()
        errors = validate_descriptor(
            value,
            self.matrix,
            "b" * 64,
            git_commit="b" * 40,
            source_date_epoch="1",
            firmware_version="9.9.9",
        )
        self.assertTrue(any("registry SHA-256 is stale" in error for error in errors))
        self.assertTrue(any("git commit" in error for error in errors))
        self.assertTrue(any("SOURCE_DATE_EPOCH" in error for error in errors))
        self.assertTrue(any("firmware version" in error for error in errors))

    def test_candidate_snapshots_effective_family_and_target_gates(self) -> None:
        bitforge = find_target(self.matrix, "bitforge-nano")
        value = create_descriptor(
            self.matrix,
            bitforge,
            "bitforge-nano-unit-a-20260823",
            self.commit,
            self.epoch,
            self.registry_sha,
            self.version,
        )
        self.assertIn("dual-fan-proof", value["required_gates"])

        touch = find_target(self.matrix, "bitaxe-touch")
        value = create_descriptor(
            self.matrix,
            touch,
            "bitaxe-touch-unit-a-20260823",
            self.commit,
            self.epoch,
            self.registry_sha,
            self.version,
        )
        self.assertIn("accessory-first-article", value["required_gates"])

    def test_identity_only_hammer_cannot_skip_engineering_gate(self) -> None:
        hammer = find_target(self.matrix, "hammer-bc04")
        with self.assertRaises(CandidateError):
            proposed_registry_row(hammer, "hammer-bc04-unit-a-20260823")

    def test_candidate_row_does_not_mutate_the_source_registry(self) -> None:
        original = json.loads(json.dumps(self.target))
        proposed_registry_row(self.target, self.receipt_id)
        self.assertEqual(self.target, original)

    def test_descriptor_can_round_trip_as_canonical_json(self) -> None:
        value = self.descriptor()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            observed = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(candidate_id(observed), observed["candidate_id"])

    def test_admission_manifest_preserves_exact_payload_and_signatures(self) -> None:
        qualification = {
            "promotionState": "qualification",
            "qualificationOnly": True,
            "promotionCandidateId": "a" * 64,
            "promotionCandidateDescriptorSha256": "b" * 64,
            "hardwareEvidenceIndexSha256": "c" * 64,
            "otaSignature": "d" * 128,
            "signature": "e" * 128,
            "payloads": [
                {"name": "update", "sha256": "f" * 64, "size": 123},
                {"name": "factory", "sha256": "1" * 64, "size": 456},
            ],
        }
        admitted = admitted_manifest(qualification, "2" * 64)
        self.assertEqual(admitted["promotionState"], "registry")
        self.assertFalse(admitted["qualificationOnly"])
        self.assertIsNone(admitted["promotionCandidateId"])
        self.assertIsNone(admitted["promotionCandidateDescriptorSha256"])
        self.assertEqual(admitted["hardwareEvidenceIndexSha256"], "2" * 64)
        self.assertEqual(admitted["payloads"], qualification["payloads"])
        self.assertEqual(admitted["otaSignature"], qualification["otaSignature"])
        self.assertEqual(admitted["signature"], qualification["signature"])


if __name__ == "__main__":
    unittest.main()
