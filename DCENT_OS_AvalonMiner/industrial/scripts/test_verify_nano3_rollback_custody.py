#!/usr/bin/env python3
"""Adversarial tests for the Nano 3 W1 rollback custody manifest."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from prepare_nano3_user_donor_restore import (  # noqa: E402
    Nano3DonorRestoreError,
    load_accepted_donor,
    verify_restore_bytes,
)
from verify_nano3_rollback_custody import (  # noqa: E402
    EVIDENCE_SPECS,
    EXPECTED_FLASH_TOOL_SIZE,
    EXPECTED_RESTORE_RECEIPT_SIZE,
    EXPECTED_RESTORE_SIZE,
    EXPECTED_V19_RECEIPT_SIZE,
    EXPECTED_V19_SIZE,
    HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
    Nano3RollbackCustodyError,
    _assert_blocked_command_state,
    _verify_evidence,
    _write_new,
    build_manifest,
    canonical_manifest_bytes,
    main,
)


WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
DONOR = (
    WORKSPACE_ROOT
    / "knowledge-base"
    / "firmware-archive"
    / "avalon-k230"
    / "stock"
    / "heater_nano3_master_image.img"
)
ROLLBACK = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "build"
    / "image"
    / "STOCK_NANO3_RESTORE.kdimg"
)
ROLLBACK_RECEIPT = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "build"
    / "image"
    / "candidates"
    / "nano3-user-donor-restore-v13"
    / "live-proven-restore.receipt.json"
)
V19_DIR = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "build"
    / "image"
    / "candidates"
    / "nano3-user-donor-mutation-v19"
)
CANDIDATE = V19_DIR / "DCENT_NANO3_ROOTFS_COEXISTENCE.kdimg"
CANDIDATE_RECEIPT = V19_DIR / "DCENT_NANO3_ROOTFS_COEXISTENCE.receipt.json"
FLASH_TOOL = (
    WORKSPACE_ROOT
    / "projects"
    / "dcent-toolbox"
    / "src"
    / "dcent_toolbox"
    / "cli"
    / "commands"
    / "flash.py"
)
EVIDENCE_PATHS = {
    "r0_transcript": WORKSPACE_ROOT
    / "docs"
    / "dev"
    / "2026-08-21-nano3-first-contact"
    / "evidence"
    / "R0-stock-restore-20260821.txt",
    "g2_transcript": WORKSPACE_ROOT
    / "docs"
    / "dev"
    / "2026-08-21-nano3-first-contact"
    / "evidence"
    / "G2-stock-roundtrip.txt",
    "stock_boot_record": WORKSPACE_ROOT
    / "docs"
    / "dev"
    / "2026-08-21-nano3-first-contact"
    / "README.md",
    "restore_workflow_record": WORKSPACE_ROOT
    / "docs"
    / "dev"
    / "2026-08-21-nano3-first-contact"
    / "evidence"
    / "R3-nano3-user-donor-restore-v13-20260823.txt",
    "v19_image_report": WORKSPACE_ROOT
    / "docs"
    / "dev"
    / "2026-08-23-nano3-full-enablement"
    / "agent-products"
    / "image-wright-w1.md",
}


HELD_INPUTS = (
    DONOR,
    ROLLBACK,
    ROLLBACK_RECEIPT,
    CANDIDATE,
    CANDIDATE_RECEIPT,
    FLASH_TOOL,
    *EVIDENCE_PATHS.values(),
)


@unittest.skipUnless(
    all(path.is_file() for path in HELD_INPUTS),
    "exact operator-held donor/rollback/v19/evidence inputs are required",
)
class Nano3RollbackCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.donor = load_accepted_donor(DONOR)
        cls.restore = ROLLBACK.read_bytes()
        cls.restore_receipt = ROLLBACK_RECEIPT.read_bytes()
        cls.candidate = CANDIDATE.read_bytes()
        cls.candidate_receipt = CANDIDATE_RECEIPT.read_bytes()
        cls.flash_tool = FLASH_TOOL.read_bytes()
        cls.evidence = {
            name: path.read_bytes() for name, path in EVIDENCE_PATHS.items()
        }
        cls.manifest = build_manifest(
            donor=cls.donor,
            restore=cls.restore,
            restore_receipt=cls.restore_receipt,
            candidate=cls.candidate,
            candidate_receipt=cls.candidate_receipt,
            evidence=cls.evidence,
            flash_tool=cls.flash_tool,
        )

    @staticmethod
    def _main_argv(output: Path) -> list[str]:
        return [
            "verify_nano3_rollback_custody.py",
            "--donor",
            str(DONOR),
            "--rollback",
            str(ROLLBACK),
            "--rollback-receipt",
            str(ROLLBACK_RECEIPT),
            "--candidate",
            str(CANDIDATE),
            "--candidate-receipt",
            str(CANDIDATE_RECEIPT),
            "--r0-transcript",
            str(EVIDENCE_PATHS["r0_transcript"]),
            "--g2-transcript",
            str(EVIDENCE_PATHS["g2_transcript"]),
            "--stock-boot-record",
            str(EVIDENCE_PATHS["stock_boot_record"]),
            "--restore-workflow-record",
            str(EVIDENCE_PATHS["restore_workflow_record"]),
            "--v19-image-report",
            str(EVIDENCE_PATHS["v19_image_report"]),
            "--flash-tool",
            str(FLASH_TOOL),
            "--manifest",
            str(output),
        ]

    def test_exact_bundle_is_desk_admitted_but_command_and_authority_stay_closed(
        self,
    ) -> None:
        self.assertEqual(len(self.restore), EXPECTED_RESTORE_SIZE)
        self.assertEqual(len(self.restore_receipt), EXPECTED_RESTORE_RECEIPT_SIZE)
        self.assertEqual(len(self.candidate), EXPECTED_V19_SIZE)
        self.assertEqual(len(self.candidate_receipt), EXPECTED_V19_RECEIPT_SIZE)
        self.assertEqual(len(self.flash_tool), EXPECTED_FLASH_TOOL_SIZE)
        self.assertEqual(
            self.manifest["rollback"]["sha256"],
            HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
        )
        self.assertTrue(self.manifest["rollback"]["historical_live_restore_performed"])
        self.assertFalse(self.manifest["rollback"]["rollback_from_v19_performed"])
        self.assertEqual(self.manifest["current_command_state"]["status"], "blocked")
        self.assertFalse(
            self.manifest["current_command_state"][
                "exact_rollback_command_currently_admitted"
            ]
        )
        self.assertFalse(self.manifest["claims"]["authorization_a_granted"])
        self.assertFalse(self.manifest["claims"]["flash_authorized"])

    def test_exact_geometry_preserves_data_and_forbids_factory_reset(self) -> None:
        rollback = self.manifest["rollback"]
        boundary = self.manifest["persistent_data_boundary"]
        self.assertEqual(rollback["partition_count"], 12)
        self.assertEqual(rollback["last_nand_end"], 0x06400000)
        self.assertEqual(boundary["offset"], 0x06400000)
        self.assertEqual(boundary["end"], 0x08000000)
        self.assertEqual(boundary["size_bytes"], 0x01C00000)
        self.assertEqual(boundary["required_cli_flag"], "--no-data-erase")
        self.assertTrue(boundary["erase_data_flag_forbidden"])
        self.assertFalse(boundary["included_in_rollback_artifact"])
        self.assertFalse(boundary["factory_reset_performed"])

    def test_manifest_is_canonical_path_payload_secret_and_key_free(self) -> None:
        encoded = canonical_manifest_bytes(self.manifest)
        self.assertEqual(encoded, canonical_manifest_bytes(json.loads(encoded)))
        forbidden = (
            str(WORKSPACE_ROOT).encode(),
            b"knowledge-base",
            b"projects/",
            b"projects\\",
            b"C:\\",
            b"pool_password",
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
            self.donor[:64],
        )
        for value in forbidden:
            self.assertNotIn(value, encoded)
        claims = self.manifest["claims"]
        self.assertFalse(claims["manifest_contains_factory_payload_bytes"])
        self.assertFalse(claims["manifest_contains_local_paths"])
        self.assertFalse(claims["manifest_contains_credentials"])
        self.assertFalse(claims["manifest_contains_private_keys"])
        self.assertFalse(claims["redistribution_authorized"])

    def test_historical_machine_proof_never_becomes_stock_boot_proof(self) -> None:
        rows = {
            row["evidence_id"]: row for row in self.manifest["historical_evidence"]
        }
        self.assertEqual(
            rows["r0-stock-restore-write-transcript-2026-08-21"]["proof_scope"],
            "machine-recorded-write-complete-boot-pending",
        )
        self.assertEqual(
            rows["first-contact-operator-stock-boot-record"]["proof_scope"],
            "operator-recorded-normal-stock-boot",
        )

    def test_one_byte_restore_mutation_is_refused(self) -> None:
        changed = bytearray(self.restore)
        changed[-1] ^= 1
        with self.assertRaisesRegex(Nano3DonorRestoreError, "neither"):
            verify_restore_bytes(self.donor, bytes(changed))

    def test_one_byte_candidate_mutation_is_refused_before_custody_admission(self) -> None:
        changed = bytearray(self.candidate)
        changed[-1] ^= 1
        with self.assertRaisesRegex(Nano3RollbackCustodyError, "exact W1 v19"):
            build_manifest(
                donor=self.donor,
                restore=self.restore,
                restore_receipt=self.restore_receipt,
                candidate=bytes(changed),
                candidate_receipt=self.candidate_receipt,
                evidence=self.evidence,
                flash_tool=self.flash_tool,
            )

    def test_one_byte_evidence_mutation_is_refused(self) -> None:
        spec = EVIDENCE_SPECS["r0_transcript"]
        changed = bytearray(self.evidence["r0_transcript"])
        changed[-1] ^= 1
        with self.assertRaisesRegex(Nano3RollbackCustodyError, "size/SHA-256"):
            _verify_evidence(bytes(changed), spec)

    def test_incomplete_evidence_set_is_refused(self) -> None:
        incomplete = dict(self.evidence)
        incomplete.pop("g2_transcript")
        with self.assertRaisesRegex(Nano3RollbackCustodyError, "evidence set"):
            build_manifest(
                donor=self.donor,
                restore=self.restore,
                restore_receipt=self.restore_receipt,
                candidate=self.candidate,
                candidate_receipt=self.candidate_receipt,
                evidence=incomplete,
                flash_tool=self.flash_tool,
            )

    def test_unexpected_signed_sibling_is_refused_for_separate_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rollback = Path(temporary) / "restore.kdimg"
            rollback.write_bytes(b"placeholder")
            release_manifest = rollback.with_name(rollback.name + ".release.json")
            release_manifest.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                Nano3RollbackCustodyError, "separate signed-bundle review"
            ):
                _assert_blocked_command_state(rollback, self.flash_tool)

    def test_manifest_output_is_create_new_only(self) -> None:
        encoded = canonical_manifest_bytes(self.manifest)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "custody.json"
            _write_new(output, encoded)
            before = hashlib.sha256(output.read_bytes()).hexdigest()
            with self.assertRaisesRegex(Nano3RollbackCustodyError, "overwrite"):
                _write_new(output, encoded)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), before)

    def test_cli_success_output_does_not_echo_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "custody.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(sys, "argv", self._main_argv(output)),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 0)
            self.assertEqual(stderr.getvalue(), "")
            summary = stdout.getvalue()
            self.assertNotIn(str(output), summary)
            self.assertNotIn(str(WORKSPACE_ROOT), summary)
            self.assertTrue(output.is_file())

    def test_cli_failure_output_does_not_echo_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "custody.json"
            output.write_text("existing", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(sys, "argv", self._main_argv(output)),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 2)
            self.assertEqual(stdout.getvalue(), "")
            failure = stderr.getvalue()
            self.assertIn("refusing to overwrite manifest", failure)
            self.assertNotIn(str(output), failure)
            self.assertNotIn(str(WORKSPACE_ROOT), failure)


if __name__ == "__main__":
    unittest.main()
