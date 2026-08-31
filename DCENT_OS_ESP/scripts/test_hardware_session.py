#!/usr/bin/env python3
"""Regression tests for resumable, authorization-gated hardware sessions."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from hardware_evidence import sha256_file, validate_evidence_index  # noqa: E402
from hardware_session import (  # noqa: E402
    SessionError,
    authorize_session,
    finalize_session,
    gate_artifact_template,
    json_bytes,
    new_session,
    session_status,
)
from promotion_candidate import create_descriptor  # noqa: E402
from target_matrix import MANIFEST_PATH, find_target, load_manifest  # noqa: E402
from test_hardware_evidence import EvidenceFixture  # noqa: E402


class HardwareSessionTests(unittest.TestCase):
    def make_session(self, root: Path) -> tuple[dict, Path, dict, dict]:
        matrix = load_manifest()
        target = find_target(matrix, "lucky-lv08")
        descriptor = create_descriptor(
            matrix,
            target,
            "lucky-lv08-unit-a-20260823",
            "a" * 40,
            "1786482223",
            sha256_file(MANIFEST_PATH),
            "0.3.0",
        )
        manifest_path = root / "qualification-manifest.json"
        manifest_path.write_text('{"version":"0.3.0"}\n', encoding="ascii")
        descriptor_path = root / "promotion-candidate.json"
        descriptor_path.write_bytes(json_bytes(descriptor))
        session = new_session(
            matrix,
            descriptor,
            sha256_file(descriptor_path),
            manifest_path,
            {"version": "0.3.0", "otaKeyId": "test-key"},
            "c" * 64,
            "d" * 64,
            "operator@example.invalid",
            "witness@example.invalid",
        )
        directory = root / "session"
        (directory / "gates").mkdir(parents=True)
        (directory / "promotion-candidate.json").write_bytes(descriptor_path.read_bytes())
        (directory / "session.json").write_bytes(json_bytes(session))
        for gate in session["gates"]:
            (directory / "gates" / f"{gate}.json").write_bytes(
                json_bytes(gate_artifact_template(session, gate, target))
            )
        return session, directory, matrix, target

    def test_plan_is_offline_and_every_gate_starts_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session, directory, matrix, _target = self.make_session(Path(temporary))
            status = session_status(session, directory, matrix)
            self.assertEqual(session["state"], "planned-offline")
            self.assertFalse(session["live_device_contact"])
            self.assertEqual(set(status["pending_gates"]), set(session["gates"]))
            self.assertFalse(status["finalizable"])

    def test_authorization_requires_exact_operator_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session, directory, _matrix, _target = self.make_session(Path(temporary))
            with self.assertRaises(SessionError):
                authorize_session(
                    session,
                    directory,
                    "operator@example.invalid",
                    "wrong",
                    "2026-08-20T00:00:00Z",
                )
            authorize_session(
                session,
                directory,
                "operator@example.invalid",
                f"authorize-live-{session['receipt_id']}",
                "2026-08-20T00:00:00Z",
            )
            self.assertEqual(session["state"], "authorized-live")
            self.assertTrue(session["live_device_contact"])
            artifact = json.loads(
                (directory / "gates" / "safe-boot.json").read_text(encoding="utf-8")
            )
            self.assertTrue(artifact["live_device_contact"])

    def test_complete_typed_session_can_be_retained_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session, directory, matrix, target = self.make_session(root)
            authorize_session(
                session,
                directory,
                "operator@example.invalid",
                f"authorize-live-{session['receipt_id']}",
                "2026-08-20T00:00:00Z",
            )
            with tempfile.TemporaryDirectory() as fixture_directory:
                fixture = EvidenceFixture(Path(fixture_directory))
                for gate in session["gates"]:
                    artifact_path = directory / "gates" / f"{gate}.json"
                    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
                    measurements = fixture.gate_artifact(gate)["measurements"]
                    if gate == "exact-sku-identity":
                        measurements.update(
                            reported_board_target=target["board_target"],
                            reported_device_model=target["device_model"],
                            reported_asic=target["asic"],
                            reported_chip_count=target["chip_count"],
                            reported_promotion_receipt_id=session["receipt_id"],
                        )
                    artifact.update(
                        observed_at="2026-08-22T00:00:00Z",
                        passed=True,
                        measurements=measurements,
                    )
                    artifact_path.write_bytes(json_bytes(artifact))

            status = session_status(session, directory, matrix)
            self.assertTrue(status["finalizable"])
            evidence_root = root / "authority" / "hardware-evidence"
            evidence_root.mkdir(parents=True)
            (evidence_root / "index.json").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "product": "DCENT_OS for ESP",
                        "authority": "retained-exact-sku-hardware-receipts",
                        "receipts": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            receipt_path = finalize_session(
                session,
                directory,
                matrix,
                evidence_root,
                "2026-08-23T00:00:00Z",
                f"finalize-{session['receipt_id']}",
            )
            self.assertTrue(receipt_path.is_file())
            index = json.loads((evidence_root / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(
                validate_evidence_index(index, matrix, evidence_root.parent), []
            )
            self.assertEqual(index["receipts"][0]["receipt_id"], session["receipt_id"])
            with self.assertRaises(SessionError):
                finalize_session(
                    session,
                    directory,
                    matrix,
                    evidence_root,
                    "2026-08-23T00:00:00Z",
                    f"finalize-{session['receipt_id']}",
                )


if __name__ == "__main__":
    unittest.main()
