#!/usr/bin/env python3
"""Adversarial tests for the Antminer S21 lane verifier and source auditor."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "s21_lane_verify", SCRIPT_DIR / "s21_lane_verify.py"
)
assert SPEC is not None and SPEC.loader is not None
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)

OPERATOR_AUTH = (
    "I, the operator, authorize this exact bounded bench action on this unit "
    "today for the Antminer S21 complete-enablement campaign."
)


def stage_custody_evidence(root: Path, phase_id: str) -> Path:
    evidence = root / phase_id
    evidence.mkdir(parents=True)
    (evidence / "authorization.txt").write_text(OPERATOR_AUTH, encoding="utf-8")
    (evidence / "custody.json").write_text(
        json.dumps({"unit": "s21-generation-bench", "state": "in-custody"}),
        encoding="utf-8",
    )
    (evidence / "fingerprint.txt").write_text(
        "control_board=C76 amlogic a113d\nasic=BM1368\n",
        encoding="utf-8",
    )
    return evidence


def stage_bounded_evidence(root: Path, transcript: str) -> Path:
    evidence = root / "s21-bounded-work"
    evidence.mkdir(parents=True)
    (evidence / "authorization.txt").write_text(OPERATOR_AUTH, encoding="utf-8")
    trial = evidence / "trial"
    trial.mkdir()
    (trial / "run.log").write_text("trial output\n", encoding="utf-8")
    (evidence / "transcript.txt").write_text(transcript, encoding="utf-8")
    return evidence


class ConditionTruthTests(unittest.TestCase):
    """Pin today's repository truth; the wave that changes it updates these."""

    def test_sku_rows_and_unlock_surfaces_hold_today(self) -> None:
        self.assertTrue(lane.condition_skus_s21_rows_present()[0])
        self.assertTrue(lane.condition_s21_install_routes_present()[0])
        self.assertTrue(lane.condition_amlogic_unlock_surface_present()[0])

    def test_hydro_fingerprint_closed_while_td003_and_tiers_stay_blocked(self) -> None:
        ok, detail = lane.condition_s21_hydro_fingerprint_distinct()
        self.assertTrue(ok, detail)
        for condition in (
            lane.condition_td003_s21xp_release,
            lane.condition_td003_t21_release,
            lane.condition_td003_s21plus_release,
            lane.condition_support_tiers_promoted,
        ):
            ok, detail = condition()
            self.assertFalse(ok, detail)
            self.assertTrue(detail)


class AuditTests(unittest.TestCase):
    def test_missing_pins_and_failing_conditions_audit_blocked(self) -> None:
        for phase_id in (
            "s21xp-admission-promotion",
            "t21-admission-promotion",
            "plus-admission-promotion",
            "cv-swap-recovery-plan",
            "support-tier-promotion",
        ):
            result = lane.audit_source_tree(phase_id)
            self.assertIsNotNone(result)
            self.assertEqual(result["classification"], "blocked_tooling")
            self.assertTrue(result["blocker"])

        self.assertEqual(
            lane.audit_source_tree("variant-matrix-closure"),
            {"classification": "ready", "blocker": None},
        )

        for phase_id in ("s21pro-first-light-plan", "hydro-build-target-plan"):
            self.assertEqual(
                lane.audit_source_tree(phase_id),
                {"classification": "ready", "blocker": None},
            )

    def test_condition_free_desk_lanes_audit_ready(self) -> None:
        for phase_id in (
            "hashboard-revision-atlas",
            "nopic-psu-polarity-atlas",
            "unlock-surface-closure",
            "eeprom-cipher-closure",
            "s21xp-production-map-closure",
            "t21-controller-contract-closure",
            "hydro-identity-closure",
            "plus-generation-identity-closure",
        ):
            result = lane.audit_source_tree(phase_id)
            self.assertEqual(result, {"classification": "ready", "blocker": None})

    def test_unknown_phase_audits_none(self) -> None:
        self.assertIsNone(lane.audit_source_tree("not-a-phase"))


class ReceiptTests(unittest.TestCase):
    def test_custody_receipt_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            evidence = stage_custody_evidence(Path(raw_temp), "t21-unit-custody")
            receipt = lane.prepare_receipt(
                "t21-unit-custody",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "serial-T21-001",
                    "control_board": "am3-t21",
                    "firmware_state": "locked-stock",
                },
            )
            self.assertEqual(receipt["campaign_id"], lane.CAMPAIGN_ID)
            verified = lane.verify_workflow_evidence(evidence)
            self.assertEqual(verified["verification_id"], receipt["verification_id"])

    def test_tampered_evidence_byte_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            evidence = stage_custody_evidence(Path(raw_temp), "t21-unit-custody")
            lane.prepare_receipt(
                "t21-unit-custody",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "serial-T21-001",
                    "control_board": "am3-t21",
                    "firmware_state": "locked-stock",
                },
            )
            (evidence / "fingerprint.txt").write_text(
                "control_board=mutated\n", encoding="utf-8"
            )
            with self.assertRaises(lane.LaneVerifyError):
                lane.verify_workflow_evidence(evidence)

    def test_missing_leaf_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            evidence = stage_custody_evidence(Path(raw_temp), "t21-unit-custody")
            (evidence / "custody.json").unlink()
            with self.assertRaises(lane.LaneVerifyError):
                lane.prepare_receipt(
                    "t21-unit-custody",
                    evidence,
                    operator_authorization=OPERATOR_AUTH,
                    unit_identity={
                        "ip_or_serial": "serial-T21-001",
                        "control_board": "am3-t21",
                        "firmware_state": "locked-stock",
                    },
                )

    def test_share_bearing_phase_requires_accepted_line(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            evidence = stage_bounded_evidence(root, "share accepted\n")
            lane.prepare_receipt(
                "s21-bounded-work",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "203.0.113.135",
                    "control_board": "am3-s21",
                    "firmware_state": "braiinsos",
                },
            )
            lane.verify_workflow_evidence(evidence)
            (evidence / "transcript.txt").write_text(
                "no shares here\n", encoding="utf-8"
            )
            lane.prepare_receipt(
                "s21-bounded-work",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "203.0.113.135",
                    "control_board": "am3-s21",
                    "firmware_state": "braiinsos",
                },
            )
            with self.assertRaises(lane.LaneVerifyError):
                lane.verify_workflow_evidence(evidence)

    def test_desk_receipt_needs_no_operator_block(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            evidence = Path(raw_temp) / "hashboard-revision-atlas"
            evidence.mkdir(parents=True)
            (evidence / "hashboard-atlas.json").write_text(
                json.dumps({"boards": ["BHB68603", "BHB68709"]}), encoding="utf-8"
            )
            (evidence / "analysis.md").write_text("atlas analysis\n", encoding="utf-8")
            receipt = lane.prepare_receipt("hashboard-revision-atlas", evidence)
            self.assertNotIn("operator_authorization", receipt)
            lane.verify_workflow_evidence(evidence)

    def test_receipt_from_foreign_campaign_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            evidence = stage_custody_evidence(Path(raw_temp), "t21-unit-custody")
            lane.prepare_receipt(
                "t21-unit-custody",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "serial-T21-001",
                    "control_board": "am3-t21",
                    "firmware_state": "locked-stock",
                },
            )
            receipt_path = evidence / lane.RECEIPT_NAME
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["campaign_id"] = "s19j-pro-complete-enablement-20260826"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaises(lane.LaneVerifyError):
                lane.verify_workflow_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
