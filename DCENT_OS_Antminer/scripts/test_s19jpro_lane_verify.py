#!/usr/bin/env python3
"""Adversarial tests for the S19j Pro lane verifier and source auditor."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "s19jpro_lane_verify", SCRIPT_DIR / "s19jpro_lane_verify.py"
)
assert SPEC is not None and SPEC.loader is not None
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)

OPERATOR_AUTH = (
    "I, the operator, authorize this exact bounded bench action on this unit "
    "today for the S19j Pro complete-enablement campaign."
)


def stage_operator_evidence(root: Path, transcript: str = "share accepted\n") -> Path:
    evidence = root / "xil-bounded-work"
    evidence.mkdir(parents=True)
    (evidence / "authorization.txt").write_text(OPERATOR_AUTH, encoding="utf-8")
    trial = evidence / "trial"
    trial.mkdir()
    (trial / "run.log").write_text("trial output\n", encoding="utf-8")
    (evidence / "transcript.txt").write_text(transcript, encoding="utf-8")
    return evidence


class ConditionTruthTests(unittest.TestCase):
    """Pin today's repository truth; the wave that changes it updates these."""

    def test_unlock_routes_and_web_packages_hold_today(self) -> None:
        self.assertTrue(lane.condition_unlock_routes_present()[0])
        self.assertTrue(lane.condition_web_unlock_packages_present()[0])

    def test_sku_rows_now_hold_while_td003_and_tiers_stay_blocked(self) -> None:
        ok, _ = lane.condition_skus_first_class_rows()
        self.assertTrue(ok)
        for condition in (
            lane.condition_td003_s19jproplus_release,
            lane.condition_support_tiers_promoted,
        ):
            ok, detail = condition()
            self.assertFalse(ok, detail)
            self.assertTrue(detail)


class AuditTests(unittest.TestCase):
    def test_missing_pins_audit_blocked(self) -> None:
        for phase_id in (
            "s19jproplus-td003-promotion",
            "cv-emmc-recovery-plan",
        ):
            result = lane.audit_source_tree(phase_id)
            self.assertIsNotNone(result)
            self.assertEqual(result["classification"], "blocked_tooling")
            self.assertTrue(result["blocker"])

    def test_closed_pins_audit_ready(self) -> None:
        # xil-full-chain-init's pinned acceptance test landed 2026-08-27;
        # the XIL first-install bench card landed the same day.
        for phase_id in ("xil-full-chain-init", "xil-stock-first-install-plan"):
            result = lane.audit_source_tree(phase_id)
            self.assertEqual(result, {"classification": "ready", "blocker": None})

    def test_atlas_is_source_ready_without_conditions(self) -> None:
        result = lane.audit_source_tree("hashboard-revision-atlas")
        self.assertEqual(result, {"classification": "ready", "blocker": None})

    def test_unknown_phase_audits_none(self) -> None:
        self.assertIsNone(lane.audit_source_tree("not-a-phase"))


class EvidenceVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)

    def test_operator_receipt_round_trip(self) -> None:
        evidence = stage_operator_evidence(self.root)
        receipt = lane.prepare_receipt(
            "xil-bounded-work",
            evidence,
            operator_authorization=OPERATOR_AUTH,
            unit_identity={
                "ip_or_serial": "203.0.113.109",
                "control_board": "am2-s19jpro-zynq",
                "firmware_state": "braiinsos",
            },
        )
        self.assertEqual(receipt["campaign_id"], lane.CAMPAIGN_ID)
        verified = lane.verify_workflow_evidence(evidence)
        self.assertEqual(verified, receipt)

    def test_desk_phase_with_passing_conditions_verifies(self) -> None:
        evidence = self.root / "unlock-surface-closure"
        evidence.mkdir()
        (evidence / "unlock-ladder.md").write_text("ladder\n", encoding="utf-8")
        (evidence / "analysis.md").write_text("analysis\n", encoding="utf-8")
        lane.prepare_receipt("unlock-surface-closure", evidence)
        verified = lane.verify_workflow_evidence(evidence)
        self.assertEqual(verified["phase_id"], "unlock-surface-closure")

    def test_failing_condition_refuses_even_with_valid_receipt(self) -> None:
        evidence = self.root / "support-tier-promotion"
        evidence.mkdir()
        (evidence / "promotion-ledger.md").write_text("ledger\n", encoding="utf-8")
        lane.prepare_receipt("support-tier-promotion", evidence)
        with self.assertRaisesRegex(lane.LaneVerifyError, "repository conditions"):
            lane.verify_workflow_evidence(evidence)

    def test_post_hoc_edit_breaks_manifest(self) -> None:
        evidence = stage_operator_evidence(self.root)
        lane.prepare_receipt(
            "xil-bounded-work",
            evidence,
            operator_authorization=OPERATOR_AUTH,
            unit_identity={
                "ip_or_serial": "203.0.113.109",
                "control_board": "am2-s19jpro-zynq",
                "firmware_state": "braiinsos",
            },
        )
        (evidence / "trial" / "run.log").write_text("edited\n", encoding="utf-8")
        with self.assertRaisesRegex(lane.LaneVerifyError, "file_manifest"):
            lane.verify_workflow_evidence(evidence)

    def test_tampered_verification_id_refused(self) -> None:
        evidence = stage_operator_evidence(self.root)
        lane.prepare_receipt(
            "xil-bounded-work",
            evidence,
            operator_authorization=OPERATOR_AUTH,
            unit_identity={
                "ip_or_serial": "203.0.113.109",
                "control_board": "am2-s19jpro-zynq",
                "firmware_state": "braiinsos",
            },
        )
        receipt_path = evidence / lane.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["verification_id"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(lane.LaneVerifyError, "verification_id"):
            lane.verify_workflow_evidence(evidence)

    def test_missing_leaf_refused(self) -> None:
        evidence = stage_operator_evidence(self.root)
        (evidence / "transcript.txt").unlink()
        with self.assertRaises(lane.LaneVerifyError):
            lane.prepare_receipt(
                "xil-bounded-work",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": "203.0.113.109",
                    "control_board": "am2-s19jpro-zynq",
                    "firmware_state": "braiinsos",
                },
            )

    def test_empty_directory_leaf_refused(self) -> None:
        evidence = stage_operator_evidence(self.root)
        (evidence / "trial" / "run.log").unlink()
        with self.assertRaisesRegex(lane.LaneVerifyError, "empty"):
            lane.verify_workflow_evidence(evidence)

    def test_share_phase_requires_accepted_line(self) -> None:
        evidence = stage_operator_evidence(self.root, transcript="no shares here\n")
        lane.prepare_receipt(
            "xil-bounded-work",
            evidence,
            operator_authorization=OPERATOR_AUTH,
            unit_identity={
                "ip_or_serial": "203.0.113.109",
                "control_board": "am2-s19jpro-zynq",
                "firmware_state": "braiinsos",
            },
        )
        with self.assertRaisesRegex(lane.LaneVerifyError, "accepted"):
            lane.verify_workflow_evidence(evidence)

    def test_short_authorization_refused(self) -> None:
        evidence = stage_operator_evidence(self.root)
        with self.assertRaises(lane.LaneVerifyError):
            lane.prepare_receipt(
                "xil-bounded-work",
                evidence,
                operator_authorization="ok",
                unit_identity={
                    "ip_or_serial": "203.0.113.109",
                    "control_board": "am2-s19jpro-zynq",
                    "firmware_state": "braiinsos",
                },
            )

    def test_sealed_artifact_round_trip(self) -> None:
        seal_root = lane.REPO_ROOT / "artifacts/s19jpro-enablement"
        test_dir = seal_root / ".test-seal-roundtrip"
        test_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, seal_root, ignore_errors=True)
        artifact = test_dir / "dcentrald"
        payload = b"payload-bytes-for-seal-test"
        artifact.write_bytes(payload)
        local_path = "artifacts/s19jpro-enablement/.test-seal-roundtrip/dcentrald"

        evidence = self.root / "xil-persistent-install"
        evidence.mkdir()
        (evidence / "authorization.txt").write_text(OPERATOR_AUTH, encoding="utf-8")
        trial = evidence / "trial"
        trial.mkdir()
        (trial / "run.log").write_text("install trial\n", encoding="utf-8")
        receipt = lane.prepare_receipt(
            "xil-persistent-install",
            evidence,
            operator_authorization=OPERATOR_AUTH,
            unit_identity={
                "ip_or_serial": "203.0.113.25",
                "control_board": "am2-s19jpro-zynq",
                "firmware_state": "dcentos-target",
            },
            artifact_local_path=local_path,
            artifact_id="test-seal",
        )
        self.assertIn("sha256/", receipt["artifact"]["portable_path"])
        verified = lane.verify_workflow_evidence(evidence)
        self.assertEqual(verified["artifact"]["bytes"], len(payload))

        artifact.write_bytes(payload + b"x")
        with self.assertRaisesRegex(lane.LaneVerifyError, "identity mismatch"):
            lane.verify_workflow_evidence(evidence)

    def test_seal_rejects_paths_outside_campaign_prefix(self) -> None:
        evidence = self.root / "aml-persistent-install"
        evidence.mkdir()
        (evidence / "authorization.txt").write_text(OPERATOR_AUTH, encoding="utf-8")
        (evidence / "trial").mkdir()
        (evidence / "trial" / "run.log").write_text("t\n", encoding="utf-8")
        with self.assertRaisesRegex(lane.LaneVerifyError, "s19jpro-enablement"):
            lane.prepare_receipt(
                "aml-persistent-install",
                evidence,
                operator_authorization=OPERATOR_AUTH,
                unit_identity={
                    "ip_or_serial": ".133",
                    "control_board": "am3-s19jpro-aml",
                    "firmware_state": "vnish",
                },
                artifact_local_path="DCENT_OS_Antminer/README.md",
                artifact_id="bad",
            )

    def test_unknown_phase_refused(self) -> None:
        rogue = self.root / "not-a-phase"
        rogue.mkdir()
        with self.assertRaisesRegex(lane.LaneVerifyError, "unknown campaign phase"):
            lane.verify_workflow_evidence(rogue)

    def test_symlink_leaf_refused_when_symlinks_supported(self) -> None:
        evidence = stage_operator_evidence(self.root)
        target = evidence / "trial" / "real.log"
        target.write_text("real\n", encoding="utf-8")
        link = evidence / "trial" / "link.log"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable on this host")
        with self.assertRaises(lane.LaneVerifyError):
            lane.verify_workflow_evidence(evidence)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)

    def test_prepare_audit_verify_cli_round_trip(self) -> None:
        evidence = stage_operator_evidence(self.root)
        rc = lane.main(
            [
                "prepare",
                "--phase",
                "xil-bounded-work",
                "--evidence-dir",
                str(evidence),
                "--operator-authorization",
                OPERATOR_AUTH,
                "--unit-ip-or-serial",
                "203.0.113.109",
                "--control-board",
                "am2-s19jpro-zynq",
                "--firmware-state",
                "braiinsos",
            ]
        )
        self.assertEqual(rc, 0)
        rc = lane.main(["verify", "--evidence-dir", str(evidence)])
        self.assertEqual(rc, 0)
        rc = lane.main(["audit", "--phase", "xil-full-chain-init"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
