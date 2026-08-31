#!/usr/bin/env python3
"""Adversarial tests for the offline Antminer S21 complete-enablement
controller."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "s21_enablement_workflow.py"
SPEC = importlib.util.spec_from_file_location("s21_enablement_workflow", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)

LANE_SPEC = importlib.util.spec_from_file_location(
    "s21_lane_verify_for_registry", SCRIPT_DIR / "s21_lane_verify.py"
)
assert LANE_SPEC is not None and LANE_SPEC.loader is not None
lane = importlib.util.module_from_spec(LANE_SPEC)
LANE_SPEC.loader.exec_module(lane)

EXPECTED_FRONTIER = {
    "variant-matrix-closure",
    "s21-stock-unit-custody",
    "s21pro-unit-custody",
    "s21xp-unit-custody",
    "t21-unit-custody",
    "hydro-unit-custody",
    "plus-unit-custody",
    "cv-unit-acquisition",
}


class S21WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.manifest_sha = workflow.load_manifest(
            workflow.DEFAULT_MANIFEST
        )

    def evaluate_in_temp(self, manifest=None):
        with tempfile.TemporaryDirectory() as raw_temp:
            return workflow.evaluate(
                manifest if manifest is not None else self.manifest,
                self.manifest_sha,
                Path(raw_temp) / "evidence",
                None,
            )

    def test_manifest_spans_all_seven_lanes_and_terminal(self) -> None:
        phase_ids = [phase["id"] for phase in self.manifest["phases"]]
        for lane_prefix, required in (
            (
                "s21",
                (
                    "s21-stock-unit-custody",
                    "s21-stock-unlock-live",
                    "s21-nopic-polarity-dmm",
                    "s21-eeprom-live-capture",
                    "eeprom-cipher-closure",
                    "s21-persistent-install",
                    "s21-acceptance",
                ),
            ),
            (
                "s21pro",
                (
                    "s21pro-first-light-plan",
                    "s21pro-unit-custody",
                    "s21pro-persistent-install",
                    "s21pro-acceptance",
                ),
            ),
            (
                "s21xp",
                (
                    "s21xp-production-map-closure",
                    "s21xp-admission-promotion",
                    "s21xp-persistent-install",
                    "s21xp-acceptance",
                ),
            ),
            (
                "t21",
                (
                    "t21-controller-contract-closure",
                    "t21-admission-promotion",
                    "t21-persistent-install",
                    "t21-acceptance",
                ),
            ),
            (
                "hydro",
                (
                    "hydro-identity-closure",
                    "hydro-build-target-plan",
                    "hydro-recovery-boot",
                    "hydro-acceptance",
                ),
            ),
            (
                "plus",
                (
                    "plus-generation-identity-closure",
                    "plus-admission-promotion",
                    "plus-persistent-install",
                    "plus-acceptance",
                ),
            ),
            ("cv", ("cv-unit-acquisition", "cv-swap-recovery-plan")),
        ):
            for required_id in required:
                self.assertIn(required_id, phase_ids)
        for foundation in (
            "offline-repo-contract",
            "variant-matrix-closure",
            "unlock-surface-closure",
            "hashboard-revision-atlas",
            "nopic-psu-polarity-atlas",
            "support-tier-promotion",
            "complete-s21-enablement",
        ):
            self.assertIn(foundation, phase_ids)
        terminal = self.manifest["phases"][-1]
        self.assertEqual(terminal["kind"], "terminal")
        self.assertEqual(
            set(terminal["depends_on"]),
            {"support-tier-promotion", "cv-swap-recovery-plan"},
        )

    def test_manifest_matches_lane_verifier_registry_exactly(self) -> None:
        module_phase_ids = {
            phase["id"]
            for phase in self.manifest["phases"]
            if phase["verifier"]["kind"] == "module"
        }
        self.assertEqual(module_phase_ids, set(lane.PHASE_SPECS.keys()))

    def test_every_lane_reaches_its_acceptance_before_promotion(self) -> None:
        phase_by_id = {phase["id"]: phase for phase in self.manifest["phases"]}
        promotion = phase_by_id["support-tier-promotion"]
        self.assertEqual(
            set(promotion["depends_on"]),
            {
                "hashboard-revision-atlas",
                "eeprom-cipher-closure",
                "s21-acceptance",
                "s21pro-acceptance",
                "s21xp-acceptance",
                "t21-acceptance",
                "hydro-acceptance",
                "plus-acceptance",
            },
        )

    def test_td003_gated_lanes_cannot_reach_live_before_promotion(self) -> None:
        phase_by_id = {phase["id"]: phase for phase in self.manifest["phases"]}
        for promotion_id, live_id in (
            ("s21xp-admission-promotion", "s21xp-no-work-safeoff"),
            ("t21-admission-promotion", "t21-no-work-safeoff"),
            ("plus-admission-promotion", "plus-no-work-safeoff"),
        ):
            self.assertIn(promotion_id, phase_by_id[live_id]["depends_on"])

    def test_manifest_is_fail_closed_and_tools_contain_no_contact_primitive(self) -> None:
        policy = self.manifest["contact_policy"]
        self.assertTrue(policy["controller_is_offline_only"])
        self.assertTrue(policy["live_contact_requires_fresh_operator_authorization"])
        self.assertTrue(
            policy["nand_or_emmc_write_requires_separate_explicit_authorization"]
        )
        self.assertFalse(policy["controller_may_grant_authority"])
        for tool in (SCRIPT_PATH, SCRIPT_DIR / "s21_lane_verify.py"):
            source = tool.read_text(encoding="utf-8")
            for forbidden in (
                "import socket",
                "import requests",
                "import paramiko",
                "subprocess",
                "ssh ",
                "scp ",
                "/sys/class/gpio",
                "flash_erase",
                "nandwrite",
            ):
                with self.subTest(tool=tool.name, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)

    def test_current_frontier_is_derived_and_terminal_remains_denied(self) -> None:
        report = self.evaluate_in_temp()
        states = {phase["id"]: phase["state"] for phase in report["phases"]}
        self.assertEqual(states["offline-repo-contract"], "verified")
        self.assertEqual(states["variant-matrix-closure"], "ready")
        self.assertEqual(states["s21-stock-unit-custody"], "awaiting_operator")
        self.assertEqual(states["cv-unit-acquisition"], "awaiting_operator")
        self.assertEqual(states["s21-bounded-work"], "waiting")
        self.assertEqual(states["complete-s21-enablement"], "waiting")
        self.assertFalse(report["complete"])
        self.assertEqual(set(report["frontier"]), EXPECTED_FRONTIER)

    def test_agent_wave_has_bounded_owner_review_and_separate_operator_gates(self) -> None:
        report = self.evaluate_in_temp()
        wave = workflow.emit_agent_tasks(self.manifest, report)
        self.assertEqual(wave["max_parallel_agents"], 3)
        self.assertEqual(wave["campaign_id"], self.manifest["campaign_id"])
        owner_tasks = {task["task_id"] for task in wave["tasks"]}
        self.assertIn("variant-matrix-closure-owner", owner_tasks)
        self.assertIn("variant-matrix-closure-independent-review", owner_tasks)
        gates = {gate["phase_id"] for gate in wave["operator_gates"]}
        self.assertEqual(
            gates,
            {
                "s21-stock-unit-custody",
                "s21pro-unit-custody",
                "s21xp-unit-custody",
                "t21-unit-custody",
                "hydro-unit-custody",
                "plus-unit-custody",
                "cv-unit-acquisition",
            },
        )
        for task in wave["tasks"]:
            if task["role"].endswith("owner"):
                self.assertIn("miner/network contact", task["forbidden"])
            if task["role"].endswith("independent-review"):
                self.assertEqual(task["expert"], "DCENT_QA")

    def test_dependency_cycle_is_refused(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        by_id = {phase["id"]: phase for phase in manifest["phases"]}
        by_id["variant-matrix-closure"]["depends_on"].append(
            "support-tier-promotion"
        )
        with tempfile.TemporaryDirectory() as raw_temp:
            mutated = Path(raw_temp) / "manifest.json"
            mutated.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(workflow.WorkflowError) as caught:
                workflow.load_manifest(mutated)
        self.assertIn("cycle", str(caught.exception))

    def test_tampered_repo_identity_is_refused(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        repo_phase = next(
            phase
            for phase in manifest["phases"]
            if phase["id"] == "offline-repo-contract"
        )
        identity = repo_phase["verifier"]["required_identities"]
        first_path = repo_phase["verifier"]["required_paths"][0]
        identity[first_path]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as raw_temp:
            mutated = Path(raw_temp) / "manifest.json"
            mutated.write_text(json.dumps(manifest), encoding="utf-8")
            loaded, sha = workflow.load_manifest(mutated)
            report = workflow.evaluate(
                loaded, sha, Path(raw_temp) / "evidence", None
            )
        states = {phase["id"]: phase["state"] for phase in report["phases"]}
        self.assertEqual(states["offline-repo-contract"], "refused")

    def test_wrong_schema_is_refused(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["schema"] = "something.else/v1"
        with tempfile.TemporaryDirectory() as raw_temp:
            mutated = Path(raw_temp) / "manifest.json"
            mutated.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(workflow.WorkflowError):
                workflow.load_manifest(mutated)

    def test_manifest_digest_is_stable(self) -> None:
        _, again = workflow.load_manifest(workflow.DEFAULT_MANIFEST)
        self.assertEqual(again, self.manifest_sha)
        self.assertEqual(len(self.manifest_sha), 64)


if __name__ == "__main__":
    unittest.main()
