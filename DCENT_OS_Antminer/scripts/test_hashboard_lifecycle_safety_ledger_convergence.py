#!/usr/bin/env python3
"""Pin hashboard lifecycle and safety composition to exact ledger ownership."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

ROW_ID = "hashboard.catalog_registry"
ROW_MODULES = [
    "asic_protocol",
    "chain_transport",
    "hashrate_geometry",
    "interconnect",
    "serial_work_engine",
    "serial_work_policy",
    "ticket_mask",
    "mining_lifecycle",
    "powerup_schedule",
    "safety_command",
    "work_dispatch_safety",
]
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/"
    "test_hashboard_lifecycle_safety_ledger_convergence.py -q (6/6)"
)
NEW_REQUIRED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- mining_lifecycle::tests (13/13)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- powerup_schedule::tests (13/13)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- safety_command::tests (12/12)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- work_dispatch_safety::tests (21/21)",
    CONVERGENCE_TEST,
}


class HashboardLifecycleSafetyLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.row = cls.entries[ROW_ID]

    def test_row_owns_exact_nonduplicated_lifecycle_expansion(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        self.assertEqual(self.row["offline_contract_modules"], ROW_MODULES)
        for module in ROW_MODULES:
            with self.subTest(module=module):
                self.assertEqual(owners[module], [ROW_ID])

    def test_modules_are_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for module in ROW_MODULES:
            with self.subTest(module=module):
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", self.row["dcentos_anchor"])

    def test_row_records_lifecycle_depth_and_authority_ceiling(self) -> None:
        self.assertEqual(self.row["status"], "evidence-insufficient")
        self.assertTrue(NEW_REQUIRED_TESTS.issubset(set(self.row["tests"])))
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "refuse bursts below the minimum stagger",
            "dispatch refusal is evaluated first",
            "revocation is terminal for the lifecycle",
            "cut-before-fan execution stops immediately on cut failure",
            "pure action/report does not prove electrical off",
            "exclusive carrier/lifecycle ownership",
        ):
            self.assertIn(needle, serialized)

    def test_lifecycle_and_powerup_refuse_dispatch_burst_and_empty_sets(self) -> None:
        lifecycle = (COMMON_SRC / "mining_lifecycle.rs").read_text(encoding="utf-8")
        powerup = (COMMON_SRC / "powerup_schedule.rs").read_text(encoding="utf-8")
        for needle in (
            "composed_plan_refuses_dispatch_before_powerup_math",
            "plan_multi_chain_enable_hard_refuses_simultaneous_burst",
            "plan_production_multi_chain_enable_refuses_empty_targets",
            "MultiChainEnableAuthority::PowerUpOnly",
        ):
            self.assertIn(needle, lifecycle)
        for needle in (
            "MIN_PRODUCTION_STAGGER_MS",
            "production_refuses_zero_stagger_multi_chain",
            "plan_production_enable_sequence_binds_targets_not_step_ids",
            "require_nonempty_fails_on_empty",
        ):
            self.assertIn(needle, powerup)

    def test_dispatch_and_safety_actions_are_terminal_ordered_and_fail_closed(
        self,
    ) -> None:
        dispatch = (COMMON_SRC / "work_dispatch_safety.rs").read_text(encoding="utf-8")
        actions = (COMMON_SRC / "safety_command.rs").read_text(encoding="utf-8")
        for needle in (
            "fresh_generation_requires_finite_measured_cooldown_below_controller_boundary",
            "refuses_cross_cycle_heartbeat_mix",
            "terminal_revoke_latch_blocks_re_admit",
            "revoke_cuts_hash_before_noise_and_stops_feed",
            "admission_publication_is_fail_closed_and_one_way",
        ):
            self.assertIn(needle, dispatch)
        for needle in (
            "HOME_FAN_PWM_SAFETY_MAX",
            "thermal_hard_stop_steps_cut_power_before_fans",
            "apply_safety_action_executes_cut_before_fan_and_reports",
            "apply_safety_action_stops_on_cut_error_without_fan",
        ):
            self.assertIn(needle, actions)

    def test_workflow_and_aggregate_own_all_four_new_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in (
            "mining_lifecycle",
            "powerup_schedule",
            "safety_command",
            "work_dispatch_safety",
        ):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_hashboard_lifecycle_safety_ledger_convergence.py -q",
            aggregate,
        )
        self.assertIn(
            "scripts/test_hashboard_work_contract_ledger_convergence.py -q",
            aggregate,
        )


if __name__ == "__main__":
    unittest.main()
