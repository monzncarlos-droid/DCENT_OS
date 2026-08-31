#!/usr/bin/env python3
"""Pin cooling custody and durable thermal lockout to exact feature ownership."""

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

ROW_ID = "feature.immersion_cooling"
ROW_MODULES = ["cooling_medium", "cooling_custody", "thermal_lockout"]
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/"
    "test_cooling_custody_lockout_ledger_convergence.py -q (6/6)"
)
REQUIRED_TESTS = {
    "cargo +1.90.0 test -p dcentrald-thermal immersion --lib (15/15)",
    "daemon source contract: default ImmersionConfig is disabled and the air-cooled-looking platform path requires explicit acknowledgement",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- cooling_medium::tests (12/12)",
    "python DCENT_OS_Antminer/scripts/test_feature_policy_ledger_convergence.py -q (6/6)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- cooling_custody::tests (8/8)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- thermal_lockout::tests (12/12)",
    CONVERGENCE_TEST,
}


class CoolingCustodyLockoutLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.row = cls.entries[ROW_ID]

    def test_row_owns_exact_nonduplicated_expanded_modules(self) -> None:
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

    def test_row_records_measured_depth_and_non_authorizing_scope(self) -> None:
        self.assertEqual(self.row["status"], "experimental")
        self.assertEqual(set(self.row["tests"]), REQUIRED_TESTS)
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "C52 low-byte receipt",
            "prearmed thermal generation is Unknown",
            "cool SoC cannot clear a hashboard lockout",
            "failed lockout persistence",
            "durable parent-directory synchronization",
            "without proving a physical loop",
        ):
            self.assertIn(needle, serialized)

    def test_c52_home_custody_fails_closed_and_stays_model_scoped(self) -> None:
        source = (COMMON_SRC / "cooling_custody.rs").read_text(encoding="utf-8")
        for needle in (
            "C52_MODE_LOW_BYTE",
            "C49_MODE_LOW_BYTE",
            "Am2S17Preserve",
            "MissingRequiredReceipt",
            "ReadbackMismatch",
            "home_missing_receipt_refuses",
            "home_c49_readback_refuses",
            "home_c52_receipt_admits",
        ):
            self.assertIn(needle, source)

    def test_thermal_lockout_release_is_durable_source_matched_and_strict(self) -> None:
        source = (COMMON_SRC / "thermal_lockout.rs").read_text(encoding="utf-8")
        for needle in (
            "prearmed_thermal_generation",
            "corrupt_or_ambiguous_records_never_parse_as_clear",
            "board_lockout_refuses_cool_soc_as_same_domain_evidence",
            "experimental_board_proxy_requires_dwell_and_non_warming_repeated_samples",
            "fan_failure_requires_new_tach_readiness_and_safe_samples",
            "failed_lockout_persistence_cannot_clear_prelaunch_session_admission",
            "durable_round_trip_and_removal_never_treat_corruption_as_absence",
        ):
            self.assertIn(needle, source)

    def test_workflow_and_aggregate_own_both_new_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in ("cooling_custody", "thermal_lockout"):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_cooling_custody_lockout_ledger_convergence.py -q",
            aggregate,
        )
        self.assertIn("scripts/test_feature_policy_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
