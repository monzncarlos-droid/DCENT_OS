#!/usr/bin/env python3
"""Pin the path-aware dcentrald-thermal registry and both complete profiles."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
THERMAL_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-thermal"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_thermal_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_DEFAULT_COUNTS = {
    "battery": 0,
    "controller": 54,
    "curtailment": 3,
    "die_calibration": 16,
    "heater": 4,
    "immersion": 7,
    "offgrid": 10,
    "profiles": 9,
    "supervisor": 52,
}
EXPECTED_NO_DEFAULT_COUNTS = {
    name: count for name, count in EXPECTED_DEFAULT_COUNTS.items() if name != "offgrid"
}


class DcentraldThermalModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_registry_exactly_matches_declared_exports_and_hal_profile(self) -> None:
        lib_rs = (THERMAL_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        declared = set(re.findall(r"^pub mod ([A-Za-z0-9_]+);", lib_rs, re.M))
        self.assertEqual(declared, set(EXPECTED_DEFAULT_COUNTS))
        self.assertEqual(set(self.modules), declared)
        self.assertRegex(
            lib_rs,
            r'#\[cfg\(feature = "hal"\)\]\s+pub mod offgrid;',
        )
        self.assertEqual(self.modules["offgrid"]["required_feature"], "hal")

    def test_every_source_and_ledger_scope_exists_at_a_nonproduction_ceiling(
        self,
    ) -> None:
        for name, row in self.modules.items():
            with self.subTest(module=name):
                source = REPO_ROOT / row["source"]
                self.assertTrue(source.is_file(), source)
                self.assertTrue(row["ledger_rows"])
                self.assertGreaterEqual(len(row["authority_ceiling"]), 80)
                for owner in row["ledger_rows"]:
                    self.assertIn(owner, self.ledger)
                    self.assertIn(
                        self.ledger[owner]["status"],
                        {"experimental", "evidence-insufficient"},
                    )

    def test_default_and_hal_free_test_accounting_is_exact(self) -> None:
        self.assertEqual(
            {name: row["default_tests"] for name, row in self.modules.items()},
            EXPECTED_DEFAULT_COUNTS,
        )
        self.assertEqual(
            {
                name: self.modules[name]["no_default_tests"]
                for name in EXPECTED_NO_DEFAULT_COUNTS
            },
            EXPECTED_NO_DEFAULT_COUNTS,
        )
        self.assertEqual(sum(EXPECTED_DEFAULT_COUNTS.values()), 155)
        self.assertEqual(sum(EXPECTED_NO_DEFAULT_COUNTS.values()), 145)
        self.assertEqual(self.registry["default_zero_test_prefixes"], ["battery"])
        self.assertEqual(self.registry["no_default_zero_test_prefixes"], ["battery"])
        self.assertEqual(self.registry["default_tests"], 155)
        self.assertEqual(self.registry["no_default_tests"], 145)
        self.assertEqual(self.registry["declared_public_modules"], 9)
        self.assertEqual(self.registry["hal_free_modules"], 8)

    def test_source_retains_high_risk_fail_closed_boundaries(self) -> None:
        sources = {
            name: (THERMAL_ROOT / "src" / f"{name}.rs").read_text(encoding="utf-8")
            for name in (
                "controller",
                "die_calibration",
                "immersion",
                "offgrid",
                "supervisor",
            )
        }
        self.assertIn("home_tick_never_commands_pwm_above_cap", sources["controller"])
        self.assertIn(
            "immersion_on_still_fails_closed_on_stale_temp", sources["controller"]
        )
        self.assertIn(
            "guarantees the thermal supervisor can only ever trip EARLIER",
            sources["die_calibration"],
        )
        self.assertIn("EXPLICIT, default-OFF opt-in", sources["immersion"])
        self.assertIn(
            "nan_bus_voltage_fails_closed_and_does_not_poison_ema", sources["offgrid"]
        )
        self.assertIn(
            "hydro_configured_non_finite_inlet_fails_closed", sources["supervisor"]
        )
        self.assertIn(
            "min_per_board_zero_still_fails_closed_on_all_nan", sources["supervisor"]
        )

    def test_registry_keeps_software_actions_separate_from_physical_authority(
        self,
    ) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-thermal")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not prove",
            "fresh sensors",
            "fan identity",
            "electrical cutoff",
            "authority to control physical hardware",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_and_aggregate_own_both_complete_profiles(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-thermal --lib", workflow)
        self.assertIn(
            "cargo test --locked -p dcentrald-thermal --lib --no-default-features",
            workflow,
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_dcentrald_thermal_module_registry.py -q", aggregate)
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("thermal-crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
