#!/usr/bin/env python3
"""Pin the complete diagnostics module/profile inventory and authority ceiling."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DIAGNOSTICS_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-diagnostics"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_diagnostics_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

DEFAULT_COUNTS = {
    "board_health": 13,
    "builders": 8,
    "chip_analysis_bridge": 3,
    "chip_health": 6,
    "diagnostic_mode": 2,
    "evidence": 7,
    "fault_knowledge": 8,
    "hashreport": 10,
    "manufacturing_interface": 1,
    "progress": 0,
    "repair_advisor": 15,
    "report": 18,
    "snapshot": 0,
    "subprocess": 0,
    "troubleshoot": 0,
}
PATTERN_COUNTS = {
    **DEFAULT_COUNTS,
    "manufacturing_interface": 2,
    "pattern_test": 6,
}
FACTORY_COUNTS = {**PATTERN_COUNTS, "factory_test_plan": 12}
EXPECTED_PROFILES = {
    "default": DEFAULT_COUNTS,
    "pattern_selftest": PATTERN_COUNTS,
    "factory_test_plan": FACTORY_COUNTS,
}


class DcentraldDiagnosticsModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}
        cls.lib_rs = (DIAGNOSTICS_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")

    def test_registry_exactly_matches_declared_public_modules_and_cfgs(self) -> None:
        public = set(re.findall(r"^pub mod ([A-Za-z0-9_]+)[ \t]*;", self.lib_rs, re.M))
        self.assertEqual(public, set(FACTORY_COUNTS))
        self.assertEqual(set(self.modules), public)
        self.assertEqual(self.registry["declared_public_modules"], 17)
        self.assertIn(
            '#[cfg(feature = "factory-test-plan")]\npub mod factory_test_plan;',
            self.lib_rs,
        )
        self.assertIn(
            '#[cfg(feature = "pattern-selftest")]\npub mod pattern_test;',
            self.lib_rs,
        )

    def test_every_source_profile_ledger_status_and_ceiling_is_explicit(self) -> None:
        for name, row in self.modules.items():
            with self.subTest(module=name):
                self.assertTrue((REPO_ROOT / row["source"]).is_file())
                self.assertEqual(
                    row["compile_profiles"],
                    [
                        profile
                        for profile, counts in EXPECTED_PROFILES.items()
                        if name in counts
                    ],
                )
                self.assertTrue(row["ledger_rows"])
                self.assertGreaterEqual(len(row["authority_ceiling"]), 110)
                for owner in row["ledger_rows"]:
                    self.assertIn(owner, self.ledger)
                    self.assertIn(
                        self.ledger[owner]["status"],
                        {"experimental", "evidence-insufficient"},
                    )

    def test_test_accounting_is_exact_for_all_three_profiles(self) -> None:
        profiles = {row["profile"]: row for row in self.registry["feature_profiles"]}
        expected_metadata = {
            "default": ([], 15, 91, 21, 112),
            "pattern_selftest": (["pattern-selftest"], 16, 98, 21, 119),
            "factory_test_plan": (
                ["factory-test-plan", "pattern-selftest", "dep:sha2"],
                17,
                110,
                21,
                131,
            ),
        }
        self.assertEqual(set(profiles), set(EXPECTED_PROFILES))
        for profile, expected_counts in EXPECTED_PROFILES.items():
            with self.subTest(profile=profile):
                actual_counts = {
                    name: row["tests_by_profile"][profile]
                    for name, row in self.modules.items()
                    if profile in row["tests_by_profile"]
                }
                self.assertEqual(actual_counts, expected_counts)
                features, modules, scoped, root, total = expected_metadata[profile]
                self.assertEqual(profiles[profile]["features"], features)
                self.assertEqual(profiles[profile]["public_modules"], modules)
                self.assertEqual(profiles[profile]["module_scoped_tests"], scoped)
                self.assertEqual(profiles[profile]["crate_root_tests"], root)
                self.assertEqual(profiles[profile]["total_tests"], total)
                self.assertEqual(sum(expected_counts.values()), scoped)
        self.assertEqual(
            self.registry["crate_root_test_prefixes"],
            [{"prefix": "capability_tests", "tests": 21}],
        )

    def test_cargo_feature_graph_is_exact(self) -> None:
        cargo = (DIAGNOSTICS_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        features = cargo.split("[features]", 1)[1].split("[lints]", 1)[0]
        definitions = re.findall(
            r"^([A-Za-z0-9_-]+)\s*=\s*(\[[^\n]*\])", features, re.M
        )
        self.assertEqual(
            definitions,
            [
                ("pattern-selftest", "[]"),
                ("factory-test-plan", '["pattern-selftest", "dep:sha2"]'),
            ],
        )

    def test_high_risk_source_boundaries_remain_non_authorizing(self) -> None:
        sources = {
            name: (DIAGNOSTICS_ROOT / "src" / f"{name}.rs").read_text(encoding="utf-8")
            for name in (
                "evidence",
                "factory_test_plan",
                "manufacturing_interface",
                "pattern_test",
                "repair_advisor",
                "subprocess",
                "troubleshoot",
            )
        }
        for field in (
            "typed_measured_pass_authorized",
            "manufacturing_grade_authorized",
            "hardware_mutation_authorized",
        ):
            self.assertEqual(self.lib_rs.count(f"{field}: false,"), 8)
            self.assertNotIn(f"{field}: true,", self.lib_rs)

        evidence_production = sources["evidence"].split("#[cfg(test)]", 1)[0]
        self.assertNotIn("pub fn measured(", evidence_production)
        self.assertNotIn("pub fn measured_validated(", evidence_production)
        self.assertIn("#[cfg(test)]\n    pub(crate) fn measured(", sources["evidence"])
        self.assertIn(
            "#[cfg(test)]\n    pub(crate) fn measured_validated(", sources["evidence"]
        )

        manufacturing = sources["manufacturing_interface"]
        self.assertEqual(manufacturing.count("hardware_mutation_authorized: false,"), 3)
        self.assertEqual(
            manufacturing.count("manufacturing_pass_authorized: false,"), 3
        )
        self.assertNotIn("hardware_mutation_authorized: true,", manufacturing)
        repair = sources["repair_advisor"]
        self.assertEqual(repair.count("hardware_mutation_authorized: false,"), 6)
        self.assertEqual(repair.count("manufacturing_pass_authorized: false,"), 6)
        self.assertNotIn("hardware_mutation_authorized: true,", repair)

        pattern = sources["pattern_test"]
        for needle in (
            "performs **no hardware",
            "dispatches no work",
            "admit_work_dispatch",
        ):
            self.assertIn(needle, pattern)
        factory = sources["factory_test_plan"]
        self.assertIn("OfflineOnlyNonAuthorizing", factory)
        production_factory = factory.split("#[cfg(test)]", 1)[0]
        self.assertEqual(production_factory.count("DeniedAuthority::Denied"), 9)
        self.assertIn(
            "let mut cmd = Command::new(&self.python_path);", sources["subprocess"]
        )
        for needle in ("interpreter", "tool", "arguments", "target", "side effects"):
            self.assertIn(needle, self.modules["subprocess"]["authority_ceiling"])
        self.assertIn("caller-supplied and unattested", sources["troubleshoot"])
        self.assertIn("no pass verdict", sources["troubleshoot"])

        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-diagnostics")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not authorize a probe or process execution",
            "hardware access or mutation",
            "repair action",
            "manufacturing verdict",
            "measured pass",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_aggregate_and_campaign_own_all_profiles(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "cargo test --locked -p dcentrald-diagnostics --lib",
            "cargo test --locked -p dcentrald-diagnostics --lib --features pattern-selftest",
            "cargo test --locked -p dcentrald-diagnostics --lib --features factory-test-plan",
        ):
            self.assertIn(command, workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_diagnostics_module_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("diagnostics-crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
