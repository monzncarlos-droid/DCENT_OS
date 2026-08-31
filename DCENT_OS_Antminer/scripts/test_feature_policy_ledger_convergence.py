#!/usr/bin/env python3
"""Pin cooling and diagnostic policy modules to exact ledger and CI owners."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DCENTRALD_ROOT = DCENTOS_ROOT / "dcentrald"
COMMON_SRC = DCENTRALD_ROOT / "dcentrald-common" / "src"
DIAGNOSTICS_SRC = DCENTRALD_ROOT / "dcentrald-diagnostics" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

ROW_MODULES = {
    "feature.immersion_cooling": ["cooling_medium"],
    "feature.diagnostics_repair": ["diagnostic_mode", "measurement"],
}

CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_feature_policy_ledger_convergence.py -q (6/6)"
)

REQUIRED_TESTS = {
    "feature.immersion_cooling": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- cooling_medium::tests (12/12)",
        CONVERGENCE_TEST,
    },
    "feature.diagnostics_repair": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- diagnostic_mode::tests (6/6)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- measurement::tests (6/6)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-diagnostics --lib -- diagnostic_mode::tests (2/2)",
        CONVERGENCE_TEST,
    },
}


class FeaturePolicyLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}

    def test_feature_rows_own_required_nonduplicated_core_common_modules(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        for row_id, modules in ROW_MODULES.items():
            with self.subTest(row=row_id):
                self.assertTrue(
                    set(modules).issubset(
                        self.entries[row_id]["offline_contract_modules"]
                    )
                )
                for module in modules:
                    self.assertEqual(owners[module], [row_id])

    def test_modules_are_exported_anchored_and_consumed_by_exact_features(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for row_id, modules in ROW_MODULES.items():
            for module in modules:
                with self.subTest(module=module):
                    self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                    self.assertIn(f"pub mod {module};", lib_rs)
                    self.assertIn(
                        f"{module}.rs", self.entries[row_id]["dcentos_anchor"]
                    )
        immersion = (
            DCENTRALD_ROOT / "dcentrald-thermal" / "src" / "immersion.rs"
        ).read_text(encoding="utf-8")
        facade = (DIAGNOSTICS_SRC / "diagnostic_mode.rs").read_text(encoding="utf-8")
        self.assertIn(
            "dcentrald_common::cooling_medium::fan_bypass_permitted", immersion
        )
        self.assertIn("pub use dcentrald_common", facade)
        self.assertIn("MeasurementProvenance", facade)

    def test_rows_record_measured_depth_and_non_authorizing_scope(self) -> None:
        needles = {
            "feature.immersion_cooling": (
                "default-off",
                "unknown and unrecognized cooling labels",
                "ends in a power cut",
                "caller-supplied policy",
                "pump",
            ),
            "feature.diagnostics_repair": (
                "Snapshot cannot be relabeled",
                "freely constructible pure labels",
                "Modeled measurement provenance",
                "run-bound issuers",
                "manufacturing pass",
            ),
        }
        for row_id, required_tests in REQUIRED_TESTS.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["status"], "experimental")
                self.assertTrue(required_tests.issubset(set(entry["tests"])))
                self.assertGreaterEqual(len(entry["safety"]), 6)
                self.assertGreaterEqual(len(entry["instrumentation"]), 5)
                serialized = json.dumps(entry, sort_keys=True)
                for needle in needles[row_id]:
                    self.assertIn(needle, serialized)

    def test_cooling_policy_fails_closed_without_physical_loop_authority(self) -> None:
        source = (COMMON_SRC / "cooling_medium.rs").read_text(encoding="utf-8")
        for needle in (
            "pub fn fan_bypass_permitted",
            "CutLadderError::EmptyLadder",
            "CutLadderError::TerminalRungNotACut",
            "CutLadderError::FanRaiseBeforeHashCut",
            "CutLadderError::FanRungOnFanlessMedium",
            "parse_label_is_exact_match_fail_closed",
            "undeclared_medium_gets_air_rules_never_fanless_certification",
        ):
            self.assertIn(needle, source)

    def test_diagnostic_labels_and_provenance_do_not_mint_receipts(self) -> None:
        mode = (COMMON_SRC / "diagnostic_mode.rs").read_text(encoding="utf-8")
        measurement = (COMMON_SRC / "measurement.rs").read_text(encoding="utf-8")
        facade = (DIAGNOSTICS_SRC / "diagnostic_mode.rs").read_text(encoding="utf-8")
        for needle in (
            "pub const fn can_claim_measured_pass_authority",
            "matches!(self, Self::ActiveStim)",
            "DiagnosticModeError::UnknownReportKind",
            "DiagnosticModeError::ModeMismatch",
        ):
            self.assertIn(needle, mode)
        for needle in (
            "pub const fn measured(value: T) -> Self",
            "pub const fn is_physical_truth",
            "Self::Modeled | Self::Unknown => RailVoltageSource::Unknown",
            "modeled_never_maps_to_measured_rail",
        ):
            self.assertIn(needle, measurement)
        self.assertIn(
            "MeasurementProvenance::Modeled => EvidenceKind::Inferred", facade
        )
        self.assertIn(
            "MeasurementProvenance::Unknown => EvidenceKind::Unavailable", facade
        )

    def test_workflow_and_aggregate_own_every_focused_contract(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        commands = (
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- cooling_medium::tests",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- diagnostic_mode::tests",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- measurement::tests",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-diagnostics --lib -- diagnostic_mode::tests",
        )
        for command in commands:
            self.assertIn(command, workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_feature_policy_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
