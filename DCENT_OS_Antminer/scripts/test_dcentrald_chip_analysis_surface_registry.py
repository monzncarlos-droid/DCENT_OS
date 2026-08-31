#!/usr/bin/env python3
"""Pin the chip-analysis root API, tests, consumers, and pure authority ceiling."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-chip-analysis"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_chip_analysis_surface_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_FUNCTIONS = {
    "analyze_chip": "fn(i32, &[i32], &[i32], i64, f64) -> ChipAnalysis",
    "compute_cross_slot_zscore": "fn(i32, &[i32]) -> f32",
    "compute_hot_gradient": "fn(i32, &[i32]) -> f32",
    "compute_hot_zscore": "fn(i32, f32, f32) -> f32",
    "compute_mean_std": "fn(&[i32]) -> (f32, f32)",
    "compute_nonce_deficit": "fn(i64, f64) -> f32",
    "compute_slot_avg_nonce": "fn(&[i64]) -> f64",
}
EXPECTED_DECLARATIONS = {
    "analyze_chip": "pub fn analyze_chip( chip_temp: i32, neighbors: &[i32], cross_slot_samples: &[i32], chip_nonce: i64, slot_avg_nonce: f64, ) -> ChipAnalysis",
    "compute_cross_slot_zscore": "pub fn compute_cross_slot_zscore(temp: i32, cross_slot_samples: &[i32]) -> f32",
    "compute_hot_gradient": "pub fn compute_hot_gradient(center: i32, neighbors: &[i32]) -> f32",
    "compute_hot_zscore": "pub fn compute_hot_zscore(temp: i32, mean: f32, std: f32) -> f32",
    "compute_mean_std": "pub fn compute_mean_std(temps: &[i32]) -> (f32, f32)",
    "compute_nonce_deficit": "pub fn compute_nonce_deficit(chip_nonce: i64, slot_avg: f64) -> f32",
    "compute_slot_avg_nonce": "pub fn compute_slot_avg_nonce(chip_nonces: &[i64]) -> f64",
}
EXPECTED_TESTS = {
    "analyze_chip_combines_all_three_axes",
    "analyze_chip_healthy_chip_is_all_zero",
    "cross_slot_zscore_cool_chip_is_zero",
    "cross_slot_zscore_division_path_worked_example",
    "cross_slot_zscore_uniform_population_caps",
    "gradient_cool_or_equal_chip_is_zero",
    "gradient_hot_chip_returns_positive_delta",
    "gradient_no_neighbors_is_zero",
    "mean_std_empty_and_single",
    "mean_std_uniform_population",
    "mean_std_worked_example",
    "nonce_deficit_at_or_above_average_is_zero",
    "nonce_deficit_invalid_inputs_are_finite_and_conservative",
    "nonce_deficit_no_slot_nonces_is_zero",
    "nonce_deficit_worked_examples",
    "slot_avg_nonce_cannot_overflow_and_clamps_negative_counters",
    "slot_avg_nonce_empty_is_zero",
    "slot_avg_nonce_worked_example",
    "zscore_at_or_below_mean_is_zero",
    "zscore_invalid_statistics_are_finite_and_capped",
    "zscore_standard_division_path",
    "zscore_uniform_population_returns_capped_deviation",
}


def normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


class DcentraldChipAnalysisSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.source = (CRATE_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        cls.normalized_source = normalize_whitespace(cls.source)
        cls.cargo = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_root_public_and_private_surface_is_exact(self) -> None:
        self.assertEqual(re.findall(r"^pub mod ([A-Za-z0-9_]+)", self.source, re.M), [])
        self.assertEqual(
            set(re.findall(r"^pub fn ([A-Za-z0-9_]+)\(", self.source, re.M)),
            set(EXPECTED_FUNCTIONS),
        )
        self.assertEqual(
            {
                row["name"]: row["signature"]
                for row in self.registry["public_functions"]
            },
            EXPECTED_FUNCTIONS,
        )
        self.assertEqual(len(self.registry["public_functions"]), 7)
        for declaration in EXPECTED_DECLARATIONS.values():
            self.assertIn(normalize_whitespace(declaration), self.normalized_source)

        self.assertEqual(
            self.registry["public_types"],
            [
                {
                    "name": "ChipAnalysis",
                    "kind": "struct",
                    "fields": [
                        {"name": "gradient", "type": "f32"},
                        {"name": "cross_slot_zscore", "type": "f32"},
                        {"name": "nonce_deficit", "type": "f32"},
                    ],
                    "authority_ceiling": self.registry["public_types"][0][
                        "authority_ceiling"
                    ],
                }
            ],
        )
        fields = re.search(
            r"pub struct ChipAnalysis\s*\{(?P<body>.*?)\n\}", self.source, re.S
        )
        self.assertIsNotNone(fields)
        self.assertEqual(
            re.findall(r"pub ([A-Za-z0-9_]+): ([A-Za-z0-9_]+),", fields.group("body")),
            [
                ("gradient", "f32"),
                ("cross_slot_zscore", "f32"),
                ("nonce_deficit", "f32"),
            ],
        )
        constants = re.findall(
            r"^const ([A-Z0-9_]+): ([A-Za-z0-9_]+) = ([0-9.]+);", self.source, re.M
        )
        self.assertEqual(
            self.registry["private_constants"],
            [
                {"name": name, "type": kind, "value": value}
                for name, kind, value in constants
            ],
        )

    def test_crate_root_test_accounting_is_exact(self) -> None:
        tests = set(re.findall(r"#\[test\]\s+fn ([A-Za-z0-9_]+)\(", self.source))
        self.assertEqual(tests, EXPECTED_TESTS)
        self.assertEqual(
            self.registry["crate_root_test_prefixes"],
            [{"prefix": "tests", "tests": sorted(EXPECTED_TESTS)}],
        )
        self.assertEqual(self.registry["total_tests"], 22)
        self.assertEqual(self.registry["compile_profiles"][0]["tests"], 22)

    def test_profile_dependency_consumer_and_ledger_scope_is_exact(self) -> None:
        self.assertNotIn("[features]", self.cargo)
        dependencies = self.cargo.split("[dependencies]", 1)[1].split(
            "[dev-dependencies]", 1
        )[0]
        dev_dependencies = self.cargo.split("[dev-dependencies]", 1)[1].split(
            "[lints.clippy]", 1
        )[0]
        self.assertFalse(re.sub(r"(?m)^\s*#.*$", "", dependencies).strip())
        self.assertFalse(re.sub(r"(?m)^\s*#.*$", "", dev_dependencies).strip())
        self.assertEqual(self.registry["direct_dependencies"], [])
        consumers = []
        for manifest in (DCENTOS_ROOT / "dcentrald").glob("*/Cargo.toml"):
            if manifest == CRATE_ROOT / "Cargo.toml":
                continue
            if "dcentrald-chip-analysis" in manifest.read_text(encoding="utf-8"):
                consumers.append(manifest.parent.name)
        self.assertEqual(sorted(consumers), ["dcentrald-diagnostics"])
        self.assertEqual(self.registry["direct_consumers"], consumers)
        self.assertEqual(
            self.registry["compile_profiles"],
            [
                {
                    "profile": "default",
                    "features": [],
                    "public_modules": 0,
                    "public_types": 1,
                    "public_functions": 7,
                    "tests": 22,
                }
            ],
        )
        self.assertEqual(self.registry["ledger_rows"], ["feature.diagnostics_repair"])
        self.assertEqual(
            self.ledger["feature.diagnostics_repair"]["status"], "experimental"
        )
        for row in [*self.registry["public_types"], *self.registry["public_functions"]]:
            self.assertGreaterEqual(len(row["authority_ceiling"]), 110)

    def test_adversarial_math_stays_finite_bounded_and_overflow_free(
        self,
    ) -> None:
        for needle in (
            "nonce.max(0) as f64",
            "if !mean.is_finite() || !std.is_finite() || std < 0.0 { return ZSCORE_UNIFORM_CAP; }",
            "if !slot_avg.is_finite() { return 100.0; }",
            "let chip_nonce_f = chip_nonce.max(0) as f64;",
            "deficit.clamp(0.0, 100.0) as f32",
            "compute_slot_avg_nonce(&[i64::MAX, i64::MAX])",
            "compute_nonce_deficit(100, f64::NAN)",
            "compute_nonce_deficit(100, f64::INFINITY)",
            "compute_hot_zscore(60, f32::NAN, 1.0)",
        ):
            self.assertIn(normalize_whitespace(needle), self.normalized_source)
        self.assertNotIn("let total: i64 = chip_nonces.iter().sum();", self.source)

    def test_crate_remains_std_only_hal_free_and_non_authorizing(self) -> None:
        self.assertIn("#![forbid(unsafe_code)]", self.source)
        for forbidden in (
            "use std::fs",
            "use std::net",
            "use std::process",
            "Command::new",
            "tokio::",
            "unsafe {",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-chip-analysis")
        for needle in (
            "do not prove sensor provenance",
            "physical chip identity",
            "repair disposition",
            "tuning safety",
            "hardware authority",
        ):
            self.assertIn(needle, self.registry["authority_ceiling"])

    def test_workflow_aggregate_and_campaign_own_the_complete_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-chip-analysis --lib", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_chip_analysis_surface_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("chip-analysis surface convergence", campaign)


if __name__ == "__main__":
    unittest.main()
