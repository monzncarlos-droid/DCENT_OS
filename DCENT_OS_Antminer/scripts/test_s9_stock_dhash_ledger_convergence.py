#!/usr/bin/env python3
"""Pin the stock-S9 DHASH offline contracts, authority boundary, and CI owners."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DCENTRALD_ROOT = DCENTOS_ROOT / "dcentrald"
COMMON_SRC = DCENTRALD_ROOT / "dcentrald-common" / "src"
HAL_SRC = DCENTRALD_ROOT / "dcentrald-hal" / "src"
DAEMON_SRC = DCENTRALD_ROOT / "dcentrald" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "s9_ordinary_stock_profile",
    "s9_stock_thermal",
    "sha256_padding",
    "stock_fpga_carrier_preflight",
    "stock_fpga_policy",
}

EXPECTED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- stock_fpga_ (36/36)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s9_stock_thermal (14/14)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s9_ordinary_stock_profile (14/14)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- sha256_padding (1/1)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-hal --lib -- stock_fpga_ (17/17)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- stock_ (20/20)",
    "python DCENT_OS_Antminer/scripts/test_s9_stock_dhash_ledger_convergence.py -q (6/6)",
}


class S9StockDhashLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [
            entry for entry in ledger["entries"] if entry["id"] == "fpga.s9_stock_dhash"
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one fpga.s9_stock_dhash entry, found {len(matches)}"
            )
        cls.entry = matches[0]

    def test_ledger_tracks_the_exact_five_common_contract_modules(self) -> None:
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in EXPECTED_MODULES:
            self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)

    def test_row_records_current_depth_without_promoting_live_authority(self) -> None:
        self.assertEqual(self.entry["status"], "experimental")
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 11)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 8)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "four-way AsicBoost",
            "RuntimeDispatchKind::StockFpga",
            "no issuer",
            "management-only",
            "S9j-e531",
            "ordinary-S9",
            "V1-only",
            "accepted-share",
            "bounded join",
            "full-init-dhash-refused",
        ):
            self.assertIn(needle, row)

    def test_common_policy_profile_and_thermal_surfaces_stay_offline_only(self) -> None:
        policy = (COMMON_SRC / "stock_fpga_policy.rs").read_text(encoding="utf-8")
        ordinary = (COMMON_SRC / "s9_ordinary_stock_profile.rs").read_text(
            encoding="utf-8"
        )
        thermal = (COMMON_SRC / "s9_stock_thermal.rs").read_text(encoding="utf-8")
        padding = (COMMON_SRC / "sha256_padding.rs").read_text(encoding="utf-8")
        self.assertIn("pub const fn stock_asicboost_admitted", policy)
        self.assertIn("false\n}", policy)
        self.assertIn("intentionally no live receipt issuer", ordinary)
        self.assertIn("performs no I/O and its success remains non-authoritative", ordinary)
        self.assertIn("Release-scoped S9j stock thermal/fan contract (pure, no I/O)", thermal)
        self.assertIn("does not prove that every S9/S9i/S9j release", thermal)
        self.assertIn("Hardware-neutral SHA-256 message padding", padding)

    def test_live_receipt_has_no_issuer_and_top_level_dispatch_stays_closed(self) -> None:
        hal = (HAL_SRC / "stock_fpga_preflight.rs").read_text(encoding="utf-8")
        production = hal.split("#[cfg(test)]", 1)[0]
        self.assertIn("retained_fabric_lease: OsI2cFabricLease", production)
        for constructor in ("pub fn new(", "pub fn issue(", "pub fn mint("):
            self.assertNotIn(constructor, production)

        main = (DAEMON_SRC / "main.rs").read_text(encoding="utf-8")
        branch = main.split("} else if stock_fpga_mode {", 1)[1].split("} else {", 1)[0]
        self.assertIn("stock FPGA runtime remains NOT-ADMITTED", branch)
        self.assertIn("HardwareMutationGate::new_closed()", branch)
        self.assertIn('enter_management_only_idle(\n            "stock-fpga-not-admitted"', branch)
        self.assertNotIn("StockMiner::new(", branch)

    def test_workflow_runs_all_six_zero_match_safe_owners(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- stock_fpga_",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s9_stock_thermal",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s9_ordinary_stock_profile",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- sha256_padding",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-hal --lib -- stock_fpga_",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- stock_",
        ):
            self.assertIn(command, workflow)

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_s9_stock_dhash_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
