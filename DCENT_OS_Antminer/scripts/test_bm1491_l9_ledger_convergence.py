#!/usr/bin/env python3
"""Pin the BM1491/L9 source, ledger, scaffold, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
DRIVER = (
    DCENTOS_ROOT
    / "dcentrald"
    / "dcentrald-asic"
    / "src"
    / "drivers"
    / "bm1491.rs"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "bm1491_l9_carrier_preflight",
    "bm1491_l9_heartbeat",
    "bm1491_l9_iic_routes",
    "bm1491_l9_init",
    "bm1491_l9_operating",
    "bm1491_l9_power",
    "bm1491_l9_safety",
    "bm1491_l9_sensor_transport",
    "bm1491_l9_submission",
    "bm1491_l9_work",
}

EXPECTED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1491_ (128/128)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1491 --lib (7/7)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1491 --lib (3/3 negative separation tests)",
    "python DCENT_OS_Antminer/scripts/test_bm1491_l9_ledger_convergence.py -q (6/6)",
}


class Bm1491L9LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1491"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1491 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1491_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1491_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_every_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)
        self.assertIn("drivers/bm1491.rs", anchor)

    def test_row_records_current_depth_weaknesses_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertNotIn("acceptance_chip_labels", self.entry)
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 6)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 6)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "unbounded persistent-NACK",
            "missing-unlock",
            "no-safe-off",
            "id>=4",
            "GPIO-412",
            "nonce decode is synthetic",
            "inert no-op",
            "not covered by the BM1489",
        ):
            self.assertIn(needle, row)

    def test_live_driver_remains_a_precisely_bounded_scaffold(self) -> None:
        driver = DRIVER.read_text(encoding="utf-8")
        for needle in (
            "SCAFFOLD — simulator only, no live L9-CVCtrl unit",
            "BM1491 init_chain: SCAFFOLD",
            "BM1491 set_frequency not implemented",
            "BM1491 send_work not implemented",
            "No-op (like the",
            "Synthetic decode so the offline harness can exercise the path",
            "init_chain_fails_closed",
            "operational_baud_is_recovered_but_not_driven",
        ):
            self.assertIn(needle, driver)

    def test_workflow_runs_the_common_suite_with_a_zero_match_guard(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1491_",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1491_l9_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
