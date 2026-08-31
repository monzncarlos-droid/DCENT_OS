#!/usr/bin/env python3
"""Pin the BM1485/L3+ source, ledger, refusal, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
DRIVER = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic" / "src" / "drivers" / "bm1485.rs"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "bm1485_l3plus_pic_firmware",
    "bm1485_l3plus_stock",
    "bm1485_l3plus_stock_carrier",
    "bm1485_l3plus_stock_cooling",
    "bm1485_l3plus_stock_lifecycle",
    "bm1485_l3plus_stock_pic",
    "bm1485_l3plus_stock_pll",
    "bm1485_l3plus_stock_shutdown",
    "bm1485_l3plus_stock_submit",
    "bm1485_l3plus_stock_work",
}


class Bm1485L3PlusLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1485"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1485 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1485_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1485_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_every_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)

    def test_row_records_current_depth_without_promoting_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertNotIn("acceptance_chip_labels", self.entry)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "75/75",
            "80/80",
            "21/21",
            "12/12",
            "recovery-tool",
            "no generation",
            "accepted-untracked",
            "electrical-off",
            "same-unit",
            "synthetic",
            "no I/O",
        ):
            self.assertIn(needle, row)

    def test_live_driver_remains_scaffold_and_every_hardware_surface_refuses(self) -> None:
        driver = DRIVER.read_text(encoding="utf-8")
        for needle in (
            "pub const CHIP_ID_IS_SILICON_READABLE: bool = false",
            "BM1485 driver — SCAFFOLD, refuses to energize",
            "fn init_chain",
            "fn set_frequency",
            "fn set_voltage",
            "fn send_work",
            "fn decode_nonce",
            "every_reachable_fail_closed_surface_refuses",
        ):
            self.assertIn(needle, driver)

    def test_workflow_runs_default_and_recovery_feature_suites_safely(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1485_",
            workflow,
        )
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --features recovery-tool --lib -- bm1485_",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1485_l3plus_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
