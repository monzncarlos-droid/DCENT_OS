#!/usr/bin/env python3
"""Pin the BM1489/L7 source, ledger, scaffold, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
ASIC_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic" / "src" / "drivers"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "bm1489_l7_return",
    "bm1489_l7_safety",
    "bm1489_l7_sensor_transport",
    "bm1489_l7_share_qualification",
    "bm1489_l7_submission",
    "bm1489_l7_vnish",
    "bm1489_l7_work",
}

EXPECTED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1489_ (108/108)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1489 --lib (19/19)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-asic --features scrypt-l7 --lib -- drivers::scrypt_l7 (11/11)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1489 --lib (11/11)",
    "python DCENT_OS_Antminer/scripts/test_bm1489_l7_ledger_convergence.py -q (6/6)",
}


class Bm1489L7LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1489"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1489 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1489_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1489_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_every_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)
        self.assertIn("drivers/bm1489.rs", anchor)
        self.assertIn("drivers/scrypt_l7.rs", anchor)

    def test_row_records_current_depth_weaknesses_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertNotIn("acceptance_chip_labels", self.entry)
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 5)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 4)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "127-emission",
            "validity-before-payload",
            "forged",
            "electrical-off",
            "tracked/untracked",
            "decode is synthetic",
            "inert no-op",
        ):
            self.assertIn(needle, row)
        self.assertNotIn("repeat count still depends", row)
        self.assertNotIn("runtime-BSS-dependent repetition whose count remains unresolved", row)

    def test_both_live_drivers_remain_scaffold_bounded(self) -> None:
        legacy = (ASIC_SRC / "bm1489.rs").read_text(encoding="utf-8")
        feature = (ASIC_SRC / "scrypt_l7.rs").read_text(encoding="utf-8")
        registry = (ASIC_SRC / "mod.rs").read_text(encoding="utf-8")
        for needle in (
            "SIMULATOR-ONLY SCAFFOLD",
            "BM1489 init_chain: SCAFFOLD",
            "BM1489 set_frequency: SCAFFOLD",
            "BM1489 send_work: SCAFFOLD",
            "synthetic decode for simulator",
            "init_chain_returns_scaffold_error_on_simulator",
        ):
            self.assertIn(needle, legacy)
        for needle in (
            "chain/work-FIFO transport",
            "ScryptL7 set_frequency deferred",
            "ScryptL7 send_work deferred",
            "PIC path is inert",
            "synthetic decode",
            "init_and_send_work_fail_closed_deferred",
        ):
            self.assertIn(needle, feature)
        self.assertIn('#[cfg(feature = "scrypt-l7")]', registry)
        self.assertIn("Box::new(scrypt_l7::ScryptL7Driver::new())", registry)
        self.assertIn("ChipDriverMaturity::Scaffold", registry)

    def test_workflow_runs_common_and_feature_scaffold_suites_safely(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1489_",
            workflow,
        )
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-asic --features scrypt-l7 --lib -- drivers::scrypt_l7",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1489_l7_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
