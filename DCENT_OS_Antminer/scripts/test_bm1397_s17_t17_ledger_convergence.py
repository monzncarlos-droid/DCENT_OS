#!/usr/bin/env python3
"""Pin the BM1397/S17/T17 source, ledger, experimental, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
ASIC_DRIVERS = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic" / "src" / "drivers"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_FAMILY_MODULES = {"bm1397_s17_bhb07601"}
EXPECTED_OFFLINE_MODULES = {
    "bm1397_s17_bhb07601",
    "x17_amtc_factory_evidence",
}

EXPECTED_TESTS = {
    "Windows: py -3 -m pytest -q test_x17_amtc_evidence.py --rootdir=. from tools/ (12/12 held corpus)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1397_ (21/21)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- x17_amtc_factory_evidence (5/5)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1397 --lib (3/3)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1397 --lib (12/12 data-only)",
    "python DCENT_OS_Antminer/scripts/test_bm1397_s17_t17_ledger_convergence.py -q (6/6)",
}


class Bm1397S17T17LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1397"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1397 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1397_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1397_*.rs")}
        self.assertEqual(source_modules, EXPECTED_FAMILY_MODULES)
        self.assertEqual(
            set(self.entry["offline_contract_modules"]), EXPECTED_OFFLINE_MODULES
        )

    def test_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in EXPECTED_OFFLINE_MODULES:
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)
        self.assertIn("drivers/bm1397.rs", anchor)

    def test_row_records_current_depth_acceptance_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["acceptance_chip_labels"], ["BM1397"])
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 8)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 8)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "exact-chip experimental policy",
            "production recognition returns no driver",
            "per-core open-core sweep",
            "factory evidence is not production",
            "wrong PIC16 voltage spine",
            "BM1396",
            "electrical rail-off",
            "accepted-share",
        ):
            self.assertIn(needle, row)

    def test_driver_and_registry_keep_experimental_execution_exactly_gated(self) -> None:
        driver = (ASIC_DRIVERS / "bm1397.rs").read_text(encoding="utf-8")
        registry = (ASIC_DRIVERS / "mod.rs").read_text(encoding="utf-8")
        skeleton = (COMMON_SRC / "bm1397_s17_bhb07601.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("impl ChipDriver for Bm1397Driver", driver)
        self.assertIn("SKIPS the", driver)
        self.assertIn("per-core open-core sweep", driver)
        self.assertIn("AsicProtocolIdentity::Bm1397", driver)
        self.assertIn("BM1397_MINING_DEFAULT_ENABLED: bool = false", skeleton)
        self.assertIn("FactoryEvidenceNotProduction", skeleton)
        self.assertIn("ChipDriverMaturity::Experimental", registry)
        self.assertIn("production.detect(bm1397::CHIP_ID).is_none()", registry)
        self.assertIn("ChipRegistry::with_experimental_driver(bm1397::CHIP_ID)", registry)
        self.assertIn("ChipRegistry::with_experimental_driver(bm1398::CHIP_ID)", registry)

    def test_workflow_runs_common_and_factory_suites_with_zero_match_guards(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1397_",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- x17_amtc_factory_evidence",
        ):
            self.assertIn(command, workflow)

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1397_s17_t17_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
