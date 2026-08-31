#!/usr/bin/env python3
"""Pin PIC, manufacturing, and S21-family evidence modules to exact owners."""

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

ROW_MODULES = {
    "pic.catalog_registry": ["dspic_decode", "dspic_heartbeat"],
    "manufacturing.pattern_interfaces": ["factory_aging"],
    "pll.source_expectation_registry": ["pll_model", "s21_domain_adc", "s21_vco_hold"],
}

CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_evidence_registry_ledger_convergence.py "
    "-q (6/6)"
)

REQUIRED_TESTS = {
    "pic.catalog_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- dspic_decode::tests (13/13)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- dspic_heartbeat::tests (9/9)",
        CONVERGENCE_TEST,
    },
    "manufacturing.pattern_interfaces": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- factory_aging::tests (2/2)",
        CONVERGENCE_TEST,
    },
    "pll.source_expectation_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- pll_model (26/26)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s21_domain_adc::tests (7/7)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s21_vco_hold::tests (4/4)",
        CONVERGENCE_TEST,
    },
}


class EvidenceRegistryLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}

    def test_rows_own_exact_nonduplicated_common_modules(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        for row_id, modules in ROW_MODULES.items():
            with self.subTest(row=row_id):
                self.assertEqual(self.entries[row_id]["offline_contract_modules"], modules)
                for module in modules:
                    self.assertEqual(owners[module], [row_id])

    def test_modules_are_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for row_id, modules in ROW_MODULES.items():
            for module in modules:
                with self.subTest(module=module):
                    self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                    self.assertIn(f"pub mod {module};", lib_rs)
                    self.assertIn(f"{module}.rs", self.entries[row_id]["dcentos_anchor"])

    def test_rows_record_measured_depth_and_evidence_only_scope(self) -> None:
        expected_status = {
            "pic.catalog_registry": "evidence-insufficient",
            "manufacturing.pattern_interfaces": "experimental",
            "pll.source_expectation_registry": "evidence-insufficient",
        }
        needles = {
            "pic.catalog_registry": (
                "framed bytes cannot be decoded as bare",
                "fw8A scale parity remains unproved",
                "physically absent AM2 middle slot",
                "No watchdog authority",
            ),
            "manufacturing.pattern_interfaces": (
                "desk-only data",
                "explicitly refused as execution inputs",
                "S9 SE only where exact binary evidence agrees",
                "manufacturing authorization",
            ),
            "pll.source_expectation_registry": (
                "BM1370 path A",
                "BM1368 path B",
                "sealed per-SKU F/V envelope",
                "hw-threshold float default remains unknown",
            ),
        }
        for row_id, required_tests in REQUIRED_TESTS.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["status"], expected_status[row_id])
                self.assertTrue(required_tests.issubset(set(entry["tests"])))
                self.assertGreaterEqual(len(entry["safety"]), 5)
                self.assertGreaterEqual(len(entry["instrumentation"]), 5)
                serialized = json.dumps(entry, sort_keys=True)
                for needle in needles[row_id]:
                    self.assertIn(needle, serialized)

    def test_dspic_decode_and_heartbeat_remain_fail_closed(self) -> None:
        decode = (COMMON_SRC / "dspic_decode.rs").read_text(encoding="utf-8")
        heartbeat = (COMMON_SRC / "dspic_heartbeat.rs").read_text(encoding="utf-8")
        for needle in (
            "BareVoltageReplyError::NotBareShape",
            "FramedMeasureVoltageReplyError::ZeroRail",
            "framed_measure_voltage_i2c0_envelope_adc",
            "framed_fw89_measure_rejects_cmd_echo_shape",
            "framed_fw89_measure_rejects_old_shift_artifact",
        ):
            self.assertIn(needle, decode)
        for needle in (
            "Some(eff) if eff != selected => vec![eff]",
            "multi_chain_with_sparse_pic_addresses_skips_none_without_inventing",
            "empty_topology_fail_closes_to_empty_map",
            "production_daemon_builds_pic_temp_chain_map_before_dispatch_chains_move",
        ):
            self.assertIn(needle, heartbeat)

    def test_factory_and_s21_evidence_never_enable_execution(self) -> None:
        factory = (COMMON_SRC / "factory_aging.rs").read_text(encoding="utf-8")
        adc = (COMMON_SRC / "s21_domain_adc.rs").read_text(encoding="utf-8")
        vco = (COMMON_SRC / "s21_vco_hold.rs").read_text(encoding="utf-8")
        for needle in (
            "refuse_factory_voltage_token_as_sweep_start",
            "refuse_pattern_path_as_runtime_work",
            "refuse_factory_aging_execute",
            "scan_work_counts_and_refusals_drive_shipped_functions",
        ):
            self.assertIn(needle, factory)
        for needle in (
            "path_a_bm1370_volts",
            "path_b_bm1368_reg_volts",
            "S21DomainAdcError::SealedEnvelopeRequired",
            "upward_admit_refuses_without_telemetry_climb_stays_off",
        ):
            self.assertIn(needle, adc)
        for needle in (
            "S21_AUTOTUNE_ENABLED: bool = false",
            "S21_DOMAIN_CLIMB_ENABLED: bool = false",
            "HwThresholdFloatDefaultDeskPending",
            "refuse_s21_domain_climb",
        ):
            self.assertIn(needle, vco)

    def test_workflow_and_aggregate_own_all_five_focused_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in (
            "dspic_decode",
            "dspic_heartbeat",
            "factory_aging",
            "s21_domain_adc",
            "s21_vco_hold",
        ):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_evidence_registry_ledger_convergence.py -q", aggregate)
        self.assertIn("scripts/test_foundational_registry_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
