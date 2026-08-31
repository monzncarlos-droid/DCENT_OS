#!/usr/bin/env python3
"""Pin Zynq topology and common voltage contracts to exact ledger owners."""

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
    "platform.zynq": ["am2_topology", "xil_dual_chain_desk"],
    "voltage_controller.model_scoped": ["at3_rail", "chain_voltage", "voltage_rail"],
}

CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_zynq_voltage_ledger_convergence.py "
    "-q (6/6)"
)

REQUIRED_TESTS = {
    "platform.zynq": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- am2_topology::tests (1/1)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- xil_dual_chain_desk::tests (3/3)",
        CONVERGENCE_TEST,
    },
    "voltage_controller.model_scoped": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- at3_rail::tests (6/6)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- chain_voltage::tests (13/13)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- voltage_rail::tests (40/40)",
        CONVERGENCE_TEST,
    },
}


class ZynqVoltageLedgerConvergenceTests(unittest.TestCase):
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

    def test_rows_record_measured_depth_and_authority_ceilings(self) -> None:
        needles = {
            "platform.zynq": (
                "four-slot UART",
                "desk-only missing-SKU",
                "caller-recorded observations",
                "never cross-correlate",
            ),
            "voltage_controller.model_scoped": (
                "implausible",
                "bounded TTL",
                "public process-global AT-3 publisher",
                "runtime-discovered",
                "electrical readback",
            ),
        }
        for row_id, required_tests in REQUIRED_TESTS.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["status"], "experimental")
                self.assertTrue(required_tests.issubset(set(entry["tests"])))
                self.assertGreaterEqual(len(entry["safety"]), 7)
                self.assertGreaterEqual(len(entry["instrumentation"]), 7)
                serialized = json.dumps(entry, sort_keys=True)
                for needle in needles[row_id]:
                    self.assertIn(needle, serialized)

    def test_zynq_topology_stays_static_desk_only_and_chain_isolated(self) -> None:
        topology = (COMMON_SRC / "am2_topology.rs").read_text(encoding="utf-8")
        desk = (COMMON_SRC / "xil_dual_chain_desk.rs").read_text(encoding="utf-8")
        for needle in (
            'pub const AM2_SLOT_UARTS: [&str; AM2_SLOT_COUNT]',
            'pub const AM2_SLOT_DSPIC_ADDRS: [u8; AM2_SLOT_COUNT]',
            'assert_eq!(slot_for_uart("/dev/ttyS5"), None)',
            'assert_eq!(dspic_address_for_slot(4), None)',
        ):
            self.assertIn(needle, topology)
        for needle in (
            "XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP",
            "desk_slots_are_independent",
            "XilDeskLedgerMergeError::CrossCorrelateForbidden",
            "presence_reset_get_address_work_ledgers_do_not_cross_correlate",
        ):
            self.assertIn(needle, desk)

    def test_voltage_readback_and_admission_fail_closed(self) -> None:
        at3 = (COMMON_SRC / "at3_rail.rs").read_text(encoding="utf-8")
        chain = (COMMON_SRC / "chain_voltage.rs").read_text(encoding="utf-8")
        rail = (COMMON_SRC / "voltage_rail.rs").read_text(encoding="utf-8")
        for needle in (
            "pub const DEFAULT_FRESH_TTL: Duration = Duration::from_secs(90)",
            "pub fn publish(chain_id: u8, mv: u16, fw8a_scale_unverified: bool)",
            "a_stale_reading_is_excluded_from_the_snapshot",
            "advisory_snapshot_carries_the_fw8a_flag",
        ):
            self.assertIn(needle, at3)
        for needle in (
            "pub const fn plausible_rail_mv",
            "mv > 0 && mv <= max_mv",
            "from_0x3a_reply_dead_rail_falls_back_to_commanded_not_a_fake_zero",
            "RailVoltageSource::Unknown",
        ):
            self.assertIn(needle, chain)
        for needle in (
            "VoltageRailAdapterKind::RuntimeDiscovered",
            "ExternalDacNoPic energize not implemented",
            "admit_dspic_firmware_for_energize",
            "energize_stops_before_enable_if_set_refused",
            "safe_off_and_walk_down_order",
        ):
            self.assertIn(needle, rail)

    def test_workflow_and_aggregate_own_all_five_focused_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in (
            "am2_topology",
            "xil_dual_chain_desk",
            "at3_rail",
            "chain_voltage",
            "voltage_rail",
        ):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_zynq_voltage_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
