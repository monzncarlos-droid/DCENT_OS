#!/usr/bin/env python3
"""Pin shared hashboard work/bookkeeping contracts to exact ledger ownership."""

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

ROW_ID = "hashboard.catalog_registry"
CORE_MODULES = [
    "asic_protocol",
    "chain_transport",
    "hashrate_geometry",
    "interconnect",
    "serial_work_engine",
    "serial_work_policy",
    "ticket_mask",
]
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/"
    "test_hashboard_work_contract_ledger_convergence.py -q (6/6)"
)
REQUIRED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- asic_protocol::tests (13/13)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- chain_transport::tests (34/34)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- hashrate_geometry::tests (8/8)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- interconnect::tests (10/10)",
    "python DCENT_OS_Antminer/scripts/test_hashboard_contract_ledger_convergence.py -q (6/6)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- serial_work_engine::tests (43/43)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- serial_work_policy::tests (5/5)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- ticket_mask::tests (4/4)",
    CONVERGENCE_TEST,
}


class HashboardWorkContractLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.row = cls.entries[ROW_ID]

    def test_row_owns_required_nonduplicated_expanded_core_modules(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        self.assertTrue(
            set(CORE_MODULES).issubset(self.row["offline_contract_modules"])
        )
        for module in CORE_MODULES:
            with self.subTest(module=module):
                self.assertEqual(owners[module], [ROW_ID])

    def test_modules_are_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for module in CORE_MODULES:
            with self.subTest(module=module):
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", self.row["dcentos_anchor"])

    def test_row_records_measured_depth_and_work_authority_ceiling(self) -> None:
        self.assertEqual(self.row["status"], "evidence-insufficient")
        self.assertTrue(REQUIRED_TESTS.issubset(set(self.row["tests"])))
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "wire-byte progress",
            "generation-keyed dedup",
            "authenticated job/share/session ownership",
            "unknown identities never invent bit-reversal",
            "accepted-share",
            "carrier/lifecycle ownership",
        ):
            self.assertIn(needle, serialized)

    def test_serial_engine_keeps_progress_identity_and_execution_separate(self) -> None:
        source = (COMMON_SRC / "serial_work_engine.rs").read_text(encoding="utf-8")
        for needle in (
            "SerialMiningEngineBookkeeping",
            "s19k_track1_rx_death_parser_note",
            "serial_rx_interval_separates_wire_silence_from_parser_stall",
            "serial_bring_up_refuses_management_only_and_wrong_transport_kind",
            "am2_and_bb_plugins_share_bm1362_protocol_but_distinct_identity",
            "serial_bring_up_plugin_executes_on_recording_transport",
        ):
            self.assertIn(needle, source)

    def test_work_policy_and_ticket_encoding_remain_pure_and_scoped(self) -> None:
        policy = (COMMON_SRC / "serial_work_policy.rs").read_text(encoding="utf-8")
        ticket = (COMMON_SRC / "ticket_mask.rs").read_text(encoding="utf-8")
        for needle in (
            "GENERATION_SEEN_RETAIN_WINDOW",
            "generation_dedup_cutoff",
            "generation_dedup_key_and_cutoff_are_stable",
            "should_clear_seen_shares",
        ):
            self.assertIn(needle, policy)
        for needle in (
            "ticket_mask_encoding_for_chip_id",
            "bit_reverse_u32_bytewise",
            "bit_reversed_matches_bm1397_jig_goldens",
            "plain_matches_bm136x_fixtures",
            "chip_id_map_and_drivers_thin_wrap",
        ):
            self.assertIn(needle, ticket)

    def test_workflow_and_aggregate_own_all_three_new_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in ("serial_work_engine", "serial_work_policy", "ticket_mask"):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_hashboard_work_contract_ledger_convergence.py -q",
            aggregate,
        )
        self.assertIn(
            "scripts/test_hashboard_contract_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
