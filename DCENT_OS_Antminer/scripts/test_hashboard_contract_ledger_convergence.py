#!/usr/bin/env python3
"""Pin shared hashboard composition contracts to exact ledger and CI ownership."""

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
CORE_MODULES = ["asic_protocol", "chain_transport", "hashrate_geometry", "interconnect"]
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_hashboard_contract_ledger_convergence.py "
    "-q (6/6)"
)
REQUIRED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- asic_protocol::tests (13/13)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- chain_transport::tests (34/34)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- hashrate_geometry::tests (8/8)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- interconnect::tests (10/10)",
    CONVERGENCE_TEST,
}


class HashboardContractLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.row = cls.entries[ROW_ID]

    def test_row_owns_required_nonduplicated_core_common_modules(self) -> None:
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

    def test_row_records_measured_depth_and_non_authorizing_scope(self) -> None:
        self.assertEqual(self.row["status"], "evidence-insufficient")
        self.assertTrue(REQUIRED_TESTS.issubset(set(self.row["tests"])))
        self.assertGreaterEqual(len(self.row["safety"]), 6)
        self.assertGreaterEqual(len(self.row["instrumentation"]), 6)
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "do not prove a physically attached hashboard",
            "runtime-discovered silicon",
            "empty work frames",
            "fabricated multi-TH default",
            "S17/S19 connector descriptions remain explicitly partial",
            "no offline contract in this row grants device",
        ):
            self.assertIn(needle, serialized)

    def test_protocol_and_transport_contracts_fail_closed(self) -> None:
        protocol = (COMMON_SRC / "asic_protocol.rs").read_text(encoding="utf-8")
        transport = (COMMON_SRC / "chain_transport.rs").read_text(encoding="utf-8")
        for needle in (
            "ManagementOnlyTransport",
            "RuntimeDiscoveredProtocol",
            "bm1391_catalog_identity_refuses_active_transports",
            "bm1396_pure_contract_does_not_admit_an_active_carrier_or_work",
        ):
            self.assertIn(needle, protocol)
        for needle in (
            "RecordingChainTransport",
            "empty_work_frame_refused",
            "stock_fpga_backend_refuses_bm1397plus_even_if_protocol_were_1397",
            "live_hal_bm1397plus_backend_remains_the_io_twin",
        ):
            self.assertIn(needle, transport)

    def test_geometry_and_interconnect_preserve_evidence_boundaries(self) -> None:
        geometry = (COMMON_SRC / "hashrate_geometry.rs").read_text(encoding="utf-8")
        interconnect = (COMMON_SRC / "interconnect.rs").read_text(encoding="utf-8")
        for needle in (
            "nominal_hashrate_ghs_from_geometry",
            "geometry_nominal_refuses_empty_enum",
            "daemon_post_enum_paths_wire_enumerated_stratum_nominal",
        ):
            self.assertIn(needle, geometry)
        for needle in (
            "PresencePolarity::ActiveHigh",
            "s17_s19_family_maps_stay_partial_and_presence_free",
            "s15_en_pin_is_name_only",
            "every_connector_is_cited_and_consistent",
        ):
            self.assertIn(needle, interconnect)

    def test_workflow_and_aggregate_own_all_four_focused_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in CORE_MODULES:
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_hashboard_contract_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
