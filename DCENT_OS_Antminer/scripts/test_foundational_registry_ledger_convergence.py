#!/usr/bin/env python3
"""Pin foundational common registries to exact ledger and CI ownership."""

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
    "firmware.package_producer_registry": "artifact_producer",
    "control_board.boarddesc_backlog": "board_desc",
    "install.route_method_registry": "install_matrix",
    "pll.source_expectation_registry": "pll_model",
}

CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_foundational_registry_ledger_convergence.py "
    "-q (6/6)"
)

ROW_TESTS = {
    "firmware.package_producer_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- artifact_producer (5/5)",
        CONVERGENCE_TEST,
    },
    "control_board.boarddesc_backlog": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- board_desc (61/61)",
        CONVERGENCE_TEST,
    },
    "install.route_method_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- install_matrix (18/18)",
        CONVERGENCE_TEST,
    },
    "pll.source_expectation_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- pll_model (26/26)",
        CONVERGENCE_TEST,
    },
}


class FoundationalRegistryLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}

    def test_each_registry_row_owns_its_exact_core_common_module(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        for row_id, module in ROW_MODULES.items():
            with self.subTest(row=row_id):
                self.assertIn(module, self.entries[row_id]["offline_contract_modules"])
                self.assertEqual(owners[module], [row_id])

    def test_modules_are_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for row_id, module in ROW_MODULES.items():
            with self.subTest(module=module):
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", self.entries[row_id]["dcentos_anchor"])

    def test_rows_record_measured_depth_and_fail_closed_scope(self) -> None:
        needles = {
            "firmware.package_producer_registry": (
                "15 primary",
                "PackageOnlyDenied",
                "artifact_producers.json",
                "uniform release claim",
            ),
            "control_board.boarddesc_backlog": (
                "12 exact BoardDesc",
                "ManagementOnlyByPolicy",
                "unknown targets return no descriptor",
                "acceptance release state",
            ),
            "install.route_method_registry": (
                "63 control-board routes",
                "120 board/method",
                "persistent-writer authority",
                "S9-only",
            ),
            "pll.source_expectation_registry": (
                "nine exact PLL",
                "0x1372",
                "non-25-MHz",
                "no executable PLL family",
            ),
        }
        for row_id, expected_tests in ROW_TESTS.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["status"], "evidence-insufficient")
                self.assertTrue(expected_tests.issubset(set(entry["tests"])))
                self.assertGreaterEqual(len(entry["safety"]), 4)
                self.assertGreaterEqual(len(entry["instrumentation"]), 4)
                row = json.dumps(entry, sort_keys=True)
                for needle in needles[row_id]:
                    self.assertIn(needle, row)

    def test_source_contracts_keep_registry_presence_non_authorizing(self) -> None:
        producer = (COMMON_SRC / "artifact_producer.rs").read_text(encoding="utf-8")
        board = (COMMON_SRC / "board_desc.rs").read_text(encoding="utf-8")
        install = (COMMON_SRC / "install_matrix.rs").read_text(encoding="utf-8")
        pll = (COMMON_SRC / "pll_model.rs").read_text(encoding="utf-8")
        for needle in (
            "ArtifactInstallContract::PackageOnlyDenied",
            "published_filenames_are_safe_unique_basenames",
            "producer_targets_are_unique_and_cover_every_artifact_claim",
        ):
            self.assertIn(needle, producer)
        for needle in (
            "pub fn lookup(board_target: &str) -> Option<&'static BoardDesc>",
            "unknown_target_is_none",
            "RuntimeStatus::ManagementOnlyByPolicy",
        ):
            self.assertIn(needle, board)
        for needle in (
            "public_beta_first_install_is_s9_only",
            "x19_aml_packages_grant_no_persistent_writer_authority",
            "t21_package_evidence_grants_no_persistent_writer_authority",
        ):
            self.assertIn(needle, install)
        for needle in (
            "admit_pll_reference_fails_closed_on_mismatch_and_undeclared",
            "protocol_mapping_refuses_stock_and_runtime",
            "pll_family_for_protocol",
        ):
            self.assertIn(needle, pll)

    def test_workflow_runs_all_four_zero_match_safe_owners(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in ROW_MODULES.values():
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}",
                workflow,
            )

    def test_aggregate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_foundational_registry_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
