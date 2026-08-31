#!/usr/bin/env python3
"""Pin recovery durability and diagnostic privacy to exact ledger owners."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DCENTRALD_ROOT = DCENTOS_ROOT / "dcentrald"
COMMON_SRC = DCENTRALD_ROOT / "dcentrald-common" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

ROW_MODULES = {
    "recovery.interface_registry": ["atomic_file", "mutation_disposition"],
    "feature.diagnostics_repair": [
        "diagnostic_mode",
        "measurement",
        "wallet_mask",
    ],
}
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/"
    "test_recovery_durability_privacy_ledger_convergence.py -q (6/6)"
)
REQUIRED_TESTS = {
    "recovery.interface_registry": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- atomic_file::tests (13/13)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- mutation_disposition::tests (12/12)",
        CONVERGENCE_TEST,
    },
    "feature.diagnostics_repair": {
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- wallet_mask::tests (27/27)",
        CONVERGENCE_TEST,
    },
}


class RecoveryDurabilityPrivacyLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}

    def test_rows_own_exact_nonduplicated_module_sets(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        for row_id, modules in ROW_MODULES.items():
            with self.subTest(row=row_id):
                self.assertEqual(
                    self.entries[row_id]["offline_contract_modules"], modules
                )
                for module in modules:
                    self.assertEqual(owners[module], [row_id])

    def test_modules_are_compile_exported_anchored_and_measured(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for row_id, modules in ROW_MODULES.items():
            entry = self.entries[row_id]
            self.assertTrue(REQUIRED_TESTS[row_id].issubset(set(entry["tests"])))
            for module in modules:
                with self.subTest(module=module):
                    self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                    self.assertIn(f"pub mod {module};", lib_rs)
                    self.assertIn(f"{module}.rs", entry["dcentos_anchor"])

    def test_atomic_and_mutation_contracts_preserve_ambiguity(self) -> None:
        atomic = (COMMON_SRC / "atomic_file.rs").read_text(encoding="utf-8")
        mutation = (COMMON_SRC / "mutation_disposition.rs").read_text(encoding="utf-8")
        for needle in (
            "directory_sync_failure_reports_already_published_target",
            "directory_sync_failure_reports_unlinked_but_not_durable",
            "symlink_target_is_rejected_without_following_it",
            "concurrent_writers_publish_one_complete_payload",
        ):
            self.assertIn(needle, atomic)
        for needle in (
            "foreign_boot_id_is_unresolved_and_never_auto_cleared",
            "corruption_and_symlinks_are_unreadable_refusals_never_absence",
            "mutated_without_receipt_refuses_and_typed_safe_off_receipt_admits",
            "clear_authority_is_one_use_and_bound_to_the_loaded_resolved_path",
        ):
            self.assertIn(needle, mutation)

    def test_ledger_names_receipt_clear_and_privacy_ceiling(self) -> None:
        recovery = json.dumps(
            self.entries["recovery.interface_registry"], sort_keys=True
        )
        diagnostic = json.dumps(
            self.entries["feature.diagnostics_repair"], sort_keys=True
        )
        for needle in (
            "freely constructible typed receipt",
            "direct path-only clearing and clearance retargeting are unavailable",
            "does not prove a watchdog was armed",
            "do not authenticate receipt constructors",
        ):
            self.assertIn(needle, recovery)
        for needle in (
            "privacy display transform, not anonymization",
            "WIF/xpub material is deliberately outside the detector",
            "first-six/last-four remain linkable",
            "property-generated arbitrary text",
        ):
            self.assertIn(needle, diagnostic)

    def test_wallet_mask_is_bounded_and_consumed_at_publication_edges(self) -> None:
        wallet = (COMMON_SRC / "wallet_mask.rs").read_text(encoding="utf-8")
        for needle in (
            "pub fn mask_wallet(addr: &str) -> String",
            "pub fn is_likely_wallet(s: &str) -> bool",
            "pub fn mask_in_string(s: &str) -> Cow<'_, str>",
            "bech32_mixed_case_not_masked",
            "per_call_mask_independent_of_passthrough_gate",
        ):
            self.assertIn(needle, wallet)
        consumers = (DCENTRALD_ROOT / "dcentrald-api" / "src" / "rest.rs").read_text(
            encoding="utf-8"
        )
        stratum = (
            DCENTRALD_ROOT / "dcentrald-stratum" / "src" / "v1" / "client.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("wallet_mask::mask_in_string", consumers)
        self.assertIn("wallet_mask::mask_wallet", consumers)
        self.assertIn("wallet_mask::mask_wallet", stratum)

    def test_workflow_and_aggregate_own_all_contracts_and_prior_guard(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in ("atomic_file", "mutation_disposition", "wallet_mask"):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_recovery_durability_privacy_ledger_convergence.py -q",
            aggregate,
        )
        self.assertIn("scripts/test_feature_policy_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
