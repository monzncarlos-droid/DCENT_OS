#!/usr/bin/env python3
"""Pin opaque, exact-path mutation-journal clearance across source and CI."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
DCENTRALD_ROOT = DCENTOS_ROOT / "dcentrald"
COMMON = DCENTRALD_ROOT / "dcentrald-common" / "src" / "mutation_disposition.rs"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

ROW_ID = "recovery.interface_registry"
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/"
    "test_mutation_clearance_ledger_convergence.py -q (6/6)"
)


class MutationClearanceLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.row = next(entry for entry in ledger["entries"] if entry["id"] == ROW_ID)
        cls.source = COMMON.read_text(encoding="utf-8")

    def test_recovery_owner_retains_exact_modules_and_measured_depth(self) -> None:
        self.assertEqual(
            self.row["offline_contract_modules"],
            ["atomic_file", "mutation_disposition"],
        )
        self.assertEqual(self.row["status"], "evidence-insufficient")
        required = {
            "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- mutation_disposition::tests (12/12)",
            "Linux: cargo test --locked -p dcentrald-hal --test mutation_disposition_crash (3/3)",
            CONVERGENCE_TEST,
        }
        self.assertTrue(required.issubset(set(self.row["tests"])))

    def test_adjudication_and_clearance_are_opaque_and_path_bound(self) -> None:
        for needle in (
            "enum MutationDispositionState",
            "pub struct MutationDispositionAdjudication",
            "path: PathBuf",
            "pub struct MutationClearance",
            "clearance: record.as_ref().map",
            "path: adjudication.path.clone()",
        ):
            self.assertIn(needle, self.source)
        self.assertNotIn("pub enum MutationDispositionAdjudication", self.source)
        self.assertNotIn(
            "#[derive(Debug, Clone)]\npub struct MutationClearance", self.source
        )

    def test_clear_consumes_only_the_clearance_not_an_arbitrary_path(self) -> None:
        clear = self.source.partition("pub fn clear_mutation_disposition(")[2]
        self.assertTrue(clear, "clear function")
        signature = clear.partition("{")[0]
        self.assertIn("clearance: MutationClearance", signature)
        self.assertNotIn("impl AsRef<Path>", signature)
        self.assertIn("remove_file(clearance.path)", clear)
        self.assertIn(
            "clear_authority_is_one_use_and_bound_to_the_loaded_resolved_path",
            self.source,
        )
        self.assertIn("clearance must not retarget another path", self.source)

    def test_both_daemon_chokepoints_consume_path_bound_clearance(self) -> None:
        for relative in (
            Path("dcentrald") / "src" / "main.rs",
            Path("dcentrald") / "src" / "daemon.rs",
        ):
            source = (DCENTRALD_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertIn(".resolved_record()", source)
                self.assertIn("admission.into_clearance()", source)
                self.assertIn("clear_mutation_disposition(clearance)", source)
                self.assertNotIn(
                    "clear_mutation_disposition(&mutation_disposition_path)", source
                )
                self.assertNotIn("clear_mutation_disposition(&journal_path)", source)

    def test_ledger_preserves_receipt_provenance_and_physical_ceiling(self) -> None:
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "non-cloneable, exact-path MutationClearance",
            "TypedSafeOffReceipt values remain caller-constructible data",
            "do not authenticate receipt constructors",
            "prove physical SafeOff",
        ):
            self.assertIn(needle, serialized)

    def test_workflow_and_aggregate_own_unit_integration_and_guard(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- mutation_disposition::tests",
            workflow,
        )
        self.assertIn(
            "cargo test --locked -p dcentrald-hal --test mutation_disposition_crash",
            workflow,
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_mutation_clearance_ledger_convergence.py -q", aggregate
        )
        self.assertIn(
            "scripts/test_recovery_durability_privacy_ledger_convergence.py -q",
            aggregate,
        )


if __name__ == "__main__":
    unittest.main()
