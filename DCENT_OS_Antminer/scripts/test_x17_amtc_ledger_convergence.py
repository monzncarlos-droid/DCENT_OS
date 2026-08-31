#!/usr/bin/env python3
"""Pin X17 AMTC factory/recovery module ownership and authority refusal."""

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

FACTORY_MODULE = "x17_amtc_factory_evidence"
RECOVERY_MODULE = "x17_amtc_recovery_evidence"
BM1397_MODULES = {"bm1397_s17_bhb07601", FACTORY_MODULE}

RECOVERY_TESTS = {
    "Windows held corpus: py -3 -m pytest -q test_x17_amtc_evidence.py --rootdir=. from DCENT_OS_Antminer/tools (12/12)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- x17_amtc_recovery_evidence (5/5)",
    "python DCENT_OS_Antminer/scripts/test_x17_amtc_ledger_convergence.py -q (6/6)",
}


class X17AmtcLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.factory = cls.entries["asic.bm1397"]
        cls.recovery = cls.entries["recovery.x17_amtc_archive_evidence"]
        cls.bm1396 = cls.entries["asic.bm1396"]

    def test_factory_and_recovery_modules_have_one_nonduplicated_owner(self) -> None:
        self.assertEqual(set(self.factory["offline_contract_modules"]), BM1397_MODULES)
        self.assertEqual(self.recovery["offline_contract_modules"], [RECOVERY_MODULE])
        self.assertNotIn(RECOVERY_MODULE, self.bm1396["offline_contract_modules"])

        owners = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        self.assertEqual(owners[FACTORY_MODULE], ["asic.bm1397"])
        self.assertEqual(
            owners[RECOVERY_MODULE], ["recovery.x17_amtc_archive_evidence"]
        )

    def test_both_contract_modules_are_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for module, entry in (
            (FACTORY_MODULE, self.factory),
            (RECOVERY_MODULE, self.recovery),
        ):
            with self.subTest(module=module):
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", entry["dcentos_anchor"])

    def test_rows_record_exact_scope_and_measured_ownership(self) -> None:
        self.assertEqual(self.factory["status"], "evidence-insufficient")
        self.assertEqual(self.recovery["status"], "evidence-insufficient")
        self.assertEqual(set(self.recovery["tests"]), RECOVERY_TESTS)
        self.assertGreaterEqual(len(self.factory["safety"]), 8)
        self.assertGreaterEqual(len(self.factory["instrumentation"]), 8)
        self.assertGreaterEqual(len(self.recovery["safety"]), 3)
        self.assertGreaterEqual(len(self.recovery["instrumentation"]), 5)

        factory = json.dumps(self.factory, sort_keys=True)
        recovery = json.dumps(self.recovery, sort_keys=True)
        for needle in (
            "factory evidence is not production",
            "BHB07601",
            "BHB07702",
            "x17_amtc_factory_evidence (5/5)",
        ):
            self.assertIn(needle, factory)
        for needle in (
            "no runme.sh",
            "MD5",
            "unchecked command statuses",
            "no rollback",
            "NOT-IMPLEMENTED",
        ):
            self.assertIn(needle, recovery)

    def test_factory_and_recovery_authority_methods_all_return_false(self) -> None:
        expectations = {
            FACTORY_MODULE: (
                "X17AmtcFactoryAuthority::EvidenceOnly",
                "X17_AMTC_FACTORY_UNRESOLVED: [&str; 7]",
            ),
            RECOVERY_MODULE: (
                "X17RecoveryAuthority::EvidenceOnly",
                "X17_RECOVERY_UNRESOLVED: [&str; 6]",
            ),
        }
        for module, required in expectations.items():
            with self.subTest(module=module):
                source = (COMMON_SRC / f"{module}.rs").read_text(encoding="utf-8")
                for needle in required:
                    self.assertIn(needle, source)
                authority = source.split("impl ", 1)[1].split("#[cfg(test)]", 1)[0]
                self.assertEqual(authority.count("pub const fn permits_"), 5)
                self.assertGreaterEqual(authority.count("false\n    }"), 5)

    def test_workflow_runs_both_zero_match_safe_rust_owners(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in (FACTORY_MODULE, RECOVERY_MODULE):
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}",
                workflow,
            )

    def test_aggregate_owns_new_and_updated_convergence_suites(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        for suite in (
            "scripts/test_bm1397_s17_t17_ledger_convergence.py -q",
            "scripts/test_x17_amtc_ledger_convergence.py -q",
        ):
            self.assertIn(suite, aggregate)


if __name__ == "__main__":
    unittest.main()
