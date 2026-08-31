#!/usr/bin/env python3
"""Pin the fabric-lease module/root API inventory and complete suite owner."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
FABRIC_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-fabric-lease"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_fabric_lease_surface_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_TYPES = {
    "FabricLeaseError",
    "I2cLeasePurpose",
    "OsI2cFabricLease",
    "PhysicalI2cFabricId",
}
EXPECTED_METHODS = {
    "acquire",
    "allocation",
    "fabric",
    "into_io_error",
    "io_kind",
    "is_busy",
    "linux_adapter",
    "validate_current_process",
}


class DcentraldFabricLeaseSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        cls.source = (FABRIC_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_registry_exactly_matches_module_and_root_public_surface(self) -> None:
        modules = set(re.findall(r"^pub mod ([A-Za-z0-9_]+) \{", self.source, re.M))
        self.assertEqual(modules, {"topology"})
        self.assertEqual(set(self.modules), modules)
        types = set(
            re.findall(r"^pub (?:struct|enum) ([A-Za-z0-9_]+)", self.source, re.M)
        )
        self.assertEqual(types, EXPECTED_TYPES)
        methods = set(
            re.findall(r"^    pub (?:const )?fn ([A-Za-z0-9_]+)\(", self.source, re.M)
        )
        self.assertEqual(methods, EXPECTED_METHODS)
        root = self.registry["crate_root_surface"]
        self.assertEqual(set(root["public_types"]), EXPECTED_TYPES)
        self.assertEqual(set(root["public_methods"]), EXPECTED_METHODS)

    def test_source_and_ledger_scope_exist_at_a_nonproduction_ceiling(self) -> None:
        rows = [*self.registry["modules"], self.registry["crate_root_surface"]]
        for row in rows:
            source = REPO_ROOT / row["source"]
            self.assertTrue(source.is_file(), source)
            self.assertTrue(row["ledger_rows"])
            self.assertGreaterEqual(len(row["authority_ceiling"]), 80)
            for owner in row["ledger_rows"]:
                self.assertIn(owner, self.ledger)
                self.assertIn(
                    self.ledger[owner]["status"],
                    {"experimental", "evidence-insufficient"},
                )

    def test_module_root_and_complete_test_accounting_is_exact(self) -> None:
        self.assertEqual(self.modules["topology"]["tests"], 0)
        self.assertEqual(
            self.modules["topology"]["public_constants"],
            [
                "AM2_PSU_GPIO",
                "STOCK_S9_FPGA_IIC",
                "NAMED_PHYSICAL_I2C_FABRICS",
            ],
        )
        root = self.registry["crate_root_surface"]
        self.assertEqual(root["test_prefix"], "tests")
        self.assertEqual(root["tests"], 14)
        self.assertEqual(self.registry["declared_public_modules"], 1)
        self.assertEqual(self.registry["declared_root_public_types"], 4)
        self.assertEqual(self.registry["declared_root_public_methods"], 8)
        self.assertEqual(self.registry["module_prefixed_tests"], 0)
        self.assertEqual(self.registry["crate_root_tests"], 14)
        self.assertEqual(self.registry["total_tests"], 14)

    def test_source_retains_load_bearing_ownership_boundaries(self) -> None:
        for needle in (
            "O_CLOEXEC | libc::O_NOFOLLOW",
            "libc::LOCK_EX | libc::LOCK_NB",
            "lease release must never unlink the file",
            "source_contract_never_unlinks_or_explicitly_unlocks",
            "copied_lease_state_rejects_a_different_process_identity",
            "subprocess_contention_and_sigkill_release_are_kernel_proven",
            "symlink_and_hardlink_lock_targets_are_refused",
        ):
            self.assertIn(needle, self.source)

    def test_registry_keeps_cooperation_separate_from_physical_authority(
        self,
    ) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-fabric-lease")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "cooperative flock lease",
            "same inode",
            "privileged bypass",
            "rail safety",
            "authorize any I2C or hardware operation",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_and_aggregate_own_complete_locked_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-fabric-lease --lib", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_fabric_lease_surface_registry.py -q",
            aggregate,
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("fabric-lease surface convergence", campaign)


if __name__ == "__main__":
    unittest.main()
