#!/usr/bin/env python3
"""Pin BM1385/S7 exact evidence, source, ledger, and CI to one contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
FIXTURES = DCENTOS_ROOT / "tools" / "fixtures" / "bm1385_s7"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_FIXTURES = {
    "Config.ini-S7-45": (
        2_055,
        "632abf407d5ea7f527f219322d3470ab9a1e2756b33dc0471ed1e01cc2b361c2",
    ),
    "Config.ini-S7-54": (
        2_066,
        "7df112aef6246d376f6c02088ad1e9baeac72d8bbfd8b351232f56704baa1177",
    ),
}


class Bm1385S7ConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1385"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1385 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ci_fixtures_remain_byte_identical_to_the_admitted_hashes(self) -> None:
        self.assertEqual(
            {path.name for path in FIXTURES.iterdir() if path.is_file()},
            set(EXPECTED_FIXTURES),
        )
        for name, (size, digest) in EXPECTED_FIXTURES.items():
            data = (FIXTURES / name).read_bytes()
            self.assertEqual(len(data), size)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_host_pure_module_is_exported_and_keeps_every_authority_false(self) -> None:
        source = (COMMON_SRC / "bm1385_s7_offline.rs").read_text(encoding="utf-8")
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod bm1385_s7_offline;", lib_rs)
        for field in (
            "device_io: false",
            "runtime_admission: false",
            "transport: false",
            "work_dispatch: false",
            "share_submission: false",
            "voltage_control: false",
            "thermal_control: false",
            "rail_power: false",
            "install: false",
        ):
            self.assertIn(field, source)
        self.assertIn("OfflineEvidenceOnly", source)
        self.assertIn("NoReturnedCrc", source)
        self.assertIn("RegisterCrc5Verified", source)
        self.assertIn("UnknownFactoryFrequency", source)

    def test_ledger_records_depth_without_promoting_runtime(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["offline_contract_modules"], ["bm1385_s7_offline"])
        self.assertNotIn(
            "acceptance_chip_labels",
            self.entry,
            "BM1385 has no acceptance-registry SKU and must not forge one",
        )
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "10/10",
            "5/5",
            "2/2",
            "CRC5 over 27 bits",
            "CRC5 over 35 bits",
            "NoReturnedCrc",
            "OfflineEvidenceOnly",
            EXPECTED_FIXTURES["Config.ini-S7-45"][1],
            EXPECTED_FIXTURES["Config.ini-S7-54"][1],
        ):
            self.assertIn(needle, row)
        self.assertNotIn("S7-45 versus S7-54 topology binding", row)

    def test_ledger_keeps_the_current_live_blockers_and_raw_value_caveat(self) -> None:
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "carrier-bound passive enumeration",
            "deployed FIL",
            "voltage-controller command",
            "external LM75A",
            "independent thermal cutoff",
            "verified rail-off",
            "known-work",
            "accepted-share",
            "Pic_VOLTAGE=1 with IICPic=0 and DAC=0",
            "0x1385",
        ):
            self.assertIn(needle, row)

    def test_workflow_executes_both_zero_match_safe_rust_and_bytes_tests(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1385_",
            workflow,
        )
        self.assertIn(
            "python3 -m pytest -q tools/test_bm1385_s7_factory_evidence.py",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1385_s7_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
