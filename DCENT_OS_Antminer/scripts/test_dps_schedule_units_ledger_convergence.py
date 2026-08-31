#!/usr/bin/env python3
"""Pin DPS night scheduling, time, and hashrate units to exact ownership."""

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

ROW_ID = "feature.dps"
ROW_MODULES = ["night_power", "time", "units"]
CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_dps_schedule_units_ledger_convergence.py "
    "-q (6/6)"
)
REQUIRED_TESTS = {
    "cargo +1.90.0 test -p dcentrald-autotuner dps --lib (33/33)",
    "daemon source contract: DCENT_DPS_GOVERNOR_SHADOW remains observe-only while PowerTarget and HashrateTarget use the existing tuner command path",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- night_power::tests (11/11)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- time::tests (5/5)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- units::tests (3/3)",
    CONVERGENCE_TEST,
}


class DpsScheduleUnitsLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}
        cls.row = cls.entries[ROW_ID]

    def test_row_owns_exact_nonduplicated_common_modules(self) -> None:
        owners: dict[str, list[str]] = {}
        for entry in self.entries.values():
            for module in entry.get("offline_contract_modules", []):
                owners.setdefault(module, []).append(entry["id"])
        self.assertEqual(self.row["offline_contract_modules"], ROW_MODULES)
        for module in ROW_MODULES:
            with self.subTest(module=module):
                self.assertEqual(owners[module], [ROW_ID])

    def test_modules_are_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for module in ROW_MODULES:
            with self.subTest(module=module):
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", self.row["dcentos_anchor"])

    def test_row_records_measured_depth_and_non_authorizing_scope(self) -> None:
        self.assertEqual(self.row["status"], "experimental")
        self.assertEqual(set(self.row["tests"]), REQUIRED_TESTS)
        self.assertGreaterEqual(len(self.row["safety"]), 8)
        self.assertGreaterEqual(len(self.row["instrumentation"]), 8)
        serialized = json.dumps(self.row, sort_keys=True)
        for needle in (
            "decrease-first night watt/frequency/fan policy",
            "1000x target error",
            "fresh below-hot board sample",
            "UTC-12 through UTC+14",
            "saved window or desired serial MHz",
            "unit math grants no target, actuator, device, or measurement authority",
        ):
            self.assertIn(needle, serialized)

    def test_night_policy_is_restrictive_and_restoration_is_temperature_gated(
        self,
    ) -> None:
        source = (COMMON_SRC / "night_power.rs").read_text(encoding="utf-8")
        for needle in (
            "NIGHT_FAN_PWM_SAFETY_CAP",
            "effective_night_fan_pwm",
            "effective_night_frequency_mhz",
            "serial_night_power_read_truth",
            "serial_midrun_frequency_step",
            "serial_pll_raise_permitted",
            "thermal_and_home_night_take_the_more_restrictive_cap",
            "home_night_frequency_is_live_and_most_restrictive",
        ):
            self.assertIn(needle, source)

    def test_time_and_units_make_boundary_errors_explicit(self) -> None:
        time_source = (COMMON_SRC / "time.rs").read_text(encoding="utf-8")
        units = (COMMON_SRC / "units.rs").read_text(encoding="utf-8")
        for needle in (
            "MIN_TZ_OFFSET_HOURS",
            "MAX_TZ_OFFSET_HOURS",
            "is_valid_tz_offset",
            "negative_offset_wraps_backward_past_midnight",
        ):
            self.assertIn(needle, time_source)
        for needle in (
            "GHS_PER_THS",
            "ghs_to_ths",
            "ths_to_ghs",
            "newtypes_convert_explicitly_not_silently",
        ):
            self.assertIn(needle, units)

    def test_workflow_and_aggregate_own_all_three_focused_contracts(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for module in ROW_MODULES:
            self.assertIn(
                "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common "
                f"--lib -- {module}::tests",
                workflow,
            )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dps_schedule_units_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
