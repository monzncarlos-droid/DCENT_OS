#!/usr/bin/env python3
"""Unit tests for check_work_dispatch_ci_coverage (drives shipped inventory pin)."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_work_dispatch_ci_coverage.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_work_dispatch_ci_coverage", SCRIPT
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class WorkDispatchCiCoverageTests(unittest.TestCase):
    def test_repo_sources_expose_lifecycle_suite_per_engine(self):
        mod = _load()
        for engine, path in mod.ENGINE_MODULES:
            names = mod.work_dispatch_tests_in_source(path)
            # serial/stock: 7 lifecycle; hybrid: 7 + P1-5 multi-PIC; daemon: 9
            if engine == "s19j_hybrid_mining":
                minimum = 8
            elif engine == "daemon":
                minimum = 9
            else:
                minimum = 7
            self.assertGreaterEqual(
                len(names),
                minimum,
                f"{engine} work_dispatch_admission_tests should have ≥{minimum} tests, got {names}",
            )
        hybrid = mod.work_dispatch_tests_in_source(mod.HYBRID_SRC)
        self.assertIn(
            "multi_pic_voltage_enable_uses_production_powerup_planner",
            hybrid,
        )

    def test_required_selectors_use_sibling_module_path(self):
        """Not serial_mining::tests::... — sibling work_dispatch_admission_tests."""
        mod = _load()
        selectors = mod.required_work_dispatch_selectors()
        self.assertTrue(
            any(
                s.startswith("serial_mining::work_dispatch_admission_tests::")
                for s in selectors
            )
        )
        self.assertFalse(
            any(
                "::tests::work_dispatch_admission_tests::" in s for s in selectors
            ),
            "must not nest work_dispatch under tests:: (sibling module)",
        )
        self.assertIn(
            "serial_mining::work_dispatch_admission_tests::serial_admit_green_succeeds",
            selectors,
        )
        self.assertIn(
            "s19j_hybrid_mining::work_dispatch_admission_tests::hybrid_admit_green_succeeds",
            selectors,
        )
        self.assertTrue(
            any(
                s.startswith("stock_mining::work_dispatch_admission_tests::")
                for s in selectors
            )
        )
        self.assertTrue(
            any(
                s.startswith("daemon::work_dispatch_admission_tests::")
                for s in selectors
            )
        )
        self.assertIn(
            "daemon::work_dispatch_admission_tests::daemon_admit_green_succeeds_with_initialized_pics",
            selectors,
        )

    def test_repo_workflow_and_static_pass_after_wiring(self):
        """Drive the real default paths (post-wiring acceptance)."""
        mod = _load()
        self.assertTrue(mod.WORKFLOW.is_file())
        self.assertTrue(mod.STATIC_GATE.is_file())
        rc = mod.main([])
        self.assertEqual(
            rc,
            0,
            "repo workflow + static inventory must wire all must-have selectors",
        )

    def test_missing_selector_fails(self):
        mod = _load()
        required = mod.all_required_selectors()
        self.assertGreaterEqual(len(required), 21)
        # Build minimal workflow/static missing one serial admit test.
        keep = [s for s in required if "serial_admit_green_succeeds" not in s]
        lines = [
            f"sh ../scripts/run_exact_cargo_test.sh {s} --locked -p dcentrald --bin dcentrald"
            for s in keep
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wf = root / "wf.yml"
            st = root / "static.sh"
            body = "\n".join(lines) + "\n"
            wf.write_text(body, encoding="utf-8")
            st.write_text(body, encoding="utf-8")
            failures = mod.check_coverage(workflow_path=wf, static_path=st)
            self.assertTrue(
                any("serial_admit_green_succeeds" in f for f in failures),
                failures,
            )

    def test_serial_must_wire_includes_bip320_and_hash_on_disconnect(self):
        mod = _load()
        extra = mod.required_serial_must_wire_selectors()
        self.assertTrue(
            any("serial_rolled_version_reconstructs" in s for s in extra)
        )
        self.assertTrue(
            any("hash_on_disconnect" in s for s in extra)
        )

    def test_repo_has_zero_serial_tests_orphans(self):
        """Ratchet: every serial_mining::tests unit is exact-wired (tier-5)."""
        mod = _load()
        under = set(mod.inventory_serial_tests_under_tests_mod())
        wf_sel = mod.selectors_from_commands(
            mod.extract_exact_commands(mod.WORKFLOW)
        )
        wired = {
            s.removeprefix("serial_mining::tests::")
            for s in wf_sel
            if s.startswith("serial_mining::tests::")
        }
        orphans = sorted(under - wired)
        self.assertEqual(
            orphans,
            [],
            f"serial_mining::tests orphans must be empty, got {orphans}",
        )
        # Tier list entries must still exist in source.
        unknown = sorted(set(mod.SERIAL_MUST_WIRE_UNDER_TESTS) - under)
        self.assertEqual(
            unknown,
            [],
            f"SERIAL_MUST_WIRE_UNDER_TESTS has stale names: {unknown}",
        )

    def test_repo_has_zero_hybrid_tests_orphans(self):
        """Ratchet: every s19j_hybrid_mining::tests unit is exact-wired."""
        mod = _load()
        under = set(mod.inventory_hybrid_tests_under_tests_mod())
        wf_sel = mod.selectors_from_commands(
            mod.extract_exact_commands(mod.WORKFLOW)
        )
        wired = {
            s.removeprefix("s19j_hybrid_mining::tests::")
            for s in wf_sel
            if s.startswith("s19j_hybrid_mining::tests::")
        }
        orphans = sorted(under - wired)
        self.assertEqual(
            orphans,
            [],
            f"s19j_hybrid_mining::tests orphans must be empty, got {orphans}",
        )
        self.assertGreaterEqual(len(under), 80, "hybrid tests inventory unexpectedly small")


if __name__ == "__main__":
    unittest.main()
