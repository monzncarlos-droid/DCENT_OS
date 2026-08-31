"""Tests for the S19k native population-coverage readiness gate."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

import s19k_native_population_coverage_verify as coverage


class NativePopulationCoverageTests(unittest.TestCase):
    def test_current_runtime_is_profile_aware_and_covers_all_routes(self) -> None:
        result = coverage.audit_source_tree()
        self.assertEqual(result["classification"], "ready")
        self.assertEqual(result["missing_runtime_markers"], {})
        self.assertEqual(result["fixed_route_markers_present"], [])
        self.assertEqual(len(result["logical_chain_routes"]), 3)
        self.assertFalse(result["physical_connector_geometry_proven"])
        self.assertFalse(result["electrical_interchangeability_proven"])

    def test_profile_aware_marker_contract_can_become_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, markers in coverage.READY_MARKERS.items():
                path = root.joinpath(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(markers) + "\n", encoding="utf-8")
            result = coverage.audit_source_tree(root)
            self.assertEqual(result["classification"], "ready")
            self.assertEqual(result["missing_runtime_markers"], {})
            self.assertEqual(result["fixed_route_markers_present"], [])

    def test_fixed_route_marker_forces_blocked_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, markers in coverage.READY_MARKERS.items():
                path = root.joinpath(*relative.split("/"))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(markers) + "\n", encoding="utf-8")
            owner = root.joinpath(*coverage.OWNER_PATH.split("/"))
            owner.write_text(
                owner.read_text(encoding="utf-8") + coverage.FIXED_MARKERS[0] + "\n",
                encoding="utf-8",
            )
            result = coverage.audit_source_tree(root)
            self.assertEqual(result["classification"], "blocked_tooling")
            self.assertEqual(
                result["fixed_route_markers_present"], [coverage.FIXED_MARKERS[0]]
            )


if __name__ == "__main__":
    unittest.main()
