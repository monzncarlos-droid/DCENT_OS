#!/usr/bin/env python3
"""Tests for the four-row S19k board-population product matrix."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
common = importlib.import_module("s19k_native_live_common")
matrix_verify = importlib.import_module("s19k_board_population_matrix_verify")
fixtures = importlib.import_module("test_s19k_persistent_transaction_verifiers")


POPULATIONS = {
    "bhb56902-only": (
        ("/dev/ttyS1", "/dev/ttyS2"),
        ("BHB56902", "BHB56902"),
    ),
    "bhb56903-only": (
        ("/dev/ttyS1", "/dev/ttyS2"),
        ("BHB56903", "BHB56903"),
    ),
    "mixed-bhb56902-bhb56903": (
        ("/dev/ttyS1", "/dev/ttyS2"),
        ("BHB56902", "BHB56903"),
    ),
    "all-three-uarts-populated": (
        ("/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"),
        ("BHB56902", "BHB56903", "BHB56902"),
    ),
}


def write(path: Path, data: bytes | str) -> bytes:
    encoded = data.encode("ascii") if isinstance(data, str) else data
    path.write_bytes(encoded)
    return encoded


def build_matrix(
    root: Path,
    *,
    duplicate_install_run_ids: bool = False,
    relabel_profile: str | None = None,
    stage: bool = True,
) -> dict[str, object] | None:
    row_results: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for index, profile in enumerate(matrix_verify.PROFILES, 1):
        row = root / profile
        install_dir = row / "install"
        acceptance_dir = row / "acceptance"
        install_dir.mkdir(parents=True)
        acceptance_dir.mkdir()
        install_run = "matrix-install-duplicate" if duplicate_install_run_ids else f"matrix-install-{index}"
        installed = fixtures.install_fixture(install_dir, run_id=install_run)
        fixture_profile = (
            relabel_profile
            if profile == "mixed-bhb56902-bhb56903" and relabel_profile
            else profile
        )
        uart_paths, board_names = POPULATIONS[fixture_profile]
        accepted = fixtures.acceptance_fixture(
            acceptance_dir,
            installed,
            profile=fixture_profile,
            uart_paths=uart_paths,
            board_names=board_names,
            run_id=f"matrix-acceptance-{index}",
        )
        row_results[profile] = (installed, accepted)

    reviewed: dict[str, object] = {}
    for profile, (installed, accepted) in row_results.items():
        install_data = (root / profile / "install" / "verification.json").read_bytes()
        acceptance_data = (
            root / profile / "acceptance" / "verification.json"
        ).read_bytes()
        reviewed[profile] = {
            "install_verification_id": installed["verification_id"],
            "install_verification_sha256": hashlib.sha256(install_data).hexdigest(),
            "acceptance_verification_id": accepted["verification_id"],
            "acceptance_verification_sha256": hashlib.sha256(
                acceptance_data
            ).hexdigest(),
            "install_and_acceptance_replayed": True,
            "actual_restore_reinstall_observed": True,
        }
    review = {
        "schema": matrix_verify.REVIEW_SCHEMA,
        "reviewer": "reviewer-three",
        "profiles": reviewed,
        "all_profiles_independently_replayed": True,
        "actual_restore_reinstall_observed": True,
        "terminal_claim_authorized": False,
    }
    write(root / matrix_verify.REVIEW_NAME, common.canonical_json(review))
    if not stage:
        return None
    return matrix_verify.stage_receipt(root)


class BoardPopulationMatrixVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        current = matrix_verify.population_coverage.audit_source_tree()
        current["classification"] = "ready"
        current["blocker"] = None
        current["missing_runtime_markers"] = {}
        current["fixed_route_markers_present"] = []
        patcher = mock.patch.object(
            matrix_verify.population_coverage,
            "audit_source_tree",
            return_value=current,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_positive_four_profile_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = build_matrix(root)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertTrue(result["product_matrix_complete"])
            self.assertEqual(result["profile_count"], 4)
            self.assertEqual(
                result["rows"]["mixed-bhb56902-bhb56903"]["board_names"],
                ["BHB56902", "BHB56903"],
            )
            self.assertEqual(
                len(result["rows"]["all-three-uarts-populated"]["native_uart_paths"]),
                3,
            )
            replayed = matrix_verify.verify_workflow_evidence(root)
            common.verify_workflow_receipt(root, replayed)
            self.assertEqual(replayed, result)

    def test_duplicate_install_runs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_matrix(root, duplicate_install_run_ids=True, stage=False)
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "run_ids are not distinct"
            ):
                matrix_verify.verify_workflow_evidence(root)

    def test_profile_directory_cannot_relabel_a_trial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_matrix(root, relabel_profile="bhb56902-only", stage=False)
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError,
                "install and acceptance receipts do not join",
            ):
                matrix_verify.verify_workflow_evidence(root)

    def test_stale_independent_review_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_matrix(root, stage=False)
            review_path = root / matrix_verify.REVIEW_NAME
            _, review = common.load_canonical_json(review_path, "test review")
            review["profiles"]["bhb56903-only"][
                "acceptance_verification_sha256"
            ] = "0" * 64
            write(review_path, common.canonical_json(review))
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "does not bind the row"
            ):
                matrix_verify.verify_workflow_evidence(root)

    def test_reviewer_cannot_be_an_install_or_acceptance_principal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_matrix(root, stage=False)
            review_path = root / matrix_verify.REVIEW_NAME
            _, review = common.load_canonical_json(review_path, "test review")
            review["reviewer"] = "operator-one"
            write(review_path, common.canonical_json(review))
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "reviewer is not independent"
            ):
                matrix_verify.verify_workflow_evidence(root)

    def test_stage_refuses_to_clobber_a_different_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_matrix(root)
            write(root / matrix_verify.RECEIPT_NAME, b"{}\n")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "refusing to overwrite"
            ):
                matrix_verify.stage_receipt(root)


class CurrentPopulationCoverageGateTests(unittest.TestCase):
    def test_current_ready_gate_proceeds_to_matrix_membership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError,
                "incomplete or extra member set",
            ):
                matrix_verify.verify_workflow_evidence(Path(temporary))


if __name__ == "__main__":
    unittest.main()
