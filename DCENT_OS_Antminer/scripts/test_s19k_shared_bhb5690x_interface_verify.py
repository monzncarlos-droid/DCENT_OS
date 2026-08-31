#!/usr/bin/env python3
"""Adversarial tests for the static BHB5690x interface verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "s19k_shared_bhb5690x_interface_verify.py"
SPEC = importlib.util.spec_from_file_location("s19k_shared_interface", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class SharedBhb5690xInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.topology_902 = json.loads(
            (verifier.REPO_ROOT / verifier.TOPOLOGY_902).read_text(encoding="utf-8")
        )
        cls.topology_903 = json.loads(
            (verifier.REPO_ROOT / verifier.TOPOLOGY_903).read_text(encoding="utf-8")
        )
        cls.input_document = json.loads(
            (verifier.REPO_ROOT / verifier.INPUT).read_text(encoding="utf-8")
        )

    def test_exact_corpus_accepts_only_bounded_static_claim(self) -> None:
        result = verifier.verify_static_interface()
        self.assertTrue(result["shared_controller_facing_functional_compatibility"])
        self.assertTrue(result["shared_stock_power_feed_class"])
        for refused in (
            "shared_keyed_harness_pin_contract",
            "internal_layout_equivalence",
            "electrical_levels_proven",
            "probe_authority",
            "instrumentation_gate_satisfied",
            "live_contact_authority",
            "persistent_mutation_authority",
        ):
            with self.subTest(refused=refused):
                self.assertFalse(result[refused])

    def test_topology_diff_is_exactly_two_model_name_leaves(self) -> None:
        result = verifier._validate_topologies(
            self.topology_902, self.topology_903
        )
        self.assertEqual(
            result["diff_paths"], ["/machine", "/mix_boardnames/0"]
        )

    def test_exact_five_file_inspector_decodes_both_route_implementations(self) -> None:
        result = verifier._validate_vnish_five_file_route(verifier.REPO_ROOT)
        expected = [
            {
                "zero_based_chain_index": 0,
                "uart_device": "/dev/ttyS3",
                "plug_gpio": 439,
                "reset_gpio": 454,
                "reset_active_low": True,
            },
            {
                "zero_based_chain_index": 1,
                "uart_device": "/dev/ttyS2",
                "plug_gpio": 440,
                "reset_gpio": 455,
                "reset_active_low": True,
            },
            {
                "zero_based_chain_index": 2,
                "uart_device": "/dev/ttyS1",
                "plug_gpio": 441,
                "reset_gpio": 456,
                "reset_active_low": True,
            },
        ]
        self.assertEqual(result["routes"], expected)
        self.assertTrue(result["independent_route_implementations_agree"])
        self.assertTrue(result["production_association_verified"])
        self.assertFalse(result["route_activation_authority"])
        self.assertFalse(result["physical_connector_mapping_proven"])

    def test_five_file_inspector_rejects_rehashed_binary_substitution(self) -> None:
        original_read = verifier._read_regular
        held = {
            logical: original_read(verifier.REPO_ROOT / logical, logical)
            for logical in (
                verifier.VNISH_FW_INFO,
                verifier.VNISH_HWSCAN_INIT,
                verifier.VNISH_BOARD_SETUP,
                verifier.VNISH_HWSCAN,
                verifier.VNISH_CGMINER,
            )
        }
        changed = bytearray(held[verifier.VNISH_CGMINER])
        changed[len(changed) // 2] ^= 1

        def substituted(_path: Path, label: str) -> bytes:
            if label == verifier.VNISH_CGMINER:
                return bytes(changed)
            return held[label]

        with mock.patch.object(verifier, "_read_regular", side_effect=substituted):
            with self.assertRaisesRegex(
                verifier.InterfaceEvidenceError, "five-file identity mismatch"
            ):
                verifier._validate_vnish_five_file_route(verifier.REPO_ROOT)

    def test_semantic_topology_drift_is_refused(self) -> None:
        mutated = copy.deepcopy(self.topology_903)
        mutated["chain"]["chain_asic_num"] = 76
        with self.assertRaisesRegex(verifier.InterfaceEvidenceError, "diff escaped"):
            verifier._validate_topologies(self.topology_902, mutated)

    def test_missing_mixed_operation_attestation_is_refused(self) -> None:
        mutated = copy.deepcopy(self.input_document)
        mutated["operator_attestation"]["regular_mixed_same_unit_operation"] = False
        with self.assertRaisesRegex(verifier.InterfaceEvidenceError, "not attested"):
            verifier._validate_input(mutated)

    def test_unrecorded_harness_claim_is_refused(self) -> None:
        mutated = copy.deepcopy(self.input_document)
        mutated["operator_attestation"]["standard_unmodified_keyed_harness"] = True
        with self.assertRaisesRegex(verifier.InterfaceEvidenceError, "unasserted"):
            verifier._validate_input(mutated)

    def test_guide_pin_drift_is_refused(self) -> None:
        mutated = copy.deepcopy(self.input_document)
        mutated["guide"]["j450_candidate_pins"]["7"] = "RXD"
        with self.assertRaisesRegex(verifier.InterfaceEvidenceError, "candidate map"):
            verifier._validate_input(mutated)


if __name__ == "__main__":
    unittest.main()
