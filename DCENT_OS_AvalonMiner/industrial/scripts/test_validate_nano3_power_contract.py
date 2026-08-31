#!/usr/bin/env python3
"""Tests for the Nano 3 safety-interlock desk-package validator."""

from __future__ import annotations

import copy
import csv
import json
import unittest

from validate_nano3_power_contract import (
    DEFAULT_BOM,
    DEFAULT_CONTRACT,
    DEFAULT_FAULT_MATRIX,
    DEFAULT_QUALIFICATION_TEMPLATE,
    EXPECTED_BOM_HEADERS,
    EXPECTED_FAULT_HEADERS,
    HARDWARE_ROOT,
    validate_bom,
    validate_contract,
    validate_fault_matrix,
    validate_qualification_template,
)


def read_csv(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return tuple(reader.fieldnames or ()), list(reader)


class Nano3PowerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        cls.bom_headers, cls.bom = read_csv(DEFAULT_BOM)
        cls.fault_headers, cls.faults = read_csv(DEFAULT_FAULT_MATRIX)
        cls.qualification = json.loads(
            DEFAULT_QUALIFICATION_TEMPLATE.read_text(encoding="utf-8")
        )

    def mutated_contract(self) -> dict:
        return copy.deepcopy(self.contract)

    def test_checked_in_desk_package_is_fail_closed(self) -> None:
        self.assertEqual(validate_contract(self.contract), [])
        self.assertEqual(validate_bom(self.bom_headers, self.bom), [])
        self.assertEqual(validate_fault_matrix(self.fault_headers, self.faults), [])
        self.assertEqual(
            validate_qualification_template(self.qualification, HARDWARE_ROOT), []
        )

    def test_marketplace_12v_metadata_cannot_become_identity(self) -> None:
        candidate = self.mutated_contract()
        candidate["usb_power_interface"]["marketplace_listing_metadata"][
            "electrical_identity_acceptance"
        ] = "ACCEPTED"
        self.assertIn(
            "marketplace metadata must be rejected as electrical identity",
            validate_contract(candidate),
        )

    def test_tp14a1_captive_lead_cannot_be_substituted(self) -> None:
        candidate = self.mutated_contract()
        candidate["usb_power_interface"]["first_party_reference_candidate"][
            "captive_usb_c_cable"
        ] = False
        self.assertIn(
            "TP14A1 lane must retain its captive USB-C output cable",
            validate_contract(candidate),
        )

    def test_missing_28v_epr_profile_is_rejected(self) -> None:
        candidate = self.mutated_contract()
        candidate["usb_power_interface"]["first_party_reference_candidate"][
            "output_pdos_from_label_and_analyzer_record"
        ].remove("28V@5A_EPR")
        self.assertIn(
            "TP14A1 reference PDO set must exactly match the reviewed set",
            validate_contract(candidate),
        )

    def test_candidate_cannot_be_marked_approved(self) -> None:
        candidate = self.mutated_contract()
        candidate["usb_power_interface"]["candidate_pair_approved"] = True
        self.assertIn(
            "candidate_pair_approved must remain false",
            validate_contract(candidate),
        )

    def test_native_takeover_cannot_be_enabled(self) -> None:
        candidate = self.mutated_contract()
        candidate["native_takeover_allowed"] = True
        self.assertIn(
            "native_takeover_allowed must remain false",
            validate_contract(candidate),
        )

    def test_edm_cannot_regress_to_continuous_mirror_permit(self) -> None:
        candidate = self.mutated_contract()
        candidate["power_path"]["edm_evaluation"][
            "continuous_mirror_contact_series_permit_forbidden"
        ] = False
        self.assertIn(
            "power_path.edm_evaluation.continuous_mirror_contact_series_permit_forbidden must remain true",
            validate_contract(candidate),
        )

    def test_reset_cannot_become_a_maintained_enable(self) -> None:
        candidate = self.mutated_contract()
        candidate["state_machine"]["manual_reset_is_edge_not_maintained_enable"] = False
        self.assertIn(
            "state_machine.manual_reset_is_edge_not_maintained_enable must remain true",
            validate_contract(candidate),
        )

    def test_unknown_authority_fields_and_extra_csv_columns_are_rejected(self) -> None:
        candidate = self.mutated_contract()
        candidate["production_arm_allowed"] = True
        self.assertTrue(
            any(
                "contract keys changed" in error
                for error in validate_contract(candidate)
            )
        )

        qualification = copy.deepcopy(self.qualification)
        qualification["authority"]["operator_override"] = True
        self.assertTrue(
            any(
                "qualification.authority keys changed" in error
                for error in validate_qualification_template(
                    qualification, HARDWARE_ROOT
                )
            )
        )

        bom = copy.deepcopy(self.bom)
        bom[0][None] = ["APPROVED"]
        self.assertIn(
            "BOM row 2 has missing or extra columns",
            validate_bom(EXPECTED_BOM_HEADERS, bom),
        )

    def test_bom_selection_claim_and_missing_monitor_power_fault_are_rejected(
        self,
    ) -> None:
        bom = copy.deepcopy(self.bom)
        bom[0]["Selection status"] = "APPROVED"
        self.assertTrue(
            any(
                "must remain unselected/unapproved" in error
                for error in validate_bom(EXPECTED_BOM_HEADERS, bom)
            )
        )

        bom = copy.deepcopy(self.bom)
        wd1 = next(row for row in bom if row["Ref"] == "WD1")
        wd1["Minimum requirement"] = wd1["Minimum requirement"].replace(
            "monitor-power loss", "ordinary fault"
        )
        self.assertTrue(
            any(
                "BOM WD1 lost fail-closed requirements" in error
                for error in validate_bom(EXPECTED_BOM_HEADERS, bom)
            )
        )

    def test_fault_deletion_pass_claim_and_edm_weakening_are_rejected(self) -> None:
        faults = copy.deepcopy(self.faults)
        faults = [row for row in faults if row["ID"] != "PWR-15"]
        self.assertIn(
            "fault matrix IDs/order must exactly match the reviewed set",
            validate_fault_matrix(EXPECTED_FAULT_HEADERS, faults),
        )

        faults = copy.deepcopy(self.faults)
        next(row for row in faults if row["ID"] == "PWR-14")["Desk status"] = "PASS"
        self.assertIn(
            "fault PWR-14 must remain PENDING in the desk matrix",
            validate_fault_matrix(EXPECTED_FAULT_HEADERS, faults),
        )

        faults = copy.deepcopy(self.faults)
        next(row for row in faults if row["ID"] == "EDM-01")["Required outcome"] = (
            "log only"
        )
        self.assertTrue(
            any(
                "fault EDM-01 lost required outcome terms" in error
                for error in validate_fault_matrix(EXPECTED_FAULT_HEADERS, faults)
            )
        )

    def test_qualification_template_cannot_self_promote_or_invent_values(self) -> None:
        candidate = copy.deepcopy(self.qualification)
        candidate["qualification_status"] = "QUALIFIED"
        candidate["authority"]["production_arm_allowed"] = True
        candidate["numeric_envelope"]["minimum_fan_rpm"] = 1500
        candidate["fault_results"][0]["result"] = "PASS"
        candidate["fault_results"][0]["evidence_ids"] = ["invented"]
        errors = validate_qualification_template(candidate, HARDWARE_ROOT)
        self.assertIn(
            "qualification template status must remain TEMPLATE_NOT_QUALIFIED", errors
        )
        self.assertIn(
            "qualification.authority.production_arm_allowed must remain false", errors
        )
        self.assertIn(
            "qualification.numeric_envelope.minimum_fan_rpm must remain null", errors
        )
        self.assertIn(
            "qualification fault PWR-01 must remain pending/evidence-free", errors
        )

    def test_qualification_template_is_bound_to_exact_source_bytes(self) -> None:
        candidate = copy.deepcopy(self.qualification)
        candidate["source_artifacts"][0]["sha256"] = "0" * 64
        self.assertIn(
            "qualification source hash mismatch: README.md",
            validate_qualification_template(candidate, HARDWARE_ROOT),
        )

    def test_qualification_template_cannot_drop_required_fault_or_evidence_role(
        self,
    ) -> None:
        candidate = copy.deepcopy(self.qualification)
        candidate["fault_results"] = candidate["fault_results"][:-1]
        candidate["required_evidence_roles"] = candidate["required_evidence_roles"][:-1]
        errors = validate_qualification_template(candidate, HARDWARE_ROOT)
        self.assertIn(
            "qualification fault result IDs/order must match the fault matrix", errors
        )
        self.assertIn("qualification required evidence roles changed", errors)


if __name__ == "__main__":
    unittest.main()
