#!/usr/bin/env python3
"""Fail-closed validation for the Nano 3 external safety-interlock package.

This is a desk-only consistency gate. It deliberately accepts only the
checked-in unqualified template and refuses a completed/approved record. A
future production qualification needs a separate signed-record compiler and a
reviewed change to the Rust energization latches; changing a JSON status is
never authority.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HARDWARE_ROOT = PROJECT_ROOT / "hardware" / "nano3-safety-interlock"
DEFAULT_CONTRACT = HARDWARE_ROOT / "interlock-contract.json"
DEFAULT_BOM = HARDWARE_ROOT / "bom.csv"
DEFAULT_FAULT_MATRIX = HARDWARE_ROOT / "fault-injection-matrix.csv"
DEFAULT_QUALIFICATION_TEMPLATE = HARDWARE_ROOT / "qualification-record.template.json"

REQUIRED_PLUGABLE_PDOS = {
    "5V@3A",
    "9V@3A",
    "15V@3A",
    "20V@5A",
    "28V@5A_EPR",
}
REQUIRED_TP14A1_PDOS = REQUIRED_PLUGABLE_PDOS | {"12V@3A"}

EXPECTED_BOM_REFS = (
    "QF1/F1",
    "PS1",
    "PWR-USB",
    "K1/K2",
    "SR1",
    "WD1",
    "WD2",
    "KT1/KT2",
    "TH1/TH2",
    "TL1/TL2",
    "FS1",
    "S0",
    "S1",
    "Q1/Q2",
    "J2",
    "J3",
    "J4/J5",
    "J6/J7",
    "J8/J9",
    "J10",
    "F2/F3",
    "TB/ENC",
    "DS1",
    "TP1 set",
)

EXPECTED_FAULT_IDS = (
    "PWR-01",
    "PWR-02",
    "PWR-03",
    "PWR-04",
    "PWR-05",
    "PWR-06",
    "PWR-07",
    "PWR-08",
    "PWR-09",
    "PWR-10",
    "PWR-11",
    "PWR-12",
    "PWR-13",
    "PWR-14",
    "PWR-15",
    "PWR-16",
    "PWR-17",
    "EST-01",
    "EST-02",
    "EST-03",
    "HB-01",
    "HB-02",
    "HB-03",
    "HB-04",
    "HB-05",
    "HB-06",
    "HB-07",
    "TH-01",
    "TH-02",
    "TH-03",
    "TH-04",
    "TH-05",
    "TH-06",
    "TH-07",
    "TH-08",
    "FAN-01",
    "FAN-02",
    "FAN-03",
    "FAN-04",
    "FAN-05",
    "FAN-06",
    "CTL-01",
    "CTL-02",
    "CTL-03",
    "CTL-04",
    "CTL-05",
    "CTL-06",
    "CTL-07",
    "BOOT-01",
    "BOOT-02",
    "BOOT-03",
    "BOOT-04",
    "BOOT-05",
    "BOOT-06",
    "RST-01",
    "EDM-01",
    "EDM-02",
    "DIAG-01",
    "CUT-01",
    "CUT-02",
    "SOAK-01",
    "EMI-01",
    "MIS-01",
)

EXPECTED_SOURCE_ARTIFACTS = (
    "README.md",
    "WIRING.md",
    "USB_C_POWER_CHAIN_QUALIFICATION.md",
    "bom.csv",
    "fault-injection-matrix.csv",
    "interlock-contract.json",
)

REQUIRED_QUALIFICATION_EVIDENCE_ROLES = (
    "input-current-trace",
    "usb-pd-negotiation-capture",
    "usb-thermal-trace",
    "adapter-output-trace",
    "asic-rail-collapse-trace",
    "hash-cessation-trace",
    "calibrated-th1-th2-traces",
    "fan-frequency-trace",
    "physical-heartbeat-trace",
    "k1-k2-coil-edm-traces",
    "post-cut-passive-coast-down-trace",
    "completed-fault-matrix",
    "cold-warm-hot-soak-results",
    "calibration-records",
    "electrical-safety-review",
    "functional-safety-review",
)

EXPECTED_BOM_HEADERS = (
    "Ref",
    "Qty",
    "Class",
    "Minimum requirement",
    "Reason",
    "Selection status",
    "Qualification evidence",
)
EXPECTED_FAULT_HEADERS = (
    "ID",
    "Category",
    "Injection",
    "Precondition",
    "Required outcome",
    "Latch/reset requirement",
    "Evidence required",
    "Desk status",
)

EXPECTED_CONTRACT_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "fixture_id",
        "document_status",
        "safety_claim",
        "target",
        "cutoff_boundary",
        "cutoff_class",
        "post_cut_active_cooling_retained",
        "production_cut_acceptance_rule",
        "rail_cut_verified",
        "hash_stop_verified",
        "live_validation_required",
        "stock_physical_heartbeat_verified",
        "native_takeover_allowed",
        "source_evidence",
        "power_path",
        "usb_power_interface",
        "required_healthy_inputs",
        "heartbeat",
        "temperature",
        "fan",
        "state_machine",
        "startup_bypass",
        "timing",
        "release_evidence_required",
        "compiled_production_qualification",
    }
)

EXPECTED_TEMPLATE_KEYS = {
    "root": frozenset(
        {
            "schema_version",
            "record_type",
            "qualification_status",
            "record_id",
            "record_created_utc",
            "authority",
            "source_artifacts",
            "target",
            "power_chain",
            "numeric_envelope",
            "power_chain_qualification",
            "fault_results",
            "required_evidence_roles",
            "evidence_artifacts",
            "reviews",
            "qualification_record_compiler_implemented",
            "scope_statement",
        }
    ),
    "authority": frozenset(
        {
            "production_arm_allowed",
            "native_takeover_allowed",
            "unattended_operation_allowed",
            "hardware_contact_allowed",
            "energization_allowed",
        }
    ),
    "target": frozenset(
        {"model", "asset_id", "hardware_revision", "firmware_build_sha256"}
    ),
    "power_chain": frozenset(
        {
            "candidate_lane",
            "fixture_asset_id",
            "charger_asset_id",
            "charger_model",
            "cable_asset_id",
            "cable_model",
            "substitution_requalification_acknowledged",
        }
    ),
    "numeric_envelope": frozenset(
        {
            "minimum_fan_rpm",
            "maximum_inlet_temperature_c",
            "maximum_outlet_temperature_c",
            "th1_trip_temperature_c",
            "th2_trip_temperature_c",
            "reset_temperature_c",
            "maximum_channel_disagreement_c",
            "heartbeat_timeout_ms",
            "startup_window_ms",
            "maximum_safe_cutoff_ms",
            "worst_case_contactor_release_ms",
            "worst_case_hash_stop_ms",
            "worst_case_rail_collapse_ms",
            "worst_case_watchdog_expiry_to_cut_ms",
            "maximum_post_cut_temperature_rise_c",
            "worst_case_post_cut_temperature_rise_c",
            "maximum_post_cut_peak_temperature_c",
            "worst_case_post_cut_peak_temperature_c",
            "uncertainty_included",
            "numeric_cooling_and_heartbeat_envelope_complete",
            "numeric_cutoff_and_coast_down_envelope_complete",
        }
    ),
    "power_chain_qualification": frozenset(
        {
            "specimen_authenticity_nameplate_listing_match_passed",
            "pd_capture_passed",
            "stable_required_pdo_rdo_passed",
            "e_marker_or_captive_lead_identity_passed",
            "cold_trials_per_used_orientation",
            "warm_rearm_trials",
            "thermal_equilibrium_slope_c_per_hour",
            "thermal_equilibrium_hold_hours",
            "sustained_total_hours",
            "post_equilibrium_hours",
            "sustained_thermal_passed",
            "analyzer_removed_repeat_passed",
            "cutoff_correlation_passed",
            "post_test_inspection_passed",
        }
    ),
}


def _mapping(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return {}
    return value


def _exact_keys(
    value: dict[str, Any], expected: frozenset[str], path: str, errors: list[str]
) -> None:
    observed = frozenset(value)
    if observed == expected:
        return
    missing = ",".join(sorted(expected - observed)) or "none"
    unexpected = ",".join(sorted(observed - expected)) or "none"
    errors.append(f"{path} keys changed (missing={missing}; unexpected={unexpected})")


def _list(value: Any, path: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return []
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contains_all(value: Any, terms: tuple[str, ...]) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return all(term.lower() in lowered for term in terms)


def validate_contract(contract: dict[str, Any]) -> list[str]:
    """Return every release-blocking machine-contract error."""

    errors: list[str] = []
    _exact_keys(contract, EXPECTED_CONTRACT_ROOT_KEYS, "contract", errors)
    if contract.get("schema_version") != 2:
        errors.append("schema_version must be 2")
    if contract.get("document_status") != "desk-specification":
        errors.append("document_status must remain desk-specification")
    if contract.get("safety_claim") != "none":
        errors.append("safety_claim must remain 'none' before qualification")
    for field in (
        "rail_cut_verified",
        "hash_stop_verified",
        "stock_physical_heartbeat_verified",
    ):
        if contract.get(field) is not False:
            errors.append(f"{field} must remain false")
    if contract.get("live_validation_required") is not True:
        errors.append("live_validation_required must remain true")
    if contract.get("native_takeover_allowed") is not False:
        errors.append("native_takeover_allowed must remain false")
    if contract.get("cutoff_class") != "whole-device containment":
        errors.append("cutoff_class must remain whole-device containment")
    if contract.get("post_cut_active_cooling_retained") is not False:
        errors.append("whole-device cutoff must not claim retained active cooling")

    power = _mapping(contract.get("power_path"), "power_path", errors)
    if power.get("protective_earth_switched") is not False:
        errors.append("power_path.protective_earth_switched must remain false")
    for field in (
        "k1_k2_separate_safety_outputs_required",
        "mechanically_linked_feedback_required",
    ):
        if power.get(field) is not True:
            errors.append(f"power_path.{field} must remain true")
    if power.get("exact_components") != "TBD_ENGINEERING_SELECTION":
        errors.append("power_path.exact_components must remain TBD")

    edm = _mapping(power.get("edm_evaluation"), "power_path.edm_evaluation", errors)
    for field in (
        "state_dependent_feedback_required",
        "open_pole_proof_required_before_arm",
        "energized_transition_proof_required_after_pickup",
        "open_transition_proof_required_after_trip",
        "continuous_mirror_contact_series_permit_forbidden",
        "feedback_discrepancy_latches_fault",
    ):
        if edm.get(field) is not True:
            errors.append(f"power_path.edm_evaluation.{field} must remain true")
    if edm.get("feedback_transition_timeout_ms") != (
        "TBD_K1_K2_SR1_SELECTION_AND_LIVE_VALIDATION"
    ):
        errors.append("EDM feedback timeout must remain unqualified")

    usb = _mapping(contract.get("usb_power_interface"), "usb_power_interface", errors)
    if usb.get("approved_charger_model") != "TBD_PD_ANALYZER_AND_THERMAL_VALIDATION":
        errors.append("approved_charger_model must remain TBD")
    if usb.get("approved_cable_model") != "TBD_E_MARKER_AND_THERMAL_VALIDATION":
        errors.append("approved_cable_model must remain TBD")
    if usb.get("candidate_pair_approved") is not False:
        errors.append("candidate_pair_approved must remain false")
    if usb.get("substitution_without_requalification_allowed") is not False:
        errors.append("power-component substitution must require requalification")
    if usb.get("third_party_reports_are_qualification_evidence") is not False:
        errors.append("third-party reports cannot be qualification evidence")
    if usb.get("canaan_documented_nano3_input") != "28V":
        errors.append("Nano 3 documented input must be 28V")
    if usb.get("canaan_documented_maximum_power_w") != 140:
        errors.append("Nano 3 documented maximum power must be 140W")
    if usb.get("canaan_documented_required_max_profile") != "28V@5A":
        errors.append("Nano 3 maximum profile must be 28V@5A")

    plugable_pdos = set(usb.get("candidate_charger_advertised_pdos", []))
    if plugable_pdos != REQUIRED_PLUGABLE_PDOS:
        errors.append("Plugable candidate PDO set must exactly match the reviewed set")
    if usb.get("candidate_charger_model") != (
        "Plugable PS-EPR-140C1 North American direct-plug variant"
    ):
        errors.append("Plugable charger candidate identity changed")
    if usb.get("candidate_cable_model") != "Plugable USB4-240W-1M passive 1 m":
        errors.append("Plugable cable candidate identity changed")

    canaan = _mapping(
        usb.get("first_party_reference_candidate"),
        "usb_power_interface.first_party_reference_candidate",
        errors,
    )
    if canaan.get("model") != "TP14A1":
        errors.append("Canaan first-party reference model must be TP14A1")
    if canaan.get("captive_usb_c_cable") is not True:
        errors.append("TP14A1 lane must retain its captive USB-C output cable")
    if canaan.get("candidate_approved") is not False:
        errors.append("TP14A1 candidate must remain unapproved")
    if (
        canaan.get("physical_specimen_authenticity_and_nameplate_match_required")
        is not True
    ):
        errors.append("TP14A1 physical authenticity/nameplate match must be required")
    if (
        set(canaan.get("output_pdos_from_label_and_analyzer_record", []))
        != REQUIRED_TP14A1_PDOS
    ):
        errors.append("TP14A1 reference PDO set must exactly match the reviewed set")

    marketplace = _mapping(
        usb.get("marketplace_listing_metadata"),
        "usb_power_interface.marketplace_listing_metadata",
        errors,
    )
    if marketplace.get("listing_identity_proven") is not False:
        errors.append("marketplace listing identity must remain unproven")
    if marketplace.get("electrical_identity_acceptance") != (
        "REJECTED_UNTIL_PHYSICAL_NAMEPLATE_AND_PD_CAPTURE"
    ):
        errors.append("marketplace metadata must be rejected as electrical identity")
    listing = _mapping(
        marketplace.get("reported_fields"),
        "usb_power_interface.marketplace_listing_metadata.reported_fields",
        errors,
    )
    if (
        listing.get("output_voltage") != "12Vdc"
        or listing.get("output_current") != "11.67A"
    ):
        errors.append(
            "operator-pasted contradictory 12V/11.67A metadata must remain recorded"
        )

    state = _mapping(contract.get("state_machine"), "state_machine", errors)
    if state.get("states") != [
        "SAFE_OFF",
        "SELF_TEST",
        "START_WINDOW",
        "RUN",
        "TRIPPED_LATCHED",
        "EDM_FAULT",
    ]:
        errors.append("state_machine states/order changed")
    for field in (
        "manual_reset_required_after_trip",
        "manual_reset_is_edge_not_maintained_enable",
        "trip_or_power_loss_clears_internal_run_latch",
        "reset_held_through_fault_cannot_rearm",
    ):
        if state.get(field) is not True:
            errors.append(f"state_machine.{field} must remain true")
    for field in ("automatic_restart", "production_bypass_allowed"):
        if state.get(field) is not False:
            errors.append(f"state_machine.{field} must remain false")

    heartbeat = _mapping(contract.get("heartbeat"), "heartbeat", errors)
    if heartbeat.get("valid_cycles_before_run") != 6:
        errors.append("heartbeat must require six valid cycles")
    if heartbeat.get("commissioning_timeout_seconds") != 1.5:
        errors.append("heartbeat commissioning timeout must remain 1.5 seconds")
    for field in (
        "rising_and_falling_edges_required",
        "stuck_high_is_fault",
        "stuck_low_is_fault",
    ):
        if heartbeat.get(field) is not True:
            errors.append(f"heartbeat.{field} must remain true")

    temperature = _mapping(contract.get("temperature"), "temperature", errors)
    if temperature.get("channel_count") != 2:
        errors.append("temperature must retain two channels")
    for field in ("independent_hardware_limits", "open_short_detection_required"):
        if temperature.get(field) is not True:
            errors.append(f"temperature.{field} must remain true")

    startup = _mapping(contract.get("startup_bypass"), "startup_bypass", errors)
    for field in ("hard_temperature_bypassed", "estop_bypassed", "edm_bypassed"):
        if startup.get(field) is not False:
            errors.append(f"startup_bypass.{field} must remain false")
    if startup.get("single_timer_stuck_closed_must_trip") is not True:
        errors.append("one stuck startup timer must still trip")
    if startup.get("retrigger_while_contactors_closed_allowed") is not False:
        errors.append("startup timers must not retrigger while contactors are closed")

    compiled = _mapping(
        contract.get("compiled_production_qualification"),
        "compiled_production_qualification",
        errors,
    )
    for field in (
        "numeric_cooling_and_heartbeat_envelope_complete",
        "numeric_cutoff_and_coast_down_envelope_complete",
        "native_build_pin_present",
    ):
        if compiled.get(field) is not False:
            errors.append(
                f"compiled_production_qualification.{field} must remain false"
            )
    for field, value in compiled.items():
        if field.endswith(
            (
                "record_id",
                "record_sha256",
                "asset_id",
                "fan_rpm",
                "temperature_c",
                "timeout_ms",
            )
        ):
            if not isinstance(value, str) or not value.startswith("TBD_"):
                errors.append(
                    f"compiled_production_qualification.{field} must remain TBD"
                )

    return errors


def validate_bom(headers: tuple[str, ...], rows: list[dict[str, str]]) -> list[str]:
    """Validate that the desk BOM is complete but claims no selected part."""

    errors: list[str] = []
    if headers != EXPECTED_BOM_HEADERS:
        errors.append("BOM headers changed")
    refs = tuple(row.get("Ref", "") for row in rows)
    if refs != EXPECTED_BOM_REFS:
        errors.append("BOM rows/order must exactly match the reviewed desk set")
    if len(set(refs)) != len(refs):
        errors.append("BOM Ref values must be unique")
    for index, row in enumerate(rows, start=2):
        if frozenset(row) != frozenset(EXPECTED_BOM_HEADERS):
            errors.append(f"BOM row {index} has missing or extra columns")
        if any(not str(row.get(field, "")).strip() for field in EXPECTED_BOM_HEADERS):
            errors.append(f"BOM row {index} contains a blank field")
        status = row.get("Selection status", "")
        if not (status.startswith("TBD_") or status == "CANDIDATE_NOT_APPROVED"):
            errors.append(
                f"BOM {row.get('Ref', index)} must remain unselected/unapproved"
            )

    by_ref = {row.get("Ref"): row for row in rows}
    requirements = {
        "K1/K2": ("guided", "mirror", "inrush"),
        "WD1": ("separately protected", "monitor-power loss"),
        "WD2": ("separately protected", "monitor-power loss"),
        "TL1/TL2": ("independent", "monitor-power loss"),
        "FS1": ("separately protected", "monitor-power-loss"),
        "S1": ("edge", "maintained", "automatic restart"),
    }
    for ref, terms in requirements.items():
        if not _contains_all(by_ref.get(ref, {}).get("Minimum requirement"), terms):
            errors.append(
                f"BOM {ref} lost fail-closed requirements: {', '.join(terms)}"
            )
    return errors


def validate_fault_matrix(
    headers: tuple[str, ...], rows: list[dict[str, str]]
) -> list[str]:
    """Validate exact fault coverage and the all-pending desk posture."""

    errors: list[str] = []
    if headers != EXPECTED_FAULT_HEADERS:
        errors.append("fault matrix headers changed")
    ids = tuple(row.get("ID", "") for row in rows)
    if ids != EXPECTED_FAULT_IDS:
        errors.append("fault matrix IDs/order must exactly match the reviewed set")
    if len(set(ids)) != len(ids):
        errors.append("fault matrix IDs must be unique")
    for index, row in enumerate(rows, start=2):
        if frozenset(row) != frozenset(EXPECTED_FAULT_HEADERS):
            errors.append(f"fault matrix row {index} has missing or extra columns")
        if any(not str(row.get(field, "")).strip() for field in EXPECTED_FAULT_HEADERS):
            errors.append(f"fault matrix row {index} contains a blank field")
        if not row.get("Desk status", "").startswith("PENDING_"):
            errors.append(
                f"fault {row.get('ID', index)} must remain PENDING in the desk matrix"
            )

    by_id = {row.get("ID"): row for row in rows}
    critical_terms = {
        "PWR-05": ("k2 opens", "edm"),
        "PWR-06": ("k1 opens", "edm"),
        "PWR-10": ("safe_off", "does not auto-power"),
        "PWR-14": ("both coils drop",),
        "PWR-15": ("both coils drop",),
        "PWR-16": ("both coils drop",),
        "PWR-17": ("both coils drop",),
        "HB-01": ("both coils drop", "qualified heartbeat timeout"),
        "RST-01": ("rejects the maintained input", "neither contactor re-energizes"),
        "EDM-01": ("state-dependent discrepancy", "refuses re-arm"),
        "EDM-02": ("state-dependent discrepancy", "refuses re-arm"),
        "CUT-01": ("asic rail", "hashing ceases"),
        "CUT-02": ("passive temperature", "whole-device cutoff is rejected"),
    }
    for fault_id, terms in critical_terms.items():
        if not _contains_all(by_id.get(fault_id, {}).get("Required outcome"), terms):
            errors.append(
                f"fault {fault_id} lost required outcome terms: {', '.join(terms)}"
            )
    return errors


def validate_qualification_template(
    record: dict[str, Any], hardware_root: Path = HARDWARE_ROOT
) -> list[str]:
    """Validate a complete, hash-bound template that grants no authority."""

    errors: list[str] = []
    _exact_keys(record, EXPECTED_TEMPLATE_KEYS["root"], "qualification", errors)
    if record.get("schema_version") != 1:
        errors.append("qualification template schema_version must be 1")
    if record.get("record_type") != "dcent-nano3-interlock-production-qualification":
        errors.append("qualification template record_type changed")
    if record.get("qualification_status") != "TEMPLATE_NOT_QUALIFIED":
        errors.append(
            "qualification template status must remain TEMPLATE_NOT_QUALIFIED"
        )
    if record.get("record_id") != "TBD_AFTER_SIGNED_LIVE_QUALIFICATION":
        errors.append("qualification template record_id must remain TBD")
    if record.get("record_created_utc") is not None:
        errors.append("qualification template record_created_utc must remain null")

    authority = _mapping(record.get("authority"), "qualification.authority", errors)
    _exact_keys(
        authority,
        EXPECTED_TEMPLATE_KEYS["authority"],
        "qualification.authority",
        errors,
    )
    for field in (
        "production_arm_allowed",
        "native_takeover_allowed",
        "unattended_operation_allowed",
        "hardware_contact_allowed",
        "energization_allowed",
    ):
        if authority.get(field) is not False:
            errors.append(f"qualification.authority.{field} must remain false")

    source_rows = _list(
        record.get("source_artifacts"), "qualification.source_artifacts", errors
    )
    source_paths = tuple(
        row.get("path", "") if isinstance(row, dict) else "" for row in source_rows
    )
    if source_paths != EXPECTED_SOURCE_ARTIFACTS:
        errors.append("qualification source artifact set/order changed")
    for row in source_rows:
        if not isinstance(row, dict):
            errors.append("qualification source artifact entries must be objects")
            continue
        _exact_keys(
            row,
            frozenset({"path", "sha256"}),
            "qualification.source_artifacts[]",
            errors,
        )
        relative = row.get("path")
        expected_hash = row.get("sha256")
        if relative not in EXPECTED_SOURCE_ARTIFACTS:
            continue
        path = hardware_root / relative
        try:
            actual_hash = _sha256_file(path)
        except OSError as exc:
            errors.append(f"cannot hash qualification source {relative}: {exc}")
            continue
        if expected_hash != actual_hash:
            errors.append(f"qualification source hash mismatch: {relative}")

    target = _mapping(record.get("target"), "qualification.target", errors)
    _exact_keys(
        target, EXPECTED_TEMPLATE_KEYS["target"], "qualification.target", errors
    )
    if target.get("model") != "Canaan Avalon Nano 3":
        errors.append("qualification target model changed")
    for field in ("asset_id", "hardware_revision", "firmware_build_sha256"):
        value = target.get(field)
        if not isinstance(value, str) or not value.startswith("TBD_"):
            errors.append(f"qualification.target.{field} must remain TBD")

    power = _mapping(record.get("power_chain"), "qualification.power_chain", errors)
    _exact_keys(
        power,
        EXPECTED_TEMPLATE_KEYS["power_chain"],
        "qualification.power_chain",
        errors,
    )
    for field in (
        "candidate_lane",
        "fixture_asset_id",
        "charger_asset_id",
        "charger_model",
        "cable_asset_id",
        "cable_model",
    ):
        value = power.get(field)
        if not isinstance(value, str) or not value.startswith("TBD_"):
            errors.append(f"qualification.power_chain.{field} must remain TBD")
    if power.get("substitution_requalification_acknowledged") is not False:
        errors.append("template cannot acknowledge power-chain substitution control")

    numeric = _mapping(
        record.get("numeric_envelope"), "qualification.numeric_envelope", errors
    )
    _exact_keys(
        numeric,
        EXPECTED_TEMPLATE_KEYS["numeric_envelope"],
        "qualification.numeric_envelope",
        errors,
    )
    for field, value in numeric.items():
        if field.endswith("_complete") or field == "uncertainty_included":
            if value is not False:
                errors.append(
                    f"qualification.numeric_envelope.{field} must remain false"
                )
        elif value is not None:
            errors.append(f"qualification.numeric_envelope.{field} must remain null")

    power_tests = _mapping(
        record.get("power_chain_qualification"),
        "qualification.power_chain_qualification",
        errors,
    )
    _exact_keys(
        power_tests,
        EXPECTED_TEMPLATE_KEYS["power_chain_qualification"],
        "qualification.power_chain_qualification",
        errors,
    )
    for field, value in power_tests.items():
        if isinstance(value, bool):
            if value is not False:
                errors.append(
                    f"qualification.power_chain_qualification.{field} must remain false"
                )
        elif value is not None:
            errors.append(
                f"qualification.power_chain_qualification.{field} must remain null"
            )

    fault_rows = _list(
        record.get("fault_results"), "qualification.fault_results", errors
    )
    fault_ids = tuple(
        row.get("id", "") if isinstance(row, dict) else "" for row in fault_rows
    )
    if fault_ids != EXPECTED_FAULT_IDS:
        errors.append(
            "qualification fault result IDs/order must match the fault matrix"
        )
    for row in fault_rows:
        if not isinstance(row, dict):
            errors.append("qualification fault result entries must be objects")
            continue
        _exact_keys(
            row,
            frozenset({"id", "result", "evidence_ids"}),
            "qualification.fault_results[]",
            errors,
        )
        if row.get("result") != "PENDING" or row.get("evidence_ids") != []:
            errors.append(
                f"qualification fault {row.get('id', '?')} must remain pending/evidence-free"
            )

    if record.get("evidence_artifacts") != []:
        errors.append("qualification template evidence_artifacts must remain empty")
    if record.get("required_evidence_roles") != list(
        REQUIRED_QUALIFICATION_EVIDENCE_ROLES
    ):
        errors.append("qualification required evidence roles changed")

    reviews = _mapping(record.get("reviews"), "qualification.reviews", errors)
    _exact_keys(
        reviews,
        frozenset({"electrical_safety", "functional_safety"}),
        "qualification.reviews",
        errors,
    )
    for role in ("electrical_safety", "functional_safety"):
        review = _mapping(reviews.get(role), f"qualification.reviews.{role}", errors)
        _exact_keys(
            review,
            frozenset({"verdict", "reviewer_id", "review_artifact_id"}),
            f"qualification.reviews.{role}",
            errors,
        )
        if review.get("verdict") != "PENDING":
            errors.append(f"qualification review {role} must remain PENDING")
        for field in ("reviewer_id", "review_artifact_id"):
            value = review.get(field)
            if not isinstance(value, str) or not value.startswith("TBD_"):
                errors.append(f"qualification.reviews.{role}.{field} must remain TBD")

    if record.get("qualification_record_compiler_implemented") is not False:
        errors.append(
            "qualification record compiler must remain explicitly unimplemented"
        )
    return errors


def _read_json(path: Path, label: str) -> tuple[Optional[dict[str, Any]], list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"cannot read {label}: {exc}"]
    if not isinstance(value, dict):
        return None, [f"{label} root must be an object"]
    return value, []


def _read_csv(
    path: Path, label: str
) -> tuple[tuple[str, ...], list[dict[str, str]], list[str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = tuple(reader.fieldnames or ())
            rows = list(reader)
    except (OSError, csv.Error) as exc:
        return (), [], [f"cannot read {label}: {exc}"]
    return headers, rows, []


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--bom", type=Path, default=DEFAULT_BOM)
    parser.add_argument("--fault-matrix", type=Path, default=DEFAULT_FAULT_MATRIX)
    parser.add_argument(
        "--qualification-template",
        type=Path,
        default=DEFAULT_QUALIFICATION_TEMPLATE,
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    errors: list[str] = []

    contract, read_errors = _read_json(args.contract, "power contract")
    errors.extend(read_errors)
    if contract is not None:
        errors.extend(validate_contract(contract))

    bom_headers, bom_rows, read_errors = _read_csv(args.bom, "BOM")
    errors.extend(read_errors)
    if not read_errors:
        errors.extend(validate_bom(bom_headers, bom_rows))

    fault_headers, fault_rows, read_errors = _read_csv(
        args.fault_matrix, "fault matrix"
    )
    errors.extend(read_errors)
    if not read_errors:
        errors.extend(validate_fault_matrix(fault_headers, fault_rows))

    template, read_errors = _read_json(
        args.qualification_template, "qualification template"
    )
    errors.extend(read_errors)
    if template is not None:
        errors.extend(validate_qualification_template(template, args.contract.parent))

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "PASS: Nano 3 interlock desk package is internally consistent, "
        "fully pending, and grants no production/native authority"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
