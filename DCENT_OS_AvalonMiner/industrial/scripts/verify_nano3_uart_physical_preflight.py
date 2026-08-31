#!/usr/bin/env python3
"""Verify a signed Nano 3 non-S UART physical-preflight bundle.

This program is deliberately file-only. It has no serial, USB, network,
process-control, power, probe, capture, or device-discovery code. A valid
bundle proves only that exact local bytes satisfy this reviewed schema and that
the supplied keys signed them. It does not prove physical provenance, key
custody, witness authority, or grant enclosure, energization, attachment,
capture, or Authorization C authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import struct
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PLAN_SCHEMA = "dcent.nano3.uart-physical-preflight-plan.v1"
RECEIPT_SCHEMA = "dcent.nano3.uart-physical-preflight-receipt.v1"
OUTPUT_SCHEMA = "dcent.nano3.uart-physical-preflight-validation.v1"
PLAN_STATUS = "APPROVED_FOR_EXACT_PREFLIGHT_PHASES"
RECEIPT_STATUS = "COMPLETED_PENDING_INDEPENDENT_PHYSICAL_PROVENANCE"
TEMPLATE_STATUS = "TEMPLATE_NOT_AUTHORIZED"
TARGET_MODEL = "canaan-avalon-nano3-non-s"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_VALIDITY_SECONDS = 24 * 60 * 60
HARD_MAX_ZERO_ENERGY_V = 0.05
HARD_MAX_GROUND_POTENTIAL_V = 0.05
HARD_MIN_VOLTAGE_RATING_MARGIN_V = 0.5
HARD_MIN_ANALYZER_INPUT_IMPEDANCE_OHM = 1_000_000.0
HARD_MAX_SIGNAL_CONTINUITY_OHM = 10.0
HARD_MAX_GROUND_CONTINUITY_OHM = 1.0
MIN_ZERO_ENERGY_OBSERVATION_MS = 1_000.0
MAX_PHOTO_DIMENSION = 12_000
MIN_PHOTO_WIDTH = 640
MIN_PHOTO_HEIGHT = 480
MAX_PHOTO_PIXELS = 20_000_000
MAX_PHOTO_DECOMPRESSED_BYTES = 80_000_000
EVIDENCE_RECORD_SCHEMA = "dcent.nano3.uart-preflight-evidence-record.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")

PLAN_NAME = "preflight-plan.json"
PLAN_OPERATOR_SIGNATURE_NAME = "preflight-plan.operator.sig"
PLAN_REVIEWER_SIGNATURE_NAME = "preflight-plan.electrical-reviewer.sig"
RECEIPT_NAME = "preflight-receipt.json"
RECEIPT_OPERATOR_SIGNATURE_NAME = "preflight-receipt.operator.sig"
RECEIPT_REVIEWER_SIGNATURE_NAME = "preflight-receipt.electrical-reviewer.sig"
OPERATOR_PUBLIC_KEY_NAME = "operator.ed25519.pub"
REVIEWER_PUBLIC_KEY_NAME = "electrical-reviewer.ed25519.pub"
EVIDENCE_DIRECTORY_NAME = "evidence"

PLAN_OPERATOR_DOMAIN = b"DCENT-NANO3-UART-PREFLIGHT-PLAN-OPERATOR-V1\x00"
PLAN_REVIEWER_DOMAIN = b"DCENT-NANO3-UART-PREFLIGHT-PLAN-ELECTRICAL-REVIEW-V1\x00"
RECEIPT_OPERATOR_DOMAIN = b"DCENT-NANO3-UART-PREFLIGHT-RECEIPT-OPERATOR-V1\x00"
RECEIPT_REVIEWER_DOMAIN = b"DCENT-NANO3-UART-PREFLIGHT-RECEIPT-ELECTRICAL-REVIEW-V1\x00"

PHASE_ORDER = (
    "deenergized_enclosure_continuity_scope_attach",
    "bounded_energized_scope_measurement",
    "deenergized_scope_detach",
    "deenergized_analyzer_attach",
    "capture_energization",
    "deenergized_analyzer_detach",
)
AUTHORIZED_PHASES = frozenset(
    {
        "deenergized_enclosure_continuity_scope_attach",
        "bounded_energized_scope_measurement",
        "deenergized_scope_detach",
        "deenergized_analyzer_attach",
        "deenergized_analyzer_detach",
    }
)

EXPECTED_PHASE_ACTIONS = {
    "deenergized_enclosure_continuity_scope_attach": [
        "open_exact_deenergized_unit",
        "document_exact_board_and_taps",
        "measure_zero_energy_with_prevalidated_handheld_dmm",
        "map_three_taps_by_deenergized_continuity",
        "attach_scope_ground_first_signals_second",
    ],
    "bounded_energized_scope_measurement": [
        "energize_only_for_bounded_scope_voltage_measurement",
        "measure_levels_polarity_idle_overshoot_drive_mode_usb_earth_and_ground_potential",
    ],
    "deenergized_scope_detach": [
        "deenergize_and_objectively_verify_zero_energy",
        "detach_scope_signals_first_ground_last",
    ],
    "deenergized_analyzer_attach": [
        "measure_zero_energy_with_prevalidated_handheld_dmm",
        "reverify_deenergized_continuity",
        "attach_receive_only_analyzer_ground_first_signals_second",
    ],
    "capture_energization": [],
    "deenergized_analyzer_detach": [
        "objectively_verify_zero_energy_with_prevalidated_handheld_dmm",
        "detach_analyzer_signals_first_ground_last",
        "close_exact_unit",
    ],
}

PHASE_AUTHORIZATION_EVIDENCE = {
    name: f"{name}_authorization_record" for name in AUTHORIZED_PHASES
}

PHOTO_EVIDENCE_TYPES = frozenset(
    {
        "board_top_photo",
        "board_bottom_photo",
        "board_connectors_photo",
        "k230_marking_photo",
        "mining_controller_marking_photo",
        "tap_overview_photo",
        "scope_attached_photo",
        "analyzer_attached_photo",
        "final_detached_photo",
    }
)
RECORD_EVIDENCE_TYPES = frozenset(
    {
        "unit_identity_record",
        "board_revision_record",
        "clock_source_record",
        "power_disconnect_record",
        "host_to_controller_continuity_record",
        "controller_to_host_continuity_record",
        "signal_ground_continuity_record",
        "zero_energy_before_scope_attach_record",
        "usb_earth_coupling_record",
        "ground_potential_record",
        "voltage_measurement_record",
        "zero_energy_before_scope_detach_record",
        "scope_detach_record",
        "zero_energy_before_analyzer_attach_record",
        "analyzer_channel_mapping_record",
        "zero_energy_before_analyzer_detach_record",
        "analyzer_detach_record",
        "esd_control_record",
        "electrical_compatibility_review_record",
        "scope_identity_record",
        "scope_calibration_record",
        "probe_identity_record",
        "probe_calibration_record",
        "analyzer_identity_record",
        "analyzer_calibration_record",
        "deenergization_meter_identity_record",
        "deenergization_meter_calibration_record",
        "operator_key_custody_record",
        "electrical_reviewer_key_custody_record",
        *PHASE_AUTHORIZATION_EVIDENCE.values(),
    }
)
REQUIRED_EVIDENCE_TYPES = tuple(sorted(PHOTO_EVIDENCE_TYPES | RECORD_EVIDENCE_TYPES))

SESSION_EVIDENCE_TYPES = frozenset(
    {
        "clock_source_record",
        "operator_key_custody_record",
        "electrical_reviewer_key_custody_record",
        "deenergization_meter_identity_record",
        "deenergization_meter_calibration_record",
    }
)
PHASE_EVIDENCE_TYPES = {
    "deenergized_enclosure_continuity_scope_attach": [
        "board_bottom_photo",
        "board_connectors_photo",
        "board_revision_record",
        "board_top_photo",
        "esd_control_record",
        "host_to_controller_continuity_record",
        "k230_marking_photo",
        "mining_controller_marking_photo",
        "power_disconnect_record",
        "probe_calibration_record",
        "probe_identity_record",
        "scope_attached_photo",
        "scope_calibration_record",
        "scope_identity_record",
        "signal_ground_continuity_record",
        "tap_overview_photo",
        "unit_identity_record",
        "controller_to_host_continuity_record",
        "zero_energy_before_scope_attach_record",
    ],
    "bounded_energized_scope_measurement": [
        "ground_potential_record",
        "usb_earth_coupling_record",
        "voltage_measurement_record",
    ],
    "deenergized_scope_detach": [
        "scope_detach_record",
        "zero_energy_before_scope_detach_record",
    ],
    "deenergized_analyzer_attach": [
        "analyzer_attached_photo",
        "analyzer_calibration_record",
        "analyzer_channel_mapping_record",
        "analyzer_identity_record",
        "zero_energy_before_analyzer_attach_record",
    ],
    "capture_energization": [],
    "deenergized_analyzer_detach": [
        "analyzer_detach_record",
        "electrical_compatibility_review_record",
        "final_detached_photo",
        "zero_energy_before_analyzer_detach_record",
    ],
}

FALSE_CLAIMS = frozenset(
    {
        "authorization_c_granted",
        "capture_authorized",
        "capture_performed",
        "device_contact_performed_by_validator",
        "energization_authorized_by_validator",
        "hardware_action_authorized_by_validator",
        "physical_provenance_proven_by_validator",
        "reviewer_key_authority_proven_by_validator",
        "operator_key_authority_proven_by_validator",
        "uart_protocol_qualified",
    }
)


class PreflightError(RuntimeError):
    """An input failed the fail-closed file contract."""


def fail(message: str) -> NoReturn:
    raise PreflightError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def _is_alias(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"{label} unavailable: {exc.__class__.__name__}")
    if _is_alias(path) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a non-aliased regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} size is outside 1..{maximum}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"{label} open failed: {exc.__class__.__name__}")
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeded its bound while reading")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or before.st_dev != opened.st_dev
        or before.st_ino != opened.st_ino
        or opened.st_dev != after.st_dev
        or opened.st_ino != after.st_ino
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or total != after.st_size
    ):
        fail(f"{label} changed while reading")
    return b"".join(chunks)


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path, MAX_JSON_BYTES, label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not canonical ASCII JSON: {exc.__class__.__name__}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    if canonical_json(value) != raw:
        fail(f"{label} is not canonical JSON")
    return value, raw


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        fail(
            f"{label} keys mismatch missing={sorted(expected - observed)} "
            f"extra={sorted(observed - expected)}"
        )


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        fail(f"{label} must be a bounded identifier")
    if value.startswith("REPLACE"):
        fail(f"{label} remains a placeholder")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def exact_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        fail(f"{label} must be {str(expected).lower()}")


def finite_number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        fail(f"{label} is outside {minimum}..{maximum}")
    return result


def utc_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} must be RFC3339 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not valid UTC")
    if parsed.tzinfo != timezone.utc:
        fail(f"{label} must be UTC")
    return parsed


def _require_false_claims(claims: Any, label: str) -> None:
    facts = mapping(claims, label)
    exact_keys(facts, set(FALSE_CLAIMS), label)
    for claim in FALSE_CLAIMS:
        exact_bool(facts.get(claim), False, f"{label}.{claim}")


def _validate_target(target_value: Any, label: str) -> dict[str, Any]:
    target = mapping(target_value, label)
    exact_keys(
        target,
        {
            "model",
            "nano3s_substitution_forbidden",
            "unit_asset_id",
            "unit_fingerprint_sha256",
            "board_revision",
            "board_revision_evidence_type",
        },
        label,
    )
    if target.get("model") != TARGET_MODEL:
        fail(f"{label}.model must be the exact non-S Nano 3 model")
    exact_bool(
        target.get("nano3s_substitution_forbidden"),
        True,
        f"{label}.nano3s_substitution_forbidden",
    )
    token(target.get("unit_asset_id"), f"{label}.unit_asset_id")
    digest(target.get("unit_fingerprint_sha256"), f"{label}.unit_fingerprint_sha256")
    token(target.get("board_revision"), f"{label}.board_revision")
    if target.get("board_revision_evidence_type") != "board_revision_record":
        fail(f"{label}.board_revision_evidence_type mismatch")
    return target


def _validate_roles(roles_value: Any) -> dict[str, Any]:
    roles = mapping(roles_value, "plan.roles")
    exact_keys(roles, {"operator", "electrical_reviewer", "independent"}, "plan.roles")
    exact_bool(roles.get("independent"), True, "plan.roles.independent")
    for name in ("operator", "electrical_reviewer"):
        role = mapping(roles.get(name), f"plan.roles.{name}")
        exact_keys(role, {"identity", "public_key_sha256", "custody_evidence_type"}, f"plan.roles.{name}")
        token(role.get("identity"), f"plan.roles.{name}.identity")
        digest(role.get("public_key_sha256"), f"plan.roles.{name}.public_key_sha256")
        expected_custody = (
            "operator_key_custody_record"
            if name == "operator"
            else "electrical_reviewer_key_custody_record"
        )
        if role.get("custody_evidence_type") != expected_custody:
            fail(f"plan.roles.{name}.custody_evidence_type mismatch")
    if roles["operator"]["identity"] == roles["electrical_reviewer"]["identity"]:
        fail("operator and electrical reviewer identities must differ")
    if roles["operator"]["public_key_sha256"] == roles["electrical_reviewer"]["public_key_sha256"]:
        fail("operator and electrical reviewer keys must differ")
    return roles


def _validate_phase_scopes(phases_value: Any, valid_from: datetime, valid_until: datetime) -> dict[str, Any]:
    phases = mapping(phases_value, "plan.phase_scopes")
    exact_keys(phases, set(PHASE_ORDER), "plan.phase_scopes")
    for phase_name in PHASE_ORDER:
        phase = mapping(phases.get(phase_name), f"plan.phase_scopes.{phase_name}")
        exact_keys(
            phase,
            {
                "authorization_id",
                "authorization_nonce_sha256",
                "authorization_evidence_type",
                "authorization_receipt_sha256",
                "authorized",
                "performed_by_plan",
                "authorized_from_utc",
                "authorized_until_utc",
                "actions",
            },
            f"plan.phase_scopes.{phase_name}",
        )
        if phase_name == "capture_energization":
            if (
                phase.get("authorization_id") is not None
                or phase.get("authorization_nonce_sha256") is not None
                or phase.get("authorization_evidence_type") is not None
                or phase.get("authorization_receipt_sha256") is not None
            ):
                fail("capture energization must not carry an authorization identity")
            exact_bool(phase.get("authorized"), False, "capture_energization.authorized")
            exact_bool(phase.get("performed_by_plan"), False, "capture_energization.performed_by_plan")
            if phase.get("authorized_from_utc") is not None or phase.get("authorized_until_utc") is not None:
                fail("capture energization must not carry an authorization window")
            if phase.get("actions") != []:
                fail("capture energization actions must be empty")
            continue
        token(phase.get("authorization_id"), f"{phase_name}.authorization_id")
        digest(phase.get("authorization_nonce_sha256"), f"{phase_name}.authorization_nonce_sha256")
        if phase.get("authorization_evidence_type") != PHASE_AUTHORIZATION_EVIDENCE[phase_name]:
            fail(f"{phase_name}.authorization_evidence_type mismatch")
        digest(
            phase.get("authorization_receipt_sha256"),
            f"{phase_name}.authorization_receipt_sha256",
        )
        exact_bool(phase.get("authorized"), True, f"{phase_name}.authorized")
        exact_bool(phase.get("performed_by_plan"), False, f"{phase_name}.performed_by_plan")
        start = utc_time(phase.get("authorized_from_utc"), f"{phase_name}.authorized_from_utc")
        end = utc_time(phase.get("authorized_until_utc"), f"{phase_name}.authorized_until_utc")
        if start < valid_from or end > valid_until or start >= end:
            fail(f"{phase_name} authorization window is outside plan validity")
        if phase.get("actions") != EXPECTED_PHASE_ACTIONS[phase_name]:
            fail(f"{phase_name}.actions differ from the exact admitted scope")
    nonces = [
        phases[name]["authorization_nonce_sha256"]
        for name in AUTHORIZED_PHASES
    ]
    if len(nonces) != len(set(nonces)):
        fail("phase authorization nonces must be unique")
    return phases


def _validate_instruments(instruments_value: Any, label: str) -> dict[str, Any]:
    instruments = mapping(instruments_value, label)
    exact_keys(
        instruments,
        {"oscilloscope", "scope_probe", "logic_analyzer", "deenergization_meter"},
        label,
    )
    common = {"asset_id", "model", "hardware_revision", "serial_fingerprint_sha256", "identity_evidence_type", "calibration_evidence_type", "calibration_valid_until_utc"}
    scope = mapping(instruments.get("oscilloscope"), f"{label}.oscilloscope")
    exact_keys(scope, common | {"input_rating_v", "protective_earth_class"}, f"{label}.oscilloscope")
    probe = mapping(instruments.get("scope_probe"), f"{label}.scope_probe")
    exact_keys(probe, common | {"input_rating_v", "input_impedance_ohm", "probe_kind", "attenuation_ratio"}, f"{label}.scope_probe")
    analyzer = mapping(instruments.get("logic_analyzer"), f"{label}.logic_analyzer")
    exact_keys(
        analyzer,
        common
        | {
            "software_version",
            "software_sha256",
            "absolute_max_input_v",
            "input_impedance_ohm",
            "receive_only",
            "tx_connected",
            "pullup_enabled",
            "power_output_enabled",
            "shared_usb_power_to_target",
        },
        f"{label}.logic_analyzer",
    )
    meter = mapping(
        instruments.get("deenergization_meter"), f"{label}.deenergization_meter"
    )
    exact_keys(
        meter,
        common
        | {
            "input_rating_v",
            "input_impedance_ohm",
            "measurement_kind",
            "power_class",
            "probe_attachment_method",
            "independently_attachable_while_deenergized",
        },
        f"{label}.deenergization_meter",
    )
    expected_evidence = {
        "oscilloscope": ("scope_identity_record", "scope_calibration_record"),
        "scope_probe": ("probe_identity_record", "probe_calibration_record"),
        "logic_analyzer": ("analyzer_identity_record", "analyzer_calibration_record"),
        "deenergization_meter": (
            "deenergization_meter_identity_record",
            "deenergization_meter_calibration_record",
        ),
    }
    for name, fact in instruments.items():
        for field in ("asset_id", "model", "hardware_revision"):
            token(fact.get(field), f"{label}.{name}.{field}")
        digest(fact.get("serial_fingerprint_sha256"), f"{label}.{name}.serial_fingerprint_sha256")
        identity_type, calibration_type = expected_evidence[name]
        if fact.get("identity_evidence_type") != identity_type or fact.get("calibration_evidence_type") != calibration_type:
            fail(f"{label}.{name} evidence type mismatch")
        utc_time(fact.get("calibration_valid_until_utc"), f"{label}.{name}.calibration_valid_until_utc")
    finite_number(scope.get("input_rating_v"), f"{label}.oscilloscope.input_rating_v", 0.1, 10_000.0)
    if scope.get("protective_earth_class") not in {"earth_referenced", "battery_isolated", "double_insulated"}:
        fail(f"{label}.oscilloscope.protective_earth_class invalid")
    finite_number(probe.get("input_rating_v"), f"{label}.scope_probe.input_rating_v", 0.1, 10_000.0)
    finite_number(probe.get("input_impedance_ohm"), f"{label}.scope_probe.input_impedance_ohm", 1_000.0, 1e12)
    finite_number(probe.get("attenuation_ratio"), f"{label}.scope_probe.attenuation_ratio", 1.0, 10_000.0)
    if probe.get("probe_kind") not in {"passive_high_impedance", "rated_differential", "isolated_active"}:
        fail(f"{label}.scope_probe.probe_kind invalid")
    token(analyzer.get("software_version"), f"{label}.logic_analyzer.software_version")
    digest(analyzer.get("software_sha256"), f"{label}.logic_analyzer.software_sha256")
    finite_number(analyzer.get("absolute_max_input_v"), f"{label}.logic_analyzer.absolute_max_input_v", 0.1, 1000.0)
    finite_number(analyzer.get("input_impedance_ohm"), f"{label}.logic_analyzer.input_impedance_ohm", 1_000.0, 1e12)
    for field, expected in (
        ("receive_only", True),
        ("tx_connected", False),
        ("pullup_enabled", False),
        ("power_output_enabled", False),
        ("shared_usb_power_to_target", False),
    ):
        exact_bool(analyzer.get(field), expected, f"{label}.logic_analyzer.{field}")
    finite_number(
        meter.get("input_rating_v"),
        f"{label}.deenergization_meter.input_rating_v",
        5.0,
        10_000.0,
    )
    finite_number(
        meter.get("input_impedance_ohm"),
        f"{label}.deenergization_meter.input_impedance_ohm",
        1_000_000.0,
        1e12,
    )
    if meter.get("measurement_kind") != "dc_voltage_true_rms_bounded":
        fail(f"{label}.deenergization_meter.measurement_kind mismatch")
    if meter.get("power_class") != "battery_isolated":
        fail(f"{label}.deenergization_meter must be battery isolated")
    if meter.get("probe_attachment_method") != "rated_handheld_noninvasive_probes":
        fail(f"{label}.deenergization_meter probe method mismatch")
    exact_bool(
        meter.get("independently_attachable_while_deenergized"),
        True,
        f"{label}.deenergization_meter.independently_attachable_while_deenergized",
    )
    return instruments


def validate_plan(plan: dict[str, Any], raw: bytes) -> dict[str, Any]:
    exact_keys(
        plan,
        {"schema", "status", "purpose", "preflight", "target", "roles", "phase_scopes", "intended_instruments", "electrical_method", "required_evidence_types", "claims"},
        "plan",
    )
    if plan.get("schema") != PLAN_SCHEMA:
        fail("plan schema mismatch")
    if plan.get("status") != PLAN_STATUS:
        fail("plan is not approved for exact preflight phases")
    if plan.get("purpose") != "non_s_nano3_uart_physical_electrical_preflight_only":
        fail("plan purpose mismatch")
    preflight = mapping(plan.get("preflight"), "plan.preflight")
    exact_keys(
        preflight,
        {
            "preflight_id",
            "session_nonce_sha256",
            "issued_at_utc",
            "valid_from_utc",
            "valid_until_utc",
            "clock_source_evidence_type",
            "clock_source_kind",
            "clock_source_fingerprint_sha256",
            "clock_independently_trusted",
            "maximum_clock_uncertainty_ms",
            "one_shot_same_host_ledger",
        },
        "plan.preflight",
    )
    token(preflight.get("preflight_id"), "plan.preflight.preflight_id")
    digest(preflight.get("session_nonce_sha256"), "plan.preflight.session_nonce_sha256")
    issued = utc_time(preflight.get("issued_at_utc"), "plan.preflight.issued_at_utc")
    valid_from = utc_time(preflight.get("valid_from_utc"), "plan.preflight.valid_from_utc")
    valid_until = utc_time(preflight.get("valid_until_utc"), "plan.preflight.valid_until_utc")
    if valid_from > issued or issued >= valid_until:
        fail("plan validity ordering is invalid")
    if (valid_until - valid_from).total_seconds() > MAX_VALIDITY_SECONDS:
        fail("plan validity exceeds 24 hours")
    if preflight.get("clock_source_evidence_type") != "clock_source_record":
        fail("plan clock source evidence mismatch")
    if preflight.get("clock_source_kind") != "operator_asserted_utc":
        fail("plan clock source must remain explicitly operator-asserted")
    digest(
        preflight.get("clock_source_fingerprint_sha256"),
        "plan.preflight.clock_source_fingerprint_sha256",
    )
    exact_bool(
        preflight.get("clock_independently_trusted"),
        False,
        "plan.preflight.clock_independently_trusted",
    )
    finite_number(preflight.get("maximum_clock_uncertainty_ms"), "plan.preflight.maximum_clock_uncertainty_ms", 0.0, 5000.0)
    exact_bool(preflight.get("one_shot_same_host_ledger"), True, "plan.preflight.one_shot_same_host_ledger")
    target = _validate_target(plan.get("target"), "plan.target")
    roles = _validate_roles(plan.get("roles"))
    phases = _validate_phase_scopes(plan.get("phase_scopes"), valid_from, valid_until)
    instruments = _validate_instruments(plan.get("intended_instruments"), "plan.intended_instruments")
    for instrument_name, instrument in instruments.items():
        calibration_end = utc_time(
            instrument["calibration_valid_until_utc"],
            f"plan.intended_instruments.{instrument_name}.calibration_valid_until_utc",
        )
        if calibration_end < valid_until:
            fail(f"{instrument_name} calibration expires before the plan window ends")
    method = mapping(plan.get("electrical_method"), "plan.electrical_method")
    exact_keys(
        method,
        {
            "isolation_strategy",
            "maximum_reviewed_ground_potential_v",
            "maximum_zero_energy_v",
            "maximum_signal_continuity_ohm",
            "maximum_ground_continuity_ohm",
            "minimum_voltage_rating_margin_v",
            "minimum_analyzer_input_impedance_ohm",
            "scope_attach_order",
            "scope_detach_order",
            "analyzer_attach_order",
            "analyzer_detach_order",
            "esd_controls_required",
            "direct_single_ended_earth_reference_forbidden",
        },
        "plan.electrical_method",
    )
    if method.get("isolation_strategy") not in {"battery_isolated_scope", "rated_differential_probe", "reviewed_no_usb_common_reference"}:
        fail("plan isolation strategy is not admitted")
    finite_number(
        method.get("maximum_reviewed_ground_potential_v"),
        "maximum_reviewed_ground_potential_v",
        0.0,
        HARD_MAX_GROUND_POTENTIAL_V,
    )
    finite_number(
        method.get("maximum_zero_energy_v"),
        "maximum_zero_energy_v",
        0.0,
        HARD_MAX_ZERO_ENERGY_V,
    )
    finite_number(
        method.get("maximum_signal_continuity_ohm"),
        "maximum_signal_continuity_ohm",
        0.0,
        HARD_MAX_SIGNAL_CONTINUITY_OHM,
    )
    finite_number(
        method.get("maximum_ground_continuity_ohm"),
        "maximum_ground_continuity_ohm",
        0.0,
        HARD_MAX_GROUND_CONTINUITY_OHM,
    )
    finite_number(
        method.get("minimum_voltage_rating_margin_v"),
        "minimum_voltage_rating_margin_v",
        HARD_MIN_VOLTAGE_RATING_MARGIN_V,
        1000.0,
    )
    finite_number(
        method.get("minimum_analyzer_input_impedance_ohm"),
        "minimum_analyzer_input_impedance_ohm",
        HARD_MIN_ANALYZER_INPUT_IMPEDANCE_OHM,
        1e12,
    )
    strategy = method["isolation_strategy"]
    scope_class = instruments["oscilloscope"]["protective_earth_class"]
    probe_kind = instruments["scope_probe"]["probe_kind"]
    if strategy == "battery_isolated_scope" and scope_class != "battery_isolated":
        fail("battery-isolated strategy requires a battery-isolated scope")
    if strategy == "rated_differential_probe" and probe_kind not in {
        "rated_differential",
        "isolated_active",
    }:
        fail("differential isolation strategy requires a rated differential probe")
    if strategy == "reviewed_no_usb_common_reference" and scope_class == "earth_referenced":
        fail("no-USB common-reference strategy cannot use an earth-referenced scope")
    expected_attach = ["proven_signal_ground", "host_to_controller", "controller_to_host"]
    expected_detach = ["host_to_controller", "controller_to_host", "proven_signal_ground"]
    for prefix in ("scope", "analyzer"):
        if method.get(f"{prefix}_attach_order") != expected_attach:
            fail(f"{prefix} attach order must be ground first, signals second")
        if method.get(f"{prefix}_detach_order") != expected_detach:
            fail(f"{prefix} detach order must be signals first, ground last")
    exact_bool(method.get("esd_controls_required"), True, "esd_controls_required")
    exact_bool(method.get("direct_single_ended_earth_reference_forbidden"), True, "direct_single_ended_earth_reference_forbidden")
    if plan.get("required_evidence_types") != list(REQUIRED_EVIDENCE_TYPES):
        fail("plan required evidence types mismatch")
    _require_false_claims(plan.get("claims"), "plan.claims")
    return {
        "sha256": sha256_bytes(raw),
        "preflight": preflight,
        "target": target,
        "roles": roles,
        "phases": phases,
        "instruments": instruments,
        "method": method,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def _validate_evidence_entry(entry_value: Any, index: int) -> dict[str, Any]:
    entry = mapping(entry_value, f"receipt.evidence[{index}]")
    exact_keys(entry, {"evidence_type", "evidence_id", "filename", "sha256", "size_bytes", "media_type", "captured_at_utc"}, f"receipt.evidence[{index}]")
    evidence_type = entry.get("evidence_type")
    if evidence_type not in REQUIRED_EVIDENCE_TYPES:
        fail(f"receipt evidence type {evidence_type!r} is not admitted")
    token(entry.get("evidence_id"), f"receipt.evidence[{index}].evidence_id")
    filename = entry.get("filename")
    if not isinstance(filename, str) or not filename or filename != Path(filename).name or "/" in filename or "\\" in filename:
        fail(f"receipt.evidence[{index}].filename must be a basename")
    digest(entry.get("sha256"), f"receipt.evidence[{index}].sha256")
    size = entry.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_EVIDENCE_FILE_BYTES:
        fail(f"receipt.evidence[{index}].size_bytes is invalid")
    media_type = entry.get("media_type")
    if evidence_type in PHOTO_EVIDENCE_TYPES:
        if media_type != "image/png":
            fail(f"{evidence_type} must be a fully parsed PNG")
    elif media_type != "application/json":
        fail(f"{evidence_type} must be a structured JSON evidence record")
    utc_time(entry.get("captured_at_utc"), f"receipt.evidence[{index}].captured_at_utc")
    return entry


def _validate_zero_energy(value: Any, label: str, plan: dict[str, Any]) -> dict[str, Any]:
    fact = mapping(value, label)
    exact_keys(
        fact,
        {
            "power_disconnect_asset_id",
            "power_disconnect_evidence_type",
            "power_disconnected_at_utc",
            "observation_started_at_utc",
            "observation_ended_at_utc",
            "minimum_observation_duration_ms",
            "measurement_points",
            "measurement_instrument_asset_id",
            "evidence_type",
            "maximum_observed_abs_v",
            "measurement_uncertainty_v",
            "reviewed_limit_v",
            "passed",
        },
        label,
    )
    token(fact.get("power_disconnect_asset_id"), f"{label}.power_disconnect_asset_id")
    if fact.get("power_disconnect_evidence_type") != "power_disconnect_record":
        fail(f"{label}.power_disconnect_evidence_type mismatch")
    disconnected = utc_time(
        fact.get("power_disconnected_at_utc"), f"{label}.power_disconnected_at_utc"
    )
    observation_started = utc_time(
        fact.get("observation_started_at_utc"), f"{label}.observation_started_at_utc"
    )
    observation_ended = utc_time(
        fact.get("observation_ended_at_utc"), f"{label}.observation_ended_at_utc"
    )
    duration_ms = finite_number(
        fact.get("minimum_observation_duration_ms"),
        f"{label}.minimum_observation_duration_ms",
        MIN_ZERO_ENERGY_OBSERVATION_MS,
        60_000.0,
    )
    if disconnected > observation_started or observation_started >= observation_ended:
        fail(f"{label} disconnect/observation chronology is invalid")
    if (observation_ended - observation_started).total_seconds() * 1000 < duration_ms:
        fail(f"{label} objective observation is shorter than its claimed minimum")
    if fact.get("measurement_points") != [
        "uart_signal_ground_to_chassis",
        "uart_signal_ground_to_host_to_controller",
        "uart_signal_ground_to_controller_to_host",
        "target_power_rail_to_uart_signal_ground",
    ]:
        fail(f"{label}.measurement_points do not cover the exact zero-energy set")
    if (
        fact.get("measurement_instrument_asset_id")
        != plan["instruments"]["deenergization_meter"]["asset_id"]
    ):
        fail(f"{label}.measurement_instrument_asset_id differs from the signed plan")
    if fact.get("evidence_type") not in {
        "zero_energy_before_scope_attach_record",
        "zero_energy_before_scope_detach_record",
        "zero_energy_before_analyzer_attach_record",
        "zero_energy_before_analyzer_detach_record",
    }:
        fail(f"{label}.evidence_type invalid")
    observed = finite_number(fact.get("maximum_observed_abs_v"), f"{label}.maximum_observed_abs_v", 0.0, 100.0)
    uncertainty = finite_number(fact.get("measurement_uncertainty_v"), f"{label}.measurement_uncertainty_v", 0.0, 100.0)
    limit = finite_number(fact.get("reviewed_limit_v"), f"{label}.reviewed_limit_v", 0.0, 10.0)
    if limit != float(plan["method"]["maximum_zero_energy_v"]):
        fail(f"{label}.reviewed_limit_v differs from signed plan")
    if observed + uncertainty > limit:
        fail(f"{label} does not prove the reviewed zero-energy bound")
    exact_bool(fact.get("passed"), True, f"{label}.passed")
    return {
        **fact,
        "_disconnected": disconnected,
        "_observation_started": observation_started,
        "_observation_ended": observation_ended,
    }


def _validate_phase_receipts(value: Any, plan: dict[str, Any]) -> dict[str, Any]:
    phases = mapping(value, "receipt.phase_receipts")
    exact_keys(phases, set(PHASE_ORDER), "receipt.phase_receipts")
    previous_end: datetime | None = None
    uncertainty_s = float(plan["preflight"]["maximum_clock_uncertainty_ms"]) / 1000.0
    for phase_name in PHASE_ORDER:
        phase = mapping(phases.get(phase_name), f"receipt.phase_receipts.{phase_name}")
        if phase_name == "capture_energization":
            exact_keys(phase, {"authorization_id", "authorized", "performed", "began_at_utc", "ended_at_utc"}, f"receipt.phase_receipts.{phase_name}")
            if phase != {"authorization_id": None, "authorized": False, "performed": False, "began_at_utc": None, "ended_at_utc": None}:
                fail("capture energization must remain unauthorized and unperformed")
            continue
        exact_keys(
            phase,
            {
                "authorization_id",
                "authorization_nonce_sha256",
                "authorization_evidence_type",
                "authorization_receipt_sha256",
                "performed",
                "began_at_utc",
                "ended_at_utc",
                "clock_source_evidence_type",
                "clock_uncertainty_ms",
                "zero_energy",
                "evidence_types",
            },
            f"receipt.phase_receipts.{phase_name}",
        )
        planned = plan["phases"][phase_name]
        if any(
            phase.get(field) != planned[field]
            for field in (
                "authorization_id",
                "authorization_nonce_sha256",
                "authorization_evidence_type",
                "authorization_receipt_sha256",
            )
        ):
            fail(f"{phase_name} authorization binding mismatch")
        exact_bool(phase.get("performed"), True, f"{phase_name}.performed")
        began = utc_time(phase.get("began_at_utc"), f"{phase_name}.began_at_utc")
        ended = utc_time(phase.get("ended_at_utc"), f"{phase_name}.ended_at_utc")
        if began >= ended:
            fail(f"{phase_name} timestamps are not increasing")
        phase_uncertainty_ms = finite_number(phase.get("clock_uncertainty_ms"), f"{phase_name}.clock_uncertainty_ms", 0.0, plan["preflight"]["maximum_clock_uncertainty_ms"])
        phase_uncertainty_s = phase_uncertainty_ms / 1000.0
        authorized_from = utc_time(planned["authorized_from_utc"], f"{phase_name}.authorized_from")
        authorized_until = utc_time(planned["authorized_until_utc"], f"{phase_name}.authorized_until")
        if (began.timestamp() - phase_uncertainty_s < authorized_from.timestamp() or ended.timestamp() + phase_uncertainty_s > authorized_until.timestamp()):
            fail(f"{phase_name} evidence falls outside its authorization window")
        if previous_end is not None and began.timestamp() - uncertainty_s < previous_end.timestamp():
            fail(f"{phase_name} overlaps or precedes the prior phase under clock uncertainty")
        previous_end = ended
        if phase.get("clock_source_evidence_type") != "clock_source_record":
            fail(f"{phase_name} clock source evidence mismatch")
        zero = phase.get("zero_energy")
        if phase_name == "bounded_energized_scope_measurement":
            if zero is not None:
                fail("energized scope measurement must not self-assert zero energy")
        else:
            zero_fact = _validate_zero_energy(
                zero, f"{phase_name}.zero_energy", plan
            )
            if (
                zero_fact["_disconnected"].timestamp() - phase_uncertainty_s
                < authorized_from.timestamp()
                or zero_fact["_observation_started"].timestamp()
                - phase_uncertainty_s
                < began.timestamp()
                or zero_fact["_observation_ended"].timestamp()
                + phase_uncertainty_s
                > ended.timestamp()
            ):
                fail(f"{phase_name} zero-energy observation is outside its phase")
        if phase.get("evidence_types") != PHASE_EVIDENCE_TYPES[phase_name]:
            fail(f"{phase_name}.evidence_types differ from the exact admitted set")
    return phases


def _validate_mapping(value: Any, plan: dict[str, Any]) -> dict[str, Any]:
    facts = mapping(value, "receipt.signal_mapping")
    exact_keys(facts, {"host_to_controller", "controller_to_host", "signal_ground"}, "receipt.signal_mapping")
    expected = {
        "host_to_controller": ("k230_uart_tx", "mining_controller_uart_rx", "host_to_controller_continuity_record"),
        "controller_to_host": ("mining_controller_uart_tx", "k230_uart_rx", "controller_to_host_continuity_record"),
        "signal_ground": ("uart_signal_ground_tap", "known_board_signal_ground", "signal_ground_continuity_record"),
    }
    for name, (source, destination, evidence_type) in expected.items():
        fact = mapping(facts.get(name), f"receipt.signal_mapping.{name}")
        exact_keys(fact, {"tap_id", "source_endpoint", "destination_endpoint", "basis", "silkscreen_inference_used", "continuity_resistance_ohm", "measurement_uncertainty_ohm", "evidence_type"}, f"receipt.signal_mapping.{name}")
        token(fact.get("tap_id"), f"receipt.signal_mapping.{name}.tap_id")
        if fact.get("source_endpoint") != source or fact.get("destination_endpoint") != destination:
            fail(f"receipt.signal_mapping.{name} endpoint mismatch")
        if fact.get("basis") != "deenergized_continuity_to_named_endpoints":
            fail(f"receipt.signal_mapping.{name} basis mismatch")
        exact_bool(fact.get("silkscreen_inference_used"), False, f"receipt.signal_mapping.{name}.silkscreen_inference_used")
        resistance = finite_number(
            fact.get("continuity_resistance_ohm"),
            f"receipt.signal_mapping.{name}.continuity_resistance_ohm",
            0.0,
            HARD_MAX_SIGNAL_CONTINUITY_OHM,
        )
        uncertainty = finite_number(
            fact.get("measurement_uncertainty_ohm"),
            f"receipt.signal_mapping.{name}.measurement_uncertainty_ohm",
            0.0,
            HARD_MAX_SIGNAL_CONTINUITY_OHM,
        )
        plan_limit_field = (
            "maximum_ground_continuity_ohm"
            if name == "signal_ground"
            else "maximum_signal_continuity_ohm"
        )
        if resistance + uncertainty > float(plan["method"][plan_limit_field]):
            fail(f"receipt.signal_mapping.{name} exceeds its signed continuity bound")
        if fact.get("evidence_type") != evidence_type:
            fail(f"receipt.signal_mapping.{name} evidence mismatch")
    return facts


def _validate_levels(value: Any, plan: dict[str, Any], instruments: dict[str, Any]) -> dict[str, Any]:
    levels = mapping(value, "receipt.measured_levels")
    exact_keys(levels, {"host_to_controller", "controller_to_host", "analyzer_threshold_v", "measurement_uncertainty_v", "threshold_margin_v", "ground_potential_v", "ground_potential_uncertainty_v", "isolation_strategy", "usb_earth_relationship", "compatibility_decision", "decision_evidence_type"}, "receipt.measured_levels")
    uncertainty = finite_number(levels.get("measurement_uncertainty_v"), "measurement_uncertainty_v", 0.0, 100.0)
    threshold = finite_number(levels.get("analyzer_threshold_v"), "analyzer_threshold_v", -100.0, 100.0)
    threshold_margin = finite_number(levels.get("threshold_margin_v"), "threshold_margin_v", 0.0, 100.0)
    maximum_overshoot = 0.0
    for name in ("host_to_controller", "controller_to_host"):
        fact = mapping(levels.get(name), f"receipt.measured_levels.{name}")
        exact_keys(fact, {"low_min_v", "low_max_v", "high_min_v", "high_max_v", "overshoot_min_v", "overshoot_max_v", "idle_state", "polarity", "drive_mode", "direct_logic_input_compatible"}, f"receipt.measured_levels.{name}")
        low_min = finite_number(fact.get("low_min_v"), f"{name}.low_min_v", -100.0, 100.0)
        low_max = finite_number(fact.get("low_max_v"), f"{name}.low_max_v", -100.0, 100.0)
        high_min = finite_number(fact.get("high_min_v"), f"{name}.high_min_v", -100.0, 100.0)
        high_max = finite_number(fact.get("high_max_v"), f"{name}.high_max_v", -100.0, 100.0)
        over_min = finite_number(fact.get("overshoot_min_v"), f"{name}.overshoot_min_v", -1000.0, 1000.0)
        over_max = finite_number(fact.get("overshoot_max_v"), f"{name}.overshoot_max_v", -1000.0, 1000.0)
        if not low_min <= low_max < high_min <= high_max or not over_min <= low_min or not over_max >= high_max:
            fail(f"{name} measured level ordering is invalid")
        if not threshold >= low_max + uncertainty + threshold_margin or not threshold <= high_min - uncertainty - threshold_margin:
            fail(f"{name} analyzer threshold has insufficient measured margin")
        if fact.get("idle_state") not in {"logic_low", "logic_high"} or fact.get("polarity") not in {"non_inverted", "inverted"}:
            fail(f"{name} idle/polarity is not measured")
        if fact.get("drive_mode") not in {"push_pull", "translated_push_pull", "open_drain_reviewed_with_external_bias"}:
            fail(f"{name} drive mode is unknown or incompatible")
        exact_bool(fact.get("direct_logic_input_compatible"), True, f"{name}.direct_logic_input_compatible")
        maximum_overshoot = max(maximum_overshoot, abs(over_min), abs(over_max))
    margin = float(plan["method"]["minimum_voltage_rating_margin_v"])
    analyzer = instruments["logic_analyzer"]
    scope = instruments["oscilloscope"]
    probe = instruments["scope_probe"]
    if float(analyzer["absolute_max_input_v"]) < maximum_overshoot + uncertainty + margin:
        fail("logic analyzer absolute input rating margin is insufficient")
    if min(float(scope["input_rating_v"]), float(probe["input_rating_v"])) < maximum_overshoot + uncertainty + margin:
        fail("scope/probe input rating margin is insufficient")
    if float(analyzer["input_impedance_ohm"]) < float(plan["method"]["minimum_analyzer_input_impedance_ohm"]):
        fail("logic analyzer input impedance is below the reviewed plan")
    ground = finite_number(levels.get("ground_potential_v"), "ground_potential_v", 0.0, 1000.0)
    ground_uncertainty = finite_number(levels.get("ground_potential_uncertainty_v"), "ground_potential_uncertainty_v", 0.0, 100.0)
    if ground + ground_uncertainty > float(plan["method"]["maximum_reviewed_ground_potential_v"]):
        fail("ground potential exceeds the reviewed bound")
    if levels.get("isolation_strategy") != plan["method"]["isolation_strategy"]:
        fail("observed isolation strategy differs from the signed plan")
    if levels.get("usb_earth_relationship") not in {"no_usb_connection", "battery_isolated", "rated_galvanic_isolation", "reviewed_common_reference_no_shared_power"}:
        fail("USB/earth relationship is not admitted")
    expected_relationships = {
        "battery_isolated_scope": {"no_usb_connection", "battery_isolated"},
        "rated_differential_probe": {
            "no_usb_connection",
            "rated_galvanic_isolation",
        },
        "reviewed_no_usb_common_reference": {
            "reviewed_common_reference_no_shared_power"
        },
    }
    if levels["usb_earth_relationship"] not in expected_relationships[
        levels["isolation_strategy"]
    ]:
        fail("USB/earth relationship is inconsistent with the isolation strategy")
    if levels.get("compatibility_decision") != "accepted_for_passive_receive_only_attachment":
        fail("electrical compatibility decision is not accepted")
    if levels.get("decision_evidence_type") != "electrical_compatibility_review_record":
        fail("compatibility decision evidence mismatch")
    return levels


def _validate_evidence_time_and_authorization_joins(
    evidence: list[dict[str, Any]], phases: dict[str, Any], plan: dict[str, Any]
) -> None:
    by_type = {item["evidence_type"]: item for item in evidence}
    assigned = set(SESSION_EVIDENCE_TYPES)
    assigned.update(PHASE_AUTHORIZATION_EVIDENCE.values())
    for phase_evidence in PHASE_EVIDENCE_TYPES.values():
        assigned.update(phase_evidence)
    if assigned != set(REQUIRED_EVIDENCE_TYPES):
        fail("internal evidence-to-phase assignment is incomplete")

    maximum_uncertainty_s = (
        float(plan["preflight"]["maximum_clock_uncertainty_ms"]) / 1000.0
    )
    first_phase_start = utc_time(
        phases[PHASE_ORDER[0]]["began_at_utc"], "first phase began_at_utc"
    )
    plan_issued = utc_time(
        plan["preflight"]["issued_at_utc"], "plan.preflight.issued_at_utc"
    )
    if plan_issued.timestamp() + maximum_uncertainty_s > first_phase_start.timestamp():
        fail("signed plan issuance does not robustly precede phase one")
    for evidence_type in SESSION_EVIDENCE_TYPES:
        captured = utc_time(
            by_type[evidence_type]["captured_at_utc"],
            f"{evidence_type}.captured_at_utc",
        )
        if (
            captured.timestamp() - maximum_uncertainty_s
            < plan["valid_from"].timestamp()
            or captured.timestamp() + maximum_uncertainty_s
            > plan_issued.timestamp()
        ):
            fail(f"{evidence_type} is not robustly inside the pre-action plan window")

    for phase_name in AUTHORIZED_PHASES:
        planned = plan["phases"][phase_name]
        completed = phases[phase_name]
        uncertainty_s = float(completed["clock_uncertainty_ms"]) / 1000.0
        began = utc_time(completed["began_at_utc"], f"{phase_name}.began_at_utc")
        ended = utc_time(completed["ended_at_utc"], f"{phase_name}.ended_at_utc")
        authorized_from = utc_time(
            planned["authorized_from_utc"], f"{phase_name}.authorized_from_utc"
        )
        authorization_type = PHASE_AUTHORIZATION_EVIDENCE[phase_name]
        authorization_entry = by_type[authorization_type]
        if authorization_entry["sha256"] != planned["authorization_receipt_sha256"]:
            fail(f"{phase_name} authorization record byte identity mismatch")
        authorized_at = utc_time(
            authorization_entry["captured_at_utc"],
            f"{authorization_type}.captured_at_utc",
        )
        if (
            authorized_at.timestamp() - uncertainty_s < authorized_from.timestamp()
            or authorized_at.timestamp() + uncertainty_s > plan_issued.timestamp()
        ):
            fail(f"{phase_name} authorization record is not in the pre-action window")
        for evidence_type in PHASE_EVIDENCE_TYPES[phase_name]:
            captured = utc_time(
                by_type[evidence_type]["captured_at_utc"],
                f"{evidence_type}.captured_at_utc",
            )
            if (
                captured.timestamp() - uncertainty_s < began.timestamp()
                or captured.timestamp() + uncertainty_s > ended.timestamp()
            ):
                fail(f"{evidence_type} is not robustly inside {phase_name}")
            zero_energy = completed.get("zero_energy")
            if (
                isinstance(zero_energy, dict)
                and evidence_type == zero_energy.get("evidence_type")
            ):
                observation_ended = utc_time(
                    zero_energy.get("observation_ended_at_utc"),
                    f"{evidence_type}.observation_ended_at_utc",
                )
                if (
                    captured.timestamp() - uncertainty_s
                    < observation_ended.timestamp()
                ):
                    fail(f"{evidence_type} was recorded before its observation ended")


def validate_receipt(receipt: dict[str, Any], raw: bytes, plan: dict[str, Any], plan_raw: bytes, plan_signatures: dict[str, bytes]) -> dict[str, Any]:
    exact_keys(
        receipt,
        {"schema", "status", "purpose", "plan_binding", "completed_at_utc", "target", "instruments", "phase_receipts", "evidence", "signal_mapping", "measured_levels", "procedure_observations", "post_evidence_review", "claims"},
        "receipt",
    )
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("status") != RECEIPT_STATUS:
        fail("receipt schema/status mismatch")
    if receipt.get("purpose") != "validate_completed_non_s_uart_preflight_evidence_only":
        fail("receipt purpose mismatch")
    binding = mapping(receipt.get("plan_binding"), "receipt.plan_binding")
    exact_keys(binding, {"plan_sha256", "plan_operator_signature_sha256", "plan_reviewer_signature_sha256", "preflight_id", "session_nonce_sha256"}, "receipt.plan_binding")
    expected_binding = {
        "plan_sha256": sha256_bytes(plan_raw),
        "plan_operator_signature_sha256": sha256_bytes(plan_signatures["operator"]),
        "plan_reviewer_signature_sha256": sha256_bytes(plan_signatures["reviewer"]),
        "preflight_id": plan["preflight"]["preflight_id"],
        "session_nonce_sha256": plan["preflight"]["session_nonce_sha256"],
    }
    if binding != expected_binding:
        fail("receipt does not bind the exact signed plan")
    completed = utc_time(receipt.get("completed_at_utc"), "receipt.completed_at_utc")
    if completed < plan["valid_from"] or completed > plan["valid_until"]:
        fail("receipt completion is outside plan validity")
    target = _validate_target(receipt.get("target"), "receipt.target")
    if target != plan["target"]:
        fail("receipt target differs from signed plan")
    instruments = _validate_instruments(receipt.get("instruments"), "receipt.instruments")
    if instruments != plan["instruments"]:
        fail("receipt instruments differ from signed plan")
    phases = _validate_phase_receipts(receipt.get("phase_receipts"), plan)
    final_phase_end = utc_time(
        phases["deenergized_analyzer_detach"]["ended_at_utc"],
        "deenergized_analyzer_detach.ended_at_utc",
    )
    maximum_uncertainty_s = (
        float(plan["preflight"]["maximum_clock_uncertainty_ms"]) / 1000.0
    )
    if completed.timestamp() - maximum_uncertainty_s < final_phase_end.timestamp():
        fail("receipt completion does not robustly follow the final phase")
    evidence_value = receipt.get("evidence")
    if not isinstance(evidence_value, list):
        fail("receipt.evidence must be a list")
    evidence = [_validate_evidence_entry(item, index) for index, item in enumerate(evidence_value)]
    observed_types = [item["evidence_type"] for item in evidence]
    if observed_types != list(REQUIRED_EVIDENCE_TYPES):
        fail("receipt evidence must enumerate every required type exactly once in canonical order")
    if len({item["filename"] for item in evidence}) != len(evidence) or len({item["evidence_id"] for item in evidence}) != len(evidence):
        fail("receipt evidence filenames and IDs must be unique")
    _validate_evidence_time_and_authorization_joins(evidence, phases, plan)
    mapping_facts = _validate_mapping(receipt.get("signal_mapping"), plan)
    measured_levels = _validate_levels(receipt.get("measured_levels"), plan, instruments)
    procedure = mapping(receipt.get("procedure_observations"), "receipt.procedure_observations")
    exact_keys(procedure, {"scope_attach_order", "scope_detach_order", "analyzer_attach_order", "analyzer_detach_order", "ground_continuity_reverified_before_analyzer", "esd_controls_observed", "analyzer_receive_only_confirmed", "analyzer_tx_absent", "analyzer_pullup_absent", "analyzer_power_output_absent", "shared_usb_power_absent", "unexpected_voltage_or_reset_observed", "stock_behavior_changed"}, "receipt.procedure_observations")
    for field in ("scope_attach_order", "scope_detach_order", "analyzer_attach_order", "analyzer_detach_order"):
        if procedure.get(field) != plan["method"][field]:
            fail(f"procedure {field} differs from signed plan")
    for field, expected in (
        ("ground_continuity_reverified_before_analyzer", True),
        ("esd_controls_observed", True),
        ("analyzer_receive_only_confirmed", True),
        ("analyzer_tx_absent", True),
        ("analyzer_pullup_absent", True),
        ("analyzer_power_output_absent", True),
        ("shared_usb_power_absent", True),
        ("unexpected_voltage_or_reset_observed", False),
        ("stock_behavior_changed", False),
    ):
        exact_bool(procedure.get(field), expected, f"receipt.procedure_observations.{field}")
    review = mapping(receipt.get("post_evidence_review"), "receipt.post_evidence_review")
    exact_keys(review, {"decision", "decision_domain", "every_raw_evidence_hash_reviewed", "numeric_values_and_uncertainty_reviewed", "phase_scope_and_time_windows_reviewed", "instrument_rating_and_calibration_reviewed", "usb_earth_ground_and_isolation_reviewed", "compatibility_evidence_type"}, "receipt.post_evidence_review")
    if review.get("decision") != "accept_file_bundle_for_preflight_record_only" or review.get("decision_domain") != "post-evidence-electrical-review-not-capture-authorization":
        fail("post-evidence reviewer decision/domain mismatch")
    for field in ("every_raw_evidence_hash_reviewed", "numeric_values_and_uncertainty_reviewed", "phase_scope_and_time_windows_reviewed", "instrument_rating_and_calibration_reviewed", "usb_earth_ground_and_isolation_reviewed"):
        exact_bool(review.get(field), True, f"receipt.post_evidence_review.{field}")
    if review.get("compatibility_evidence_type") != "electrical_compatibility_review_record":
        fail("post-evidence review evidence mismatch")
    _require_false_claims(receipt.get("claims"), "receipt.claims")
    return {
        "sha256": sha256_bytes(raw),
        "completed": completed,
        "target": target,
        "instruments": instruments,
        "phases": phases,
        "evidence": evidence,
        "mapping": mapping_facts,
        "levels": measured_levels,
        "review": review,
    }


def _verify_signature(public_key: bytes, signature: bytes, domain: bytes, payload: bytes, label: str) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        fail(f"{label} key/signature size mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, domain + payload)
    except (InvalidSignature, ValueError):
        fail(f"{label} signature is invalid")


def _validate_png(raw: bytes, label: str) -> None:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        fail(f"{label} PNG signature mismatch")
    offset = 8
    chunks: list[tuple[bytes, bytes]] = []
    while offset < len(raw):
        if len(raw) - offset < 12:
            fail(f"{label} PNG chunk is truncated")
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        chunk_type = raw[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(raw) or not re.fullmatch(rb"[A-Za-z]{4}", chunk_type):
            fail(f"{label} PNG chunk framing is invalid")
        data = raw[offset + 8 : offset + 8 + length]
        observed_crc = struct.unpack(">I", raw[offset + 8 + length : end])[0]
        if zlib.crc32(chunk_type + data) & 0xFFFFFFFF != observed_crc:
            fail(f"{label} PNG chunk CRC mismatch")
        chunks.append((chunk_type, data))
        offset = end
        if chunk_type == b"IEND":
            break
    if offset != len(raw) or not chunks or chunks[0][0] != b"IHDR":
        fail(f"{label} PNG framing/terminal IEND is invalid")
    if chunks[-1] != (b"IEND", b"") or len(chunks[0][1]) != 13:
        fail(f"{label} PNG IHDR/IEND is invalid")
    width, height, bit_depth, color_type, compression, filtering, interlace = (
        struct.unpack(">IIBBBBB", chunks[0][1])
    )
    if (
        not MIN_PHOTO_WIDTH <= width <= MAX_PHOTO_DIMENSION
        or not MIN_PHOTO_HEIGHT <= height <= MAX_PHOTO_DIMENSION
        or width * height > MAX_PHOTO_PIXELS
        or bit_depth != 8
        or color_type not in {2, 6}
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        fail(f"{label} PNG dimensions or encoding are not admitted")
    idat_indices = [index for index, chunk in enumerate(chunks) if chunk[0] == b"IDAT"]
    if not idat_indices or idat_indices != list(
        range(idat_indices[0], idat_indices[-1] + 1)
    ):
        fail(f"{label} PNG must have contiguous IDAT chunks")
    compressed = b"".join(chunks[index][1] for index in idat_indices)
    channels = 3 if color_type == 2 else 4
    row_size = width * channels
    expected_size = height * (row_size + 1)
    if expected_size > MAX_PHOTO_DECOMPRESSED_BYTES:
        fail(f"{label} PNG decompressed image exceeds its hard bound")
    try:
        inflater = zlib.decompressobj()
        pixels = inflater.decompress(compressed, expected_size + 1)
        remaining = expected_size + 1 - len(pixels)
        if remaining > 0:
            pixels += inflater.flush(remaining)
    except zlib.error:
        fail(f"{label} PNG image data is not a valid zlib stream")
    if (
        len(pixels) != expected_size
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
    ):
        fail(f"{label} PNG decompressed image size mismatch")
    if any(pixels[row * (row_size + 1)] > 4 for row in range(height)):
        fail(f"{label} PNG contains an invalid row filter")


def _plan_phases(plan: dict[str, Any]) -> dict[str, Any]:
    return plan["phases"] if "phases" in plan else plan["phase_scopes"]


def _plan_instruments(plan: dict[str, Any]) -> dict[str, Any]:
    return (
        plan["instruments"]
        if "instruments" in plan
        else plan["intended_instruments"]
    )


def _plan_method(plan: dict[str, Any]) -> dict[str, Any]:
    return plan["method"] if "method" in plan else plan["electrical_method"]


def _authorization_context(plan: dict[str, Any]) -> dict[str, Any]:
    phases = _plan_phases(plan)
    return {
        "purpose": "non_s_nano3_uart_physical_electrical_preflight_only",
        "preflight": plan["preflight"],
        "target": plan["target"],
        "roles": plan["roles"],
        "phase_scopes": {
            name: {
                key: value
                for key, value in phases[name].items()
                if key != "authorization_receipt_sha256"
            }
            for name in PHASE_ORDER
        },
        "intended_instruments": _plan_instruments(plan),
        "electrical_method": _plan_method(plan),
        "required_evidence_types": list(REQUIRED_EVIDENCE_TYPES),
    }


def _authorization_projection(phase_name: str, plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase_name": phase_name,
        "authorization_context": _authorization_context(plan),
    }


def _evidence_phase(evidence_type: str) -> str:
    if evidence_type in SESSION_EVIDENCE_TYPES:
        return "pre_action_session"
    for phase_name, authorization_type in PHASE_AUTHORIZATION_EVIDENCE.items():
        if evidence_type == authorization_type:
            return phase_name
    for phase_name, evidence_types in PHASE_EVIDENCE_TYPES.items():
        if evidence_type in evidence_types:
            return phase_name
    fail(f"internal phase assignment missing for {evidence_type}")


def _expected_evidence_facts(
    evidence_type: str, plan: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    instruments = receipt["instruments"]
    phase_receipts = receipt["phase_receipts"]
    mapping_facts = receipt["signal_mapping"]
    measured = receipt["measured_levels"]
    procedure = receipt["procedure_observations"]
    for phase_name, authorization_type in PHASE_AUTHORIZATION_EVIDENCE.items():
        if evidence_type == authorization_type:
            return _authorization_projection(phase_name, plan)
    if evidence_type == "clock_source_record":
        return {
            key: plan["preflight"][key]
            for key in (
                "clock_source_kind",
                "clock_source_fingerprint_sha256",
                "clock_independently_trusted",
                "maximum_clock_uncertainty_ms",
            )
        }
    if evidence_type == "operator_key_custody_record":
        return {"role": plan["roles"]["operator"]}
    if evidence_type == "electrical_reviewer_key_custody_record":
        return {"role": plan["roles"]["electrical_reviewer"]}
    if evidence_type == "unit_identity_record":
        return {"target": receipt["target"]}
    if evidence_type == "board_revision_record":
        return {
            "model": receipt["target"]["model"],
            "unit_fingerprint_sha256": receipt["target"]["unit_fingerprint_sha256"],
            "board_revision": receipt["target"]["board_revision"],
            "nano3s_substitution_forbidden": receipt["target"][
                "nano3s_substitution_forbidden"
            ],
        }
    instrument_records = {
        "scope_identity_record": "oscilloscope",
        "scope_calibration_record": "oscilloscope",
        "probe_identity_record": "scope_probe",
        "probe_calibration_record": "scope_probe",
        "analyzer_identity_record": "logic_analyzer",
        "analyzer_calibration_record": "logic_analyzer",
        "deenergization_meter_identity_record": "deenergization_meter",
        "deenergization_meter_calibration_record": "deenergization_meter",
    }
    if evidence_type in instrument_records:
        instrument_name = instrument_records[evidence_type]
        return {
            "instrument_role": instrument_name,
            "instrument": instruments[instrument_name],
        }
    if evidence_type == "power_disconnect_record":
        zero = phase_receipts[
            "deenergized_enclosure_continuity_scope_attach"
        ]["zero_energy"]
        return {
            key: zero[key]
            for key in (
                "power_disconnect_asset_id",
                "power_disconnect_evidence_type",
                "power_disconnected_at_utc",
            )
        }
    continuity_records = {
        "host_to_controller_continuity_record": "host_to_controller",
        "controller_to_host_continuity_record": "controller_to_host",
        "signal_ground_continuity_record": "signal_ground",
    }
    if evidence_type in continuity_records:
        signal_name = continuity_records[evidence_type]
        return {"signal_name": signal_name, "mapping": mapping_facts[signal_name]}
    zero_records = {
        "zero_energy_before_scope_attach_record": "deenergized_enclosure_continuity_scope_attach",
        "zero_energy_before_scope_detach_record": "deenergized_scope_detach",
        "zero_energy_before_analyzer_attach_record": "deenergized_analyzer_attach",
        "zero_energy_before_analyzer_detach_record": "deenergized_analyzer_detach",
    }
    if evidence_type in zero_records:
        return {"zero_energy": phase_receipts[zero_records[evidence_type]]["zero_energy"]}
    if evidence_type == "usb_earth_coupling_record":
        return {
            "isolation_strategy": measured["isolation_strategy"],
            "usb_earth_relationship": measured["usb_earth_relationship"],
            "scope_protective_earth_class": instruments["oscilloscope"][
                "protective_earth_class"
            ],
            "analyzer_shared_usb_power_to_target": instruments["logic_analyzer"][
                "shared_usb_power_to_target"
            ],
        }
    if evidence_type == "ground_potential_record":
        return {
            key: measured[key]
            for key in ("ground_potential_v", "ground_potential_uncertainty_v")
        }
    if evidence_type == "voltage_measurement_record":
        return {
            key: measured[key]
            for key in (
                "host_to_controller",
                "controller_to_host",
                "analyzer_threshold_v",
                "measurement_uncertainty_v",
                "threshold_margin_v",
            )
        }
    if evidence_type == "scope_detach_record":
        return {"scope_detach_order": procedure["scope_detach_order"]}
    if evidence_type == "analyzer_channel_mapping_record":
        return {
            "signal_mapping": mapping_facts,
            "analyzer": instruments["logic_analyzer"],
            "receive_only_confirmed": procedure["analyzer_receive_only_confirmed"],
        }
    if evidence_type == "analyzer_detach_record":
        return {"analyzer_detach_order": procedure["analyzer_detach_order"]}
    if evidence_type == "esd_control_record":
        return {"esd_controls_observed": procedure["esd_controls_observed"]}
    if evidence_type == "electrical_compatibility_review_record":
        return {
            "post_evidence_review": receipt["post_evidence_review"],
            "measured_levels": measured,
            "instrument_ratings_and_calibration": instruments,
        }
    fail(f"internal structured facts schema missing for {evidence_type}")


def _validate_json_evidence_record(
    raw: bytes,
    entry: dict[str, Any],
    plan: dict[str, Any],
    receipt: dict[str, Any],
    label: str,
) -> None:
    try:
        record = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} JSON evidence is invalid")
    if not isinstance(record, dict) or canonical_json(record) != raw:
        fail(f"{label} JSON evidence must be canonical")
    exact_keys(
        record,
        {
            "schema",
            "evidence_type",
            "evidence_id",
            "captured_at_utc",
            "unit_fingerprint_sha256",
            "session_nonce_sha256",
            "phase_name",
            "phase_authorization_nonce_sha256",
            "facts",
        },
        label,
    )
    if (
        record.get("schema") != EVIDENCE_RECORD_SCHEMA
        or record.get("evidence_type") != entry["evidence_type"]
        or record.get("evidence_id") != entry["evidence_id"]
        or record.get("captured_at_utc") != entry["captured_at_utc"]
        or record.get("unit_fingerprint_sha256")
        != plan["target"]["unit_fingerprint_sha256"]
        or record.get("session_nonce_sha256")
        != plan["preflight"]["session_nonce_sha256"]
    ):
        fail(f"{label} structured identity/time binding mismatch")
    expected_phase = _evidence_phase(entry["evidence_type"])
    expected_nonce = (
        None
        if expected_phase == "pre_action_session"
        else _plan_phases(plan)[expected_phase]["authorization_nonce_sha256"]
    )
    if (
        record.get("phase_name") != expected_phase
        or record.get("phase_authorization_nonce_sha256") != expected_nonce
    ):
        fail(f"{label} phase/authorization nonce binding mismatch")
    if record.get("facts") != _expected_evidence_facts(
        entry["evidence_type"], plan, receipt
    ):
        fail(f"{label} time-local facts differ from the signed receipt")


def _require_existing_nonaliased_chain(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    cursor = absolute
    while True:
        if not cursor.exists() or _is_alias(cursor):
            fail(f"{label} ancestor chain is missing or aliased")
        if cursor == absolute and not cursor.is_dir():
            fail(f"{label} must be a directory")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return absolute


def _identity(path: Path) -> tuple[int, int, int, int, int]:
    facts = path.lstat()
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_mode,
        facts.st_size,
        facts.st_mtime_ns,
    )


def _directory_snapshot(path: Path, expected: set[str], label: str) -> dict[str, Any]:
    root = _require_existing_nonaliased_chain(path, label)
    entries = list(root.iterdir())
    if {entry.name for entry in entries} != expected:
        fail(f"{label} membership mismatch")
    if any(_is_alias(entry) for entry in entries):
        fail(f"{label} members must not be aliases")
    return {
        "root": root,
        "root_identity": _identity(root),
        "members": {entry.name: _identity(entry) for entry in entries},
    }


def _revalidate_directory_snapshot(snapshot: dict[str, Any], label: str) -> None:
    root = snapshot["root"]
    expected = set(snapshot["members"])
    observed = _directory_snapshot(root, expected, label)
    if (
        observed["root_identity"] != snapshot["root_identity"]
        or observed["members"] != snapshot["members"]
    ):
        fail(f"{label} identity changed during validation")


def _load_bundle(bundle_root: Path) -> dict[str, Any]:
    expected = {
        PLAN_NAME,
        PLAN_OPERATOR_SIGNATURE_NAME,
        PLAN_REVIEWER_SIGNATURE_NAME,
        RECEIPT_NAME,
        RECEIPT_OPERATOR_SIGNATURE_NAME,
        RECEIPT_REVIEWER_SIGNATURE_NAME,
        OPERATOR_PUBLIC_KEY_NAME,
        REVIEWER_PUBLIC_KEY_NAME,
        EVIDENCE_DIRECTORY_NAME,
    }
    bundle_snapshot = _directory_snapshot(bundle_root, expected, "bundle")
    bundle_root = bundle_snapshot["root"]
    evidence_root = bundle_root / EVIDENCE_DIRECTORY_NAME
    if not evidence_root.is_dir():
        fail("evidence member must be a directory")
    plan, plan_raw = load_json(bundle_root / PLAN_NAME, "preflight plan")
    receipt, receipt_raw = load_json(bundle_root / RECEIPT_NAME, "preflight receipt")
    raw = {
        "plan_operator_signature": read_regular(bundle_root / PLAN_OPERATOR_SIGNATURE_NAME, 64, "plan operator signature"),
        "plan_reviewer_signature": read_regular(bundle_root / PLAN_REVIEWER_SIGNATURE_NAME, 64, "plan reviewer signature"),
        "receipt_operator_signature": read_regular(bundle_root / RECEIPT_OPERATOR_SIGNATURE_NAME, 64, "receipt operator signature"),
        "receipt_reviewer_signature": read_regular(bundle_root / RECEIPT_REVIEWER_SIGNATURE_NAME, 64, "receipt reviewer signature"),
        "operator_public_key": read_regular(bundle_root / OPERATOR_PUBLIC_KEY_NAME, 32, "operator public key"),
        "reviewer_public_key": read_regular(bundle_root / REVIEWER_PUBLIC_KEY_NAME, 32, "reviewer public key"),
    }
    return {
        "plan": plan,
        "plan_raw": plan_raw,
        "receipt": receipt,
        "receipt_raw": receipt_raw,
        "raw": raw,
        "evidence_root": evidence_root,
        "bundle_snapshot": bundle_snapshot,
    }


def validate_bundle(bundle_root: Path, *, verification_time_utc: datetime | None = None) -> dict[str, Any]:
    bundle = _load_bundle(bundle_root)
    plan = validate_plan(bundle["plan"], bundle["plan_raw"])
    raw = bundle["raw"]
    if raw["operator_public_key"] == raw["reviewer_public_key"]:
        fail("operator and electrical reviewer public keys must differ")
    operator_key_sha = sha256_bytes(raw["operator_public_key"])
    reviewer_key_sha = sha256_bytes(raw["reviewer_public_key"])
    if operator_key_sha != plan["roles"]["operator"]["public_key_sha256"] or reviewer_key_sha != plan["roles"]["electrical_reviewer"]["public_key_sha256"]:
        fail("public key identity differs from signed plan")
    _verify_signature(raw["operator_public_key"], raw["plan_operator_signature"], PLAN_OPERATOR_DOMAIN, bundle["plan_raw"], "plan operator")
    _verify_signature(raw["reviewer_public_key"], raw["plan_reviewer_signature"], PLAN_REVIEWER_DOMAIN, bundle["plan_raw"], "plan electrical reviewer")
    receipt = validate_receipt(
        bundle["receipt"],
        bundle["receipt_raw"],
        plan,
        bundle["plan_raw"],
        {"operator": raw["plan_operator_signature"], "reviewer": raw["plan_reviewer_signature"]},
    )
    _verify_signature(raw["operator_public_key"], raw["receipt_operator_signature"], RECEIPT_OPERATOR_DOMAIN, bundle["receipt_raw"], "receipt operator")
    _verify_signature(raw["reviewer_public_key"], raw["receipt_reviewer_signature"], RECEIPT_REVIEWER_DOMAIN, bundle["receipt_raw"], "receipt electrical reviewer")
    now = verification_time_utc or datetime.now(timezone.utc)
    if now.tzinfo != timezone.utc or now < plan["valid_from"] or now > plan["valid_until"]:
        fail("verification time is outside signed plan validity")
    maximum_uncertainty_s = (
        float(plan["preflight"]["maximum_clock_uncertainty_ms"]) / 1000.0
    )
    if receipt["completed"].timestamp() + maximum_uncertainty_s > now.timestamp():
        fail("receipt completion is later than the verifier clock")
    expected_filenames = {item["filename"] for item in receipt["evidence"]}
    evidence_snapshot = _directory_snapshot(
        bundle["evidence_root"], expected_filenames, "evidence directory"
    )
    evidence_entries = [
        evidence_snapshot["root"] / name for name in expected_filenames
    ]
    if any(not item.is_file() for item in evidence_entries):
        fail("evidence members must be regular files")
    total = 0
    public_evidence = []
    by_filename = {item.name: item for item in evidence_entries}
    for fact in receipt["evidence"]:
        evidence_raw = read_regular(by_filename[fact["filename"]], MAX_EVIDENCE_FILE_BYTES, f"evidence {fact['evidence_type']}")
        total += len(evidence_raw)
        if total > MAX_EVIDENCE_TOTAL_BYTES:
            fail("evidence total exceeds bound")
        if len(evidence_raw) != fact["size_bytes"] or sha256_bytes(evidence_raw) != fact["sha256"]:
            fail(f"evidence {fact['evidence_type']} byte identity mismatch")
        if fact["media_type"] == "image/png":
            _validate_png(evidence_raw, f"evidence {fact['evidence_type']}")
        else:
            _validate_json_evidence_record(
                evidence_raw,
                fact,
                plan,
                bundle["receipt"],
                f"evidence {fact['evidence_type']}",
            )
        public_evidence.append(
            {
                key: fact[key]
                for key in ("evidence_type", "sha256", "size_bytes", "media_type")
            }
        )
    _revalidate_directory_snapshot(evidence_snapshot, "evidence directory")
    _revalidate_directory_snapshot(bundle["bundle_snapshot"], "bundle")
    return {
        "schema": OUTPUT_SCHEMA,
        "proof_scope": "file-only-signed-preflight-plan-and-post-evidence-receipt",
        "session_nonce_sha256": plan["preflight"]["session_nonce_sha256"],
        "model": TARGET_MODEL,
        "unit_fingerprint_sha256": plan["target"]["unit_fingerprint_sha256"],
        "board_revision": plan["target"]["board_revision"],
        "plan_sha256": plan["sha256"],
        "receipt_sha256": receipt["sha256"],
        "plan_operator_signature_sha256": sha256_bytes(raw["plan_operator_signature"]),
        "plan_reviewer_signature_sha256": sha256_bytes(raw["plan_reviewer_signature"]),
        "receipt_operator_signature_sha256": sha256_bytes(raw["receipt_operator_signature"]),
        "receipt_reviewer_signature_sha256": sha256_bytes(raw["receipt_reviewer_signature"]),
        "operator_public_key_sha256": operator_key_sha,
        "reviewer_public_key_sha256": reviewer_key_sha,
        "signature_domains_separate": True,
        "evidence": public_evidence,
        "evidence_count": len(public_evidence),
        "evidence_total_bytes": total,
        "time_local_structured_record_facts_validated": True,
        "photo_structure_and_minimum_dimensions_validated": True,
        "photo_subject_identity_machine_proven": False,
        "phase_order": list(PHASE_ORDER),
        "capture_energization_authorized": False,
        "capture_energization_performed": False,
        "preflight_file_contract_valid": True,
        "device_contact_performed_by_validator": False,
        "physical_provenance_proven": False,
        "operator_key_authority_proven": False,
        "reviewer_key_authority_proven": False,
        "physical_actions_authorized_by_validator": False,
        "authorization_c_granted": False,
        "uart_protocol_qualified": False,
        "signer_asserted_utc_only": True,
        "trusted_time_provenance": False,
        "global_replay_resistance": False,
        "same_host_replay_requires_intact_private_ledger": True,
        "parent_directory_alias_checks": True,
        "input_directory_identity_revalidated": True,
        "windows_acl_privacy_proven": False,
        "directory_fsync_portability_guaranteed": False,
        "paths_in_public_receipt": False,
    }


def _ensure_nonaliased_directory(path: Path, *, private: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    missing: list[Path] = []
    cursor = absolute
    while not cursor.exists():
        if _is_alias(cursor):
            fail("directory chain contains an alias")
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            fail("directory chain has no existing anchor")
        cursor = parent
    if _is_alias(cursor) or not cursor.is_dir():
        fail("directory chain anchor must be a non-aliased directory")
    for item in reversed(missing):
        try:
            item.mkdir(mode=0o700 if private else 0o755)
        except OSError as exc:
            fail(f"directory creation failed: {exc.__class__.__name__}")
        if _is_alias(item) or not item.is_dir():
            fail("created directory became an alias")
    cursor = absolute
    while True:
        if _is_alias(cursor) or not cursor.is_dir():
            fail("directory chain contains an alias or non-directory")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if private and os.name != "nt":
        absolute.chmod(0o700)
        if stat.S_IMODE(absolute.stat(follow_symlinks=False).st_mode) & 0o077:
            fail("private directory permissions are too broad")
    return absolute


def _fsync_directory_if_supported(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    flags = os.O_RDONLY | os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"directory open for durability failed: {exc.__class__.__name__}")
    try:
        os.fsync(descriptor)
    except OSError as exc:
        fail(f"directory durability sync failed: {exc.__class__.__name__}")
    finally:
        os.close(descriptor)


def _private_ledger(root: Path) -> None:
    _ensure_nonaliased_directory(root, private=True)


def write_once(path: Path, raw: bytes, label: str) -> None:
    parent = _ensure_nonaliased_directory(path.parent, private=False)
    target = parent / path.name
    if target.exists() or _is_alias(target):
        fail(f"{label} already exists; refusing overwrite")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        fail(f"cannot create {label}: {exc.__class__.__name__}")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        fail(f"cannot persist {label}: {exc.__class__.__name__}")
    if _is_alias(target) or not target.is_file():
        fail(f"{label} is not a non-aliased regular file after creation")
    _fsync_directory_if_supported(parent)


def require_create_new_target(path: Path, label: str) -> None:
    parent = _ensure_nonaliased_directory(path.parent, private=False)
    target = parent / path.name
    if target.exists() or _is_alias(target):
        fail(f"{label} already exists; refusing overwrite")


def consume_once(receipt: dict[str, Any], ledger_root: Path) -> str:
    _private_ledger(ledger_root)
    nonce = digest(receipt["session_nonce_sha256"], "session_nonce_sha256")
    name = sha256_bytes(bytes.fromhex(nonce)) + ".json"
    record = canonical_json(
        {
            "schema": "dcent.nano3.uart-physical-preflight-consumption.v1",
            "session_nonce_sha256": nonce,
            "plan_sha256": receipt["plan_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "replay_scope": "same-host-ledger-only",
        }
    )
    write_once(ledger_root / name, record, "preflight nonce receipt")
    return sha256_bytes(record)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a signed Nano 3 non-S UART physical-preflight bundle "
            "using local files only; never contact hardware or grant C."
        )
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        require_create_new_target(args.output, "public preflight validation receipt")
        receipt = validate_bundle(args.bundle)
        consumption_sha = consume_once(receipt, args.ledger_root)
        receipt["same_host_nonce_consumed"] = True
        receipt["consumption_receipt_sha256"] = consumption_sha
        receipt["same_host_replay_only"] = True
        receipt["cross_host_or_privileged_deletion_replay_residual"] = True
        write_once(args.output, canonical_json(receipt), "public preflight validation receipt")
    except PreflightError as exc:
        print(
            "preflight_file_contract_valid=false authorization_c_granted=false "
            f"device_contact=none error={exc}",
            file=sys.stderr,
        )
        return 2
    print(
        "preflight_file_contract_valid=true authorization_c_granted=false "
        "capture_authorized=false device_contact=none"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
