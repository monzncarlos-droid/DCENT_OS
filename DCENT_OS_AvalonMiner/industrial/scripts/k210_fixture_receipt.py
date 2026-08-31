#!/usr/bin/env python3
"""Create and verify dual-reviewed A1246 fixture-qualification bundles.

This tool is host-only and has no miner, network, serial, USB, GPIO, JTAG,
programmer, power, flash, or process-control transport. It snapshots evidence
from separately authorized work that already occurred. A valid receipt grants
no authority for future contact, probing, power, writes, mining, or release.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_discovery_module():
    path = Path(__file__).with_name("k210_discovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_discovery_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 evidence primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


discovery = _load_discovery_module()

SCHEMA_VERSION = 1
SCOPE = discovery.SCOPE
DESCRIPTOR_KIND = "dcent_k210_fixture_qualification_descriptor"
RECEIPT_KIND = "dcent_k210_fixture_qualification_receipt"
DISPOSITION = "past_fixture_evidence_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
REVIEWER_SIGNATURE_NAME = "reviewer.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_fixture_operator"
REVIEWER_ROLE = "k210_fixture_ee_reviewer"
OPERATOR_NAMESPACE = "dcent-k210-fixture-operator-v1"
REVIEWER_NAMESPACE = "dcent-k210-fixture-reviewer-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM
MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_FLASH_BYTES = 1024 * 1024 * 1024

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

FIXTURE_ACTIONS = {
    "closed_chassis_passive_logic_capture",
    "controller_only_power_characterization",
    "deenergized_continuity_measurement",
    "external_programmer_read_only_backup",
    "fixture_visual_inspection",
}
ACTIONS_PERFORMED = {
    "continuity_measured": True,
    "controller_only_powered": True,
    "firmware_written": False,
    "flash_read": True,
    "flash_written": False,
    "hash_power_energized_during_open_chassis": False,
    "power_state_changed": True,
    "stock_powered_passive_capture": True,
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_future_probe_or_capture": False,
    "authorizes_future_read_or_write": False,
    "authorizes_install": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}
DISPOSITIONS = {
    "controller_only_power_ready",
    "cooling_custody_ready",
    "independent_cutoff_ready",
    "jtag_probe_ready",
    "passive_capture_fixture_ready",
    "recovery_fixture_ready",
    "rom_isp_probe_ready",
}
REQUIRED_EVIDENCE_KINDS = (
    "completion_matrix",
    "cooling_cutoff_record",
    "discovery_receipt_copy",
    "electrical_measurement_record",
    "fixture_overview_photo",
    "flash_fixture_record",
    "identity_isolation_record",
    "instrument_record",
    "programmer_isolation_photo",
    "qualification_log",
)
PHOTO_KINDS = {"fixture_overview_photo", "programmer_isolation_photo"}
JSON_KINDS = set(REQUIRED_EVIDENCE_KINDS) - PHOTO_KINDS
METHOD_BY_KIND = {
    "completion_matrix": "offline_record",
    "cooling_cutoff_record": "authorized_fixture_measurement",
    "discovery_receipt_copy": "offline_record",
    "electrical_measurement_record": "authorized_fixture_measurement",
    "fixture_overview_photo": "visual_inspection",
    "flash_fixture_record": "authorized_fixture_measurement",
    "identity_isolation_record": "authorized_fixture_measurement",
    "instrument_record": "offline_record",
    "programmer_isolation_photo": "visual_inspection",
    "qualification_log": "offline_record",
}
REQUIRED_SIGNAL_CLASSES = {"flash", "hashboard", "jtag", "rom_isp", "uart"}
REQUIRED_INSTRUMENT_ROLES = {
    "bench_supply",
    "external_programmer",
    "logic_analyzer",
    "multimeter",
}


class FixtureError(RuntimeError):
    """A fixture descriptor, bundle, signature, or evidence invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], context: str
) -> None:
    actual = set(value)
    wanted = set(expected)
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise FixtureError(f"{context} keys invalid: {'; '.join(details)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    try:
        return discovery._observed_text(value, context, maximum)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise FixtureError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not PRINCIPAL_RE.fullmatch(text):
        raise FixtureError(f"{context} is not a canonical signer principal")
    return text


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise FixtureError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise FixtureError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise FixtureError(f"{context} must be lowercase SHA-256")
    return value


def _integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise FixtureError(f"{context} must be an integer in {minimum}..{maximum}")
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise FixtureError(f"{context} must be a portable POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise FixtureError(f"{context} must be a canonical relative path")
    if any(part in ("", ".", "..") for part in path.parts):
        raise FixtureError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        return discovery._load_manifest(path)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        target = discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc
    if target["kind"] != "physical_model":
        raise FixtureError("fixture qualification requires a physical-model target")
    return target


def _validate_evidence(value: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(REQUIRED_EVIDENCE_KINDS):
        raise FixtureError(
            f"evidence must contain exactly {len(REQUIRED_EVIDENCE_KINDS)} records"
        )
    ids: set[str] = set()
    kinds: set[str] = set()
    paths: set[str] = set()
    normalized = []
    for index, item in enumerate(value):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise FixtureError(f"{context} must be an object")
        keys = (
            "acquired_at_utc",
            "bytes",
            "id",
            "kind",
            "media_type",
            "method",
            "path",
            "redaction",
            "sha256",
        )
        if not hashed:
            keys = tuple(key for key in keys if key not in {"bytes", "sha256"})
        _require_exact_keys(item, keys, context)
        evidence_id = _identifier(item["id"], f"{context}.id")
        kind = item["kind"]
        if kind not in REQUIRED_EVIDENCE_KINDS:
            raise FixtureError(f"{context}.kind is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if evidence_id in ids or kind in kinds or path in paths:
            raise FixtureError("evidence IDs, kinds, and paths must each be unique")
        ids.add(evidence_id)
        kinds.add(kind)
        paths.add(path)
        expected_media = "image/png" if kind in PHOTO_KINDS else "application/json"
        if item["media_type"] != expected_media:
            raise FixtureError(f"{context}.media_type must be {expected_media}")
        if item["method"] != METHOD_BY_KIND[kind]:
            raise FixtureError(f"{context}.method does not match its evidence kind")
        if item["redaction"] not in discovery.REDACTION_STATES:
            raise FixtureError(f"{context}.redaction is unsupported")
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _integer(
                item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES
            )
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    if kinds != set(REQUIRED_EVIDENCE_KINDS):
        raise FixtureError("fixture evidence kind set is not exact")
    return normalized


CORE_KEYS = (
    "actions_performed",
    "authorization",
    "completed_at_utc",
    "discovery_receipt_id",
    "evidence",
    "fixture_id",
    "kind",
    "operator_id",
    "reviewer_id",
    "schema_version",
    "scope",
    "started_at_utc",
    "target_id",
    "unit_fingerprint_sha256",
    "unit_label",
)
RECEIPT_ONLY_KEYS = (
    "authority_ceiling",
    "descriptor_sha256",
    "disposition",
    "fixture_evidence_set_sha256",
    "fixture_identity",
    "receipt_id",
    "signing",
)


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> dict[str, dict[str, Any]]:
    _require_exact_keys(
        value,
        CORE_KEYS + RECEIPT_ONLY_KEYS if receipt else CORE_KEYS,
        "fixture record",
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise FixtureError("fixture schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind:
        raise FixtureError("fixture record kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    _identifier(value["fixture_id"], "fixture_id")
    _sha(value["discovery_receipt_id"], "discovery_receipt_id")
    _sha(value["unit_fingerprint_sha256"], "unit_fingerprint_sha256")
    operator = _principal(value["operator_id"], "operator_id")
    reviewer = _principal(value["reviewer_id"], "reviewer_id")
    if operator == reviewer:
        raise FixtureError("fixture operator and EE reviewer must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise FixtureError("fixture start must precede completion")
    if value["actions_performed"] != ACTIONS_PERFORMED:
        raise FixtureError("fixture actions_performed contract drifted")
    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise FixtureError("authorization must be an object")
    _require_exact_keys(
        authorization,
        (
            "authorized_actions",
            "operator_reference",
            "valid_from_utc",
            "valid_until_utc",
        ),
        "authorization",
    )
    _text(authorization["operator_reference"], "authorization.operator_reference")
    valid_from = _utc(authorization["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(
        authorization["valid_until_utc"], "authorization.valid_until_utc"
    )
    if valid_from >= valid_until or not valid_from <= started < completed <= valid_until:
        raise FixtureError("fixture work is outside the authorization interval")
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or len(actions) != len(FIXTURE_ACTIONS)
        or set(actions) != FIXTURE_ACTIONS
    ):
        raise FixtureError("authorization does not contain the exact fixture action set")
    evidence = _validate_evidence(value["evidence"], hashed=receipt)
    for index, item in enumerate(evidence):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise FixtureError(f"evidence[{index}] is outside fixture chronology")
    return {item["kind"]: item for item in evidence}


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc


def _hash_source(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise FixtureError(str(exc)) from exc


def _evidence_path(
    evidence: Mapping[str, Mapping[str, Any]], root: Path, kind: str
) -> Path:
    item = evidence[kind]
    return _source(root, _safe_path(item["path"], f"{kind}.path"))


def _semantic_json(
    evidence: Mapping[str, Mapping[str, Any]], root: Path, kind: str
) -> dict[str, Any]:
    return _load_json(_evidence_path(evidence, root, kind), kind, canonical=True)


def _validate_log(
    document: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        document,
        (
            "anomalies",
            "authorization_reference",
            "events",
            "session",
            "stopped_reason",
        ),
        "qualification_log",
    )
    _text(document["session"], "qualification_log.session", 200)
    if document["authorization_reference"] != receipt["authorization"][
        "operator_reference"
    ]:
        raise FixtureError("qualification log authorization reference drifted")
    if document["stopped_reason"] not in (None, ""):
        raise FixtureError("fixture qualification records a stopped session")
    if document["anomalies"] != []:
        raise FixtureError("fixture qualification contains unresolved anomalies")
    events = document["events"]
    if not isinstance(events, list) or len(events) != len(FIXTURE_ACTIONS):
        raise FixtureError("qualification log must contain one event per action")
    started = _utc(receipt["started_at_utc"], "started_at_utc")
    completed = _utc(receipt["completed_at_utc"], "completed_at_utc")
    observed_actions: set[str] = set()
    for index, event in enumerate(events):
        context = f"qualification_log.events[{index}]"
        if not isinstance(event, dict):
            raise FixtureError(f"{context} must be an object")
        _require_exact_keys(event, ("action", "detail", "time_utc"), context)
        action = event["action"]
        if action not in FIXTURE_ACTIONS or action in observed_actions:
            raise FixtureError(f"{context}.action is unknown or duplicated")
        observed_actions.add(action)
        timestamp = _utc(event["time_utc"], f"{context}.time_utc")
        if not started <= timestamp <= completed:
            raise FixtureError(f"{context} is outside fixture chronology")
        _text(event["detail"], f"{context}.detail", 512)
    if observed_actions != FIXTURE_ACTIONS:
        raise FixtureError("qualification log action set is incomplete")


def _validate_identity(
    document: Mapping[str, Any], discovery_receipt: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        document,
        (
            "back_power_paths",
            "common_ground_point",
            "controller_board_model",
            "controller_board_revision",
            "hash_power_physically_disconnected",
            "hashboard_revisions",
            "rail_absence_feedback_method",
            "rail_absent_verified",
            "stock_dna",
            "stock_firmware_version",
            "stock_hwtype",
            "stock_swtype",
        ),
        "identity_isolation_record",
    )
    for field in (
        "common_ground_point",
        "controller_board_model",
        "controller_board_revision",
        "rail_absence_feedback_method",
    ):
        _text(document[field], f"identity_isolation_record.{field}")
    if (
        document["hash_power_physically_disconnected"] is not True
        or document["rail_absent_verified"] is not True
    ):
        raise FixtureError("hash-power isolation and independent feedback must pass")
    identity = discovery_receipt["identity"]
    joins = {
        "controller_board_model": "controller_board_model",
        "controller_board_revision": "controller_board_revision",
        "stock_dna": "stock_dna",
        "stock_firmware_version": "stock_firmware_version",
        "stock_hwtype": "stock_hwtype",
        "stock_swtype": "stock_swtype",
    }
    for field, discovery_field in joins.items():
        if document[field] != identity[discovery_field]:
            raise FixtureError(f"identity isolation {field} contradicts discovery")
    revisions = document["hashboard_revisions"]
    if (
        not isinstance(revisions, list)
        or len(revisions) != identity["hashboard_count"]
        or len(revisions) != len(set(revisions))
    ):
        raise FixtureError("hashboard revisions do not match discovered topology")
    for index, revision in enumerate(revisions):
        _text(revision, f"hashboard_revisions[{index}]")
    paths = document["back_power_paths"]
    if not isinstance(paths, list) or not paths:
        raise FixtureError("back_power_paths must be a non-empty array")
    names: set[str] = set()
    for index, path in enumerate(paths):
        context = f"back_power_paths[{index}]"
        if not isinstance(path, dict):
            raise FixtureError(f"{context} must be an object")
        _require_exact_keys(path, ("interface", "max_observed_mv", "tested"), context)
        name = _identifier(path["interface"], f"{context}.interface")
        if name in names or path["tested"] is not True:
            raise FixtureError("back-power paths must be unique and tested")
        names.add(name)
        _integer(path["max_observed_mv"], f"{context}.max_observed_mv", 0, 500)


def _validate_electrical(document: Mapping[str, Any]) -> None:
    _require_exact_keys(
        document,
        (
            "controller_input_connector",
            "current_limit_ma",
            "inrush_ma",
            "nominal_mv",
            "polarity",
            "signals",
            "signals_complete",
            "steady_state_ma",
        ),
        "electrical_measurement_record",
    )
    _text(document["controller_input_connector"], "controller_input_connector")
    if document["polarity"] not in {"negative_to_ground", "positive_to_ground"}:
        raise FixtureError("controller input polarity is unsupported")
    nominal = _integer(document["nominal_mv"], "nominal_mv", 500, 60_000)
    _integer(document["current_limit_ma"], "current_limit_ma", 1, 20_000)
    _integer(document["inrush_ma"], "inrush_ma", 0, 20_000)
    _integer(document["steady_state_ma"], "steady_state_ma", 1, 20_000)
    if document["signals_complete"] is not True:
        raise FixtureError("signal-level census is incomplete")
    signals = document["signals"]
    if not isinstance(signals, list) or not 5 <= len(signals) <= 64:
        raise FixtureError("signals must contain 5..64 measured entries")
    names: set[str] = set()
    classes: set[str] = set()
    for index, signal in enumerate(signals):
        context = f"signals[{index}]"
        if not isinstance(signal, dict):
            raise FixtureError(f"{context} must be an object")
        _require_exact_keys(
            signal,
            (
                "direction",
                "idle_mv",
                "interface_class",
                "max_probe_input_mv",
                "name",
                "probe_attenuation_x",
                "reference_ground",
            ),
            context,
        )
        name = _identifier(signal["name"], f"{context}.name")
        if name in names:
            raise FixtureError("signal names must be unique")
        names.add(name)
        interface_class = signal["interface_class"]
        if interface_class not in REQUIRED_SIGNAL_CLASSES:
            raise FixtureError(f"{context}.interface_class is unsupported")
        classes.add(interface_class)
        if signal["direction"] not in {
            "asic_to_controller",
            "bidirectional",
            "controller_to_asic",
            "input",
            "output",
        }:
            raise FixtureError(f"{context}.direction is unsupported")
        idle = _integer(signal["idle_mv"], f"{context}.idle_mv", 0, 6_000)
        maximum = _integer(
            signal["max_probe_input_mv"], f"{context}.max_probe_input_mv", 1, 12_000
        )
        if maximum < idle or maximum < nominal // 20:
            raise FixtureError(f"{context} probe input rating is inconsistent")
        _integer(
            signal["probe_attenuation_x"], f"{context}.probe_attenuation_x", 1, 100
        )
        _text(signal["reference_ground"], f"{context}.reference_ground")
    if classes != REQUIRED_SIGNAL_CLASSES:
        raise FixtureError("signal census does not cover every required interface class")


def _validate_flash(document: Mapping[str, Any]) -> None:
    _require_exact_keys(
        document,
        (
            "back_power_max_mv",
            "capacity_bytes",
            "chip_select_isolated",
            "device_id",
            "in_circuit_contention_excluded",
            "k210_held_in_reset",
            "manufacturer",
            "model",
            "package",
            "primary_datasheet_sha256",
            "programmer",
            "read_a_sha256",
            "read_b_sha256",
            "read_bytes",
            "supply_mv",
            "technology",
        ),
        "flash_fixture_record",
    )
    for field in ("device_id", "manufacturer", "model", "package"):
        _text(document[field], f"flash_fixture_record.{field}")
    if document["technology"] not in {"emmc", "spi_nand", "spi_nor"}:
        raise FixtureError("flash technology is unsupported")
    capacity = _integer(document["capacity_bytes"], "capacity_bytes", 1, MAX_FLASH_BYTES)
    supply = _integer(document["supply_mv"], "supply_mv", 1_000, 5_500)
    _sha(document["primary_datasheet_sha256"], "primary_datasheet_sha256")
    if (
        document["chip_select_isolated"] is not True
        or document["in_circuit_contention_excluded"] is not True
        or document["k210_held_in_reset"] is not True
    ):
        raise FixtureError("flash isolation/contention controls are incomplete")
    _integer(document["back_power_max_mv"], "back_power_max_mv", 0, 500)
    if document["read_bytes"] != capacity:
        raise FixtureError("programmer reads are not full-device reads")
    read_a = _sha(document["read_a_sha256"], "read_a_sha256")
    read_b = _sha(document["read_b_sha256"], "read_b_sha256")
    if read_a != read_b:
        raise FixtureError("fixture programmer reads are not byte-identical")
    programmer = document["programmer"]
    if not isinstance(programmer, dict):
        raise FixtureError("programmer must be an object")
    _require_exact_keys(
        programmer,
        (
            "adapter",
            "current_limit_ma",
            "firmware_version",
            "model",
            "output_mv",
            "serial",
        ),
        "programmer",
    )
    for field in ("adapter", "firmware_version", "model", "serial"):
        _text(programmer[field], f"programmer.{field}")
    output = _integer(programmer["output_mv"], "programmer.output_mv", 1_000, 5_500)
    _integer(
        programmer["current_limit_ma"], "programmer.current_limit_ma", 1, 5_000
    )
    if abs(output - supply) > 100:
        raise FixtureError("programmer output does not match measured flash supply")


def _validate_cooling(
    document: Mapping[str, Any], discovery_receipt: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        document,
        (
            "airflow_direction",
            "cooling_class",
            "cooling_controller",
            "cutoff_asserted_during_controller_only",
            "fan_or_pump_count",
            "hash_rail_absent_verified",
            "independent_cutoff_method",
            "rail_feedback_method",
            "stock_baseline_recorded",
            "watchdog_strategy",
        ),
        "cooling_cutoff_record",
    )
    identity = discovery_receipt["identity"]
    for field in ("cooling_class", "cooling_controller", "fan_or_pump_count"):
        if document[field] != identity[field]:
            raise FixtureError(f"cooling record {field} contradicts discovery")
    for field in (
        "airflow_direction",
        "independent_cutoff_method",
        "rail_feedback_method",
        "watchdog_strategy",
    ):
        _text(document[field], f"cooling_cutoff_record.{field}")
    if any(
        document[field] is not True
        for field in (
            "cutoff_asserted_during_controller_only",
            "hash_rail_absent_verified",
            "stock_baseline_recorded",
        )
    ):
        raise FixtureError("cooling/cutoff qualification is incomplete")


def _validate_instruments(
    document: Mapping[str, Any], completed_at: datetime
) -> None:
    _require_exact_keys(
        document,
        (
            "esd_controls_verified",
            "fused_current_limited_feed",
            "instruments",
            "isolated_supply",
            "probe_strain_relief",
        ),
        "instrument_record",
    )
    if any(
        document[field] is not True
        for field in (
            "esd_controls_verified",
            "fused_current_limited_feed",
            "isolated_supply",
            "probe_strain_relief",
        )
    ):
        raise FixtureError("instrument/ESD controls are incomplete")
    instruments = document["instruments"]
    if not isinstance(instruments, list) or not 4 <= len(instruments) <= 16:
        raise FixtureError("instrument record must contain 4..16 entries")
    roles: set[str] = set()
    identities: set[str] = set()
    for index, instrument in enumerate(instruments):
        context = f"instruments[{index}]"
        if not isinstance(instrument, dict):
            raise FixtureError(f"{context} must be an object")
        _require_exact_keys(
            instrument,
            ("calibration_id", "calibration_valid_until_utc", "model", "role", "serial"),
            context,
        )
        role = _identifier(instrument["role"], f"{context}.role")
        roles.add(role)
        identity = "\x00".join(
            (
                _text(instrument["model"], f"{context}.model"),
                _text(instrument["serial"], f"{context}.serial"),
            )
        )
        if identity in identities:
            raise FixtureError("instrument model/serial pairs must be unique")
        identities.add(identity)
        _text(instrument["calibration_id"], f"{context}.calibration_id")
        if (
            _utc(
                instrument["calibration_valid_until_utc"],
                f"{context}.calibration_valid_until_utc",
            )
            <= completed_at
        ):
            raise FixtureError(f"{context} calibration expired before qualification")
    if not REQUIRED_INSTRUMENT_ROLES.issubset(roles):
        raise FixtureError("instrument record lacks a required role")


def _validate_completion(
    document: Mapping[str, Any], started: datetime, completed: datetime
) -> dict[str, bool]:
    _require_exact_keys(
        document,
        ("deviations", "dispositions", "reviewed_at_utc", "unresolved_points"),
        "completion_matrix",
    )
    if document["deviations"] != [] or document["unresolved_points"] != []:
        raise FixtureError("fixture completion has deviations or unresolved points")
    reviewed = _utc(document["reviewed_at_utc"], "completion_matrix.reviewed_at_utc")
    if not started <= reviewed <= completed:
        raise FixtureError("fixture review time is outside chronology")
    dispositions = document["dispositions"]
    if not isinstance(dispositions, dict) or set(dispositions) != DISPOSITIONS:
        raise FixtureError("fixture disposition set is not exact")
    if any(value is not True for value in dispositions.values()):
        raise FixtureError("every fixture disposition must be explicitly true")
    return dict(sorted(dispositions.items()))


def _validate_semantics(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any], root: Path
) -> dict[str, Any]:
    evidence = {item["kind"]: item for item in receipt["evidence"]}
    discovery_path = _evidence_path(evidence, root, "discovery_receipt_copy")
    try:
        discovery_receipt = discovery.load_json(
            discovery_path, "discovery receipt copy", require_canonical=True
        )
        discovery._validate_receipt(discovery_receipt, manifest)
    except discovery.DiscoveryError as exc:
        raise FixtureError(f"discovery receipt copy is invalid: {exc}") from exc
    joins = {
        "receipt_id": "discovery_receipt_id",
        "target_id": "target_id",
        "unit_fingerprint_sha256": "unit_fingerprint_sha256",
        "unit_label": "unit_label",
    }
    for discovery_field, fixture_field in joins.items():
        if discovery_receipt[discovery_field] != receipt[fixture_field]:
            raise FixtureError(
                f"discovery receipt copy {discovery_field} does not match fixture"
            )
    _validate_log(_semantic_json(evidence, root, "qualification_log"), receipt)
    identity_record = _semantic_json(evidence, root, "identity_isolation_record")
    _validate_identity(identity_record, discovery_receipt)
    _validate_electrical(
        _semantic_json(evidence, root, "electrical_measurement_record")
    )
    _validate_flash(_semantic_json(evidence, root, "flash_fixture_record"))
    _validate_cooling(
        _semantic_json(evidence, root, "cooling_cutoff_record"), discovery_receipt
    )
    completed = _utc(receipt["completed_at_utc"], "completed_at_utc")
    _validate_instruments(
        _semantic_json(evidence, root, "instrument_record"), completed
    )
    dispositions = _validate_completion(
        _semantic_json(evidence, root, "completion_matrix"),
        _utc(receipt["started_at_utc"], "started_at_utc"),
        completed,
    )
    for kind in sorted(PHOTO_KINDS):
        path = _evidence_path(evidence, root, kind)
        try:
            raw = discovery._read_regular(path, kind, MAX_EVIDENCE_FILE_BYTES)
            discovery._inspect_photo(raw, kind, "image/png")
        except discovery.DiscoveryError as exc:
            raise FixtureError(f"{kind} is inadmissible: {exc}") from exc
    identity = discovery_receipt["identity"]
    try:
        variants = discovery._target_variant_rows(manifest, receipt["target_id"])
    except discovery.DiscoveryError as exc:
        raise FixtureError(f"cannot resolve fixture variant profile: {exc}") from exc
    matches = [
        row
        for row in variants
        if row["firmware_version"] == identity["stock_firmware_version"]
        and row["hwtype"] == identity["stock_hwtype"]
        and identity["stock_swtype"] in row["sw_list"]
        and row["asic_family"] == identity["asic_family"]
        and row["hashboard_count"] == identity["hashboard_count"]
    ]
    if len(matches) != 1:
        raise FixtureError("fixture discovery identity does not resolve one variant profile")
    summary = {
        "asic_family": identity["asic_family"],
        "controller_board_model": identity_record["controller_board_model"],
        "controller_board_revision": identity_record["controller_board_revision"],
        "dispositions": dispositions,
        "hashboard_revisions": list(identity_record["hashboard_revisions"]),
        "stock_firmware_build": identity["stock_firmware_version"],
        "stock_hwtype": identity["stock_hwtype"],
        "stock_swtype": identity["stock_swtype"],
        "variant_profile_id": matches[0]["profile_id"],
    }
    if "fixture_identity" in receipt and receipt["fixture_identity"] != {
        key: summary[key]
        for key in (
            "asic_family",
            "controller_board_model",
            "controller_board_revision",
            "hashboard_revisions",
            "stock_firmware_build",
            "stock_hwtype",
            "stock_swtype",
            "variant_profile_id",
        )
    }:
        raise FixtureError("signed fixture identity summary contradicts evidence")
    return summary


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    projection = {key: receipt[key] for key in CORE_KEYS}
    projection["kind"] = DESCRIPTOR_KIND
    projection["evidence"] = [
        {key: value for key, value in item.items() if key not in {"bytes", "sha256"}}
        for item in receipt["evidence"]
    ]
    return projection


def _evidence_projection(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "bytes": item["bytes"],
            "id": item["id"],
            "kind": item["kind"],
            "sha256": item["sha256"],
        }
        for item in sorted(receipt["evidence"], key=lambda row: row["id"])
    ]


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise FixtureError("signing must be an object")
    _require_exact_keys(value, ("operator", "reviewer"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "reviewer": (REVIEWER_ROLE, REVIEWER_NAMESPACE),
    }
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise FixtureError(f"signing.{name} must be an object")
        _require_exact_keys(
            item, ("algorithm", "key_id_sha256", "namespace", "role"), f"signing.{name}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role
        ):
            raise FixtureError(f"signing.{name} contract drifted")
        _sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256")
    if value["operator"]["key_id_sha256"] == value["reviewer"]["key_id_sha256"]:
        raise FixtureError("fixture signing keys must be distinct")


def _validate_receipt(
    receipt: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    _validate_core(receipt, manifest, receipt=True)
    if receipt["authority_ceiling"] != AUTHORITY_CEILING:
        raise FixtureError("fixture authority ceiling drifted")
    if receipt["disposition"] != DISPOSITION:
        raise FixtureError("fixture disposition drifted")
    identity = receipt["fixture_identity"]
    if not isinstance(identity, dict):
        raise FixtureError("fixture_identity must be an object")
    _require_exact_keys(
        identity,
        (
            "asic_family",
            "controller_board_model",
            "controller_board_revision",
            "hashboard_revisions",
            "stock_firmware_build",
            "stock_hwtype",
            "stock_swtype",
            "variant_profile_id",
        ),
        "fixture_identity",
    )
    for field in (
        "asic_family",
        "controller_board_model",
        "controller_board_revision",
        "stock_firmware_build",
        "stock_hwtype",
        "stock_swtype",
    ):
        _text(identity[field], f"fixture_identity.{field}")
    _identifier(identity["variant_profile_id"], "fixture_identity.variant_profile_id")
    revisions = identity["hashboard_revisions"]
    if (
        not isinstance(revisions, list)
        or not revisions
        or len(revisions) != len(set(revisions))
    ):
        raise FixtureError("fixture_identity hashboard revisions are invalid")
    for index, revision in enumerate(revisions):
        _text(revision, f"fixture_identity.hashboard_revisions[{index}]")
    _validate_signing(receipt["signing"])
    descriptor_sha = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    if descriptor_sha != receipt["descriptor_sha256"]:
        raise FixtureError("fixture descriptor SHA-256 mismatch")
    evidence_sha = hashlib.sha256(
        b"DCENT-K210-FIXTURE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    if evidence_sha != receipt["fixture_evidence_set_sha256"]:
        raise FixtureError("fixture evidence-set SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-FIXTURE-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise FixtureError("fixture receipt ID mismatch")


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    operator_private_key: Path,
    reviewer_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_core(descriptor, manifest, receipt=False)
    enriched = []
    sources: dict[str, Path] = {}
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        relative = _safe_path(item["path"], f"evidence {item['id']} path")
        source = _source(evidence_root, relative)
        size, digest = _hash_source(source, f"evidence {item['id']}")
        if size > MAX_EVIDENCE_FILE_BYTES:
            raise FixtureError(f"evidence {item['id']} exceeds the per-file limit")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise FixtureError("fixture evidence exceeds the aggregate byte limit")
        row = dict(item)
        row["bytes"] = size
        row["sha256"] = digest
        enriched.append(row)
        sources[item["id"]] = source
    try:
        operator_key = discovery.inspect_private_key(operator_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
    except discovery.DiscoveryError as exc:
        raise FixtureError(f"fixture private key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise FixtureError("fixture operator and reviewer keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(FIXTURE_ACTIONS)
    normalized["evidence"] = enriched
    normalized["kind"] = RECEIPT_KIND
    receipt: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "disposition": DISPOSITION,
        "signing": {
            "operator": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": operator_key["key_id_sha256"],
                "namespace": OPERATOR_NAMESPACE,
                "role": OPERATOR_ROLE,
            },
            "reviewer": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": reviewer_key["key_id_sha256"],
                "namespace": REVIEWER_NAMESPACE,
                "role": REVIEWER_ROLE,
            },
        },
    }
    semantics = _validate_semantics(manifest, receipt, evidence_root)
    receipt["fixture_identity"] = {
        key: semantics[key]
        for key in (
            "asic_family",
            "controller_board_model",
            "controller_board_revision",
            "hashboard_revisions",
            "stock_firmware_build",
            "stock_hwtype",
            "stock_swtype",
            "variant_profile_id",
        )
    }
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    receipt["fixture_evidence_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-FIXTURE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-FIXTURE-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest)
    _validate_semantics(manifest, receipt, evidence_root)
    return receipt, sources


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    operator_private_key: Path,
    reviewer_private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise FixtureError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "fixture descriptor", canonical=False)
    receipt, sources = build_receipt(
        manifest,
        descriptor,
        evidence_root,
        operator_private_key,
        reviewer_private_key,
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        evidence_destination = temporary / EVIDENCE_DIRECTORY
        evidence_destination.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = evidence_destination.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_source(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise FixtureError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        operator_signature = discovery.sign_sshsig_file(
            receipt_path, operator_private_key, OPERATOR_NAMESPACE
        )
        reviewer_signature = discovery.sign_sshsig_file(
            receipt_path, reviewer_private_key, REVIEWER_NAMESPACE
        )
        (temporary / OPERATOR_SIGNATURE_NAME).write_bytes(operator_signature)
        (temporary / REVIEWER_SIGNATURE_NAME).write_bytes(reviewer_signature)
        discovery.verify_sshsig_bytes(
            receipt_raw,
            temporary / OPERATOR_SIGNATURE_NAME,
            discovery.inspect_private_key(operator_private_key)["canonical_line"],
            receipt["operator_id"],
            OPERATOR_NAMESPACE,
        )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            temporary / REVIEWER_SIGNATURE_NAME,
            discovery.inspect_private_key(reviewer_private_key)["canonical_line"],
            receipt["reviewer_id"],
            REVIEWER_NAMESPACE,
        )
        _verify_exact_members(temporary, receipt)
        os.replace(temporary, bundle_out.resolve())
    except discovery.DiscoveryError as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        raise FixtureError(str(exc)) from exc
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return receipt


def verify_bundle(
    manifest: Mapping[str, Any],
    bundle: Path,
    operator_public_key: Path,
    reviewer_public_key: Path,
    expected_operator_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise FixtureError(f"fixture bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise FixtureError("fixture bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "fixture receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        reviewer_key = discovery.inspect_public_key(reviewer_public_key)
        receipt_raw = discovery._read_regular(
            receipt_path, "fixture receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise FixtureError(f"fixture trust/signature input is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise FixtureError("fixture trust keys must be distinct")
    expected = (
        (
            "operator",
            operator_key,
            expected_operator_key_id,
            bundle / OPERATOR_SIGNATURE_NAME,
            receipt["operator_id"],
            OPERATOR_NAMESPACE,
        ),
        (
            "reviewer",
            reviewer_key,
            expected_reviewer_key_id,
            bundle / REVIEWER_SIGNATURE_NAME,
            receipt["reviewer_id"],
            REVIEWER_NAMESPACE,
        ),
    )
    for role, key, pinned, signature_path, principal, namespace in expected:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise FixtureError(f"{role} public key does not match its trust anchor")
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise FixtureError(f"fixture receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw,
                signature_path,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise FixtureError(f"fixture {role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        relative = _safe_path(item["path"], f"evidence {item['id']} path")
        source = _source(bundle / EVIDENCE_DIRECTORY, relative)
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise FixtureError("fixture evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise FixtureError(f"evidence {item['id']} digest or size mismatch")
    semantics = _validate_semantics(
        manifest, receipt, bundle / EVIDENCE_DIRECTORY
    )
    _verify_exact_members(bundle, receipt)
    return {
        "authority_granted": False,
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "asic_family": semantics["asic_family"],
        "controller_board_model": semantics["controller_board_model"],
        "controller_board_revision": semantics["controller_board_revision"],
        "dispositions": semantics["dispositions"],
        "fixture_evidence_set_sha256": receipt["fixture_evidence_set_sha256"],
        "fixture_id": receipt["fixture_id"],
        "fixture_qualification_eligible": True,
        "hashboard_revisions": semantics["hashboard_revisions"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "reviewer_key_id_sha256": reviewer_key["key_id_sha256"],
        "state": "verified_signed_fixture_qualification",
        "stock_firmware_build": semantics["stock_firmware_build"],
        "stock_hwtype": semantics["stock_hwtype"],
        "stock_swtype": semantics["stock_swtype"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "variant_profile_id": semantics["variant_profile_id"],
    }


def _verify_exact_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_files = {
        RECEIPT_NAME,
        OPERATOR_SIGNATURE_NAME,
        REVIEWER_SIGNATURE_NAME,
    }
    expected_directories = {EVIDENCE_DIRECTORY}
    for item in receipt["evidence"]:
        relative = PurePosixPath(EVIDENCE_DIRECTORY) / _safe_path(
            item["path"], f"evidence {item['id']} path"
        )
        expected_files.add(str(relative))
        expected_directories.update(str(parent) for parent in relative.parents)
    expected_directories.discard(".")
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    pending = [(bundle, PurePosixPath())]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise FixtureError(f"fixture bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise FixtureError(
                    f"fixture bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise FixtureError(f"fixture bundle contains a linked member: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise FixtureError(f"fixture bundle has a special member: {relative}")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise FixtureError("fixture bundle member set is not exact")


def _template(
    manifest: Mapping[str, Any], discovery_receipt_path: Path
) -> dict[str, Any]:
    observed = _load_json(discovery_receipt_path, "discovery receipt", canonical=True)
    try:
        discovery._validate_receipt(observed, manifest)
    except discovery.DiscoveryError as exc:
        raise FixtureError(f"discovery receipt is invalid: {exc}") from exc
    paths = {
        "completion_matrix": "records/completion-matrix.json",
        "cooling_cutoff_record": "records/cooling-cutoff.json",
        "discovery_receipt_copy": "identity/discovery-receipt.json",
        "electrical_measurement_record": "records/electrical-measurements.json",
        "fixture_overview_photo": "photos/fixture-overview.png",
        "flash_fixture_record": "records/flash-fixture.json",
        "identity_isolation_record": "records/identity-isolation.json",
        "instrument_record": "records/instruments.json",
        "programmer_isolation_photo": "photos/programmer-isolation.png",
        "qualification_log": "records/qualification-log.json",
    }
    evidence = []
    for index, kind in enumerate(REQUIRED_EVIDENCE_KINDS, 1):
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T01:00:00Z",
                "id": f"e{index:02d}-{kind.replace('_', '-')}",
                "kind": kind,
                "media_type": "image/png" if kind in PHOTO_KINDS else "application/json",
                "method": METHOD_BY_KIND[kind],
                "path": paths[kind],
                "redaction": "none",
            }
        )
    return {
        "actions_performed": dict(ACTIONS_PERFORMED),
        "authorization": {
            "authorized_actions": sorted(FIXTURE_ACTIONS),
            "operator_reference": "REPLACE_WITH_EXACT_FIXTURE_AUTHORIZATION",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T02:00:00Z",
        },
        "completed_at_utc": "2026-01-01T01:30:00Z",
        "discovery_receipt_id": observed["receipt_id"],
        "evidence": evidence,
        "fixture_id": "REPLACE_WITH_FIXTURE_ID",
        "kind": DESCRIPTOR_KIND,
        "operator_id": "REPLACE_WITH_OPERATOR_ID",
        "reviewer_id": "REPLACE_WITH_EE_REVIEWER_ID",
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "started_at_utc": "2026-01-01T00:30:00Z",
        "target_id": observed["target_id"],
        "unit_fingerprint_sha256": observed["unit_fingerprint_sha256"],
        "unit_label": observed["unit_label"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser("template")
    template.add_argument("--discovery-receipt", type=Path, required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--reviewer-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--operator-public-key", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    return parser


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="ascii", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError as exc:
        raise FixtureError(f"refusing to overwrite existing output: {path}") from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_manifest(args.manifest)
        if args.command == "template":
            descriptor = _template(manifest, args.discovery_receipt)
            _write_new_json(args.out, descriptor)
            print(f"K210_FIXTURE_TEMPLATE_WRITTEN target={descriptor['target_id']}")
            return 0
        if args.command == "create":
            receipt = create_bundle(
                manifest,
                args.descriptor,
                args.evidence_root,
                args.operator_private_key,
                args.reviewer_private_key,
                args.bundle_out,
            )
            print(
                f"K210_FIXTURE_BUNDLE_CREATED target={receipt['target_id']} "
                f"receipt={receipt['receipt_id']}"
            )
            return 0
        result = verify_bundle(
            manifest,
            args.bundle,
            args.operator_public_key,
            args.reviewer_public_key,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except FixtureError as exc:
        print(f"K210_FIXTURE_ERROR: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
