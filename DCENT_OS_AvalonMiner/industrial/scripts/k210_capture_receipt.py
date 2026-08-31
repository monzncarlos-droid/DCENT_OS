#!/usr/bin/env python3
"""Create and verify signed exact-unit A1246 passive-capture bundles.

This tool is host-only. It has no miner, network, serial, USB, analyzer,
GPIO, JTAG, ISP, programmer, power, flash, or transmit transport. It
reproduces canonical `.k210cap` bytes from already-exported signed inputs and
admits past P1 observations only. A valid receipt grants no future authority
and makes no opcode, framing, register, codec, or production claim.
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
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 evidence primitive: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = _load_module("k210_fixture_receipt.py", "k210_fixture_receipt")
discovery = fixture.discovery
capture_ingest = _load_module("k210_capture_ingest.py", "k210_capture_ingest")

SCHEMA_VERSION = 1
SCOPE = discovery.SCOPE
DESCRIPTOR_KIND = "dcent_k210_passive_capture_descriptor"
RECEIPT_KIND = "dcent_k210_passive_capture_receipt"
DISPOSITION = "past_p1_capture_evidence_only_no_future_authority"
ADMISSION_CLASS = "p1_controller_passive"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
REVIEWER_SIGNATURE_NAME = "reviewer.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_capture_operator"
REVIEWER_ROLE = "k210_capture_reviewer"
OPERATOR_NAMESPACE = "dcent-k210-capture-operator-v1"
REVIEWER_NAMESPACE = "dcent-k210-capture-reviewer-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

MAX_JSON_BYTES = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = capture_ingest.MAX_CSV_BYTES
MAX_TOTAL_EVIDENCE_BYTES = 600 * 1024 * 1024
MIN_SAMPLE_RATE_HZ = capture_ingest.CENSUS_MIN_RECOMMENDED_RATE_HZ
CORE_SIGNALS = {"CI", "DI", "RI", "CKI", "CO", "DO", "RO", "CKO"}

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

CAPTURE_ACTIONS = {
    "closed_chassis_stock_bounded_work_capture",
    "closed_chassis_stock_safe_idle_capture",
    "cooling_telemetry_observation",
    "hash_power_cutoff_verification",
    "stock_read_only_identity_queries",
}
ACTIONS_PERFORMED = {
    "closed_chassis_only": True,
    "configuration_changed": False,
    "firmware_written": False,
    "hash_power_energized_during_bounded_work": True,
    "hash_power_independently_cut_during_safe_idle": True,
    "power_state_changed": True,
    "reboot_requested": False,
    "signal_driven_by_analyzer_or_fixture": False,
    "stock_bounded_work_executed": True,
}
AUTHORITY_CEILING = {
    "authorizes_codec_or_wire_contract": False,
    "authorizes_contact": False,
    "authorizes_future_capture_or_transmit": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_future_read_or_write": False,
    "authorizes_install": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_asic_control": False,
    "qualifies_production": False,
}

SINGLE_EVIDENCE_KINDS = {
    "campaign_log",
    "cooling_telemetry_record",
    "cutoff_feedback_record",
    "discovery_receipt_copy",
    "fixture_receipt_copy",
    "state_control_record",
    "stock_identity_record",
    "work_exchange_record",
}
MULTI_EVIDENCE_COUNTS = {
    "k210cap_artifact": (2, 2),
    "physical_channel_map": (2, 2),
    "source_csv": (2, 4),
}
ALL_EVIDENCE_KINDS = SINGLE_EVIDENCE_KINDS | set(MULTI_EVIDENCE_COUNTS)
MEDIA_TYPE_BY_KIND = {
    **{kind: "application/json" for kind in SINGLE_EVIDENCE_KINDS},
    "k210cap_artifact": "application/x-dcent-k210-capture",
    "physical_channel_map": "application/json",
    "source_csv": "text/csv",
}
METHOD_BY_KIND = {
    "campaign_log": "offline_record",
    "cooling_telemetry_record": "authorized_stock_capture",
    "cutoff_feedback_record": "authorized_stock_capture",
    "discovery_receipt_copy": "offline_record",
    "fixture_receipt_copy": "offline_record",
    "k210cap_artifact": "deterministic_normalization",
    "physical_channel_map": "authorized_stock_capture",
    "source_csv": "authorized_stock_capture",
    "state_control_record": "authorized_stock_capture",
    "stock_identity_record": "stock_read_only_management",
    "work_exchange_record": "authorized_bounded_stock_work",
}


class CaptureReceiptError(RuntimeError):
    """A capture descriptor, bundle, signature, or semantic invariant failed."""


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
        raise CaptureReceiptError(
            f"{context} keys invalid: missing={missing} unexpected={extra}"
        )


def _text(value: Any, context: str, maximum: int = 200) -> str:
    try:
        return discovery._observed_text(value, context, maximum)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 96)
    if not IDENTIFIER_RE.fullmatch(text):
        raise CaptureReceiptError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    try:
        return fixture._principal(value, context)
    except fixture.FixtureError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise CaptureReceiptError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise CaptureReceiptError(f"{context} is not a valid UTC timestamp") from exc


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise CaptureReceiptError(f"{context} must be lowercase SHA-256")
    return value


def _integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise CaptureReceiptError(
            f"{context} must be an integer in {minimum}..{maximum}"
        )
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    try:
        return fixture._safe_path(value, context)
    except fixture.FixtureError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _load_json(path: Path, label: str, *, canonical: bool = True) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        return discovery._load_manifest(path)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _read(path: Path, label: str, maximum: int = MAX_EVIDENCE_FILE_BYTES) -> bytes:
    try:
        return discovery._read_regular(path, label, maximum)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


def _hash(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc


CORE_KEYS = (
    "actions_performed",
    "admission_class",
    "authorization",
    "campaign_id",
    "captures",
    "completed_at_utc",
    "discovery_receipt_id",
    "evidence",
    "fixture_evidence_set_sha256",
    "fixture_receipt_id",
    "kind",
    "operator_id",
    "reviewer_id",
    "schema_version",
    "scope",
    "started_at_utc",
    "stock_aup_sha256",
    "target_id",
    "unit_fingerprint_sha256",
    "unit_label",
    "variant_profile_id",
)
RECEIPT_ONLY_KEYS = (
    "authority_ceiling",
    "capture_set_sha256",
    "descriptor_sha256",
    "disposition",
    "receipt_id",
    "signing",
)


def _validate_capture_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise CaptureReceiptError("captures must contain exactly the two P1 states")
    states: set[str] = set()
    ids: set[str] = set()
    normalized = []
    for index, row in enumerate(value):
        context = f"captures[{index}]"
        if not isinstance(row, dict):
            raise CaptureReceiptError(f"{context} must be an object")
        _require_exact_keys(
            row,
            (
                "capture_id",
                "k210cap_evidence_id",
                "mapping_evidence_id",
                "source_csv_evidence_ids",
                "state",
            ),
            context,
        )
        capture_id = _identifier(row["capture_id"], f"{context}.capture_id")
        if capture_id in ids:
            raise CaptureReceiptError("capture IDs must be distinct")
        ids.add(capture_id)
        state = row["state"]
        if state not in capture_ingest.CAPTURE_STATES or state in states:
            raise CaptureReceiptError("capture state set is duplicated or unsupported")
        states.add(state)
        _identifier(row["k210cap_evidence_id"], f"{context}.k210cap_evidence_id")
        _identifier(row["mapping_evidence_id"], f"{context}.mapping_evidence_id")
        csv_ids = row["source_csv_evidence_ids"]
        if (
            not isinstance(csv_ids, list)
            or not 1 <= len(csv_ids) <= 2
            or len(csv_ids) != len(set(csv_ids))
        ):
            raise CaptureReceiptError(f"{context} must reference one or two source CSVs")
        for csv_index, evidence_id in enumerate(csv_ids):
            _identifier(evidence_id, f"{context}.source_csv_evidence_ids[{csv_index}]")
        normalized.append(dict(row))
    if states != set(capture_ingest.CAPTURE_STATES):
        raise CaptureReceiptError("capture rows do not cover both required P1 states")
    return normalized


def _validate_evidence(value: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 14 <= len(value) <= 16:
        raise CaptureReceiptError("capture evidence must contain 14..16 records")
    ids: set[str] = set()
    paths: set[str] = set()
    counts: dict[str, int] = {}
    normalized = []
    for index, item in enumerate(value):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise CaptureReceiptError(f"{context} must be an object")
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
        if kind not in ALL_EVIDENCE_KINDS:
            raise CaptureReceiptError(f"{context}.kind is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if evidence_id in ids or path in paths:
            raise CaptureReceiptError("evidence IDs and paths must each be unique")
        ids.add(evidence_id)
        paths.add(path)
        counts[kind] = counts.get(kind, 0) + 1
        if item["media_type"] != MEDIA_TYPE_BY_KIND[kind]:
            raise CaptureReceiptError(f"{context}.media_type is wrong for {kind}")
        if item["method"] != METHOD_BY_KIND[kind]:
            raise CaptureReceiptError(f"{context}.method is wrong for {kind}")
        if item["redaction"] not in discovery.REDACTION_STATES:
            raise CaptureReceiptError(f"{context}.redaction is unsupported")
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _integer(item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    if any(counts.get(kind) != 1 for kind in SINGLE_EVIDENCE_KINDS):
        raise CaptureReceiptError("single-instance capture evidence kind set is not exact")
    for kind, (minimum, maximum) in MULTI_EVIDENCE_COUNTS.items():
        if not minimum <= counts.get(kind, 0) <= maximum:
            raise CaptureReceiptError(f"capture evidence count for {kind} is not admissible")
    if set(counts) != ALL_EVIDENCE_KINDS:
        raise CaptureReceiptError("capture evidence kind vocabulary is not exact")
    return normalized


def _target_profile(manifest: Mapping[str, Any], profile_id: str) -> Mapping[str, Any]:
    matches = [
        row
        for row in manifest.get("firmware_profiles", [])
        if isinstance(row, dict) and row.get("id") == profile_id
    ]
    if len(matches) != 1:
        raise CaptureReceiptError("variant_profile_id does not resolve exactly once")
    return matches[0]


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _require_exact_keys(
        value, CORE_KEYS + RECEIPT_ONLY_KEYS if receipt else CORE_KEYS, "capture record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise CaptureReceiptError("capture schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind or value["admission_class"] != ADMISSION_CLASS:
        raise CaptureReceiptError("capture kind or admission class mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    try:
        target = discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(str(exc)) from exc
    if target["kind"] != "physical_model":
        raise CaptureReceiptError("P1 capture admission requires a physical model")
    profile_id = _identifier(value["variant_profile_id"], "variant_profile_id")
    profile = _target_profile(manifest, profile_id)
    if profile_id not in {
        row["profile_id"]
        for row in manifest["a1246_variant_identity_contract"]["variants"]
        if row["target_id"] == target_id
    }:
        raise CaptureReceiptError("variant profile is not admitted for target")
    _sha(profile["aup_sha256"], "manifest profile AUP SHA-256")
    if value["stock_aup_sha256"] != profile["aup_sha256"]:
        raise CaptureReceiptError("stock AUP digest does not match the resolved profile")
    for field in (
        "discovery_receipt_id",
        "fixture_evidence_set_sha256",
        "fixture_receipt_id",
        "stock_aup_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], field)
    _identifier(value["unit_label"], "unit_label")
    _identifier(value["campaign_id"], "campaign_id")
    operator = _principal(value["operator_id"], "operator_id")
    reviewer = _principal(value["reviewer_id"], "reviewer_id")
    if operator == reviewer:
        raise CaptureReceiptError("capture operator and reviewer must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise CaptureReceiptError("capture start must precede completion")
    if value["actions_performed"] != ACTIONS_PERFORMED:
        raise CaptureReceiptError("capture actions_performed contract drifted")
    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise CaptureReceiptError("authorization must be an object")
    _require_exact_keys(
        authorization,
        ("authorized_actions", "operator_reference", "valid_from_utc", "valid_until_utc"),
        "authorization",
    )
    _text(authorization["operator_reference"], "authorization.operator_reference")
    valid_from = _utc(authorization["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(authorization["valid_until_utc"], "authorization.valid_until_utc")
    if valid_from >= valid_until or not valid_from <= started < completed <= valid_until:
        raise CaptureReceiptError("capture campaign is outside its authorization interval")
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or len(actions) != len(CAPTURE_ACTIONS)
        or set(actions) != CAPTURE_ACTIONS
    ):
        raise CaptureReceiptError("authorization does not contain the exact action set")
    captures = _validate_capture_rows(value["captures"])
    evidence = _validate_evidence(value["evidence"], hashed=receipt)
    for index, item in enumerate(evidence):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise CaptureReceiptError(f"evidence[{index}] is outside campaign chronology")
    return captures, evidence


def _evidence_by_id(
    evidence: Sequence[Mapping[str, Any]], root: Path
) -> dict[str, tuple[Mapping[str, Any], Path]]:
    result = {}
    for item in evidence:
        result[item["id"]] = (
            item,
            _source(root, _safe_path(item["path"], f"evidence {item['id']} path")),
        )
    return result


def _require_evidence_ref(
    by_id: Mapping[str, tuple[Mapping[str, Any], Path]],
    evidence_id: str,
    kind: str,
    context: str,
) -> Path:
    item = by_id.get(evidence_id)
    if item is None or item[0]["kind"] != kind:
        raise CaptureReceiptError(f"{context} does not reference {kind} evidence")
    return item[1]


def _single_evidence_path(
    evidence: Sequence[Mapping[str, Any]], root: Path, kind: str
) -> Path:
    item = next(row for row in evidence if row["kind"] == kind)
    return _source(root, _safe_path(item["path"], f"{kind}.path"))


def _json_evidence(
    evidence: Sequence[Mapping[str, Any]], root: Path, kind: str
) -> dict[str, Any]:
    return _load_json(_single_evidence_path(evidence, root, kind), kind)


def _validate_log(document: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        document,
        ("authorization_reference", "deviations", "events", "faults", "stop_events"),
        "campaign_log",
    )
    if document["authorization_reference"] != receipt["authorization"]["operator_reference"]:
        raise CaptureReceiptError("campaign log authorization reference drifted")
    for field in ("deviations", "faults", "stop_events"):
        if document[field] != []:
            raise CaptureReceiptError(f"capture campaign has nonempty {field}")
    events = document["events"]
    if not isinstance(events, list) or len(events) != len(CAPTURE_ACTIONS):
        raise CaptureReceiptError("campaign log must contain one event per action")
    observed: set[str] = set()
    started = _utc(receipt["started_at_utc"], "started_at_utc")
    completed = _utc(receipt["completed_at_utc"], "completed_at_utc")
    for index, event in enumerate(events):
        context = f"campaign_log.events[{index}]"
        if not isinstance(event, dict):
            raise CaptureReceiptError(f"{context} must be an object")
        _require_exact_keys(event, ("action", "detail", "time_utc"), context)
        action = event["action"]
        if action not in CAPTURE_ACTIONS or action in observed:
            raise CaptureReceiptError("campaign log action is unknown or duplicated")
        observed.add(action)
        if not started <= _utc(event["time_utc"], f"{context}.time_utc") <= completed:
            raise CaptureReceiptError(f"{context} is outside campaign chronology")
        _text(event["detail"], f"{context}.detail", 512)


def _validate_identity_record(
    document: Mapping[str, Any],
    discovery_receipt: Mapping[str, Any],
    fixture_summary: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    _require_exact_keys(
        document,
        ("after", "before", "identity_drift", "stock_aup_sha256"),
        "stock_identity_record",
    )
    if document["identity_drift"] is not False:
        raise CaptureReceiptError("stock identity drift was observed")
    if document["stock_aup_sha256"] != receipt["stock_aup_sha256"]:
        raise CaptureReceiptError("stock identity record AUP digest drifted")
    identity = discovery_receipt["identity"]
    expected = {
        "asic_family": identity["asic_family"],
        "controller_board_model": fixture_summary["controller_board_model"],
        "controller_board_revision": fixture_summary["controller_board_revision"],
        "hashboard_revisions": fixture_summary["hashboard_revisions"],
        "stock_dna": identity["stock_dna"],
        "stock_firmware_build": identity["stock_firmware_version"],
        "stock_hwtype": identity["stock_hwtype"],
        "stock_swtype": identity["stock_swtype"],
        "unit_serial": identity["miner_serial"],
    }
    if document["before"] != expected or document["after"] != expected:
        raise CaptureReceiptError("before/after stock identity does not exact-join discovery")


def _validate_state_control(document: Mapping[str, Any]) -> None:
    _require_exact_keys(document, ("bounded_work_exchange", "safe_idle_detection"), "state_control_record")
    idle = document["safe_idle_detection"]
    work = document["bounded_work_exchange"]
    if not isinstance(idle, dict) or not isinstance(work, dict):
        raise CaptureReceiptError("state control entries must be objects")
    _require_exact_keys(
        idle,
        (
            "closed_chassis",
            "hash_power_requested",
            "independent_cutoff_asserted",
            "stock_firmware_running",
        ),
        "safe_idle_detection state",
    )
    if idle != {
        "closed_chassis": True,
        "hash_power_requested": False,
        "independent_cutoff_asserted": True,
        "stock_firmware_running": True,
    }:
        raise CaptureReceiptError("safe-idle state controls are not exact")
    _require_exact_keys(
        work,
        (
            "closed_chassis",
            "cooling_confirmed",
            "independent_cutoff_available",
            "stock_firmware_running",
            "stock_work_bounded",
        ),
        "bounded_work_exchange state",
    )
    if any(value is not True for value in work.values()):
        raise CaptureReceiptError("bounded-work state controls are incomplete")


def _validate_cutoff(document: Mapping[str, Any], safe_capture_id: str) -> None:
    _require_exact_keys(
        document,
        (
            "continuous_monitoring",
            "independent_feedback_method",
            "loss_events",
            "rail_absent_for_full_capture",
            "safe_idle_capture_id",
        ),
        "cutoff_feedback_record",
    )
    _text(document["independent_feedback_method"], "independent_feedback_method")
    if (
        document["safe_idle_capture_id"] != safe_capture_id
        or document["continuous_monitoring"] is not True
        or document["rail_absent_for_full_capture"] is not True
        or document["loss_events"] != []
    ):
        raise CaptureReceiptError("safe-idle cutoff feedback is incomplete")


def _validate_cooling(document: Mapping[str, Any], capture_ids: set[str]) -> None:
    _require_exact_keys(
        document,
        (
            "capture_ids",
            "fan_or_pump_faults",
            "fans_or_pumps_operational",
            "limit_millicelsius",
            "max_observed_millicelsius",
            "sample_count",
            "stock_baseline_after",
            "stock_baseline_before",
            "telemetry_gap",
        ),
        "cooling_telemetry_record",
    )
    if set(document["capture_ids"]) != capture_ids or len(document["capture_ids"]) != 2:
        raise CaptureReceiptError("cooling record does not cover both captures")
    observed = _integer(
        document["max_observed_millicelsius"], "max_observed_millicelsius", -40_000, 200_000
    )
    limit = _integer(document["limit_millicelsius"], "limit_millicelsius", 1, 200_000)
    _integer(document["sample_count"], "sample_count", 2, 1_000_000)
    if observed >= limit:
        raise CaptureReceiptError("capture cooling temperature reached its limit")
    if (
        document["fans_or_pumps_operational"] is not True
        or document["stock_baseline_before"] is not True
        or document["stock_baseline_after"] is not True
        or document["telemetry_gap"] is not False
        or document["fan_or_pump_faults"] != []
    ):
        raise CaptureReceiptError("cooling telemetry custody is incomplete")


def _validate_work(document: Mapping[str, Any], work_capture_id: str, auth: str) -> None:
    _require_exact_keys(
        document,
        (
            "authorization_reference",
            "capture_id",
            "completed_work_units",
            "duration_ms",
            "job_observed",
            "nonce_observed",
            "poolless_test_work",
            "requested_work_units",
            "status_observed",
            "stopped",
        ),
        "work_exchange_record",
    )
    if document["capture_id"] != work_capture_id or document["authorization_reference"] != auth:
        raise CaptureReceiptError("bounded-work record does not join its capture/authorization")
    requested = _integer(document["requested_work_units"], "requested_work_units", 1, 1_000_000)
    completed = _integer(document["completed_work_units"], "completed_work_units", 1, requested)
    _integer(document["duration_ms"], "duration_ms", 1, 600_000)
    if completed > requested:
        raise CaptureReceiptError("completed work exceeds the authorized bound")
    for field in ("job_observed", "nonce_observed", "poolless_test_work", "status_observed"):
        if document[field] is not True:
            raise CaptureReceiptError(f"bounded-work evidence lacks {field}")
    if document["stopped"] is not False:
        raise CaptureReceiptError("bounded-work campaign records a stop")


def _reproduce_capture(
    row: Mapping[str, Any],
    by_id: Mapping[str, tuple[Mapping[str, Any], Path]],
    receipt: Mapping[str, Any],
    discovery_receipt: Mapping[str, Any],
    fixture_summary: Mapping[str, Any],
) -> tuple[dict[str, int], dict[str, Any]]:
    mapping_path = _require_evidence_ref(
        by_id, row["mapping_evidence_id"], "physical_channel_map", "capture map"
    )
    artifact_path = _require_evidence_ref(
        by_id, row["k210cap_evidence_id"], "k210cap_artifact", "capture artifact"
    )
    csv_paths = [
        _require_evidence_ref(by_id, evidence_id, "source_csv", "capture source CSV")
        for evidence_id in row["source_csv_evidence_ids"]
    ]
    try:
        channels, provenance = capture_ingest._load_mapping(mapping_path)
        csv_data = [
            (
                path,
                capture_ingest._read_bounded_regular_file(
                    path, "signed source CSV", capture_ingest.MAX_CSV_BYTES
                ),
            )
            for path in csv_paths
        ]
        wanted_by_file = capture_ingest._resolve_signal_sources(channels, csv_data)
        tracks = []
        for path, raw in csv_data:
            tracks.extend(
                capture_ingest._parse_digital_csv(
                    raw, path, "signed source CSV", wanted_by_file[path]
                )
            )
        normalized = capture_ingest._merge_and_normalize(
            tracks,
            capture_ingest._parse_seconds_to_ps(provenance["capture_end_s"]),
            provenance["sample_rate_hz"],
            len(csv_data),
        )
        reproduced = capture_ingest.encode_artifact(provenance, normalized)
        observed = _read(artifact_path, "signed k210cap", capture_ingest.MAX_ARTIFACT_BYTES)
        decoded = capture_ingest.decode_artifact(observed)
    except capture_ingest.CaptureIngestError as exc:
        raise CaptureReceiptError(f"capture {row['capture_id']} is invalid: {exc}") from exc
    if reproduced != observed:
        raise CaptureReceiptError(
            f"capture {row['capture_id']} is not byte-reproducible from signed map/CSV inputs"
        )
    if not CORE_SIGNALS.issubset(channels) or not set(channels).issubset(
        capture_ingest.SIGNAL_DIRECTIONS
    ):
        raise CaptureReceiptError("capture map lacks the core eight signals")
    identity = discovery_receipt["identity"]
    expected_revision_set = "|".join(sorted(fixture_summary["hashboard_revisions"]))
    expected_provenance = {
        "asic_family": identity["asic_family"],
        "authorization_reference": receipt["authorization"]["operator_reference"],
        "capture_session_id": row["capture_id"],
        "capture_state": row["state"],
        "controller_revision": fixture_summary["controller_board_revision"],
        "hashboard_revision": expected_revision_set,
        "model": identity["marketing_model"],
        "operator": receipt["operator_id"],
        "stock_aup_sha256": receipt["stock_aup_sha256"],
        "stock_firmware_build": identity["stock_firmware_version"],
        "unit_serial": identity["miner_serial"],
    }
    for field, expected in expected_provenance.items():
        if provenance.get(field) != expected:
            raise CaptureReceiptError(
                f"capture {row['capture_id']} provenance {field} does not exact-join"
            )
    if set(provenance) - (
        set(capture_ingest.REQUIRED_PROVENANCE_FIELDS)
        | {"stock_aup_sha256", "unit_serial"}
    ):
        raise CaptureReceiptError("capture provenance contains unaudited optional fields")
    if decoded.sample_rate_hz < MIN_SAMPLE_RATE_HZ:
        raise CaptureReceiptError("capture sample rate is below the 50 MS/s P1 minimum")
    if decoded.signal_names() != sorted(channels):
        raise CaptureReceiptError("artifact signal map does not match the physical channel map")
    directions = [
        decoded.signals[event[1]]["direction"] for event in decoded.events
    ]
    if row["state"] == "bounded_work_exchange" and (
        not directions
        or capture_ingest.DIRECTION_CONTROLLER_TO_ASIC not in directions
        or capture_ingest.DIRECTION_ASIC_TO_CONTROLLER not in directions
    ):
        raise CaptureReceiptError(
            "bounded-work capture lacks nonempty bidirectional edge evidence"
        )
    return channels, {
        "artifact_sha256": hashlib.sha256(observed).hexdigest(),
        "capture_id": row["capture_id"],
        "controller_to_asic_events": directions.count(
            capture_ingest.DIRECTION_CONTROLLER_TO_ASIC
        ),
        "events": len(decoded.events),
        "asic_to_controller_events": directions.count(
            capture_ingest.DIRECTION_ASIC_TO_CONTROLLER
        ),
        "logical_digest": decoded.digest.hex(),
        "sample_rate_hz": decoded.sample_rate_hz,
        "state": row["state"],
    }


def _validate_semantics(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any], root: Path
) -> dict[str, Any]:
    evidence = receipt["evidence"]
    discovery_path = _single_evidence_path(evidence, root, "discovery_receipt_copy")
    fixture_path = _single_evidence_path(evidence, root, "fixture_receipt_copy")
    discovery_receipt = _load_json(discovery_path, "discovery receipt copy")
    fixture_receipt = _load_json(fixture_path, "fixture receipt copy")
    try:
        discovery._validate_receipt(discovery_receipt, manifest)
        fixture._validate_receipt(fixture_receipt, manifest)
    except (discovery.DiscoveryError, fixture.FixtureError) as exc:
        raise CaptureReceiptError(f"capture predecessor copy is invalid: {exc}") from exc
    fixture_summary = fixture_receipt["fixture_identity"]
    discovery_joins = {
        "receipt_id": "discovery_receipt_id",
        "target_id": "target_id",
        "unit_fingerprint_sha256": "unit_fingerprint_sha256",
        "unit_label": "unit_label",
    }
    for predecessor_field, capture_field in discovery_joins.items():
        if discovery_receipt[predecessor_field] != receipt[capture_field]:
            raise CaptureReceiptError(
                f"discovery receipt {predecessor_field} does not join capture"
            )
    fixture_joins = {
        "discovery_receipt_id": "discovery_receipt_id",
        "fixture_evidence_set_sha256": "fixture_evidence_set_sha256",
        "receipt_id": "fixture_receipt_id",
        "target_id": "target_id",
        "unit_fingerprint_sha256": "unit_fingerprint_sha256",
        "unit_label": "unit_label",
    }
    for predecessor_field, capture_field in fixture_joins.items():
        if fixture_receipt[predecessor_field] != receipt[capture_field]:
            raise CaptureReceiptError(
                f"fixture receipt {predecessor_field} does not join capture"
            )
    if fixture_summary["variant_profile_id"] != receipt["variant_profile_id"]:
        raise CaptureReceiptError("fixture variant profile does not join capture")
    _validate_log(_json_evidence(evidence, root, "campaign_log"), receipt)
    _validate_identity_record(
        _json_evidence(evidence, root, "stock_identity_record"),
        discovery_receipt,
        fixture_summary,
        receipt,
    )
    _validate_state_control(_json_evidence(evidence, root, "state_control_record"))
    capture_by_state = {row["state"]: row for row in receipt["captures"]}
    idle = capture_by_state["safe_idle_detection"]
    work = capture_by_state["bounded_work_exchange"]
    _validate_cutoff(
        _json_evidence(evidence, root, "cutoff_feedback_record"), idle["capture_id"]
    )
    capture_ids = {row["capture_id"] for row in receipt["captures"]}
    _validate_cooling(
        _json_evidence(evidence, root, "cooling_telemetry_record"), capture_ids
    )
    _validate_work(
        _json_evidence(evidence, root, "work_exchange_record"),
        work["capture_id"],
        receipt["authorization"]["operator_reference"],
    )
    by_id = _evidence_by_id(evidence, root)
    referenced_ids: set[str] = set()
    maps = []
    summaries = []
    for row in receipt["captures"]:
        referenced_ids.add(row["k210cap_evidence_id"])
        referenced_ids.add(row["mapping_evidence_id"])
        referenced_ids.update(row["source_csv_evidence_ids"])
        channels, summary = _reproduce_capture(
            row, by_id, receipt, discovery_receipt, fixture_summary
        )
        maps.append(channels)
        summaries.append(summary)
    capture_evidence_ids = {
        item["id"]
        for item in evidence
        if item["kind"] in {"k210cap_artifact", "physical_channel_map", "source_csv"}
    }
    if referenced_ids != capture_evidence_ids:
        raise CaptureReceiptError("capture rows do not reference the exact source artifact set")
    if maps[0] != maps[1]:
        raise CaptureReceiptError("physical channel mapping drifted between P1 states")
    return {
        "captures": sorted(summaries, key=lambda item: item["state"]),
        "controller_board_revision": fixture_summary["controller_board_revision"],
        "hashboard_revisions": fixture_summary["hashboard_revisions"],
        "variant_profile_id": fixture_summary["variant_profile_id"],
    }


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
        raise CaptureReceiptError("signing must be an object")
    _require_exact_keys(value, ("operator", "reviewer"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "reviewer": (REVIEWER_ROLE, REVIEWER_NAMESPACE),
    }
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise CaptureReceiptError(f"signing.{name} must be an object")
        _require_exact_keys(
            item, ("algorithm", "key_id_sha256", "namespace", "role"), f"signing.{name}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role
        ):
            raise CaptureReceiptError(f"signing.{name} contract drifted")
        _sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256")
    if value["operator"]["key_id_sha256"] == value["reviewer"]["key_id_sha256"]:
        raise CaptureReceiptError("capture signing keys must be distinct")


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _validate_core(receipt, manifest, receipt=True)
    if receipt["authority_ceiling"] != AUTHORITY_CEILING:
        raise CaptureReceiptError("capture authority ceiling drifted")
    if receipt["disposition"] != DISPOSITION:
        raise CaptureReceiptError("capture disposition drifted")
    _validate_signing(receipt["signing"])
    descriptor_sha = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    if descriptor_sha != receipt["descriptor_sha256"]:
        raise CaptureReceiptError("capture descriptor SHA-256 mismatch")
    capture_set_sha = hashlib.sha256(
        b"DCENT-K210-P1-CAPTURE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    if capture_set_sha != receipt["capture_set_sha256"]:
        raise CaptureReceiptError("capture-set SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-CAPTURE-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise CaptureReceiptError("capture receipt ID mismatch")


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
        size, digest = _hash(source, f"evidence {item['id']}")
        if size > MAX_EVIDENCE_FILE_BYTES:
            raise CaptureReceiptError(f"evidence {item['id']} exceeds the per-file limit")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise CaptureReceiptError("capture evidence exceeds the aggregate byte limit")
        enriched.append({**item, "bytes": size, "sha256": digest})
        sources[item["id"]] = source
    try:
        operator_key = discovery.inspect_private_key(operator_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(f"capture private key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise CaptureReceiptError("capture operator and reviewer keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(CAPTURE_ACTIONS)
    normalized["captures"] = sorted(normalized["captures"], key=lambda row: row["state"])
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
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    receipt["capture_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-P1-CAPTURE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-CAPTURE-RECEIPT-ID-V1\x00"
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
        raise CaptureReceiptError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "capture descriptor", canonical=False)
    receipt, sources = build_receipt(
        manifest, descriptor, evidence_root, operator_private_key, reviewer_private_key
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        destination_root = temporary / EVIDENCE_DIRECTORY
        destination_root.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = destination_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise CaptureReceiptError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        (temporary / OPERATOR_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(receipt_path, operator_private_key, OPERATOR_NAMESPACE)
        )
        (temporary / REVIEWER_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(receipt_path, reviewer_private_key, REVIEWER_NAMESPACE)
        )
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
        raise CaptureReceiptError(str(exc)) from exc
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
        raise CaptureReceiptError(f"capture bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise CaptureReceiptError("capture bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "capture receipt")
    _validate_receipt(receipt, manifest)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        reviewer_key = discovery.inspect_public_key(reviewer_public_key)
        receipt_raw = discovery._read_regular(receipt_path, "capture receipt", MAX_JSON_BYTES)
    except discovery.DiscoveryError as exc:
        raise CaptureReceiptError(f"capture trust/signature input is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise CaptureReceiptError("capture trust keys must be distinct")
    for role, key, pinned, signature_path, principal, namespace in (
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
    ):
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise CaptureReceiptError(f"{role} public key does not match its trust anchor")
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise CaptureReceiptError(f"capture receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw, signature_path, key["canonical_line"], principal, namespace
            )
        except discovery.DiscoveryError as exc:
            raise CaptureReceiptError(f"capture {role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise CaptureReceiptError("capture evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise CaptureReceiptError(f"evidence {item['id']} digest or size mismatch")
    semantics = _validate_semantics(manifest, receipt, bundle / EVIDENCE_DIRECTORY)
    _verify_exact_members(bundle, receipt)
    return {
        "admission_class": receipt["admission_class"],
        "authority_granted": False,
        "capture_set_sha256": receipt["capture_set_sha256"],
        "captures": semantics["captures"],
        "controller_board_revision": semantics["controller_board_revision"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "fixture_evidence_set_sha256": receipt["fixture_evidence_set_sha256"],
        "fixture_receipt_id": receipt["fixture_receipt_id"],
        "hashboard_revisions": semantics["hashboard_revisions"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "p1_capture_admission_eligible": True,
        "receipt_id": receipt["receipt_id"],
        "reviewer_key_id_sha256": reviewer_key["key_id_sha256"],
        "state": "verified_signed_p1_passive_capture",
        "stock_aup_sha256": receipt["stock_aup_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "variant_profile_id": receipt["variant_profile_id"],
        "wire_contract_claimed": False,
    }


def _verify_exact_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_files = {RECEIPT_NAME, OPERATOR_SIGNATURE_NAME, REVIEWER_SIGNATURE_NAME}
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
            raise CaptureReceiptError(f"capture bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise CaptureReceiptError(f"capture bundle contains a linked member: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise CaptureReceiptError(f"capture bundle has a special member: {relative}")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise CaptureReceiptError("capture bundle member set is not exact")


def _template(
    manifest: Mapping[str, Any], discovery_receipt_path: Path, fixture_receipt_path: Path
) -> dict[str, Any]:
    discovered = _load_json(discovery_receipt_path, "discovery receipt")
    qualified = _load_json(fixture_receipt_path, "fixture receipt")
    try:
        discovery._validate_receipt(discovered, manifest)
        fixture._validate_receipt(qualified, manifest)
    except (discovery.DiscoveryError, fixture.FixtureError) as exc:
        raise CaptureReceiptError(f"capture predecessor receipt is invalid: {exc}") from exc
    if (
        qualified["discovery_receipt_id"] != discovered["receipt_id"]
        or qualified["unit_fingerprint_sha256"] != discovered["unit_fingerprint_sha256"]
    ):
        raise CaptureReceiptError("fixture receipt does not join discovery receipt")
    identity = discovered["identity"]
    variants = [
        row
        for row in discovery._target_variant_rows(manifest, discovered["target_id"])
        if row["firmware_version"] == identity["stock_firmware_version"]
        and row["hwtype"] == identity["stock_hwtype"]
        and identity["stock_swtype"] in row["sw_list"]
        and row["asic_family"] == identity["asic_family"]
        and row["hashboard_count"] == identity["hashboard_count"]
    ]
    if len(variants) != 1:
        raise CaptureReceiptError("discovery identity does not resolve one profile")
    profile = _target_profile(manifest, variants[0]["profile_id"])
    paths = {
        "campaign_log": "records/campaign-log.json",
        "cooling_telemetry_record": "records/cooling.json",
        "cutoff_feedback_record": "records/cutoff.json",
        "discovery_receipt_copy": "identity/discovery-receipt.json",
        "fixture_receipt_copy": "identity/fixture-receipt.json",
        "state_control_record": "records/state-control.json",
        "stock_identity_record": "records/stock-identity.json",
        "work_exchange_record": "records/work-exchange.json",
    }
    evidence = []
    for index, kind in enumerate(sorted(SINGLE_EVIDENCE_KINDS), 1):
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T01:00:00Z",
                "id": f"e{index:02d}-{kind.replace('_', '-')}",
                "kind": kind,
                "media_type": MEDIA_TYPE_BY_KIND[kind],
                "method": METHOD_BY_KIND[kind],
                "path": paths[kind],
                "redaction": "none",
            }
        )
    captures = []
    for state in capture_ingest.CAPTURE_STATES:
        prefix = "idle" if state == "safe_idle_detection" else "work"
        ids = {
            "artifact": f"{prefix}-artifact",
            "map": f"{prefix}-map",
            "csv": f"{prefix}-csv",
        }
        evidence.extend(
            (
                {
                    "acquired_at_utc": "2026-01-01T01:00:00Z",
                    "id": ids["artifact"],
                    "kind": "k210cap_artifact",
                    "media_type": MEDIA_TYPE_BY_KIND["k210cap_artifact"],
                    "method": METHOD_BY_KIND["k210cap_artifact"],
                    "path": f"captures/{prefix}.k210cap",
                    "redaction": "none",
                },
                {
                    "acquired_at_utc": "2026-01-01T01:00:00Z",
                    "id": ids["map"],
                    "kind": "physical_channel_map",
                    "media_type": MEDIA_TYPE_BY_KIND["physical_channel_map"],
                    "method": METHOD_BY_KIND["physical_channel_map"],
                    "path": f"captures/{prefix}-map.json",
                    "redaction": "none",
                },
                {
                    "acquired_at_utc": "2026-01-01T01:00:00Z",
                    "id": ids["csv"],
                    "kind": "source_csv",
                    "media_type": MEDIA_TYPE_BY_KIND["source_csv"],
                    "method": METHOD_BY_KIND["source_csv"],
                    "path": f"captures/{prefix}.csv",
                    "redaction": "none",
                },
            )
        )
        captures.append(
            {
                "capture_id": f"REPLACE_WITH_{prefix.upper()}_CAPTURE_ID",
                "k210cap_evidence_id": ids["artifact"],
                "mapping_evidence_id": ids["map"],
                "source_csv_evidence_ids": [ids["csv"]],
                "state": state,
            }
        )
    return {
        "actions_performed": dict(ACTIONS_PERFORMED),
        "admission_class": ADMISSION_CLASS,
        "authorization": {
            "authorized_actions": sorted(CAPTURE_ACTIONS),
            "operator_reference": "REPLACE_WITH_EXACT_CAPTURE_AUTHORIZATION",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T02:00:00Z",
        },
        "campaign_id": "REPLACE_WITH_CAPTURE_CAMPAIGN_ID",
        "captures": captures,
        "completed_at_utc": "2026-01-01T01:30:00Z",
        "discovery_receipt_id": discovered["receipt_id"],
        "evidence": evidence,
        "fixture_evidence_set_sha256": qualified["fixture_evidence_set_sha256"],
        "fixture_receipt_id": qualified["receipt_id"],
        "kind": DESCRIPTOR_KIND,
        "operator_id": "REPLACE_WITH_CAPTURE_OPERATOR",
        "reviewer_id": "REPLACE_WITH_CAPTURE_REVIEWER",
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "started_at_utc": "2026-01-01T00:30:00Z",
        "stock_aup_sha256": profile["aup_sha256"],
        "target_id": discovered["target_id"],
        "unit_fingerprint_sha256": discovered["unit_fingerprint_sha256"],
        "unit_label": discovered["unit_label"],
        "variant_profile_id": variants[0]["profile_id"],
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
    template.add_argument("--fixture-receipt", type=Path, required=True)
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
    if path.exists() or path.is_symlink():
        raise CaptureReceiptError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_manifest(args.manifest)
        if args.command == "template":
            descriptor = _template(
                manifest, args.discovery_receipt, args.fixture_receipt
            )
            _write_new_json(args.out, descriptor)
            print(f"K210_CAPTURE_TEMPLATE_WRITTEN target={descriptor['target_id']}")
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
                f"K210_CAPTURE_BUNDLE_CREATED target={receipt['target_id']} "
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
    except (CaptureReceiptError, fixture.FixtureError) as exc:
        print(f"K210_CAPTURE_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
