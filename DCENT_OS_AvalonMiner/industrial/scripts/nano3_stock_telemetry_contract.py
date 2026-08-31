#!/usr/bin/env python3
"""Offline compiler/validator for the held stock Nano 3 telemetry contract.

This module never opens a socket and has no subprocess, mutation, fan, UART,
watchdog, flash, reboot, or target-control path.  It promotes a field only from
an exact, hash-bound raw response in a source bundle.  Prose summaries and
synthetic fixtures remain explicitly non-authoritative.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


SOURCE_SCHEMA = "dcent.nano3.stock-telemetry-source-bundle.v1"
CONTRACT_SCHEMA = "dcent.nano3.stock-telemetry-contract.v1"
CAPTURE_REQUEST_SCHEMA = "dcent.nano3.stock-telemetry-capture-request.v1"
PURPOSE = "stock_nano3_attended_soak_telemetry_contract_only"
TARGET_MODEL = "canaan-avalon-nano3-non-s"
HELD_BTCMINER_SHA256 = (
    "e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751"
)
EXPECTED_COMMANDS = ("version", "summary", "stats", "devs", "pools", "lcd")
EXPECTED_CAPTURE_SEQUENCE = tuple(
    (round_number, command)
    for round_number in (1, 2)
    for command in EXPECTED_COMMANDS
)
READ_CODES = {
    "version": 22,
    "summary": 11,
    "stats": 70,
    "devs": 9,
    "pools": 7,
    "lcd": 125,
}
PAYLOAD_KEYS = {
    "version": "VERSION",
    "summary": "SUMMARY",
    "stats": "STATS",
    "devs": "DEVS",
    "pools": "POOLS",
    "lcd": "LCD",
}
SUMMARY_POINTERS = {
    "mhs_5s": "/SUMMARY/0/MHS 5s",
    "accepted": "/SUMMARY/0/Accepted",
    "rejected": "/SUMMARY/0/Rejected",
    "hardware_errors": "/SUMMARY/0/Hardware Errors",
}
MAX_JSON_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,95}$")
MM_INTEGER_FIELDS = frozenset(
    {"Temp", "OTemp", "TMax", "TAvg", "TarT", "Fan1", "HW", "DHW", "SoftOFF"}
)
MM_REQUIRED_SENSOR_FIELDS = ("Temp", "OTemp", "TMax", "TAvg", "Fan1", "FanR")


class ContractError(RuntimeError):
    """Fail-closed source, contract, or runtime validation error."""


def _duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


def strict_json_loads(text: str, label: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_key,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {token}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed {label}: {exc}") from exc


def canonical_json(document: Any) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii") + b"\n"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encode_request(command: str) -> bytes:
    if command not in EXPECTED_COMMANDS:
        raise ContractError(f"unsupported capture command {command!r}")
    return canonical_json({"command": command}).rstrip(b"\n") + b"\x00"


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        raise ContractError(
            f"{label} keys mismatch; missing={sorted(expected-observed)}, "
            f"unknown={sorted(observed-expected)}"
        )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    return value


def _text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ContractError(f"{label} must be a nonempty string")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractError(f"{label} must be lowercase SHA-256")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractError(f"{label} must be RFC3339 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{label} is not valid RFC3339 UTC") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{label} lacks a timezone")
    return parsed


def read_bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ContractError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContractError(f"{label} must be a non-symlink regular file")
    if before.st_size > maximum:
        raise ContractError(f"{label} exceeds {maximum} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum:
                raise ContractError(f"opened {label} is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ContractError(f"cannot read {label}: {exc}") from exc
    if len(raw) > maximum:
        raise ContractError(f"{label} exceeds {maximum} bytes")
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ContractError(f"{label} changed while read")
    return raw


def decode_response(raw: bytes, command: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ContractError("CGMiner response is empty or oversized")
    first_nul = raw.find(b"\x00")
    if first_nul < 0 or any(byte != 0 for byte in raw[first_nul:]):
        raise ContractError("CGMiner response must be one JSON object followed only by NULs")
    payload = raw[:first_nul]
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ContractError("CGMiner response is not UTF-8") from exc
    document = strict_json_loads(text, f"{command} response")
    if not isinstance(document, dict):
        raise ContractError("CGMiner response root must be an object")
    statuses = document.get("STATUS")
    if not isinstance(statuses, list) or len(statuses) != 1 or not isinstance(statuses[0], dict):
        raise ContractError("CGMiner response must contain exactly one STATUS object")
    status_entry = statuses[0]
    if status_entry.get("STATUS") != "S":
        raise ContractError("CGMiner response STATUS is not exact success")
    code = status_entry.get("Code")
    when = status_entry.get("When")
    response_id = document.get("id")
    if isinstance(code, bool) or not isinstance(code, int) or code != READ_CODES[command]:
        raise ContractError("CGMiner response status Code mismatch")
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        raise ContractError("CGMiner STATUS.When must be a nonnegative integer")
    if isinstance(response_id, bool) or not isinstance(response_id, int) or response_id != 1:
        raise ContractError("CGMiner response id must be exact integer 1")
    key = PAYLOAD_KEYS[command]
    payload_value = document.get(key)
    if not isinstance(payload_value, list) or not payload_value:
        raise ContractError(f"CGMiner {key} payload must be a nonempty list")
    return document


def parse_mm_status(raw: str) -> dict[str, str]:
    """Parse one exact flat stock ``KEY[value]`` status string.

    The held binary emits flat bracket fields.  Nested brackets, truncation,
    duplicate keys, junk between fields, and empty keys are ambiguous and are
    rejected rather than repaired.
    """

    if not isinstance(raw, str) or not raw.strip() or len(raw.encode("utf-8")) > 65536:
        raise ContractError("MM ID0 status must be a bounded nonempty string")
    out: dict[str, str] = {}
    position = 0
    length = len(raw)
    while position < length:
        while position < length and raw[position].isspace():
            position += 1
        if position == length:
            break
        opening = raw.find("[", position)
        if opening <= position:
            raise ContractError("MM status has junk or an empty key")
        key = raw[position:opening].strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            raise ContractError(f"MM status key is not exact ASCII token: {key!r}")
        closing = raw.find("]", opening + 1)
        if closing < 0 or "[" in raw[opening + 1 : closing]:
            raise ContractError(f"MM status field {key!r} is truncated or nested")
        value = raw[opening + 1 : closing]
        if key in out:
            raise ContractError(f"MM status contains duplicate field {key!r}")
        out[key] = value
        position = closing + 1
        if position < length and not raw[position].isspace():
            raise ContractError("MM status fields are not whitespace separated")
    return out


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a nonnegative integer")
    return value


def _finite_nonnegative(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ContractError(f"{label} must be finite and nonnegative")
    return result


def _validate_mm_sensor_fields(fields: Mapping[str, str]) -> dict[str, Any]:
    present: dict[str, Any] = {}
    for name in MM_REQUIRED_SENSOR_FIELDS:
        if name not in fields:
            continue
        value = fields[name]
        if name == "FanR":
            match = re.fullmatch(r"([0-9]{1,3})%", value)
            if not match or not 0 <= int(match.group(1)) <= 100:
                raise ContractError("MM FanR has ambiguous/non-percent units")
            present[name] = int(match.group(1))
        else:
            if not re.fullmatch(r"-?[0-9]+", value):
                raise ContractError(f"MM {name} is not exact integer text")
            parsed = int(value)
            if name == "Fan1":
                if not 0 <= parsed <= 100000:
                    raise ContractError("MM Fan1 RPM is outside structural bounds")
            elif not -273 <= parsed <= 250:
                raise ContractError(f"MM {name} temperature is outside structural bounds")
            present[name] = parsed
    return present


def _validate_source_bundle_document(bundle: Any) -> Mapping[str, Any]:
    bundle = _mapping(bundle, "source bundle")
    _exact_keys(
        bundle,
        {"schema", "purpose", "bundle_id", "provenance", "target", "capture", "responses"},
        "source bundle",
    )
    if bundle.get("schema") != SOURCE_SCHEMA or bundle.get("purpose") != PURPOSE:
        raise ContractError("source bundle schema/purpose mismatch")
    bundle_id = _text(bundle.get("bundle_id"), "bundle_id", 8)
    if not ID_RE.fullmatch(bundle_id):
        raise ContractError("bundle_id has invalid shape")
    if bundle.get("provenance") not in {
        "operator_attested_live_raw_unsigned",
        "synthetic_fixture",
    }:
        raise ContractError(
            "source provenance must be operator_attested_live_raw_unsigned or synthetic_fixture"
        )
    target = _mapping(bundle.get("target"), "target")
    _exact_keys(
        target,
        {
            "model",
            "btcminer_sha256",
            "expected_version_fields",
            "identity_receipt_path",
            "identity_receipt_sha256",
        },
        "target",
    )
    if target.get("model") != TARGET_MODEL or target.get("btcminer_sha256") != HELD_BTCMINER_SHA256:
        raise ContractError("source target/btcminer identity mismatch")
    _sha(target.get("identity_receipt_sha256"), "target.identity_receipt_sha256")
    _text(target.get("identity_receipt_path"), "target.identity_receipt_path")
    version = _mapping(target.get("expected_version_fields"), "expected_version_fields")
    _exact_keys(version, {"CGMiner", "VERSION", "PROD"}, "expected_version_fields")
    for key in version:
        _text(version[key], f"expected_version_fields.{key}")
    capture = _mapping(bundle.get("capture"), "capture")
    _exact_keys(
        capture,
        {
            "capture_id",
            "started_at_utc",
            "ended_at_utc",
            "one_connection_per_command",
            "request_framing",
            "response_framing",
            "raw_response_bytes_retained",
            "capture_receipt_path",
            "capture_receipt_sha256",
        },
        "capture",
    )
    capture_id = _text(capture.get("capture_id"), "capture_id", 8)
    if not ID_RE.fullmatch(capture_id):
        raise ContractError("capture_id has invalid shape")
    started = _utc(capture.get("started_at_utc"), "capture.started_at_utc")
    ended = _utc(capture.get("ended_at_utc"), "capture.ended_at_utc")
    if ended < started or (ended - started).total_seconds() > 600:
        raise ContractError("capture time window is reversed or exceeds ten minutes")
    if capture.get("one_connection_per_command") is not True:
        raise ContractError("capture must bind one connection per command")
    if capture.get("request_framing") != "minified_json_plus_one_nul":
        raise ContractError("capture request framing mismatch")
    if capture.get("response_framing") != "one_json_object_then_nuls_read_to_eof":
        raise ContractError("capture response framing mismatch")
    if capture.get("raw_response_bytes_retained") is not True:
        raise ContractError("source bundle did not retain raw response bytes")
    _sha(capture.get("capture_receipt_sha256"), "capture.capture_receipt_sha256")
    _text(capture.get("capture_receipt_path"), "capture.capture_receipt_path")
    responses = bundle.get("responses")
    if not isinstance(responses, list) or len(responses) != len(EXPECTED_CAPTURE_SEQUENCE):
        raise ContractError("source bundle needs exactly two complete six-command rounds")
    return bundle


def compile_bundle(bundle_path: Path) -> dict[str, Any]:
    bundle_raw = read_bounded_regular(bundle_path, MAX_JSON_BYTES, "source bundle")
    try:
        bundle_doc = strict_json_loads(bundle_raw.decode("utf-8"), "source bundle")
    except UnicodeError as exc:
        raise ContractError("source bundle is not UTF-8") from exc
    bundle = _validate_source_bundle_document(bundle_doc)
    receipt_pins: dict[str, dict[str, Any]] = {}
    for label, section, path_key, hash_key in (
        (
            "target identity receipt",
            bundle["target"],
            "identity_receipt_path",
            "identity_receipt_sha256",
        ),
        (
            "capture receipt",
            bundle["capture"],
            "capture_receipt_path",
            "capture_receipt_sha256",
        ),
    ):
        receipt_path = Path(str(section[path_key]))
        if not receipt_path.is_absolute():
            receipt_path = bundle_path.parent / receipt_path
        receipt_raw = read_bounded_regular(receipt_path, MAX_JSON_BYTES, label)
        if sha256_bytes(receipt_raw) != section[hash_key]:
            raise ContractError(f"{label} SHA-256 mismatch")
        receipt_pins[label] = {
            "bytes": len(receipt_raw),
            "sha256": sha256_bytes(receipt_raw),
        }
    response_records: list[dict[str, Any]] = []
    documents: dict[str, list[dict[str, Any]]] = {
        command: [] for command in EXPECTED_COMMANDS
    }
    seen_pairs: set[tuple[int, str]] = set()
    prior_capture_time: Optional[datetime] = None
    capture_started = _utc(bundle["capture"]["started_at_utc"], "capture.started_at_utc")
    capture_ended = _utc(bundle["capture"]["ended_at_utc"], "capture.ended_at_utc")
    for index, item_value in enumerate(bundle["responses"]):
        item = _mapping(item_value, f"responses[{index}]")
        _exact_keys(
            item,
            {
                "sequence",
                "round",
                "command",
                "captured_at_utc",
                "request_bytes",
                "request_sha256",
                "response_path",
                "response_bytes",
                "response_sha256",
            },
            f"responses[{index}]",
        )
        if item.get("sequence") != index + 1:
            raise ContractError("response sequence must be exact contiguous order")
        round_number = item.get("round")
        command = item.get("command")
        expected_round, expected_command = EXPECTED_CAPTURE_SEQUENCE[index]
        pair = (round_number, command)
        if pair in seen_pairs or pair != (expected_round, expected_command):
            raise ContractError("response round/command order is duplicated or mismatched")
        seen_pairs.add(pair)
        captured = _utc(item.get("captured_at_utc"), f"responses[{index}].captured_at_utc")
        if captured < capture_started or captured > capture_ended:
            raise ContractError("response timestamp is outside the declared capture window")
        if prior_capture_time is not None and captured < prior_capture_time:
            raise ContractError("response capture timestamps regress")
        prior_capture_time = captured
        expected_request = encode_request(command)
        if item.get("request_bytes") != len(expected_request) or item.get("request_sha256") != sha256_bytes(expected_request):
            raise ContractError(f"{command} request bytes/hash mismatch")
        response_path_text = _text(item.get("response_path"), "response_path")
        response_path = Path(response_path_text)
        if not response_path.is_absolute():
            response_path = bundle_path.parent / response_path
        raw_response = read_bounded_regular(response_path, MAX_RESPONSE_BYTES, f"{command} raw response")
        expected_size = item.get("response_bytes")
        if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size != len(raw_response):
            raise ContractError(f"{command} response byte count mismatch")
        expected_hash = _sha(item.get("response_sha256"), f"{command}.response_sha256")
        if sha256_bytes(raw_response) != expected_hash:
            raise ContractError(f"{command} response SHA-256 mismatch")
        documents[command].append(decode_response(raw_response, command))
        response_records.append(
            {
                "sequence": index + 1,
                "round": round_number,
                "command": command,
                "captured_at_utc": item["captured_at_utc"],
                "request_bytes": len(expected_request),
                "request_sha256": sha256_bytes(expected_request),
                "response_bytes": len(raw_response),
                "response_sha256": expected_hash,
            }
        )

    version_expected = bundle["target"]["expected_version_fields"]
    for document in documents["version"]:
        version_entries = document["VERSION"]
        if len(version_entries) != 1 or not isinstance(version_entries[0], dict):
            raise ContractError("VERSION must contain exactly one object")
        if any(version_entries[0].get(key) != value for key, value in version_expected.items()):
            raise ContractError("raw VERSION fields do not bind the expected target identity")

    accepted_values: list[int] = []
    for document in documents["summary"]:
        summary = document["SUMMARY"]
        if len(summary) != 1 or not isinstance(summary[0], dict):
            raise ContractError("SUMMARY must contain exactly one object")
        _finite_nonnegative(summary[0].get("MHS 5s"), "SUMMARY.MHS 5s")
        for field in ("Accepted", "Rejected", "Hardware Errors"):
            value = _nonnegative_int(summary[0].get(field), f"SUMMARY.{field}")
            if field == "Accepted":
                accepted_values.append(value)
    if accepted_values[1] < accepted_values[0]:
        raise ContractError("SUMMARY Accepted counter regressed across capture rounds")

    round_sensor_values: list[dict[str, Any]] = []
    for document in documents["stats"]:
        stats = document["STATS"]
        stats_entry = stats[0] if len(stats) == 1 and isinstance(stats[0], dict) else None
        if stats_entry is None:
            raise ContractError("STATS must contain exactly one object")
        mm_count = stats_entry.get("MM Count")
        if isinstance(mm_count, bool) or not isinstance(mm_count, int) or mm_count != 1:
            raise ContractError("held Nano 3 contract requires exact MM Count integer 1")
        mm_raw = stats_entry.get("MM ID0")
        if not isinstance(mm_raw, str):
            raise ContractError("STATS lacks exact MM ID0 string")
        round_sensor_values.append(_validate_mm_sensor_fields(parse_mm_status(mm_raw)))
    sensor_coverage = all(
        all(name in values for name in MM_REQUIRED_SENSOR_FIELDS)
        for values in round_sensor_values
    )

    pool_fields = True
    for document in documents["pools"]:
        pools = document["POOLS"]
        pool_fields = pool_fields and bool(pools) and all(
            isinstance(entry, dict)
            and isinstance(entry.get("POOL"), int)
            and not isinstance(entry.get("POOL"), bool)
            and isinstance(entry.get("URL"), str)
            and isinstance(entry.get("User"), str)
            for entry in pools
        )
    lcd_fields = True
    for document in documents["lcd"]:
        lcd = document["LCD"]
        lcd_fields = lcd_fields and (
            len(lcd) == 1
            and isinstance(lcd[0], dict)
            and isinstance(lcd[0].get("Current Pool"), str)
            and isinstance(lcd[0].get("User"), str)
        )
    raw_bytes_observed = bundle["provenance"] == "operator_attested_live_raw_unsigned"
    observed_fields = {
        "summary_mhs_5s": raw_bytes_observed,
        "summary_accepted_rejected_hardware_errors": raw_bytes_observed,
        "stats_mm_id0_required_field_tokens": raw_bytes_observed and sensor_coverage,
        "pools_url_user": raw_bytes_observed and pool_fields,
        "lcd_current_pool_user": raw_bytes_observed and lcd_fields,
    }
    capabilities = {
        "mhs_5s_mh_per_second": False,
        "accepted_counter": False,
        "rejected_counter": False,
        "hardware_error_counter": False,
        "board_inlet_temperature_c": False,
        "board_outlet_temperature_c": False,
        "die_max_temperature_c": False,
        "die_average_temperature_c": False,
        "fan_1_rpm": False,
        "fan_command_percent": False,
        "all_required_temperature_sensors_covered": False,
        "stock_auto_mode_observable": False,
        "source_sensor_sample_freshness_observable": False,
        "current_pool_and_user": False,
        "lcd_pool_and_user_corroboration": False,
    }
    blockers = []
    if not raw_bytes_observed:
        blockers.append("synthetic_fixture_is_not_authentic_live_provenance")
    else:
        blockers.append("operator_attested_raw_capture_has_no_independent_signed_source_authority")
    if not sensor_coverage:
        blockers.append("raw_stats_missing_required_board_die_or_fan_fields")
    blockers.extend(
        [
            "stock_auto_mode_has_no_proven_read_only_response_field",
            "stock_sensor_values_have_no_proven_source_sample_timestamp",
        ]
    )
    contract = {
        "schema": CONTRACT_SCHEMA,
        "purpose": PURPOSE,
        "contract_id": f"{bundle['bundle_id']}.compiled-v1",
        "authority": "none; this receipt grants no contact or live action",
        "provenance": bundle["provenance"],
        "source_bundle_sha256": sha256_bytes(bundle_raw),
        "target": dict(bundle["target"]),
        "capture": dict(bundle["capture"]),
        "receipt_pins": receipt_pins,
        "source_responses": response_records,
        "observed_fields_non_load_bearing": observed_fields,
        "static_semantics": {
            "btcminer_sha256": HELD_BTCMINER_SHA256,
            "stats_payload": "STATS[0].MM ID0 flat KEY[value] string",
            "temperature_units": "stock_format_integer_reported_temperature; physical_sensor_join_not_admitted",
            "fan_1_units": "stock_format_integer_reported_fan_value; rpm_semantics_require_reviewed_join",
            "fan_r_units": "integer_percent_with_percent_suffix",
            "summary_mhs_5s_units": "megahashes_per_second",
            "status_when_semantics": "response_generation_epoch_only_not_sensor_sample_time",
            "generic_devs_temperature_supported": False,
        },
        "runtime_mapping": {
            "mode": "stock_mm_id0_unverified_v1" if raw_bytes_observed else "synthetic_not_live_usable",
            "summary_pointers": dict(SUMMARY_POINTERS),
            "stats_object_pointer": "/STATS/0",
            "module_count_field": "MM Count",
            "module_status_field": "MM ID0",
            "temperature_fields": ["Temp", "OTemp", "TMax", "TAvg"],
            "fan_rpm_fields": ["Fan1"],
            "fan_command_percent_field": "FanR",
            "auto_mode_field": None,
            "sensor_sample_epoch_field": None,
        },
        "capabilities": capabilities,
        "soak_runtime_ready": False,
        "blockers": blockers,
        "synthetic_values_can_authorize_live": False,
    }
    validate_contract_document(contract, live=False, allow_blocked=True)
    return contract


def fixture_contract(
    *, temperature_pointers: Sequence[str], fan_rpm_pointers: Sequence[str],
    auto_mode_pointer: str, sensor_sample_epoch_pointer: str,
) -> dict[str, Any]:
    """Return a test-only contract that can be consumed only in fixture mode."""

    return {
        "schema": CONTRACT_SCHEMA,
        "purpose": PURPOSE,
        "contract_id": "fixture-only-stock-telemetry-contract-v1",
        "authority": "none; synthetic fixture only",
        "provenance": "synthetic_fixture",
        "source_bundle_sha256": "0" * 64,
        "target": {
            "model": TARGET_MODEL,
            "btcminer_sha256": HELD_BTCMINER_SHA256,
            "expected_version_fields": {
                "CGMiner": "fixture-cgminer",
                "VERSION": "fixture-version",
                "PROD": "fixture-product",
            },
            "identity_receipt_path": "fixture-only",
            "identity_receipt_sha256": "0" * 64,
        },
        "capture": {
            "capture_id": "fixture-capture-v1",
            "started_at_utc": "2000-01-01T00:00:00Z",
            "ended_at_utc": "2000-01-01T00:00:01Z",
            "one_connection_per_command": True,
            "request_framing": "minified_json_plus_one_nul",
            "response_framing": "one_json_object_then_nuls_read_to_eof",
            "raw_response_bytes_retained": True,
            "capture_receipt_path": "fixture-only",
            "capture_receipt_sha256": "0" * 64,
        },
        "receipt_pins": {
            "target identity receipt": {"bytes": 0, "sha256": "0" * 64},
            "capture receipt": {"bytes": 0, "sha256": "0" * 64},
        },
        "source_responses": [],
        "observed_fields_non_load_bearing": {
            "summary_mhs_5s": False,
            "summary_accepted_rejected_hardware_errors": False,
            "stats_mm_id0_required_field_tokens": False,
            "pools_url_user": False,
            "lcd_current_pool_user": False,
        },
        "static_semantics": {
            "btcminer_sha256": HELD_BTCMINER_SHA256,
            "stats_payload": "fixture_only",
            "temperature_units": "fixture_declared_celsius",
            "fan_1_units": "fixture_declared_rpm",
            "fan_r_units": "fixture_declared_percent",
            "summary_mhs_5s_units": "fixture_declared_megahashes_per_second",
            "status_when_semantics": "fixture_only",
            "generic_devs_temperature_supported": False,
        },
        "runtime_mapping": {
            "mode": "fixture_json_pointers_v1",
            "summary_pointers": dict(SUMMARY_POINTERS),
            "temperature_pointers": list(temperature_pointers),
            "fan_rpm_pointers": list(fan_rpm_pointers),
            "auto_mode_pointer": auto_mode_pointer,
            "sensor_sample_epoch_pointer": sensor_sample_epoch_pointer,
        },
        "capabilities": {
            key: False
            for key in (
                "mhs_5s_mh_per_second",
                "accepted_counter",
                "rejected_counter",
                "hardware_error_counter",
                "board_inlet_temperature_c",
                "board_outlet_temperature_c",
                "die_max_temperature_c",
                "die_average_temperature_c",
                "fan_1_rpm",
                "fan_command_percent",
                "all_required_temperature_sensors_covered",
                "stock_auto_mode_observable",
                "source_sensor_sample_freshness_observable",
                "current_pool_and_user",
                "lcd_pool_and_user_corroboration",
            )
        },
        "soak_runtime_ready": True,
        "blockers": ["synthetic_fixture_is_not_authentic_live_provenance"],
        "synthetic_values_can_authorize_live": False,
    }


CONTRACT_KEYS = {
    "schema", "purpose", "contract_id", "authority", "provenance",
    "source_bundle_sha256", "target", "capture", "source_responses",
    "receipt_pins", "observed_fields_non_load_bearing", "static_semantics",
    "runtime_mapping", "capabilities", "soak_runtime_ready", "blockers",
    "synthetic_values_can_authorize_live",
}


def validate_contract_document(
    document: Any, *, live: bool, allow_blocked: bool = False
) -> Mapping[str, Any]:
    contract = _mapping(document, "telemetry contract")
    _exact_keys(contract, CONTRACT_KEYS, "telemetry contract")
    if contract.get("schema") != CONTRACT_SCHEMA or contract.get("purpose") != PURPOSE:
        raise ContractError("telemetry contract schema/purpose mismatch")
    _text(contract.get("contract_id"), "contract_id", 8)
    _text(contract.get("authority"), "authority", 8)
    if contract.get("synthetic_values_can_authorize_live") is not False:
        raise ContractError("contract must deny synthetic live authority")
    _sha(contract.get("source_bundle_sha256"), "source_bundle_sha256")
    target = _mapping(contract.get("target"), "target")
    if target.get("model") != TARGET_MODEL or target.get("btcminer_sha256") != HELD_BTCMINER_SHA256:
        raise ContractError("contract target/btcminer binding mismatch")
    mapping = _mapping(contract.get("runtime_mapping"), "runtime_mapping")
    if mapping.get("summary_pointers") != SUMMARY_POINTERS:
        raise ContractError("contract summary pointers mismatch exact stock contract")
    provenance = contract.get("provenance")
    ready = contract.get("soak_runtime_ready")
    if not isinstance(ready, bool):
        raise ContractError("soak_runtime_ready must be boolean")
    blockers = contract.get("blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise ContractError("contract blockers must be a string list")
    if live:
        if provenance != "operator_attested_live_raw_unsigned":
            raise ContractError("live runner rejects fixture/prose telemetry provenance")
        if mapping.get("mode") != "stock_mm_id0_unverified_v1":
            raise ContractError("live contract extraction mode mismatch")
        raise ContractError(
            "contract v1 cannot authorize live use: source authority, AUTO, and source freshness are unproven"
        )
    else:
        if provenance == "synthetic_fixture":
            permitted_fixture_modes = {"fixture_json_pointers_v1"}
            if allow_blocked:
                permitted_fixture_modes.add("synthetic_not_live_usable")
            if mapping.get("mode") not in permitted_fixture_modes:
                raise ContractError("fixture contract extraction mode mismatch")
        elif (
            provenance == "operator_attested_live_raw_unsigned"
            and mapping.get("mode") != "stock_mm_id0_unverified_v1"
        ):
            raise ContractError("operator-attested contract extraction mode mismatch")
        else:
            if provenance not in {
                "synthetic_fixture",
                "operator_attested_live_raw_unsigned",
            }:
                raise ContractError("contract provenance is unknown")
        if not ready and not allow_blocked:
            raise ContractError("telemetry contract is not soak-runtime-ready")
    return contract


def load_contract(path: Path, expected_sha256: str, *, live: bool) -> Mapping[str, Any]:
    _sha(expected_sha256, "contract receipt SHA-256")
    raw = read_bounded_regular(path, MAX_JSON_BYTES, "telemetry contract receipt")
    if sha256_bytes(raw) != expected_sha256:
        raise ContractError("telemetry contract receipt SHA-256 mismatch")
    try:
        document = strict_json_loads(raw.decode("utf-8"), "telemetry contract receipt")
    except UnicodeError as exc:
        raise ContractError("telemetry contract receipt is not UTF-8") from exc
    return validate_contract_document(document, live=live)


def _resolve_pointer(document: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ContractError("fixture JSON pointer is invalid")
    current = document
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            raise ContractError(f"fixture JSON pointer is missing: {pointer}")
    return current


def validate_fixture_runtime_sample(
    contract: Mapping[str, Any], stats: Mapping[str, Any], devs: Mapping[str, Any],
    *, now_epoch: float, freshness_seconds: float, previous_sample_epoch: Optional[float],
) -> tuple[float, list[float], float]:
    """Validate the existing synthetic runner shape, never a live stock sample."""

    validate_contract_document(contract, live=False)
    if contract.get("provenance") != "synthetic_fixture":
        raise ContractError("fixture runtime validator rejects non-fixture contract")
    merged = {"stats": stats, "devs": devs}
    mapping = contract["runtime_mapping"]
    temperatures = [
        _finite_number(_resolve_pointer(merged, pointer), "fixture temperature")
        for pointer in mapping["temperature_pointers"]
    ]
    rpms = [
        _finite_number(_resolve_pointer(merged, pointer), "fixture fan RPM")
        for pointer in mapping["fan_rpm_pointers"]
    ]
    if not temperatures or not rpms:
        raise ContractError("fixture contract lacks temperature/fan coverage")
    if _resolve_pointer(merged, mapping["auto_mode_pointer"]) != "AUTO":
        raise ContractError("fixture fan mode is not exact AUTO")
    epoch = _finite_number(
        _resolve_pointer(merged, mapping["sensor_sample_epoch_pointer"]),
        "fixture sensor epoch",
    )
    if epoch > now_epoch:
        raise ContractError("fixture sensor sample is from the future")
    if now_epoch - epoch > freshness_seconds:
        raise ContractError("fixture sensor sample is stale")
    if previous_sample_epoch is not None and epoch <= previous_sample_epoch:
        raise ContractError("fixture sensor sample replayed or did not advance")
    return max(temperatures), rpms, epoch


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ContractError(f"{label} is not finite")
    return result


def capture_request() -> dict[str, Any]:
    requests = []
    sequence = 0
    # Two rounds are the minimum useful raw capture for cross-sample checks;
    # they still cannot establish source-sensor freshness or AUTO mode.
    for round_number in (1, 2):
        for command in EXPECTED_COMMANDS:
            sequence += 1
            raw = encode_request(command)
            requests.append(
                {
                    "sequence": sequence,
                    "round": round_number,
                    "command": command,
                    "request_base64": base64.b64encode(raw).decode("ascii"),
                    "request_bytes": len(raw),
                    "request_sha256": sha256_bytes(raw),
                }
            )
    return {
        "schema": CAPTURE_REQUEST_SCHEMA,
        "purpose": PURPOSE,
        "authority": "none; operator review and separate live authorization required",
        "target": {"model": TARGET_MODEL, "btcminer_sha256": HELD_BTCMINER_SHA256},
        "transport": {
            "one_tcp_connection_per_command": True,
            "request_framing": "minified_json_plus_one_nul",
            "response_framing": "read_to_eof_then_one_json_object_then_nuls",
            "hard_connect_read_total_timeouts_required": True,
            "raw_bytes_and_host_utc_monotonic_timestamps_required": True,
        },
        "requests": requests,
        "also_required": [
            "exact VERSION target fields and independent held btcminer SHA-256 receipt",
            "raw response bytes before redaction; credentials remain protected",
            "capture receipt binding target, binary, request/response hashes, sizes, order, and times",
            "reviewed read-only evidence for actual AUTO-mode state (no stock API field is currently proven)",
            "reviewed source-sample freshness for die/board/fan values (STATUS.When is response time only)",
            "evidence that MM Count and every required die/board sensor are covered",
        ],
        "known_non_solutions": [
            "R3 prose summaries are not raw response bytes",
            "DEVS Temperature=0 is invalid for the held stock target",
            "FanR percent does not prove AUTO rather than manual mode",
            "STATUS.When does not timestamp the underlying sensor samples",
            "stock 90 C PID target is not a safety limit",
        ],
        "telemetry_authorization_a_status": "NO_GO",
    }


def _write_new(path: Path, raw: bytes) -> None:
    """Write a new draft completely and sync its file contents.

    The output is deliberately not a durable authorization receipt: parent
    directory persistence and source authority remain outside this compiler.
    """

    if path.exists():
        raise ContractError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise ContractError("output parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise ContractError("output write made no forward progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    compile_parser = sub.add_parser("compile", help="compile a hash-bound offline source bundle")
    compile_parser.add_argument("--source-bundle", required=True, type=Path)
    compile_parser.add_argument("--output", required=True, type=Path)
    validate_parser = sub.add_parser("validate-contract", help="validate a contract without contact")
    validate_parser.add_argument("--contract", required=True, type=Path)
    validate_parser.add_argument("--sha256", required=True)
    validate_parser.add_argument("--live", action="store_true")
    request_parser = sub.add_parser("capture-request", help="emit the exact missing capture request")
    request_parser.add_argument("--output", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "compile":
            contract = compile_bundle(args.source_bundle)
            raw = canonical_json(contract)
            _write_new(args.output, raw)
            print(
                f"COMPILED_DRAFT sha256={sha256_bytes(raw)} "
                "soak_runtime_ready=false durable_authority_receipt=false"
            )
        elif args.command == "validate-contract":
            load_contract(args.contract, args.sha256, live=args.live)
            print("VALID fixture-only" if not args.live else "VALID live")
        else:
            raw = canonical_json(capture_request())
            if args.output:
                _write_new(args.output, raw)
                print(
                    f"CAPTURE_REQUEST_DRAFT sha256={sha256_bytes(raw)} "
                    "authorization_a=NO_GO durable_authority_receipt=false"
                )
            else:
                sys.stdout.buffer.write(raw)
        return 0
    except ContractError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
