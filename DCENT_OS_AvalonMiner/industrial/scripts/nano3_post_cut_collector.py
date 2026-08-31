#!/usr/bin/env python3
"""Compile a bounded Nano 3 external post-cut observation receipt.

This tool is deliberately file-only. It opens no network endpoint or hardware
device and does not perform, request, or authorize a power cut. A passing
receipt proves only that the supplied, independently acquired evidence obeys
one reviewed session plan. It never grants Authorization A, production safety,
interlock qualification, energization, flash, or reboot authority.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PLAN_SCHEMA = "dcent.nano3.post-cut-plan.v2"
ACK_SCHEMA = "dcent.nano3.post-cut-ack.v2"
ADAPTER_ENVELOPE_SCHEMA = "dcent.nano3.post-cut-adapter-envelope.v1"
RECEIPT_SCHEMA = "dcent.nano3.post-cut-receipt.v2"
TEMPLATE_STATUS = "TEMPLATE_NOT_QUALIFIED"
APPROVED_STATUS = "APPROVED_FOR_ONE_ATTENDED_SESSION"
ACTION = "manual_whole_unit_ac_disconnect"
MAX_INPUT_BYTES = 1_048_576
MAX_SAMPLE_ROWS = 10_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
NUMBER_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
CSV_COLUMNS = [
    "sequence",
    "monotonic_ms",
    "captured_at_utc",
    "sensor_asset_record_sha256",
    "meter_asset_record_sha256",
    "temperature_c",
    "wall_w",
    "input_voltage_v",
    "fan_supply_voltage_v",
    "api_supply_voltage_v",
]
FALSE_CLAIMS = {
    "authorization_a_granted",
    "cut_action_performed_by_collector",
    "energization_authorized",
    "hardware_contact_performed_by_collector",
    "independent_interlock_qualified",
    "production_authority_granted",
    "reenergization_authorized",
    "unattended_operation_authorized",
}


class ValidationError(ValueError):
    """Raised when an input fails the fail-closed contract."""


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"{label} unavailable: {exc.__class__.__name__}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a non-symlink regular file")
    if before.st_size <= 0 or before.st_size > MAX_INPUT_BYTES:
        fail(f"{label} size is outside 1..{MAX_INPUT_BYTES}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        fail(f"{label} open failed: {exc.__class__.__name__}")
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            fail(f"{label} changed type during open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, MAX_INPUT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                fail(f"{label} exceeds size bound while reading")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        before.st_dev != opened.st_dev
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
    raw = read_regular(path, label)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{label} must be UTF-8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        fail(f"{label} is invalid JSON at line {exc.lineno} column {exc.colno}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value, raw


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{label} key mismatch missing={missing} extra={extra}")


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def exact_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        fail(f"{label} must be {str(expected).lower()}")


def token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        fail(f"{label} must be a bounded identifier")
    if value.startswith("REPLACE"):
        fail(f"{label} is still a placeholder")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum or result > maximum:
        fail(f"{label} is outside {minimum}..{maximum}")
    return result


def utc_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not a valid UTC timestamp")
    if parsed.tzinfo != timezone.utc:
        fail(f"{label} must be UTC")
    return parsed


def validate_plan(plan: dict[str, Any], *, require_approved: bool) -> dict[str, Any]:
    exact_keys(
        plan,
        {"schema", "status", "session", "sources", "envelope", "reviews", "claims"},
        "plan",
    )
    if plan.get("schema") != PLAN_SCHEMA:
        fail("plan schema mismatch")
    status = plan.get("status")
    if status not in {TEMPLATE_STATUS, APPROVED_STATUS}:
        fail("plan status is unknown")
    if require_approved and status != APPROVED_STATUS:
        fail("plan is not approved for one attended session")

    session = mapping(plan.get("session"), "session")
    exact_keys(
        session,
        {
            "session_id",
            "session_nonce_sha256",
            "authorization_ref",
            "authorized_from_utc",
            "authorized_until_utc",
            "exact_unit_fingerprint_sha256",
            "operator_public_key_sha256",
            "action",
        },
        "session",
    )
    sources = mapping(plan.get("sources"), "sources")
    exact_keys(sources, {"capture_adapter", "sensor", "wall_meter"}, "sources")
    adapter = mapping(sources.get("capture_adapter"), "sources.capture_adapter")
    sensor = mapping(sources.get("sensor"), "sources.sensor")
    meter = mapping(sources.get("wall_meter"), "sources.wall_meter")
    exact_keys(
        adapter,
        {
            "public_key_sha256",
            "identity_record_sha256",
            "channel_contract_record_sha256",
            "powered_independently_of_nano",
            "method",
        },
        "sources.capture_adapter",
    )
    sensor_keys = {
        "asset_record_sha256",
        "calibration_record_sha256",
        "placement_record_sha256",
        "identity_label",
        "powered_independently_of_nano",
        "role",
        "channel",
        "units",
        "coverage",
    }
    meter_keys = {
        "asset_record_sha256",
        "calibration_record_sha256",
        "channel_contract_record_sha256",
        "identity_label",
        "powered_independently_of_nano",
        "role",
        "channel",
        "units",
    }
    exact_keys(sensor, sensor_keys, "sources.sensor")
    exact_keys(meter, meter_keys, "sources.wall_meter")
    exact_bool(adapter.get("powered_independently_of_nano"), True, "adapter independent power")
    exact_bool(sensor.get("powered_independently_of_nano"), True, "sensor independent power")
    exact_bool(meter.get("powered_independently_of_nano"), True, "meter independent power")
    if adapter.get("method") != "signed_external_multichannel_export_v1":
        fail("capture adapter method mismatch")
    if sensor.get("role") != "external_hotspot_temperature":
        fail("sensor role mismatch")
    if sensor.get("channel") != "temperature_c" or sensor.get("units") != "degree_celsius":
        fail("sensor channel/units mismatch")
    if sensor.get("coverage") != "qualified_worst_case_hotspot_external":
        fail("sensor coverage is not the reviewed worst-case hotspot")
    if meter.get("role") != "whole_unit_input_power":
        fail("wall meter role mismatch")
    if meter.get("channel") != "wall_w" or meter.get("units") != "watt":
        fail("wall meter channel/units mismatch")

    envelope = mapping(plan.get("envelope"), "envelope")
    exact_keys(
        envelope,
        {
            "baseline_sample_count",
            "minimum_observation_seconds",
            "maximum_first_post_cut_delay_seconds",
            "maximum_sample_gap_seconds",
            "maximum_utc_monotonic_drift_seconds",
            "maximum_temperature_c",
            "maximum_post_cut_temperature_rise_c",
            "maximum_positive_trend_c_per_minute",
            "temperature_uncertainty_c",
            "wall_zero_maximum_w",
            "wall_uncertainty_w",
            "wall_zero_grace_seconds",
            "wall_zero_hold_seconds",
            "voltage_uncertainty_v",
            "input_absent_maximum_v",
            "fan_supply_absent_maximum_v",
            "api_supply_absent_maximum_v",
        },
        "envelope",
    )
    reviews = mapping(plan.get("reviews"), "reviews")
    exact_keys(
        reviews,
        {
            "thermal_reviewer_public_key_sha256",
            "electrical_reviewer_public_key_sha256",
            "distinct_reviewers",
            "engineering_envelope_approved",
            "source_calibration_approved",
            "post_cut_method_approved",
        },
        "reviews",
    )
    claims = mapping(plan.get("claims"), "claims")
    exact_keys(claims, FALSE_CLAIMS, "claims")
    for key in sorted(FALSE_CLAIMS):
        exact_bool(claims.get(key), False, f"claims.{key}")

    if status == TEMPLATE_STATUS:
        if require_approved:
            fail("template cannot compile evidence")
        for key in (
            "engineering_envelope_approved",
            "source_calibration_approved",
            "post_cut_method_approved",
        ):
            exact_bool(reviews.get(key), False, f"reviews.{key}")
        return plan

    session_id = token(session.get("session_id"), "session.session_id")
    del session_id
    digest(session.get("session_nonce_sha256"), "session.session_nonce_sha256")
    token(session.get("authorization_ref"), "session.authorization_ref")
    start = utc_time(session.get("authorized_from_utc"), "session.authorized_from_utc")
    end = utc_time(session.get("authorized_until_utc"), "session.authorized_until_utc")
    if end <= start or (end - start).total_seconds() > 8 * 3600:
        fail("authorization window must be positive and at most eight hours")
    digest(session.get("exact_unit_fingerprint_sha256"), "session exact unit")
    digest(session.get("operator_public_key_sha256"), "session operator public key")
    if session.get("action") != ACTION:
        fail("only the reviewed manual whole-unit AC action is supported")

    for key in ("public_key_sha256", "identity_record_sha256", "channel_contract_record_sha256"):
        digest(adapter.get(key), f"capture adapter {key}")
    for key in ("asset_record_sha256", "calibration_record_sha256", "placement_record_sha256"):
        digest(sensor.get(key), f"sensor {key}")
    for key in ("asset_record_sha256", "calibration_record_sha256", "channel_contract_record_sha256"):
        digest(meter.get(key), f"wall meter {key}")
    token(sensor.get("identity_label"), "sensor identity label")
    token(meter.get("identity_label"), "wall meter identity label")
    if sensor["asset_record_sha256"] == meter["asset_record_sha256"]:
        fail("sensor and meter assets must be distinct")

    baseline_count = number(envelope.get("baseline_sample_count"), "baseline count", 3, 100)
    if not baseline_count.is_integer():
        fail("baseline sample count must be an integer")
    number(envelope.get("minimum_observation_seconds"), "minimum observation", 120, 3600)
    number(envelope.get("maximum_first_post_cut_delay_seconds"), "first sample delay", 0.05, 10)
    number(envelope.get("maximum_sample_gap_seconds"), "sample gap", 0.05, 30)
    number(envelope.get("maximum_utc_monotonic_drift_seconds"), "clock drift", 0, 2)
    number(envelope.get("maximum_temperature_c"), "maximum temperature", -20, 150)
    number(envelope.get("maximum_post_cut_temperature_rise_c"), "maximum temperature rise", 0, 100)
    number(envelope.get("maximum_positive_trend_c_per_minute"), "maximum positive trend", 0, 200)
    number(envelope.get("temperature_uncertainty_c"), "temperature uncertainty", 0, 20)
    number(envelope.get("wall_zero_maximum_w"), "wall-zero threshold", 0, 100)
    number(envelope.get("wall_uncertainty_w"), "wall uncertainty", 0, 100)
    number(envelope.get("wall_zero_grace_seconds"), "wall-zero grace", 0, 60)
    number(envelope.get("wall_zero_hold_seconds"), "wall-zero hold", 1, 300)
    number(envelope.get("voltage_uncertainty_v"), "voltage uncertainty", 0, 10)
    number(envelope.get("input_absent_maximum_v"), "input absent threshold", 0, 20)
    number(envelope.get("fan_supply_absent_maximum_v"), "fan absent threshold", 0, 20)
    number(envelope.get("api_supply_absent_maximum_v"), "API absent threshold", 0, 20)
    if envelope["wall_uncertainty_w"] > envelope["wall_zero_maximum_w"]:
        fail("wall uncertainty alone exceeds the wall-zero threshold")
    for key in ("distinct_reviewers", "engineering_envelope_approved", "source_calibration_approved", "post_cut_method_approved"):
        exact_bool(reviews.get(key), True, f"reviews.{key}")
    voltage_uncertainty = envelope["voltage_uncertainty_v"]
    for key in ("input_absent_maximum_v", "fan_supply_absent_maximum_v", "api_supply_absent_maximum_v"):
        if voltage_uncertainty > envelope[key]:
            fail(f"voltage uncertainty alone exceeds {key}")
    thermal = digest(reviews.get("thermal_reviewer_public_key_sha256"), "thermal reviewer")
    electrical = digest(reviews.get("electrical_reviewer_public_key_sha256"), "electrical reviewer")
    if thermal == electrical:
        fail("thermal and electrical reviewers must be distinct")
    return plan


def validate_ack(ack: dict[str, Any], plan: dict[str, Any]) -> tuple[datetime, int]:
    exact_keys(
        ack,
        {
            "schema",
            "session_id",
            "session_nonce_sha256",
            "authorization_ref",
            "exact_unit_fingerprint_sha256",
            "operator_public_key_sha256",
            "action",
            "acknowledged_at_utc",
            "monotonic_ms",
            "input_power_removed",
            "stock_fan_power_lost_acknowledged",
            "stock_api_power_lost_acknowledged",
            "continue_external_observation",
            "reenergization_forbidden_during_window",
        },
        "ack",
    )
    if ack.get("schema") != ACK_SCHEMA:
        fail("ack schema mismatch")
    session = plan["session"]
    for key in (
        "session_id",
        "session_nonce_sha256",
        "authorization_ref",
        "exact_unit_fingerprint_sha256",
        "operator_public_key_sha256",
        "action",
    ):
        if ack.get(key) != session.get(key):
            fail(f"ack {key} does not match the plan")
    for key in (
        "input_power_removed",
        "stock_fan_power_lost_acknowledged",
        "stock_api_power_lost_acknowledged",
        "continue_external_observation",
        "reenergization_forbidden_during_window",
    ):
        exact_bool(ack.get(key), True, f"ack.{key}")
    when = utc_time(ack.get("acknowledged_at_utc"), "ack timestamp")
    start = utc_time(session["authorized_from_utc"], "authorization start")
    end = utc_time(session["authorized_until_utc"], "authorization end")
    if not start <= when <= end:
        fail("cut acknowledgement is outside the authorization window")
    monotonic = ack.get("monotonic_ms")
    if isinstance(monotonic, bool) or not isinstance(monotonic, int) or monotonic < 0:
        fail("ack monotonic_ms must be a non-negative integer")
    return when, monotonic


def validate_adapter_envelope(
    envelope: dict[str, Any],
    plan: dict[str, Any],
    plan_raw: bytes,
    ack: dict[str, Any],
    ack_raw: bytes,
    samples_raw: bytes,
    samples: list[Sample],
) -> None:
    exact_keys(
        envelope,
        {
            "schema",
            "session_id",
            "session_nonce_sha256",
            "authorization_ref",
            "exact_unit_fingerprint_sha256",
            "plan_sha256",
            "ack_sha256",
            "samples_sha256",
            "samples_size_bytes",
            "monotonic_clock_domain_sha256",
            "cut_event_monotonic_ms",
            "cut_event_utc",
            "first_sample_monotonic_ms",
            "last_sample_monotonic_ms",
        },
        "adapter capture envelope",
    )
    if envelope.get("schema") != ADAPTER_ENVELOPE_SCHEMA:
        fail("adapter capture envelope schema mismatch")
    session = plan["session"]
    for key in (
        "session_id",
        "session_nonce_sha256",
        "authorization_ref",
        "exact_unit_fingerprint_sha256",
    ):
        if envelope.get(key) != session.get(key):
            fail(f"adapter capture envelope {key} does not match the plan")
    expected = {
        "plan_sha256": sha256_bytes(plan_raw),
        "ack_sha256": sha256_bytes(ack_raw),
        "samples_sha256": sha256_bytes(samples_raw),
        "samples_size_bytes": len(samples_raw),
        "cut_event_monotonic_ms": ack["monotonic_ms"],
        "cut_event_utc": ack["acknowledged_at_utc"],
        "first_sample_monotonic_ms": samples[0].monotonic_ms,
        "last_sample_monotonic_ms": samples[-1].monotonic_ms,
    }
    for key, value in expected.items():
        if envelope.get(key) != value:
            fail(f"adapter capture envelope {key} mismatch")
    digest(envelope.get("monotonic_clock_domain_sha256"), "adapter monotonic clock domain")


def csv_number(value: str, label: str) -> float:
    if value != value.strip() or not NUMBER_RE.fullmatch(value):
        fail(f"{label} must be a canonical decimal number")
    result = float(value)
    if not math.isfinite(result):
        fail(f"{label} must be finite")
    return result


@dataclass(frozen=True)
class Sample:
    sequence: int
    monotonic_ms: int
    captured_at: datetime
    temperature_c: float
    wall_w: float
    input_voltage_v: float
    fan_supply_voltage_v: float
    api_supply_voltage_v: float


def parse_samples(raw: bytes, plan: dict[str, Any]) -> list[Sample]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("samples must be UTF-8")
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    if reader.fieldnames != CSV_COLUMNS:
        fail("samples CSV columns/order mismatch")
    rows: list[Sample] = []
    sensor_hash = plan["sources"]["sensor"]["asset_record_sha256"]
    meter_hash = plan["sources"]["wall_meter"]["asset_record_sha256"]
    try:
        for row in reader:
            if len(rows) >= MAX_SAMPLE_ROWS:
                fail("samples exceed row bound")
            if None in row or any(value is None for value in row.values()):
                fail("sample row has missing or extra columns")
            sequence_text = row["sequence"]
            monotonic_text = row["monotonic_ms"]
            if not sequence_text.isascii() or not sequence_text.isdigit():
                fail("sequence must be a canonical non-negative integer")
            if not monotonic_text.isascii() or not monotonic_text.isdigit():
                fail("monotonic_ms must be a canonical non-negative integer")
            sequence = int(sequence_text)
            monotonic_ms = int(monotonic_text)
            if sequence != len(rows):
                fail("sample sequence must begin at zero and be contiguous")
            if row["sensor_asset_record_sha256"] != sensor_hash:
                fail("sample sensor identity mismatch")
            if row["meter_asset_record_sha256"] != meter_hash:
                fail("sample wall-meter identity mismatch")
            sample = Sample(
                sequence=sequence,
                monotonic_ms=monotonic_ms,
                captured_at=utc_time(row["captured_at_utc"], "sample timestamp"),
                temperature_c=csv_number(row["temperature_c"], "sample temperature"),
                wall_w=csv_number(row["wall_w"], "sample wall power"),
                input_voltage_v=csv_number(row["input_voltage_v"], "sample input voltage"),
                fan_supply_voltage_v=csv_number(row["fan_supply_voltage_v"], "sample fan voltage"),
                api_supply_voltage_v=csv_number(row["api_supply_voltage_v"], "sample API voltage"),
            )
            if not -50 <= sample.temperature_c <= 200:
                fail("sample temperature is outside parser bounds")
            if not 0 <= sample.wall_w <= 10_000:
                fail("sample wall power is outside parser bounds")
            for label, value in (
                ("input", sample.input_voltage_v),
                ("fan", sample.fan_supply_voltage_v),
                ("API", sample.api_supply_voltage_v),
            ):
                if not 0 <= value <= 300:
                    fail(f"sample {label} voltage is outside parser bounds")
            if rows:
                previous = rows[-1]
                if sample.monotonic_ms <= previous.monotonic_ms:
                    fail("sample monotonic clock must increase strictly")
                if sample.captured_at <= previous.captured_at:
                    fail("sample UTC clock must increase strictly")
            rows.append(sample)
    except csv.Error as exc:
        fail(f"samples CSV is malformed: {exc}")
    if not rows:
        fail("samples CSV is empty")
    return rows


def analyze(plan: dict[str, Any], ack_time: datetime, ack_ms: int, samples: list[Sample]) -> dict[str, Any]:
    envelope = plan["envelope"]
    baseline_needed = int(envelope["baseline_sample_count"])
    before = [sample for sample in samples if sample.monotonic_ms < ack_ms]
    after = [sample for sample in samples if sample.monotonic_ms >= ack_ms]
    if len(before) < baseline_needed:
        fail("insufficient pre-cut baseline samples")
    before = before[-baseline_needed:]
    if not after:
        fail("no post-cut samples")
    voltage_uncertainty = envelope["voltage_uncertainty_v"]
    input_limit = envelope["input_absent_maximum_v"]
    fan_limit = envelope["fan_supply_absent_maximum_v"]
    api_limit = envelope["api_supply_absent_maximum_v"]
    for sample in before:
        if (
            sample.input_voltage_v - voltage_uncertainty <= input_limit
            or sample.fan_supply_voltage_v - voltage_uncertainty <= fan_limit
            or sample.api_supply_voltage_v - voltage_uncertainty <= api_limit
        ):
            fail("baseline voltages do not prove input/fan/API power present")
    for sample in after:
        if (
            sample.input_voltage_v + voltage_uncertainty > input_limit
            or sample.fan_supply_voltage_v + voltage_uncertainty > fan_limit
            or sample.api_supply_voltage_v + voltage_uncertainty > api_limit
        ):
            fail("measured post-cut voltages indicate re-energization or retained stock power")

    first_delay = (after[0].monotonic_ms - ack_ms) / 1000
    if first_delay > envelope["maximum_first_post_cut_delay_seconds"]:
        fail("first post-cut sample is late")
    duration = (after[-1].monotonic_ms - ack_ms) / 1000
    if duration < envelope["minimum_observation_seconds"]:
        fail("post-cut observation interval is too short")

    max_gap = envelope["maximum_sample_gap_seconds"]
    for left, right in zip(samples, samples[1:]):
        if (right.monotonic_ms - left.monotonic_ms) / 1000 > max_gap:
            fail("sample gap exceeds reviewed bound")

    drift_bound = envelope["maximum_utc_monotonic_drift_seconds"]
    origin = samples[0]
    for sample in samples:
        monotonic_delta = (sample.monotonic_ms - origin.monotonic_ms) / 1000
        utc_delta = (sample.captured_at - origin.captured_at).total_seconds()
        if abs(monotonic_delta - utc_delta) > drift_bound:
            fail("UTC and monotonic sample clocks diverge")
    ack_utc_delta = (ack_time - origin.captured_at).total_seconds()
    ack_monotonic_delta = (ack_ms - origin.monotonic_ms) / 1000
    if abs(ack_utc_delta - ack_monotonic_delta) > drift_bound:
        fail("cut acknowledgement clocks diverge")

    start = utc_time(plan["session"]["authorized_from_utc"], "authorization start")
    end = utc_time(plan["session"]["authorized_until_utc"], "authorization end")
    if samples[0].captured_at < start or samples[-1].captured_at > end:
        fail("sample evidence lies outside the authorization window")

    temp_uncertainty = envelope["temperature_uncertainty_c"]
    baseline_mean = sum(sample.temperature_c for sample in before) / len(before)
    max_post_temp = max(sample.temperature_c for sample in after)
    conservative_peak = max_post_temp + temp_uncertainty
    conservative_rise = max_post_temp - baseline_mean + 2 * temp_uncertainty
    if conservative_peak > envelope["maximum_temperature_c"]:
        fail("uncertainty-adjusted post-cut peak exceeds the reviewed ceiling")
    if conservative_rise > envelope["maximum_post_cut_temperature_rise_c"]:
        fail("uncertainty-adjusted post-cut rise exceeds the reviewed ceiling")
    max_trend = float("-inf")
    for left, right in zip(after, after[1:]):
        minutes = (right.monotonic_ms - left.monotonic_ms) / 60_000
        trend = (right.temperature_c - left.temperature_c + 2 * temp_uncertainty) / minutes
        max_trend = max(max_trend, trend)
    if len(after) < 2:
        fail("at least two post-cut samples are required")
    if max_trend > envelope["maximum_positive_trend_c_per_minute"]:
        fail("uncertainty-adjusted positive temperature trend exceeds the reviewed ceiling")

    wall_uncertainty = envelope["wall_uncertainty_w"]
    wall_threshold = envelope["wall_zero_maximum_w"]
    grace_ms = ack_ms + int(envelope["wall_zero_grace_seconds"] * 1000)
    wall_rows = [sample for sample in after if sample.monotonic_ms >= grace_ms]
    if not wall_rows:
        fail("no wall-power samples exist after the grace interval")
    if any(sample.wall_w + wall_uncertainty > wall_threshold for sample in wall_rows):
        fail("uncertainty-adjusted wall power does not remain in the reviewed zero band")
    wall_hold = (wall_rows[-1].monotonic_ms - wall_rows[0].monotonic_ms) / 1000
    if wall_hold < envelope["wall_zero_hold_seconds"]:
        fail("wall-zero hold interval is too short")

    return {
        "baseline_sample_count": len(before),
        "post_cut_sample_count": len(after),
        "observation_seconds": duration,
        "first_post_cut_delay_seconds": first_delay,
        "maximum_sample_gap_seconds": max(
            (right.monotonic_ms - left.monotonic_ms) / 1000
            for left, right in zip(samples, samples[1:])
        ),
        "baseline_mean_temperature_c": baseline_mean,
        "observed_peak_temperature_c": max_post_temp,
        "uncertainty_adjusted_peak_temperature_c": conservative_peak,
        "uncertainty_adjusted_post_cut_rise_c": conservative_rise,
        "maximum_uncertainty_adjusted_positive_trend_c_per_minute": max_trend,
        "maximum_observed_post_grace_wall_w": max(sample.wall_w for sample in wall_rows),
        "maximum_uncertainty_adjusted_post_grace_wall_w": max(
            sample.wall_w + wall_uncertainty for sample in wall_rows
        ),
        "wall_zero_hold_seconds": wall_hold,
        "maximum_uncertainty_adjusted_post_cut_input_voltage_v": max(
            sample.input_voltage_v + voltage_uncertainty for sample in after
        ),
        "maximum_uncertainty_adjusted_post_cut_fan_supply_voltage_v": max(
            sample.fan_supply_voltage_v + voltage_uncertainty for sample in after
        ),
        "maximum_uncertainty_adjusted_post_cut_api_supply_voltage_v": max(
            sample.api_supply_voltage_v + voltage_uncertainty for sample in after
        ),
        "input_power_absence_derived_from_voltage_for_all_post_cut_samples": True,
        "stock_fan_power_absence_derived_from_voltage_for_all_post_cut_samples": True,
        "stock_api_power_absence_derived_from_voltage_for_all_post_cut_samples": True,
        "reenergization_observed": False,
    }


def verify_bound_file(path: Path, expected_sha256: str, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = read_regular(path, label)
    actual = sha256_bytes(raw)
    if actual != expected_sha256:
        fail(f"{label} SHA-256 mismatch")
    return raw, {"sha256": actual, "size_bytes": len(raw)}


def load_public_key(path: Path, expected_sha256: str, label: str) -> tuple[Ed25519PublicKey, dict[str, Any]]:
    raw, record = verify_bound_file(path, expected_sha256, label)
    if len(raw) != 32:
        fail(f"{label} must be an exact 32-byte raw Ed25519 public key")
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        fail(f"{label} is not a valid raw Ed25519 public key")
    return key, record


def verify_detached_signature(
    key: Ed25519PublicKey,
    signature_path: Path,
    domain: bytes,
    payload: bytes,
    label: str,
) -> dict[str, Any]:
    signature = read_regular(signature_path, f"{label} signature")
    if len(signature) != 64:
        fail(f"{label} signature must be exactly 64 bytes")
    message = domain + b"\0" + hashlib.sha256(payload).digest()
    try:
        key.verify(signature, message)
    except InvalidSignature:
        fail(f"{label} signature verification failed")
    return {"sha256": sha256_bytes(signature), "size_bytes": len(signature)}


def verify_provenance(
    args: argparse.Namespace,
    plan: dict[str, Any],
    plan_raw: bytes,
    ack_raw: bytes,
    samples_raw: bytes,
    adapter_envelope_raw: bytes,
) -> dict[str, Any]:
    reviews = plan["reviews"]
    session = plan["session"]
    adapter_plan = plan["sources"]["capture_adapter"]
    thermal_key, thermal_key_record = load_public_key(
        args.thermal_reviewer_public_key,
        reviews["thermal_reviewer_public_key_sha256"],
        "thermal reviewer public key",
    )
    electrical_key, electrical_key_record = load_public_key(
        args.electrical_reviewer_public_key,
        reviews["electrical_reviewer_public_key_sha256"],
        "electrical reviewer public key",
    )
    operator_key, operator_key_record = load_public_key(
        args.operator_public_key,
        session["operator_public_key_sha256"],
        "operator public key",
    )
    adapter_key, adapter_key_record = load_public_key(
        args.adapter_public_key,
        adapter_plan["public_key_sha256"],
        "capture adapter public key",
    )
    signatures = {
        "thermal_plan_signature": verify_detached_signature(
            thermal_key,
            args.thermal_plan_signature,
            b"dcent.nano3.post-cut.plan.thermal.v1",
            plan_raw,
            "thermal plan",
        ),
        "electrical_plan_signature": verify_detached_signature(
            electrical_key,
            args.electrical_plan_signature,
            b"dcent.nano3.post-cut.plan.electrical.v1",
            plan_raw,
            "electrical plan",
        ),
        "operator_ack_signature": verify_detached_signature(
            operator_key,
            args.operator_ack_signature,
            b"dcent.nano3.post-cut.ack.operator.v1",
            ack_raw,
            "operator acknowledgement",
        ),
        "adapter_samples_signature": verify_detached_signature(
            adapter_key,
            args.adapter_samples_signature,
            b"dcent.nano3.post-cut.samples.adapter.v1",
            samples_raw,
            "adapter samples",
        ),
        "adapter_capture_envelope_signature": verify_detached_signature(
            adapter_key,
            args.adapter_capture_signature,
            b"dcent.nano3.post-cut.adapter-envelope.v1",
            adapter_envelope_raw,
            "adapter capture envelope",
        ),
    }
    source_records: dict[str, dict[str, Any]] = {}
    bindings = (
        (args.adapter_identity_record, adapter_plan["identity_record_sha256"], "adapter_identity"),
        (args.adapter_channel_contract, adapter_plan["channel_contract_record_sha256"], "adapter_channel_contract"),
        (args.sensor_asset_record, plan["sources"]["sensor"]["asset_record_sha256"], "sensor_asset"),
        (
            args.sensor_calibration_record,
            plan["sources"]["sensor"]["calibration_record_sha256"],
            "sensor_calibration",
        ),
        (args.sensor_placement_record, plan["sources"]["sensor"]["placement_record_sha256"], "sensor_placement"),
        (args.meter_asset_record, plan["sources"]["wall_meter"]["asset_record_sha256"], "meter_asset"),
        (
            args.meter_calibration_record,
            plan["sources"]["wall_meter"]["calibration_record_sha256"],
            "meter_calibration",
        ),
        (
            args.meter_channel_contract,
            plan["sources"]["wall_meter"]["channel_contract_record_sha256"],
            "meter_channel_contract",
        ),
    )
    for path, expected, label in bindings:
        _, source_records[label] = verify_bound_file(path, expected, label.replace("_", " "))

    nonce, nonce_record = verify_bound_file(
        args.session_nonce,
        session["session_nonce_sha256"],
        "session nonce reveal",
    )
    if len(nonce) != 32:
        fail("session nonce reveal must be exactly 32 bytes")
    return {
        "public_keys": {
            "thermal_reviewer": thermal_key_record,
            "electrical_reviewer": electrical_key_record,
            "operator": operator_key_record,
            "capture_adapter": adapter_key_record,
        },
        "signatures": signatures,
        "source_records": source_records,
        "session_nonce_reveal": nonce_record,
    }


def consume_once(ledger_dir: Path, plan: dict[str, Any], plan_sha256: str) -> dict[str, Any]:
    validate_directory_chain(ledger_dir, "consumption ledger", require_private=True)
    nonce_hash = plan["session"]["session_nonce_sha256"]
    marker = ledger_dir / f"nano3-post-cut-{nonce_hash}.consumed.json"
    body = canonical_json_bytes(
        {
            "schema": "dcent.nano3.post-cut-local-consumption.v1",
            "session_id": plan["session"]["session_id"],
            "session_nonce_sha256": nonce_hash,
            "authorization_ref": plan["session"]["authorization_ref"],
            "plan_sha256": plan_sha256,
            "local_only": True,
            "global_replay_prevented": False,
        }
    )
    write_new(marker, body, "local consumption marker")
    return {"marker_sha256": sha256_bytes(body), "local_one_shot_enforced": True, "global_replay_prevented": False}


def make_receipt(
    plan: dict[str, Any],
    plan_raw: bytes,
    ack_raw: bytes,
    samples_raw: bytes,
    adapter_envelope_raw: bytes,
    metrics: dict[str, Any],
    provenance: dict[str, Any],
    consumption: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "result": "PASS_SIGNED_FORMAT_AND_ENVELOPE_ONLY",
        "session": {
            "session_id": plan["session"]["session_id"],
            "session_nonce_sha256": plan["session"]["session_nonce_sha256"],
            "authorization_ref": plan["session"]["authorization_ref"],
            "exact_unit_fingerprint_sha256": plan["session"]["exact_unit_fingerprint_sha256"],
            "action": ACTION,
        },
        "sources": {
            "capture_adapter_public_key_sha256": plan["sources"]["capture_adapter"]["public_key_sha256"],
            "sensor_asset_record_sha256": plan["sources"]["sensor"]["asset_record_sha256"],
            "sensor_calibration_record_sha256": plan["sources"]["sensor"]["calibration_record_sha256"],
            "sensor_placement_record_sha256": plan["sources"]["sensor"]["placement_record_sha256"],
            "wall_meter_asset_record_sha256": plan["sources"]["wall_meter"]["asset_record_sha256"],
            "wall_meter_calibration_record_sha256": plan["sources"]["wall_meter"]["calibration_record_sha256"],
            "wall_meter_channel_contract_record_sha256": plan["sources"]["wall_meter"][
                "channel_contract_record_sha256"
            ],
            "independent_power_required": True,
        },
        "inputs": {
            "plan_sha256": sha256_bytes(plan_raw),
            "plan_size_bytes": len(plan_raw),
            "ack_sha256": sha256_bytes(ack_raw),
            "ack_size_bytes": len(ack_raw),
            "samples_sha256": sha256_bytes(samples_raw),
            "samples_size_bytes": len(samples_raw),
            "adapter_capture_envelope_sha256": sha256_bytes(adapter_envelope_raw),
            "adapter_capture_envelope_size_bytes": len(adapter_envelope_raw),
        },
        "metrics": metrics,
        "cryptographic_provenance": provenance,
        "consumption": consumption,
        "claims": {key: False for key in sorted(FALSE_CLAIMS)},
        "scope": {
            "adapter_signature_verified": True,
            "adapter_key_authority_verified_by_compiler": False,
            "collector_opened_hardware_or_network": False,
            "operator_ack_signature_verified": True,
            "operator_key_authority_verified_by_compiler": False,
            "physical_channel_wiring_verified_by_compiler": False,
            "physical_sensor_mount_and_coverage_verified_by_compiler": False,
            "physical_source_authenticity_verified_by_compiler": False,
            "plan_reviewer_signatures_verified": True,
            "reviewer_key_authority_verified_by_compiler": False,
            "local_create_new_receipt_enforced": True,
            "parent_directory_fsync_required_where_supported": True,
            "crash_durability_not_globally_attested": True,
            "global_replay_prevented": False,
            "pass_is_not_interlock_qualification": True,
            "pass_is_not_authorization_a": True,
            "pass_is_not_production_authority": True,
        },
    }


def validate_directory_chain(path: Path, label: str, *, require_private: bool = False) -> os.stat_result:
    if not path.is_absolute():
        fail(f"{label} must be an absolute path")
    for component in reversed((path, *path.parents)):
        try:
            current = component.lstat()
        except OSError as exc:
            fail(f"{label} path component unavailable: {exc.__class__.__name__}")
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
            fail(f"{label} path chain must contain only non-symlink directories")
    final = path.lstat()
    if require_private and os.name != "nt" and final.st_mode & 0o077:
        fail(f"{label} must have owner-only permissions")
    return final


def write_new(path: Path, data: bytes, label: str = "receipt") -> None:
    parent = path.parent
    validate_directory_chain(parent, f"{label} parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        fail(f"{label} already exists; overwrite is forbidden")
    except OSError as exc:
        fail(f"{label} create failed: {exc.__class__.__name__}")
    try:
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                fail(f"{label} write made no progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
        try:
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as exc:
            fail(f"{label} parent directory open for fsync failed: {exc.__class__.__name__}")
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            fail(f"{label} parent directory fsync failed: {exc.__class__.__name__}")
        finally:
            os.close(directory_fd)


def compile_receipt(args: argparse.Namespace) -> int:
    plan, plan_raw = load_json(args.plan, "plan")
    validate_plan(plan, require_approved=True)
    actual_plan_hash = sha256_bytes(plan_raw)
    if args.plan_sha256 != actual_plan_hash:
        fail("explicit plan SHA-256 does not match")
    if args.session_id != plan["session"]["session_id"]:
        fail("explicit session id does not match")
    if args.authorization_ref != plan["session"]["authorization_ref"]:
        fail("explicit authorization reference does not match")
    ack, ack_raw = load_json(args.ack, "cut acknowledgement")
    ack_time, ack_ms = validate_ack(ack, plan)
    samples_raw = read_regular(args.samples, "samples")
    samples = parse_samples(samples_raw, plan)
    adapter_envelope, adapter_envelope_raw = load_json(
        args.adapter_capture_envelope,
        "adapter capture envelope",
    )
    validate_adapter_envelope(
        adapter_envelope,
        plan,
        plan_raw,
        ack,
        ack_raw,
        samples_raw,
        samples,
    )
    metrics = analyze(plan, ack_time, ack_ms, samples)
    provenance = verify_provenance(
        args,
        plan,
        plan_raw,
        ack_raw,
        samples_raw,
        adapter_envelope_raw,
    )
    if args.receipt.exists() or args.receipt.is_symlink():
        fail("receipt already exists; overwrite is forbidden")
    consumption = consume_once(args.consumption_ledger, plan, actual_plan_hash)
    receipt = make_receipt(
        plan,
        plan_raw,
        ack_raw,
        samples_raw,
        adapter_envelope_raw,
        metrics,
        provenance,
        consumption,
    )
    encoded = canonical_json_bytes(receipt)
    write_new(args.receipt, encoded)
    print(
        "PASS_SIGNED_FORMAT_AND_ENVELOPE_ONLY: receipt compiled; "
        f"receipt_sha256={sha256_bytes(encoded)}; authorization_a=false"
    )
    return 0


def validate_plan_command(args: argparse.Namespace) -> int:
    plan, raw = load_json(args.plan, "plan")
    validate_plan(plan, require_approved=False)
    status = plan["status"]
    print(
        f"PASS: post-cut plan schema valid; status={status}; "
        f"plan_sha256={sha256_bytes(raw)}; authorization_a=false"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-plan", help="validate a plan without contact")
    validate.add_argument("--plan", required=True, type=Path)
    validate.set_defaults(handler=validate_plan_command)
    compile_parser = subparsers.add_parser("compile", help="compile an offline evidence receipt")
    compile_parser.add_argument("--plan", required=True, type=Path)
    compile_parser.add_argument("--plan-sha256", required=True)
    compile_parser.add_argument("--session-id", required=True)
    compile_parser.add_argument("--authorization-ref", required=True)
    compile_parser.add_argument("--ack", required=True, type=Path)
    compile_parser.add_argument("--samples", required=True, type=Path)
    compile_parser.add_argument("--receipt", required=True, type=Path)
    compile_parser.add_argument("--session-nonce", required=True, type=Path)
    compile_parser.add_argument("--consumption-ledger", required=True, type=Path)
    compile_parser.add_argument("--thermal-reviewer-public-key", required=True, type=Path)
    compile_parser.add_argument("--thermal-plan-signature", required=True, type=Path)
    compile_parser.add_argument("--electrical-reviewer-public-key", required=True, type=Path)
    compile_parser.add_argument("--electrical-plan-signature", required=True, type=Path)
    compile_parser.add_argument("--operator-public-key", required=True, type=Path)
    compile_parser.add_argument("--operator-ack-signature", required=True, type=Path)
    compile_parser.add_argument("--adapter-public-key", required=True, type=Path)
    compile_parser.add_argument("--adapter-samples-signature", required=True, type=Path)
    compile_parser.add_argument("--adapter-capture-envelope", required=True, type=Path)
    compile_parser.add_argument("--adapter-capture-signature", required=True, type=Path)
    compile_parser.add_argument("--adapter-identity-record", required=True, type=Path)
    compile_parser.add_argument("--adapter-channel-contract", required=True, type=Path)
    compile_parser.add_argument("--sensor-asset-record", required=True, type=Path)
    compile_parser.add_argument("--sensor-calibration-record", required=True, type=Path)
    compile_parser.add_argument("--sensor-placement-record", required=True, type=Path)
    compile_parser.add_argument("--meter-asset-record", required=True, type=Path)
    compile_parser.add_argument("--meter-calibration-record", required=True, type=Path)
    compile_parser.add_argument("--meter-channel-contract", required=True, type=Path)
    compile_parser.set_defaults(handler=compile_receipt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ValidationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
