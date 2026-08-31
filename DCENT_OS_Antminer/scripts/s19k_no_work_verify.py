#!/usr/bin/env python3
"""Verify the joined S19k Phase-1 instrumentation + Phase-2 no-work gate.

This host-only tool performs no network or hardware operation. It combines the
content-bound target transcript/closeout receipts with independent common-clock
rail, GPIO, reset, cooling, temperature, and UART captures. A target GPIO
receipt alone is deliberately insufficient to produce the success sentinel.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import s19k_bounded_transcript_verify as common
import s19k_phase12_capture_verify as raw_capture
import s19k_phase12_normalize as normalizer


PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"
RECEIPT_SCHEMA = "dcentos.s19k-handoff-no-work-transcript/v1"
SOURCE_RUNTIME_SCHEMA = common.SOURCE_RUNTIME_SCHEMA
PENDING_RUNTIME_SCHEMA = common.PENDING_RUNTIME_SCHEMA
TERMINAL_HANDOFF_SCHEMA = common.TERMINAL_HANDOFF_SCHEMA
SAFEOFF_SCHEMA = common.SAFEOFF_SCHEMA
LIVE_IDENTITY_SCHEMA = common.LIVE_IDENTITY_SCHEMA
MANIFEST_SCHEMA = "dcentos.s19k-phase12-instrument-manifest/v2"
VERIFICATION_SCHEMA = "dcentos.s19k-phase12-no-work-host-verification/v2"
BUNDLE_SCHEMA = "dcentos.s19k-phase12-evidence-bundle/v2"
PREPARER_FILENAME = "s19k_no_work_prepare.py"
NORMALIZER_FILENAME = "s19k_phase12_normalize.py"
EMBEDDED_RESULT_FILENAME = "phase12_host_verification.json"
BUNDLE_RECEIPT_FILENAME = "phase12_bundle_complete"
EVIDENCE_FILENAMES = {
    "preflight": "instrumentation_preflight.kv",
    "normalization_config": "normalization_config.json",
    "normalization_receipt": "phase12_normalization_receipt",
    "instrument_source": "instrument_source.raw",
    "instrument_csv": "instrument.csv",
    "uart_source": "uart_source.raw",
    "uart_csv": "uart.csv",
    "capture_contract": raw_capture.CONTRACT_NAME,
    "capture_blocks": raw_capture.BLOCKS_NAME,
    "capture_verification": raw_capture.RECEIPT_NAME,
}
LIVE88_PROFILE = "live88_two_bhb56903_slots_2_3"
NO_WORK_MARKER = (
    "S19k handoff-no-work active: jobs will be discarded and UART work is "
    "structurally refused"
)
DISCARDED_JOB_MARKER = "S19k handoff-no-work discarded pool job before clean/work state"
GETADDRESS_MARKER = "S19k GetAddress observe (silence is not a parser error)"
THERMAL_READY_MARKER = (
    "BM1366 Track-1 leftover: thermal Ready (complete TMP75 coverage + "
    "tach-proven fans at PWM 100); GPIO437 not written"
)
J3_HANDOFF_MARKER = (
    "S19k Track-1 assumed inherited rails after supervisor-first/child-second "
    "J3-confirmed stock exit"
)
FULL_FRAME_MARKER = "FULL FRAME ON WIRE ("
BOUNDED_TX_MARKER = "S19K_BOUNDED_WORK_TX_EVIDENCE"
DISPATCH_ADMITTED_MARKER = "serial work-dispatch admission OK"
EXPECTED_WRAPPER_EXIT = 130
REQUIRED_PATHS = ("/dev/ttyS1", "/dev/ttyS2")
OPTIONAL_PATHS = ("/dev/ttyS3",)
MAX_SAMPLE_GAP_MS = 1_000
MIN_BASELINE_MS = 2_000
MIN_POST_DECAY_CONFIRM_MS = 5_000
MAX_BASELINE_VARIATION_PERCENT = 5
MAX_DECAY_PERCENT_OF_BASELINE = 5
MAX_CANONICAL_BYTES = 64 * 1024 * 1024
MIN_SPINNING_FAN_RPM = 2_000
MIN_SPINNING_FANS = 2
MAX_PREFLIGHT_AGE_SECONDS = 24 * 60 * 60
MIN_RESET_TO_CUT_MARGIN_MS = 2
MIN_GPIO_EDGE_SAMPLE_RATE_HZ = 100_000
MAX_GPIO_EDGE_RESOLUTION_US = 10
MIN_TACH_SAMPLE_RATE_HZ = 10_000
S19K_UART_MAX_BAUD = 3_125_000
MIN_UART_OVERSAMPLE = 8
MIN_DIGITAL_INPUT_IMPEDANCE_OHMS = 1_000_000

VerificationError = common.VerificationError
fail = common.fail


RECEIPT_KEYS = (
    "schema",
    "deploy_mode",
    "transcript_path",
    "transcript_mnt_id",
    "transcript_inode",
    "transcript_mode",
    "transcript_uid",
    "transcript_gid",
    "transcript_sha256",
    "transcript_bytes",
    "source_runtime_active_schema",
    "source_runtime_active_path",
    "source_runtime_active_sha256",
    "source_runtime_active_bytes",
    "pending_runtime_schema",
    "pending_runtime_path",
    "pending_runtime_sha256",
    "pending_runtime_bytes",
    "terminal_handoff_receipt_schema",
    "terminal_handoff_receipt_path",
    "terminal_handoff_receipt_sha256",
    "terminal_handoff_receipt_bytes",
    "safeoff_receipt_schema",
    "safeoff_receipt_path",
    "safeoff_receipt_sha256",
    "safeoff_receipt_bytes",
    "startup_c1_schema",
    "startup_c1_path",
    "startup_c1_sha256",
    "startup_c1_bytes",
    "startup_j1_schema",
    "startup_j1_path",
    "startup_j1_sha256",
    "startup_j1_bytes",
    "startup_j2_schema",
    "startup_j2_path",
    "startup_j2_sha256",
    "startup_j2_bytes",
    "startup_release_schema",
    "startup_release_path",
    "startup_release_sha256",
    "startup_release_bytes",
    "binary_sha256",
    "binary_bytes",
    "config_sha256",
    "config_bytes",
    "runner_sha256",
    "runner_bytes",
    "custody_observer_sha256",
    "custody_observer_bytes",
    "stock_restart_helper_sha256",
    "stock_restart_helper_bytes",
    "live_identity_schema",
    "live_identity_profile",
    "live_identity_sha256",
    "live_identity_model_sha256",
    "wrapper_exit_status",
    "no_work_active_count",
    "discarded_job_count",
    "full_frame_count",
    "bounded_tx_count",
    "dispatch_admitted_count",
    "semantic_verification",
    "persistent_mutation",
    "publication",
)

MANIFEST_KEYS = (
    "schema",
    "claim",
    "plan_sha256",
    "target_receipt_sha256",
    "transcript_sha256",
    "verifier_sha256",
    "verifier_bytes",
    "preparer_sha256",
    "preparer_bytes",
    "normalizer_sha256",
    "normalizer_bytes",
    "capture_verifier_sha256",
    "capture_verifier_bytes",
    "preflight_file",
    "preflight_sha256",
    "preflight_bytes",
    "normalization_config_file",
    "normalization_config_sha256",
    "normalization_config_bytes",
    "normalization_receipt_file",
    "normalization_receipt_sha256",
    "normalization_receipt_bytes",
    "instrument_source_file",
    "instrument_source_sha256",
    "instrument_source_bytes",
    "instrument_csv_file",
    "instrument_csv_sha256",
    "instrument_csv_bytes",
    "uart_source_file",
    "uart_source_sha256",
    "uart_source_bytes",
    "uart_csv_file",
    "uart_csv_sha256",
    "uart_csv_bytes",
    "capture_contract_file",
    "capture_contract_sha256",
    "capture_contract_bytes",
    "capture_blocks_file",
    "capture_blocks_sha256",
    "capture_blocks_bytes",
    "capture_verification_file",
    "capture_verification_sha256",
    "capture_verification_bytes",
    "common_clock_id",
    "rail_signal",
    "created_utc",
    "publication",
)

PREFLIGHT_SCHEMA = "dcentos.s19k-instrumentation-preflight/v3"
PREFLIGHT_KEYS = (
    "schema",
    "authorization_reference",
    "authorized_utc",
    "ssh_host_key_sha256",
    "authorized_miner_identity_sha256",
    "hardware_reviewer",
    "board_revision",
    "test_point_id",
    "test_point_reference_node",
    "test_point_approval",
    "rail_coverage",
    "rail_slot2_location",
    "rail_slot3_location",
    "rail_slot2_reference_or_conductor",
    "rail_slot3_reference_or_conductor",
    "rail_capture_topology",
    "rail_composite_rule",
    "measurement_method",
    "expected_range_min",
    "expected_range_max",
    "expected_range_unit",
    "instrument_identity",
    "instrument_voltage_rating_millivolts",
    "instrument_current_rating_milliamps",
    "instrument_cat_rating",
    "instrument_isolation",
    "lead_insulation_status",
    "fuse_status",
    "calibration_status",
    "calibration_due_utc",
    "rail_slot2_channel",
    "rail_slot3_channel",
    "rail_polarity",
    "gpio437_channel",
    "gpio437_test_point",
    "gpio437_polarity",
    "gpio454_channel",
    "gpio454_test_point",
    "gpio454_polarity",
    "gpio455_channel",
    "gpio455_test_point",
    "gpio455_polarity",
    "gpio456_channel",
    "gpio456_test_point",
    "gpio456_polarity",
    "gpio_reference_node",
    "gpio_probe_interface",
    "gpio_expected_max_millivolts",
    "gpio_input_rating_millivolts",
    "gpio_input_impedance_ohms",
    "gpio_logic_threshold_approval",
    "gpio_edge_clock",
    "gpio_edge_sample_rate_hz",
    "gpio_edge_resolution_us",
    "fan0_tach_channel",
    "fan0_tach_test_point",
    "fan1_tach_channel",
    "fan1_tach_test_point",
    "fan2_tach_channel",
    "fan2_tach_test_point",
    "fan3_tach_channel",
    "fan3_tach_test_point",
    "fan_tach_reference_node",
    "fan_tach_probe_interface",
    "fan_tach_expected_max_millivolts",
    "fan_tach_input_rating_millivolts",
    "fan_tach_input_impedance_ohms",
    "fan_tach_sample_rate_hz",
    "fan_harness_status",
    "temperature_channels",
    "ttys1_rx_channel",
    "ttys1_rx_test_point",
    "ttys1_tx_channel",
    "ttys1_tx_test_point",
    "ttys2_rx_channel",
    "ttys2_rx_test_point",
    "ttys2_tx_channel",
    "ttys2_tx_test_point",
    "ttys3_rx_channel",
    "ttys3_rx_test_point",
    "ttys3_tx_channel",
    "ttys3_tx_test_point",
    "uart_reference_node",
    "uart_probe_interface",
    "uart_expected_max_millivolts",
    "uart_input_rating_millivolts",
    "uart_input_impedance_ohms",
    "uart_line_contract",
    "uart_max_baud",
    "uart_sample_rate_hz",
    "wall_power_channel",
    "common_clock_id",
    "clock_sync_method",
    "clock_sync_event_id",
    "clock_skew_max_ms",
    "timestamp_unit",
    "timestamp_rounding",
    "slow_monitor_sample_rate_millihz",
    "recording_advancing_proof",
    "emergency_responder",
    "disconnect_path",
    "disconnect_tested_utc",
    "disconnect_test_status",
    "operator_ack",
    "publication",
)

BUNDLE_KEYS = (
    "schema",
    "instrument_manifest_sha256",
    "instrument_manifest_bytes",
    "host_verification_sha256",
    "host_verification_bytes",
    "verification_id",
    "preparer_sha256",
    "preparer_bytes",
    "file_count",
    "publication",
)

INSTRUMENT_HEADER = (
    "monotonic_ms",
    "event",
    "rail_value",
    "fan0_rpm",
    "fan1_rpm",
    "fan2_rpm",
    "fan3_rpm",
    "slot2_inlet_millic",
    "slot2_outlet_millic",
    "slot3_inlet_millic",
    "slot3_outlet_millic",
    "gpio437_raw",
    "gpio454_raw",
    "gpio455_raw",
    "gpio456_raw",
)

UART_HEADER = ("monotonic_ms", "path", "direction", "frame_hex")


@dataclass(frozen=True)
class InstrumentRow:
    monotonic_ms: int
    event: str
    rail_value: int
    fans: tuple[int, int, int, int]
    temperatures_millic: tuple[int, int, int, int]
    gpio437: int
    resets: tuple[int, int, int]


@dataclass(frozen=True)
class UartRow:
    monotonic_ms: int
    path: str
    direction: str
    frame: bytes


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(reparse and getattr(metadata, "st_file_attributes", 0) & reparse)
    ):
        fail(f"{label} must be a real non-link directory")


def _stable_regular_digest(path: Path, label: str) -> tuple[str, int]:
    try:
        before_path = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(before_path.st_mode)
        or stat.S_ISLNK(before_path.st_mode)
        or bool(reparse and getattr(before_path, "st_file_attributes", 0) & reparse)
    ):
        fail(f"{label} must be a real regular non-link file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
            before_path.st_dev,
            before_path.st_ino,
        ):
            fail(f"{label} changed before it was opened")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot stream {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    if identity_before != identity_after or observed != before.st_size:
        fail(f"{label} changed while it was streamed")
    return digest.hexdigest(), observed


def _stable_regular_bytes_bounded(path: Path, label: str, max_bytes: int) -> bytes:
    try:
        before_path = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(before_path.st_mode)
        or stat.S_ISLNK(before_path.st_mode)
        or bool(reparse and getattr(before_path, "st_file_attributes", 0) & reparse)
    ):
        fail(f"{label} must be a real regular non-link file")
    if before_path.st_size > max_bytes:
        fail(f"{label} exceeds the 64 MiB canonical evidence limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
            before_path.st_dev,
            before_path.st_ino,
        ):
            fail(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > max_bytes:
                fail(f"{label} exceeds the 64 MiB canonical evidence limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    if identity_before != identity_after or observed != before.st_size:
        fail(f"{label} changed while it was read")
    return b"".join(chunks)


def _canonical_uint(value: str, label: str, *, positive: bool = False) -> int:
    return common._uint(value, label, positive=positive)


def _canonical_int(value: str, label: str) -> int:
    if not re.fullmatch(r"0|-?[1-9][0-9]*", value):
        fail(f"{label} is not a canonical integer")
    return int(value)


def _verify_plan(fields: dict[str, str]) -> None:
    required = {
        "schema": PLAN_SCHEMA,
        "operator_artifact_pin": "required-and-matched",
        "mode": "handoff-no-work",
        "work_authority": "disabled",
        "no_work_flag": "--s19k-track1-no-work",
        "persistent_mutation": "false",
        "native_bm1366": "refused",
        "clear_for_flash": "false",
        "dry_run": "false",
        "ssh_host_key_admission": "exact-operator-pin",
        "ssh_global_known_hosts": "disabled-on-contact",
        "required_ports": "population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
    }
    for key, expected in required.items():
        common._require(fields, key, expected, "deploy plan")
    common._sha(fields.get("sha256"), "plan artifact sha256")
    _canonical_uint(fields.get("bytes", ""), "plan artifact bytes", positive=True)
    common._require(fields, "expected_artifact_sha256", fields["sha256"], "deploy plan")
    common._require(fields, "expected_artifact_bytes", fields["bytes"], "deploy plan")
    for prefix in ("runner", "config", "custody_observer", "stock_restart_helper"):
        common._sha(fields.get(f"{prefix}_sha256"), f"plan {prefix} sha256")
        _canonical_uint(
            fields.get(f"{prefix}_bytes", ""),
            f"plan {prefix} bytes",
            positive=True,
        )
    host_key = fields.get("ssh_host_key_sha256", "")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_key):
        fail("live deploy plan lacks a canonical pinned SSH host-key digest")


def _resolve_receipt_file(
    trial_dir: Path,
    receipt: dict[str, str],
    path_key: str,
    sha_key: str,
    bytes_key: str,
    expected_name: str | None,
    label: str,
) -> tuple[Path, bytes]:
    remote = PurePosixPath(receipt[path_key])
    if expected_name is not None and remote.name != expected_name:
        fail(f"{label} is not the canonical trial filename")
    return common._resolve_bound_file(
        trial_dir,
        receipt[path_key],
        common._sha(receipt.get(sha_key), f"receipt {sha_key}"),
        _canonical_uint(
            receipt.get(bytes_key, ""), f"receipt {bytes_key}", positive=True
        ),
        label,
    )


def _verify_startup_chain(
    receipt: dict[str, str],
    c1_data: bytes,
    j1_data: bytes,
    j2_data: bytes,
    release_data: bytes,
) -> str:
    records = {
        "c1": common._parse_kv_bytes(c1_data, "startup C1")[0],
        "j1": common._parse_kv_bytes(j1_data, "startup J1")[0],
        "j2": common._parse_kv_bytes(j2_data, "startup J2")[0],
        "release": common._parse_kv_bytes(release_data, "startup release")[0],
    }
    expected = {
        "c1": ("dcentos.s19k-startup-c1-child-identity/v1", "1"),
        "j1": ("dcentos.s19k-startup-j1-daemon-blocked/v1", "2"),
        "j2": ("dcentos.s19k-startup-j2-child-bound/v1", "3"),
        "release": ("dcentos.s19k-startup-release/v1", "3-release"),
    }
    transaction = records["c1"].get("transaction_id", "")
    common._sha(transaction, "startup transaction_id")
    for name, (schema, ordinal) in expected.items():
        common._require(records[name], "schema", schema, f"startup {name}")
        common._require(records[name], "ordinal", ordinal, f"startup {name}")
        common._require(records[name], "transaction_id", transaction, f"startup {name}")
        common._require(
            records[name],
            "publication",
            "no-clobber-hard-link-after-fsync",
            f"startup {name}",
        )
    for name in ("c1", "j1", "j2"):
        common._require(
            records[name], "persistent_mutation", "false", f"startup {name}"
        )
    common._require(
        records["c1"],
        "predecessor_schema",
        "dcentos.s19k-startup-j0-prefork/v1",
        "startup C1",
    )
    common._sha(records["c1"].get("predecessor_sha256"), "startup C1 predecessor")
    _canonical_uint(
        records["c1"].get("predecessor_bytes", ""),
        "startup C1 predecessor bytes",
        positive=True,
    )
    for name, predecessor_name, predecessor_schema, predecessor_data in (
        ("j1", "C1", expected["c1"][0], c1_data),
        ("j2", "J1", expected["j1"][0], j1_data),
        ("release", "J2", expected["j2"][0], j2_data),
    ):
        common._require(
            records[name], "predecessor_schema", predecessor_schema, f"startup {name}"
        )
        common._require(
            records[name],
            "predecessor_sha256",
            common._hash(predecessor_data),
            f"startup {name}",
        )
        common._require(
            records[name],
            "predecessor_bytes",
            str(len(predecessor_data)),
            f"startup {name}",
        )
    for name in ("c1", "j1", "j2"):
        common._require(
            records[name],
            "transcript_path",
            receipt["transcript_path"],
            f"startup {name}",
        )
        for key in (
            "transcript_mnt_id",
            "transcript_inode",
            "transcript_mode",
            "transcript_uid",
            "transcript_gid",
        ):
            common._require(records[name], key, receipt[key], f"startup {name}")
    for name in ("c1", "j1", "j2"):
        common._require(
            records[name], "watchdog_start_intent", "false", f"startup {name}"
        )
        common._require(records[name], "watchdog_armed", "false", f"startup {name}")
        common._require(records[name], "signal_attempted", "false", f"startup {name}")
        common._require(records[name], "inherited_rails", "false", f"startup {name}")
        common._require(
            records[name], "route_or_uart_opened", "false", f"startup {name}"
        )
        common._require(records[name], "hardware_opened", "false", f"startup {name}")
    common._require(records["release"], "parent_release", "true", "startup release")
    return transaction


def _verify_transcript(data: bytes, receipt: dict[str, str]) -> dict[str, object]:
    text = common._decode_text(data, "no-work transcript")
    if "\x1b" in text:
        fail("no-work transcript contains escape bytes; runner output must be non-ANSI")
    lines = text.splitlines()
    marker_contract = {
        NO_WORK_MARKER: "no_work_active_count",
        DISCARDED_JOB_MARKER: "discarded_job_count",
        FULL_FRAME_MARKER: "full_frame_count",
        BOUNDED_TX_MARKER: "bounded_tx_count",
        DISPATCH_ADMITTED_MARKER: "dispatch_admitted_count",
    }
    marked: dict[str, list[str]] = {}
    for marker, receipt_key in marker_contract.items():
        matched = [line for line in lines if marker in line]
        marked[marker] = matched
        expected = _canonical_uint(
            receipt.get(receipt_key, ""), f"receipt {receipt_key}"
        )
        if len(matched) != expected:
            fail(f"wrapper marker count for {marker!r} does not match the transcript")
    if len(marked[NO_WORK_MARKER]) != 1:
        fail("no-work transcript requires exactly one active authority marker")
    no_work_line = marked[NO_WORK_MARKER][0]
    for key, value in (
        ("work_authority", "disabled"),
        ("dispatch_admitted", "false"),
        ("actor_tx_guard", "true"),
    ):
        if common._simple_field(no_work_line, key) != value:
            fail(f"no-work marker requires {key}={value}")
    if (
        marked[FULL_FRAME_MARKER]
        or marked[BOUNDED_TX_MARKER]
        or marked[DISPATCH_ADMITTED_MARKER]
    ):
        fail(
            "no-work transcript contains a work-dispatch or physical work-frame marker"
        )
    if any("NEW BLOCK" in line for line in lines):
        fail(
            "no-work transcript reached clean/work state instead of discarding the pool job"
        )
    for line in marked[DISCARDED_JOB_MARKER]:
        if common._simple_field(line, "work_authority") != "disabled":
            fail("discarded-job marker lost disabled work authority")

    getaddress = [line for line in lines if GETADDRESS_MARKER in line]
    required_seen: dict[str, int] = {path: 0 for path in REQUIRED_PATHS}
    optional_seen = 0
    for line in getaddress:
        path = common._simple_field(line, "path")
        frames = _canonical_uint(
            common._simple_field(line, "frames"), "GetAddress frames"
        )
        completeness = common._simple_field(line, "enum_st")
        if path in required_seen:
            if frames != 77 or completeness != "Complete77":
                fail(f"{path} lacks exact Complete77 work-baud geometry")
            required_seen[path] += 1
        elif path in OPTIONAL_PATHS:
            if frames == 77 and completeness == "Complete77":
                fail(
                    "optional ttyS3 unexpectedly presents a third complete board on live88"
                )
            optional_seen += 1
        else:
            fail("GetAddress evidence names a UART outside the plan contract")
    if any(count != 1 for count in required_seen.values()):
        fail("no-work transcript requires one Complete77 observation per required UART")

    thermal = [line for line in lines if THERMAL_READY_MARKER in line]
    if len(thermal) != 1:
        fail(
            "no-work transcript requires exactly one complete thermal/tach admission marker"
        )
    if (
        _canonical_uint(common._simple_field(thermal[0], "seated"), "thermal seated")
        != 2
    ):
        fail("thermal admission does not cover both live88 hashboards")
    if (
        _canonical_uint(
            common._simple_field(thermal[0], "spinning_fans"), "spinning fans"
        )
        < MIN_SPINNING_FANS
    ):
        fail("thermal admission has too few spinning fans")

    j3 = [line for line in lines if J3_HANDOFF_MARKER in line]
    if len(j3) != 1:
        fail("no-work transcript requires one J3-confirmed terminal stock handoff")
    if common._simple_field(j3[0], "live_identity_profile") != LIVE88_PROFILE:
        fail("J3 handoff marker does not name the exact live88 profile")
    if (
        common._simple_field(j3[0], "live_identity_sha256")
        != receipt["live_identity_sha256"]
    ):
        fail("J3 handoff live identity differs from the terminal receipt")

    return {
        "required_paths": list(REQUIRED_PATHS),
        "optional_getaddress_observations": optional_seen,
        "discarded_job_markers": len(marked[DISCARDED_JOB_MARKER]),
        "target_work_frame_markers": 0,
    }


def _parse_config_dangerous_millic(data: bytes) -> int:
    text = common._decode_text(data, "staged config")
    section = ""
    values: list[int] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]", line)
        if match:
            section = match.group(1)
            continue
        if section == "thermal":
            match = re.fullmatch(r"dangerous_temp_c\s*=\s*([0-9]+)", line)
            if match:
                values.append(int(match.group(1)))
    if len(values) != 1 or not 40 <= values[0] <= 100:
        fail("staged config lacks one credible [thermal].dangerous_temp_c")
    return values[0] * 1_000


def _csv_rows(
    data: bytes, expected_header: tuple[str, ...], label: str
) -> list[list[str]]:
    text = common._decode_text(data, label)
    if "\x1b" in text:
        fail(f"{label} contains escape bytes")
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as error:
        fail(f"{label} is not strict CSV: {error}")
    if not rows or tuple(rows[0]) != expected_header:
        fail(f"{label} header does not match the exact canonical schema")
    if any(
        len(row) != len(expected_header) or any(value == "" for value in row)
        for row in rows[1:]
    ):
        fail(f"{label} contains an incomplete or malformed row")
    if len(rows) < 2:
        fail(f"{label} contains no evidence rows")
    return rows[1:]


def _parse_instrument(
    data: bytes,
    dangerous_millic: int,
    *,
    rail_range_min: int | None = None,
    rail_range_max: int | None = None,
) -> tuple[list[InstrumentRow], dict[str, int]]:
    if (rail_range_min is None) != (rail_range_max is None):
        fail("instrument rail range must provide both reviewed bounds")
    if (
        rail_range_min is not None
        and rail_range_max is not None
        and rail_range_min >= rail_range_max
    ):
        fail("instrument rail range is empty or reversed")
    parsed: list[InstrumentRow] = []
    for number, row in enumerate(
        _csv_rows(data, INSTRUMENT_HEADER, "instrument CSV"), 2
    ):
        timestamp = _canonical_uint(row[0], f"instrument row {number} monotonic_ms")
        if row[1] not in ("sample", "run-start"):
            fail(f"instrument row {number} has an invalid event")
        rail = _canonical_uint(row[2], f"instrument row {number} rail_value")
        if (
            rail_range_min is not None
            and rail_range_max is not None
            and not rail_range_min <= rail <= rail_range_max
        ):
            fail(
                f"instrument row {number} rail_value is outside the reviewed range"
            )
        fans = tuple(
            _canonical_uint(value, f"instrument row {number} fan RPM")
            for value in row[3:7]
        )
        temps = tuple(
            _canonical_int(value, f"instrument row {number} temperature")
            for value in row[7:11]
        )
        gpios = tuple(
            _canonical_uint(value, f"instrument row {number} GPIO")
            for value in row[11:15]
        )
        if any(value not in (0, 1) for value in gpios):
            fail(f"instrument row {number} has a non-binary GPIO sample")
        if any(not -40_000 <= value < dangerous_millic for value in temps):
            fail(
                f"instrument row {number} has unsafe or implausible temperature evidence"
            )
        parsed.append(
            InstrumentRow(
                timestamp,
                row[1],
                rail,
                fans,  # type: ignore[arg-type]
                temps,  # type: ignore[arg-type]
                gpios[0],
                gpios[1:],  # type: ignore[arg-type]
            )
        )
    if any(
        right.monotonic_ms <= left.monotonic_ms
        for left, right in zip(parsed, parsed[1:])
    ):
        fail("instrument timestamps are not strictly increasing")
    run_rows = [row for row in parsed if row.event == "run-start"]
    if len(run_rows) != 1:
        fail("instrument CSV requires exactly one run-start event")
    run_start = run_rows[0]
    run_index = parsed.index(run_start)
    baseline = parsed[:run_index]
    if (
        len(baseline) < 3
        or baseline[-1].monotonic_ms - baseline[0].monotonic_ms < MIN_BASELINE_MS
    ):
        fail("instrument CSV lacks a stable two-second stock baseline")
    if any(
        row.gpio437 != 0 or row.resets != (0, 1, 1) or row.rail_value <= 0
        for row in baseline
    ):
        fail(
            "stock baseline does not match engaged GPIO437 and reset tuple 454:0,455:1,456:1"
        )
    baseline_mean = sum(row.rail_value for row in baseline) // len(baseline)
    baseline_span = max(row.rail_value for row in baseline) - min(
        row.rail_value for row in baseline
    )
    if (
        baseline_mean <= 0
        or baseline_span * 100 > baseline_mean * MAX_BASELINE_VARIATION_PERCENT
    ):
        fail("independent rail baseline is not positive and stable within five percent")
    cut_indices = [
        index
        for index in range(run_index + 1, len(parsed))
        if parsed[index].gpio437 == 1
    ]
    if not cut_indices:
        fail("instrument CSV has no GPIO437 0-to-1 cut transition")
    cut_index = cut_indices[0]
    if parsed[cut_index - 1].gpio437 != 0 or any(
        row.gpio437 != 0 for row in parsed[:cut_index]
    ):
        fail("GPIO437 cut is not one unambiguous 0-to-1 transition")
    if any(row.gpio437 != 1 for row in parsed[cut_index:]):
        fail("GPIO437 re-engaged after the checked cut")
    reset_low_indices = [
        index
        for index in range(run_index, cut_index)
        if parsed[index].resets == (0, 0, 0)
    ]
    if not reset_low_indices:
        fail("resets 454/455/456 were not all low before GPIO437 cut")
    reset_low_index = reset_low_indices[0]
    if any(row.resets != (0, 0, 0) for row in parsed[reset_low_index:]):
        fail("a reset line rose after the pre-cut all-low observation")
    reset_to_cut_ms = (
        parsed[cut_index].monotonic_ms - parsed[reset_low_index].monotonic_ms
    )
    if reset_to_cut_ms < MIN_RESET_TO_CUT_MARGIN_MS:
        fail(
            "reset-before-GPIO437 evidence lacks the required two-millisecond "
            "canonical timing margin"
        )
    decay_indices = [
        index
        for index in range(cut_index, len(parsed))
        if parsed[index].rail_value * 100
        <= baseline_mean * MAX_DECAY_PERCENT_OF_BASELINE
    ]
    if not decay_indices:
        fail("independent rail signal never decayed below five percent of baseline")
    decay_first = decay_indices[0]
    decay_second = next(
        (
            index
            for index in decay_indices[1:]
            if parsed[index].monotonic_ms - parsed[decay_first].monotonic_ms
            >= MIN_POST_DECAY_CONFIRM_MS
        ),
        None,
    )
    if decay_second is None:
        fail("rail decay lacks two low observations at least five seconds apart")
    if any(
        row.rail_value * 100 > baseline_mean * MAX_DECAY_PERCENT_OF_BASELINE
        for row in parsed[decay_first:]
    ):
        fail("independent rail signal rebounded after the first low observation")
    for left, right in zip(parsed, parsed[1:]):
        if right.monotonic_ms - left.monotonic_ms > MAX_SAMPLE_GAP_MS:
            fail(
                "instrument capture has a gap larger than one second through capture end"
            )
    for row in parsed[run_index:]:
        if sum(rpm >= MIN_SPINNING_FAN_RPM for rpm in row.fans) < MIN_SPINNING_FANS:
            fail("independent cooling evidence was lost before capture end")
    return parsed, {
        "capture_start_ms": parsed[0].monotonic_ms,
        "run_start_ms": run_start.monotonic_ms,
        "reset_low_ms": parsed[reset_low_index].monotonic_ms,
        "gpio437_cut_ms": parsed[cut_index].monotonic_ms,
        "reset_to_gpio437_cut_margin_ms": reset_to_cut_ms,
        "rail_decay_first_ms": parsed[decay_first].monotonic_ms,
        "rail_decay_confirmed_ms": parsed[decay_second].monotonic_ms,
        "capture_end_ms": parsed[-1].monotonic_ms,
        "rail_baseline_mean": baseline_mean,
        "rail_decay_limit": baseline_mean * MAX_DECAY_PERCENT_OF_BASELINE // 100,
    }


def _utc(value: str, label: str) -> datetime:
    if not re.fullmatch(
        r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
        value,
    ):
        fail(f"{label} is not canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        fail(f"{label} is not a real UTC timestamp")
    return parsed


def _record_token(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", value):
        fail(f"{label} is not a safe non-empty record token")
    return value


def _verify_preflight(
    data: bytes,
    *,
    plan: dict[str, str],
    manifest: dict[str, str],
    expected_live_identity_sha256: str,
) -> dict[str, object]:
    receipt, _ = common._parse_kv_bytes(
        data,
        "instrumentation preflight receipt",
        exact_keys=PREFLIGHT_KEYS,
    )
    for key, value in {
        "schema": PREFLIGHT_SCHEMA,
        "ssh_host_key_sha256": plan["ssh_host_key_sha256"],
        "authorized_miner_identity_sha256": expected_live_identity_sha256,
        "test_point_approval": "hardware-reviewer-approved-deenergized",
        "lead_insulation_status": "inspected-intact",
        "fuse_status": "verified-serviceable-or-not-applicable-reviewed",
        "calibration_status": "in-calibration-and-zero-checked",
        "common_clock_id": manifest["common_clock_id"],
        "clock_sync_method": "recorded-common-clock-edge",
        "timestamp_unit": "milliseconds",
        "timestamp_rounding": "exact-or-conservative-floor",
        "recording_advancing_proof": "two-distinct-pre-run-samples-observed",
        "disconnect_path": "reachable-ac-input-disconnect",
        "disconnect_test_status": "proven-deenergized-before-probe-attachment",
        "operator_ack": "abort-on-rebound-cooling-loss-clock-loss-or-probe-movement",
        "publication": "pre-energization-reviewed-record",
    }.items():
        common._require(receipt, key, value, "instrumentation preflight receipt")
    for key in (
        "authorization_reference",
        "hardware_reviewer",
        "board_revision",
        "test_point_id",
        "test_point_reference_node",
        "rail_slot2_location",
        "rail_slot3_location",
        "rail_slot2_reference_or_conductor",
        "rail_slot3_reference_or_conductor",
        "instrument_identity",
        "instrument_cat_rating",
        "rail_slot2_channel",
        "rail_slot3_channel",
        "gpio437_channel",
        "gpio437_test_point",
        "gpio454_channel",
        "gpio454_test_point",
        "gpio455_channel",
        "gpio455_test_point",
        "gpio456_channel",
        "gpio456_test_point",
        "gpio_reference_node",
        "fan0_tach_channel",
        "fan0_tach_test_point",
        "fan1_tach_channel",
        "fan1_tach_test_point",
        "fan2_tach_channel",
        "fan2_tach_test_point",
        "fan3_tach_channel",
        "fan3_tach_test_point",
        "fan_tach_reference_node",
        "temperature_channels",
        "ttys1_rx_channel",
        "ttys1_rx_test_point",
        "ttys1_tx_channel",
        "ttys1_tx_test_point",
        "ttys2_rx_channel",
        "ttys2_rx_test_point",
        "ttys2_tx_channel",
        "ttys2_tx_test_point",
        "ttys3_rx_channel",
        "ttys3_rx_test_point",
        "ttys3_tx_channel",
        "ttys3_tx_test_point",
        "uart_reference_node",
        "wall_power_channel",
        "clock_sync_event_id",
        "emergency_responder",
    ):
        _record_token(receipt[key], f"instrumentation preflight {key}")
    common._sha(
        receipt["authorized_miner_identity_sha256"],
        "instrumentation preflight authorized miner identity",
    )
    range_min = _canonical_uint(
        receipt["expected_range_min"], "instrumentation preflight range minimum"
    )
    range_max = _canonical_uint(
        receipt["expected_range_max"],
        "instrumentation preflight range maximum",
        positive=True,
    )
    if range_min >= range_max:
        fail("instrumentation preflight expected range is empty or reversed")
    voltage_rating = _canonical_uint(
        receipt["instrument_voltage_rating_millivolts"],
        "instrumentation preflight voltage rating",
    )
    current_rating = _canonical_uint(
        receipt["instrument_current_rating_milliamps"],
        "instrumentation preflight current rating",
    )
    measurement_contract = {
        "rail-millivolts": (
            "isolated-differential-voltage",
            "millivolts",
            "isolated-differential",
            "two-isolated-slot-voltage-channels",
            "maximum-of-slot2-and-slot3-magnitude",
        ),
        "rail-current-milliamps": (
            "noninvasive-current-clamp",
            "milliamps",
            "noninvasive",
            "two-slot-dc-feed-current-clamps-one-polarity",
            "sum-of-slot2-and-slot3-magnitude",
        ),
    }
    method, unit, isolation, rail_topology, rail_composite = measurement_contract[
        manifest["rail_signal"]
    ]
    for key, value in {
        "measurement_method": method,
        "expected_range_unit": unit,
        "instrument_isolation": isolation,
        "rail_coverage": "slots2-and3-only-populated-hashboard-feeds",
        "rail_capture_topology": rail_topology,
        "rail_composite_rule": rail_composite,
        "rail_polarity": "positive-is-energized",
        "gpio437_polarity": "raw0-energized-raw1-safeoff",
        "gpio454_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio455_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio456_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "gpio_logic_threshold_approval": "hardware-reviewer-approved-for-observed-levels",
        "gpio_edge_clock": "common-clock-native-single-acquisition",
        "fan_tach_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "fan_harness_status": "untouched-fans-remain-connected",
        "uart_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "uart_line_contract": "passive-8n1-noninverting-no-transmit",
    }.items():
        common._require(receipt, key, value, "instrumentation preflight receipt")
    gpio_channels = [receipt[f"gpio{gpio}_channel"] for gpio in (437, 454, 455, 456)]
    gpio_points = [
        receipt[f"gpio{gpio}_test_point"] for gpio in (437, 454, 455, 456)
    ]
    if len(set(gpio_channels)) != 4 or len(set(gpio_points)) != 4:
        fail("instrumentation preflight GPIO channels and test points must be unique")
    rail_channels = [receipt[f"rail_slot{slot}_channel"] for slot in (2, 3)]
    if len(set(rail_channels)) != 2:
        fail("instrumentation preflight rail channels must be unique per populated slot")
    tach_channels = [receipt[f"fan{fan}_tach_channel"] for fan in range(4)]
    tach_points = [receipt[f"fan{fan}_tach_test_point"] for fan in range(4)]
    if len(set(tach_channels)) != 4 or len(set(tach_points)) != 4:
        fail("instrumentation preflight fan tach channels and test points must be unique")
    uart_channels = [
        receipt[f"ttys{path}_{direction}_channel"]
        for path in (1, 2, 3)
        for direction in ("rx", "tx")
    ]
    uart_points = [
        receipt[f"ttys{path}_{direction}_test_point"]
        for path in (1, 2, 3)
        for direction in ("rx", "tx")
    ]
    if len(set(uart_channels)) != 6 or len(set(uart_points)) != 6:
        fail("instrumentation preflight UART channels and test points must be unique")
    if method == "isolated-differential-voltage" and voltage_rating < range_max:
        fail("instrumentation preflight voltage rating is below the reviewed range")
    if method == "noninvasive-current-clamp" and current_rating < range_max:
        fail("instrumentation preflight current rating is below the reviewed range")
    cat_rating = receipt["instrument_cat_rating"]
    if not (
        cat_rating == "not-applicable-reviewed"
        or re.fullmatch(r"CAT-[IVX]+-[1-9][0-9]*V", cat_rating)
    ):
        fail("instrumentation preflight CAT rating is not explicit and reviewed")
    slow_sample_rate = _canonical_uint(
        receipt["slow_monitor_sample_rate_millihz"],
        "instrumentation preflight slow-monitor sample rate",
        positive=True,
    )
    if slow_sample_rate < 1_000:
        fail(
            "instrumentation preflight slow-monitor sample rate is below one sample per second"
        )
    gpio_expected_max = _canonical_uint(
        receipt["gpio_expected_max_millivolts"],
        "instrumentation preflight GPIO expected maximum",
        positive=True,
    )
    gpio_input_rating = _canonical_uint(
        receipt["gpio_input_rating_millivolts"],
        "instrumentation preflight GPIO input rating",
        positive=True,
    )
    gpio_input_impedance = _canonical_uint(
        receipt["gpio_input_impedance_ohms"],
        "instrumentation preflight GPIO input impedance",
        positive=True,
    )
    gpio_edge_rate = _canonical_uint(
        receipt["gpio_edge_sample_rate_hz"],
        "instrumentation preflight GPIO edge sample rate",
        positive=True,
    )
    gpio_edge_resolution = _canonical_uint(
        receipt["gpio_edge_resolution_us"],
        "instrumentation preflight GPIO edge resolution",
        positive=True,
    )
    tach_expected_max = _canonical_uint(
        receipt["fan_tach_expected_max_millivolts"],
        "instrumentation preflight tach expected maximum",
        positive=True,
    )
    tach_input_rating = _canonical_uint(
        receipt["fan_tach_input_rating_millivolts"],
        "instrumentation preflight tach input rating",
        positive=True,
    )
    tach_input_impedance = _canonical_uint(
        receipt["fan_tach_input_impedance_ohms"],
        "instrumentation preflight tach input impedance",
        positive=True,
    )
    tach_sample_rate = _canonical_uint(
        receipt["fan_tach_sample_rate_hz"],
        "instrumentation preflight tach sample rate",
        positive=True,
    )
    uart_expected_max = _canonical_uint(
        receipt["uart_expected_max_millivolts"],
        "instrumentation preflight UART expected maximum",
        positive=True,
    )
    uart_input_rating = _canonical_uint(
        receipt["uart_input_rating_millivolts"],
        "instrumentation preflight UART input rating",
        positive=True,
    )
    uart_input_impedance = _canonical_uint(
        receipt["uart_input_impedance_ohms"],
        "instrumentation preflight UART input impedance",
        positive=True,
    )
    uart_max_baud = _canonical_uint(
        receipt["uart_max_baud"],
        "instrumentation preflight UART maximum baud",
        positive=True,
    )
    uart_sample_rate = _canonical_uint(
        receipt["uart_sample_rate_hz"],
        "instrumentation preflight UART sample rate",
        positive=True,
    )
    if gpio_input_rating < gpio_expected_max:
        fail("instrumentation preflight GPIO input is electrically underrating")
    if tach_input_rating < tach_expected_max:
        fail("instrumentation preflight tach input is electrically underrating")
    if uart_input_rating < uart_expected_max:
        fail("instrumentation preflight UART input is electrically underrating")
    if min(gpio_input_impedance, tach_input_impedance, uart_input_impedance) < (
        MIN_DIGITAL_INPUT_IMPEDANCE_OHMS
    ):
        fail("instrumentation preflight digital input impedance is below one megohm")
    if gpio_edge_rate < MIN_GPIO_EDGE_SAMPLE_RATE_HZ:
        fail("instrumentation preflight GPIO edge sample rate is below 100 kHz")
    if gpio_edge_resolution > MAX_GPIO_EDGE_RESOLUTION_US:
        fail("instrumentation preflight GPIO edge resolution exceeds 10 microseconds")
    if tach_sample_rate < MIN_TACH_SAMPLE_RATE_HZ:
        fail("instrumentation preflight tach sample rate is below 10 kHz")
    if uart_max_baud != S19K_UART_MAX_BAUD:
        fail("instrumentation preflight UART maximum baud is not exact S19k FastUART")
    if uart_sample_rate < uart_max_baud * MIN_UART_OVERSAMPLE:
        fail("instrumentation preflight UART sample rate is below eight-times oversampling")
    skew = _canonical_uint(
        receipt["clock_skew_max_ms"], "instrumentation preflight clock skew"
    )
    if skew > 1:
        fail("instrumentation preflight common-clock skew exceeds one millisecond")
    created = _utc(manifest["created_utc"], "instrument manifest created_utc")
    authorized = _utc(receipt["authorized_utc"], "preflight authorized_utc")
    disconnected = _utc(
        receipt["disconnect_tested_utc"], "preflight disconnect_tested_utc"
    )
    calibration_due = _utc(
        receipt["calibration_due_utc"], "preflight calibration_due_utc"
    )
    if not disconnected <= authorized <= created:
        fail("instrumentation preflight order is not disconnect <= authority <= capture")
    age = int((created - authorized).total_seconds())
    if age > MAX_PREFLIGHT_AGE_SECONDS:
        fail("instrumentation preflight is older than 24 hours at bundle creation")
    if calibration_due < created:
        fail("instrumentation calibration expired before bundle creation")
    return {
        "preflight_schema": PREFLIGHT_SCHEMA,
        "preflight_authorization_reference": receipt["authorization_reference"],
        "preflight_hardware_reviewer": receipt["hardware_reviewer"],
        "preflight_test_point_id": receipt["test_point_id"],
        "preflight_board_revision": receipt["board_revision"],
        "preflight_instrument_identity": receipt["instrument_identity"],
        "preflight_authorized_utc": receipt["authorized_utc"],
        "preflight_clock_skew_max_ms": skew,
        "preflight_measurement_method": method,
        "preflight_expected_range": [range_min, range_max, unit],
        "preflight_expected_range_min": range_min,
        "preflight_expected_range_max": range_max,
        "preflight_expected_range_unit": unit,
        "preflight_voltage_rating_millivolts": voltage_rating,
        "preflight_current_rating_milliamps": current_rating,
        "preflight_slow_monitor_sample_rate_millihz": slow_sample_rate,
        "preflight_gpio_edge_sample_rate_hz": gpio_edge_rate,
        "preflight_gpio_edge_resolution_us": gpio_edge_resolution,
        "preflight_fan_tach_sample_rate_hz": tach_sample_rate,
        "preflight_uart_max_baud": uart_max_baud,
        "preflight_uart_sample_rate_hz": uart_sample_rate,
        "preflight_rail_coverage": receipt["rail_coverage"],
        "preflight_rail_capture_topology": rail_topology,
        "preflight_rail_composite_rule": rail_composite,
    }


def _parse_uart(
    data: bytes, timing: dict[str, int]
) -> tuple[list[UartRow], dict[str, object]]:
    parsed: list[UartRow] = []
    seen_rows: set[tuple[int, str, str, bytes]] = set()
    for number, row in enumerate(_csv_rows(data, UART_HEADER, "UART CSV"), 2):
        timestamp = _canonical_uint(row[0], f"UART row {number} monotonic_ms")
        if row[1] not in REQUIRED_PATHS + OPTIONAL_PATHS:
            fail(f"UART row {number} names a path outside the plan contract")
        if row[2] not in ("tx", "rx"):
            fail(f"UART row {number} has an invalid direction")
        if not re.fullmatch(r"[0-9A-F]+", row[3]) or len(row[3]) % 2:
            fail(
                f"UART row {number} frame_hex is not canonical uppercase even-length hex"
            )
        frame = bytes.fromhex(row[3])
        if not 2 <= len(frame) <= 4096:
            fail(f"UART row {number} frame has an invalid length")
        value = UartRow(timestamp, row[1], row[2], frame)
        key = (timestamp, row[1], row[2], frame)
        if key in seen_rows:
            fail("UART CSV repeats an identical timestamped frame")
        seen_rows.add(key)
        parsed.append(value)
    if any(
        right.monotonic_ms < left.monotonic_ms
        for left, right in zip(parsed, parsed[1:])
    ):
        fail("UART timestamps are not monotonic")
    if any(
        row.monotonic_ms < timing["capture_start_ms"]
        or row.monotonic_ms > timing["capture_end_ms"]
        for row in parsed
    ):
        fail("UART timestamps fall outside the common-clock instrument capture")
    work_signature = bytes.fromhex("55AA2136")
    tx_tails: dict[str, bytes] = {}
    for row in parsed:
        if row.direction != "tx":
            continue
        combined = tx_tails.get(row.path, b"") + row.frame
        if work_signature in combined:
            fail("independent UART capture contains a forbidden 55AA2136 work frame")
        tx_tails[row.path] = combined[-(len(work_signature) - 1) :]
    window = [
        row
        for row in parsed
        if timing["run_start_ms"] <= row.monotonic_ms < timing["gpio437_cut_ms"]
    ]
    coverage: dict[str, list[str]] = {}
    for path in REQUIRED_PATHS:
        directions = sorted({row.direction for row in window if row.path == path})
        if directions != ["rx", "tx"]:
            fail(f"independent UART capture lacks both TX and RX coverage for {path}")
        coverage[path] = directions
    return parsed, {
        "uart_frame_count": len(parsed),
        "uart_window_frame_count": len(window),
        "uart_required_path_coverage": coverage,
        "uart_work_frame_count": 0,
    }


def _evidence_file(
    evidence_dir: Path,
    manifest: dict[str, str],
    prefix: str,
    label: str,
) -> tuple[Path, bytes]:
    filename = manifest[f"{prefix}_file"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename):
        fail(f"{label} filename is not one safe direct-child basename")
    path = evidence_dir / filename
    data = _stable_regular_bytes_bounded(path, label, MAX_CANONICAL_BYTES)
    expected_sha = common._sha(
        manifest.get(f"{prefix}_sha256"), f"manifest {prefix}_sha256"
    )
    expected_bytes = _canonical_uint(
        manifest.get(f"{prefix}_bytes", ""),
        f"manifest {prefix}_bytes",
        positive=True,
    )
    if common._hash(data) != expected_sha or len(data) != expected_bytes:
        fail(f"{label} does not match the instrument manifest")
    return path, data


def _stream_evidence_file(
    evidence_dir: Path,
    manifest: dict[str, str],
    prefix: str,
    label: str,
) -> tuple[Path, str, int]:
    filename = manifest[f"{prefix}_file"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename):
        fail(f"{label} filename is not one safe direct-child basename")
    path = evidence_dir / filename
    digest, size = _stable_regular_digest(path, label)
    expected_sha = common._sha(
        manifest.get(f"{prefix}_sha256"), f"manifest {prefix}_sha256"
    )
    expected_bytes = _canonical_uint(
        manifest.get(f"{prefix}_bytes", ""),
        f"manifest {prefix}_bytes",
        positive=True,
    )
    if digest != expected_sha or size != expected_bytes:
        fail(f"{label} does not match the instrument manifest")
    return path, digest, size


def verify(
    plan_path: Path,
    trial_dir: Path,
    evidence_dir: Path,
    *,
    require_bundle_complete: bool = True,
) -> dict[str, object]:
    plan_data, plan = common._parse_kv_file(plan_path, "deploy plan")
    _verify_plan(plan)
    _real_directory(trial_dir, "copied trial directory")
    _real_directory(evidence_dir, "instrument evidence directory")

    receipt_path = trial_dir / "runtime_handoff_no_work_transcript"
    receipt_data, receipt = common._parse_kv_file(
        receipt_path,
        "handoff-no-work transcript receipt",
        exact_keys=RECEIPT_KEYS,
    )
    required_receipt = {
        "schema": RECEIPT_SCHEMA,
        "deploy_mode": "handoff-no-work",
        "transcript_mode": "0600",
        "transcript_uid": "0",
        "transcript_gid": "0",
        "source_runtime_active_schema": SOURCE_RUNTIME_SCHEMA,
        "pending_runtime_schema": PENDING_RUNTIME_SCHEMA,
        "terminal_handoff_receipt_schema": TERMINAL_HANDOFF_SCHEMA,
        "safeoff_receipt_schema": SAFEOFF_SCHEMA,
        "live_identity_schema": LIVE_IDENTITY_SCHEMA,
        "live_identity_profile": LIVE88_PROFILE,
        "wrapper_exit_status": str(EXPECTED_WRAPPER_EXIT),
        "no_work_active_count": "1",
        "full_frame_count": "0",
        "bounded_tx_count": "0",
        "dispatch_admitted_count": "0",
        "semantic_verification": "host-plus-independent-instruments-required",
        "persistent_mutation": "false",
        "publication": "no-clobber-hard-link-after-fsync",
    }
    for key, value in required_receipt.items():
        common._require(receipt, key, value, "handoff-no-work transcript receipt")
    _canonical_uint(
        receipt.get("discarded_job_count", ""), "receipt discarded_job_count"
    )
    _canonical_uint(
        receipt.get("transcript_mnt_id", ""), "receipt transcript_mnt_id", positive=True
    )
    _canonical_uint(
        receipt.get("transcript_inode", ""), "receipt transcript_inode", positive=True
    )

    remote_paths = {
        key: PurePosixPath(receipt[key])
        for key in RECEIPT_KEYS
        if key.endswith("_path") and key != "transcript_path"
    }
    remote_paths["transcript_path"] = PurePosixPath(receipt["transcript_path"])
    parents = {path.parent for path in remote_paths.values()}
    if len(parents) != 1:
        fail("no-work receipt paths do not share one remote trial directory")
    remote_parent = next(iter(parents))
    if remote_parent.parent != PurePosixPath(
        "/tmp"
    ) or not remote_parent.name.startswith("dcentrald_bench_t1_"):
        fail("no-work receipt does not name one direct S19k /tmp trial directory")
    if not re.fullmatch(
        r"\.startup_daemon_transcript\.[1-9][0-9]*\.[1-9][0-9]*",
        PurePosixPath(receipt["transcript_path"]).name,
    ):
        fail("no-work receipt has a non-canonical daemon transcript filename")

    transcript_path, transcript_data = _resolve_receipt_file(
        trial_dir,
        receipt,
        "transcript_path",
        "transcript_sha256",
        "transcript_bytes",
        None,
        "no-work transcript",
    )
    source_path, source_data = _resolve_receipt_file(
        trial_dir,
        receipt,
        "source_runtime_active_path",
        "source_runtime_active_sha256",
        "source_runtime_active_bytes",
        "runtime_active_pre_safeoff",
        "source runtime receipt",
    )
    pending_path, pending_data = _resolve_receipt_file(
        trial_dir,
        receipt,
        "pending_runtime_path",
        "pending_runtime_sha256",
        "pending_runtime_bytes",
        "runtime_active",
        "pending runtime receipt",
    )
    terminal_path, terminal_data = _resolve_receipt_file(
        trial_dir,
        receipt,
        "terminal_handoff_receipt_path",
        "terminal_handoff_receipt_sha256",
        "terminal_handoff_receipt_bytes",
        "runtime_terminal_safeoff",
        "terminal handoff receipt",
    )
    safeoff_path, safeoff_data = _resolve_receipt_file(
        trial_dir,
        receipt,
        "safeoff_receipt_path",
        "safeoff_receipt_sha256",
        "safeoff_receipt_bytes",
        "runtime_safeoff_terminal_receipt",
        "SafeOff companion",
    )
    startup_data: dict[str, bytes] = {}
    for prefix, expected_name, label in (
        ("startup_c1", "runtime_startup_c1_child_identity", "startup C1"),
        ("startup_j1", "runtime_startup_j1_daemon_blocked", "startup J1"),
        ("startup_j2", "runtime_startup_j2_child_bound", "startup J2"),
        ("startup_release", "runtime_startup_release", "startup release"),
    ):
        _, startup_data[prefix] = _resolve_receipt_file(
            trial_dir,
            receipt,
            f"{prefix}_path",
            f"{prefix}_sha256",
            f"{prefix}_bytes",
            expected_name,
            label,
        )

    staged_contract = (
        ("dcentrald", "sha256", "bytes", "staged daemon"),
        ("dcentrald_s19k.toml", "config_sha256", "config_bytes", "staged config"),
        ("run_trial", "runner_sha256", "runner_bytes", "staged runner"),
        (
            "supervisor_custody_observer",
            "custody_observer_sha256",
            "custody_observer_bytes",
            "staged custody observer",
        ),
        (
            "stock_restart_helper",
            "stock_restart_helper_sha256",
            "stock_restart_helper_bytes",
            "staged stock restart helper",
        ),
    )
    staged: dict[str, bytes] = {}
    for filename, sha_key, bytes_key, label in staged_contract:
        data = common._stable_regular_bytes(trial_dir / filename, label)
        if common._hash(data) != plan[sha_key] or len(data) != int(plan[bytes_key]):
            fail(f"{label} does not match the live deploy plan")
        staged[filename] = data

    source = common._parse_kv_bytes(source_data, "source runtime receipt")[0]
    pending = common._parse_kv_bytes(pending_data, "pending runtime receipt")[0]
    terminal = common._parse_kv_bytes(terminal_data, "terminal handoff receipt")[0]
    common._require(source, "schema", SOURCE_RUNTIME_SCHEMA, "source runtime receipt")
    common._require(source, "deploy_mode", "handoff-no-work", "source runtime receipt")
    common._verify_bound_record(source, receipt, plan, "source runtime receipt")
    for key, value in {
        "schema": PENDING_RUNTIME_SCHEMA,
        "phase": "terminal-safeoff-stock-restart-pending",
        "terminal": "true",
        "source_runtime_active_schema": SOURCE_RUNTIME_SCHEMA,
        "source_runtime_active_sha256": receipt["source_runtime_active_sha256"],
        "safeoff_receipt_schema": SAFEOFF_SCHEMA,
        "safeoff_receipt_sha256": receipt["safeoff_receipt_sha256"],
        "terminal_handoff_receipt_schema": TERMINAL_HANDOFF_SCHEMA,
        "terminal_handoff_receipt_sha256": receipt["terminal_handoff_receipt_sha256"],
        "resets": "454:0,455:0,456:0",
        "psu": "437:1",
        "dcentrald": "absent",
        "stock_supervisor": "absent",
        "stock_bosminer": "absent",
        "watchdog_fd": "absent",
        "next_authority": "exact-stock-restart-helper-only",
        "persistent_mutation": "false",
    }.items():
        common._require(pending, key, value, "pending runtime receipt")
    common._verify_bound_record(pending, receipt, plan, "pending runtime receipt")
    for key, value in {
        "schema": TERMINAL_HANDOFF_SCHEMA,
        "disposition": "terminal-safeoff-partial-stock-owner",
        "terminal_safeoff": "true",
        "watchdog_magic_close": "true",
        "watchdog_worker_joined": "true",
        "resets": "454:0,455:0,456:0",
        "psu": "437:1",
        "supervisor_gone": "true",
        "child_gone": "true",
        "global_stock_absence": "true",
        "replacement_or_ambiguity": "false",
        "persistent_mutation": "false",
    }.items():
        common._require(terminal, key, value, "terminal handoff receipt")
    common._verify_bound_record(terminal, receipt, plan, "terminal handoff receipt")
    safeoff_line = common._verify_safeoff_line(
        common._decode_text(safeoff_data, "SafeOff companion"), receipt
    )
    transaction_id = _verify_startup_chain(
        receipt,
        startup_data["startup_c1"],
        startup_data["startup_j1"],
        startup_data["startup_j2"],
        startup_data["startup_release"],
    )
    transcript_result = _verify_transcript(transcript_data, receipt)

    manifest_path = evidence_dir / "phase12_instrument_manifest"
    manifest_data, manifest = common._parse_kv_file(
        manifest_path,
        "instrument manifest",
        exact_keys=MANIFEST_KEYS,
    )
    verifier_sha, verifier_bytes = _stable_regular_digest(
        Path(__file__), "host verifier"
    )
    preparer_path = Path(__file__).with_name(PREPARER_FILENAME)
    preparer_sha, preparer_bytes = _stable_regular_digest(
        preparer_path,
        "host evidence preparer",
    )
    normalizer_path = Path(__file__).with_name(NORMALIZER_FILENAME)
    normalizer_sha, normalizer_bytes = _stable_regular_digest(
        normalizer_path,
        "Phase 1+2 capture normalizer",
    )
    capture_verifier_path = Path(raw_capture.__file__)
    capture_verifier_sha, capture_verifier_bytes = _stable_regular_digest(
        capture_verifier_path,
        "Phase 1+2 raw capture verifier",
    )
    for key, value in {
        "schema": MANIFEST_SCHEMA,
        "claim": "joined-phase1-instrumentation+phase2-handoff-no-work",
        "plan_sha256": common._hash(plan_data),
        "target_receipt_sha256": common._hash(receipt_data),
        "transcript_sha256": receipt["transcript_sha256"],
        "verifier_sha256": verifier_sha,
        "verifier_bytes": str(verifier_bytes),
        "preparer_sha256": preparer_sha,
        "preparer_bytes": str(preparer_bytes),
        "normalizer_sha256": normalizer_sha,
        "normalizer_bytes": str(normalizer_bytes),
        "capture_verifier_sha256": capture_verifier_sha,
        "capture_verifier_bytes": str(capture_verifier_bytes),
        "publication": "post-run-content-manifest",
    }.items():
        common._require(manifest, key, value, "instrument manifest")
    if manifest.get("rail_signal") not in ("rail-millivolts", "rail-current-milliamps"):
        fail(
            "instrument manifest rail_signal is not an independent hashboard rail measurement"
        )
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", manifest.get("common_clock_id", "")
    ):
        fail("instrument manifest common_clock_id is not a safe evidence token")
    if not re.fullmatch(
        r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
        manifest.get("created_utc", ""),
    ):
        fail("instrument manifest created_utc is not canonical UTC")
    file_prefixes = tuple(EVIDENCE_FILENAMES)
    if len({manifest[f"{prefix}_file"] for prefix in file_prefixes}) != len(
        file_prefixes
    ):
        fail(
            "instrument manifest must preserve ten distinct preflight, provenance, and capture files"
        )
    preflight_path, preflight_data = _evidence_file(
        evidence_dir, manifest, "preflight", "instrumentation preflight receipt"
    )
    preflight_result = _verify_preflight(
        preflight_data,
        plan=plan,
        manifest=manifest,
        expected_live_identity_sha256=receipt["live_identity_sha256"],
    )
    normalization_config_path, normalization_config_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "normalization_config",
        "normalization config",
    )
    normalization_receipt_path, normalization_receipt_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "normalization_receipt",
        "normalization receipt",
    )
    instrument_source_path, instrument_source_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "instrument_source",
        "raw instrument export",
    )
    instrument_csv_path, instrument_csv = _evidence_file(
        evidence_dir, manifest, "instrument_csv", "canonical instrument CSV"
    )
    uart_source_path, uart_source_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "uart_source",
        "raw UART export",
    )
    uart_csv_path, uart_csv = _evidence_file(
        evidence_dir, manifest, "uart_csv", "canonical UART CSV"
    )
    capture_contract_path, capture_contract_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "capture_contract",
        "raw capture contract",
    )
    capture_blocks_path, capture_blocks_sha, _ = _stream_evidence_file(
        evidence_dir,
        manifest,
        "capture_blocks",
        "raw per-channel capture blocks",
    )
    capture_verification_path, capture_verification_sha, _ = (
        _stream_evidence_file(
            evidence_dir,
            manifest,
            "capture_verification",
            "raw capture verification receipt",
        )
    )
    try:
        normalization = normalizer.verify_normalization(
            config_path=normalization_config_path,
            instrument_source=instrument_source_path,
            uart_source=uart_source_path,
            instrument_csv=instrument_csv_path,
            uart_csv=uart_csv_path,
            receipt_path=normalization_receipt_path,
        )
    except normalizer.NormalizationError as error:
        fail(f"capture normalization provenance is invalid: {error}")
    if normalization["common_clock_id"] != manifest["common_clock_id"]:
        fail("normalization receipt common_clock_id does not match the manifest")
    if normalization["rail_signal"] != manifest["rail_signal"]:
        fail("normalization receipt rail_signal does not match the manifest")
    try:
        raw_capture_result = raw_capture.verify_files(
            capture_contract_path,
            capture_blocks_path,
            capture_verification_path,
        )
    except raw_capture.CaptureVerificationError as error:
        fail(f"raw per-channel capture provenance is invalid: {error}")
    if raw_capture_result["common_clock_id"] != manifest["common_clock_id"]:
        fail("raw capture common_clock_id does not match the manifest")
    if raw_capture_result["rail_signal"] != manifest["rail_signal"]:
        fail("raw capture rail_signal does not match the manifest")
    if (
        raw_capture_result["contract"]["sha256"] != capture_contract_sha
        or raw_capture_result["blocks"]["sha256"] != capture_blocks_sha
    ):
        fail("raw capture verification does not bind the manifested source bytes")
    dangerous_millic = _parse_config_dangerous_millic(staged["dcentrald_s19k.toml"])
    instrument_rows, timing = _parse_instrument(
        instrument_csv,
        dangerous_millic,
        rail_range_min=int(preflight_result["preflight_expected_range_min"]),
        rail_range_max=int(preflight_result["preflight_expected_range_max"]),
    )
    try:
        raw_rail_signal, raw_rail_samples = raw_capture.rail_composite_at_times(
            capture_contract_path,
            capture_blocks_path,
            [row.monotonic_ms * 1_000_000 for row in instrument_rows],
        )
    except raw_capture.CaptureVerificationError as error:
        fail(f"raw two-rail composite replay is invalid: {error}")
    if raw_rail_signal != manifest["rail_signal"]:
        fail("raw two-rail composite signal does not match the manifest")
    for row, (slot2, slot3, composite) in zip(
        instrument_rows, raw_rail_samples
    ):
        if row.rail_value != composite:
            fail(
                "canonical rail_value is not the exact maximum of the retained "
                f"slot2/slot3 samples at {row.monotonic_ms} ms"
            )
    try:
        raw_capture_recheck = raw_capture.verify_files(
            capture_contract_path,
            capture_blocks_path,
            capture_verification_path,
        )
    except raw_capture.CaptureVerificationError as error:
        fail(f"raw per-channel capture changed during rail replay: {error}")
    if raw_capture_recheck != raw_capture_result:
        fail("raw per-channel capture changed during rail replay")
    uart_rows, uart_result = _parse_uart(uart_csv, timing)
    if (
        raw_capture_result["window_start_ns"]
        > timing["capture_start_ms"] * 1_000_000
        or raw_capture_result["window_end_ns"]
        < timing["capture_end_ms"] * 1_000_000
    ):
        fail("raw per-channel blocks do not cover the canonical evidence window")

    result: dict[str, object] = {
        "schema": VERIFICATION_SCHEMA,
        "claim": "no-work handoff, checked SafeOff, independent rail cut, reset-before-cut, cooling-through-decay, and zero captured UART work frames",
        "publication": "host-create-new-file-and-directory-fsync",
        "plan_sha256": common._hash(plan_data),
        "target_receipt_sha256": common._hash(receipt_data),
        "transcript_sha256": receipt["transcript_sha256"],
        "instrument_manifest_sha256": common._hash(manifest_data),
        "artifact_sha256": plan["sha256"],
        "runner_sha256": plan["runner_sha256"],
        "live_identity_sha256": receipt["live_identity_sha256"],
        "startup_transaction_id": transaction_id,
        "safeoff_receipt": safeoff_line,
        "transcript_file": transcript_path.name,
        "source_runtime_file": source_path.name,
        "pending_runtime_file": pending_path.name,
        "terminal_handoff_file": terminal_path.name,
        "safeoff_file": safeoff_path.name,
        "preflight_file": preflight_path.name,
        "preflight_sha256": common._hash(preflight_data),
        "instrument_csv_file": instrument_csv_path.name,
        "uart_csv_file": uart_csv_path.name,
        "normalization_config_sha256": normalization_config_sha,
        "normalization_receipt_sha256": normalization_receipt_sha,
        "normalization_id": normalization["normalization_id"],
        "raw_capture_verification_id": raw_capture_result["verification_id"],
        "capture_contract_sha256": capture_contract_sha,
        "capture_blocks_sha256": capture_blocks_sha,
        "capture_verification_sha256": capture_verification_sha,
        "raw_capture_channel_count": len(raw_capture_result["channels"]),
        "raw_capture_rates_and_gaps_computed": raw_capture_result[
            "rates_and_gaps_computed_from_raw_blocks"
        ],
        "both_populated_rail_feeds_retained": raw_capture_result[
            "both_populated_rail_feeds_retained"
        ],
        "rail_composite_rule_verified": "maximum-of-slot2-and-slot3-magnitude",
        "instrument_source_sha256": instrument_source_sha,
        "uart_source_sha256": uart_source_sha,
        "instrument_sample_count": len(instrument_rows),
        "uart_sample_count": len(uart_rows),
        "common_clock_id": manifest["common_clock_id"],
        "rail_signal": manifest["rail_signal"],
        "verifier_sha256": verifier_sha,
        "verifier_bytes": verifier_bytes,
        "preparer_sha256": preparer_sha,
        "preparer_bytes": preparer_bytes,
        "normalizer_sha256": normalizer_sha,
        "normalizer_bytes": normalizer_bytes,
        "capture_verifier_sha256": capture_verifier_sha,
        "capture_verifier_bytes": capture_verifier_bytes,
        "dangerous_temp_millic": dangerous_millic,
        **timing,
        **preflight_result,
        **transcript_result,
        **uart_result,
    }
    canonical = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    result["verification_id"] = hashlib.sha256(
        (canonical + "\n").encode("ascii")
    ).hexdigest()
    if require_bundle_complete:
        _verify_bundle_completion(evidence_dir, manifest, manifest_data, result)
    return result


def _canonical_result_bytes(result: dict[str, object]) -> bytes:
    return (
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _verify_bundle_completion(
    evidence_dir: Path,
    manifest: dict[str, str],
    manifest_data: bytes,
    result: dict[str, object],
) -> None:
    for prefix, filename in EVIDENCE_FILENAMES.items():
        common._require(manifest, f"{prefix}_file", filename, "instrument manifest")
    result_path = evidence_dir / EMBEDDED_RESULT_FILENAME
    result_data = common._stable_regular_bytes(
        result_path, "embedded host verification"
    )
    expected_result = _canonical_result_bytes(result)
    if result_data != expected_result:
        fail("embedded host verification differs from fresh semantic verification")
    receipt_path = evidence_dir / BUNDLE_RECEIPT_FILENAME
    _, receipt = common._parse_kv_file(
        receipt_path,
        "Phase 1+2 bundle completion receipt",
        exact_keys=BUNDLE_KEYS,
    )
    expected_files = {
        "phase12_instrument_manifest",
        EMBEDDED_RESULT_FILENAME,
        BUNDLE_RECEIPT_FILENAME,
        *(manifest[f"{prefix}_file"] for prefix in EVIDENCE_FILENAMES),
    }
    for key, value in {
        "schema": BUNDLE_SCHEMA,
        "instrument_manifest_sha256": common._hash(manifest_data),
        "instrument_manifest_bytes": str(len(manifest_data)),
        "host_verification_sha256": common._hash(result_data),
        "host_verification_bytes": str(len(result_data)),
        "verification_id": str(result["verification_id"]),
        "preparer_sha256": str(result["preparer_sha256"]),
        "preparer_bytes": str(result["preparer_bytes"]),
        "file_count": str(len(EVIDENCE_FILENAMES) + 3),
        "publication": "host-staged-hard-link-bundle-and-directory-fsync",
    }.items():
        common._require(receipt, key, value, "Phase 1+2 bundle completion receipt")
    actual_files: set[str] = set()
    try:
        with os.scandir(evidence_dir) as entries:
            for entry in entries:
                if len(actual_files) >= len(expected_files):
                    fail(
                        "Phase 1+2 evidence bundle file set is incomplete or contains extras"
                    )
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    fail(f"cannot stat Phase 1+2 bundle member {entry.name!r}: {error}")
                if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    fail("Phase 1+2 evidence bundle contains a non-regular member")
                if os.name == "posix" and metadata.st_nlink != 1:
                    fail(
                        "Phase 1+2 evidence bundle member must have exactly one hard link"
                    )
                actual_files.add(entry.name)
    except OSError as error:
        fail(f"cannot enumerate Phase 1+2 evidence bundle: {error}")
    if actual_files != expected_files:
        fail("Phase 1+2 evidence bundle file set is incomplete or contains extras")


def _publish_result(path: Path, result: dict[str, object]) -> None:
    parent = path.parent.resolve(strict=True)
    _real_directory(parent, "verification output parent")
    if path.name in ("", ".", ".."):
        fail("verification output requires a filename")
    output = parent / path.name
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        fail(f"cannot stat verification output: {error}")
    else:
        fail("verification output already exists; refusing to clobber it")

    payload = _canonical_result_bytes(result)
    descriptor = -1
    created = False
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short verification-result write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(output)
            except OSError:
                pass
        fail(
            f"cannot publish verification output with file and directory fsync: {error}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the joined S19k instrumented handoff-no-work gate"
    )
    parser.add_argument(
        "--plan", required=True, type=Path, help="live schema-v12 no-work deploy plan"
    )
    parser.add_argument(
        "--trial-dir",
        required=True,
        type=Path,
        help="complete copied remote trial directory",
    )
    parser.add_argument(
        "--instrument-dir",
        required=True,
        type=Path,
        help="common-clock raw/canonical instrument evidence directory",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new no-clobber canonical host-verification receipt (run under Linux/WSL)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the complete verification result"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan_path = args.plan.resolve(strict=True)
        trial_dir = args.trial_dir.resolve(strict=True)
        evidence_dir = args.instrument_dir.resolve(strict=True)
        output_parent = args.output.parent.resolve(strict=True)
        if output_parent == evidence_dir:
            fail(
                "external verification output must be outside the sealed evidence bundle"
            )
        result = verify(
            plan_path,
            trial_dir,
            evidence_dir,
        )
        _publish_result(args.output, result)
    except (OSError, VerificationError) as error:
        print(f"S19K_PHASE12_NO_WORK_REFUSED: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(
            "S19K_PHASE12_NO_WORK_OK "
            f"verification_id={result['verification_id']} "
            f"transcript_sha256={result['transcript_sha256']} "
            f"rail_decay_confirmed_ms={result['rail_decay_confirmed_ms']} "
            f"uart_work_frame_count={result['uart_work_frame_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
