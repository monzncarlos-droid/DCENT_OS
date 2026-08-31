#!/usr/bin/env python3
"""Fail-closed host verifier for the S19k Track-1 endurance gate.

The miner publishes bounded minute aggregates, not an unbounded UART log.  The
host collector stores every segment and a content chain before acknowledging
it.  This verifier independently replays that chain and checks the declared
Phase-3 operating band, UART acceptance windows, wall-power coverage, and the
target's terminal SafeOff receipts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import struct
import sys
import time
from typing import Iterable, Mapping


PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"
BASELINE_SCHEMA = "dcentos.s19k-endurance-baseline/v4"
SEGMENT_SCHEMA = "dcentos.s19k-endurance-segment/v1"
MANIFEST_SCHEMA = "dcentos.s19k-endurance-off-target-manifest-entry/v1"
DAEMON_TERMINAL_SCHEMA = "dcentos.s19k-endurance-daemon-terminal/v1"
DAEMON_FAILURE_SCHEMA = "dcentos.s19k-endurance-daemon-failure/v1"
TARGET_RECEIPT_SCHEMA = "dcentos.s19k-endurance-work-receipt/v1"
TARGET_FAILURE_RECEIPT_SCHEMA = "dcentos.s19k-endurance-failure-receipt/v1"
FINAL_RECEIPT_SCHEMA = "dcentos.s19k-endurance-host-verification/v1"
FINAL_FAILURE_RECEIPT_SCHEMA = "dcentos.s19k-endurance-host-failure-verification/v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY = re.compile(r"^[a-z][a-z0-9_]*$")
SEGMENT_NAME = re.compile(r"^segment\.([0-9]{6})\.kv$")
MANIFEST_NAME = re.compile(r"^manifest\.([0-9]{6})\.kv$")
MINIMUM_MS = 86_400_000
MAXIMUM_MS = 93_600_000
WINDOW_MS = 21_600_000
MIN_INTERVAL_MS = 55_000
MAX_INTERVAL_MS = 75_000
MAX_WALL_DRIFT_MS = 120_000
MAX_SEGMENT_BYTES = 65_536
MAX_SEGMENTS = 1_561
POST_SAFEOFF_DELAY_MS = 10_000
POST_SAFEOFF_SAMPLE_SEPARATION_MS = 5_000
POST_SAFEOFF_MAX_SAMPLE_GAP_MS = 5_000
REQUIRED_PATHS = ("/dev/ttyS1", "/dev/ttyS2")

BASELINE_KEYS = (
    "schema",
    "phase3_plan_sha256",
    "phase3_plan_bytes",
    "phase3_transcript_sha256",
    "phase3_transcript_bytes",
    "phase3_receipt_sha256",
    "phase3_receipt_bytes",
    "phase3_wall_power_csv_sha256",
    "phase3_wall_power_csv_bytes",
    "phase3_wall_power_sample_count",
    "phase3_wall_power_first_unix_ms",
    "phase3_wall_power_last_unix_ms",
    "phase3_verifier_sha256",
    "phase3_verifier_bytes",
    "phase3_baseline_builder_sha256",
    "phase3_baseline_builder_bytes",
    "phase3_host_verification_sha256",
    "phase3_host_verification_bytes",
    "phase3_verification_id",
    "phase3_safeoff_manifest_sha256",
    "phase3_safeoff_manifest_bytes",
    "phase3_instrumentation_preflight_sha256",
    "phase3_instrumentation_preflight_bytes",
    "phase3_normalization_config_sha256",
    "phase3_normalization_config_bytes",
    "phase3_instrument_source_sha256",
    "phase3_instrument_source_bytes",
    "phase3_normalization_receipt_sha256",
    "phase3_normalization_receipt_bytes",
    "phase3_safeoff_csv_sha256",
    "phase3_safeoff_csv_bytes",
    "phase3_physical_verifier_sha256",
    "phase3_physical_verifier_bytes",
    "phase3_safeoff_parser_sha256",
    "phase3_safeoff_parser_bytes",
    "phase3_normalizer_sha256",
    "phase3_normalizer_bytes",
    "phase3_physical_verification_sha256",
    "phase3_physical_verification_bytes",
    "phase3_physical_verification_id",
    "hashrate_min_millighs",
    "hashrate_max_millighs",
    "reject_rate_max_ppm",
    "wall_power_min_mw",
    "wall_power_max_mw",
    "safeoff_wall_power_max_mw",
    "warmup_intervals",
    "autotuner",
    "declared_before_launch_unix_s",
    "publication",
)
PHASE3_PROVENANCE_FILES = (
    ("phase3_plan.kv", "phase3_plan_sha256", "phase3_plan_bytes", 65_536),
    ("phase3_transcript.log", "phase3_transcript_sha256", "phase3_transcript_bytes", 128 * 1024 * 1024),
    ("phase3_receipt.kv", "phase3_receipt_sha256", "phase3_receipt_bytes", 65_536),
    ("phase3_wall_power.csv", "phase3_wall_power_csv_sha256", "phase3_wall_power_csv_bytes", 32 * 1024 * 1024),
    ("phase3_verifier.py", "phase3_verifier_sha256", "phase3_verifier_bytes", 2 * 1024 * 1024),
    ("phase3_baseline_builder.py", "phase3_baseline_builder_sha256", "phase3_baseline_builder_bytes", 2 * 1024 * 1024),
    ("phase3_host_verification.json", "phase3_host_verification_sha256", "phase3_host_verification_bytes", 65_536),
    ("phase3_safeoff_manifest.kv", "phase3_safeoff_manifest_sha256", "phase3_safeoff_manifest_bytes", 65_536),
    ("instrumentation_preflight.kv", "phase3_instrumentation_preflight_sha256", "phase3_instrumentation_preflight_bytes", 65_536),
    ("phase3_normalization_config.json", "phase3_normalization_config_sha256", "phase3_normalization_config_bytes", 1024 * 1024),
    ("phase3_instrument_source.raw", "phase3_instrument_source_sha256", "phase3_instrument_source_bytes", 64 * 1024 * 1024),
    ("phase3_normalization_receipt", "phase3_normalization_receipt_sha256", "phase3_normalization_receipt_bytes", 65_536),
    ("phase3_safeoff.csv", "phase3_safeoff_csv_sha256", "phase3_safeoff_csv_bytes", 64 * 1024 * 1024),
    ("phase3_physical_verifier.py", "phase3_physical_verifier_sha256", "phase3_physical_verifier_bytes", 2 * 1024 * 1024),
    ("phase3_safeoff_parser.py", "phase3_safeoff_parser_sha256", "phase3_safeoff_parser_bytes", 2 * 1024 * 1024),
    ("phase3_normalizer.py", "phase3_normalizer_sha256", "phase3_normalizer_bytes", 2 * 1024 * 1024),
    ("phase3_physical_verification.json", "phase3_physical_verification_sha256", "phase3_physical_verification_bytes", 65_536),
)
MANIFEST_KEYS = (
    "schema",
    "sequence",
    "predecessor_manifest_sha256",
    "segment_relative_path",
    "segment_sha256",
    "segment_bytes",
    "collected_wall_unix_ms",
    "publication",
)
DAEMON_TERMINAL_KEYS = (
    "schema",
    "outcome",
    "elapsed_s",
    "minimum_s",
    "maximum_s",
    "segment_count",
    "terminal_sequence",
    "segment_chain_head_sha256",
    "off_target_manifest_sha256",
    "off_target_manifest_bytes",
    "runtime_active_sha256",
    "runtime_active_bytes",
    "live_identity_sha256",
    "acceptance_windows",
    "publication",
)
TARGET_RECEIPT_KEYS = (
    "schema",
    "deploy_mode",
    "daemon_terminal_path",
    "daemon_terminal_sha256",
    "daemon_terminal_bytes",
    "segment_count",
    "terminal_sequence",
    "segment_chain_head_sha256",
    "off_target_manifest_sha256",
    "off_target_manifest_bytes",
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
    "wrapper_exit_status",
    "semantic_verification",
    "persistent_mutation",
    "publication",
)
FINAL_COLLECTION_KEYS = (
    "schema",
    "daemon_terminal_sha256",
    "terminal_handoff_sha256",
    "safeoff_sha256",
    "endurance_receipt_sha256",
    "runtime_active_pre_safeoff_sha256",
    "runtime_pending_sha256",
    "collected_wall_unix_ms",
    "publication",
)
DAEMON_FAILURE_KEYS = (
    "schema",
    "outcome",
    "elapsed_s",
    "segment_count",
    "acknowledged_segments",
    "unacknowledged_segments",
    "unacknowledged_bytes",
    "segment_chain_head_sha256",
    "off_target_manifest_sha256",
    "off_target_manifest_bytes",
    "runtime_active_sha256",
    "runtime_active_bytes",
    "live_identity_sha256",
    "checked_safeoff",
    "failure_reason_utf8_hex",
    "publication",
)
TARGET_FAILURE_RECEIPT_KEYS = (
    "schema",
    "deploy_mode",
    "outcome",
    "daemon_failure_path",
    "daemon_failure_sha256",
    "daemon_failure_bytes",
    "elapsed_s",
    "segment_count",
    "acknowledged_segments",
    "unacknowledged_segments",
    "unacknowledged_bytes",
    "segment_chain_head_sha256",
    "off_target_manifest_sha256",
    "off_target_manifest_bytes",
    "failure_reason_utf8_hex",
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
    "wrapper_exit_status",
    "semantic_verification",
    "persistent_mutation",
    "publication",
)
FAILURE_COLLECTION_KEYS = (
    "schema",
    "daemon_failure_sha256",
    "terminal_handoff_sha256",
    "safeoff_sha256",
    "endurance_failure_receipt_sha256",
    "runtime_active_pre_safeoff_sha256",
    "runtime_pending_sha256",
    "collected_wall_unix_ms",
    "publication",
)
COLLECTION_START_KEYS = (
    "schema",
    "started_wall_unix_ms",
    "miner_target_sha256",
    "ssh_host_key_sha256",
    "launch_plan_sha256",
    "baseline_sha256",
    "publication",
)


class EnduranceVerificationError(ValueError):
    """Evidence cannot support a production-readiness pass."""


def fail(message: str) -> None:
    raise EnduranceVerificationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(metadata, "st_file_attributes", 0) & flag)


def stable_regular_bytes(path: Path, label: str, maximum: int | None = None) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {path}: {error}")
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        fail(f"{label} is not a regular non-link file: {path}")
    if before.st_nlink != 1:
        fail(f"{label} must have exactly one hard link: {path}")
    if maximum is not None and before.st_size > maximum:
        fail(f"{label} exceeds {maximum} bytes: {path}")
    try:
        data = path.read_bytes()
        after = os.lstat(path)
    except OSError as error:
        fail(f"cannot read {label}: {path}: {error}")
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
    if identity_before != identity_after or len(data) != before.st_size:
        fail(f"{label} changed while it was read: {path}")
    return data


def require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {path}: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        fail(f"{label} is not a real directory: {path}")


def parse_kv_bytes(
    data: bytes,
    label: str,
    exact_keys: tuple[str, ...] | None = None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if not data or not data.endswith(b"\n") or b"\r" in data or b"\0" in data:
        fail(f"{label} is not terminal-newline canonical text")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    fields: dict[str, str] = {}
    order: list[str] = []
    for line in text.splitlines():
        if "=" not in line:
            fail(f"{label} has a malformed field")
        key, value = line.split("=", 1)
        if not KEY.fullmatch(key) or not value or key in fields:
            fail(f"{label} has an empty, duplicate, or non-canonical field")
        fields[key] = value
        order.append(key)
    observed = tuple(order)
    if exact_keys is not None and observed != exact_keys:
        fail(f"{label} has an inexact field set or order")
    return fields, observed


def parse_kv_file(
    path: Path,
    label: str,
    exact_keys: tuple[str, ...] | None = None,
    maximum: int | None = None,
) -> tuple[dict[str, str], bytes, tuple[str, ...]]:
    data = stable_regular_bytes(path, label, maximum)
    fields, order = parse_kv_bytes(data, label, exact_keys)
    return fields, data, order


def require_sha256(value: str, label: str) -> str:
    if not HEX64.fullmatch(value):
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def canonical_uint(value: str, label: str, *, positive: bool = False, maximum: int | None = None) -> int:
    if not value.isascii() or not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        fail(f"{label} is not canonical unsigned decimal")
    parsed = int(value)
    if positive and parsed == 0:
        fail(f"{label} must be positive")
    if maximum is not None and parsed > maximum:
        fail(f"{label} exceeds {maximum}")
    return parsed


def canonical_int(value: str, label: str) -> int:
    if not re.fullmatch(r"0|-?[1-9][0-9]*", value):
        fail(f"{label} is not canonical signed decimal")
    return int(value)


def require_field(fields: Mapping[str, str], key: str, expected: str, label: str) -> None:
    if fields.get(key) != expected:
        fail(f"{label} {key} mismatch")


def parse_baseline(path: Path) -> tuple[dict[str, str], bytes]:
    fields, data, _ = parse_kv_file(path, "endurance baseline", BASELINE_KEYS, 4096)
    require_field(fields, "schema", BASELINE_SCHEMA, "baseline")
    for filename, hash_key, size_key, maximum in PHASE3_PROVENANCE_FILES:
        require_sha256(fields[hash_key], f"baseline {filename}")
        canonical_uint(
            fields[size_key],
            f"baseline {filename} bytes",
            positive=True,
            maximum=maximum,
        )
    sample_count = canonical_uint(
        fields["phase3_wall_power_sample_count"],
        "Phase-3 wall-power sample count",
        positive=True,
        maximum=10_000_000,
    )
    if sample_count < 2:
        fail("Phase-3 wall-power baseline has fewer than two samples")
    first_meter_ms = canonical_uint(
        fields["phase3_wall_power_first_unix_ms"],
        "Phase-3 first wall-power time",
        positive=True,
    )
    last_meter_ms = canonical_uint(
        fields["phase3_wall_power_last_unix_ms"],
        "Phase-3 last wall-power time",
        positive=True,
    )
    if last_meter_ms - first_meter_ms < 60_000:
        fail("Phase-3 wall-power baseline does not span at least 60 seconds")
    require_sha256(fields["phase3_verification_id"], "Phase-3 verification identifier")
    require_sha256(
        fields["phase3_physical_verification_id"],
        "Phase-3 physical verification identifier",
    )
    hashrate_min = canonical_uint(fields["hashrate_min_millighs"], "hashrate minimum", positive=True)
    hashrate_max = canonical_uint(fields["hashrate_max_millighs"], "hashrate maximum", positive=True)
    if hashrate_min >= hashrate_max:
        fail("baseline hashrate band is empty")
    canonical_uint(fields["reject_rate_max_ppm"], "reject-rate maximum", maximum=1_000_000)
    power_min = canonical_uint(fields["wall_power_min_mw"], "wall-power minimum", positive=True)
    power_max = canonical_uint(fields["wall_power_max_mw"], "wall-power maximum", positive=True)
    if power_min >= power_max:
        fail("baseline wall-power band is empty")
    safeoff_power_max = canonical_uint(
        fields["safeoff_wall_power_max_mw"],
        "SafeOff wall-power maximum",
        positive=True,
    )
    if safeoff_power_max >= power_min:
        fail("SafeOff wall-power maximum must be below the energized operating band")
    if safeoff_power_max * 10 > power_min:
        fail("SafeOff wall-power maximum exceeds 10% of the energized minimum")
    canonical_uint(fields["warmup_intervals"], "warmup intervals", maximum=120)
    require_field(fields, "autotuner", "disabled", "baseline")
    declaration = canonical_uint(
        fields["declared_before_launch_unix_s"],
        "baseline declaration time",
        positive=True,
    )
    if declaration * 1000 < last_meter_ms:
        fail("baseline declaration predates its Phase-3 power evidence")
    require_field(
        fields,
        "publication",
        "no-clobber-hard-link-after-fsync",
        "baseline",
    )
    return fields, data


def parse_plan(path: Path) -> tuple[dict[str, str], bytes]:
    fields, data, _ = parse_kv_file(path, "launch plan", maximum=65_536)
    expected = {
        "schema": PLAN_SCHEMA,
        "operator_artifact_pin": "required-and-matched",
        "dry_run": "false",
        "mode": "endurance-work-proof",
        "explicit_loud_authority": "true",
        "work_authority": "endurance-proof",
        "endurance_work_proof_flag": "--s19k-track1-endurance-work-proof",
        "endurance_minimum_s": "86400",
        "endurance_maximum_s": "93600",
        "endurance_interval_s": "60",
        "endurance_acceptance_windows": "4x6h-per-required-uart",
        "endurance_collector_ack_timeout_s": "300",
        "endurance_max_unacked_segments": "6",
        "endurance_max_unacked_bytes": "524288",
        "ssh_host_key_admission": "exact-operator-pin",
        "ssh_global_known_hosts": "disabled-on-contact",
        "persistent_mutation": "false",
        "clear_for_flash": "false",
        "native_bm1366": "refused",
        "runtime_receipt_schema": "dcentos.s19k-tmp-runtime/v5",
    }
    for key, value in expected.items():
        require_field(fields, key, value, "launch plan")
    require_field(
        fields,
        "expected_artifact_sha256",
        fields.get("sha256", ""),
        "launch plan",
    )
    require_field(
        fields,
        "expected_artifact_bytes",
        fields.get("bytes", ""),
        "launch plan",
    )
    for key in (
        "sha256", "config_sha256", "runner_sha256", "custody_observer_sha256",
        "stock_restart_helper_sha256", "endurance_collector_sha256",
        "endurance_verifier_sha256", "endurance_baseline_sha256",
        "miner_target_sha256",
    ):
        require_sha256(fields.get(key, ""), f"launch-plan {key}")
    for key in (
        "bytes", "config_bytes", "runner_bytes", "custody_observer_bytes",
        "stock_restart_helper_bytes", "endurance_collector_bytes",
        "endurance_verifier_bytes", "endurance_baseline_bytes",
    ):
        canonical_uint(fields.get(key, ""), f"launch-plan {key}", positive=True)
    fingerprint = fields.get("ssh_host_key_sha256", "")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        fail("launch plan lacks a canonical pinned OpenSSH host-key fingerprint")
    launch = fields.get("launch", "")
    remote_dir = fields.get("remote_dir", "")
    if not remote_dir.startswith("/tmp/dcentrald_bench_t1_") or " " in remote_dir:
        fail("launch plan remote directory is not the exact Track-1 namespace")
    try:
        launch_tokens = shlex.split(launch, posix=True)
    except ValueError as error:
        fail(f"launch plan command is malformed: {error}")
    expected_tail = (
        fields["sha256"], fields["bytes"], fields["config_sha256"], fields["config_bytes"],
        fields["runner_sha256"], fields["runner_bytes"], fields["custody_observer_sha256"],
        fields["custody_observer_bytes"], fields["stock_restart_helper_sha256"],
        fields["stock_restart_helper_bytes"],
    )
    if (
        len(launch_tokens) != 15
        or launch_tokens[0] != f"{remote_dir}/run_trial"
        or launch_tokens[1] != "run"
        or launch_tokens[2] != remote_dir
        or launch_tokens[3] not in ("am3-s19k", "am3-s19kpro", "am3-aml-s19kpro")
        or launch_tokens[4] != "endurance-work-proof"
        or tuple(launch_tokens[5:]) != expected_tail
    ):
        fail("launch plan command is not the exact content-bound endurance runner command")
    return fields, data


def _hash_bound_field(hasher: "hashlib._Hash", key: bytes, value: bytes) -> None:
    hasher.update(struct.pack(">Q", len(key)))
    hasher.update(key)
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)


def genesis_sha256(runtime_sha256: str, runtime_bytes: int, identity_sha256: str) -> str:
    hasher = hashlib.sha256()
    for key, value in (
        (b"schema", SEGMENT_SCHEMA.encode("ascii")),
        (b"runtime_active_sha256", runtime_sha256.encode("ascii")),
        (b"runtime_active_bytes", str(runtime_bytes).encode("ascii")),
        (b"live_identity_sha256", identity_sha256.encode("ascii")),
    ):
        _hash_bound_field(hasher, key, value)
    return hasher.hexdigest()


def decode_hex(value: str, label: str, maximum: int = 16_384) -> bytes:
    if len(value) % 2 or len(value) > maximum * 2 or not re.fullmatch(r"[0-9a-f]*", value):
        fail(f"{label} is not canonical bounded lowercase hex")
    return bytes.fromhex(value)


def decode_lineage(value: str, label: str) -> dict[str, str]:
    data = decode_hex(value, label)
    keys = (
        "elapsed_s", "accepted", "path", "attribution", "work_generation",
        "worker_name", "job_id", "extranonce2", "ntime", "nonce", "version_bits", "version",
    )
    offset = 0
    result: dict[str, str] = {}
    for expected in keys:
        if offset + 4 > len(data):
            fail(f"{label} is truncated")
        key_size = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if offset + key_size + 4 > len(data):
            fail(f"{label} has an invalid key length")
        try:
            key = data[offset:offset + key_size].decode("utf-8")
        except UnicodeDecodeError:
            fail(f"{label} key is not UTF-8")
        offset += key_size
        value_size = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if offset + value_size > len(data):
            fail(f"{label} has an invalid value length")
        try:
            decoded = data[offset:offset + value_size].decode("utf-8")
        except UnicodeDecodeError:
            fail(f"{label} value is not UTF-8")
        offset += value_size
        if key != expected or not decoded:
            fail(f"{label} has an inexact canonical field sequence")
        result[key] = decoded
    if offset != len(data):
        fail(f"{label} has trailing bytes")
    if result["accepted"] not in ("true", "false"):
        fail(f"{label} accepted value is invalid")
    canonical_uint(result["elapsed_s"], f"{label} elapsed_s")
    if not re.fullmatch(r"[0-9a-f]{8}", result["version"]):
        fail(f"{label} version is invalid")
    return result


def expected_segment_keys(path_count: int, event_count: int, lineage_count: int) -> tuple[str, ...]:
    keys = [
        "schema", "sequence", "segment_kind", "predecessor_sha256", "genesis_sha256",
        "runtime_active_sha256", "runtime_active_bytes", "live_identity_sha256",
        "interval_monotonic_start_ms", "interval_monotonic_end_ms", "interval_duration_ms",
        "interval_wall_start_unix_ms", "interval_wall_end_unix_ms", "interval_wall_duration_ms",
        "pool_state_hex", "aggregate_hashrate_millighs", "hottest_temp_millic",
        "dangerous_temp_millic", "fan_pwm", "fan_readings", "gpio437", "required_path_count",
    ]
    for index in range(path_count):
        keys.extend((f"path_{index}_hex", f"path_{index}_chips", f"path_{index}_complete77"))
        for counter in (
            "tx_frames", "rx_wire_bytes", "rx_frames", "valid_nonces",
            "shares_submitted", "shares_accepted", "shares_rejected",
        ):
            keys.extend((f"path_{index}_{counter}_total", f"path_{index}_{counter}_delta"))
        keys.append(f"path_{index}_accepted_window_bits")
    keys.append("event_count")
    keys.extend(f"event_{index}_hex" for index in range(event_count))
    keys.append("share_lineage_count")
    keys.extend(f"share_lineage_{index}_hex" for index in range(lineage_count))
    keys.extend((
        "acceptance_complete", "collector_ack_timeout_s", "collector_max_unacked_segments",
        "collector_max_unacked_bytes", "publication",
    ))
    return tuple(keys)


def load_meter(path: Path) -> tuple[list[tuple[int, int]], bytes]:
    data = stable_regular_bytes(path, "wall-power CSV", 32 * 1024 * 1024)
    if not data.endswith(b"\n") or b"\r" in data or b"\0" in data:
        fail("wall-power CSV is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("wall-power CSV is not ASCII")
    reader = csv.reader(lines, strict=True)
    try:
        header = next(reader)
    except StopIteration:
        fail("wall-power CSV is empty")
    if header != ["wall_unix_ms", "power_mw"]:
        fail("wall-power CSV header is not canonical")
    rows: list[tuple[int, int]] = []
    previous = -1
    for row_number, row in enumerate(reader, 2):
        if len(row) != 2:
            fail(f"wall-power CSV row {row_number} has an inexact field count")
        wall = canonical_uint(row[0], f"wall-power row {row_number} time", positive=True)
        power = canonical_uint(row[1], f"wall-power row {row_number} power", positive=True)
        if wall <= previous:
            fail("wall-power timestamps are not strictly increasing")
        previous = wall
        rows.append((wall, power))
    if not rows:
        fail("wall-power CSV has no observations")
    return rows, data


def verify_contiguous_post_safeoff_decay(
    rows: list[tuple[int, int]],
    final_collected_ms: int,
    safeoff_power_max_mw: int,
    label: str,
) -> int:
    """Require a bounded, continuously low suffix after the SafeOff delay."""
    earliest = final_collected_ms + POST_SAFEOFF_DELAY_MS
    suffix = [(wall, power) for wall, power in rows if wall >= earliest]
    if len(suffix) < 2:
        fail(f"{label} is absent or has fewer than two samples")
    if suffix[0][0] - earliest > POST_SAFEOFF_MAX_SAMPLE_GAP_MS:
        fail(f"{label} starts after an unbounded meter gap")
    if any(
        later[0] - earlier[0] > POST_SAFEOFF_MAX_SAMPLE_GAP_MS
        for earlier, later in zip(suffix, suffix[1:])
    ):
        fail(f"{label} contains an unbounded meter gap")
    if any(power > safeoff_power_max_mw for _, power in suffix):
        fail(f"{label} contains a power rebound or late re-energization")
    if suffix[-1][0] - suffix[0][0] < POST_SAFEOFF_SAMPLE_SEPARATION_MS:
        fail(f"{label} is too brief")
    return len(suffix)


def verify_phase3_provenance(
    evidence_dir: Path,
    baseline: Mapping[str, str],
) -> str:
    """Verify the exact Phase-3 inputs/tools retained with an endurance run."""
    path = evidence_dir / "phase3_provenance"
    require_real_directory(path, "Phase-3 provenance directory")
    expected_names = tuple(item[0] for item in PHASE3_PROVENANCE_FILES)
    observed_names = tuple(sorted(child.name for child in path.iterdir()))
    if observed_names != tuple(sorted(expected_names)):
        fail("Phase-3 provenance directory has an inexact entry set")

    retained: dict[str, bytes] = {}
    aggregate = hashlib.sha256()
    for filename, hash_key, size_key, maximum in PHASE3_PROVENANCE_FILES:
        data = stable_regular_bytes(
            path / filename,
            f"retained Phase-3 provenance {filename}",
            maximum,
        )
        if sha256_bytes(data) != baseline[hash_key] or len(data) != int(baseline[size_key]):
            fail(f"retained Phase-3 provenance differs from baseline: {filename}")
        retained[filename] = data
        _hash_bound_field(aggregate, filename.encode("ascii"), data)

    meter_rows, _ = load_meter(path / "phase3_wall_power.csv")
    if (
        len(meter_rows) != int(baseline["phase3_wall_power_sample_count"])
        or meter_rows[0][0] != int(baseline["phase3_wall_power_first_unix_ms"])
        or meter_rows[-1][0] != int(baseline["phase3_wall_power_last_unix_ms"])
    ):
        fail("retained Phase-3 wall-power geometry differs from the baseline")
    power_min = int(baseline["wall_power_min_mw"])
    power_max = int(baseline["wall_power_max_mw"])
    if any(power < power_min or power > power_max for _, power in meter_rows):
        fail("retained Phase-3 wall power falls outside the baseline band")

    verification_data = retained["phase3_host_verification.json"]
    try:
        verification = json.loads(verification_data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("retained Phase-3 host verification is not canonical ASCII JSON")
    canonical = (
        json.dumps(verification, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if canonical != verification_data or not isinstance(verification, dict):
        fail("retained Phase-3 host verification is not canonical object JSON")
    expected_result = {
        "plan_sha256": baseline["phase3_plan_sha256"],
        "transcript_sha256": baseline["phase3_transcript_sha256"],
        "receipt_sha256": baseline["phase3_receipt_sha256"],
        "verification_id": baseline["phase3_verification_id"],
    }
    for key, expected in expected_result.items():
        if verification.get(key) != expected:
            fail(f"retained Phase-3 host verification does not bind {key}")
    if (
        verification.get("required_paths") != list(REQUIRED_PATHS)
        or verification.get("accepted_paths") != list(REQUIRED_PATHS)
    ):
        fail("retained Phase-3 verification does not admit exact ttyS1/ttyS2 authority")

    physical_data = retained["phase3_physical_verification.json"]
    try:
        physical_verification = json.loads(physical_data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("retained Phase-3 physical verification is not canonical ASCII JSON")
    physical_canonical = (
        json.dumps(
            physical_verification,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")
    if physical_canonical != physical_data or not isinstance(
        physical_verification, dict
    ):
        fail("retained Phase-3 physical verification is not canonical object JSON")
    for key, expected in {
        "schema": "dcentos.s19k-phase3-physical-verification/v2",
        "plan_sha256": baseline["phase3_plan_sha256"],
        "bounded_verification_id": baseline["phase3_verification_id"],
        "manifest_sha256": baseline["phase3_safeoff_manifest_sha256"],
        "preflight_sha256": baseline["phase3_instrumentation_preflight_sha256"],
        "normalization_config_sha256": baseline[
            "phase3_normalization_config_sha256"
        ],
        "instrument_source_sha256": baseline["phase3_instrument_source_sha256"],
        "normalization_receipt_sha256": baseline[
            "phase3_normalization_receipt_sha256"
        ],
        "capture_sha256": baseline["phase3_safeoff_csv_sha256"],
        "verification_id": baseline["phase3_physical_verification_id"],
    }.items():
        if physical_verification.get(key) != expected:
            fail(f"retained Phase-3 physical verification does not bind {key}")
    if physical_verification.get("rail_decay_confirmed_ms") is None:
        fail("retained Phase-3 physical verification lacks rail decay confirmation")
    if physical_verification.get("capture_end_ms", -1) < physical_verification.get(
        "rail_decay_confirmed_ms", 0
    ):
        fail("retained Phase-3 physical capture ends before decay confirmation")
    return aggregate.hexdigest()


def _names(
    path: Path,
    pattern: re.Pattern[str],
    label: str,
    *,
    allow_empty: bool = False,
) -> list[tuple[int, Path]]:
    require_real_directory(path, label)
    result: list[tuple[int, Path]] = []
    for child in path.iterdir():
        match = pattern.fullmatch(child.name)
        if not match:
            fail(f"{label} contains an unexpected entry: {child.name}")
        result.append((int(match.group(1)), child))
    result.sort()
    if (not result and not allow_empty) or [sequence for sequence, _ in result] != list(range(len(result))):
        fail(f"{label} is empty or non-contiguous")
    return result


def verify_evidence(
    evidence_dir: Path,
    baseline_path: Path,
    wall_power_path: Path,
    plan_path: Path | None = None,
    *,
    expected_failure: bool = False,
) -> dict[str, object]:
    require_real_directory(evidence_dir, "endurance evidence directory")
    baseline, baseline_data = parse_baseline(baseline_path)
    phase3_provenance_sha256 = verify_phase3_provenance(evidence_dir, baseline)
    plan: dict[str, str] | None = None
    plan_data = b""
    if plan_path is not None:
        plan, plan_data = parse_plan(plan_path)
        if sha256_bytes(baseline_data) != plan["endurance_baseline_sha256"] or len(baseline_data) != int(plan["endurance_baseline_bytes"]):
            fail("baseline bytes do not match the launch plan")
    meter_rows, meter_data = load_meter(wall_power_path)
    collection_start, collection_start_data, _ = parse_kv_file(
        evidence_dir / "COLLECTION_START.kv",
        "collection start receipt",
        COLLECTION_START_KEYS,
        4096,
    )
    require_field(
        collection_start,
        "schema",
        "dcentos.s19k-endurance-collection-start/v1",
        "collection start receipt",
    )
    collection_started_ms = canonical_uint(
        collection_start["started_wall_unix_ms"],
        "collection start time",
        positive=True,
    )
    if collection_started_ms < int(baseline["declared_before_launch_unix_s"]) * 1000:
        fail("endurance baseline was not declared before collection launch")
    require_sha256(collection_start["miner_target_sha256"], "collection miner target")
    require_sha256(collection_start["launch_plan_sha256"], "collection launch plan")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", collection_start["ssh_host_key_sha256"]):
        fail("collection start SSH host key is not a canonical SHA-256 fingerprint")
    require_field(
        collection_start,
        "baseline_sha256",
        sha256_bytes(baseline_data),
        "collection start receipt",
    )
    require_field(
        collection_start,
        "publication",
        "host-create-new-fsync",
        "collection start receipt",
    )
    if plan is not None:
        require_field(
            collection_start,
            "miner_target_sha256",
            plan["miner_target_sha256"],
            "collection start receipt",
        )
        require_field(
            collection_start,
            "ssh_host_key_sha256",
            plan["ssh_host_key_sha256"],
            "collection start receipt",
        )
        require_field(
            collection_start,
            "launch_plan_sha256",
            sha256_bytes(plan_data),
            "collection start receipt",
        )
    segment_files = _names(
        evidence_dir / "segments",
        SEGMENT_NAME,
        "segment directory",
        allow_empty=expected_failure,
    )
    manifest_files = _names(
        evidence_dir / "manifests",
        MANIFEST_NAME,
        "manifest directory",
        allow_empty=expected_failure,
    )
    if len(segment_files) != len(manifest_files) or len(segment_files) > MAX_SEGMENTS:
        fail("segment and manifest geometry differs or exceeds the 26-hour bound")

    predecessor_segment = ""
    predecessor_manifest = EMPTY_SHA256
    manifest_bytes = 0
    manifest_heads = [EMPTY_SHA256]
    manifest_sizes = [0]
    runtime_sha = ""
    runtime_bytes = 0
    identity_sha = ""
    genesis = ""
    previous_mono_end: int | None = None
    previous_wall_end: int | None = None
    first_wall_start: int | None = None
    previous_totals: dict[tuple[str, str], int] = {}
    expected_fan_ids: tuple[int, ...] | None = None
    accepted_windows = {path: 0 for path in REQUIRED_PATHS}
    total_accepted = 0
    total_rejected = 0
    warmup = int(baseline["warmup_intervals"])
    hashrate_min = int(baseline["hashrate_min_millighs"])
    hashrate_max = int(baseline["hashrate_max_millighs"])
    power_min = int(baseline["wall_power_min_mw"])
    power_max = int(baseline["wall_power_max_mw"])
    final_fields: dict[str, str] = {}
    final_segment_data = b""

    for sequence, segment_path in segment_files:
        segment_fields, segment_data, _ = parse_kv_file(
            segment_path, f"segment {sequence}", maximum=MAX_SEGMENT_BYTES
        )
        try:
            path_count = canonical_uint(segment_fields["required_path_count"], "required path count", positive=True, maximum=8)
            event_count = canonical_uint(segment_fields["event_count"], "event count", maximum=1024)
            lineage_count = canonical_uint(segment_fields["share_lineage_count"], "lineage count", maximum=4096)
        except KeyError:
            fail(f"segment {sequence} lacks a dynamic count")
        expected_keys = expected_segment_keys(path_count, event_count, lineage_count)
        _, observed_order = parse_kv_bytes(segment_data, f"segment {sequence}")
        if observed_order != expected_keys:
            fail(f"segment {sequence} has an inexact field set or order")
        require_field(segment_fields, "schema", SEGMENT_SCHEMA, f"segment {sequence}")
        if canonical_uint(segment_fields["sequence"], "segment sequence") != sequence:
            fail("segment filename and sequence differ")
        kind = segment_fields["segment_kind"]
        if expected_failure:
            if kind == "terminal-pass" and sequence != len(segment_files) - 1:
                fail(f"segment {sequence} has a non-final terminal-pass kind")
            if kind not in ("minute", "terminal-pass"):
                fail(f"segment {sequence} has an invalid failure-observation kind")
        else:
            expected_kind = "terminal-pass" if sequence == len(segment_files) - 1 else "minute"
            if kind != expected_kind:
                fail(f"segment {sequence} kind is not {expected_kind}")
        segment_sha = sha256_bytes(segment_data)
        if sequence == 0:
            runtime_sha = require_sha256(segment_fields["runtime_active_sha256"], "runtime active")
            runtime_bytes = canonical_uint(segment_fields["runtime_active_bytes"], "runtime active bytes", positive=True)
            identity_sha = require_sha256(segment_fields["live_identity_sha256"], "live identity")
            genesis = genesis_sha256(runtime_sha, runtime_bytes, identity_sha)
            predecessor_segment = genesis
        if segment_fields["predecessor_sha256"] != predecessor_segment:
            fail(f"segment {sequence} does not extend the segment chain")
        require_field(segment_fields, "genesis_sha256", genesis, f"segment {sequence}")
        require_field(segment_fields, "runtime_active_sha256", runtime_sha, f"segment {sequence}")
        require_field(segment_fields, "runtime_active_bytes", str(runtime_bytes), f"segment {sequence}")
        require_field(segment_fields, "live_identity_sha256", identity_sha, f"segment {sequence}")

        mono_start = canonical_uint(segment_fields["interval_monotonic_start_ms"], "monotonic start")
        mono_end = canonical_uint(segment_fields["interval_monotonic_end_ms"], "monotonic end", positive=True)
        duration = canonical_uint(segment_fields["interval_duration_ms"], "interval duration", positive=True)
        wall_start = canonical_uint(segment_fields["interval_wall_start_unix_ms"], "wall start", positive=True)
        wall_end = canonical_uint(segment_fields["interval_wall_end_unix_ms"], "wall end", positive=True)
        wall_duration = canonical_uint(segment_fields["interval_wall_duration_ms"], "wall duration", positive=True)
        if first_wall_start is None:
            first_wall_start = wall_start
        if mono_end - mono_start != duration or wall_end - wall_start != wall_duration:
            fail(f"segment {sequence} interval arithmetic is inconsistent")
        if not MIN_INTERVAL_MS <= duration <= MAX_INTERVAL_MS or abs(duration - wall_duration) > MAX_WALL_DRIFT_MS:
            fail(f"segment {sequence} is not a complete bounded minute")
        if sequence == 0 and mono_start > MAX_INTERVAL_MS:
            fail("first endurance segment does not begin at the admitted observation origin")
        if previous_mono_end is not None and (mono_start != previous_mono_end or wall_start != previous_wall_end):
            fail(f"segment {sequence} is not temporally contiguous")
        previous_mono_end, previous_wall_end = mono_end, wall_end
        decode_hex(segment_fields["pool_state_hex"], "pool state", 4096).decode("utf-8", "strict")
        hashrate = canonical_uint(segment_fields["aggregate_hashrate_millighs"], "aggregate hashrate")
        hottest = canonical_int(segment_fields["hottest_temp_millic"], "hottest temperature")
        dangerous = canonical_int(segment_fields["dangerous_temp_millic"], "dangerous temperature")
        if hottest >= dangerous:
            fail(f"segment {sequence} reached dangerous temperature")
        canonical_uint(segment_fields["fan_pwm"], "fan PWM", maximum=100)
        fans = segment_fields["fan_readings"].split(",")
        if not fans or any(not re.fullmatch(r"[0-9]+:[1-9][0-9]*", item) for item in fans):
            fail(f"segment {sequence} lacks canonical spinning-fan evidence")
        fan_ids = tuple(int(item.split(":", 1)[0]) for item in fans)
        if len(set(fan_ids)) != len(fan_ids):
            fail(f"segment {sequence} contains duplicate fan channels")
        if expected_fan_ids is None:
            expected_fan_ids = fan_ids
        elif fan_ids != expected_fan_ids:
            fail(f"segment {sequence} fan channel identity or ordering changed")
        require_field(segment_fields, "gpio437", "0", f"segment {sequence}")
        require_field(segment_fields, "collector_ack_timeout_s", "300", f"segment {sequence}")
        require_field(segment_fields, "collector_max_unacked_segments", "6", f"segment {sequence}")
        require_field(segment_fields, "collector_max_unacked_bytes", "524288", f"segment {sequence}")
        require_field(segment_fields, "publication", "no-clobber-hard-link-after-fsync", f"segment {sequence}")
        if path_count != len(REQUIRED_PATHS):
            fail(f"segment {sequence} does not contain exactly two required UARTs")

        observed_paths: list[str] = []
        segment_accepted = 0
        segment_rejected = 0
        for index in range(path_count):
            path = decode_hex(segment_fields[f"path_{index}_hex"], f"segment {sequence} path").decode("ascii", "strict")
            observed_paths.append(path)
            require_field(segment_fields, f"path_{index}_chips", "77", f"segment {sequence}")
            require_field(segment_fields, f"path_{index}_complete77", "true", f"segment {sequence}")
            for counter in (
                "tx_frames", "rx_wire_bytes", "rx_frames", "valid_nonces",
                "shares_submitted", "shares_accepted", "shares_rejected",
            ):
                total = canonical_uint(segment_fields[f"path_{index}_{counter}_total"], f"{path} {counter} total")
                delta = canonical_uint(segment_fields[f"path_{index}_{counter}_delta"], f"{path} {counter} delta")
                prior = previous_totals.get((path, counter), total - delta)
                if total < delta or total - prior != delta:
                    fail(f"segment {sequence} {path} {counter} counter relation is inconsistent")
                if counter in (
                    "tx_frames",
                    "rx_wire_bytes",
                    "rx_frames",
                    "valid_nonces",
                ) and delta == 0:
                    fail(f"segment {sequence} {path} {counter} made no progress")
                previous_totals[(path, counter)] = total
                if counter == "shares_accepted":
                    segment_accepted += delta
                elif counter == "shares_rejected":
                    segment_rejected += delta
            bits = segment_fields[f"path_{index}_accepted_window_bits"]
            if not re.fullmatch(r"[01]{4}", bits):
                fail(f"segment {sequence} {path} acceptance bits are invalid")
        if tuple(observed_paths) != REQUIRED_PATHS:
            fail(f"segment {sequence} UART order or identity changed")

        lineage_accepted = 0
        lineage_rejected = 0
        for index in range(lineage_count):
            lineage = decode_lineage(segment_fields[f"share_lineage_{index}_hex"], f"segment {sequence} lineage {index}")
            if lineage["path"] not in accepted_windows:
                fail(f"segment {sequence} lineage names a non-required UART")
            elapsed_s = int(lineage["elapsed_s"])
            if elapsed_s * 1000 > mono_end + MAX_INTERVAL_MS:
                fail(f"segment {sequence} lineage time is ahead of its segment")
            if lineage["accepted"] == "true":
                lineage_accepted += 1
                if elapsed_s < 86_400:
                    accepted_windows[lineage["path"]] |= 1 << (elapsed_s // 21_600)
            else:
                lineage_rejected += 1
        if lineage_accepted != segment_accepted or lineage_rejected != segment_rejected:
            fail(f"segment {sequence} share counters and pool-result lineage differ")
        total_accepted += segment_accepted
        total_rejected += segment_rejected
        for index, path in enumerate(REQUIRED_PATHS):
            expected_bits = f"{accepted_windows[path]:04b}"
            require_field(segment_fields, f"path_{index}_accepted_window_bits", expected_bits, f"segment {sequence}")
        complete = all(bits == 0b1111 for bits in accepted_windows.values())
        require_field(segment_fields, "acceptance_complete", str(complete).lower(), f"segment {sequence}")

        if sequence >= warmup:
            if not hashrate_min <= hashrate <= hashrate_max:
                fail(f"segment {sequence} hashrate is outside the predeclared Phase-3 band")
            covered = [power for wall, power in meter_rows if wall_start <= wall <= wall_end]
            if not covered:
                fail(f"segment {sequence} has no wall-power observation")
            if any(power < power_min or power > power_max for power in covered):
                fail(f"segment {sequence} wall power is outside the predeclared Phase-3 band")

        manifest_path = manifest_files[sequence][1]
        manifest_fields, manifest_data, _ = parse_kv_file(
            manifest_path, f"manifest {sequence}", MANIFEST_KEYS, 4096
        )
        require_field(manifest_fields, "schema", MANIFEST_SCHEMA, f"manifest {sequence}")
        require_field(manifest_fields, "sequence", str(sequence), f"manifest {sequence}")
        require_field(manifest_fields, "predecessor_manifest_sha256", predecessor_manifest, f"manifest {sequence}")
        require_field(manifest_fields, "segment_relative_path", f"segments/segment.{sequence:06}.kv", f"manifest {sequence}")
        require_field(manifest_fields, "segment_sha256", segment_sha, f"manifest {sequence}")
        require_field(manifest_fields, "segment_bytes", str(len(segment_data)), f"manifest {sequence}")
        collected_wall = canonical_uint(
            manifest_fields["collected_wall_unix_ms"],
            "manifest collection time",
            positive=True,
        )
        if not (
            wall_end - MAX_WALL_DRIFT_MS
            <= collected_wall
            <= wall_end + 300_000 + MAX_WALL_DRIFT_MS
        ):
            fail(f"manifest {sequence} collection time is outside the acknowledgement SLA")
        require_field(manifest_fields, "publication", "host-create-new-fsync", f"manifest {sequence}")
        predecessor_manifest = sha256_bytes(manifest_data)
        manifest_bytes = len(manifest_data)
        manifest_heads.append(predecessor_manifest)
        manifest_sizes.append(manifest_bytes)
        predecessor_segment = segment_sha
        final_fields = segment_fields
        final_segment_data = segment_data

    if (
        first_wall_start is not None
        and collection_started_ms > first_wall_start + MAX_WALL_DRIFT_MS
    ):
        fail("collection allegedly started after target endurance telemetry began")

    if expected_failure:
        return verify_failure_final(
            evidence_dir,
            baseline,
            baseline_data,
            meter_rows,
            meter_data,
            plan,
            plan_data,
            segment_files,
            runtime_sha,
            runtime_bytes,
            identity_sha,
            predecessor_segment,
            previous_wall_end,
            manifest_heads,
            manifest_sizes,
            collection_start_data,
            phase3_provenance_sha256,
        )
    if previous_mono_end is None or previous_mono_end < MINIMUM_MS or previous_mono_end >= MAXIMUM_MS:
        fail("endurance duration is outside the 24-hour minimum / 26-hour maximum")
    if not all(bits == 0b1111 for bits in accepted_windows.values()):
        fail("accepted-share evidence is incomplete in one or more fixed UART windows")
    resolved = total_accepted + total_rejected
    if resolved == 0 or total_rejected * 1_000_000 > int(baseline["reject_rate_max_ppm"]) * resolved:
        fail("resolved-share rejection rate exceeds the predeclared maximum")

    final_dir = evidence_dir / "final"
    require_real_directory(final_dir, "final receipt directory")
    daemon, daemon_data, _ = parse_kv_file(final_dir / "daemon_terminal", "daemon terminal", DAEMON_TERMINAL_KEYS, 4096)
    require_field(daemon, "schema", DAEMON_TERMINAL_SCHEMA, "daemon terminal")
    require_field(daemon, "outcome", "pass-pending-runner-safeoff", "daemon terminal")
    require_field(daemon, "minimum_s", "86400", "daemon terminal")
    require_field(daemon, "maximum_s", "93600", "daemon terminal")
    require_field(daemon, "segment_count", str(len(segment_files)), "daemon terminal")
    require_field(daemon, "terminal_sequence", str(len(segment_files) - 1), "daemon terminal")
    require_field(daemon, "segment_chain_head_sha256", sha256_bytes(final_segment_data), "daemon terminal")
    require_field(daemon, "off_target_manifest_sha256", predecessor_manifest, "daemon terminal")
    require_field(daemon, "off_target_manifest_bytes", str(manifest_bytes), "daemon terminal")
    require_field(daemon, "runtime_active_sha256", runtime_sha, "daemon terminal")
    require_field(daemon, "runtime_active_bytes", str(runtime_bytes), "daemon terminal")
    require_field(daemon, "live_identity_sha256", identity_sha, "daemon terminal")
    require_field(daemon, "acceptance_windows", "4x6h-per-required-uart", "daemon terminal")
    require_field(daemon, "publication", "no-clobber-hard-link-after-fsync", "daemon terminal")
    elapsed_s = canonical_uint(daemon["elapsed_s"], "daemon elapsed seconds", positive=True)
    if elapsed_s < 86_400 or elapsed_s >= 93_600:
        fail("daemon terminal elapsed time is out of bounds")
    if abs(elapsed_s * 1000 - previous_mono_end) > MAX_INTERVAL_MS:
        fail("daemon terminal elapsed time disagrees with the monotonic segment chain")

    terminal_handoff, terminal_handoff_data, _ = parse_kv_file(final_dir / "terminal_handoff", "terminal handoff", maximum=65_536)
    require_field(terminal_handoff, "schema", "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1", "terminal handoff")
    require_field(terminal_handoff, "disposition", "terminal-safeoff-partial-stock-owner", "terminal handoff")
    require_field(terminal_handoff, "terminal_safeoff", "true", "terminal handoff")
    require_field(terminal_handoff, "resets", "454:0,455:0,456:0", "terminal handoff")
    safeoff_data = stable_regular_bytes(final_dir / "safeoff", "SafeOff receipt", 65_536)
    try:
        safeoff_text = safeoff_data.decode("ascii").strip()
    except UnicodeDecodeError:
        fail("SafeOff receipt is not ASCII")
    safeoff_tokens = safeoff_text.split(" ")
    if len(safeoff_tokens) != 11 or safeoff_tokens[0] != "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT":
        fail("SafeOff receipt has an inexact token set")
    safeoff_fields: dict[str, str] = {}
    for token in safeoff_tokens[1:]:
        if "=" not in token:
            fail("SafeOff receipt has a malformed field")
        key, value = token.split("=", 1)
        if not key or not value or key in safeoff_fields:
            fail("SafeOff receipt has an empty or duplicate field")
        safeoff_fields[key] = value
    if safeoff_fields.get("schema") != "dcentos.s19k-track1-safeoff/v1" or safeoff_fields.get("resets") != "454:0,455:0,456:0" or safeoff_fields.get("psu") != "437:1" or safeoff_fields.get("live_identity_sha256") != identity_sha:
        fail("SafeOff receipt does not prove reset-low / PSU-off terminal state")
    target, target_data, _ = parse_kv_file(
        final_dir / "endurance_receipt",
        "target endurance receipt",
        TARGET_RECEIPT_KEYS,
        65_536,
    )
    require_field(target, "schema", TARGET_RECEIPT_SCHEMA, "target endurance receipt")
    require_field(target, "deploy_mode", "endurance-work-proof", "target endurance receipt")
    require_field(target, "daemon_terminal_sha256", sha256_bytes(daemon_data), "target endurance receipt")
    require_field(target, "daemon_terminal_bytes", str(len(daemon_data)), "target endurance receipt")
    require_field(target, "segment_count", str(len(segment_files)), "target endurance receipt")
    require_field(target, "terminal_sequence", str(len(segment_files) - 1), "target endurance receipt")
    require_field(target, "segment_chain_head_sha256", sha256_bytes(final_segment_data), "target endurance receipt")
    require_field(target, "off_target_manifest_sha256", predecessor_manifest, "target endurance receipt")
    require_field(target, "off_target_manifest_bytes", str(manifest_bytes), "target endurance receipt")
    require_field(target, "source_runtime_active_schema", "dcentos.s19k-tmp-runtime/v5", "target endurance receipt")
    require_field(target, "source_runtime_active_sha256", runtime_sha, "target endurance receipt")
    require_field(target, "source_runtime_active_bytes", str(runtime_bytes), "target endurance receipt")
    require_field(target, "pending_runtime_schema", "dcentos.s19k-stock-restart-pending/v4", "target endurance receipt")
    require_field(target, "terminal_handoff_receipt_sha256", sha256_bytes(terminal_handoff_data), "target endurance receipt")
    require_field(target, "terminal_handoff_receipt_bytes", str(len(terminal_handoff_data)), "target endurance receipt")
    require_field(target, "safeoff_receipt_sha256", sha256_bytes(safeoff_data), "target endurance receipt")
    require_field(target, "safeoff_receipt_bytes", str(len(safeoff_data)), "target endurance receipt")
    require_field(target, "live_identity_schema", "dcentos.s19k-braiins-live-identity/v2", "target endurance receipt")
    require_field(target, "live_identity_sha256", identity_sha, "target endurance receipt")
    require_field(target, "wrapper_exit_status", "0", "target endurance receipt")
    require_field(target, "semantic_verification", "host-required", "target endurance receipt")
    require_field(target, "persistent_mutation", "false", "target endurance receipt")
    require_field(target, "publication", "no-clobber-hard-link-after-fsync", "target endurance receipt")
    if plan is not None:
        bindings = {
            "binary_sha256": "sha256", "binary_bytes": "bytes",
            "config_sha256": "config_sha256", "config_bytes": "config_bytes",
            "runner_sha256": "runner_sha256", "runner_bytes": "runner_bytes",
            "custody_observer_sha256": "custody_observer_sha256", "custody_observer_bytes": "custody_observer_bytes",
            "stock_restart_helper_sha256": "stock_restart_helper_sha256",
            "stock_restart_helper_bytes": "stock_restart_helper_bytes",
        }
        for target_key, plan_key in bindings.items():
            require_field(target, target_key, plan[plan_key], "target endurance receipt")

    source_runtime_data = stable_regular_bytes(
        final_dir / "runtime_active_pre_safeoff",
        "pre-SafeOff runtime receipt",
        65_536,
    )
    pending_runtime_data = stable_regular_bytes(
        final_dir / "runtime_pending",
        "pending stock-restart receipt",
        65_536,
    )
    source_runtime, _ = parse_kv_bytes(source_runtime_data, "pre-SafeOff runtime receipt")
    pending_runtime, _ = parse_kv_bytes(pending_runtime_data, "pending stock-restart receipt")
    require_field(source_runtime, "schema", "dcentos.s19k-tmp-runtime/v5", "pre-SafeOff runtime receipt")
    require_field(source_runtime, "deploy_mode", "endurance-work-proof", "pre-SafeOff runtime receipt")
    require_field(pending_runtime, "schema", "dcentos.s19k-stock-restart-pending/v4", "pending stock-restart receipt")
    require_field(target, "source_runtime_active_sha256", sha256_bytes(source_runtime_data), "target endurance receipt")
    require_field(target, "source_runtime_active_bytes", str(len(source_runtime_data)), "target endurance receipt")
    require_field(target, "pending_runtime_sha256", sha256_bytes(pending_runtime_data), "target endurance receipt")
    require_field(target, "pending_runtime_bytes", str(len(pending_runtime_data)), "target endurance receipt")

    final_collection, final_collection_data, _ = parse_kv_file(
        evidence_dir / "FINAL_COLLECTION.kv",
        "final collection receipt",
        FINAL_COLLECTION_KEYS,
        4096,
    )
    require_field(
        final_collection,
        "schema",
        "dcentos.s19k-endurance-final-collection/v1",
        "final collection receipt",
    )
    for key, data in (
        ("daemon_terminal_sha256", daemon_data),
        ("terminal_handoff_sha256", terminal_handoff_data),
        ("safeoff_sha256", safeoff_data),
        ("endurance_receipt_sha256", target_data),
        ("runtime_active_pre_safeoff_sha256", source_runtime_data),
        ("runtime_pending_sha256", pending_runtime_data),
    ):
        require_field(
            final_collection,
            key,
            sha256_bytes(data),
            "final collection receipt",
        )
    require_field(
        final_collection,
        "publication",
        "host-create-new-fsync",
        "final collection receipt",
    )
    final_collected_ms = canonical_uint(
        final_collection["collected_wall_unix_ms"],
        "final collection time",
        positive=True,
    )
    if final_collected_ms < previous_wall_end:
        fail("final target receipts were allegedly collected before the terminal segment")
    safeoff_limit = int(baseline["safeoff_wall_power_max_mw"])
    low_sample_count = verify_contiguous_post_safeoff_decay(
        meter_rows,
        final_collected_ms,
        safeoff_limit,
        "independent post-SafeOff wall-power decay",
    )

    return {
        "schema": FINAL_RECEIPT_SCHEMA,
        "outcome": "pass",
        "verified_wall_unix_s": int(time.time()),
        "plan_sha256": sha256_bytes(plan_data) if plan is not None else "not-supplied",
        "baseline_sha256": sha256_bytes(baseline_data),
        "phase3_provenance_sha256": phase3_provenance_sha256,
        "wall_power_csv_sha256": sha256_bytes(meter_data),
        "wall_power_csv_bytes": len(meter_data),
        "collection_start_sha256": sha256_bytes(collection_start_data),
        "segment_count": len(segment_files),
        "terminal_sequence": len(segment_files) - 1,
        "segment_chain_head_sha256": sha256_bytes(final_segment_data),
        "off_target_manifest_sha256": predecessor_manifest,
        "off_target_manifest_bytes": manifest_bytes,
        "elapsed_s": elapsed_s,
        "accepted_shares": total_accepted,
        "rejected_shares": total_rejected,
        "ttyS1_acceptance_windows": "1111",
        "ttyS2_acceptance_windows": "1111",
        "daemon_terminal_sha256": sha256_bytes(daemon_data),
        "terminal_handoff_sha256": sha256_bytes(terminal_handoff_data),
        "safeoff_sha256": sha256_bytes(safeoff_data),
        "target_endurance_receipt_sha256": sha256_bytes(target_data),
        "runtime_active_pre_safeoff_sha256": sha256_bytes(source_runtime_data),
        "runtime_pending_sha256": sha256_bytes(pending_runtime_data),
        "final_collection_sha256": sha256_bytes(final_collection_data),
        "safeoff_wall_power_max_mw": safeoff_limit,
        "safeoff_low_power_samples": low_sample_count,
        "publication": "host-create-new-fsync",
    }


def verify_failure_final(
    evidence_dir: Path,
    baseline: Mapping[str, str],
    baseline_data: bytes,
    meter_rows: list[tuple[int, int]],
    meter_data: bytes,
    plan: Mapping[str, str] | None,
    plan_data: bytes,
    segment_files: list[tuple[int, Path]],
    replay_runtime_sha: str,
    replay_runtime_bytes: int,
    replay_identity_sha: str,
    replay_chain_head: str,
    previous_wall_end: int | None,
    manifest_heads: list[str],
    manifest_sizes: list[int],
    collection_start_data: bytes,
    phase3_provenance_sha256: str,
) -> dict[str, object]:
    """Verify a non-passing run still produced complete controlled-fault evidence."""
    final_dir = evidence_dir / "final"
    require_real_directory(final_dir, "failure final receipt directory")
    source_data = stable_regular_bytes(
        final_dir / "runtime_active_pre_safeoff",
        "failure pre-SafeOff runtime receipt",
        65_536,
    )
    pending_data = stable_regular_bytes(
        final_dir / "runtime_pending",
        "failure pending stock-restart receipt",
        65_536,
    )
    source, _ = parse_kv_bytes(source_data, "failure pre-SafeOff runtime receipt")
    pending, _ = parse_kv_bytes(pending_data, "failure pending stock-restart receipt")
    require_field(source, "schema", "dcentos.s19k-tmp-runtime/v5", "failure source runtime")
    require_field(source, "deploy_mode", "endurance-work-proof", "failure source runtime")
    require_field(pending, "schema", "dcentos.s19k-stock-restart-pending/v4", "failure pending runtime")
    runtime_sha = sha256_bytes(source_data)
    runtime_bytes = len(source_data)

    daemon, daemon_data, _ = parse_kv_file(
        final_dir / "daemon_failure",
        "daemon failure",
        DAEMON_FAILURE_KEYS,
        65_536,
    )
    target, target_data, _ = parse_kv_file(
        final_dir / "endurance_failure_receipt",
        "target endurance failure receipt",
        TARGET_FAILURE_RECEIPT_KEYS,
        65_536,
    )
    require_field(daemon, "schema", DAEMON_FAILURE_SCHEMA, "daemon failure")
    require_field(daemon, "outcome", "fail-after-checked-safeoff", "daemon failure")
    require_field(daemon, "checked_safeoff", "true", "daemon failure")
    require_field(
        daemon,
        "publication",
        "no-clobber-hard-link-after-fsync",
        "daemon failure",
    )
    require_field(target, "schema", TARGET_FAILURE_RECEIPT_SCHEMA, "target failure receipt")
    require_field(target, "deploy_mode", "endurance-work-proof", "target failure receipt")
    require_field(target, "outcome", "fail-after-checked-safeoff", "target failure receipt")
    require_field(target, "daemon_failure_sha256", sha256_bytes(daemon_data), "target failure receipt")
    require_field(target, "daemon_failure_bytes", str(len(daemon_data)), "target failure receipt")
    require_field(target, "source_runtime_active_schema", "dcentos.s19k-tmp-runtime/v5", "target failure receipt")
    require_field(target, "source_runtime_active_sha256", runtime_sha, "target failure receipt")
    require_field(target, "source_runtime_active_bytes", str(runtime_bytes), "target failure receipt")
    require_field(target, "pending_runtime_schema", "dcentos.s19k-stock-restart-pending/v4", "target failure receipt")
    require_field(target, "pending_runtime_sha256", sha256_bytes(pending_data), "target failure receipt")
    require_field(target, "pending_runtime_bytes", str(len(pending_data)), "target failure receipt")
    require_field(target, "live_identity_schema", "dcentos.s19k-braiins-live-identity/v2", "target failure receipt")
    identity_sha = require_sha256(target["live_identity_sha256"], "failure live identity")
    require_field(daemon, "runtime_active_sha256", runtime_sha, "daemon failure")
    require_field(daemon, "runtime_active_bytes", str(runtime_bytes), "daemon failure")
    require_field(daemon, "live_identity_sha256", identity_sha, "daemon failure")
    if replay_runtime_sha:
        if (replay_runtime_sha, replay_runtime_bytes, replay_identity_sha) != (
            runtime_sha,
            runtime_bytes,
            identity_sha,
        ):
            fail("failure segment genesis does not bind the preserved runtime/identity")

    segment_count = canonical_uint(daemon["segment_count"], "failure segment count", maximum=MAX_SEGMENTS)
    acknowledged = canonical_uint(
        daemon["acknowledged_segments"],
        "failure acknowledged segment count",
        maximum=segment_count,
    )
    unacknowledged = canonical_uint(
        daemon["unacknowledged_segments"],
        "failure unacknowledged segment count",
        maximum=MAX_SEGMENTS,
    )
    unacknowledged_bytes = canonical_uint(
        daemon["unacknowledged_bytes"],
        "failure unacknowledged bytes",
        maximum=524_288,
    )
    if segment_count != len(segment_files) or unacknowledged != segment_count - acknowledged:
        fail("daemon failure segment/acknowledgement geometry is inconsistent")
    observed_unacknowledged_bytes = sum(
        len(stable_regular_bytes(path, f"unacknowledged segment {sequence}", MAX_SEGMENT_BYTES))
        for sequence, path in segment_files[acknowledged:]
    )
    if unacknowledged_bytes != observed_unacknowledged_bytes:
        fail("daemon failure unacknowledged byte count differs from the sealed suffix")
    expected_chain_head = (
        replay_chain_head
        if segment_files
        else genesis_sha256(runtime_sha, runtime_bytes, identity_sha)
    )
    require_field(daemon, "segment_chain_head_sha256", expected_chain_head, "daemon failure")
    require_field(
        daemon,
        "off_target_manifest_sha256",
        manifest_heads[acknowledged],
        "daemon failure",
    )
    require_field(
        daemon,
        "off_target_manifest_bytes",
        str(manifest_sizes[acknowledged]),
        "daemon failure",
    )
    reason = decode_hex(daemon["failure_reason_utf8_hex"], "daemon failure reason", 8192)
    if not reason:
        fail("daemon failure reason is empty")
    try:
        reason_text = reason.decode("utf-8")
    except UnicodeDecodeError:
        fail("daemon failure reason is not UTF-8")
    elapsed_s = canonical_uint(daemon["elapsed_s"], "daemon failure elapsed seconds")
    for key in (
        "elapsed_s",
        "segment_count",
        "acknowledged_segments",
        "unacknowledged_segments",
        "unacknowledged_bytes",
        "segment_chain_head_sha256",
        "off_target_manifest_sha256",
        "off_target_manifest_bytes",
        "failure_reason_utf8_hex",
    ):
        require_field(target, key, daemon[key], "target failure receipt")

    terminal_handoff, terminal_handoff_data, _ = parse_kv_file(
        final_dir / "terminal_handoff",
        "failure terminal handoff",
        maximum=65_536,
    )
    require_field(
        terminal_handoff,
        "schema",
        "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
        "failure terminal handoff",
    )
    require_field(
        terminal_handoff,
        "disposition",
        "terminal-safeoff-partial-stock-owner",
        "failure terminal handoff",
    )
    require_field(terminal_handoff, "terminal_safeoff", "true", "failure terminal handoff")
    require_field(terminal_handoff, "resets", "454:0,455:0,456:0", "failure terminal handoff")
    safeoff_data = stable_regular_bytes(final_dir / "safeoff", "failure SafeOff receipt", 65_536)
    try:
        safeoff_tokens = safeoff_data.decode("ascii").strip().split(" ")
    except UnicodeDecodeError:
        fail("failure SafeOff receipt is not ASCII")
    if len(safeoff_tokens) != 11 or safeoff_tokens[0] != "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT":
        fail("failure SafeOff receipt has an inexact token set")
    safeoff_fields: dict[str, str] = {}
    for token in safeoff_tokens[1:]:
        if "=" not in token:
            fail("failure SafeOff receipt has a malformed field")
        key, value = token.split("=", 1)
        if not key or not value or key in safeoff_fields:
            fail("failure SafeOff receipt has an empty or duplicate field")
        safeoff_fields[key] = value
    if (
        safeoff_fields.get("schema") != "dcentos.s19k-track1-safeoff/v1"
        or safeoff_fields.get("resets") != "454:0,455:0,456:0"
        or safeoff_fields.get("psu") != "437:1"
        or safeoff_fields.get("live_identity_sha256") != identity_sha
    ):
        fail("failure SafeOff receipt does not prove reset-low / PSU-off state")
    require_field(target, "terminal_handoff_receipt_schema", "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1", "target failure receipt")
    require_field(target, "terminal_handoff_receipt_sha256", sha256_bytes(terminal_handoff_data), "target failure receipt")
    require_field(target, "terminal_handoff_receipt_bytes", str(len(terminal_handoff_data)), "target failure receipt")
    require_field(target, "safeoff_receipt_schema", "dcentos.s19k-track1-safeoff/v1", "target failure receipt")
    require_field(target, "safeoff_receipt_sha256", sha256_bytes(safeoff_data), "target failure receipt")
    require_field(target, "safeoff_receipt_bytes", str(len(safeoff_data)), "target failure receipt")
    wrapper_status = canonical_uint(
        target["wrapper_exit_status"],
        "failure wrapper status",
        positive=True,
        maximum=255,
    )
    require_field(target, "semantic_verification", "host-required", "target failure receipt")
    require_field(target, "persistent_mutation", "false", "target failure receipt")
    require_field(target, "publication", "no-clobber-hard-link-after-fsync", "target failure receipt")
    if plan is not None:
        bindings = {
            "binary_sha256": "sha256",
            "binary_bytes": "bytes",
            "config_sha256": "config_sha256",
            "config_bytes": "config_bytes",
            "runner_sha256": "runner_sha256",
            "runner_bytes": "runner_bytes",
            "custody_observer_sha256": "custody_observer_sha256",
            "custody_observer_bytes": "custody_observer_bytes",
            "stock_restart_helper_sha256": "stock_restart_helper_sha256",
            "stock_restart_helper_bytes": "stock_restart_helper_bytes",
        }
        for target_key, plan_key in bindings.items():
            require_field(target, target_key, plan[plan_key], "target failure receipt")
        remote = plan["remote_dir"]
        for key, suffix in (
            ("daemon_failure_path", "/endurance_evidence/daemon_failure"),
            ("source_runtime_active_path", "/runtime_active_pre_safeoff"),
            ("pending_runtime_path", "/runtime_active"),
            ("terminal_handoff_receipt_path", "/runtime_terminal_safeoff"),
            ("safeoff_receipt_path", "/runtime_safeoff_terminal_receipt"),
        ):
            require_field(target, key, remote + suffix, "target failure receipt")

    collection, collection_data, _ = parse_kv_file(
        evidence_dir / "FAILURE_COLLECTION.kv",
        "failure final collection receipt",
        FAILURE_COLLECTION_KEYS,
        4096,
    )
    require_field(
        collection,
        "schema",
        "dcentos.s19k-endurance-failure-final-collection/v1",
        "failure final collection receipt",
    )
    for key, data in (
        ("daemon_failure_sha256", daemon_data),
        ("terminal_handoff_sha256", terminal_handoff_data),
        ("safeoff_sha256", safeoff_data),
        ("endurance_failure_receipt_sha256", target_data),
        ("runtime_active_pre_safeoff_sha256", source_data),
        ("runtime_pending_sha256", pending_data),
    ):
        require_field(collection, key, sha256_bytes(data), "failure final collection receipt")
    require_field(collection, "publication", "host-create-new-fsync", "failure final collection receipt")
    collected_ms = canonical_uint(
        collection["collected_wall_unix_ms"],
        "failure final collection time",
        positive=True,
    )
    if previous_wall_end is not None and collected_ms < previous_wall_end:
        fail("failure target receipts were collected before the last segment")
    safeoff_limit = int(baseline["safeoff_wall_power_max_mw"])
    low_sample_count = verify_contiguous_post_safeoff_decay(
        meter_rows,
        collected_ms,
        safeoff_limit,
        "independent post-failure SafeOff wall-power decay",
    )
    return {
        "schema": FINAL_FAILURE_RECEIPT_SCHEMA,
        "outcome": "controlled-failure-evidence-pass",
        "verified_wall_unix_s": int(time.time()),
        "plan_sha256": sha256_bytes(plan_data) if plan is not None else "not-supplied",
        "baseline_sha256": sha256_bytes(baseline_data),
        "phase3_provenance_sha256": phase3_provenance_sha256,
        "wall_power_csv_sha256": sha256_bytes(meter_data),
        "wall_power_csv_bytes": len(meter_data),
        "collection_start_sha256": sha256_bytes(collection_start_data),
        "wrapper_exit_status": wrapper_status,
        "elapsed_s": elapsed_s,
        "segment_count": segment_count,
        "acknowledged_segments_at_failure": acknowledged,
        "unacknowledged_segments_at_failure": unacknowledged,
        "segment_chain_head_sha256": expected_chain_head,
        "off_target_manifest_sha256_at_failure": manifest_heads[acknowledged],
        "collected_off_target_manifest_sha256": manifest_heads[-1],
        "collected_off_target_manifest_bytes": manifest_sizes[-1],
        "failure_reason_utf8_hex": reason.hex(),
        "failure_reason_utf8_sha256": sha256_bytes(reason),
        "daemon_failure_sha256": sha256_bytes(daemon_data),
        "terminal_handoff_sha256": sha256_bytes(terminal_handoff_data),
        "safeoff_sha256": sha256_bytes(safeoff_data),
        "target_failure_receipt_sha256": sha256_bytes(target_data),
        "runtime_active_pre_safeoff_sha256": runtime_sha,
        "runtime_pending_sha256": sha256_bytes(pending_data),
        "failure_collection_sha256": sha256_bytes(collection_data),
        "safeoff_wall_power_max_mw": safeoff_limit,
        "safeoff_low_power_samples": low_sample_count,
        "publication": "host-create-new-fsync",
    }


def receipt_bytes(receipt: Mapping[str, object]) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in receipt.items()).encode("ascii")


def _fsync_publication_directory(path: Path) -> None:
    if os.name == "nt":
        fail("host verification receipt publication requires POSIX directory fsync; run inside WSL/Linux")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _clean_receipt_publication_scratch(path: Path) -> None:
    require_real_directory(path.parent, "host verification receipt parent")
    pattern = re.compile(
        rf"^\.{re.escape(path.name)}\.tmp\.[1-9][0-9]*\.[0-9a-f]{{16}}$"
    )
    changed = False
    for child in path.parent.iterdir():
        if pattern.fullmatch(child.name) is None:
            continue
        metadata = os.lstat(child)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail("host verification receipt has an inexact stale publication scratch")
        if os.path.lexists(path):
            target = os.lstat(path)
            if (
                not stat.S_ISREG(target.st_mode)
                or stat.S_ISLNK(target.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_nlink)
                != (target.st_dev, target.st_ino, 2)
            ):
                fail("host verification receipt scratch is not its target's sole extra link")
        elif metadata.st_nlink != 1:
            fail("unpublished host verification receipt scratch has an inexact link count")
        os.unlink(child)
        changed = True
    if changed:
        _fsync_publication_directory(path.parent)


def publish_new(path: Path, data: bytes) -> None:
    if os.name == "nt":
        fail("host verification receipt publication requires POSIX directory fsync; run inside WSL/Linux")
    _clean_receipt_publication_scratch(path)
    if os.path.lexists(path):
        fail(f"host verification receipt already exists: {path}")
    scratch = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(scratch, flags, 0o600)
    linked = False
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                fail("short write preparing host verification receipt")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(data)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail("prepared host verification receipt inode is inexact")
        os.link(scratch, path, follow_symlinks=False)
        linked = True
        _fsync_publication_directory(path.parent)
    finally:
        os.close(descriptor)
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass
    if linked:
        _fsync_publication_directory(path.parent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    baseline = subparsers.add_parser("baseline", help="admit one predeclared Phase-3 operating band")
    baseline.add_argument("path", type=Path)
    verify = subparsers.add_parser("verify", help="verify a complete collected endurance observation")
    verify.add_argument("evidence_dir", type=Path)
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--wall-power-csv", type=Path, required=True)
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--write-final-receipt", action="store_true")
    verify_failure = subparsers.add_parser(
        "verify-failure",
        help="verify a collected controlled-fault outcome and checked SafeOff",
    )
    verify_failure.add_argument("evidence_dir", type=Path)
    verify_failure.add_argument("--baseline", type=Path, required=True)
    verify_failure.add_argument("--wall-power-csv", type=Path, required=True)
    verify_failure.add_argument("--plan", type=Path, required=True)
    verify_failure.add_argument("--write-final-receipt", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "baseline":
            parse_baseline(args.path)
            print("S19K_ENDURANCE_BASELINE_OK")
            return 0
        result = verify_evidence(
            args.evidence_dir,
            args.baseline,
            args.wall_power_csv,
            args.plan,
            expected_failure=args.command == "verify-failure",
        )
        data = receipt_bytes(result)
        if args.write_final_receipt:
            receipt_name = (
                "HOST_ENDURANCE_FAILURE_VERIFICATION.kv"
                if args.command == "verify-failure"
                else "HOST_ENDURANCE_VERIFICATION.kv"
            )
            publish_new(args.evidence_dir / receipt_name, data)
        sys.stdout.buffer.write(data)
        return 0
    except (EnduranceVerificationError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
