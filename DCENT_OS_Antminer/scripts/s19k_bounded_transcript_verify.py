#!/usr/bin/env python3
"""Verify one copied S19k Track-1 bounded-work evidence directory.

This host-only tool performs no network or hardware operation.  It verifies
the live deploy plan, the wrapper's post-SafeOff transcript receipt, every
recorded Closed11d TX and CRC-admitted RX frame, RX/share/pool attribution,
per-logical-UART acceptance, and the terminal SafeOff/pending custody chain.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Iterable


PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"
PROOF_SCHEMA = "dcentos.s19k-bounded-work-proof/v1"
RECEIPT_SCHEMA = "dcentos.s19k-bounded-work-transcript/v1"
SOURCE_RUNTIME_SCHEMA = "dcentos.s19k-tmp-runtime/v5"
PENDING_RUNTIME_SCHEMA = "dcentos.s19k-stock-restart-pending/v4"
TERMINAL_HANDOFF_SCHEMA = "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1"
SAFEOFF_SCHEMA = "dcentos.s19k-track1-safeoff/v1"
LIVE_IDENTITY_SCHEMA = "dcentos.s19k-braiins-live-identity/v2"
EXPECTED_TIMEOUT_S = 600
EXPECTED_WORK_EVIDENCE = (
    "content-bound-terminal-transcript+all-crc-admitted-rx+"
    "all-required-path-tx+exact-pool-result-origin"
)
EXPECTED_SUCCESS = (
    "accepted-share-per-required-logical-uart+checked-terminal-safeoff"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_BYTES = re.compile(r"^[0-9A-Fa-f]+$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_./:@+\-]+$")
PATH_TOKEN = re.compile(r"^/dev/ttyS[1-3]$")

STARTED = "S19K_BOUNDED_WORK_PROOF_STARTED"
TX = "S19K_BOUNDED_WORK_TX_EVIDENCE"
RX = "S19K_BOUNDED_WORK_RX_EVIDENCE"
ATTRIBUTION = "S19K_BOUNDED_WORK_RX_ATTRIBUTION_EVIDENCE"
POOL_RESULT = "S19K_BOUNDED_WORK_POOL_RESULT_EVIDENCE"
COMPLETE = "S19K_BOUNDED_WORK_PROOF_COMPLETE"
INCOMPLETE = "S19K_BOUNDED_WORK_PROOF_INCOMPLETE"

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
    "started_count",
    "tx_count",
    "rx_count",
    "attribution_count",
    "pool_result_count",
    "complete_count",
    "incomplete_count",
    "semantic_verification",
    "persistent_mutation",
    "publication",
)


class VerificationError(ValueError):
    """The supplied evidence cannot prove the bounded-work claim."""


def fail(message: str) -> None:
    raise VerificationError(message)


def _stable_regular_bytes(path: Path, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or bool(reparse and getattr(before, "st_file_attributes", 0) & reparse)
    ):
        fail(f"{label} must be a real regular non-link file: {path}")
    try:
        data = path.read_bytes()
        after = os.lstat(path)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    observed_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    )
    observed_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_mode,
    )
    if observed_before != observed_after or len(data) != before.st_size:
        fail(f"{label} changed while it was read")
    return data


def _decode_text(data: bytes, label: str) -> str:
    if b"\x00" in data:
        fail(f"{label} contains a NUL byte")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        fail(f"{label} is not strict UTF-8: {error}")


def _parse_kv_bytes(
    data: bytes,
    label: str,
    *,
    exact_keys: Iterable[str] | None = None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    text = _decode_text(data, label)
    fields: dict[str, str] = {}
    keys: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{label} line {number} is not key=value")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z0-9_]+", key):
            fail(f"{label} line {number} has an invalid key")
        if key in fields:
            fail(f"{label} repeats key {key}")
        if "\r" in value or "\n" in value:
            fail(f"{label} key {key} has an invalid value")
        fields[key] = value
        keys.append(key)
    if exact_keys is not None and tuple(keys) != tuple(exact_keys):
        fail(f"{label} ordered keys do not match the exact contract")
    return fields, tuple(keys)


def _parse_kv_file(
    path: Path,
    label: str,
    *,
    exact_keys: Iterable[str] | None = None,
) -> tuple[bytes, dict[str, str]]:
    data = _stable_regular_bytes(path, label)
    fields, _ = _parse_kv_bytes(data, label, exact_keys=exact_keys)
    return data, fields


def _require(fields: dict[str, str], key: str, expected: str, label: str) -> None:
    if fields.get(key) != expected:
        fail(f"{label} requires {key}={expected!r}, got {fields.get(key)!r}")


def _uint(value: str | None, label: str, *, positive: bool = False) -> int:
    if value is None or not re.fullmatch(r"0|[1-9][0-9]*", value):
        fail(f"{label} is not a canonical unsigned integer")
    number = int(value)
    if positive and number == 0:
        fail(f"{label} must be positive")
    return number


def _sha(value: str | None, label: str) -> str:
    if value is None or not HEX64.fullmatch(value):
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_bound_file(
    trial_dir: Path,
    remote_path: str,
    expected_sha: str,
    expected_bytes: int,
    label: str,
) -> tuple[Path, bytes]:
    pure = PurePosixPath(remote_path)
    if (
        not pure.is_absolute()
        or not remote_path.startswith("/tmp/dcentrald_bench_t1_")
        or pure.name in ("", ".", "..")
    ):
        fail(f"{label} has an invalid remote trial path")
    local = trial_dir / pure.name
    if local.parent != trial_dir:
        fail(f"{label} escaped the copied trial directory")
    data = _stable_regular_bytes(local, label)
    if len(data) != expected_bytes or _hash(data) != expected_sha:
        fail(f"{label} bytes do not match the wrapper receipt")
    return local, data


def _simple_field(line: str, key: str) -> str:
    key_re = re.escape(key)
    patterns = (
        rf"(?:^|\s){key_re}=Some\(\"([^\"]*)\"\)",
        rf"(?:^|\s){key_re}=\"([^\"]*)\"",
        rf"(?:^|\s){key_re}=([^\s,]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    fail(f"event {line!r} is missing field {key}")


def _span_field(line: str, key: str, next_key: str) -> str:
    match = re.search(
        rf"(?:^|\s){re.escape(key)}=(.*?)\s+{re.escape(next_key)}=",
        line,
    )
    if not match or not match.group(1).strip():
        fail(f"event is missing span field {key}")
    return re.sub(r"\s+", "", match.group(1))


def _path_list(line: str, key: str) -> tuple[str, ...]:
    match = re.search(rf"(?:^|\s){re.escape(key)}=([\[{{])", line)
    if not match:
        fail(f"event is missing path list {key}")
    opener = match.group(1)
    closer = "]" if opener == "[" else "}"
    end = line.find(closer, match.end())
    if end < 0:
        fail(f"event {key} has no closing collection delimiter")
    body = line[match.end() : end].strip()
    if not body:
        return ()
    quoted = re.findall(r'\"([^\"]+)\"', body)
    values = quoted if quoted else [part.strip() for part in body.split(",")]
    if key == "paths" and "SerialPathTxReceipt" in body:
        entry_count = body.count("SerialPathTxReceipt {")
        if (
            entry_count != len(values)
            or body.count("committed: true") != entry_count
            or body.count("error: None") != entry_count
        ):
            fail("TX paths debug receipt contains an uncommitted/error path")
    if any(not PATH_TOKEN.fullmatch(value) for value in values):
        fail(f"event {key} contains an invalid logical UART")
    if len(values) != len(set(values)):
        fail(f"event {key} repeats a logical UART")
    return tuple(values)


def _hex_wire(line: str, expected_bytes: int) -> bytes:
    value = _simple_field(line, "wire_hex")
    if len(value) != expected_bytes * 2 or not HEX_BYTES.fullmatch(value):
        fail(f"wire_hex is not exactly {expected_bytes} bytes")
    return bytes.fromhex(value)


def _crc5(data: bytes) -> int:
    crc = 0x1F
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            crc_bit = (crc >> 4) & 1
            crc = (crc << 1) & 0x1F
            if bit ^ crc_bit:
                crc ^= 0x05
    return crc


def _crc16_itu_t(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _nonce(value: str) -> str:
    normalized = value.removeprefix("0x").lower()
    if not re.fullmatch(r"[0-9a-f]{8}", normalized):
        fail(f"invalid share nonce {value!r}")
    return normalized


def _version(value: str) -> str:
    normalized = value.removeprefix("0x").lower()
    if not re.fullmatch(r"[0-9a-f]{8}", normalized):
        fail(f"invalid share version {value!r}")
    return normalized


def _safe_token(value: str, label: str) -> str:
    if not value or not SAFE_TOKEN.fullmatch(value):
        fail(f"{label} is not a safe evidence token")
    return value


@dataclass(frozen=True)
class ShareEvidence:
    path: str
    job_id: str
    nonce: str
    work_generation: str
    attribution: str
    physical_chip_core: str
    version: str


def _share_from_attribution(line: str) -> ShareEvidence:
    if _simple_field(line, "schema") != PROOF_SCHEMA:
        fail("attribution event has the wrong schema")
    if _simple_field(line, "event") != "rx-share-attributed":
        fail("attribution event has the wrong event type")
    if _simple_field(line, "crc_status") != "full-frame-zero-remainder":
        fail("attribution event lacks CRC admission")
    if _simple_field(line, "meets_pool_target") != "true":
        fail("attribution event is not a pool-target share")
    return ShareEvidence(
        path=_simple_field(line, "path"),
        job_id=_safe_token(_simple_field(line, "pool_job_id"), "pool job id"),
        nonce=_nonce(_simple_field(line, "nonce")),
        work_generation=_span_field(line, "work_generation", "pool_job_id"),
        attribution=_safe_token(_simple_field(line, "attribution"), "attribution"),
        physical_chip_core=_span_field(line, "physical_chip_core", "meets_pool_target"),
        version=_version(_simple_field(line, "rolled_version")),
    )


def _share_from_pool_result(line: str) -> tuple[ShareEvidence, bool]:
    if _simple_field(line, "schema") != PROOF_SCHEMA:
        fail("pool-result event has the wrong schema")
    if _simple_field(line, "event") != "pool-result":
        fail("pool-result event has the wrong event type")
    result = _simple_field(line, "result")
    if result not in ("accepted", "rejected"):
        fail("pool-result event has an invalid result")
    # These are part of the exact submitted-share sidecar evidence even though
    # attribution matching uses the common fields below.
    _safe_token(_simple_field(line, "worker_name"), "worker name")
    if not re.fullmatch(r"[0-9A-Fa-f]+", _simple_field(line, "extranonce2")):
        fail("pool-result extranonce2 is not hex")
    if not re.fullmatch(r"[0-9A-Fa-f]{8}", _simple_field(line, "ntime")):
        fail("pool-result ntime is not eight hex digits")
    share = ShareEvidence(
        path=_simple_field(line, "path"),
        job_id=_safe_token(_simple_field(line, "pool_job_id"), "pool job id"),
        nonce=_nonce(_simple_field(line, "nonce")),
        work_generation=_span_field(line, "work_generation", "pool_job_id"),
        attribution=_safe_token(_simple_field(line, "attribution"), "attribution"),
        physical_chip_core=_span_field(line, "physical_chip_core", "work_generation"),
        version=_version(_simple_field(line, "version")),
    )
    return share, result == "accepted"


def _verify_plan(fields: dict[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    required = {
        "schema": PLAN_SCHEMA,
        "operator_artifact_pin": "required-and-matched",
        "mode": "bounded-work-proof",
        "work_authority": "bounded-proof",
        "bounded_work_proof_flag": "--s19k-track1-bounded-work-proof",
        "work_proof_timeout_s": str(EXPECTED_TIMEOUT_S),
        "work_evidence": EXPECTED_WORK_EVIDENCE,
        "work_proof_success": EXPECTED_SUCCESS,
        "persistent_mutation": "false",
        "native_bm1366": "refused",
        "clear_for_flash": "false",
        "dry_run": "false",
        "ssh_host_key_admission": "exact-operator-pin",
        "ssh_global_known_hosts": "disabled-on-contact",
    }
    for key, value in required.items():
        _require(fields, key, value, "deploy plan")
    _sha(fields.get("sha256"), "plan artifact sha256")
    _uint(fields.get("bytes"), "plan artifact bytes", positive=True)
    _require(
        fields,
        "expected_artifact_sha256",
        fields["sha256"],
        "deploy plan",
    )
    _require(
        fields,
        "expected_artifact_bytes",
        fields["bytes"],
        "deploy plan",
    )
    for prefix in ("runner", "config", "custody_observer", "stock_restart_helper"):
        _sha(fields.get(f"{prefix}_sha256"), f"plan {prefix} sha256")
        _uint(fields.get(f"{prefix}_bytes"), f"plan {prefix} bytes", positive=True)
    host_key = fields.get("ssh_host_key_sha256", "")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_key):
        fail("live deploy plan lacks a canonical pinned SSH host-key digest")
    _require(
        fields,
        "required_ports",
        "population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
        "deploy plan",
    )
    return ("/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"), ()


def _verify_bound_record(
    fields: dict[str, str],
    receipt: dict[str, str],
    plan: dict[str, str],
    kind: str,
) -> None:
    for prefix, plan_sha, plan_bytes in (
        ("binary", "sha256", "bytes"),
        ("config", "config_sha256", "config_bytes"),
        ("runner", "runner_sha256", "runner_bytes"),
        ("custody_observer", "custody_observer_sha256", "custody_observer_bytes"),
        ("stock_restart_helper", "stock_restart_helper_sha256", "stock_restart_helper_bytes"),
    ):
        _require(receipt, f"{prefix}_sha256", plan[plan_sha], "transcript receipt")
        _require(receipt, f"{prefix}_bytes", plan[plan_bytes], "transcript receipt")
        if f"{prefix}_sha256" in fields:
            _require(fields, f"{prefix}_sha256", plan[plan_sha], kind)
        if f"{prefix}_bytes" in fields:
            _require(fields, f"{prefix}_bytes", plan[plan_bytes], kind)
    _require(fields, "persistent_mutation", "false", kind)
    _require(fields, "live_identity_sha256", receipt["live_identity_sha256"], kind)
    _require(fields, "live_identity_profile", receipt["live_identity_profile"], kind)


def _verify_safeoff_line(text: str, receipt: dict[str, str]) -> str:
    lines = [line for line in text.splitlines() if line.startswith("DCENT_S19K_TRACK1_SAFEOFF_RECEIPT ")]
    if len(lines) != 1:
        fail("SafeOff companion must contain exactly one canonical receipt line")
    fields: dict[str, str] = {}
    for token in lines[0].split()[1:]:
        if "=" not in token:
            fail("SafeOff receipt contains a malformed token")
        key, value = token.split("=", 1)
        if key in fields:
            fail(f"SafeOff receipt repeats {key}")
        fields[key] = value
    required = {
        "schema": SAFEOFF_SCHEMA,
        "live_identity_sha256": receipt["live_identity_sha256"],
        "live_identity_profile": receipt["live_identity_profile"],
        "live_identity_model_sha256": receipt["live_identity_model_sha256"],
        "resets": "454:0,455:0,456:0",
        "psu": "437:1",
    }
    for key, value in required.items():
        _require(fields, key, value, "SafeOff receipt")
    return lines[0]


def _verify_transcript(
    data: bytes,
    receipt: dict[str, str],
    required_plan_paths: tuple[str, ...],
    optional_paths: tuple[str, ...],
) -> dict[str, object]:
    text = _decode_text(data, "bounded-work transcript")
    if "\x1b" in text:
        fail("bounded-work transcript contains escape bytes; runner output must be non-ANSI")
    lines = text.splitlines()
    markers = {
        STARTED: [],
        TX: [],
        RX: [],
        ATTRIBUTION: [],
        POOL_RESULT: [],
        COMPLETE: [],
        INCOMPLETE: [],
    }
    for index, line in enumerate(lines):
        for marker in markers:
            if marker in line:
                markers[marker].append((index, line))
    expected_counts = {
        STARTED: "started_count",
        TX: "tx_count",
        RX: "rx_count",
        ATTRIBUTION: "attribution_count",
        POOL_RESULT: "pool_result_count",
        COMPLETE: "complete_count",
        INCOMPLETE: "incomplete_count",
    }
    for marker, key in expected_counts.items():
        if len(markers[marker]) != _uint(receipt.get(key), f"receipt {key}"):
            fail(f"wrapper marker count for {marker} does not match the transcript")
    if len(markers[STARTED]) != 1 or len(markers[COMPLETE]) != 1 or markers[INCOMPLETE]:
        fail("bounded proof requires one STARTED, one COMPLETE, and zero INCOMPLETE markers")
    if not markers[TX] or not markers[RX] or not markers[ATTRIBUTION] or not markers[POOL_RESULT]:
        fail("bounded proof lacks TX/RX/attribution/pool-result evidence")

    started_index, started_line = markers[STARTED][0]
    if _simple_field(started_line, "schema") != PROOF_SCHEMA:
        fail("STARTED marker has the wrong proof schema")
    if _uint(_simple_field(started_line, "timeout_s"), "proof timeout") != EXPECTED_TIMEOUT_S:
        fail("STARTED marker has the wrong timeout")
    active_paths = _path_list(started_line, "required_paths")
    if not active_paths:
        fail("STARTED marker has an empty selected UART population")
    if not set(active_paths).issubset(set(required_plan_paths) | set(optional_paths)):
        fail("STARTED marker names a UART outside the plan contract")

    sequences: list[int] = []
    for index, line in markers[TX]:
        if index <= started_index:
            fail("TX evidence preceded STARTED")
        if _simple_field(line, "schema") != PROOF_SCHEMA:
            fail("TX evidence has the wrong schema")
        if _simple_field(line, "event") != "tx-all-required-committed":
            fail("bounded success contains a partial/unknown TX event")
        if _uint(_simple_field(line, "wire_bytes"), "TX wire_bytes") != 88:
            fail("TX evidence does not claim 88 bytes")
        wire = _hex_wire(line, 88)
        if wire[:4] != bytes.fromhex("55AA2136"):
            fail("TX evidence is not a Closed11d work frame")
        if int.from_bytes(wire[-2:], "big") != _crc16_itu_t(wire[2:-2]):
            fail("TX evidence has an invalid CRC16-ITU-T")
        if _uint(_simple_field(line, "asic_job_id"), "TX asic_job_id") != wire[4]:
            fail("TX asic_job_id does not match the wire")
        if set(_path_list(line, "paths")) != set(active_paths):
            fail("TX evidence was not committed to every active logical UART")
        _span_field(line, "work_generation", "pool_job_id")
        _safe_token(_simple_field(line, "pool_job_id"), "TX pool job id")
        sequences.append(_uint(_simple_field(line, "commit_sequence"), "TX commit_sequence"))
    if sequences != list(range(len(sequences))):
        fail("TX commit_sequence is not unique, contiguous, and ordered from zero")

    rx_frames: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, line in markers[RX]:
        if index <= started_index:
            fail("RX evidence preceded STARTED")
        if _simple_field(line, "schema") != PROOF_SCHEMA:
            fail("RX evidence has the wrong schema")
        if _simple_field(line, "event") != "rx-crc-admitted":
            fail("RX evidence has the wrong event type")
        path = _simple_field(line, "path")
        if path not in active_paths:
            fail("RX evidence names a non-active logical UART")
        if _uint(_simple_field(line, "wire_bytes"), "RX wire_bytes") != 11:
            fail("RX evidence does not claim 11 bytes")
        if _simple_field(line, "crc_status") != "full-frame-zero-remainder":
            fail("RX evidence lacks full-frame CRC admission")
        wire = _hex_wire(line, 11)
        if wire[:2] != bytes.fromhex("AA55") or _crc5(wire[2:]) != 0:
            fail("RX evidence does not reconstruct an admitted BM1366 frame")
        rx_frames[(path, wire.hex().lower())].append(index)

    attributed: dict[ShareEvidence, list[int]] = defaultdict(list)
    for index, line in markers[ATTRIBUTION]:
        if index <= started_index:
            fail("attribution evidence preceded STARTED")
        share = _share_from_attribution(line)
        if share.path not in active_paths:
            fail("attribution names a non-active logical UART")
        wire = _hex_wire(line, 11)
        frame_key = (share.path, wire.hex().lower())
        preceding_frames = rx_frames.get(frame_key, [])
        if not preceding_frames or preceding_frames[0] >= index:
            fail("attribution has no preceding CRC-admitted RX frame")
        preceding_frames.pop(0)
        attributed[share].append(index)

    accepted_paths: set[str] = set()
    last_accepted_index = -1
    for index, line in markers[POOL_RESULT]:
        if index <= started_index:
            fail("pool-result evidence preceded STARTED")
        share, accepted = _share_from_pool_result(line)
        if share.path not in active_paths:
            fail("pool result names a non-active logical UART")
        origins = attributed.get(share, [])
        if not origins or origins[0] >= index:
            fail("pool result has no exact RX attribution origin")
        origins.pop(0)
        if accepted:
            accepted_paths.add(share.path)
            last_accepted_index = index

    complete_index, complete_line = markers[COMPLETE][0]
    if _simple_field(complete_line, "schema") != PROOF_SCHEMA:
        fail("COMPLETE marker has the wrong schema")
    if complete_index <= last_accepted_index or complete_index <= started_index:
        fail("COMPLETE marker did not follow the accepted-share evidence")
    if set(_path_list(complete_line, "required_paths")) != set(active_paths):
        fail("COMPLETE required_paths changed from STARTED")
    if set(_path_list(complete_line, "accepted_paths")) != set(active_paths):
        fail("COMPLETE marker does not claim every active logical UART")
    if accepted_paths != set(active_paths):
        fail("pool results do not prove one accepted share per active logical UART")

    return {
        "required_paths": list(active_paths),
        "accepted_paths": sorted(accepted_paths),
        "tx_count": len(markers[TX]),
        "rx_count": len(markers[RX]),
        "attribution_count": len(markers[ATTRIBUTION]),
        "pool_result_count": len(markers[POOL_RESULT]),
    }


def verify(plan_path: Path, trial_dir: Path) -> dict[str, object]:
    plan_data, plan = _parse_kv_file(plan_path, "deploy plan")
    required_paths, optional_paths = _verify_plan(plan)

    try:
        trial_metadata = os.lstat(trial_dir)
    except OSError as error:
        fail(f"cannot stat copied trial directory: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISDIR(trial_metadata.st_mode)
        or stat.S_ISLNK(trial_metadata.st_mode)
        or bool(reparse and getattr(trial_metadata, "st_file_attributes", 0) & reparse)
    ):
        fail("copied trial directory must be a real non-link directory")

    receipt_path = trial_dir / "runtime_bounded_work_transcript"
    receipt_data, receipt = _parse_kv_file(
        receipt_path,
        "bounded-work transcript receipt",
        exact_keys=RECEIPT_KEYS,
    )
    receipt_required = {
        "schema": RECEIPT_SCHEMA,
        "deploy_mode": "bounded-work-proof",
        "transcript_mode": "0600",
        "transcript_uid": "0",
        "transcript_gid": "0",
        "source_runtime_active_schema": SOURCE_RUNTIME_SCHEMA,
        "pending_runtime_schema": PENDING_RUNTIME_SCHEMA,
        "terminal_handoff_receipt_schema": TERMINAL_HANDOFF_SCHEMA,
        "safeoff_receipt_schema": SAFEOFF_SCHEMA,
        "live_identity_schema": LIVE_IDENTITY_SCHEMA,
        "wrapper_exit_status": "0",
        "semantic_verification": "host-required",
        "persistent_mutation": "false",
        "publication": "no-clobber-hard-link-after-fsync",
    }
    for key, value in receipt_required.items():
        _require(receipt, key, value, "bounded-work transcript receipt")
    remote_paths = {
        key: PurePosixPath(receipt[key])
        for key in (
            "transcript_path",
            "source_runtime_active_path",
            "pending_runtime_path",
            "terminal_handoff_receipt_path",
            "safeoff_receipt_path",
        )
    }
    remote_parents = {path.parent for path in remote_paths.values()}
    if len(remote_parents) != 1:
        fail("transcript receipt paths do not share one remote trial directory")
    remote_parent = next(iter(remote_parents))
    if (
        remote_parent.parent != PurePosixPath("/tmp")
        or not remote_parent.name.startswith("dcentrald_bench_t1_")
    ):
        fail("transcript receipt does not name one direct S19k /tmp trial directory")
    expected_basenames = {
        "source_runtime_active_path": "runtime_active_pre_safeoff",
        "pending_runtime_path": "runtime_active",
        "terminal_handoff_receipt_path": "runtime_terminal_safeoff",
        "safeoff_receipt_path": "runtime_safeoff_terminal_receipt",
    }
    for key, expected in expected_basenames.items():
        if remote_paths[key].name != expected:
            fail(f"transcript receipt {key} is not the canonical trial filename")
    if not re.fullmatch(
        r"\.startup_daemon_transcript\.[1-9][0-9]*\.[1-9][0-9]*",
        remote_paths["transcript_path"].name,
    ):
        fail("transcript receipt has a non-canonical daemon transcript filename")
    _uint(receipt.get("transcript_mnt_id"), "receipt transcript_mnt_id", positive=True)
    _uint(receipt.get("transcript_inode"), "receipt transcript_inode", positive=True)
    for key in (
        "transcript_sha256",
        "source_runtime_active_sha256",
        "pending_runtime_sha256",
        "terminal_handoff_receipt_sha256",
        "safeoff_receipt_sha256",
        "binary_sha256",
        "config_sha256",
        "runner_sha256",
        "custody_observer_sha256",
        "stock_restart_helper_sha256",
        "live_identity_sha256",
        "live_identity_model_sha256",
    ):
        _sha(receipt.get(key), f"receipt {key}")
    for key in (
        "transcript_bytes",
        "source_runtime_active_bytes",
        "pending_runtime_bytes",
        "terminal_handoff_receipt_bytes",
        "safeoff_receipt_bytes",
        "binary_bytes",
        "config_bytes",
        "runner_bytes",
        "custody_observer_bytes",
        "stock_restart_helper_bytes",
    ):
        _uint(receipt.get(key), f"receipt {key}", positive=True)

    transcript_path, transcript_data = _resolve_bound_file(
        trial_dir,
        receipt["transcript_path"],
        receipt["transcript_sha256"],
        int(receipt["transcript_bytes"]),
        "bounded-work transcript",
    )
    source_path, source_data = _resolve_bound_file(
        trial_dir,
        receipt["source_runtime_active_path"],
        receipt["source_runtime_active_sha256"],
        int(receipt["source_runtime_active_bytes"]),
        "source runtime receipt",
    )
    pending_path, pending_data = _resolve_bound_file(
        trial_dir,
        receipt["pending_runtime_path"],
        receipt["pending_runtime_sha256"],
        int(receipt["pending_runtime_bytes"]),
        "pending runtime receipt",
    )
    terminal_path, terminal_data = _resolve_bound_file(
        trial_dir,
        receipt["terminal_handoff_receipt_path"],
        receipt["terminal_handoff_receipt_sha256"],
        int(receipt["terminal_handoff_receipt_bytes"]),
        "terminal handoff receipt",
    )
    safeoff_path, safeoff_data = _resolve_bound_file(
        trial_dir,
        receipt["safeoff_receipt_path"],
        receipt["safeoff_receipt_sha256"],
        int(receipt["safeoff_receipt_bytes"]),
        "SafeOff companion",
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
    for filename, sha_key, bytes_key, label in staged_contract:
        staged_data = _stable_regular_bytes(trial_dir / filename, label)
        if _hash(staged_data) != plan[sha_key] or len(staged_data) != int(plan[bytes_key]):
            fail(f"{label} does not match the live deploy plan")
    source, _ = _parse_kv_bytes(source_data, "source runtime receipt")
    pending, _ = _parse_kv_bytes(pending_data, "pending runtime receipt")
    terminal, _ = _parse_kv_bytes(terminal_data, "terminal handoff receipt")

    _require(source, "schema", SOURCE_RUNTIME_SCHEMA, "source runtime receipt")
    _require(source, "deploy_mode", "bounded-work-proof", "source runtime receipt")
    _verify_bound_record(source, receipt, plan, "source runtime receipt")

    pending_required = {
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
    }
    for key, value in pending_required.items():
        _require(pending, key, value, "pending runtime receipt")
    _verify_bound_record(pending, receipt, plan, "pending runtime receipt")

    terminal_required = {
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
    }
    for key, value in terminal_required.items():
        _require(terminal, key, value, "terminal handoff receipt")
    _verify_bound_record(terminal, receipt, plan, "terminal handoff receipt")
    safeoff_line = _verify_safeoff_line(
        _decode_text(safeoff_data, "SafeOff companion"), receipt
    )
    semantic = _verify_transcript(
        transcript_data,
        receipt,
        required_paths,
        optional_paths,
    )

    result: dict[str, object] = {
        "schema": "dcentos.s19k-bounded-work-host-verification/v1",
        "claim": (
            "content-bound bounded-work transcript proves accepted share per active "
            "logical UART and checked terminal SafeOff"
        ),
        "plan_sha256": _hash(plan_data),
        "receipt_sha256": _hash(receipt_data),
        "transcript_sha256": receipt["transcript_sha256"],
        "artifact_sha256": plan["sha256"],
        "live_identity_sha256": receipt["live_identity_sha256"],
        "safeoff_receipt": safeoff_line,
        "transcript_file": transcript_path.name,
        "source_runtime_file": source_path.name,
        "pending_runtime_file": pending_path.name,
        "terminal_handoff_file": terminal_path.name,
        "safeoff_file": safeoff_path.name,
        **semantic,
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    result["verification_id"] = hashlib.sha256((canonical + "\n").encode("ascii")).hexdigest()
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify copied S19k bounded-work transcript and terminal receipts"
    )
    parser.add_argument("--plan", required=True, type=Path, help="live schema-v12 deploy plan")
    parser.add_argument(
        "--trial-dir",
        required=True,
        type=Path,
        help="complete copied remote trial directory",
    )
    parser.add_argument("--json", action="store_true", help="emit the complete verification result")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify(args.plan.resolve(strict=True), args.trial_dir.resolve(strict=True))
    except (OSError, VerificationError) as error:
        print(f"S19K_BOUNDED_TRANSCRIPT_REFUSED: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(
            "S19K_BOUNDED_TRANSCRIPT_OK "
            f"verification_id={result['verification_id']} "
            f"transcript_sha256={result['transcript_sha256']} "
            f"required_paths={','.join(result['required_paths'])} "
            f"tx={result['tx_count']} rx={result['rx_count']} "
            f"pool_results={result['pool_result_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
