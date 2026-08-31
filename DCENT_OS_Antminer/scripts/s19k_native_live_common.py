#!/usr/bin/env python3
"""Shared fail-closed readers for S19k native live evidence.

This module is deliberately offline-only.  It accepts immutable, hash-bound
exports from the attended run; it contains no serial, GPIO, SSH, power, or
storage-writing code.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable


MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_BYTES = 128 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}\Z")
UART_PATHS = ("/dev/ttyS1", "/dev/ttyS2")


class NativeLiveEvidenceError(ValueError):
    """Native live evidence is absent, malformed, or semantically unsafe."""


def fail(message: str) -> None:
    raise NativeLiveEvidenceError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def stable_file(path: Path, label: str, maximum: int = MAX_CAPTURE_BYTES) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} has an invalid byte count")
    try:
        data = path.read_bytes()
        after = os.lstat(path)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(data) != before.st_size:
        fail(f"{label} changed while it was read")
    if os.name == "posix" and before.st_nlink != 1:
        fail(f"{label} must have exactly one hard link")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_object(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has an inexact key set")
    return value


def canonical_uint(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} must be an integer")
    if value < 0 or (positive and value == 0):
        fail(f"{label} must be {'positive' if positive else 'nonnegative'}")
    return value


def token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        fail(f"{label} is not a canonical token")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not a canonical SHA-256")
    return value


def load_canonical_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    data = stable_file(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not UTF-8 JSON: {error}")
    if not isinstance(value, dict) or data != canonical_json(value):
        fail(f"{label} is not a canonical JSON object")
    return data, value


def csv_rows(path: Path, header: tuple[str, ...], label: str) -> tuple[bytes, list[list[str]]]:
    data = stable_file(path, label)
    try:
        text = data.decode("ascii")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        fail(f"{label} is not strict ASCII CSV: {error}")
    if not rows or tuple(rows[0]) != header:
        fail(f"{label} header is not exact")
    if len(rows) < 2 or any(
        len(row) != len(header) or any(cell == "" for cell in row) for row in rows[1:]
    ):
        fail(f"{label} has missing or malformed evidence rows")
    return data, rows[1:]


def csv_uint(value: str, label: str, *, positive: bool = False) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        fail(f"{label} is not a canonical unsigned integer")
    result = int(value)
    if positive and result == 0:
        fail(f"{label} must be positive")
    return result


def csv_int(value: str, label: str) -> int:
    if not re.fullmatch(r"0|-?[1-9][0-9]*", value):
        fail(f"{label} is not a canonical integer")
    return int(value)


def verify_manifest(
    evidence_dir: Path,
    *,
    schema: str,
    phase: str,
    payload_files: tuple[str, ...],
    extra_keys: tuple[str, ...],
) -> tuple[bytes, dict[str, Any], dict[str, bytes]]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail("evidence directory must be a real directory")
    manifest_data, manifest = load_canonical_json(
        evidence_dir / "capture-manifest.json", "native capture manifest"
    )
    exact_object(
        manifest,
        ("schema", "phase", "run_id", "common_clock_id", "files") + extra_keys,
        "native capture manifest",
    )
    if manifest["schema"] != schema or manifest["phase"] != phase:
        fail("native capture manifest schema or phase mismatch")
    token(manifest["run_id"], "native run_id")
    token(manifest["common_clock_id"], "native common_clock_id")
    files = exact_object(manifest["files"], payload_files, "native manifest files")
    expected_names = {"capture-manifest.json", "verification.json", *payload_files}
    try:
        actual_names = set()
        for child in evidence_dir.iterdir():
            metadata = os.lstat(child)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                fail("native evidence directory contains a non-regular member")
            actual_names.add(child.name)
    except OSError as error:
        fail(f"cannot enumerate native evidence directory: {error}")
    if actual_names != expected_names:
        fail("native evidence directory file set is incomplete or contains extras")
    payload: dict[str, bytes] = {}
    for name in payload_files:
        identity = exact_object(files[name], ("sha256", "bytes"), f"identity for {name}")
        expected_sha = digest(identity["sha256"], f"identity SHA-256 for {name}")
        expected_bytes = canonical_uint(identity["bytes"], f"identity bytes for {name}", positive=True)
        data = stable_file(evidence_dir / name, name)
        if sha256(data) != expected_sha or len(data) != expected_bytes:
            fail(f"{name} does not match the capture manifest")
        payload[name] = data
    return manifest_data, manifest, payload


def validate_embedded_receipt(data: bytes, label: str) -> dict[str, Any]:
    try:
        receipt = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not UTF-8 JSON: {error}")
    if not isinstance(receipt, dict) or data != canonical_json(receipt):
        fail(f"{label} is not canonical JSON")
    return receipt


def add_verification_id(result: dict[str, Any]) -> dict[str, Any]:
    if "verification_id" in result:
        fail("result already contains a verification identifier")
    result["verification_id"] = sha256(canonical_json(result))
    return result


def verify_workflow_receipt(evidence_dir: Path, result: dict[str, Any]) -> None:
    """Require the published workflow receipt to equal the fresh result bytes."""

    observed = stable_file(
        evidence_dir / "verification.json",
        "native workflow verification receipt",
        MAX_JSON_BYTES,
    )
    if observed != canonical_json(result):
        fail(
            "native workflow verification.json is stale, noncanonical, or "
            "does not match freshly replayed evidence"
        )


def verify_receipt_id(receipt: dict[str, Any], label: str) -> str:
    value = digest(receipt.get("verification_id"), f"{label} verification_id")
    body = dict(receipt)
    del body["verification_id"]
    if sha256(canonical_json(body)) != value:
        fail(f"{label} verification_id is stale")
    return value


def parse_uart(path: Path, *, require_work: bool) -> tuple[bytes, dict[str, Any]]:
    header = ("monotonic_ms", "path", "direction", "frame_hex")
    data, rows = csv_rows(path, header, "native UART capture")
    previous = -1
    coverage = {item: set() for item in UART_PATHS}
    work_paths: set[str] = set()
    rx_paths: set[str] = set()
    tails = {item: b"" for item in UART_PATHS}
    signature = bytes.fromhex("55AA2136")
    for number, row in enumerate(rows, 2):
        timestamp = csv_uint(row[0], f"UART row {number} timestamp")
        if timestamp < previous:
            fail("native UART capture timestamps are not monotonic")
        previous = timestamp
        if row[1] not in UART_PATHS or row[2] not in ("tx", "rx"):
            fail(f"native UART row {number} has an inadmissible path or direction")
        if re.fullmatch(r"[0-9A-F]+", row[3]) is None or len(row[3]) % 2:
            fail(f"native UART row {number} has noncanonical frame hex")
        frame = bytes.fromhex(row[3])
        if not 2 <= len(frame) <= 4096:
            fail(f"native UART row {number} has an invalid frame length")
        coverage[row[1]].add(row[2])
        if row[2] == "rx":
            rx_paths.add(row[1])
        else:
            combined = tails[row[1]] + frame
            if signature in combined:
                work_paths.add(row[1])
            tails[row[1]] = combined[-3:]
    if any(coverage[path] != {"tx", "rx"} for path in UART_PATHS):
        fail("native UART capture lacks bidirectional coverage on both logical UARTs")
    if require_work and work_paths != set(UART_PATHS):
        fail("native UART capture lacks a work frame on each logical UART")
    if not require_work and work_paths:
        fail("native no-work capture contains a forbidden 55AA2136 work frame")
    return data, {
        "uart_frame_count": len(rows),
        "uart_paths": list(UART_PATHS),
        "uart_rx_paths": sorted(rx_paths),
        "uart_work_paths": sorted(work_paths),
    }
