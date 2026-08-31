#!/usr/bin/env python3
"""Verify common-clock raw capture blocks for the S19k Phase 1+2 gate.

This host-only verifier does not contact hardware. It rejects sparse decoded
events and declared preflight rates as substitutes for retained samples. Each
rail, GPIO, fan-tach, and populated-UART direction must carry actual bit-packed
or run-length payloads over one exact common-clock window. Rates, continuity,
and gaps are calculated from those blocks.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping, NoReturn, Sequence


CONTRACT_SCHEMA = "dcentos.s19k-phase12-capture-contract/v2"
VERIFICATION_SCHEMA = "dcentos.s19k-phase12-raw-capture-verification/v2"
CLAIM = (
    "retained-common-clock-per-channel-raw-block-coverage-"
    "not-electrical-calibration-no-work-safeoff-or-live-authority"
)
CONTRACT_NAME = "capture_contract.json"
BLOCKS_NAME = "capture_blocks.csv"
RECEIPT_NAME = "capture_verification.json"
HEADER = (
    "common_clock_id",
    "block_id",
    "channel",
    "start_ns",
    "period_ns",
    "sample_count",
    "encoding",
    "data_hex",
)
CONTRACT_KEYS = (
    "schema",
    "common_clock_id",
    "window_start_ns",
    "window_end_ns",
    "rail_signal",
    "populated_uart_paths",
)
REQUIRED_UART_PATHS = ("/dev/ttyS1", "/dev/ttyS2")
OPTIONAL_UART_PATHS = ("/dev/ttyS3",)
RAIL_CHANNELS = ("rail-slot2", "rail-slot3")
GPIO_CHANNELS = ("gpio437", "gpio454", "gpio455", "gpio456")
TACH_CHANNELS = tuple(f"fan{index}-tach" for index in range(4))
PERIOD_LIMIT_NS = {
    "rail": 1_000_000,  # at least 1 ksample/s
    "gpio": 10_000,  # at least 100 ksample/s
    "tach": 100_000,  # at least 10 ksample/s
    "uart": 10,  # at least 100 Msample/s for the 12 Mbaud line
}
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_BLOCK_BYTES = 256 * 1024 * 1024
MAX_ROWS = 1_000_000
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
UINT_RE = re.compile(r"0|[1-9][0-9]*")
HEX_RE = re.compile(r"(?:[0-9a-f]{2})+")


class CaptureVerificationError(ValueError):
    """Raw capture evidence is absent, ambiguous, discontinuous, or stale."""


def fail(message: str) -> NoReturn:
    raise CaptureVerificationError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or bool(reparse and getattr(before, "st_file_attributes", 0) & reparse)
        or getattr(before, "st_nlink", 1) != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        fail(f"{label} must be a bounded single-link real regular file")
    data = path.read_bytes()
    after = path.lstat()
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(data) != before.st_size
    ):
        fail(f"{label} changed while it was read")
    return data


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        fail(f"{label} must be a canonical integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and UINT_RE.fullmatch(value):
        result = int(value)
    else:
        fail(f"{label} must be a canonical integer")
    if positive and result <= 0:
        fail(f"{label} must be positive")
    return result


def _contract(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"capture contract is not UTF-8 JSON: {error}")
    if not isinstance(value, dict) or set(value) != set(CONTRACT_KEYS):
        fail("capture contract key set is not exact")
    if data != canonical_json(value):
        fail("capture contract is not canonical JSON")
    if value.get("schema") != CONTRACT_SCHEMA:
        fail(f"capture contract must use schema {CONTRACT_SCHEMA}")
    clock = value.get("common_clock_id")
    if not isinstance(clock, str) or TOKEN_RE.fullmatch(clock) is None:
        fail("capture common_clock_id is invalid")
    start = _uint(value.get("window_start_ns"), "capture window start")
    end = _uint(value.get("window_end_ns"), "capture window end", positive=True)
    if end <= start:
        fail("capture window is empty or reversed")
    if value.get("rail_signal") not in (
        "rail-millivolts",
        "rail-current-milliamps",
    ):
        fail("capture rail_signal is not admitted")
    paths = value.get("populated_uart_paths")
    if (
        not isinstance(paths, list)
        or not all(isinstance(item, str) for item in paths)
        or len(paths) != len(set(paths))
        or paths != sorted(paths)
        or not set(REQUIRED_UART_PATHS).issubset(paths)
        or not set(paths).issubset(REQUIRED_UART_PATHS + OPTIONAL_UART_PATHS)
    ):
        fail("populated UART paths must canonically include ttyS1/ttyS2 and only optional ttyS3")
    return value


def _channel_class(channel: str) -> str:
    if channel in RAIL_CHANNELS:
        return "rail"
    if channel in GPIO_CHANNELS:
        return "gpio"
    if channel in TACH_CHANNELS:
        return "tach"
    if re.fullmatch(r"ttyS[123]-(?:rx|tx)", channel):
        return "uart"
    fail(f"unsupported raw capture channel {channel}")


def _required_channels(paths: Sequence[str]) -> tuple[str, ...]:
    uart = tuple(
        f"{Path(path).name}-{direction}"
        for path in paths
        for direction in ("rx", "tx")
    )
    return RAIL_CHANNELS + GPIO_CHANNELS + TACH_CHANNELS + uart


def _validate_payload(
    channel_class: str, encoding: str, sample_count: int, data_hex: str, label: str
) -> None:
    if HEX_RE.fullmatch(data_hex) is None:
        fail(f"{label} data_hex must be non-empty canonical lowercase bytes")
    data = bytes.fromhex(data_hex)
    if channel_class == "rail":
        allowed = ("u16le", "rle-u16le-v1")
    else:
        allowed = ("bitpack-lsb0", "rle-bit-v1")
    if encoding not in allowed:
        fail(f"{label} encoding is invalid for {channel_class}")
    if encoding == "u16le":
        if len(data) != sample_count * 2:
            fail(f"{label} u16 payload length does not match sample_count")
        return
    if encoding == "bitpack-lsb0":
        if len(data) != (sample_count + 7) // 8:
            fail(f"{label} bit-packed payload length does not match sample_count")
        remainder = sample_count % 8
        if remainder and data[-1] & ~((1 << remainder) - 1):
            fail(f"{label} bit-packed unused bits are not zero")
        return
    record_size = 6 if encoding == "rle-u16le-v1" else 5
    if len(data) % record_size or not data:
        fail(f"{label} RLE payload has an invalid record boundary")
    observed = 0
    previous: bytes | None = None
    for offset in range(0, len(data), record_size):
        value_size = 2 if record_size == 6 else 1
        value = data[offset : offset + value_size]
        if record_size == 5 and value not in (b"\x00", b"\x01"):
            fail(f"{label} RLE bit value is not binary")
        count = int.from_bytes(
            data[offset + value_size : offset + record_size], "little"
        )
        if count <= 0 or value == previous:
            fail(f"{label} RLE records are empty or noncanonical")
        observed += count
        previous = value
    if observed != sample_count:
        fail(f"{label} RLE sample total does not match sample_count")


def _rows(data: bytes, contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        fail(f"capture blocks are not ASCII CSV: {error}")
    if "\r" in text or not text.endswith("\n"):
        fail("capture blocks must use canonical LF-terminated CSV")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        fail("capture blocks CSV is empty")
    if tuple(header) != HEADER:
        fail("capture blocks CSV header is not exact")
    result: list[dict[str, Any]] = []
    for number, row in enumerate(reader, 2):
        if number > MAX_ROWS + 1:
            fail("capture blocks CSV contains too many rows")
        if len(row) != len(HEADER):
            fail(f"capture block row {number} has an inexact field count")
        if row[0] != contract["common_clock_id"]:
            fail(f"capture block row {number} uses a different common clock")
        block_id = _uint(row[1], f"capture block row {number} block_id")
        channel = row[2]
        channel_class = _channel_class(channel)
        start = _uint(row[3], f"capture block row {number} start_ns")
        period = _uint(row[4], f"capture block row {number} period_ns", positive=True)
        count = _uint(row[5], f"capture block row {number} sample_count", positive=True)
        if period > PERIOD_LIMIT_NS[channel_class]:
            fail(f"capture block row {number} measured {channel_class} rate is too low")
        _validate_payload(channel_class, row[6], count, row[7], f"capture block row {number}")
        result.append(
            {
                "block_id": block_id,
                "channel": channel,
                "class": channel_class,
                "start_ns": start,
                "period_ns": period,
                "sample_count": count,
                "end_ns": start + period * count,
                "encoding": row[6],
                "data_hex": row[7],
                "data_sha256": digest(bytes.fromhex(row[7])),
            }
        )
    if not result:
        fail("capture blocks CSV has no data rows")
    return result


def build_result(contract_path: Path, blocks_path: Path) -> dict[str, Any]:
    contract_data = _read_regular(
        contract_path, MAX_CONTRACT_BYTES, "capture contract"
    )
    blocks_data = _read_regular(blocks_path, MAX_BLOCK_BYTES, "capture blocks")
    contract = _contract(contract_data)
    rows = _rows(blocks_data, contract)
    required = _required_channels(contract["populated_uart_paths"])
    by_channel: dict[str, list[dict[str, Any]]] = {name: [] for name in required}
    for row in rows:
        if row["channel"] not in by_channel:
            fail(f"capture contains undeclared or unpopulated channel {row['channel']}")
        by_channel[row["channel"]].append(row)
    start = contract["window_start_ns"]
    end = contract["window_end_ns"]
    metrics: list[dict[str, Any]] = []
    for channel in required:
        blocks = by_channel[channel]
        if not blocks:
            fail(f"capture is missing required raw channel {channel}")
        blocks.sort(key=lambda item: (item["start_ns"], item["block_id"]))
        expected_ids = list(range(len(blocks)))
        if [item["block_id"] for item in blocks] != expected_ids:
            fail(f"capture channel {channel} block IDs are not canonical and contiguous")
        if blocks[0]["start_ns"] > start or blocks[-1]["end_ns"] < end:
            fail(f"capture channel {channel} does not cover the common-clock window")
        maximum_gap = 0
        for previous, current in zip(blocks, blocks[1:]):
            gap = current["start_ns"] - previous["end_ns"]
            if gap < 0:
                fail(f"capture channel {channel} blocks overlap")
            maximum_gap = max(maximum_gap, gap)
            if gap > max(previous["period_ns"], current["period_ns"]):
                fail(f"capture channel {channel} has an unmeasured sample gap")
        slowest_period = max(item["period_ns"] for item in blocks)
        metrics.append(
            {
                "channel": channel,
                "class": blocks[0]["class"],
                "block_count": len(blocks),
                "sample_count": sum(item["sample_count"] for item in blocks),
                "first_sample_ns": blocks[0]["start_ns"],
                "covered_until_ns": blocks[-1]["end_ns"],
                "maximum_gap_ns": maximum_gap,
                "slowest_period_ns": slowest_period,
                "minimum_measured_rate_hz": 1_000_000_000 // slowest_period,
                "block_payload_sha256": digest(canonical_json(blocks)),
            }
        )
    result: dict[str, Any] = {
        "schema": VERIFICATION_SCHEMA,
        "claim": CLAIM,
        "contract": {
            "sha256": digest(contract_data),
            "bytes": len(contract_data),
        },
        "blocks": {"sha256": digest(blocks_data), "bytes": len(blocks_data)},
        "common_clock_id": contract["common_clock_id"],
        "window_start_ns": start,
        "window_end_ns": end,
        "populated_uart_paths": contract["populated_uart_paths"],
        "rail_signal": contract["rail_signal"],
        "channels": metrics,
        "both_populated_rail_feeds_retained": True,
        "rates_and_gaps_computed_from_raw_blocks": True,
        "common_clock_window_covered": True,
        "decoded_uart_frames_sufficient_without_raw_blocks": False,
        "electrical_calibration_proven": False,
        "no_work_proven": False,
        "safeoff_proven": False,
        "live_contact_authority": False,
    }
    result["verification_id"] = digest(canonical_json(result))
    return result


def _rail_value_at(block: Mapping[str, Any], sample_index: int) -> int:
    data = bytes.fromhex(str(block["data_hex"]))
    if block["encoding"] == "u16le":
        offset = sample_index * 2
        return int.from_bytes(data[offset : offset + 2], "little")
    cursor = 0
    for offset in range(0, len(data), 6):
        value = int.from_bytes(data[offset : offset + 2], "little")
        count = int.from_bytes(data[offset + 2 : offset + 6], "little")
        if sample_index < cursor + count:
            return value
        cursor += count
    fail("rail RLE sample lookup exceeded the retained payload")


def rail_composite_at_times(
    contract_path: Path, blocks_path: Path, timestamps_ns: Sequence[int]
) -> tuple[str, list[tuple[int, int, int]]]:
    """Return slot2, slot3, and maximum values at exact common-clock times."""

    contract = _contract(
        _read_regular(contract_path, MAX_CONTRACT_BYTES, "capture contract")
    )
    rows = _rows(
        _read_regular(blocks_path, MAX_BLOCK_BYTES, "capture blocks"), contract
    )
    rails = {
        channel: [row for row in rows if row["channel"] == channel]
        for channel in RAIL_CHANNELS
    }
    samples: list[tuple[int, int, int]] = []
    previous = -1
    for timestamp in timestamps_ns:
        if timestamp < previous:
            fail("rail lookup timestamps are not monotonic")
        previous = timestamp
        values: list[int] = []
        for channel in RAIL_CHANNELS:
            matches = [
                block
                for block in rails[channel]
                if block["start_ns"] <= timestamp < block["end_ns"]
            ]
            if len(matches) != 1:
                fail(f"rail lookup at {timestamp} ns is ambiguous for {channel}")
            block = matches[0]
            index = (timestamp - block["start_ns"]) // block["period_ns"]
            values.append(_rail_value_at(block, index))
        samples.append((values[0], values[1], max(values)))
    return str(contract["rail_signal"]), samples


def stage_receipt(evidence_dir: Path) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail("capture evidence directory must be a real directory")
    observed = {item.name for item in evidence_dir.iterdir()}
    inputs = {CONTRACT_NAME, BLOCKS_NAME}
    if observed not in (inputs, inputs | {RECEIPT_NAME}):
        fail(f"capture evidence file set is not exact: {sorted(observed)}")
    result = build_result(
        evidence_dir / CONTRACT_NAME, evidence_dir / BLOCKS_NAME
    )
    expected = canonical_json(result)
    destination = evidence_dir / RECEIPT_NAME
    if destination.exists():
        if _read_regular(destination, MAX_CONTRACT_BYTES, "capture receipt") != expected:
            fail("refusing to overwrite a stale capture receipt")
        return result
    with tempfile.NamedTemporaryFile(
        dir=evidence_dir,
        prefix=f".{RECEIPT_NAME}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(expected)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return result


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail("capture evidence directory must be a real directory")
    observed = {item.name for item in evidence_dir.iterdir()}
    expected_names = {CONTRACT_NAME, BLOCKS_NAME, RECEIPT_NAME}
    if observed != expected_names:
        fail(f"capture evidence file set is not exact: {sorted(observed)}")
    return verify_files(
        evidence_dir / CONTRACT_NAME,
        evidence_dir / BLOCKS_NAME,
        evidence_dir / RECEIPT_NAME,
    )


def verify_files(
    contract_path: Path, blocks_path: Path, receipt_path: Path
) -> dict[str, Any]:
    result = build_result(contract_path, blocks_path)
    receipt = _read_regular(receipt_path, MAX_CONTRACT_BYTES, "capture receipt")
    if receipt != canonical_json(result):
        fail("capture receipt is stale or noncanonical")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "verify"))
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence_dir = args.evidence_dir.resolve(strict=True)
        result = (
            stage_receipt(evidence_dir)
            if args.command == "stage"
            else verify_workflow_evidence(evidence_dir)
        )
    except (OSError, CaptureVerificationError) as error:
        print(f"S19K_PHASE12_CAPTURE_REFUSED: {error}", file=os.sys.stderr)
        return 1
    os.sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
