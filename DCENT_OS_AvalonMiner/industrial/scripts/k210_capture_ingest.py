#!/usr/bin/env python3
"""K210 controller<->ASIC digital-capture ingestion for the Avalon gauntlet.

This tool converts operator-exported Saleae digital CSV captures of the K210
MM3/MM4 controller-to-hashboard chain signals into one canonical, bounded,
logically digested ``.k210cap`` v1 artifact, and computes clock-recovery and
descriptive frame statistics from such artifacts. It is deliberately
host-only: it has no network, serial, USB, logic-analyzer, GPIO, flash,
programmer, or miner-contact code, and it contains no transmit path of any
kind.

Claim discipline (inherited from ``K210_AVALON_PROTOCOL_EVIDENCE_AUDIT.md``
and the 2026-08-23 wire-contract asset census): the K210 controller<->ASIC
wire contract is UNKNOWN. This tool asserts no frame format, no opcode, no
register map, and no "discovered protocol". Clock-rate references to 4 MHz
(CK) and 6.097 MHz (C) are EXPECTED values from documentary evidence
(ZeusBTC A11/A12 repair-guide pin table via census section 6, fact 5),
printed for comparison only. Signal direction tags come from the same
documentary pin table (CI/DI/RI/CKI controller->board; CO/DO/RO/CKO
board->controller) and are probe-plan orientation facts, not a wire
contract. All identity/provenance fields are operator declarations recorded
NON-CRYPTOGRAPHICALLY; the file digest is integrity, not authentication. No
artifact produced or verified here authorizes contacting hardware,
transmitting, or admitting a codec; the gauntlet's ``asic_control`` stays
``not_implemented`` until the audit's named-revision admission rules are
satisfied by a separate process.

Format specification: ``gauntlet/K210_CAPTURE_ARTIFACT.md``.
"""

from __future__ import annotations

import argparse
import bisect
import csv as csv_module
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Format constants (.k210cap v1)
# ---------------------------------------------------------------------------

ARTIFACT_MAGIC = b"DK210CAP"
ARTIFACT_VERSION = 1
ARTIFACT_HEADER_LEN = 128
ARTIFACT_EVENT_LEN = 16
MAX_EVENTS = 262_144  # 2**18 hard bound, mirroring the n3cap discipline
MAX_PROVENANCE_BYTES = 4_096
MAX_CHANNEL_MAP_BYTES = 4_096
MAX_ARTIFACT_BYTES = (
    ARTIFACT_HEADER_LEN
    + MAX_PROVENANCE_BYTES
    + MAX_CHANNEL_MAP_BYTES
    + MAX_EVENTS * ARTIFACT_EVENT_LEN
)
MAX_CSV_BYTES = 256 * 1024 * 1024
MAX_TOTAL_OBSERVATIONS = 4_000_000
MAX_MAPPING_BYTES = 4 * 1024 * 1024
DIGEST_DOMAIN = b"DCENT-K210-DIGITAL-CAPTURE-V1\0"

OFFSET_MAGIC = 0
OFFSET_VERSION = 8
OFFSET_HEADER_LEN = 10
OFFSET_EVENT_COUNT = 12
OFFSET_PROVENANCE_LEN = 16
OFFSET_CHANNEL_MAP_LEN = 20
OFFSET_ENDED_PS = 24
OFFSET_SAMPLE_RATE = 32
OFFSET_SOURCE_COUNT = 40
OFFSET_SIGNAL_COUNT = 41
OFFSET_RESERVED2 = 42
OFFSET_DIGEST = 44
OFFSET_RESERVED_TAIL = 76

DIRECTION_CONTROLLER_TO_ASIC = "controller_to_asic"
DIRECTION_ASIC_TO_CONTROLLER = "asic_to_controller"

# Documentary chain-signal vocabulary (ZeusBTC A11/A12 pin table via census
# section 6, fact 4). Only these names may appear in an operator mapping.
# "TO" is deliberately absent: its direction is not documented, so mapping it
# would be an unsupported wire claim.
SIGNAL_DIRECTIONS: Dict[str, str] = {
    "CI": DIRECTION_CONTROLLER_TO_ASIC,
    "DI": DIRECTION_CONTROLLER_TO_ASIC,
    "RI": DIRECTION_CONTROLLER_TO_ASIC,
    "CKI": DIRECTION_CONTROLLER_TO_ASIC,
    "FBDI": DIRECTION_CONTROLLER_TO_ASIC,
    "CO": DIRECTION_ASIC_TO_CONTROLLER,
    "DO": DIRECTION_ASIC_TO_CONTROLLER,
    "RO": DIRECTION_ASIC_TO_CONTROLLER,
    "CKO": DIRECTION_ASIC_TO_CONTROLLER,
    "FBDO": DIRECTION_ASIC_TO_CONTROLLER,
}

TIME_COLUMN_CANDIDATES = ("time [s]", "time")
CAPTURE_STATES = ("safe_idle_detection", "bounded_work_exchange")
REQUIRED_PROVENANCE_FIELDS = (
    "asic_family",
    "authorization_reference",
    "capture_end_s",
    "capture_session_id",
    "capture_state",
    "controller_revision",
    "hashboard_revision",
    "model",
    "operator",
    "sample_rate_hz",
    "stock_firmware_build",
)
OPTIONAL_PROVENANCE_FIELDS = ("notes", "stock_aup_sha256", "unit_serial")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# Documentary clock rates (census section 6, fact 5): CK working clock 4 MHz,
# C transmission clock 6.097 MHz. EXPECTED values, not measurements.
DOCUMENTARY_EXPECTED_CLOCKS_HZ = (4_000_000, 6_097_000)
DOCUMENTARY_CLOCK_SOURCE = "zeusbtc_a11_a12_pin_table_via_census_s6_fact5"
DOCUMENTARY_MATCH_TOLERANCE = 0.02
CLOCK_DOMINANCE_SHARE = 0.80

# Census P1 instrument budget: >=50 MS/s for the 6.097 MHz transmission clock.
CENSUS_MIN_RECOMMENDED_RATE_HZ = 50_000_000

MAPPING_FORMAT = "k210-capture-map-v1"

USAGE_EPILOG = """\
examples:
  py -3 k210_capture_ingest.py ingest \\
      --map session-map.json --csv digital.csv --output capture.k210cap
  py -3 k210_capture_ingest.py stats --input capture.k210cap --clock-signal CKO
  py -3 k210_capture_ingest.py validate --input capture.k210cap
  py -3 k210_capture_ingest.py inventory --input capture.k210cap
  py -3 k210_capture_ingest.py extract --input capture.k210cap \\
      --first-event 0 --event-count 512 --output burst.k210cap

Every command is file-only and host-only. Outputs carry
DESCRIPTIVE-NOT-A-CONTRACT labels and never authorize a device, a transmit
path, or a codec admission.

Support open-source Bitcoin mining firmware through the D-Central fund:
https://d-central.tech/fund/
"""


class CaptureIngestError(RuntimeError):
    """A capture input, artifact, or claim-discipline invariant failed."""


# ---------------------------------------------------------------------------
# Strict decimal-seconds parser (mirrors the nano3-n3cap picosecond parser)
# ---------------------------------------------------------------------------


def _parse_seconds_to_ps(raw: str) -> int:
    """Parse one strict decimal-seconds string into integer picoseconds.

    Accepts an optional sign, one optional decimal point, and an optional
    base-10 exponent in -30..30. Values are rounded half-up to picoseconds.
    Anything else (empty, NaN, hex, double dots, double exponents, runaway
    scales) is refused.
    """

    text = raw.strip()
    if not text:
        raise CaptureIngestError("timestamp is empty")
    negative = False
    if text[0] in "+-":
        negative = text[0] == "-"
        text = text[1:]
    if not text:
        raise CaptureIngestError(f"timestamp {raw!r} has no mantissa")
    pieces = re.split(r"[eE]", text)
    if len(pieces) > 2:
        raise CaptureIngestError(f"timestamp {raw!r} has multiple exponent markers")
    exponent = 0
    if len(pieces) == 2:
        if not re.fullmatch(r"[+-]?[0-9]+", pieces[1]):
            raise CaptureIngestError(f"timestamp {raw!r} has an invalid exponent")
        exponent = int(pieces[1])
    if not -30 <= exponent <= 30:
        raise CaptureIngestError(f"timestamp {raw!r} exponent is outside -30..30")
    mantissa = pieces[0]
    if mantissa.count(".") > 1:
        raise CaptureIngestError(f"timestamp {raw!r} has multiple decimal points")
    if len(mantissa) > 40:
        raise CaptureIngestError(f"timestamp {raw!r} mantissa is too large")
    saw_digit = False
    fractional_digits = 0
    saw_decimal = False
    coefficient = 0
    for character in mantissa:
        if character.isdigit():
            saw_digit = True
            coefficient = coefficient * 10 + int(character)
            if saw_decimal:
                fractional_digits += 1
        elif character == ".":
            saw_decimal = True
        else:
            raise CaptureIngestError(
                f"timestamp {raw!r} must contain only decimal digits and one dot"
            )
    if not saw_digit:
        raise CaptureIngestError(f"timestamp {raw!r} has no digits")
    power = 12 + exponent - fractional_digits
    if power >= 0:
        magnitude = coefficient * (10**power)
    else:
        divisor = 10 ** (-power)
        quotient, remainder = divmod(coefficient, divisor)
        magnitude = quotient + (1 if remainder * 2 >= divisor else 0)
    if magnitude > 10**30:
        raise CaptureIngestError(f"timestamp {raw!r} is too large")
    return -magnitude if negative else magnitude


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _no_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureIngestError(f"JSON object has duplicate key {key!r}")
        result[key] = value
    return result


def _loads_strict(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except CaptureIngestError:
        raise
    except ValueError as exc:
        raise CaptureIngestError(f"invalid JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Path safety (mirrors nano3-n3cap: device names, symlinks, create-new)
# ---------------------------------------------------------------------------


def _reject_windows_device_path(path: Path, role: str) -> None:
    display = str(path)
    normalized = display.replace("/", "\\")
    if (
        normalized.startswith("\\\\.\\")
        or normalized.startswith("\\\\?\\")
        or normalized.startswith("\\??\\")
    ):
        raise CaptureIngestError(
            f"{role} path uses a Windows device namespace: {path}"
        )
    for component in path.parts:
        trimmed = component.rstrip(" .")
        stem = trimmed.split(".")[0].upper()
        reserved = (
            stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
            or re.fullmatch(r"COM[1-9]", stem) is not None
            or re.fullmatch(r"LPT[1-9]", stem) is not None
        )
        if reserved:
            raise CaptureIngestError(
                f"{role} path uses a Windows device namespace or reserved "
                f"device name: {path}"
            )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _file_identity(metadata: os.stat_result) -> Tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _reject_symlink_or_nonregular(path: Path, role: str) -> int:
    _reject_windows_device_path(path, role)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CaptureIngestError(f"cannot inspect {role} {path}: {exc}") from exc
    if _is_link_or_reparse(metadata):
        raise CaptureIngestError(f"{role} must not be a link/reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise CaptureIngestError(f"{role} is not a regular file: {path}")
    return metadata.st_size


def _require_extension(path: Path, extension: str, role: str) -> None:
    if path.suffix.lower() != "." + extension.lower():
        raise CaptureIngestError(f"{role} path must end in .{extension}: {path}")


def _read_bounded_regular_file(path: Path, role: str, maximum: int) -> bytes:
    observed = _reject_symlink_or_nonregular(path, role)
    if observed > maximum:
        raise CaptureIngestError(
            f"{role} exceeds the {maximum}-byte offline input limit: {observed} bytes"
        )
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if opened.st_size != observed:
                raise CaptureIngestError(f"{role} changed before it was opened")
            data = stream.read(maximum + 1)
            final = os.fstat(stream.fileno())
    except OSError as exc:
        raise CaptureIngestError(f"cannot read {role} {path}: {exc}") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise CaptureIngestError(f"cannot reinspect {role} {path}: {exc}") from exc
    if (
        len(data) > maximum
        or len(data) != opened.st_size
        or _file_identity(opened) != _file_identity(final)
        or _file_identity(final) != _file_identity(after)
        or _is_link_or_reparse(after)
    ):
        raise CaptureIngestError(f"{role} changed while being read: {path}")
    return data


def _hash_regular_file(path: Path, role: str) -> str:
    return hashlib.sha256(
        _read_bounded_regular_file(path, role, MAX_CSV_BYTES)
    ).hexdigest()


def _prepare_output(path: Path) -> None:
    _reject_windows_device_path(path, "output")
    if path.exists() or path.is_symlink():
        raise CaptureIngestError(
            f"output already exists; refusing to overwrite: {path}"
        )
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        raise CaptureIngestError(f"output parent is not a directory: {parent}")


def _write_create_new(path: Path, data: bytes) -> None:
    try:
        handle = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o644,
        )
    except FileExistsError as exc:
        raise CaptureIngestError(
            f"output already exists; refusing to overwrite: {path}"
        ) from exc
    except OSError as exc:
        raise CaptureIngestError(f"cannot create output {path}: {exc}") from exc
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(handle, data[offset : offset + 1024 * 1024])
        os.fsync(handle)
    except OSError as exc:
        raise CaptureIngestError(f"cannot write output {path}: {exc}") from exc
    finally:
        os.close(handle)


# ---------------------------------------------------------------------------
# Operator mapping file and provenance validation
# ---------------------------------------------------------------------------


def _require_ascii(
    value: Any, field: str, maximum: int, allow_empty: bool = False
) -> str:
    if not isinstance(value, str):
        raise CaptureIngestError(f"provenance field {field!r} must be a string")
    if not value and not allow_empty:
        raise CaptureIngestError(f"provenance field {field!r} must not be empty")
    if len(value) > maximum:
        raise CaptureIngestError(
            f"provenance field {field!r} exceeds {maximum} characters"
        )
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CaptureIngestError(
            f"provenance field {field!r} must be ASCII"
        ) from exc
    if not allow_empty and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise CaptureIngestError(
            f"provenance field {field!r} must not contain control characters"
        )
    return value


def _validate_provenance(provenance: Any) -> Dict[str, Any]:
    if not isinstance(provenance, dict):
        raise CaptureIngestError("provenance must be a JSON object")
    unknown = sorted(
        set(provenance)
        - set(REQUIRED_PROVENANCE_FIELDS)
        - set(OPTIONAL_PROVENANCE_FIELDS)
    )
    if unknown:
        raise CaptureIngestError(f"provenance has unknown field(s): {unknown}")
    missing = sorted(set(REQUIRED_PROVENANCE_FIELDS) - set(provenance))
    if missing:
        raise CaptureIngestError(
            f"provenance is missing required field(s): {missing}"
        )

    for field, limit in (
        ("capture_session_id", 128),
        ("operator", 128),
        ("authorization_reference", 256),
        ("model", 64),
        ("controller_revision", 64),
        ("hashboard_revision", 64),
        ("asic_family", 64),
        ("stock_firmware_build", 64),
        ("unit_serial", 128),
    ):
        if field in provenance:
            _require_ascii(provenance[field], field, limit)

    state = provenance["capture_state"]
    if state not in CAPTURE_STATES:
        raise CaptureIngestError(
            f"provenance capture_state must be one of {sorted(CAPTURE_STATES)}, "
            f"got {state!r}"
        )

    rate = provenance["sample_rate_hz"]
    if isinstance(rate, bool) or not isinstance(rate, int):
        raise CaptureIngestError("provenance sample_rate_hz must be an integer")
    if not 1 <= rate <= 10**12:
        raise CaptureIngestError(
            "provenance sample_rate_hz must be in 1..10^12"
        )

    end_raw = provenance["capture_end_s"]
    if not isinstance(end_raw, str):
        raise CaptureIngestError(
            "provenance capture_end_s must be a decimal string"
        )
    _parse_seconds_to_ps(end_raw)  # validate shape; the value is used later

    if "stock_aup_sha256" in provenance:
        pinned = provenance["stock_aup_sha256"]
        if not isinstance(pinned, str) or not HEX64_RE.fullmatch(pinned):
            raise CaptureIngestError(
                "provenance stock_aup_sha256 must be 64 lowercase hex characters"
            )
    if "notes" in provenance:
        _require_ascii(provenance["notes"], "notes", 512, allow_empty=True)

    canonical = _canonical_json(provenance)
    if len(canonical) > MAX_PROVENANCE_BYTES:
        raise CaptureIngestError(
            f"canonical provenance block exceeds {MAX_PROVENANCE_BYTES} bytes"
        )
    return provenance


def _load_mapping(path: Path) -> Tuple[Dict[str, int], Dict[str, Any]]:
    _reject_windows_device_path(path, "channel map")
    _require_extension(path, "json", "channel map")
    data = _read_bounded_regular_file(path, "channel map", MAX_MAPPING_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CaptureIngestError(f"channel map {path} is not UTF-8") from exc
    document = _loads_strict(text)
    if not isinstance(document, dict):
        raise CaptureIngestError(f"channel map {path} must be a JSON object")
    expected_keys = {"format", "channels", "provenance"}
    unknown = sorted(set(document) - expected_keys)
    missing = sorted(expected_keys - set(document))
    if unknown or missing:
        raise CaptureIngestError(
            f"channel map must contain exactly {sorted(expected_keys)}; "
            f"unknown={unknown} missing={missing}"
        )
    if document["format"] != MAPPING_FORMAT:
        raise CaptureIngestError(
            f"channel map format must be {MAPPING_FORMAT!r}, "
            f"got {document['format']!r}"
        )
    channels = document["channels"]
    if not isinstance(channels, dict) or not channels:
        raise CaptureIngestError(
            "channel map 'channels' must be a non-empty object"
        )
    normalized: Dict[str, int] = {}
    seen_channels: Dict[int, str] = {}
    for name, channel in channels.items():
        if name not in SIGNAL_DIRECTIONS:
            raise CaptureIngestError(
                f"channel map signal {name!r} is not in the documented K210 "
                f"chain vocabulary {sorted(SIGNAL_DIRECTIONS)}"
            )
        if isinstance(channel, bool) or not isinstance(channel, int) or channel < 0:
            raise CaptureIngestError(
                f"channel for signal {name!r} must be a non-negative integer"
            )
        if channel in seen_channels:
            raise CaptureIngestError(
                f"signals {seen_channels[channel]!r} and {name!r} are both "
                f"mapped to channel {channel}; the mapping is ambiguous"
            )
        seen_channels[channel] = name
        normalized[name] = channel
    provenance = _validate_provenance(document["provenance"])
    return normalized, provenance


# ---------------------------------------------------------------------------
# Saleae digital CSV parsing
# ---------------------------------------------------------------------------


def _normalize_header_cell(cell: str) -> str:
    return " ".join(cell.split()).lower()


class DigitalCsvTrack:
    """Per-signal explicit observations from one CSV export."""

    def __init__(self, name: str, channel: int) -> None:
        self.name = name
        self.channel = channel
        self.observations: List[Tuple[int, int]] = []


def _decode_csv_text(data: bytes, path: Path, role: str) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CaptureIngestError(f"{role} {path} is not UTF-8") from exc


def _csv_header(data: bytes, path: Path, role: str) -> List[str]:
    text = _decode_csv_text(data, path, role)
    reader = csv_module.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration:
        raise CaptureIngestError(f"{role} {path} is empty") from None
    if not header or not any(cell.strip() for cell in header):
        raise CaptureIngestError(f"{role} {path} has no header row")
    return [_normalize_header_cell(cell) for cell in header]


def _parse_digital_csv(
    data: bytes, path: Path, role: str, wanted: Mapping[str, int]
) -> List[DigitalCsvTrack]:
    """Parse one Saleae digital CSV export for the wanted signals.

    Returns per-signal observation lists (the first sample row included).
    Refuses missing or ambiguous time columns, missing channel columns,
    corrupt rows, non-binary cell values, backward time, and a first row
    that does not explicitly establish every wanted signal's initial level.
    """

    header = _csv_header(data, path, role)
    time_matches = [
        i for i, cell in enumerate(header) if cell in TIME_COLUMN_CANDIDATES
    ]
    if not time_matches:
        raise CaptureIngestError(
            f"{role} {path} has no supported time column "
            f"{list(TIME_COLUMN_CANDIDATES)}; headers={header!r}"
        )
    if len(time_matches) > 1:
        raise CaptureIngestError(
            f"{role} {path} has ambiguous time columns at {time_matches}"
        )
    time_index = time_matches[0]

    tracks: List[DigitalCsvTrack] = []
    column_of_track: List[int] = []
    for name in sorted(wanted):
        column_name = f"channel {wanted[name]}"
        matches = [i for i, cell in enumerate(header) if cell == column_name]
        if len(matches) > 1:
            raise CaptureIngestError(
                f"{role} {path} has ambiguous {column_name!r} columns at {matches}"
            )
        if not matches:
            raise CaptureIngestError(
                f"{role} {path} has no {column_name!r} column for signal {name!r}"
            )
        tracks.append(DigitalCsvTrack(name, wanted[name]))
        column_of_track.append(matches[0])
    if not tracks:
        raise CaptureIngestError(
            f"{role} {path} carries none of the mapped signals; refusing the input"
        )

    text = _decode_csv_text(data, path, role)
    reader = csv_module.reader(io.StringIO(text, newline=""))
    next(reader)  # header, validated above

    previous_ps: Optional[int] = None
    total_observations = 0
    for row_number, row in enumerate(reader, start=2):
        if not row or not any(cell.strip() for cell in row):
            continue  # tolerate blank lines
        if len(row) != len(header):
            raise CaptureIngestError(
                f"{role} {path} row {row_number} has {len(row)} fields, "
                f"expected {len(header)}"
            )
        time_raw = row[time_index].strip()
        if not time_raw:
            raise CaptureIngestError(
                f"{role} {path} row {row_number} has an empty time field"
            )
        try:
            row_ps = _parse_seconds_to_ps(time_raw)
        except CaptureIngestError as exc:
            raise CaptureIngestError(
                f"{role} {path} row {row_number}: {exc}"
            ) from exc
        if previous_ps is not None and row_ps < previous_ps:
            raise CaptureIngestError(
                f"{role} {path} row {row_number} moves backward in time: "
                f"{previous_ps} -> {row_ps} ps"
            )
        is_first_row = previous_ps is None
        for track, column in zip(tracks, column_of_track):
            cell = row[column].strip()
            if cell == "":
                if is_first_row:
                    raise CaptureIngestError(
                        f"{role} {path} row {row_number} does not explicitly "
                        f"establish the initial level of signal {track.name!r}"
                    )
                continue  # carry-forward: no new information this row
            if cell not in ("0", "1"):
                raise CaptureIngestError(
                    f"{role} {path} row {row_number} signal {track.name!r} has "
                    f"non-binary value {cell!r}"
                )
            track.observations.append((row_ps, int(cell)))
            total_observations += 1
            if total_observations > MAX_TOTAL_OBSERVATIONS:
                raise CaptureIngestError(
                    f"{role} {path} exceeds the {MAX_TOTAL_OBSERVATIONS}-observation "
                    f"offline bound"
                )
        previous_ps = row_ps

    if previous_ps is None:
        raise CaptureIngestError(f"{role} {path} contains no sample rows")
    for track in tracks:
        if not track.observations:
            raise CaptureIngestError(
                f"{role} {path} never observes signal {track.name!r}"
            )
    return tracks


# ---------------------------------------------------------------------------
# Normalization: monotonic edge lists and the merged directed event stream
# ---------------------------------------------------------------------------


def _edges_from_track(track: DigitalCsvTrack) -> Tuple[int, int, List[Tuple[int, int]]]:
    """Reduce one observation track to (initial_ps, initial_level, edges).

    Edges are actual level changes only; restatements of the current level
    are dropped. An edge at or before the previous reference time is refused
    (two flips inside one timestamp cannot be ordered).
    """

    initial_ps, initial_level = track.observations[0]
    current = initial_level
    reference_ps = initial_ps
    edges: List[Tuple[int, int]] = []
    for ps, level in track.observations[1:]:
        if level == current:
            continue
        if ps <= reference_ps:
            raise CaptureIngestError(
                f"signal {track.name!r} changes level twice at or before "
                f"{reference_ps} ps; the edge order is not resolvable"
            )
        edges.append((ps, level))
        current = level
        reference_ps = ps
    return initial_ps, initial_level, edges


class NormalizedCapture:
    """Merged, bounded, directed edge stream plus per-signal initial levels."""

    def __init__(
        self,
        signals: List[Dict[str, Any]],
        events: List[Tuple[int, int, int]],
        ended_ps: int,
        origin_ps: int,
        source_count: int,
        sample_rate_hz: int,
    ) -> None:
        self.signals = signals
        self.events = events  # (elapsed_ps, signal_index, level), canonical
        self.ended_ps = ended_ps
        self.origin_ps = origin_ps
        self.source_count = source_count
        self.sample_rate_hz = sample_rate_hz


def _merge_and_normalize(
    tracks: Sequence[DigitalCsvTrack],
    capture_end_ps: int,
    sample_rate_hz: int,
    source_count: int,
) -> NormalizedCapture:
    """Merge per-CSV tracks into the canonical directed event stream.

    Events are ordered by (elapsed_ps, signal_index). An exact-timestamp
    collision between a controller->asic edge and an asic->controller edge
    is refused: the instrument could not resolve their causal order, and
    this tool refuses to fabricate one (mirroring the n3cap cross-direction
    tie refusal). Same-direction simultaneity within one sample is
    preserved and canonically ordered by signal index.
    """

    specs = [_edges_from_track(track) for track in tracks]
    origin_ps = min(spec[0] for spec in specs)

    signal_specs = [
        (track.name, SIGNAL_DIRECTIONS[track.name], spec)
        for track, spec in zip(tracks, specs)
    ]
    signal_specs.sort(key=lambda item: item[0])  # deterministic index order

    raw_events: List[Tuple[int, int, int, str]] = []
    for index, (name, direction, (_initial_ps, _initial_level, edges)) in enumerate(
        signal_specs
    ):
        for ps, level in edges:
            raw_events.append((ps - origin_ps, index, level, direction))
    raw_events.sort(key=lambda event: (event[0], event[1]))

    if len(raw_events) > MAX_EVENTS:
        raise CaptureIngestError(
            f"capture contains {len(raw_events)} directed edges, above the "
            f"{MAX_EVENTS}-event canonical bound"
        )

    tie_index = 0
    while tie_index < len(raw_events):
        group_ps = raw_events[tie_index][0]
        directions: set = set()
        names: List[str] = []
        scan = tie_index
        while scan < len(raw_events) and raw_events[scan][0] == group_ps:
            directions.add(raw_events[scan][3])
            names.append(signal_specs[raw_events[scan][1]][0])
            scan += 1
        if len(directions) > 1:
            raise CaptureIngestError(
                f"cross-direction edge order is ambiguous at {group_ps} ps "
                f"(signals {sorted(names)}); the sample could not resolve "
                f"controller->asic versus asic->controller order"
            )
        tie_index = scan

    ended_ps = capture_end_ps - origin_ps
    if ended_ps < 0:
        raise CaptureIngestError(
            f"capture end {capture_end_ps} ps precedes the first observation at "
            f"{origin_ps} ps"
        )
    last_event_ps = raw_events[-1][0] if raw_events else 0
    if ended_ps < last_event_ps:
        raise CaptureIngestError(
            f"capture end {ended_ps} ps (elapsed) precedes the final edge at "
            f"{last_event_ps} ps"
        )
    for _name, _direction, (initial_ps, _initial_level, _edges) in signal_specs:
        if initial_ps - origin_ps > ended_ps:
            raise CaptureIngestError(
                "capture end precedes a signal's first observation"
            )

    signals = [
        {
            "direction": direction,
            "index": index,
            "initial_level": initial_level,
            "initial_observed_ps": initial_ps - origin_ps,
            "name": name,
        }
        for index, (name, direction, (initial_ps, initial_level, _edges)) in enumerate(
            signal_specs
        )
    ]
    events = [(ps, index, level) for ps, index, level, _direction in raw_events]
    return NormalizedCapture(
        signals, events, ended_ps, origin_ps, source_count, sample_rate_hz
    )


# ---------------------------------------------------------------------------
# Canonical artifact encode / decode
# ---------------------------------------------------------------------------


def _channel_map_bytes(signals: Sequence[Mapping[str, Any]]) -> bytes:
    payload = {"signals": [dict(signal) for signal in signals]}
    encoded = _canonical_json(payload)
    if len(encoded) > MAX_CHANNEL_MAP_BYTES:
        raise CaptureIngestError(
            f"canonical channel map exceeds {MAX_CHANNEL_MAP_BYTES} bytes"
        )
    return encoded


def _logical_digest(
    event_count: int,
    signal_count: int,
    ended_ps: int,
    provenance_bytes: bytes,
    channel_map: bytes,
    events: Sequence[Tuple[int, int, int]],
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(DIGEST_DOMAIN)
    hasher.update(
        struct.pack("<HIQB", ARTIFACT_VERSION, event_count, ended_ps, signal_count)
    )
    hasher.update(struct.pack("<I", len(provenance_bytes)))
    hasher.update(provenance_bytes)
    hasher.update(struct.pack("<I", len(channel_map)))
    hasher.update(channel_map)
    for elapsed_ps, signal_index, level in events:
        hasher.update(struct.pack("<QBB", elapsed_ps, signal_index, level))
    return hasher.digest()


class DecodedArtifact:
    """A strictly decoded ``.k210cap`` v1 artifact."""

    def __init__(
        self,
        provenance: Dict[str, Any],
        provenance_bytes: bytes,
        signals: List[Dict[str, Any]],
        events: List[Tuple[int, int, int]],
        ended_ps: int,
        sample_rate_hz: int,
        source_count: int,
        digest: bytes,
    ) -> None:
        self.provenance = provenance
        self.provenance_bytes = provenance_bytes
        self.signals = signals
        self.events = events
        self.ended_ps = ended_ps
        self.sample_rate_hz = sample_rate_hz
        self.source_count = source_count
        self.digest = digest

    def signal_names(self) -> List[str]:
        return [signal["name"] for signal in self.signals]


def encode_artifact(
    provenance: Mapping[str, Any], normalized: NormalizedCapture
) -> bytes:
    provenance_bytes = _canonical_json(provenance)
    if len(provenance_bytes) > MAX_PROVENANCE_BYTES:
        raise CaptureIngestError("canonical provenance block exceeds bound")
    channel_map = _channel_map_bytes(normalized.signals)
    digest = _logical_digest(
        len(normalized.events),
        len(normalized.signals),
        normalized.ended_ps,
        provenance_bytes,
        channel_map,
        normalized.events,
    )
    header = bytearray(ARTIFACT_HEADER_LEN)
    struct.pack_into("<8s", header, OFFSET_MAGIC, ARTIFACT_MAGIC)
    struct.pack_into("<H", header, OFFSET_VERSION, ARTIFACT_VERSION)
    struct.pack_into("<H", header, OFFSET_HEADER_LEN, ARTIFACT_HEADER_LEN)
    struct.pack_into("<I", header, OFFSET_EVENT_COUNT, len(normalized.events))
    struct.pack_into("<I", header, OFFSET_PROVENANCE_LEN, len(provenance_bytes))
    struct.pack_into("<I", header, OFFSET_CHANNEL_MAP_LEN, len(channel_map))
    struct.pack_into("<Q", header, OFFSET_ENDED_PS, normalized.ended_ps)
    struct.pack_into("<Q", header, OFFSET_SAMPLE_RATE, normalized.sample_rate_hz)
    header[OFFSET_SOURCE_COUNT] = normalized.source_count
    header[OFFSET_SIGNAL_COUNT] = len(normalized.signals)
    struct.pack_into("<H", header, OFFSET_RESERVED2, 0)
    header[OFFSET_DIGEST : OFFSET_DIGEST + 32] = digest

    body = bytearray()
    body += provenance_bytes
    body += channel_map
    for elapsed_ps, signal_index, level in normalized.events:
        body += struct.pack("<QBB", elapsed_ps, signal_index, level)
        body += b"\x00" * 6
    artifact = bytes(header) + bytes(body)
    if len(artifact) > MAX_ARTIFACT_BYTES:
        raise CaptureIngestError("encoded artifact exceeds canonical bound")
    return artifact


def decode_artifact(data: bytes) -> DecodedArtifact:
    """Strictly decode and re-verify one ``.k210cap`` v1 artifact.

    Refuses bad magic, unsupported versions, non-canonical header lengths,
    bound violations, nonzero reserved bytes, non-canonical JSON, schema
    drift, non-alternating or backward per-signal edges, cross-direction
    timestamp ties, non-canonical event ordering, truncation, trailing
    bytes, and any logical digest mismatch.
    """

    if len(data) < ARTIFACT_HEADER_LEN:
        raise CaptureIngestError(
            f"artifact has {len(data)} bytes, below header size {ARTIFACT_HEADER_LEN}"
        )
    if len(data) > MAX_ARTIFACT_BYTES:
        raise CaptureIngestError(
            f"artifact has {len(data)} bytes, above limit {MAX_ARTIFACT_BYTES}"
        )
    if data[OFFSET_MAGIC : OFFSET_MAGIC + 8] != ARTIFACT_MAGIC:
        raise CaptureIngestError(
            f"artifact magic is {data[OFFSET_MAGIC : OFFSET_MAGIC + 8]!r}, "
            f"expected {ARTIFACT_MAGIC!r}"
        )
    version = struct.unpack_from("<H", data, OFFSET_VERSION)[0]
    if version != ARTIFACT_VERSION:
        raise CaptureIngestError(f"unsupported artifact version {version}")
    header_len = struct.unpack_from("<H", data, OFFSET_HEADER_LEN)[0]
    if header_len != ARTIFACT_HEADER_LEN:
        raise CaptureIngestError(
            f"artifact header length {header_len} is not canonical "
            f"{ARTIFACT_HEADER_LEN}"
        )
    event_count = struct.unpack_from("<I", data, OFFSET_EVENT_COUNT)[0]
    provenance_len = struct.unpack_from("<I", data, OFFSET_PROVENANCE_LEN)[0]
    channel_map_len = struct.unpack_from("<I", data, OFFSET_CHANNEL_MAP_LEN)[0]
    ended_ps = struct.unpack_from("<Q", data, OFFSET_ENDED_PS)[0]
    sample_rate_hz = struct.unpack_from("<Q", data, OFFSET_SAMPLE_RATE)[0]
    source_count = data[OFFSET_SOURCE_COUNT]
    signal_count = data[OFFSET_SIGNAL_COUNT]
    declared_digest = data[OFFSET_DIGEST : OFFSET_DIGEST + 32]
    if struct.unpack_from("<H", data, OFFSET_RESERVED2)[0] != 0:
        raise CaptureIngestError("artifact header reserved bytes are nonzero")
    if any(byte != 0 for byte in data[OFFSET_RESERVED_TAIL:ARTIFACT_HEADER_LEN]):
        raise CaptureIngestError("artifact header reserved tail is nonzero")
    if event_count > MAX_EVENTS:
        raise CaptureIngestError(
            f"artifact declares {event_count} events, above limit {MAX_EVENTS}"
        )
    if not 1 <= provenance_len <= MAX_PROVENANCE_BYTES:
        raise CaptureIngestError(
            f"artifact provenance length {provenance_len} is invalid"
        )
    if not 1 <= channel_map_len <= MAX_CHANNEL_MAP_BYTES:
        raise CaptureIngestError(
            f"artifact channel map length {channel_map_len} is invalid"
        )
    if source_count not in (1, 2):
        raise CaptureIngestError(f"artifact source count {source_count} is invalid")
    if not 1 <= sample_rate_hz <= 10**12:
        raise CaptureIngestError("artifact sample rate is invalid")
    expected_len = (
        ARTIFACT_HEADER_LEN
        + provenance_len
        + channel_map_len
        + event_count * ARTIFACT_EVENT_LEN
    )
    if len(data) != expected_len:
        raise CaptureIngestError(
            f"artifact length {len(data)} does not match its declared layout "
            f"({expected_len} bytes)"
        )

    cursor = ARTIFACT_HEADER_LEN
    provenance_bytes = data[cursor : cursor + provenance_len]
    cursor += provenance_len
    channel_map = data[cursor : cursor + channel_map_len]
    cursor += channel_map_len

    try:
        provenance_text = provenance_bytes.decode("ascii")
        channel_map_text = channel_map.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CaptureIngestError("artifact JSON blocks are not ASCII") from exc
    provenance = _loads_strict(provenance_text)
    _validate_provenance(provenance)
    if _canonical_json(provenance) != provenance_bytes:
        raise CaptureIngestError("artifact provenance JSON is not canonical")
    map_document = _loads_strict(channel_map_text)
    if not isinstance(map_document, dict) or set(map_document) != {"signals"}:
        raise CaptureIngestError(
            "artifact channel map must be an object with only 'signals'"
        )
    signals_raw = map_document["signals"]
    if not isinstance(signals_raw, list) or not signals_raw:
        raise CaptureIngestError("artifact channel map has no signals")
    if len(signals_raw) != signal_count:
        raise CaptureIngestError(
            "artifact signal count field does not match the map"
        )
    expected_signal_keys = {
        "direction",
        "index",
        "initial_level",
        "initial_observed_ps",
        "name",
    }
    signals: List[Dict[str, Any]] = []
    for position, signal in enumerate(signals_raw):
        if not isinstance(signal, dict) or set(signal) != expected_signal_keys:
            raise CaptureIngestError(
                f"artifact channel map signal {position} has non-canonical fields"
            )
        if signal["index"] != position:
            raise CaptureIngestError(
                f"artifact channel map signal {position} has index {signal['index']}"
            )
        name = signal["name"]
        if name not in SIGNAL_DIRECTIONS:
            raise CaptureIngestError(
                f"artifact channel map signal {name!r} is outside the "
                f"documented vocabulary"
            )
        if signal["direction"] != SIGNAL_DIRECTIONS[name]:
            raise CaptureIngestError(
                f"artifact channel map direction for {name!r} contradicts the "
                f"documentary pin table"
            )
        if signal["initial_level"] not in (0, 1):
            raise CaptureIngestError(
                f"artifact initial level for {name!r} is invalid"
            )
        observed = signal["initial_observed_ps"]
        if (
            isinstance(observed, bool)
            or not isinstance(observed, int)
            or not 0 <= observed <= ended_ps
        ):
            raise CaptureIngestError(
                f"artifact initial observation time for {name!r} is invalid"
            )
        signals.append(signal)
    if _canonical_json(map_document) != channel_map:
        raise CaptureIngestError("artifact channel map JSON is not canonical")

    events: List[Tuple[int, int, int]] = []
    last_level_by_signal: Dict[int, int] = {}
    last_ps_by_signal: Dict[int, int] = {}
    for event_index in range(event_count):
        record = data[cursor : cursor + ARTIFACT_EVENT_LEN]
        cursor += ARTIFACT_EVENT_LEN
        if record[10:] != b"\x00" * 6:
            raise CaptureIngestError(
                f"artifact event {event_index} reserved bytes are nonzero"
            )
        elapsed_ps, signal_index, level = struct.unpack_from("<QBB", record, 0)
        if signal_index >= signal_count:
            raise CaptureIngestError(
                f"artifact event {event_index} references unknown signal {signal_index}"
            )
        if level not in (0, 1):
            raise CaptureIngestError(
                f"artifact event {event_index} has invalid level"
            )
        if signal_index in last_ps_by_signal:
            if elapsed_ps <= last_ps_by_signal[signal_index]:
                raise CaptureIngestError(
                    f"artifact event {event_index} does not advance time for its signal"
                )
            if level == last_level_by_signal[signal_index]:
                raise CaptureIngestError(
                    f"artifact event {event_index} repeats the level of its signal; "
                    f"edges must alternate"
                )
        else:
            first_signal = signals[signal_index]
            if elapsed_ps <= first_signal["initial_observed_ps"]:
                raise CaptureIngestError(
                    f"artifact event {event_index} does not strictly follow its "
                    f"signal's initial observation"
                )
            if level == first_signal["initial_level"]:
                raise CaptureIngestError(
                    f"artifact event {event_index} repeats its signal's initial level"
                )
        if elapsed_ps > ended_ps:
            raise CaptureIngestError(
                f"artifact event {event_index} at {elapsed_ps} ps exceeds the "
                f"capture end {ended_ps} ps"
            )
        last_ps_by_signal[signal_index] = elapsed_ps
        last_level_by_signal[signal_index] = level
        events.append((elapsed_ps, signal_index, level))

    if events != sorted(events, key=lambda event: (event[0], event[1])):
        raise CaptureIngestError("artifact events are not in canonical order")

    cursor_group = 0
    while cursor_group < len(events):
        group_ps = events[cursor_group][0]
        directions = {
            signals[event[1]]["direction"]
            for event in events[cursor_group:]
            if event[0] == group_ps
        }
        if len(directions) > 1:
            raise CaptureIngestError(
                f"artifact contains a cross-direction tie at {group_ps} ps"
            )
        while cursor_group < len(events) and events[cursor_group][0] == group_ps:
            cursor_group += 1

    calculated = _logical_digest(
        event_count, signal_count, ended_ps, provenance_bytes, channel_map, events
    )
    if calculated != declared_digest:
        raise CaptureIngestError(
            "artifact logical digest mismatch: declared "
            f"{declared_digest.hex()}, calculated {calculated.hex()}"
        )
    return DecodedArtifact(
        provenance,
        provenance_bytes,
        signals,
        events,
        ended_ps,
        sample_rate_hz,
        source_count,
        calculated,
    )


def _read_artifact(path: Path) -> Tuple[bytes, str]:
    _reject_windows_device_path(path, "input artifact")
    _require_extension(path, "k210cap", "input artifact")
    data = _read_bounded_regular_file(path, "input artifact", MAX_ARTIFACT_BYTES)
    return data, hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Descriptive statistics (clock recovery, run lengths, bursts, byte alignment)
# ---------------------------------------------------------------------------


def _percentile(sorted_values: Sequence[int], fraction: float) -> Optional[int]:
    if not sorted_values:
        return None
    index = max(
        0, min(len(sorted_values) - 1, int(fraction * len(sorted_values) + 0.999999) - 1)
    )
    return sorted_values[index]


def _format_optional(value: Optional[int]) -> str:
    return "none" if value is None else str(value)


def _edge_lists(decoded: DecodedArtifact) -> Dict[str, Tuple[List[int], List[int]]]:
    """Per-signal (edge times, edge levels) in canonical order."""

    result: Dict[str, Tuple[List[int], List[int]]] = {
        signal["name"]: ([], []) for signal in decoded.signals
    }
    for elapsed_ps, signal_index, level in decoded.events:
        name = decoded.signals[signal_index]["name"]
        result[name][0].append(elapsed_ps)
        result[name][1].append(level)
    return result


def _level_at(
    edge_times: Sequence[int],
    edge_levels: Sequence[int],
    initial_level: int,
    when_ps: int,
) -> int:
    position = bisect.bisect_right(edge_times, when_ps)
    if position == 0:
        return initial_level
    return edge_levels[position - 1]


def _cluster_deltas(deltas: Sequence[int]) -> List[Tuple[int, int, float]]:
    """Greedy-cluster sorted edge gaps into (count, median, share) groups.

    A delta joins the current cluster while it stays within max(1000 ps,
    0.5% of the cluster's first member) of that first member. Deterministic
    and order-independent because clustering runs on the sorted delta list.
    """

    if not deltas:
        return []
    ordered = sorted(deltas)
    clusters: List[List[int]] = [[ordered[0]]]
    for delta in ordered[1:]:
        reference = clusters[-1][0]
        tolerance = max(1000, reference // 200)
        if delta - reference <= tolerance:
            clusters[-1].append(delta)
        else:
            clusters.append([delta])
    total = len(ordered)
    summarized = [
        (len(cluster), cluster[len(cluster) // 2], len(cluster) / total)
        for cluster in clusters
    ]
    summarized.sort(key=lambda item: (-item[0], item[1]))
    return summarized


def _signal_stats_lines(decoded: DecodedArtifact, burst_gap_ps: int) -> List[str]:
    lines: List[str] = []
    edges = _edge_lists(decoded)
    span_ps = decoded.ended_ps
    for signal in decoded.signals:
        name = signal["name"]
        times, _levels = edges[name]
        deltas = sorted(
            times[index + 1] - times[index] for index in range(len(times) - 1)
        )
        rate = (len(times) / span_ps * 1e12) if span_ps > 0 else 0.0
        lines.append(
            f"signal[{signal['index']}]=name:{name} "
            f"direction:{signal['direction']} edges:{len(times)} "
            f"edge_rate_hz:{rate:.3f} initial_level:{signal['initial_level']} "
            f"initial_observed_ps:{signal['initial_observed_ps']}"
        )
        lines.append(
            f"run_gap_ps[{name}]=min:{_format_optional(_percentile(deltas, 0.0))} "
            f"median:{_format_optional(_percentile(deltas, 0.5))} "
            f"p90:{_format_optional(_percentile(deltas, 0.9))} "
            f"max:{_format_optional(_percentile(deltas, 1.0))}"
        )
        clusters = _cluster_deltas(deltas)
        if clusters:
            count, median, share = clusters[0]
            periodic = share >= CLOCK_DOMINANCE_SHARE
            candidate_hz = 1e12 / (2 * median) if median > 0 else 0.0
            lines.append(
                f"clock_candidate[{name}]="
                f"periodic_dominant:{str(periodic).lower()} "
                f"median_edge_gap_ps:{median} "
                f"top_cluster_share:{share:.4f} "
                f"candidate_frequency_hz:{candidate_hz:.0f}"
            )
            for expected in DOCUMENTARY_EXPECTED_CLOCKS_HZ:
                if (
                    candidate_hz > 0
                    and abs(candidate_hz - expected) / expected
                    <= DOCUMENTARY_MATCH_TOLERANCE
                ):
                    lines.append(
                        f"documentary_match[{name}]=expected_hz:{expected} "
                        f"candidate_hz:{candidate_hz:.0f} "
                        f"relative_error:{abs(candidate_hz - expected) / expected:.5f}"
                    )
        else:
            lines.append(
                f"clock_candidate[{name}]=periodic_dominant:false "
                f"edges_below_two:true"
            )

        if len(times) >= 2:
            bursts: List[List[int]] = [[times[0]]]
            for index in range(1, len(times)):
                if times[index] - times[index - 1] >= burst_gap_ps:
                    bursts.append([times[index]])
                else:
                    bursts[-1].append(times[index])
            if len(bursts) >= 2:
                sizes = sorted(len(burst) for burst in bursts)
                gaps = sorted(
                    bursts[index + 1][0] - bursts[index][-1]
                    for index in range(len(bursts) - 1)
                )
                lines.append(
                    f"burst_summary[{name}]=bursts:{len(bursts)} "
                    f"burst_gap_threshold_ps:{burst_gap_ps} "
                    f"edges_per_burst_min:{sizes[0]} "
                    f"edges_per_burst_median:{_percentile(sizes, 0.5)} "
                    f"edges_per_burst_max:{sizes[-1]} "
                    f"inter_burst_gap_ps_min:{_percentile(gaps, 0.0)} "
                    f"inter_burst_gap_ps_median:{_percentile(gaps, 0.5)} "
                    f"inter_burst_gap_ps_p90:{_percentile(gaps, 0.9)} "
                    f"inter_burst_gap_ps_max:{_percentile(gaps, 1.0)}"
                )
            else:
                lines.append(
                    f"burst_summary[{name}]=bursts:1 "
                    f"burst_gap_threshold_ps:{burst_gap_ps}"
                )
    return lines


def _bytes_from_bits(bits: Sequence[int], msb_first: bool) -> List[int]:
    usable = len(bits) - (len(bits) % 8)
    result = []
    for start in range(0, usable, 8):
        byte = 0
        for offset in range(8):
            bit = bits[start + offset]
            byte |= bit << (7 - offset) if msb_first else bit << offset
        result.append(byte)
    return result


def _byte_alignment_lines(decoded: DecodedArtifact, clock_name: str) -> List[str]:
    edges = _edge_lists(decoded)
    if clock_name not in edges:
        raise CaptureIngestError(
            f"--clock-signal {clock_name!r} is not a signal in this artifact "
            f"({decoded.signal_names()})"
        )
    clock_times, clock_levels = edges[clock_name]
    lines: List[str] = []
    for polarity, label in ((1, "rising"), (0, "falling")):
        sample_times = [
            clock_times[index]
            for index in range(len(clock_times))
            if clock_levels[index] == polarity
        ]
        for signal in decoded.signals:
            if signal["name"] == clock_name:
                continue
            times, levels = edges[signal["name"]]
            bits = [
                _level_at(times, levels, signal["initial_level"], when)
                for when in sample_times
            ]
            for msb_first, order_label in ((True, "msb_first"), (False, "lsb_first")):
                for offset in range(8):
                    byte_values = _bytes_from_bits(bits[offset:], msb_first)
                    if not byte_values:
                        continue
                    histogram = Counter(byte_values)
                    top = sorted(
                        histogram.items(), key=lambda item: (-item[1], item[0])
                    )[:3]
                    top_text = ",".join(
                        f"0x{value:02x}:{count}" for value, count in top
                    )
                    lines.append(
                        f"byte_alignment[clock:{clock_name}]"
                        f"[data:{signal['name']}][edges:{label}]"
                        f"[order:{order_label}][offset:{offset}]= "
                        f"bytes:{len(byte_values)} distinct:{len(histogram)} "
                        f"top:{top_text}"
                    )
    if not lines:
        raise CaptureIngestError(
            f"--clock-signal {clock_name!r} provides no sampling edges for "
            f"alignment"
        )
    return lines


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _resolve_signal_sources(
    channels: Mapping[str, int],
    csv_data: Sequence[Tuple[Path, bytes]],
) -> Dict[Path, Dict[str, int]]:
    """Assign each mapped signal to exactly one CSV that carries its column."""

    headers = {
        path: _csv_header(data, path, "digital CSV") for path, data in csv_data
    }
    wanted_by_file: Dict[Path, Dict[str, int]] = {path: {} for path, _ in csv_data}
    for name in sorted(channels):
        column = f"channel {channels[name]}"
        hosting = [path for path, header in headers.items() if column in header]
        if not hosting:
            raise CaptureIngestError(
                f"no input CSV carries a {column!r} column for signal {name!r}"
            )
        if len(hosting) > 1:
            raise CaptureIngestError(
                f"signal {name!r} ({column!r}) appears in more than one input "
                f"CSV; the mapping is ambiguous"
            )
        wanted_by_file[hosting[0]][name] = channels[name]
    for path, wanted in wanted_by_file.items():
        if not wanted:
            raise CaptureIngestError(
                f"input CSV {path} carries none of the mapped signals"
            )
    return wanted_by_file


def cmd_ingest(args: argparse.Namespace) -> int:
    csv_paths = [Path(value) for value in args.csv]
    if not 1 <= len(csv_paths) <= 2:
        raise CaptureIngestError("ingest requires exactly one or two --csv inputs")
    normalized_paths = [
        os.path.normcase(os.path.abspath(str(path))) for path in csv_paths
    ]
    if len(set(normalized_paths)) != len(csv_paths):
        raise CaptureIngestError("the same CSV path was supplied more than once")
    for path in csv_paths:
        _reject_symlink_or_nonregular(path, "digital CSV")

    output = Path(args.output)
    _require_extension(output, "k210cap", "output artifact")
    _prepare_output(output)

    channels, provenance = _load_mapping(Path(args.map))

    csv_data: List[Tuple[Path, bytes]] = []
    for path in csv_paths:
        _require_extension(path, "csv", "digital CSV")
        csv_data.append(
            (path, _read_bounded_regular_file(path, "digital CSV", MAX_CSV_BYTES))
        )
    wanted_by_file = _resolve_signal_sources(channels, csv_data)

    tracks: List[DigitalCsvTrack] = []
    for path, data in csv_data:
        tracks.extend(
            _parse_digital_csv(data, path, "digital CSV", wanted_by_file[path])
        )

    capture_end_ps = _parse_seconds_to_ps(provenance["capture_end_s"])
    normalized = _merge_and_normalize(
        tracks, capture_end_ps, provenance["sample_rate_hz"], len(csv_data)
    )
    artifact = encode_artifact(provenance, normalized)
    decoded = decode_artifact(artifact)
    _write_create_new(output, artifact)
    artifact_sha256 = hashlib.sha256(artifact).hexdigest()

    forward = sum(
        1
        for event in decoded.events
        if decoded.signals[event[1]]["direction"] == DIRECTION_CONTROLLER_TO_ASIC
    )
    print(f"csv_count={len(csv_paths)}")
    for path, data in csv_data:
        print(f"csv_sha256[{path.name}]={hashlib.sha256(data).hexdigest()}")
    if args.source_capture is not None:
        source = Path(args.source_capture)
        _require_extension(source, "sal", "source capture")
        magic = _read_bounded_regular_file(source, "source capture", 4)
        if magic[:4] != b"PK\x03\x04":
            raise CaptureIngestError(
                f"source capture is not a Saleae .sal ZIP archive: {source}"
            )
        print(
            f"source_capture_sha256={_hash_regular_file(source, 'source capture')}"
        )
    print(f"artifact_sha256={artifact_sha256}")
    print(f"logical_digest={decoded.digest.hex()}")
    print(f"origin_ps={normalized.origin_ps}")
    print(f"ended_ps={decoded.ended_ps}")
    print(f"events={len(decoded.events)}")
    print(f"controller_to_asic_events={forward}")
    print(f"asic_to_controller_events={len(decoded.events) - forward}")
    for signal in decoded.signals:
        print(
            f"signal[{signal['index']}]=name:{signal['name']} "
            f"direction:{signal['direction']} "
            f"initial_level:{signal['initial_level']}"
        )
    if provenance["sample_rate_hz"] < CENSUS_MIN_RECOMMENDED_RATE_HZ:
        print(
            "warning=declared_sample_rate_below_census_budget "
            f"minimum_recommended_hz={CENSUS_MIN_RECOMMENDED_RATE_HZ}"
        )
    print("provenance_binding=operator_declared_non_cryptographic")
    print("wire_contract_claimed=false")
    print("authorizes_transmit=false")
    print("authorizes_device=false")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    data, artifact_sha256 = _read_artifact(Path(args.input))
    decoded = decode_artifact(data)
    forward = sum(
        1
        for event in decoded.events
        if decoded.signals[event[1]]["direction"] == DIRECTION_CONTROLLER_TO_ASIC
    )
    print(f"artifact_sha256={artifact_sha256}")
    print(f"logical_digest={decoded.digest.hex()}")
    print("digest_status=verified")
    print(f"format_version={ARTIFACT_VERSION}")
    print(f"source_count={decoded.source_count}")
    print(f"ended_ps={decoded.ended_ps}")
    print(f"events={len(decoded.events)}")
    print(f"controller_to_asic_events={forward}")
    print(f"asic_to_controller_events={len(decoded.events) - forward}")
    print(f"signals={len(decoded.signals)}")
    print(f"declared_sample_rate_hz={decoded.sample_rate_hz}")
    print(f"capture_state={decoded.provenance['capture_state']}")
    print("identity=operator_declared_non_cryptographic")
    print("file_digest_is_integrity_not_authentication=true")
    print("wire_contract_claimed=false")
    print("authorizes_transmit=false")
    print("authorizes_device=false")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    data, artifact_sha256 = _read_artifact(Path(args.input))
    decoded = decode_artifact(data)
    print(f"artifact_sha256={artifact_sha256}")
    print(f"logical_digest={decoded.digest.hex()}")
    print(f"ended_ps={decoded.ended_ps}")
    print(f"events={len(decoded.events)}")
    for signal in decoded.signals:
        print(
            f"signal[{signal['index']}]=name:{signal['name']} "
            f"direction:{signal['direction']} "
            f"initial_level:{signal['initial_level']} "
            f"initial_observed_ps:{signal['initial_observed_ps']}"
        )
    for index, (elapsed_ps, signal_index, level) in enumerate(decoded.events):
        signal = decoded.signals[signal_index]
        print(
            f"event[{index}]=elapsed_ps:{elapsed_ps} signal:{signal['name']} "
            f"direction:{signal['direction']} level:{level}"
        )
    print("provenance_binding=operator_declared_non_cryptographic")
    print("wire_contract_claimed=false")
    print("authorizes_transmit=false")
    print("authorizes_device=false")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output = Path(args.output)
    data, source_sha256 = _read_artifact(input_path)
    source = decode_artifact(data)
    _require_extension(output, "k210cap", "output artifact")
    _prepare_output(output)

    first_event = args.first_event
    event_count = args.event_count
    if event_count <= 0:
        raise CaptureIngestError("extract requires a positive --event-count")
    if first_event < 0:
        raise CaptureIngestError("--first-event must be a non-negative integer")
    available = len(source.events)
    if first_event >= available:
        raise CaptureIngestError(
            f"extract starts at event {first_event}, but only {available} event(s) exist"
        )
    end_exclusive = first_event + event_count
    if end_exclusive > available:
        raise CaptureIngestError(
            f"extract range first={first_event} count={event_count} exceeds "
            f"{available} event(s)"
        )

    selected = source.events[first_event:end_exclusive]
    # The source channel map records levels at the original capture origin.
    # An excerpt that begins later must instead encode the level immediately
    # before its first retained event; otherwise a signal whose earlier edge
    # was omitted can appear to repeat its initial level and the excerpt is not
    # self-consistent. Replay only the bounded prefix and preserve all other
    # signal metadata verbatim.
    excerpt_signals = [dict(signal) for signal in source.signals]
    levels_at_boundary = [signal["initial_level"] for signal in source.signals]
    for _elapsed_ps, signal_index, level in source.events[:first_event]:
        levels_at_boundary[signal_index] = level
    for signal_index, level in enumerate(levels_at_boundary):
        excerpt_signals[signal_index]["initial_level"] = level
    if end_exclusive == available:
        ended_ps = source.ended_ps
        boundary = "source-capture-end"
    else:
        last_selected_ps = selected[-1][0]
        next_ps = source.events[end_exclusive][0]
        if next_ps <= last_selected_ps:
            raise CaptureIngestError(
                f"extract cannot place an end boundary between event "
                f"{end_exclusive - 1} at {last_selected_ps} ps and event "
                f"{end_exclusive} at {next_ps} ps"
            )
        ended_ps = last_selected_ps
        boundary = "last-selected-event-no-post-event-silence"

    extracted_normalized = NormalizedCapture(
        excerpt_signals, selected, ended_ps, 0, source.source_count, source.sample_rate_hz
    )
    artifact = encode_artifact(source.provenance, extracted_normalized)
    extracted = decode_artifact(artifact)
    _write_create_new(output, artifact)
    print(f"source_artifact_sha256={source_sha256}")
    print(f"source_logical_digest={source.digest.hex()}")
    print(f"source_events={available}")
    print(f"first_event={first_event}")
    print(f"event_count={event_count}")
    print(f"source_end_exclusive={end_exclusive}")
    print(f"end_boundary={boundary}")
    if end_exclusive == available:
        print("next_source_event=none")
    else:
        print(f"next_source_event={end_exclusive}")
    print(f"output_artifact_sha256={hashlib.sha256(artifact).hexdigest()}")
    print(f"output_logical_digest={extracted.digest.hex()}")
    print(f"output_ended_ps={extracted.ended_ps}")
    print("provenance_binding=operator_declared_non_cryptographic")
    print("authorizes_transmit=false")
    print("authorizes_device=false")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    data, artifact_sha256 = _read_artifact(Path(args.input))
    decoded = decode_artifact(data)
    burst_raw = str(args.burst_gap_us)
    if not re.fullmatch(r"[0-9]+", burst_raw) or int(burst_raw) > 10**9:
        raise CaptureIngestError(
            "--burst-gap-us must be a non-negative integer of microseconds"
        )
    burst_gap_ps = int(burst_raw) * 1_000_000

    print("classification=DESCRIPTIVE-NOT-A-CONTRACT")
    print(f"artifact_sha256={artifact_sha256}")
    print(f"logical_digest={decoded.digest.hex()}")
    print(f"ended_ps={decoded.ended_ps}")
    print(f"declared_sample_rate_hz={decoded.sample_rate_hz}")
    print(f"capture_state={decoded.provenance['capture_state']}")
    print(
        "declared_identity=model:" + decoded.provenance["model"]
        + " controller_revision:" + decoded.provenance["controller_revision"]
        + " hashboard_revision:" + decoded.provenance["hashboard_revision"]
        + " asic_family:" + decoded.provenance["asic_family"]
        + " stock_firmware_build:" + decoded.provenance["stock_firmware_build"]
        + " (operator_declared_non_cryptographic)"
    )
    for line in _signal_stats_lines(decoded, burst_gap_ps):
        print(line)
    print(
        "documentary_expected_clocks_hz="
        + ",".join(str(value) for value in DOCUMENTARY_EXPECTED_CLOCKS_HZ)
    )
    print(f"documentary_expected_clocks_source={DOCUMENTARY_CLOCK_SOURCE}")
    if args.clock_signal is not None:
        for line in _byte_alignment_lines(decoded, args.clock_signal):
            print(line)
    print("classification=DESCRIPTIVE-NOT-A-CONTRACT")
    print("wire_contract_claimed=false")
    print("authorizes_transmit=false")
    print("authorizes_device=false")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k210_capture_ingest.py",
        description=(
            "File-only K210 digital-capture ingestion: Saleae digital CSV -> "
            "canonical bounded .k210cap v1 artifact, strict validation, "
            "deterministic triage, and DESCRIPTIVE-NOT-A-CONTRACT statistics. "
            "Host-only; no device, network, or transmit path."
        ),
        allow_abbrev=False,
        epilog=USAGE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser(
        "ingest", help="convert digital CSV export(s) to .k210cap"
    )
    ingest.add_argument(
        "--map",
        required=True,
        type=Path,
        help="operator channel-map and provenance JSON",
    )
    ingest.add_argument(
        "--csv",
        required=True,
        action="append",
        type=Path,
        help="Saleae digital CSV export (repeat for exactly one or two files)",
    )
    ingest.add_argument(
        "--source-capture",
        type=Path,
        default=None,
        help="optional .sal archive to hash into the receipt",
    )
    ingest.add_argument(
        "--output", required=True, type=Path, help="new .k210cap artifact path"
    )
    ingest.set_defaults(handler=cmd_ingest)

    stats = subparsers.add_parser(
        "stats", help="descriptive clock/burst/alignment statistics"
    )
    stats.add_argument("--input", required=True, type=Path, help=".k210cap artifact")
    stats.add_argument(
        "--clock-signal",
        default=None,
        help="signal name for byte-alignment candidates (e.g. CKO)",
    )
    stats.add_argument(
        "--burst-gap-us",
        default="1000",
        help="inter-burst gap threshold in integer microseconds (default 1000)",
    )
    stats.set_defaults(handler=cmd_stats)

    validate = subparsers.add_parser(
        "validate", help="strictly re-verify one artifact"
    )
    validate.add_argument("--input", required=True, type=Path, help=".k210cap artifact")
    validate.set_defaults(handler=cmd_validate)

    inventory = subparsers.add_parser(
        "inventory", help="indexed event triage report"
    )
    inventory.add_argument(
        "--input", required=True, type=Path, help=".k210cap artifact"
    )
    inventory.set_defaults(handler=cmd_inventory)

    extract = subparsers.add_parser(
        "extract", help="copy one contiguous event range to a new artifact"
    )
    extract.add_argument(
        "--input", required=True, type=Path, help="source .k210cap artifact"
    )
    extract.add_argument(
        "--first-event", required=True, type=int, help="zero-based first event index"
    )
    extract.add_argument(
        "--event-count", required=True, type=int, help="number of events to retain"
    )
    extract.add_argument(
        "--output", required=True, type=Path, help="new .k210cap artifact path"
    )
    extract.set_defaults(handler=cmd_extract)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except CaptureIngestError as exc:
        print(f"K210_CAPTURE_INGEST_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
