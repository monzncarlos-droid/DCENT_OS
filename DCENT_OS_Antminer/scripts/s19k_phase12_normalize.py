#!/usr/bin/env python3
"""Deterministically derive S19k Phase-1/2 canonical CSVs from raw CSV exports.

The normalizer is host-only and performs no network or hardware operation. A
canonical declarative JSON config maps raw instrument and UART columns into the
two verifier schemas. The tool publishes both derived CSVs plus a content-bound
normalization receipt in a new directory. The verify_normalization function
replays the same mapping and requires byte-identical outputs.
"""

from __future__ import annotations

import argparse
import csv
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
from typing import Iterator


CONFIG_SCHEMA = "dcentos.s19k-phase12-normalization-config/v1"
RECEIPT_SCHEMA = "dcentos.s19k-phase12-normalization/v1"
INSTRUMENT_OUTPUT = "instrument.csv"
UART_OUTPUT = "uart.csv"
RECEIPT_OUTPUT = "phase12_normalization_receipt"
INSTRUMENT_ONLY_OUTPUT = "phase3_safeoff.csv"
INSTRUMENT_ONLY_RECEIPT_OUTPUT = "phase3_normalization_receipt"
INSTRUMENT_ONLY_RECEIPT_SCHEMA = "dcentos.s19k-phase3-normalization/v1"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CANONICAL_BYTES = 64 * 1024 * 1024
PUBLICATION = "host-staged-directory-rename-and-fsync"

REQUIRED_PATHS = ("/dev/ttyS1", "/dev/ttyS2")
OPTIONAL_PATHS = ("/dev/ttyS3",)
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

CONFIG_KEYS = ("schema", "common_clock_id", "rail_signal", "instrument", "uart")
SECTION_KEYS = ("delimiter", "trim_whitespace", "timestamp", "fields")
TIMESTAMP_KEYS = ("column", "unit", "offset_ms", "rounding")
SCALED_KEYS = ("column", "kind", "multiply", "divide", "add")
ENUM_KEYS = ("column", "kind", "values")
FRAME_KEYS = ("column", "kind")
RECEIPT_KEYS = (
    "schema",
    "normalizer_sha256",
    "normalizer_bytes",
    "config_sha256",
    "config_bytes",
    "instrument_source_sha256",
    "instrument_source_bytes",
    "uart_source_sha256",
    "uart_source_bytes",
    "instrument_csv_sha256",
    "instrument_csv_bytes",
    "instrument_row_count",
    "uart_csv_sha256",
    "uart_csv_bytes",
    "uart_row_count",
    "common_clock_id",
    "rail_signal",
    "normalization_id",
    "publication",
)
NORMALIZATION_ID_KEYS = tuple(
    key for key in RECEIPT_KEYS if key not in ("normalization_id", "publication")
)
INSTRUMENT_ONLY_RECEIPT_KEYS = (
    "schema",
    "normalizer_sha256",
    "normalizer_bytes",
    "config_sha256",
    "config_bytes",
    "instrument_source_sha256",
    "instrument_source_bytes",
    "instrument_csv_sha256",
    "instrument_csv_bytes",
    "instrument_row_count",
    "common_clock_id",
    "rail_signal",
    "normalization_id",
    "publication",
)
INSTRUMENT_ONLY_ID_KEYS = tuple(
    key
    for key in INSTRUMENT_ONLY_RECEIPT_KEYS
    if key not in ("normalization_id", "publication")
)


class NormalizationError(ValueError):
    """Raw capture inputs cannot produce an admitted normalization receipt."""


def fail(message: str) -> None:
    raise NormalizationError(message)


def _exact_keys(value: object, keys: tuple[str, ...], label: str) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != set(keys)
        or len(value) != len(keys)
    ):
        fail(f"{label} has an inexact key set")
    return value


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} must be an integer")
    if positive and value <= 0:
        fail(f"{label} must be positive")
    return value


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            fail("short normalization write")
        offset += written


def _identity(path: Path, label: str, *, nonempty: bool = True) -> tuple[int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(reparse and getattr(metadata, "st_file_attributes", 0) & reparse)
        or (nonempty and metadata.st_size <= 0)
    ):
        fail(f"{label} must be a non-empty real regular non-link file")
    return metadata.st_dev, metadata.st_ino


def _stable_digest(
    path: Path,
    label: str,
    *,
    max_bytes: int | None = None,
) -> tuple[str, int]:
    path_identity = _identity(path, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != path_identity:
            fail(f"{label} changed before hashing")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            if max_bytes is not None and observed > max_bytes:
                fail(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot hash {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stable_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )
    stable_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    if stable_before != stable_after or observed != before.st_size:
        fail(f"{label} changed while hashing")
    return digest.hexdigest(), observed


def _copy_stable(source: Path, target: Path, label: str) -> tuple[str, int]:
    source_identity = _identity(source, label)
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    target_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    source_fd = -1
    target_fd = -1
    try:
        source_fd = os.open(source, source_flags)
        before = os.fstat(source_fd)
        if (before.st_dev, before.st_ino) != source_identity:
            fail(f"{label} changed before it was frozen")
        target_fd = os.open(target, target_flags, 0o600)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            _write_all(target_fd, chunk)
        os.fsync(target_fd)
        after = os.fstat(source_fd)
    except OSError as error:
        fail(f"cannot freeze {label}: {error}")
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if source_fd >= 0:
            os.close(source_fd)
    stable_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )
    stable_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    if stable_before != stable_after or observed != before.st_size:
        fail(f"{label} changed while it was frozen")
    return digest.hexdigest(), observed


def _read_bounded(path: Path, label: str, limit: int) -> bytes:
    _, size = _stable_digest(path, label, max_bytes=limit)
    if size > limit:
        fail(f"{label} exceeds its size limit")
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"cannot read {label}: {error}")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"normalization config repeats JSON key {key!r}")
        result[key] = value
    return result


def _read_config(path: Path) -> tuple[bytes, dict[str, object]]:
    data = _read_bounded(path, "normalization config", MAX_CONFIG_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("normalization config must be canonical ASCII JSON")
    try:
        parsed = json.loads(text, object_pairs_hook=_json_object)
    except (json.JSONDecodeError, NormalizationError) as error:
        fail(f"normalization config is invalid JSON: {error}")
    canonical = (
        json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if data != canonical:
        fail("normalization config is not canonical sorted compact JSON plus LF")
    config = _validate_config(parsed)
    return data, config


def _validate_timestamp(value: object, label: str) -> dict[str, object]:
    timestamp = _exact_keys(value, TIMESTAMP_KEYS, label)
    if not isinstance(timestamp["column"], str) or not timestamp["column"]:
        fail(f"{label} column must be a non-empty string")
    if timestamp["unit"] not in ("s", "ms", "us", "ns"):
        fail(f"{label} unit must be s, ms, us, or ns")
    _integer(timestamp["offset_ms"], f"{label} offset_ms")
    if timestamp["rounding"] not in ("exact", "floor"):
        fail(f"{label} rounding must be exact or floor")
    return timestamp


def _validate_mapping(
    value: object,
    label: str,
    *,
    allowed_outputs: set[str] | None = None,
) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    kind = value.get("kind")
    if kind == "scaled-decimal":
        mapping = _exact_keys(value, SCALED_KEYS, label)
        if not isinstance(mapping["column"], str) or not mapping["column"]:
            fail(f"{label} column must be a non-empty string")
        _integer(mapping["multiply"], f"{label} multiply", positive=True)
        _integer(mapping["divide"], f"{label} divide", positive=True)
        _integer(mapping["add"], f"{label} add")
        if allowed_outputs is not None:
            fail(f"{label} must use an enum mapping")
        return mapping
    if kind == "enum":
        mapping = _exact_keys(value, ENUM_KEYS, label)
        if not isinstance(mapping["column"], str) or not mapping["column"]:
            fail(f"{label} column must be a non-empty string")
        values = mapping["values"]
        if not isinstance(values, dict) or not values:
            fail(f"{label} values must be a non-empty object")
        for raw, canonical in values.items():
            if not isinstance(raw, str) or not isinstance(canonical, str):
                fail(f"{label} enum keys and values must be strings")
        if allowed_outputs is not None and set(values.values()) != allowed_outputs:
            fail(f"{label} enum outputs must be exactly {sorted(allowed_outputs)}")
        return mapping
    fail(f"{label} has an unsupported mapping kind")


def _validate_section(
    value: object,
    label: str,
    expected_fields: tuple[str, ...],
) -> dict[str, object]:
    section = _exact_keys(value, SECTION_KEYS, label)
    delimiter = section["delimiter"]
    if delimiter not in (",", ";", "\t"):
        fail(f"{label} delimiter must be comma, semicolon, or tab")
    if not isinstance(section["trim_whitespace"], bool):
        fail(f"{label} trim_whitespace must be boolean")
    timestamp = _validate_timestamp(section["timestamp"], f"{label} timestamp")
    fields = section["fields"]
    if not isinstance(fields, dict) or set(fields) != set(expected_fields):
        fail(f"{label} fields must map the exact canonical field set")
    columns = [str(timestamp["column"])]
    for name in expected_fields:
        if label == "uart" and name == "frame_hex":
            frame = _exact_keys(fields[name], FRAME_KEYS, "uart field frame_hex")
            if frame["kind"] != "hex-bytes":
                fail("uart frame_hex mapping kind must be hex-bytes")
            if not isinstance(frame["column"], str) or not frame["column"]:
                fail("uart frame_hex column must be a non-empty string")
            columns.append(str(frame["column"]))
            continue
        allowed: set[str] | None = None
        if label == "instrument" and name == "event":
            allowed = {"run-start", "sample"}
        mapping = _validate_mapping(
            fields[name],
            f"{label} field {name}",
            allowed_outputs=allowed,
        )
        columns.append(str(mapping["column"]))
    if len(columns) != len(set(columns)):
        fail(f"{label} config aliases multiple canonical fields to one raw column")
    return section


def _validate_config(value: object) -> dict[str, object]:
    config = _exact_keys(value, CONFIG_KEYS, "normalization config")
    if config["schema"] != CONFIG_SCHEMA:
        fail("normalization config schema is not admitted")
    clock = config["common_clock_id"]
    if not isinstance(clock, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", clock
    ):
        fail("normalization common_clock_id is not a safe evidence token")
    if config["rail_signal"] not in (
        "rail-millivolts",
        "rail-current-milliamps",
    ):
        fail("normalization rail_signal is not admitted")
    _validate_section(
        config["instrument"],
        "instrument",
        INSTRUMENT_HEADER[1:],
    )
    uart = _validate_section(config["uart"], "uart", UART_HEADER[1:])
    uart_fields = uart["fields"]
    assert isinstance(uart_fields, dict)
    _validate_mapping(
        uart_fields["path"],
        "uart field path",
        allowed_outputs=set(REQUIRED_PATHS + OPTIONAL_PATHS),
    )
    _validate_mapping(
        uart_fields["direction"],
        "uart field direction",
        allowed_outputs={"tx", "rx"},
    )
    frame = _exact_keys(uart_fields["frame_hex"], FRAME_KEYS, "uart field frame_hex")
    if frame["kind"] != "hex-bytes":
        fail("uart frame_hex mapping kind must be hex-bytes")
    if not isinstance(frame["column"], str) or not frame["column"]:
        fail("uart frame_hex column must be a non-empty string")
    return config


def _raw_value(row: dict[str, str | None], column: str, trim: bool, label: str) -> str:
    value = row.get(column)
    if value is None:
        fail(f"{label} is missing raw column {column!r}")
    return value.strip(" \t") if trim else value


def _decimal(raw: str, label: str) -> Decimal:
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", raw):
        fail(f"{label} is not a canonical decimal")
    try:
        return Decimal(raw)
    except InvalidOperation:
        fail(f"{label} is not a finite decimal")


def _timestamp(raw: str, spec: dict[str, object], label: str) -> int:
    factor = {
        "s": Decimal(1000),
        "ms": Decimal(1),
        "us": Decimal(1) / Decimal(1000),
        "ns": Decimal(1) / Decimal(1_000_000),
    }[str(spec["unit"])]
    converted = _decimal(raw, label) * factor + Decimal(int(spec["offset_ms"]))
    integral = converted.to_integral_value(rounding=ROUND_FLOOR)
    if spec["rounding"] == "exact" and converted != integral:
        fail(f"{label} does not convert to an exact millisecond")
    result = int(integral)
    if result < 0 or result > (1 << 63) - 1:
        fail(f"{label} is outside the admitted monotonic range")
    return result


def _mapped(
    row: dict[str, str | None],
    spec: dict[str, object],
    trim: bool,
    label: str,
) -> str:
    raw = _raw_value(row, str(spec["column"]), trim, label)
    if spec["kind"] == "enum":
        values = spec["values"]
        assert isinstance(values, dict)
        mapped = values.get(raw)
        if not isinstance(mapped, str):
            fail(f"{label} has an unmapped raw value {raw!r}")
        return mapped
    value = _decimal(raw, label) * Decimal(int(spec["multiply"])) / Decimal(
        int(spec["divide"])
    ) + Decimal(int(spec["add"]))
    integral = value.to_integral_value(rounding=ROUND_FLOOR)
    if value != integral:
        fail(f"{label} does not scale to an exact integer")
    result = int(integral)
    if result < 0 or result > (1 << 63) - 1:
        fail(f"{label} is outside the admitted unsigned range")
    return str(result)


def _frame(raw: str, label: str) -> str:
    value = raw.strip(" \t")
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        if len(value) % 2:
            fail(f"{label} has an odd contiguous hex length")
        canonical = value.upper()
    else:
        tokens = re.split(r"[,\s:_-]+", value)
        if not tokens or any(not token for token in tokens):
            fail(f"{label} has an invalid byte-token separator")
        normalized: list[str] = []
        for token in tokens:
            byte = token[2:] if token.lower().startswith("0x") else token
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", byte):
                fail(f"{label} contains a non-byte hex token")
            normalized.append(byte.upper())
        canonical = "".join(normalized)
    size = len(canonical) // 2
    if not 2 <= size <= 4096:
        fail(f"{label} frame length is outside 2..4096 bytes")
    return canonical


def _csv_rows(
    path: Path,
    section: dict[str, object],
    label: str,
) -> Iterator[tuple[int, dict[str, str | None]]]:
    delimiter = str(section["delimiter"])
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    with handle:
        try:
            reader = csv.DictReader(handle, delimiter=delimiter, strict=True)
            header = reader.fieldnames
            if (
                header is None
                or not header
                or any(not field for field in header)
                or len(header) != len(set(header))
            ):
                fail(f"{label} has an empty or duplicate CSV header")
            referenced = {
                str(section["timestamp"]["column"]),
                *(
                    str(mapping["column"])
                    for mapping in section["fields"].values()
                    if isinstance(mapping, dict)
                ),
            }
            missing = referenced - set(header)
            if missing:
                fail(f"{label} lacks configured columns {sorted(missing)}")
            for number, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    fail(f"{label} row {number} has an inexact column count")
                yield number, row
        except csv.Error as error:
            fail(f"{label} is invalid CSV: {error}")


def _new_output(path: Path, header: tuple[str, ...]) -> tuple[int, object, int]:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as error:
        fail(f"cannot create normalization output {path.name!r}: {error}")
    digest = hashlib.sha256()
    data = (",".join(header) + "\n").encode("ascii")
    _write_all(descriptor, data)
    digest.update(data)
    return descriptor, digest, len(data)


def _append_output(
    descriptor: int,
    digest: object,
    observed: int,
    values: list[str],
) -> int:
    if any("," in value or "\r" in value or "\n" in value for value in values):
        fail("canonical normalization output contains an unsafe CSV field")
    data = (",".join(values) + "\n").encode("ascii")
    observed += len(data)
    if observed > MAX_CANONICAL_BYTES:
        fail("canonical normalization output exceeds 64 MiB")
    _write_all(descriptor, data)
    digest.update(data)
    return observed


def _derive_instrument(
    source: Path,
    output: Path,
    config: dict[str, object],
) -> tuple[str, int, int]:
    section = config["instrument"]
    assert isinstance(section, dict)
    fields = section["fields"]
    assert isinstance(fields, dict)
    timestamp_spec = section["timestamp"]
    assert isinstance(timestamp_spec, dict)
    descriptor, digest, observed = _new_output(output, INSTRUMENT_HEADER)
    rows = 0
    run_starts = 0
    previous = -1
    try:
        for number, row in _csv_rows(source, section, "raw instrument export"):
            trim = bool(section["trim_whitespace"])
            timestamp = _timestamp(
                _raw_value(
                    row,
                    str(timestamp_spec["column"]),
                    trim,
                    f"instrument row {number} timestamp",
                ),
                timestamp_spec,
                f"instrument row {number} timestamp",
            )
            if timestamp <= previous:
                fail("normalized instrument timestamps are not strictly increasing")
            previous = timestamp
            values = [str(timestamp)]
            for field in INSTRUMENT_HEADER[1:]:
                mapping = fields[field]
                assert isinstance(mapping, dict)
                mapped = _mapped(
                    row,
                    mapping,
                    trim,
                    f"instrument row {number} {field}",
                )
                if field == "event" and mapped == "run-start":
                    run_starts += 1
                values.append(mapped)
            observed = _append_output(descriptor, digest, observed, values)
            rows += 1
        if rows == 0:
            fail("raw instrument export has no data rows")
        if run_starts != 1:
            fail("normalized instrument evidence requires exactly one run-start row")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), observed, rows


def _derive_uart(
    source: Path,
    output: Path,
    config: dict[str, object],
) -> tuple[str, int, int]:
    section = config["uart"]
    assert isinstance(section, dict)
    fields = section["fields"]
    assert isinstance(fields, dict)
    timestamp_spec = section["timestamp"]
    assert isinstance(timestamp_spec, dict)
    descriptor, digest, observed = _new_output(output, UART_HEADER)
    rows = 0
    previous = -1
    try:
        for number, row in _csv_rows(source, section, "raw UART export"):
            trim = bool(section["trim_whitespace"])
            timestamp = _timestamp(
                _raw_value(
                    row,
                    str(timestamp_spec["column"]),
                    trim,
                    f"UART row {number} timestamp",
                ),
                timestamp_spec,
                f"UART row {number} timestamp",
            )
            if timestamp < previous:
                fail("normalized UART timestamps are not monotonic")
            previous = timestamp
            path_spec = fields["path"]
            direction_spec = fields["direction"]
            frame_spec = fields["frame_hex"]
            assert isinstance(path_spec, dict)
            assert isinstance(direction_spec, dict)
            assert isinstance(frame_spec, dict)
            values = [
                str(timestamp),
                _mapped(row, path_spec, trim, f"UART row {number} path"),
                _mapped(
                    row,
                    direction_spec,
                    trim,
                    f"UART row {number} direction",
                ),
                _frame(
                    _raw_value(
                        row,
                        str(frame_spec["column"]),
                        trim,
                        f"UART row {number} frame",
                    ),
                    f"UART row {number} frame",
                ),
            ]
            observed = _append_output(descriptor, digest, observed, values)
            rows += 1
        if rows == 0:
            fail("raw UART export has no data rows")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), observed, rows


def _derive_files(
    config_path: Path,
    instrument_source: Path,
    uart_source: Path,
    instrument_output: Path,
    uart_output: Path,
) -> dict[str, object]:
    config_data, config = _read_config(config_path)
    instrument_sha, instrument_bytes, instrument_rows = _derive_instrument(
        instrument_source,
        instrument_output,
        config,
    )
    uart_sha, uart_bytes, uart_rows = _derive_uart(
        uart_source,
        uart_output,
        config,
    )
    return {
        "config": config,
        "config_data": config_data,
        "instrument_csv_sha256": instrument_sha,
        "instrument_csv_bytes": instrument_bytes,
        "instrument_row_count": instrument_rows,
        "uart_csv_sha256": uart_sha,
        "uart_csv_bytes": uart_bytes,
        "uart_row_count": uart_rows,
    }


def _kv_bytes(keys: tuple[str, ...], values: dict[str, str]) -> bytes:
    if set(values) != set(keys) or len(values) != len(keys):
        fail("normalization receipt construction has an inexact key set")
    return "".join(f"{key}={values[key]}\n" for key in keys).encode("ascii")


def _normalization_id(values: dict[str, str]) -> str:
    projected = {key: values[key] for key in NORMALIZATION_ID_KEYS}
    return hashlib.sha256(_kv_bytes(NORMALIZATION_ID_KEYS, projected)).hexdigest()


def _receipt_values(
    *,
    config_sha256: str,
    config_bytes: int,
    instrument_source_sha256: str,
    instrument_source_bytes: int,
    uart_source_sha256: str,
    uart_source_bytes: int,
    derived: dict[str, object],
) -> dict[str, str]:
    normalizer_sha, normalizer_bytes = _stable_digest(
        Path(__file__),
        "Phase 1+2 normalizer",
    )
    config = derived["config"]
    assert isinstance(config, dict)
    values = {
        "schema": RECEIPT_SCHEMA,
        "normalizer_sha256": normalizer_sha,
        "normalizer_bytes": str(normalizer_bytes),
        "config_sha256": config_sha256,
        "config_bytes": str(config_bytes),
        "instrument_source_sha256": instrument_source_sha256,
        "instrument_source_bytes": str(instrument_source_bytes),
        "uart_source_sha256": uart_source_sha256,
        "uart_source_bytes": str(uart_source_bytes),
        "instrument_csv_sha256": str(derived["instrument_csv_sha256"]),
        "instrument_csv_bytes": str(derived["instrument_csv_bytes"]),
        "instrument_row_count": str(derived["instrument_row_count"]),
        "uart_csv_sha256": str(derived["uart_csv_sha256"]),
        "uart_csv_bytes": str(derived["uart_csv_bytes"]),
        "uart_row_count": str(derived["uart_row_count"]),
        "common_clock_id": str(config["common_clock_id"]),
        "rail_signal": str(config["rail_signal"]),
        "publication": PUBLICATION,
    }
    values["normalization_id"] = _normalization_id(values)
    return values


def _instrument_receipt_values(
    *,
    config_sha256: str,
    config_bytes: int,
    instrument_source_sha256: str,
    instrument_source_bytes: int,
    instrument_csv_sha256: str,
    instrument_csv_bytes: int,
    instrument_row_count: int,
    config: dict[str, object],
) -> dict[str, str]:
    normalizer_sha, normalizer_bytes = _stable_digest(
        Path(__file__), "Phase-3 instrument normalizer"
    )
    values = {
        "schema": INSTRUMENT_ONLY_RECEIPT_SCHEMA,
        "normalizer_sha256": normalizer_sha,
        "normalizer_bytes": str(normalizer_bytes),
        "config_sha256": config_sha256,
        "config_bytes": str(config_bytes),
        "instrument_source_sha256": instrument_source_sha256,
        "instrument_source_bytes": str(instrument_source_bytes),
        "instrument_csv_sha256": instrument_csv_sha256,
        "instrument_csv_bytes": str(instrument_csv_bytes),
        "instrument_row_count": str(instrument_row_count),
        "common_clock_id": str(config["common_clock_id"]),
        "rail_signal": str(config["rail_signal"]),
        "publication": PUBLICATION,
    }
    projected = {key: values[key] for key in INSTRUMENT_ONLY_ID_KEYS}
    values["normalization_id"] = hashlib.sha256(
        _kv_bytes(INSTRUMENT_ONLY_ID_KEYS, projected)
    ).hexdigest()
    return values


def _write_new(path: Path, data: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except OSError as error:
        fail(f"cannot publish {path.name!r}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_receipt(path: Path) -> tuple[bytes, dict[str, str]]:
    data = _read_bounded(path, "normalization receipt", 64 * 1024)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("normalization receipt must be ASCII")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            fail("normalization receipt has a malformed line")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"normalization receipt repeats field {key}")
        values[key] = value
    if tuple(values) != RECEIPT_KEYS:
        fail("normalization receipt has an inexact ordered field set")
    if data != _kv_bytes(RECEIPT_KEYS, values):
        fail("normalization receipt is not canonical")
    return data, values


def _parse_instrument_receipt(path: Path) -> tuple[bytes, dict[str, str]]:
    data = _read_bounded(path, "Phase-3 normalization receipt", 64 * 1024)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("Phase-3 normalization receipt must be ASCII")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            fail("Phase-3 normalization receipt has a malformed line")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"Phase-3 normalization receipt repeats field {key}")
        values[key] = value
    if tuple(values) != INSTRUMENT_ONLY_RECEIPT_KEYS:
        fail("Phase-3 normalization receipt has an inexact ordered field set")
    if data != _kv_bytes(INSTRUMENT_ONLY_RECEIPT_KEYS, values):
        fail("Phase-3 normalization receipt is not canonical")
    return data, values


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        fail("normalization publication requires Linux/WSL directory fsync")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_normalization(
    *,
    config_path: Path,
    instrument_source: Path,
    uart_source: Path,
    instrument_csv: Path,
    uart_csv: Path,
    receipt_path: Path,
) -> dict[str, str]:
    paths = {
        "normalization config": config_path.absolute(),
        "raw instrument export": instrument_source.absolute(),
        "raw UART export": uart_source.absolute(),
        "canonical instrument CSV": instrument_csv.absolute(),
        "canonical UART CSV": uart_csv.absolute(),
        "normalization receipt": receipt_path.absolute(),
    }
    identities = {label: _identity(path, label) for label, path in paths.items()}
    if len(set(identities.values())) != len(identities):
        fail("normalization inputs and outputs must be six distinct inodes")
    with tempfile.TemporaryDirectory(prefix="s19k-phase12-normalize-verify-") as temp:
        root = Path(temp)
        frozen_config = root / "config.json"
        frozen_instrument = root / "instrument.raw"
        frozen_uart = root / "uart.raw"
        config_sha, config_bytes = _copy_stable(
            paths["normalization config"],
            frozen_config,
            "normalization config",
        )
        instrument_source_sha, instrument_source_bytes = _copy_stable(
            paths["raw instrument export"],
            frozen_instrument,
            "raw instrument export",
        )
        uart_source_sha, uart_source_bytes = _copy_stable(
            paths["raw UART export"],
            frozen_uart,
            "raw UART export",
        )
        generated_instrument = root / INSTRUMENT_OUTPUT
        generated_uart = root / UART_OUTPUT
        derived = _derive_files(
            frozen_config,
            frozen_instrument,
            frozen_uart,
            generated_instrument,
            generated_uart,
        )
        supplied_instrument_sha, supplied_instrument_bytes = _stable_digest(
            paths["canonical instrument CSV"],
            "canonical instrument CSV",
            max_bytes=MAX_CANONICAL_BYTES,
        )
        supplied_uart_sha, supplied_uart_bytes = _stable_digest(
            paths["canonical UART CSV"],
            "canonical UART CSV",
            max_bytes=MAX_CANONICAL_BYTES,
        )
        if (
            supplied_instrument_sha != derived["instrument_csv_sha256"]
            or supplied_instrument_bytes != derived["instrument_csv_bytes"]
        ):
            fail(
                "canonical instrument CSV is not the deterministic raw-source derivation"
            )
        if (
            supplied_uart_sha != derived["uart_csv_sha256"]
            or supplied_uart_bytes != derived["uart_csv_bytes"]
        ):
            fail("canonical UART CSV is not the deterministic raw-source derivation")
        expected = _receipt_values(
            config_sha256=config_sha,
            config_bytes=config_bytes,
            instrument_source_sha256=instrument_source_sha,
            instrument_source_bytes=instrument_source_bytes,
            uart_source_sha256=uart_source_sha,
            uart_source_bytes=uart_source_bytes,
            derived=derived,
        )
    _, observed = _parse_receipt(paths["normalization receipt"])
    for key in RECEIPT_KEYS:
        if observed[key] != expected[key]:
            fail(f"normalization receipt field {key} does not match replay")
    return observed


def verify_instrument_normalization(
    *,
    config_path: Path,
    instrument_source: Path,
    instrument_csv: Path,
    receipt_path: Path,
) -> dict[str, str]:
    """Replay one raw Phase-3 instrument export into the exact SafeOff CSV."""
    paths = {
        "normalization config": config_path.absolute(),
        "raw instrument export": instrument_source.absolute(),
        "canonical instrument CSV": instrument_csv.absolute(),
        "Phase-3 normalization receipt": receipt_path.absolute(),
    }
    identities = {label: _identity(path, label) for label, path in paths.items()}
    if len(set(identities.values())) != len(identities):
        fail("Phase-3 normalization inputs and outputs must be four distinct inodes")
    with tempfile.TemporaryDirectory(prefix="s19k-phase3-normalize-verify-") as temp:
        root = Path(temp)
        frozen_config = root / "config.json"
        frozen_instrument = root / "instrument.raw"
        config_sha, config_bytes = _copy_stable(
            paths["normalization config"], frozen_config, "normalization config"
        )
        instrument_source_sha, instrument_source_bytes = _copy_stable(
            paths["raw instrument export"],
            frozen_instrument,
            "raw instrument export",
        )
        _, config = _read_config(frozen_config)
        generated = root / INSTRUMENT_ONLY_OUTPUT
        generated_sha, generated_bytes, row_count = _derive_instrument(
            frozen_instrument, generated, config
        )
        supplied_sha, supplied_bytes = _stable_digest(
            paths["canonical instrument CSV"],
            "canonical instrument CSV",
            max_bytes=MAX_CANONICAL_BYTES,
        )
        if supplied_sha != generated_sha or supplied_bytes != generated_bytes:
            fail(
                "canonical Phase-3 instrument CSV is not the deterministic raw-source derivation"
            )
        expected = _instrument_receipt_values(
            config_sha256=config_sha,
            config_bytes=config_bytes,
            instrument_source_sha256=instrument_source_sha,
            instrument_source_bytes=instrument_source_bytes,
            instrument_csv_sha256=generated_sha,
            instrument_csv_bytes=generated_bytes,
            instrument_row_count=row_count,
            config=config,
        )
    _, observed = _parse_instrument_receipt(paths["Phase-3 normalization receipt"])
    for key in INSTRUMENT_ONLY_RECEIPT_KEYS:
        if observed[key] != expected[key]:
            fail(f"Phase-3 normalization receipt field {key} does not match replay")
    return observed


def normalize_instrument(
    *, config_path: Path, instrument_source: Path, output_dir: Path
) -> dict[str, str]:
    """Publish a no-clobber Phase-3 canonical capture and replay receipt."""
    if os.name == "nt":
        fail("normalization publication requires Linux/WSL directory fsync")
    config_path = config_path.absolute()
    instrument_source = instrument_source.absolute()
    if _identity(config_path, "normalization config") == _identity(
        instrument_source, "raw instrument export"
    ):
        fail("normalization config and raw capture must be distinct inodes")
    parent = output_dir.parent.resolve(strict=True)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", output_dir.name):
        fail("normalization output must be one safe direct-child directory name")
    output = parent / output_dir.name
    if os.path.lexists(output):
        fail("normalization output directory already exists; refusing to clobber it")
    staging = parent / f".{output.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    os.mkdir(staging, 0o700)
    frozen_config = staging / ".normalization_config.input"
    frozen_instrument = staging / ".instrument_source.input"
    config_sha, config_bytes = _copy_stable(
        config_path, frozen_config, "normalization config"
    )
    instrument_source_sha, instrument_source_bytes = _copy_stable(
        instrument_source, frozen_instrument, "raw instrument export"
    )
    _, config = _read_config(frozen_config)
    instrument_output = staging / INSTRUMENT_ONLY_OUTPUT
    instrument_sha, instrument_bytes, row_count = _derive_instrument(
        frozen_instrument, instrument_output, config
    )
    receipt = _instrument_receipt_values(
        config_sha256=config_sha,
        config_bytes=config_bytes,
        instrument_source_sha256=instrument_source_sha,
        instrument_source_bytes=instrument_source_bytes,
        instrument_csv_sha256=instrument_sha,
        instrument_csv_bytes=instrument_bytes,
        instrument_row_count=row_count,
        config=config,
    )
    _write_new(
        staging / INSTRUMENT_ONLY_RECEIPT_OUTPUT,
        _kv_bytes(INSTRUMENT_ONLY_RECEIPT_KEYS, receipt),
    )
    os.unlink(frozen_config)
    os.unlink(frozen_instrument)
    _fsync_directory(staging)
    if os.path.lexists(output):
        fail("normalization output appeared during publication")
    os.rename(staging, output)
    _fsync_directory(parent)
    return verify_instrument_normalization(
        config_path=config_path,
        instrument_source=instrument_source,
        instrument_csv=output / INSTRUMENT_ONLY_OUTPUT,
        receipt_path=output / INSTRUMENT_ONLY_RECEIPT_OUTPUT,
    )


def normalize(
    *,
    config_path: Path,
    instrument_source: Path,
    uart_source: Path,
    output_dir: Path,
) -> dict[str, str]:
    if os.name == "nt":
        fail("normalization publication requires Linux/WSL")
    config_path = config_path.absolute()
    instrument_source = instrument_source.absolute()
    uart_source = uart_source.absolute()
    identities = {
        _identity(config_path, "normalization config"),
        _identity(instrument_source, "raw instrument export"),
        _identity(uart_source, "raw UART export"),
    }
    if len(identities) != 3:
        fail("normalization config and raw captures must be distinct inodes")
    parent = output_dir.parent.resolve(strict=True)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", output_dir.name):
        fail("normalization output must be one safe direct-child directory name")
    output = parent / output_dir.name
    if os.path.lexists(output):
        fail("normalization output directory already exists; refusing to clobber it")
    staging = parent / f".{output.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    os.mkdir(staging, 0o700)
    frozen_config = staging / ".normalization_config.input"
    frozen_instrument = staging / ".instrument_source.input"
    frozen_uart = staging / ".uart_source.input"
    config_sha, config_bytes = _copy_stable(
        config_path, frozen_config, "normalization config"
    )
    instrument_source_sha, instrument_source_bytes = _copy_stable(
        instrument_source,
        frozen_instrument,
        "raw instrument export",
    )
    uart_source_sha, uart_source_bytes = _copy_stable(
        uart_source,
        frozen_uart,
        "raw UART export",
    )
    instrument_output = staging / INSTRUMENT_OUTPUT
    uart_output = staging / UART_OUTPUT
    derived = _derive_files(
        frozen_config,
        frozen_instrument,
        frozen_uart,
        instrument_output,
        uart_output,
    )
    receipt = _receipt_values(
        config_sha256=config_sha,
        config_bytes=config_bytes,
        instrument_source_sha256=instrument_source_sha,
        instrument_source_bytes=instrument_source_bytes,
        uart_source_sha256=uart_source_sha,
        uart_source_bytes=uart_source_bytes,
        derived=derived,
    )
    _write_new(staging / RECEIPT_OUTPUT, _kv_bytes(RECEIPT_KEYS, receipt))
    os.unlink(frozen_config)
    os.unlink(frozen_instrument)
    os.unlink(frozen_uart)
    _fsync_directory(staging)
    if os.path.lexists(output):
        fail("normalization output appeared during publication")
    os.rename(staging, output)
    _fsync_directory(parent)
    return verify_normalization(
        config_path=config_path,
        instrument_source=instrument_source,
        uart_source=uart_source,
        instrument_csv=output / INSTRUMENT_OUTPUT,
        uart_csv=output / UART_OUTPUT,
        receipt_path=output / RECEIPT_OUTPUT,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--instrument-source", required=True, type=Path)
    parser.add_argument("--uart-source", type=Path)
    parser.add_argument(
        "--instrument-only",
        action="store_true",
        help="derive only Phase-3 SafeOff instrument CSV plus its replay receipt",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.instrument_only:
            if args.uart_source is not None:
                raise NormalizationError(
                    "--instrument-only refuses an unrelated --uart-source"
                )
            result = normalize_instrument(
                config_path=args.config,
                instrument_source=args.instrument_source,
                output_dir=args.output_dir,
            )
        else:
            if args.uart_source is None:
                raise NormalizationError(
                    "Phase-1+2 normalization requires --uart-source"
                )
            result = normalize(
                config_path=args.config,
                instrument_source=args.instrument_source,
                uart_source=args.uart_source,
                output_dir=args.output_dir,
            )
    except (OSError, NormalizationError) as error:
        print(f"S19K_PHASE12_NORMALIZATION_REFUSED: {error}", file=sys.stderr)
        return 1
    if args.instrument_only:
        print(
            "S19K_PHASE3_NORMALIZATION_OK "
            f"normalization_id={result['normalization_id']} "
            f"instrument_rows={result['instrument_row_count']}"
        )
    else:
        print(
            "S19K_PHASE12_NORMALIZATION_OK "
            f"normalization_id={result['normalization_id']} "
            f"instrument_rows={result['instrument_row_count']} "
            f"uart_rows={result['uart_row_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
