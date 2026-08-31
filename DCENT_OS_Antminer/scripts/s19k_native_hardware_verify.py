#!/usr/bin/env python3
"""Verify the S19k Pro native hardware evidence contract without live contact.

The verifier reads only a copied evidence directory.  It cannot authorize or
perform mining, network access, GPIO writes, reset writes, NAND mutation, or
key extraction.  Success proves only the content-bound physical observations
described by the returned receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

import s19k_bounded_transcript_verify as common
import s19k_no_work_verify as phase12
import s19k_phase12_normalize as normalizer


MANIFEST_SCHEMA = "dcentos.s19k-native-hardware-manifest/v1"
RESULT_SCHEMA = "dcentos.s19k-native-hardware-verification/v1"
MAPPING_SCHEMA = "dcentos.s19k-native-hardware-mapping/v1"
PHASE12_RESULT_SCHEMA = "dcentos.s19k-phase12-no-work-host-verification/v2"
LIVE_PROFILE = "live88_two_bhb56903_slots_2_3"
CLAIM = "reviewed-common-clock-native-hardware-contract"

MANIFEST_FILENAME = "native_hardware_manifest.kv"
PLAN_FILENAME = "adopted_phase12_plan.kv"
PHASE12_RESULT_FILENAME = "adopted_phase12_verification.json"
PREFLIGHT_FILENAME = "instrumentation_preflight.kv"
NORMALIZATION_CONFIG_FILENAME = "normalization_config.json"
INSTRUMENT_SOURCE_FILENAME = "instrument_source.raw"
UART_SOURCE_FILENAME = "uart_source.raw"
NORMALIZATION_RECEIPT_FILENAME = "native_hardware_normalization_receipt"
INSTRUMENT_FILENAME = "instrument.csv"
UART_FILENAME = "uart.csv"
MAPPING_FILENAME = "mapping.kv"
WORKFLOW_RECEIPT_FILENAME = "verification.json"

INPUT_FILES = (
    PLAN_FILENAME,
    PHASE12_RESULT_FILENAME,
    PREFLIGHT_FILENAME,
    NORMALIZATION_CONFIG_FILENAME,
    INSTRUMENT_SOURCE_FILENAME,
    UART_SOURCE_FILENAME,
    NORMALIZATION_RECEIPT_FILENAME,
    INSTRUMENT_FILENAME,
    UART_FILENAME,
    MAPPING_FILENAME,
)
PREFIXES = (
    "adopted_plan",
    "adopted_phase12_verification",
    "preflight",
    "normalization_config",
    "instrument_source",
    "uart_source",
    "normalization_receipt",
    "instrument_csv",
    "uart_csv",
    "mapping",
)
PREFIX_FILENAMES = dict(zip(PREFIXES, INPUT_FILES))
MANIFEST_KEYS = (
    "schema",
    "claim",
    "phase12_verification_id",
    *(value for prefix in PREFIXES for value in (
        f"{prefix}_file",
        f"{prefix}_sha256",
        f"{prefix}_bytes",
    )),
    "common_clock_id",
    "rail_signal",
    "created_utc",
    "publication",
)
MAPPING_KEYS = (
    "schema",
    "claim",
    "live_identity_profile",
    "live_identity_sha256",
    "board_target",
    "board_revision",
    "board_name",
    "populated_physical_addresses",
    "physical_address_2_uart",
    "physical_address_2_reset_gpio",
    "physical_address_3_uart",
    "physical_address_3_reset_gpio",
    "absent_physical_address",
    "absent_reset_gpio",
    "unpopulated_uart",
    "mapping_method",
    "gpio437_energized_raw",
    "gpio437_safeoff_raw",
    "reset_polarity",
    "fan_channels",
    "temperature_channels",
    "instrument_csv_sha256",
    "uart_csv_sha256",
    "normalization_id",
    "mapping_id",
    "publication",
)
MAPPING_ID_KEYS = tuple(
    key for key in MAPPING_KEYS if key not in ("mapping_id", "publication")
)

MAX_SMALL_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
DANGEROUS_TEMP_MILLIC = 80_000
MIN_WINDOW_MS = 2_000
GETADDRESS_PROBE = bytes.fromhex("55AA510900280000301112")
EXPECTED_MAP = {2: "/dev/ttyS2", 3: "/dev/ttyS1"}
EXPECTED_RESET_MAP = {455: "/dev/ttyS2", 456: "/dev/ttyS1"}


class NativeHardwareError(ValueError):
    """Copied evidence does not satisfy the native hardware contract."""


def fail(message: str) -> None:
    raise NativeHardwareError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_kv(fields: dict[str, str], keys: tuple[str, ...]) -> bytes:
    try:
        return "".join(f"{key}={fields[key]}\n" for key in keys).encode("ascii")
    except (KeyError, UnicodeEncodeError) as error:
        fail(f"key/value receipt cannot be represented canonically: {error}")


def _real_directory(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat native hardware evidence directory: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(reparse and getattr(metadata, "st_file_attributes", 0) & reparse)
    ):
        fail("native hardware evidence directory must be a real non-link directory")


def _read(path: Path, label: str, maximum: int) -> bytes:
    try:
        data = common._stable_regular_bytes(path, label)
    except common.VerificationError as error:
        fail(str(error))
    if not data or len(data) > maximum:
        fail(f"{label} must be non-empty and no larger than {maximum} bytes")
    return data


def _parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not canonical ASCII JSON: {error}")
    if not isinstance(value, dict) or canonical_json(value) != data:
        fail(f"{label} is not one canonical JSON object")
    return value


def _verification_id(value: dict[str, Any], label: str) -> str:
    observed = value.get("verification_id")
    if not isinstance(observed, str) or not re.fullmatch(r"[0-9a-f]{64}", observed):
        fail(f"{label} lacks a canonical verification_id")
    projected = dict(value)
    del projected["verification_id"]
    expected = _hash(canonical_json(projected))
    if observed != expected:
        fail(f"{label} verification_id does not match its canonical contents")
    return observed


def _verify_phase12_result(data: bytes, plan_data: bytes) -> dict[str, Any]:
    result = _parse_json(data, "adopted Phase 1+2 verification")
    verification_id = _verification_id(result, "adopted Phase 1+2 verification")
    required = {
        "schema": PHASE12_RESULT_SCHEMA,
        "claim": (
            "no-work handoff, checked SafeOff, independent rail cut, "
            "reset-before-cut, cooling-through-decay, and zero captured UART work frames"
        ),
        "plan_sha256": _hash(plan_data),
        "live_identity_sha256": result.get("live_identity_sha256"),
        "uart_work_frame_count": 0,
        "publication": "host-create-new-file-and-directory-fsync",
    }
    for key, expected in required.items():
        if result.get(key) != expected:
            fail(f"adopted Phase 1+2 verification has invalid {key}")
    live_sha = result.get("live_identity_sha256")
    if not isinstance(live_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", live_sha):
        fail("adopted Phase 1+2 verification has no canonical live identity")
    expected_coverage = {
        "/dev/ttyS1": ["rx", "tx"],
        "/dev/ttyS2": ["rx", "tx"],
    }
    if result.get("uart_required_path_coverage") != expected_coverage:
        fail("adopted Phase 1+2 verification lacks the exact two-UART coverage")
    safeoff = result.get("safeoff_receipt")
    anchors = (
        f"live_identity_sha256={live_sha}",
        f"live_identity_profile={LIVE_PROFILE}",
        "live_identity_physical_addresses=2,3",
        "live_identity_board_names=BHB56903,BHB56903",
        "resets=454:0,455:0,456:0",
        "psu=437:1",
    )
    if not isinstance(safeoff, str) or any(anchor not in safeoff for anchor in anchors):
        fail("adopted Phase 1+2 verification lacks the exact live88 SafeOff identity")
    result["verification_id"] = verification_id
    return result


def _window_segments(
    rows: list[phase12.InstrumentRow], state: tuple[int, int, int]
) -> list[tuple[int, int]]:
    segments: list[tuple[int, int]] = []
    start: int | None = None
    for index, row in enumerate(rows):
        if row.resets == state and start is None:
            start = index
        elif row.resets != state and start is not None:
            segments.append((start, index))
            start = None
    if start is not None:
        segments.append((start, len(rows)))
    return segments


def _directions(
    rows: list[phase12.UartRow], path: str, start_ms: int, end_ms: int
) -> set[str]:
    return {
        row.direction
        for row in rows
        if row.path == path and start_ms <= row.monotonic_ms < end_ms
    }


def _verify_recovery(
    uart_rows: list[phase12.UartRow], start_ms: int, end_ms: int, label: str
) -> None:
    if start_ms >= end_ms:
        fail(f"{label} recovery interval is empty")
    for path in phase12.REQUIRED_PATHS:
        if _directions(uart_rows, path, start_ms, end_ms) != {"rx", "tx"}:
            fail(f"{label} lacks TX/RX recovery evidence for {path}")


def _verify_reset_mapping(
    instrument_rows: list[phase12.InstrumentRow],
    uart_rows: list[phase12.UartRow],
    timing: dict[str, int],
) -> dict[str, int]:
    run_index = next(
        index for index, row in enumerate(instrument_rows) if row.event == "run-start"
    )
    cut_index = next(
        index
        for index, row in enumerate(instrument_rows)
        if row.monotonic_ms == timing["gpio437_cut_ms"]
    )
    active = instrument_rows[run_index:cut_index]
    allowed = {(0, 1, 1), (0, 0, 1), (0, 1, 0), (0, 0, 0)}
    if any(row.resets not in allowed for row in active):
        fail("reset characterization contains an unreviewed reset combination")
    if any(row.gpio437 != 0 for row in active):
        fail("GPIO437 changed during reset characterization")

    windows: dict[int, tuple[int, int, int, int]] = {}
    for gpio, state in ((455, (0, 0, 1)), (456, (0, 1, 0))):
        segments = _window_segments(active, state)
        if len(segments) != 1:
            fail(f"reset GPIO{gpio} requires exactly one isolated assertion window")
        start_index, end_index = segments[0]
        start_ms = active[start_index].monotonic_ms
        end_ms = (
            active[end_index].monotonic_ms
            if end_index < len(active)
            else timing["gpio437_cut_ms"]
        )
        last_ms = active[end_index - 1].monotonic_ms
        if last_ms - start_ms < MIN_WINDOW_MS:
            fail(f"reset GPIO{gpio} isolated assertion is shorter than two seconds")
        windows[gpio] = (start_index, end_index, start_ms, end_ms)

    if windows[455][2] >= windows[456][2]:
        fail("reset GPIO455 and GPIO456 isolation order is not canonical")
    reset_low_ms = timing["reset_low_ms"]
    if windows[456][3] >= reset_low_ms:
        fail("reset isolation lacks a released recovery interval before terminal reset")
    for row in active:
        if row.monotonic_ms < reset_low_ms and row.resets == (0, 0, 0):
            fail("terminal all-low reset occurred before isolation and recovery completed")

    recovery_intervals = (
        (timing["run_start_ms"], windows[455][2], "pre-isolation"),
        (windows[455][3], windows[456][2], "between-isolation"),
        (windows[456][3], reset_low_ms, "post-isolation"),
    )
    for start_ms, end_ms, label in recovery_intervals:
        _verify_recovery(uart_rows, start_ms, end_ms, label)

    for gpio in (455, 456):
        start_ms, end_ms = windows[gpio][2:4]
        silent = EXPECTED_RESET_MAP[gpio]
        responsive = next(path for path in phase12.REQUIRED_PATHS if path != silent)
        for path in phase12.REQUIRED_PATHS:
            probes = [
                row
                for row in uart_rows
                if row.path == path
                and row.direction == "tx"
                and row.frame == GETADDRESS_PROBE
                and start_ms <= row.monotonic_ms < end_ms
            ]
            if len(probes) < 2:
                fail(f"reset GPIO{gpio} lacks repeated GetAddress probes on {path}")
        silent_rx = [
            row
            for row in uart_rows
            if row.path == silent
            and row.direction == "rx"
            and start_ms <= row.monotonic_ms < end_ms
        ]
        responsive_rx = [
            row
            for row in uart_rows
            if row.path == responsive
            and row.direction == "rx"
            and start_ms <= row.monotonic_ms < end_ms
        ]
        if silent_rx or len(responsive_rx) < 2:
            fail(f"reset GPIO{gpio} does not uniquely silence {silent}")

    if any(
        row.path == "/dev/ttyS3"
        and row.direction == "rx"
        and timing["run_start_ms"] <= row.monotonic_ms < timing["gpio437_cut_ms"]
        for row in uart_rows
    ):
        fail("unpopulated /dev/ttyS3 produced RX evidence")
    return {
        "reset_gpio455_assert_ms": windows[455][2],
        "reset_gpio455_release_ms": windows[455][3],
        "reset_gpio456_assert_ms": windows[456][2],
        "reset_gpio456_release_ms": windows[456][3],
    }


def _verify_physical_series(
    rows: list[phase12.InstrumentRow], timing: dict[str, int]
) -> dict[str, int]:
    run_rows = [row for row in rows if row.monotonic_ms >= timing["run_start_ms"]]
    if any(any(rpm < phase12.MIN_SPINNING_FAN_RPM for rpm in row.fans) for row in run_rows):
        fail("four-channel cooling was not retained through capture end")
    energized = [
        row
        for row in rows
        if timing["run_start_ms"] <= row.monotonic_ms < timing["gpio437_cut_ms"]
    ]
    if not energized or any(
        row.gpio437 != 0 or row.rail_value <= timing["rail_decay_limit"]
        for row in energized
    ):
        fail("raw GPIO437=0 is not continuously correlated with an energized rail")
    freshness_rows = [
        row
        for row in rows
        if timing["run_start_ms"] <= row.monotonic_ms < timing["reset_low_ms"]
    ]
    if len(freshness_rows) < 2:
        fail("temperature freshness interval is empty")
    fresh = sum(
        len({row.temperatures_millic[index] for row in freshness_rows}) >= 2
        for index in range(4)
    )
    if fresh != 4:
        fail("all four temperature channels must show advancing fresh samples")
    return {"fan_channels_verified": 4, "temperature_channels_fresh": fresh}


def _mapping_id(fields: dict[str, str]) -> str:
    projected = {key: fields[key] for key in MAPPING_ID_KEYS}
    data = "".join(f"{key}={projected[key]}\n" for key in MAPPING_ID_KEYS).encode(
        "ascii"
    )
    return _hash(data)


def _verify_mapping(
    data: bytes,
    *,
    preflight: dict[str, Any],
    live_sha: str,
    normalization_id: str,
    instrument_sha: str,
    uart_sha: str,
) -> dict[str, str]:
    try:
        fields, _ = common._parse_kv_bytes(
            data, "native hardware mapping receipt", exact_keys=MAPPING_KEYS
        )
    except common.VerificationError as error:
        fail(str(error))
    if data != _canonical_kv(fields, MAPPING_KEYS):
        fail("native hardware mapping receipt is not canonical key/value bytes")
    required = {
        "schema": MAPPING_SCHEMA,
        "claim": "physical-reset-isolation-common-clock-correlation",
        "live_identity_profile": LIVE_PROFILE,
        "live_identity_sha256": live_sha,
        "board_target": "am3-s19k",
        "board_revision": str(preflight["preflight_board_revision"]),
        "board_name": "BHB56903",
        "populated_physical_addresses": "2,3",
        "physical_address_2_uart": EXPECTED_MAP[2],
        "physical_address_2_reset_gpio": "455",
        "physical_address_3_uart": EXPECTED_MAP[3],
        "physical_address_3_reset_gpio": "456",
        "absent_physical_address": "1",
        "absent_reset_gpio": "454",
        "unpopulated_uart": "/dev/ttyS3",
        "mapping_method": "common-clock-reset-isolation-repeated-getaddress",
        "gpio437_energized_raw": "0",
        "gpio437_safeoff_raw": "1",
        "reset_polarity": "raw1-released-raw0-asserted",
        "fan_channels": "fan0,fan1,fan2,fan3",
        "temperature_channels": "slot2-inlet,slot2-outlet,slot3-inlet,slot3-outlet",
        "instrument_csv_sha256": instrument_sha,
        "uart_csv_sha256": uart_sha,
        "normalization_id": normalization_id,
        "publication": "post-capture-content-bound-receipt",
    }
    for key, expected in required.items():
        if fields.get(key) != expected:
            fail(f"native hardware mapping receipt requires {key}={expected!r}")
    if fields["mapping_id"] != _mapping_id(fields):
        fail("native hardware mapping_id does not match the canonical receipt")
    return fields


def _verify_inputs(evidence_dir: Path, *, include_workflow_receipt: bool) -> dict[str, Any]:
    _real_directory(evidence_dir)
    expected = {MANIFEST_FILENAME, *INPUT_FILES}
    if include_workflow_receipt:
        expected.add(WORKFLOW_RECEIPT_FILENAME)
    try:
        names = {child.name for child in evidence_dir.iterdir()}
    except OSError as error:
        fail(f"cannot enumerate native hardware evidence directory: {error}")
    if names != expected:
        fail("native hardware evidence directory has an inexact entry set")

    manifest_data = _read(
        evidence_dir / MANIFEST_FILENAME, "native hardware manifest", MAX_SMALL_BYTES
    )
    try:
        manifest, _ = common._parse_kv_bytes(
            manifest_data, "native hardware manifest", exact_keys=MANIFEST_KEYS
        )
    except common.VerificationError as error:
        fail(str(error))
    if manifest_data != _canonical_kv(manifest, MANIFEST_KEYS):
        fail("native hardware manifest is not canonical key/value bytes")
    for key, expected_value in {
        "schema": MANIFEST_SCHEMA,
        "claim": CLAIM,
        "publication": "post-run-content-manifest",
    }.items():
        if manifest.get(key) != expected_value:
            fail(f"native hardware manifest requires {key}={expected_value!r}")
    if manifest.get("rail_signal") not in (
        "rail-millivolts",
        "rail-current-milliamps",
    ):
        fail("native hardware manifest has no independent rail signal")
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", manifest.get("common_clock_id", "")
    ):
        fail("native hardware manifest common clock is not canonical")

    blobs: dict[str, bytes] = {}
    for prefix in PREFIXES:
        filename = PREFIX_FILENAMES[prefix]
        if manifest.get(f"{prefix}_file") != filename:
            fail(f"native hardware manifest has a noncanonical {prefix} filename")
        maximum = (
            MAX_CAPTURE_BYTES
            if prefix in ("instrument_source", "uart_source", "instrument_csv", "uart_csv")
            else MAX_SMALL_BYTES
        )
        data = _read(evidence_dir / filename, prefix.replace("_", " "), maximum)
        if manifest.get(f"{prefix}_sha256") != _hash(data):
            fail(f"native hardware manifest {prefix} SHA-256 mismatch")
        if manifest.get(f"{prefix}_bytes") != str(len(data)):
            fail(f"native hardware manifest {prefix} byte count mismatch")
        blobs[prefix] = data

    try:
        plan_fields, _ = common._parse_kv_bytes(blobs["adopted_plan"], "adopted plan")
        phase12._verify_plan(plan_fields)
    except common.VerificationError as error:
        fail(f"adopted Phase 1+2 plan is invalid: {error}")
    phase12_result = _verify_phase12_result(
        blobs["adopted_phase12_verification"], blobs["adopted_plan"]
    )
    if manifest.get("phase12_verification_id") != phase12_result["verification_id"]:
        fail("native hardware manifest is bound to another Phase 1+2 verification")

    try:
        preflight = phase12._verify_preflight(
            blobs["preflight"],
            plan=plan_fields,
            manifest=manifest,
            expected_live_identity_sha256=str(phase12_result["live_identity_sha256"]),
        )
    except common.VerificationError as error:
        fail(f"native hardware instrumentation preflight is invalid: {error}")

    try:
        normalization = normalizer.verify_normalization(
            config_path=evidence_dir / NORMALIZATION_CONFIG_FILENAME,
            instrument_source=evidence_dir / INSTRUMENT_SOURCE_FILENAME,
            uart_source=evidence_dir / UART_SOURCE_FILENAME,
            instrument_csv=evidence_dir / INSTRUMENT_FILENAME,
            uart_csv=evidence_dir / UART_FILENAME,
            receipt_path=evidence_dir / NORMALIZATION_RECEIPT_FILENAME,
        )
    except normalizer.NormalizationError as error:
        fail(f"native hardware normalization provenance is invalid: {error}")
    for key in ("common_clock_id", "rail_signal"):
        if normalization[key] != manifest[key]:
            fail(f"native hardware normalization {key} does not match the manifest")

    try:
        instrument_rows, timing = phase12._parse_instrument(
            blobs["instrument_csv"],
            DANGEROUS_TEMP_MILLIC,
            rail_range_min=int(preflight["preflight_expected_range_min"]),
            rail_range_max=int(preflight["preflight_expected_range_max"]),
        )
        uart_rows, uart_result = phase12._parse_uart(blobs["uart_csv"], timing)
    except common.VerificationError as error:
        fail(f"native hardware canonical capture is invalid: {error}")
    physical = _verify_physical_series(instrument_rows, timing)
    reset = _verify_reset_mapping(instrument_rows, uart_rows, timing)
    mapping = _verify_mapping(
        blobs["mapping"],
        preflight=preflight,
        live_sha=str(phase12_result["live_identity_sha256"]),
        normalization_id=normalization["normalization_id"],
        instrument_sha=_hash(blobs["instrument_csv"]),
        uart_sha=_hash(blobs["uart_csv"]),
    )

    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "claim": CLAIM,
        "authority_granted": False,
        "live_identity_profile": LIVE_PROFILE,
        "live_identity_sha256": phase12_result["live_identity_sha256"],
        "phase12_verification_id": phase12_result["verification_id"],
        "phase12_plan_sha256": _hash(blobs["adopted_plan"]),
        "manifest_sha256": _hash(manifest_data),
        "instrumentation_preflight_sha256": _hash(blobs["preflight"]),
        "normalization_config_sha256": _hash(blobs["normalization_config"]),
        "instrument_source_sha256": _hash(blobs["instrument_source"]),
        "uart_source_sha256": _hash(blobs["uart_source"]),
        "normalization_receipt_sha256": _hash(blobs["normalization_receipt"]),
        "instrument_csv_sha256": _hash(blobs["instrument_csv"]),
        "uart_csv_sha256": _hash(blobs["uart_csv"]),
        "mapping_receipt_sha256": _hash(blobs["mapping"]),
        "mapping_id": mapping["mapping_id"],
        "normalization_id": normalization["normalization_id"],
        "common_clock_id": manifest["common_clock_id"],
        "rail_signal": manifest["rail_signal"],
        "board_revision": preflight["preflight_board_revision"],
        "test_point_id": preflight["preflight_test_point_id"],
        "tty_to_physical_address": {"/dev/ttyS1": 3, "/dev/ttyS2": 2},
        "physical_address_to_tty": {"2": "/dev/ttyS2", "3": "/dev/ttyS1"},
        "reset_gpio_to_tty": {"455": "/dev/ttyS2", "456": "/dev/ttyS1"},
        "absent_physical_address": 1,
        "absent_reset_gpio": 454,
        "unpopulated_uart": "/dev/ttyS3",
        "gpio437_raw_energized": 0,
        "gpio437_raw_safeoff": 1,
        "instrument_sample_count": len(instrument_rows),
        "uart_frame_count": len(uart_rows),
        "dangerous_temp_millic": DANGEROUS_TEMP_MILLIC,
        **preflight,
        **timing,
        **uart_result,
        **physical,
        **reset,
    }
    result["verification_id"] = _hash(canonical_json(result))
    if include_workflow_receipt:
        receipt = _read(
            evidence_dir / WORKFLOW_RECEIPT_FILENAME,
            "native hardware workflow receipt",
            MAX_SMALL_BYTES,
        )
        if receipt != canonical_json(result):
            fail("verification.json is stale, noncanonical, or not freshly reproducible")
    return result


def verify_evidence(
    evidence_dir: Path, *, require_workflow_receipt: bool = True
) -> dict[str, Any]:
    """Verify copied evidence, optionally requiring its canonical result receipt."""
    return _verify_inputs(evidence_dir, include_workflow_receipt=require_workflow_receipt)


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    """Entry point consumed by ``s19k_gauntlet_workflow.py``."""
    return verify_evidence(evidence_dir, require_workflow_receipt=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_workflow_evidence(args.evidence_dir.resolve())
    except (OSError, NativeHardwareError) as error:
        print(f"S19K_NATIVE_HARDWARE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_NATIVE_HARDWARE_OK "
        f"verification_id={result['verification_id']} "
        "authority_granted=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
