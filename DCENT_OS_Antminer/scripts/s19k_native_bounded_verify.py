#!/usr/bin/env python3
"""Verify bounded native S19k work/share evidence and terminal SafeOff."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import s19k_native_live_common as common


SCHEMA = "dcentos.s19k-native-bounded-capture/v1"
RESULT_SCHEMA = "dcentos.s19k-native-bounded-verification/v1"
PHASE = "native-bounded-work"
FILES = (
    "phase12-verification.json",
    "events.csv",
    "terminal-safety.csv",
    "uart.csv",
)
EXTRA_KEYS = (
    "target_identity_sha256",
    "artifact_sha256",
    "owner_verification_sha256",
    "hardware_verification_sha256",
    "phase12_verification_id",
    "phase12_verification_sha256",
    "maximum_runtime_ms",
    "rail_off_max",
)
EVENT_HEADER = ("sequence", "monotonic_ms", "event", "path", "job_id", "value")
SAFETY_HEADER = (
    "monotonic_ms",
    "event",
    "rail_value",
    "gpio437_raw",
    "gpio454_raw",
    "gpio455_raw",
    "gpio456_raw",
    "fan0_rpm",
    "fan1_rpm",
    "fan2_rpm",
    "fan3_rpm",
)


def _events(path: Path, maximum_runtime_ms: int) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, EVENT_HEADER, "native bounded event capture")
    previous = -1
    start: int | None = None
    safeoff: int | None = None
    terminal: int | None = None
    work: dict[str, set[str]] = {path: set() for path in common.UART_PATHS}
    nonce: dict[str, set[str]] = {path: set() for path in common.UART_PATHS}
    accepted: dict[str, set[str]] = {path: set() for path in common.UART_PATHS}
    for index, row in enumerate(rows):
        if common.csv_uint(row[0], f"bounded event row {index + 2} sequence") != index:
            common.fail("native bounded events are not a contiguous zero-based sequence")
        timestamp = common.csv_uint(row[1], f"bounded event row {index + 2} timestamp")
        if timestamp <= previous:
            common.fail("native bounded event timestamps are not strictly increasing")
        previous = timestamp
        event, uart_path, job_id, value = row[2:]
        if event == "bounded-start" and uart_path == "global" and job_id == "none" and value == "600-seconds-maximum":
            if start is not None:
                common.fail("native bounded capture repeats its start")
            start = timestamp
            continue
        if event == "safeoff-begin" and uart_path == "global" and job_id == "none" and value == "checked":
            if safeoff is not None:
                common.fail("native bounded capture repeats SafeOff")
            safeoff = timestamp
            continue
        if event == "owner-terminal" and uart_path == "global" and job_id == "none" and value == "checked":
            if terminal is not None:
                common.fail("native bounded capture repeats terminal ownership")
            terminal = timestamp
            continue
        if uart_path not in common.UART_PATHS:
            common.fail("native bounded event names an inadmissible UART")
        common.token(job_id, "native bounded job_id")
        if event == "work-tx" and value == "captured":
            work[uart_path].add(job_id)
        elif event == "nonce-rx" and value == "captured":
            nonce[uart_path].add(job_id)
        elif event == "pool-accepted" and value == "true":
            accepted[uart_path].add(job_id)
        else:
            common.fail("native bounded capture contains an inadmissible event")
    if start is None or safeoff is None or terminal is None or not start < safeoff < terminal:
        common.fail("native bounded capture lacks one ordered start/SafeOff/terminal chain")
    if safeoff - start > maximum_runtime_ms:
        common.fail("native bounded work exceeded its admitted runtime")
    accepted_job: dict[str, str] = {}
    for uart_path in common.UART_PATHS:
        joined = work[uart_path] & nonce[uart_path] & accepted[uart_path]
        if not joined:
            common.fail(f"native bounded capture lacks an end-to-end accepted share for {uart_path}")
        accepted_job[uart_path] = sorted(joined)[0]
    return data, {
        "bounded_start_ms": start,
        "safeoff_begin_ms": safeoff,
        "owner_terminal_ms": terminal,
        "bounded_runtime_ms": safeoff - start,
        "accepted_share_job_id": accepted_job,
        "accepted_share_paths": list(common.UART_PATHS),
    }


def _terminal_safety(path: Path, rail_off_max: int) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, SAFETY_HEADER, "native bounded terminal safety capture")
    parsed: list[tuple[int, str, int, tuple[int, ...], tuple[int, ...]]] = []
    for number, row in enumerate(rows, 2):
        timestamp = common.csv_uint(row[0], f"terminal safety row {number} timestamp")
        if row[1] not in ("pre-safeoff", "safeoff", "sample", "terminal"):
            common.fail("native bounded safety capture has an invalid event")
        rail = common.csv_uint(row[2], f"terminal safety row {number} rail")
        gpios = tuple(common.csv_uint(value, f"terminal safety row {number} GPIO") for value in row[3:7])
        fans = tuple(common.csv_uint(value, f"terminal safety row {number} fan") for value in row[7:11])
        if any(value not in (0, 1) for value in gpios):
            common.fail("native bounded safety capture has a non-binary GPIO")
        parsed.append((timestamp, row[1], rail, gpios, fans))
    if any(right[0] <= left[0] or right[0] - left[0] > 1_000 for left, right in zip(parsed, parsed[1:])):
        common.fail("native bounded safety capture has a gap over one second")
    pre = [row for row in parsed if row[1] == "pre-safeoff"]
    cut = [row for row in parsed if row[1] == "safeoff"]
    terminal = [row for row in parsed if row[1] == "terminal"]
    if not (len(pre) == len(cut) == len(terminal) == 1 and pre[0][0] < cut[0][0] < terminal[0][0]):
        common.fail("native bounded safety capture lacks one ordered pre/cut/terminal chain")
    if pre[0][3] != (0, 0, 1, 1):
        common.fail("native bounded pre-SafeOff GPIO tuple is wrong")
    after = [row for row in parsed if row[0] >= cut[0][0]]
    if any(row[3] != (1, 0, 0, 0) for row in after):
        common.fail("native bounded terminal GPIOs are not checked SafeOff")
    low = [row for row in after if row[2] <= rail_off_max]
    if len(low) < 2 or low[-1][0] - low[0][0] < 5_000:
        common.fail("native bounded rail decay is not independently confirmed")
    if any(sum(rpm >= 1_000 for rpm in row[4]) != 4 for row in parsed if row[0] <= low[-1][0]):
        common.fail("native bounded capture lost four-channel cooling before rail decay")
    return data, {
        "terminal_safety_sample_count": len(parsed),
        "terminal_gpio437_cut_ms": cut[0][0],
        "terminal_rail_decay_confirmed_ms": low[-1][0],
    }


def verify_evidence(
    evidence_dir: Path, *, require_workflow_receipt: bool = True
) -> dict[str, Any]:
    manifest_data, manifest, payload = common.verify_manifest(
        evidence_dir,
        schema=SCHEMA,
        phase=PHASE,
        payload_files=FILES,
        extra_keys=EXTRA_KEYS,
    )
    for key in (
        "target_identity_sha256",
        "artifact_sha256",
        "owner_verification_sha256",
        "hardware_verification_sha256",
        "phase12_verification_id",
        "phase12_verification_sha256",
    ):
        common.digest(manifest[key], key)
    phase12_data = payload["phase12-verification.json"]
    if common.sha256(phase12_data) != manifest["phase12_verification_sha256"]:
        common.fail("native Phase 1+2 receipt hash does not match the manifest")
    phase12 = common.validate_embedded_receipt(phase12_data, "native Phase 1+2 receipt")
    phase12_id = common.verify_receipt_id(phase12, "native Phase 1+2 receipt")
    if phase12.get("schema") != "dcentos.s19k-native-phase12-verification/v1" or phase12_id != manifest["phase12_verification_id"]:
        common.fail("native Phase 1+2 receipt identity or schema mismatch")
    for key in (
        "target_identity_sha256",
        "artifact_sha256",
        "owner_verification_sha256",
        "hardware_verification_sha256",
    ):
        if phase12.get(key) != manifest[key]:
            common.fail(f"native bounded capture does not preserve Phase 1+2 {key}")
    maximum = common.canonical_uint(manifest["maximum_runtime_ms"], "maximum runtime", positive=True)
    if maximum != 600_000:
        common.fail("native bounded runtime must be exactly 600 seconds maximum")
    rail_off_max = common.canonical_uint(manifest["rail_off_max"], "rail_off_max")
    _, events = _events(evidence_dir / "events.csv", maximum)
    _, safety = _terminal_safety(evidence_dir / "terminal-safety.csv", rail_off_max)
    _, uart = common.parse_uart(evidence_dir / "uart.csv", require_work=True)
    if not events["safeoff_begin_ms"] <= safety["terminal_gpio437_cut_ms"] <= events["owner_terminal_ms"]:
        common.fail("native bounded event/SafeOff clocks do not join")
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "claim": "one end-to-end accepted share per mapped native UART plus checked terminal SafeOff",
        "run_id": manifest["run_id"],
        "common_clock_id": manifest["common_clock_id"],
        "target_identity_sha256": manifest["target_identity_sha256"],
        "artifact_sha256": manifest["artifact_sha256"],
        "owner_verification_sha256": manifest["owner_verification_sha256"],
        "hardware_verification_sha256": manifest["hardware_verification_sha256"],
        "phase12_verification_id": phase12_id,
        "capture_manifest_sha256": common.sha256(manifest_data),
        "persistent_mutation": False,
        **events,
        **safety,
        **uart,
    }
    result = common.add_verification_id(result)
    if require_workflow_receipt:
        common.verify_workflow_receipt(evidence_dir, result)
    return result


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    return verify_evidence(evidence_dir, require_workflow_receipt=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_workflow_evidence(args.evidence_dir.resolve(strict=True))
    except (OSError, common.NativeLiveEvidenceError) as error:
        print(f"S19K_NATIVE_BOUNDED_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(common.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
