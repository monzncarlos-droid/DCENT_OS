#!/usr/bin/env python3
"""Verify a 24-hour native S19k run, fault matrix, and terminal SafeOff."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import s19k_native_bounded_verify as bounded
import s19k_native_live_common as common


SCHEMA = "dcentos.s19k-native-endurance-capture/v1"
RESULT_SCHEMA = "dcentos.s19k-native-endurance-verification/v1"
PHASE = "native-endurance"
FILES = (
    "bounded-verification.json",
    "observations.csv",
    "wall-power.csv",
    "faults.csv",
    "terminal-safety.csv",
)
EXTRA_KEYS = (
    "target_identity_sha256",
    "artifact_sha256",
    "owner_verification_sha256",
    "hardware_verification_sha256",
    "bounded_verification_id",
    "bounded_verification_sha256",
    "required_duration_ms",
    "maximum_observation_gap_ms",
    "dangerous_temp_millic",
    "rail_off_max",
    "safeoff_wall_power_max_mw",
)
OBSERVATION_HEADER = (
    "monotonic_ms",
    "path",
    "accepted_total",
    "rejected_total",
    "hashrate_ths_x100",
    "temp_millic",
    "fan0_rpm",
    "fan1_rpm",
    "fan2_rpm",
    "fan3_rpm",
)
WALL_HEADER = ("wall_unix_ms", "event", "power_mw")
FAULT_HEADER = (
    "fault_id",
    "trial_id",
    "outcome",
    "safeoff_verified",
    "recovery_verified",
    "persistent_mutation",
)
REQUIRED_FAULTS = {
    "uart-silence-ttyS1",
    "uart-silence-ttyS2",
    "sensor-stale",
    "fan-loss",
    "overtemperature",
    "daemon-exit",
    "watchdog-expiry",
}


def _observations(
    path: Path, *, required_duration: int, maximum_gap: int, dangerous: int
) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, OBSERVATION_HEADER, "native endurance observations")
    by_path: dict[str, list[tuple[int, int, int]]] = {item: [] for item in common.UART_PATHS}
    total_rejected = 0
    for number, row in enumerate(rows, 2):
        timestamp = common.csv_uint(row[0], f"observation row {number} timestamp")
        uart_path = row[1]
        if uart_path not in common.UART_PATHS:
            common.fail("native endurance observation names an inadmissible UART")
        accepted = common.csv_uint(row[2], f"observation row {number} accepted")
        rejected = common.csv_uint(row[3], f"observation row {number} rejected")
        hashrate = common.csv_uint(row[4], f"observation row {number} hashrate", positive=True)
        temperature = common.csv_int(row[5], f"observation row {number} temperature")
        fans = tuple(common.csv_uint(value, f"observation row {number} fan") for value in row[6:10])
        if not -40_000 <= temperature < dangerous:
            common.fail("native endurance temperature is unsafe or implausible")
        if any(rpm < 1_000 for rpm in fans):
            common.fail("native endurance observation lacks all four cooling channels")
        if hashrate == 0:
            common.fail("native endurance observation contains zero hashrate")
        by_path[uart_path].append((timestamp, accepted, rejected))
        total_rejected += rejected
    starts: list[int] = []
    ends: list[int] = []
    final_accepted: dict[str, int] = {}
    for uart_path, samples in by_path.items():
        if len(samples) < 5:
            common.fail(f"native endurance lacks enough samples for {uart_path}")
        if any(right[0] <= left[0] or right[0] - left[0] > maximum_gap for left, right in zip(samples, samples[1:])):
            common.fail(f"native endurance sampling is discontinuous for {uart_path}")
        if any(right[1] < left[1] or right[2] < left[2] for left, right in zip(samples, samples[1:])):
            common.fail("native endurance share counters decreased")
        duration = samples[-1][0] - samples[0][0]
        if duration < required_duration:
            common.fail(f"native endurance duration is short for {uart_path}")
        quarter = required_duration // 4
        for index in range(4):
            lower = samples[0][0] + index * quarter
            upper = samples[0][0] + (index + 1) * quarter
            window = [sample for sample in samples if lower <= sample[0] <= upper]
            if len(window) < 2 or window[-1][1] <= window[0][1]:
                common.fail(f"native endurance lacks accepted-share progress in quarter {index + 1} on {uart_path}")
        starts.append(samples[0][0])
        ends.append(samples[-1][0])
        final_accepted[uart_path] = samples[-1][1]
    if max(starts) - min(starts) > maximum_gap or max(ends) - min(ends) > maximum_gap:
        common.fail("native endurance UART observation windows are not joined")
    return data, {
        "observation_count": len(rows),
        "endurance_start_ms": max(starts),
        "endurance_end_ms": min(ends),
        "verified_duration_ms": min(ends) - max(starts),
        "accepted_total_by_path": final_accepted,
        "reported_rejected_counter_sum": total_rejected,
    }


def _wall_power(path: Path, *, duration: int, maximum_gap: int, safeoff_max: int) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, WALL_HEADER, "native endurance wall-power capture")
    parsed: list[tuple[int, str, int]] = []
    for number, row in enumerate(rows, 2):
        timestamp = common.csv_uint(row[0], f"wall-power row {number} timestamp", positive=True)
        if row[1] not in ("run-start", "sample", "safeoff", "terminal"):
            common.fail("native endurance wall-power event is invalid")
        power = common.csv_uint(row[2], f"wall-power row {number} power")
        parsed.append((timestamp, row[1], power))
    if any(right[0] <= left[0] or right[0] - left[0] > maximum_gap for left, right in zip(parsed, parsed[1:])):
        common.fail("native endurance wall-power capture is discontinuous")
    starts = [row for row in parsed if row[1] == "run-start"]
    cuts = [row for row in parsed if row[1] == "safeoff"]
    terminals = [row for row in parsed if row[1] == "terminal"]
    if not (len(starts) == len(cuts) == len(terminals) == 1 and starts[0][0] < cuts[0][0] < terminals[0][0]):
        common.fail("native endurance wall-power capture lacks one start/SafeOff/terminal chain")
    if cuts[0][0] - starts[0][0] < duration:
        common.fail("independent wall-power duration is short")
    after = [row for row in parsed if row[0] >= cuts[0][0] and row[2] <= safeoff_max]
    if len(after) < 2 or after[-1][0] - after[0][0] < 5_000:
        common.fail("independent post-SafeOff wall power is not confirmed low")
    return data, {
        "wall_power_sample_count": len(parsed),
        "wall_power_start_unix_ms": starts[0][0],
        "wall_power_safeoff_unix_ms": cuts[0][0],
        "wall_power_terminal_unix_ms": terminals[0][0],
        "safeoff_wall_power_low_samples": len(after),
    }


def _faults(path: Path) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, FAULT_HEADER, "native endurance fault matrix")
    seen: set[str] = set()
    trial_ids: set[str] = set()
    for number, row in enumerate(rows, 2):
        fault_id, trial_id, outcome, safeoff, recovery, persistent = row
        if fault_id not in REQUIRED_FAULTS or fault_id in seen:
            common.fail("native endurance fault matrix is incomplete or duplicated")
        common.token(trial_id, f"fault row {number} trial_id")
        if trial_id in trial_ids:
            common.fail("native endurance fault trials are not independent")
        if (outcome, safeoff, recovery, persistent) != ("controlled-safeoff", "true", "true", "false"):
            common.fail("native endurance fault did not prove SafeOff and recovery without mutation")
        seen.add(fault_id)
        trial_ids.add(trial_id)
    if seen != REQUIRED_FAULTS:
        common.fail("native endurance fault matrix is incomplete")
    return data, {"fault_count": len(seen), "verified_faults": sorted(seen)}


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
        "bounded_verification_id",
        "bounded_verification_sha256",
    ):
        common.digest(manifest[key], key)
    bounded_data = payload["bounded-verification.json"]
    if common.sha256(bounded_data) != manifest["bounded_verification_sha256"]:
        common.fail("native bounded receipt hash does not match the manifest")
    bounded_receipt = common.validate_embedded_receipt(bounded_data, "native bounded receipt")
    bounded_id = common.verify_receipt_id(bounded_receipt, "native bounded receipt")
    if bounded_receipt.get("schema") != "dcentos.s19k-native-bounded-verification/v1" or bounded_id != manifest["bounded_verification_id"]:
        common.fail("native bounded receipt identity or schema mismatch")
    for key in (
        "target_identity_sha256",
        "artifact_sha256",
        "owner_verification_sha256",
        "hardware_verification_sha256",
    ):
        if bounded_receipt.get(key) != manifest[key]:
            common.fail(f"native endurance capture does not preserve bounded {key}")
    duration = common.canonical_uint(manifest["required_duration_ms"], "required duration", positive=True)
    gap = common.canonical_uint(manifest["maximum_observation_gap_ms"], "maximum observation gap", positive=True)
    dangerous = common.canonical_uint(manifest["dangerous_temp_millic"], "dangerous temperature", positive=True)
    rail_off_max = common.canonical_uint(manifest["rail_off_max"], "rail_off_max")
    wall_safeoff = common.canonical_uint(manifest["safeoff_wall_power_max_mw"], "safeoff wall-power limit", positive=True)
    if duration != 86_400_000 or not 1_000 <= gap <= 60_000 or not 40_000 <= dangerous <= 100_000:
        common.fail("native endurance duration/gap/temperature contract is inexact")
    _, observations = _observations(evidence_dir / "observations.csv", required_duration=duration, maximum_gap=gap, dangerous=dangerous)
    _, wall = _wall_power(evidence_dir / "wall-power.csv", duration=duration, maximum_gap=gap, safeoff_max=wall_safeoff)
    _, faults = _faults(evidence_dir / "faults.csv")
    _, terminal = bounded._terminal_safety(evidence_dir / "terminal-safety.csv", rail_off_max)
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "claim": "24-hour native dual-UART endurance, complete controlled-fault closure, and checked terminal SafeOff",
        "run_id": manifest["run_id"],
        "common_clock_id": manifest["common_clock_id"],
        "target_identity_sha256": manifest["target_identity_sha256"],
        "artifact_sha256": manifest["artifact_sha256"],
        "owner_verification_sha256": manifest["owner_verification_sha256"],
        "hardware_verification_sha256": manifest["hardware_verification_sha256"],
        "bounded_verification_id": bounded_id,
        "capture_manifest_sha256": common.sha256(manifest_data),
        "persistent_mutation": False,
        **observations,
        **wall,
        **faults,
        **terminal,
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
        print(f"S19K_NATIVE_ENDURANCE_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(common.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
