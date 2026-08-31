#!/usr/bin/env python3
"""Verify independent Phase-3 terminal SafeOff evidence without hardware contact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping

import s19k_bounded_transcript_verify as common
import s19k_no_work_verify as phase12
import s19k_phase12_normalize as normalizer


SCHEMA = "dcentos.s19k-phase3-physical-manifest/v2"
RESULT_SCHEMA = "dcentos.s19k-phase3-physical-verification/v2"
MANIFEST_FILENAME = "phase3_safeoff_manifest.kv"
PREFLIGHT_FILENAME = "instrumentation_preflight.kv"
NORMALIZATION_CONFIG_FILENAME = "normalization_config.json"
SOURCE_FILENAME = "instrument_source.raw"
NORMALIZATION_RECEIPT_FILENAME = "phase3_normalization_receipt"
CAPTURE_FILENAME = "phase3_safeoff.csv"
MANIFEST_KEYS = (
    "schema",
    "claim",
    "plan_sha256",
    "bounded_verification_id",
    "preflight_file",
    "preflight_sha256",
    "preflight_bytes",
    "normalization_config_file",
    "normalization_config_sha256",
    "normalization_config_bytes",
    "instrument_source_file",
    "instrument_source_sha256",
    "instrument_source_bytes",
    "normalization_receipt_file",
    "normalization_receipt_sha256",
    "normalization_receipt_bytes",
    "capture_file",
    "capture_sha256",
    "capture_bytes",
    "common_clock_id",
    "rail_signal",
    "created_utc",
    "publication",
)
EXPECTED_FILES = {
    MANIFEST_FILENAME,
    PREFLIGHT_FILENAME,
    NORMALIZATION_CONFIG_FILENAME,
    SOURCE_FILENAME,
    NORMALIZATION_RECEIPT_FILENAME,
    CAPTURE_FILENAME,
}
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class PhysicalVerificationError(ValueError):
    """Phase-3 physical evidence did not satisfy the fail-closed contract."""


def fail(message: str) -> None:
    raise PhysicalVerificationError(message)


def _stable(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        fail(f"{label} must be a non-empty bounded regular non-link file")
    data = path.read_bytes()
    after = os.lstat(path)
    identity = lambda value: (  # noqa: E731
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
    )
    if identity(before) != identity(after) or len(data) != before.st_size:
        fail(f"{label} changed while it was read")
    return data


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_evidence(
    evidence_dir: Path,
    *,
    plan: Mapping[str, str],
    plan_data: bytes,
    bounded_result: Mapping[str, object],
    dangerous_temp_millic: int,
) -> dict[str, object]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail("Phase-3 physical evidence directory must be a real directory")
    names = {child.name for child in evidence_dir.iterdir()}
    if names != EXPECTED_FILES:
        fail("Phase-3 physical evidence directory has an inexact entry set")
    manifest_data = _stable(
        evidence_dir / MANIFEST_FILENAME, "Phase-3 physical manifest", 65_536
    )
    manifest, _ = common._parse_kv_bytes(
        manifest_data,
        "Phase-3 physical manifest",
        exact_keys=MANIFEST_KEYS,
    )
    verification_id = bounded_result.get("verification_id")
    if not isinstance(verification_id, str) or not re.fullmatch(
        r"[0-9a-f]{64}", verification_id
    ):
        fail("bounded verifier did not return a canonical verification identifier")
    for key, value in {
        "schema": SCHEMA,
        "claim": "independent-terminal-safeoff-after-bounded-work",
        "plan_sha256": _hash(plan_data),
        "bounded_verification_id": verification_id,
        "preflight_file": PREFLIGHT_FILENAME,
        "normalization_config_file": NORMALIZATION_CONFIG_FILENAME,
        "instrument_source_file": SOURCE_FILENAME,
        "normalization_receipt_file": NORMALIZATION_RECEIPT_FILENAME,
        "capture_file": CAPTURE_FILENAME,
        "publication": "post-run-content-manifest",
    }.items():
        common._require(manifest, key, value, "Phase-3 physical manifest")
    if manifest.get("rail_signal") not in (
        "rail-millivolts",
        "rail-current-milliamps",
    ):
        fail("Phase-3 rail signal is not an independent rail measurement")
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", manifest.get("common_clock_id", "")
    ):
        fail("Phase-3 common clock identifier is not canonical")

    preflight_data = _stable(
        evidence_dir / PREFLIGHT_FILENAME, "Phase-3 instrumentation preflight", 65_536
    )
    normalization_config_data = _stable(
        evidence_dir / NORMALIZATION_CONFIG_FILENAME,
        "Phase-3 normalization config",
        normalizer.MAX_CONFIG_BYTES,
    )
    source_data = _stable(
        evidence_dir / SOURCE_FILENAME,
        "Phase-3 raw instrument export",
        MAX_CAPTURE_BYTES,
    )
    normalization_receipt_data = _stable(
        evidence_dir / NORMALIZATION_RECEIPT_FILENAME,
        "Phase-3 normalization receipt",
        65_536,
    )
    capture_data = _stable(
        evidence_dir / CAPTURE_FILENAME, "Phase-3 SafeOff capture", MAX_CAPTURE_BYTES
    )
    for prefix, data in (
        ("preflight", preflight_data),
        ("normalization_config", normalization_config_data),
        ("instrument_source", source_data),
        ("normalization_receipt", normalization_receipt_data),
        ("capture", capture_data),
    ):
        common._require(
            manifest,
            f"{prefix}_sha256",
            _hash(data),
            "Phase-3 physical manifest",
        )
        common._require(
            manifest,
            f"{prefix}_bytes",
            str(len(data)),
            "Phase-3 physical manifest",
        )
    expected_live_identity_sha256 = bounded_result.get("live_identity_sha256")
    if not isinstance(expected_live_identity_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_live_identity_sha256
    ):
        fail("bounded verifier did not return a canonical live miner identity")
    preflight = phase12._verify_preflight(
        preflight_data,
        plan=dict(plan),
        manifest=manifest,
        expected_live_identity_sha256=expected_live_identity_sha256,
    )
    try:
        normalization = normalizer.verify_instrument_normalization(
            config_path=evidence_dir / NORMALIZATION_CONFIG_FILENAME,
            instrument_source=evidence_dir / SOURCE_FILENAME,
            instrument_csv=evidence_dir / CAPTURE_FILENAME,
            receipt_path=evidence_dir / NORMALIZATION_RECEIPT_FILENAME,
        )
    except normalizer.NormalizationError as error:
        fail(f"Phase-3 capture normalization provenance is invalid: {error}")
    if normalization["common_clock_id"] != manifest["common_clock_id"]:
        fail("Phase-3 normalization common_clock_id does not match the manifest")
    if normalization["rail_signal"] != manifest["rail_signal"]:
        fail("Phase-3 normalization rail_signal does not match the manifest")
    rows, timing = phase12._parse_instrument(
        capture_data,
        dangerous_temp_millic,
        rail_range_min=int(preflight["preflight_expected_range_min"]),
        rail_range_max=int(preflight["preflight_expected_range_max"]),
    )
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "claim": "bounded-work transcript joined to independent continuous terminal SafeOff",
        "plan_sha256": _hash(plan_data),
        "bounded_verification_id": verification_id,
        "manifest_sha256": _hash(manifest_data),
        "preflight_sha256": _hash(preflight_data),
        "normalization_config_sha256": _hash(normalization_config_data),
        "instrument_source_sha256": _hash(source_data),
        "normalization_receipt_sha256": _hash(normalization_receipt_data),
        "normalization_id": normalization["normalization_id"],
        "capture_sha256": _hash(capture_data),
        "capture_sample_count": len(rows),
        "common_clock_id": manifest["common_clock_id"],
        "rail_signal": manifest["rail_signal"],
        **preflight,
        **timing,
    }
    canonical = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    result["verification_id"] = hashlib.sha256(
        (canonical + "\n").encode("ascii")
    ).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--trial-dir", required=True, type=Path)
    parser.add_argument("--physical-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        plan_path = args.plan.resolve(strict=True)
        trial_dir = args.trial_dir.resolve(strict=True)
        bounded_result = common.verify(plan_path, trial_dir)
        plan_data, plan = common._parse_kv_file(plan_path, "Phase-3 live plan")
        config = common._stable_regular_bytes(
            trial_dir / "dcentrald_s19k.toml", "Phase-3 staged config"
        )
        dangerous_temp_millic = phase12._parse_config_dangerous_millic(config)
        result = verify_evidence(
            args.physical_dir.resolve(strict=True),
            plan=plan,
            plan_data=plan_data,
            bounded_result=bounded_result,
            dangerous_temp_millic=dangerous_temp_millic,
        )
    except (OSError, common.VerificationError, PhysicalVerificationError) as error:
        print(f"S19K_PHASE3_PHYSICAL_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(
        (
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
    )
    print(
        "S19K_PHASE3_PHYSICAL_OK "
        f"verification_id={result['verification_id']} "
        f"rail_decay_confirmed_ms={result['rail_decay_confirmed_ms']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
