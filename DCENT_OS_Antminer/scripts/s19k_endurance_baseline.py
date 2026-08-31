#!/usr/bin/env python3
"""Build one provenance-bound S19k endurance baseline from a verified Phase-3 trial."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Iterable, Mapping

import s19k_bounded_transcript_verify as bounded
import s19k_endurance_verify as endurance
import s19k_no_work_verify as phase12
import s19k_phase3_physical_verify as physical


MIN_PHASE3_METER_SPAN_MS = 60_000
PROVENANCE_FILENAMES = (
    "phase3_plan.kv",
    "phase3_transcript.log",
    "phase3_receipt.kv",
    "phase3_wall_power.csv",
    "phase3_verifier.py",
    "phase3_baseline_builder.py",
    "phase3_host_verification.json",
    "phase3_safeoff_manifest.kv",
    "instrumentation_preflight.kv",
    "phase3_normalization_config.json",
    "phase3_instrument_source.raw",
    "phase3_normalization_receipt",
    "phase3_safeoff.csv",
    "phase3_physical_verifier.py",
    "phase3_safeoff_parser.py",
    "phase3_normalizer.py",
    "phase3_physical_verification.json",
)
PROVENANCE_FIELD_KEYS = (
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
)


class BaselineBuildError(ValueError):
    """The supplied Phase-3 evidence cannot mint an endurance baseline."""


def fail(message: str) -> None:
    raise BaselineBuildError(message)


def sha256_bytes(data: bytes) -> str:
    return endurance.sha256_bytes(data)


def canonical_verification_bytes(result: Mapping[str, object]) -> bytes:
    return (
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _positive(value: int, label: str) -> int:
    if value <= 0:
        fail(f"{label} must be positive")
    return value


def _validate_policy(policy: Mapping[str, int]) -> None:
    hashrate_min = _positive(policy["hashrate_min_millighs"], "hashrate minimum")
    hashrate_max = _positive(policy["hashrate_max_millighs"], "hashrate maximum")
    if hashrate_min >= hashrate_max:
        fail("hashrate baseline band is empty")
    reject_rate = policy["reject_rate_max_ppm"]
    if reject_rate < 0 or reject_rate > 1_000_000:
        fail("reject-rate maximum is outside 0..1000000 ppm")
    wall_min = _positive(policy["wall_power_min_mw"], "wall-power minimum")
    wall_max = _positive(policy["wall_power_max_mw"], "wall-power maximum")
    if wall_min >= wall_max:
        fail("wall-power baseline band is empty")
    safeoff = _positive(
        policy["safeoff_wall_power_max_mw"],
        "SafeOff wall-power maximum",
    )
    if safeoff >= wall_min:
        fail("SafeOff wall-power maximum is not below the energized band")
    warmup = policy["warmup_intervals"]
    if warmup < 0 or warmup > 120:
        fail("warmup interval count is outside 0..120")


def gather_phase3_provenance(
    phase3_plan: Path,
    phase3_trial_dir: Path,
    phase3_wall_power_csv: Path,
    phase3_physical_dir: Path,
    policy: Mapping[str, int],
) -> tuple[dict[str, object], dict[str, bytes]]:
    """Reverify Phase 3 and return canonical baseline fields plus preserved bytes."""
    _validate_policy(policy)
    result = bounded.verify(phase3_plan, phase3_trial_dir)
    if (
        result.get("required_paths") != list(endurance.REQUIRED_PATHS)
        or result.get("accepted_paths") != list(endurance.REQUIRED_PATHS)
    ):
        fail("Phase-3 verification does not prove the exact ttyS1/ttyS2 authority")

    plan_data = endurance.stable_regular_bytes(
        phase3_plan,
        "Phase-3 live plan",
        65_536,
    )
    plan_fields, _ = bounded._parse_kv_bytes(plan_data, "Phase-3 live plan")
    dangerous_temp_millic = phase12._parse_config_dangerous_millic(
        endurance.stable_regular_bytes(
            phase3_trial_dir / "dcentrald_s19k.toml",
            "Phase-3 staged config",
            2 * 1024 * 1024,
        )
    )
    physical_result = physical.verify_evidence(
        phase3_physical_dir,
        plan=plan_fields,
        plan_data=plan_data,
        bounded_result=result,
        dangerous_temp_millic=dangerous_temp_millic,
    )
    receipt_data = endurance.stable_regular_bytes(
        phase3_trial_dir / "runtime_bounded_work_transcript",
        "Phase-3 transcript receipt",
        65_536,
    )
    transcript_name = result.get("transcript_file")
    if not isinstance(transcript_name, str) or not re.fullmatch(
        r"\.startup_daemon_transcript\.[1-9][0-9]*\.[1-9][0-9]*",
        transcript_name,
    ):
        fail("Phase-3 verifier returned a non-canonical transcript filename")
    transcript_data = endurance.stable_regular_bytes(
        phase3_trial_dir / transcript_name,
        "Phase-3 transcript",
        128 * 1024 * 1024,
    )
    meter_rows, meter_data = endurance.load_meter(phase3_wall_power_csv)
    if len(meter_rows) < 2 or meter_rows[-1][0] - meter_rows[0][0] < MIN_PHASE3_METER_SPAN_MS:
        fail("Phase-3 wall-power evidence does not span at least 60 seconds")
    wall_min = policy["wall_power_min_mw"]
    wall_max = policy["wall_power_max_mw"]
    if any(power < wall_min or power > wall_max for _, power in meter_rows):
        fail("Phase-3 wall-power evidence falls outside the predeclared energized band")

    verifier_data = endurance.stable_regular_bytes(
        Path(bounded.__file__).resolve(),
        "Phase-3 independent verifier",
        2 * 1024 * 1024,
    )
    builder_data = endurance.stable_regular_bytes(
        Path(__file__).resolve(),
        "endurance baseline builder",
        2 * 1024 * 1024,
    )
    verification_data = canonical_verification_bytes(result)
    physical_verification_data = canonical_verification_bytes(physical_result)
    verification_id = result.get("verification_id")
    if not isinstance(verification_id, str):
        fail("Phase-3 verifier did not return a verification identifier")
    endurance.require_sha256(verification_id, "Phase-3 verification identifier")
    if (
        result.get("plan_sha256") != sha256_bytes(plan_data)
        or result.get("receipt_sha256") != sha256_bytes(receipt_data)
        or result.get("transcript_sha256") != sha256_bytes(transcript_data)
    ):
        fail("Phase-3 verifier result does not bind the exact retained input bytes")

    physical_verification_id = physical_result.get("verification_id")
    if not isinstance(physical_verification_id, str):
        fail("Phase-3 physical verifier did not return a verification identifier")
    endurance.require_sha256(
        physical_verification_id, "Phase-3 physical verification identifier"
    )
    physical_manifest_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.MANIFEST_FILENAME,
        "Phase-3 physical manifest",
        65_536,
    )
    physical_preflight_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.PREFLIGHT_FILENAME,
        "Phase-3 instrumentation preflight",
        65_536,
    )
    physical_normalization_config_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.NORMALIZATION_CONFIG_FILENAME,
        "Phase-3 physical normalization config",
        1024 * 1024,
    )
    physical_source_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.SOURCE_FILENAME,
        "Phase-3 physical raw instrument export",
        physical.MAX_CAPTURE_BYTES,
    )
    physical_normalization_receipt_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.NORMALIZATION_RECEIPT_FILENAME,
        "Phase-3 physical normalization receipt",
        65_536,
    )
    physical_capture_data = endurance.stable_regular_bytes(
        phase3_physical_dir / physical.CAPTURE_FILENAME,
        "Phase-3 terminal SafeOff capture",
        physical.MAX_CAPTURE_BYTES,
    )
    physical_verifier_data = endurance.stable_regular_bytes(
        Path(physical.__file__).resolve(),
        "Phase-3 physical verifier",
        2 * 1024 * 1024,
    )
    safeoff_parser_data = endurance.stable_regular_bytes(
        Path(phase12.__file__).resolve(),
        "Phase-3 shared SafeOff parser",
        2 * 1024 * 1024,
    )
    normalizer_data = endurance.stable_regular_bytes(
        Path(physical.normalizer.__file__).resolve(),
        "Phase-3 normalization implementation",
        2 * 1024 * 1024,
    )

    files = {
        "phase3_plan.kv": plan_data,
        "phase3_transcript.log": transcript_data,
        "phase3_receipt.kv": receipt_data,
        "phase3_wall_power.csv": meter_data,
        "phase3_verifier.py": verifier_data,
        "phase3_baseline_builder.py": builder_data,
        "phase3_host_verification.json": verification_data,
        "phase3_safeoff_manifest.kv": physical_manifest_data,
        "instrumentation_preflight.kv": physical_preflight_data,
        "phase3_normalization_config.json": physical_normalization_config_data,
        "phase3_instrument_source.raw": physical_source_data,
        "phase3_normalization_receipt": physical_normalization_receipt_data,
        "phase3_safeoff.csv": physical_capture_data,
        "phase3_physical_verifier.py": physical_verifier_data,
        "phase3_safeoff_parser.py": safeoff_parser_data,
        "phase3_normalizer.py": normalizer_data,
        "phase3_physical_verification.json": physical_verification_data,
    }
    fields: dict[str, object] = {
        "phase3_plan_sha256": sha256_bytes(plan_data),
        "phase3_plan_bytes": len(plan_data),
        "phase3_transcript_sha256": sha256_bytes(transcript_data),
        "phase3_transcript_bytes": len(transcript_data),
        "phase3_receipt_sha256": sha256_bytes(receipt_data),
        "phase3_receipt_bytes": len(receipt_data),
        "phase3_wall_power_csv_sha256": sha256_bytes(meter_data),
        "phase3_wall_power_csv_bytes": len(meter_data),
        "phase3_wall_power_sample_count": len(meter_rows),
        "phase3_wall_power_first_unix_ms": meter_rows[0][0],
        "phase3_wall_power_last_unix_ms": meter_rows[-1][0],
        "phase3_verifier_sha256": sha256_bytes(verifier_data),
        "phase3_verifier_bytes": len(verifier_data),
        "phase3_baseline_builder_sha256": sha256_bytes(builder_data),
        "phase3_baseline_builder_bytes": len(builder_data),
        "phase3_host_verification_sha256": sha256_bytes(verification_data),
        "phase3_host_verification_bytes": len(verification_data),
        "phase3_verification_id": verification_id,
        "phase3_safeoff_manifest_sha256": sha256_bytes(physical_manifest_data),
        "phase3_safeoff_manifest_bytes": len(physical_manifest_data),
        "phase3_instrumentation_preflight_sha256": sha256_bytes(physical_preflight_data),
        "phase3_instrumentation_preflight_bytes": len(physical_preflight_data),
        "phase3_normalization_config_sha256": sha256_bytes(
            physical_normalization_config_data
        ),
        "phase3_normalization_config_bytes": len(physical_normalization_config_data),
        "phase3_instrument_source_sha256": sha256_bytes(physical_source_data),
        "phase3_instrument_source_bytes": len(physical_source_data),
        "phase3_normalization_receipt_sha256": sha256_bytes(
            physical_normalization_receipt_data
        ),
        "phase3_normalization_receipt_bytes": len(
            physical_normalization_receipt_data
        ),
        "phase3_safeoff_csv_sha256": sha256_bytes(physical_capture_data),
        "phase3_safeoff_csv_bytes": len(physical_capture_data),
        "phase3_physical_verifier_sha256": sha256_bytes(physical_verifier_data),
        "phase3_physical_verifier_bytes": len(physical_verifier_data),
        "phase3_safeoff_parser_sha256": sha256_bytes(safeoff_parser_data),
        "phase3_safeoff_parser_bytes": len(safeoff_parser_data),
        "phase3_normalizer_sha256": sha256_bytes(normalizer_data),
        "phase3_normalizer_bytes": len(normalizer_data),
        "phase3_physical_verification_sha256": sha256_bytes(physical_verification_data),
        "phase3_physical_verification_bytes": len(physical_verification_data),
        "phase3_physical_verification_id": physical_verification_id,
    }
    return fields, files


def build_baseline_bytes(
    phase3_plan: Path,
    phase3_trial_dir: Path,
    phase3_wall_power_csv: Path,
    phase3_physical_dir: Path,
    policy: Mapping[str, int],
    declared_unix_s: int | None = None,
) -> tuple[bytes, dict[str, bytes]]:
    provenance, files = gather_phase3_provenance(
        phase3_plan,
        phase3_trial_dir,
        phase3_wall_power_csv,
        phase3_physical_dir,
        policy,
    )
    declared = int(time.time()) if declared_unix_s is None else declared_unix_s
    if declared <= 0:
        fail("baseline declaration time must be positive")
    values: list[tuple[str, object]] = [("schema", endurance.BASELINE_SCHEMA)]
    values.extend((key, provenance[key]) for key in PROVENANCE_FIELD_KEYS)
    values.extend((key, policy[key]) for key in (
        "hashrate_min_millighs",
        "hashrate_max_millighs",
        "reject_rate_max_ppm",
        "wall_power_min_mw",
        "wall_power_max_mw",
        "safeoff_wall_power_max_mw",
        "warmup_intervals",
    ))
    values.extend((
        ("autotuner", "disabled"),
        ("declared_before_launch_unix_s", declared),
        ("publication", "no-clobber-hard-link-after-fsync"),
    ))
    data = "".join(f"{key}={value}\n" for key, value in values).encode("ascii")
    endurance.parse_kv_bytes(data, "constructed endurance baseline", endurance.BASELINE_KEYS)
    return data, files


def verify_against_baseline(
    baseline: Mapping[str, str],
    phase3_plan: Path,
    phase3_trial_dir: Path,
    phase3_wall_power_csv: Path,
    phase3_physical_dir: Path,
) -> dict[str, bytes]:
    policy = {
        key: int(baseline[key])
        for key in (
            "hashrate_min_millighs",
            "hashrate_max_millighs",
            "reject_rate_max_ppm",
            "wall_power_min_mw",
            "wall_power_max_mw",
            "safeoff_wall_power_max_mw",
            "warmup_intervals",
        )
    }
    observed, files = gather_phase3_provenance(
        phase3_plan,
        phase3_trial_dir,
        phase3_wall_power_csv,
        phase3_physical_dir,
        policy,
    )
    for key in PROVENANCE_FIELD_KEYS:
        if str(observed[key]) != baseline[key]:
            fail(f"Phase-3 provenance differs from baseline field {key}")
    return files


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        fail("baseline publication requires POSIX directory fsync; run inside WSL/Linux")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _clean_publication_scratch(path: Path) -> None:
    endurance.require_real_directory(path.parent, "endurance baseline parent directory")
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
            fail("endurance baseline has an inexact stale publication scratch")
        if os.path.lexists(path):
            target = os.lstat(path)
            if (
                not stat.S_ISREG(target.st_mode)
                or stat.S_ISLNK(target.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_nlink)
                != (target.st_dev, target.st_ino, 2)
            ):
                fail("endurance baseline scratch is not its target's sole extra link")
        elif metadata.st_nlink != 1:
            fail("unpublished endurance baseline scratch has an inexact link count")
        os.unlink(child)
        changed = True
    if changed:
        _fsync_directory(path.parent)


def publish_new(path: Path, data: bytes) -> None:
    if os.name == "nt":
        fail("baseline publication requires POSIX directory fsync; run inside WSL/Linux")
    _clean_publication_scratch(path)
    if os.path.lexists(path):
        fail(f"baseline output already exists: {path}")
    scratch = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
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
                fail("short write preparing endurance baseline")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(data)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
        ):
            fail("prepared endurance baseline inode is inexact")
        os.link(scratch, path, follow_symlinks=False)
        linked = True
        _fsync_directory(path.parent)
    finally:
        os.close(descriptor)
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass
    if linked:
        _fsync_directory(path.parent)


def _canonical_nonnegative(value: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError("must be canonical unsigned decimal")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase3-plan", type=Path, required=True)
    parser.add_argument("--phase3-trial-dir", type=Path, required=True)
    parser.add_argument("--phase3-wall-power-csv", type=Path, required=True)
    parser.add_argument("--phase3-physical-dir", type=Path, required=True)
    parser.add_argument("--hashrate-min-millighs", type=_canonical_nonnegative, required=True)
    parser.add_argument("--hashrate-max-millighs", type=_canonical_nonnegative, required=True)
    parser.add_argument("--reject-rate-max-ppm", type=_canonical_nonnegative, required=True)
    parser.add_argument("--wall-power-min-mw", type=_canonical_nonnegative, required=True)
    parser.add_argument("--wall-power-max-mw", type=_canonical_nonnegative, required=True)
    parser.add_argument("--safeoff-wall-power-max-mw", type=_canonical_nonnegative, required=True)
    parser.add_argument("--warmup-intervals", type=_canonical_nonnegative, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = {
        "hashrate_min_millighs": args.hashrate_min_millighs,
        "hashrate_max_millighs": args.hashrate_max_millighs,
        "reject_rate_max_ppm": args.reject_rate_max_ppm,
        "wall_power_min_mw": args.wall_power_min_mw,
        "wall_power_max_mw": args.wall_power_max_mw,
        "safeoff_wall_power_max_mw": args.safeoff_wall_power_max_mw,
        "warmup_intervals": args.warmup_intervals,
    }
    try:
        data, _ = build_baseline_bytes(
            args.phase3_plan.resolve(strict=True),
            args.phase3_trial_dir.resolve(strict=True),
            args.phase3_wall_power_csv.resolve(strict=True),
            args.phase3_physical_dir.resolve(strict=True),
            policy,
        )
        publish_new(args.output.resolve(strict=False), data)
    except (
        BaselineBuildError,
        bounded.VerificationError,
        endurance.EnduranceVerificationError,
        physical.PhysicalVerificationError,
        OSError,
    ) as error:
        print(f"S19K_ENDURANCE_BASELINE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_ENDURANCE_BASELINE_OK "
        f"path={args.output} sha256={sha256_bytes(data)} bytes={len(data)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
