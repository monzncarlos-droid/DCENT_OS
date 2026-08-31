#!/usr/bin/env python3
"""Prepare and verify one immutable S19k joined Phase-1/Phase-2 evidence bundle.

This host-only tool performs no network or hardware operation. It freezes ten
operator-supplied preflight/provenance/capture files into fixed names, builds the exact content
manifest, runs the independent semantic verifier, and publishes a completion
receipt last. Run it inside Linux/WSL for real file and directory fsync.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import sys

import s19k_bounded_transcript_verify as common
import s19k_no_work_verify as verifier
import s19k_phase12_capture_verify as raw_capture
import s19k_phase12_normalize as normalizer


FIXED_FILES = verifier.EVIDENCE_FILENAMES
MAX_CANONICAL_BYTES = verifier.MAX_CANONICAL_BYTES


class PreparationError(ValueError):
    """The supplied files cannot form an admitted Phase-1/Phase-2 bundle."""


def fail(message: str) -> None:
    raise PreparationError(message)


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a real non-link directory")


def _source_identity(path: Path, label: str) -> tuple[int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(reparse and getattr(metadata, "st_file_attributes", 0) & reparse)
        or metadata.st_size <= 0
    ):
        fail(f"{label} must be one non-empty real regular non-link file")
    return metadata.st_dev, metadata.st_ino


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            fail("short evidence write")
        offset += written


def _copy_regular(
    source: Path,
    target: Path,
    label: str,
    *,
    expected_identity: tuple[int, int],
    max_bytes: int | None = None,
) -> tuple[str, int]:
    source_path = os.lstat(source)
    source_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    source_fd = -1
    target_fd = -1
    try:
        source_fd = os.open(source, source_flags)
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino)
            != (source_path.st_dev, source_path.st_ino)
            or (before.st_dev, before.st_ino) != expected_identity
        ):
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
            if max_bytes is not None and observed > max_bytes:
                fail(f"{label} exceeds the 64 MiB canonical evidence limit")
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
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
    )
    if before_identity != after_identity or observed != before.st_size:
        fail(f"{label} changed while it was frozen")
    return digest.hexdigest(), observed


def _write_new(path: Path, data: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except OSError as error:
        fail(f"cannot publish staged evidence file {path.name!r}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        fail("evidence bundle publication requires Linux/WSL directory fsync")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _kv_bytes(keys: tuple[str, ...], values: dict[str, str]) -> bytes:
    if set(keys) != set(values) or len(keys) != len(values):
        fail("constructed evidence record has an inexact key set")
    return "".join(f"{key}={values[key]}\n" for key in keys).encode("ascii")


def _publish_bundle(staging: Path, output: Path, filenames: tuple[str, ...]) -> None:
    if os.path.lexists(output):
        fail("evidence output directory already exists; refusing to clobber it")
    os.mkdir(output, 0o700)
    regular = tuple(
        name for name in filenames if name != verifier.BUNDLE_RECEIPT_FILENAME
    )
    for name in regular:
        os.link(staging / name, output / name, follow_symlinks=False)
    _fsync_directory(output)
    os.link(
        staging / verifier.BUNDLE_RECEIPT_FILENAME,
        output / verifier.BUNDLE_RECEIPT_FILENAME,
        follow_symlinks=False,
    )
    _fsync_directory(output)
    _fsync_directory(output.parent)
    for name in filenames:
        os.unlink(staging / name)
    os.rmdir(staging)
    _fsync_directory(output.parent)


def prepare(
    *,
    plan_path: Path,
    trial_dir: Path,
    preflight: Path,
    normalization_config: Path,
    normalization_receipt: Path,
    instrument_source: Path,
    instrument_csv: Path,
    uart_source: Path,
    uart_csv: Path,
    capture_contract: Path,
    capture_blocks: Path,
    capture_verification: Path,
    common_clock_id: str,
    rail_signal: str,
    created_utc: str,
    output_dir: Path,
) -> dict[str, object]:
    if os.name == "nt":
        fail("evidence preparation requires Linux/WSL publication semantics")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", common_clock_id):
        fail("common clock identifier is not a safe evidence token")
    if rail_signal not in ("rail-millivolts", "rail-current-milliamps"):
        fail("rail signal must be rail-millivolts or rail-current-milliamps")
    if not re.fullmatch(
        r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
        created_utc,
    ):
        fail("created UTC is not canonical YYYY-MM-DDTHH:MM:SSZ")

    plan_path = plan_path.absolute()
    trial_dir = trial_dir.absolute()
    sources = {
        "preflight": preflight.absolute(),
        "normalization_config": normalization_config.absolute(),
        "normalization_receipt": normalization_receipt.absolute(),
        "instrument_source": instrument_source.absolute(),
        "instrument_csv": instrument_csv.absolute(),
        "uart_source": uart_source.absolute(),
        "uart_csv": uart_csv.absolute(),
        "capture_contract": capture_contract.absolute(),
        "capture_blocks": capture_blocks.absolute(),
        "capture_verification": capture_verification.absolute(),
    }
    identities = {
        key: _source_identity(path, key.replace("_", " "))
        for key, path in sources.items()
    }
    if len(set(identities.values())) != len(identities):
        fail("preflight, normalization, raw, and canonical inputs must be ten distinct inodes")
    for key in ("instrument_csv", "uart_csv"):
        if sources[key].stat().st_size > MAX_CANONICAL_BYTES:
            fail(f"{key.replace('_', ' ')} exceeds the 64 MiB canonical evidence limit")

    output_parent = output_dir.parent.resolve(strict=True)
    _real_directory(output_parent, "evidence output parent")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", output_dir.name):
        fail("evidence output must be one safe direct-child directory name")
    output = output_parent / output_dir.name
    if os.path.lexists(output):
        fail("evidence output directory already exists; refusing to clobber it")
    staging = output_parent / f".{output.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    os.mkdir(staging, 0o700)

    copied: dict[str, tuple[str, int]] = {}
    for key, source in sources.items():
        copied[key] = _copy_regular(
            source,
            staging / FIXED_FILES[key],
            key.replace("_", " "),
            expected_identity=identities[key],
            max_bytes=MAX_CANONICAL_BYTES if key.endswith("_csv") else None,
        )

    try:
        normalization = normalizer.verify_normalization(
            config_path=staging / FIXED_FILES["normalization_config"],
            instrument_source=staging / FIXED_FILES["instrument_source"],
            uart_source=staging / FIXED_FILES["uart_source"],
            instrument_csv=staging / FIXED_FILES["instrument_csv"],
            uart_csv=staging / FIXED_FILES["uart_csv"],
            receipt_path=staging / FIXED_FILES["normalization_receipt"],
        )
    except normalizer.NormalizationError as error:
        fail(f"capture normalization provenance is invalid: {error}")
    if normalization["common_clock_id"] != common_clock_id:
        fail("common clock identifier does not match the normalization receipt")
    if normalization["rail_signal"] != rail_signal:
        fail("rail signal does not match the normalization receipt")
    try:
        raw_capture_result = raw_capture.verify_files(
            staging / FIXED_FILES["capture_contract"],
            staging / FIXED_FILES["capture_blocks"],
            staging / FIXED_FILES["capture_verification"],
        )
    except raw_capture.CaptureVerificationError as error:
        fail(f"raw per-channel capture provenance is invalid: {error}")
    if raw_capture_result["common_clock_id"] != common_clock_id:
        fail("common clock identifier does not match the raw capture receipt")

    plan_data, plan = common._parse_kv_file(plan_path, "deploy plan")
    verifier._verify_plan(plan)
    receipt_data, receipt = common._parse_kv_file(
        trial_dir / "runtime_handoff_no_work_transcript",
        "handoff-no-work transcript receipt",
        exact_keys=verifier.RECEIPT_KEYS,
    )
    verifier_sha, verifier_bytes = verifier._stable_regular_digest(
        Path(verifier.__file__),
        "host verifier",
    )
    preparer_sha, preparer_bytes = verifier._stable_regular_digest(
        Path(__file__),
        "host evidence preparer",
    )
    normalizer_sha, normalizer_bytes = verifier._stable_regular_digest(
        Path(normalizer.__file__),
        "Phase 1+2 capture normalizer",
    )
    capture_verifier_sha, capture_verifier_bytes = verifier._stable_regular_digest(
        Path(raw_capture.__file__),
        "Phase 1+2 raw capture verifier",
    )
    manifest_values = {
        "schema": verifier.MANIFEST_SCHEMA,
        "claim": "joined-phase1-instrumentation+phase2-handoff-no-work",
        "plan_sha256": common._hash(plan_data),
        "target_receipt_sha256": common._hash(receipt_data),
        "transcript_sha256": common._sha(
            receipt.get("transcript_sha256"),
            "target transcript sha256",
        ),
        "verifier_sha256": verifier_sha,
        "verifier_bytes": str(verifier_bytes),
        "preparer_sha256": preparer_sha,
        "preparer_bytes": str(preparer_bytes),
        "normalizer_sha256": normalizer_sha,
        "normalizer_bytes": str(normalizer_bytes),
        "capture_verifier_sha256": capture_verifier_sha,
        "capture_verifier_bytes": str(capture_verifier_bytes),
        "common_clock_id": common_clock_id,
        "rail_signal": rail_signal,
        "created_utc": created_utc,
        "publication": "post-run-content-manifest",
    }
    for prefix, filename in FIXED_FILES.items():
        manifest_values[f"{prefix}_file"] = filename
        manifest_values[f"{prefix}_sha256"] = copied[prefix][0]
        manifest_values[f"{prefix}_bytes"] = str(copied[prefix][1])
    manifest_data = _kv_bytes(verifier.MANIFEST_KEYS, manifest_values)
    manifest_path = staging / "phase12_instrument_manifest"
    _write_new(manifest_path, manifest_data)

    result = verifier.verify(
        plan_path,
        trial_dir,
        staging,
        require_bundle_complete=False,
    )
    embedded_result_path = staging / verifier.EMBEDDED_RESULT_FILENAME
    verifier._publish_result(embedded_result_path, result)
    result_data = common._stable_regular_bytes(
        embedded_result_path,
        "embedded host verification",
    )
    bundle_values = {
        "schema": verifier.BUNDLE_SCHEMA,
        "instrument_manifest_sha256": common._hash(manifest_data),
        "instrument_manifest_bytes": str(len(manifest_data)),
        "host_verification_sha256": common._hash(result_data),
        "host_verification_bytes": str(len(result_data)),
        "verification_id": str(result["verification_id"]),
        "preparer_sha256": preparer_sha,
        "preparer_bytes": str(preparer_bytes),
        "file_count": str(len(FIXED_FILES) + 3),
        "publication": "host-staged-hard-link-bundle-and-directory-fsync",
    }
    bundle_data = _kv_bytes(verifier.BUNDLE_KEYS, bundle_values)
    _write_new(staging / verifier.BUNDLE_RECEIPT_FILENAME, bundle_data)
    _fsync_directory(staging)
    filenames = (
        *FIXED_FILES.values(),
        "phase12_instrument_manifest",
        verifier.EMBEDDED_RESULT_FILENAME,
        verifier.BUNDLE_RECEIPT_FILENAME,
    )
    _publish_bundle(staging, output, filenames)
    final = verifier.verify(plan_path, trial_dir, output)
    if final != result:
        fail("published evidence bundle differs from its staged semantic verification")
    return final


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--trial-dir", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--normalization-config", required=True, type=Path)
    parser.add_argument("--normalization-receipt", required=True, type=Path)
    parser.add_argument("--instrument-source", required=True, type=Path)
    parser.add_argument("--instrument-csv", required=True, type=Path)
    parser.add_argument("--uart-source", required=True, type=Path)
    parser.add_argument("--uart-csv", required=True, type=Path)
    parser.add_argument("--capture-contract", required=True, type=Path)
    parser.add_argument("--capture-blocks", required=True, type=Path)
    parser.add_argument("--capture-verification", required=True, type=Path)
    parser.add_argument("--common-clock-id", required=True)
    parser.add_argument(
        "--rail-signal",
        required=True,
        choices=("rail-millivolts", "rail-current-milliamps"),
    )
    parser.add_argument("--created-utc", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare(
            plan_path=args.plan,
            trial_dir=args.trial_dir,
            preflight=args.preflight,
            normalization_config=args.normalization_config,
            normalization_receipt=args.normalization_receipt,
            instrument_source=args.instrument_source,
            instrument_csv=args.instrument_csv,
            uart_source=args.uart_source,
            uart_csv=args.uart_csv,
            capture_contract=args.capture_contract,
            capture_blocks=args.capture_blocks,
            capture_verification=args.capture_verification,
            common_clock_id=args.common_clock_id,
            rail_signal=args.rail_signal,
            created_utc=args.created_utc,
            output_dir=args.output_dir,
        )
    except (OSError, PreparationError, verifier.VerificationError) as error:
        print(f"S19K_PHASE12_BUNDLE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_PHASE12_NO_WORK_OK "
        f"verification_id={result['verification_id']} "
        f"transcript_sha256={result['transcript_sha256']} "
        f"rail_decay_confirmed_ms={result['rail_decay_confirmed_ms']} "
        f"uart_work_frame_count={result['uart_work_frame_count']}"
    )
    print(
        "S19K_PHASE12_BUNDLE_OK "
        f"verification_id={result['verification_id']} "
        f"bundle_schema={verifier.BUNDLE_SCHEMA}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
