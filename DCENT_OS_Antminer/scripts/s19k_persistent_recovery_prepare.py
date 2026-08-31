#!/usr/bin/env python3
"""Freeze one copied S19k persistent-recovery rehearsal into a verifiable bundle.

This host-only tool performs no network or hardware operation. It freezes the
operator-copied rehearsal capture -- the mutation authority, device identity,
offset-exact backup manifest, rehearsal, and independent-witness records, the
captured ``/proc/mtd`` table, the duplicate ``nanddump --padbad`` backup and
restored-readback partition leaves, and the held Bitmain-signed stock BMU --
into the exact layout the persistent-recovery verifier admits. It derives the
partition-layout leaf from the pinned global offset map plus the captured
table (there is no layout flag to get wrong), mints the post-rehearsal content
manifest, runs the independent verifier, and publishes the receipt last. Run it
inside Linux/WSL for real file and directory fsync. A published bundle is
recovery evidence only: it never grants mutation or persistent-install
authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Callable, Dict, Mapping, Sequence, Tuple

import s19k_persistent_recovery_verify as verifier


BUNDLE_PUBLICATION = "host-staged-hard-link-bundle-and-directory-fsync"
LEAF_DIRECTORIES = (verifier.BACKUP_DIR, verifier.READBACK_DIR)


class PreparationError(ValueError):
    """The supplied capture cannot form an admitted recovery bundle."""

    def __init__(self, message: str) -> None:
        super().__init__(f"refusing to prepare recovery evidence: {message}")


def fail(message: str) -> None:
    raise PreparationError(message)


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a real non-link directory")


def _leaf_directory_shape(
    directory: Path, label: str, partitions: Sequence[verifier.PartitionSpec]
) -> None:
    _real_directory(directory, label)
    wanted = {part.backup_name for part in partitions}
    found = {child.name for child in directory.iterdir()}
    if found != wanted:
        fail(
            f"{label} entry set is inexact: "
            f"missing={sorted(wanted - found)} extra={sorted(found - wanted)}"
        )


def _source_leaf(
    path: Path, label: str, *, exact_bytes: int | None, maximum: int
) -> Tuple[int, int]:
    """Require one stable regular single-link input leaf and return its inode."""
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        fail(f"{label} must be one non-empty real regular single-link file")
    if exact_bytes is not None:
        if metadata.st_size != exact_bytes:
            fail(
                f"{label} is {metadata.st_size} bytes; the admitted contract "
                f"requires exactly {exact_bytes}"
            )
    elif metadata.st_size > maximum:
        fail(f"{label} exceeds the {maximum}-byte bounded-input limit")
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
    expected_identity: Tuple[int, int],
    exact_bytes: int | None = None,
    maximum: int,
) -> Tuple[str, int]:
    source_stat = os.lstat(source)
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
            != (source_stat.st_dev, source_stat.st_ino)
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
            if observed > maximum:
                fail(f"{label} exceeds the {maximum}-byte bounded-input limit")
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
        before.st_dev, before.st_ino, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns, before.st_mode,
    )
    after_identity = (
        after.st_dev, after.st_ino, after.st_size,
        after.st_mtime_ns, after.st_ctime_ns, after.st_mode,
    )
    if before_identity != after_identity or observed != before.st_size:
        fail(f"{label} changed while it was frozen")
    if exact_bytes is not None and observed != exact_bytes:
        fail(
            f"{label} froze {observed} bytes; the admitted contract "
            f"requires exactly {exact_bytes}"
        )
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


def _derive_layout(
    *,
    session_id: str,
    device_id: str,
    proc_mtd: bytes,
    partitions: Sequence[verifier.PartitionSpec],
) -> bytes:
    """Mint the exact partition-layout leaf from pinned geometry + capture."""
    layout = {
        "schema": verifier.LAYOUT_SCHEMA,
        "session_id": session_id,
        "device_id": device_id,
        "source": "captured-proc-mtd-plus-global-offset-map",
        "proc_mtd_file": verifier.PROC_MTD_FILE,
        "proc_mtd_sha256": hashlib.sha256(proc_mtd).hexdigest(),
        "nand_total_bytes": partitions[-1].offset + partitions[-1].size,
        "holes": verifier._holes(partitions),
        "partitions": [
            {
                "index": part.index,
                "name": part.name,
                "device": f"mtd{part.index}",
                "offset": part.offset,
                "bytes": part.size,
                "erasesize": part.erasesize,
            }
            for part in partitions
        ],
    }
    return verifier.canonical_json(layout)


def _publish_bundle(
    staging: Path, output: Path, leaf_names: Sequence[str]
) -> None:
    if os.path.lexists(output):
        fail("evidence output directory already exists; refusing to clobber it")
    os.mkdir(output, 0o700)
    for directory in LEAF_DIRECTORIES:
        os.mkdir(output / directory, 0o700)
    for name in leaf_names:
        os.link(staging / name, output / name, follow_symlinks=False)
    for directory in LEAF_DIRECTORIES:
        _fsync_directory(output / directory)
    _fsync_directory(output)
    _fsync_directory(output.parent)
    for name in leaf_names:
        os.unlink(staging / name)
    for directory in LEAF_DIRECTORIES:
        os.rmdir(staging / directory)
    os.rmdir(staging)
    _fsync_directory(output.parent)


def prepare(
    *,
    authority_path: Path,
    device_identity_path: Path,
    backup_manifest_path: Path,
    rehearsal_path: Path,
    witness_path: Path,
    proc_mtd_path: Path,
    backup_dir: Path,
    readback_dir: Path,
    stock_bmu_path: Path,
    output_dir: Path,
    partitions: Sequence[verifier.PartitionSpec] | None = None,
    stock: verifier.StockBmuContract | None = None,
    stock_verifier: Callable[
        [Path, verifier.StockBmuContract], Mapping[str, Any]
    ] | None = None,
) -> Dict[str, Any]:
    if os.name == "nt":
        fail("evidence preparation requires Linux/WSL publication semantics")
    if partitions is None:
        partitions = verifier.PARTITIONS
    if stock is None:
        stock = verifier.STOCK_BMU
    if stock_verifier is None:
        stock_verifier = verifier.verify_signed_stock_bmu
    verifier._validate_static_contract(partitions, stock)

    json_sources = {
        "authority": authority_path.absolute(),
        "device_identity": device_identity_path.absolute(),
        "backup_manifest": backup_manifest_path.absolute(),
        "rehearsal": rehearsal_path.absolute(),
        "independent_witness": witness_path.absolute(),
    }
    staged_json_names = {
        "authority": verifier.AUTHORITY_FILE,
        "device_identity": verifier.DEVICE_FILE,
        "backup_manifest": verifier.BACKUP_FILE,
        "rehearsal": verifier.REHEARSAL_FILE,
        "independent_witness": verifier.WITNESS_FILE,
    }
    proc_mtd_source = proc_mtd_path.absolute()
    stock_source = stock_bmu_path.absolute()
    backup_source = backup_dir.absolute()
    readback_source = readback_dir.absolute()

    _leaf_directory_shape(backup_source, "raw backup directory", partitions)
    _leaf_directory_shape(
        readback_source, "raw restored-readback directory", partitions
    )

    identities: Dict[str, Tuple[int, int]] = {}
    for key, path in json_sources.items():
        identities[key] = _source_leaf(
            path, key.replace("_", " "), exact_bytes=None,
            maximum=verifier.MAX_JSON_BYTES,
        )
    identities["proc_mtd"] = _source_leaf(
        proc_mtd_source, "captured proc_mtd table", exact_bytes=None,
        maximum=verifier.MAX_JSON_BYTES,
    )
    identities["stock_bmu"] = _source_leaf(
        stock_source, "held signed stock BMU", exact_bytes=stock.size,
        maximum=stock.size,
    )
    for part in partitions:
        for directory, label in (
            (backup_source, "backup"), (readback_source, "restored readback"),
        ):
            identities[f"{label}:mtd{part.index}"] = _source_leaf(
                directory / part.backup_name,
                f"{label} leaf mtd{part.index}",
                exact_bytes=part.size,
                maximum=part.size,
            )
    if len(set(identities.values())) != len(identities):
        fail("every frozen input leaf must be one distinct single-link inode")

    proc_mtd_bytes = proc_mtd_source.read_bytes()
    if proc_mtd_bytes != verifier._proc_mtd_bytes(partitions):
        fail(
            "captured /proc/mtd does not equal the exact admitted partition "
            "table; refusing to derive the layout leaf"
        )

    output_parent = output_dir.parent.resolve(strict=True)
    _real_directory(output_parent, "evidence output parent")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", output_dir.name) is None:
        fail("evidence output must be one safe direct-child directory name")
    output = output_parent / output_dir.name
    if os.path.lexists(output):
        fail("evidence output directory already exists; refusing to clobber it")
    staging = output_parent / f".{output.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    os.mkdir(staging, 0o700)
    for directory in LEAF_DIRECTORIES:
        os.mkdir(staging / directory, 0o700)

    frozen: Dict[str, Tuple[str, int]] = {}
    for key, source in json_sources.items():
        frozen[staged_json_names[key]] = _copy_regular(
            source, staging / staged_json_names[key], key.replace("_", " "),
            expected_identity=identities[key], maximum=verifier.MAX_JSON_BYTES,
        )
    frozen[verifier.PROC_MTD_FILE] = _copy_regular(
        proc_mtd_source, staging / verifier.PROC_MTD_FILE, "captured proc_mtd",
        expected_identity=identities["proc_mtd"],
        maximum=verifier.MAX_JSON_BYTES,
    )
    if (
        frozen[verifier.PROC_MTD_FILE][0]
        != hashlib.sha256(proc_mtd_bytes).hexdigest()
        or frozen[verifier.PROC_MTD_FILE][1] != len(proc_mtd_bytes)
    ):
        fail("captured /proc/mtd changed between admission and freeze")
    frozen[stock.filename] = _copy_regular(
        stock_source, staging / stock.filename, "held signed stock BMU",
        expected_identity=identities["stock_bmu"], exact_bytes=stock.size,
        maximum=stock.size,
    )
    for part in partitions:
        for source, staged_dir, identity_label in (
            (backup_source, verifier.BACKUP_DIR, "backup"),
            (readback_source, verifier.READBACK_DIR, "restored readback"),
        ):
            name = f"{staged_dir}/{part.backup_name}"
            frozen[name] = _copy_regular(
                source / part.backup_name,
                staging / Path(name),
                f"{staged_dir} leaf mtd{part.index}",
                expected_identity=identities[f"{identity_label}:mtd{part.index}"],
                exact_bytes=part.size,
                maximum=part.size,
            )

    try:
        device_raw = (staging / verifier.DEVICE_FILE).read_bytes()
        device_value = json.loads(device_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"device identity is not canonical ASCII JSON: {error}")
    if not isinstance(device_value, dict) or device_raw != verifier.canonical_json(
        device_value
    ):
        fail("device identity is not canonical JSON")
    session_id = verifier._hex64(
        device_value.get("session_id"), "device identity session_id"
    )
    device_id = verifier._hex64(
        device_value.get("device_id"), "device identity device_id"
    )
    layout_bytes = _derive_layout(
        session_id=session_id,
        device_id=device_id,
        proc_mtd=proc_mtd_bytes,
        partitions=partitions,
    )
    _write_new(staging / verifier.LAYOUT_FILE, layout_bytes)
    frozen[verifier.LAYOUT_FILE] = (
        hashlib.sha256(layout_bytes).hexdigest(), len(layout_bytes)
    )

    contract = {
        "schema": verifier.CONTRACT_SCHEMA,
        "session_id": session_id,
        "claim": "pre-dcentos-write-stock-recovery-rehearsal",
        "publication": "post-rehearsal-content-manifest",
        "dcentos_write_attempted": False,
        "dcentos_write_count": 0,
        "files": {
            name: {"bytes": frozen[name][1], "sha256": frozen[name][0]}
            for name in sorted(verifier._leaf_names(partitions, stock))
        },
    }
    _write_new(staging / verifier.CONTRACT_FILE, verifier.canonical_json(contract))
    for directory in LEAF_DIRECTORIES:
        _fsync_directory(staging / directory)
    _fsync_directory(staging)

    result = verifier.verify_evidence(
        staging,
        partitions=partitions,
        stock=stock,
        stock_verifier=stock_verifier,
    )
    _write_new(
        staging / verifier.VERIFICATION_FILE, verifier.canonical_json(result)
    )
    _fsync_directory(staging)

    leaf_names = [
        *sorted(verifier._leaf_names(partitions, stock)),
        verifier.CONTRACT_FILE,
        verifier.VERIFICATION_FILE,
    ]
    _publish_bundle(staging, output, leaf_names)
    final = verifier.verify_evidence(
        output, partitions=partitions, stock=stock, stock_verifier=stock_verifier
    )
    if final != result:
        fail("published evidence bundle differs from its staged verification")
    return dict(final)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True, type=Path)
    parser.add_argument("--device-identity", required=True, type=Path)
    parser.add_argument("--backup-manifest", required=True, type=Path)
    parser.add_argument("--rehearsal", required=True, type=Path)
    parser.add_argument("--independent-witness", required=True, type=Path)
    parser.add_argument("--proc-mtd", required=True, type=Path)
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--readback-dir", required=True, type=Path)
    parser.add_argument("--stock-bmu", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare(
            authority_path=args.authority,
            device_identity_path=args.device_identity,
            backup_manifest_path=args.backup_manifest,
            rehearsal_path=args.rehearsal,
            witness_path=args.independent_witness,
            proc_mtd_path=args.proc_mtd,
            backup_dir=args.backup_dir,
            readback_dir=args.readback_dir,
            stock_bmu_path=args.stock_bmu,
            output_dir=args.output_dir,
        )
    except (OSError, PreparationError, verifier.PersistentRecoveryError) as error:
        print(f"S19K_PERSISTENT_RECOVERY_BUNDLE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_PERSISTENT_RECOVERY_OK "
        f"verification_id={result['verification_id']} "
        f"session_id={result['session_id']} "
        "mutation_authority_granted=false dcentos_write_authorized=false"
    )
    print(
        "S19K_PERSISTENT_RECOVERY_BUNDLE_OK "
        f"verification_id={result['verification_id']} "
        f"bundle_schema={result['schema']} "
        f"partition_leaf_pairs={len(result['partitions'])} "
        f"publication={BUNDLE_PUBLICATION}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
