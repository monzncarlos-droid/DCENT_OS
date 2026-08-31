#!/usr/bin/env python3
"""Verify two secret-safe Nano 3 persistence snapshots from distinct boots."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Optional


MAX_SNAPSHOT_BYTES = 16 * 1024
PAIR_DIGEST_DOMAIN = b"DCENT-NANO3-PERSISTENCE-PAIR-V1\0"
SCHEMA = "dcent-nano3-persistence-snapshot-v1"
FIELD_ORDER = (
    "schema",
    "scope",
    "phase",
    "run_id",
    "boot_id",
    "data_mount_device",
    "data_mount_type",
    "data_mount_identity",
    "data_mtd_num",
    "data_volume_name",
    "readiness_marker",
    "systemcfg_bytes",
    "systemcfg_sha256",
    "systemcfg_structure_sha256",
    "systemcfg_mode",
    "systemcfg_owner",
    "cgminer_bytes",
    "cgminer_sha256",
    "cgminer_structure_sha256",
    "cgminer_mode",
    "cgminer_owner",
    "configuration_values_printed",
    "snapshot_complete",
    "authorizes_device",
    "authorizes_reboot",
    "authorizes_transmit",
    "authorizes_energization",
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]*\Z")
MODE = re.compile(r"[0-7]{3,4}\Z")
OWNER = re.compile(r"[0-9]+:[0-9]+\Z")


class PersistenceSnapshotError(ValueError):
    """A snapshot or pair violates the closed persistence contract."""


def _reject_windows_device_path(path: Path) -> None:
    display = str(path).replace("/", "\\")
    if display.startswith(("\\\\.\\", "\\\\?\\", "\\??\\")):
        raise PersistenceSnapshotError("snapshot path uses a device namespace")
    reserved = {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    reserved.update(f"COM{number}" for number in range(1, 10))
    reserved.update(f"LPT{number}" for number in range(1, 10))
    for component in re.split(r"[\\/]", str(path)):
        stem = component.rstrip(" .").split(".", 1)[0].upper()
        if stem in reserved:
            raise PersistenceSnapshotError("snapshot path uses a reserved device name")


def read_regular_bounded(path: Path) -> bytes:
    """Read one bounded regular, non-symlink file without echoing its content."""

    _reject_windows_device_path(path)
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise PersistenceSnapshotError("snapshot path is unavailable") from exc
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise PersistenceSnapshotError("snapshot input must be a regular non-symlink file")
    if path_metadata.st_size > MAX_SNAPSHOT_BYTES:
        raise PersistenceSnapshotError("snapshot exceeds the bounded input limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PersistenceSnapshotError("snapshot could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PersistenceSnapshotError("opened snapshot is not a regular file")
        if (path_metadata.st_dev, path_metadata.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise PersistenceSnapshotError("snapshot path changed while it was opened")
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_SNAPSHOT_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_SNAPSHOT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_SNAPSHOT_BYTES:
            raise PersistenceSnapshotError("snapshot exceeds the bounded input limit")
        finished = os.fstat(descriptor)
        finished_identity = (
            finished.st_dev,
            finished.st_ino,
            finished.st_mode,
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
        )
        if finished_identity != opened_identity or total != opened.st_size:
            raise PersistenceSnapshotError("snapshot changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_snapshot(raw: bytes) -> dict[str, str]:
    """Parse one exact-order snapshot without returning unrecognized content."""

    if not raw or len(raw) > MAX_SNAPSHOT_BYTES:
        raise PersistenceSnapshotError("snapshot size is outside the accepted range")
    if b"\r" in raw or not raw.endswith(b"\n"):
        raise PersistenceSnapshotError("snapshot newline encoding is not canonical")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PersistenceSnapshotError("snapshot is not strict UTF-8") from exc
    lines = text[:-1].split("\n")
    if len(lines) != len(FIELD_ORDER):
        raise PersistenceSnapshotError("snapshot field count is not canonical")

    parsed: dict[str, str] = {}
    for line_number, (line, expected_name) in enumerate(zip(lines, FIELD_ORDER), 1):
        name, separator, value = line.partition("=")
        if separator != "=" or name != expected_name or not value:
            raise PersistenceSnapshotError(
                f"snapshot field {line_number} is absent, reordered, or malformed"
            )
        parsed[name] = value

    exact = {
        "schema": SCHEMA,
        "scope": "read-only-structure-and-digest",
        "data_mount_device": "/dev/ubi2_0",
        "data_mount_type": "ubifs",
        "data_mount_identity": "ubi2_0:ubifs",
        "data_mtd_num": "12",
        "data_volume_name": "ubi_data_part",
        "readiness_marker": "exact-directory",
        "configuration_values_printed": "false",
        "snapshot_complete": "1",
        "authorizes_device": "false",
        "authorizes_reboot": "false",
        "authorizes_transmit": "false",
        "authorizes_energization": "false",
    }
    for name, expected in exact.items():
        if parsed[name] != expected:
            raise PersistenceSnapshotError(f"snapshot fixed field {name} changed")
    if parsed["phase"] not in {"pre-reboot", "post-reboot"}:
        raise PersistenceSnapshotError("snapshot phase is not admitted")
    if not HEX64.fullmatch(parsed["run_id"]):
        raise PersistenceSnapshotError("snapshot run ID is not canonical")
    if not BOOT_ID.fullmatch(parsed["boot_id"]):
        raise PersistenceSnapshotError("snapshot boot ID is not canonical")

    for prefix in ("systemcfg", "cgminer"):
        if not POSITIVE_DECIMAL.fullmatch(parsed[f"{prefix}_bytes"]):
            raise PersistenceSnapshotError(f"{prefix} size is not canonical")
        size = int(parsed[f"{prefix}_bytes"])
        if size > 65536:
            raise PersistenceSnapshotError(f"{prefix} exceeds the config size ceiling")
        for suffix in ("sha256", "structure_sha256"):
            if not HEX64.fullmatch(parsed[f"{prefix}_{suffix}"]):
                raise PersistenceSnapshotError(f"{prefix} digest is not canonical")
        if not MODE.fullmatch(parsed[f"{prefix}_mode"]):
            raise PersistenceSnapshotError(f"{prefix} mode is not canonical")
        if not OWNER.fullmatch(parsed[f"{prefix}_owner"]):
            raise PersistenceSnapshotError(f"{prefix} owner is not canonical")
    return parsed


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_pair(before_raw: bytes, after_raw: bytes) -> dict[str, str]:
    """Verify exact persistence across two distinct boot IDs."""

    before = parse_snapshot(before_raw)
    after = parse_snapshot(after_raw)
    if before["phase"] != "pre-reboot" or after["phase"] != "post-reboot":
        raise PersistenceSnapshotError("snapshot phases are not pre then post")
    if before["run_id"] != after["run_id"]:
        raise PersistenceSnapshotError("snapshot run IDs do not match")
    if before["boot_id"] == after["boot_id"]:
        raise PersistenceSnapshotError("snapshots do not prove distinct boots")

    stable_fields = (
        "data_mount_device",
        "data_mount_type",
        "data_mount_identity",
        "data_mtd_num",
        "data_volume_name",
        "readiness_marker",
        "systemcfg_bytes",
        "systemcfg_sha256",
        "systemcfg_structure_sha256",
        "systemcfg_mode",
        "systemcfg_owner",
        "cgminer_bytes",
        "cgminer_sha256",
        "cgminer_structure_sha256",
        "cgminer_mode",
        "cgminer_owner",
    )
    for name in stable_fields:
        if before[name] != after[name]:
            raise PersistenceSnapshotError(f"persistent field {name} changed across boots")

    pair_hasher = hashlib.sha256()
    pair_hasher.update(PAIR_DIGEST_DOMAIN)
    pair_hasher.update(len(before_raw).to_bytes(8, "little"))
    pair_hasher.update(before_raw)
    pair_hasher.update(len(after_raw).to_bytes(8, "little"))
    pair_hasher.update(after_raw)
    return {
        "before_snapshot_sha256": _sha256(before_raw),
        "after_snapshot_sha256": _sha256(after_raw),
        "pair_digest": pair_hasher.hexdigest(),
        "run_id": before["run_id"],
        "before_boot_id": before["boot_id"],
        "after_boot_id": after["boot_id"],
        "systemcfg_bytes": before["systemcfg_bytes"],
        "systemcfg_sha256": before["systemcfg_sha256"],
        "systemcfg_structure_sha256": before["systemcfg_structure_sha256"],
        "cgminer_bytes": before["cgminer_bytes"],
        "cgminer_sha256": before["cgminer_sha256"],
        "cgminer_structure_sha256": before["cgminer_structure_sha256"],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        before_raw = read_regular_bounded(args.before)
        after_raw = read_regular_bounded(args.after)
        report = verify_pair(before_raw, after_raw)
    except PersistenceSnapshotError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    for name in (
        "before_snapshot_sha256",
        "after_snapshot_sha256",
        "pair_digest",
        "run_id",
        "before_boot_id",
        "after_boot_id",
        "systemcfg_bytes",
        "systemcfg_sha256",
        "systemcfg_structure_sha256",
        "cgminer_bytes",
        "cgminer_sha256",
        "cgminer_structure_sha256",
    ):
        print(f"{name}={report[name]}")
    print("persistence_contract=pass")
    print("snapshot_provenance=operator-supplied-unsigned")
    print("configuration_values_printed=false")
    print("authorizes_device=false")
    print("authorizes_reboot=false")
    print("authorizes_transmit=false")
    print("authorizes_energization=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
