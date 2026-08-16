#!/usr/bin/env python3
"""Admit and extract one source-defined DCENT_OS AM3-BB SD payload.

The two AM3-BB post-image hooks deliberately emit different package shapes.
This helper binds the caller to one exact board target, validates the complete
outer-tar/member/manifest/checksum contract, and only then publishes regular
files below an empty host directory.  It never opens a block device or grants
install authority.
"""

from __future__ import annotations

import argparse
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from typing import BinaryIO
import zlib


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_UNPACKED_CPIO_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 10
MAX_MANIFEST_BYTES = 256 * 1024
MAX_README_BYTES = 64 * 1024
MAX_CHECKSUM_BYTES = 16 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
ED25519_SIGNATURE_BYTES = 64

_TOKEN = re.compile(r"^[A-Za-z0-9._+:-]+$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._+:/@-]+$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FULL_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


@dataclass(frozen=True)
class _Profile:
    target: str
    prefix: str
    required_payloads: tuple[str, ...]
    optional_payloads: tuple[str, ...]
    payload_order: tuple[str, ...]
    legacy_ramdisk: bool

    @property
    def allowed_files(self) -> frozenset[str]:
        return frozenset(
            self.required_payloads
            + self.optional_payloads
            + (
                "SHA256SUMS",
                "MANIFEST.json",
                "MANIFEST.sig",
                "release_ed25519.pub",
            )
        )


_PROFILES = {
    "am3-bb": _Profile(
        target="am3-bb",
        prefix="dcentos-am3-bb-sdcard",
        required_payloads=("uramdisk.image.gz", "README.txt"),
        optional_payloads=("rootfs.ext2",),
        payload_order=("uramdisk.image.gz", "rootfs.ext2", "README.txt"),
        legacy_ramdisk=False,
    ),
    "am3-bb-s19jpro": _Profile(
        target="am3-bb-s19jpro",
        prefix="dcentos-am3-bb-s19jpro-sdcard",
        required_payloads=("uramdisk.image.gz", "ramdisk.gz", "README.txt"),
        optional_payloads=(),
        payload_order=("uramdisk.image.gz", "ramdisk.gz", "README.txt"),
        legacy_ramdisk=True,
    ),
}

_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "product",
        "family",
        "package_type",
        "board_family",
        "board",
        "board_target",
        "version",
        "created_at_utc",
        "status",
        "provenance",
        "nand_install",
        "payloads",
    }
)
_PROVENANCE_KEYS = frozenset(
    {
        "source_commit",
        "source_tree_state",
        "source_date_epoch",
        "source_commit_epoch",
        "build_target",
        "build_arch",
        "toolchain_id",
    }
)
_PAYLOAD_DESCRIPTOR_KEYS = frozenset({"path", "size", "sha256"})


class PayloadArchiveError(ValueError):
    """The archive is not an exact, bounded AM3-BB payload."""


def _profile(expected_target: str) -> _Profile:
    try:
        return _PROFILES[expected_target]
    except KeyError as exc:
        choices = ", ".join(sorted(_PROFILES))
        raise PayloadArchiveError(
            f"expected target must be one of: {choices}"
        ) from exc


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PayloadArchiveError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise PayloadArchiveError(f"non-finite JSON value is forbidden: {value}")


def _member_parts(name: str) -> tuple[str, ...]:
    if "\\" in name or "\x00" in name:
        raise PayloadArchiveError(f"unsafe archive member name: {name!r}")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise PayloadArchiveError(f"unsafe archive member path: {name!r}")
    if any(part in {"", "."} or ":" in part for part in path.parts):
        raise PayloadArchiveError(f"non-canonical archive member path: {name!r}")
    return path.parts


def _open_regular_archive(path: Path) -> tuple[BinaryIO, os.stat_result]:
    if path.is_symlink():
        raise PayloadArchiveError("payload archive must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PayloadArchiveError(f"cannot open payload archive: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PayloadArchiveError("payload archive must be a regular file")
        if opened.st_nlink != 1:
            raise PayloadArchiveError("payload archive must not have hard-link aliases")
        if opened.st_size <= 0 or opened.st_size > MAX_ARCHIVE_BYTES:
            raise PayloadArchiveError("payload archive size is outside the safety limit")
        return os.fdopen(descriptor, "rb"), opened
    except Exception:
        os.close(descriptor)
        raise


def _same_open_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _tar_octal(field: bytes, label: str) -> int:
    token = field.rstrip(b"\x00 ").lstrip(b" ")
    if not token or any(byte not in b"01234567" for byte in token):
        raise PayloadArchiveError(f"tar {label} is not canonical octal")
    return int(token, 8)


def _tar_text(field: bytes, label: str) -> str:
    value, separator, padding = field.partition(b"\x00")
    if separator and any(padding):
        raise PayloadArchiveError(f"tar {label} has non-zero string padding")
    try:
        return value.decode("ascii")
    except UnicodeError as exc:
        raise PayloadArchiveError(f"tar {label} must be ASCII") from exc


def _preflight_tar_headers(source: BinaryIO, profile: _Profile) -> None:
    """Reject extension headers before ``tarfile`` can buffer their bodies."""

    source.seek(0)
    members = 0
    total = 0
    seen: set[str] = set()
    while True:
        header = source.read(512)
        if len(header) != 512:
            raise PayloadArchiveError("payload tar is truncated before its end marker")
        if not any(header):
            second = source.read(512)
            if len(second) != 512 or any(second):
                raise PayloadArchiveError("payload tar requires two zero end blocks")
            while True:
                tail = source.read(1024 * 1024)
                if not tail:
                    break
                if any(tail):
                    raise PayloadArchiveError(
                        "payload archive has non-zero data after the tar end marker"
                    )
            break

        stored_checksum = _tar_octal(header[148:156], "checksum")
        calculated_checksum = (
            sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
        )
        if stored_checksum != calculated_checksum:
            raise PayloadArchiveError("payload tar header checksum mismatch")
        member_type = header[156:157]
        if member_type not in {b"\x00", tarfile.REGTYPE, tarfile.DIRTYPE}:
            raise PayloadArchiveError(
                "payload tar extension/link/device/sparse headers are forbidden"
            )
        name = _tar_text(header[0:100], "name")
        prefix = _tar_text(header[345:500], "prefix")
        full_name = f"{prefix}/{name}" if prefix else name
        parts = _member_parts(full_name)
        canonical = "/".join(parts)
        if canonical in seen:
            raise PayloadArchiveError(f"duplicate archive member: {canonical}")
        seen.add(canonical)
        if parts == (profile.prefix,):
            if member_type != tarfile.DIRTYPE:
                raise PayloadArchiveError("canonical package root must be a directory")
        elif (
            len(parts) != 2
            or parts[0] != profile.prefix
            or parts[1] not in profile.allowed_files
            or member_type == tarfile.DIRTYPE
        ):
            raise PayloadArchiveError(f"unexpected target package path: {canonical}")

        size = _tar_octal(header[124:136], "member size")
        if size > MAX_MEMBER_BYTES:
            raise PayloadArchiveError(f"payload member size is unsafe: {canonical}")
        if member_type == tarfile.DIRTYPE and size != 0:
            raise PayloadArchiveError("canonical package root directory has data")
        members += 1
        if members > MAX_MEMBERS:
            raise PayloadArchiveError("payload archive has too many members")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise PayloadArchiveError("payload archive expands beyond the safety limit")
        padded = (size + 511) & ~511
        if source.seek(padded, os.SEEK_CUR) > os.fstat(source.fileno()).st_size:
            raise PayloadArchiveError("payload tar member extends beyond the archive")
    source.seek(0)


def _copy_exact(source: BinaryIO, destination: Path, size: int) -> str:
    digest = hashlib.sha256()
    copied = 0
    with destination.open("xb") as target:
        while copied < size:
            chunk = source.read(min(1024 * 1024, size - copied))
            if not chunk:
                raise PayloadArchiveError(
                    f"short payload member while reading {destination.name}"
                )
            target.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
        if source.read(1):
            raise PayloadArchiveError(
                f"payload member exceeds declared size: {destination.name}"
            )
    return digest.hexdigest()


def _validate_gzip_cpio(path: Path) -> None:
    unpacked = 0
    lead = bytearray()
    try:
        with gzip.open(path, "rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                if len(lead) < 6:
                    lead.extend(chunk[: 6 - len(lead)])
                unpacked += len(chunk)
                if unpacked > MAX_UNPACKED_CPIO_BYTES:
                    raise PayloadArchiveError(
                        "uramdisk.image.gz expands beyond the CPIO safety limit"
                    )
    except (EOFError, gzip.BadGzipFile, OSError, zlib.error) as exc:
        raise PayloadArchiveError(f"uramdisk.image.gz is not valid gzip: {exc}") from exc
    if bytes(lead) not in {b"070701", b"070702"}:
        raise PayloadArchiveError(
            "uramdisk.image.gz does not begin with a newc/crc CPIO archive"
        )


def _stream_sha256(path: Path, *, offset: int = 0) -> tuple[int, str, int]:
    digest = hashlib.sha256()
    crc = 0
    size = 0
    with path.open("rb") as source:
        source.seek(offset)
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            crc = binascii.crc32(chunk, crc)
            size += len(chunk)
    return size, digest.hexdigest(), crc & 0xFFFFFFFF


def _validate_legacy_ramdisk(ramdisk: Path, raw_cpio: Path) -> None:
    with ramdisk.open("rb") as source:
        header = source.read(64)
    if len(header) != 64:
        raise PayloadArchiveError("ramdisk.gz is shorter than a U-Boot legacy header")
    fields = struct.unpack(">7I4B32s", header)
    magic, header_crc, _timestamp, data_size, _load, _entry, data_crc = fields[:7]
    operating_system, arch, image_type, compression, raw_name = fields[7:]
    if magic != 0x27051956:
        raise PayloadArchiveError("ramdisk.gz has the wrong U-Boot legacy magic")
    zero_crc_header = header[:4] + b"\x00\x00\x00\x00" + header[8:]
    if (binascii.crc32(zero_crc_header) & 0xFFFFFFFF) != header_crc:
        raise PayloadArchiveError("ramdisk.gz U-Boot header CRC mismatch")
    if (operating_system, arch, image_type, compression) != (5, 2, 3, 1):
        raise PayloadArchiveError(
            "ramdisk.gz is not an ARM Linux gzip legacy ramdisk"
        )
    name = raw_name.split(b"\x00", 1)[0]
    if not name.startswith(b"DCENT_OS am3-bb-s19jpro"):
        raise PayloadArchiveError("ramdisk.gz has the wrong target-bound image name")
    wrapped_size, wrapped_sha, wrapped_crc = _stream_sha256(ramdisk, offset=64)
    raw_size, raw_sha, _ = _stream_sha256(raw_cpio)
    if wrapped_size != data_size or wrapped_crc != data_crc:
        raise PayloadArchiveError("ramdisk.gz U-Boot data size/CRC mismatch")
    if (wrapped_size, wrapped_sha) != (raw_size, raw_sha):
        raise PayloadArchiveError(
            "ramdisk.gz does not wrap the exact uramdisk.image.gz bytes"
        )


def _validate_ext2(path: Path) -> None:
    if path.stat().st_size < 2048 or path.stat().st_size % 1024:
        raise PayloadArchiveError("rootfs.ext2 has non-canonical image geometry")
    with path.open("rb") as source:
        source.seek(1024 + 56)
        magic = source.read(2)
    if magic != b"\x53\xef":
        raise PayloadArchiveError("rootfs.ext2 is missing the ext2/3/4 superblock magic")


def _require_keys(document: dict[str, object], keys: frozenset[str], label: str) -> None:
    actual = frozenset(document)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise PayloadArchiveError(
            f"{label} keys mismatch (missing={missing}, extra={extra})"
        )


def _parse_manifest(path: Path) -> dict[str, object]:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise PayloadArchiveError("MANIFEST.json exceeds the safety limit")
    try:
        raw = path.read_text(encoding="ascii")
        document = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PayloadArchiveError(f"MANIFEST.json is not strict ASCII JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise PayloadArchiveError("MANIFEST.json root must be an object")
    _require_keys(document, _MANIFEST_KEYS, "MANIFEST.json")
    return document


def _validate_provenance(document: dict[str, object], *, signed: bool) -> None:
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise PayloadArchiveError("manifest provenance must be an object")
    _require_keys(provenance, _PROVENANCE_KEYS, "manifest provenance")
    source_epoch = provenance["source_date_epoch"]
    commit_epoch = provenance["source_commit_epoch"]
    if (
        isinstance(source_epoch, bool)
        or not isinstance(source_epoch, int)
        or source_epoch < 0
        or isinstance(commit_epoch, bool)
        or not isinstance(commit_epoch, int)
        or commit_epoch != source_epoch
    ):
        raise PayloadArchiveError("manifest provenance epochs are invalid or unequal")
    commit = provenance["source_commit"]
    tree_state = provenance["source_tree_state"]
    if not isinstance(commit, str) or not isinstance(tree_state, str):
        raise PayloadArchiveError("manifest source identity fields must be strings")
    if signed:
        if not _FULL_OBJECT_ID.fullmatch(commit):
            raise PayloadArchiveError("signed manifest requires a full Git object id")
        if tree_state not in {"clean", "exact_git_object_snapshot"}:
            raise PayloadArchiveError("signed manifest requires clean snapshot provenance")
    else:
        if commit != "unbound" and not re.fullmatch(r"[0-9a-fA-F]+", commit):
            raise PayloadArchiveError("unsigned manifest source commit is invalid")
        if tree_state not in {"clean", "dirty", "unbound", "exact_git_object_snapshot"}:
            raise PayloadArchiveError("unsigned manifest source tree state is invalid")
    for key in ("build_target", "build_arch", "toolchain_id"):
        value = provenance[key]
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise PayloadArchiveError(f"manifest provenance {key} is invalid")


def _validate_created_at(value: object, epoch: int) -> None:
    if not isinstance(value, str):
        raise PayloadArchiveError("manifest created_at_utc must be a string")
    try:
        created = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise PayloadArchiveError("manifest created_at_utc is not canonical UTC") from exc
    if int(created.timestamp()) != epoch:
        raise PayloadArchiveError("manifest created_at_utc does not match source epoch")


def _parse_checksums(path: Path) -> list[tuple[str, str]]:
    if path.stat().st_size > MAX_CHECKSUM_BYTES:
        raise PayloadArchiveError("SHA256SUMS exceeds the safety limit")
    try:
        text = path.read_text(encoding="ascii")
    except UnicodeError as exc:
        raise PayloadArchiveError("SHA256SUMS must be ASCII") from exc
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
        if match is None:
            raise PayloadArchiveError("SHA256SUMS contains a non-canonical row")
        digest, leaf = match.groups()
        if leaf in seen:
            raise PayloadArchiveError(f"SHA256SUMS repeats {leaf}")
        seen.add(leaf)
        rows.append((leaf, digest))
    rebuilt = "".join(f"{digest}  {leaf}\n" for leaf, digest in rows)
    if text != rebuilt:
        raise PayloadArchiveError("SHA256SUMS must use canonical LF-terminated rows")
    return rows


def _verify_embedded_signature(root: Path) -> None:
    signature = root / "MANIFEST.sig"
    public_key = root / "release_ed25519.pub"
    manifest = root / "MANIFEST.json"
    if signature.stat().st_size != ED25519_SIGNATURE_BYTES:
        raise PayloadArchiveError("MANIFEST.sig must be a 64-byte Ed25519 signature")
    if public_key.stat().st_size > MAX_PUBLIC_KEY_BYTES:
        raise PayloadArchiveError("release_ed25519.pub exceeds the safety limit")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise PayloadArchiveError(
            "OpenSSL is required to check signed AM3-BB package consistency"
        )
    try:
        completed = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-sigfile",
                str(signature),
                "-in",
                str(manifest),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PayloadArchiveError(f"cannot verify MANIFEST.sig: {exc}") from exc
    if completed.returncode != 0:
        raise PayloadArchiveError(
            "MANIFEST.sig does not verify against the embedded public key"
        )


def _validate_contract(
    root: Path,
    profile: _Profile,
    names: set[str],
    measured: dict[str, tuple[int, str]],
) -> str:
    required = set(profile.required_payloads) | {"SHA256SUMS", "MANIFEST.json"}
    if not required.issubset(names):
        raise PayloadArchiveError(
            f"payload is missing required target files: {sorted(required - names)}"
        )
    document = _parse_manifest(root / "MANIFEST.json")
    expected_scalars = {
        "schema": 1,
        "product": "DCENT_OS",
        "family": "antminer",
        "package_type": "sdcard_payload",
        "board_family": "am3-bb",
        "board": profile.target,
        "board_target": profile.target,
        "nand_install": False,
    }
    if type(document.get("schema")) is not int:  # bool must not satisfy schema=1
        raise PayloadArchiveError("manifest schema must be the integer 1")
    if document.get("nand_install") is not False:
        raise PayloadArchiveError("manifest must deny NAND installation")
    for key, expected in expected_scalars.items():
        if document.get(key) != expected:
            raise PayloadArchiveError(f"manifest field mismatch: {key}")
    version = document.get("version")
    status_value = document.get("status")
    if not isinstance(version, str) or not _TOKEN.fullmatch(version):
        raise PayloadArchiveError("manifest version is not a canonical token")
    if not isinstance(status_value, str) or not _TOKEN.fullmatch(status_value):
        raise PayloadArchiveError("manifest status is not a canonical token")

    payloads = document.get("payloads")
    if not isinstance(payloads, dict):
        raise PayloadArchiveError("manifest payloads must be an object")
    signed = "verification_key" in payloads
    sidecars_present = {"MANIFEST.sig", "release_ed25519.pub"}.intersection(names)
    if signed:
        if sidecars_present != {"MANIFEST.sig", "release_ed25519.pub"}:
            raise PayloadArchiveError("signed manifest requires both signature sidecars")
        if status_value not in {"release", "production", "stable"}:
            raise PayloadArchiveError("signed manifest has a non-release status")
        signature_scope = "embedded-key-self-consistency-only"
    else:
        if sidecars_present:
            raise PayloadArchiveError("unsigned manifest forbids signature sidecars")
        if status_value != "lab_unsigned":
            raise PayloadArchiveError("unsigned manifest requires status=lab_unsigned")
        signature_scope = "unsigned-lab"

    _validate_provenance(document, signed=signed)
    provenance = document["provenance"]
    assert isinstance(provenance, dict)
    _validate_created_at(document["created_at_utc"], provenance["source_date_epoch"])

    actual_payload_names = [
        leaf for leaf in profile.payload_order if leaf in names
    ]
    expected_payload_keys = set(actual_payload_names)
    if signed:
        expected_payload_keys.add("verification_key")
    if set(payloads) != expected_payload_keys:
        raise PayloadArchiveError(
            "manifest payload set does not match the exact archive profile"
        )
    for manifest_key in actual_payload_names:
        descriptor = payloads[manifest_key]
        if not isinstance(descriptor, dict):
            raise PayloadArchiveError(f"manifest payload {manifest_key} must be an object")
        _require_keys(descriptor, _PAYLOAD_DESCRIPTOR_KEYS, manifest_key)
        size, digest = measured[manifest_key]
        expected = {
            "path": f"{profile.prefix}/{manifest_key}",
            "size": size,
            "sha256": digest,
        }
        if descriptor != expected:
            raise PayloadArchiveError(f"manifest payload binding mismatch: {manifest_key}")
    if signed:
        descriptor = payloads["verification_key"]
        if not isinstance(descriptor, dict):
            raise PayloadArchiveError("manifest verification_key must be an object")
        _require_keys(descriptor, _PAYLOAD_DESCRIPTOR_KEYS, "verification_key")
        size, digest = measured["release_ed25519.pub"]
        if descriptor != {
            "path": f"{profile.prefix}/release_ed25519.pub",
            "size": size,
            "sha256": digest,
        }:
            raise PayloadArchiveError("manifest verification-key binding mismatch")

    checksum_rows = _parse_checksums(root / "SHA256SUMS")
    expected_checksum_leaves = list(actual_payload_names)
    if signed:
        expected_checksum_leaves.append("release_ed25519.pub")
    if [leaf for leaf, _ in checksum_rows] != expected_checksum_leaves:
        raise PayloadArchiveError("SHA256SUMS rows do not match producer order/profile")
    for leaf, digest in checksum_rows:
        if measured[leaf][1] != digest:
            raise PayloadArchiveError(f"SHA256SUMS binding mismatch: {leaf}")

    if (root / "README.txt").stat().st_size > MAX_README_BYTES:
        raise PayloadArchiveError("README.txt exceeds the safety limit")
    _validate_gzip_cpio(root / "uramdisk.image.gz")
    if profile.legacy_ramdisk:
        _validate_legacy_ramdisk(root / "ramdisk.gz", root / "uramdisk.image.gz")
    if "rootfs.ext2" in names:
        _validate_ext2(root / "rootfs.ext2")
    if signed:
        _verify_embedded_signature(root)
    return signature_scope


def extract_payload(
    archive: Path,
    output_dir: Path,
    *,
    expected_target: str,
) -> dict[str, object]:
    """Admit one exact target package and publish its regular members."""

    profile = _profile(expected_target)
    archive = Path(archive)
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise PayloadArchiveError("output directory must be an existing non-symlink directory")
    if any(output_dir.iterdir()):
        raise PayloadArchiveError("output directory must be empty")

    source, opened = _open_regular_archive(archive)
    try:
        _preflight_tar_headers(source, profile)
    except Exception:
        source.close()
        raise
    seen: set[str] = set()
    names: set[str] = set()
    measured: dict[str, tuple[int, str]] = {}
    total = 0
    root_entry_seen = False
    with source, tempfile.TemporaryDirectory(
        prefix=".dcent-am3-bb-admit-", dir=output_dir
    ) as staging_name:
        staging = Path(staging_name)
        package_root = staging / profile.prefix
        package_root.mkdir()
        try:
            with tarfile.open(fileobj=source, mode="r:") as handle:
                member_count = 0
                for member in handle:
                    member_count += 1
                    if member_count > MAX_MEMBERS:
                        raise PayloadArchiveError("payload archive has too many members")
                    if member.pax_headers:
                        raise PayloadArchiveError(
                            f"extended/sparse tar headers are forbidden: {member.name}"
                        )
                    parts = _member_parts(member.name)
                    canonical = "/".join(parts)
                    if canonical in seen:
                        raise PayloadArchiveError(f"duplicate archive member: {canonical}")
                    seen.add(canonical)
                    if parts == (profile.prefix,):
                        if member.type != tarfile.DIRTYPE or member.size != 0:
                            raise PayloadArchiveError("canonical package root must be a directory")
                        root_entry_seen = True
                        continue
                    if len(parts) != 2 or parts[0] != profile.prefix:
                        raise PayloadArchiveError(f"unexpected target package path: {canonical}")
                    leaf = parts[1]
                    if leaf not in profile.allowed_files:
                        raise PayloadArchiveError(f"unexpected target package file: {canonical}")
                    if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                        raise PayloadArchiveError(f"non-regular payload member: {canonical}")
                    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                        raise PayloadArchiveError(f"payload member size is unsafe: {canonical}")
                    total += member.size
                    if total > MAX_TOTAL_BYTES:
                        raise PayloadArchiveError("payload archive expands beyond the safety limit")
                    extracted = handle.extractfile(member)
                    if extracted is None:
                        raise PayloadArchiveError(f"cannot read payload member: {canonical}")
                    with extracted:
                        digest = _copy_exact(extracted, package_root / leaf, member.size)
                    names.add(leaf)
                    measured[leaf] = (member.size, digest)
        except (OSError, tarfile.TarError) as exc:
            raise PayloadArchiveError(f"cannot parse AM3-BB payload tar: {exc}") from exc

        if not root_entry_seen:
            raise PayloadArchiveError("payload archive is missing its canonical root entry")
        if not _same_open_file(opened, os.fstat(source.fileno())):
            raise PayloadArchiveError("payload archive changed while it was inspected")
        signature_scope = _validate_contract(package_root, profile, names, measured)
        destination = output_dir / profile.prefix
        if destination.exists() or destination.is_symlink():
            raise PayloadArchiveError("canonical output destination already exists")
        os.replace(package_root, destination)

    return {
        "schema": "dcentos.am3_bb_source_package_admission.v1",
        "board_target": profile.target,
        "prefix": profile.prefix,
        "files": sorted(names),
        "total_bytes": total,
        "source_schema_admitted": True,
        "signature_scope": signature_scope,
        "installable": False,
        "install_authority": "none",
        "device_contact": "none",
        "block_device_write": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--expected-target", required=True, choices=sorted(_PROFILES)
    )
    args = parser.parse_args()
    try:
        result = extract_payload(
            args.archive,
            args.output_dir,
            expected_target=args.expected_target,
        )
    except (OSError, PayloadArchiveError) as exc:
        parser.error(str(exc))
    print(
        "ADMITTED: exact source-schema AM3-BB payload "
        f"target={result['board_target']} files={len(result['files'])} "
        "install_authority=none"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
