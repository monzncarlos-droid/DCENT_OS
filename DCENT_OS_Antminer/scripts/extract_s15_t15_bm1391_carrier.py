#!/usr/bin/env python3
"""Extract the held S15/T15 BM1391 carrier contract without touching hardware.

The input packages are exact, operator-held Bitmain release tarballs.  This
tool bounds every decompression step, rejects archive/path/schema drift, reads
selected files directly from the ext2 ramdisk, and emits deterministic JSON.

The semantic carrier facts are intentionally pinned to the reviewed package
and cgminer hashes.  They are static evidence, not install, runtime, or wire
mutation authority.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import posixpath
import stat
import struct
import sys
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_RAMDISK_BYTES = 128 * 1024 * 1024
MAX_TAR_MEMBERS = 32
UIMAGE_MAGIC = 0x27051956

OUTER_MEMBERS = frozenset(
    {
        "cert.pem",
        "cert.pem.sig",
        "fw.tar.gz",
        "fw.tar.gz.sig",
        "runme.sh",
        "runme.sh.sig",
        "version_number",
    }
)
INNER_MEMBERS = frozenset(
    {"BOOT.bin", "md5_info", "runme.sh", "uImage", "uramdisk.image.gz"}
)

_PRIVATE_COMMON_FILE_PIN_ROWS = (
    (
        "/lib/modules/bitmain_axi.ko",
        7_519,
        "00500755f72420e3c084e0ea6ecfe71b7989a219a972c2db5e34818f3f750ab4",
    ),
    (
        "/lib/modules/fpga_mem_driver.ko",
        8_030,
        "2ec39eda2d5b691c07475b73797c335949a56eb6df9b0a5d83881474bfff0c3f",
    ),
)

# Detached compatibility snapshot.  Admission uses the primitive-only private
# rows captured by ``inspect_model`` and ``build_report``, never this public map.
COMMON_FILE_PINS = {
    path: (size, digest) for path, size, digest in _PRIVATE_COMMON_FILE_PIN_ROWS
}

_PRIVATE_MODEL_PIN_ROWS = (
    (
        "S15",
        24_962_829,
        "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
        "1.92992.0.14",
        "3038ed2272ca35f32571e871ca1ca615337167abedbca62261d5049e443629c4",
        "04572993000af9bd2257bb03f6cad72cc7e341b9ea7614d9a25506b58d0f72cd",
        "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8",
        4_488,
        "a558be52e41b2ca74fbf5e16e57f8096aa6e79ad44b479ded3d7ba27598da4ba",
        1_659,
        "d19080f7ba095bd538c896f2d4985751c78066d556ea00b9caeadc726aed09b9",
        431,
        "eaad2ee240947990d084a4739efb35811ac06178d910e8bcfa5a2562345cf8f9",
        "/etc/91602_patten_72.txt",
        147_456,
        17_694_720,
        "165aa04898d62fc689f0d116aeb6301380b7dbb961d10dfa61831ab1868f21c0",
    ),
    (
        "T15",
        23_696_441,
        "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
        "1.92992.0.13",
        "cda8ebaba3d8d1cefcffa7688a59ecede6b309f3f961ea856bdc296ebd662505",
        "e3f6d7c1cf6ab59c43762906debc13b164d2d2bf3aa1d6e193eb53aa848bde37",
        "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01",
        5_532,
        "eb58a01bd0cb8e8c7b5546825fbeb0f2d9e15e922a32853fb7dea27fb6e194ac",
        1_702,
        "e32e94df4cf97e0cb1239852d8ed8672bcd60760e478e687a5e619bad7097294",
        431,
        "859868786b6385f3f0ae542c6f786d39a3778054800ae5c5371fce69e7333fd7",
        "/etc/91602_patten_60.txt",
        122_880,
        14_622_720,
        "29e450043a8cae2c207efee971a2233835d20a4c0d01fbe3a6dd20fd4dcdd563",
    ),
)


def _detached_model_pins(
    _rows: Tuple[Tuple[object, ...], ...] = _PRIVATE_MODEL_PIN_ROWS,
) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for row in _rows:
        result[str(row[0])] = {
            "package_size": row[1],
            "package_sha256": row[2],
            "version": row[3],
            "fw_tar_sha256": row[4],
            "ramdisk_sha256": row[5],
            "cgminer_sha256": row[6],
            "cgminer_script": (row[7], row[8]),
            "setup_script": (row[9], row[10]),
            "factory_config": (row[11], row[12]),
            "pattern_path": row[13],
            "pattern_lines": row[14],
            "pattern_pin": (row[15], row[16]),
        }
    return result


# Detached compatibility snapshot. Mutating it cannot affect admission.
MODEL_PINS: Mapping[str, Mapping[str, Any]] = _detached_model_pins()

BOOT_BIN_PIN = (
    2_735_664,
    "e6b85d66e226856203588794afb56da458716129852848c2c6069cb0ba84ab32",
)
KERNEL_PIN = (
    4_006_832,
    "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f",
)
CERT_SHA256 = "d2545120c0ffc9cb60b83024780ea96d990f4d90b8224b869add52112fa1cd3c"


class EvidenceError(ValueError):
    """The held input failed a bound, pin, or structural check."""


@dataclass(frozen=True)
class CarrierContractReceipt:
    """Immutable semantic profile; exact-artifact association is separate."""

    canonical_contract_json: str
    artifact_association_verified: bool = field(default=False, init=False)
    evidence_only: bool = field(default=True, init=False)
    install_authority: bool = field(default=False, init=False)
    live_probe_authority: bool = field(default=False, init=False)
    runtime_mutation_authority: bool = field(default=False, init=False)
    wire_transaction_authority: bool = field(default=False, init=False)
    device_contact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True)
class CarrierEvidenceReceipt:
    """Immutable receipt minted only after both exact held packages pass."""

    schema: str
    canonical_models_json: str
    shared_carrier_contract: CarrierContractReceipt
    receipt_verified: bool = field(default=False, init=False)
    evidence_only: bool = field(default=True, init=False)
    install_authority: bool = field(default=False, init=False)
    live_probe_authority: bool = field(default=False, init=False)
    runtime_mutation_authority: bool = field(default=False, init=False)
    wire_transaction_authority: bool = field(default=False, init=False)
    device_contact_authority: bool = field(default=False, init=False)


def _build_receipt_views():
    trusted_loads = json.loads
    trusted_dumps = json.dumps
    trusted_sha256 = hashlib.sha256
    trusted_isinstance = isinstance
    trusted_dict_cls = dict
    trusted_error_cls = EvidenceError
    trusted_len = len
    contract_size = 7_040
    contract_sha256 = "44d21708c393c842739491319e0280126f3b423167249442ff873a87ba1118ea"
    models_size = 3_761
    models_sha256 = "66b661cf5948a19c16cd780d9057ed9948816704d92a57a0f6152682dbbcaa49"
    schema = "dcent.s15-t15-bm1391-carrier-evidence.v1"

    def checked_contract(
        value: CarrierContractReceipt, association_required: Optional[bool]
    ) -> Dict[str, Any]:
        encoded = value.canonical_contract_json.encode("utf-8")
        if trusted_len(encoded) != contract_size:
            raise trusted_error_cls("canonical carrier contract size drift")
        if trusted_sha256(encoded).hexdigest() != contract_sha256:
            raise trusted_error_cls("canonical carrier contract hash drift")
        if (
            value.evidence_only,
            value.install_authority,
            value.live_probe_authority,
            value.runtime_mutation_authority,
            value.wire_transaction_authority,
            value.device_contact_authority,
        ) != (True, False, False, False, False, False):
            raise trusted_error_cls("carrier contract authority fields were altered")
        if (
            association_required is not None
            and value.artifact_association_verified is not association_required
        ):
            raise trusted_error_cls("carrier contract association field was altered")
        decoded = trusted_loads(value.canonical_contract_json)
        if not trusted_isinstance(decoded, trusted_dict_cls):
            raise trusted_error_cls("canonical carrier contract is not an object")
        return decoded

    def checked_evidence(value: CarrierEvidenceReceipt) -> Dict[str, Any]:
        if value.schema != schema:
            raise trusted_error_cls("carrier evidence schema drift")
        if value.receipt_verified is not True:
            raise trusted_error_cls("carrier evidence receipt is not verified")
        if (
            value.evidence_only,
            value.install_authority,
            value.live_probe_authority,
            value.runtime_mutation_authority,
            value.wire_transaction_authority,
            value.device_contact_authority,
        ) != (True, False, False, False, False, False):
            raise trusted_error_cls("carrier evidence authority fields were altered")
        encoded = value.canonical_models_json.encode("utf-8")
        if trusted_len(encoded) != models_size:
            raise trusted_error_cls("canonical model evidence size drift")
        if trusted_sha256(encoded).hexdigest() != models_sha256:
            raise trusted_error_cls("canonical model evidence hash drift")
        models = trusted_loads(value.canonical_models_json)
        if not trusted_isinstance(models, trusted_dict_cls):
            raise trusted_error_cls("canonical model evidence is not an object")
        return {
            "schema": value.schema,
            "models": models,
            "shared_carrier_contract": checked_contract(
                value.shared_carrier_contract, True
            ),
        }

    def contract_to_dict(self: CarrierContractReceipt) -> Dict[str, Any]:
        """Return a fresh detached serialization, never a trust-bearing alias."""

        return checked_contract(self, None)

    def evidence_to_dict(self: CarrierEvidenceReceipt) -> Dict[str, Any]:
        """Return the legacy JSON object as a fresh, detached compatibility view."""

        return checked_evidence(self)

    def evidence_to_pretty_json(self: CarrierEvidenceReceipt) -> str:
        """Preserve the established sorted/indented CLI report encoding."""

        return trusted_dumps(checked_evidence(self), indent=2, sort_keys=True) + "\n"

    def cli_pretty_json(self: CarrierEvidenceReceipt) -> str:
        """Private CLI serializer independent of the public method object."""

        return trusted_dumps(checked_evidence(self), indent=2, sort_keys=True) + "\n"

    return (
        contract_to_dict,
        evidence_to_dict,
        evidence_to_pretty_json,
        cli_pretty_json,
    )


(
    CarrierContractReceipt.to_dict,
    CarrierEvidenceReceipt.to_dict,
    CarrierEvidenceReceipt.to_pretty_json,
    _private_cli_pretty_json,
) = _build_receipt_views()
del _build_receipt_views


def sha256(data: bytes, _sha256: Any = hashlib.sha256) -> str:
    return _sha256(data).hexdigest()


def _is_reparse_or_symlink(
    path: Path,
    _is_link: Any = stat.S_ISLNK,
    _reparse_flag: int = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
    _getattr: Any = getattr,
    _bool: Any = bool,
) -> bool:
    info = path.lstat()
    return _is_link(info.st_mode) or _bool(
        _getattr(info, "st_file_attributes", 0) & _reparse_flag
    )


def _reject_reparse_components(
    path: Path,
    _predicate: Any = _is_reparse_or_symlink,
    _error_cls: type = EvidenceError,
    _list: Any = list,
    _reversed: Any = reversed,
) -> None:
    absolute = path.absolute()
    chain = _list(_reversed(absolute.parents)) + [absolute]
    for component in chain:
        if component.exists() and _predicate(component):
            raise _error_cls(
                f"symlink/reparse path component refused: {component.name or component}"
            )


def checked_blob(
    path: Path,
    expected_size: int,
    expected_sha256: str,
    *,
    os_open: Any = os.open,
    os_read: Any = os.read,
    os_fstat: Any = os.fstat,
    os_close: Any = os.close,
    _reject_path: Any = _reject_reparse_components,
    _is_regular: Any = stat.S_ISREG,
    _max_package_bytes: int = MAX_PACKAGE_BYTES,
    _chunk_bytes: int = 1024 * 1024,
    _error_cls: type = EvidenceError,
    _sha256_fn: Any = sha256,
    _str: Any = str,
    _min: Any = min,
    _len: Any = len,
    _getattr: Any = getattr,
    _open_flags: int = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    ),
) -> bytes:
    """Snapshot one exact single-link file through a stable descriptor."""

    if expected_size <= 0 or expected_size > _max_package_bytes:
        raise _error_cls(f"package size outside bound: {expected_size}")
    _reject_path(path)
    before_path = path.lstat()
    if not _is_regular(before_path.st_mode) or before_path.st_nlink != 1:
        raise _error_cls("package must be a single-link regular file")
    if before_path.st_size != expected_size:
        raise _error_cls("package size pin mismatch before read")

    descriptor = os_open(_str(path), _open_flags)
    try:
        before = os_fstat(descriptor)
        if not _is_regular(before.st_mode) or before.st_nlink != 1:
            raise _error_cls("opened package is not a regular single-link file")
        if before.st_size != expected_size:
            raise _error_cls("package size pin mismatch on descriptor")
        if (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise _error_cls("package identity changed before descriptor open")

        remaining = expected_size
        chunks = []
        while remaining:
            chunk = os_read(descriptor, _min(_chunk_bytes, remaining))
            if not chunk:
                raise _error_cls("package reached EOF before pinned size")
            if _len(chunk) > remaining:
                raise _error_cls("reader returned bytes beyond pinned size")
            chunks.append(chunk)
            remaining -= _len(chunk)
        if os_read(descriptor, 1):
            raise _error_cls("package grew beyond pinned size")

        after = os_fstat(descriptor)
        if not _is_regular(after.st_mode) or after.st_nlink != 1:
            raise _error_cls("package stopped being a regular single-link file")
        stable_fields = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_nlink,
            _getattr(before, "st_ctime_ns", None),
        )
        after_fields = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_nlink,
            _getattr(after, "st_ctime_ns", None),
        )
        if after_fields != stable_fields:
            raise _error_cls("package metadata changed during read")
        data = b"".join(chunks)
    finally:
        os_close(descriptor)

    actual = _sha256_fn(data)
    if actual != expected_sha256:
        raise _error_cls(
            f"package hash drift for {path.name}: expected {expected_sha256}, got {actual}"
        )
    return data


def bounded_gzip(
    data: bytes,
    limit: int,
    label: str,
    _decompressobj: Any = zlib.decompressobj,
    _max_wbits: int = zlib.MAX_WBITS,
    _bytearray: Any = bytearray,
    _bytes: Any = bytes,
    _len: Any = len,
    _error_cls: type = EvidenceError,
) -> bytes:
    decoder = _decompressobj(16 + _max_wbits)
    output = _bytearray()
    cursor = 0
    while cursor < _len(data):
        chunk = data[cursor : cursor + 64 * 1024]
        cursor += _len(chunk)
        output.extend(decoder.decompress(chunk, limit + 1 - _len(output)))
        if _len(output) > limit:
            raise _error_cls(f"{label} exceeds decompression bound")
        if decoder.eof:
            if decoder.unused_data or cursor != _len(data):
                raise _error_cls(f"{label} has trailing or concatenated gzip data")
            break
    if not decoder.eof:
        raise _error_cls(f"{label} is a truncated gzip stream")
    output.extend(decoder.flush(limit + 1 - _len(output)))
    if _len(output) > limit:
        raise _error_cls(f"{label} exceeds decompression bound")
    return _bytes(output)


def _safe_member_name(
    name: str,
    _bool: Any = bool,
    _normpath: Any = posixpath.normpath,
    _all: Any = all,
) -> bool:
    return (
        _bool(name)
        and "\\" not in name
        and not name.startswith("/")
        and _normpath(name) == name
        and _all(part not in ("", ".", "..") for part in name.split("/"))
    )


def exact_tar_gz(
    data: bytes,
    expected: Iterable[str],
    label: str,
    _bounded_gzip: Any = bounded_gzip,
    _max_tar_bytes: int = MAX_TAR_BYTES,
    _max_tar_members: int = MAX_TAR_MEMBERS,
    _frozenset: Any = frozenset,
    _open_tar: Any = tarfile.open,
    _bytes_io: Any = io.BytesIO,
    _tar_error: type = tarfile.TarError,
    _safe_name: Any = _safe_member_name,
    _len: Any = len,
    _sorted: Any = sorted,
    _error_cls: type = EvidenceError,
) -> Dict[str, bytes]:
    raw = _bounded_gzip(data, _max_tar_bytes, f"{label} tar")
    expected_set = _frozenset(expected)
    result: Dict[str, bytes] = {}
    try:
        with _open_tar(fileobj=_bytes_io(raw), mode="r:") as archive:
            members = archive.getmembers()
            if _len(members) > _max_tar_members:
                raise _error_cls(f"{label} has too many members")
            for member in members:
                if not _safe_name(member.name):
                    raise _error_cls(f"{label} has unsafe path {member.name!r}")
                if not member.isreg():
                    raise _error_cls(
                        f"{label} member is not a regular file: {member.name}"
                    )
                if member.name in result:
                    raise _error_cls(f"{label} has duplicate member {member.name}")
                if member.size < 0 or member.size > _max_tar_bytes:
                    raise _error_cls(
                        f"{label} member size outside bound: {member.name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise _error_cls(f"{label} cannot read {member.name}")
                payload = stream.read(member.size + 1)
                if _len(payload) != member.size:
                    raise _error_cls(f"{label} member is truncated: {member.name}")
                result[member.name] = payload
    except _tar_error as error:
        raise _error_cls(f"invalid {label} tar: {error}") from error
    if _frozenset(result) != expected_set:
        missing = _sorted(expected_set - _frozenset(result))
        extra = _sorted(_frozenset(result) - expected_set)
        raise _error_cls(f"{label} schema drift; missing={missing}, extra={extra}")
    return result


def checked_pin(
    data: bytes,
    pin: Tuple[int, str],
    label: str,
    _len: Any = len,
    _sha256_fn: Any = sha256,
    _error_cls: type = EvidenceError,
) -> None:
    expected_size, expected_hash = pin
    if _len(data) != expected_size or _sha256_fn(data) != expected_hash:
        raise _error_cls(f"{label} failed exact size/hash pin")


def parse_legacy_ramdisk(
    image: bytes,
    expected_hash: str,
    _sha256_fn: Any = sha256,
    _len: Any = len,
    _unpack: Any = struct.unpack,
    _bytearray: Any = bytearray,
    _crc32: Any = zlib.crc32,
    _uimage_magic: int = UIMAGE_MAGIC,
    _bounded_gzip: Any = bounded_gzip,
    _max_ramdisk_bytes: int = MAX_RAMDISK_BYTES,
    _error_cls: type = EvidenceError,
) -> Tuple[bytes, Dict[str, Any]]:
    if _sha256_fn(image) != expected_hash:
        raise _error_cls("uramdisk.image.gz hash drift")
    if _len(image) < 64:
        raise _error_cls("legacy ramdisk is truncated")
    fields = _unpack(">7I4B32s", image[:64])
    magic, header_crc, timestamp, size, load, entry, data_crc = fields[:7]
    os_id, arch, image_type, compression = fields[7:11]
    name = fields[11].rstrip(b"\0")
    header_for_crc = _bytearray(image[:64])
    header_for_crc[4:8] = b"\0\0\0\0"
    if magic != _uimage_magic or _crc32(header_for_crc) & 0xFFFFFFFF != header_crc:
        raise _error_cls("legacy ramdisk header CRC/magic invalid")
    payload = image[64:]
    if size != _len(payload) or _crc32(payload) & 0xFFFFFFFF != data_crc:
        raise _error_cls("legacy ramdisk data CRC/size invalid")
    if (load, entry, os_id, arch, image_type, compression, name) != (
        0,
        0,
        5,
        2,
        3,
        1,
        b"",
    ):
        raise _error_cls("legacy ramdisk metadata drift")
    ext2 = _bounded_gzip(payload, _max_ramdisk_bytes, "ext2 ramdisk")
    return ext2, {
        "data_crc32": f"{data_crc:08x}",
        "payload_size": size,
        "timestamp": timestamp,
        "type": "Linux/ARM/ramdisk/gzip",
    }


class Ext2Reader:
    """Small fail-closed reader for regular files in the held ext2 images."""

    def __init__(
        self,
        image: bytes,
        _len: Any = len,
        _ceil: Any = math.ceil,
        _range: Any = range,
        _any: Any = any,
        _error_cls: type = EvidenceError,
    ):
        self.image = image
        if _len(image) < 2048:
            raise _error_cls("ext2 image is truncated")
        sb = image[1024:2048]
        self.inodes_count = self._u32(sb, 0)
        self.blocks_count = self._u32(sb, 4)
        self.first_data_block = self._u32(sb, 20)
        log_block_size = self._u32(sb, 24)
        self.blocks_per_group = self._u32(sb, 32)
        self.inodes_per_group = self._u32(sb, 40)
        revision = self._u32(sb, 76)
        self.inode_size = self._u16(sb, 88) if revision else 128
        compat = self._u32(sb, 92)
        incompat = self._u32(sb, 96)
        ro_compat = self._u32(sb, 100)
        if self._u16(sb, 56) != 0xEF53:
            raise _error_cls("ext2 superblock magic invalid")
        if log_block_size > 2:
            raise _error_cls("unsupported ext2 block size")
        self.block_size = 1024 << log_block_size
        if (
            self.block_size * self.blocks_count > _len(image)
            or self.blocks_per_group == 0
            or self.inodes_per_group == 0
            or self.inode_size not in (128, 256)
        ):
            raise _error_cls("ext2 geometry invalid")
        # FILETYPE is the only incompatible feature in the held images.
        if incompat & ~0x2 or ro_compat & ~0x1 or compat & ~0x38:
            raise _error_cls("unsupported ext2 feature flags")
        group_count = _ceil(
            (self.blocks_count - self.first_data_block) / self.blocks_per_group
        )
        descriptor_offset = (2 if self.block_size == 1024 else 1) * self.block_size
        descriptor_bytes = group_count * 32
        if descriptor_offset + descriptor_bytes > _len(image):
            raise _error_cls("ext2 group descriptors truncated")
        self.inode_tables = [
            self._u32(image, descriptor_offset + group * 32 + 8)
            for group in _range(group_count)
        ]
        if _any(
            block <= 0 or block >= self.blocks_count for block in self.inode_tables
        ):
            raise _error_cls("ext2 inode table outside image")

    @staticmethod
    def _u16(data: bytes, offset: int, _unpack_from: Any = struct.unpack_from) -> int:
        return _unpack_from("<H", data, offset)[0]

    @staticmethod
    def _u32(data: bytes, offset: int, _unpack_from: Any = struct.unpack_from) -> int:
        return _unpack_from("<I", data, offset)[0]

    def _block(self, number: int, _error_cls: type = EvidenceError) -> bytes:
        if number <= 0 or number >= self.blocks_count:
            raise _error_cls(f"ext2 block outside image: {number}")
        offset = number * self.block_size
        return self.image[offset : offset + self.block_size]

    def _inode(
        self,
        number: int,
        _unpack_from: Any = struct.unpack_from,
        _len: Any = len,
        _error_cls: type = EvidenceError,
    ) -> Tuple[int, int, Sequence[int]]:
        if number <= 0 or number > self.inodes_count:
            raise _error_cls(f"ext2 inode outside image: {number}")
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        offset = self.inode_tables[group] * self.block_size + index * self.inode_size
        inode = self.image[offset : offset + self.inode_size]
        if _len(inode) != self.inode_size:
            raise _error_cls("ext2 inode is truncated")
        mode = self._u16(inode, 0)
        size = self._u32(inode, 4)
        if mode & 0xF000 == 0x8000 and self.inode_size >= 112:
            size |= self._u32(inode, 108) << 32
        pointers = _unpack_from("<15I", inode, 40)
        return mode, size, pointers

    def _indirect(
        self, block: int, depth: int, _unpack: Any = struct.unpack
    ) -> Iterable[int]:
        if block == 0:
            return
        values = _unpack("<" + "I" * (self.block_size // 4), self._block(block))
        for value in values:
            if value == 0:
                continue
            if depth == 1:
                yield value
            else:
                yield from self._indirect(value, depth - 1)

    def _inode_data(
        self,
        number: int,
        _max_ramdisk_bytes: int = MAX_RAMDISK_BYTES,
        _ceil: Any = math.ceil,
        _len: Any = len,
        _error_cls: type = EvidenceError,
    ) -> Tuple[int, bytes]:
        mode, size, pointers = self._inode(number)
        if size > _max_ramdisk_bytes:
            raise _error_cls("ext2 inode exceeds reader bound")
        blocks: List[int] = [value for value in pointers[:12] if value]
        blocks.extend(self._indirect(pointers[12], 1))
        blocks.extend(self._indirect(pointers[13], 2))
        blocks.extend(self._indirect(pointers[14], 3))
        needed = _ceil(size / self.block_size)
        if _len(blocks) < needed:
            raise _error_cls("sparse/truncated ext2 inode is unsupported")
        content = b"".join(self._block(block) for block in blocks[:needed])[:size]
        return mode, content

    def _directory(
        self,
        number: int,
        _len: Any = len,
        _error_cls: type = EvidenceError,
        _unicode_error: type = UnicodeDecodeError,
    ) -> Dict[str, int]:
        mode, content = self._inode_data(number)
        if mode & 0xF000 != 0x4000:
            raise _error_cls("ext2 path component is not a directory")
        result: Dict[str, int] = {}
        offset = 0
        while offset < _len(content):
            if offset + 8 > _len(content):
                raise _error_cls("ext2 directory entry truncated")
            inode = self._u32(content, offset)
            record_length = self._u16(content, offset + 4)
            name_length = content[offset + 6]
            if (
                record_length < 8
                or record_length % 4
                or offset + record_length > _len(content)
            ):
                raise _error_cls("ext2 directory record invalid")
            if name_length > record_length - 8:
                raise _error_cls("ext2 directory name invalid")
            if inode:
                try:
                    name = content[offset + 8 : offset + 8 + name_length].decode(
                        "utf-8"
                    )
                except _unicode_error as error:
                    raise _error_cls("non-UTF8 ext2 path is unsupported") from error
                if name in result:
                    raise _error_cls(f"duplicate ext2 directory name: {name}")
                result[name] = inode
            offset += record_length
        return result

    def read_regular(
        self,
        path: str,
        _normpath: Any = posixpath.normpath,
        _error_cls: type = EvidenceError,
    ) -> bytes:
        if not path.startswith("/") or _normpath(path) != path:
            raise _error_cls(f"invalid ext2 path: {path!r}")
        inode = 2
        parts = [part for part in path.split("/") if part]
        for part in parts:
            if part in (".", ".."):
                raise _error_cls(f"unsafe ext2 path: {path!r}")
            entries = self._directory(inode)
            if part not in entries:
                raise _error_cls(f"missing ext2 path: {path}")
            inode = entries[part]
        mode, content = self._inode_data(inode)
        if mode & 0xF000 != 0x8000:
            raise _error_cls(f"ext2 target is not a regular file: {path}")
        return content


def _file_record(
    path: str,
    data: bytes,
    _sha256_fn: Any = sha256,
    _len: Any = len,
) -> Dict[str, Any]:
    return {"path": path, "sha256": _sha256_fn(data), "size": _len(data)}


def _inspect_model_impl(
    model: str,
    package: Path,
    _model_rows: Tuple[Tuple[object, ...], ...] = _PRIVATE_MODEL_PIN_ROWS,
    _common_rows: Tuple[Tuple[object, ...], ...] = _PRIVATE_COMMON_FILE_PIN_ROWS,
    _outer_members: frozenset = OUTER_MEMBERS,
    _inner_members: frozenset = INNER_MEMBERS,
    _boot_pin: Tuple[int, str] = BOOT_BIN_PIN,
    _kernel_pin: Tuple[int, str] = KERNEL_PIN,
    _cert_sha256: str = CERT_SHA256,
    _checked_blob: Any = checked_blob,
    _exact_tar_gz: Any = exact_tar_gz,
    _sha256_fn: Any = sha256,
    _checked_pin: Any = checked_pin,
    _parse_ramdisk: Any = parse_legacy_ramdisk,
    _reader_cls: type = Ext2Reader,
    _file_record_fn: Any = _file_record,
    _md5: Any = hashlib.md5,
    _len: Any = len,
    _any: Any = any,
    _error_cls: type = EvidenceError,
) -> Dict[str, Any]:
    matches = [row for row in _model_rows if row[0] == model]
    if _len(matches) != 1:
        raise _error_cls(f"unknown or duplicate private model pin: {model}")
    row = matches[0]
    pins = {
        "package_size": row[1],
        "package_sha256": row[2],
        "version": row[3],
        "fw_tar_sha256": row[4],
        "ramdisk_sha256": row[5],
        "cgminer_sha256": row[6],
        "cgminer_script": (row[7], row[8]),
        "setup_script": (row[9], row[10]),
        "factory_config": (row[11], row[12]),
        "pattern_path": row[13],
        "pattern_lines": row[14],
        "pattern_pin": (row[15], row[16]),
    }
    package_data = _checked_blob(package, pins["package_size"], pins["package_sha256"])
    outer = _exact_tar_gz(package_data, _outer_members, f"{model} outer")
    if outer["version_number"].decode("ascii").strip() != pins["version"]:
        raise _error_cls(f"{model} version_number drift")
    if _sha256_fn(outer["cert.pem"]) != _cert_sha256:
        raise _error_cls(f"{model} embedded certificate drift")
    if _sha256_fn(outer["fw.tar.gz"]) != pins["fw_tar_sha256"]:
        raise _error_cls(f"{model} fw.tar.gz hash drift")
    inner = _exact_tar_gz(outer["fw.tar.gz"], _inner_members, f"{model} firmware")
    _checked_pin(inner["BOOT.bin"], _boot_pin, f"{model} BOOT.bin")
    _checked_pin(inner["uImage"], _kernel_pin, f"{model} uImage")
    expected_md5 = inner["md5_info"].decode("ascii").strip()
    actual_md5 = _md5(inner["uramdisk.image.gz"]).hexdigest()  # noqa: S324
    if expected_md5 != actual_md5:
        raise _error_cls(f"{model} md5_info does not bind ramdisk")
    ext2, uimage = _parse_ramdisk(inner["uramdisk.image.gz"], pins["ramdisk_sha256"])
    reader = _reader_cls(ext2)
    selected_paths = [
        "/usr/bin/cgminer",
        "/etc/init.d/cgminer.sh",
        "/etc/init.d/bitmainer_setup.sh",
        "/etc/cgminer.conf.factory",
        "/lib/modules/bitmain_axi.ko",
        "/lib/modules/fpga_mem_driver.ko",
        pins["pattern_path"],
    ]
    selected = {path: reader.read_regular(path) for path in selected_paths}
    if _sha256_fn(selected["/usr/bin/cgminer"]) != pins["cgminer_sha256"]:
        raise _error_cls(f"{model} cgminer hash drift")
    _checked_pin(
        selected["/etc/init.d/cgminer.sh"], pins["cgminer_script"], "cgminer.sh"
    )
    _checked_pin(
        selected["/etc/init.d/bitmainer_setup.sh"], pins["setup_script"], "setup script"
    )
    _checked_pin(
        selected["/etc/cgminer.conf.factory"], pins["factory_config"], "factory config"
    )
    _checked_pin(selected[pins["pattern_path"]], pins["pattern_pin"], "pattern file")
    if selected[pins["pattern_path"]].count(b"\n") != pins["pattern_lines"]:
        raise _error_cls(f"{model} pattern line-count drift")
    for path, size, digest in _common_rows:
        _checked_pin(selected[path], (size, digest), path)
    script = selected["/etc/init.d/cgminer.sh"]
    required_script_bytes = (
        b"# RED LED: GPIO941",
        b"# GREEN LED: GPIO942",
        b"echo 954 > /sys/class/gpio/export",
        b"echo 955 > /sys/class/gpio/export",
        b"echo 958 > /sys/class/gpio/export",
        b"echo 959 > /sys/class/gpio/export",
        b"insmod /lib/modules/bitmain_axi.ko",
        b"fpga_mem_offset_addr=0x3F000000",
        b"fpga_mem_offset_addr=0x1F000000",
        b"fpga_mem_offset_addr=0x0F000000",
    )
    if _any(token not in script for token in required_script_bytes):
        raise _error_cls(f"{model} carrier init-script contract drift")
    return {
        "artifact": {
            "package_sha256": pins["package_sha256"],
            "version": pins["version"],
            "embedded_certificate_sha256": _cert_sha256,
            "signature_evidence": "payload-contained-signature-material-not-an-anchored-root",
        },
        "boot": {
            "boot_bin": _file_record_fn("BOOT.bin", inner["BOOT.bin"]),
            "devicetree_member_present": "devicetree.dtb" in inner,
            "kernel": _file_record_fn("uImage", inner["uImage"]),
            "ramdisk": _file_record_fn("uramdisk.image.gz", inner["uramdisk.image.gz"]),
            "ramdisk_header": uimage,
        },
        "rootfs": {
            "ext2_sha256": _sha256_fn(ext2),
            "ext2_size": _len(ext2),
            "selected_files": [
                _file_record_fn(path, selected[path]) for path in selected_paths
            ],
            "pattern_lines": pins["pattern_lines"],
        },
    }


def _carrier_contract_payload() -> Dict[str, Any]:
    return {
        "derivation": {
            "method": "reviewed-static-semantic-profile",
            "mechanical_extraction": False,
            "binding": "profile is admitted only after exact package, cgminer, module, script, and selected-rootfs pins pass",
            "reviewed_function_offsets": {
                "S15": {
                    "carrier_map_init": "0x0003c5c0",
                    "pll_builder": "0x00038da4",
                    "work_submit": "0x00045040",
                    "fpga_return_thread": "0x00046780",
                    "pic_frame_transport": "0x0007dad4",
                    "pic_start": "0x0007e0e4",
                    "pic_heartbeat": "0x0007e304",
                    "pic_init": "0x0007ef10",
                    "external_temperature_transaction": "0x000814bc",
                    "external_temperature_decode": "0x00083a9c",
                    "chain_reset": "0x00087310",
                    "fan_tach_decode": "0x00087988",
                    "work_word_write": "0x0008a3e8",
                    "work_ready_read": "0x0008a448",
                },
                "T15": {
                    "carrier_map_init": "0x0003c5b8",
                    "pll_builder": "0x00038da4",
                    "work_submit": "0x00045074",
                    "fpga_return_thread": "0x000467b4",
                    "pic_frame_transport": "0x0007da9c",
                    "pic_start": "0x0007e0ac",
                    "pic_heartbeat": "0x0007e2cc",
                    "pic_init": "0x0007eed8",
                    "external_temperature_transaction": "0x00081484",
                    "chain_reset": "0x00087230",
                    "work_word_write": "0x0008a308",
                    "work_ready_read": "0x0008a368",
                },
                "modules": {
                    "bitmain_axi.ko": "axi_fpga_dev_init/axi_fpga_dev_mmap",
                    "fpga_mem_driver.ko": "fpga_mem_init/fpga_mem_mmap",
                },
            },
        },
        "authority": {
            "evidence_only": True,
            "install_authorized": False,
            "live_probe_authorized": False,
            "runtime_mutation_authorized": False,
            "safe_runtime_composition_proven": False,
            "wire_transactions_authorized": False,
        },
        "axi_fpga": {
            "device": "/dev/axi_fpga_dev",
            "physical_base": "0x40000000",
            "kernel_region_length": "0x1400",
            "userspace_map_length": "0x160",
            "version_magic_low16": "0xc501",
            "registers": {
                "fan_tach_stream": "0x04",
                "work_fifo_ready_bitmap": "0x0c",
                "general_i2c_command": "0x30",
                "chain_reset_bitmap": "0x34",
                "work_words": {"count": 13, "first": "0x40", "last": "0x70"},
                "fan_pwm_control": "0x84",
                "mining_timeout_control": "0x88",
                "misc_control": "0x100",
            },
        },
        "fpga_memory": {
            "device": "/dev/fpga_mem",
            "map_length": "0x01000000",
            "physical_base_by_memtotal_kib": [
                {"condition": ">1000000", "base": "0x3f000000"},
                {"condition": ">400000 and <1000000", "base": "0x1f000000"},
                {"condition": "otherwise", "base": "0x0f000000"},
            ],
            "data_window_offsets": ["0x00200000", "0x00210000"],
        },
        "gpio": {
            "init_outputs_low": {
                "941": "red LED",
                "942": "green LED",
                "954": "LCD CS",
                "955": "LCD SID",
                "958": "LCD SCLK",
                "959": "LCD RESET",
            },
            "gpio907": {
                "observed_helpers": ["drive low", "drive high"],
                "polarity_and_load": "unproven",
                "authorized": False,
            },
            "asic_chain_reset": {
                "location": "AXI register 0x34, not a proved Linux GPIO",
                "operation": "read-modify-write bit (1 << chain)",
                "stock_sequence_seconds": ["assert", 3, "deassert", 1],
                "authorized": False,
            },
        },
        "fpga_serial_and_work": {
            "linux_uart_device": None,
            "electrical_uart_mapping": "unproven",
            "transport": "FPGA AXI command/work registers",
            "work_word0_for_chain": "0x01000080 | (chain << 16)",
            "mutation_authorized": False,
        },
        "bm1391_enumeration": {
            "counted_reply": "register 0x00 with response value high16 == 0x1391",
            "expected_responses_per_present_chain": {
                "S15": {
                    "count": 72,
                    "function": "0x00041248",
                    "count_compare": "0x0004171c",
                    "chip_id_compare": "0x000417b4..0x000417b8",
                },
                "T15": {
                    "count": 60,
                    "function": "0x00041250",
                    "count_compare": "0x0004172c",
                    "chip_id_compare": "0x000417c4..0x000417c8",
                },
            },
            "physical_topology_authorized": False,
            "caveat": (
                "the held S15 binary requires 72 responses while the S15 guide "
                "states 60 twice but separately implies 72 from six chips in each "
                "of 12 domains; exact board/release discrimination is unresolved. "
                "T15 has no independent "
                "held physical-topology source"
            ),
        },
        "fpga_return_and_work_binding": {
            "record": {
                "length_bytes": 8,
                "byte_order": "two little-endian u32 words",
                "nonce_selector": "word0 bit31",
                "chain": "word0 bits3:0",
            },
            "nonce": {
                "stock_valid_bit": "word0 bit7",
                "external_enable_required": True,
                "work_id": "word0 bits30:16 masked to 0x7fff",
                "nonce": "word1 full u32",
                "word0_bit6_checked_by_stock": False,
            },
            "register": {
                "crc_error": "word0 bit6",
                "crc5": "word0 bits28:24",
                "type": "word0 bits30:29 (diagnostic; not a queue gate)",
                "chip_address": "word0 bits23:16",
                "register": "word0 bits15:8",
                "value": "word1 full u32",
                "register_0x40_has_external_include_gate": True,
            },
            "outstanding_work_record_bytes": 64,
            "bound_nonce_record_bytes": 60,
            "bound_fields": [
                "snapshot word +0x00 (job id)",
                "returned work id",
                "snapshot words +0x04/+0x08/+0x0c",
                "returned nonce and chain",
                "snapshot bytes +0x20..+0x3f",
            ],
            "host_ring": {
                "capacity": 511,
                "write_index_wraps_after": 510,
                "queued_count_saturates_at": 511,
                "stock_nonce_full_behavior": "copy occurs before capacity refusal; unread overwrite is possible",
                "clean_codec_behavior": "full enqueue refused before copy",
            },
            "runtime_authorized": False,
        },
        "pic": {
            "transport": "FPGA general-I2C command register 0x30",
            "channel_selector_for_reviewed_binary": "0x20 | (chain & 7)",
            "generic_frame": ["0x55", "0xaa", "0x04", "command", "data0", "data1"],
            "start": {
                "frame": ["0x55", "0xaa", "0x04", "0x07", "0x00", "0x0b"],
                "expected_reply": ["0x07", "0x01"],
                "attempts": 3,
            },
            "init": {
                "frame": ["0x55", "0xaa", "0x04", "0x06", "0x00", "0x0a"],
                "expected_reply": ["0x06", "0x01"],
                "attempts": 3,
            },
            "heartbeat": {
                "frame": ["0x55", "0xaa", "0x04", "0x16", "0x00", "0x1a"],
                "expected_reply": ["0x16", "0x01"],
                "attempts": 3,
                "caller_period_seconds": 10,
                "observed_failure_action": "retry/log only; no safe rail cut proved",
            },
            "pre_bringup_frame": {
                "bytes": ["0x55", "0xaa", "0x05", "0x15", "0x01", "0x00", "0x1b"],
                "expected_reply": ["0x15", "0x01"],
                "attempts": 3,
            },
            "mutation_authorized": False,
        },
        "thermal_and_fans": {
            "external_temperature": {
                "asic_register": "0x1c",
                "attempts": 2,
                "stock_decode": "(reply_low_byte - 0x40); secondary value adds 15",
                "wire_read_authorized": False,
            },
            "fan_tach": {
                "register": "0x04",
                "fan_index_bits": "10:8",
                "count_bits": "7:0",
                "stock_rpm_scale": 120,
            },
            "fan_pwm": {
                "register": "0x84",
                "stock_percent_clamp": [30, 100],
                "stock_encoding": "((percent // 2) << 16) | ((5000 - 50*percent) // 100)",
                "mutation_authorized": False,
            },
            "safe_cutoff_composition": "unproven",
        },
        "pll": {
            "reference_clock_mhz": 25.0,
            "stock_word_fields": {
                "fbdiv": "23:16",
                "refdiv": "15:8",
                "postdiv1": "7:4",
                "postdiv2": "3:0",
            },
            "factory_frequency_token": "O (PIC/EEPROM-selected, not a numeric default)",
            "safe_default_frequency_mhz": None,
            "mutation_authorized": False,
        },
        "watchdogs": {
            "pic_heartbeat": "10-second caller; three retries; log-only failure observed",
            "mining_timeout_register": "AXI 0x88; not established as a safety watchdog",
            "generic_cgminer_watchdog": "process/miner policy; not a carrier rail-cut proof",
            "safe_shutdown_path_proven": False,
        },
        "remaining_blockers": [
            "controller/board revision identity and DTB are absent from both packages",
            "GPIO907 load and polarity are not established",
            "electrical UART routing and signal levels are not established",
            "PIC heartbeat failure does not prove de-energization",
            "thermal sampling does not prove an independent fail-safe cutoff",
            "no numeric default PLL/frequency is established by the factory config",
            "no lab capture binds this stock composition to a DCENT runtime",
            "the S15 stock 72-response profile meets an internally inconsistent guide (60 stated twice, 72 implied once)",
            "T15 physical chip count and chain-slot population lack an independent source",
            "recovered work binding does not prove DCENT session ownership, share validation, or stale-work eviction",
        ],
    }


def _build_public_api(
    _source_inspector: Any = _inspect_model_impl,
    _source_contract_payload: Any = _carrier_contract_payload,
):
    """Close every admission/mint dependency before publishing the API."""

    trusted_inspect_model = _source_inspector
    trusted_contract_payload = _source_contract_payload
    trusted_dumps = json.dumps
    trusted_sha256 = hashlib.sha256
    trusted_contract_cls = CarrierContractReceipt
    trusted_receipt_cls = CarrierEvidenceReceipt
    trusted_setattr = object.__setattr__
    trusted_error_cls = EvidenceError
    trusted_fspath = os.fspath
    trusted_abspath = os.path.abspath
    trusted_dirname = os.path.dirname
    trusted_lstat = os.lstat
    trusted_open = os.open
    trusted_read = os.read
    trusted_fstat = os.fstat
    trusted_close = os.close
    trusted_is_regular = stat.S_ISREG
    trusted_is_symlink = stat.S_ISLNK
    trusted_getattr = getattr
    trusted_len = len
    trusted_min = min
    trusted_reversed = reversed
    trusted_key_error = KeyError
    trusted_reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    trusted_open_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    package_pins = {
        "S15": (
            24_962_829,
            "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
            1_873,
            "c4ca441f5331217f261d15c9e6f9ae578c79aa885325ca7ef6e2bcb2dd48961e",
        ),
        "T15": (
            23_696_441,
            "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
            1_873,
            "1fd534437eb653d00f0495a3c5253025d6cfff204c0047be21387bcad2abc408",
        ),
    }
    models_size = 3_761
    models_sha256 = "66b661cf5948a19c16cd780d9057ed9948816704d92a57a0f6152682dbbcaa49"
    contract_size = 7_040
    contract_sha256 = "44d21708c393c842739491319e0280126f3b423167249442ff873a87ba1118ea"
    common_paths = (
        "/lib/modules/bitmain_axi.ko",
        "/lib/modules/fpga_mem_driver.ko",
    )

    def metadata_tuple(value: Any) -> Tuple[Any, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_mode,
            value.st_nlink,
            trusted_getattr(value, "st_ctime_ns", None),
        )

    def reject_source_reparse_components(raw_path: str) -> str:
        absolute = trusted_abspath(raw_path)
        chain = []
        current = absolute
        while True:
            chain.append(current)
            parent = trusted_dirname(current)
            if parent == current:
                break
            current = parent
        for component in trusted_reversed(chain):
            info = trusted_lstat(component)
            if trusted_is_symlink(info.st_mode) or (
                trusted_getattr(info, "st_file_attributes", 0) & trusted_reparse_flag
            ):
                raise trusted_error_cls("symlink/reparse source path component refused")
        return absolute

    def admit_exact_outer(model: str, package: Path) -> None:
        try:
            expected_size, expected_digest, _, _ = package_pins[model]
        except trusted_key_error as error:
            raise trusted_error_cls(f"unknown exact model: {model}") from error
        raw_path = trusted_fspath(package)
        absolute = reject_source_reparse_components(raw_path)
        before_path = trusted_lstat(absolute)
        if not trusted_is_regular(before_path.st_mode) or before_path.st_nlink != 1:
            raise trusted_error_cls("package must be a single-link regular file")
        if before_path.st_size != expected_size:
            raise trusted_error_cls("package size pin mismatch before read")

        descriptor = trusted_open(absolute, trusted_open_flags)
        try:
            before = trusted_fstat(descriptor)
            if not trusted_is_regular(before.st_mode) or before.st_nlink != 1:
                raise trusted_error_cls(
                    "opened package is not a regular single-link file"
                )
            if before.st_size != expected_size:
                raise trusted_error_cls("package size pin mismatch on descriptor")
            if (before.st_dev, before.st_ino) != (
                before_path.st_dev,
                before_path.st_ino,
            ):
                raise trusted_error_cls(
                    "package identity changed before descriptor open"
                )
            digest = trusted_sha256()
            remaining = expected_size
            while remaining:
                chunk = trusted_read(descriptor, trusted_min(1024 * 1024, remaining))
                if not chunk:
                    raise trusted_error_cls("package reached EOF before pinned size")
                if trusted_len(chunk) > remaining:
                    raise trusted_error_cls("reader returned bytes beyond pinned size")
                digest.update(chunk)
                remaining -= trusted_len(chunk)
            if trusted_read(descriptor, 1):
                raise trusted_error_cls("package grew beyond pinned size")
            after = trusted_fstat(descriptor)
            if metadata_tuple(after) != metadata_tuple(before):
                raise trusted_error_cls("package metadata changed during read")
        finally:
            trusted_close(descriptor)
        after_path = trusted_lstat(absolute)
        if metadata_tuple(after_path) != metadata_tuple(before_path):
            raise trusted_error_cls("package path metadata changed during read")
        actual = digest.hexdigest()
        if actual != expected_digest:
            raise trusted_error_cls(
                f"package hash drift for {model}: expected {expected_digest}, got {actual}"
            )

    def canonical_model(model: str, package: Path) -> Tuple[Dict[str, Any], str]:
        admit_exact_outer(model, package)
        result = trusted_inspect_model(model, package)
        canonical = trusted_dumps(result, sort_keys=True, separators=(",", ":"))
        encoded = canonical.encode("utf-8")
        _, _, expected_size, expected_digest = package_pins[model]
        if trusted_len(encoded) != expected_size:
            raise trusted_error_cls(f"{model} canonical evidence size drift")
        if trusted_sha256(encoded).hexdigest() != expected_digest:
            raise trusted_error_cls(f"{model} canonical evidence hash drift")
        return result, canonical

    def canonical_contract() -> str:
        canonical = trusted_dumps(
            trusted_contract_payload(), sort_keys=True, separators=(",", ":")
        )
        encoded = canonical.encode("utf-8")
        if trusted_len(encoded) != contract_size:
            raise trusted_error_cls("canonical carrier contract size drift")
        if trusted_sha256(encoded).hexdigest() != contract_sha256:
            raise trusted_error_cls("canonical carrier contract hash drift")
        return canonical

    def inspect_model(model: str, package: Path) -> Dict[str, Any]:
        """Inspect one exact release without exposing dependency overrides."""

        result, _ = canonical_model(model, package)
        return result

    def carrier_contract() -> CarrierContractReceipt:
        """Return an immutable, deliberately unassociated semantic profile."""

        return trusted_contract_cls(canonical_contract_json=canonical_contract())

    def build_report_impl(s15: Path, t15: Path) -> CarrierEvidenceReceipt:
        """Inspect both packages and mint one immutable exact-evidence receipt.

        The CLI JSON object remains byte-compatible through :meth:`to_pretty_json`.
        Python callers now receive a trust-bearing receipt rather than a mutable
        nested dictionary; :meth:`to_dict` creates a detached compatibility view.
        """

        s15_model, _ = canonical_model("S15", s15)
        t15_model, _ = canonical_model("T15", t15)
        models = {"S15": s15_model, "T15": t15_model}
        s15_files = {
            item["path"]: item for item in models["S15"]["rootfs"]["selected_files"]
        }
        t15_files = {
            item["path"]: item for item in models["T15"]["rootfs"]["selected_files"]
        }
        for path in common_paths:
            if s15_files[path] != t15_files[path]:
                raise trusted_error_cls(f"S15/T15 common module drift: {path}")
        for boot_name in ("boot_bin", "kernel"):
            if models["S15"]["boot"][boot_name] != models["T15"]["boot"][boot_name]:
                raise trusted_error_cls(
                    f"S15/T15 shared boot artifact drift: {boot_name}"
                )

        canonical_models = trusted_dumps(models, sort_keys=True, separators=(",", ":"))
        encoded_models = canonical_models.encode("utf-8")
        if trusted_len(encoded_models) != models_size:
            raise trusted_error_cls("combined canonical model evidence size drift")
        if trusted_sha256(encoded_models).hexdigest() != models_sha256:
            raise trusted_error_cls("combined canonical model evidence hash drift")
        contract = trusted_contract_cls(canonical_contract_json=canonical_contract())
        trusted_setattr(contract, "artifact_association_verified", True)
        receipt = trusted_receipt_cls(
            schema="dcent.s15-t15-bm1391-carrier-evidence.v1",
            canonical_models_json=canonical_models,
            shared_carrier_contract=contract,
        )
        trusted_setattr(receipt, "receipt_verified", True)
        return receipt

    def build_report(s15: Path, t15: Path) -> CarrierEvidenceReceipt:
        """Public wrapper around the private exact-evidence mint."""

        return build_report_impl(s15, t15)

    def cli_build_report(s15: Path, t15: Path) -> CarrierEvidenceReceipt:
        """Private CLI wrapper, distinct from the public function object."""

        return build_report_impl(s15, t15)

    return inspect_model, carrier_contract, build_report, cli_build_report


inspect_model, carrier_contract, build_report, _private_cli_build_report = (
    _build_public_api()
)
del _build_public_api
del _inspect_model_impl
del _carrier_contract_payload


def parse_args(
    argv: Sequence[str],
    _argparse: Any = argparse,
    _description: Optional[str] = __doc__,
    _path_cls: type = Path,
) -> argparse.Namespace:
    parser = _argparse.ArgumentParser(description=_description)
    parser.add_argument(
        "--s15", type=_path_cls, required=True, help="held signed S15 tar.gz"
    )
    parser.add_argument(
        "--t15", type=_path_cls, required=True, help="held signed T15 tar.gz"
    )
    parser.add_argument(
        "--output", type=_path_cls, help="write JSON here (stdout by default)"
    )
    return parser.parse_args(argv)


def _build_cli(
    _source_build_report: Any = _private_cli_build_report,
    _source_serializer: Any = _private_cli_pretty_json,
):
    trusted_parser_cls = argparse.ArgumentParser
    trusted_description = __doc__
    trusted_path_cls = Path
    trusted_build_report = _source_build_report
    trusted_serialize = _source_serializer
    trusted_argv = sys.argv
    trusted_stdout = sys.stdout
    trusted_stderr = sys.stderr
    trusted_print = print
    trusted_errors = (EvidenceError, OSError, UnicodeError)
    trusted_error_cls = EvidenceError
    trusted_fspath = os.fspath
    trusted_abspath = os.path.abspath
    trusted_normcase = os.path.normcase
    trusted_dirname = os.path.dirname
    trusted_lstat = os.lstat
    trusted_open = os.open
    trusted_write = os.write
    trusted_fsync = os.fsync
    trusted_fstat = os.fstat
    trusted_close = os.close
    trusted_is_directory = stat.S_ISDIR
    trusted_is_regular = stat.S_ISREG
    trusted_is_symlink = stat.S_ISLNK
    trusted_getattr = getattr
    trusted_bool = bool
    trusted_len = len
    trusted_reversed = reversed
    trusted_not_found = FileNotFoundError
    trusted_reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    trusted_write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    def parse_cli(argv: Sequence[str]) -> argparse.Namespace:
        parser = trusted_parser_cls(description=trusted_description)
        parser.add_argument(
            "--s15", type=trusted_path_cls, required=True, help="held signed S15 tar.gz"
        )
        parser.add_argument(
            "--t15", type=trusted_path_cls, required=True, help="held signed T15 tar.gz"
        )
        parser.add_argument(
            "--output",
            type=trusted_path_cls,
            help="write JSON here (stdout by default)",
        )
        return parser.parse_args(argv)

    def path_identity(info: Any) -> Tuple[Any, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            trusted_getattr(info, "st_file_attributes", 0),
        )

    def is_reparse(info: Any) -> bool:
        return trusted_is_symlink(info.st_mode) or trusted_bool(
            trusted_getattr(info, "st_file_attributes", 0) & trusted_reparse_flag
        )

    def preflight_output(
        output: Path, s15: Path, t15: Path
    ) -> Tuple[str, Tuple[Any, ...]]:
        absolute = trusted_abspath(trusted_fspath(output))
        normalized = trusted_normcase(absolute)
        for source in (s15, t15):
            if normalized == trusted_normcase(trusted_abspath(trusted_fspath(source))):
                raise trusted_error_cls("output path aliases an input package")

        try:
            trusted_lstat(absolute)
        except trusted_not_found:
            pass
        else:
            raise trusted_error_cls("output path already exists; refusing overwrite")

        parent = trusted_dirname(absolute)
        chain = []
        current = parent
        while True:
            chain.append(current)
            ancestor = trusted_dirname(current)
            if ancestor == current:
                break
            current = ancestor
        parent_info = None
        for component in trusted_reversed(chain):
            try:
                info = trusted_lstat(component)
            except trusted_not_found as error:
                raise trusted_error_cls("output parent path does not exist") from error
            if is_reparse(info):
                raise trusted_error_cls("symlink/reparse output path component refused")
            parent_info = info
        if parent_info is None or not trusted_is_directory(parent_info.st_mode):
            raise trusted_error_cls("output parent is not a directory")
        return absolute, path_identity(parent_info)

    def exclusive_write(
        absolute: str, encoded: bytes, expected_parent: Tuple[Any, ...]
    ) -> None:
        parent = trusted_dirname(absolute)
        current_parent = trusted_lstat(parent)
        if (
            is_reparse(current_parent)
            or path_identity(current_parent) != expected_parent
        ):
            raise trusted_error_cls("output parent identity changed before create")
        descriptor = trusted_open(absolute, trusted_write_flags, 0o600)
        try:
            opened = trusted_fstat(descriptor)
            if not trusted_is_regular(opened.st_mode) or opened.st_nlink != 1:
                raise trusted_error_cls("new output is not a single-link regular file")
            offset = 0
            while offset < trusted_len(encoded):
                written = trusted_write(descriptor, encoded[offset:])
                if written <= 0:
                    raise trusted_error_cls("short write while creating output")
                offset += written
            trusted_fsync(descriptor)
            after = trusted_fstat(descriptor)
            if (
                not trusted_is_regular(after.st_mode)
                or after.st_nlink != 1
                or after.st_size != trusted_len(encoded)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise trusted_error_cls("output identity changed during write")
        finally:
            trusted_close(descriptor)
        output_info = trusted_lstat(absolute)
        if is_reparse(output_info) or (output_info.st_dev, output_info.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise trusted_error_cls("output path identity changed after write")
        final_parent = trusted_lstat(parent)
        if is_reparse(final_parent) or path_identity(final_parent) != expected_parent:
            raise trusted_error_cls("output parent identity changed during write")

    def main(argv: Optional[Sequence[str]] = None) -> int:
        args = parse_cli(trusted_argv[1:] if argv is None else argv)
        try:
            output_state = (
                preflight_output(args.output, args.s15, args.t15)
                if args.output
                else None
            )
            report = trusted_build_report(args.s15, args.t15)
            encoded = trusted_serialize(report)
            if args.output:
                absolute, initial_parent = output_state
                final_absolute, final_parent = preflight_output(
                    args.output, args.s15, args.t15
                )
                if final_absolute != absolute or final_parent != initial_parent:
                    raise trusted_error_cls("output path changed before create")
                exclusive_write(absolute, encoded.encode("utf-8"), final_parent)
            else:
                trusted_stdout.write(encoded)
        except trusted_errors as error:
            trusted_print(f"error: {error}", file=trusted_stderr)
            return 1
        return 0

    return main


main = _build_cli()
del _build_cli
del _private_cli_build_report
del _private_cli_pretty_json


if __name__ == "__main__":
    raise SystemExit(main())
