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
import posixpath
import struct
import sys
import tarfile
import zlib
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

COMMON_FILE_PINS = {
    "/lib/modules/bitmain_axi.ko": (
        7_519,
        "00500755f72420e3c084e0ea6ecfe71b7989a219a972c2db5e34818f3f750ab4",
    ),
    "/lib/modules/fpga_mem_driver.ko": (
        8_030,
        "2ec39eda2d5b691c07475b73797c335949a56eb6df9b0a5d83881474bfff0c3f",
    ),
}

MODEL_PINS: Mapping[str, Mapping[str, Any]] = {
    "S15": {
        "package_sha256": "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
        "version": "1.92992.0.14",
        "fw_tar_sha256": "3038ed2272ca35f32571e871ca1ca615337167abedbca62261d5049e443629c4",
        "ramdisk_sha256": "04572993000af9bd2257bb03f6cad72cc7e341b9ea7614d9a25506b58d0f72cd",
        "cgminer_sha256": "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8",
        "cgminer_script": (
            4_488,
            "a558be52e41b2ca74fbf5e16e57f8096aa6e79ad44b479ded3d7ba27598da4ba",
        ),
        "setup_script": (
            1_659,
            "d19080f7ba095bd538c896f2d4985751c78066d556ea00b9caeadc726aed09b9",
        ),
        "factory_config": (
            431,
            "eaad2ee240947990d084a4739efb35811ac06178d910e8bcfa5a2562345cf8f9",
        ),
        "pattern_path": "/etc/91602_patten_72.txt",
        "pattern_lines": 147_456,
        "pattern_pin": (
            17_694_720,
            "165aa04898d62fc689f0d116aeb6301380b7dbb961d10dfa61831ab1868f21c0",
        ),
    },
    "T15": {
        "package_sha256": "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
        "version": "1.92992.0.13",
        "fw_tar_sha256": "cda8ebaba3d8d1cefcffa7688a59ecede6b309f3f961ea856bdc296ebd662505",
        "ramdisk_sha256": "e3f6d7c1cf6ab59c43762906debc13b164d2d2bf3aa1d6e193eb53aa848bde37",
        "cgminer_sha256": "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01",
        "cgminer_script": (
            5_532,
            "eb58a01bd0cb8e8c7b5546825fbeb0f2d9e15e922a32853fb7dea27fb6e194ac",
        ),
        "setup_script": (
            1_702,
            "e32e94df4cf97e0cb1239852d8ed8672bcd60760e478e687a5e619bad7097294",
        ),
        "factory_config": (
            431,
            "859868786b6385f3f0ae542c6f786d39a3778054800ae5c5371fce69e7333fd7",
        ),
        "pattern_path": "/etc/91602_patten_60.txt",
        "pattern_lines": 122_880,
        "pattern_pin": (
            14_622_720,
            "29e450043a8cae2c207efee971a2233835d20a4c0d01fbe3a6dd20fd4dcdd563",
        ),
    },
}

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


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_blob(path: Path, expected_sha256: str) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > MAX_PACKAGE_BYTES:
        raise EvidenceError(f"package size outside bound: {size}")
    data = path.read_bytes()
    actual = sha256(data)
    if actual != expected_sha256:
        raise EvidenceError(
            f"package hash drift for {path.name}: expected {expected_sha256}, got {actual}"
        )
    return data


def bounded_gzip(data: bytes, limit: int, label: str) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    cursor = 0
    while cursor < len(data):
        chunk = data[cursor : cursor + 64 * 1024]
        cursor += len(chunk)
        output.extend(decoder.decompress(chunk, limit + 1 - len(output)))
        if len(output) > limit:
            raise EvidenceError(f"{label} exceeds decompression bound")
        if decoder.eof:
            if decoder.unused_data or cursor != len(data):
                raise EvidenceError(f"{label} has trailing or concatenated gzip data")
            break
    if not decoder.eof:
        raise EvidenceError(f"{label} is a truncated gzip stream")
    output.extend(decoder.flush(limit + 1 - len(output)))
    if len(output) > limit:
        raise EvidenceError(f"{label} exceeds decompression bound")
    return bytes(output)


def _safe_member_name(name: str) -> bool:
    return (
        bool(name)
        and "\\" not in name
        and not name.startswith("/")
        and posixpath.normpath(name) == name
        and all(part not in ("", ".", "..") for part in name.split("/"))
    )


def exact_tar_gz(data: bytes, expected: Iterable[str], label: str) -> Dict[str, bytes]:
    raw = bounded_gzip(data, MAX_TAR_BYTES, f"{label} tar")
    expected_set = frozenset(expected)
    result: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_TAR_MEMBERS:
                raise EvidenceError(f"{label} has too many members")
            for member in members:
                if not _safe_member_name(member.name):
                    raise EvidenceError(f"{label} has unsafe path {member.name!r}")
                if not member.isreg():
                    raise EvidenceError(
                        f"{label} member is not a regular file: {member.name}"
                    )
                if member.name in result:
                    raise EvidenceError(f"{label} has duplicate member {member.name}")
                if member.size < 0 or member.size > MAX_TAR_BYTES:
                    raise EvidenceError(
                        f"{label} member size outside bound: {member.name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise EvidenceError(f"{label} cannot read {member.name}")
                payload = stream.read(member.size + 1)
                if len(payload) != member.size:
                    raise EvidenceError(f"{label} member is truncated: {member.name}")
                result[member.name] = payload
    except tarfile.TarError as error:
        raise EvidenceError(f"invalid {label} tar: {error}") from error
    if frozenset(result) != expected_set:
        missing = sorted(expected_set - frozenset(result))
        extra = sorted(frozenset(result) - expected_set)
        raise EvidenceError(f"{label} schema drift; missing={missing}, extra={extra}")
    return result


def checked_pin(data: bytes, pin: Tuple[int, str], label: str) -> None:
    expected_size, expected_hash = pin
    if len(data) != expected_size or sha256(data) != expected_hash:
        raise EvidenceError(f"{label} failed exact size/hash pin")


def parse_legacy_ramdisk(
    image: bytes, expected_hash: str
) -> Tuple[bytes, Dict[str, Any]]:
    if sha256(image) != expected_hash:
        raise EvidenceError("uramdisk.image.gz hash drift")
    if len(image) < 64:
        raise EvidenceError("legacy ramdisk is truncated")
    fields = struct.unpack(">7I4B32s", image[:64])
    magic, header_crc, timestamp, size, load, entry, data_crc = fields[:7]
    os_id, arch, image_type, compression = fields[7:11]
    name = fields[11].rstrip(b"\0")
    header_for_crc = bytearray(image[:64])
    header_for_crc[4:8] = b"\0\0\0\0"
    if magic != UIMAGE_MAGIC or zlib.crc32(header_for_crc) & 0xFFFFFFFF != header_crc:
        raise EvidenceError("legacy ramdisk header CRC/magic invalid")
    payload = image[64:]
    if size != len(payload) or zlib.crc32(payload) & 0xFFFFFFFF != data_crc:
        raise EvidenceError("legacy ramdisk data CRC/size invalid")
    if (load, entry, os_id, arch, image_type, compression, name) != (
        0,
        0,
        5,
        2,
        3,
        1,
        b"",
    ):
        raise EvidenceError("legacy ramdisk metadata drift")
    ext2 = bounded_gzip(payload, MAX_RAMDISK_BYTES, "ext2 ramdisk")
    return ext2, {
        "data_crc32": f"{data_crc:08x}",
        "payload_size": size,
        "timestamp": timestamp,
        "type": "Linux/ARM/ramdisk/gzip",
    }


class Ext2Reader:
    """Small fail-closed reader for regular files in the held ext2 images."""

    def __init__(self, image: bytes):
        self.image = image
        if len(image) < 2048:
            raise EvidenceError("ext2 image is truncated")
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
            raise EvidenceError("ext2 superblock magic invalid")
        if log_block_size > 2:
            raise EvidenceError("unsupported ext2 block size")
        self.block_size = 1024 << log_block_size
        if (
            self.block_size * self.blocks_count > len(image)
            or self.blocks_per_group == 0
            or self.inodes_per_group == 0
            or self.inode_size not in (128, 256)
        ):
            raise EvidenceError("ext2 geometry invalid")
        # FILETYPE is the only incompatible feature in the held images.
        if incompat & ~0x2 or ro_compat & ~0x1 or compat & ~0x38:
            raise EvidenceError("unsupported ext2 feature flags")
        group_count = math.ceil(
            (self.blocks_count - self.first_data_block) / self.blocks_per_group
        )
        descriptor_offset = (2 if self.block_size == 1024 else 1) * self.block_size
        descriptor_bytes = group_count * 32
        if descriptor_offset + descriptor_bytes > len(image):
            raise EvidenceError("ext2 group descriptors truncated")
        self.inode_tables = [
            self._u32(image, descriptor_offset + group * 32 + 8)
            for group in range(group_count)
        ]
        if any(block <= 0 or block >= self.blocks_count for block in self.inode_tables):
            raise EvidenceError("ext2 inode table outside image")

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        return struct.unpack_from("<H", data, offset)[0]

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        return struct.unpack_from("<I", data, offset)[0]

    def _block(self, number: int) -> bytes:
        if number <= 0 or number >= self.blocks_count:
            raise EvidenceError(f"ext2 block outside image: {number}")
        offset = number * self.block_size
        return self.image[offset : offset + self.block_size]

    def _inode(self, number: int) -> Tuple[int, int, Sequence[int]]:
        if number <= 0 or number > self.inodes_count:
            raise EvidenceError(f"ext2 inode outside image: {number}")
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        offset = self.inode_tables[group] * self.block_size + index * self.inode_size
        inode = self.image[offset : offset + self.inode_size]
        if len(inode) != self.inode_size:
            raise EvidenceError("ext2 inode is truncated")
        mode = self._u16(inode, 0)
        size = self._u32(inode, 4)
        if mode & 0xF000 == 0x8000 and self.inode_size >= 112:
            size |= self._u32(inode, 108) << 32
        pointers = struct.unpack_from("<15I", inode, 40)
        return mode, size, pointers

    def _indirect(self, block: int, depth: int) -> Iterable[int]:
        if block == 0:
            return
        values = struct.unpack("<" + "I" * (self.block_size // 4), self._block(block))
        for value in values:
            if value == 0:
                continue
            if depth == 1:
                yield value
            else:
                yield from self._indirect(value, depth - 1)

    def _inode_data(self, number: int) -> Tuple[int, bytes]:
        mode, size, pointers = self._inode(number)
        if size > MAX_RAMDISK_BYTES:
            raise EvidenceError("ext2 inode exceeds reader bound")
        blocks: List[int] = [value for value in pointers[:12] if value]
        blocks.extend(self._indirect(pointers[12], 1))
        blocks.extend(self._indirect(pointers[13], 2))
        blocks.extend(self._indirect(pointers[14], 3))
        needed = math.ceil(size / self.block_size)
        if len(blocks) < needed:
            raise EvidenceError("sparse/truncated ext2 inode is unsupported")
        content = b"".join(self._block(block) for block in blocks[:needed])[:size]
        return mode, content

    def _directory(self, number: int) -> Dict[str, int]:
        mode, content = self._inode_data(number)
        if mode & 0xF000 != 0x4000:
            raise EvidenceError("ext2 path component is not a directory")
        result: Dict[str, int] = {}
        offset = 0
        while offset < len(content):
            if offset + 8 > len(content):
                raise EvidenceError("ext2 directory entry truncated")
            inode = self._u32(content, offset)
            record_length = self._u16(content, offset + 4)
            name_length = content[offset + 6]
            if (
                record_length < 8
                or record_length % 4
                or offset + record_length > len(content)
            ):
                raise EvidenceError("ext2 directory record invalid")
            if name_length > record_length - 8:
                raise EvidenceError("ext2 directory name invalid")
            if inode:
                try:
                    name = content[offset + 8 : offset + 8 + name_length].decode(
                        "utf-8"
                    )
                except UnicodeDecodeError as error:
                    raise EvidenceError("non-UTF8 ext2 path is unsupported") from error
                if name in result:
                    raise EvidenceError(f"duplicate ext2 directory name: {name}")
                result[name] = inode
            offset += record_length
        return result

    def read_regular(self, path: str) -> bytes:
        if not path.startswith("/") or posixpath.normpath(path) != path:
            raise EvidenceError(f"invalid ext2 path: {path!r}")
        inode = 2
        parts = [part for part in path.split("/") if part]
        for part in parts:
            if part in (".", ".."):
                raise EvidenceError(f"unsafe ext2 path: {path!r}")
            entries = self._directory(inode)
            if part not in entries:
                raise EvidenceError(f"missing ext2 path: {path}")
            inode = entries[part]
        mode, content = self._inode_data(inode)
        if mode & 0xF000 != 0x8000:
            raise EvidenceError(f"ext2 target is not a regular file: {path}")
        return content


def _file_record(path: str, data: bytes) -> Dict[str, Any]:
    return {"path": path, "sha256": sha256(data), "size": len(data)}


def inspect_model(model: str, package: Path) -> Dict[str, Any]:
    pins = MODEL_PINS[model]
    package_data = checked_blob(package, pins["package_sha256"])
    outer = exact_tar_gz(package_data, OUTER_MEMBERS, f"{model} outer")
    if outer["version_number"].decode("ascii").strip() != pins["version"]:
        raise EvidenceError(f"{model} version_number drift")
    if sha256(outer["cert.pem"]) != CERT_SHA256:
        raise EvidenceError(f"{model} embedded certificate drift")
    if sha256(outer["fw.tar.gz"]) != pins["fw_tar_sha256"]:
        raise EvidenceError(f"{model} fw.tar.gz hash drift")
    inner = exact_tar_gz(outer["fw.tar.gz"], INNER_MEMBERS, f"{model} firmware")
    checked_pin(inner["BOOT.bin"], BOOT_BIN_PIN, f"{model} BOOT.bin")
    checked_pin(inner["uImage"], KERNEL_PIN, f"{model} uImage")
    expected_md5 = inner["md5_info"].decode("ascii").strip()
    actual_md5 = hashlib.md5(inner["uramdisk.image.gz"]).hexdigest()  # noqa: S324
    if expected_md5 != actual_md5:
        raise EvidenceError(f"{model} md5_info does not bind ramdisk")
    ext2, uimage = parse_legacy_ramdisk(
        inner["uramdisk.image.gz"], pins["ramdisk_sha256"]
    )
    reader = Ext2Reader(ext2)
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
    if sha256(selected["/usr/bin/cgminer"]) != pins["cgminer_sha256"]:
        raise EvidenceError(f"{model} cgminer hash drift")
    checked_pin(
        selected["/etc/init.d/cgminer.sh"], pins["cgminer_script"], "cgminer.sh"
    )
    checked_pin(
        selected["/etc/init.d/bitmainer_setup.sh"], pins["setup_script"], "setup script"
    )
    checked_pin(
        selected["/etc/cgminer.conf.factory"], pins["factory_config"], "factory config"
    )
    checked_pin(selected[pins["pattern_path"]], pins["pattern_pin"], "pattern file")
    if selected[pins["pattern_path"]].count(b"\n") != pins["pattern_lines"]:
        raise EvidenceError(f"{model} pattern line-count drift")
    for path, pin in COMMON_FILE_PINS.items():
        checked_pin(selected[path], pin, path)
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
    if any(token not in script for token in required_script_bytes):
        raise EvidenceError(f"{model} carrier init-script contract drift")
    return {
        "artifact": {
            "package_sha256": pins["package_sha256"],
            "version": pins["version"],
            "embedded_certificate_sha256": CERT_SHA256,
            "signature_evidence": "payload-contained-signature-material-not-an-anchored-root",
        },
        "boot": {
            "boot_bin": _file_record("BOOT.bin", inner["BOOT.bin"]),
            "devicetree_member_present": "devicetree.dtb" in inner,
            "kernel": _file_record("uImage", inner["uImage"]),
            "ramdisk": _file_record("uramdisk.image.gz", inner["uramdisk.image.gz"]),
            "ramdisk_header": uimage,
        },
        "rootfs": {
            "ext2_sha256": sha256(ext2),
            "ext2_size": len(ext2),
            "selected_files": [
                _file_record(path, selected[path]) for path in selected_paths
            ],
            "pattern_lines": pins["pattern_lines"],
        },
    }


def carrier_contract() -> Dict[str, Any]:
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


def build_report(s15: Path, t15: Path) -> Dict[str, Any]:
    models = {"S15": inspect_model("S15", s15), "T15": inspect_model("T15", t15)}
    s15_files = {
        item["path"]: item for item in models["S15"]["rootfs"]["selected_files"]
    }
    t15_files = {
        item["path"]: item for item in models["T15"]["rootfs"]["selected_files"]
    }
    for path in COMMON_FILE_PINS:
        if s15_files[path] != t15_files[path]:
            raise EvidenceError(f"S15/T15 common module drift: {path}")
    for boot_name in ("boot_bin", "kernel"):
        if models["S15"]["boot"][boot_name] != models["T15"]["boot"][boot_name]:
            raise EvidenceError(f"S15/T15 shared boot artifact drift: {boot_name}")
    return {
        "schema": "dcent.s15-t15-bm1391-carrier-evidence.v1",
        "models": models,
        "shared_carrier_contract": carrier_contract(),
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--s15", type=Path, required=True, help="held signed S15 tar.gz"
    )
    parser.add_argument(
        "--t15", type=Path, required=True, help="held signed T15 tar.gz"
    )
    parser.add_argument(
        "--output", type=Path, help="write JSON here (stdout by default)"
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = build_report(args.s15, args.t15)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(encoded)
    except (EvidenceError, OSError, UnicodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
