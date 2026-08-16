#!/usr/bin/env python3
"""Hash-bound, host-only AM2 Xilinx pre-userspace safety analyzer.

The admitted S19j Pro and S19 Pro donor images start at a resident Zynq
BootROM/FSBL/U-Boot chain which is not carried by the SD image.  This analyzer
proves the narrower donor-media handoff (uEnv -> decoded mini-loader -> bootm),
binds the shared stock Bootgen FSBL/FPGA/U-Boot bundle to exact vendor package
epochs, and records the state-dependent write branches in held redundant
environments.  Only S19j Pro has an identity-bound live NAND capture; model-
named S19 Pro packages are not a substitute for a physical-board capture.

The result is evidence, not permission to boot, install, or write media.  The
implementation opens no network endpoint, invokes no helper process, and
never opens an output or device path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePath
import re
import stat
import struct
import sys
from typing import Any, NamedTuple
import zlib


SCHEMA = "dcentos.am2_xilinx_preinit_safety.v2"
MAX_DONOR_BYTES = 64 * 1024 * 1024
MAX_RESIDENT_BYTES = 16 * 1024 * 1024
MAX_STOCK_PACKAGE_BYTES = 32 * 1024 * 1024

IMAGE_BASE = 0x01000000
BOOT_SIZE = 81_920
STAGE_MAGIC = 0xDEADBEEF
STRUCT_OFFSET = 0x10
STRUCT_LENGTH = 0x50
STAGE_SEED_OFFSET = 0x194
LCG_MULTIPLIER = 0x0019660D
LCG_INCREMENT = 0x3C6EF35F
TARGET_MARKER_OFFSET = 0x4028
TARGET_MARKER_LENGTH = 3
NORMALIZED_DECODED_BOOT_SHA256 = (
    "54d98f8c477af9a32d14cccb87b4f169d3e6c3b297ca3433e1bbdafc353676ea"
)
EXACT_UENV = b"uenvcmd=dcache off && fatload mmc 0 0x1000000 boot.bin && go 0x1000000"


class EvidenceError(ValueError):
    """Raised when held evidence does not match the exact admitted contract."""


class Profile(NamedTuple):
    target: str
    physical_model: str
    source_path: Path
    image_size: int
    image_sha256: str
    boot_sha256: str
    decoded_boot_sha256: str
    target_marker_hex: str
    update_size: int
    update_sha256: str


PROFILES = {
    "am2-s19j": Profile(
        "am2-s19j",
        "Antminer S19j Pro",
        Path(
            ""
            "awesome-1.2.6-xil-sd-install/"
            "awesome-s19jpro-xil-sd-v1.2.6-install.img"
        ),
        52_429_312,
        "0d6442db1d490573492c160d331b3d64bc32f3d2d53cfc031bbe7062410b921e",
        "e473b6857b2039d40a1407934fc5b7ee82ddb04f41f376b42ccedd38f888563e",
        "5f6161164d5ee66d62587e85e77e26c4d37e564ab21a857d70541ca38636ae93",
        "6cb9dd",
        12_876_990,
        "190e3dda577a2817268f487aadb8302a3753110c260b8f8d4645fd8f2e1814e2",
    ),
    "am2-s19pro": Profile(
        "am2-s19pro",
        "Antminer S19 Pro",
        Path(
            ""
            "awesome-1.2.6-xil-sd-install/"
            "awesome-s19pro-xil-sd-v1.2.6-install.img"
        ),
        52_429_312,
        "a6b7c268ea1a644b5ada9b0cd5f98a793fea8c6c021742c8ccdb6dfdc4e124a3",
        "8b6d4f440bcc9bf694217c253997b4f9eecc9e57f429ba1a66d3fc768d399809",
        "cc299fd07f020ee4c9eeb7b61385bf87bc0a2dffb05a9122a2dfeaab70310c2c",
        "419ddd",
        12_867_731,
        "c8edc73e6c985cc30ffa851f2065cabc5b22149d677880073225fb0597b7d3ce",
    ),
}

RESIDENT_BOOT_PATH = Path("")
RESIDENT_BOOT_SIZE = 8_388_608
RESIDENT_BOOT_SHA256 = (
    "5dc89d1a853a9c63f5ef12cc02d9bc95173662298f2bb01993e65acbed3900be"
)
RESIDENT_ENV_PATH = Path("")
RESIDENT_ENV_SIZE = 524_288
RESIDENT_ENV_SHA256 = (
    "a0565f2afaf92d269824cde211526c20ea6e300c2dfcda9b682324f57ea36d1d"
)

LIVE_25_ROOT = Path("artifacts/xil-beta-live-s19jpro-25-20260618T071615Z")
LIVE_25_IDENTITY_PATH = LIVE_25_ROOT / "am2_full_nand_identity.txt"
LIVE_25_IDENTITY_SIZE = 459
LIVE_25_IDENTITY_SHA256 = (
    "dc777b4b3a0bfbc870760d56a17c252707a5e4ed549c5e728152d39ed7810e9b"
)
LIVE_25_MANIFEST_PATH = LIVE_25_ROOT / "am2_full_nand_backup_manifest.json"
LIVE_25_MANIFEST_SIZE = 6_302
LIVE_25_MANIFEST_SHA256 = (
    "bd122bf54ba409110b33ec6dd78ff5c5a4c6b583e9bc89cc18c09a6b8f7bddd0"
)
LIVE_25_BOOT_PATH = LIVE_25_ROOT / "full_nand/boot.bin"
LIVE_25_ENV_PATH = LIVE_25_ROOT / "full_nand/uboot_env.bin"
LIVE_25_ENV_SHA256 = (
    "cb75dbdaea0c7fb5fa5289322726dd3b3964d22a1dcfbd151ed3c2477b4fc0af"
)

STOCK_BOOTGEN_SIZE = 2_788_160
STOCK_BOOTGEN_SHA256 = (
    "d48645b3a7e6c04b0dcb5049ff8c920abd480bbfe48f100927389d1032839498"
)
BMU_HEADER_SIZE = 2_048


class StockPackage(NamedTuple):
    physical_model: str
    firmware_epoch: str
    path: Path
    size: int
    sha256: str


STOCK_PACKAGES = (
    StockPackage(
        "Antminer S19j Pro",
        "2021-05-15",
        Path(
            ""
            "stock-20210515/bin/update.bmu"
        ),
        17_906_637,
        "4f1a17a6acec4249b32d523ba3e282ac883a6fb735ab75ba7fd956e72a26e156",
    ),
    StockPackage(
        "Antminer S19 Pro",
        "2020-06-01",
        Path(
            ""
            "stock-20200601/bin/update.bmu"
        ),
        18_106_509,
        "0b285b01de5770031f44134051ec00837387bf29ea1ae3beb266e1ee6362a48f",
    ),
    StockPackage(
        "Antminer S19 Pro",
        "2022-12-26",
        Path(
            ""
            "stock-20221226_dup2/update.bmu"
        ),
        17_964_303,
        "d8e47edf04f77fdac3641be3a6a8b94660e2f9a32f509449cbe3972f1701b661",
    ),
)

EXPECTED_BOOTGEN_PARTITIONS = (
    (
        "FSBL_Zynq7007_miner.elf",
        0x00001700,
        131_088,
        0x00000000,
        0x00000000,
        0x00008010,
        "42b1bcb12a018a7fea3d8f58ae8d9465765d960803b4c29f656ed6c8ab3ba257",
    ),
    (
        "FPGA_Zynq7007_miner.bit",
        0x00021E00,
        2_083_744,
        0x00000000,
        0x00000000,
        0x00008020,
        "ba99e606632de9523a64c15bb6ef65faa5020ad1279dc5e29a32b9aafd1e8bff",
    ),
    (
        "u-boot.elf",
        0x0021F080,
        562_140,
        0x04000000,
        0x04000000,
        0x00008010,
        "f547e56d1c6b0b7562acec789e797708e1f54b240250871f4544b56c0ca825cd",
    ),
)


class FatMember(NamedTuple):
    name: str
    alias: bytes
    size: int
    sha256: str | None


COMMON_FAT_MEMBERS = (
    FatMember("BOOT.BIN", b"BOOT    BIN", BOOT_SIZE, None),
    FatMember(
        "uEnv.txt",
        b"UENV    TXT",
        len(EXACT_UENV),
        "bb52d354c7e8313f89031596a0bd9b54e35d0d08fab41d94c07266f23d222ba6",
    ),
    FatMember(
        "uImage",
        b"UIMAGE     ",
        4_057_312,
        "c9c4d287896946a0f1387d047f93d799dc38d7591090b4e7cc947874a8eb5fd7",
    ),
    FatMember(
        "devicetree.dtb",
        b"DEVICE~1DTB",
        8_043,
        "89c8fc15d63c29aed9921551ce96f56edb85db79033de77101b57b0f4bd6dd9b",
    ),
    FatMember("update.image.gz", b"UPDATE~1GZ ", 0, None),
)

EXPECTED_PARTITIONS = (
    (0x80, 0x0C, 1, 65_536),
    (0x00, 0x83, 65_537, 4_096),
    (0x00, 0x83, 69_633, 32_768),
    (0x00, 0x00, 0, 0),
)

EXPECTED_LOADER_WORDS = {
    0x4828: 0xE3510000,
    0x482C: 0x13500000,
    0x4840: 0xEBFFFFAE,
    0x4860: 0xE59F202C,
    0x4864: 0xE5832000,
    0x486C: 0xE2833004,
    0x4870: 0xE59F2020,
    0x4874: 0xE5832000,
    0x4894: 0xE3A00000,
    0x4898: 0xE12FFF1E,
    0x40E0: 0xEB0001D2,
    0x4104: 0xEB00045E,
    0x41C8: 0xEB000457,
    0x41F8: 0xEB0003BA,
}

LOADER_STRINGS = {
    0xEDC8: b"mmc\0",
    0xEDCC: b"fatload\0",
    0xEDD4: b"uImage\0",
    0xEDDC: b"0x2000000\0",
    0xEDE8: b"0\0",
    0xEDEC: b"update.image.gz\0",
    0xEDFC: b"0x4000000\0",
    0xEE08: b"devicetree.dtb\0",
    0xEE18: b"0x3000000\0",
    0xEE24: b"In RSAVerify(): Hash\0",
    0xEEA0: b"bootm\0",
}

FORBIDDEN_LOADER_PERSISTENCE_TOKENS = (
    b"saveenv",
    b"env save",
    b"nand write",
    b"nand erase",
    b"mtd write",
    b"ubi write",
    b"ubifsmount",
    b"mmc write",
    b"fatwrite",
    b"ext4write",
    b"sf write",
    b"sf erase",
)

RESIDENT_BOOT_TOKENS = {
    0x280652: b"bootcmd=run $modeboot\0",
    0x280824: b"bootenv=uEnv.txt\0",
    0x280835: b"loadbootenv=load mmc 0 ${loadbootenv_addr} ${bootenv}\0",
    0x28086B: (
        b"importbootenv=echo Importing environment from SD ...; "
        b"env import -t ${loadbootenv_addr} $filesize\0"
    ),
    0x2808CD: b"sd_uEnvtxt_existence_test=test -e mmc 0 /uEnv.txt\0",
    0x2808FF: b"preboot=if test $modeboot = sdboot",
    0x280CF3: b"uenvboot=if run loadbootenv;",
    0x280D99: b"sdboot=if mmcinfo; then run uenvboot;",
    0x281033: b"nandboot=echo Copying Linux from NAND flash to RAM...",
    0x2880CF: b"U-Boot 2016.07-gdb5d44e-dirty\0",
}

REQUIRED_ENV_ENTRIES = (
    "bootcmd",
    "nandboot",
    "nandboot_mode_select",
    "nandboot_recovery",
    "sdboot",
    "uenv_load",
    "uenv_reset",
    "auto_recovery",
)


def _sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes | bytearray, offset: int) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as exc:
        raise EvidenceError("truncated 16-bit field") from exc


def _u32(data: bytes | bytearray, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise EvidenceError("truncated 32-bit field") from exc


def _reject_device_or_remote_path(path: Path, *, label: str) -> None:
    raw = os.fspath(path)
    normalized = raw.replace("/", "\\")
    if normalized.startswith(("\\\\", "\\??\\", "\\Device\\")):
        raise EvidenceError(f"{label} must not use a remote or device namespace")
    if re.match(r"^[A-Za-z]:$", normalized):
        raise EvidenceError(f"{label} must not name a drive device")
    posix_style = raw.replace("\\", "/")
    if posix_style == "/dev" or posix_style.startswith(("/dev/", "/proc/", "/sys/")):
        raise EvidenceError(f"{label} must not use a kernel or device filesystem")


def _is_link_like(identity: os.stat_result) -> bool:
    if stat.S_ISLNK(identity.st_mode):
        return True
    attributes = getattr(identity, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse)


def _validate_workspace_root(supplied: Path) -> Path:
    _reject_device_or_remote_path(supplied, label="workspace_root")
    try:
        identity = os.lstat(supplied)
    except OSError as exc:
        raise EvidenceError(f"workspace_root is missing or unreadable: {exc}") from exc
    if _is_link_like(identity):
        raise EvidenceError("workspace_root must not be a link or reparse point")
    if not stat.S_ISDIR(identity.st_mode):
        raise EvidenceError("workspace_root must be a directory")
    return supplied.resolve(strict=True)


def _safe_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in PurePath(relative).parts:
        raise EvidenceError(f"unsafe relative evidence path: {relative}")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            identity = os.lstat(current)
        except OSError as exc:
            raise EvidenceError(f"missing or unreadable evidence path {relative}: {exc}") from exc
        if _is_link_like(identity):
            raise EvidenceError(f"evidence path must not traverse a link: {current}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(identity.st_mode):
            raise EvidenceError(f"evidence parent is not a directory: {current}")
    return current


def _read_regular_once(
    root: Path,
    relative: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum_size: int,
) -> tuple[bytes, dict[str, Any]]:
    path = _safe_path(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open evidence {relative}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"evidence must be a regular file: {relative}")
        if before.st_nlink != 1:
            raise EvidenceError(f"evidence must have exactly one hard link: {relative}")
        if before.st_size != expected_size or before.st_size > maximum_size:
            raise EvidenceError(
                f"evidence size mismatch for {relative}: {before.st_size}"
            )
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise EvidenceError(f"evidence exceeds size limit: {relative}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise EvidenceError(f"evidence changed while being read: {relative}")
    finally:
        os.close(descriptor)
    actual_sha256 = digest.hexdigest()
    if total != expected_size or actual_sha256 != expected_sha256:
        raise EvidenceError(
            f"evidence digest mismatch for {relative}: {actual_sha256}"
        )
    return b"".join(chunks), {
        "path": relative.as_posix(),
        "size": total,
        "sha256": actual_sha256,
        "regular_non_link_single_link": True,
        "same_handle_identity_stable": True,
    }


def _parse_fat16(image: bytes, profile: Profile) -> tuple[dict[str, bytes], dict[str, Any]]:
    if image[510:512] != b"\x55\xaa":
        raise EvidenceError("donor image has no MBR signature")
    partitions: list[tuple[int, int, int, int]] = []
    for index in range(4):
        entry = image[446 + index * 16 : 462 + index * 16]
        partitions.append((entry[0], entry[4], _u32(entry, 8), _u32(entry, 12)))
    if tuple(partitions) != EXPECTED_PARTITIONS:
        raise EvidenceError("donor MBR partition map changed")

    partition_offset = EXPECTED_PARTITIONS[0][2] * 512
    boot_sector = image[partition_offset : partition_offset + 512]
    if boot_sector[510:512] != b"\x55\xaa":
        raise EvidenceError("FAT boot-sector signature missing")
    bytes_per_sector = _u16(boot_sector, 11)
    sectors_per_cluster = boot_sector[13]
    reserved_sectors = _u16(boot_sector, 14)
    fat_count = boot_sector[16]
    root_entries = _u16(boot_sector, 17)
    fat_sectors = _u16(boot_sector, 22)
    if (
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        root_entries,
        fat_sectors,
    ) != (512, 4, 4, 2, 512, 64):
        raise EvidenceError("FAT16 geometry changed")
    root_offset = partition_offset + (
        reserved_sectors + fat_count * fat_sectors
    ) * bytes_per_sector
    root_bytes = root_entries * 32
    data_offset = root_offset + root_bytes
    fat_offset = partition_offset + reserved_sectors * bytes_per_sector
    fat = image[fat_offset : fat_offset + fat_sectors * bytes_per_sector]

    members: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []
    for spec in COMMON_FAT_MEMBERS:
        entry = None
        for offset in range(root_offset, root_offset + root_bytes, 32):
            candidate = image[offset : offset + 32]
            if candidate[:11] == spec.alias:
                entry = candidate
                break
        if entry is None or entry[11] & 0x18:
            raise EvidenceError(f"missing regular FAT member {spec.name}")
        size = _u32(entry, 28)
        expected_size = profile.update_size if spec.name == "update.image.gz" else spec.size
        if size != expected_size:
            raise EvidenceError(f"FAT member size mismatch for {spec.name}: {size}")
        cluster = _u16(entry, 26)
        remaining = size
        content = bytearray()
        seen: set[int] = set()
        cluster_bytes = sectors_per_cluster * bytes_per_sector
        while remaining:
            if cluster < 2 or cluster >= 0xFFF8 or cluster in seen:
                raise EvidenceError(f"invalid FAT chain for {spec.name}")
            seen.add(cluster)
            source_offset = data_offset + (cluster - 2) * cluster_bytes
            if source_offset + cluster_bytes > len(image):
                raise EvidenceError(f"FAT chain leaves image for {spec.name}")
            take = min(remaining, cluster_bytes)
            content.extend(image[source_offset : source_offset + take])
            remaining -= take
            if remaining:
                fat_entry = cluster * 2
                if fat_entry + 2 > len(fat):
                    raise EvidenceError(f"FAT chain table overflow for {spec.name}")
                cluster = _u16(fat, fat_entry)
        payload = bytes(content)
        expected_sha256 = (
            profile.boot_sha256
            if spec.name == "BOOT.BIN"
            else profile.update_sha256
            if spec.name == "update.image.gz"
            else spec.sha256
        )
        actual_sha256 = _sha256(payload)
        if actual_sha256 != expected_sha256:
            raise EvidenceError(f"FAT member digest mismatch for {spec.name}")
        members[spec.name] = payload
        records.append(
            {
                "name": spec.name,
                "fat_alias_hex": spec.alias.hex(),
                "size": size,
                "sha256": actual_sha256,
            }
        )
    return members, {
        "partition_map": [
            {
                "index": index + 1,
                "boot_flag": f"0x{item[0]:02x}",
                "type": f"0x{item[1]:02x}",
                "start_lba": item[2],
                "sector_count": item[3],
            }
            for index, item in enumerate(partitions)
        ],
        "fat16_geometry": {
            "partition_start_lba": 1,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "reserved_sectors": reserved_sectors,
            "fat_count": fat_count,
            "root_entries": root_entries,
            "fat_sectors": fat_sectors,
        },
        "members": records,
    }


def _crc_msb_table(polynomial: int) -> bytes:
    words: list[int] = []
    for index in range(256):
        value = index << 24
        for _ in range(8):
            value = (
                ((value << 1) ^ polynomial)
                if value & 0x80000000
                else (value << 1)
            ) & 0xFFFFFFFF
        words.append(value)
    return b"".join(struct.pack("<I", word) for word in words)


def _decrypt_control_struct(data: bytes | bytearray, seed: int) -> tuple[int, ...]:
    if len(data) != STRUCT_LENGTH:
        raise EvidenceError("control structure length changed")
    state = seed
    words: list[int] = []
    for offset in range(0, STRUCT_LENGTH, 4):
        state = (state * LCG_MULTIPLIER + LCG_INCREMENT) & 0xFFFFFFFF
        words.append(_u32(data, offset) ^ state)
    return tuple(words)


def _stage_transform(region: bytes | bytearray, polynomial: int) -> bytes:
    table = _crc_msb_table(polynomial)
    return bytes(((table[index % len(table)] ^ value) - table[index % len(table)]) & 0xFF for index, value in enumerate(region))


def _arm_bl_target(word: int, instruction_offset: int) -> int:
    if word & 0xFF000000 != 0xEB000000:
        raise EvidenceError(f"expected ARM BL at 0x{instruction_offset:05x}")
    displacement = (word & 0x00FFFFFF) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return instruction_offset + 8 + displacement


def _decode_and_verify_loader(boot: bytes, profile: Profile) -> dict[str, Any]:
    if len(boot) != BOOT_SIZE or _sha256(boot) != profile.boot_sha256:
        raise EvidenceError("target-bound BOOT.BIN mismatch")
    decoded = bytearray(boot)
    stages: list[dict[str, Any]] = []
    file_offset = 0
    for stage_index in range(4):
        if _u32(decoded, file_offset + 0x0C) != STAGE_MAGIC:
            raise EvidenceError(f"loader stage {stage_index} magic mismatch")
        seed = _u32(decoded, file_offset + STAGE_SEED_OFFSET)
        words = _decrypt_control_struct(
            decoded[file_offset + STRUCT_OFFSET : file_offset + STRUCT_OFFSET + STRUCT_LENGTH],
            seed,
        )
        polynomial, destination, length = words[:3]
        destination_offset = destination - IMAGE_BASE
        expected_offset = (stage_index + 1) * 0x1000
        expected_length = 0x1000 if stage_index < 3 else 0x10000
        if (destination_offset, length) != (expected_offset, expected_length):
            raise EvidenceError(f"loader stage {stage_index} range changed")
        decoded[destination_offset : destination_offset + length] = _stage_transform(
            decoded[destination_offset : destination_offset + length], polynomial
        )
        stages.append(
            {
                "stage": stage_index,
                "source_offset": file_offset,
                "destination": f"0x{destination:08x}",
                "length": length,
                "polynomial": f"0x{polynomial:08x}",
            }
        )
        file_offset = destination_offset

    decoded_bytes = bytes(decoded)
    if _sha256(decoded_bytes) != profile.decoded_boot_sha256:
        raise EvidenceError("decoded target-bound BOOT.BIN digest mismatch")
    marker = decoded_bytes[
        TARGET_MARKER_OFFSET : TARGET_MARKER_OFFSET + TARGET_MARKER_LENGTH
    ]
    if marker.hex() != profile.target_marker_hex:
        raise EvidenceError("decoded target marker mismatch")
    normalized = bytearray(decoded_bytes)
    normalized[
        TARGET_MARKER_OFFSET : TARGET_MARKER_OFFSET + TARGET_MARKER_LENGTH
    ] = b"\0" * TARGET_MARKER_LENGTH
    if _sha256(normalized) != NORMALIZED_DECODED_BOOT_SHA256:
        raise EvidenceError("decoded shared loader template mismatch")
    for offset, expected in EXPECTED_LOADER_WORDS.items():
        if _u32(decoded_bytes, offset) != expected:
            raise EvidenceError(f"loader instruction mismatch at 0x{offset:05x}")
    expected_calls = {0x4840: 0x4700, 0x40E0: 0x4830, 0x4104: 0x5284, 0x41C8: 0x532C, 0x41F8: 0x50E8}
    for offset, target in expected_calls.items():
        if _arm_bl_target(_u32(decoded_bytes, offset), offset) != target:
            raise EvidenceError(f"loader call target mismatch at 0x{offset:05x}")
    for offset, token in LOADER_STRINGS.items():
        if decoded_bytes[offset : offset + len(token)] != token:
            raise EvidenceError(f"loader string table mismatch at 0x{offset:05x}")
    lowered = decoded_bytes.lower()
    present_forbidden = [
        token.decode("ascii")
        for token in FORBIDDEN_LOADER_PERSISTENCE_TOKENS
        if token in lowered
    ]
    if present_forbidden:
        raise EvidenceError(f"loader gained persistent-write tokens: {present_forbidden}")
    return {
        "encoded_sha256": profile.boot_sha256,
        "decoded_sha256": profile.decoded_boot_sha256,
        "normalized_decoded_sha256": NORMALIZED_DECODED_BOOT_SHA256,
        "target_marker_hex": marker.hex(),
        "self_decode_stages": stages,
        "rsa_locator_and_memory_patch_precede_load_and_boot": True,
        "exact_commands": [
            "fatload mmc 0 0x2000000 uImage",
            "fatload mmc 0 0x4000000 update.image.gz",
            "fatload mmc 0 0x3000000 devicetree.dtb",
            "bootm 0x2000000 0x4000000 0x3000000",
        ],
        "persistent_write_tokens_absent": True,
        "persistent_write_tokens_checked": [
            token.decode("ascii") for token in FORBIDDEN_LOADER_PERSISTENCE_TOKENS
        ],
    }


def _extract_single_bmu_boot(raw: bytes, package: StockPackage) -> bytes:
    """Extract only the exact first BOOT component from a pinned single BMU."""
    if len(raw) != package.size or len(raw) < BMU_HEADER_SIZE + STOCK_BOOTGEN_SIZE:
        raise EvidenceError(f"stock package size changed for {package.firmware_epoch}")
    if raw[0] != 0x26:
        raise EvidenceError("stock package is not a single-BMU container")
    if raw[0x518] != 7:
        raise EvidenceError("stock package file-count changed")
    if raw[0x51D] != 0:
        raise EvidenceError("stock package first component is not BOOT.bin")
    declared_size = int.from_bytes(raw[0x51E:0x522], "big")
    if declared_size != STOCK_BOOTGEN_SIZE:
        raise EvidenceError("stock package BOOT.bin declared size changed")
    boot = raw[BMU_HEADER_SIZE : BMU_HEADER_SIZE + declared_size]
    if _sha256(boot) != STOCK_BOOTGEN_SHA256:
        raise EvidenceError("stock package BOOT.bin digest changed")
    return boot


def _parse_bootgen(boot: bytes) -> dict[str, Any]:
    if len(boot) != STOCK_BOOTGEN_SIZE or _sha256(boot) != STOCK_BOOTGEN_SHA256:
        raise EvidenceError("stock Bootgen image identity changed")
    header_words = {
        "width_detection": _u32(boot, 0x20),
        "signature": _u32(boot, 0x24),
        "key_source": _u32(boot, 0x28),
        "header_version": _u32(boot, 0x2C),
        "fsbl_offset": _u32(boot, 0x30),
        "fsbl_size": _u32(boot, 0x34),
        "iht_offset": _u32(boot, 0x98),
        "pht_offset": _u32(boot, 0x9C),
    }
    if header_words != {
        "width_detection": 0xAA995566,
        "signature": 0x584C4E58,
        "key_source": 0,
        "header_version": 0x01010000,
        "fsbl_offset": 0x1700,
        "fsbl_size": 131_088,
        "iht_offset": 0x8C0,
        "pht_offset": 0xC80,
    }:
        raise EvidenceError("stock Bootgen header changed")
    iht = tuple(_u32(boot, 0x8C0 + offset) for offset in range(0, 20, 4))
    if iht != (0x01020000, 3, 0x320, 0x240, 0x410):
        raise EvidenceError("stock Bootgen image-header table changed")

    partitions: list[dict[str, Any]] = []
    for index, expected in enumerate(EXPECTED_BOOTGEN_PARTITIONS):
        name, offset, size, load, execute, attributes, expected_sha256 = expected
        header_offset = 0xC80 + index * 0x40
        actual_size = _u32(boot, header_offset + 4) * 4
        actual_offset = _u32(boot, header_offset + 20) * 4
        actual_load = _u32(boot, header_offset + 12)
        actual_execute = _u32(boot, header_offset + 16)
        actual_attributes = _u32(boot, header_offset + 24)
        if (
            actual_offset,
            actual_size,
            actual_load,
            actual_execute,
            actual_attributes,
        ) != (offset, size, load, execute, attributes):
            raise EvidenceError(f"stock Bootgen partition {index} geometry changed")
        payload = boot[offset : offset + size]
        actual_sha256 = _sha256(payload)
        if len(payload) != size or actual_sha256 != expected_sha256:
            raise EvidenceError(f"stock Bootgen partition {index} digest changed")
        partitions.append(
            {
                "index": index,
                "name": name,
                "offset": offset,
                "size": size,
                "load_address": f"0x{load:08x}",
                "execution_address": f"0x{execute:08x}",
                "attributes": f"0x{attributes:08x}",
                "rsa_authentication_certificate_flag_present": bool(
                    attributes & 0x8000
                ),
                "sha256": actual_sha256,
            }
        )
    return {
        "size": len(boot),
        "sha256": _sha256(boot),
        "format": "Xilinx Zynq-7000 Bootgen image",
        "plaintext_not_encrypted": True,
        "rsa_attribute_flags_present_not_cryptographically_verified_here": True,
        "header": {
            "width_detection": "0xaa995566",
            "signature": "XNLX",
            "header_version": "0x01010000",
            "image_header_table_offset": 0x8C0,
            "partition_header_table_offset": 0xC80,
            "partition_count": 3,
        },
        "partitions": partitions,
    }


def _verify_live_25_identity(identity: bytes, manifest: bytes) -> dict[str, Any]:
    try:
        identity_text = identity.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError("S19j Pro .25 identity is not ASCII") from exc
    required_identity_lines = {
        "MAC=aa:bb:cc:dd:ee:ff",
        "DCENTOS_DISK_BOARD_TARGET=am2-s19jpro-xil",
        'mtd0: 00800000 00020000 "boot"',
        'mtd4: 00080000 00020000 "uboot_env"',
        'mtd9: 01e00000 00020000 "factory"',
    }
    if not required_identity_lines.issubset(set(identity_text.splitlines())):
        raise EvidenceError("S19j Pro .25 identity contract changed")
    try:
        parsed = json.loads(manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("S19j Pro .25 backup manifest is invalid") from exc
    miner = parsed.get("miner", {})
    if (
        parsed.get("schema_version") != 1
        or parsed.get("kind") != "am2_full_nand_backup"
        or parsed.get("readback_verified") is not True
        or parsed.get("required_partitions_present") is not True
        or parsed.get("total_size_bytes") != 268_435_456
        or miner.get("mac") != "aa:bb:cc:dd:ee:ff"
        or miner.get("board_target") != "am2"
    ):
        raise EvidenceError("S19j Pro .25 backup manifest contract changed")
    partitions = {item.get("name"): item for item in parsed.get("partitions", [])}
    for name, size, digest in (
        ("boot", RESIDENT_BOOT_SIZE, RESIDENT_BOOT_SHA256),
        ("uboot_env", RESIDENT_ENV_SIZE, LIVE_25_ENV_SHA256),
    ):
        item = partitions.get(name, {})
        if (
            item.get("size_bytes") != size
            or item.get("sha256") != digest
            or item.get("ok") is not True
        ):
            raise EvidenceError(f"S19j Pro .25 manifest {name} binding changed")
    return {
        "capture_label": "S19j Pro Xilinx .25",
        "mac": "aa:bb:cc:dd:ee:ff",
        "disk_board_target": "am2-s19jpro-xil",
        "manifest_board_target": "am2",
        "readback_verified_by_capture_manifest": True,
        "nand_total_size": 268_435_456,
        "note": "Manifest truth is evidence lineage, not an independent re-read by this analyzer.",
    }


def _parse_redundant_environment(
    raw: bytes,
    *,
    require_identical: bool = True,
    expected_flags: tuple[int, int] | None = None,
    allowed_differing_keys: frozenset[str] = frozenset(),
    selected_bank: int = 0,
) -> tuple[dict[str, str], dict[str, Any]]:
    if len(raw) != RESIDENT_ENV_SIZE:
        raise EvidenceError("resident environment size mismatch")
    banks: list[dict[str, Any]] = []
    parsed_banks: list[dict[str, str]] = []
    for index, base in enumerate((0, 0x20000)):
        bank = raw[base : base + 0x20000]
        expected_crc = _u32(bank, 0)
        actual_crc = zlib.crc32(bank[5:]) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise EvidenceError(f"resident environment bank {index} CRC mismatch")
        data = bank[5:]
        terminator = data.find(b"\0\0")
        if terminator < 0:
            raise EvidenceError(f"resident environment bank {index} has no terminator")
        entries: dict[str, str] = {}
        for raw_entry in data[:terminator].split(b"\0"):
            try:
                text = raw_entry.decode("ascii")
            except UnicodeDecodeError as exc:
                raise EvidenceError("resident environment entry is not ASCII") from exc
            if "=" not in text:
                raise EvidenceError("resident environment entry has no assignment")
            key, value = text.split("=", 1)
            if not key or key in entries:
                raise EvidenceError("resident environment has invalid/duplicate key")
            entries[key] = value
        parsed_banks.append(entries)
        banks.append(
            {
                "index": index,
                "offset": base,
                "length": 0x20000,
                "crc32": f"0x{actual_crc:08x}",
                "redundancy_flag": bank[4],
                "entry_count": len(entries),
            }
        )
    if expected_flags is not None and tuple(
        item["redundancy_flag"] for item in banks
    ) != expected_flags:
        raise EvidenceError("resident environment redundancy flags changed")
    differing_keys = sorted(
        key
        for key in set(parsed_banks[0]) | set(parsed_banks[1])
        if parsed_banks[0].get(key) != parsed_banks[1].get(key)
    )
    if require_identical and differing_keys:
        raise EvidenceError("redundant resident environment banks disagree")
    if not require_identical and set(differing_keys) != allowed_differing_keys:
        raise EvidenceError("redundant resident environment bank differences changed")
    if selected_bank not in (0, 1):
        raise EvidenceError("invalid selected environment bank")
    entries = parsed_banks[selected_bank]
    for bank_entries in parsed_banks:
        missing = [name for name in REQUIRED_ENV_ENTRIES if name not in bank_entries]
        if missing:
            raise EvidenceError(f"resident environment is missing entries: {missing}")
    required_fragments = {
        "auto_recovery": ("saveenv", "setenv upgrade_stage 1"),
        "nandboot": ("saveenv", "run auto_recovery", "ubi read", "nand read"),
        "nandboot_mode_select": ("run uenv_reset",),
        "uenv_load": ("env import -t", "load mmc"),
        "uenv_reset": ("nand erase.part uboot_env",),
        "sdboot": ("run uenv_load", "sd_uenvcmd"),
    }
    for bank_entries in parsed_banks:
        for key, fragments in required_fragments.items():
            if any(fragment not in bank_entries[key] for fragment in fragments):
                raise EvidenceError(f"resident environment semantics changed for {key}")
    return entries, {
        "format": "two 128-KiB CRC32+flag redundant banks",
        "banks": banks,
        "differing_keys": differing_keys,
        "selected_bank_for_observed_flag_order": selected_bank,
    }


def _verify_resident_boot(raw: bytes) -> dict[str, Any]:
    for offset, token in RESIDENT_BOOT_TOKENS.items():
        if raw[offset : offset + len(token)] != token:
            raise EvidenceError(f"resident boot token mismatch at 0x{offset:06x}")
    return {
        "uboot_version": "U-Boot 2016.07-gdb5d44e-dirty (Apr 26 2020)",
        "compiled_default_contract": {
            "bootcmd": "run $modeboot",
            "preboot": "when modeboot=sdboot, import /uEnv.txt",
            "uenvboot": "import /uEnv.txt and execute uenvcmd when non-empty",
            "sdboot": "run uenvboot, then load kernel/DTB/ramdisk from MMC",
            "nandboot": "NAND reads only in this compiled-default command string",
        },
        "donor_uenv_variable_name_compatible_with_compiled_default": True,
    }


def analyze(workspace_root: Path, target: str) -> dict[str, Any]:
    root = _validate_workspace_root(workspace_root)
    try:
        profile = PROFILES[target]
    except KeyError as exc:
        raise EvidenceError(f"unsupported target: {target}") from exc

    donor, donor_record = _read_regular_once(
        root,
        profile.source_path,
        expected_size=profile.image_size,
        expected_sha256=profile.image_sha256,
        maximum_size=MAX_DONOR_BYTES,
    )
    resident_boot, resident_boot_record = _read_regular_once(
        root,
        RESIDENT_BOOT_PATH,
        expected_size=RESIDENT_BOOT_SIZE,
        expected_sha256=RESIDENT_BOOT_SHA256,
        maximum_size=MAX_RESIDENT_BYTES,
    )
    resident_env, resident_env_record = _read_regular_once(
        root,
        RESIDENT_ENV_PATH,
        expected_size=RESIDENT_ENV_SIZE,
        expected_sha256=RESIDENT_ENV_SHA256,
        maximum_size=MAX_RESIDENT_BYTES,
    )
    live_25_identity, live_25_identity_record = _read_regular_once(
        root,
        LIVE_25_IDENTITY_PATH,
        expected_size=LIVE_25_IDENTITY_SIZE,
        expected_sha256=LIVE_25_IDENTITY_SHA256,
        maximum_size=4_096,
    )
    live_25_manifest, live_25_manifest_record = _read_regular_once(
        root,
        LIVE_25_MANIFEST_PATH,
        expected_size=LIVE_25_MANIFEST_SIZE,
        expected_sha256=LIVE_25_MANIFEST_SHA256,
        maximum_size=64 * 1024,
    )
    live_25_boot, live_25_boot_record = _read_regular_once(
        root,
        LIVE_25_BOOT_PATH,
        expected_size=RESIDENT_BOOT_SIZE,
        expected_sha256=RESIDENT_BOOT_SHA256,
        maximum_size=MAX_RESIDENT_BYTES,
    )
    live_25_env, live_25_env_record = _read_regular_once(
        root,
        LIVE_25_ENV_PATH,
        expected_size=RESIDENT_ENV_SIZE,
        expected_sha256=LIVE_25_ENV_SHA256,
        maximum_size=MAX_RESIDENT_BYTES,
    )
    stock_records: list[dict[str, Any]] = []
    stock_boots: list[bytes] = []
    for package in STOCK_PACKAGES:
        raw, record = _read_regular_once(
            root,
            package.path,
            expected_size=package.size,
            expected_sha256=package.sha256,
            maximum_size=MAX_STOCK_PACKAGE_BYTES,
        )
        stock_boots.append(_extract_single_bmu_boot(raw, package))
        stock_records.append(
            {
                **record,
                "physical_model": package.physical_model,
                "firmware_epoch": package.firmware_epoch,
                "container_format": "single BMU (0x26)",
                "first_component_offset": BMU_HEADER_SIZE,
                "first_component_size": STOCK_BOOTGEN_SIZE,
                "first_component_sha256": STOCK_BOOTGEN_SHA256,
            }
        )
    if any(boot != stock_boots[0] for boot in stock_boots[1:]):
        raise EvidenceError("stock package Bootgen components are not byte-identical")
    if resident_boot[:STOCK_BOOTGEN_SIZE] != stock_boots[0]:
        raise EvidenceError("S19j .139 NAND boot prefix does not match stock packages")
    if live_25_boot[:STOCK_BOOTGEN_SIZE] != stock_boots[0]:
        raise EvidenceError("S19j Pro .25 NAND boot prefix does not match stock packages")
    bootgen = _parse_bootgen(stock_boots[0])
    live_25_identity_analysis = _verify_live_25_identity(
        live_25_identity, live_25_manifest
    )
    members, fat = _parse_fat16(donor, profile)
    if members["uEnv.txt"] != EXACT_UENV:
        raise EvidenceError("donor uEnv command bytes changed")
    loader = _decode_and_verify_loader(members["BOOT.BIN"], profile)
    resident_boot_analysis = _verify_resident_boot(resident_boot)
    environment, environment_layout = _parse_redundant_environment(resident_env)
    live_25_environment, live_25_environment_layout = _parse_redundant_environment(
        live_25_env,
        require_identical=False,
        expected_flags=(151, 152),
        allowed_differing_keys=frozenset({"firmware"}),
        selected_bank=1,
    )
    if (
        live_25_environment.get("firmware") != "2"
        or live_25_environment.get("modeboot") != "nandboot"
        or any(
            name in live_25_environment
            for name in ("sd_boot", "uenvcmd", "sd_uenvcmd")
        )
    ):
        raise EvidenceError("S19j Pro .25 active environment selector changed")
    if "run sdboot" not in live_25_environment["nandboot"]:
        raise EvidenceError("S19j Pro .25 nandboot no longer contains SD branch")

    environment_hazards = [
        {
            "operation": "saveenv",
            "persistence": "writes redundant NAND uboot_env partition",
            "persistent_write_excluded": False,
            "reachable_from": "nandboot -> recovery cleanup or auto_recovery",
            "condition": "recovery=yes, upgrade_stage=0, or upgrade_stage=1",
        },
        {
            "operation": "nand erase.part uboot_env",
            "persistence": "erases the complete NAND uboot_env partition",
            "persistent_write_excluded": False,
            "reachable_from": "nandboot -> uenv_reset; nandboot_mode_select -> uenv_reset",
            "condition": "factory_reset=yes or front button held through factory_reset_delay",
        },
        {
            "operation": "setenv; env set",
            "persistence": "volatile environment mutation unless followed by saveenv",
            "persistent_write_excluded": True,
            "reachable_from": "firmware_select, auto_recovery, nandboot, sdboot, and recovery setup",
            "condition": "the containing command branch executes",
        },
        {
            "operation": "env import -t",
            "persistence": "volatile environment mutation only",
            "persistent_write_excluded": True,
            "reachable_from": "nandboot or sdboot -> uenv_load",
            "condition": "uEnv.txt load succeeds",
        },
        {
            "operation": "nand read",
            "persistence": "read-only NAND access",
            "persistent_write_excluded": True,
            "reachable_from": "nandboot or nandboot_recovery",
            "condition": "selected mode/path reaches NAND boot",
        },
        {
            "operation": "ubi part",
            "persistence": "UBI attach; metadata side effects are not excluded without the exact U-Boot source/configuration",
            "persistent_write_excluded": False,
            "reachable_from": "normal nandboot firmware path",
            "condition": "recovery/SD path did not transfer control first",
        },
        {
            "operation": "ubi read",
            "persistence": "read request following the separately unproven UBI attach",
            "persistent_write_excluded": True,
            "reachable_from": "normal nandboot firmware path",
            "condition": "ubi part succeeded",
        },
    ]

    blocker_ledger = [
        {
            "id": "resident-chain-not-contained-by-donor",
            "state": "narrowed-not-closed",
            "detail": "The SD image begins at uEnv.txt. Exact stock FSBL/U-Boot bytes are now package-bound, and S19j Pro .25 has a matching NAND capture, but BootROM strap/eFuse boot-source policy and pre-U-Boot side effects remain board state.",
            "required_artifact": "per-controller boot-source configuration plus cold-boot trace from reset vector through resident U-Boot",
        },
        {
            "id": "bootrom-selector-configuration-unbound",
            "state": "missing-identity-bound-capture",
            "detail": "A model-named vendor package and NAND image do not capture Zynq boot-mode straps, RSA_EN/eFuse policy, fallback source ordering, or front-button state at reset.",
            "required_artifact": "controller-identified boot-mode/eFuse readout and reset-to-U-Boot UART trace for each admitted board revision",
        },
        {
            "id": "persistent-environment-state-dependent-writes",
            "state": "reachable-write-branches-observed",
            "detail": "The held environment reaches saveenv and nand erase.part uboot_env before kernel boot for specific state/button conditions.",
            "required_artifact": "a proven SD-first selector path that precedes those branches for every admitted environment state",
        },
        {
            "id": "resident-ubi-attach-side-effects",
            "state": "unproven",
            "detail": "The normal NAND path reaches ubi part before ubi read; the exact U-Boot source/configuration needed to exclude attach-time metadata writes is not held or target-bound.",
            "required_artifact": "hash-bound source/configuration or disassembly proving the exact resident ubi part implementation is storage-read-only",
        },
        {
            "id": "compiled-default-versus-persisted-selector-drift",
            "state": "semantics-conflict",
            "detail": "The donor defines only uenvcmd. The identity-bound S19j Pro .25 environment starts modeboot=nandboot and its sdboot executes only sd_uenvcmd; setting sd_boot=yes still does not invoke the donor mini-loader and instead expects absent system.bit.gz/fit.itb files.",
            "required_artifact": "a target-bound selector/load contract that invokes the donor uenvcmd, or donor media rebuilt to the proven resident sd_uenvcmd contract",
        },
        {
            "id": "fsbl-side-effects-not-disassembled",
            "state": "unproven",
            "detail": "The exact shared 131,088-byte FSBL is now hash-bound, but its storage and environment side effects have not been closed by source or instruction-level analysis.",
            "required_artifact": "storage-side-effect disassembly/source analysis of FSBL SHA256 42b1bcb12a018a7fea3d8f58ae8d9465765d960803b4c29f656ed6c8ab3ba257",
        },
        {
            "id": "cold-boot-path-unwitnessed",
            "state": "unproven",
            "detail": "No hash-bound UART trace demonstrates donor uEnv -> mini-loader -> bootm on either exact target from all admitted initial states.",
            "required_artifact": "cold-boot UART traces with media hashes, board identity, environment dump, and no-write instrumentation",
        },
    ]
    if target == "am2-s19pro":
        blocker_ledger.append(
            {
                "id": "s19pro-active-environment-not-held",
                "state": "exact-capture-absent",
                "detail": "S19 Pro stock packages bind the resident Bootgen bundle to vendor firmware epochs, but no physically identified S19 Pro redundant environment or full NAND capture was found.",
                "required_artifact": "S19 Pro Xilinx identity record, mtd0 boot.bin, mtd4 uboot_env.bin, boot-mode state, and cold-boot UART from the same unit",
            }
        )

    evidence_digest = hashlib.sha256()
    all_records = (
        donor_record,
        resident_boot_record,
        resident_env_record,
        live_25_identity_record,
        live_25_manifest_record,
        live_25_boot_record,
        live_25_env_record,
        *stock_records,
    )
    for record in all_records:
        evidence_digest.update(record["path"].encode("utf-8"))
        evidence_digest.update(b"\0")
        evidence_digest.update(record["sha256"].encode("ascii"))
        evidence_digest.update(b"\0")

    return {
        "schema": SCHEMA,
        "target": profile.target,
        "physical_model": profile.physical_model,
        "control_board_family": "AM2 Xilinx Zynq-7000 (exact PCB/revision unbound)",
        "state": "resident-bundle-lineage-proven-whole-preinit-safety-blocked",
        "evidence_set_sha256": evidence_digest.hexdigest(),
        "donor_media": {**donor_record, **fat},
        "donor_execution_contract": {
            "uenv_sha256": _sha256(EXACT_UENV),
            "uenv_exact_command": EXACT_UENV.decode("ascii").strip(),
            "uenv_operations": [
                {"command": "dcache off", "effect": "volatile CPU cache state"},
                {"command": "fatload mmc", "effect": "read BOOT.BIN from SD into DRAM"},
                {"command": "go", "effect": "transfer execution to DRAM"},
            ],
            "loader": loader,
            "kernel_sha256": _sha256(members["uImage"]),
            "devicetree_sha256": _sha256(members["devicetree.dtb"]),
            "encoded_ramdisk_sha256": _sha256(members["update.image.gz"]),
        },
        "related_resident_evidence": {
            "lineage": "observed S19j AM2 .139 capture; exact boot prefix also occurs in identity-bound S19j Pro .25 NAND",
            "boot_partition": {**resident_boot_record, **resident_boot_analysis},
            "environment_partition": {
                **resident_env_record,
                **environment_layout,
                "bootcmd": environment["bootcmd"],
                "modeboot_present": "modeboot" in environment,
                "uenvcmd_present": "uenvcmd" in environment,
                "sd_uenvcmd_present": "sd_uenvcmd" in environment,
            },
            "pre_init_access_ledger": environment_hazards,
        },
        "resident_boot_bundle_lineage": {
            "stock_packages": stock_records,
            "bootgen_component": bootgen,
            "all_stock_package_components_byte_identical": True,
            "s19j_139_nand_prefix_byte_identical": True,
            "s19jpro_25_nand_prefix_byte_identical": True,
            "proof_scope": "Exact byte lineage; RSA attributes are parsed but signatures are not cryptographically verified and eFuse enforcement is not verified here.",
        },
        "identity_bound_s19jpro_25": {
            "identity": {**live_25_identity_record, **live_25_identity_analysis},
            "backup_manifest": live_25_manifest_record,
            "boot_partition": live_25_boot_record,
            "environment_partition": {
                **live_25_env_record,
                **live_25_environment_layout,
                "observed_selected_firmware": live_25_environment["firmware"],
                "modeboot": live_25_environment["modeboot"],
                "sd_boot_present": "sd_boot" in live_25_environment,
                "uenvcmd_present": "uenvcmd" in live_25_environment,
                "sd_uenvcmd_present": "sd_uenvcmd" in live_25_environment,
                "nandboot_has_conditional_sdboot": True,
                "sdboot_invokes_only_sd_uenvcmd": True,
            },
            "donor_uenv_invoked_by_persisted_selector": False,
            "donor_required_sdboot_files_present": False,
        },
        "evidence_exhaustion": {
            "searched_classes": [
                "stock Bitmain S19j Pro/S19 Pro single-BMU packages and extractions",
                "S19j AM2 .139 and S19j Pro .25 full-NAND captures",
                "held VNish Xilinx SD donor images",
                "HashSource stock Bootgen baseline and boot-chain research",
                "DCENT_OS Development Kit firmware/carves (duplicates, not independent captures)",
                "UART/log text for resident U-Boot and donor hook execution",
                "Ghidra project names/content for resident FSBL/U-Boot",
                "reachable and unreachable git objects for AM2 boot/env captures",
            ],
            "negative_findings_are_not_authority": True,
            "session_search_snapshot_not_revalidated_by_analyzer": True,
            "exact_missing_capture": {
                "s19jpro": "cold-boot UART plus boot-mode/eFuse/strap and button-state witness from the same .25 identity",
                "s19pro": "controller identity + mtd0 + mtd4 + boot-mode/eFuse/strap + cold-boot UART from one physically identified Xilinx S19 Pro",
            },
            "different_epoch_warning": "HashSource BOOT.bin SHA256 5938dad3f8e7a2f8a0ca70b7d9b0497ca7ba7f0ff22033e27be33d6b986032c8 is a different 2,788,544-byte Bootgen epoch and was not substituted for the exact shared stock package/live-NAND image.",
            "ghidra_pre_uenv_project_found": False,
            "cold_boot_uart_trace_found": False,
            "s19pro_identity_bound_environment_found": False,
            "unreachable_git_history_audit": {
                "unreachable_commits_walked": 82,
                "unique_relevant_unreachable_blobs": 6,
                "resident_chain_token_matches": 0,
                "xilinx_vnish_update_blob": {
                    "git_object": "bf8266ab8978a73de21e98e476c6e346dea3c536",
                    "size": 16_313_438,
                    "sha256": "006fe3acf0c5043cb1a513f1a0936b0393a0dddf8ba0debe4eeebe41516ee895",
                    "bounded_archive_result": "outer signed update contains fw.tar.gz; inner archive contains only fw.md5, install.sh, and uramdisk.image.gz, not resident FSBL/U-Boot/environment",
                },
                "braiins_metadata_only": "Two unreachable opkg control blobs identify uboot-zynq-am2-s17 and uboot-zynq-am2-s17-sd version 2016.03, but no package payload or controller capture is present.",
            },
        },
        "proof_facets": {
            "exact_donor_media_and_members_verified": True,
            "donor_uenv_operations_persistent_write_free": True,
            "decoded_miniloader_persistent_write_operations_absent": True,
            "donor_handoff_no_persistent_writes_proven": True,
            "resident_bootgen_fsbl_uboot_bound_to_model_named_stock_package": True,
            "resident_bootgen_bundle_bound_to_identity_captured_s19jpro_25": True,
            "resident_bootrom_configuration_bound_to_target": False,
            "resident_environment_bound_to_target": target == "am2-s19j",
            "donor_handoff_invoked_by_identity_bound_resident_environment": False,
            "all_initial_environment_states_safe": False,
            "resident_pre_handoff_no_persistent_writes_proven": False,
            "whole_pre_init_no_persistent_writes_proven": False,
            "cold_boot_witnessed": False,
        },
        "blocker_ledger": blocker_ledger,
        "authority": {
            "artifact_generation_authorized_by_this_report": False,
            "operator_boot_authorized": False,
            "external_media_write_authorized": False,
            "persistent_install_authorized": False,
            "raw_device_write_authorized": False,
        },
        "device_contact": "none",
        "network_contact": "none",
        "subprocess_execution": "none",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--target", required=True, choices=tuple(PROFILES))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = analyze(args.workspace_root, args.target)
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
