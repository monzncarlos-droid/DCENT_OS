#!/usr/bin/env python3
"""Verify the hash-pinned S19k Pro Amlogic secure-firmware RE boundary.

This verifier is offline-only.  It validates copied evidence bytes, container
headers, the shared AMLSECU key selector, and the tracked analysis record.  It
does not contact a miner, recover a runtime secret, decrypt a boot image, or
grant native/persistent execution authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = PROJECT_ROOT.parent.parent
DEFAULT_EVIDENCE_DIR = (
    REPO_ROOT / ".s19k-gauntlet-evidence/native-secure-firmware-re"
)
REPORT_PATH = (
    REPO_ROOT
    / ""
    "S19K_PRO_STOCK_BMU_AND_AML_BOOT_RE_20260823.md"
)
REPORT_SHA256 = "764efe95b6fd9a5c79ed060fd836240be16291f2aae8b28a0e552cf9723fb8a2"
MAX_FILE_BYTES = 32 * 1024 * 1024
TARGET_KEY_SHA256 = bytes.fromhex(
    "5dc75d64bec75d4feb52c46d9bcc374cdb2f627fc6574b064d03f35032f925e8"
)
KEY_BLOB_OFFSET = 0xC200
KEY_BLOB_SIZE = 0x4000
KEY_BLOB_SHA256 = "a203acd22f2d2038a1ab067ff993769489f7415c570f191c7ab3d8db5bc72fdc"
KEY_DIGEST_OFFSETS = (0x460, 0x4C0, 0x520)
LZ4C_HEADER = struct.Struct("<IHHII32s32s12sI32s")
LZ4C_MAGIC = 0x43345A4C

EXPECTED_FILES: Mapping[str, tuple[int, str]] = {
    "s19kp_uboot_bl33_raw.bin": (
        494960,
        "6accb882644c24a4f643f9eedc9c724fbcc4acd3a28c08a5f493453a0329f446",
    ),
    "s19kp_uboot_bl33_decompressed.bin": (
        923584,
        "103c64d90f72fffeb1a79d0133c656a31eecff959fd1502e0c302adc66f6711e",
    ),
    "s19kp_bl31_raw.bin": (
        201728,
        "4f8bbca7db32b4a7c030a9f547bf02f3f862ad2131568b7ca731963c99866f45",
    ),
    "s19kp_bl2_raw.bin": (
        45056,
        "72a920a55737856426f1fe83d71640fdce409f384d5a96210b4da6200e0bd44f",
    ),
    "uboot_aml_sdc_burn": (
        818688,
        "2ef29d8f2d1eb9d34bfc9084519515e98ac5c6f280c1cfa1967172f396264593",
    ),
    "vnish_PART_boot": (
        12763648,
        "b2d8cf586005f99ffee614dde914098205acc9a27ac42ccc7c52332fe6e685bf",
    ),
    "bitmain_unknown_09": (
        12927488,
        "985703e0732629e80d539ac5501d7652b4ca6c225aac32540f9f9587b1ea839a",
    ),
}

HELD_SOURCE_PATHS: Mapping[str, Path] = {
    "s19kp_uboot_bl33_raw.bin": REPO_ROOT
    / ""
    "s19kp_uboot_bl33_raw.bin",
    "s19kp_uboot_bl33_decompressed.bin": REPO_ROOT
    / ""
    "s19kp_uboot_bl33_decompressed.bin",
    "s19kp_bl31_raw.bin": REPO_ROOT
    / "",
    "s19kp_bl2_raw.bin": REPO_ROOT
    / "",
    "uboot_aml_sdc_burn": REPO_ROOT
    / ""
    "upgrade_extracted/uboot_aml_sdc_burn",
    "vnish_PART_boot": REPO_ROOT
    / ""
    "upgrade_extracted/PART_boot",
    "bitmain_unknown_09": REPO_ROOT
    / ""
    "merge-extracted/00_Antminer_S19k_Pro_AMLCtrl_BHB56XXX_contents/unknown_09",
}


class NativeReError(ValueError):
    """Evidence does not prove the pinned offline classification."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise NativeReError(f"required evidence is not a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise NativeReError(f"evidence exceeds {maximum} bytes: {path}")
    return path.read_bytes()


def verify_lz4c(raw: bytes, plaintext: bytes) -> dict[str, Any]:
    if len(raw) < LZ4C_HEADER.size:
        raise NativeReError("BL33 LZ4C container is truncated")
    (
        magic,
        flags,
        header_size,
        original_size,
        compressed_size,
        payload_sha,
        timestamp_raw,
        _nonce,
        second_magic,
        header_sha,
    ) = LZ4C_HEADER.unpack_from(raw)
    if (magic, second_magic, flags, header_size) != (
        LZ4C_MAGIC,
        LZ4C_MAGIC,
        0,
        LZ4C_HEADER.size,
    ):
        raise NativeReError("BL33 LZ4C header identity is invalid")
    payload_end = header_size + compressed_size
    if payload_end > len(raw) or any(raw[payload_end:]):
        raise NativeReError("BL33 compressed extent or zero padding is invalid")
    if hashlib.sha256(raw[:0x60]).digest() != header_sha:
        raise NativeReError("BL33 LZ4C header digest mismatch")
    if len(plaintext) != original_size or hashlib.sha256(plaintext).digest() != payload_sha:
        raise NativeReError("BL33 plaintext does not match the signed container header")
    try:
        timestamp = timestamp_raw.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise NativeReError("BL33 timestamp is not ASCII") from error
    return {
        "compressed_bytes": compressed_size,
        "header_sha256": header_sha.hex(),
        "original_bytes": original_size,
        "payload_sha256": payload_sha.hex(),
        "timestamp": timestamp,
        "trailing_zero_bytes": len(raw) - payload_end,
    }


def verify_bl31(raw: bytes) -> dict[str, Any]:
    if len(raw) < 0x290 or raw[0x10:0x14] != b"@AML":
        raise NativeReError("BL31 @AML header is absent")
    version = struct.unpack_from("<I", raw, 0x14)[0]
    payload_size = struct.unpack_from("<Q", raw, 0x20)[0]
    header_size = struct.unpack_from("<Q", raw, 0x28)[0]
    expected_sha = raw[0x30:0x50]
    if version != 1 or header_size != 0x290:
        raise NativeReError("BL31 @AML version or header size is invalid")
    payload = raw[header_size:]
    if len(payload) != payload_size or hashlib.sha256(payload).digest() != expected_sha:
        raise NativeReError("BL31 payload extent or digest mismatch")
    required_strings = (
        b"Amlogic-secure-boot-module-v0.4",
        b"plat/amlogic/board/axg/secureboot/secureboot.c",
        b"AMLSECU!",
    )
    if any(value not in payload for value in required_strings):
        raise NativeReError("BL31 secure-boot identity strings are incomplete")
    return {
        "header_bytes": header_size,
        "load_address": "0x05100000",
        "payload_bytes": payload_size,
        "payload_sha256": expected_sha.hex(),
        "version": version,
    }


def all_offsets(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return offsets
        offsets.append(offset)
        cursor = offset + len(needle)


def verify_boot_image(data: bytes, magic: bytes, label: str) -> dict[str, Any]:
    if data[:8] != magic or data[0x400:0x408] != b"AMLSECU!":
        raise NativeReError(f"{label} Android/AMLSECU identity mismatch")
    offsets = all_offsets(data, TARGET_KEY_SHA256)
    if offsets != list(KEY_DIGEST_OFFSETS):
        raise NativeReError(
            f"{label} AMLSECU key digest offsets mismatch: "
            f"{[hex(offset) for offset in offsets]}"
        )
    return {
        "image_magic": magic.decode("ascii"),
        "amlsecu_offset": "0x400",
        "key_digest_offsets": [f"0x{offset:x}" for offset in offsets],
    }


def verify_report(report_path: Path = REPORT_PATH) -> str:
    report = read_regular(report_path, 1024 * 1024)
    digest = sha256_bytes(report)
    if digest != REPORT_SHA256:
        raise NativeReError(
            f"tracked RE report digest mismatch: expected {REPORT_SHA256}, got {digest}"
        )
    anchors = (
        b"x0=0x820000ff",
        b"operation `0x40`",
        b"FUN_0511d180",
        b"FUN_0511df20",
        b"0xfffc02a8",
        b"0xfffc0b70",
        b"plaintext is **not** recovered",
        b"not authorized by this research or by the campaign controller",
    )
    if any(anchor not in report for anchor in anchors):
        raise NativeReError("tracked RE report is missing a required honesty anchor")
    return digest


def verify_evidence(
    evidence_dir: Path,
    *,
    expected_files: Mapping[str, tuple[int, str]] = EXPECTED_FILES,
    report_path: Path = REPORT_PATH,
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise NativeReError(f"evidence directory is absent or a symlink: {evidence_dir}")
    blobs: dict[str, bytes] = {}
    identities: dict[str, dict[str, Any]] = {}
    for name, (expected_size, expected_sha) in expected_files.items():
        data = read_regular(evidence_dir / name)
        observed_sha = sha256_bytes(data)
        if len(data) != expected_size or observed_sha != expected_sha:
            raise NativeReError(
                f"{name} identity mismatch: bytes={len(data)} sha256={observed_sha}"
            )
        blobs[name] = data
        identities[name] = {"bytes": len(data), "sha256": observed_sha}

    lz4c = verify_lz4c(
        blobs["s19kp_uboot_bl33_raw.bin"],
        blobs["s19kp_uboot_bl33_decompressed.bin"],
    )
    bl31 = verify_bl31(blobs["s19kp_bl31_raw.bin"])
    bl2 = blobs["s19kp_bl2_raw.bin"]
    if bl2[:0x10] != bytes(0x10) or bl2[0x10:0x14] != bytes.fromhex("02000014"):
        raise NativeReError("BL2 SRAM image entry at offset 0x10 is invalid")

    package = blobs["uboot_aml_sdc_burn"]
    key_blob = package[KEY_BLOB_OFFSET : KEY_BLOB_OFFSET + KEY_BLOB_SIZE]
    if len(key_blob) != KEY_BLOB_SIZE or sha256_bytes(key_blob) != KEY_BLOB_SHA256:
        raise NativeReError("packaged BL2/FIP key blob identity mismatch")
    if key_blob[0x10:0x18] != bytes.fromhex("010064aa78563412"):
        raise NativeReError("packaged BL2/FIP key blob record marker mismatch")

    vnish = verify_boot_image(blobs["vnish_PART_boot"], b"MNUDAID!", "VNish boot")
    bitmain = verify_boot_image(
        blobs["bitmain_unknown_09"], b"ANDROID!", "Bitmain boot"
    )
    static_search = (
        bl2
        + blobs["s19kp_bl31_raw.bin"]
        + blobs["s19kp_uboot_bl33_raw.bin"]
        + blobs["s19kp_uboot_bl33_decompressed.bin"]
        + key_blob
    )
    if TARGET_KEY_SHA256 in static_search:
        raise NativeReError("selected image key digest unexpectedly appears in static key corpus")

    report_sha = verify_report(report_path)
    return {
        "schema": "dcentos.s19k-native-re-verification/v1",
        "classification": "runtime-secure-sram-key-boundary",
        "plaintext_recovered": False,
        "live_contact_authorized": False,
        "target_key_sha256": TARGET_KEY_SHA256.hex(),
        "target_key_present_in_static_key_corpus": False,
        "files": identities,
        "bl33_lz4c": lz4c,
        "bl31_aml": bl31,
        "bl2": {"load_address": "0xfffc0000", "entry_offset": "0x10"},
        "key_blob": {
            "bytes": KEY_BLOB_SIZE,
            "package_offset": "0xc200",
            "sha256": KEY_BLOB_SHA256,
        },
        "vnish_boot": vnish,
        "bitmain_boot": bitmain,
        "research_report_sha256": report_sha,
    }


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    """Entry point consumed by ``s19k_gauntlet_workflow.py``."""
    return verify_evidence(evidence_dir)


def stage_held_corpus(evidence_dir: Path) -> dict[str, Any]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    if evidence_dir.is_symlink():
        raise NativeReError(f"evidence directory must not be a symlink: {evidence_dir}")
    for name, source in HELD_SOURCE_PATHS.items():
        source_data = read_regular(source)
        destination = evidence_dir / name
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise NativeReError(f"existing evidence target is unsafe: {destination}")
            if destination.read_bytes() != source_data:
                raise NativeReError(f"refusing to overwrite different evidence: {destination}")
            continue
        shutil.copyfile(source, destination)
    result = verify_evidence(evidence_dir)
    receipt = evidence_dir / "verification.json"
    expected_receipt = canonical_json(result)
    if receipt.exists():
        if read_regular(receipt, 4 * 1024 * 1024) != expected_receipt:
            raise NativeReError(f"refusing to overwrite stale receipt: {receipt}")
    else:
        with receipt.open("xb") as handle:
            handle.write(expected_receipt)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("verify", "stage-held-corpus"), help="offline operation"
    )
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    args = parser.parse_args(argv)
    try:
        evidence_dir = args.evidence_dir.resolve()
        if args.command == "stage-held-corpus":
            result = stage_held_corpus(evidence_dir)
        else:
            result = verify_evidence(evidence_dir)
            receipt = evidence_dir / "verification.json"
            if read_regular(receipt, 4 * 1024 * 1024) != canonical_json(result):
                raise NativeReError("verification.json is absent, stale, or noncanonical")
    except (OSError, NativeReError) as error:
        print(f"S19K_NATIVE_RE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_NATIVE_RE_OK "
        f"classification={result['classification']} "
        f"plaintext_recovered={str(result['plaintext_recovered']).lower()} "
        f"target_key_sha256={result['target_key_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
