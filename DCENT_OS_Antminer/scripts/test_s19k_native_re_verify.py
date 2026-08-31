#!/usr/bin/env python3
"""Adversarial tests for the offline S19k native secure-firmware verifier."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).with_name("s19k_native_re_verify.py")
SPEC = importlib.util.spec_from_file_location("s19k_native_re_verify", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
native_re = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native_re)


def lz4c_pair() -> tuple[bytes, bytes]:
    plaintext = b"synthetic-bl33-plaintext"
    compressed = b"synthetic-compressed-block"
    timestamp = b"2022071518:32:39".ljust(32, b"\0")
    prefix = struct.pack(
        "<IHHII32s32s12sI",
        native_re.LZ4C_MAGIC,
        0,
        native_re.LZ4C_HEADER.size,
        len(plaintext),
        len(compressed),
        hashlib.sha256(plaintext).digest(),
        timestamp,
        bytes(12),
        native_re.LZ4C_MAGIC,
    )
    header = prefix + hashlib.sha256(prefix).digest()
    return header + compressed + bytes(5), plaintext


def bl31_image() -> bytes:
    payload = (
        b"Amlogic-secure-boot-module-v0.4\0"
        b"plat/amlogic/board/axg/secureboot/secureboot.c\0AMLSECU!"
    )
    header = bytearray(0x290)
    header[0x10:0x14] = b"@AML"
    struct.pack_into("<I", header, 0x14, 1)
    struct.pack_into("<Q", header, 0x20, len(payload))
    struct.pack_into("<Q", header, 0x28, len(header))
    header[0x30:0x50] = hashlib.sha256(payload).digest()
    return bytes(header) + payload


def boot_image(magic: bytes) -> bytes:
    data = bytearray(0x600)
    data[:8] = magic
    data[0x400:0x408] = b"AMLSECU!"
    for offset in native_re.KEY_DIGEST_OFFSETS:
        data[offset : offset + 32] = native_re.TARGET_KEY_SHA256
    return bytes(data)


class NativeReVerifierTests(unittest.TestCase):
    def test_lz4c_header_binds_plaintext_and_zero_tail(self) -> None:
        raw, plaintext = lz4c_pair()
        result = native_re.verify_lz4c(raw, plaintext)
        self.assertEqual(result["trailing_zero_bytes"], 5)
        with self.assertRaises(native_re.NativeReError):
            native_re.verify_lz4c(raw[:-1] + b"\x01", plaintext)
        with self.assertRaises(native_re.NativeReError):
            native_re.verify_lz4c(raw, plaintext + b"x")

    def test_bl31_header_binds_secure_boot_payload(self) -> None:
        raw = bl31_image()
        result = native_re.verify_bl31(raw)
        self.assertEqual(result["header_bytes"], 0x290)
        damaged = bytearray(raw)
        damaged[-1] ^= 1
        with self.assertRaises(native_re.NativeReError):
            native_re.verify_bl31(bytes(damaged))

    def test_boot_images_require_exact_three_digest_offsets(self) -> None:
        data = boot_image(b"ANDROID!")
        result = native_re.verify_boot_image(data, b"ANDROID!", "stock")
        self.assertEqual(result["key_digest_offsets"], ["0x460", "0x4c0", "0x520"])
        with self.assertRaises(native_re.NativeReError):
            native_re.verify_boot_image(data + native_re.TARGET_KEY_SHA256, b"ANDROID!", "stock")

    def test_complete_synthetic_evidence_and_mutation_refusal(self) -> None:
        raw_lz4c, plain = lz4c_pair()
        bl31 = bl31_image()
        bl2 = bytearray(0x20)
        bl2[0x10:0x14] = bytes.fromhex("02000014")
        package = bytearray(native_re.KEY_BLOB_OFFSET + native_re.KEY_BLOB_SIZE)
        key_blob = bytearray(native_re.KEY_BLOB_SIZE)
        key_blob[0x10:0x18] = bytes.fromhex("010064aa78563412")
        package[native_re.KEY_BLOB_OFFSET :] = key_blob
        files = {
            "s19kp_uboot_bl33_raw.bin": raw_lz4c,
            "s19kp_uboot_bl33_decompressed.bin": plain,
            "s19kp_bl31_raw.bin": bl31,
            "s19kp_bl2_raw.bin": bytes(bl2),
            "uboot_aml_sdc_burn": bytes(package),
            "vnish_PART_boot": boot_image(b"MNUDAID!"),
            "bitmain_unknown_09": boot_image(b"ANDROID!"),
        }
        expected = {
            name: (len(data), hashlib.sha256(data).hexdigest())
            for name, data in files.items()
        }
        old_key_blob_sha = native_re.KEY_BLOB_SHA256
        native_re.KEY_BLOB_SHA256 = hashlib.sha256(key_blob).hexdigest()
        try:
            with tempfile.TemporaryDirectory() as raw_dir:
                evidence = Path(raw_dir)
                for name, data in files.items():
                    (evidence / name).write_bytes(data)
                result = native_re.verify_evidence(
                    evidence, expected_files=expected, report_path=native_re.REPORT_PATH
                )
                self.assertEqual(result["classification"], "runtime-secure-sram-key-boundary")
                self.assertFalse(result["plaintext_recovered"])
                (evidence / "s19kp_bl2_raw.bin").write_bytes(bytes(bl2) + b"x")
                with self.assertRaises(native_re.NativeReError):
                    native_re.verify_evidence(
                        evidence, expected_files=expected, report_path=native_re.REPORT_PATH
                    )
        finally:
            native_re.KEY_BLOB_SHA256 = old_key_blob_sha

    def test_tracked_report_is_hash_bound_and_denies_authority(self) -> None:
        self.assertEqual(native_re.verify_report(), native_re.REPORT_SHA256)


if __name__ == "__main__":
    unittest.main()
