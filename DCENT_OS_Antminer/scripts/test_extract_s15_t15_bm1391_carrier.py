#!/usr/bin/env python3
"""Focused tests for the read-only S15/T15 BM1391 carrier extractor."""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import struct
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).with_name("extract_s15_t15_bm1391_carrier.py")
SPEC = importlib.util.spec_from_file_location("bm1391_carrier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(carrier)


def tar_gz(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


def regular(name: str, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


class BoundedPrimitiveTests(unittest.TestCase):
    def test_bounded_gzip_rejects_bomb_trailing_and_truncation(self):
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(gzip.compress(b"123456789"), 8, "test")
        concatenated = gzip.compress(b"one") + gzip.compress(b"two")
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(concatenated, 100, "test")
        with self.assertRaises(carrier.EvidenceError):
            carrier.bounded_gzip(gzip.compress(b"payload")[:-2], 100, "test")

    def test_archive_rejects_unsafe_duplicate_and_nonregular_members(self):
        unsafe = tar_gz([regular("../escape", b"x")])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(unsafe, {"../escape"}, "test")

        duplicate = tar_gz([regular("same", b"a"), regular("same", b"b")])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(duplicate, {"same"}, "test")

        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        nonregular = tar_gz([(link, None)])
        with self.assertRaises(carrier.EvidenceError):
            carrier.exact_tar_gz(nonregular, {"link"}, "test")

    def test_archive_schema_is_exact(self):
        archive = tar_gz([regular("expected", b"ok"), regular("extra", b"no")])
        with self.assertRaisesRegex(carrier.EvidenceError, "schema drift"):
            carrier.exact_tar_gz(archive, {"expected"}, "test")

    def test_legacy_uimage_crc_and_metadata_are_checked(self):
        payload = gzip.compress(b"synthetic-ext2", mtime=0)
        data_crc = zlib.crc32(payload) & 0xFFFFFFFF
        fields = [
            carrier.UIMAGE_MAGIC,
            0,
            123,
            len(payload),
            0,
            0,
            data_crc,
            5,
            2,
            3,
            1,
            b"\0" * 32,
        ]
        header = bytearray(struct.pack(">7I4B32s", *fields))
        struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
        image = bytes(header) + payload
        decoded, metadata = carrier.parse_legacy_ramdisk(image, carrier.sha256(image))
        self.assertEqual(decoded, b"synthetic-ext2")
        self.assertEqual(metadata["type"], "Linux/ARM/ramdisk/gzip")

        damaged = bytearray(image)
        damaged[-1] ^= 1
        with self.assertRaises(carrier.EvidenceError):
            carrier.parse_legacy_ramdisk(bytes(damaged), carrier.sha256(bytes(damaged)))

    def test_contract_never_grants_runtime_or_wire_authority(self):
        contract = carrier.carrier_contract()
        self.assertEqual(
            contract["derivation"]["method"], "reviewed-static-semantic-profile"
        )
        self.assertFalse(contract["derivation"]["mechanical_extraction"])
        authority = contract["authority"]
        self.assertTrue(authority["evidence_only"])
        for field in (
            "install_authorized",
            "live_probe_authorized",
            "runtime_mutation_authorized",
            "safe_runtime_composition_proven",
            "wire_transactions_authorized",
        ):
            self.assertFalse(authority[field], field)
        self.assertFalse(contract["pic"]["mutation_authorized"])
        self.assertFalse(
            contract["thermal_and_fans"]["external_temperature"]["wire_read_authorized"]
        )
        self.assertIsNone(contract["pll"]["safe_default_frequency_mhz"])
        self.assertFalse(contract["watchdogs"]["safe_shutdown_path_proven"])
        enumeration = contract["bm1391_enumeration"]
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["S15"]["count"],
            72,
        )
        self.assertEqual(
            enumeration["expected_responses_per_present_chain"]["T15"]["count"],
            60,
        )
        self.assertFalse(enumeration["physical_topology_authorized"])
        self.assertIn("unresolved", enumeration["caveat"])
        binding = contract["fpga_return_and_work_binding"]
        self.assertEqual(binding["record"]["length_bytes"], 8)
        self.assertEqual(binding["outstanding_work_record_bytes"], 64)
        self.assertEqual(binding["bound_nonce_record_bytes"], 60)
        self.assertEqual(binding["host_ring"]["capacity"], 511)
        self.assertIn("overwrite", binding["host_ring"]["stock_nonce_full_behavior"])
        self.assertIn("refused", binding["host_ring"]["clean_codec_behavior"])
        self.assertFalse(binding["nonce"]["word0_bit6_checked_by_stock"])
        self.assertFalse(binding["runtime_authorized"])


class HeldCorpusRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workspace = Path(__file__).resolve().parents[3]
        cls.s15 = (
            workspace
            / "Latest Bitmain FW"
            / ("Antminer-S15-user-OM-201912131535-sig_4864.tar.gz")
        )
        cls.t15 = (
            workspace
            / "Latest Bitmain FW"
            / ("Antminer-T15-user-OM-201912131546-sig_4867.tar.gz")
        )
        if not cls.s15.is_file() or not cls.t15.is_file():
            raise unittest.SkipTest("operator-held S15/T15 corpus is absent")
        cls.report = carrier.build_report(cls.s15, cls.t15)

    def test_exact_held_packages_and_selected_rootfs_files(self):
        self.assertEqual(
            self.report["schema"], "dcent.s15-t15-bm1391-carrier-evidence.v1"
        )
        for model in ("S15", "T15"):
            evidence = self.report["models"][model]
            self.assertFalse(evidence["boot"]["devicetree_member_present"])
            self.assertEqual(evidence["rootfs"]["ext2_size"], 100 * 1024 * 1024)
            self.assertEqual(len(evidence["rootfs"]["selected_files"]), 7)
            self.assertEqual(
                evidence["artifact"]["signature_evidence"],
                "payload-contained-signature-material-not-an-anchored-root",
            )

    def test_s15_t15_shared_carrier_bytes_are_identical(self):
        models = self.report["models"]
        self.assertEqual(
            models["S15"]["boot"]["boot_bin"], models["T15"]["boot"]["boot_bin"]
        )
        self.assertEqual(
            models["S15"]["boot"]["kernel"], models["T15"]["boot"]["kernel"]
        )
        selected = {}
        for model in ("S15", "T15"):
            selected[model] = {
                item["path"]: item for item in models[model]["rootfs"]["selected_files"]
            }
        for path in carrier.COMMON_FILE_PINS:
            self.assertEqual(selected["S15"][path], selected["T15"][path])

    def test_output_is_deterministic_and_contains_no_input_paths(self):
        encoded_a = json.dumps(self.report, indent=2, sort_keys=True) + "\n"
        encoded_b = (
            json.dumps(
                carrier.build_report(self.s15, self.t15), indent=2, sort_keys=True
            )
            + "\n"
        )
        self.assertEqual(encoded_a, encoded_b)
        self.assertNotIn(str(self.s15.parent), encoded_a)

    def test_package_pin_fails_closed_on_byte_drift(self):
        damaged = bytearray(self.s15.read_bytes())
        damaged[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "damaged.tar.gz"
            path.write_bytes(damaged)
            with self.assertRaisesRegex(carrier.EvidenceError, "package hash drift"):
                carrier.checked_blob(path, carrier.MODEL_PINS["S15"]["package_sha256"])


if __name__ == "__main__":
    unittest.main()
