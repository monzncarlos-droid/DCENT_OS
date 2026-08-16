#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("extract_am2_s17_kernel.py")
SPEC = importlib.util.spec_from_file_location("extract_am2_s17_kernel", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


WORKSPACE = Path(__file__).resolve().parents[3]
DONOR = WORKSPACE / ""


def _its(kernel_ref: str = "kernel@1", dtb_ref: str = "fdt@1") -> str:
    return f'''/dts-v1/;
/ {{
    description = "DCENT_OS S17 model-bound UBI kernel FIT";
    #address-cells = <1>;
    images {{
        kernel@1 {{
            description = "DCENT_OS S17 UBI kernel";
            data = /incbin/("kernel.bin");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "none";
            load = <0x00008000>;
            entry = <0x00008000>;
            hash@1 {{ algo = "crc32"; }};
            hash@2 {{ algo = "sha1"; }};
        }};
        fdt@1 {{
            description = "Antminer S17 model-bound device tree";
            data = /incbin/("s17.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1 {{ algo = "crc32"; }};
            hash@2 {{ algo = "sha1"; }};
        }};
    }};
    configurations {{
        default = "config@1";
        config@1 {{
            description = "DCENT_OS S17 kernel plus exact S17 DTB";
            kernel = "{kernel_ref}";
            fdt = "{dtb_ref}";
        }};
    }};
}};
'''


def _build_fit(
    root: Path,
    kernel: bytes,
    dtb: bytes,
    *,
    kernel_ref: str = "kernel@1",
    dtb_ref: str = "fdt@1",
) -> Path:
    mkimage = shutil.which("mkimage")
    if mkimage is None:
        raise unittest.SkipTest("mkimage with FIT support is not installed")
    root.mkdir()
    (root / "kernel.bin").write_bytes(kernel)
    (root / "s17.dtb").write_bytes(dtb)
    (root / "s17.its").write_text(_its(kernel_ref, dtb_ref), encoding="ascii")
    output = root / "s17.itb"
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = str(subject.SOURCE_FIT_TIMESTAMP)
    result = subprocess.run(
        [mkimage, "-f", "s17.its", output.name],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(f"mkimage failed: {result.stdout}\n{result.stderr}")
    return output


class S17DonorAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        if not DONOR.is_file():
            self.skipTest("exact held Braiins S17 SD donor is not present")

    def test_exact_disk_fit_kernel_dtb_and_boot_contract_admit(self) -> None:
        kernel, dtb, receipt = subject.admit_donor(DONOR)
        self.assertEqual(subject.DONOR_SHA256, receipt["donor"]["sha256"])
        self.assertEqual(subject.SOURCE_FIT_SHA256, receipt["source_fit"]["sha256"])
        self.assertEqual(subject.KERNEL_SHA256, subject.sha256_bytes(kernel))
        self.assertEqual(subject.DTB_SHA256, subject.sha256_bytes(dtb))
        self.assertEqual(subject.DTB_MODEL, receipt["source_fit"]["dtb"]["model"])
        self.assertEqual("mtd7/firmware1", receipt["uboot"]["firmware_slots"]["1"])
        self.assertEqual("mtd8/firmware2", receipt["uboot"]["firmware_slots"]["2"])
        self.assertFalse(receipt["authorization"]["stock_first_install"])
        self.assertFalse(receipt["authorization"]["flash"])

    def test_wrong_outer_image_hash_is_refused_before_partition_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "mutated.img"
            raw = bytearray(DONOR.read_bytes())
            raw[len(raw) // 2] ^= 1
            mutated.write_bytes(raw)
            with self.assertRaisesRegex(subject.AdmissionError, "size/SHA256"):
                subject.admit_donor(mutated)

    def test_wrong_dtb_model_is_refused_even_with_matching_test_hash(self) -> None:
        _kernel, dtb, _receipt = subject.admit_donor(DONOR)
        mutated = dtb.replace(
            b"Antminer S17 Miner Control Board", b"Antminer T17 Miner Control Board", 1
        )
        self.assertEqual(len(dtb), len(mutated))
        with mock.patch.object(
            subject, "DTB_SHA256", hashlib.sha256(mutated).hexdigest()
        ):
            with self.assertRaisesRegex(subject.AdmissionError, "DTB model mismatch"):
                subject._validate_dtb(mutated)

    def test_extract_is_exclusive_and_records_denied_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel"
            dtb = root / "s17.dtb"
            receipt = root / "receipt.json"
            result = subject.extract(DONOR, kernel, dtb, receipt)
            decoded = json.loads(receipt.read_text("ascii"))
            self.assertEqual(subject.SCHEMA, decoded["schema"])
            self.assertFalse(result["authorization"]["device_contact"])
            with self.assertRaisesRegex(subject.AdmissionError, "must all be absent"):
                subject.extract(DONOR, kernel, dtb, receipt)

    def test_exact_model_bound_fit_fits_23_usable_lebs(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            receipt = subject.verify_ubi_fit(fit)
        self.assertEqual(23 * 126_976, receipt["geometry"]["kernel_capacity_bytes"])
        self.assertEqual(subject.OUTPUT_FIT_SIZE, receipt["geometry"]["fit_bytes"])
        self.assertEqual(subject.OUTPUT_FIT_SHA256, receipt["fit"]["sha256"])
        self.assertEqual(74_868, receipt["geometry"]["margin_bytes"])
        self.assertTrue(receipt["geometry"]["fits"])
        self.assertGreater(receipt["geometry"]["margin_bytes"], 0)
        self.assertEqual(subject.DTB_MODEL, receipt["fit"]["dtb_model"])
        self.assertFalse(receipt["authorization"]["stock_first_install"])

    def test_wrong_fit_payload_hash_is_refused(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            raw = bytearray(fit.read_bytes())
            offset = raw.find(kernel)
            self.assertGreaterEqual(offset, 0)
            raw[offset + len(kernel) // 2] ^= 1
            bad = Path(directory) / "wrong-hash.itb"
            bad.write_bytes(raw)
            with self.assertRaisesRegex(subject.AdmissionError, "reproducible pin"):
                subject.verify_ubi_fit(bad)

    def test_wrong_fit_configuration_is_refused(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            raw = bytearray(fit.read_bytes())
            offset = raw.rfind(b"kernel@1\0")
            self.assertGreaterEqual(offset, 0)
            raw[offset : offset + len(b"kernel@1")] = b"kernel@2"
            wrong_config = Path(directory) / "wrong-config.itb"
            wrong_config.write_bytes(raw)
            with mock.patch.object(
                subject, "OUTPUT_FIT_SHA256", hashlib.sha256(raw).hexdigest()
            ):
                with self.assertRaisesRegex(
                    subject.AdmissionError, "selects the wrong kernel"
                ):
                    subject.verify_ubi_fit(wrong_config)

    def test_cli_extract_emits_machine_readable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(subject.__file__)),
                    "extract",
                    "--donor",
                    str(DONOR),
                    "--kernel-output",
                    str(root / "kernel"),
                    "--dtb-output",
                    str(root / "s17.dtb"),
                    "--receipt",
                    str(root / "receipt.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                subject.DONOR_SHA256, json.loads(result.stdout)["donor"]["sha256"]
            )


if __name__ == "__main__":
    unittest.main()
