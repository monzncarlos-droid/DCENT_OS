#!/usr/bin/env python3
"""Tests for the local-only Nano 3 rootfs mutation verifier."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from verify_nano3_user_donor_mutation import (
    BUILD_SCRIPT,
    Nano3MutationError,
    canonical_receipt_bytes,
    load_accepted_donor,
    main,
    verify_mutation_bytes,
)


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
DONOR = (
    WORKSPACE_ROOT
    / "knowledge-base"
    / "firmware-archive"
    / "avalon-k230"
    / "stock"
    / "heater_nano3_master_image.img"
)
CANDIDATE = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "build"
    / "image"
    / "candidates"
    / "nano3-data-fault-recovery-working-v12"
    / "DCENT_NANO3_ROOTFS_COEXISTENCE.kdimg"
)
FULL_WRAPPER = (
    CANDIDATE.parent / "DCENT_NANO3_STOCK_CHAIN_COEXISTENCE.kdimg"
)


@unittest.skipUnless(
    DONOR.is_file() and CANDIDATE.is_file() and FULL_WRAPPER.is_file(),
    "held donor and v12 candidates are required for exact integration tests",
)
class Nano3UserDonorMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.donor = load_accepted_donor(DONOR)
        cls.candidate = CANDIDATE.read_bytes()
        cls.receipt = verify_mutation_bytes(cls.donor, cls.candidate)

    def test_exact_rootfs_only_mutation_passes(self) -> None:
        mutation = self.receipt["mutation"]
        self.assertEqual(mutation["exact_write_slots"], ["rootfs_1", "rootfs_2"])
        self.assertEqual(mutation["partition_count"], 2)
        self.assertEqual(mutation["last_nand_end"], 0x04400000)
        self.assertFalse(mutation["persistent_data_included"])
        self.assertTrue(all(row["differs_from_donor"] for row in self.receipt["slots"]))

    def test_receipt_is_path_and_payload_free_and_non_authorizing(self) -> None:
        encoded = canonical_receipt_bytes(self.receipt)
        self.assertEqual(encoded, canonical_receipt_bytes(json.loads(encoded)))
        self.assertNotIn(str(DONOR).encode(), encoded)
        self.assertNotIn(str(CANDIDATE).encode(), encoded)
        self.assertNotIn(self.donor[:64], encoded)
        self.assertFalse(self.receipt["claims"]["redistribution_authorized"])
        self.assertFalse(self.receipt["claims"]["flash_authorized"])
        self.assertFalse(self.receipt["claims"]["hardware_action_performed"])
        self.assertFalse(
            self.receipt["mutation"]["filesystem_contents_verified_by_this_receipt"]
        )

    def test_full_factory_wrapper_is_refused(self) -> None:
        with self.assertRaisesRegex(Nano3MutationError, "not labeled rootfs-only"):
            verify_mutation_bytes(self.donor, FULL_WRAPPER.read_bytes())

    def test_one_byte_payload_mutation_is_refused(self) -> None:
        changed = bytearray(self.candidate)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            verify_mutation_bytes(self.donor, bytes(changed))

    def test_builder_defaults_to_mutation_only_and_guards_full_wrapper(self) -> None:
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('OUTPUT_SCOPE="${OUTPUT_SCOPE:-rootfs-only}"', script)
        self.assertIn('if output_scope == "both":', script)
        self.assertIn(
            "ACKNOWLEDGE_LOCAL_FACTORY_BYTES=user-owned-donor-local-only", script
        )

    def test_cli_writes_new_receipt_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt.json"
            arguments = [
                "verify_nano3_user_donor_mutation.py",
                "--donor",
                str(DONOR),
                "--mutation",
                str(CANDIDATE),
                "--receipt",
                str(receipt),
            ]
            import sys

            original = sys.argv
            try:
                sys.argv = arguments
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(), 0)
                self.assertEqual(
                    hashlib.sha256(receipt.read_bytes()).hexdigest(),
                    hashlib.sha256(canonical_receipt_bytes(self.receipt)).hexdigest(),
                )
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(), 2)
            finally:
                sys.argv = original

    def test_wrong_size_donor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "wrong.img"
            wrong.write_bytes(b"wrong")
            with self.assertRaisesRegex(Nano3MutationError, "size"):
                load_accepted_donor(wrong)


if __name__ == "__main__":
    unittest.main()
