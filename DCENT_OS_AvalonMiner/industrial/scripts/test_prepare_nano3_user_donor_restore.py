#!/usr/bin/env python3
"""Tests for the operator-local Nano 3 factory-restore workflow."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prepare_nano3_user_donor_restore import (
    HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
    LOCAL_ONLY_ACKNOWLEDGEMENT,
    Nano3DonorRestoreError,
    _build,
    _verify,
    canonical_receipt_bytes,
    load_accepted_donor,
    verify_restore_bytes,
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
HISTORICAL_RESTORE = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "build"
    / "image"
    / "STOCK_NANO3_RESTORE.kdimg"
)


@unittest.skipUnless(
    DONOR.is_file() and HISTORICAL_RESTORE.is_file(),
    "held donor and historical restore are required for exact integration tests",
)
class Nano3UserDonorRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.donor = load_accepted_donor(DONOR)
        cls.restore = HISTORICAL_RESTORE.read_bytes()
        cls.receipt = verify_restore_bytes(cls.donor, cls.restore)

    def test_live_proven_restore_is_exact_donor_projection(self) -> None:
        restore = self.receipt["restore"]
        self.assertEqual(restore["sha256"], HISTORICAL_LIVE_PROVEN_RESTORE_SHA256)
        self.assertEqual(restore["container_profile"], "live-proven-2026-08-21")
        self.assertEqual(restore["partition_count"], 12)
        self.assertEqual(restore["last_nand_end"], 0x06400000)
        self.assertFalse(restore["persistent_data_included"])
        self.assertTrue(
            all(slot["exact_donor_slice"] for slot in self.receipt["slots"])
        )

    def test_receipt_is_canonical_path_free_and_payload_free(self) -> None:
        encoded = canonical_receipt_bytes(self.receipt)
        self.assertEqual(encoded, canonical_receipt_bytes(json.loads(encoded)))
        self.assertNotIn(str(DONOR).encode(), encoded)
        self.assertNotIn(str(HISTORICAL_RESTORE).encode(), encoded)
        self.assertNotIn(self.donor[:64], encoded)
        claims = self.receipt["claims"]
        self.assertFalse(claims["receipt_contains_factory_payload_bytes"])
        self.assertFalse(claims["receipt_contains_local_paths"])
        self.assertFalse(claims["redistribution_authorized"])
        self.assertFalse(claims["flash_authorized"])
        self.assertFalse(claims["hardware_action_performed"])

    def test_one_byte_container_mutation_is_refused(self) -> None:
        changed = bytearray(self.restore)
        changed[-1] ^= 1
        with self.assertRaisesRegex(Nano3DonorRestoreError, "neither"):
            verify_restore_bytes(self.donor, bytes(changed))

    def test_verify_command_writes_new_receipt_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = Path(temporary) / "receipt.json"
            args = argparse.Namespace(
                donor=DONOR,
                restore=HISTORICAL_RESTORE,
                receipt=receipt_path,
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(_verify(args), 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["status"], "PASS")
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(
                summary["receipt_sha256"],
                hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            )
            with self.assertRaisesRegex(Nano3DonorRestoreError, "overwrite"):
                _verify(args)

    def test_build_requires_exact_local_only_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                donor=DONOR,
                output=Path(temporary) / "restore.kdimg",
                receipt=Path(temporary) / "receipt.json",
                acknowledge_local_only="wrong",
            )
            with self.assertRaisesRegex(Nano3DonorRestoreError, "acknowledge"):
                _build(args)
            self.assertFalse(args.output.exists())
            self.assertFalse(args.receipt.exists())

    def test_build_creates_current_canonical_without_touching_donor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "restore.kdimg"
            receipt_path = Path(temporary) / "receipt.json"
            donor_hash_before = hashlib.sha256(DONOR.read_bytes()).hexdigest()
            args = argparse.Namespace(
                donor=DONOR,
                output=output_path,
                receipt=receipt_path,
                acknowledge_local_only=LOCAL_ONLY_ACKNOWLEDGEMENT,
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(_build(args), 0)
            built_receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(
                built_receipt["restore"]["container_profile"],
                "current-tooling-canonical",
            )
            self.assertEqual(
                hashlib.sha256(output_path.read_bytes()).hexdigest(),
                built_receipt["restore"]["sha256"],
            )
            self.assertEqual(
                hashlib.sha256(DONOR.read_bytes()).hexdigest(), donor_hash_before
            )


class Nano3UserDonorRestoreFailureTests(unittest.TestCase):
    def test_wrong_size_donor_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "wrong.img"
            wrong.write_bytes(b"not a donor")
            with self.assertRaisesRegex(Nano3DonorRestoreError, "size"):
                load_accepted_donor(wrong)


if __name__ == "__main__":
    unittest.main()
