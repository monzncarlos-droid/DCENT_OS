#!/usr/bin/env python3
"""Tests for the Nano 3 secret-safe persistence snapshot verifier."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_nano3_persistence_snapshots import (
    FIELD_ORDER,
    PersistenceSnapshotError,
    _reject_windows_device_path,
    main,
    parse_snapshot,
    read_regular_bounded,
    verify_pair,
)


RUN_ID = "11" * 32
BEFORE_BOOT = "11111111-2222-3333-4444-555555555555"
AFTER_BOOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SYSTEM_HASH = "ab" * 32
SYSTEM_STRUCTURE_HASH = "33" * 32
CGMINER_HASH = "44" * 32
CGMINER_STRUCTURE_HASH = "55" * 32


def snapshot_values(phase: str, boot_id: str) -> dict[str, str]:
    return {
        "schema": "dcent-nano3-persistence-snapshot-v1",
        "scope": "read-only-structure-and-digest",
        "phase": phase,
        "run_id": RUN_ID,
        "boot_id": boot_id,
        "data_mount_device": "/dev/ubi2_0",
        "data_mount_type": "ubifs",
        "data_mount_identity": "ubi2_0:ubifs",
        "data_mtd_num": "12",
        "data_volume_name": "ubi_data_part",
        "readiness_marker": "exact-directory",
        "systemcfg_bytes": "837",
        "systemcfg_sha256": SYSTEM_HASH,
        "systemcfg_structure_sha256": SYSTEM_STRUCTURE_HASH,
        "systemcfg_mode": "600",
        "systemcfg_owner": "1000:1000",
        "cgminer_bytes": "454",
        "cgminer_sha256": CGMINER_HASH,
        "cgminer_structure_sha256": CGMINER_STRUCTURE_HASH,
        "cgminer_mode": "600",
        "cgminer_owner": "1000:1000",
        "configuration_values_printed": "false",
        "snapshot_complete": "1",
        "authorizes_device": "false",
        "authorizes_reboot": "false",
        "authorizes_transmit": "false",
        "authorizes_energization": "false",
    }


def encode(values: dict[str, str]) -> bytes:
    return ("".join(f"{name}={values[name]}\n" for name in FIELD_ORDER)).encode()


class Nano3PersistenceSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.before_values = snapshot_values("pre-reboot", BEFORE_BOOT)
        self.after_values = snapshot_values("post-reboot", AFTER_BOOT)
        self.before = encode(self.before_values)
        self.after = encode(self.after_values)

    def test_exact_pair_passes_and_receipt_is_deterministic(self) -> None:
        report = verify_pair(self.before, self.after)
        self.assertEqual(
            report["before_snapshot_sha256"],
            "47cf41ca3e7bce7d81eda742d4f9b1ac4d3afcc9a6e87f490b26a9e80348e8a8",
        )
        self.assertEqual(
            report["after_snapshot_sha256"],
            "884fcd5f3af06a02ad1f6e5f956404bf7ca8c095917bbdc20881587f816e8723",
        )
        self.assertEqual(
            report["pair_digest"],
            "0cdc6598d3bc5b0567152576d0cb64d95a4419c12bc6d85e4e078eb75761e096",
        )
        self.assertEqual(report["run_id"], RUN_ID)
        self.assertEqual(report["before_boot_id"], BEFORE_BOOT)
        self.assertEqual(report["after_boot_id"], AFTER_BOOT)
        self.assertEqual(report["systemcfg_sha256"], SYSTEM_HASH)
        self.assertEqual(report["cgminer_sha256"], CGMINER_HASH)
        self.assertEqual(report, verify_pair(self.before, self.after))

    def test_every_persistent_metadata_class_must_match(self) -> None:
        mutations = {
            "data_volume_name": "other",
            "systemcfg_bytes": "838",
            "systemcfg_sha256": "66" * 32,
            "systemcfg_structure_sha256": "77" * 32,
            "systemcfg_mode": "640",
            "systemcfg_owner": "0:0",
            "cgminer_bytes": "455",
            "cgminer_sha256": "88" * 32,
            "cgminer_structure_sha256": "99" * 32,
            "cgminer_mode": "644",
            "cgminer_owner": "0:1000",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = dict(self.after_values)
                changed[field] = value
                with self.assertRaises(PersistenceSnapshotError):
                    verify_pair(self.before, encode(changed))

    def test_pair_requires_matching_run_distinct_boots_and_ordered_phases(self) -> None:
        same_boot = dict(self.after_values)
        same_boot["boot_id"] = BEFORE_BOOT
        with self.assertRaisesRegex(PersistenceSnapshotError, "distinct boots"):
            verify_pair(self.before, encode(same_boot))

        other_run = dict(self.after_values)
        other_run["run_id"] = "aa" * 32
        with self.assertRaisesRegex(PersistenceSnapshotError, "run IDs"):
            verify_pair(self.before, encode(other_run))

        with self.assertRaisesRegex(PersistenceSnapshotError, "pre then post"):
            verify_pair(self.after, self.before)

    def test_parser_rejects_noncanonical_and_authority_drift(self) -> None:
        hostile = [
            self.before.replace(b"\n", b"\r\n"),
            self.before.rstrip(b"\n"),
            self.before + b"secret=must-not-be-admitted\n",
            b"\xff" + self.before[1:],
            self.before.replace(b"snapshot_complete=1", b"snapshot_complete=0"),
            self.before.replace(b"authorizes_device=false", b"authorizes_device=true"),
            self.before.replace(b"systemcfg_bytes=837", b"systemcfg_bytes=0"),
            self.before.replace(b"systemcfg_bytes=837", b"systemcfg_bytes=65537"),
            self.before.replace(
                f"systemcfg_sha256={SYSTEM_HASH}".encode(),
                f"systemcfg_sha256={SYSTEM_HASH.upper()}".encode(),
            ),
        ]
        for candidate in hostile:
            with self.subTest(candidate_length=len(candidate)):
                with self.assertRaises(PersistenceSnapshotError):
                    parse_snapshot(candidate)

    def test_cli_error_never_echoes_a_hostile_value(self) -> None:
        secret = "pool-password-must-not-leak"
        hostile = self.before.replace(
            b"systemcfg_bytes=837", f"systemcfg_bytes={secret}".encode()
        )
        with tempfile.TemporaryDirectory() as directory:
            before_path = Path(directory) / "before.txt"
            after_path = Path(directory) / "after.txt"
            before_path.write_bytes(hostile)
            after_path.write_bytes(self.after)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main(
                    ["--before", str(before_path), "--after", str(after_path)]
                )
        self.assertEqual(result, 2)
        self.assertNotIn(secret, stdout.getvalue())
        self.assertNotIn(secret, stderr.getvalue())

    def test_bounded_reader_rejects_symlink_and_device_names(self) -> None:
        for unsafe in ("NUL.txt", "com4.snapshot", r"\\.\pipe\snapshot.txt"):
            with self.subTest(path=unsafe):
                with self.assertRaises(PersistenceSnapshotError):
                    _reject_windows_device_path(Path(unsafe))

        with tempfile.TemporaryDirectory() as directory:
            regular = Path(directory) / "regular.txt"
            regular.write_bytes(self.before)
            self.assertEqual(read_regular_bounded(regular), self.before)
            regular.write_bytes(b"x" * (16 * 1024 + 1))
            with self.assertRaises(PersistenceSnapshotError):
                read_regular_bounded(regular)
            regular.write_bytes(self.before)
            symlink = Path(directory) / "link.txt"
            try:
                symlink.symlink_to(regular)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(PersistenceSnapshotError):
                read_regular_bounded(symlink)

    def test_bounded_reader_rejects_concurrent_same_size_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.txt"
            snapshot.write_bytes(b"x" * 8192)
            original_read = os.read
            changed = False

            def mutating_read(descriptor: int, amount: int) -> bytes:
                nonlocal changed
                chunk = original_read(descriptor, amount)
                if chunk and not changed:
                    changed = True
                    with snapshot.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(b"y")
                        stream.flush()
                        os.fsync(stream.fileno())
                return chunk

            with mock.patch(
                "verify_nano3_persistence_snapshots.os.read",
                side_effect=mutating_read,
            ):
                with self.assertRaisesRegex(PersistenceSnapshotError, "changed"):
                    read_regular_bounded(snapshot)


if __name__ == "__main__":
    unittest.main()
