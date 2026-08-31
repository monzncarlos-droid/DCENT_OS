#!/usr/bin/env python3
"""Adversarial tests for S19k persistent-recovery bundle preparation."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_persistent_recovery_prepare as preparer  # noqa: E402
import s19k_persistent_recovery_verify as verifier  # noqa: E402
from test_s19k_persistent_recovery_verify import Fixture  # noqa: E402


class RawCaptureFixture:
    """The raw operator-side capture the preparer is allowed to freeze."""

    def __init__(self, root: Path) -> None:
        self.authored = Fixture(root / "authored")
        raw = root / "raw"
        raw.mkdir()
        self.authority = self._file(raw, verifier.AUTHORITY_FILE)
        self.device_identity = self._file(raw, verifier.DEVICE_FILE)
        self.backup_manifest = self._file(raw, verifier.BACKUP_FILE)
        self.rehearsal = self._file(raw, verifier.REHEARSAL_FILE)
        self.witness = self._file(raw, verifier.WITNESS_FILE)
        self.proc_mtd = self._file(raw, verifier.PROC_MTD_FILE)
        self.stock_bmu = self._file(raw, self.authored.stock.filename)
        self.backup_dir = raw / "backup"
        self.readback_dir = raw / "restored_readback"
        self.backup_dir.mkdir()
        self.readback_dir.mkdir()
        for part in self.authored.partitions:
            data = (self.authored.root / verifier.BACKUP_DIR / part.backup_name).read_bytes()
            (self.backup_dir / part.backup_name).write_bytes(data)
            data = (self.authored.root / verifier.READBACK_DIR / part.backup_name).read_bytes()
            (self.readback_dir / part.backup_name).write_bytes(data)
        self.raw_root = raw

    def _file(self, raw: Path, name: str) -> Path:
        target = raw / name
        target.write_bytes((self.authored.root / name).read_bytes())
        return target

    def stock_verifier(self):
        return Fixture.fake_stock_verifier

    def prepare(self, output: Path) -> dict:
        return preparer.prepare(
            authority_path=self.authority,
            device_identity_path=self.device_identity,
            backup_manifest_path=self.backup_manifest,
            rehearsal_path=self.rehearsal,
            witness_path=self.witness,
            proc_mtd_path=self.proc_mtd,
            backup_dir=self.backup_dir,
            readback_dir=self.readback_dir,
            stock_bmu_path=self.stock_bmu,
            output_dir=output,
            partitions=self.authored.partitions,
            stock=self.authored.stock,
            stock_verifier=self.stock_verifier(),
        )

    def verify(self, bundle: Path) -> dict:
        return verifier.verify_evidence(
            bundle,
            partitions=self.authored.partitions,
            stock=self.authored.stock,
            stock_verifier=self.stock_verifier(),
        )


@unittest.skipUnless(os.name == "posix", "bundle publication requires Linux/WSL")
class RecoveryBundlePreparationTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory, RawCaptureFixture, Path]:
        temporary = tempfile.TemporaryDirectory()
        capture = RawCaptureFixture(Path(temporary.name))
        return temporary, capture, Path(temporary.name) / "persistent-recovery-bundle"

    def test_prepares_exact_self_verifying_bundle(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = capture.prepare(output)
        fresh = capture.verify(output)
        self.assertEqual(result, fresh)
        top = {
            verifier.AUTHORITY_FILE,
            verifier.DEVICE_FILE,
            verifier.LAYOUT_FILE,
            verifier.PROC_MTD_FILE,
            verifier.BACKUP_FILE,
            verifier.REHEARSAL_FILE,
            verifier.WITNESS_FILE,
            capture.authored.stock.filename,
            verifier.CONTRACT_FILE,
            verifier.VERIFICATION_FILE,
            verifier.BACKUP_DIR,
            verifier.READBACK_DIR,
        }
        self.assertEqual({entry.name for entry in output.iterdir()}, top)
        for entry in output.iterdir():
            self.assertFalse(entry.is_symlink())
            if entry.is_file():
                self.assertEqual(entry.stat().st_nlink, 1)
        for directory in (verifier.BACKUP_DIR, verifier.READBACK_DIR):
            leaves = output / directory
            self.assertEqual(
                {child.name for child in leaves.iterdir()},
                {part.backup_name for part in capture.authored.partitions},
            )
            for child in leaves.iterdir():
                self.assertTrue(child.is_file())
                self.assertFalse(child.is_symlink())
                self.assertEqual(child.stat().st_nlink, 1)

    def test_published_receipt_is_canonical_and_matches_recompute(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = capture.prepare(output)
        receipt = (output / verifier.VERIFICATION_FILE).read_bytes()
        self.assertEqual(receipt, verifier.canonical_json(result))
        unsigned = dict(result)
        del unsigned["verification_id"]
        self.assertEqual(
            hashlib.sha256(verifier.canonical_json(unsigned)).hexdigest(),
            result["verification_id"],
        )

    def test_preparation_is_byte_deterministic_across_runs(self) -> None:
        temporary, capture, _ = self.fixture()
        self.addCleanup(temporary.cleanup)
        first = Path(temporary.name) / "bundle-a"
        second = Path(temporary.name) / "bundle-b"
        capture.prepare(first)
        capture.prepare(second)
        for name in (verifier.CONTRACT_FILE, verifier.VERIFICATION_FILE):
            self.assertEqual(
                (first / name).read_bytes(), (second / name).read_bytes()
            )
        for part in capture.authored.partitions:
            for directory in (verifier.BACKUP_DIR, verifier.READBACK_DIR):
                leaf = f"{directory}/{part.backup_name}"
                self.assertEqual(
                    hashlib.sha256((first / Path(leaf)).read_bytes()).hexdigest(),
                    hashlib.sha256((second / Path(leaf)).read_bytes()).hexdigest(),
                )
        self.assertNotEqual(first, second)

    def test_cli_publishes_both_required_success_sentinels(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        stdout = io.StringIO()
        with mock.patch.object(preparer.verifier, "PARTITIONS", capture.authored.partitions), \
                mock.patch.object(preparer.verifier, "STOCK_BMU", capture.authored.stock), \
                mock.patch.object(
                    preparer.verifier,
                    "verify_signed_stock_bmu",
                    capture.stock_verifier(),
                ):
            with contextlib.redirect_stdout(stdout):
                status = preparer.main(
                    [
                        "--authority", str(capture.authority),
                        "--device-identity", str(capture.device_identity),
                        "--backup-manifest", str(capture.backup_manifest),
                        "--rehearsal", str(capture.rehearsal),
                        "--independent-witness", str(capture.witness),
                        "--proc-mtd", str(capture.proc_mtd),
                        "--backup-dir", str(capture.backup_dir),
                        "--readback-dir", str(capture.readback_dir),
                        "--stock-bmu", str(capture.stock_bmu),
                        "--output-dir", str(output),
                    ]
                )
        self.assertEqual(status, 0)
        self.assertIn("S19K_PERSISTENT_RECOVERY_OK", stdout.getvalue())
        self.assertIn("S19K_PERSISTENT_RECOVERY_BUNDLE_OK", stdout.getvalue())
        self.assertIn("mutation_authority_granted=false", stdout.getvalue())
        capture.verify(output)

    def test_refuses_existing_output_without_clobbering_it(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("keep", encoding="ascii")
        with self.assertRaises(preparer.PreparationError):
            capture.prepare(output)
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep")
        self.assertEqual({entry.name for entry in output.iterdir()}, {"sentinel"})

    def test_refuses_hardlinked_readback_leaf(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        part = capture.authored.partitions[0]
        victim = capture.readback_dir / part.backup_name
        victim.unlink()
        os.link(capture.backup_dir / part.backup_name, victim)
        with self.assertRaises(preparer.PreparationError):
            capture.prepare(output)
        self.assertFalse(output.exists())

    def test_refuses_aliased_json_inputs(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        capture.witness.unlink()
        os.link(capture.rehearsal, capture.witness)
        with self.assertRaises(preparer.PreparationError):
            capture.prepare(output)
        self.assertFalse(output.exists())

    def test_refuses_proc_mtd_drift_against_pinned_table(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        capture.proc_mtd.write_bytes(
            verifier._proc_mtd_bytes(capture.authored.partitions).replace(
                b"bootloader", b"bootloadrr"
            )
        )
        with self.assertRaises(preparer.PreparationError) as raised:
            capture.prepare(output)
        self.assertIn("/proc/mtd", str(raised.exception))
        self.assertFalse(output.exists())

    def test_refuses_readback_byte_drift(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        part = capture.authored.partitions[0]
        leaf = capture.readback_dir / part.backup_name
        data = bytearray(leaf.read_bytes())
        data[0] ^= 0xFF
        leaf.write_bytes(bytes(data))
        with self.assertRaises(
            (preparer.PreparationError, verifier.PersistentRecoveryError)
        ):
            capture.prepare(output)
        self.assertFalse(output.exists())

    def test_refuses_extra_raw_leaf(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        (capture.backup_dir / "mtd99_stray.padbad.bin").write_bytes(b"stray")
        with self.assertRaises(preparer.PreparationError) as raised:
            capture.prepare(output)
        self.assertIn("entry set is inexact", str(raised.exception))
        self.assertFalse(output.exists())

    def test_refuses_truncated_backup_leaf(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        part = capture.authored.partitions[0]
        leaf = capture.backup_dir / part.backup_name
        leaf.write_bytes(leaf.read_bytes()[:-1])
        with self.assertRaises(preparer.PreparationError) as raised:
            capture.prepare(output)
        self.assertIn("requires exactly", str(raised.exception))
        self.assertFalse(output.exists())

    def test_refuses_noncanonical_device_identity(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        value = json.loads(capture.device_identity.read_text(encoding="ascii"))
        capture.device_identity.write_bytes(
            json.dumps(value, indent=2, sort_keys=True).encode("ascii")
        )
        with self.assertRaises(preparer.PreparationError) as raised:
            capture.prepare(output)
        self.assertIn("canonical", str(raised.exception).lower())
        self.assertFalse(output.exists())

    def test_windows_host_refused(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        with mock.patch.object(preparer.os, "name", "nt"):
            with self.assertRaises(preparer.PreparationError) as raised:
                capture.prepare(output)
        self.assertIn("Linux/WSL", str(raised.exception))
        self.assertFalse(output.exists())

    def test_preparer_grants_no_authority_in_result(self) -> None:
        temporary, capture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = capture.prepare(output)
        self.assertIs(result["mutation_authority_granted"], False)
        self.assertIs(result["dcentos_write_authorized"], False)
        self.assertIs(result["dcentos_write_observed"], False)


if __name__ == "__main__":
    unittest.main()
