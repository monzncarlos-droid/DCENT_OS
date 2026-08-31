#!/usr/bin/env python3
"""Tests for private S19k mutable-source permission normalization."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("s19k_hermetic_normalize_source_copy.py")
SPEC = importlib.util.spec_from_file_location("s19k_normalize_source_copy_test", SCRIPT)
assert SPEC and SPEC.loader
normalizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = normalizer
SPEC.loader.exec_module(normalizer)


@unittest.skipIf(os.name == "nt", "exact POSIX ownership/mode test requires Linux")
@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "must exercise nonroot UID")
class MutableSourceNormalizationTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        sealed = root / "sealed"
        mutable = root / "mutable"
        (sealed / "nested").mkdir(parents=True)
        (sealed / "excluded/generated").mkdir(parents=True)
        (sealed / "plain.txt").write_bytes(b"plain\n")
        (sealed / "nested/tool.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        (sealed / "excluded/generated/output").write_bytes(b"exclude\n")
        os.symlink("../plain.txt", sealed / "nested/plain-link")
        shutil.copytree(sealed, mutable, symlinks=True)
        shutil.rmtree(mutable / "excluded")
        for current, directories, files in os.walk(sealed, topdown=False):
            for name in files:
                path = Path(current) / name
                if not path.is_symlink():
                    path.chmod(0o555 if path.name == "tool.sh" else 0o444)
            for name in directories:
                path = Path(current) / name
                if not path.is_symlink():
                    path.chmod(0o500)
        sealed.chmod(0o500)
        for current, directories, files in os.walk(mutable, topdown=False):
            for name in files:
                path = Path(current) / name
                if not path.is_symlink():
                    path.chmod(0o555 if path.name == "tool.sh" else 0o444)
            for name in directories:
                path = Path(current) / name
                if not path.is_symlink():
                    path.chmod(0o500)
        mutable.chmod(0o500)
        return sealed, mutable

    def test_real_sealed_0500_0444_0555_tree_becomes_private_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sealed, mutable = self.fixture(Path(temporary))
            result = normalizer.normalize_source_copy(
                sealed, mutable, excluded=("excluded",)
            )
            self.assertEqual(result, {"directories": 1, "regular_files": 2, "symlinks": 1})
            self.assertEqual(stat.S_IMODE(mutable.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((mutable / "nested").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((mutable / "plain.txt").stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE((mutable / "nested/tool.sh").stat().st_mode), 0o700
            )
            self.assertEqual(os.readlink(mutable / "nested/plain-link"), "../plain.txt")
            self.assertEqual(stat.S_IMODE(sealed.stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE((sealed / "plain.txt").stat().st_mode), 0o444)

    def test_byte_drift_refuses_before_mode_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sealed, mutable = self.fixture(Path(temporary))
            (mutable / "plain.txt").chmod(0o600)
            (mutable / "plain.txt").write_bytes(b"drift\n")
            (mutable / "plain.txt").chmod(0o444)
            with self.assertRaisesRegex(normalizer.NormalizeError, "bytes differ"):
                normalizer.normalize_source_copy(
                    sealed, mutable, excluded=("excluded",)
                )


if __name__ == "__main__":
    unittest.main()
