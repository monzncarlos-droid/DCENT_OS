#!/usr/bin/env python3
"""Adversarial tests for the S19k production-host preflight."""

from __future__ import annotations

from collections import namedtuple
import importlib.util
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import sys


SCRIPT = Path(__file__).with_name("s19k_hermetic_host_preflight.py")
SPEC = importlib.util.spec_from_file_location("s19k_hermetic_host_preflight", SCRIPT)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


def fixture_path(*parts: str) -> Path:
    base = Path("C:/dcent") if sys.platform == "win32" else Path("/srv/dcent")
    return base.joinpath(*parts)


class HostPreflightTests(unittest.TestCase):
    def test_capacity_model_is_conservative_and_authority_false(self) -> None:
        self.assertEqual(preflight.REQUIRED_FREE_BYTES, 392 * preflight.GIB)
        self.assertEqual(preflight.REQUIRED_FREE_INODES, 8_000_000)
        root = {
            "label": "build-parent",
            "path": "/srv/dcent/build",
            "device": 7,
            "filesystem": "ext4",
            "mountpoint": "/srv/dcent",
            "mount_options": ["rw"],
            "mode": "0700",
            "uid": 1000,
            "gid": 1000,
            "free_bytes": preflight.REQUIRED_FREE_BYTES,
            "free_inodes": preflight.REQUIRED_FREE_INODES,
        }
        with mock.patch.object(preflight, "verify_private_root", return_value=root):
            report = preflight.build_report(
                [("build-parent", fixture_path("build"))],
                {"client_version": "29", "server_version": "29", "server_os": "linux"},
            )
        self.assertFalse(report["production_ready"])
        self.assertFalse(report["release_authority_granted"])
        self.assertFalse(report["install_authority_granted"])
        self.assertFalse(report["flash_authority_granted"])
        self.assertIn("daemon-id", report["docker_trust_nonclaim"])
        self.assertIn("security-posture-not-bound", report["docker_trust_nonclaim"])

    def test_root_arguments_are_exact_unique_absolute_paths(self) -> None:
        if sys.platform == "win32":
            valid = str(Path("C:/dcent/source").absolute())
        else:
            valid = "/srv/dcent/source"
        parsed = preflight.parse_roots([f"source-parent={valid}"])
        self.assertEqual(parsed[0][0], "source-parent")
        for values, expected in (
            ([], "at least one"),
            (["missing-separator"], "LABEL=ABSOLUTE_PATH"),
            ([f"Bad={valid}"], "unique canonical"),
            ([f"same={valid}", f"same={valid}"], "unique canonical"),
            ([f"one={valid}", f"two={valid}"], "repeat a path"),
        ):
            with self.subTest(values=values):
                with self.assertRaisesRegex(preflight.PreflightError, expected):
                    preflight.parse_roots(values)

    def test_private_root_refuses_low_capacity_and_wrong_custody(self) -> None:
        Statvfs = namedtuple("Statvfs", "f_bavail f_frsize f_favail")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=1000,
                st_gid=1000,
                st_dev=7,
            )
            with mock.patch.object(preflight.os, "lstat", return_value=metadata), mock.patch.object(
                preflight.os, "getuid", return_value=1000, create=True
            ), mock.patch.object(
                preflight.os, "getgid", return_value=1000, create=True
            ), mock.patch.object(
                preflight,
                "linux_mount_contract",
                return_value=("ext4", frozenset({"rw"}), "/"),
            ), mock.patch.object(
                preflight.os, "statvfs", create=True
            ) as statvfs_mock:
                statvfs_mock.return_value = Statvfs(
                    preflight.REQUIRED_FREE_BYTES // 4096,
                    4096,
                    preflight.REQUIRED_FREE_INODES,
                )
                accepted = preflight.verify_private_root(root, "build-parent")
                self.assertEqual(accepted["filesystem"], "ext4")
                statvfs_mock.return_value = Statvfs(
                    preflight.REQUIRED_FREE_BYTES // 4096 - 1,
                    4096,
                    preflight.REQUIRED_FREE_INODES,
                )
                with self.assertRaisesRegex(preflight.PreflightError, "free bytes"):
                    preflight.verify_private_root(root, "build-parent")
                statvfs_mock.return_value = Statvfs(
                    preflight.REQUIRED_FREE_BYTES // 4096,
                    4096,
                    preflight.REQUIRED_FREE_INODES - 1,
                )
                with self.assertRaisesRegex(preflight.PreflightError, "free inodes"):
                    preflight.verify_private_root(root, "build-parent")

            wrong_owner = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=999,
                st_gid=1000,
                st_dev=7,
            )
            with mock.patch.object(
                preflight.os, "lstat", return_value=wrong_owner
            ), mock.patch.object(
                preflight.os, "getuid", return_value=1000, create=True
            ), mock.patch.object(
                preflight.os, "getgid", return_value=1000, create=True
            ):
                with self.assertRaisesRegex(preflight.PreflightError, "not owned"):
                    preflight.verify_private_root(root, "build-parent")

    def test_same_device_capacity_disagreement_refuses(self) -> None:
        first = {"device": 1, "free_bytes": 10, "free_inodes": 20}
        second = {"device": 1, "free_bytes": 9, "free_inodes": 20}
        with mock.patch.object(preflight, "verify_private_root", side_effect=(first, second)):
            with self.assertRaisesRegex(preflight.PreflightError, "capacity observations"):
                preflight.build_report(
                    [("one", fixture_path("one")), ("two", fixture_path("two"))],
                    {"server_os": "linux"},
                )

    def test_build_report_refuses_duplicate_and_ancestor_roots(self) -> None:
        parent = fixture_path("custody")
        child = parent / "build"
        for roots in (
            [("one", parent), ("two", parent)],
            [("one", parent), ("two", child)],
            [("one", child), ("two", parent)],
        ):
            with self.subTest(roots=roots), mock.patch.object(
                preflight, "verify_private_root"
            ) as verify:
                with self.assertRaisesRegex(preflight.PreflightError, "overlap"):
                    preflight.build_report(roots, {"server_os": "linux"})
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
