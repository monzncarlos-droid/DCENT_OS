#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Behavior and image-wiring tests for the S19k persistent /data owner."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT = Path(__file__).resolve().parents[1]
BOARD = (
    PROJECT
    / "br2_external_dcentos"
    / "board"
    / "amlogic"
    / "am3-s19kpro"
)
HELPER = BOARD / "rootfs-overlay/usr/sbin/dcent-s19k-data-mount"


def _write_line(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="ascii", newline="\n")


def _shell_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt" and len(value) >= 3 and value[1:3] == ":/":
        return f"/mnt/{value[0].lower()}{value[2:]}"
    return value


def _run_in_wsl(
    argv: list[str], variables: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    assignments = [f"{name}={value}" for name, value in variables.items()]
    command = "exec env " + " ".join(
        shlex.quote(argument) for argument in (*assignments, *argv)
    )
    return subprocess.run(
        ["bash", "-lc", command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class MountFixture:
    def __init__(self, root: Path, *, mounted: bool = True) -> None:
        self.root = root
        self.proc_mtd = root / "proc-mtd"
        self.mtd_sysfs = root / "sys/class/mtd"
        self.ubi_sysfs = root / "sys/class/ubi"
        self.dev_root = root / "dev"
        self.mountinfo = root / "mountinfo"
        self.data_dir = root / "data"
        self.release_marker = root / "etc/dcentos/release-image"
        self.board_target = root / "etc/dcentos/board_target"
        self.platform = root / "etc/dcentos/platform"
        self.data_dir.mkdir(parents=True)
        self.dev_root.mkdir(parents=True)
        self.ubi_sysfs.mkdir(parents=True)
        self.proc_mtd.write_text(
            'dev:    size   erasesize  name\n'
            'mtd0: 00200000 00020000 "bootloader"\n'
            'mtd1: 00800000 00020000 "tpl"\n'
            'mtd2: 03200000 00020000 "stock_system"\n'
            'mtd3: 00500000 00020000 "stock_config"\n'
            'mtd4: 02000000 00020000 "overlay"\n'
            'mtd5: 09900000 00020000 "system"\n',
            encoding="ascii",
            newline="\n",
        )
        _write_line(self.mtd_sysfs / "mtd4/name", "overlay")
        _write_line(self.mtd_sysfs / "mtd4/size", "33554432")
        _write_line(self.mtd_sysfs / "mtd4/erasesize", "131072")
        _write_line(self.ubi_sysfs / "ubi2/mtd_num", "4")
        _write_line(self.ubi_sysfs / "ubi2_0/name", "overlay")
        _write_line(self.ubi_sysfs / "ubi2_0/type", "dynamic")
        _write_line(self.ubi_sysfs / "ubi2_0/dev", "248:1")
        (self.dev_root / "ubi2_0").write_bytes(b"")
        self.release_marker.parent.mkdir(parents=True, exist_ok=True)
        self.release_marker.write_text(
            "# DCENT_OS PRODUCTION/RELEASE image marker.\n"
            "# Presence => dashboard/API require a password; the freedom-first\n"
            "# passwordless opt-out is DISABLED and root SSH password login is\n"
            "# locked. Built with DCENT_RELEASE_IMAGE=1. Do not hand-create.\n"
            "release_image=1\n",
            encoding="ascii",
            newline="\n",
        )
        _write_line(self.board_target, "am3-s19k")
        _write_line(self.platform, "am3-aml-s19k")
        self.mountinfo.write_text(
            self.expected_mount_record() if mounted else "",
            encoding="ascii",
            newline="\n",
        )

    @property
    def node(self) -> Path:
        return self.dev_root / "ubi2_0"

    def expected_mount_record(self) -> str:
        return (
            f"36 25 0:32 / {_shell_path(self.data_dir)} "
            "rw,nosuid,nodev,noexec,relatime - ubifs "
            f"{_shell_path(self.node)} rw,assert=read-only\n"
        )

    def environment(self) -> dict[str, str]:
        return {
            "DCENT_S19K_DATA_TEST_MODE": "1",
            "DCENT_S19K_PROC_MTD": _shell_path(self.proc_mtd),
            "DCENT_S19K_MTD_SYSFS": _shell_path(self.mtd_sysfs),
            "DCENT_S19K_UBI_SYSFS": _shell_path(self.ubi_sysfs),
            "DCENT_S19K_DEV_ROOT": _shell_path(self.dev_root),
            "DCENT_S19K_MOUNTINFO": _shell_path(self.mountinfo),
            "DCENT_S19K_DATA_DIR": _shell_path(self.data_dir),
            "DCENT_S19K_RELEASE_MARKER": _shell_path(self.release_marker),
            "DCENT_S19K_BOARD_TARGET_FILE": _shell_path(self.board_target),
            "DCENT_S19K_PLATFORM_FILE": _shell_path(self.platform),
        }

    def run(self, action: str = "verify") -> subprocess.CompletedProcess[str]:
        return _run_in_wsl(
            ["bash", _shell_path(HELPER), action], self.environment()
        )


def test_exact_existing_overlay_mount_is_admitted(tmp_path: Path) -> None:
    fixture = MountFixture(tmp_path)
    result = fixture.run()
    assert result.returncode == 0, result.stderr
    assert "VERIFIED mtd4 -> ubi2_0 -> /data" in result.stdout


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("mtd-size", "geometry"),
        ("duplicate-mtd", "count"),
        ("foreign-map", "six-MTD"),
        ("marker-extra", "line count"),
        ("wrong-volume-name", "name"),
        ("static-volume", "type"),
        ("extra-volume", "exactly one"),
        ("ambiguous-attachment", "one exact"),
        ("wrong-filesystem", "UBIFS"),
        ("wrong-source", "admitted UBI"),
        ("read-only", "lacks rw"),
        ("exec-enabled", "lacks noexec"),
    ],
)
def test_identity_and_mount_ambiguity_fail_closed(
    tmp_path: Path,
    mutation: str,
    reason: str,
) -> None:
    fixture = MountFixture(tmp_path)
    if mutation == "mtd-size":
        fixture.proc_mtd.write_text(
            fixture.proc_mtd.read_text().replace("02000000", "02100000"),
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "duplicate-mtd":
        with fixture.proc_mtd.open("a", encoding="ascii", newline="\n") as handle:
            handle.write('mtd4: 02000000 00020000 "overlay"\n')
    elif mutation == "foreign-map":
        fixture.proc_mtd.write_text(
            fixture.proc_mtd.read_text().replace(
                'mtd3: 00500000 00020000 "stock_config"',
                'mtd3: 00600000 00020000 "stock_config"',
            ),
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "marker-extra":
        fixture.release_marker.write_text(
            fixture.release_marker.read_text() + "release_ready=true\n",
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "wrong-volume-name":
        _write_line(fixture.ubi_sysfs / "ubi2_0/name", "nvdata")
    elif mutation == "static-volume":
        _write_line(fixture.ubi_sysfs / "ubi2_0/type", "static")
    elif mutation == "extra-volume":
        _write_line(fixture.ubi_sysfs / "ubi2_1/name", "extra")
    elif mutation == "ambiguous-attachment":
        _write_line(fixture.ubi_sysfs / "ubi3/mtd_num", "4")
    elif mutation == "wrong-filesystem":
        fixture.mountinfo.write_text(
            fixture.expected_mount_record().replace(" - ubifs ", " - tmpfs "),
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "wrong-source":
        fixture.mountinfo.write_text(
            fixture.expected_mount_record().replace("ubi2_0 rw", "ubi9_0 rw"),
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "read-only":
        fixture.mountinfo.write_text(
            fixture.expected_mount_record().replace(
                "rw,nosuid,nodev,noexec", "ro,nosuid,nodev,noexec"
            ),
            encoding="ascii",
            newline="\n",
        )
    elif mutation == "exec-enabled":
        fixture.mountinfo.write_text(
            fixture.expected_mount_record().replace(
                "rw,nosuid,nodev,noexec", "rw,nosuid,nodev"
            ),
            encoding="ascii",
            newline="\n",
        )
    else:  # pragma: no cover - parameter table is exhaustive
        raise AssertionError(mutation)

    result = fixture.run()
    assert result.returncode != 0
    assert reason in result.stderr


def test_start_mounts_only_the_preexisting_admitted_volume(tmp_path: Path) -> None:
    fixture = MountFixture(tmp_path, mounted=False)
    fake_mount = tmp_path / "fake-mount"
    fake_mount.write_text(
        "#!/bin/sh\n"
        "[ \"$1\" = -t ] && [ \"$2\" = ubifs ] || exit 91\n"
        "[ \"$3\" = -o ] && [ \"$4\" = rw,nosuid,nodev,noexec ] || exit 92\n"
        "[ \"$5\" = \"$DCENT_S19K_EXPECT_NODE\" ] || exit 93\n"
        "[ \"$6\" = \"$DCENT_S19K_DATA_DIR\" ] || exit 94\n"
        "printf '%s\\n' \"$DCENT_S19K_EXPECT_RECORD\" > \"$DCENT_S19K_MOUNTINFO\"\n",
        encoding="ascii",
        newline="\n",
    )
    fake_mount.chmod(0o755)
    env = fixture.environment()
    env["DCENT_S19K_MOUNT_BIN"] = _shell_path(fake_mount)
    env["DCENT_S19K_EXPECT_NODE"] = _shell_path(fixture.node)
    env["DCENT_S19K_EXPECT_RECORD"] = fixture.expected_mount_record().rstrip("\n")
    result = _run_in_wsl(
        ["bash", _shell_path(HELPER), "start"], env
    )
    assert result.returncode == 0, result.stderr
    assert fixture.mountinfo.read_text(encoding="ascii") == fixture.expected_mount_record()


def test_start_attaches_only_exact_mtd4_then_mounts_existing_volume(tmp_path: Path) -> None:
    fixture = MountFixture(tmp_path, mounted=False)
    shutil.rmtree(fixture.ubi_sysfs)
    fixture.ubi_sysfs.mkdir(parents=True)
    (fixture.dev_root / "ubi2_0").unlink()
    fake_attach = tmp_path / "fake-ubiattach"
    fake_attach.write_text(
        "#!/bin/sh\n"
        "[ \"$1\" = -m ] && [ \"$2\" = 4 ] || exit 81\n"
        "mkdir -p \"$DCENT_S19K_UBI_SYSFS/ubi7\" "
        "\"$DCENT_S19K_UBI_SYSFS/ubi7_0\"\n"
        "printf '4\\n' > \"$DCENT_S19K_UBI_SYSFS/ubi7/mtd_num\"\n"
        "printf 'overlay\\n' > \"$DCENT_S19K_UBI_SYSFS/ubi7_0/name\"\n"
        "printf 'dynamic\\n' > \"$DCENT_S19K_UBI_SYSFS/ubi7_0/type\"\n"
        "printf '248:1\\n' > \"$DCENT_S19K_UBI_SYSFS/ubi7_0/dev\"\n"
        ": > \"$DCENT_S19K_DEV_ROOT/ubi7_0\"\n",
        encoding="ascii",
        newline="\n",
    )
    fake_attach.chmod(0o755)
    fake_mount = tmp_path / "fake-mount"
    fake_mount.write_text(
        "#!/bin/sh\n"
        "[ \"$1\" = -t ] && [ \"$2\" = ubifs ] || exit 91\n"
        "[ \"$3\" = -o ] && [ \"$4\" = rw,nosuid,nodev,noexec ] || exit 92\n"
        "[ \"$5\" = \"$DCENT_S19K_EXPECT_NODE\" ] || exit 93\n"
        "printf '%s\\n' \"$DCENT_S19K_EXPECT_RECORD\" > \"$DCENT_S19K_MOUNTINFO\"\n",
        encoding="ascii",
        newline="\n",
    )
    fake_mount.chmod(0o755)
    expected_node = fixture.dev_root / "ubi7_0"
    expected_record = fixture.expected_mount_record().replace(
        _shell_path(fixture.node), _shell_path(expected_node)
    )
    env = fixture.environment()
    env["DCENT_S19K_UBIATTACH_BIN"] = _shell_path(fake_attach)
    env["DCENT_S19K_MOUNT_BIN"] = _shell_path(fake_mount)
    env["DCENT_S19K_EXPECT_NODE"] = _shell_path(expected_node)
    env["DCENT_S19K_EXPECT_RECORD"] = expected_record.rstrip("\n")
    result = _run_in_wsl(
        ["bash", _shell_path(HELPER), "start"], env
    )
    assert result.returncode == 0, result.stderr
    assert "ubi7_0" in result.stdout
    assert fixture.mountinfo.read_text(encoding="ascii") == expected_record


def test_unknown_media_is_refused_before_ubiattach(tmp_path: Path) -> None:
    fixture = MountFixture(tmp_path, mounted=False)
    fixture.proc_mtd.write_text(
        fixture.proc_mtd.read_text().replace(
            'mtd3: 00500000 00020000 "stock_config"',
            'mtd3: 00600000 00020000 "stock_config"',
        ),
        encoding="ascii",
        newline="\n",
    )
    shutil.rmtree(fixture.ubi_sysfs)
    fixture.ubi_sysfs.mkdir(parents=True)
    attach_called = tmp_path / "attach-called"
    fake_attach = tmp_path / "fake-ubiattach"
    fake_attach.write_text(
        "#!/bin/sh\n"
        f": > {shlex.quote(_shell_path(attach_called))}\n",
        encoding="ascii",
        newline="\n",
    )
    fake_attach.chmod(0o755)
    env = fixture.environment()
    env["DCENT_S19K_UBIATTACH_BIN"] = _shell_path(fake_attach)
    result = _run_in_wsl(
        ["bash", _shell_path(HELPER), "start"], env
    )
    assert result.returncode != 0
    assert "six-MTD" in result.stderr
    assert not attach_called.exists()


def test_mount_owner_contains_no_media_creation_or_write_primitive() -> None:
    source = HELPER.read_text(encoding="utf-8")
    executable = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    for forbidden in (
        "ubiformat",
        "ubimkvol",
        "ubirmvol",
        "ubidetach",
        "flash_erase",
        "nandwrite",
        "nanddump",
        "mkfs",
        " dd ",
    ):
        assert forbidden not in executable
    assert '"$UBIATTACH_BIN" -m "$EXPECTED_MTD_INDEX"' in executable
    assert (
        '"$MOUNT_BIN" -t ubifs -o rw,nosuid,nodev,noexec '
        '"$_dcent_node" "$DATA_DIR"'
    ) in executable


def test_image_orders_and_packages_the_exact_mount_owner() -> None:
    init = BOARD / "rootfs-overlay/etc/init.d"
    assert (init / "S38s19k-data").is_file()
    assert "S38s19k-data" < "S49s19k-postinstall-witness" < "S50dropbear"
    post_build = (BOARD / "post-build.sh").read_text(encoding="utf-8")
    post_image = (BOARD / "post-image.sh").read_text(encoding="utf-8")
    defconfig = (
        PROJECT / "br2_external_dcentos/configs/dcentos_am3_s19kpro_defconfig"
    ).read_text(encoding="utf-8")
    assert "S19K_DATA_HELPER" in post_build
    assert "S19K_DATA_INIT" in post_build
    assert 'require_rootfs_path "etc/init.d/S38s19k-data"' in post_image
    assert 'require_rootfs_path "usr/sbin/dcent-s19k-data-mount"' in post_image
    assert 'require_rootfs_path "usr/sbin/ubiattach"' in post_image
    assert "BR2_PACKAGE_MTD_UBIATTACH=y" in defconfig
