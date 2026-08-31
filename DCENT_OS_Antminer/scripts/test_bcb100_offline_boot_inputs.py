#!/usr/bin/env python3
"""Focused tests for the host-only BCB100 boot-input analyzer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
ANALYZER = SCRIPT_DIR / "analyze_bcb100_offline_boot_inputs.py"
SPEC = importlib.util.spec_from_file_location("bcb100_offline_boot_inputs", ANALYZER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _fixture(root: Path) -> None:
    bcb = root / ""
    ipc = bcb / (
        "FAB-BRR_CB_P03_REV_A1_1-STM32MP157-A.3/IPC-2581 Files/"
        "BRR_CB_P03_REV_A1_1-STM32MP157.cvg"
    )
    bos = root / ""
    (bos / "scripts").mkdir(parents=True)
    (bos / "defaults").mkdir()
    (bos / ".git/refs/heads").mkdir(parents=True)
    ipc.parent.mkdir(parents=True)

    (bcb / "README.md").write_text(
        "STM32MP157CAB3\n128 MB RAM and 4GB of eMMC memory\n"
        "By default eMMC is chosen as the default boot option\n"
        "the MPU will boot OS from the SD card\n",
        encoding="utf-8",
    )
    ipc.write_text(
        " ".join(
            f'net="{name}"'
            for name in (
                "UART4_RX",
                "UART4_TX",
                "BOOT0",
                "BOOT1",
                "BOOT2",
                "CARD_DETECT",
                "SDMMC1_CK",
                "SDMMC2_CK",
            )
        ),
        encoding="utf-8",
    )
    names = [name for _, name, _ in MODULE.EXPECTED_OUTPUTS]
    (bos / "README.md").write_text(
        "\n".join(names)
        + "\nmmc gp create -c 49152 1 1 0 /dev/mmcblk0\n"
        "mmc write_reliability set -y 0 /dev/mmcblk0\n"
        "dd if=/dev/zero of=/dev/mmcblk0 bs=4M count=4\n"
        "dd if=$FSBL of=/dev/mmcblk0boot0 bs=4096 conv=fsync\n"
        "dd if=$FSBL of=/dev/mmcblk0boot1 bs=4096 conv=fsync\n"
        "dd if=$FIP of=/dev/mmcblk0 bs=4096 conv=fsync\n"
        "dd if=rootfs of=/dev/mmcblk0gp0 bs=4M conv=fsync\n",
        encoding="utf-8",
    )
    dependency_names = "\n".join(f'    "{name}"' for name in MODULE.DEPENDENCIES)
    (bos / "scripts/00_bootstrap.sh").write_text(
        'REPO_URL="${REPO_URL:-git@github.com:braiins}"\n'
        f"repos=(\n{dependency_names}\n)\n"
        '[[ -n "$TAG_NAME" ]] && git_args+=("--branch=$TAG_NAME")\n'
        'git clone "${git_args[@]}" "$REPO_URL/$repo.git"\n',
        encoding="utf-8",
    )
    (bos / "scripts/01_configure.sh").write_text(
        'cp "./defaults/stm32mp15_ii1.conf" output\n'
        'echo "src-link bos $BUILD_DIR/bos-packages"\n'
        "openwrt_nix ./scripts/feeds update -a\n"
        "openwrt_nix make defconfig\n",
        encoding="utf-8",
    )
    (bos / "scripts/02_make.sh").write_text(
        'openwrt_nix make -j"$MAKE_JOBS" "$@"\n', encoding="utf-8"
    )
    (bos / "defaults/stm32mp15_ii1.conf").write_text(
        "CONFIG_TARGET_stm32mp15_ii1=y\n"
        "CONFIG_TARGET_DEVICE_stm32mp15_ii1_DEVICE_emmc=y\n"
        "CONFIG_TARGET_DEVICE_stm32mp15_ii1_DEVICE_sd=y\n"
        "CONFIG_PACKAGE_boot-stm32mp15_ii1=y\n"
        'CONFIG_EXTERNAL_ARM_TRUSTED_FIRMWARE_STM32MP15_TREE="../arm-trusted-firmware-stm"\n'
        'CONFIG_EXTERNAL_KERNEL_TREE="../linux-stm"\n'
        'CONFIG_EXTERNAL_UBOOT_STM32MP15_TREE="../u-boot-stm"\n',
        encoding="utf-8",
    )
    (bos / "flake.nix").write_text(
        'nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";\n',
        encoding="utf-8",
    )
    (bos / "flake.lock").write_text(
        json.dumps(
            {
                "nodes": {
                    "nixpkgs": {"locked": {"rev": "1" * 40}},
                    "flake-utils": {"locked": {"rev": "2" * 40}},
                }
            }
        ),
        encoding="utf-8",
    )
    (bos / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (bos / ".git/refs/heads/main").write_text("3" * 40 + "\n", encoding="ascii")
    (bos / ".git/shallow").write_text("3" * 40 + "\n", encoding="ascii")


class Bcb100OfflineBootInputTests(unittest.TestCase):
    def test_absent_dependencies_and_layout_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)

            result = MODULE.analyze(root)

            self.assertEqual(result["schema"], MODULE.SCHEMA)
            self.assertEqual(result["board_target"], "bcb100-s19jpro")
            self.assertEqual(result["state"], "dependency-and-layout-evidence-incomplete")
            self.assertEqual(len(result["source_evidence"]), 9)
            self.assertEqual(len(result["dependency_ledger"]), 6)
            self.assertTrue(
                all(item["local_state"] == "missing" for item in result["dependency_ledger"])
            )
            self.assertTrue(
                all(
                    item["state"] == "missing-from-canonical-build-output"
                    for item in result["expected_outputs"]
                )
            )
            self.assertEqual(
                result["layout_contract"]["sd"]["internal_partition_table"],
                "missing-with-openwrt-ii1-image-recipe",
            )
            self.assertEqual(
                result["layout_contract"]["emmc"]["status"],
                "manual-destructive-topology-only",
            )
            self.assertFalse(result["boot_artifact_generation_authorized"])
            self.assertFalse(result["operator_boot_authorized"])
            self.assertFalse(result["external_media_write_authorized"])
            self.assertFalse(result["persistent_storage_write_authorized"])
            self.assertFalse(result["installation_authorized"])
            self.assertFalse(result["raw_device_reachable"])
            self.assertEqual(result["device_contact"], "none")
            self.assertEqual(result["network_contact"], "none")

    def test_evidence_digest_is_deterministic_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            first = MODULE.analyze(root)
            second = MODULE.analyze(root)
            self.assertEqual(first, second)

            source = root / ""
            source.write_text(source.read_text(encoding="utf-8") + "bounded change\n")
            changed = MODULE.analyze(root)
            self.assertNotEqual(first["evidence_set_sha256"], changed["evidence_set_sha256"])
            record = next(
                item
                for item in changed["source_evidence"]
                if item["role"] == "bcb100-hardware-readme"
            )
            self.assertEqual(record["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_present_repository_remains_unpinned_and_unadmitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            dependency = root / ""
            (dependency / ".git/refs/heads").mkdir(parents=True)
            (dependency / ".git/HEAD").write_text(
                "ref: refs/heads/main\n", encoding="ascii"
            )
            (dependency / ".git/refs/heads/main").write_text(
                "a" * 40 + "\n", encoding="ascii"
            )

            result = MODULE.analyze(root)
            entry = next(
                item for item in result["dependency_ledger"] if item["name"] == "u-boot-stm"
            )
            self.assertEqual(entry["local_state"], "held-but-unpinned-by-bootstrap")
            self.assertEqual(entry["observed_local_head"], "a" * 40)
            self.assertFalse(entry["admitted_for_reproducible_build"])
            self.assertFalse(result["boot_artifact_generation_authorized"])

    def test_canonical_output_is_hashed_but_never_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            output_dir = root / MODULE.OUTPUT_DIRECTORY
            output_dir.mkdir(parents=True)
            name = MODULE.EXPECTED_OUTPUTS[0][1]
            candidate = output_dir / name
            candidate.write_bytes(b"untrusted boot-looking bytes")

            result = MODULE.analyze(root)
            entry = next(item for item in result["expected_outputs"] if item["filename"] == name)
            self.assertEqual(entry["state"], "held-untrusted-output-hashed")
            self.assertEqual(entry["sha256"], hashlib.sha256(candidate.read_bytes()).hexdigest())
            self.assertFalse(result["boot_artifact_generation_authorized"])
            self.assertFalse(result["operator_boot_authorized"])

    def test_source_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            source = root / ""
            backing = root / "backing"
            source.replace(backing)
            try:
                source.symlink_to(backing)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(
                MODULE.EvidenceError, "must not traverse a link"
            ):
                MODULE.analyze(root)

    def test_source_multilink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            source = root / ""
            other = root / "other"
            try:
                os.link(source, other)
            except (OSError, NotImplementedError):
                self.skipTest("hardlink creation is unavailable")
            with self.assertRaisesRegex(MODULE.EvidenceError, "exactly one hard link"):
                MODULE.analyze(root)

    def test_no_contact_or_helper_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            with (
                mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
                mock.patch.object(subprocess, "run", side_effect=AssertionError("helper")),
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("helper")),
            ):
                result = MODULE.analyze(root)
            self.assertEqual(result["network_contact"], "none")
            self.assertEqual(result["helper_execution"], "none")
            self.assertFalse(result["raw_device_reachable"])

    def test_report_is_exclusive_and_preserves_existing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _fixture(root)
            result = MODULE.analyze(root)
            output = root / "bcb100-evidence.json"
            created = MODULE.write_report(result, output)
            saved = json.loads(created.read_text(encoding="utf-8"))
            self.assertEqual(saved["evidence_set_sha256"], result["evidence_set_sha256"])
            self.assertFalse(saved["boot_artifact_generation_authorized"])
            with self.assertRaisesRegex(MODULE.EvidenceError, "must be new"):
                MODULE.write_report(result, output)
            self.assertEqual(json.loads(output.read_text()), saved)

    def test_device_and_remote_namespaces_are_refused_before_contact(self) -> None:
        for path in (
            Path(r"\\server\share\report.json"),
            Path(r"\\.\PhysicalDrive7"),
            Path(r"\\?\GLOBALROOT\Device\Harddisk0"),
            Path(r"\??\PhysicalDrive7"),
            Path(r"\Device\Harddisk0"),
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                MODULE.EvidenceError, "remote or device namespace"
            ):
                MODULE._reject_device_or_remote_path(path, label="test")


if __name__ == "__main__":
    unittest.main()
