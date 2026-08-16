#!/usr/bin/env python3
"""Focused host-only tests for the AM2 Xilinx legacy-ramdisk producer."""

from __future__ import annotations

import binascii
from dataclasses import replace
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
DCENTOS_ROOT = SCRIPT_DIR.parent
ZYNQ_INIT_DIR = (
    DCENTOS_ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d"
)
BUILDROOT_BUSYBOX_DIR = DCENTOS_ROOT / "buildroot/package/busybox"
BUILDER = SCRIPT_DIR / "build_am2_xilinx_legacy_ramdisk.py"
SPEC = importlib.util.spec_from_file_location("am2_xilinx_legacy_ramdisk", BUILDER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _newc_entry(name: str, payload: bytes, inode: int, mode: int = 0o100755) -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    values = (inode, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name_bytes), 0)
    result = b"070701" + b"".join(f"{value:08X}".encode("ascii") for value in values)
    result += name_bytes
    result += b"\0" * (-len(result) % 4)
    result += payload
    result += b"\0" * (-len(result) % 4)
    return result


def _target_config(board_target: str, variant: str) -> bytes:
    return (
        "BOARD_FAMILY=am2\n"
        f"BOARD_TARGET={board_target}\n"
        "PLATFORM=zynq-bm3-am2\n"
        "SOC=zynq-7000\n"
        "ARCH=armv7\n"
        f"VARIANT={variant}\n"
    ).encode("ascii")


def _arm_elf(tag: bytes) -> bytes:
    header = bytearray(116)
    header[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHI", header, 16, 2, 40, 1)
    struct.pack_into("<II", header, 24, 0x10000, 52)
    struct.pack_into("<HHH", header, 40, 52, 32, 1)
    struct.pack_into("<8I", header, 52, 1, 84, 0x10000, 0x10000, 32, 32, 5, 4)
    header[84 : 84 + min(32, len(tag))] = tag[:32]
    return bytes(header)


def _cpio(
    board_target: str,
    *,
    missing: str = "",
    marker: bool = False,
    extra_members: dict[str, bytes] | None = None,
) -> bytes:
    variant = "s19jpro" if board_target == "am2-s19j" else "s19pro"
    init_binary = _arm_elf(b"dcentos-init")
    members = {
        "bin/busybox": _arm_elf(b"busybox"),
        "init": b"sbin/init",
        "sbin/init": init_binary,
        "usr/sbin/dropbear": _arm_elf(b"dropbear"),
        "usr/local/bin/dcentrald": _arm_elf(b"dcentrald"),
        "etc/dcentos/board_target": f"{board_target}\n".encode("ascii"),
        "etc/dcentos/board_family": b"am2\n",
        "etc/dcentos/platform": b"zynq-bm3-am2\n",
        "etc/dcentos/dcentos-init.sha256": (
            hashlib.sha256(init_binary).hexdigest() + "\n"
        ).encode("ascii"),
        "etc/dcentos/first-boot-grace": b"first-boot-only\n",
        "etc/default/dropbear": (
            DCENTOS_ROOT
            / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/default/dropbear"
        ).read_bytes(),
        "etc/dcentrald-target.conf": _target_config(board_target, variant),
        "etc/dcentrald.toml": (
            b"[mining]\nenabled = false\n[pool]\nurl = \"\"\n"
            b"[hash_on_disconnect]\nenabled = false\n"
        ),
        "etc/dcentos-early-init.sh": (
            b"#!/bin/sh\n"
            b"EXTERNAL_MEDIA_POLICY=/usr/libexec/dcentos/zynq-external-media-ephemeral.sh\n"
            b"EXTERNAL_MEDIA_EPHEMERAL=1\n"
            b"echo 'MTD/UBI device-node creation suppressed'\n"
            b"elif mount -t ubifs ubi0:rootfs_data /data; then :; fi\n"
            b"echo 'External-media identity is absent or unsafe'\n"
            b"echo 'hardware writes suppressed'\n"
            b"test 1 = 2 && exit 82\n"
        ),
        "usr/libexec/dcentos/zynq-external-media-ephemeral.sh": (
            b"dcent_external_media_prepare_ephemeral_root() {\n"
            b"mount -t tmpfs -o size=16m,mode=0755,nosuid,nodev,noexec tmpfs /data\n"
            b"dcent_external_media_data_is_ephemeral\n"
            b"touch /run/dcentos/external-media-ephemeral-ready\n}\n"
        ),
        "etc/init.d/rcS": (ZYNQ_INIT_DIR / "rcS").read_bytes(),
        "etc/init.d/rcK": (ZYNQ_INIT_DIR / "rcK").read_bytes(),
        "etc/init.d/S01syslogd": (BUILDROOT_BUSYBOX_DIR / "S01syslogd").read_bytes(),
        "etc/init.d/S02klogd": (BUILDROOT_BUSYBOX_DIR / "S02klogd").read_bytes(),
        "etc/init.d/S40network": (ZYNQ_INIT_DIR / "S40network").read_bytes(),
        "etc/init.d/S41ntp": (ZYNQ_INIT_DIR / "S41ntp").read_bytes(),
        "etc/init.d/S43logrotate": (ZYNQ_INIT_DIR / "S43logrotate").read_bytes(),
        "etc/init.d/S45persistent": (ZYNQ_INIT_DIR / "S45persistent").read_bytes(),
        "etc/init.d/S50dropbear": (ZYNQ_INIT_DIR / "S50dropbear").read_bytes(),
        "etc/init.d/S82dcentrald": (
            b"#!/bin/sh\nEXTERNAL_MEDIA_MARKER=${DCENTOS_EXTERNAL_MEDIA_MARKER:-marker}\n"
            b"echo '[SKIP] dcentrald hardware owner: external-media boot remains safe-idle/management-only'\n"
        ),
        "etc/init.d/S99upgrade": b"#!/bin/sh\necho 'U-Boot environment commit is disabled'\n",
    }
    if board_target == "am2-s19j":
        members["etc/dcentrald/xil_override.toml"] = (
            b"[mining]\nenabled = false\n[pool]\nurl = ''\n"
            b"[hash_on_disconnect]\nenabled = false\n"
        )
        members["etc/init.d/S81dcentos-xil-seed"] = (
            b"#!/bin/sh\nEXTERNAL_MEDIA_MARKER=${DCENTOS_EXTERNAL_MEDIA_MARKER:-marker}\n"
            b"echo 'External-media posture: XIL .25 persistent mining seed is disabled'\n"
        )
    members.pop(missing, None)
    if marker:
        members[MODULE.EPHEMERAL_MARKER] = b""
    members.update(extra_members or {})
    archive = b""
    for inode, (name, payload) in enumerate(members.items(), 1):
        mode = 0o120777 if name == "init" else 0o100755
        if name == "usr/libexec/dcentos/zynq-external-media-ephemeral.sh":
            mode = 0o100644
        archive += _newc_entry(name, payload, inode, mode)
    archive += _newc_entry("TRAILER!!!", b"", len(members) + 1, 0)
    return archive


def _write_source(
    root: Path,
    board_target: str,
    *,
    missing: str = "",
    marker: bool = False,
    extra_members: dict[str, bytes] | None = None,
) -> Path:
    source = root / "rootfs.cpio.gz"
    source.write_bytes(
        gzip.compress(
            _cpio(
                board_target,
                missing=missing,
                marker=marker,
                extra_members=extra_members,
            ),
            mtime=0,
        )
    )
    return source


class Am2XilinxLegacyRamdiskTests(unittest.TestCase):
    def test_both_exact_build_targets_plan_without_output(self) -> None:
        for build_target, board_target in (
            ("am2-s19j", "am2-s19j"),
            ("am2-s19pro", "am2-s19pro"),
        ):
            with self.subTest(build_target=build_target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = _write_source(root, board_target)
                output = root / f"dcent-{board_target}-ramdisk.uimg"

                result = MODULE.prepare_legacy_ramdisk(build_target, source, output)

                self.assertEqual(result["state"], "host-artifact-plan-ready-no-output")
                self.assertEqual(result["payload_board_target"], board_target)
                self.assertTrue(result["host_artifact_materialization_authorized"])
                self.assertFalse(result["external_media_write_authorized"])
                self.assertFalse(result["operator_boot_authorized"])
                self.assertFalse(result["persistent_install_authorized"])
                self.assertFalse(output.exists())
                self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_execute_inserts_marker_and_wraps_exact_deterministic_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")
            source_before = source.read_bytes()
            output_a = root / "a.uimg"
            output_b = root / "b.uimg"

            result_a = MODULE.prepare_legacy_ramdisk(
                "am2-s19j", source, output_a, source_date_epoch=1_700_000_000, execute=True
            )
            MODULE.prepare_legacy_ramdisk(
                "am2-s19j", source, output_b, source_date_epoch=1_700_000_000, execute=True
            )

            self.assertEqual(source.read_bytes(), source_before)
            self.assertEqual(output_a.read_bytes(), output_b.read_bytes())
            image = output_a.read_bytes()
            fields = struct.unpack(">7I4B32s", image[:64])
            self.assertEqual(fields[0], MODULE.UBOOT_MAGIC)
            self.assertEqual(fields[2], 1_700_000_000)
            self.assertEqual(fields[3], len(image) - 64)
            self.assertEqual(fields[4:6], (0, 0))
            self.assertEqual(fields[7:11], (5, 2, 3, 1))
            self.assertEqual(fields[11].rstrip(b"\0"), b"DCENT_OS am2-s19j")
            header = bytearray(image[:64])
            header[4:8] = b"\0\0\0\0"
            self.assertEqual(fields[1], binascii.crc32(header) & 0xFFFFFFFF)
            self.assertEqual(fields[6], binascii.crc32(image[64:]) & 0xFFFFFFFF)
            cpio = MODULE._decompress_exact_gzip(image[64:])
            analysis = MODULE._analyze_newc(cpio)
            self.assertTrue(analysis.marker_present)
            self.assertEqual(
                set(analysis.auto_start_names),
                set(MODULE.EXTERNAL_MEDIA_ALLOWED_INIT_SHA256),
            )
            self.assertNotIn("etc/init.d/S82dcentrald", analysis.auto_start_names)
            self.assertNotIn("etc/init.d/S99upgrade", analysis.auto_start_names)
            source_analysis = MODULE._analyze_newc(gzip.decompress(source_before))
            self.assertFalse(source_analysis.marker_present)

            manifest = json.loads(Path(result_a["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], MODULE.SCHEMA)
            self.assertEqual(manifest["build_target"], "am2-s19j")
            self.assertEqual(manifest["payload_board_target"], "am2-s19j")
            self.assertTrue(manifest["external_media_cpio"]["ephemeral_marker_inserted"])
            self.assertTrue(manifest["external_media_cpio"]["idle_first_config_verified"])
            self.assertTrue(manifest["external_media_cpio"]["policy_scripts_verified"])
            self.assertFalse(
                manifest["external_media_cpio"]["unexpected_auto_start_members_present"]
            )
            self.assertIn(
                "etc/init.d/S82dcentrald",
                manifest["external_media_cpio"]["auto_start_members_removed"],
            )
            self.assertTrue(manifest["external_media_marker_inserted"])
            self.assertTrue(manifest["idle_first_config_verified"])
            self.assertTrue(manifest["policy_scripts_verified"])
            self.assertEqual(
                manifest["output"]["sha256"],
                hashlib.sha256(image).hexdigest(),
            )
            self.assertEqual(
                manifest["source"]["sha256"],
                hashlib.sha256(source_before).hexdigest(),
            )
            self.assertFalse(manifest["external_media_cpio"]["ephemeral_policy_semantics_proven"])
            self.assertTrue(
                manifest["external_media_cpio"][
                    "pid1_binary_self_hash_binding_verified"
                ]
            )
            self.assertFalse(
                manifest["external_media_cpio"][
                    "pid1_external_media_gate_release_attested"
                ]
            )
            self.assertEqual(
                manifest["external_media_cpio"]["pid1_external_media_start_order"][0],
                "S45persistent",
            )
            self.assertFalse(manifest["operator_boot_authorized"])
            self.assertEqual(result_a["state"], "host-artifact-generated-readback-verified")

    def test_unexpected_auto_start_script_is_removed_from_external_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.cpio.gz"
            source.write_bytes(
                gzip.compress(
                    _cpio(
                        "am2-s19pro",
                        extra_members={
                            "etc/init.d/S46evil": (
                                b"#!/bin/sh\nfw_setenv firmware 2\n"
                                b"ubiupdatevol /dev/ubi0_1 /evil\n"
                            )
                        },
                    ),
                    mtime=0,
                )
            )
            output = root / "filtered.uimg"

            result = MODULE.prepare_legacy_ramdisk(
                "am2-s19pro", source, output, execute=True
            )

            external = MODULE._decompress_exact_gzip(output.read_bytes()[64:])
            analysis = MODULE._analyze_newc(external)
            self.assertNotIn("etc/init.d/S46evil", analysis.member_spans)
            manifest = json.loads(Path(result["manifest_path"]).read_text())
            self.assertIn(
                "etc/init.d/S46evil",
                manifest["external_media_cpio"]["auto_start_members_removed"],
            )

    def test_root_sourced_network_override_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.cpio.gz"
            source.write_bytes(
                gzip.compress(
                    _cpio(
                        "am2-s19pro",
                        extra_members={"etc/network/static": b"fw_setenv firmware 2\n"},
                    ),
                    mtime=0,
                )
            )
            output = root / "refused.uimg"

            with self.assertRaisesRegex(
                MODULE.LegacyRamdiskError, "root-sourced configuration"
            ):
                MODULE.prepare_legacy_ramdisk(
                    "am2-s19pro", source, output, execute=True
                )

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_alternate_init_and_prebaked_flash_nodes_are_refused(self) -> None:
        cases = (
            ({"init": b"evil/init"}, "must resolve exactly"),
            ({"dev/mtd0": b"not-a-real-node"}, "device nodes"),
        )
        for extra_members, error in cases:
            with self.subTest(extra_members=extra_members), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "rootfs.cpio.gz"
                source.write_bytes(
                    gzip.compress(
                        _cpio("am2-s19pro", extra_members=extra_members), mtime=0
                    )
                )
                output = root / "refused.uimg"
                with self.assertRaisesRegex(MODULE.LegacyRamdiskError, error):
                    MODULE.prepare_legacy_ramdisk(
                        "am2-s19pro", source, output, execute=True
                    )
                self.assertFalse(output.exists())

    def test_wrong_target_identity_refuses_without_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19pro")
            output = root / "wrong.uimg"

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "identity mismatch"):
                MODULE.prepare_legacy_ramdisk(
                    "am2-s19j", source, output, execute=True
                )

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_missing_actual_am2_management_member_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j", missing="etc/dcentos/first-boot-grace")

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "first-boot-grace"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, root / "missing.uimg")

    def test_placeholder_runtime_binary_refuses_sidecar_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.cpio.gz"
            valid = _arm_elf(b"dcentrald")
            archive = _cpio("am2-s19j").replace(valid, b"P" * len(valid))
            source.write_bytes(gzip.compress(archive, mtime=0))
            output = root / "placeholder.uimg"

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "wrong ELF identity"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, output, execute=True)

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_pid1_self_hash_mismatch_refuses_sidecar_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(
                root,
                "am2-s19pro",
                extra_members={"etc/dcentos/dcentos-init.sha256": b"0" * 64 + b"\n"},
            )
            output = root / "pid1-mismatch.uimg"

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "self-hash"):
                MODULE.prepare_legacy_ramdisk(
                    "am2-s19pro", source, output, execute=True
                )

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_non_idle_config_refuses_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.cpio.gz"
            archive = _cpio("am2-s19j").replace(
                b"[mining]\nenabled = false", b"[mining]\nenabled = true ", 1
            )
            source.write_bytes(gzip.compress(archive, mtime=0))
            output = root / "active.uimg"

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "not idle-first"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, output, execute=True)

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_incomplete_ephemeral_policy_refuses_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rootfs.cpio.gz"
            policy_token = b"dcent_external_media_data_is_ephemeral"
            archive = _cpio("am2-s19j").replace(policy_token, b"x" * len(policy_token))
            source.write_bytes(gzip.compress(archive, mtime=0))
            output = root / "unproven.uimg"

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "policy contract is incomplete"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, output, execute=True)

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_ramdisk_larger_than_exact_vendor_window_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")
            output = root / "too-large.uimg"
            bounded_profile = replace(MODULE.TARGETS["am2-s19j"], update_window_bytes=128)

            with mock.patch.dict(MODULE.TARGETS, {"am2-s19j": bounded_profile}):
                with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "does not fit"):
                    MODULE.prepare_legacy_ramdisk("am2-s19j", source, output, execute=True)

            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.manifest.json").exists())

    def test_ordinary_rootfs_must_not_already_carry_external_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j", marker=True)

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "must not carry"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, root / "marked.uimg")

    def test_s17_family_is_not_admitted_by_model_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "unsupported build target"):
                MODULE.prepare_legacy_ramdisk("am2-s17pro", source, root / "s17.uimg")

    def test_stale_output_is_refused_in_plan_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")
            output = root / "stale.uimg"
            output.write_bytes(b"operator-data")

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "must both be new"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, output)

            self.assertEqual(output.read_bytes(), b"operator-data")

    def test_source_as_output_is_refused_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.uimg"
            source.write_bytes(gzip.compress(_cpio("am2-s19j"), mtime=0))
            before = source.read_bytes()

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "aliases"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, source, execute=True)

            self.assertEqual(source.read_bytes(), before)

    def test_source_symlink_and_multilink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")
            linked = root / "linked.cpio.gz"
            os.link(source, linked)

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "one hard link"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, root / "hard.uimg")

        if os.name != "nt":
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = _write_source(root, "am2-s19j")
                linked = root / "linked.cpio.gz"
                linked.symlink_to(source)
                with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "non-reparse regular"):
                    MODULE.prepare_legacy_ramdisk("am2-s19j", linked, root / "sym.uimg")

    def test_concatenated_gzip_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = _write_source(root, "am2-s19j")
            source.write_bytes(source.read_bytes() + gzip.compress(b"second", mtime=0))

            with self.assertRaisesRegex(MODULE.LegacyRamdiskError, "concatenated"):
                MODULE.prepare_legacy_ramdisk("am2-s19j", source, root / "concat.uimg")

    def test_unc_source_and_output_paths_are_rejected_without_contact(self) -> None:
        for label, path in (
            ("source", Path(r"\\server\share\rootfs.cpio.gz")),
            ("output", Path(r"\\server\share\dcent.uimg")),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.LegacyRamdiskError, "UNC"
            ):
                MODULE._reject_device_namespace(path, label=label)

    def test_defconfigs_add_cpio_without_removing_squashfs(self) -> None:
        config_root = SCRIPT_DIR.parent / "br2_external_dcentos" / "configs"
        for name in (
            "dcentos_am2_s19jpro_defconfig",
            "dcentos_am2_s19pro_defconfig",
        ):
            text = (config_root / name).read_text(encoding="utf-8")
            self.assertIn("BR2_TARGET_ROOTFS_SQUASHFS=y", text)
            self.assertIn("BR2_TARGET_ROOTFS_CPIO=y", text)
            self.assertIn("BR2_TARGET_ROOTFS_CPIO_GZIP=y", text)


if __name__ == "__main__":
    unittest.main()
