#!/usr/bin/env python3
"""Hash-bound, host-only BCB100/STM32MP157 boot-input census.

This analyzer deliberately stops before artifact construction.  The held
``bos-build`` checkout describes the BCB100 ``ii1`` outputs and the manual
eMMC write sequence, but obtains six independent repositories without a
default tag or commit.  Those repositories, their generated image recipes,
and their bootable outputs are not held in the canonical build directory.

The JSON result is evidence, not permission to build, boot, install, or write
media.  The implementation opens no network endpoint, invokes no build/helper
process, and never opens a device path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePath
import re
import stat
import sys
from typing import Any, NamedTuple


SCHEMA = "dcentos.bcb100_offline_boot_inputs.v1"
BOARD_TARGET = "bcb100-s19jpro"
CONTROL_BOARD = "BRR_CB_P03_REV_A1_1-STM32MP157"
SOC = "STM32MP157CAB3"
MAX_DECLARATION_BYTES = 32 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024

BOS_BUILD = Path("")
BCB100 = Path("")
OUTPUT_DIRECTORY = BOS_BUILD / "build/openwrt/bin/targets/stm32mp15/ii1"

DEPENDENCIES = {
    "openwrt": "ii1 image recipes, target metadata, and generated SD/eMMC layout",
    "bos-assets": "BOS runtime assets referenced by the held configuration",
    "bos-packages": "boot-stm32mp15_ii1 package and provisioning logic",
    "linux-stm": "BCB100 kernel, configuration, and device tree",
    "u-boot-stm": "BCB100 U-Boot defconfig, device tree, environment, and FIP input",
    "arm-trusted-firmware-stm": "BCB100 TF-A port, DDR configuration, and FSBL input",
}

EXPECTED_OUTPUTS = (
    (
        "emmc-fsbl",
        "openwrt-stm32mp15-ii1-emmc-mmcblk0bootx.img.gz",
        "gzip-wrapped TF-A first-stage image documented for both eMMC boot partitions",
    ),
    (
        "emmc-fip",
        "openwrt-stm32mp15-ii1-emmc-mmcblk0.img.gz",
        "gzip-wrapped FIP documented for eMMC user area offset zero",
    ),
    (
        "emmc-rootfs",
        "openwrt-stm32mp15-ii1-emmc-squashfs-mmcblk0gp0.img",
        "squashfs image documented for eMMC general-purpose partition zero",
    ),
    (
        "emmc-sysupgrade",
        "openwrt-stm32mp15-ii1-emmc-squashfs-sysupgrade.tar",
        "OpenWrt eMMC sysupgrade container",
    ),
    (
        "sd-composite",
        "openwrt-stm32mp15-ii1-sd-squashfs-user.img.gz",
        "gzip-wrapped whole-card SD image",
    ),
    (
        "sd-sysupgrade",
        "openwrt-stm32mp15-ii1-sd-squashfs-sysupgrade.tar",
        "OpenWrt SD sysupgrade container",
    ),
)


class EvidenceError(ValueError):
    """Raised when a held input cannot be inspected without ambiguity."""


class SourceSpec(NamedTuple):
    role: str
    path: Path
    tokens: tuple[bytes, ...]


SOURCE_SPECS = (
    SourceSpec(
        "bcb100-hardware-readme",
        BCB100 / "README.md",
        (
            b"STM32MP157CAB3",
            b"128 MB RAM and 4GB of eMMC memory",
            b"By default eMMC is chosen",
            b"the MPU will boot OS from the SD card",
        ),
    ),
    SourceSpec(
        "bcb100-ipc2581-netlist",
        BCB100
        / "FAB-BRR_CB_P03_REV_A1_1-STM32MP157-A.3/IPC-2581 Files/"
        "BRR_CB_P03_REV_A1_1-STM32MP157.cvg",
        (
            b'net="UART4_RX"',
            b'net="UART4_TX"',
            b'net="BOOT0"',
            b'net="BOOT1"',
            b'net="BOOT2"',
            b'net="CARD_DETECT"',
            b'net="SDMMC1_CK"',
            b'net="SDMMC2_CK"',
        ),
    ),
    SourceSpec(
        "bos-build-readme",
        BOS_BUILD / "README.md",
        tuple(name.encode("ascii") for _, name, _ in EXPECTED_OUTPUTS)
        + (
            b"mmc gp create -c 49152 1 1 0 /dev/mmcblk0",
            b"mmc write_reliability set -y 0 /dev/mmcblk0",
            b"dd if=/dev/zero of=/dev/mmcblk0 bs=4M count=4",
            b"dd if=$FSBL of=/dev/mmcblk0boot0 bs=4096 conv=fsync",
            b"dd if=$FSBL of=/dev/mmcblk0boot1 bs=4096 conv=fsync",
            b"dd if=$FIP of=/dev/mmcblk0 bs=4096 conv=fsync",
            b"of=/dev/mmcblk0gp0 bs=4M conv=fsync",
        ),
    ),
    SourceSpec(
        "bos-bootstrap",
        BOS_BUILD / "scripts/00_bootstrap.sh",
        tuple(name.encode("ascii") for name in DEPENDENCIES)
        + (
            b'REPO_URL="${REPO_URL:-git@github.com:braiins}"',
            b'[[ -n "$TAG_NAME" ]] && git_args+=("--branch=$TAG_NAME")',
            b'git clone "${git_args[@]}" "$REPO_URL/$repo.git"',
        ),
    ),
    SourceSpec(
        "bos-configure",
        BOS_BUILD / "scripts/01_configure.sh",
        (
            b'cp "./defaults/stm32mp15_ii1.conf"',
            b'echo "src-link bos $BUILD_DIR/bos-packages"',
            b"./scripts/feeds update -a",
            b"make defconfig",
        ),
    ),
    SourceSpec(
        "bos-make",
        BOS_BUILD / "scripts/02_make.sh",
        (b'openwrt_nix make -j"$MAKE_JOBS"',),
    ),
    SourceSpec(
        "bos-ii1-config",
        BOS_BUILD / "defaults/stm32mp15_ii1.conf",
        (
            b"CONFIG_TARGET_stm32mp15_ii1=y",
            b"CONFIG_TARGET_DEVICE_stm32mp15_ii1_DEVICE_emmc=y",
            b"CONFIG_TARGET_DEVICE_stm32mp15_ii1_DEVICE_sd=y",
            b"CONFIG_PACKAGE_boot-stm32mp15_ii1=y",
            b'CONFIG_EXTERNAL_ARM_TRUSTED_FIRMWARE_STM32MP15_TREE="../arm-trusted-firmware-stm"',
            b'CONFIG_EXTERNAL_KERNEL_TREE="../linux-stm"',
            b'CONFIG_EXTERNAL_UBOOT_STM32MP15_TREE="../u-boot-stm"',
        ),
    ),
    SourceSpec(
        "bos-nix-environment",
        BOS_BUILD / "flake.nix",
        (b'nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable"',),
    ),
    SourceSpec(
        "bos-nix-lock",
        BOS_BUILD / "flake.lock",
        (b'"nixpkgs"', b'"flake-utils"', b'"locked"'),
    ),
)


def _reject_device_or_remote_path(path: Path, *, label: str) -> None:
    raw = os.fspath(path)
    normalized = raw.replace("/", "\\")
    if normalized.startswith(("\\\\", "\\??\\", "\\Device\\")):
        raise EvidenceError(f"{label} must not use a remote or device namespace")
    if re.match(r"^[A-Za-z]:$", normalized):
        raise EvidenceError(f"{label} must not name a drive device")
    posix_style = raw.replace("\\", "/")
    if posix_style == "/dev" or posix_style.startswith(("/dev/", "/proc/", "/sys/")):
        raise EvidenceError(f"{label} must not use a kernel or device filesystem")


def _is_link_like(identity: os.stat_result) -> bool:
    if stat.S_ISLNK(identity.st_mode):
        return True
    attributes = getattr(identity, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse)


def _validate_workspace_root(supplied: Path) -> Path:
    _reject_device_or_remote_path(supplied, label="workspace_root")
    try:
        identity = os.lstat(supplied)
    except OSError as exc:
        raise EvidenceError(f"workspace_root is missing or unreadable: {exc}") from exc
    if _is_link_like(identity):
        raise EvidenceError("workspace_root must not be a link or reparse point")
    if not stat.S_ISDIR(identity.st_mode):
        raise EvidenceError("workspace_root must be a directory")
    return supplied.resolve(strict=True)


def _safe_path(root: Path, relative: Path, *, expect_directory: bool = False) -> Path:
    if relative.is_absolute() or ".." in PurePath(relative).parts:
        raise EvidenceError(f"unsafe relative evidence path: {relative}")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            identity = os.lstat(current)
        except FileNotFoundError:
            if index == len(relative.parts) - 1:
                return current
            raise EvidenceError(f"evidence parent is missing: {current}") from None
        except OSError as exc:
            raise EvidenceError(f"cannot inspect evidence path {current}: {exc}") from exc
        if _is_link_like(identity):
            raise EvidenceError(f"evidence path must not traverse a link: {current}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(identity.st_mode):
            raise EvidenceError(f"evidence parent is not a directory: {current}")
        if index == len(relative.parts) - 1 and expect_directory and not stat.S_ISDIR(
            identity.st_mode
        ):
            raise EvidenceError(f"expected evidence directory: {current}")
    return current


def _read_regular_once(root: Path, spec: SourceSpec) -> tuple[bytes, dict[str, Any]]:
    path = _safe_path(root, spec.path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"missing or unreadable {spec.role}: {spec.path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"{spec.role} must be a regular file")
        if before.st_nlink != 1:
            raise EvidenceError(f"{spec.role} must have exactly one hard link")
        if before.st_size > MAX_DECLARATION_BYTES:
            raise EvidenceError(f"{spec.role} exceeds the declaration size limit")
        digest = hashlib.sha256()
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content.extend(chunk)
            digest.update(chunk)
            if len(content) > MAX_DECLARATION_BYTES:
                raise EvidenceError(f"{spec.role} grew beyond the declaration size limit")
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity:
            raise EvidenceError(f"{spec.role} changed while being inspected")
    finally:
        os.close(descriptor)
    missing = [token.decode("utf-8") for token in spec.tokens if token not in content]
    if missing:
        raise EvidenceError(f"{spec.role} is missing required declarations: {missing}")
    return bytes(content), {
        "role": spec.role,
        "path": spec.path.as_posix(),
        "size": len(content),
        "sha256": digest.hexdigest(),
        "state": "held-regular-file-hashed",
    }


def _hash_optional_artifact(path: Path, relative: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {
            "path": relative.as_posix(),
            "state": "missing-from-canonical-build-output",
            "size": None,
            "sha256": None,
        }
    identity = os.lstat(path)
    if _is_link_like(identity) or not stat.S_ISREG(identity.st_mode):
        raise EvidenceError(f"candidate boot output is not a plain regular file: {relative}")
    if identity.st_nlink != 1:
        raise EvidenceError(f"candidate boot output is multiply linked: {relative}")
    if identity.st_size > MAX_ARTIFACT_BYTES:
        raise EvidenceError(f"candidate boot output exceeds the inspection limit: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise EvidenceError(f"candidate boot output grew beyond its limit: {relative}")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise EvidenceError(f"candidate boot output changed during hashing: {relative}")
    finally:
        os.close(descriptor)
    return {
        "path": relative.as_posix(),
        "state": "held-untrusted-output-hashed",
        "size": total,
        "sha256": digest.hexdigest(),
    }


def _read_small_plain(path: Path, *, label: str) -> str | None:
    try:
        identity = os.lstat(path)
    except OSError:
        return None
    if _is_link_like(identity) or not stat.S_ISREG(identity.st_mode):
        raise EvidenceError(f"{label} must be a plain regular file")
    if identity.st_nlink != 1 or identity.st_size > 1024 * 1024:
        raise EvidenceError(f"{label} has an unsafe link count or size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        payload = os.read(descriptor, 1024 * 1024 + 1)
        after = os.fstat(descriptor)
        if len(payload) > 1024 * 1024:
            raise EvidenceError(f"{label} grew beyond its size limit")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise EvidenceError(f"{label} changed during inspection")
    finally:
        os.close(descriptor)
    try:
        return payload.decode("ascii").strip()
    except UnicodeError as exc:
        raise EvidenceError(f"{label} is not ASCII") from exc


def _git_head_without_vcs(repository: Path) -> str | None:
    git_dir = repository / ".git"
    try:
        identity = os.lstat(git_dir)
    except OSError:
        return None
    if _is_link_like(identity) or not stat.S_ISDIR(identity.st_mode):
        raise EvidenceError(f"Git metadata must be a plain directory: {git_dir}")
    head_path = git_dir / "HEAD"
    head = _read_small_plain(head_path, label=f"Git HEAD for {repository}")
    if head is None:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{40}", head):
        return head.lower()
    if not head.startswith("ref: "):
        return None
    reference = head[5:]
    if reference.startswith("/") or ".." in PurePath(reference).parts:
        return None
    loose = git_dir / Path(reference)
    value = _read_small_plain(loose, label=f"Git ref for {repository}") or ""
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return value.lower()
    packed = git_dir / "packed-refs"
    packed_text = _read_small_plain(packed, label=f"packed Git refs for {repository}")
    if packed_text is None:
        return None
    lines = packed_text.splitlines()
    suffix = f" {reference}"
    for line in lines:
        if line.endswith(suffix) and re.fullmatch(r"[0-9a-fA-F]{40} .+", line):
            return line[:40].lower()
    return None


def _dependency_ledger(root: Path) -> list[dict[str, Any]]:
    ledger = []
    for name, role in DEPENDENCIES.items():
        relative = Path("") / name
        candidate = root / relative
        try:
            identity = os.lstat(candidate)
        except FileNotFoundError:
            state = "missing"
            commit = None
        except OSError as exc:
            raise EvidenceError(f"cannot inspect dependency {relative}: {exc}") from exc
        else:
            if stat.S_ISLNK(identity.st_mode):
                raise EvidenceError(f"dependency repository must not be a link: {relative}")
            if not stat.S_ISDIR(identity.st_mode):
                raise EvidenceError(f"dependency repository must be a directory: {relative}")
            state = "held-but-unpinned-by-bootstrap"
            commit = _git_head_without_vcs(candidate)
        ledger.append(
            {
                "name": name,
                "role": role,
                "declared_url": f"git@github.com:braiins/{name}.git",
                "declared_revision": None,
                "local_path": relative.as_posix(),
                "local_state": state,
                "observed_local_head": commit,
                "admitted_for_reproducible_build": False,
            }
        )
    return ledger


def analyze(workspace_root: Path) -> dict[str, Any]:
    """Return a deterministic, no-contact dependency and layout ledger."""

    root = _validate_workspace_root(Path(workspace_root))
    contents: dict[str, bytes] = {}
    evidence = []
    for spec in SOURCE_SPECS:
        content, record = _read_regular_once(root, spec)
        contents[spec.role] = content
        evidence.append(record)

    try:
        lock = json.loads(contents["bos-nix-lock"])
        nixpkgs_revision = lock["nodes"]["nixpkgs"]["locked"]["rev"]
        flake_utils_revision = lock["nodes"]["flake-utils"]["locked"]["rev"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"bos Nix lock has an unexpected shape: {exc}") from exc
    for value, label in (
        (nixpkgs_revision, "nixpkgs"),
        (flake_utils_revision, "flake-utils"),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise EvidenceError(f"bos Nix lock does not pin a valid {label} revision")

    dependencies = _dependency_ledger(root)
    outputs = []
    for role, name, description in EXPECTED_OUTPUTS:
        relative = OUTPUT_DIRECTORY / name
        record = _hash_optional_artifact(root / relative, relative)
        record.update({"role": role, "filename": name, "description": description})
        outputs.append(record)

    digest_input = "".join(
        f"{item['role']}\0{item['path']}\0{item['size']}\0{item['sha256']}\n"
        for item in evidence
    ).encode("utf-8")
    evidence_set_sha256 = hashlib.sha256(digest_input).hexdigest()
    declaring_commit = _git_head_without_vcs(root / BOS_BUILD)

    missing_paths = [
        item["local_path"] for item in dependencies if item["local_state"] == "missing"
    ] + [item["path"] for item in outputs if item["state"].startswith("missing")]
    missing_capabilities = [
        "exact OpenWrt stm32mp15/ii1 DEVICE_sd image recipe, partition offsets, partition types, and filesystem labels",
        "exact OpenWrt stm32mp15/ii1 DEVICE_emmc generated layout implementation",
        "boot-stm32mp15_ii1 package source and provisioning semantics",
        "BCB100 TF-A platform port and DDR configuration used to produce the FSBL",
        "BCB100 U-Boot defconfig, device tree, environment, FIP recipe, and SD/eMMC boot commands",
        "BCB100 Linux configuration and device tree",
        "DCENT_OS STM32MP157 ARMv7 Buildroot target/rootfs integration",
        "offline dependency closure for the Nix inputs and all OpenWrt source/download inputs",
        "trusted release manifest binding the six documented output names to sizes and cryptographic hashes",
        "power-loss-safe field transaction and rollback contract for eMMC boot0/boot1/user/GP0 writes",
        "operational BOOT0/BOOT1/BOOT2, UART electrical/baud/orientation, and USB/serial recovery contract",
    ]

    return {
        "schema": SCHEMA,
        "board_target": BOARD_TARGET,
        "control_board": CONTROL_BOARD,
        "soc": SOC,
        "state": "dependency-and-layout-evidence-incomplete",
        "proof_scope": "hash-bound-held-source-and-canonical-output-census-only",
        "proof_ceiling": "hardware-selection-and-partial-emmc-topology-evidence",
        "evidence_set_sha256": evidence_set_sha256,
        "source_evidence": evidence,
        "build_driver": {
            "path": BOS_BUILD.as_posix(),
            "observed_git_head": declaring_commit,
            "git_history_scope": "shallow-checkout"
            if _read_small_plain(
                root / BOS_BUILD / ".git/shallow", label="bos-build shallow marker"
            )
            else "not-proven",
            "dependency_clone_policy": "optional shared TAG_NAME; otherwise each remote default branch",
            "dependencies_pinned_by_held_build_driver": False,
            "nix_tool_environment_pins": {
                "nixpkgs": nixpkgs_revision,
                "flake-utils": flake_utils_revision,
            },
            "nix_tool_environment_available_offline": False,
        },
        "dependency_ledger": dependencies,
        "expected_outputs": outputs,
        "layout_contract": {
            "sd": {
                "selection": "insert SD while eMMC boot is working, then reset",
                "documented_container": "openwrt-stm32mp15-ii1-sd-squashfs-user.img.gz",
                "internal_partition_table": "missing-with-openwrt-ii1-image-recipe",
                "first_stage_offsets": "missing",
                "kernel_dtb_rootfs_offsets": "missing",
                "status": "selection-proven-layout-unproven",
            },
            "emmc": {
                "manufacturing_partition_commands": [
                    "mmc enh_attrs set 0x03 /dev/mmcblk0",
                    "mmc gp create -c 49152 1 1 0 /dev/mmcblk0",
                    "mmc write_reliability set -c 1 /dev/mmcblk0",
                    "mmc enh_area set -c 0 344064 /dev/mmcblk0",
                    "mmc write_reliability set -y 0 /dev/mmcblk0",
                ],
                "documented_write_sequence": [
                    "clear force_ro for /dev/mmcblk0boot0 and /dev/mmcblk0boot1",
                    "mmc bootbus set single_backward x1 x1 /dev/mmcblk0",
                    "zero first 16 MiB of /dev/mmcblk0",
                    "write identical FSBL bytes at offset zero of /dev/mmcblk0boot0 and /dev/mmcblk0boot1 with bs=4096",
                    "mmc bootpart enable 1 1 /dev/mmcblk0",
                    "write FIP bytes at offset zero of /dev/mmcblk0 with bs=4096",
                    "write rootfs bytes at offset zero of /dev/mmcblk0gp0 with bs=4M",
                    "sync",
                ],
                "exact_component_sizes": "missing",
                "field_rollback_transaction": "missing",
                "status": "manual-destructive-topology-only",
            },
        },
        "proof_facets": {
            "board_identity": "held-open-hardware-source",
            "sd_boot_selection": "held-open-hardware-source",
            "debug_uart_and_boot_strap_nets": "held-ipc2581-source-operational-contract-missing",
            "bos_target_selectors": "held-build-configuration",
            "expected_output_names": "held-build-documentation",
            "dependency_revisions": "unversioned-by-held-bootstrap",
            "bootable_output_bytes": "missing",
            "sd_layout": "missing",
            "emmc_layout": "partial-destructive-command-sequence-only",
            "dcentos_target_rootfs": "missing",
            "hardware_boot_witness": "not_observed",
        },
        "exact_missing_paths": missing_paths,
        "missing_capabilities": missing_capabilities,
        "host_report_generation_authorized": True,
        "boot_artifact_generation_authorized": False,
        "operator_boot_authorized": False,
        "external_media_write_authorized": False,
        "persistent_storage_write_authorized": False,
        "installation_authorized": False,
        "raw_device_reachable": False,
        "device_contact": "none",
        "network_contact": "none",
        "helper_execution": "none",
    }


def write_report(report: dict[str, Any], output_path: Path) -> Path:
    """Create one report exclusively; never replace or follow an output path."""

    output = Path(output_path)
    _reject_device_or_remote_path(output, label="output")
    if output.exists() or output.is_symlink():
        raise EvidenceError("output path must be new and must not be a symlink")
    try:
        parent_identity = os.lstat(output.parent)
    except OSError as exc:
        raise EvidenceError(f"output parent is missing or unreadable: {exc}") from exc
    if _is_link_like(parent_identity) or not stat.S_ISDIR(parent_identity.st_mode):
        raise EvidenceError("output parent must be a plain directory")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output, flags, 0o600)
    except OSError as exc:
        raise EvidenceError(f"cannot create exclusive report output: {exc}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceError("short write while creating report")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        try:
            output.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="local DCENT Projects workspace root (required; no discovery or network)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional new JSON report path; stdout is used when omitted",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = analyze(args.workspace_root)
        if args.output is None:
            json.dump(report, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            created = write_report(report, args.output)
            print(created)
    except EvidenceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
