#!/usr/bin/env python3
"""Create and verify signed Avalon K210 replacement-firmware evidence bundles.

This tool is host-only and has no miner, programmer, serial, USB, JTAG, GPIO,
power, flash, network, or install transport. It snapshots two completed offline
builds plus source/review evidence and exact-joins a positive boot-policy
receipt. A valid bundle proves an artifact contract only and grants no future
hardware contact, installation, hashing, or release authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import zlib
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_boot_module():
    path = Path(__file__).with_name("k210_boot_policy_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_boot_policy_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 boot-policy primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot = _load_boot_module()
recovery = boot.recovery
discovery = boot.discovery

SCHEMA_VERSION = 1
SCOPE = boot.SCOPE
DESCRIPTOR_KIND = "dcent_k210_replacement_firmware_descriptor"
RECEIPT_KIND = "dcent_k210_replacement_firmware_receipt"
DISPOSITION = "offline_replacement_artifact_evidence_no_install_authority"
RECEIPT_NAME = "receipt.json"
BUILDER_SIGNATURE_NAME = "builder.sig"
REVIEWER_SIGNATURE_NAME = "reviewer.sig"
EVIDENCE_DIRECTORY = "evidence"
BUILDER_ROLE = "k210_replacement_builder"
REVIEWER_ROLE = "k210_replacement_reviewer"
BUILDER_NAMESPACE = "dcent-k210-replacement-builder-v1"
REVIEWER_NAMESPACE = "dcent-k210-replacement-reviewer-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM
MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 32
MAX_EVIDENCE_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 1024 * 1024 * 1024
MAX_APP_BYTES = 6 * 1024 * 1024
K210_LOAD_BASE = boot.K210_CANDIDATE_LOAD_ADDRESS
AUP_MAGIC = b"AUP format\x00\x00\x00\x00\x00\x00"
ELF_PT_LOAD = 1
ELF_MACHINE_RISCV = 243

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = boot.HEX64_RE
FIRMWARE_VERSION_RE = re.compile(r"^[0-9]{8}_dcent_[a-z0-9][a-z0-9._-]{0,31}$")
TAG_RE = re.compile(r"^[ -~]{1,31}$")

REQUIRED_BSP_CAPABILITIES = (
    "board_identity_check",
    "clock_tree_init",
    "independent_cutoff_monitor",
    "memory_layout",
    "monotonic_timer",
    "reset_entry",
    "safe_idle_entry",
    "sensor_readout",
    "trap_vector",
    "watchdog_fail_closed",
)
REQUIRED_EVIDENCE_COUNTS = {
    "board_profile_record": 1,
    "boot_policy_receipt_copy": 1,
    "clean_room_review": 1,
    "firmware_aup": 2,
    "firmware_elf": 2,
    "firmware_raw": 2,
    "license_review": 1,
    "reproducibility_log": 2,
    "sbom": 1,
    "source_archive": 1,
    "source_manifest": 1,
    "toolchain_manifest": 2,
}
EVIDENCE_KINDS = set(REQUIRED_EVIDENCE_COUNTS)
MEDIA_TYPES = {
    "application/json",
    "application/octet-stream",
    "application/spdx+json",
    "application/x-tar",
    "application/zip",
    "text/plain",
}
EVIDENCE_METHODS = {
    "independent_offline_build",
    "offline_artifact",
    "review_attestation",
}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_flash_write": False,
    "authorizes_install": False,
    "authorizes_network_or_debug_access": False,
    "authorizes_power_or_cooling_control": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}
SAFE_DEFAULTS = {
    "boots_to_safe_idle": True,
    "cooling_safe_state_precedes_hash_power": True,
    "hash_power_default_off": True,
    "interrupts_fail_closed": True,
    "voltage_default_off": True,
    "watchdog_fail_closed": True,
}


class ReplacementError(RuntimeError):
    """A replacement descriptor, bundle, or artifact invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _translate(callable_value, *args, **kwargs):
    try:
        return callable_value(*args, **kwargs)
    except boot.BootPolicyError as exc:
        raise ReplacementError(str(exc)) from exc


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], context: str
) -> None:
    return _translate(boot._require_exact_keys, value, expected, context)


def _text(value: Any, context: str, maximum: int = 160) -> str:
    return _translate(boot._text, value, context, maximum)


def _identifier(value: Any, context: str) -> str:
    return _translate(boot._identifier, value, context)


def _principal(value: Any, context: str) -> str:
    return _translate(boot._principal, value, context)


def _sha(value: Any, context: str) -> str:
    return _translate(boot._sha, value, context)


def _utc(value: Any, context: str) -> datetime:
    return _translate(boot._utc, value, context)


def _bool(value: Any, context: str) -> bool:
    return _translate(boot._bool, value, context)


def _int(value: Any, context: str, minimum: int, maximum: int) -> int:
    return _translate(boot._int, value, context, minimum, maximum)


def _safe_path(value: Any, context: str) -> PurePosixPath:
    return _translate(boot._safe_path, value, context)


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc


def _hash_source(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc


def _read_artifact(path: Path, label: str) -> bytes:
    try:
        return discovery._read_regular(path, label, MAX_EVIDENCE_FILE_BYTES)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc


def _evidence_ref(
    evidence: Mapping[str, Mapping[str, Any]],
    evidence_id: Any,
    kind: str,
    context: str,
) -> Mapping[str, Any]:
    canonical = _identifier(evidence_id, context)
    item = evidence.get(canonical)
    if item is None or item["kind"] != kind:
        raise ReplacementError(f"{context} must reference {kind} evidence")
    return item


def _validate_evidence(evidence: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        raise ReplacementError(f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records")
    ids: set[str] = set()
    paths: set[str] = set()
    counts: dict[str, int] = {}
    normalized = []
    for index, item in enumerate(evidence):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise ReplacementError(f"{context} must be an object")
        keys = (
            "acquired_at_utc",
            "bytes",
            "id",
            "kind",
            "media_type",
            "method",
            "path",
            "redaction",
            "sha256",
        )
        if not hashed:
            keys = tuple(key for key in keys if key not in ("bytes", "sha256"))
        _require_exact_keys(item, keys, context)
        evidence_id = _identifier(item["id"], f"{context}.id")
        if evidence_id in ids:
            raise ReplacementError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise ReplacementError(f"{context}.kind is unsupported")
        counts[kind] = counts.get(kind, 0) + 1
        if item["media_type"] not in MEDIA_TYPES:
            raise ReplacementError(f"{context}.media_type is unsupported")
        if item["method"] not in EVIDENCE_METHODS:
            raise ReplacementError(f"{context}.method is unsupported")
        if item["redaction"] not in REDACTION_STATES:
            raise ReplacementError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise ReplacementError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _int(item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    if counts != REQUIRED_EVIDENCE_COUNTS:
        raise ReplacementError(
            "replacement evidence-kind counts are not the exact required set"
        )
    return normalized


def _fixed_string(data: bytes) -> str:
    raw = data.split(b"\x00", 1)[0]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReplacementError("AUP fixed string is not ASCII") from exc


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ReplacementError("AUP u32 exceeds the artifact")
    return struct.unpack_from("<I", data, offset)[0]


def inspect_plain_aup(data: bytes) -> dict[str, Any]:
    if len(data) < 104 or data[:16] != AUP_MAGIC:
        raise ReplacementError("replacement AUP magic or minimum size is invalid")
    if _u32(data, 0x10) != 2:
        raise ReplacementError("replacement AUP must use format version 2")
    payload_len = _u32(data, 0x14)
    hardware_count = _u32(data, 0x5C)
    software_count = _u32(data, 0x60)
    if not 1 <= hardware_count <= 64 or not 1 <= software_count <= 64:
        raise ReplacementError("replacement AUP compatibility counts are invalid")
    list_end = 0x64 + 32 * (hardware_count + software_count)
    header_size = list_end + 4
    if header_size + payload_len != len(data):
        raise ReplacementError("replacement AUP declared size does not match bytes")
    if _u32(data, list_end) != zlib.crc32(data[:list_end]) & 0xFFFF_FFFF:
        raise ReplacementError("replacement AUP header CRC mismatch")
    payload = data[header_size:]
    if _u32(data, 0x58) != zlib.crc32(payload) & 0xFFFF_FFFF:
        raise ReplacementError("replacement AUP payload CRC mismatch")
    if len(payload) < 38 or payload[0] != 0:
        raise ReplacementError("replacement AUP must contain a non-empty AES0 image")
    app_size = _u32(payload, 1)
    if not 1 <= app_size <= MAX_APP_BYTES or 5 + app_size + 32 != len(payload):
        raise ReplacementError("replacement AUP K210 application length is invalid")
    if hashlib.sha256(payload[: 5 + app_size]).digest() != payload[5 + app_size :]:
        raise ReplacementError("replacement AUP inner SHA-256 mismatch")
    offset = 0x64
    hardware = []
    software = []
    for _ in range(hardware_count):
        hardware.append(_fixed_string(data[offset : offset + 32]))
        offset += 32
    for _ in range(software_count):
        software.append(_fixed_string(data[offset : offset + 32]))
        offset += 32
    return {
        "app": payload[5 : 5 + app_size],
        "firmware_version": _fixed_string(data[0x18:0x58]),
        "hardware": hardware,
        "software": software,
        "wrapper_bytes": len(payload),
    }


def inspect_single_load_elf(data: bytes, load_address: int) -> dict[str, Any]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ReplacementError("replacement ELF magic or minimum size is invalid")
    if data[4] != 2 or data[5] != 1:
        raise ReplacementError("replacement ELF must be ELF64 little-endian")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 2 or machine != ELF_MACHINE_RISCV:
        raise ReplacementError("replacement ELF must be a RISC-V executable")
    entry = struct.unpack_from("<Q", data, 24)[0]
    if entry != load_address:
        raise ReplacementError(
            "replacement ELF entry does not match measured load address"
        )
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    entry_size = struct.unpack_from("<H", data, 54)[0]
    count = struct.unpack_from("<H", data, 56)[0]
    if entry_size < 56 or count == 0 or program_offset < 64:
        raise ReplacementError("replacement ELF program-header table is invalid")
    if program_offset + entry_size * count > len(data):
        raise ReplacementError("replacement ELF program-header table exceeds the file")
    loads = []
    for index in range(count):
        offset = program_offset + index * entry_size
        segment_type, flags = struct.unpack_from("<II", data, offset)
        if segment_type != ELF_PT_LOAD:
            continue
        file_offset, virtual, physical, file_size, memory_size = struct.unpack_from(
            "<QQQQQ", data, offset + 8
        )
        if (
            file_size == 0
            or file_size > memory_size
            or file_offset + file_size > len(data)
            or virtual != physical
        ):
            raise ReplacementError("replacement ELF load segment is invalid")
        loads.append(
            {
                "flags": flags,
                "file_offset": file_offset,
                "file_size": file_size,
                "memory_size": memory_size,
                "virtual_address": virtual,
            }
        )
    if len(loads) != 1:
        raise ReplacementError("replacement ELF must contain exactly one load segment")
    load = loads[0]
    if load["virtual_address"] != load_address or not load["flags"] & 1:
        raise ReplacementError(
            "replacement ELF load segment is not executable at entry"
        )
    return {
        **load,
        "raw": data[load["file_offset"] : load["file_offset"] + load["file_size"]],
    }


def _validate_tags(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ReplacementError(f"{context} must contain 1..64 tags")
    if len(value) != len(set(value)):
        raise ReplacementError(f"{context} tags must be unique")
    for index, tag in enumerate(value):
        if not isinstance(tag, str) or not TAG_RE.fullmatch(tag) or "\x00" in tag:
            raise ReplacementError(f"{context}[{index}] is not a canonical AUP tag")
    return list(value)


def _validate_firmware(
    value: Any, evidence: Mapping[str, Mapping[str, Any]], *, receipt: bool
) -> None:
    if not isinstance(value, dict):
        raise ReplacementError("firmware must be an object")
    _require_exact_keys(
        value,
        (
            "clean_room_review_evidence_id",
            "firmware_class",
            "firmware_version",
            "license_review_evidence_id",
            "restricted_vendor_code_included",
            "sbom_evidence_id",
            "source_archive_evidence_id",
            "source_archive_sha256",
            "source_commit",
            "source_dirty",
            "source_license",
            "source_manifest_evidence_id",
            "third_party_license_review_passed",
            "vendor_binary_blob_included",
        ),
        "firmware",
    )
    if value["firmware_class"] != "target_bound_safe_idle_runtime":
        raise ReplacementError("firmware class is not target-bound safe-idle runtime")
    version = value["firmware_version"]
    if not isinstance(version, str) or not FIRMWARE_VERSION_RE.fullmatch(version):
        raise ReplacementError("firmware version is not canonical")
    if not HEX40_RE.fullmatch(value["source_commit"]):
        raise ReplacementError("source_commit must be lowercase 40-hex")
    if _bool(value["source_dirty"], "firmware.source_dirty") is not False:
        raise ReplacementError("replacement source tree must be clean")
    if value["source_license"] != "GPL-3.0-only":
        raise ReplacementError("replacement source license must be GPL-3.0-only")
    for key in ("restricted_vendor_code_included", "vendor_binary_blob_included"):
        if _bool(value[key], f"firmware.{key}") is not False:
            raise ReplacementError(f"firmware.{key} must be false")
    if (
        _bool(
            value["third_party_license_review_passed"],
            "firmware.third_party_license_review_passed",
        )
        is not True
    ):
        raise ReplacementError("third-party license review must pass")
    archive = _evidence_ref(
        evidence,
        value["source_archive_evidence_id"],
        "source_archive",
        "firmware.source_archive_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["source_manifest_evidence_id"],
        "source_manifest",
        "firmware.source_manifest_evidence_id",
    )
    _evidence_ref(
        evidence, value["sbom_evidence_id"], "sbom", "firmware.sbom_evidence_id"
    )
    _evidence_ref(
        evidence,
        value["license_review_evidence_id"],
        "license_review",
        "firmware.license_review_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["clean_room_review_evidence_id"],
        "clean_room_review",
        "firmware.clean_room_review_evidence_id",
    )
    _sha(value["source_archive_sha256"], "firmware.source_archive_sha256")
    if receipt and archive["sha256"] != value["source_archive_sha256"]:
        raise ReplacementError("source archive SHA-256 does not match its evidence")


def _profile_for_target(
    manifest: Mapping[str, Any], target_id: str
) -> Mapping[str, Any] | None:
    target = _target(manifest, target_id)
    profile_id = target.get("stock_profile")
    if profile_id is None:
        return None
    for profile in manifest["firmware_profiles"]:
        if profile["id"] == profile_id:
            return profile
    raise ReplacementError(f"target {target_id} cites a missing stock profile")


def _validate_board_profile(
    value: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    manifest: Mapping[str, Any],
    record: Mapping[str, Any],
) -> None:
    if not isinstance(value, dict):
        raise ReplacementError("board_profile must be an object")
    _require_exact_keys(
        value,
        (
            "aup_hw_list",
            "aup_sw_list",
            "boot_flash_device_id",
            "boot_image_capacity_bytes",
            "boot_image_offset_bytes",
            "boot_policy_receipt_id",
            "capabilities",
            "default_posture",
            "id",
            "load_address",
            "profile_evidence_id",
            "profile_sha256",
            "target_id",
            "unit_fingerprint_sha256",
        ),
        "board_profile",
    )
    _identifier(value["id"], "board_profile.id")
    if value["target_id"] != record["target_id"]:
        raise ReplacementError("board profile target does not match receipt")
    if value["unit_fingerprint_sha256"] != record["unit_fingerprint_sha256"]:
        raise ReplacementError("board profile unit does not match receipt")
    if value["boot_policy_receipt_id"] != record["boot_policy_receipt_id"]:
        raise ReplacementError("board profile boot receipt does not match receipt")
    _sha(value["profile_sha256"], "board_profile.profile_sha256")
    profile_evidence = _evidence_ref(
        evidence,
        value["profile_evidence_id"],
        "board_profile_record",
        "board_profile.profile_evidence_id",
    )
    if (
        "sha256" in profile_evidence
        and profile_evidence["sha256"] != value["profile_sha256"]
    ):
        raise ReplacementError("board profile SHA-256 does not match its evidence")
    _identifier(value["boot_flash_device_id"], "board_profile.boot_flash_device_id")
    _int(
        value["boot_image_offset_bytes"],
        "board_profile.boot_image_offset_bytes",
        0,
        boot.MAX_FLASH_BYTES - 1,
    )
    _int(
        value["boot_image_capacity_bytes"],
        "board_profile.boot_image_capacity_bytes",
        1,
        boot.MAX_FLASH_BYTES,
    )
    if (
        _int(
            value["load_address"],
            "board_profile.load_address",
            0,
            0xFFFF_FFFF_FFFF_FFFF,
        )
        != K210_LOAD_BASE
    ):
        raise ReplacementError(
            "board profile load address drifted from measured K210 contract"
        )
    hardware = _validate_tags(value["aup_hw_list"], "board_profile.aup_hw_list")
    software = _validate_tags(value["aup_sw_list"], "board_profile.aup_sw_list")
    held_profile = _profile_for_target(manifest, record["target_id"])
    if held_profile is not None and (
        hardware != held_profile["hw_list"] or software != held_profile["sw_list"]
    ):
        raise ReplacementError(
            "board profile AUP tags do not match the held target profile"
        )
    if value["capabilities"] != list(REQUIRED_BSP_CAPABILITIES):
        raise ReplacementError("board profile capabilities are not the exact BSP set")
    if value["default_posture"] != SAFE_DEFAULTS:
        raise ReplacementError("board profile safe defaults drifted")


def _validate_builds(
    builds: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    completed_at: datetime,
    source_archive_sha256: str,
) -> None:
    if not isinstance(builds, list) or len(builds) != 2:
        raise ReplacementError("builds must contain exactly two independent runs")
    build_ids: set[str] = set()
    host_ids: set[str] = set()
    workspace_ids: set[str] = set()
    referenced_artifacts: set[str] = set()
    referenced_logs: set[str] = set()
    for index, build in enumerate(builds):
        context = f"builds[{index}]"
        if not isinstance(build, dict):
            raise ReplacementError(f"{context} must be an object")
        _require_exact_keys(
            build,
            (
                "aup_evidence_id",
                "build_log_evidence_id",
                "completed_at_utc",
                "elf_evidence_id",
                "environment_sha256",
                "host_id",
                "id",
                "raw_evidence_id",
                "source_archive_sha256",
                "started_at_utc",
                "toolchain_manifest_evidence_id",
                "workspace_id",
            ),
            context,
        )
        build_id = _identifier(build["id"], f"{context}.id")
        host_id = _identifier(build["host_id"], f"{context}.host_id")
        workspace_id = _identifier(build["workspace_id"], f"{context}.workspace_id")
        build_ids.add(build_id)
        host_ids.add(host_id)
        workspace_ids.add(workspace_id)
        started = _utc(build["started_at_utc"], f"{context}.started_at_utc")
        completed = _utc(build["completed_at_utc"], f"{context}.completed_at_utc")
        if started >= completed or completed > completed_at:
            raise ReplacementError(f"{context} chronology is invalid")
        _sha(build["environment_sha256"], f"{context}.environment_sha256")
        if build["source_archive_sha256"] != source_archive_sha256:
            raise ReplacementError(f"{context} source archive digest drifted")
        refs = (
            ("build_log_evidence_id", "reproducibility_log"),
            ("toolchain_manifest_evidence_id", "toolchain_manifest"),
            ("elf_evidence_id", "firmware_elf"),
            ("raw_evidence_id", "firmware_raw"),
            ("aup_evidence_id", "firmware_aup"),
        )
        for key, kind in refs:
            item = _evidence_ref(evidence, build[key], kind, f"{context}.{key}")
            if kind in {"firmware_elf", "firmware_raw", "firmware_aup"}:
                referenced_artifacts.add(item["id"])
            else:
                referenced_logs.add(item["id"])
    if len(build_ids) != 2 or len(host_ids) != 2 or len(workspace_ids) != 2:
        raise ReplacementError("replacement builds are not host/workspace independent")
    if len(referenced_artifacts) != 6 or len(referenced_logs) != 4:
        raise ReplacementError(
            "replacement build evidence references are not independent"
        )


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise ReplacementError("signing must be an object")
    _require_exact_keys(value, ("builder", "reviewer"), "signing")
    expected = {
        "builder": (BUILDER_ROLE, BUILDER_NAMESPACE),
        "reviewer": (REVIEWER_ROLE, REVIEWER_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise ReplacementError(f"signing.{name} must be an object")
        _require_exact_keys(
            item, ("algorithm", "key_id_sha256", "namespace", "role"), f"signing.{name}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["role"] != role
            or item["namespace"] != namespace
        ):
            raise ReplacementError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise ReplacementError("builder and reviewer signing keys must be distinct")


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> None:
    core_keys = (
        "board_profile",
        "boot_policy_receipt_id",
        "builder_id",
        "builds",
        "completed_at_utc",
        "discovery_receipt_id",
        "evidence",
        "firmware",
        "kind",
        "recovery_receipt_id",
        "reviewer_id",
        "schema_version",
        "scope",
        "stock_backup_set_sha256",
        "target_id",
        "unit_fingerprint_sha256",
        "unit_label",
    )
    receipt_only = (
        "artifact_set_sha256",
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "receipt_id",
        "signing",
    )
    _require_exact_keys(
        value, core_keys + receipt_only if receipt else core_keys, "replacement record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise ReplacementError("replacement schema or scope mismatch")
    if value["kind"] != (RECEIPT_KIND if receipt else DESCRIPTOR_KIND):
        raise ReplacementError("replacement record kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    for key in (
        "unit_fingerprint_sha256",
        "discovery_receipt_id",
        "recovery_receipt_id",
        "stock_backup_set_sha256",
        "boot_policy_receipt_id",
    ):
        _sha(value[key], key)
    builder = _principal(value["builder_id"], "builder_id")
    reviewer = _principal(value["reviewer_id"], "reviewer_id")
    if builder == reviewer:
        raise ReplacementError("replacement builder and reviewer must be distinct")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    evidence_rows = _validate_evidence(value["evidence"], hashed=receipt)
    evidence = {item["id"]: item for item in evidence_rows}
    for index, item in enumerate(evidence_rows):
        if (
            _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
            > completed
        ):
            raise ReplacementError(f"evidence[{index}] is after receipt completion")
    _validate_firmware(value["firmware"], evidence, receipt=receipt)
    _validate_board_profile(value["board_profile"], evidence, manifest, value)
    _validate_builds(
        value["builds"],
        evidence,
        completed,
        value["firmware"]["source_archive_sha256"],
    )
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise ReplacementError("replacement authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise ReplacementError("replacement disposition drifted")
        _sha(value["artifact_set_sha256"], "artifact_set_sha256")
        _sha(value["descriptor_sha256"], "descriptor_sha256")
        _sha(value["receipt_id"], "receipt_id")
        _validate_signing(value["signing"])


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "artifact_set_sha256",
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "receipt_id",
        "signing",
    }
    descriptor = {key: value for key, value in receipt.items() if key not in excluded}
    descriptor["kind"] = DESCRIPTOR_KIND
    descriptor["evidence"] = [
        {key: value for key, value in item.items() if key not in ("bytes", "sha256")}
        for item in receipt["evidence"]
    ]
    return descriptor


def _artifact_projection(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence = {item["id"]: item for item in receipt["evidence"]}
    projection = []
    for build in sorted(receipt["builds"], key=lambda item: item["id"]):
        artifacts = []
        for field in ("elf_evidence_id", "raw_evidence_id", "aup_evidence_id"):
            item = evidence[build[field]]
            artifacts.append(
                {
                    "bytes": item["bytes"],
                    "id": item["id"],
                    "kind": item["kind"],
                    "sha256": item["sha256"],
                }
            )
        projection.append({"artifacts": artifacts, "build_id": build["id"]})
    return projection


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _validate_core(receipt, manifest, receipt=True)
    if (
        hashlib.sha256(
            canonical_json_bytes(_descriptor_projection(receipt))
        ).hexdigest()
        != receipt["descriptor_sha256"]
    ):
        raise ReplacementError("replacement descriptor SHA-256 mismatch")
    artifact_digest = hashlib.sha256(
        b"DCENT-K210-REPLACEMENT-ARTIFACT-SET-V1\x00"
        + canonical_json_bytes(_artifact_projection(receipt))
    ).hexdigest()
    if artifact_digest != receipt["artifact_set_sha256"]:
        raise ReplacementError("replacement artifact-set SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    expected_id = hashlib.sha256(
        b"DCENT-K210-REPLACEMENT-RECEIPT-ID-V1\x00" + canonical_json_bytes(without_id)
    ).hexdigest()
    if expected_id != receipt["receipt_id"]:
        raise ReplacementError("replacement receipt ID mismatch")


def _load_boot_copy(
    manifest: Mapping[str, Any], record: Mapping[str, Any], evidence_root: Path
) -> dict[str, Any]:
    copies = [
        item
        for item in record["evidence"]
        if item["kind"] == "boot_policy_receipt_copy"
    ]
    if len(copies) != 1:
        raise ReplacementError("exactly one boot-policy receipt copy is required")
    source = _source(
        evidence_root, _safe_path(copies[0]["path"], "boot receipt evidence path")
    )
    observed = _load_json(source, "boot-policy receipt copy", canonical=True)
    try:
        boot._validate_receipt(observed, manifest)
    except boot.BootPolicyError as exc:
        raise ReplacementError(f"boot-policy receipt copy is invalid: {exc}") from exc
    expected = {
        "receipt_id": record["boot_policy_receipt_id"],
        "discovery_receipt_id": record["discovery_receipt_id"],
        "recovery_receipt_id": record["recovery_receipt_id"],
        "stock_backup_set_sha256": record["stock_backup_set_sha256"],
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
        "unit_label": record["unit_label"],
    }
    for key, wanted in expected.items():
        if observed[key] != wanted:
            raise ReplacementError(
                f"boot-policy receipt copy {key} does not match replacement"
            )
    if (
        observed["security_policy"]["force_decrypt_state"] != "disabled"
        or observed["plaintext_probe"]["plaintext_boot_supported"] is not True
        or observed["flash_policy"]["candidate_load_contract_compatible"] is not True
    ):
        raise ReplacementError(
            "boot-policy receipt is not positive for an AES0 replacement"
        )
    board = record["board_profile"]
    flash = observed["flash_policy"]
    flash_matches = [
        device
        for device in flash["devices"]
        if device["id"] == board["boot_flash_device_id"]
    ]
    if len(flash_matches) != 1:
        raise ReplacementError(
            "board profile boot flash is absent from boot-policy receipt"
        )
    if (
        board["boot_image_offset_bytes"] != flash["boot_image_offset_bytes"]
        or board["boot_image_capacity_bytes"] != flash["boot_image_length_bytes"]
        or board["load_address"] != flash["measured_boot_load_address"]
    ):
        raise ReplacementError(
            "board profile boot geometry does not match boot-policy receipt"
        )
    return observed


def _artifact_sources(
    record: Mapping[str, Any], evidence_root: Path
) -> dict[str, Path]:
    return {
        item["id"]: _source(
            evidence_root, _safe_path(item["path"], f"evidence {item['id']} path")
        )
        for item in record["evidence"]
    }


def _validate_artifacts(
    record: Mapping[str, Any], sources: Mapping[str, Path]
) -> dict[str, str]:
    profile = record["board_profile"]
    firmware = record["firmware"]
    outputs = []
    for build in record["builds"]:
        elf = _read_artifact(
            sources[build["elf_evidence_id"]], f"build {build['id']} ELF"
        )
        raw = _read_artifact(
            sources[build["raw_evidence_id"]], f"build {build['id']} raw image"
        )
        aup = _read_artifact(
            sources[build["aup_evidence_id"]], f"build {build['id']} AUP"
        )
        if not raw or len(raw) > profile["boot_image_capacity_bytes"]:
            raise ReplacementError(
                "replacement raw image does not fit measured boot region"
            )
        elf_result = inspect_single_load_elf(elf, profile["load_address"])
        if (
            elf_result["raw"] != raw
            or elf_result["memory_size"] > profile["boot_image_capacity_bytes"]
        ):
            raise ReplacementError(
                "replacement ELF does not map exactly to the raw image"
            )
        aup_result = inspect_plain_aup(aup)
        if (
            aup_result["app"] != raw
            or aup_result["firmware_version"] != firmware["firmware_version"]
            or aup_result["hardware"] != profile["aup_hw_list"]
            or aup_result["software"] != profile["aup_sw_list"]
            or aup_result["wrapper_bytes"] > profile["boot_image_capacity_bytes"]
        ):
            raise ReplacementError(
                "replacement AUP does not match raw image, profile, or boot region"
            )
        outputs.append(
            {
                "aup": hashlib.sha256(aup).hexdigest(),
                "elf": hashlib.sha256(elf).hexdigest(),
                "raw": hashlib.sha256(raw).hexdigest(),
            }
        )
    if outputs[0] != outputs[1]:
        raise ReplacementError("independent replacement builds are not byte-identical")
    return outputs[0]


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    builder_private_key: Path,
    reviewer_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_core(descriptor, manifest, receipt=False)
    _load_boot_copy(manifest, descriptor, evidence_root)
    sources = _artifact_sources(descriptor, evidence_root)
    evidence_with_hashes = []
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        size, digest = _hash_source(sources[item["id"]], f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise ReplacementError(
                "replacement evidence exceeds the aggregate byte limit"
            )
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
    normalized = json.loads(json.dumps(descriptor))
    normalized["evidence"] = evidence_with_hashes
    normalized["kind"] = RECEIPT_KIND
    try:
        builder_key = discovery.inspect_private_key(builder_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(f"replacement signing key is invalid: {exc}") from exc
    if builder_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise ReplacementError("builder and reviewer private keys must be distinct")
    receipt: dict[str, Any] = {
        **normalized,
        "artifact_set_sha256": "0" * 64,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "descriptor_sha256": "0" * 64,
        "disposition": DISPOSITION,
        "receipt_id": "0" * 64,
        "signing": {
            "builder": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": builder_key["key_id_sha256"],
                "namespace": BUILDER_NAMESPACE,
                "role": BUILDER_ROLE,
            },
            "reviewer": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": reviewer_key["key_id_sha256"],
                "namespace": REVIEWER_NAMESPACE,
                "role": REVIEWER_ROLE,
            },
        },
    }
    _validate_core(receipt, manifest, receipt=True)
    _load_boot_copy(manifest, receipt, evidence_root)
    _validate_artifacts(receipt, sources)
    receipt["artifact_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-REPLACEMENT-ARTIFACT-SET-V1\x00"
        + canonical_json_bytes(_artifact_projection(receipt))
    ).hexdigest()
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-REPLACEMENT-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest)
    return receipt, sources


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    builder_private_key: Path,
    reviewer_private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise ReplacementError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "replacement descriptor", canonical=False)
    receipt, sources = build_receipt(
        manifest,
        descriptor,
        evidence_root,
        builder_private_key,
        reviewer_private_key,
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        destination_root = temporary / EVIDENCE_DIRECTORY
        destination_root.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = destination_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_source(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise ReplacementError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        builder_path = temporary / BUILDER_SIGNATURE_NAME
        reviewer_path = temporary / REVIEWER_SIGNATURE_NAME
        builder_path.write_bytes(
            discovery.sign_sshsig_file(
                receipt_path, builder_private_key, BUILDER_NAMESPACE
            )
        )
        reviewer_path.write_bytes(
            discovery.sign_sshsig_file(
                receipt_path, reviewer_private_key, REVIEWER_NAMESPACE
            )
        )
        builder_key = discovery.inspect_private_key(builder_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
        if (
            builder_key["key_id_sha256"]
            != receipt["signing"]["builder"]["key_id_sha256"]
            or reviewer_key["key_id_sha256"]
            != receipt["signing"]["reviewer"]["key_id_sha256"]
        ):
            raise ReplacementError(
                "a replacement signing key changed during bundle creation"
            )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            builder_path,
            builder_key["canonical_line"],
            receipt["builder_id"],
            BUILDER_NAMESPACE,
        )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            reviewer_path,
            reviewer_key["canonical_line"],
            receipt["reviewer_id"],
            REVIEWER_NAMESPACE,
        )
        _verify_exact_members(temporary, receipt)
        os.replace(temporary, bundle_out.resolve())
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return receipt


def verify_bundle(
    manifest: Mapping[str, Any],
    bundle: Path,
    builder_public_key: Path,
    reviewer_public_key: Path,
    expected_builder_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise ReplacementError(
            f"replacement bundle cannot be inspected: {exc}"
        ) from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ReplacementError("replacement bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "replacement receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    _load_boot_copy(manifest, receipt, bundle / EVIDENCE_DIRECTORY)
    try:
        builder_key = discovery.inspect_public_key(builder_public_key)
        reviewer_key = discovery.inspect_public_key(reviewer_public_key)
    except discovery.DiscoveryError as exc:
        raise ReplacementError(f"replacement trust key is invalid: {exc}") from exc
    if builder_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise ReplacementError("builder and reviewer trust keys must be distinct")
    try:
        receipt_raw = discovery._read_regular(
            receipt_path, "replacement receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise ReplacementError(str(exc)) from exc
    if receipt_raw != canonical_json_bytes(receipt):
        raise ReplacementError("replacement receipt changed after validation")
    expected = (
        (
            "builder",
            builder_key,
            expected_builder_key_id,
            bundle / BUILDER_SIGNATURE_NAME,
            receipt["builder_id"],
            BUILDER_NAMESPACE,
        ),
        (
            "reviewer",
            reviewer_key,
            expected_reviewer_key_id,
            bundle / REVIEWER_SIGNATURE_NAME,
            receipt["reviewer_id"],
            REVIEWER_NAMESPACE,
        ),
    )
    for role, key, pinned, signature_path, principal, namespace in expected:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise ReplacementError(
                f"{role} public key does not match the manifest trust anchor"
            )
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise ReplacementError(f"replacement receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw, signature_path, key["canonical_line"], principal, namespace
            )
        except discovery.DiscoveryError as exc:
            raise ReplacementError(
                f"replacement {role} signature is invalid: {exc}"
            ) from exc
    total = 0
    sources = _artifact_sources(receipt, bundle / EVIDENCE_DIRECTORY)
    for item in receipt["evidence"]:
        size, digest = _hash_source(sources[item["id"]], f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise ReplacementError(
                "replacement evidence exceeds the aggregate byte limit"
            )
        if size != item["bytes"] or digest != item["sha256"]:
            raise ReplacementError(f"evidence {item['id']} digest or size mismatch")
    artifact_hashes = _validate_artifacts(receipt, sources)
    _verify_exact_members(bundle, receipt)
    profile_digest = hashlib.sha256(
        b"DCENT-K210-BOARD-PROFILE-V1\x00"
        + canonical_json_bytes(receipt["board_profile"])
    ).hexdigest()
    return {
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "aup_sha256": artifact_hashes["aup"],
        "authority_granted": False,
        "board_profile_sha256": profile_digest,
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "elf_sha256": artifact_hashes["elf"],
        "firmware_version": receipt["firmware"]["firmware_version"],
        "raw_sha256": artifact_hashes["raw"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "replacement_firmware_gate_eligible": True,
        "source_archive_sha256": receipt["firmware"]["source_archive_sha256"],
        "state": "verified_signed_replacement_firmware",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "builder_key_id_sha256": builder_key["key_id_sha256"],
        "reviewer_key_id_sha256": reviewer_key["key_id_sha256"],
    }


def _verify_exact_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_files = {RECEIPT_NAME, BUILDER_SIGNATURE_NAME, REVIEWER_SIGNATURE_NAME}
    expected_directories = {EVIDENCE_DIRECTORY}
    for item in receipt["evidence"]:
        relative = PurePosixPath(EVIDENCE_DIRECTORY) / _safe_path(
            item["path"], f"evidence {item['id']} path"
        )
        expected_files.add(str(relative))
        expected_directories.update(str(parent) for parent in relative.parents)
    expected_directories.discard(".")
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    pending = [(bundle, PurePosixPath())]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise ReplacementError(
                f"replacement bundle cannot be enumerated: {exc}"
            ) from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReplacementError(
                    f"replacement bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise ReplacementError(
                    f"replacement bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise ReplacementError(
                    f"replacement bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ReplacementError("replacement bundle member set is not exact")


def _template(manifest: Mapping[str, Any], boot_receipt_path: Path) -> dict[str, Any]:
    observed = _load_json(boot_receipt_path, "boot-policy receipt", canonical=True)
    try:
        boot._validate_receipt(observed, manifest)
    except boot.BootPolicyError as exc:
        raise ReplacementError(f"boot-policy receipt is invalid: {exc}") from exc
    if (
        observed["security_policy"]["force_decrypt_state"] != "disabled"
        or observed["plaintext_probe"]["plaintext_boot_supported"] is not True
        or observed["flash_policy"]["candidate_load_contract_compatible"] is not True
    ):
        raise ReplacementError("template requires a positive AES0 boot-policy receipt")
    target = _target(manifest, observed["target_id"])
    profile = _profile_for_target(manifest, observed["target_id"])
    hardware = profile["hw_list"] if profile else [f"hw-{target['id']}"]
    software = profile["sw_list"] if profile else ["mm3"]
    flash = observed["flash_policy"]
    evidence_specs = (
        (
            "boot-policy-receipt",
            "boot_policy_receipt_copy",
            "identity/boot-policy-receipt.json",
            "application/json",
            "offline_artifact",
        ),
        (
            "board-profile",
            "board_profile_record",
            "source/board-profile.json",
            "application/json",
            "review_attestation",
        ),
        (
            "source-archive",
            "source_archive",
            "source/source.tar",
            "application/x-tar",
            "offline_artifact",
        ),
        (
            "source-manifest",
            "source_manifest",
            "source/source-manifest.json",
            "application/json",
            "offline_artifact",
        ),
        (
            "sbom",
            "sbom",
            "review/sbom.spdx.json",
            "application/spdx+json",
            "review_attestation",
        ),
        (
            "license-review",
            "license_review",
            "review/license-review.json",
            "application/json",
            "review_attestation",
        ),
        (
            "clean-room-review",
            "clean_room_review",
            "review/clean-room-review.json",
            "application/json",
            "review_attestation",
        ),
    )
    evidence = []
    for evidence_id, kind, path, media_type, method in evidence_specs:
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T00:40:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": media_type,
                "method": method,
                "path": path,
                "redaction": "none",
            }
        )
    builds = []
    for suffix, minute in (("a", "10"), ("b", "20")):
        rows = (
            (
                f"build-{suffix}-log",
                "reproducibility_log",
                f"build-{suffix}/build.json",
                "application/json",
            ),
            (
                f"build-{suffix}-toolchain",
                "toolchain_manifest",
                f"build-{suffix}/toolchain.json",
                "application/json",
            ),
            (
                f"build-{suffix}-elf",
                "firmware_elf",
                f"build-{suffix}/firmware.elf",
                "application/octet-stream",
            ),
            (
                f"build-{suffix}-raw",
                "firmware_raw",
                f"build-{suffix}/firmware.bin",
                "application/octet-stream",
            ),
            (
                f"build-{suffix}-aup",
                "firmware_aup",
                f"build-{suffix}/firmware.aup",
                "application/octet-stream",
            ),
        )
        for evidence_id, kind, path, media_type in rows:
            evidence.append(
                {
                    "acquired_at_utc": f"2026-01-01T00:{minute}:00Z",
                    "id": evidence_id,
                    "kind": kind,
                    "media_type": media_type,
                    "method": "independent_offline_build",
                    "path": path,
                    "redaction": "none",
                }
            )
        builds.append(
            {
                "aup_evidence_id": f"build-{suffix}-aup",
                "build_log_evidence_id": f"build-{suffix}-log",
                "completed_at_utc": f"2026-01-01T00:{minute}:00Z",
                "elf_evidence_id": f"build-{suffix}-elf",
                "environment_sha256": "0" * 64,
                "host_id": f"replace-host-{suffix}",
                "id": f"build-{suffix}",
                "raw_evidence_id": f"build-{suffix}-raw",
                "source_archive_sha256": "0" * 64,
                "started_at_utc": f"2026-01-01T00:0{5 if suffix == 'a' else 6}:00Z",
                "toolchain_manifest_evidence_id": f"build-{suffix}-toolchain",
                "workspace_id": f"replace-workspace-{suffix}",
            }
        )
    board_profile = {
        "aup_hw_list": hardware,
        "aup_sw_list": software,
        "boot_flash_device_id": flash["boot_flash_device_id"],
        "boot_image_capacity_bytes": flash["boot_image_length_bytes"],
        "boot_image_offset_bytes": flash["boot_image_offset_bytes"],
        "boot_policy_receipt_id": observed["receipt_id"],
        "capabilities": list(REQUIRED_BSP_CAPABILITIES),
        "default_posture": dict(SAFE_DEFAULTS),
        "id": f"{observed['target_id']}-replace-profile",
        "load_address": flash["measured_boot_load_address"],
        "profile_evidence_id": "board-profile",
        "profile_sha256": "0" * 64,
        "target_id": observed["target_id"],
        "unit_fingerprint_sha256": observed["unit_fingerprint_sha256"],
    }
    descriptor = {
        "board_profile": board_profile,
        "boot_policy_receipt_id": observed["receipt_id"],
        "builder_id": "REPLACE",
        "builds": builds,
        "completed_at_utc": "2026-01-01T00:50:00Z",
        "discovery_receipt_id": observed["discovery_receipt_id"],
        "evidence": evidence,
        "firmware": {
            "clean_room_review_evidence_id": "clean-room-review",
            "firmware_class": "target_bound_safe_idle_runtime",
            "firmware_version": "20260101_dcent_replace",
            "license_review_evidence_id": "license-review",
            "restricted_vendor_code_included": False,
            "sbom_evidence_id": "sbom",
            "source_archive_evidence_id": "source-archive",
            "source_archive_sha256": "0" * 64,
            "source_commit": "0" * 40,
            "source_dirty": False,
            "source_license": "GPL-3.0-only",
            "source_manifest_evidence_id": "source-manifest",
            "third_party_license_review_passed": True,
            "vendor_binary_blob_included": False,
        },
        "kind": DESCRIPTOR_KIND,
        "recovery_receipt_id": observed["recovery_receipt_id"],
        "reviewer_id": "REPLACE-REVIEWER",
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "stock_backup_set_sha256": observed["stock_backup_set_sha256"],
        "target_id": observed["target_id"],
        "unit_fingerprint_sha256": observed["unit_fingerprint_sha256"],
        "unit_label": observed["unit_label"],
    }
    _validate_core(descriptor, manifest, receipt=False)
    return descriptor


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser(
        "template", help="write a descriptor bound to a positive boot receipt"
    )
    template.add_argument("--boot-policy-receipt", type=Path, required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign reproducible replacement evidence"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--builder-private-key", type=Path, required=True)
    create.add_argument("--reviewer-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed replacement bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--builder-public-key", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    verify.add_argument("--expected-builder-key-id")
    verify.add_argument("--expected-reviewer-key-id")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
        if args.command == "template":
            descriptor = _template(manifest, args.boot_policy_receipt)
            try:
                discovery._write_new(
                    args.out,
                    (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode(
                        "ascii"
                    ),
                    "replacement descriptor template",
                )
            except discovery.DiscoveryError as exc:
                raise ReplacementError(str(exc)) from exc
            print(
                f"K210_REPLACEMENT_TEMPLATE_WRITTEN target={descriptor['target_id']} path={args.out}"
            )
            return 0
        if args.command == "create":
            receipt = create_bundle(
                manifest,
                args.descriptor,
                args.evidence_root,
                args.builder_private_key,
                args.reviewer_private_key,
                args.bundle_out,
            )
            print(
                f"K210_REPLACEMENT_BUNDLE_CREATED target={receipt['target_id']} receipt_id={receipt['receipt_id']} disposition={receipt['disposition']}"
            )
            return 0
        for label, value in (
            ("--expected-builder-key-id", args.expected_builder_key_id),
            ("--expected-reviewer-key-id", args.expected_reviewer_key_id),
        ):
            if value is not None and not HEX64_RE.fullmatch(value):
                raise ReplacementError(f"{label} must be lowercase SHA-256 hex")
        result = verify_bundle(
            manifest,
            args.bundle,
            args.builder_public_key,
            args.reviewer_public_key,
            args.expected_builder_key_id,
            args.expected_reviewer_key_id,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (
        ReplacementError,
        boot.BootPolicyError,
        recovery.RecoveryError,
        discovery.DiscoveryError,
    ) as exc:
        print(f"K210_REPLACEMENT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
