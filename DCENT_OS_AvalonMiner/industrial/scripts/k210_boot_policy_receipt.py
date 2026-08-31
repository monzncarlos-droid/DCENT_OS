#!/usr/bin/env python3
"""Create and verify signed Avalon K210 boot-policy measurement bundles.

This tool is host-only and has no miner, programmer, serial, USB, JTAG, GPIO,
power, flash, or block-device transport. It snapshots caller-supplied evidence
from a completed, separately authorized exact-unit measurement. A valid bundle
may record a positive or negative compatibility result and grants no authority
for future contact, mutation, installation, hashing, or release.
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
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_recovery_module():
    path = Path(__file__).with_name("k210_recovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_recovery_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 recovery primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = _load_recovery_module()
discovery = recovery.discovery

SCHEMA_VERSION = 1
SCOPE = recovery.SCOPE
DESCRIPTOR_KIND = "dcent_k210_boot_policy_descriptor"
RECEIPT_KIND = "dcent_k210_boot_policy_receipt"
DISPOSITION = "past_boot_policy_measurement_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_boot_policy_operator"
WITNESS_ROLE = "k210_boot_policy_witness"
OPERATOR_NAMESPACE = "dcent-k210-boot-operator-v1"
WITNESS_NAMESPACE = "dcent-k210-boot-witness-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM
MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 64
MAX_EVIDENCE_FILE_BYTES = discovery.MAX_EVIDENCE_FILE_BYTES
MAX_TOTAL_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FLASH_DEVICES = recovery.MAX_FLASH_DEVICES
MAX_FLASH_BYTES = recovery.MAX_FLASH_BYTES
MAX_FLASH_REGIONS = 128
K210_CANDIDATE_LOAD_ADDRESS = 0x80000000

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

BOOT_POLICY_ACTIONS = {
    "controller_boot_observation",
    "controller_flash_map_read",
    "controller_jtag_probe",
    "controller_rom_isp_probe",
    "controller_security_policy_measurement",
    "controlled_aes0_boot_probe",
    "power_cycle_for_measurement",
    "stock_flash_restore",
}
BASE_ACTIONS_PERFORMED = {
    "controller_boot_observed": True,
    "controller_flash_map_read": True,
    "controller_jtag_probed": True,
    "controller_rom_isp_probed": True,
    "controller_security_policy_measured": True,
    "hash_power_energized": False,
    "production_hashing_commanded": False,
    "stock_state_verified_after_measurement": True,
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_future_flash_write": False,
    "authorizes_future_jtag_or_isp_access": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_install": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}
REQUIRED_EVIDENCE_KINDS = (
    "efuse_record",
    "flash_map_record",
    "jtag_record",
    "load_address_record",
    "plaintext_probe_record",
    "recovery_receipt_copy",
    "rom_isp_record",
    "safety_isolation_record",
    "stock_postboot_record",
    "stock_preboot_record",
)
EVIDENCE_KINDS = set(REQUIRED_EVIDENCE_KINDS) | {
    "plaintext_probe_artifact",
    "updater_parser_record",
}
MEDIA_TYPES = {
    "application/json",
    "application/octet-stream",
    "image/jpeg",
    "image/png",
    "text/plain",
}
EVIDENCE_METHODS = {
    "authorized_boot_policy_measurement",
    "offline_artifact",
    "visual_inspection",
}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}
FLASH_TECHNOLOGIES = {"emmc", "spi_nand", "spi_nor"}
FLASH_REGION_ROLES = {
    "boot_image",
    "calibration",
    "other_stock",
    "persistent_config",
    "unallocated",
    "updater_staging",
}
FORCE_DECRYPT_STATES = {"disabled", "enabled"}
SECURITY_MEASUREMENT_METHODS = {"controlled_plaintext_probe", "direct_efuse_read"}
OTP_BOOT_KEY_STATES = {"not_directly_readable", "not_provisioned", "provisioned"}
ACCESS_STATES = {"accessible", "locked", "not_bonded"}
PLAINTEXT_DELIVERIES = {
    "direct_external_memory_restore",
    "not_performed",
    "stock_aup_update",
}
PLAINTEXT_RESULTS = {
    "booted",
    "not_run_force_decrypt_enabled",
    "rejected_by_boot_policy",
    "rejected_by_updater",
}
PLAINTEXT_OBSERVATIONS = {
    "direct_policy",
    "jtag_program_counter",
    "logic_analyzer",
    "uart_beacon",
}


class BootPolicyError(RuntimeError):
    """A boot-policy descriptor, bundle, or evidence invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], context: str
) -> None:
    actual = set(value)
    wanted = set(expected)
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        raise BootPolicyError(f"{context} keys invalid: {'; '.join(detail)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BootPolicyError(
            f"{context} must be a non-empty string <= {maximum} chars"
        )
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise BootPolicyError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise BootPolicyError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not PRINCIPAL_RE.fullmatch(text):
        raise BootPolicyError(f"{context} is not a canonical signer principal")
    return text


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise BootPolicyError(f"{context} must be lowercase SHA-256")
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise BootPolicyError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise BootPolicyError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise BootPolicyError(f"{context} must be boolean")
    return value


def _int(value: Any, context: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise BootPolicyError(f"{context} must be an integer in {minimum}..{maximum}")
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise BootPolicyError(f"{context} must be a portable POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise BootPolicyError(f"{context} must be a canonical relative path")
    if any(part in ("", ".", "..") for part in path.parts):
        raise BootPolicyError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(str(exc)) from exc


def _evidence_ref(
    evidence: Mapping[str, Mapping[str, Any]],
    evidence_id: Any,
    kind: str,
    context: str,
) -> Mapping[str, Any]:
    canonical = _identifier(evidence_id, context)
    item = evidence.get(canonical)
    if item is None or item["kind"] != kind:
        raise BootPolicyError(f"{context} must reference {kind} evidence")
    return item


def _validate_evidence(evidence: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        raise BootPolicyError(f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records")
    ids: set[str] = set()
    paths: set[str] = set()
    kinds: dict[str, int] = {}
    normalized = []
    for index, item in enumerate(evidence):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise BootPolicyError(f"{context} must be an object")
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
            raise BootPolicyError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise BootPolicyError(f"{context}.kind is unsupported")
        kinds[kind] = kinds.get(kind, 0) + 1
        if item["media_type"] not in MEDIA_TYPES:
            raise BootPolicyError(f"{context}.media_type is unsupported")
        if item["method"] not in EVIDENCE_METHODS:
            raise BootPolicyError(f"{context}.method is unsupported")
        if item["redaction"] not in REDACTION_STATES:
            raise BootPolicyError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise BootPolicyError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _int(item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    for kind in REQUIRED_EVIDENCE_KINDS:
        if kinds.get(kind) != 1:
            raise BootPolicyError(f"exactly one {kind} evidence record is required")
    if kinds.get("plaintext_probe_artifact", 0) > 1:
        raise BootPolicyError("at most one plaintext_probe_artifact is permitted")
    return normalized


def _validate_stock_identity(value: Any) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError("stock_identity must be an object")
    _require_exact_keys(
        value,
        ("stock_dna", "stock_firmware_version", "stock_hwtype", "stock_swtype"),
        "stock_identity",
    )
    for key in value:
        _text(value[key], f"stock_identity.{key}", 128)


def _validate_safety(value: Any, evidence: Mapping[str, Mapping[str, Any]]) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError("safety_isolation must be an object")
    _require_exact_keys(
        value,
        (
            "controller_only_power",
            "cooling_safe_for_controller_only",
            "evidence_id",
            "hash_power_physical_disconnect_verified",
            "independent_hash_power_cutoff_asserted",
        ),
        "safety_isolation",
    )
    for key in (
        "controller_only_power",
        "cooling_safe_for_controller_only",
        "hash_power_physical_disconnect_verified",
        "independent_hash_power_cutoff_asserted",
    ):
        if _bool(value[key], f"safety_isolation.{key}") is not True:
            raise BootPolicyError(f"safety_isolation.{key} must be true")
    _evidence_ref(
        evidence,
        value["evidence_id"],
        "safety_isolation_record",
        "safety_isolation.evidence_id",
    )


def _validate_flash_policy(
    value: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    recovery_flash_devices: Mapping[str, Mapping[str, Any]] | None,
) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError("flash_policy must be an object")
    _require_exact_keys(
        value,
        (
            "boot_flash_device_id",
            "boot_image_length_bytes",
            "boot_image_offset_bytes",
            "candidate_load_address",
            "candidate_load_contract_compatible",
            "devices",
            "flash_map_evidence_id",
            "load_address_evidence_id",
            "measured_boot_load_address",
        ),
        "flash_policy",
    )
    _evidence_ref(
        evidence,
        value["flash_map_evidence_id"],
        "flash_map_record",
        "flash_policy.flash_map_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["load_address_evidence_id"],
        "load_address_record",
        "flash_policy.load_address_evidence_id",
    )
    candidate_address = _int(
        value["candidate_load_address"],
        "flash_policy.candidate_load_address",
        0,
        0xFFFF_FFFF_FFFF_FFFF,
    )
    if candidate_address != K210_CANDIDATE_LOAD_ADDRESS:
        raise BootPolicyError(
            "candidate load address drifted from the desk-only K210 contract"
        )
    measured_address = _int(
        value["measured_boot_load_address"],
        "flash_policy.measured_boot_load_address",
        0,
        0xFFFF_FFFF_FFFF_FFFF,
    )
    compatible = _bool(
        value["candidate_load_contract_compatible"],
        "flash_policy.candidate_load_contract_compatible",
    )
    if compatible != (measured_address == candidate_address):
        raise BootPolicyError(
            "candidate load compatibility does not match measured address"
        )
    devices = value["devices"]
    if not isinstance(devices, list) or not 1 <= len(devices) <= MAX_FLASH_DEVICES:
        raise BootPolicyError(
            f"flash_policy.devices must contain 1..{MAX_FLASH_DEVICES} devices"
        )
    observed: dict[str, Mapping[str, Any]] = {}
    boot_regions: list[tuple[str, int, int]] = []
    for index, device in enumerate(devices):
        context = f"flash_policy.devices[{index}]"
        if not isinstance(device, dict):
            raise BootPolicyError(f"{context} must be an object")
        _require_exact_keys(
            device,
            ("capacity_bytes", "id", "manufacturer", "model", "regions", "technology"),
            context,
        )
        device_id = _identifier(device["id"], f"{context}.id")
        if device_id in observed:
            raise BootPolicyError("flash-policy device IDs must be unique")
        capacity = _int(
            device["capacity_bytes"], f"{context}.capacity_bytes", 1, MAX_FLASH_BYTES
        )
        if device["technology"] not in FLASH_TECHNOLOGIES:
            raise BootPolicyError(f"{context}.technology is unsupported")
        _text(device["manufacturer"], f"{context}.manufacturer", 80)
        _text(device["model"], f"{context}.model", 80)
        regions = device["regions"]
        if not isinstance(regions, list) or not 1 <= len(regions) <= MAX_FLASH_REGIONS:
            raise BootPolicyError(
                f"{context}.regions must contain 1..{MAX_FLASH_REGIONS} records"
            )
        cursor = 0
        for region_index, region in enumerate(regions):
            region_context = f"{context}.regions[{region_index}]"
            if not isinstance(region, dict):
                raise BootPolicyError(f"{region_context} must be an object")
            _require_exact_keys(
                region,
                ("label", "length_bytes", "offset_bytes", "role"),
                region_context,
            )
            offset = _int(
                region["offset_bytes"],
                f"{region_context}.offset_bytes",
                0,
                capacity - 1,
            )
            length = _int(
                region["length_bytes"], f"{region_context}.length_bytes", 1, capacity
            )
            if offset != cursor or offset + length > capacity:
                raise BootPolicyError(
                    f"{context}.regions must be ordered, contiguous, and in bounds"
                )
            if region["role"] not in FLASH_REGION_ROLES:
                raise BootPolicyError(f"{region_context}.role is unsupported")
            _text(region["label"], f"{region_context}.label", 80)
            if region["role"] == "boot_image":
                boot_regions.append((device_id, offset, length))
            cursor += length
        if cursor != capacity:
            raise BootPolicyError(f"{context}.regions do not cover the full device")
        observed[device_id] = device
    if recovery_flash_devices is not None:
        if set(observed) != set(recovery_flash_devices):
            raise BootPolicyError("flash-policy devices do not match recovery devices")
        for device_id, device in observed.items():
            recovered = recovery_flash_devices[device_id]
            for key in ("capacity_bytes", "manufacturer", "model", "technology"):
                if device[key] != recovered[key]:
                    raise BootPolicyError(
                        f"flash-policy {device_id}.{key} does not match recovery"
                    )
    boot_device = _identifier(
        value["boot_flash_device_id"], "flash_policy.boot_flash_device_id"
    )
    boot_offset = _int(
        value["boot_image_offset_bytes"],
        "flash_policy.boot_image_offset_bytes",
        0,
        MAX_FLASH_BYTES - 1,
    )
    boot_length = _int(
        value["boot_image_length_bytes"],
        "flash_policy.boot_image_length_bytes",
        1,
        MAX_FLASH_BYTES,
    )
    if (boot_device, boot_offset, boot_length) not in boot_regions:
        raise BootPolicyError(
            "declared boot image does not match a measured boot_image region"
        )


def _validate_access_policy(
    value: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    *,
    kind: str,
) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError(f"{kind}_policy must be an object")
    if kind == "rom_isp":
        keys = (
            "erase_capable",
            "evidence_id",
            "existing_flash_independent",
            "read_capable",
            "state",
            "transport",
            "write_capable",
        )
    else:
        keys = (
            "evidence_id",
            "halt_capable",
            "idcode",
            "read_memory_capable",
            "state",
            "transport",
            "write_memory_capable",
        )
    _require_exact_keys(value, keys, f"{kind}_policy")
    state = value["state"]
    if state not in ACCESS_STATES:
        raise BootPolicyError(f"{kind}_policy.state is unsupported")
    _text(value["transport"], f"{kind}_policy.transport", 96)
    _evidence_ref(
        evidence, value["evidence_id"], f"{kind}_record", f"{kind}_policy.evidence_id"
    )
    if kind == "rom_isp":
        capabilities = [
            _bool(value[name], f"rom_isp_policy.{name}")
            for name in (
                "erase_capable",
                "existing_flash_independent",
                "read_capable",
                "write_capable",
            )
        ]
        if state != "accessible" and any(capabilities):
            raise BootPolicyError("inaccessible ROM ISP cannot claim capabilities")
        if state == "accessible" and not value["existing_flash_independent"]:
            raise BootPolicyError(
                "accessible ROM ISP must be existing-flash-independent"
            )
    else:
        capabilities = [
            _bool(value[name], f"jtag_policy.{name}")
            for name in ("halt_capable", "read_memory_capable", "write_memory_capable")
        ]
        idcode = value["idcode"]
        if idcode is not None:
            _text(idcode, "jtag_policy.idcode", 32)
        if state != "accessible" and (any(capabilities) or idcode is not None):
            raise BootPolicyError(
                "inaccessible JTAG cannot claim an IDCODE or capabilities"
            )
        if state == "accessible" and idcode is None:
            raise BootPolicyError("accessible JTAG must record an IDCODE")


def _validate_security_policy(
    value: Any, evidence: Mapping[str, Mapping[str, Any]]
) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise BootPolicyError("security_policy must be an object")
    _require_exact_keys(
        value,
        (
            "evidence_id",
            "force_decrypt_state",
            "measurement_method",
            "otp_boot_key_state",
        ),
        "security_policy",
    )
    state = value["force_decrypt_state"]
    if state not in FORCE_DECRYPT_STATES:
        raise BootPolicyError("security_policy.force_decrypt_state is unsupported")
    method = value["measurement_method"]
    if method not in SECURITY_MEASUREMENT_METHODS:
        raise BootPolicyError("security_policy.measurement_method is unsupported")
    if value["otp_boot_key_state"] not in OTP_BOOT_KEY_STATES:
        raise BootPolicyError("security_policy.otp_boot_key_state is unsupported")
    _evidence_ref(
        evidence, value["evidence_id"], "efuse_record", "security_policy.evidence_id"
    )
    return state, method


def _validate_plaintext_probe(
    value: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    force_decrypt_state: str,
    security_measurement_method: str,
    actions: Mapping[str, Any],
) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError("plaintext_probe must be an object")
    _require_exact_keys(
        value,
        (
            "aes_enable",
            "artifact_evidence_id",
            "delivery",
            "evidence_id",
            "observation_method",
            "performed",
            "plaintext_boot_supported",
            "result",
            "stock_flash_restored_after_measurement",
            "stock_identity_matched_after_measurement",
            "stock_postboot_evidence_id",
            "stock_preboot_evidence_id",
            "stock_state_verified_after_measurement",
        ),
        "plaintext_probe",
    )
    performed = _bool(value["performed"], "plaintext_probe.performed")
    if value["aes_enable"] != 0:
        raise BootPolicyError("plaintext_probe.aes_enable must be zero")
    delivery = value["delivery"]
    result = value["result"]
    observation = value["observation_method"]
    if delivery not in PLAINTEXT_DELIVERIES:
        raise BootPolicyError("plaintext_probe.delivery is unsupported")
    if result not in PLAINTEXT_RESULTS:
        raise BootPolicyError("plaintext_probe.result is unsupported")
    if observation not in PLAINTEXT_OBSERVATIONS:
        raise BootPolicyError("plaintext_probe.observation_method is unsupported")
    _evidence_ref(
        evidence,
        value["evidence_id"],
        "plaintext_probe_record",
        "plaintext_probe.evidence_id",
    )
    _evidence_ref(
        evidence,
        value["stock_preboot_evidence_id"],
        "stock_preboot_record",
        "plaintext_probe.stock_preboot_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["stock_postboot_evidence_id"],
        "stock_postboot_record",
        "plaintext_probe.stock_postboot_evidence_id",
    )
    if (
        _bool(
            value["stock_state_verified_after_measurement"],
            "plaintext_probe.stock_state_verified_after_measurement",
        )
        is not True
    ):
        raise BootPolicyError("stock state must be verified after measurement")
    if (
        _bool(
            value["stock_identity_matched_after_measurement"],
            "plaintext_probe.stock_identity_matched_after_measurement",
        )
        is not True
    ):
        raise BootPolicyError("stock identity must match after measurement")
    supported = _bool(
        value["plaintext_boot_supported"], "plaintext_probe.plaintext_boot_supported"
    )
    if supported != (result == "booted"):
        raise BootPolicyError("plaintext boot support does not match the probe result")
    artifact_id = value["artifact_evidence_id"]
    if performed:
        if (
            delivery == "not_performed"
            or result == "not_run_force_decrypt_enabled"
            or observation == "direct_policy"
        ):
            raise BootPolicyError(
                "performed plaintext probe has a non-performed outcome"
            )
        if force_decrypt_state == "enabled" and result != "rejected_by_boot_policy":
            raise BootPolicyError(
                "force-decrypt enabled can only record a rejected plaintext probe"
            )
        _evidence_ref(
            evidence,
            artifact_id,
            "plaintext_probe_artifact",
            "plaintext_probe.artifact_evidence_id",
        )
    else:
        if force_decrypt_state != "enabled":
            raise BootPolicyError(
                "force-decrypt disabled requires a measured plaintext probe"
            )
        if (
            delivery != "not_performed"
            or result != "not_run_force_decrypt_enabled"
            or observation != "direct_policy"
            or artifact_id is not None
        ):
            raise BootPolicyError(
                "unperformed plaintext probe is not the canonical force-decrypt outcome"
            )
        if security_measurement_method != "direct_efuse_read":
            raise BootPolicyError(
                "an unperformed plaintext probe requires a direct eFuse measurement"
            )
    if security_measurement_method == "controlled_plaintext_probe" and not performed:
        raise BootPolicyError(
            "controlled_plaintext_probe measurement requires a performed probe"
        )
    if actions["controlled_aes0_boot_probe_performed"] != performed:
        raise BootPolicyError("actions_performed disagrees with plaintext probe")
    if actions["custom_firmware_written"] != performed:
        raise BootPolicyError(
            "custom firmware write disclosure disagrees with plaintext probe"
        )
    restored = _bool(
        value["stock_flash_restored_after_measurement"],
        "plaintext_probe.stock_flash_restored_after_measurement",
    )
    if (
        restored != performed
        or actions["stock_flash_restored_after_measurement"] != restored
    ):
        raise BootPolicyError(
            "stock flash restore disclosure disagrees with plaintext probe"
        )


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise BootPolicyError("signing must be an object")
    _require_exact_keys(value, ("operator", "witness"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "witness": (WITNESS_ROLE, WITNESS_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise BootPolicyError(f"signing.{name} must be an object")
        _require_exact_keys(
            item, ("algorithm", "key_id_sha256", "namespace", "role"), f"signing.{name}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["role"] != role
            or item["namespace"] != namespace
        ):
            raise BootPolicyError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise BootPolicyError("operator and witness signing keys must be distinct")


def _validate_core(
    value: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    receipt: bool,
    recovery_flash_devices: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    core_keys = (
        "actions_performed",
        "authorization",
        "completed_at_utc",
        "discovery_receipt_id",
        "evidence",
        "flash_policy",
        "jtag_policy",
        "kind",
        "operator_id",
        "plaintext_probe",
        "recovery_receipt_id",
        "rom_isp_policy",
        "safety_isolation",
        "schema_version",
        "scope",
        "security_policy",
        "started_at_utc",
        "stock_backup_set_sha256",
        "stock_identity",
        "target_id",
        "unit_fingerprint_sha256",
        "unit_label",
        "witness_id",
    )
    receipt_only = (
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "receipt_id",
        "signing",
    )
    _require_exact_keys(
        value, core_keys + receipt_only if receipt else core_keys, "boot-policy record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise BootPolicyError("boot-policy schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind:
        raise BootPolicyError("boot-policy record kind mismatch")
    _target(manifest, _identifier(value["target_id"], "target_id"))
    _identifier(value["unit_label"], "unit_label")
    _sha(value["unit_fingerprint_sha256"], "unit_fingerprint_sha256")
    _sha(value["discovery_receipt_id"], "discovery_receipt_id")
    _sha(value["recovery_receipt_id"], "recovery_receipt_id")
    _sha(value["stock_backup_set_sha256"], "stock_backup_set_sha256")
    operator = _principal(value["operator_id"], "operator_id")
    witness = _principal(value["witness_id"], "witness_id")
    if operator == witness:
        raise BootPolicyError("boot-policy operator and witness must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise BootPolicyError("boot-policy start must precede completion")
    actions = value["actions_performed"]
    if not isinstance(actions, dict):
        raise BootPolicyError("actions_performed must be an object")
    expected_action_keys = set(BASE_ACTIONS_PERFORMED) | {
        "controlled_aes0_boot_probe_performed",
        "custom_firmware_written",
        "stock_flash_restored_after_measurement",
    }
    if set(actions) != expected_action_keys:
        raise BootPolicyError("actions_performed keys drifted")
    for key, expected in BASE_ACTIONS_PERFORMED.items():
        if actions[key] is not expected:
            raise BootPolicyError(f"actions_performed.{key} drifted")
    for key in (
        "controlled_aes0_boot_probe_performed",
        "custom_firmware_written",
        "stock_flash_restored_after_measurement",
    ):
        _bool(actions[key], f"actions_performed.{key}")
    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise BootPolicyError("authorization must be an object")
    _require_exact_keys(
        authorization,
        (
            "authorized_actions",
            "operator_reference",
            "valid_from_utc",
            "valid_until_utc",
        ),
        "authorization",
    )
    _text(authorization["operator_reference"], "authorization.operator_reference", 160)
    valid_from = _utc(authorization["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(
        authorization["valid_until_utc"], "authorization.valid_until_utc"
    )
    if (
        valid_from >= valid_until
        or not valid_from <= started < completed <= valid_until
    ):
        raise BootPolicyError(
            "boot-policy measurement is outside the authorization interval"
        )
    authorized_actions = authorization["authorized_actions"]
    if (
        not isinstance(authorized_actions, list)
        or set(authorized_actions) != BOOT_POLICY_ACTIONS
        or len(authorized_actions) != len(BOOT_POLICY_ACTIONS)
    ):
        raise BootPolicyError(
            "authorization does not contain the exact boot-policy action set"
        )
    evidence_rows = _validate_evidence(value["evidence"], hashed=receipt)
    evidence = {item["id"]: item for item in evidence_rows}
    for index, item in enumerate(evidence_rows):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise BootPolicyError(
                f"evidence[{index}] is outside boot-policy chronology"
            )
    _validate_stock_identity(value["stock_identity"])
    _validate_safety(value["safety_isolation"], evidence)
    _validate_flash_policy(value["flash_policy"], evidence, recovery_flash_devices)
    force_decrypt, security_method = _validate_security_policy(
        value["security_policy"], evidence
    )
    _validate_access_policy(value["rom_isp_policy"], evidence, kind="rom_isp")
    _validate_access_policy(value["jtag_policy"], evidence, kind="jtag")
    _validate_plaintext_probe(
        value["plaintext_probe"],
        evidence,
        force_decrypt,
        security_method,
        actions,
    )
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise BootPolicyError("boot-policy authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise BootPolicyError("boot-policy disposition drifted")
        _sha(value["descriptor_sha256"], "descriptor_sha256")
        _sha(value["receipt_id"], "receipt_id")
        _validate_signing(value["signing"])


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
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


def _validate_receipt(
    receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    recovery_flash_devices: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    _validate_core(
        receipt,
        manifest,
        receipt=True,
        recovery_flash_devices=recovery_flash_devices,
    )
    descriptor = _descriptor_projection(receipt)
    if (
        hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
        != receipt["descriptor_sha256"]
    ):
        raise BootPolicyError("boot-policy descriptor SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    expected_id = hashlib.sha256(
        b"DCENT-K210-BOOT-POLICY-RECEIPT-ID-V1\x00" + canonical_json_bytes(without_id)
    ).hexdigest()
    if expected_id != receipt["receipt_id"]:
        raise BootPolicyError("boot-policy receipt ID mismatch")


def _hash_source(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(str(exc)) from exc


def _load_recovery_copy(
    manifest: Mapping[str, Any],
    boot_record: Mapping[str, Any],
    evidence_root: Path,
) -> dict[str, Any]:
    copies = [
        item
        for item in boot_record["evidence"]
        if item["kind"] == "recovery_receipt_copy"
    ]
    if len(copies) != 1:
        raise BootPolicyError("exactly one recovery receipt copy is required")
    source = _source(
        evidence_root, _safe_path(copies[0]["path"], "recovery receipt evidence path")
    )
    try:
        observed = discovery.load_json(
            source, "recovery receipt copy", require_canonical=True
        )
        recovery._validate_receipt(observed, manifest)
    except (discovery.DiscoveryError, recovery.RecoveryError) as exc:
        raise BootPolicyError(f"recovery receipt copy is invalid: {exc}") from exc
    expected = {
        "receipt_id": boot_record["recovery_receipt_id"],
        "discovery_receipt_id": boot_record["discovery_receipt_id"],
        "stock_backup_set_sha256": boot_record["stock_backup_set_sha256"],
        "target_id": boot_record["target_id"],
        "unit_fingerprint_sha256": boot_record["unit_fingerprint_sha256"],
        "unit_label": boot_record["unit_label"],
    }
    for key, value in expected.items():
        if observed[key] != value:
            raise BootPolicyError(
                f"recovery receipt copy {key} does not match boot-policy record"
            )
    if observed["stock_identity"] != boot_record["stock_identity"]:
        raise BootPolicyError(
            "recovery receipt copy stock identity does not match boot-policy record"
        )
    return observed


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_core(descriptor, manifest, receipt=False)
    recovered = _load_recovery_copy(manifest, descriptor, evidence_root)
    recovery_devices = {device["id"]: device for device in recovered["flash_devices"]}
    _validate_core(
        descriptor,
        manifest,
        receipt=False,
        recovery_flash_devices=recovery_devices,
    )
    evidence_with_hashes = []
    sources: dict[str, Path] = {}
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        relative = _safe_path(item["path"], f"evidence {item['id']} path")
        source = _source(evidence_root, relative)
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise BootPolicyError(
                "boot-policy evidence exceeds the aggregate byte limit"
            )
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
        sources[item["id"]] = source
    try:
        operator_key = discovery.inspect_private_key(operator_private_key)
        witness_key = discovery.inspect_private_key(witness_private_key)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(f"boot-policy signing key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise BootPolicyError("operator and witness private keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(BOOT_POLICY_ACTIONS)
    normalized["evidence"] = evidence_with_hashes
    normalized["kind"] = RECEIPT_KIND
    receipt: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "disposition": DISPOSITION,
        "signing": {
            "operator": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": operator_key["key_id_sha256"],
                "namespace": OPERATOR_NAMESPACE,
                "role": OPERATOR_ROLE,
            },
            "witness": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": witness_key["key_id_sha256"],
                "namespace": WITNESS_NAMESPACE,
                "role": WITNESS_ROLE,
            },
        },
    }
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-BOOT-POLICY-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest, recovery_devices)
    return receipt, sources


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise BootPolicyError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "boot-policy descriptor", canonical=False)
    receipt, sources = build_receipt(
        manifest,
        descriptor,
        evidence_root,
        operator_private_key,
        witness_private_key,
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        evidence_destination = temporary / EVIDENCE_DIRECTORY
        evidence_destination.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = evidence_destination.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_source(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise BootPolicyError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        operator_signature = discovery.sign_sshsig_file(
            receipt_path, operator_private_key, OPERATOR_NAMESPACE
        )
        witness_signature = discovery.sign_sshsig_file(
            receipt_path, witness_private_key, WITNESS_NAMESPACE
        )
        operator_path = temporary / OPERATOR_SIGNATURE_NAME
        witness_path = temporary / WITNESS_SIGNATURE_NAME
        operator_path.write_bytes(operator_signature)
        witness_path.write_bytes(witness_signature)
        operator_key = discovery.inspect_private_key(operator_private_key)
        witness_key = discovery.inspect_private_key(witness_private_key)
        if (
            operator_key["key_id_sha256"]
            != receipt["signing"]["operator"]["key_id_sha256"]
            or witness_key["key_id_sha256"]
            != receipt["signing"]["witness"]["key_id_sha256"]
        ):
            raise BootPolicyError(
                "a boot-policy signing key changed during bundle creation"
            )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            operator_path,
            operator_key["canonical_line"],
            receipt["operator_id"],
            OPERATOR_NAMESPACE,
        )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            witness_path,
            witness_key["canonical_line"],
            receipt["witness_id"],
            WITNESS_NAMESPACE,
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
    operator_public_key: Path,
    witness_public_key: Path,
    expected_operator_key_id: str | None = None,
    expected_witness_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise BootPolicyError(f"boot-policy bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise BootPolicyError("boot-policy bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "boot-policy receipt", canonical=True)
    recovered = _load_recovery_copy(manifest, receipt, bundle / EVIDENCE_DIRECTORY)
    recovery_devices = {device["id"]: device for device in recovered["flash_devices"]}
    _validate_receipt(receipt, manifest, recovery_devices)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        witness_key = discovery.inspect_public_key(witness_public_key)
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(f"boot-policy trust key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise BootPolicyError("operator and witness trust keys must be distinct")
    try:
        receipt_raw = discovery._read_regular(
            receipt_path, "boot-policy receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise BootPolicyError(str(exc)) from exc
    if receipt_raw != canonical_json_bytes(receipt):
        raise BootPolicyError("boot-policy receipt changed after validation")
    expected = (
        (
            "operator",
            operator_key,
            expected_operator_key_id,
            bundle / OPERATOR_SIGNATURE_NAME,
            receipt["operator_id"],
            OPERATOR_NAMESPACE,
        ),
        (
            "witness",
            witness_key,
            expected_witness_key_id,
            bundle / WITNESS_SIGNATURE_NAME,
            receipt["witness_id"],
            WITNESS_NAMESPACE,
        ),
    )
    for role, key, pinned, signature_path, principal, namespace in expected:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise BootPolicyError(
                f"{role} public key does not match the manifest trust anchor"
            )
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise BootPolicyError(f"boot-policy receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw, signature_path, key["canonical_line"], principal, namespace
            )
        except discovery.DiscoveryError as exc:
            raise BootPolicyError(
                f"boot-policy {role} signature is invalid: {exc}"
            ) from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise BootPolicyError(
                "boot-policy evidence exceeds the aggregate byte limit"
            )
        if size != item["bytes"] or digest != item["sha256"]:
            raise BootPolicyError(f"evidence {item['id']} digest or size mismatch")
    _verify_exact_members(bundle, receipt)
    flash_digest = hashlib.sha256(
        b"DCENT-K210-FLASH-POLICY-V1\x00"
        + canonical_json_bytes(receipt["flash_policy"])
    ).hexdigest()
    return {
        "authority_granted": False,
        "boot_policy_gate_eligible": True,
        "candidate_load_contract_compatible": receipt["flash_policy"][
            "candidate_load_contract_compatible"
        ],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "flash_policy_sha256": flash_digest,
        "force_decrypt_state": receipt["security_policy"]["force_decrypt_state"],
        "jtag_capabilities": {
            "halt_capable": receipt["jtag_policy"]["halt_capable"],
            "read_memory_capable": receipt["jtag_policy"]["read_memory_capable"],
            "write_memory_capable": receipt["jtag_policy"]["write_memory_capable"],
        },
        "jtag_state": receipt["jtag_policy"]["state"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "plaintext_boot_supported": receipt["plaintext_probe"][
            "plaintext_boot_supported"
        ],
        "plaintext_probe_performed": receipt["plaintext_probe"]["performed"],
        "plaintext_probe_result": receipt["plaintext_probe"]["result"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "rom_isp_capabilities": {
            "erase_capable": receipt["rom_isp_policy"]["erase_capable"],
            "existing_flash_independent": receipt["rom_isp_policy"][
                "existing_flash_independent"
            ],
            "read_capable": receipt["rom_isp_policy"]["read_capable"],
            "write_capable": receipt["rom_isp_policy"]["write_capable"],
        },
        "rom_isp_state": receipt["rom_isp_policy"]["state"],
        "state": "verified_signed_boot_policy_measurement",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "witness_key_id_sha256": witness_key["key_id_sha256"],
    }


def _verify_exact_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_files = {RECEIPT_NAME, OPERATOR_SIGNATURE_NAME, WITNESS_SIGNATURE_NAME}
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
            raise BootPolicyError(
                f"boot-policy bundle cannot be enumerated: {exc}"
            ) from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BootPolicyError(
                    f"boot-policy bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise BootPolicyError(
                    f"boot-policy bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise BootPolicyError(
                    f"boot-policy bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise BootPolicyError("boot-policy bundle member set is not exact")


def _template(
    manifest: Mapping[str, Any], recovery_receipt_path: Path
) -> dict[str, Any]:
    observed = _load_json(recovery_receipt_path, "recovery receipt", canonical=True)
    try:
        recovery._validate_receipt(observed, manifest)
    except recovery.RecoveryError as exc:
        raise BootPolicyError(f"recovery receipt is invalid: {exc}") from exc
    evidence_specs = (
        ("recovery-receipt", "recovery_receipt_copy", "identity/recovery-receipt.json"),
        (
            "safety-isolation",
            "safety_isolation_record",
            "records/safety-isolation.json",
        ),
        ("flash-map", "flash_map_record", "records/flash-map.json"),
        ("efuse", "efuse_record", "records/efuse.json"),
        ("rom-isp", "rom_isp_record", "records/rom-isp.json"),
        ("jtag", "jtag_record", "records/jtag.json"),
        ("load-address", "load_address_record", "records/load-address.json"),
        ("plaintext-probe", "plaintext_probe_record", "records/plaintext-probe.json"),
        ("stock-preboot", "stock_preboot_record", "records/stock-preboot.json"),
        ("stock-postboot", "stock_postboot_record", "records/stock-postboot.json"),
    )
    evidence = [
        {
            "acquired_at_utc": "2026-01-01T00:40:00Z",
            "id": evidence_id,
            "kind": kind,
            "media_type": "application/json",
            "method": "offline_artifact"
            if kind == "recovery_receipt_copy"
            else "authorized_boot_policy_measurement",
            "path": path,
            "redaction": "none",
        }
        for evidence_id, kind, path in evidence_specs
    ]
    devices = []
    for device in observed["flash_devices"]:
        devices.append(
            {
                "capacity_bytes": device["capacity_bytes"],
                "id": device["id"],
                "manufacturer": device["manufacturer"],
                "model": device["model"],
                "regions": [
                    {
                        "label": "REPLACE_WITH_MEASURED_REGION_LABEL",
                        "length_bytes": device["capacity_bytes"],
                        "offset_bytes": 0,
                        "role": "boot_image",
                    }
                ],
                "technology": device["technology"],
            }
        )
    boot = devices[0]
    descriptor = {
        "actions_performed": {
            **BASE_ACTIONS_PERFORMED,
            "controlled_aes0_boot_probe_performed": False,
            "custom_firmware_written": False,
            "stock_flash_restored_after_measurement": False,
        },
        "authorization": {
            "authorized_actions": sorted(BOOT_POLICY_ACTIONS),
            "operator_reference": "REPLACE_WITH_OPERATOR_AUTHORIZATION_REFERENCE",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T01:00:00Z",
        },
        "completed_at_utc": "2026-01-01T00:50:00Z",
        "discovery_receipt_id": observed["discovery_receipt_id"],
        "evidence": evidence,
        "flash_policy": {
            "boot_flash_device_id": boot["id"],
            "boot_image_length_bytes": boot["capacity_bytes"],
            "boot_image_offset_bytes": 0,
            "candidate_load_address": K210_CANDIDATE_LOAD_ADDRESS,
            "candidate_load_contract_compatible": True,
            "devices": devices,
            "flash_map_evidence_id": "flash-map",
            "load_address_evidence_id": "load-address",
            "measured_boot_load_address": K210_CANDIDATE_LOAD_ADDRESS,
        },
        "jtag_policy": {
            "evidence_id": "jtag",
            "halt_capable": False,
            "idcode": None,
            "read_memory_capable": False,
            "state": "locked",
            "transport": "REPLACE",
            "write_memory_capable": False,
        },
        "kind": DESCRIPTOR_KIND,
        "operator_id": "REPLACE",
        "plaintext_probe": {
            "aes_enable": 0,
            "artifact_evidence_id": None,
            "delivery": "not_performed",
            "evidence_id": "plaintext-probe",
            "observation_method": "direct_policy",
            "performed": False,
            "plaintext_boot_supported": False,
            "result": "not_run_force_decrypt_enabled",
            "stock_flash_restored_after_measurement": False,
            "stock_identity_matched_after_measurement": True,
            "stock_postboot_evidence_id": "stock-postboot",
            "stock_preboot_evidence_id": "stock-preboot",
            "stock_state_verified_after_measurement": True,
        },
        "recovery_receipt_id": observed["receipt_id"],
        "rom_isp_policy": {
            "erase_capable": False,
            "evidence_id": "rom-isp",
            "existing_flash_independent": False,
            "read_capable": False,
            "state": "locked",
            "transport": "REPLACE",
            "write_capable": False,
        },
        "safety_isolation": {
            "controller_only_power": True,
            "cooling_safe_for_controller_only": True,
            "evidence_id": "safety-isolation",
            "hash_power_physical_disconnect_verified": True,
            "independent_hash_power_cutoff_asserted": True,
        },
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "security_policy": {
            "evidence_id": "efuse",
            "force_decrypt_state": "enabled",
            "measurement_method": "direct_efuse_read",
            "otp_boot_key_state": "not_directly_readable",
        },
        "started_at_utc": "2026-01-01T00:05:00Z",
        "stock_backup_set_sha256": observed["stock_backup_set_sha256"],
        "stock_identity": dict(observed["stock_identity"]),
        "target_id": observed["target_id"],
        "unit_fingerprint_sha256": observed["unit_fingerprint_sha256"],
        "unit_label": observed["unit_label"],
        "witness_id": "REPLACE-WITNESS",
    }
    recovery_devices = {device["id"]: device for device in observed["flash_devices"]}
    _validate_core(
        descriptor, manifest, receipt=False, recovery_flash_devices=recovery_devices
    )
    return descriptor


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser(
        "template", help="write a descriptor bound to a recovery receipt"
    )
    template.add_argument("--recovery-receipt", type=Path, required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign completed boot-policy evidence"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed boot-policy bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--operator-public-key", type=Path, required=True)
    verify.add_argument("--witness-public-key", type=Path, required=True)
    verify.add_argument("--expected-operator-key-id")
    verify.add_argument("--expected-witness-key-id")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
        if args.command == "template":
            descriptor = _template(manifest, args.recovery_receipt)
            try:
                discovery._write_new(
                    args.out,
                    (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode(
                        "ascii"
                    ),
                    "boot-policy descriptor template",
                )
            except discovery.DiscoveryError as exc:
                raise BootPolicyError(str(exc)) from exc
            print(
                f"K210_BOOT_POLICY_TEMPLATE_WRITTEN target={descriptor['target_id']} path={args.out}"
            )
            return 0
        if args.command == "create":
            receipt = create_bundle(
                manifest,
                args.descriptor,
                args.evidence_root,
                args.operator_private_key,
                args.witness_private_key,
                args.bundle_out,
            )
            print(
                f"K210_BOOT_POLICY_BUNDLE_CREATED target={receipt['target_id']} receipt_id={receipt['receipt_id']} disposition={receipt['disposition']}"
            )
            return 0
        for label, value in (
            ("--expected-operator-key-id", args.expected_operator_key_id),
            ("--expected-witness-key-id", args.expected_witness_key_id),
        ):
            if value is not None and not HEX64_RE.fullmatch(value):
                raise BootPolicyError(f"{label} must be lowercase SHA-256 hex")
        result = verify_bundle(
            manifest,
            args.bundle,
            args.operator_public_key,
            args.witness_public_key,
            args.expected_operator_key_id,
            args.expected_witness_key_id,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (BootPolicyError, recovery.RecoveryError, discovery.DiscoveryError) as exc:
        print(f"K210_BOOT_POLICY_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
