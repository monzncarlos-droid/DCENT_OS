#!/usr/bin/env python3
"""Create and verify signed Avalon K210 stock-recovery evidence bundles.

This tool is host-only and has no miner, programmer, serial, USB, GPIO, power,
flash, or block-device transport. It snapshots caller-supplied evidence from a
completed, separately authorized recovery drill. A valid bundle records past
results and grants no authority for future contact, mutation, or release.
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


def _load_discovery_module():
    path = Path(__file__).with_name("k210_discovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_discovery_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 evidence primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


discovery = _load_discovery_module()

SCHEMA_VERSION = 1
SCOPE = discovery.SCOPE
DESCRIPTOR_KIND = "dcent_k210_stock_recovery_descriptor"
RECEIPT_KIND = "dcent_k210_stock_recovery_receipt"
DISPOSITION = "past_recovery_evidence_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_recovery_operator"
WITNESS_ROLE = "k210_recovery_witness"
OPERATOR_NAMESPACE = "dcent-k210-recovery-operator-v1"
WITNESS_NAMESPACE = "dcent-k210-recovery-witness-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM
MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 96
MAX_EVIDENCE_FILE_BYTES = discovery.MAX_EVIDENCE_FILE_BYTES
MAX_TOTAL_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FLASH_DEVICES = 4
MAX_FLASH_BYTES = 1024 * 1024 * 1024

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

RECOVERY_ACTIONS = {
    "cold_boot_stock_validation",
    "controlled_restore_interruption",
    "controller_flash_read",
    "full_flash_readback",
    "power_cycle_for_recovery",
    "stock_flash_restore",
}
ACTIONS_PERFORMED = {
    "cold_boot_stock_validation": True,
    "controlled_restore_interruption": True,
    "custom_firmware_written": False,
    "full_flash_backup_read": True,
    "full_flash_readback": True,
    "production_hashing_commanded": False,
    "stock_flash_restored": True,
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_future_flash_write": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_install": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}
MECHANISM_CLASSES = {
    "external_memory_programmer",
    "k210_rom_isp",
    "vendor_service_bootrom",
}
INTERRUPTION_KINDS = {"power_loss", "process_termination", "transport_loss"}
EVIDENCE_KINDS = {
    "backup_log",
    "discovery_receipt_copy",
    "flash_geometry_record",
    "full_readback_image",
    "interruption_log",
    "restore_log",
    "safety_record",
    "stock_backup_image",
    "stock_cold_boot_record",
    "stock_identity_record",
}
MEDIA_TYPES = {
    "application/json",
    "application/octet-stream",
    "image/jpeg",
    "image/png",
    "text/plain",
}
EVIDENCE_METHODS = {
    "authorized_recovery_execution",
    "offline_artifact",
    "visual_inspection",
}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}


class RecoveryError(RuntimeError):
    """A stock-recovery descriptor, bundle, or evidence invariant failed."""


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
        raise RecoveryError(f"{context} keys invalid: {'; '.join(detail)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RecoveryError(f"{context} must be a non-empty string <= {maximum} chars")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise RecoveryError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise RecoveryError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not PRINCIPAL_RE.fullmatch(text):
        raise RecoveryError(f"{context} is not a canonical signer principal")
    return text


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise RecoveryError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RecoveryError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise RecoveryError(f"{context} must be lowercase SHA-256")
    return value


def _positive_int(value: Any, context: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise RecoveryError(f"{context} must be an integer in 1..{maximum}")
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise RecoveryError(f"{context} must be a portable POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise RecoveryError(f"{context} must be a canonical relative path")
    if any(part in ("", ".", "..") for part in path.parts):
        raise RecoveryError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _validate_evidence(evidence: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        raise RecoveryError(f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records")
    ids: set[str] = set()
    paths: set[str] = set()
    normalized = []
    required_kinds = {"discovery_receipt_copy", "safety_record"}
    observed_kinds: set[str] = set()
    for index, item in enumerate(evidence):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise RecoveryError(f"{context} must be an object")
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
            raise RecoveryError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise RecoveryError(f"{context}.kind is unsupported")
        observed_kinds.add(kind)
        if item["media_type"] not in MEDIA_TYPES:
            raise RecoveryError(f"{context}.media_type is unsupported")
        if item["method"] not in EVIDENCE_METHODS:
            raise RecoveryError(f"{context}.method is unsupported")
        if item["redaction"] not in REDACTION_STATES:
            raise RecoveryError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise RecoveryError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _positive_int(item["bytes"], f"{context}.bytes", MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    missing = sorted(required_kinds - observed_kinds)
    if missing:
        raise RecoveryError(f"recovery evidence is missing {', '.join(missing)}")
    return normalized


def _validate_stock_identity(value: Any) -> None:
    if not isinstance(value, dict):
        raise RecoveryError("stock_identity must be an object")
    _require_exact_keys(
        value,
        ("stock_dna", "stock_firmware_version", "stock_hwtype", "stock_swtype"),
        "stock_identity",
    )
    for key in value:
        _text(value[key], f"stock_identity.{key}", 128)


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> dict[str, dict[str, Any]]:
    core_keys = (
        "actions_performed",
        "authorization",
        "completed_at_utc",
        "discovery_receipt_id",
        "evidence",
        "flash_devices",
        "interruption_drill",
        "kind",
        "operator_id",
        "restore_paths",
        "schema_version",
        "scope",
        "started_at_utc",
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
        "stock_backup_set_sha256",
    )
    _require_exact_keys(
        value, core_keys + receipt_only if receipt else core_keys, "recovery record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise RecoveryError("recovery schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind:
        raise RecoveryError("recovery record kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    _sha(value["discovery_receipt_id"], "discovery_receipt_id")
    _sha(value["unit_fingerprint_sha256"], "unit_fingerprint_sha256")
    operator = _principal(value["operator_id"], "operator_id")
    witness = _principal(value["witness_id"], "witness_id")
    if operator == witness:
        raise RecoveryError("recovery operator and witness must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise RecoveryError("recovery start must precede completion")
    if value["actions_performed"] != ACTIONS_PERFORMED:
        raise RecoveryError("recovery actions_performed contract drifted")
    _validate_stock_identity(value["stock_identity"])

    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise RecoveryError("authorization must be an object")
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
        raise RecoveryError("recovery drill is outside the authorization interval")
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or set(actions) != RECOVERY_ACTIONS
        or len(actions) != len(RECOVERY_ACTIONS)
    ):
        raise RecoveryError(
            "authorization does not contain the exact recovery action set"
        )

    evidence = _validate_evidence(value["evidence"], hashed=receipt)
    evidence_by_id = {item["id"]: item for item in evidence}
    for index, item in enumerate(evidence):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise RecoveryError(f"evidence[{index}] is outside recovery chronology")

    flash_devices = value["flash_devices"]
    if (
        not isinstance(flash_devices, list)
        or not 1 <= len(flash_devices) <= MAX_FLASH_DEVICES
    ):
        raise RecoveryError(
            f"flash_devices must contain 1..{MAX_FLASH_DEVICES} devices"
        )
    devices: dict[str, dict[str, Any]] = {}
    for index, device in enumerate(flash_devices):
        context = f"flash_devices[{index}]"
        if not isinstance(device, dict):
            raise RecoveryError(f"{context} must be an object")
        _require_exact_keys(
            device,
            (
                "backup_reads",
                "capacity_bytes",
                "geometry_evidence_id",
                "id",
                "manufacturer",
                "model",
                "technology",
            ),
            context,
        )
        device_id = _identifier(device["id"], f"{context}.id")
        if device_id in devices:
            raise RecoveryError("flash device IDs must be unique")
        capacity = _positive_int(
            device["capacity_bytes"], f"{context}.capacity_bytes", MAX_FLASH_BYTES
        )
        if device["technology"] not in {"emmc", "spi_nand", "spi_nor"}:
            raise RecoveryError(f"{context}.technology is unsupported")
        _text(device["manufacturer"], f"{context}.manufacturer", 80)
        _text(device["model"], f"{context}.model", 80)
        _evidence_ref(
            evidence_by_id,
            device["geometry_evidence_id"],
            "flash_geometry_record",
            f"{context}.geometry_evidence_id",
        )
        reads = device["backup_reads"]
        if not isinstance(reads, list) or len(reads) != 2:
            raise RecoveryError(
                f"{context}.backup_reads must contain exactly two reads"
            )
        read_mechanisms: set[str] = set()
        read_tools: set[str] = set()
        read_hashes: set[str] = set()
        read_artifacts: set[str] = set()
        read_logs: set[str] = set()
        for read_index, read in enumerate(reads):
            read_context = f"{context}.backup_reads[{read_index}]"
            if not isinstance(read, dict):
                raise RecoveryError(f"{read_context} must be an object")
            _require_exact_keys(
                read,
                (
                    "artifact_evidence_id",
                    "log_evidence_id",
                    "mechanism_class",
                    "tool",
                    "tool_serial",
                    "tool_version",
                ),
                read_context,
            )
            mechanism = _mechanism(
                read["mechanism_class"], f"{read_context}.mechanism_class"
            )
            read_mechanisms.add(mechanism)
            tool = _text(read["tool"], f"{read_context}.tool", 96)
            tool_serial = _text(read["tool_serial"], f"{read_context}.tool_serial", 96)
            _text(read["tool_version"], f"{read_context}.tool_version", 96)
            read_tools.add(f"{tool}\x00{tool_serial}")
            artifact = _evidence_ref(
                evidence_by_id,
                read["artifact_evidence_id"],
                "stock_backup_image",
                f"{read_context}.artifact_evidence_id",
            )
            log = _evidence_ref(
                evidence_by_id,
                read["log_evidence_id"],
                "backup_log",
                f"{read_context}.log_evidence_id",
            )
            read_artifacts.add(artifact["id"])
            read_logs.add(log["id"])
            if receipt:
                if artifact["bytes"] != capacity:
                    raise RecoveryError(f"{read_context} is not a full-device backup")
                read_hashes.add(artifact["sha256"])
        if (
            len(read_mechanisms) != 2
            or len(read_tools) != 2
            or len(read_artifacts) != 2
            or len(read_logs) != 2
        ):
            raise RecoveryError(f"{context} backup reads are not independent")
        if "external_memory_programmer" not in read_mechanisms:
            raise RecoveryError(f"{context} lacks an external programmer backup")
        if receipt and len(read_hashes) != 1:
            raise RecoveryError(f"{context} independent backup reads disagree")
        devices[device_id] = dict(device)

    restore_paths = value.get("restore_paths")
    if restore_paths is None:
        raise RecoveryError("recovery record is missing restore_paths")
    if not isinstance(restore_paths, list) or len(restore_paths) != 2:
        raise RecoveryError("restore_paths must contain exactly two paths")
    paths: dict[str, dict[str, Any]] = {}
    path_mechanisms: set[str] = set()
    path_tools: set[str] = set()
    path_logs: set[str] = set()
    path_boots: set[str] = set()
    path_identities: set[str] = set()
    path_readbacks: set[str] = set()
    for index, path in enumerate(restore_paths):
        context = f"restore_paths[{index}]"
        if not isinstance(path, dict):
            raise RecoveryError(f"{context} must be an object")
        _require_exact_keys(
            path,
            (
                "cold_boot_evidence_id",
                "completed_at_utc",
                "device_results",
                "existing_flash_independent",
                "id",
                "log_evidence_id",
                "mechanism_class",
                "started_at_utc",
                "stock_booted",
                "stock_identity_evidence_id",
                "stock_identity_matched",
                "tool",
                "tool_serial",
                "tool_version",
            ),
            context,
        )
        path_id = _identifier(path["id"], f"{context}.id")
        if path_id in paths:
            raise RecoveryError("restore path IDs must be unique")
        mechanism = _mechanism(path["mechanism_class"], f"{context}.mechanism_class")
        path_mechanisms.add(mechanism)
        tool = _text(path["tool"], f"{context}.tool", 96)
        tool_serial = _text(path["tool_serial"], f"{context}.tool_serial", 96)
        _text(path["tool_version"], f"{context}.tool_version", 96)
        path_tools.add(f"{tool}\x00{tool_serial}")
        if path["existing_flash_independent"] is not True:
            raise RecoveryError(f"{context} depends on intact existing flash")
        path_started = _utc(path["started_at_utc"], f"{context}.started_at_utc")
        path_completed = _utc(path["completed_at_utc"], f"{context}.completed_at_utc")
        if not started <= path_started < path_completed <= completed:
            raise RecoveryError(f"{context} chronology is outside the drill")
        if (
            path["stock_booted"] is not True
            or path["stock_identity_matched"] is not True
        ):
            raise RecoveryError(
                f"{context} did not restore the expected stock identity"
            )
        log = _evidence_ref(
            evidence_by_id,
            path["log_evidence_id"],
            "restore_log",
            f"{context}.log_evidence_id",
        )
        boot = _evidence_ref(
            evidence_by_id,
            path["cold_boot_evidence_id"],
            "stock_cold_boot_record",
            f"{context}.cold_boot_evidence_id",
        )
        identity = _evidence_ref(
            evidence_by_id,
            path["stock_identity_evidence_id"],
            "stock_identity_record",
            f"{context}.stock_identity_evidence_id",
        )
        path_logs.add(log["id"])
        path_boots.add(boot["id"])
        path_identities.add(identity["id"])
        _validate_device_results(
            path["device_results"],
            devices,
            evidence_by_id,
            context,
            receipt,
        )
        for result in path["device_results"]:
            path_readbacks.add(result["readback_evidence_id"])
        paths[path_id] = dict(path)
    if len(path_mechanisms) != 2 or len(path_tools) != 2:
        raise RecoveryError("restore paths are not independent")
    expected_path_records = len(restore_paths)
    if (
        len(path_logs) != expected_path_records
        or len(path_boots) != expected_path_records
        or len(path_identities) != expected_path_records
        or len(path_readbacks) != expected_path_records * len(devices)
    ):
        raise RecoveryError("restore paths reused result evidence")
    if "external_memory_programmer" not in path_mechanisms:
        raise RecoveryError("restore paths lack an external programmer route")

    interruption = value["interruption_drill"]
    if not isinstance(interruption, dict):
        raise RecoveryError("interruption_drill must be an object")
    _require_exact_keys(
        interruption,
        (
            "attempted_restore_path_id",
            "cold_boot_evidence_id",
            "interrupted_after_bytes",
            "interruption_kind",
            "log_evidence_id",
            "passed",
            "recovered_by_restore_path_id",
            "recovery_readbacks",
            "stock_booted",
            "stock_identity_evidence_id",
            "stock_identity_matched",
        ),
        "interruption_drill",
    )
    attempted = _identifier(
        interruption["attempted_restore_path_id"],
        "interruption_drill.attempted_restore_path_id",
    )
    recovered = _identifier(
        interruption["recovered_by_restore_path_id"],
        "interruption_drill.recovered_by_restore_path_id",
    )
    if attempted not in paths or recovered not in paths or attempted == recovered:
        raise RecoveryError(
            "interruption drill must recover through the other admitted path"
        )
    if interruption["interruption_kind"] not in INTERRUPTION_KINDS:
        raise RecoveryError("interruption drill kind is unsupported")
    total_capacity = sum(device["capacity_bytes"] for device in devices.values())
    interrupted_after = _positive_int(
        interruption["interrupted_after_bytes"],
        "interruption_drill.interrupted_after_bytes",
        total_capacity,
    )
    if interrupted_after >= total_capacity:
        raise RecoveryError("interruption must occur before the full restore completes")
    if (
        interruption["passed"] is not True
        or interruption["stock_booted"] is not True
        or interruption["stock_identity_matched"] is not True
    ):
        raise RecoveryError("interruption recovery did not restore expected stock")
    interruption_log = _evidence_ref(
        evidence_by_id,
        interruption["log_evidence_id"],
        "interruption_log",
        "interruption_drill.log_evidence_id",
    )
    interruption_boot = _evidence_ref(
        evidence_by_id,
        interruption["cold_boot_evidence_id"],
        "stock_cold_boot_record",
        "interruption_drill.cold_boot_evidence_id",
    )
    interruption_identity = _evidence_ref(
        evidence_by_id,
        interruption["stock_identity_evidence_id"],
        "stock_identity_record",
        "interruption_drill.stock_identity_evidence_id",
    )
    _validate_recovery_readbacks(
        interruption["recovery_readbacks"], devices, evidence_by_id, receipt
    )
    interruption_readbacks = {
        item["readback_evidence_id"] for item in interruption["recovery_readbacks"]
    }
    if (
        interruption_log["id"] in path_logs
        or interruption_boot["id"] in path_boots
        or interruption_identity["id"] in path_identities
        or interruption_readbacks & path_readbacks
        or len(interruption_readbacks) != len(devices)
    ):
        raise RecoveryError("interruption drill reused prior restore evidence")
    if receipt:
        if (
            value["disposition"] != DISPOSITION
            or value["authority_ceiling"] != AUTHORITY_CEILING
        ):
            raise RecoveryError("recovery receipt authority boundary drifted")
        _sha(value["descriptor_sha256"], "descriptor_sha256")
        _sha(value["stock_backup_set_sha256"], "stock_backup_set_sha256")
        _sha(value["receipt_id"], "receipt_id")
        _validate_signing(value["signing"])
    return evidence_by_id


def _mechanism(value: Any, context: str) -> str:
    if value not in MECHANISM_CLASSES:
        raise RecoveryError(f"{context} is unsupported")
    return value


def _evidence_ref(
    evidence: Mapping[str, dict[str, Any]], value: Any, kind: str, context: str
) -> dict[str, Any]:
    evidence_id = _identifier(value, context)
    item = evidence.get(evidence_id)
    if item is None or item["kind"] != kind:
        raise RecoveryError(f"{context} does not reference {kind} evidence")
    return item


def _validate_device_results(
    results: Any,
    devices: Mapping[str, dict[str, Any]],
    evidence: Mapping[str, dict[str, Any]],
    context: str,
    receipt: bool,
) -> None:
    if not isinstance(results, list) or len(results) != len(devices):
        raise RecoveryError(f"{context}.device_results must cover every flash device")
    seen: set[str] = set()
    for index, result in enumerate(results):
        item_context = f"{context}.device_results[{index}]"
        if not isinstance(result, dict):
            raise RecoveryError(f"{item_context} must be an object")
        _require_exact_keys(
            result,
            (
                "flash_device_id",
                "full_write_completed",
                "readback_evidence_id",
                "readback_matches",
                "source_backup_evidence_id",
            ),
            item_context,
        )
        device_id = _identifier(
            result["flash_device_id"], f"{item_context}.flash_device_id"
        )
        if device_id not in devices or device_id in seen:
            raise RecoveryError(f"{item_context} has duplicate or unknown flash device")
        seen.add(device_id)
        source = _evidence_ref(
            evidence,
            result["source_backup_evidence_id"],
            "stock_backup_image",
            f"{item_context}.source_backup_evidence_id",
        )
        device_backup_ids = {
            read["artifact_evidence_id"] for read in devices[device_id]["backup_reads"]
        }
        if source["id"] not in device_backup_ids:
            raise RecoveryError(
                f"{item_context} source is not a backup of that flash device"
            )
        readback = _evidence_ref(
            evidence,
            result["readback_evidence_id"],
            "full_readback_image",
            f"{item_context}.readback_evidence_id",
        )
        if (
            result["full_write_completed"] is not True
            or result["readback_matches"] is not True
        ):
            raise RecoveryError(
                f"{item_context} did not complete with matching readback"
            )
        if receipt and (
            source["sha256"] != readback["sha256"]
            or source["bytes"] != readback["bytes"]
            or readback["bytes"] != devices[device_id]["capacity_bytes"]
        ):
            raise RecoveryError(
                f"{item_context} readback bytes do not match the full backup"
            )


def _validate_recovery_readbacks(
    results: Any,
    devices: Mapping[str, dict[str, Any]],
    evidence: Mapping[str, dict[str, Any]],
    receipt: bool,
) -> None:
    if not isinstance(results, list) or len(results) != len(devices):
        raise RecoveryError(
            "interruption recovery readbacks must cover every flash device"
        )
    seen: set[str] = set()
    for index, result in enumerate(results):
        context = f"interruption_drill.recovery_readbacks[{index}]"
        if not isinstance(result, dict):
            raise RecoveryError(f"{context} must be an object")
        _require_exact_keys(
            result, ("flash_device_id", "readback_evidence_id"), context
        )
        device_id = _identifier(result["flash_device_id"], f"{context}.flash_device_id")
        if device_id not in devices or device_id in seen:
            raise RecoveryError(f"{context} has duplicate or unknown flash device")
        seen.add(device_id)
        readback = _evidence_ref(
            evidence,
            result["readback_evidence_id"],
            "full_readback_image",
            f"{context}.readback_evidence_id",
        )
        if receipt:
            backup_hashes = {
                evidence[read["artifact_evidence_id"]]["sha256"]
                for read in devices[device_id]["backup_reads"]
            }
            if (
                readback["bytes"] != devices[device_id]["capacity_bytes"]
                or readback["sha256"] not in backup_hashes
            ):
                raise RecoveryError(f"{context} does not match the full stock backup")


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise RecoveryError("signing must be an object")
    _require_exact_keys(value, ("operator", "witness"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "witness": (WITNESS_ROLE, WITNESS_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise RecoveryError(f"signing.{name} must be an object")
        _require_exact_keys(
            item, ("algorithm", "key_id_sha256", "namespace", "role"), f"signing.{name}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["role"] != role
            or item["namespace"] != namespace
        ):
            raise RecoveryError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise RecoveryError("operator and witness signing keys must be distinct")


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "receipt_id",
        "signing",
        "stock_backup_set_sha256",
    }
    descriptor = {key: value for key, value in receipt.items() if key not in excluded}
    descriptor["kind"] = DESCRIPTOR_KIND
    descriptor["evidence"] = [
        {key: value for key, value in item.items() if key not in ("bytes", "sha256")}
        for item in receipt["evidence"]
    ]
    return descriptor


def _backup_projection(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence = {item["id"]: item for item in receipt["evidence"]}
    projection = []
    for device in sorted(receipt["flash_devices"], key=lambda item: item["id"]):
        reads = []
        for read in sorted(
            device["backup_reads"], key=lambda item: item["artifact_evidence_id"]
        ):
            artifact = evidence[read["artifact_evidence_id"]]
            reads.append(
                {
                    "artifact_evidence_id": artifact["id"],
                    "bytes": artifact["bytes"],
                    "sha256": artifact["sha256"],
                }
            )
        projection.append(
            {
                "capacity_bytes": device["capacity_bytes"],
                "id": device["id"],
                "reads": reads,
            }
        )
    return projection


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _validate_core(receipt, manifest, receipt=True)
    descriptor = _descriptor_projection(receipt)
    if (
        hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
        != receipt["descriptor_sha256"]
    ):
        raise RecoveryError("recovery descriptor SHA-256 mismatch")
    backup_digest = hashlib.sha256(
        b"DCENT-K210-STOCK-BACKUP-SET-V1\x00"
        + canonical_json_bytes(_backup_projection(receipt))
    ).hexdigest()
    if backup_digest != receipt["stock_backup_set_sha256"]:
        raise RecoveryError("stock backup-set SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-RECOVERY-RECEIPT-ID-V1\x00" + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise RecoveryError("recovery receipt ID mismatch")


def _hash_source(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _validate_discovery_copy(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any], evidence_root: Path
) -> None:
    copies = [
        item for item in receipt["evidence"] if item["kind"] == "discovery_receipt_copy"
    ]
    if len(copies) != 1:
        raise RecoveryError("exactly one discovery receipt copy is required")
    relative = _safe_path(copies[0]["path"], "discovery receipt evidence path")
    source = _source(evidence_root, relative)
    try:
        observed = discovery.load_json(
            source, "discovery receipt copy", require_canonical=True
        )
        discovery._validate_receipt(observed, manifest)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(f"discovery receipt copy is invalid: {exc}") from exc
    expected = {
        "receipt_id": receipt["discovery_receipt_id"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
    }
    for key, value in expected.items():
        if observed[key] != value:
            raise RecoveryError(f"discovery receipt copy {key} does not match recovery")
    for key, value in receipt["stock_identity"].items():
        if observed["identity"][key] != value:
            raise RecoveryError(
                f"discovery receipt copy identity.{key} does not match recovery"
            )


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_core(descriptor, manifest, receipt=False)
    evidence_with_hashes = []
    sources: dict[str, Path] = {}
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        relative = _safe_path(item["path"], f"evidence {item['id']} path")
        source = _source(evidence_root, relative)
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RecoveryError("recovery evidence exceeds the aggregate byte limit")
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
        sources[item["id"]] = source
    operator_key = discovery.inspect_private_key(operator_private_key)
    witness_key = discovery.inspect_private_key(witness_private_key)
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RecoveryError("operator and witness private keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(RECOVERY_ACTIONS)
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
    descriptor_projection = _descriptor_projection(receipt)
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(descriptor_projection)
    ).hexdigest()
    receipt["stock_backup_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-STOCK-BACKUP-SET-V1\x00"
        + canonical_json_bytes(_backup_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-RECOVERY-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest)
    _validate_discovery_copy(manifest, receipt, evidence_root)
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
        raise RecoveryError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "recovery descriptor", canonical=False)
    try:
        receipt, sources = build_receipt(
            manifest,
            descriptor,
            evidence_root,
            operator_private_key,
            witness_private_key,
        )
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc
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
                raise RecoveryError(f"evidence {item['id']} changed during snapshot")
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
            raise RecoveryError("a recovery signing key changed during bundle creation")
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
        raise RecoveryError(f"recovery bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise RecoveryError("recovery bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "recovery receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        witness_key = discovery.inspect_public_key(witness_public_key)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(f"recovery trust key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RecoveryError("operator and witness trust keys must be distinct")
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
    try:
        receipt_raw = discovery._read_regular(
            receipt_path, "recovery receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise RecoveryError(str(exc)) from exc
    if receipt_raw != canonical_json_bytes(receipt):
        raise RecoveryError("recovery receipt changed after validation")
    for role, key, pinned, signature_path, principal, namespace in expected:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise RecoveryError(
                f"{role} public key does not match the manifest trust anchor"
            )
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise RecoveryError(f"recovery receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw, signature_path, key["canonical_line"], principal, namespace
            )
        except discovery.DiscoveryError as exc:
            raise RecoveryError(f"recovery {role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        relative = _safe_path(item["path"], f"evidence {item['id']} path")
        source = _source(bundle / EVIDENCE_DIRECTORY, relative)
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RecoveryError("recovery evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise RecoveryError(f"evidence {item['id']} digest or size mismatch")
    _validate_discovery_copy(manifest, receipt, bundle / EVIDENCE_DIRECTORY)
    _verify_exact_members(bundle, receipt)
    return {
        "authority_granted": False,
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "state": "verified_signed_stock_recovery",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "stock_restore_gate_eligible": True,
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
            raise RecoveryError(f"recovery bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RecoveryError(
                    f"recovery bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise RecoveryError(
                    f"recovery bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise RecoveryError(
                    f"recovery bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise RecoveryError("recovery bundle member set is not exact")


def _template(
    manifest: Mapping[str, Any], discovery_receipt_path: Path
) -> dict[str, Any]:
    observed = _load_json(discovery_receipt_path, "discovery receipt", canonical=True)
    try:
        discovery._validate_receipt(observed, manifest)
    except discovery.DiscoveryError as exc:
        raise RecoveryError(f"discovery receipt is invalid: {exc}") from exc
    evidence_specs = (
        (
            "discovery-receipt",
            "discovery_receipt_copy",
            "identity/discovery-receipt.json",
        ),
        ("safety", "safety_record", "records/safety.json"),
        ("geometry", "flash_geometry_record", "records/geometry.json"),
        ("backup-a", "stock_backup_image", "images/backup-a.bin"),
        ("backup-a-log", "backup_log", "records/backup-a.json"),
        ("backup-b", "stock_backup_image", "images/backup-b.bin"),
        ("backup-b-log", "backup_log", "records/backup-b.json"),
        ("restore-a-log", "restore_log", "records/restore-a.json"),
        ("restore-a-readback", "full_readback_image", "images/restore-a-readback.bin"),
        ("restore-a-boot", "stock_cold_boot_record", "records/restore-a-boot.json"),
        (
            "restore-a-identity",
            "stock_identity_record",
            "records/restore-a-identity.json",
        ),
        ("restore-b-log", "restore_log", "records/restore-b.json"),
        ("restore-b-readback", "full_readback_image", "images/restore-b-readback.bin"),
        ("restore-b-boot", "stock_cold_boot_record", "records/restore-b-boot.json"),
        (
            "restore-b-identity",
            "stock_identity_record",
            "records/restore-b-identity.json",
        ),
        ("interruption-log", "interruption_log", "records/interruption.json"),
        (
            "interruption-readback",
            "full_readback_image",
            "images/interruption-readback.bin",
        ),
        (
            "interruption-boot",
            "stock_cold_boot_record",
            "records/interruption-boot.json",
        ),
        (
            "interruption-identity",
            "stock_identity_record",
            "records/interruption-identity.json",
        ),
    )
    evidence = []
    for evidence_id, kind, path in evidence_specs:
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T00:40:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": (
                    "application/octet-stream"
                    if kind in {"stock_backup_image", "full_readback_image"}
                    else "application/json"
                ),
                "method": (
                    "offline_artifact"
                    if kind in {"discovery_receipt_copy", "safety_record"}
                    else "authorized_recovery_execution"
                ),
                "path": path,
                "redaction": "none",
            }
        )

    def restore_path(
        path_id: str,
        prefix: str,
        mechanism: str,
        backup: str,
        started: str,
        completed: str,
    ) -> dict[str, Any]:
        return {
            "cold_boot_evidence_id": f"{prefix}-boot",
            "completed_at_utc": completed,
            "device_results": [
                {
                    "flash_device_id": "controller-flash-0",
                    "full_write_completed": True,
                    "readback_evidence_id": f"{prefix}-readback",
                    "readback_matches": True,
                    "source_backup_evidence_id": backup,
                }
            ],
            "existing_flash_independent": True,
            "id": path_id,
            "log_evidence_id": f"{prefix}-log",
            "mechanism_class": mechanism,
            "started_at_utc": started,
            "stock_booted": True,
            "stock_identity_evidence_id": f"{prefix}-identity",
            "stock_identity_matched": True,
            "tool": "REPLACE",
            "tool_serial": f"REPLACE-{path_id}",
            "tool_version": "REPLACE",
        }

    descriptor = {
        "actions_performed": dict(ACTIONS_PERFORMED),
        "authorization": {
            "authorized_actions": sorted(RECOVERY_ACTIONS),
            "operator_reference": "REPLACE_WITH_OPERATOR_AUTHORIZATION_REFERENCE",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T01:00:00Z",
        },
        "completed_at_utc": "2026-01-01T00:50:00Z",
        "discovery_receipt_id": observed["receipt_id"],
        "evidence": evidence,
        "flash_devices": [
            {
                "backup_reads": [
                    {
                        "artifact_evidence_id": "backup-a",
                        "log_evidence_id": "backup-a-log",
                        "mechanism_class": "external_memory_programmer",
                        "tool": "REPLACE",
                        "tool_serial": "REPLACE-A",
                        "tool_version": "REPLACE",
                    },
                    {
                        "artifact_evidence_id": "backup-b",
                        "log_evidence_id": "backup-b-log",
                        "mechanism_class": "k210_rom_isp",
                        "tool": "REPLACE",
                        "tool_serial": "REPLACE-B",
                        "tool_version": "REPLACE",
                    },
                ],
                "capacity_bytes": 2,
                "geometry_evidence_id": "geometry",
                "id": "controller-flash-0",
                "manufacturer": "REPLACE",
                "model": "REPLACE",
                "technology": "spi_nor",
            }
        ],
        "interruption_drill": {
            "attempted_restore_path_id": "external-programmer",
            "cold_boot_evidence_id": "interruption-boot",
            "interrupted_after_bytes": 1,
            "interruption_kind": "power_loss",
            "log_evidence_id": "interruption-log",
            "passed": True,
            "recovered_by_restore_path_id": "k210-rom-isp",
            "recovery_readbacks": [
                {
                    "flash_device_id": "controller-flash-0",
                    "readback_evidence_id": "interruption-readback",
                }
            ],
            "stock_booted": True,
            "stock_identity_evidence_id": "interruption-identity",
            "stock_identity_matched": True,
        },
        "kind": DESCRIPTOR_KIND,
        "operator_id": "REPLACE",
        "restore_paths": [
            restore_path(
                "external-programmer",
                "restore-a",
                "external_memory_programmer",
                "backup-a",
                "2026-01-01T00:10:00Z",
                "2026-01-01T00:20:00Z",
            ),
            restore_path(
                "k210-rom-isp",
                "restore-b",
                "k210_rom_isp",
                "backup-b",
                "2026-01-01T00:22:00Z",
                "2026-01-01T00:32:00Z",
            ),
        ],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "started_at_utc": "2026-01-01T00:05:00Z",
        "stock_identity": {
            key: observed["identity"][key]
            for key in (
                "stock_dna",
                "stock_firmware_version",
                "stock_hwtype",
                "stock_swtype",
            )
        },
        "target_id": observed["target_id"],
        "unit_fingerprint_sha256": observed["unit_fingerprint_sha256"],
        "unit_label": observed["unit_label"],
        "witness_id": "REPLACE-WITNESS",
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
        "template", help="write a recovery descriptor bound to a discovery receipt"
    )
    template.add_argument("--discovery-receipt", type=Path, required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign completed recovery evidence"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed recovery bundle")
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
            descriptor = _template(manifest, args.discovery_receipt)
            try:
                discovery._write_new(
                    args.out,
                    (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode(
                        "ascii"
                    ),
                    "recovery descriptor template",
                )
            except discovery.DiscoveryError as exc:
                raise RecoveryError(str(exc)) from exc
            print(
                f"K210_RECOVERY_TEMPLATE_WRITTEN target={descriptor['target_id']} path={args.out}"
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
                f"K210_RECOVERY_BUNDLE_CREATED target={receipt['target_id']} receipt_id={receipt['receipt_id']} disposition={receipt['disposition']}"
            )
            return 0
        for label, value in (
            ("--expected-operator-key-id", args.expected_operator_key_id),
            ("--expected-witness-key-id", args.expected_witness_key_id),
        ):
            if value is not None and not HEX64_RE.fullmatch(value):
                raise RecoveryError(f"{label} must be lowercase SHA-256 hex")
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
    except (RecoveryError, discovery.DiscoveryError) as exc:
        print(f"K210_RECOVERY_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
