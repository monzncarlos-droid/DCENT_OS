#!/usr/bin/env python3
"""Create and verify signed exact-route K210 rollback evidence bundles.

This host-only tool snapshots evidence from a completed, separately authorized
rollback qualification.  It has no miner, network, serial, USB, JTAG, ISP,
GPIO, programmer, flash, block-device, power, cooling, install, or release
transport.  A valid receipt records past observations and grants no authority
for future contact or mutation.
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


def _load_sibling(name: str):
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 evidence primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replacement = _load_sibling("k210_replacement_receipt.py")
boot_route = _load_sibling("k210_boot_route.py")
boot = replacement.boot
recovery = boot.recovery
discovery = boot.discovery

SCHEMA_VERSION = 1
SCOPE = replacement.SCOPE
DESCRIPTOR_KIND = "dcent_k210_exact_route_rollback_descriptor"
RECEIPT_KIND = "dcent_k210_exact_route_rollback_receipt"
DISPOSITION = "past_exact_route_rollback_evidence_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_rollback_operator"
WITNESS_ROLE = "k210_rollback_witness"
OPERATOR_NAMESPACE = "dcent-k210-rollback-operator-v1"
WITNESS_NAMESPACE = "dcent-k210-rollback-witness-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 64
MAX_EVIDENCE_FILE_BYTES = discovery.MAX_EVIDENCE_FILE_BYTES
MAX_TOTAL_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FLASH_DEVICES = recovery.MAX_FLASH_DEVICES
MAX_FLASH_BYTES = recovery.MAX_FLASH_BYTES

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

SUPPORTED_ROUTES = {"native_aes0_flash"}
INTERRUPTION_KINDS = {"power_loss", "process_termination", "transport_loss"}
ROLLBACK_ACTIONS = {
    "controlled_rollback_interruption",
    "exact_route_stock_restore",
    "full_flash_readback",
    "power_cycle_for_stock_validation",
    "replacement_artifact_identity_check",
    "stock_identity_verification",
}
ACTIONS_PERFORMED = {
    "controlled_rollback_interruption": True,
    "custom_firmware_written": False,
    "full_flash_readback": True,
    "production_hashing_commanded": False,
    "replacement_artifact_observed_before_rollback": True,
    "stock_cold_boot_validated": True,
    "stock_flash_restored": True,
    "stock_identity_matched": True,
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_debug_access": False,
    "authorizes_future_flash_write": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_install": False,
    "authorizes_jtag_or_isp_access": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}
PREDECESSOR_KINDS = {
    "boot_policy_receipt_copy",
    "boot_route_adjudication_copy",
    "discovery_receipt_copy",
    "recovery_receipt_copy",
    "replacement_firmware_receipt_copy",
}
EVIDENCE_KINDS = PREDECESSOR_KINDS | {
    "full_readback_image",
    "pre_rollback_artifact_record",
    "rollback_execution_log",
    "rollback_interruption_log",
    "stock_cold_boot_record",
    "stock_identity_record",
}
MEDIA_TYPES = {"application/json", "application/octet-stream", "text/plain"}
EVIDENCE_METHODS = {"authorized_rollback_execution", "offline_artifact"}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}


class RollbackError(RuntimeError):
    """A rollback descriptor, bundle, evidence, or trust join failed."""


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
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise RollbackError(f"{context} keys invalid: {'; '.join(details)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RollbackError(f"{context} must be a non-empty string <= {maximum} chars")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise RollbackError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise RollbackError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not PRINCIPAL_RE.fullmatch(text):
        raise RollbackError(f"{context} is not a canonical signer principal")
    return text


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise RollbackError(f"{context} must be lowercase SHA-256")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise RollbackError(f"{context} must be boolean")
    return value


def _positive_int(value: Any, context: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise RollbackError(f"{context} must be an integer in 1..{maximum}")
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise RollbackError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RollbackError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise RollbackError(f"{context} must be a portable POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise RollbackError(f"{context} must be a canonical relative path")
    if any(part in ("", ".", "..") for part in path.parts):
        raise RollbackError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise RollbackError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise RollbackError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise RollbackError(str(exc)) from exc


def _hash_source(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise RollbackError(str(exc)) from exc


def _validate_stock_identity(value: Any) -> None:
    if not isinstance(value, dict):
        raise RollbackError("stock_identity must be an object")
    fields = (
        "stock_dna",
        "stock_firmware_version",
        "stock_hwtype",
        "stock_swtype",
    )
    _require_exact_keys(value, fields, "stock_identity")
    for field in fields:
        _text(value[field], f"stock_identity.{field}", 160)


def _validate_evidence(value: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVIDENCE_ITEMS:
        raise RollbackError(f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records")
    ids: set[str] = set()
    paths: set[str] = set()
    counts: dict[str, int] = {}
    normalized = []
    for index, item in enumerate(value):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise RollbackError(f"{context} must be an object")
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
            keys = tuple(key for key in keys if key not in {"bytes", "sha256"})
        _require_exact_keys(item, keys, context)
        evidence_id = _identifier(item["id"], f"{context}.id")
        if evidence_id in ids:
            raise RollbackError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise RollbackError(f"{context}.kind is unsupported")
        counts[kind] = counts.get(kind, 0) + 1
        if item["media_type"] not in MEDIA_TYPES:
            raise RollbackError(f"{context}.media_type is unsupported")
        if item["method"] not in EVIDENCE_METHODS:
            raise RollbackError(f"{context}.method is unsupported")
        expected_method = (
            "offline_artifact"
            if kind in PREDECESSOR_KINDS
            else "authorized_rollback_execution"
        )
        if item["method"] != expected_method:
            raise RollbackError(f"{context}.method does not match its evidence kind")
        if item["redaction"] not in REDACTION_STATES:
            raise RollbackError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise RollbackError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _positive_int(item["bytes"], f"{context}.bytes", MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    exact_one = PREDECESSOR_KINDS | {
        "pre_rollback_artifact_record",
        "rollback_execution_log",
        "rollback_interruption_log",
    }
    for kind in sorted(exact_one):
        if counts.get(kind) != 1:
            raise RollbackError(f"rollback evidence requires exactly one {kind}")
    return normalized


def _evidence_ref(
    evidence: Mapping[str, Mapping[str, Any]],
    value: Any,
    kind: str,
    context: str,
) -> Mapping[str, Any]:
    evidence_id = _identifier(value, context)
    item = evidence.get(evidence_id)
    if item is None or item["kind"] != kind:
        raise RollbackError(f"{context} must reference {kind} evidence")
    return item


def _validate_readbacks(
    value: Any,
    devices: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    context: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(devices):
        raise RollbackError(
            f"{context} must cover every recovery flash device exactly once"
        )
    observed: set[str] = set()
    normalized = []
    for index, result in enumerate(value):
        item_context = f"{context}[{index}]"
        if not isinstance(result, dict):
            raise RollbackError(f"{item_context} must be an object")
        _require_exact_keys(
            result,
            (
                "baseline_backup_evidence_id",
                "flash_device_id",
                "full_device_readback",
                "readback_evidence_id",
                "readback_matches_stock",
            ),
            item_context,
        )
        device_id = _identifier(
            result["flash_device_id"], f"{item_context}.flash_device_id"
        )
        if device_id not in devices or device_id in observed:
            raise RollbackError(f"{context} has an unknown or duplicate flash device")
        observed.add(device_id)
        device = devices[device_id]
        backup_ids = {row["artifact_evidence_id"] for row in device["backup_reads"]}
        baseline = _identifier(
            result["baseline_backup_evidence_id"],
            f"{item_context}.baseline_backup_evidence_id",
        )
        if baseline not in backup_ids:
            raise RollbackError(
                f"{item_context} baseline is not an admitted recovery backup"
            )
        _evidence_ref(
            evidence,
            result["readback_evidence_id"],
            "full_readback_image",
            f"{item_context}.readback_evidence_id",
        )
        if (
            _boolean(
                result["full_device_readback"], f"{item_context}.full_device_readback"
            )
            is not True
        ):
            raise RollbackError(f"{item_context} must be a full-device readback")
        if (
            _boolean(
                result["readback_matches_stock"],
                f"{item_context}.readback_matches_stock",
            )
            is not True
        ):
            raise RollbackError(f"{item_context} must claim a stock match")
        normalized.append(dict(result))
    return normalized


def _validate_execution(
    value: Any,
    devices: Mapping[str, Mapping[str, Any]],
    restore_paths: set[str],
    evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    if not isinstance(value, dict):
        raise RollbackError("rollback_execution must be an object")
    _require_exact_keys(
        value,
        (
            "cold_boot_evidence_id",
            "completed_at_utc",
            "log_evidence_id",
            "pre_rollback_artifact_evidence_id",
            "readbacks",
            "replacement_artifact_absent_after_rollback",
            "restore_path_id",
            "started_at_utc",
            "stock_booted",
            "stock_identity_evidence_id",
            "stock_identity_matched",
        ),
        "rollback_execution",
    )
    started = _utc(value["started_at_utc"], "rollback_execution.started_at_utc")
    completed = _utc(value["completed_at_utc"], "rollback_execution.completed_at_utc")
    if started >= completed:
        raise RollbackError("rollback execution start must precede completion")
    path_id = _identifier(
        value["restore_path_id"], "rollback_execution.restore_path_id"
    )
    if path_id not in restore_paths:
        raise RollbackError(
            "rollback execution restore path is not admitted by recovery"
        )
    _evidence_ref(
        evidence,
        value["pre_rollback_artifact_evidence_id"],
        "pre_rollback_artifact_record",
        "rollback_execution.pre_rollback_artifact_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["log_evidence_id"],
        "rollback_execution_log",
        "rollback_execution.log_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["cold_boot_evidence_id"],
        "stock_cold_boot_record",
        "rollback_execution.cold_boot_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["stock_identity_evidence_id"],
        "stock_identity_record",
        "rollback_execution.stock_identity_evidence_id",
    )
    _validate_readbacks(
        value["readbacks"], devices, evidence, "rollback_execution.readbacks"
    )
    for field in (
        "replacement_artifact_absent_after_rollback",
        "stock_booted",
        "stock_identity_matched",
    ):
        if _boolean(value[field], f"rollback_execution.{field}") is not True:
            raise RollbackError(f"rollback_execution.{field} must be true")


def _validate_interruption(
    value: Any,
    devices: Mapping[str, Mapping[str, Any]],
    restore_paths: set[str],
    evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    if not isinstance(value, dict):
        raise RollbackError("interruption_drill must be an object")
    _require_exact_keys(
        value,
        (
            "attempted_restore_path_id",
            "cold_boot_evidence_id",
            "interrupted_after_bytes",
            "interruption_kind",
            "log_evidence_id",
            "passed",
            "readbacks",
            "recovered_by_restore_path_id",
            "stock_booted",
            "stock_identity_evidence_id",
            "stock_identity_matched",
        ),
        "interruption_drill",
    )
    attempted = _identifier(
        value["attempted_restore_path_id"],
        "interruption_drill.attempted_restore_path_id",
    )
    recovered = _identifier(
        value["recovered_by_restore_path_id"],
        "interruption_drill.recovered_by_restore_path_id",
    )
    if attempted not in restore_paths or recovered not in restore_paths:
        raise RollbackError("interruption drill uses an unadmitted recovery path")
    if attempted == recovered:
        raise RollbackError(
            "interruption drill must recover through the other admitted path"
        )
    if value["interruption_kind"] not in INTERRUPTION_KINDS:
        raise RollbackError("interruption_drill.interruption_kind is unsupported")
    total_capacity = sum(int(device["capacity_bytes"]) for device in devices.values())
    interrupted = _positive_int(
        value["interrupted_after_bytes"],
        "interruption_drill.interrupted_after_bytes",
        MAX_FLASH_BYTES,
    )
    if interrupted >= total_capacity:
        raise RollbackError(
            "interruption must occur before the full stock restore completes"
        )
    _evidence_ref(
        evidence,
        value["log_evidence_id"],
        "rollback_interruption_log",
        "interruption_drill.log_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["cold_boot_evidence_id"],
        "stock_cold_boot_record",
        "interruption_drill.cold_boot_evidence_id",
    )
    _evidence_ref(
        evidence,
        value["stock_identity_evidence_id"],
        "stock_identity_record",
        "interruption_drill.stock_identity_evidence_id",
    )
    _validate_readbacks(
        value["readbacks"], devices, evidence, "interruption_drill.readbacks"
    )
    for field in ("passed", "stock_booted", "stock_identity_matched"):
        if _boolean(value[field], f"interruption_drill.{field}") is not True:
            raise RollbackError(f"interruption_drill.{field} must be true")


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise RollbackError("signing must be an object")
    _require_exact_keys(value, ("operator", "witness"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "witness": (WITNESS_ROLE, WITNESS_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise RollbackError(f"signing.{name} must be an object")
        _require_exact_keys(
            item,
            ("algorithm", "key_id_sha256", "namespace", "role"),
            f"signing.{name}",
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role
        ):
            raise RollbackError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise RollbackError("operator and witness signing keys must be distinct")


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> dict[str, Mapping[str, Any]]:
    core_keys = (
        "actions_performed",
        "authorization",
        "boot_policy_receipt_id",
        "completed_at_utc",
        "discovery_receipt_id",
        "evidence",
        "interruption_drill",
        "kind",
        "operator_id",
        "recovery_receipt_id",
        "replacement_firmware_receipt_id",
        "rollback_execution",
        "route_adjudication_sha256",
        "schema_version",
        "scope",
        "selected_route",
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
        "stock_restoration_sha256",
    )
    _require_exact_keys(
        value, core_keys + receipt_only if receipt else core_keys, "rollback record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise RollbackError("rollback schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind:
        raise RollbackError("rollback record kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    for field in (
        "boot_policy_receipt_id",
        "discovery_receipt_id",
        "recovery_receipt_id",
        "replacement_firmware_receipt_id",
        "route_adjudication_sha256",
        "stock_backup_set_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], field)
    selected_route = _identifier(value["selected_route"], "selected_route")
    if selected_route not in SUPPORTED_ROUTES:
        raise RollbackError(
            "rollback schema v1 supports only the admitted native_aes0_flash route"
        )
    operator = _principal(value["operator_id"], "operator_id")
    witness = _principal(value["witness_id"], "witness_id")
    if operator == witness:
        raise RollbackError("rollback operator and witness must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise RollbackError("rollback start must precede completion")
    if value["actions_performed"] != ACTIONS_PERFORMED:
        raise RollbackError("rollback actions_performed contract drifted")
    _validate_stock_identity(value["stock_identity"])

    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise RollbackError("authorization must be an object")
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
        raise RollbackError(
            "rollback qualification is outside the authorization interval"
        )
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or set(actions) != ROLLBACK_ACTIONS
        or len(actions) != len(ROLLBACK_ACTIONS)
    ):
        raise RollbackError(
            "authorization does not contain the exact rollback action set"
        )

    evidence = _validate_evidence(value["evidence"], hashed=receipt)
    evidence_by_id = {item["id"]: item for item in evidence}
    for index, item in enumerate(evidence):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise RollbackError(f"evidence[{index}] is outside rollback chronology")

    recovery_copy = next(
        item for item in evidence if item["kind"] == "recovery_receipt_copy"
    )
    # Core validation cannot read the predecessor yet. Device coverage is
    # validated against the canonical recovery copy during build/verify.
    if not isinstance(value["rollback_execution"], dict):
        raise RollbackError("rollback_execution must be an object")
    if not isinstance(value["interruption_drill"], dict):
        raise RollbackError("interruption_drill must be an object")
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise RollbackError("rollback authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise RollbackError("rollback disposition drifted")
        for field in ("descriptor_sha256", "receipt_id", "stock_restoration_sha256"):
            _sha(value[field], field)
        _validate_signing(value["signing"])
    return {"recovery_copy": recovery_copy, "evidence": evidence_by_id}


def _boot_result_from_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    flash_digest = hashlib.sha256(
        b"DCENT-K210-FLASH-POLICY-V1\x00"
        + boot.canonical_json_bytes(receipt["flash_policy"])
    ).hexdigest()
    rom = receipt["rom_isp_policy"]
    jtag = receipt["jtag_policy"]
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
            name: jtag[name]
            for name in ("halt_capable", "read_memory_capable", "write_memory_capable")
        },
        "jtag_state": jtag["state"],
        "plaintext_boot_supported": receipt["plaintext_probe"][
            "plaintext_boot_supported"
        ],
        "plaintext_probe_performed": receipt["plaintext_probe"]["performed"],
        "plaintext_probe_result": receipt["plaintext_probe"]["result"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "rom_isp_capabilities": {
            name: rom[name]
            for name in (
                "erase_capable",
                "existing_flash_independent",
                "read_capable",
                "write_capable",
            )
        },
        "rom_isp_state": rom["state"],
        "state": "verified_signed_boot_policy_measurement",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
    }


def _validate_predecessor_records(
    manifest: Mapping[str, Any],
    discovery_receipt: Mapping[str, Any],
    recovery_receipt: Mapping[str, Any],
    boot_receipt: Mapping[str, Any],
    replacement_receipt: Mapping[str, Any],
    route_record: Mapping[str, Any],
    rollback_record: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    try:
        discovery._validate_receipt(discovery_receipt, manifest)
        recovery._validate_receipt(recovery_receipt, manifest)
        boot._validate_receipt(boot_receipt, manifest)
        replacement._validate_receipt(replacement_receipt, manifest)
    except (
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        replacement.ReplacementError,
    ) as exc:
        raise RollbackError(f"predecessor receipt is invalid: {exc}") from exc

    target_id = discovery_receipt["target_id"]
    expected = {
        "target_id": target_id,
        "unit_label": discovery_receipt["unit_label"],
        "unit_fingerprint_sha256": discovery_receipt["unit_fingerprint_sha256"],
        "discovery_receipt_id": discovery_receipt["receipt_id"],
        "recovery_receipt_id": recovery_receipt["receipt_id"],
        "boot_policy_receipt_id": boot_receipt["receipt_id"],
        "replacement_firmware_receipt_id": replacement_receipt["receipt_id"],
        "stock_backup_set_sha256": recovery_receipt["stock_backup_set_sha256"],
    }
    joins = (
        (recovery_receipt, "target_id", expected["target_id"], "recovery"),
        (recovery_receipt, "unit_label", expected["unit_label"], "recovery"),
        (
            recovery_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
            "recovery",
        ),
        (
            recovery_receipt,
            "discovery_receipt_id",
            expected["discovery_receipt_id"],
            "recovery",
        ),
        (boot_receipt, "target_id", expected["target_id"], "boot-policy"),
        (boot_receipt, "unit_label", expected["unit_label"], "boot-policy"),
        (
            boot_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
            "boot-policy",
        ),
        (
            boot_receipt,
            "discovery_receipt_id",
            expected["discovery_receipt_id"],
            "boot-policy",
        ),
        (
            boot_receipt,
            "recovery_receipt_id",
            expected["recovery_receipt_id"],
            "boot-policy",
        ),
        (
            boot_receipt,
            "stock_backup_set_sha256",
            expected["stock_backup_set_sha256"],
            "boot-policy",
        ),
        (replacement_receipt, "target_id", expected["target_id"], "replacement"),
        (replacement_receipt, "unit_label", expected["unit_label"], "replacement"),
        (
            replacement_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
            "replacement",
        ),
        (
            replacement_receipt,
            "discovery_receipt_id",
            expected["discovery_receipt_id"],
            "replacement",
        ),
        (
            replacement_receipt,
            "recovery_receipt_id",
            expected["recovery_receipt_id"],
            "replacement",
        ),
        (
            replacement_receipt,
            "boot_policy_receipt_id",
            expected["boot_policy_receipt_id"],
            "replacement",
        ),
        (
            replacement_receipt,
            "stock_backup_set_sha256",
            expected["stock_backup_set_sha256"],
            "replacement",
        ),
    )
    for source, key, wanted, label in joins:
        if source[key] != wanted:
            raise RollbackError(f"{label} receipt {key} does not exact-join rollback")
    for key, wanted in discovery_receipt["identity"].items():
        if (
            key in recovery_receipt["stock_identity"]
            and recovery_receipt["stock_identity"][key] != wanted
        ):
            raise RollbackError(
                f"recovery stock identity {key} does not join discovery"
            )

    try:
        expected_route = boot_route.adjudicate(_boot_result_from_receipt(boot_receipt))
    except boot_route.BootRouteError as exc:
        raise RollbackError(f"boot-route adjudication is invalid: {exc}") from exc
    if route_record != expected_route:
        raise RollbackError(
            "boot-route adjudication does not reproduce from boot evidence"
        )
    if route_record["selected_route"] not in SUPPORTED_ROUTES:
        raise RollbackError("selected route is not supported by rollback schema v1")
    if route_record["selected_route_state"] != "measured_compatible":
        raise RollbackError("selected route is not measured compatible")
    if route_record["authority_granted"] is not False:
        raise RollbackError("boot-route record exceeds its authority ceiling")
    expected["route_adjudication_sha256"] = route_record["adjudication_sha256"]
    expected["selected_route"] = route_record["selected_route"]
    expected["artifact_set_sha256"] = replacement_receipt["artifact_set_sha256"]
    expected["stock_identity"] = {
        key: discovery_receipt["identity"][key]
        for key in (
            "stock_dna",
            "stock_firmware_version",
            "stock_hwtype",
            "stock_swtype",
        )
    }
    if rollback_record is not None:
        fields = (
            "target_id",
            "unit_label",
            "unit_fingerprint_sha256",
            "discovery_receipt_id",
            "recovery_receipt_id",
            "boot_policy_receipt_id",
            "replacement_firmware_receipt_id",
            "stock_backup_set_sha256",
            "route_adjudication_sha256",
            "selected_route",
        )
        for key in fields:
            if rollback_record[key] != expected[key]:
                raise RollbackError(f"predecessor chain {key} does not match rollback")
        if rollback_record["stock_identity"] != expected["stock_identity"]:
            raise RollbackError("predecessor stock identity does not match rollback")
    return expected


def _load_copy(
    evidence: Sequence[Mapping[str, Any]],
    evidence_root: Path,
    kind: str,
    label: str,
) -> dict[str, Any]:
    matches = [item for item in evidence if item["kind"] == kind]
    if len(matches) != 1:
        raise RollbackError(f"exactly one {kind} is required")
    source = _source(
        evidence_root,
        _safe_path(matches[0]["path"], f"{label} evidence path"),
    )
    return _load_json(source, label, canonical=True)


def _load_predecessor_copies(
    manifest: Mapping[str, Any], record: Mapping[str, Any], evidence_root: Path
) -> dict[str, Any]:
    evidence = record["evidence"]
    discovery_receipt = _load_copy(
        evidence, evidence_root, "discovery_receipt_copy", "discovery receipt copy"
    )
    recovery_receipt = _load_copy(
        evidence, evidence_root, "recovery_receipt_copy", "recovery receipt copy"
    )
    boot_receipt = _load_copy(
        evidence, evidence_root, "boot_policy_receipt_copy", "boot-policy receipt copy"
    )
    replacement_receipt = _load_copy(
        evidence,
        evidence_root,
        "replacement_firmware_receipt_copy",
        "replacement-firmware receipt copy",
    )
    route_record = _load_copy(
        evidence,
        evidence_root,
        "boot_route_adjudication_copy",
        "boot-route adjudication copy",
    )
    joined = _validate_predecessor_records(
        manifest,
        discovery_receipt,
        recovery_receipt,
        boot_receipt,
        replacement_receipt,
        route_record,
        record,
    )
    return {
        "boot": boot_receipt,
        "discovery": discovery_receipt,
        "joined": joined,
        "recovery": recovery_receipt,
        "replacement": replacement_receipt,
        "route": route_record,
    }


def _validate_json_record(path: Path, expected: Mapping[str, Any], label: str) -> None:
    observed = _load_json(path, label, canonical=True)
    if observed != expected:
        raise RollbackError(
            f"{label} semantics do not match the signed rollback record"
        )


def _validate_semantic_evidence(
    record: Mapping[str, Any],
    evidence_root: Path,
    predecessors: Mapping[str, Any],
) -> None:
    evidence = {item["id"]: item for item in record["evidence"]}
    recovery_receipt = predecessors["recovery"]
    replacement_receipt = predecessors["replacement"]
    devices = {device["id"]: device for device in recovery_receipt["flash_devices"]}
    if not 1 <= len(devices) <= MAX_FLASH_DEVICES:
        raise RollbackError("recovery receipt has invalid flash-device coverage")
    restore_paths = {item["id"] for item in recovery_receipt["restore_paths"]}
    _validate_execution(record["rollback_execution"], devices, restore_paths, evidence)
    _validate_interruption(
        record["interruption_drill"], devices, restore_paths, evidence
    )

    used_ids = {
        item["id"] for item in record["evidence"] if item["kind"] in PREDECESSOR_KINDS
    }
    execution = record["rollback_execution"]
    interruption = record["interruption_drill"]
    used_ids.update(
        {
            execution["pre_rollback_artifact_evidence_id"],
            execution["log_evidence_id"],
            execution["cold_boot_evidence_id"],
            execution["stock_identity_evidence_id"],
            interruption["log_evidence_id"],
            interruption["cold_boot_evidence_id"],
            interruption["stock_identity_evidence_id"],
        }
    )
    for group in (execution["readbacks"], interruption["readbacks"]):
        used_ids.update(item["readback_evidence_id"] for item in group)
    if used_ids != set(evidence):
        raise RollbackError("rollback bundle contains unreferenced semantic evidence")

    common = {
        "authority_granted": False,
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    pre_artifact = {
        **common,
        "artifact_set_sha256": replacement_receipt["artifact_set_sha256"],
        "kind": "dcent_k210_pre_rollback_artifact_observation",
        "replacement_firmware_receipt_id": record["replacement_firmware_receipt_id"],
        "selected_route": record["selected_route"],
        "verified_running_before_rollback": True,
    }
    item = evidence[execution["pre_rollback_artifact_evidence_id"]]
    _validate_json_record(
        _source(evidence_root, _safe_path(item["path"], "pre-rollback artifact path")),
        pre_artifact,
        "pre-rollback artifact record",
    )
    execution_log = {
        **common,
        "completed": True,
        "faults": [],
        "kind": "dcent_k210_rollback_execution_log",
        "restore_path_id": execution["restore_path_id"],
        "route_adjudication_sha256": record["route_adjudication_sha256"],
        "selected_route": record["selected_route"],
        "stops": [],
    }
    item = evidence[execution["log_evidence_id"]]
    _validate_json_record(
        _source(evidence_root, _safe_path(item["path"], "rollback execution log path")),
        execution_log,
        "rollback execution log",
    )
    interruption_log = {
        **common,
        "attempted_restore_path_id": interruption["attempted_restore_path_id"],
        "interrupted_after_bytes": interruption["interrupted_after_bytes"],
        "interruption_kind": interruption["interruption_kind"],
        "interruption_observed": True,
        "kind": "dcent_k210_rollback_interruption_log",
        "recovered_by_restore_path_id": interruption["recovered_by_restore_path_id"],
    }
    item = evidence[interruption["log_evidence_id"]]
    _validate_json_record(
        _source(
            evidence_root, _safe_path(item["path"], "rollback interruption log path")
        ),
        interruption_log,
        "rollback interruption log",
    )
    boot_record = {
        **common,
        "kind": "dcent_k210_stock_cold_boot_observation",
        "production_hashing_commanded": False,
        "stock_booted": True,
    }
    identity_record = {
        **common,
        "identity": record["stock_identity"],
        "kind": "dcent_k210_stock_identity_observation",
        "stock_identity_matched": True,
    }
    for evidence_id in (
        execution["cold_boot_evidence_id"],
        interruption["cold_boot_evidence_id"],
    ):
        item = evidence[evidence_id]
        _validate_json_record(
            _source(evidence_root, _safe_path(item["path"], "stock boot record path")),
            boot_record,
            "stock cold-boot record",
        )
    for evidence_id in (
        execution["stock_identity_evidence_id"],
        interruption["stock_identity_evidence_id"],
    ):
        item = evidence[evidence_id]
        _validate_json_record(
            _source(
                evidence_root, _safe_path(item["path"], "stock identity record path")
            ),
            identity_record,
            "stock identity record",
        )

    recovery_evidence = {item["id"]: item for item in recovery_receipt["evidence"]}
    for context, group in (
        ("rollback execution", execution["readbacks"]),
        ("interruption recovery", interruption["readbacks"]),
    ):
        for result in group:
            baseline = recovery_evidence[result["baseline_backup_evidence_id"]]
            readback = evidence[result["readback_evidence_id"]]
            if baseline["kind"] != "stock_backup_image":
                raise RollbackError(f"{context} baseline is not a stock backup image")
            if (
                readback["bytes"] != baseline["bytes"]
                or readback["sha256"] != baseline["sha256"]
                or readback["bytes"]
                != devices[result["flash_device_id"]]["capacity_bytes"]
            ):
                raise RollbackError(
                    f"{context} readback bytes do not match admitted stock"
                )


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "receipt_id",
        "signing",
        "stock_restoration_sha256",
    }
    descriptor = {key: value for key, value in receipt.items() if key not in excluded}
    descriptor["kind"] = DESCRIPTOR_KIND
    descriptor["evidence"] = [
        {key: value for key, value in item.items() if key not in {"bytes", "sha256"}}
        for item in receipt["evidence"]
    ]
    return descriptor


def _restoration_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    evidence = {item["id"]: item for item in receipt["evidence"]}

    def project(group: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        projected = []
        for item in sorted(group, key=lambda row: row["flash_device_id"]):
            readback = evidence[item["readback_evidence_id"]]
            projected.append(
                {
                    "baseline_backup_evidence_id": item["baseline_backup_evidence_id"],
                    "bytes": readback["bytes"],
                    "flash_device_id": item["flash_device_id"],
                    "readback_evidence_id": item["readback_evidence_id"],
                    "sha256": readback["sha256"],
                }
            )
        return projected

    return {
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "interruption_readbacks": project(receipt["interruption_drill"]["readbacks"]),
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "replacement_firmware_receipt_id": receipt["replacement_firmware_receipt_id"],
        "rollback_readbacks": project(receipt["rollback_execution"]["readbacks"]),
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "selected_route": receipt["selected_route"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
    }


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _validate_core(receipt, manifest, receipt=True)
    descriptor = _descriptor_projection(receipt)
    if (
        hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
        != receipt["descriptor_sha256"]
    ):
        raise RollbackError("rollback descriptor SHA-256 mismatch")
    restoration_digest = hashlib.sha256(
        b"DCENT-K210-STOCK-RESTORATION-V1\x00"
        + canonical_json_bytes(_restoration_projection(receipt))
    ).hexdigest()
    if restoration_digest != receipt["stock_restoration_sha256"]:
        raise RollbackError("stock-restoration SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-ROLLBACK-RECEIPT-ID-V1\x00" + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise RollbackError("rollback receipt ID mismatch")


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
            raise RollbackError("rollback evidence exceeds the aggregate byte limit")
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
        sources[item["id"]] = source
    try:
        operator_key = discovery.inspect_private_key(operator_private_key)
        witness_key = discovery.inspect_private_key(witness_private_key)
    except discovery.DiscoveryError as exc:
        raise RollbackError(f"rollback signing key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RollbackError("operator and witness private keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(ROLLBACK_ACTIONS)
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
    receipt["stock_restoration_sha256"] = hashlib.sha256(
        b"DCENT-K210-STOCK-RESTORATION-V1\x00"
        + canonical_json_bytes(_restoration_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-ROLLBACK-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest)
    predecessors = _load_predecessor_copies(manifest, receipt, evidence_root)
    _validate_semantic_evidence(receipt, evidence_root, predecessors)
    return receipt, sources


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists() or bundle_out.is_symlink():
        raise RollbackError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(descriptor_path, "rollback descriptor", canonical=False)
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
                raise RollbackError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        try:
            operator_signature = discovery.sign_sshsig_file(
                receipt_path, operator_private_key, OPERATOR_NAMESPACE
            )
            witness_signature = discovery.sign_sshsig_file(
                receipt_path, witness_private_key, WITNESS_NAMESPACE
            )
        except discovery.DiscoveryError as exc:
            raise RollbackError(f"rollback signing failed: {exc}") from exc
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
            raise RollbackError("a rollback signing key changed during bundle creation")
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
    expected_operator_key_id: Optional[str] = None,
    expected_witness_key_id: Optional[str] = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise RollbackError(f"rollback bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise RollbackError("rollback bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "rollback receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        witness_key = discovery.inspect_public_key(witness_public_key)
    except discovery.DiscoveryError as exc:
        raise RollbackError(f"rollback trust key is invalid: {exc}") from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RollbackError("operator and witness trust keys must be distinct")
    try:
        receipt_raw = discovery._read_regular(
            receipt_path, "rollback receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise RollbackError(str(exc)) from exc
    if receipt_raw != canonical_json_bytes(receipt):
        raise RollbackError("rollback receipt changed after validation")
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
            raise RollbackError(
                f"{role} public key does not match the manifest trust anchor"
            )
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise RollbackError(f"rollback receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw,
                signature_path,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise RollbackError(f"rollback {role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RollbackError("rollback evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise RollbackError(f"evidence {item['id']} digest or size mismatch")
    predecessors = _load_predecessor_copies(
        manifest, receipt, bundle / EVIDENCE_DIRECTORY
    )
    _validate_semantic_evidence(receipt, bundle / EVIDENCE_DIRECTORY, predecessors)
    _verify_exact_members(bundle, receipt)
    return {
        "authority_granted": False,
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "replacement_firmware_receipt_id": receipt["replacement_firmware_receipt_id"],
        "rollback_recovery_gate_eligible": True,
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "selected_route": receipt["selected_route"],
        "state": "verified_signed_exact_route_rollback",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "stock_restoration_sha256": receipt["stock_restoration_sha256"],
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
            raise RollbackError(f"rollback bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RollbackError(
                    f"rollback bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise RollbackError(
                    f"rollback bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise RollbackError(
                    f"rollback bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise RollbackError("rollback bundle member set is not exact")


def _template(
    manifest: Mapping[str, Any],
    discovery_receipt_path: Path,
    recovery_receipt_path: Path,
    boot_receipt_path: Path,
    replacement_receipt_path: Path,
    route_adjudication_path: Path,
) -> dict[str, Any]:
    discovery_receipt = _load_json(
        discovery_receipt_path, "discovery receipt", canonical=True
    )
    recovery_receipt = _load_json(
        recovery_receipt_path, "recovery receipt", canonical=True
    )
    boot_receipt = _load_json(boot_receipt_path, "boot-policy receipt", canonical=True)
    replacement_receipt = _load_json(
        replacement_receipt_path, "replacement-firmware receipt", canonical=True
    )
    route_record = _load_json(
        route_adjudication_path, "boot-route adjudication", canonical=True
    )
    joined = _validate_predecessor_records(
        manifest,
        discovery_receipt,
        recovery_receipt,
        boot_receipt,
        replacement_receipt,
        route_record,
    )

    evidence = []

    def add(evidence_id: str, kind: str, path: str, media_type: str) -> None:
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T00:40:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": media_type,
                "method": (
                    "offline_artifact"
                    if kind in PREDECESSOR_KINDS
                    else "authorized_rollback_execution"
                ),
                "path": path,
                "redaction": "none",
            }
        )

    copies = (
        ("discovery-receipt", "discovery_receipt_copy", "predecessors/discovery.json"),
        ("recovery-receipt", "recovery_receipt_copy", "predecessors/recovery.json"),
        (
            "boot-policy-receipt",
            "boot_policy_receipt_copy",
            "predecessors/boot-policy.json",
        ),
        (
            "replacement-receipt",
            "replacement_firmware_receipt_copy",
            "predecessors/replacement.json",
        ),
        (
            "route-adjudication",
            "boot_route_adjudication_copy",
            "predecessors/route.json",
        ),
    )
    for evidence_id, kind, path in copies:
        add(evidence_id, kind, path, "application/json")
    add(
        "pre-rollback-artifact",
        "pre_rollback_artifact_record",
        "records/pre-rollback-artifact.json",
        "application/json",
    )
    add(
        "rollback-log",
        "rollback_execution_log",
        "records/rollback.json",
        "application/json",
    )
    add(
        "rollback-boot",
        "stock_cold_boot_record",
        "records/rollback-boot.json",
        "application/json",
    )
    add(
        "rollback-identity",
        "stock_identity_record",
        "records/rollback-identity.json",
        "application/json",
    )
    add(
        "interruption-log",
        "rollback_interruption_log",
        "records/interruption.json",
        "application/json",
    )
    add(
        "interruption-boot",
        "stock_cold_boot_record",
        "records/interruption-boot.json",
        "application/json",
    )
    add(
        "interruption-identity",
        "stock_identity_record",
        "records/interruption-identity.json",
        "application/json",
    )

    rollback_readbacks = []
    interruption_readbacks = []
    for device in sorted(recovery_receipt["flash_devices"], key=lambda row: row["id"]):
        baseline = sorted(
            device["backup_reads"], key=lambda row: row["artifact_evidence_id"]
        )[0]["artifact_evidence_id"]
        rollback_id = f"rollback-readback-{device['id']}"
        interruption_id = f"interruption-readback-{device['id']}"
        add(
            rollback_id,
            "full_readback_image",
            f"readbacks/rollback-{device['id']}.bin",
            "application/octet-stream",
        )
        add(
            interruption_id,
            "full_readback_image",
            f"readbacks/interruption-{device['id']}.bin",
            "application/octet-stream",
        )
        common = {
            "baseline_backup_evidence_id": baseline,
            "flash_device_id": device["id"],
            "full_device_readback": True,
            "readback_matches_stock": True,
        }
        rollback_readbacks.append({**common, "readback_evidence_id": rollback_id})
        interruption_readbacks.append(
            {**common, "readback_evidence_id": interruption_id}
        )

    restore_paths = sorted(item["id"] for item in recovery_receipt["restore_paths"])
    if len(restore_paths) < 2:
        raise RollbackError(
            "recovery receipt lacks two interruption-safe restore paths"
        )
    descriptor = {
        "actions_performed": dict(ACTIONS_PERFORMED),
        "authorization": {
            "authorized_actions": sorted(ROLLBACK_ACTIONS),
            "operator_reference": "REPLACE_WITH_OPERATOR_AUTHORIZATION_REFERENCE",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T01:00:00Z",
        },
        "boot_policy_receipt_id": joined["boot_policy_receipt_id"],
        "completed_at_utc": "2026-01-01T00:50:00Z",
        "discovery_receipt_id": joined["discovery_receipt_id"],
        "evidence": evidence,
        "interruption_drill": {
            "attempted_restore_path_id": restore_paths[0],
            "cold_boot_evidence_id": "interruption-boot",
            "interrupted_after_bytes": 1,
            "interruption_kind": "power_loss",
            "log_evidence_id": "interruption-log",
            "passed": True,
            "readbacks": interruption_readbacks,
            "recovered_by_restore_path_id": restore_paths[1],
            "stock_booted": True,
            "stock_identity_evidence_id": "interruption-identity",
            "stock_identity_matched": True,
        },
        "kind": DESCRIPTOR_KIND,
        "operator_id": "REPLACE",
        "recovery_receipt_id": joined["recovery_receipt_id"],
        "replacement_firmware_receipt_id": joined["replacement_firmware_receipt_id"],
        "rollback_execution": {
            "cold_boot_evidence_id": "rollback-boot",
            "completed_at_utc": "2026-01-01T00:30:00Z",
            "log_evidence_id": "rollback-log",
            "pre_rollback_artifact_evidence_id": "pre-rollback-artifact",
            "readbacks": rollback_readbacks,
            "replacement_artifact_absent_after_rollback": True,
            "restore_path_id": restore_paths[0],
            "started_at_utc": "2026-01-01T00:10:00Z",
            "stock_booted": True,
            "stock_identity_evidence_id": "rollback-identity",
            "stock_identity_matched": True,
        },
        "route_adjudication_sha256": joined["route_adjudication_sha256"],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "selected_route": joined["selected_route"],
        "started_at_utc": "2026-01-01T00:05:00Z",
        "stock_backup_set_sha256": joined["stock_backup_set_sha256"],
        "stock_identity": joined["stock_identity"],
        "target_id": joined["target_id"],
        "unit_fingerprint_sha256": joined["unit_fingerprint_sha256"],
        "unit_label": joined["unit_label"],
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
        "template", help="write a rollback descriptor bound to the predecessor chain"
    )
    template.add_argument("--discovery-receipt", type=Path, required=True)
    template.add_argument("--recovery-receipt", type=Path, required=True)
    template.add_argument("--boot-policy-receipt", type=Path, required=True)
    template.add_argument("--replacement-receipt", type=Path, required=True)
    template.add_argument("--route-adjudication", type=Path, required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign completed rollback evidence"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed rollback bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--operator-public-key", type=Path, required=True)
    verify.add_argument("--witness-public-key", type=Path, required=True)
    verify.add_argument("--expected-operator-key-id")
    verify.add_argument("--expected-witness-key-id")
    verify.add_argument("--format", choices=("json", "text"), default="text")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
        if args.command == "template":
            descriptor = _template(
                manifest,
                args.discovery_receipt,
                args.recovery_receipt,
                args.boot_policy_receipt,
                args.replacement_receipt,
                args.route_adjudication,
            )
            try:
                discovery._write_new(
                    args.out,
                    (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode(
                        "ascii"
                    ),
                    "rollback descriptor template",
                )
            except discovery.DiscoveryError as exc:
                raise RollbackError(str(exc)) from exc
            print(
                f"K210_ROLLBACK_TEMPLATE_WRITTEN target={descriptor['target_id']} "
                f"route={descriptor['selected_route']} path={args.out}"
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
                f"K210_ROLLBACK_BUNDLE_CREATED target={receipt['target_id']} "
                f"route={receipt['selected_route']} receipt_id={receipt['receipt_id']} "
                f"disposition={receipt['disposition']}"
            )
            return 0
        for label, value in (
            ("--expected-operator-key-id", args.expected_operator_key_id),
            ("--expected-witness-key-id", args.expected_witness_key_id),
        ):
            if value is not None and not HEX64_RE.fullmatch(value):
                raise RollbackError(f"{label} must be lowercase SHA-256 hex")
        result = verify_bundle(
            manifest,
            args.bundle,
            args.operator_public_key,
            args.witness_public_key,
            args.expected_operator_key_id,
            args.expected_witness_key_id,
        )
        if args.format == "json":
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"K210_ROLLBACK_VERIFIED target={result['target_id']} "
                f"route={result['selected_route']} receipt_id={result['receipt_id']} "
                "gate_eligible=true authority_granted=false"
            )
        return 0
    except (
        RollbackError,
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        replacement.ReplacementError,
        boot_route.BootRouteError,
    ) as exc:
        print(f"K210_ROLLBACK_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
