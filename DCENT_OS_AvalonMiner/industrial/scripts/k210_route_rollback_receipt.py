#!/usr/bin/env python3
"""Create and verify route-aware K210 rollback qualification receipts.

This schema-2 host-only tool snapshots a completed, separately authorized
rollback drill for a schema-2 route replacement artifact. It has no hardware,
install, power, cooling, or release transport and grants no future authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
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


route_replacement = _load_sibling("k210_route_replacement_receipt.py")
boot_route = route_replacement.boot_route
boot = route_replacement.boot
recovery = route_replacement.recovery
discovery = route_replacement.discovery

SCHEMA_VERSION = 2
SCOPE = route_replacement.SCOPE
DESCRIPTOR_KIND = "dcent_k210_route_rollback_descriptor"
RECEIPT_KIND = "dcent_k210_route_rollback_receipt"
DISPOSITION = "past_route_rollback_evidence_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
EVIDENCE_DIRECTORY = "evidence"
OPERATOR_ROLE = "k210_route_rollback_operator"
WITNESS_ROLE = "k210_route_rollback_witness"
OPERATOR_NAMESPACE = "dcent-k210-route-rollback-operator-v2"
WITNESS_NAMESPACE = "dcent-k210-route-rollback-witness-v2"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

ROUTES = route_replacement.ROUTES
SRAM_ROUTES = route_replacement.SRAM_ROUTES
MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 48
MAX_EVIDENCE_FILE_BYTES = discovery.MAX_EVIDENCE_FILE_BYTES
MAX_TOTAL_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024

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
COMMON_ACTIONS = {
    "controlled_route_interruption",
    "full_stock_flash_readback",
    "independent_stock_recovery",
    "replacement_artifact_absence_check",
    "stock_cold_boot_validation",
    "stock_identity_validation",
}
ROUTE_ACTION = {
    "native_aes0_flash": "native_aes0_update_interruption",
    "rom_isp_sram_bootstrap": "sram_bootstrap_abort_and_reset",
    "jtag_sram_bootstrap": "sram_bootstrap_abort_and_reset",
    "clean_replacement_controller": "replacement_controller_safe_disconnect_reconnect",
}
ACTIONS_PERFORMED = {
    "artifact_absent_after_rollback": True,
    "controlled_interruption_completed": True,
    "full_stock_flash_readback": True,
    "no_clobber_verified": True,
    "production_hashing_commanded": False,
    "stock_cold_booted": True,
    "stock_identity_matched": True,
}
PREDECESSOR_KINDS = {
    "boot_policy_receipt_copy",
    "boot_route_adjudication_copy",
    "discovery_receipt_copy",
    "recovery_receipt_copy",
    "route_replacement_receipt_copy",
}
COMMON_EVIDENCE_KINDS = PREDECESSOR_KINDS | {
    "full_readback_image",
    "route_rollback_execution_record",
    "route_rollback_interruption_record",
    "stock_cold_boot_record",
    "stock_identity_record",
}
ROUTE_EVIDENCE_KINDS = {
    "controller_disconnect_record",
    "controller_reconnect_record",
    "sram_volatile_reset_record",
}
EVIDENCE_KINDS = COMMON_EVIDENCE_KINDS | ROUTE_EVIDENCE_KINDS
MEDIA_TYPES = {"application/json", "application/octet-stream"}
EVIDENCE_METHODS = {"completed_route_rollback_qualification", "offline_artifact"}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}
INTERRUPTION_KINDS = {"power_loss", "process_termination", "transport_loss"}


class RouteRollbackError(RuntimeError):
    """A route rollback descriptor, bundle, join, or proof failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _exact(value: Mapping[str, Any], expected: Sequence[str], context: str) -> None:
    missing = sorted(set(expected) - set(value))
    extra = sorted(set(value) - set(expected))
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise RouteRollbackError(f"{context} keys invalid: {'; '.join(details)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RouteRollbackError(
            f"{context} must be a non-empty string <= {maximum} chars"
        )
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise RouteRollbackError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not route_replacement.IDENTIFIER_RE.fullmatch(text):
        raise RouteRollbackError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not route_replacement.PRINCIPAL_RE.fullmatch(text):
        raise RouteRollbackError(f"{context} is not a canonical signer principal")
    return text


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not route_replacement.HEX64_RE.fullmatch(value):
        raise RouteRollbackError(f"{context} must be lowercase SHA-256")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise RouteRollbackError(f"{context} must be boolean")
    return value


def _integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise RouteRollbackError(
            f"{context} must be an integer in {minimum}..{maximum}"
        )
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not route_replacement.UTC_RE.fullmatch(value):
        raise RouteRollbackError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RouteRollbackError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise RouteRollbackError(f"{context} must be a portable POSIX path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise RouteRollbackError(f"{context} must be canonical and relative")
    if any(part in ("", ".", "..") for part in path.parts):
        raise RouteRollbackError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(str(exc)) from exc


def _hash(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(str(exc)) from exc


def _validate_evidence(value: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVIDENCE_ITEMS:
        raise RouteRollbackError(
            f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records"
        )
    ids: set[str] = set()
    paths: set[str] = set()
    counts: dict[str, int] = {}
    normalized = []
    for index, item in enumerate(value):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise RouteRollbackError(f"{context} must be an object")
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
        _exact(item, keys, context)
        evidence_id = _identifier(item["id"], f"{context}.id")
        if evidence_id in ids:
            raise RouteRollbackError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise RouteRollbackError(f"{context}.kind is unsupported")
        counts[kind] = counts.get(kind, 0) + 1
        expected_method = (
            "offline_artifact"
            if kind in PREDECESSOR_KINDS
            else "completed_route_rollback_qualification"
        )
        if item["method"] != expected_method or item["method"] not in EVIDENCE_METHODS:
            raise RouteRollbackError(f"{context}.method does not match its kind")
        if item["media_type"] not in MEDIA_TYPES:
            raise RouteRollbackError(f"{context}.media_type is unsupported")
        if item["redaction"] not in REDACTION_STATES:
            raise RouteRollbackError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise RouteRollbackError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _integer(item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    exact_one = PREDECESSOR_KINDS | {
        "route_rollback_execution_record",
        "route_rollback_interruption_record",
        "stock_cold_boot_record",
        "stock_identity_record",
    }
    for kind in sorted(exact_one):
        if counts.get(kind) != 1:
            raise RouteRollbackError(f"exactly one {kind} is required")
    return normalized


def _evidence_ref(
    evidence: Mapping[str, Mapping[str, Any]], value: Any, kind: str, context: str
) -> Mapping[str, Any]:
    evidence_id = _identifier(value, context)
    item = evidence.get(evidence_id)
    if item is None or item["kind"] != kind:
        raise RouteRollbackError(f"{context} must reference {kind} evidence")
    return item


def _validate_stock_identity(value: Any) -> None:
    if not isinstance(value, dict):
        raise RouteRollbackError("stock_identity must be an object")
    fields = (
        "stock_dna",
        "stock_firmware_version",
        "stock_hwtype",
        "stock_swtype",
    )
    _exact(value, fields, "stock_identity")
    for field in fields:
        _text(value[field], f"stock_identity.{field}")


def _validate_readbacks(
    value: Any,
    evidence: Mapping[str, Mapping[str, Any]],
    context: str = "rollback_contract.full_stock_readbacks",
) -> None:
    if not isinstance(value, list) or not value:
        raise RouteRollbackError(f"{context} must be a non-empty list")
    devices: set[str] = set()
    for index, result in enumerate(value):
        item_context = f"{context}[{index}]"
        if not isinstance(result, dict):
            raise RouteRollbackError(f"{item_context} must be an object")
        _exact(
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
        device = _identifier(
            result["flash_device_id"], f"{item_context}.flash_device_id"
        )
        if device in devices:
            raise RouteRollbackError("stock readbacks contain a duplicate flash device")
        devices.add(device)
        _identifier(
            result["baseline_backup_evidence_id"],
            f"{item_context}.baseline_backup_evidence_id",
        )
        _evidence_ref(
            evidence,
            result["readback_evidence_id"],
            "full_readback_image",
            f"{item_context}.readback_evidence_id",
        )
        if not _boolean(
            result["full_device_readback"], f"{item_context}.full_device_readback"
        ):
            raise RouteRollbackError(f"{item_context} is not a full-device readback")
        if not _boolean(
            result["readback_matches_stock"], f"{item_context}.readback_matches_stock"
        ):
            raise RouteRollbackError(f"{item_context} does not claim a stock match")


def _validate_route_assertions(
    value: Any,
    route: str,
    evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    if not isinstance(value, dict):
        raise RouteRollbackError("rollback_contract.route_assertions must be an object")
    if route == "native_aes0_flash":
        _exact(
            value,
            (
                "full_stock_restore_completed",
                "interrupted_update_after_bytes",
                "interrupted_update_observed",
                "stock_flash_restored",
            ),
            "rollback_contract.route_assertions",
        )
        _integer(
            value["interrupted_update_after_bytes"],
            "route_assertions.interrupted_update_after_bytes",
            1,
            route_replacement.MAX_ARTIFACT_BYTES,
        )
        for field in (
            "full_stock_restore_completed",
            "interrupted_update_observed",
            "stock_flash_restored",
        ):
            if not _boolean(value[field], f"route_assertions.{field}"):
                raise RouteRollbackError(f"route_assertions.{field} must be true")
    elif route in SRAM_ROUTES:
        _exact(
            value,
            (
                "bootstrap_aborted",
                "candidate_persisted_to_flash",
                "sram_volatile_reset_performed",
                "stock_flash_unchanged",
                "transport",
                "volatile_reset_evidence_id",
            ),
            "rollback_contract.route_assertions",
        )
        if value["transport"] != route:
            raise RouteRollbackError(
                "SRAM rollback transport does not match selected route"
            )
        for field in (
            "bootstrap_aborted",
            "sram_volatile_reset_performed",
            "stock_flash_unchanged",
        ):
            if not _boolean(value[field], f"route_assertions.{field}"):
                raise RouteRollbackError(f"route_assertions.{field} must be true")
        if _boolean(
            value["candidate_persisted_to_flash"],
            "route_assertions.candidate_persisted_to_flash",
        ):
            raise RouteRollbackError("SRAM candidate persistence is forbidden")
        _evidence_ref(
            evidence,
            value["volatile_reset_evidence_id"],
            "sram_volatile_reset_record",
            "route_assertions.volatile_reset_evidence_id",
        )
    else:
        _exact(
            value,
            (
                "disconnect_evidence_id",
                "power_isolation_verified",
                "reconnect_evidence_id",
                "replacement_controller_disconnected",
                "signal_isolation_verified",
                "stock_controller_reconnected",
                "stock_flash_unchanged",
            ),
            "rollback_contract.route_assertions",
        )
        for field in (
            "power_isolation_verified",
            "replacement_controller_disconnected",
            "signal_isolation_verified",
            "stock_controller_reconnected",
            "stock_flash_unchanged",
        ):
            if not _boolean(value[field], f"route_assertions.{field}"):
                raise RouteRollbackError(f"route_assertions.{field} must be true")
        _evidence_ref(
            evidence,
            value["disconnect_evidence_id"],
            "controller_disconnect_record",
            "route_assertions.disconnect_evidence_id",
        )
        _evidence_ref(
            evidence,
            value["reconnect_evidence_id"],
            "controller_reconnect_record",
            "route_assertions.reconnect_evidence_id",
        )


def _validate_contract(
    value: Any, route: str, evidence: Mapping[str, Mapping[str, Any]]
) -> None:
    if not isinstance(value, dict):
        raise RouteRollbackError("rollback_contract must be an object")
    _exact(
        value,
        (
            "artifact_absent_after_rollback",
            "cold_boot_evidence_id",
            "execution_evidence_id",
            "full_stock_readbacks",
            "interruption_evidence_id",
            "interruption_kind",
            "no_clobber_verified",
            "recovered_by_restore_path_id",
            "recovery_path_exercised",
            "route_assertions",
            "route_id",
            "stock_booted",
            "stock_identity_evidence_id",
            "stock_identity_matched",
        ),
        "rollback_contract",
    )
    if value["route_id"] != route:
        raise RouteRollbackError("rollback contract does not match selected route")
    if value["interruption_kind"] not in INTERRUPTION_KINDS:
        raise RouteRollbackError("rollback interruption kind is unsupported")
    _identifier(
        value["recovered_by_restore_path_id"],
        "rollback_contract.recovered_by_restore_path_id",
    )
    refs = (
        ("cold_boot_evidence_id", "stock_cold_boot_record"),
        ("execution_evidence_id", "route_rollback_execution_record"),
        ("interruption_evidence_id", "route_rollback_interruption_record"),
        ("stock_identity_evidence_id", "stock_identity_record"),
    )
    for field, kind in refs:
        _evidence_ref(evidence, value[field], kind, f"rollback_contract.{field}")
    for field in (
        "artifact_absent_after_rollback",
        "no_clobber_verified",
        "recovery_path_exercised",
        "stock_booted",
        "stock_identity_matched",
    ):
        if not _boolean(value[field], f"rollback_contract.{field}"):
            raise RouteRollbackError(f"rollback_contract.{field} must be true")
    _validate_readbacks(value["full_stock_readbacks"], evidence)
    _validate_route_assertions(value["route_assertions"], route, evidence)


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise RouteRollbackError("signing must be an object")
    _exact(value, ("operator", "witness"), "signing")
    expected = {
        "operator": (OPERATOR_ROLE, OPERATOR_NAMESPACE),
        "witness": (WITNESS_ROLE, WITNESS_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise RouteRollbackError(f"signing.{name} must be an object")
        _exact(
            item,
            ("algorithm", "key_id_sha256", "namespace", "role"),
            f"signing.{name}",
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["role"] != role
            or item["namespace"] != namespace
        ):
            raise RouteRollbackError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise RouteRollbackError("operator and witness signing keys must be distinct")


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> tuple[str, dict[str, Mapping[str, Any]]]:
    core_keys = (
        "actions_performed",
        "artifact_set_sha256",
        "authorization",
        "boot_policy_receipt_id",
        "completed_at_utc",
        "discovery_receipt_id",
        "evidence",
        "interface_qualification_sha256",
        "kind",
        "operator_id",
        "recovery_receipt_id",
        "rollback_contract",
        "route_adjudication_sha256",
        "route_replacement_receipt_id",
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
        "no_clobber_sha256",
        "receipt_id",
        "signing",
        "stock_restoration_sha256",
    )
    _exact(
        value,
        core_keys + receipt_only if receipt else core_keys,
        "route rollback record",
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise RouteRollbackError("route rollback schema or scope mismatch")
    if value["kind"] != (RECEIPT_KIND if receipt else DESCRIPTOR_KIND):
        raise RouteRollbackError("route rollback record kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    for field in (
        "artifact_set_sha256",
        "boot_policy_receipt_id",
        "discovery_receipt_id",
        "interface_qualification_sha256",
        "recovery_receipt_id",
        "route_adjudication_sha256",
        "route_replacement_receipt_id",
        "stock_backup_set_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], field)
    route = value["selected_route"]
    if route not in ROUTES:
        raise RouteRollbackError("selected route is unsupported")
    operator = _principal(value["operator_id"], "operator_id")
    witness = _principal(value["witness_id"], "witness_id")
    if operator == witness:
        raise RouteRollbackError("rollback operator and witness must be distinct")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise RouteRollbackError("rollback start must precede completion")
    if value["actions_performed"] != ACTIONS_PERFORMED:
        raise RouteRollbackError("route rollback actions_performed contract drifted")
    _validate_stock_identity(value["stock_identity"])
    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        raise RouteRollbackError("authorization must be an object")
    _exact(
        authorization,
        (
            "authorized_actions",
            "operator_reference",
            "valid_from_utc",
            "valid_until_utc",
        ),
        "authorization",
    )
    _text(authorization["operator_reference"], "authorization.operator_reference")
    valid_from = _utc(authorization["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(
        authorization["valid_until_utc"], "authorization.valid_until_utc"
    )
    if (
        valid_from >= valid_until
        or not valid_from <= started < completed <= valid_until
    ):
        raise RouteRollbackError("rollback qualification is outside authorization")
    expected_actions = COMMON_ACTIONS | {ROUTE_ACTION[route]}
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or set(actions) != expected_actions
        or len(actions) != len(expected_actions)
    ):
        raise RouteRollbackError(
            "authorization action set does not match selected route"
        )
    evidence_list = _validate_evidence(value["evidence"], hashed=receipt)
    evidence = {item["id"]: item for item in evidence_list}
    for index, item in enumerate(evidence_list):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= completed:
            raise RouteRollbackError(f"evidence[{index}] is outside authorization")
    _validate_contract(value["rollback_contract"], route, evidence)
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise RouteRollbackError("route rollback authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise RouteRollbackError("route rollback disposition drifted")
        for field in (
            "descriptor_sha256",
            "no_clobber_sha256",
            "receipt_id",
            "stock_restoration_sha256",
        ):
            _sha(value[field], field)
        _validate_signing(value["signing"])
    return route, evidence


def _load_copy(
    record: Mapping[str, Any], root: Path, kind: str, label: str
) -> dict[str, Any]:
    matches = [item for item in record["evidence"] if item["kind"] == kind]
    if len(matches) != 1:
        raise RouteRollbackError(f"exactly one {kind} is required")
    return _load_json(
        _source(root, _safe_path(matches[0]["path"], f"{label} path")),
        label,
        canonical=True,
    )


def _boot_result(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return route_replacement._boot_result(receipt)


def _validate_predecessors(
    manifest: Mapping[str, Any], record: Mapping[str, Any], root: Path
) -> dict[str, Any]:
    discovery_receipt = _load_copy(
        record, root, "discovery_receipt_copy", "discovery receipt copy"
    )
    recovery_receipt = _load_copy(
        record, root, "recovery_receipt_copy", "recovery receipt copy"
    )
    boot_receipt = _load_copy(
        record, root, "boot_policy_receipt_copy", "boot-policy receipt copy"
    )
    route_record = _load_copy(
        record, root, "boot_route_adjudication_copy", "boot-route adjudication copy"
    )
    replacement_receipt = _load_copy(
        record,
        root,
        "route_replacement_receipt_copy",
        "route replacement receipt copy",
    )
    try:
        discovery._validate_receipt(discovery_receipt, manifest)
        recovery._validate_receipt(recovery_receipt, manifest)
        boot._validate_receipt(boot_receipt, manifest)
        route_replacement._validate_receipt(replacement_receipt, manifest)
    except (
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        route_replacement.RouteReplacementError,
    ) as exc:
        raise RouteRollbackError(f"predecessor receipt is invalid: {exc}") from exc
    try:
        recomputed = boot_route.adjudicate(_boot_result(boot_receipt))
    except boot_route.BootRouteError as exc:
        raise RouteRollbackError(f"boot-route recomputation failed: {exc}") from exc
    if route_record != recomputed:
        raise RouteRollbackError(
            "boot-route record does not reproduce from boot evidence"
        )
    expected = {
        "artifact_set_sha256": replacement_receipt["artifact_set_sha256"],
        "boot_policy_receipt_id": boot_receipt["receipt_id"],
        "discovery_receipt_id": discovery_receipt["receipt_id"],
        "interface_qualification_sha256": replacement_receipt[
            "interface_qualification_sha256"
        ],
        "recovery_receipt_id": recovery_receipt["receipt_id"],
        "route_adjudication_sha256": recomputed["adjudication_sha256"],
        "route_replacement_receipt_id": replacement_receipt["receipt_id"],
        "selected_route": replacement_receipt["route_selection"]["selected_route"],
        "stock_backup_set_sha256": recovery_receipt["stock_backup_set_sha256"],
        "target_id": discovery_receipt["target_id"],
        "unit_fingerprint_sha256": discovery_receipt["unit_fingerprint_sha256"],
        "unit_label": discovery_receipt["unit_label"],
    }
    predecessor_joins = (
        (recovery_receipt, "discovery_receipt_id", expected["discovery_receipt_id"]),
        (recovery_receipt, "target_id", expected["target_id"]),
        (
            recovery_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
        ),
        (boot_receipt, "discovery_receipt_id", expected["discovery_receipt_id"]),
        (boot_receipt, "recovery_receipt_id", expected["recovery_receipt_id"]),
        (boot_receipt, "stock_backup_set_sha256", expected["stock_backup_set_sha256"]),
        (replacement_receipt, "discovery_receipt_id", expected["discovery_receipt_id"]),
        (replacement_receipt, "recovery_receipt_id", expected["recovery_receipt_id"]),
        (
            replacement_receipt,
            "boot_policy_receipt_id",
            expected["boot_policy_receipt_id"],
        ),
        (
            replacement_receipt,
            "stock_backup_set_sha256",
            expected["stock_backup_set_sha256"],
        ),
        (replacement_receipt, "target_id", expected["target_id"]),
        (
            replacement_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
        ),
    )
    for predecessor, key, wanted in predecessor_joins:
        if predecessor[key] != wanted:
            raise RouteRollbackError(f"predecessor {key} exact join failed")
    if (
        replacement_receipt["route_selection"]["adjudication_sha256"]
        != expected["route_adjudication_sha256"]
    ):
        raise RouteRollbackError("route replacement adjudication digest is spliced")
    for key, wanted in expected.items():
        if record[key] != wanted:
            raise RouteRollbackError(f"predecessor {key} does not match rollback")
    stock_identity = {
        key: discovery_receipt["identity"][key]
        for key in (
            "stock_dna",
            "stock_firmware_version",
            "stock_hwtype",
            "stock_swtype",
        )
    }
    if record["stock_identity"] != stock_identity:
        raise RouteRollbackError("stock identity does not exact-join discovery")
    return {
        "boot": boot_receipt,
        "discovery": discovery_receipt,
        "recovery": recovery_receipt,
        "replacement": replacement_receipt,
        "route": recomputed,
    }


def _validate_readback_bytes(
    record: Mapping[str, Any], predecessors: Mapping[str, Any]
) -> None:
    evidence = {item["id"]: item for item in record["evidence"]}
    recovery_receipt = predecessors["recovery"]
    recovery_evidence = {item["id"]: item for item in recovery_receipt["evidence"]}
    devices = {item["id"]: item for item in recovery_receipt["flash_devices"]}
    readbacks = record["rollback_contract"]["full_stock_readbacks"]
    if len(readbacks) != len(devices):
        raise RouteRollbackError(
            "stock readback does not cover every recovery flash device"
        )
    observed = set()
    for result in readbacks:
        device_id = result["flash_device_id"]
        if device_id not in devices or device_id in observed:
            raise RouteRollbackError(
                "stock readback has an unknown or duplicate device"
            )
        observed.add(device_id)
        device = devices[device_id]
        admitted_backups = {
            item["artifact_evidence_id"] for item in device["backup_reads"]
        }
        baseline_id = result["baseline_backup_evidence_id"]
        if baseline_id not in admitted_backups:
            raise RouteRollbackError(
                "readback baseline is not an admitted stock backup"
            )
        baseline = recovery_evidence[baseline_id]
        readback = evidence[result["readback_evidence_id"]]
        if (
            baseline["kind"] != "stock_backup_image"
            or readback["bytes"] != baseline["bytes"]
            or readback["sha256"] != baseline["sha256"]
            or readback["bytes"] != device["capacity_bytes"]
        ):
            raise RouteRollbackError(
                "full stock readback bytes do not match admitted stock"
            )


def _json_evidence(
    evidence: Mapping[str, Mapping[str, Any]],
    root: Path,
    evidence_id: str,
    label: str,
) -> dict[str, Any]:
    item = evidence[evidence_id]
    return _load_json(
        _source(root, _safe_path(item["path"], f"{label} path")),
        label,
        canonical=True,
    )


def _validate_semantic_evidence(
    record: Mapping[str, Any], root: Path, predecessors: Mapping[str, Any]
) -> None:
    route = record["selected_route"]
    contract = record["rollback_contract"]
    assertions = contract["route_assertions"]
    evidence = {item["id"]: item for item in record["evidence"]}
    common = {
        "artifact_set_sha256": record["artifact_set_sha256"],
        "authority_granted": False,
        "interface_qualification_sha256": record["interface_qualification_sha256"],
        "route_adjudication_sha256": record["route_adjudication_sha256"],
        "route_replacement_receipt_id": record["route_replacement_receipt_id"],
        "selected_route": route,
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    execution_expected = {
        **common,
        "artifact_absent_after_rollback": True,
        "kind": "dcent_k210_route_rollback_execution",
        "no_clobber_verified": True,
        "recovered_by_restore_path_id": contract["recovered_by_restore_path_id"],
        "recovery_path_exercised": True,
        "stock_booted": True,
        "stock_identity_matched": True,
    }
    interruption_expected = {
        **common,
        "interruption_kind": contract["interruption_kind"],
        "interruption_observed": True,
        "kind": "dcent_k210_route_rollback_interruption",
        "route_assertions": assertions,
    }
    if (
        _json_evidence(
            evidence,
            root,
            contract["execution_evidence_id"],
            "rollback execution record",
        )
        != execution_expected
    ):
        raise RouteRollbackError(
            "rollback execution evidence is semantically inconsistent"
        )
    if (
        _json_evidence(
            evidence,
            root,
            contract["interruption_evidence_id"],
            "rollback interruption record",
        )
        != interruption_expected
    ):
        raise RouteRollbackError(
            "rollback interruption evidence is semantically inconsistent"
        )
    boot_expected = {
        "authority_granted": False,
        "kind": "dcent_k210_stock_cold_boot_observation",
        "production_hashing_commanded": False,
        "stock_booted": True,
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    identity_expected = {
        "authority_granted": False,
        "identity": record["stock_identity"],
        "kind": "dcent_k210_stock_identity_observation",
        "stock_identity_matched": True,
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    if (
        _json_evidence(
            evidence, root, contract["cold_boot_evidence_id"], "stock cold-boot record"
        )
        != boot_expected
    ):
        raise RouteRollbackError(
            "stock cold-boot evidence is semantically inconsistent"
        )
    if (
        _json_evidence(
            evidence,
            root,
            contract["stock_identity_evidence_id"],
            "stock identity record",
        )
        != identity_expected
    ):
        raise RouteRollbackError("stock identity evidence is semantically inconsistent")

    if route in SRAM_ROUTES:
        reset_expected = {
            **common,
            "candidate_persisted_to_flash": False,
            "kind": "dcent_k210_sram_volatile_reset",
            "sram_volatile_state_cleared": True,
            "stock_flash_unchanged": True,
        }
        if (
            _json_evidence(
                evidence,
                root,
                assertions["volatile_reset_evidence_id"],
                "SRAM volatile reset record",
            )
            != reset_expected
        ):
            raise RouteRollbackError("SRAM volatile reset evidence is inconsistent")
    elif route == "clean_replacement_controller":
        disconnect_expected = {
            **common,
            "connector_isolated": True,
            "kind": "dcent_k210_replacement_controller_disconnect",
            "power_isolated": True,
            "replacement_controller_disconnected": True,
            "signals_isolated": True,
        }
        reconnect_expected = {
            **common,
            "kind": "dcent_k210_stock_controller_reconnect",
            "stock_controller_reconnected": True,
            "stock_flash_unchanged": True,
        }
        if (
            _json_evidence(
                evidence,
                root,
                assertions["disconnect_evidence_id"],
                "controller disconnect record",
            )
            != disconnect_expected
        ):
            raise RouteRollbackError("controller disconnect evidence is inconsistent")
        if (
            _json_evidence(
                evidence,
                root,
                assertions["reconnect_evidence_id"],
                "stock controller reconnect record",
            )
            != reconnect_expected
        ):
            raise RouteRollbackError(
                "stock controller reconnect evidence is inconsistent"
            )

    used = {
        item["id"] for item in record["evidence"] if item["kind"] in PREDECESSOR_KINDS
    }
    used.update(
        {
            contract["cold_boot_evidence_id"],
            contract["execution_evidence_id"],
            contract["interruption_evidence_id"],
            contract["stock_identity_evidence_id"],
        }
    )
    used.update(
        item["readback_evidence_id"] for item in contract["full_stock_readbacks"]
    )
    if route in SRAM_ROUTES:
        used.add(assertions["volatile_reset_evidence_id"])
    elif route == "clean_replacement_controller":
        used.add(assertions["disconnect_evidence_id"])
        used.add(assertions["reconnect_evidence_id"])
    if used != set(evidence):
        raise RouteRollbackError(
            "rollback bundle has cross-route or unreferenced evidence"
        )
    _validate_readback_bytes(record, predecessors)

    recovery_receipt = predecessors["recovery"]
    paths = {item["id"]: item for item in recovery_receipt["restore_paths"]}
    path_id = contract["recovered_by_restore_path_id"]
    path = paths.get(path_id)
    if path is None or path["existing_flash_independent"] is not True:
        raise RouteRollbackError("rollback recovery path is not independently admitted")
    if path["mechanism_class"] != "external_memory_programmer":
        raise RouteRollbackError(
            "route rollback must recover through the admitted external programmer path"
        )


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "no_clobber_sha256",
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
    readbacks = []
    for result in sorted(
        receipt["rollback_contract"]["full_stock_readbacks"],
        key=lambda item: item["flash_device_id"],
    ):
        artifact = evidence[result["readback_evidence_id"]]
        readbacks.append(
            {
                "baseline_backup_evidence_id": result["baseline_backup_evidence_id"],
                "bytes": artifact["bytes"],
                "flash_device_id": result["flash_device_id"],
                "readback_evidence_id": result["readback_evidence_id"],
                "sha256": artifact["sha256"],
            }
        )
    return {
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "readbacks": readbacks,
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "route_replacement_receipt_id": receipt["route_replacement_receipt_id"],
        "selected_route": receipt["selected_route"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
    }


def _no_clobber_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    evidence = {item["id"]: item for item in receipt["evidence"]}
    readbacks = []
    for result in sorted(
        receipt["rollback_contract"]["full_stock_readbacks"],
        key=lambda item: item["flash_device_id"],
    ):
        artifact = evidence[result["readback_evidence_id"]]
        readbacks.append(
            {
                "bytes": artifact["bytes"],
                "flash_device_id": result["flash_device_id"],
                "readback_evidence_id": result["readback_evidence_id"],
                "sha256": artifact["sha256"],
            }
        )
    contract = receipt["rollback_contract"]
    return {
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "artifact_absent_after_rollback": contract["artifact_absent_after_rollback"],
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "no_clobber_verified": contract["no_clobber_verified"],
        "readbacks": readbacks,
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "route_assertions": contract["route_assertions"],
        "route_replacement_receipt_id": receipt["route_replacement_receipt_id"],
        "selected_route": receipt["selected_route"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "stock_identity": receipt["stock_identity"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
    }


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _validate_core(receipt, manifest, receipt=True)
    descriptor_digest = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    if descriptor_digest != receipt["descriptor_sha256"]:
        raise RouteRollbackError("route rollback descriptor digest mismatch")
    restoration_digest = hashlib.sha256(
        b"DCENT-K210-ROUTE-STOCK-RESTORATION-V2\x00"
        + canonical_json_bytes(_restoration_projection(receipt))
    ).hexdigest()
    if restoration_digest != receipt["stock_restoration_sha256"]:
        raise RouteRollbackError("route stock-restoration digest mismatch")
    no_clobber_digest = hashlib.sha256(
        b"DCENT-K210-ROUTE-NO-CLOBBER-V2\x00"
        + canonical_json_bytes(_no_clobber_projection(receipt))
    ).hexdigest()
    if no_clobber_digest != receipt["no_clobber_sha256"]:
        raise RouteRollbackError("route no-clobber digest mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-ROUTE-ROLLBACK-RECEIPT-ID-V2\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise RouteRollbackError("route rollback receipt ID mismatch")


def _artifact_sources(record: Mapping[str, Any], root: Path) -> dict[str, Path]:
    return {
        item["id"]: _source(
            root, _safe_path(item["path"], f"evidence {item['id']} path")
        )
        for item in record["evidence"]
    }


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    route, _ = _validate_core(descriptor, manifest, receipt=False)
    sources = _artifact_sources(descriptor, evidence_root)
    evidence_with_hashes = []
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        size, digest = _hash(sources[item["id"]], f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RouteRollbackError("route rollback evidence exceeds aggregate limit")
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
    try:
        operator_key = discovery.inspect_private_key(operator_private_key)
        witness_key = discovery.inspect_private_key(witness_private_key)
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(
            f"route rollback signing key is invalid: {exc}"
        ) from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RouteRollbackError("operator and witness private keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["authorization"]["authorized_actions"] = sorted(
        COMMON_ACTIONS | {ROUTE_ACTION[route]}
    )
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
        b"DCENT-K210-ROUTE-STOCK-RESTORATION-V2\x00"
        + canonical_json_bytes(_restoration_projection(receipt))
    ).hexdigest()
    receipt["no_clobber_sha256"] = hashlib.sha256(
        b"DCENT-K210-ROUTE-NO-CLOBBER-V2\x00"
        + canonical_json_bytes(_no_clobber_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-ROUTE-ROLLBACK-RECEIPT-ID-V2\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt, manifest)
    predecessors = _validate_predecessors(manifest, receipt, evidence_root)
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
        raise RouteRollbackError(f"refusing to overwrite existing bundle: {bundle_out}")
    descriptor = _load_json(
        descriptor_path, "route rollback descriptor", canonical=False
    )
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
        destination_root = temporary / EVIDENCE_DIRECTORY
        destination_root.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = destination_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise RouteRollbackError(
                    f"evidence {item['id']} changed during snapshot"
                )
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        try:
            operator_sig = discovery.sign_sshsig_file(
                receipt_path, operator_private_key, OPERATOR_NAMESPACE
            )
            witness_sig = discovery.sign_sshsig_file(
                receipt_path, witness_private_key, WITNESS_NAMESPACE
            )
        except discovery.DiscoveryError as exc:
            raise RouteRollbackError(f"route rollback signing failed: {exc}") from exc
        operator_path = temporary / OPERATOR_SIGNATURE_NAME
        witness_path = temporary / WITNESS_SIGNATURE_NAME
        operator_path.write_bytes(operator_sig)
        witness_path.write_bytes(witness_sig)
        discovery.verify_sshsig_bytes(
            receipt_raw,
            operator_path,
            operator_key_line := discovery.inspect_private_key(operator_private_key)[
                "canonical_line"
            ],
            receipt["operator_id"],
            OPERATOR_NAMESPACE,
        )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            witness_path,
            witness_key_line := discovery.inspect_private_key(witness_private_key)[
                "canonical_line"
            ],
            receipt["witness_id"],
            WITNESS_NAMESPACE,
        )
        if not operator_key_line or not witness_key_line:
            raise RouteRollbackError("route rollback signer identity changed")
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
        raise RouteRollbackError(
            f"route rollback bundle cannot be inspected: {exc}"
        ) from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise RouteRollbackError(
            "route rollback bundle must be a non-symlink directory"
        )
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "route rollback receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    try:
        operator_key = discovery.inspect_public_key(operator_public_key)
        witness_key = discovery.inspect_public_key(witness_public_key)
        receipt_raw = discovery._read_regular(
            receipt_path, "route rollback receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise RouteRollbackError(str(exc)) from exc
    if operator_key["key_id_sha256"] == witness_key["key_id_sha256"]:
        raise RouteRollbackError("operator and witness trust keys must be distinct")
    if receipt_raw != canonical_json_bytes(receipt):
        raise RouteRollbackError("route rollback receipt changed after validation")
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
            raise RouteRollbackError(f"{role} key does not match the trust anchor")
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise RouteRollbackError(f"route rollback {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw,
                signature_path,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise RouteRollbackError(
                f"route rollback {role} signature is invalid: {exc}"
            ) from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RouteRollbackError("route rollback evidence exceeds aggregate limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise RouteRollbackError(f"evidence {item['id']} digest or size mismatch")
    predecessors = _validate_predecessors(
        manifest, receipt, bundle / EVIDENCE_DIRECTORY
    )
    _validate_semantic_evidence(receipt, bundle / EVIDENCE_DIRECTORY, predecessors)
    _verify_exact_members(bundle, receipt)
    return {
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "authority_granted": False,
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "no_clobber_sha256": receipt["no_clobber_sha256"],
        "operator_key_id_sha256": operator_key["key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "rollback_recovery_gate_eligible": True,
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "route_replacement_receipt_id": receipt["route_replacement_receipt_id"],
        "selected_route": receipt["selected_route"],
        "state": "verified_signed_route_rollback",
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
            raise RouteRollbackError(f"bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise RouteRollbackError(f"bundle contains a linked member: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise RouteRollbackError(
                    f"bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise RouteRollbackError("route rollback bundle member set is not exact")


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign completed route rollback"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a route rollback bundle")
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
                f"K210_ROUTE_ROLLBACK_CREATED target={receipt['target_id']} "
                f"route={receipt['selected_route']} receipt_id={receipt['receipt_id']} "
                "authority_granted=false"
            )
            return 0
        for label, value in (
            ("--expected-operator-key-id", args.expected_operator_key_id),
            ("--expected-witness-key-id", args.expected_witness_key_id),
        ):
            if value is not None and not route_replacement.HEX64_RE.fullmatch(value):
                raise RouteRollbackError(f"{label} must be lowercase SHA-256")
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
                f"K210_ROUTE_ROLLBACK_VERIFIED target={result['target_id']} "
                f"route={result['selected_route']} receipt_id={result['receipt_id']} "
                "gate_eligible=true authority_granted=false"
            )
        return 0
    except (
        RouteRollbackError,
        route_replacement.RouteReplacementError,
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        boot_route.BootRouteError,
    ) as exc:
        print(f"K210_ROUTE_ROLLBACK_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
