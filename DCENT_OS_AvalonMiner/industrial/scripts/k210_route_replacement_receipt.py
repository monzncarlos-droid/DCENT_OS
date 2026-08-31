#!/usr/bin/env python3
"""Create and verify route-discriminated K210 replacement artifacts.

This schema-2 host-only successor leaves the native-AES0 schema-1 verifier
unchanged. It records reproducible artifacts and already-completed route
qualification evidence. It has no hardware, install, power, or release
transport and grants no future authority.
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


v1 = _load_sibling("k210_replacement_receipt.py")
boot_route = _load_sibling("k210_boot_route.py")
boot = v1.boot
recovery = boot.recovery
discovery = boot.discovery

SCHEMA_VERSION = 2
SCOPE = v1.SCOPE
DESCRIPTOR_KIND = "dcent_k210_route_replacement_firmware_descriptor"
RECEIPT_KIND = "dcent_k210_route_replacement_firmware_receipt"
DISPOSITION = "verified_route_artifact_only_no_hardware_or_install_authority"
RECEIPT_NAME = "receipt.json"
BUILDER_SIGNATURE_NAME = "builder.sig"
REVIEWER_SIGNATURE_NAME = "reviewer.sig"
EVIDENCE_DIRECTORY = "evidence"
BUILDER_ROLE = "k210_route_replacement_builder"
REVIEWER_ROLE = "k210_route_replacement_reviewer"
BUILDER_NAMESPACE = "dcent-k210-route-replacement-builder-v2"
REVIEWER_NAMESPACE = "dcent-k210-route-replacement-reviewer-v2"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

ROUTES = (
    "native_aes0_flash",
    "rom_isp_sram_bootstrap",
    "jtag_sram_bootstrap",
    "clean_replacement_controller",
)
SRAM_ROUTES = {"rom_isp_sram_bootstrap", "jtag_sram_bootstrap"}
ROUTE_STATES = {
    "native_aes0_flash": "measured_compatible",
    "rom_isp_sram_bootstrap": "eligible_for_controlled_sram_probe",
    "jtag_sram_bootstrap": "eligible_for_controlled_sram_probe",
    "clean_replacement_controller": "requires_external_qualification",
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_debug_access": False,
    "authorizes_flash_write": False,
    "authorizes_install": False,
    "authorizes_jtag_or_isp_access": False,
    "authorizes_power_or_cooling_control": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}

MAX_JSON_BYTES = 512 * 1024
MAX_EVIDENCE_ITEMS = 64
MAX_EVIDENCE_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
FIRMWARE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

PREDECESSOR_KINDS = {
    "boot_policy_receipt_copy",
    "boot_route_adjudication_copy",
    "discovery_receipt_copy",
    "recovery_receipt_copy",
}
COMMON_KINDS = PREDECESSOR_KINDS | {
    "clean_room_review",
    "license_review",
    "reproducibility_log",
    "sbom",
    "source_archive",
    "source_manifest",
    "toolchain_manifest",
}
AES0_KINDS = {"board_profile_record", "firmware_aup", "firmware_elf", "firmware_raw"}
SRAM_KINDS = {
    "firmware_elf",
    "firmware_raw",
    "sram_execution_qualification",
    "sram_execution_trace",
}
CONTROLLER_COMPONENT_KINDS = {
    "connector_map_qualification",
    "cooling_interface_qualification",
    "cutoff_interface_qualification",
    "power_interface_qualification",
    "recovery_interface_qualification",
    "signal_map_qualification",
}
CONTROLLER_KINDS = CONTROLLER_COMPONENT_KINDS | {
    "controller_firmware_artifact",
    "controller_interface_qualification",
}
EVIDENCE_KINDS = COMMON_KINDS | AES0_KINDS | SRAM_KINDS | CONTROLLER_KINDS
MEDIA_TYPES = {"application/json", "application/octet-stream", "text/plain"}
EVIDENCE_METHODS = {
    "completed_interface_qualification",
    "completed_route_execution_qualification",
    "offline_artifact",
    "reproducible_build",
}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}


class RouteReplacementError(RuntimeError):
    """A route-artifact descriptor, bundle, join, or proof failed."""


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
        raise RouteReplacementError(f"{context} keys invalid: {'; '.join(details)}")


def _text(value: Any, context: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RouteReplacementError(
            f"{context} must be a non-empty string <= {maximum} chars"
        )
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise RouteReplacementError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise RouteReplacementError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not PRINCIPAL_RE.fullmatch(text):
        raise RouteReplacementError(f"{context} is not a canonical signer principal")
    return text


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise RouteReplacementError(f"{context} must be lowercase SHA-256")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise RouteReplacementError(f"{context} must be boolean")
    return value


def _integer(value: Any, context: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise RouteReplacementError(
            f"{context} must be an integer in {minimum}..{maximum}"
        )
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise RouteReplacementError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RouteReplacementError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _safe_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise RouteReplacementError(f"{context} must be a portable POSIX path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise RouteReplacementError(f"{context} must be canonical and relative")
    if any(part in ("", ".", "..") for part in path.parts):
        raise RouteReplacementError(f"{context} contains an unsafe segment")
    return path


def _load_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc


def _hash(path: Path, label: str) -> tuple[int, str]:
    try:
        return discovery._hash_evidence(path, label)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    try:
        return discovery._target(manifest, target_id)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc


def _method_for_kind(kind: str) -> str:
    if kind in PREDECESSOR_KINDS or kind in {
        "clean_room_review",
        "license_review",
        "sbom",
        "source_archive",
        "source_manifest",
    }:
        return "offline_artifact"
    if kind in {
        "reproducibility_log",
        "toolchain_manifest",
        "board_profile_record",
        "firmware_aup",
        "firmware_elf",
        "firmware_raw",
        "controller_firmware_artifact",
    }:
        return "reproducible_build"
    if kind in {"sram_execution_qualification", "sram_execution_trace"}:
        return "completed_route_execution_qualification"
    return "completed_interface_qualification"


def _validate_evidence(value: Any, *, hashed: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVIDENCE_ITEMS:
        raise RouteReplacementError(
            f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records"
        )
    ids: set[str] = set()
    paths: set[str] = set()
    normalized = []
    counts: dict[str, int] = {}
    for index, item in enumerate(value):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise RouteReplacementError(f"{context} must be an object")
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
            raise RouteReplacementError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise RouteReplacementError(f"{context}.kind is unsupported")
        counts[kind] = counts.get(kind, 0) + 1
        if item["method"] != _method_for_kind(kind):
            raise RouteReplacementError(f"{context}.method does not match its kind")
        if item["method"] not in EVIDENCE_METHODS:
            raise RouteReplacementError(f"{context}.method is unsupported")
        if item["media_type"] not in MEDIA_TYPES:
            raise RouteReplacementError(f"{context}.media_type is unsupported")
        if item["redaction"] not in REDACTION_STATES:
            raise RouteReplacementError(f"{context}.redaction is unsupported")
        path = str(_safe_path(item["path"], f"{context}.path"))
        if path in paths:
            raise RouteReplacementError("evidence paths must be unique")
        paths.add(path)
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if hashed:
            _integer(item["bytes"], f"{context}.bytes", 1, MAX_EVIDENCE_FILE_BYTES)
            _sha(item["sha256"], f"{context}.sha256")
        normalized.append(dict(item))
    for kind in sorted(PREDECESSOR_KINDS):
        if counts.get(kind) != 1:
            raise RouteReplacementError(f"exactly one {kind} is required")
    common_one = {
        "clean_room_review",
        "license_review",
        "sbom",
        "source_archive",
        "source_manifest",
    }
    for kind in sorted(common_one):
        if counts.get(kind) != 1:
            raise RouteReplacementError(f"exactly one {kind} is required")
    if counts.get("reproducibility_log") != 2 or counts.get("toolchain_manifest") != 2:
        raise RouteReplacementError(
            "exactly two build logs and toolchain manifests are required"
        )
    return normalized


def _evidence_ref(
    evidence: Mapping[str, Mapping[str, Any]], value: Any, kind: str, context: str
) -> Mapping[str, Any]:
    evidence_id = _identifier(value, context)
    item = evidence.get(evidence_id)
    if item is None or item["kind"] != kind:
        raise RouteReplacementError(f"{context} must reference {kind} evidence")
    return item


def _validate_firmware(
    value: Any, evidence: Mapping[str, Mapping[str, Any]], *, receipt: bool
) -> None:
    if not isinstance(value, dict):
        raise RouteReplacementError("firmware must be an object")
    _exact(
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
        raise RouteReplacementError("firmware class must be target-bound safe idle")
    if not isinstance(
        value["firmware_version"], str
    ) or not FIRMWARE_VERSION_RE.fullmatch(value["firmware_version"]):
        raise RouteReplacementError("firmware version is not canonical")
    if not isinstance(value["source_commit"], str) or not HEX40_RE.fullmatch(
        value["source_commit"]
    ):
        raise RouteReplacementError("source_commit must be lowercase 40-hex")
    if value["source_license"] != "GPL-3.0-only":
        raise RouteReplacementError("source license must be GPL-3.0-only")
    false_fields = (
        "restricted_vendor_code_included",
        "source_dirty",
        "vendor_binary_blob_included",
    )
    if any(_boolean(value[field], f"firmware.{field}") for field in false_fields):
        raise RouteReplacementError("firmware source/restricted-code posture is unsafe")
    if not _boolean(
        value["third_party_license_review_passed"],
        "firmware.third_party_license_review_passed",
    ):
        raise RouteReplacementError("third-party license review must pass")
    refs = (
        ("source_archive_evidence_id", "source_archive"),
        ("source_manifest_evidence_id", "source_manifest"),
        ("sbom_evidence_id", "sbom"),
        ("license_review_evidence_id", "license_review"),
        ("clean_room_review_evidence_id", "clean_room_review"),
    )
    for key, kind in refs:
        _evidence_ref(evidence, value[key], kind, f"firmware.{key}")
    _sha(value["source_archive_sha256"], "firmware.source_archive_sha256")
    archive = evidence[value["source_archive_evidence_id"]]
    if receipt and archive["sha256"] != value["source_archive_sha256"]:
        raise RouteReplacementError("source archive digest does not match evidence")


def _artifact_keys(route: str) -> tuple[str, ...]:
    if route == "native_aes0_flash":
        return ("aup", "elf", "raw")
    if route in SRAM_ROUTES:
        return ("elf", "raw")
    return ("controller",)


def _artifact_kind(name: str) -> str:
    return {
        "aup": "firmware_aup",
        "controller": "controller_firmware_artifact",
        "elf": "firmware_elf",
        "raw": "firmware_raw",
    }[name]


def _validate_builds(
    value: Any,
    route: str,
    evidence: Mapping[str, Mapping[str, Any]],
    source_sha: str,
    completed_at: datetime,
) -> None:
    if not isinstance(value, list) or len(value) != 2:
        raise RouteReplacementError("builds must contain exactly two independent runs")
    build_ids: set[str] = set()
    host_ids: set[str] = set()
    workspace_ids: set[str] = set()
    all_artifacts: set[str] = set()
    all_support: set[str] = set()
    expected_artifacts = _artifact_keys(route)
    for index, build in enumerate(value):
        context = f"builds[{index}]"
        if not isinstance(build, dict):
            raise RouteReplacementError(f"{context} must be an object")
        _exact(
            build,
            (
                "artifacts",
                "build_log_evidence_id",
                "completed_at_utc",
                "environment_sha256",
                "host_id",
                "id",
                "source_archive_sha256",
                "started_at_utc",
                "toolchain_manifest_evidence_id",
                "workspace_id",
            ),
            context,
        )
        build_ids.add(_identifier(build["id"], f"{context}.id"))
        host_ids.add(_identifier(build["host_id"], f"{context}.host_id"))
        workspace_ids.add(_identifier(build["workspace_id"], f"{context}.workspace_id"))
        started = _utc(build["started_at_utc"], f"{context}.started_at_utc")
        completed = _utc(build["completed_at_utc"], f"{context}.completed_at_utc")
        if started >= completed or completed > completed_at:
            raise RouteReplacementError(f"{context} chronology is invalid")
        _sha(build["environment_sha256"], f"{context}.environment_sha256")
        if build["source_archive_sha256"] != source_sha:
            raise RouteReplacementError(f"{context} source archive digest drifted")
        artifacts = build["artifacts"]
        if not isinstance(artifacts, dict):
            raise RouteReplacementError(f"{context}.artifacts must be an object")
        _exact(artifacts, expected_artifacts, f"{context}.artifacts")
        for name in expected_artifacts:
            item = _evidence_ref(
                evidence,
                artifacts[name],
                _artifact_kind(name),
                f"{context}.artifacts.{name}",
            )
            all_artifacts.add(item["id"])
        for key, kind in (
            ("build_log_evidence_id", "reproducibility_log"),
            ("toolchain_manifest_evidence_id", "toolchain_manifest"),
        ):
            item = _evidence_ref(evidence, build[key], kind, f"{context}.{key}")
            all_support.add(item["id"])
    expected_count = 2 * len(expected_artifacts)
    if (
        len(build_ids) != 2
        or len(host_ids) != 2
        or len(workspace_ids) != 2
        or len(all_artifacts) != expected_count
        or len(all_support) != 4
    ):
        raise RouteReplacementError("builds are not independently evidenced")


def _candidate_routes(route_record: Mapping[str, Any]) -> list[str]:
    candidates = []
    by_id = {item["route_id"]: item for item in route_record["routes"]}
    for route in ROUTES:
        if by_id[route]["state"] == ROUTE_STATES[route]:
            candidates.append(route)
    return candidates


def _validate_route_selection(value: Any) -> str:
    if not isinstance(value, dict):
        raise RouteReplacementError("route_selection must be an object")
    _exact(
        value,
        (
            "adjudicated_candidate_routes",
            "adjudication_sha256",
            "automatic_priority_selection_used",
            "builder_approved",
            "review_basis",
            "reviewer_approved",
            "selected_route",
        ),
        "route_selection",
    )
    route = value["selected_route"]
    if route not in ROUTES:
        raise RouteReplacementError("selected route is unsupported")
    _sha(value["adjudication_sha256"], "route_selection.adjudication_sha256")
    _text(value["review_basis"], "route_selection.review_basis", 240)
    if _boolean(
        value["automatic_priority_selection_used"],
        "route_selection.automatic_priority_selection_used",
    ):
        raise RouteReplacementError("automatic route priority selection is forbidden")
    if not _boolean(value["builder_approved"], "route_selection.builder_approved"):
        raise RouteReplacementError(
            "builder must explicitly approve the selected route"
        )
    if not _boolean(value["reviewer_approved"], "route_selection.reviewer_approved"):
        raise RouteReplacementError(
            "reviewer must explicitly approve the selected route"
        )
    candidates = value["adjudicated_candidate_routes"]
    if (
        not isinstance(candidates, list)
        or any(item not in ROUTES for item in candidates)
        or len(candidates) != len(set(candidates))
        or candidates != [route_id for route_id in ROUTES if route_id in candidates]
    ):
        raise RouteReplacementError("adjudicated candidate routes are not canonical")
    if route not in candidates:
        raise RouteReplacementError("selected route is not an adjudicated candidate")
    return route


def _validate_route_contract(
    value: Any,
    route: str,
    record: Mapping[str, Any],
    evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    if not isinstance(value, dict):
        raise RouteReplacementError("route_contract must be an object")
    if route == "native_aes0_flash":
        keys = (
            "aup_hw_list",
            "aup_sw_list",
            "board_profile_evidence_id",
            "boot_flash_device_id",
            "boot_image_capacity_bytes",
            "boot_image_offset_bytes",
            "load_address",
            "route_id",
        )
        _exact(value, keys, "route_contract")
        _evidence_ref(
            evidence,
            value["board_profile_evidence_id"],
            "board_profile_record",
            "route_contract.board_profile_evidence_id",
        )
        _identifier(
            value["boot_flash_device_id"], "route_contract.boot_flash_device_id"
        )
        _integer(
            value["boot_image_offset_bytes"],
            "route_contract.boot_image_offset_bytes",
            0,
            boot.MAX_FLASH_BYTES - 1,
        )
        _integer(
            value["boot_image_capacity_bytes"],
            "route_contract.boot_image_capacity_bytes",
            1,
            boot.MAX_FLASH_BYTES,
        )
        _integer(value["load_address"], "route_contract.load_address", 1, 2**64 - 1)
        try:
            hardware = v1._validate_tags(
                value["aup_hw_list"], "route_contract.aup_hw_list"
            )
            software = v1._validate_tags(
                value["aup_sw_list"], "route_contract.aup_sw_list"
            )
            held = v1._profile_for_target(record["_manifest"], record["target_id"])
        except v1.ReplacementError as exc:
            raise RouteReplacementError(str(exc)) from exc
        if held is not None and (
            hardware != held["hw_list"] or software != held["sw_list"]
        ):
            raise RouteReplacementError(
                "AES0 AUP tags do not match the held target profile"
            )
    elif route in SRAM_ROUTES:
        keys = (
            "entry_address",
            "executable_image_size_bytes",
            "execution_qualification_evidence_id",
            "execution_trace_evidence_id",
            "load_address",
            "maximum_image_size_bytes",
            "route_id",
        )
        _exact(value, keys, "route_contract")
        load = _integer(
            value["load_address"], "route_contract.load_address", 1, 2**64 - 1
        )
        entry = _integer(
            value["entry_address"], "route_contract.entry_address", 1, 2**64 - 1
        )
        size = _integer(
            value["executable_image_size_bytes"],
            "route_contract.executable_image_size_bytes",
            1,
            MAX_ARTIFACT_BYTES,
        )
        maximum = _integer(
            value["maximum_image_size_bytes"],
            "route_contract.maximum_image_size_bytes",
            1,
            MAX_ARTIFACT_BYTES,
        )
        if entry != load or size > maximum:
            raise RouteReplacementError("SRAM entry/load/size contract is inconsistent")
        _evidence_ref(
            evidence,
            value["execution_qualification_evidence_id"],
            "sram_execution_qualification",
            "route_contract.execution_qualification_evidence_id",
        )
        _evidence_ref(
            evidence,
            value["execution_trace_evidence_id"],
            "sram_execution_trace",
            "route_contract.execution_trace_evidence_id",
        )
    else:
        keys = (
            "artifact_format",
            "connector_evidence_id",
            "controller_target",
            "cooling_evidence_id",
            "cutoff_evidence_id",
            "interface_qualification_evidence_id",
            "power_evidence_id",
            "recovery_evidence_id",
            "route_id",
            "signal_evidence_id",
        )
        _exact(value, keys, "route_contract")
        _identifier(value["artifact_format"], "route_contract.artifact_format")
        _identifier(value["controller_target"], "route_contract.controller_target")
        refs = (
            ("connector_evidence_id", "connector_map_qualification"),
            ("signal_evidence_id", "signal_map_qualification"),
            ("power_evidence_id", "power_interface_qualification"),
            ("cooling_evidence_id", "cooling_interface_qualification"),
            ("cutoff_evidence_id", "cutoff_interface_qualification"),
            ("recovery_evidence_id", "recovery_interface_qualification"),
            (
                "interface_qualification_evidence_id",
                "controller_interface_qualification",
            ),
        )
        for key, kind in refs:
            _evidence_ref(evidence, value[key], kind, f"route_contract.{key}")
    if value["route_id"] != route:
        raise RouteReplacementError("route contract does not match selected route")


def _validate_signing(value: Any) -> None:
    if not isinstance(value, dict):
        raise RouteReplacementError("signing must be an object")
    _exact(value, ("builder", "reviewer"), "signing")
    expected = {
        "builder": (BUILDER_ROLE, BUILDER_NAMESPACE),
        "reviewer": (REVIEWER_ROLE, REVIEWER_NAMESPACE),
    }
    key_ids = set()
    for name, (role, namespace) in expected.items():
        item = value[name]
        if not isinstance(item, dict):
            raise RouteReplacementError(f"signing.{name} must be an object")
        _exact(
            item,
            ("algorithm", "key_id_sha256", "namespace", "role"),
            f"signing.{name}",
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role
        ):
            raise RouteReplacementError(f"signing.{name} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{name}.key_id_sha256"))
    if len(key_ids) != 2:
        raise RouteReplacementError(
            "builder and reviewer signing keys must be distinct"
        )


def _validate_core(
    value: Mapping[str, Any], manifest: Mapping[str, Any], *, receipt: bool
) -> tuple[str, dict[str, Mapping[str, Any]]]:
    core_keys = (
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
        "route_contract",
        "route_selection",
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
        "interface_qualification_sha256",
        "receipt_id",
        "signing",
    )
    _exact(
        value,
        core_keys + receipt_only if receipt else core_keys,
        "route replacement record",
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise RouteReplacementError("route replacement schema or scope mismatch")
    if value["kind"] != (RECEIPT_KIND if receipt else DESCRIPTOR_KIND):
        raise RouteReplacementError("route replacement kind mismatch")
    target_id = _identifier(value["target_id"], "target_id")
    _target(manifest, target_id)
    _identifier(value["unit_label"], "unit_label")
    for field in (
        "boot_policy_receipt_id",
        "discovery_receipt_id",
        "recovery_receipt_id",
        "stock_backup_set_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], field)
    builder = _principal(value["builder_id"], "builder_id")
    reviewer = _principal(value["reviewer_id"], "reviewer_id")
    if builder == reviewer:
        raise RouteReplacementError("builder and reviewer principals must be distinct")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    evidence_list = _validate_evidence(value["evidence"], hashed=receipt)
    evidence = {item["id"]: item for item in evidence_list}
    route = _validate_route_selection(value["route_selection"])
    _validate_firmware(value["firmware"], evidence, receipt=receipt)
    _validate_builds(
        value["builds"],
        route,
        evidence,
        value["firmware"]["source_archive_sha256"],
        completed,
    )
    contract_record = dict(value)
    contract_record["_manifest"] = manifest
    _validate_route_contract(value["route_contract"], route, contract_record, evidence)
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise RouteReplacementError("route replacement authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise RouteReplacementError("route replacement disposition drifted")
        for field in (
            "artifact_set_sha256",
            "descriptor_sha256",
            "interface_qualification_sha256",
            "receipt_id",
        ):
            _sha(value[field], field)
        _validate_signing(value["signing"])
    return route, evidence


def _boot_result(receipt: Mapping[str, Any]) -> dict[str, Any]:
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
            key: jtag[key]
            for key in ("halt_capable", "read_memory_capable", "write_memory_capable")
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
            key: rom[key]
            for key in (
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


def _load_copy(
    record: Mapping[str, Any], root: Path, kind: str, label: str
) -> dict[str, Any]:
    matches = [item for item in record["evidence"] if item["kind"] == kind]
    if len(matches) != 1:
        raise RouteReplacementError(f"exactly one {kind} is required")
    return _load_json(
        _source(root, _safe_path(matches[0]["path"], f"{label} path")),
        label,
        canonical=True,
    )


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
    try:
        discovery._validate_receipt(discovery_receipt, manifest)
        recovery._validate_receipt(recovery_receipt, manifest)
        boot._validate_receipt(boot_receipt, manifest)
    except (
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
    ) as exc:
        raise RouteReplacementError(f"predecessor receipt is invalid: {exc}") from exc
    expected = {
        "boot_policy_receipt_id": boot_receipt["receipt_id"],
        "discovery_receipt_id": discovery_receipt["receipt_id"],
        "recovery_receipt_id": recovery_receipt["receipt_id"],
        "stock_backup_set_sha256": recovery_receipt["stock_backup_set_sha256"],
        "target_id": discovery_receipt["target_id"],
        "unit_fingerprint_sha256": discovery_receipt["unit_fingerprint_sha256"],
        "unit_label": discovery_receipt["unit_label"],
    }
    joins = (
        (recovery_receipt, "discovery_receipt_id", expected["discovery_receipt_id"]),
        (recovery_receipt, "target_id", expected["target_id"]),
        (
            recovery_receipt,
            "unit_fingerprint_sha256",
            expected["unit_fingerprint_sha256"],
        ),
        (recovery_receipt, "unit_label", expected["unit_label"]),
        (boot_receipt, "discovery_receipt_id", expected["discovery_receipt_id"]),
        (boot_receipt, "recovery_receipt_id", expected["recovery_receipt_id"]),
        (boot_receipt, "stock_backup_set_sha256", expected["stock_backup_set_sha256"]),
        (boot_receipt, "target_id", expected["target_id"]),
        (boot_receipt, "unit_fingerprint_sha256", expected["unit_fingerprint_sha256"]),
        (boot_receipt, "unit_label", expected["unit_label"]),
    )
    for predecessor, key, wanted in joins:
        if predecessor[key] != wanted:
            raise RouteReplacementError(f"predecessor {key} exact join failed")
    for key, wanted in expected.items():
        if record[key] != wanted:
            raise RouteReplacementError(f"predecessor {key} does not match replacement")
    try:
        recomputed = boot_route.adjudicate(_boot_result(boot_receipt))
    except boot_route.BootRouteError as exc:
        raise RouteReplacementError(f"boot-route recomputation failed: {exc}") from exc
    if route_record != recomputed:
        raise RouteReplacementError(
            "boot-route record does not reproduce from boot evidence"
        )
    selection = record["route_selection"]
    if selection["adjudication_sha256"] != recomputed["adjudication_sha256"]:
        raise RouteReplacementError("route selection adjudication digest is spliced")
    candidates = _candidate_routes(recomputed)
    if selection["adjudicated_candidate_routes"] != candidates:
        raise RouteReplacementError(
            "route selection candidate set does not match adjudication"
        )
    selected = selection["selected_route"]
    by_id = {item["route_id"]: item for item in recomputed["routes"]}
    if by_id[selected]["state"] != ROUTE_STATES[selected]:
        raise RouteReplacementError(
            "selected route lacks its required adjudicated state"
        )
    if selected == "native_aes0_flash" and (
        boot_receipt["security_policy"]["force_decrypt_state"] != "disabled"
        or boot_receipt["plaintext_probe"]["plaintext_boot_supported"] is not True
        or boot_receipt["flash_policy"]["candidate_load_contract_compatible"]
        is not True
    ):
        raise RouteReplacementError("AES0 selection lacks positive AES0 boot evidence")
    return {
        "boot": boot_receipt,
        "discovery": discovery_receipt,
        "recovery": recovery_receipt,
        "route": recomputed,
    }


def _read_artifact(path: Path, label: str) -> bytes:
    try:
        return discovery._read_regular(path, label, MAX_ARTIFACT_BYTES)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc


def _artifact_sources(record: Mapping[str, Any], root: Path) -> dict[str, Path]:
    return {
        item["id"]: _source(
            root, _safe_path(item["path"], f"evidence {item['id']} path")
        )
        for item in record["evidence"]
    }


def _validate_aes0_artifacts(
    record: Mapping[str, Any],
    sources: Mapping[str, Path],
    predecessors: Mapping[str, Any],
) -> dict[str, str]:
    contract = record["route_contract"]
    boot_receipt = predecessors["boot"]
    flash = boot_receipt["flash_policy"]
    matches = [
        item
        for item in flash["devices"]
        if item["id"] == contract["boot_flash_device_id"]
    ]
    if len(matches) != 1:
        raise RouteReplacementError("AES0 boot flash is absent from boot evidence")
    if (
        contract["boot_image_offset_bytes"] != flash["boot_image_offset_bytes"]
        or contract["boot_image_capacity_bytes"] != flash["boot_image_length_bytes"]
        or contract["load_address"] != flash["measured_boot_load_address"]
    ):
        raise RouteReplacementError(
            "AES0 delivery geometry does not match boot evidence"
        )
    outputs = []
    for build in record["builds"]:
        elf = _read_artifact(sources[build["artifacts"]["elf"]], "AES0 ELF")
        raw = _read_artifact(sources[build["artifacts"]["raw"]], "AES0 raw")
        aup = _read_artifact(sources[build["artifacts"]["aup"]], "AES0 AUP")
        try:
            elf_result = v1.inspect_single_load_elf(elf, contract["load_address"])
            aup_result = v1.inspect_plain_aup(aup)
        except v1.ReplacementError as exc:
            raise RouteReplacementError(str(exc)) from exc
        if (
            not raw
            or elf_result["raw"] != raw
            or elf_result["memory_size"] > contract["boot_image_capacity_bytes"]
            or aup_result["app"] != raw
            or aup_result["firmware_version"] != record["firmware"]["firmware_version"]
            or aup_result["hardware"] != contract["aup_hw_list"]
            or aup_result["software"] != contract["aup_sw_list"]
            or aup_result["wrapper_bytes"] > contract["boot_image_capacity_bytes"]
        ):
            raise RouteReplacementError(
                "AES0 ELF/raw/AUP mapping or geometry is invalid"
            )
        outputs.append(
            {
                "aup": hashlib.sha256(aup).hexdigest(),
                "elf": hashlib.sha256(elf).hexdigest(),
                "raw": hashlib.sha256(raw).hexdigest(),
            }
        )
    if outputs[0] != outputs[1]:
        raise RouteReplacementError("AES0 independent builds are not byte-identical")
    return outputs[0]


def _validate_sram_artifacts(
    record: Mapping[str, Any], sources: Mapping[str, Path]
) -> dict[str, str]:
    contract = record["route_contract"]
    outputs = []
    for build in record["builds"]:
        elf = _read_artifact(sources[build["artifacts"]["elf"]], "SRAM ELF")
        raw = _read_artifact(sources[build["artifacts"]["raw"]], "SRAM raw")
        try:
            elf_result = v1.inspect_single_load_elf(elf, contract["load_address"])
        except v1.ReplacementError as exc:
            raise RouteReplacementError(str(exc)) from exc
        if (
            not raw
            or elf_result["raw"] != raw
            or len(raw) != contract["executable_image_size_bytes"]
            or elf_result["memory_size"] > contract["maximum_image_size_bytes"]
        ):
            raise RouteReplacementError(
                "SRAM ELF/raw entry, address, or size is invalid"
            )
        outputs.append(
            {
                "elf": hashlib.sha256(elf).hexdigest(),
                "raw": hashlib.sha256(raw).hexdigest(),
            }
        )
    if outputs[0] != outputs[1]:
        raise RouteReplacementError("SRAM independent builds are not byte-identical")
    return outputs[0]


def _validate_sram_qualification(
    record: Mapping[str, Any], sources: Mapping[str, Path], artifacts: Mapping[str, str]
) -> str:
    contract = record["route_contract"]
    evidence = {item["id"]: item for item in record["evidence"]}
    trace = evidence[contract["execution_trace_evidence_id"]]
    expected = {
        "authority_granted": False,
        "entry_address": contract["entry_address"],
        "executable_image_size_bytes": contract["executable_image_size_bytes"],
        "execution_started": True,
        "hash_power_physically_disconnected": True,
        "independent_cutoff_asserted": True,
        "kind": "dcent_k210_sram_execution_qualification",
        "load_address": contract["load_address"],
        "raw_sha256": artifacts["raw"],
        "route_id": record["route_selection"]["selected_route"],
        "safe_idle_observed": True,
        "stock_restored_after_probe": True,
        "target_id": record["target_id"],
        "trace_bytes": trace["bytes"],
        "trace_sha256": trace["sha256"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    qualification = _load_json(
        sources[contract["execution_qualification_evidence_id"]],
        "SRAM execution qualification",
        canonical=True,
    )
    if qualification != expected:
        raise RouteReplacementError(
            "SRAM execution qualification is missing or inconsistent"
        )
    return hashlib.sha256(canonical_json_bytes(expected)).hexdigest()


def _validate_controller_artifacts(
    record: Mapping[str, Any], sources: Mapping[str, Path]
) -> dict[str, str]:
    artifacts = []
    for build in record["builds"]:
        data = _read_artifact(
            sources[build["artifacts"]["controller"]], "controller artifact"
        )
        if not data:
            raise RouteReplacementError("controller artifact is empty")
        artifacts.append(hashlib.sha256(data).hexdigest())
    if artifacts[0] != artifacts[1]:
        raise RouteReplacementError(
            "controller independent builds are not byte-identical"
        )
    return {"controller": artifacts[0]}


def _validate_controller_interface(
    record: Mapping[str, Any], sources: Mapping[str, Path], artifacts: Mapping[str, str]
) -> str:
    contract = record["route_contract"]
    evidence = {item["id"]: item for item in record["evidence"]}
    component_fields = (
        ("connector", "connector_evidence_id"),
        ("signal", "signal_evidence_id"),
        ("power", "power_evidence_id"),
        ("cooling", "cooling_evidence_id"),
        ("cutoff", "cutoff_evidence_id"),
        ("recovery", "recovery_evidence_id"),
    )
    components = {}
    for name, field in component_fields:
        item = evidence[contract[field]]
        components[name] = {
            "bytes": item["bytes"],
            "evidence_id": item["id"],
            "sha256": item["sha256"],
        }
    expected = {
        "artifact_format": contract["artifact_format"],
        "artifact_sha256": artifacts["controller"],
        "asic_interface_qualified": True,
        "authority_granted": False,
        "components": components,
        "connector_mapping_complete": True,
        "controller_target": contract["controller_target"],
        "cooling_custody_qualified": True,
        "independent_cutoff_qualified": True,
        "kind": "dcent_k210_replacement_controller_interface_qualification",
        "power_envelope_qualified": True,
        "recovery_interface_qualified": True,
        "route_id": "clean_replacement_controller",
        "signal_levels_qualified": True,
        "target_id": record["target_id"],
        "unit_fingerprint_sha256": record["unit_fingerprint_sha256"],
    }
    qualification = _load_json(
        sources[contract["interface_qualification_evidence_id"]],
        "controller interface qualification",
        canonical=True,
    )
    if qualification != expected:
        raise RouteReplacementError(
            "replacement-controller interface qualification is missing or inconsistent"
        )
    return hashlib.sha256(canonical_json_bytes(expected)).hexdigest()


def _referenced_ids(record: Mapping[str, Any], route: str) -> set[str]:
    used = {
        item["id"] for item in record["evidence"] if item["kind"] in PREDECESSOR_KINDS
    }
    firmware = record["firmware"]
    used.update(
        firmware[key]
        for key in (
            "clean_room_review_evidence_id",
            "license_review_evidence_id",
            "sbom_evidence_id",
            "source_archive_evidence_id",
            "source_manifest_evidence_id",
        )
    )
    for build in record["builds"]:
        used.add(build["build_log_evidence_id"])
        used.add(build["toolchain_manifest_evidence_id"])
        used.update(build["artifacts"].values())
    contract = record["route_contract"]
    if route == "native_aes0_flash":
        used.add(contract["board_profile_evidence_id"])
    elif route in SRAM_ROUTES:
        used.add(contract["execution_qualification_evidence_id"])
        used.add(contract["execution_trace_evidence_id"])
    else:
        used.update(
            contract[key]
            for key in (
                "connector_evidence_id",
                "cooling_evidence_id",
                "cutoff_evidence_id",
                "interface_qualification_evidence_id",
                "power_evidence_id",
                "recovery_evidence_id",
                "signal_evidence_id",
            )
        )
    return used


def _validate_artifacts_and_interface(
    record: Mapping[str, Any], root: Path, predecessors: Mapping[str, Any]
) -> tuple[dict[str, str], str]:
    route = record["route_selection"]["selected_route"]
    sources = _artifact_sources(record, root)
    if _referenced_ids(record, route) != set(sources):
        raise RouteReplacementError(
            "route bundle has cross-route or unreferenced evidence"
        )
    if route == "native_aes0_flash":
        artifacts = _validate_aes0_artifacts(record, sources, predecessors)
        profile = sources[record["route_contract"]["board_profile_evidence_id"]]
        _, interface_digest = _hash(profile, "AES0 board profile")
    elif route in SRAM_ROUTES:
        artifacts = _validate_sram_artifacts(record, sources)
        interface_digest = _validate_sram_qualification(record, sources, artifacts)
    else:
        artifacts = _validate_controller_artifacts(record, sources)
        interface_digest = _validate_controller_interface(record, sources, artifacts)
    return artifacts, interface_digest


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "artifact_set_sha256",
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "interface_qualification_sha256",
        "receipt_id",
        "signing",
    }
    descriptor = {key: value for key, value in receipt.items() if key not in excluded}
    descriptor["kind"] = DESCRIPTOR_KIND
    descriptor["evidence"] = [
        {key: value for key, value in item.items() if key not in {"bytes", "sha256"}}
        for item in receipt["evidence"]
    ]
    return descriptor


def _artifact_set_digest(route: str, artifacts: Mapping[str, str]) -> str:
    return hashlib.sha256(
        b"DCENT-K210-ROUTE-ARTIFACT-SET-V2\x00"
        + canonical_json_bytes({"artifacts": dict(artifacts), "selected_route": route})
    ).hexdigest()


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    route, _ = _validate_core(receipt, manifest, receipt=True)
    if (
        hashlib.sha256(
            canonical_json_bytes(_descriptor_projection(receipt))
        ).hexdigest()
        != receipt["descriptor_sha256"]
    ):
        raise RouteReplacementError("route replacement descriptor digest mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    expected_id = hashlib.sha256(
        b"DCENT-K210-ROUTE-REPLACEMENT-RECEIPT-ID-V2\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if expected_id != receipt["receipt_id"]:
        raise RouteReplacementError("route replacement receipt ID mismatch")
    if route != receipt["route_selection"]["selected_route"]:
        raise RouteReplacementError("internal selected route mismatch")


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    builder_private_key: Path,
    reviewer_private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    route, _ = _validate_core(descriptor, manifest, receipt=False)
    sources = _artifact_sources(descriptor, evidence_root)
    evidence_with_hashes = []
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        size, digest = _hash(sources[item["id"]], f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RouteReplacementError(
                "route replacement evidence exceeds aggregate limit"
            )
        enriched = dict(item)
        enriched["bytes"] = size
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
    try:
        builder_key = discovery.inspect_private_key(builder_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(
            f"route replacement signing key is invalid: {exc}"
        ) from exc
    if builder_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise RouteReplacementError(
            "builder and reviewer private keys must be distinct"
        )
    normalized = json.loads(json.dumps(descriptor))
    normalized["evidence"] = evidence_with_hashes
    normalized["kind"] = RECEIPT_KIND
    receipt: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "disposition": DISPOSITION,
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
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    predecessors = _validate_predecessors(manifest, receipt, evidence_root)
    artifacts, interface_digest = _validate_artifacts_and_interface(
        receipt, evidence_root, predecessors
    )
    receipt["artifact_set_sha256"] = _artifact_set_digest(route, artifacts)
    receipt["interface_qualification_sha256"] = interface_digest
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-ROUTE-REPLACEMENT-RECEIPT-ID-V2\x00"
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
    if bundle_out.exists() or bundle_out.is_symlink():
        raise RouteReplacementError(
            f"refusing to overwrite existing bundle: {bundle_out}"
        )
    descriptor = _load_json(
        descriptor_path, "route replacement descriptor", canonical=False
    )
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
            size, digest = _hash(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise RouteReplacementError(
                    f"evidence {item['id']} changed during snapshot"
                )
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        try:
            builder_sig = discovery.sign_sshsig_file(
                receipt_path, builder_private_key, BUILDER_NAMESPACE
            )
            reviewer_sig = discovery.sign_sshsig_file(
                receipt_path, reviewer_private_key, REVIEWER_NAMESPACE
            )
        except discovery.DiscoveryError as exc:
            raise RouteReplacementError(
                f"route replacement signing failed: {exc}"
            ) from exc
        builder_path = temporary / BUILDER_SIGNATURE_NAME
        reviewer_path = temporary / REVIEWER_SIGNATURE_NAME
        builder_path.write_bytes(builder_sig)
        reviewer_path.write_bytes(reviewer_sig)
        discovery.verify_sshsig_bytes(
            receipt_raw,
            builder_path,
            discovery.inspect_private_key(builder_private_key)["canonical_line"],
            receipt["builder_id"],
            BUILDER_NAMESPACE,
        )
        discovery.verify_sshsig_bytes(
            receipt_raw,
            reviewer_path,
            discovery.inspect_private_key(reviewer_private_key)["canonical_line"],
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
    expected_builder_key_id: Optional[str] = None,
    expected_reviewer_key_id: Optional[str] = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise RouteReplacementError(
            f"route replacement bundle cannot be inspected: {exc}"
        ) from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise RouteReplacementError(
            "route replacement bundle must be a non-symlink directory"
        )
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "route replacement receipt", canonical=True)
    _validate_receipt(receipt, manifest)
    try:
        builder_key = discovery.inspect_public_key(builder_public_key)
        reviewer_key = discovery.inspect_public_key(reviewer_public_key)
        receipt_raw = discovery._read_regular(
            receipt_path, "route replacement receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise RouteReplacementError(str(exc)) from exc
    if builder_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise RouteReplacementError("builder and reviewer trust keys must be distinct")
    if receipt_raw != canonical_json_bytes(receipt):
        raise RouteReplacementError(
            "route replacement receipt changed after validation"
        )
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
            raise RouteReplacementError(f"{role} key does not match the trust anchor")
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise RouteReplacementError(
                f"route replacement {role} signer is not trusted"
            )
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw,
                signature_path,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise RouteReplacementError(f"{role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise RouteReplacementError(
                "route replacement evidence exceeds aggregate limit"
            )
        if size != item["bytes"] or digest != item["sha256"]:
            raise RouteReplacementError(
                f"evidence {item['id']} digest or size mismatch"
            )
    predecessors = _validate_predecessors(
        manifest, receipt, bundle / EVIDENCE_DIRECTORY
    )
    artifacts, interface_digest = _validate_artifacts_and_interface(
        receipt, bundle / EVIDENCE_DIRECTORY, predecessors
    )
    route = receipt["route_selection"]["selected_route"]
    if _artifact_set_digest(route, artifacts) != receipt["artifact_set_sha256"]:
        raise RouteReplacementError("artifact-set digest changed after verification")
    if interface_digest != receipt["interface_qualification_sha256"]:
        raise RouteReplacementError("interface qualification digest changed")
    _verify_exact_members(bundle, receipt)
    installed_artifact_sha256 = artifacts[
        {
            "native_aes0_flash": "aup",
            "rom_isp_sram_bootstrap": "raw",
            "jtag_sram_bootstrap": "raw",
            "clean_replacement_controller": "controller",
        }[route]
    ]
    return {
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "authority_granted": False,
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "builder_key_id_sha256": builder_key["key_id_sha256"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "installed_artifact_sha256": installed_artifact_sha256,
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "replacement_firmware_version": receipt["firmware"]["firmware_version"],
        "replacement_firmware_gate_eligible": True,
        "reviewer_key_id_sha256": reviewer_key["key_id_sha256"],
        "route_adjudication_sha256": receipt["route_selection"]["adjudication_sha256"],
        "selected_route": route,
        "state": "verified_signed_route_replacement_firmware",
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
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
            raise RouteReplacementError(f"bundle cannot be enumerated: {exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or discovery._is_link_or_reparse(metadata):
                raise RouteReplacementError(
                    f"bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise RouteReplacementError(
                    f"bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        raise RouteReplacementError("route replacement bundle member set is not exact")


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and sign a completed route artifact"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--builder-private-key", type=Path, required=True)
    create.add_argument("--reviewer-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a route artifact bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--builder-public-key", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    verify.add_argument("--expected-builder-key-id")
    verify.add_argument("--expected-reviewer-key-id")
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
                args.builder_private_key,
                args.reviewer_private_key,
                args.bundle_out,
            )
            print(
                f"K210_ROUTE_REPLACEMENT_CREATED target={receipt['target_id']} "
                f"route={receipt['route_selection']['selected_route']} "
                f"receipt_id={receipt['receipt_id']} authority_granted=false"
            )
            return 0
        for label, value in (
            ("--expected-builder-key-id", args.expected_builder_key_id),
            ("--expected-reviewer-key-id", args.expected_reviewer_key_id),
        ):
            if value is not None and not HEX64_RE.fullmatch(value):
                raise RouteReplacementError(f"{label} must be lowercase SHA-256")
        result = verify_bundle(
            manifest,
            args.bundle,
            args.builder_public_key,
            args.reviewer_public_key,
            args.expected_builder_key_id,
            args.expected_reviewer_key_id,
        )
        if args.format == "json":
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"K210_ROUTE_REPLACEMENT_VERIFIED target={result['target_id']} "
                f"route={result['selected_route']} receipt_id={result['receipt_id']} "
                "gate_eligible=true authority_granted=false"
            )
        return 0
    except (
        RouteReplacementError,
        discovery.DiscoveryError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        v1.ReplacementError,
        boot_route.BootRouteError,
    ) as exc:
        print(f"K210_ROUTE_REPLACEMENT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
