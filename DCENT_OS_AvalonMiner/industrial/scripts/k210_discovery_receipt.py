#!/usr/bin/env python3
"""Create and verify signed, read-only Avalon K210 discovery bundles.

This tool has no miner transport. It only snapshots caller-supplied evidence,
binds it to an exact manifest row, and signs a canonical receipt with OpenSSH
SSHSIG/Ed25519. A receipt records past observations; it never authorizes future
contact, configuration, power, cooling, hashing, firmware writes, or release.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


SCHEMA_VERSION = 1
SCOPE = "canaan-avalon-k210-production-readiness"
CAPTURE_KIND = "dcent_k210_read_only_discovery_capture"
RECEIPT_KIND = "dcent_k210_read_only_discovery_receipt"
DISPOSITION = "evidence_only_no_contact_or_mutation_authority"
SIGNATURE_ALGORITHM = "sshsig-ed25519"
SIGNATURE_NAMESPACE = "dcent-k210-discovery-v1"
SIGNER_ROLE = "k210_discovery_observer"
RECEIPT_NAME = "receipt.json"
SIGNATURE_NAME = "receipt.sig"
EVIDENCE_DIRECTORY = "evidence"
MAX_JSON_BYTES = 256 * 1024
MAX_EVIDENCE_ITEMS = 32
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024
MAX_SEMANTIC_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 1024 * 1024 * 1024

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
OBSERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PLACEHOLDER_RE = re.compile(
    r"(?:^|[^A-Z0-9])(?:REPLACE(?:_OR_NOT_PRESENT|_FROM_[A-Z0-9_]+)?|"
    r"PLACEHOLDER|UNKNOWN|UNRESOLVED|NOT[_ -]?OBSERVED|TBD|TODO|N/?A)"
    r"(?:$|[^A-Z0-9])"
)
MM_ID_RE = re.compile(r"^MM ID([0-9]+)$", re.IGNORECASE)
MIN_PHOTO_DIMENSION = 64
MIN_PHOTO_BYTES = 128
MAX_PHOTO_DIMENSION = 16_384
MAX_PHOTO_PIXELS = 50_000_000
MAX_PNG_DECODED_BYTES = 200_000_000
A1246_VARIANT_CONTRACT_KEY = "a1246_variant_identity_contract"

REQUIRED_EVIDENCE_KINDS = (
    "collection_log",
    "controller_back_photo",
    "controller_front_photo",
    "cooling_topology_photo",
    "hashboard_topology_record",
    "miner_label_photo",
    "psu_label_photo",
    "stock_stats_response",
    "stock_version_response",
)
OPTIONAL_EVIDENCE_KINDS = (
    "flash_marking_photo",
    "stock_estats_response",
    "uart_pad_photo",
)
EVIDENCE_KINDS = frozenset(REQUIRED_EVIDENCE_KINDS + OPTIONAL_EVIDENCE_KINDS)
PHOTO_KINDS = frozenset(kind for kind in EVIDENCE_KINDS if kind.endswith("_photo"))
STOCK_RESPONSE_KINDS = frozenset(
    {"stock_version_response", "stock_stats_response", "stock_estats_response"}
)
EVIDENCE_METHODS = {
    "offline_record",
    "stock_read_only_management",
    "visual_inspection",
}
AUTHORIZED_ACTIONS = {
    "closed_chassis_stock_power_restoration",
    "deenergized_visual_inspection_power_down",
    "stock_read_only_management_queries",
    "visual_identity_inspection",
}
MEDIA_TYPES = {"application/json", "image/png", "text/plain"}
REDACTION_STATES = {
    "credentials_removed",
    "none",
    "personal_identifiers_removed",
}
COOLING_CLASSES = {"air", "hydro", "immersion"}

ACTIONS_PERFORMED = {
    "configuration_changed": False,
    "cooling_commanded": False,
    "firmware_written": False,
    "hash_work_injected": False,
    "power_state_changed": True,
    "reboot_requested": False,
}
AUTHORITY_CEILING = {
    "authorizes_configuration_change": False,
    "authorizes_contact": False,
    "authorizes_firmware_write": False,
    "authorizes_hashing_or_power_control": False,
    "authorizes_release": False,
    "qualifies_production": False,
}


class DiscoveryError(RuntimeError):
    """A discovery bundle, key, or evidence invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryError(f"JSON has duplicate key {key!r}")
        result[key] = value
    return result


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be inspected: {exc}") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise DiscoveryError(f"{label} must be a regular non-symlink file: {path}")
    if metadata.st_size > maximum:
        raise DiscoveryError(f"{label} exceeds {maximum} bytes: {path}")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if _file_identity(opened) != _file_identity(metadata):
                raise DiscoveryError(f"{label} changed before it was opened: {path}")
            raw = stream.read(maximum + 1)
            final = os.fstat(stream.fileno())
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be read: {exc}") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be reinspected: {exc}") from exc
    if (
        len(raw) > maximum
        or len(raw) != opened.st_size
        or _file_identity(opened) != _file_identity(final)
        or _file_identity(final) != _file_identity(after)
    ):
        raise DiscoveryError(f"{label} changed while being read: {path}")
    return raw


def load_json(path: Path, label: str, *, require_canonical: bool) -> dict[str, Any]:
    raw = _read_regular(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DiscoveryError(f"{label} root must be an object")
    if require_canonical and raw != canonical_json_bytes(value):
        raise DiscoveryError(f"{label} is not canonical JSON")
    return value


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
        raise DiscoveryError(f"{context} keys invalid: {'; '.join(detail)}")


def _text(value: Any, context: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise DiscoveryError(f"{context} must be a non-empty string <= {maximum} chars")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise DiscoveryError(f"{context} must contain printable ASCII only")
    return value


def _observed_text(
    value: Any,
    context: str,
    maximum: int = 128,
    *,
    allow_not_present: bool = False,
) -> str:
    text = _text(value, context, maximum)
    if allow_not_present and text == "not-present":
        return text
    if PLACEHOLDER_RE.search(text.upper()):
        raise DiscoveryError(f"{context} contains a placeholder or unresolved value")
    return text


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 64)
    if not IDENTIFIER_RE.fullmatch(text):
        raise DiscoveryError(f"{context} is not a canonical identifier")
    return text


def _observer(value: Any) -> str:
    text = _text(value, "observer_id", 64)
    if not OBSERVER_RE.fullmatch(text):
        raise DiscoveryError("observer_id is not canonical")
    return text


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise DiscoveryError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DiscoveryError(f"{context} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _uuid4(value: Any) -> str:
    text = _text(value, "capture_session_id", 36)
    if text == "00000000-0000-4000-8000-000000000000":
        raise DiscoveryError("capture_session_id is the unresolved template placeholder")
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise DiscoveryError("capture_session_id must be a UUID") from exc
    if parsed.version != 4 or str(parsed) != text:
        raise DiscoveryError("capture_session_id must be canonical UUIDv4")
    return text


def _safe_evidence_path(value: Any, context: str) -> PurePosixPath:
    text = _text(value, context, 240)
    if "\\" in text or ":" in text:
        raise DiscoveryError(f"{context} must be a portable POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or str(path) != text:
        raise DiscoveryError(f"{context} must be a canonical relative path")
    if any(part in ("", ".", "..") for part in path.parts):
        raise DiscoveryError(f"{context} contains an unsafe segment")
    return path


def _target(manifest: Mapping[str, Any], target_id: str) -> Mapping[str, Any]:
    for target in manifest.get("targets", []):
        if target.get("id") == target_id:
            if target.get("kind") != "physical_model":
                raise DiscoveryError(
                    f"target {target_id} is not an exact physical-model row"
                )
            if target.get("asic_family") == "unknown":
                raise DiscoveryError(
                    f"target {target_id} has no exact ASIC family in the manifest"
                )
            return target
    raise DiscoveryError(f"unknown K210 target {target_id!r}")


def _a1246_variant_rows(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    contract = manifest.get(A1246_VARIANT_CONTRACT_KEY)
    if not isinstance(contract, dict):
        raise DiscoveryError("manifest has no A1246 variant identity contract")
    _require_exact_keys(
        contract, ("evidence_ceiling", "state", "variants"), "A1246 variant contract"
    )
    if contract["state"] != "held_stock_profile_tuple_plus_observed_topology":
        raise DiscoveryError("A1246 variant identity contract state drifted")
    _text(contract["evidence_ceiling"], "A1246 variant evidence ceiling", 512)
    variants = contract["variants"]
    if not isinstance(variants, list) or not variants:
        raise DiscoveryError("A1246 variant identity contract has no variants")

    targets = {
        row.get("id"): row
        for row in manifest.get("targets", [])
        if isinstance(row, dict)
    }
    profiles = {
        row.get("id"): row
        for row in manifest.get("firmware_profiles", [])
        if isinstance(row, dict)
    }
    normalized: list[dict[str, Any]] = []
    seen_profiles: set[str] = set()
    seen_tuples: set[tuple[str, str, str, str]] = set()
    for index, row in enumerate(variants):
        context = f"A1246 variant contract row {index}"
        if not isinstance(row, dict):
            raise DiscoveryError(f"{context} must be an object")
        _require_exact_keys(
            row,
            ("hashboard_count", "marketing_model", "profile_id", "target_id"),
            context,
        )
        target_id = _identifier(row["target_id"], f"{context}.target_id")
        profile_id = _identifier(row["profile_id"], f"{context}.profile_id")
        if target_id not in {"a1246", "a1246n"}:
            raise DiscoveryError(f"{context} maps a non-A1246 target")
        target = targets.get(target_id)
        if not isinstance(target, dict) or target.get("kind") != "physical_model":
            raise DiscoveryError(f"{context} target is not a physical-model row")
        marketing_model = _text(row["marketing_model"], f"{context}.marketing_model")
        if marketing_model != target.get("display_name"):
            raise DiscoveryError(f"{context} marketing model disagrees with target")
        count = row["hashboard_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count not in (2, 3):
            raise DiscoveryError(f"{context}.hashboard_count must be 2 or 3")
        profile = profiles.get(profile_id)
        if not isinstance(profile, dict):
            raise DiscoveryError(f"{context} references a missing firmware profile")
        for field in ("asic_family", "firmware_version", "hw_list", "sw_list"):
            if field not in profile:
                raise DiscoveryError(f"{context} profile is missing {field}")
        firmware = _text(profile["firmware_version"], f"{context} firmware")
        asic_family = _text(profile["asic_family"], f"{context} ASIC family")
        hw_list = profile["hw_list"]
        sw_list = profile["sw_list"]
        if not isinstance(hw_list, list) or len(hw_list) != 1:
            raise DiscoveryError(f"{context} profile must name one HWTYPE")
        if not isinstance(sw_list, list) or not sw_list:
            raise DiscoveryError(f"{context} profile must name at least one SWTYPE")
        hwtype = _text(hw_list[0], f"{context} HWTYPE")
        if not hwtype.endswith(f"_X{count}"):
            raise DiscoveryError(f"{context} HWTYPE disagrees with hashboard count")
        if profile_id in seen_profiles:
            raise DiscoveryError("A1246 variant contract repeats a firmware profile")
        seen_profiles.add(profile_id)
        for swtype_value in sw_list:
            swtype = _text(swtype_value, f"{context} SWTYPE")
            identity_tuple = (target_id, firmware, hwtype, swtype)
            if identity_tuple in seen_tuples:
                raise DiscoveryError("A1246 variant contract has an ambiguous stock tuple")
            seen_tuples.add(identity_tuple)
        normalized.append(
            {
                **row,
                "asic_family": asic_family,
                "firmware_version": firmware,
                "hwtype": hwtype,
                "sw_list": list(sw_list),
            }
        )
    expected_profiles = {
        "a1246-a3200lc-2hash",
        "a1246-a3201-2hash",
        "a1246-a3201-temp65",
        "a1246n",
    }
    if seen_profiles != expected_profiles:
        raise DiscoveryError("A1246 variant contract does not cover the four held profiles")
    return normalized


def _target_variant_rows(
    manifest: Mapping[str, Any], target_id: str
) -> list[dict[str, Any]]:
    return [
        row for row in _a1246_variant_rows(manifest) if row["target_id"] == target_id
    ]


def _validate_identity(
    identity: Any, target: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    if not isinstance(identity, dict):
        raise DiscoveryError("identity must be an object")
    _require_exact_keys(
        identity,
        (
            "asic_family",
            "controller_board_model",
            "controller_board_revision",
            "controller_serial",
            "controller_soc",
            "cooling_class",
            "cooling_controller",
            "fan_or_pump_count",
            "hashboard_count",
            "hashboard_identifiers",
            "manufacturer",
            "marketing_model",
            "miner_serial",
            "psu_model",
            "psu_rated_watts",
            "psu_serial",
            "stock_dna",
            "stock_firmware_version",
            "stock_hwtype",
            "stock_swtype",
        ),
        "identity",
    )
    if identity["manufacturer"] != "Canaan":
        raise DiscoveryError("identity.manufacturer must be Canaan")
    if identity["marketing_model"] != target["display_name"]:
        raise DiscoveryError("identity.marketing_model does not match manifest target")
    if identity["controller_soc"] != "K210":
        raise DiscoveryError("identity.controller_soc must be observed as K210")
    variant_rows = _target_variant_rows(manifest, str(target["id"]))
    allowed_asic_families = {row["asic_family"] for row in variant_rows}
    if variant_rows:
        if identity["asic_family"] not in allowed_asic_families:
            raise DiscoveryError(
                "identity.asic_family is not an exact admitted A1246 variant; "
                "the generic target-family label is forbidden"
            )
    elif identity["asic_family"] != target["asic_family"]:
        raise DiscoveryError("identity.asic_family does not match manifest target")
    for field in (
        "controller_board_model",
        "controller_board_revision",
        "controller_serial",
        "cooling_controller",
        "miner_serial",
        "psu_model",
        "psu_serial",
        "stock_dna",
        "stock_firmware_version",
        "stock_hwtype",
        "stock_swtype",
    ):
        _observed_text(
            identity[field],
            f"identity.{field}",
            128,
            allow_not_present=field in {"controller_serial", "psu_serial"},
        )
    if identity["cooling_class"] not in COOLING_CLASSES:
        raise DiscoveryError("identity.cooling_class is unsupported")
    for field, maximum in (
        ("fan_or_pump_count", 32),
        ("hashboard_count", 8),
        ("psu_rated_watts", 10_000),
    ):
        number = identity[field]
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 1 <= number <= maximum
        ):
            raise DiscoveryError(f"identity.{field} must be an integer in 1..{maximum}")
    identifiers = identity["hashboard_identifiers"]
    if (
        not isinstance(identifiers, list)
        or len(identifiers) != identity["hashboard_count"]
    ):
        raise DiscoveryError(
            "identity.hashboard_identifiers must match identity.hashboard_count"
        )
    normalized = [
        _observed_text(item, "hashboard identifier", 128) for item in identifiers
    ]
    if len(normalized) != len(set(normalized)):
        raise DiscoveryError("identity.hashboard_identifiers must be unique")


def _validate_evidence_metadata(evidence: Any) -> list[dict[str, Any]]:
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        raise DiscoveryError(f"evidence must contain 1..{MAX_EVIDENCE_ITEMS} records")
    seen_ids: set[str] = set()
    seen_kinds: set[str] = set()
    seen_paths: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(evidence):
        context = f"evidence[{index}]"
        if not isinstance(item, dict):
            raise DiscoveryError(f"{context} must be an object")
        allowed = (
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
        expected = (
            allowed
            if "sha256" in item or "bytes" in item
            else tuple(key for key in allowed if key not in ("bytes", "sha256"))
        )
        _require_exact_keys(item, expected, context)
        evidence_id = _identifier(item["id"], f"{context}.id")
        kind = item["kind"]
        if kind not in EVIDENCE_KINDS:
            raise DiscoveryError(f"{context}.kind is unsupported")
        method = item["method"]
        if method not in EVIDENCE_METHODS:
            raise DiscoveryError(f"{context}.method is unsupported")
        if kind in PHOTO_KINDS and method != "visual_inspection":
            raise DiscoveryError(f"{context} photo must use visual_inspection")
        if kind in STOCK_RESPONSE_KINDS and method != "stock_read_only_management":
            raise DiscoveryError(
                f"{context} stock response must use stock_read_only_management"
            )
        if (
            kind in {"collection_log", "hashboard_topology_record"}
            and method != "offline_record"
        ):
            raise DiscoveryError(f"{context} record must use offline_record")
        media_type = item["media_type"]
        if media_type not in MEDIA_TYPES:
            raise DiscoveryError(f"{context}.media_type is unsupported")
        if kind in PHOTO_KINDS and media_type != "image/png":
            raise DiscoveryError(f"{context} photo must use canonical image/png")
        if kind not in PHOTO_KINDS and media_type not in {
            "application/json",
            "text/plain",
        }:
            raise DiscoveryError(f"{context} record media type is invalid")
        if item["redaction"] not in REDACTION_STATES:
            raise DiscoveryError(f"{context}.redaction is unsupported")
        path = str(_safe_evidence_path(item["path"], f"{context}.path"))
        _utc(item["acquired_at_utc"], f"{context}.acquired_at_utc")
        if evidence_id in seen_ids or kind in seen_kinds or path in seen_paths:
            raise DiscoveryError("evidence IDs, kinds, and paths must each be unique")
        seen_ids.add(evidence_id)
        seen_kinds.add(kind)
        seen_paths.add(path)
        if "bytes" in item:
            byte_count = item["bytes"]
            if (
                isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or not 1 <= byte_count <= MAX_EVIDENCE_FILE_BYTES
            ):
                raise DiscoveryError(f"{context}.bytes is outside the admitted range")
            if not isinstance(item["sha256"], str) or not HEX64_RE.fullmatch(
                item["sha256"]
            ):
                raise DiscoveryError(f"{context}.sha256 is not canonical")
        normalized.append(dict(item))
    missing = sorted(set(REQUIRED_EVIDENCE_KINDS) - seen_kinds)
    if missing:
        raise DiscoveryError(f"discovery evidence is missing {', '.join(missing)}")
    return normalized


def _decode_evidence_json(raw: bytes, kind: str) -> dict[str, Any]:
    if len(raw) > MAX_JSON_BYTES:
        raise DiscoveryError(f"{kind} JSON exceeds {MAX_JSON_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError(f"{kind} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DiscoveryError(f"{kind} JSON root must be an object")
    return value


def _case_key(mapping: Mapping[str, Any], wanted: str, context: str) -> str | None:
    matches = [key for key in mapping if key.casefold() == wanted.casefold()]
    if len(matches) > 1:
        raise DiscoveryError(f"{context} has ambiguous case variants for {wanted}")
    return matches[0] if matches else None


def _required_case_value(
    mapping: Mapping[str, Any], wanted: str, context: str
) -> Any:
    key = _case_key(mapping, wanted, context)
    if key is None:
        raise DiscoveryError(f"{context} is missing {wanted}")
    return mapping[key]


def _require_success_status(document: Mapping[str, Any], kind: str) -> None:
    status = _required_case_value(document, "STATUS", kind)
    if not isinstance(status, list) or not status or not isinstance(status[0], dict):
        raise DiscoveryError(f"{kind}.STATUS must contain an object")
    value = _required_case_value(status[0], "Status", f"{kind}.STATUS[0]")
    if value != "S":
        raise DiscoveryError(f"{kind}.STATUS[0].Status is not success")


def _normalized_model_label(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def _validate_product_labels(
    version: Mapping[str, Any], target_id: str, marketing_model: str
) -> list[str]:
    labels: list[str] = []
    for field in ("PROD", "MODEL"):
        key = _case_key(version, field, "stock_version_response.VERSION[0]")
        if key is not None:
            labels.append(_observed_text(version[key], f"stock version {field}", 128))
    if not labels:
        raise DiscoveryError("stock version has neither PROD nor MODEL identity")
    target_token = target_id.upper()
    allowed = {
        _normalized_model_label(marketing_model),
        target_token,
        f"AVALONMINER{target_token}",
        f"AVALONMINER{target_token.removeprefix('A')}",
    }
    for label in labels:
        if _normalized_model_label(label) not in allowed:
            raise DiscoveryError(
                "stock version product/model contradicts the selected manifest target"
            )
    return labels


def _parse_stock_version(
    document: Mapping[str, Any], target_id: str, marketing_model: str
) -> dict[str, str]:
    _require_success_status(document, "stock_version_response")
    entries = _required_case_value(document, "VERSION", "stock_version_response")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise DiscoveryError("stock_version_response.VERSION must contain one object")
    version = entries[0]
    firmware_key = _case_key(
        version, "VERSION", "stock_version_response.VERSION[0]"
    )
    typo_key = _case_key(version, "VERION", "stock_version_response.VERSION[0]")
    if firmware_key is not None and typo_key is not None:
        raise DiscoveryError("stock version has contradictory VERSION and VERION fields")
    selected_key = firmware_key or typo_key
    if selected_key is None:
        raise DiscoveryError("stock version has neither VERSION nor legacy VERION")
    firmware = _observed_text(version[selected_key], "stock firmware version", 128)
    hwtype = _observed_text(
        _required_case_value(version, "HWTYPE", "stock_version_response.VERSION[0]"),
        "stock HWTYPE",
        128,
    )
    swtype = _observed_text(
        _required_case_value(version, "SWTYPE", "stock_version_response.VERSION[0]"),
        "stock SWTYPE",
        128,
    )
    dna = _observed_text(
        _required_case_value(version, "DNA", "stock_version_response.VERSION[0]"),
        "stock DNA",
        128,
    )
    mac = _observed_text(
        _required_case_value(version, "MAC", "stock_version_response.VERSION[0]"),
        "stock MAC",
        32,
    )
    if not re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", mac):
        raise DiscoveryError("stock version MAC is not canonical")
    upapi = _required_case_value(version, "UPAPI", "stock_version_response.VERSION[0]")
    if isinstance(upapi, bool) or not isinstance(upapi, int) or not 0 <= upapi <= 255:
        raise DiscoveryError("stock version UPAPI must be an integer in 0..255")
    _validate_product_labels(version, target_id, marketing_model)
    return {
        "firmware_version": firmware,
        "hwtype": hwtype,
        "swtype": swtype,
        "dna": dna,
    }


def _module_count_value(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise DiscoveryError(f"{context} is not an integer module count")
    if isinstance(value, int):
        count = value
    elif isinstance(value, str) and value.isdigit():
        count = int(value)
    else:
        raise DiscoveryError(f"{context} is not an integer module count")
    if not 1 <= count <= 8:
        raise DiscoveryError(f"{context} is outside 1..8")
    return count


def _parse_stock_stats(document: Mapping[str, Any]) -> int:
    _require_success_status(document, "stock_stats_response")
    stats = _required_case_value(document, "STATS", "stock_stats_response")
    if not isinstance(stats, list) or not stats:
        raise DiscoveryError("stock_stats_response.STATS must be a non-empty array")
    mm_counts: set[int] = set()
    key_indices: set[int] = set()
    scalar_id_values: set[int] = set()
    for index, entry in enumerate(stats):
        if not isinstance(entry, dict):
            raise DiscoveryError(f"stock_stats_response.STATS[{index}] is not an object")
        count_key = _case_key(entry, "MM Count", f"stock STATS[{index}]")
        if count_key is not None:
            mm_counts.add(
                _module_count_value(entry[count_key], f"stock STATS[{index}].MM Count")
            )
        for key, value in entry.items():
            match = MM_ID_RE.fullmatch(key)
            if match is None:
                continue
            key_indices.add(int(match.group(1)))
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 7:
                scalar_id_values.add(value)
            elif isinstance(value, str) and value.isdigit() and 0 <= int(value) <= 7:
                scalar_id_values.add(int(value))
    if len(mm_counts) > 1:
        raise DiscoveryError("stock stats contains contradictory MM Count values")
    explicit_counts = set(mm_counts)
    if len(key_indices) > 1:
        explicit_counts.add(len(key_indices))
    if len(scalar_id_values) > 1:
        explicit_counts.add(len(scalar_id_values))
    if not explicit_counts:
        raise DiscoveryError(
            "stock stats does not expose an unambiguous MM Count/MM ID topology"
        )
    if len(explicit_counts) != 1:
        raise DiscoveryError("stock stats MM Count/MM ID topology is contradictory")
    return explicit_counts.pop()


def _png_dimensions(raw: bytes, kind: str) -> tuple[int, int]:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise DiscoveryError(f"{kind} is not a PNG despite its media type")
    offset = 8
    dimensions: tuple[int, int] | None = None
    saw_idat = False
    saw_iend = False
    idat_closed = False
    idat_payloads: list[bytes] = []
    channels: int | None = None
    chunk_index = 0
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise DiscoveryError(f"{kind} PNG chunk is truncated")
        size = int.from_bytes(raw[offset : offset + 4], "big")
        chunk_type = raw[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + size
        crc_end = data_end + 4
        if crc_end > len(raw) or not re.fullmatch(rb"[A-Za-z]{4}", chunk_type):
            raise DiscoveryError(f"{kind} PNG chunk structure is invalid")
        expected_crc = int.from_bytes(raw[data_end:crc_end], "big")
        observed_crc = binascii.crc32(chunk_type + raw[data_start:data_end]) & 0xFFFFFFFF
        if observed_crc != expected_crc:
            raise DiscoveryError(f"{kind} PNG chunk CRC is invalid")
        if chunk_index == 0:
            if chunk_type != b"IHDR" or size != 13:
                raise DiscoveryError(f"{kind} PNG does not begin with a valid IHDR")
            dimensions = (
                int.from_bytes(raw[data_start : data_start + 4], "big"),
                int.from_bytes(raw[data_start + 4 : data_start + 8], "big"),
            )
            bit_depth = raw[data_start + 8]
            color_type = raw[data_start + 9]
            compression = raw[data_start + 10]
            filter_method = raw[data_start + 11]
            interlace = raw[data_start + 12]
            if (
                bit_depth != 8
                or color_type not in {2, 6}
                or compression != 0
                or filter_method != 0
                or interlace != 0
            ):
                raise DiscoveryError(
                    f"{kind} PNG must be non-interlaced 8-bit RGB or RGBA"
                )
            channels = 3 if color_type == 2 else 4
        elif chunk_type == b"IHDR":
            raise DiscoveryError(f"{kind} PNG repeats IHDR")
        if chunk_type == b"IDAT":
            if idat_closed:
                raise DiscoveryError(f"{kind} PNG has non-contiguous IDAT chunks")
            saw_idat = True
            idat_payloads.append(raw[data_start:data_end])
        elif saw_idat and chunk_type != b"IEND":
            idat_closed = True
        if chunk_type[0] & 0x20 == 0 and chunk_type not in {
            b"IHDR",
            b"PLTE",
            b"IDAT",
            b"IEND",
        }:
            raise DiscoveryError(f"{kind} PNG has an unsupported critical chunk")
        if chunk_type == b"IEND":
            if size != 0 or crc_end != len(raw):
                raise DiscoveryError(f"{kind} PNG IEND/trailing bytes are invalid")
            saw_iend = True
            offset = crc_end
            break
        offset = crc_end
        chunk_index += 1
    if (
        dimensions is None
        or channels is None
        or not saw_idat
        or not saw_iend
        or offset != len(raw)
    ):
        raise DiscoveryError(f"{kind} PNG is incomplete")
    width, height = dimensions
    if (
        width <= 0
        or height <= 0
        or width > MAX_PHOTO_DIMENSION
        or height > MAX_PHOTO_DIMENSION
        or width * height > MAX_PHOTO_PIXELS
    ):
        raise DiscoveryError(f"{kind} PNG dimensions exceed the decoder limits")
    decoded_size = (1 + width * channels) * height
    if decoded_size > MAX_PNG_DECODED_BYTES:
        raise DiscoveryError(f"{kind} PNG decoded size exceeds the decoder limit")
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(b"".join(idat_payloads), decoded_size + 1)
    except zlib.error as exc:
        raise DiscoveryError(f"{kind} PNG IDAT stream is corrupt: {exc}") from exc
    if (
        len(decoded) != decoded_size
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
    ):
        raise DiscoveryError(f"{kind} PNG IDAT stream does not decode exactly")
    row_bytes = 1 + width * channels
    if any(decoded[offset] > 4 for offset in range(0, decoded_size, row_bytes)):
        raise DiscoveryError(f"{kind} PNG has an invalid scanline filter")
    return dimensions


def _inspect_photo(raw: bytes, kind: str, media_type: str) -> dict[str, int]:
    if len(raw) < MIN_PHOTO_BYTES:
        raise DiscoveryError(f"{kind} is too small to be genuine image evidence")
    if media_type == "image/png":
        width, height = _png_dimensions(raw, kind)
    else:
        raise DiscoveryError(f"{kind} photo must use canonical image/png")
    if width < MIN_PHOTO_DIMENSION or height < MIN_PHOTO_DIMENSION:
        raise DiscoveryError(
            f"{kind} dimensions are too small for identity evidence: {width}x{height}"
        )
    return {"height": height, "width": width}


def _inspect_evidence_bytes(item: Mapping[str, Any], raw: bytes) -> Any:
    kind = str(item["kind"])
    media_type = str(item["media_type"])
    if kind in PHOTO_KINDS:
        return _inspect_photo(raw, kind, media_type)
    if media_type != "application/json":
        raise DiscoveryError(f"{kind} must be application/json for semantic admission")
    return _decode_evidence_json(raw, kind)


def _validate_collection_log(
    document: Mapping[str, Any], capture: Mapping[str, Any]
) -> None:
    compact_keys = {
        "anomalies",
        "authorization_reference",
        "events",
        "operator",
        "session",
        "stopped_reason",
    }
    collector_keys = compact_keys | {
        "authority",
        "command_results",
        "commands",
        "credential_hygiene",
        "host",
        "mm3_framing",
        "notes",
        "port",
        "session_closed_at_utc",
        "session_started_at_utc",
        "tool",
    }
    actual_keys = set(document)
    if actual_keys not in (compact_keys, collector_keys):
        expected = collector_keys if "tool" in document else compact_keys
        _require_exact_keys(document, sorted(expected), "collection_log")
    _observed_text(document["session"], "collection_log.session", 200)
    _observed_text(document["operator"], "collection_log.operator", 128)
    reference = _observed_text(
        document["authorization_reference"],
        "collection_log.authorization_reference",
        160,
    )
    if reference != capture["authorization"]["operator_reference"]:
        raise DiscoveryError("collection_log authorization reference contradicts capture")
    events = document["events"]
    if not isinstance(events, list) or not events:
        raise DiscoveryError("collection_log.events must be a non-empty array")
    valid_from = _utc(capture["authorization"]["valid_from_utc"], "valid_from_utc")
    observed = _utc(capture["observed_at_utc"], "observed_at_utc")
    event_texts: list[str] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise DiscoveryError(f"collection_log.events[{index}] must be an object")
        _require_exact_keys(
            event, ("event", "time_utc"), f"collection_log.events[{index}]"
        )
        timestamp = _utc(event["time_utc"], f"collection_log.events[{index}].time_utc")
        if not valid_from <= timestamp <= observed:
            raise DiscoveryError(f"collection_log.events[{index}] is outside chronology")
        event_texts.append(
            _observed_text(
                event["event"], f"collection_log.events[{index}].event", 512
            )
        )
    missing_actions = sorted(
        action
        for action in AUTHORIZED_ACTIONS
        if not any(action in event for event in event_texts)
    )
    if missing_actions:
        raise DiscoveryError(
            "collection_log does not bind completed phase actions: "
            + ", ".join(missing_actions)
        )
    if document["stopped_reason"] not in (None, ""):
        raise DiscoveryError("collection_log records a stopped discovery session")
    anomalies = document["anomalies"]
    if not isinstance(anomalies, list):
        raise DiscoveryError("collection_log.anomalies must be an array")
    for index, item in enumerate(anomalies):
        if not isinstance(item, dict):
            raise DiscoveryError(
                f"collection_log.anomalies[{index}] must be an object"
            )
        _require_exact_keys(
            item,
            ("code", "command", "detail", "severity"),
            f"collection_log.anomalies[{index}]",
        )
        if item["severity"] not in {"note", "fault"}:
            raise DiscoveryError(
                f"collection_log.anomalies[{index}].severity is invalid"
            )
        for field in ("code", "command", "detail"):
            _observed_text(
                item[field], f"collection_log.anomalies[{index}].{field}", 512
            )
        if item["severity"] == "fault":
            raise DiscoveryError("collection_log contains a collector validation fault")
    if actual_keys == collector_keys:
        tool = document["tool"]
        if not isinstance(tool, dict):
            raise DiscoveryError("collection_log.tool must be an object")
        _require_exact_keys(
            tool,
            ("name", "read_only_allowlist", "runbook", "version"),
            "collection_log.tool",
        )
        if tool["name"] != "k210_discovery_collect" or tool["version"] != "1":
            raise DiscoveryError("collection_log collector identity is unsupported")
        allowlist = tool["read_only_allowlist"]
        if (
            not isinstance(allowlist, list)
            or len(allowlist) != 5
            or set(allowlist)
            != {"estats", "pools", "stats", "summary", "version"}
        ):
            raise DiscoveryError("collection_log collector allowlist is invalid")
        commands = document["commands"]
        if (
            not isinstance(commands, list)
            or len(commands) != len(set(commands))
            or not {"stats", "version"}.issubset(commands)
            or any(command not in allowlist for command in commands)
        ):
            raise DiscoveryError("collection_log commands are not an admitted pass")
        results = document["command_results"]
        if (
            not isinstance(results, list)
            or not results
            or len(results) != len(commands)
            or {result.get("command") for result in results if isinstance(result, dict)}
            != set(commands)
            or any(
                not isinstance(result, dict) or result.get("status") != "captured"
                for result in results
            )
        ):
            raise DiscoveryError("collection_log command results are incomplete")
        hygiene = document["credential_hygiene"]
        if not isinstance(hygiene, dict):
            raise DiscoveryError("collection_log credential_hygiene must be an object")
        _require_exact_keys(
            hygiene, ("detail", "log_records_credentials"), "credential_hygiene"
        )
        if hygiene["log_records_credentials"] is not False:
            raise DiscoveryError("collection_log records credentials")


def _validate_topology_record(
    document: Mapping[str, Any], identity: Mapping[str, Any]
) -> None:
    forbidden = {
        "asic_family",
        "profile_id",
        "stock_profile",
        "stock_profile_id",
        "variant",
        "variant_id",
    }
    if forbidden & {key.casefold() for key in document}:
        raise DiscoveryError(
            "hashboard_topology_record cannot supply or force an ASIC/profile label"
        )
    if "hashboard_count" not in document or "hashboard_identifiers" not in document:
        raise DiscoveryError(
            "hashboard_topology_record must contain hashboard_count and identifiers"
        )
    if document["hashboard_count"] != identity["hashboard_count"]:
        raise DiscoveryError("hashboard_topology_record count contradicts identity")
    identifiers = document["hashboard_identifiers"]
    if not isinstance(identifiers, list):
        raise DiscoveryError("hashboard_topology_record identifiers must be an array")
    normalized = [
        _observed_text(value, "hashboard_topology_record identifier", 128)
        for value in identifiers
    ]
    if len(normalized) != len(set(normalized)):
        raise DiscoveryError("hashboard_topology_record identifiers are not unique")
    if set(normalized) != set(identity["hashboard_identifiers"]):
        raise DiscoveryError("hashboard_topology_record identifiers contradict identity")


def _resolve_a1246_variant(
    manifest: Mapping[str, Any], capture: Mapping[str, Any], evidence: Mapping[str, Any]
) -> dict[str, Any] | None:
    target_id = str(capture["target_id"])
    rows = _target_variant_rows(manifest, target_id)
    if not rows:
        return None
    identity = capture["identity"]
    version = _parse_stock_version(
        evidence["stock_version_response"], target_id, str(identity["marketing_model"])
    )
    identity_fields = {
        "firmware_version": "stock_firmware_version",
        "hwtype": "stock_hwtype",
        "swtype": "stock_swtype",
        "dna": "stock_dna",
    }
    for observed_field, identity_field in identity_fields.items():
        if version[observed_field] != identity[identity_field]:
            raise DiscoveryError(
                f"stock_version_response {observed_field} contradicts identity.{identity_field}"
            )
    matches = [
        row
        for row in rows
        if row["firmware_version"] == version["firmware_version"]
        and row["hwtype"] == version["hwtype"]
        and version["swtype"] in row["sw_list"]
    ]
    if not matches:
        raise DiscoveryError(
            "observed stock tuple does not match an admitted held A1246 profile; "
            "generic or topology-forced A1246 mapping is forbidden"
        )
    if len(matches) != 1:
        raise DiscoveryError("observed stock tuple maps ambiguously to A1246 profiles")
    variant = matches[0]
    if identity["asic_family"] != variant["asic_family"]:
        raise DiscoveryError("identity.asic_family contradicts the resolved stock profile")
    if identity["hashboard_count"] != variant["hashboard_count"]:
        raise DiscoveryError("identity.hashboard_count contradicts the resolved stock profile")
    if identity["cooling_class"] != "air":
        raise DiscoveryError("held A1246 profiles require observed air cooling")
    stats_count = _parse_stock_stats(evidence["stock_stats_response"])
    if stats_count != variant["hashboard_count"]:
        raise DiscoveryError("stock stats topology contradicts the resolved A1246 profile")
    _validate_topology_record(evidence["hashboard_topology_record"], identity)
    _validate_collection_log(evidence["collection_log"], capture)
    return variant


def _validate_evidence_semantics(
    manifest: Mapping[str, Any], capture: Mapping[str, Any], evidence: Mapping[str, Any]
) -> dict[str, Any] | None:
    missing = sorted(set(REQUIRED_EVIDENCE_KINDS) - set(evidence))
    if missing:
        raise DiscoveryError(f"semantic evidence is missing {', '.join(missing)}")
    return _resolve_a1246_variant(manifest, capture, evidence)


def _validate_capture(capture: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _require_exact_keys(
        capture,
        (
            "actions_performed",
            "authorization",
            "capture_session_id",
            "evidence",
            "identity",
            "kind",
            "observed_at_utc",
            "observer_id",
            "schema_version",
            "scope",
            "target_id",
            "unit_label",
        ),
        "capture",
    )
    if capture["schema_version"] != SCHEMA_VERSION:
        raise DiscoveryError("unsupported discovery capture schema")
    if capture["kind"] != CAPTURE_KIND or capture["scope"] != SCOPE:
        raise DiscoveryError("discovery capture kind or scope mismatch")
    target_id = _identifier(capture["target_id"], "target_id")
    target = _target(manifest, target_id)
    _observed_text(_identifier(capture["unit_label"], "unit_label"), "unit_label", 64)
    _uuid4(capture["capture_session_id"])
    _observed_text(_observer(capture["observer_id"]), "observer_id", 64)
    observed = _utc(capture["observed_at_utc"], "observed_at_utc")
    authorization = capture["authorization"]
    if not isinstance(authorization, dict):
        raise DiscoveryError("authorization must be an object")
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
    _observed_text(
        authorization["operator_reference"],
        "authorization.operator_reference",
        160,
    )
    valid_from = _utc(authorization["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(
        authorization["valid_until_utc"], "authorization.valid_until_utc"
    )
    if valid_from >= valid_until or not valid_from <= observed <= valid_until:
        raise DiscoveryError(
            "observation is outside the recorded authorization interval"
        )
    actions = authorization["authorized_actions"]
    if (
        not isinstance(actions, list)
        or set(actions) != AUTHORIZED_ACTIONS
        or len(actions) != len(AUTHORIZED_ACTIONS)
    ):
        raise DiscoveryError(
            "authorization.authorized_actions must contain only the four exact discovery phase actions"
        )
    if capture["actions_performed"] != ACTIONS_PERFORMED:
        raise DiscoveryError(
            "actions_performed must truthfully record the stock power transition and no mutations"
        )
    _validate_identity(capture["identity"], target, manifest)
    evidence = _validate_evidence_metadata(capture["evidence"])
    for index, item in enumerate(evidence):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if not valid_from <= acquired <= observed:
            raise DiscoveryError(
                f"evidence[{index}] is outside authorization/observation chronology"
            )


def _capture_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "actions_performed": receipt["actions_performed"],
        "authorization": receipt["authorization"],
        "capture_session_id": receipt["capture_session_id"],
        "evidence": [
            {
                key: value
                for key, value in item.items()
                if key not in ("bytes", "sha256")
            }
            for item in receipt["evidence"]
        ],
        "identity": receipt["identity"],
        "kind": CAPTURE_KIND,
        "observed_at_utc": receipt["observed_at_utc"],
        "observer_id": receipt["observer_id"],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "target_id": receipt["target_id"],
        "unit_label": receipt["unit_label"],
    }


def _receipt_without_id(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "receipt_id"}


def _validate_receipt(receipt: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    _require_exact_keys(
        receipt,
        (
            "actions_performed",
            "authority_ceiling",
            "authorization",
            "capture_descriptor_sha256",
            "capture_session_id",
            "disposition",
            "evidence",
            "identity",
            "kind",
            "observed_at_utc",
            "observer_id",
            "receipt_id",
            "schema_version",
            "scope",
            "signing",
            "target_id",
            "unit_fingerprint_sha256",
            "unit_label",
        ),
        "receipt",
    )
    if receipt["schema_version"] != SCHEMA_VERSION:
        raise DiscoveryError("unsupported discovery receipt schema")
    if receipt["kind"] != RECEIPT_KIND or receipt["scope"] != SCOPE:
        raise DiscoveryError("discovery receipt kind or scope mismatch")
    if receipt["disposition"] != DISPOSITION:
        raise DiscoveryError("discovery receipt disposition drifted")
    if receipt["authority_ceiling"] != AUTHORITY_CEILING:
        raise DiscoveryError("discovery receipt gained or obscured authority")
    signing = receipt["signing"]
    if not isinstance(signing, dict):
        raise DiscoveryError("receipt.signing must be an object")
    _require_exact_keys(
        signing, ("algorithm", "key_id_sha256", "namespace", "role"), "receipt.signing"
    )
    if signing["algorithm"] != SIGNATURE_ALGORITHM:
        raise DiscoveryError("receipt signature algorithm drifted")
    if signing["namespace"] != SIGNATURE_NAMESPACE or signing["role"] != SIGNER_ROLE:
        raise DiscoveryError("receipt signature namespace or role drifted")
    for field in (
        "key_id_sha256",
        "capture_descriptor_sha256",
        "receipt_id",
        "unit_fingerprint_sha256",
    ):
        if not isinstance(
            receipt.get(field) if field != "key_id_sha256" else signing[field], str
        ):
            raise DiscoveryError(f"receipt {field} is not a string")
        value = signing[field] if field == "key_id_sha256" else receipt[field]
        if not HEX64_RE.fullmatch(value):
            raise DiscoveryError(f"receipt {field} is not canonical SHA-256")
    capture = _capture_projection(receipt)
    _validate_capture(capture, manifest)
    if (
        _sha256_bytes(canonical_json_bytes(capture))
        != receipt["capture_descriptor_sha256"]
    ):
        raise DiscoveryError("capture descriptor SHA-256 mismatch")
    identity_digest = _sha256_bytes(
        b"DCENT-K210-UNIT-IDENTITY-V1\x00" + canonical_json_bytes(receipt["identity"])
    )
    if identity_digest != receipt["unit_fingerprint_sha256"]:
        raise DiscoveryError("unit fingerprint SHA-256 mismatch")
    receipt_id = _sha256_bytes(
        b"DCENT-K210-DISCOVERY-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(_receipt_without_id(receipt))
    )
    if receipt_id != receipt["receipt_id"]:
        raise DiscoveryError("receipt ID mismatch")


def _ssh_string(raw: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(raw):
        raise DiscoveryError("OpenSSH public key blob is truncated")
    size = int.from_bytes(raw[offset : offset + 4], "big")
    start = offset + 4
    end = start + size
    if end > len(raw):
        raise DiscoveryError("OpenSSH public key blob field is truncated")
    return raw[start:end], end


def parse_ed25519_public_key(raw: bytes) -> tuple[str, str]:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise DiscoveryError("observer public key is not ASCII") from exc
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1:
        raise DiscoveryError("observer public key must contain exactly one key")
    fields = lines[0].split()
    if len(fields) not in (2, 3) or fields[0] != "ssh-ed25519":
        raise DiscoveryError("observer public key must be one ssh-ed25519 key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DiscoveryError("observer public key base64 is invalid") from exc
    algorithm, offset = _ssh_string(blob, 0)
    key, offset = _ssh_string(blob, offset)
    if algorithm != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        raise DiscoveryError("observer public key blob is not canonical Ed25519")
    canonical_line = f"ssh-ed25519 {fields[1]}"
    return canonical_line, _sha256_bytes(blob)


def inspect_public_key(path: Path) -> dict[str, str]:
    raw = _read_regular(path, "observer public key", 4096)
    canonical_line, key_id = parse_ed25519_public_key(raw)
    return {"canonical_line": canonical_line, "key_id_sha256": key_id}


def _run_ssh_keygen(
    arguments: Sequence[str], *, stdin: bytes | None = None, timeout: int = 20
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.run(
            ["ssh-keygen", *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise DiscoveryError(
            "OpenSSH ssh-keygen is required for discovery signatures"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError("ssh-keygen exceeded the bounded timeout") from exc
    return process


@contextlib.contextmanager
def _usable_private_key(private_key: Path):
    """Yield an ACL-safe key path and reject concurrent key replacement."""

    private_raw = _read_regular(private_key, "observer private key", 64 * 1024)
    if os.name != "posix":
        yield private_key
        if _read_regular(private_key, "observer private key", 64 * 1024) != private_raw:
            raise DiscoveryError("observer private key changed during signing")
        return
    with tempfile.TemporaryDirectory(prefix="dcent-k210-observer-key-") as directory:
        snapshot = Path(directory) / "observer"
        snapshot.write_bytes(private_raw)
        snapshot.chmod(0o600)
        yield snapshot


def _private_key_public_line(private_key: Path) -> tuple[str, str]:
    with _usable_private_key(private_key) as usable_key:
        process = _run_ssh_keygen(("-y", "-f", str(usable_key)))
    if process.returncode != 0:
        raise DiscoveryError(
            "observer private key is not an unlocked OpenSSH Ed25519 key"
        )
    return parse_ed25519_public_key(process.stdout)


def inspect_private_key(private_key: Path) -> dict[str, str]:
    """Return the canonical public identity of an unlocked Ed25519 private key."""

    canonical_line, key_id = _private_key_public_line(private_key)
    return {"canonical_line": canonical_line, "key_id_sha256": key_id}


def sign_sshsig_file(content_path: Path, private_key: Path, namespace: str) -> bytes:
    """Sign one bounded regular file under an explicit SSHSIG namespace."""

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", namespace):
        raise DiscoveryError("SSHSIG namespace is not canonical")
    with tempfile.TemporaryDirectory(prefix="dcent-k210-sign-") as directory:
        root = Path(directory)
        content = root / RECEIPT_NAME
        content.write_bytes(
            _read_regular(content_path, "canonical signed content", MAX_JSON_BYTES)
        )
        with _usable_private_key(private_key) as usable_key:
            process = _run_ssh_keygen(
                (
                    "-Y",
                    "sign",
                    "-f",
                    str(usable_key),
                    "-n",
                    namespace,
                    str(content),
                )
            )
        signature_path = Path(f"{content}.sig")
        if process.returncode != 0 or not signature_path.is_file():
            raise DiscoveryError("OpenSSH failed to sign the discovery receipt")
        signature = _read_regular(signature_path, "discovery signature", 4096)
    if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
        raise DiscoveryError("OpenSSH produced an unexpected discovery signature")
    return signature


def verify_sshsig_bytes(
    content_raw: bytes,
    signature_path: Path,
    public_key_line: str,
    principal: str,
    namespace: str,
) -> None:
    """Verify one SSHSIG signature against an exact principal and namespace."""

    _observer(principal)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", namespace):
        raise DiscoveryError("SSHSIG namespace is not canonical")
    signature = _read_regular(signature_path, "discovery signature", 4096)
    if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
        raise DiscoveryError("discovery signature is not canonical SSHSIG armor")
    with tempfile.TemporaryDirectory(prefix="dcent-k210-verify-") as directory:
        root = Path(directory)
        allowed = root / "allowed_signers"
        signature_snapshot = root / SIGNATURE_NAME
        allowed.write_text(
            f'{principal} namespaces="{namespace}" {public_key_line}\n',
            encoding="ascii",
        )
        signature_snapshot.write_bytes(signature)
        process = _run_ssh_keygen(
            (
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                principal,
                "-n",
                namespace,
                "-s",
                str(signature_snapshot),
            ),
            stdin=content_raw,
        )
    if process.returncode != 0:
        raise DiscoveryError("discovery SSHSIG/Ed25519 verification failed")


def _sign_receipt(receipt_path: Path, private_key: Path) -> bytes:
    return sign_sshsig_file(receipt_path, private_key, SIGNATURE_NAMESPACE)


def _verify_signature(
    receipt_raw: bytes,
    signature_path: Path,
    public_key_line: str,
    observer_id: str,
) -> None:
    verify_sshsig_bytes(
        receipt_raw,
        signature_path,
        public_key_line,
        observer_id,
        SIGNATURE_NAMESPACE,
    )


def _evidence_source(root: Path, path: PurePosixPath) -> Path:
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise DiscoveryError(f"evidence root cannot be inspected: {exc}") from exc
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise DiscoveryError("evidence root must be a non-symlink directory")
    current = root
    for index, part in enumerate(path.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise DiscoveryError(
                f"evidence path cannot be inspected: {path}: {exc}"
            ) from exc
        if _is_link_or_reparse(metadata):
            raise DiscoveryError(f"evidence path contains a link: {path}")
        final = index == len(path.parts) - 1
        expected_type = stat.S_ISREG if final else stat.S_ISDIR
        if not expected_type(metadata.st_mode):
            raise DiscoveryError(f"evidence path has an invalid type: {path}")
    return current


def _hash_evidence(path: Path, label: str) -> tuple[int, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be inspected: {exc}") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise DiscoveryError(f"{label} must be a regular non-symlink file")
    if not 1 <= metadata.st_size <= MAX_EVIDENCE_FILE_BYTES:
        raise DiscoveryError(f"{label} size is outside the admitted range")
    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if _file_identity(opened) != _file_identity(metadata):
                raise DiscoveryError(f"{label} changed before it was opened")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                observed += len(chunk)
                if observed > MAX_EVIDENCE_FILE_BYTES:
                    raise DiscoveryError(f"{label} grew beyond the admitted range")
                digest.update(chunk)
            final = os.fstat(stream.fileno())
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be read: {exc}") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise DiscoveryError(f"{label} cannot be reinspected: {exc}") from exc
    if (
        observed != metadata.st_size
        or _file_identity(metadata) != _file_identity(final)
        or _file_identity(final) != _file_identity(after)
    ):
        raise DiscoveryError(f"{label} changed while being hashed")
    return observed, digest.hexdigest()


def _read_and_inspect_evidence(
    path: Path, item: Mapping[str, Any], label: str
) -> tuple[int, str, Any]:
    raw = _read_regular(path, label, MAX_SEMANTIC_EVIDENCE_FILE_BYTES)
    if not raw:
        raise DiscoveryError(f"{label} size is outside the admitted range")
    return len(raw), _sha256_bytes(raw), _inspect_evidence_bytes(item, raw)


def build_receipt(
    manifest: Mapping[str, Any],
    capture: Mapping[str, Any],
    evidence_root: Path,
    private_key: Path,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_capture(capture, manifest)
    _, key_id = _private_key_public_line(private_key)
    evidence_with_hashes: list[dict[str, Any]] = []
    sources: dict[str, Path] = {}
    semantic_evidence: dict[str, Any] = {}
    total = 0
    for item in sorted(capture["evidence"], key=lambda value: value["id"]):
        relative = _safe_evidence_path(item["path"], f"evidence {item['id']} path")
        source = _evidence_source(evidence_root, relative)
        byte_count, digest, inspected = _read_and_inspect_evidence(
            source, item, f"evidence {item['id']}"
        )
        total += byte_count
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise DiscoveryError("discovery evidence exceeds the aggregate byte limit")
        enriched = dict(item)
        enriched["bytes"] = byte_count
        enriched["sha256"] = digest
        evidence_with_hashes.append(enriched)
        sources[item["id"]] = source
        semantic_evidence[item["kind"]] = inspected
    _validate_evidence_semantics(manifest, capture, semantic_evidence)
    normalized_capture = dict(capture)
    normalized_capture["authorization"] = dict(capture["authorization"])
    normalized_capture["authorization"]["authorized_actions"] = sorted(
        AUTHORIZED_ACTIONS
    )
    normalized_capture["evidence"] = [
        {key: value for key, value in item.items() if key not in ("bytes", "sha256")}
        for item in evidence_with_hashes
    ]
    normalized_capture["identity"] = dict(capture["identity"])
    normalized_capture["identity"]["hashboard_identifiers"] = sorted(
        capture["identity"]["hashboard_identifiers"]
    )
    _validate_capture(normalized_capture, manifest)
    receipt: dict[str, Any] = {
        **normalized_capture,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "capture_descriptor_sha256": _sha256_bytes(
            canonical_json_bytes(normalized_capture)
        ),
        "disposition": DISPOSITION,
        "evidence": evidence_with_hashes,
        "kind": RECEIPT_KIND,
        "signing": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id_sha256": key_id,
            "namespace": SIGNATURE_NAMESPACE,
            "role": SIGNER_ROLE,
        },
        "unit_fingerprint_sha256": _sha256_bytes(
            b"DCENT-K210-UNIT-IDENTITY-V1\x00"
            + canonical_json_bytes(normalized_capture["identity"])
        ),
    }
    receipt["receipt_id"] = _sha256_bytes(
        b"DCENT-K210-DISCOVERY-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(_receipt_without_id(receipt))
    )
    _validate_receipt(receipt, manifest)
    return receipt, sources


def create_bundle(
    manifest: Mapping[str, Any],
    capture_path: Path,
    evidence_root: Path,
    private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise DiscoveryError(f"refusing to overwrite existing bundle: {bundle_out}")
    capture = load_json(capture_path, "discovery capture", require_canonical=False)
    receipt, sources = build_receipt(manifest, capture, evidence_root, private_key)
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        evidence_destination = temporary / EVIDENCE_DIRECTORY
        evidence_destination.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_evidence_path(item["path"], f"evidence {item['id']} path")
            destination = evidence_destination.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_evidence(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise DiscoveryError(f"evidence {item['id']} changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        receipt_path.write_bytes(canonical_json_bytes(receipt))
        signature = _sign_receipt(receipt_path, private_key)
        signature_path = temporary / SIGNATURE_NAME
        signature_path.write_bytes(signature)
        public_line, key_id = _private_key_public_line(private_key)
        if key_id != receipt["signing"]["key_id_sha256"]:
            raise DiscoveryError(
                "observer private key changed between binding and signing"
            )
        _verify_signature(
            receipt_path.read_bytes(),
            signature_path,
            public_line,
            receipt["observer_id"],
        )
        os.replace(temporary, bundle_out.resolve())
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return receipt


def verify_bundle(
    manifest: Mapping[str, Any],
    bundle: Path,
    public_key: Path,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise DiscoveryError(f"discovery bundle cannot be inspected: {exc}") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise DiscoveryError("discovery bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    signature_path = bundle / SIGNATURE_NAME
    receipt = load_json(receipt_path, "discovery receipt", require_canonical=True)
    _validate_receipt(receipt, manifest)
    key = inspect_public_key(public_key)
    if expected_key_id is not None and key["key_id_sha256"] != expected_key_id:
        raise DiscoveryError(
            "observer public key does not match the manifest trust anchor"
        )
    if receipt["signing"]["key_id_sha256"] != key["key_id_sha256"]:
        raise DiscoveryError("receipt signer does not match the trusted observer key")
    receipt_raw = _read_regular(receipt_path, "discovery receipt", MAX_JSON_BYTES)
    if receipt_raw != canonical_json_bytes(receipt):
        raise DiscoveryError("discovery receipt changed after validation")
    _verify_signature(
        receipt_raw, signature_path, key["canonical_line"], receipt["observer_id"]
    )
    total = 0
    semantic_evidence: dict[str, Any] = {}
    for item in receipt["evidence"]:
        relative = _safe_evidence_path(item["path"], f"evidence {item['id']} path")
        evidence_path = _evidence_source(bundle / EVIDENCE_DIRECTORY, relative)
        raw = _read_regular(
            evidence_path, f"evidence {item['id']}", MAX_EVIDENCE_FILE_BYTES
        )
        size, digest = len(raw), _sha256_bytes(raw)
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise DiscoveryError("discovery evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise DiscoveryError(f"evidence {item['id']} digest or size mismatch")
        inspected = _inspect_evidence_bytes(item, raw)
        semantic_evidence[item["kind"]] = inspected
    variant = _validate_evidence_semantics(manifest, receipt, semantic_evidence)
    _verify_exact_bundle_members(bundle, receipt)
    result = {
        "authority_granted": False,
        "evidence_items": len(receipt["evidence"]),
        "evidence_semantics_verified": True,
        "identity_gate_eligible": True,
        "observer_key_id_sha256": key["key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "state": "verified_signed_exact_unit_discovery",
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
    }
    if variant is not None:
        result["variant_asic_family"] = variant["asic_family"]
        result["variant_hashboard_count"] = variant["hashboard_count"]
        result["variant_hwtype"] = variant["hwtype"]
        result["variant_profile_id"] = variant["profile_id"]
    return result


def _verify_exact_bundle_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_files = {RECEIPT_NAME, SIGNATURE_NAME}
    expected_directories = {EVIDENCE_DIRECTORY}
    for item in receipt["evidence"]:
        relative = PurePosixPath(EVIDENCE_DIRECTORY) / _safe_evidence_path(
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
            raise DiscoveryError(
                f"discovery bundle cannot be enumerated: {exc}"
            ) from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                entry_metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise DiscoveryError(
                    f"discovery bundle member cannot be inspected: {relative}: {exc}"
                ) from exc
            if entry.is_symlink() or _is_link_or_reparse(entry_metadata):
                raise DiscoveryError(
                    f"discovery bundle contains a linked member: {relative}"
                )
            if stat.S_ISDIR(entry_metadata.st_mode):
                observed_directories.add(str(relative))
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(entry_metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise DiscoveryError(
                    f"discovery bundle contains a special member: {relative}"
                )
    if observed_files != expected_files or observed_directories != expected_directories:
        unexpected = sorted(
            (observed_files - expected_files)
            | (observed_directories - expected_directories)
        )
        missing = sorted(
            (expected_files - observed_files)
            | (expected_directories - observed_directories)
        )
        detail = []
        if unexpected:
            detail.append(f"unexpected {', '.join(unexpected)}")
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        raise DiscoveryError(
            f"discovery bundle member set is not exact: {'; '.join(detail)}"
        )


def _template(manifest: Mapping[str, Any], target_id: str) -> dict[str, Any]:
    target = _target(manifest, target_id)
    variant_rows = _target_variant_rows(manifest, target_id)
    evidence = []
    for index, kind in enumerate(REQUIRED_EVIDENCE_KINDS, 1):
        if kind in PHOTO_KINDS:
            method = "visual_inspection"
            media_type = "image/png"
            suffix = ".png"
        elif kind in STOCK_RESPONSE_KINDS:
            method = "stock_read_only_management"
            media_type = "application/json"
            suffix = ".json"
        else:
            method = "offline_record"
            media_type = "application/json"
            suffix = ".json"
        evidence.append(
            {
                "acquired_at_utc": "2026-01-01T00:00:00Z",
                "id": f"e{index:02d}-{kind.replace('_', '-')}",
                "kind": kind,
                "media_type": media_type,
                "method": method,
                "path": f"{kind}{suffix}",
                "redaction": "none",
            }
        )
    return {
        "actions_performed": dict(ACTIONS_PERFORMED),
        "authorization": {
            "authorized_actions": sorted(AUTHORIZED_ACTIONS),
            "operator_reference": "REPLACE_WITH_OPERATOR_AUTHORIZATION_REFERENCE",
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2026-01-01T00:30:00Z",
        },
        "capture_session_id": "00000000-0000-4000-8000-000000000000",
        "evidence": evidence,
        "identity": {
            "asic_family": (
                "REPLACE_FROM_RESOLVED_STOCK_PROFILE"
                if variant_rows
                else target["asic_family"]
            ),
            "controller_board_model": "REPLACE",
            "controller_board_revision": "REPLACE",
            "controller_serial": "REPLACE_OR_NOT_PRESENT",
            "controller_soc": "K210",
            "cooling_class": "air",
            "cooling_controller": "REPLACE",
            "fan_or_pump_count": 0,
            "hashboard_count": 0,
            "hashboard_identifiers": [],
            "manufacturer": "Canaan",
            "marketing_model": target["display_name"],
            "miner_serial": "REPLACE",
            "psu_model": "REPLACE",
            "psu_rated_watts": 0,
            "psu_serial": "REPLACE_OR_NOT_PRESENT",
            "stock_dna": "REPLACE",
            "stock_firmware_version": "REPLACE",
            "stock_hwtype": "REPLACE",
            "stock_swtype": "REPLACE",
        },
        "kind": CAPTURE_KIND,
        "observed_at_utc": "2026-01-01T00:10:00Z",
        "observer_id": "REPLACE",
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "target_id": target_id,
        "unit_label": f"{target_id}-unit-replace",
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    return load_json(path, "K210 model manifest", require_canonical=False)


def _write_new(path: Path, raw: bytes, label: str) -> None:
    if path.exists():
        raise DiscoveryError(f"refusing to overwrite existing {label}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    except OSError as exc:
        raise DiscoveryError(f"cannot write {label}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser(
        "template", help="write an editable capture descriptor"
    )
    template.add_argument("--model", required=True)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot evidence and sign a new bundle"
    )
    create.add_argument("--capture", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed discovery bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument(
        "--expected-key-id", help="optional pinned lowercase SHA-256 key ID"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = _load_manifest(args.manifest)
        if args.command == "template":
            _write_new(
                args.out,
                (
                    json.dumps(
                        _template(manifest, args.model), indent=2, sort_keys=True
                    )
                    + "\n"
                ).encode("ascii"),
                "capture template",
            )
            print(f"K210_DISCOVERY_TEMPLATE_WRITTEN model={args.model} path={args.out}")
            return 0
        if args.command == "create":
            receipt = create_bundle(
                manifest,
                args.capture,
                args.evidence_root,
                args.private_key,
                args.bundle_out,
            )
            print(
                "K210_DISCOVERY_BUNDLE_CREATED "
                f"target={receipt['target_id']} receipt_id={receipt['receipt_id']} "
                f"disposition={receipt['disposition']}"
            )
            return 0
        if args.expected_key_id is not None and not HEX64_RE.fullmatch(
            args.expected_key_id
        ):
            raise DiscoveryError("--expected-key-id must be lowercase SHA-256 hex")
        result = verify_bundle(
            manifest, args.bundle, args.public_key, args.expected_key_id
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except DiscoveryError as exc:
        print(f"K210_DISCOVERY_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
