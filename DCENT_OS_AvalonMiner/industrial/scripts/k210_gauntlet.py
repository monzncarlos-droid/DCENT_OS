#!/usr/bin/env python3
"""Evidence-bound production-readiness gauntlet for Avalon K210 targets.

This tool is deliberately host-only. It has no network, serial, USB, GPIO,
flash, programmer, JTAG, ISP, miner-process-control, or miner-contact code.
Optional signed-receipt verification invokes only the local ``ssh-keygen``
executable. A successful
invocation means the inventory and evidence contracts are internally
consistent; production readiness is a separately derived value and remains
false until every declared hardware and release gate qualifies.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


AUP_MAGIC = b"AUP format\x00\x00\x00\x00\x00\x00"
MANIFEST_PATH = Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
REPO_ROOT = Path(__file__).resolve().parents[3]
DISCOVERY_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py"
FIXTURE_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_fixture_receipt.py"
CAPTURE_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_capture_receipt.py"
RECOVERY_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_recovery_receipt.py"
BOOT_POLICY_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_boot_policy_receipt.py"
REPLACEMENT_VERIFIER = (
    "DCENT_OS_AvalonMiner/scripts/k210_route_replacement_receipt.py"
)
ROLLBACK_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py"
BENCH_ENDURANCE_VERIFIER = (
    "DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py"
)
RELEASE_VERIFIER = "DCENT_OS_AvalonMiner/scripts/k210_release_receipt.py"
CORPUS_POLICIES = ("auto", "required", "skip")
TARGET_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
CANDIDATE_VERSION_RE = re.compile(r"^[0-9]{8}_dcent_[a-z0-9][a-z0-9._-]{0,31}$")
CANDIDATE_MAX_APP_BYTES = 6 * 1024 * 1024
CONTROLLER_EVIDENCE = {
    "confirmed_documentary",
    "confirmed_portal_classification",
    "confirmed_held_firmware",
    "confirmed_held_firmware_family",
    "needs_exact_board_confirmation",
}
BENCH_STATES = {"unknown", "reported_available"}


def _load_discovery_module():
    path = Path(__file__).with_name("k210_discovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_discovery_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 discovery verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


discovery = _load_discovery_module()


def _load_fixture_module():
    path = Path(__file__).with_name("k210_fixture_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_fixture_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 fixture verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = _load_fixture_module()


def _load_capture_module():
    path = Path(__file__).with_name("k210_capture_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_capture_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 capture verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = _load_capture_module()


def _load_recovery_module():
    path = Path(__file__).with_name("k210_recovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_recovery_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 recovery verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = _load_recovery_module()


def _load_boot_policy_module():
    path = Path(__file__).with_name("k210_boot_policy_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_boot_policy_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 boot-policy verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot_policy = _load_boot_policy_module()


def _load_replacement_module():
    path = Path(__file__).with_name("k210_route_replacement_receipt.py")
    spec = importlib.util.spec_from_file_location(
        "k210_route_replacement_receipt", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 replacement verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replacement = _load_replacement_module()


def _load_rollback_module():
    path = Path(__file__).with_name("k210_route_rollback_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_route_rollback_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 rollback verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rollback = _load_rollback_module()


def _load_bench_endurance_module():
    path = Path(__file__).with_name("k210_bench_endurance_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_bench_endurance_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 bench/endurance verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench_endurance = _load_bench_endurance_module()


def _load_release_module():
    path = Path(__file__).with_name("k210_release_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_release_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 release verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = _load_release_module()


class GauntletError(RuntimeError):
    """A manifest, corpus, or admission invariant failed."""


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise GauntletError(f"u32 at 0x{offset:x} exceeds {len(data)}-byte buffer")
    return struct.unpack_from("<I", data, offset)[0]


def _fixed_string(data: bytes) -> str:
    raw = data.split(b"\x00", 1)[0]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GauntletError("AUP fixed string is not ASCII") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_aup_bytes(data: bytes) -> Dict[str, Any]:
    """Parse and verify one exact AUP-v2/K210 image without decrypting it."""

    if len(data) < 104:
        raise GauntletError(f"AUP is only {len(data)} bytes")
    if data[:16] != AUP_MAGIC:
        raise GauntletError("AUP magic mismatch")
    fmt_ver = _u32(data, 0x10)
    if fmt_ver != 2:
        raise GauntletError(f"K210 gauntlet requires AUP v2, got {fmt_ver}")

    payload_len = _u32(data, 0x14)
    hw_count = _u32(data, 0x5C)
    sw_count = _u32(data, 0x60)
    if hw_count > 64 or sw_count > 64:
        raise GauntletError(f"unreasonable AUP list counts hw={hw_count} sw={sw_count}")
    list_end = 0x64 + 32 * (hw_count + sw_count)
    header_size = list_end + 4
    if header_size > len(data):
        raise GauntletError("AUP declared header exceeds file")
    if header_size + payload_len != len(data):
        raise GauntletError(
            f"AUP size mismatch: header {header_size} + payload {payload_len} != {len(data)}"
        )

    hw_list = []
    sw_list = []
    offset = 0x64
    for _ in range(hw_count):
        hw_list.append(_fixed_string(data[offset : offset + 32]))
        offset += 32
    for _ in range(sw_count):
        sw_list.append(_fixed_string(data[offset : offset + 32]))
        offset += 32

    stored_header_crc = _u32(data, list_end)
    computed_header_crc = zlib.crc32(data[:list_end]) & 0xFFFFFFFF
    if stored_header_crc != computed_header_crc:
        raise GauntletError(
            f"AUP header CRC mismatch: {stored_header_crc:#010x} != {computed_header_crc:#010x}"
        )

    payload = data[header_size:]
    stored_payload_crc = _u32(data, 0x58)
    computed_payload_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if stored_payload_crc != computed_payload_crc:
        raise GauntletError(
            f"AUP payload CRC mismatch: {stored_payload_crc:#010x} != {computed_payload_crc:#010x}"
        )
    if len(payload) < 37:
        raise GauntletError(
            "K210 payload is too short for boot header and SHA-256 trailer"
        )
    aes_enable = payload[0]
    if aes_enable not in (0, 1):
        raise GauntletError(f"K210 aes_enable is {aes_enable}, expected 0 or 1")
    app_size = _u32(payload, 1)
    if 5 + app_size + 32 != len(payload):
        raise GauntletError(
            f"K210 body mismatch: 5 + app {app_size} + 32 != payload {len(payload)}"
        )
    trailer = payload[5 + app_size :]
    computed_inner_sha = hashlib.sha256(payload[: 5 + app_size]).digest()
    if trailer != computed_inner_sha:
        raise GauntletError("K210 inner SHA-256 trailer mismatch")

    return {
        "fmt_ver": fmt_ver,
        "firmware_version": _fixed_string(data[0x18:0x58]),
        "payload_len": payload_len,
        "payload_crc32": f"0x{stored_payload_crc:08x}",
        "header_crc32": f"0x{stored_header_crc:08x}",
        "header_size": header_size,
        "hw_list": hw_list,
        "sw_list": sw_list,
        "aes_enable": aes_enable,
        "k210_app_size": app_size,
        "k210_sha256": trailer.hex(),
        "k210_first16_ct": payload[5:21].hex(),
    }


def build_k210_plain_boot_image(app: bytes) -> bytes:
    """Build the byte-exact non-AES K210 flash wrapper used by kflash.py.

    This only proves a container. Whether a shipped Avalon controller permits
    ``aes_enable=0`` is an exact-unit eFuse measurement and remains unproven.
    """

    if not app:
        raise GauntletError("candidate K210 application is empty")
    if len(app) > CANDIDATE_MAX_APP_BYTES:
        raise GauntletError(
            f"candidate K210 application is {len(app)} bytes; desk limit is "
            f"{CANDIDATE_MAX_APP_BYTES}"
        )
    prefix = b"\x00" + struct.pack("<I", len(app)) + app
    return prefix + hashlib.sha256(prefix).digest()


def _encode_fixed_ascii(value: str, width: int, context: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GauntletError(f"{context} must be ASCII") from exc
    if not encoded:
        raise GauntletError(f"{context} must not be empty")
    if len(encoded) >= width:
        raise GauntletError(f"{context} must be shorter than {width} bytes")
    return encoded + b"\x00" * (width - len(encoded))


def build_aup_v2(
    payload: bytes,
    firmware_version: str,
    hw_list: Sequence[str],
    sw_list: Sequence[str],
) -> bytes:
    """Build the exact variable-length AUP-v2 envelope proven by the held corpus."""

    if not payload:
        raise GauntletError("AUP payload is empty")
    if not hw_list or not sw_list:
        raise GauntletError(
            "candidate AUP requires non-empty hardware and software lists"
        )
    if len(hw_list) > 64 or len(sw_list) > 64:
        raise GauntletError("candidate AUP compatibility lists are unreasonably large")
    if len(payload) > 0xFFFF_FFFF:
        raise GauntletError("candidate AUP payload exceeds its u32 length field")

    firmware = _encode_fixed_ascii(firmware_version, 64, "firmware version")
    hardware = [_encode_fixed_ascii(item, 32, "hardware tag") for item in hw_list]
    software = [_encode_fixed_ascii(item, 32, "software tag") for item in sw_list]
    list_end = 0x64 + 32 * (len(hardware) + len(software))
    header = bytearray(list_end + 4)
    header[:16] = AUP_MAGIC
    struct.pack_into("<I", header, 0x10, 2)
    struct.pack_into("<I", header, 0x14, len(payload))
    header[0x18:0x58] = firmware
    struct.pack_into("<I", header, 0x58, zlib.crc32(payload) & 0xFFFF_FFFF)
    struct.pack_into("<I", header, 0x5C, len(hardware))
    struct.pack_into("<I", header, 0x60, len(software))
    offset = 0x64
    for item in hardware + software:
        header[offset : offset + 32] = item
        offset += 32
    struct.pack_into(
        "<I", header, list_end, zlib.crc32(header[:list_end]) & 0xFFFF_FFFF
    )
    return bytes(header) + payload


def build_candidate_package(
    manifest: Mapping[str, Any], model_id: str, app: bytes, firmware_version: str
) -> Tuple[bytes, Dict[str, Any]]:
    """Build one deterministic, target-tagged, non-authorized AES0 candidate."""

    if not CANDIDATE_VERSION_RE.fullmatch(firmware_version):
        raise GauntletError(
            "candidate firmware version must match YYYYMMDD_dcent_<lowercase-id>"
        )
    target = _target_by_id(manifest, model_id)
    if target["kind"] != "physical_model":
        raise GauntletError(
            f"candidate package requires a physical-model row, got {target['kind']}"
        )
    if target["controller_evidence"] == "needs_exact_board_confirmation":
        raise GauntletError(f"target {model_id} is not confirmed as K210")
    profile_id = target["stock_profile"]
    if profile_id is None:
        raise GauntletError(f"target {model_id} has no held compatibility profile")
    profile = next(
        (item for item in manifest["firmware_profiles"] if item["id"] == profile_id),
        None,
    )
    if profile is None:
        raise GauntletError(f"target {model_id} cites missing profile {profile_id}")

    payload = build_k210_plain_boot_image(app)
    aup = build_aup_v2(
        payload, firmware_version, profile["hw_list"], profile["sw_list"]
    )
    observed = inspect_aup_bytes(aup)
    if observed["aes_enable"] != 0 or observed["k210_app_size"] != len(app):
        raise GauntletError(
            "candidate self-verification disagrees with the requested plain app"
        )
    receipt = {
        "schema_version": 1,
        "disposition": "offline_candidate_not_authorized_for_install",
        "scope": manifest["scope"],
        "model": model_id,
        "stock_profile": profile_id,
        "controller_soc": target["controller_soc"],
        "asic_family": target["asic_family"],
        "firmware_version": firmware_version,
        "hw_list": profile["hw_list"],
        "sw_list": profile["sw_list"],
        "source_app_bytes": len(app),
        "source_app_sha256": hashlib.sha256(app).hexdigest(),
        "aes_enable": 0,
        "k210_payload_sha256": observed["k210_sha256"],
        "payload_crc32": observed["payload_crc32"],
        "header_crc32": observed["header_crc32"],
        "aup_bytes": len(aup),
        "aup_sha256": hashlib.sha256(aup).hexdigest(),
        "requires_before_any_install": [
            "exact-unit stock backup and two independent restore paths",
            "measured proof that force-decrypt eFuse permits aes_enable=0",
            "measured flash geometry, boot entry, ISP/JTAG, and recovery behavior",
            "target-bound BSP plus independent hash-power and cooling custody",
            "explicit operator authorization for the named unit and action",
        ],
    }
    return aup, receipt


def load_manifest(path: Path = MANIFEST_PATH) -> Dict[str, Any]:
    def reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GauntletError(f"manifest contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise GauntletError(f"cannot load manifest {path}: {exc}") from exc
    validate_manifest(data)
    return data


def _require_keys(row: Mapping[str, Any], keys: Iterable[str], context: str) -> None:
    missing = [key for key in keys if key not in row]
    if missing:
        raise GauntletError(f"{context} is missing keys: {', '.join(missing)}")


def _safe_repo_path(value: str, context: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise GauntletError(f"{context} must be a repository-relative path")


def _validate_global_anchor_separation(manifest: Mapping[str, Any]) -> None:
    """Prevent one identity or file from silently serving independent roles."""

    observed: list[tuple[str, Mapping[str, Any]]] = []
    for contract_name, contract in sorted(manifest.items()):
        if not contract_name.endswith("_contract") or not isinstance(contract, dict):
            continue
        if isinstance(contract.get("trust_anchor"), Mapping):
            observed.append((f"{contract_name}.signer", contract["trust_anchor"]))
        anchors = contract.get("trust_anchors")
        if isinstance(anchors, Mapping):
            observed.extend(
                (f"{contract_name}.{role}", anchor)
                for role, anchor in sorted(anchors.items())
                if isinstance(anchor, Mapping)
            )
    for field in ("key_id_sha256", "path", "role"):
        values: dict[str, str] = {}
        for name, anchor in observed:
            value = anchor.get(field)
            if not isinstance(value, str) or not value:
                continue  # contract-specific validation reports malformed anchors
            prior = values.get(value)
            if prior is not None:
                raise GauntletError(f"trust anchors {prior} and {name} reuse {field}")
            values[value] = name


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    expected_manifest_fields = {
        "a1246_variant_identity_contract",
        "boot_policy_contract",
        "bench_endurance_contract",
        "capture_contract",
        "description",
        "discovery_contract",
        "firmware_profiles",
        "fixture_contract",
        "management_contract",
        "production_gates",
        "recovery_contract",
        "release_contract",
        "replacement_firmware_contract",
        "rollback_contract",
        "runtime_contract",
        "schema_version",
        "scope",
        "targets",
        "update_transport_contract",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != expected_manifest_fields:
        missing = sorted(expected_manifest_fields - set(manifest))
        extra = sorted(set(manifest) - expected_manifest_fields)
        raise GauntletError(
            f"manifest top-level fields are not exact: missing={missing}, extra={extra}"
        )
    if manifest["schema_version"] != 1:
        raise GauntletError(f"unsupported manifest schema {manifest['schema_version']}")
    if manifest["scope"] != "canaan-avalon-k210-production-readiness":
        raise GauntletError(
            "manifest scope is not the K210 production-readiness domain"
        )
    _validate_global_anchor_separation(manifest)

    discovery_contract = manifest["discovery_contract"]
    _require_keys(
        discovery_contract,
        (
            "state",
            "verifier",
            "receipt_schema_version",
            "receipt_kind",
            "signature_algorithm",
            "signature_namespace",
            "required_evidence_kinds",
            "trust_anchor",
            "boundary",
        ),
        "discovery contract",
    )
    if discovery_contract["verifier"] != DISCOVERY_VERIFIER:
        raise GauntletError("discovery contract verifier path drifted")
    _safe_repo_path(discovery_contract["verifier"], "discovery contract verifier")
    if discovery_contract["receipt_schema_version"] != discovery.SCHEMA_VERSION:
        raise GauntletError("discovery receipt schema version drifted")
    if discovery_contract["receipt_kind"] != discovery.RECEIPT_KIND:
        raise GauntletError("discovery receipt kind drifted")
    if discovery_contract["signature_algorithm"] != discovery.SIGNATURE_ALGORITHM:
        raise GauntletError("discovery signature algorithm drifted")
    if discovery_contract["signature_namespace"] != discovery.SIGNATURE_NAMESPACE:
        raise GauntletError("discovery signature namespace drifted")
    if discovery_contract["required_evidence_kinds"] != list(
        discovery.REQUIRED_EVIDENCE_KINDS
    ):
        raise GauntletError("discovery required-evidence vocabulary drifted")
    trust_anchor = discovery_contract["trust_anchor"]
    if trust_anchor is None:
        if discovery_contract["state"] != "signed_read_only_schema_no_trust_anchor":
            raise GauntletError("unanchored discovery contract state drifted")
    else:
        if discovery_contract["state"] != "signed_read_only_receipt_admission":
            raise GauntletError("anchored discovery contract state drifted")
        if not isinstance(trust_anchor, dict):
            raise GauntletError("discovery trust anchor must be null or an object")
        _require_keys(
            trust_anchor,
            ("key_id_sha256", "path", "role"),
            "discovery trust anchor",
        )
        if set(trust_anchor) != {"key_id_sha256", "path", "role"}:
            raise GauntletError("discovery trust anchor contains unexpected fields")
        _safe_repo_path(trust_anchor["path"], "discovery trust anchor path")
        if not HEX64_RE.fullmatch(trust_anchor["key_id_sha256"]):
            raise GauntletError("discovery trust-anchor key ID is not SHA-256")
        if trust_anchor["role"] != discovery.SIGNER_ROLE:
            raise GauntletError("discovery trust-anchor role drifted")

    fixture_contract = manifest["fixture_contract"]
    required_fixture_fields = {
        "boundary",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_kinds",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(fixture_contract, dict)
        or set(fixture_contract) != required_fixture_fields
    ):
        raise GauntletError("fixture contract is not exact")
    if fixture_contract["verifier"] != FIXTURE_VERIFIER:
        raise GauntletError("fixture contract verifier path drifted")
    _safe_repo_path(fixture_contract["verifier"], "fixture contract verifier")
    if fixture_contract["receipt_schema_version"] != fixture.SCHEMA_VERSION:
        raise GauntletError("fixture receipt schema version drifted")
    if fixture_contract["receipt_kind"] != fixture.RECEIPT_KIND:
        raise GauntletError("fixture receipt kind drifted")
    if fixture_contract["signature_algorithm"] != fixture.SIGNATURE_ALGORITHM:
        raise GauntletError("fixture signature algorithm drifted")
    if fixture_contract["required_evidence_kinds"] != list(
        fixture.REQUIRED_EVIDENCE_KINDS
    ):
        raise GauntletError("fixture evidence vocabulary drifted")
    fixture_roles = fixture_contract["roles"]
    if not isinstance(fixture_roles, dict) or set(fixture_roles) != {
        "operator",
        "reviewer",
    }:
        raise GauntletError("fixture roles must contain exactly operator and reviewer")
    expected_fixture_roles = {
        "operator": (fixture.OPERATOR_ROLE, fixture.OPERATOR_NAMESPACE),
        "reviewer": (fixture.REVIEWER_ROLE, fixture.REVIEWER_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_fixture_roles.items():
        role = fixture_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"fixture {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"fixture {name} role contract drifted")
    fixture_anchors = fixture_contract["trust_anchors"]
    if not isinstance(fixture_anchors, dict) or set(fixture_anchors) != {
        "operator",
        "reviewer",
    }:
        raise GauntletError(
            "fixture trust anchors must contain exactly operator and reviewer"
        )
    fixture_anchor_presence = {
        name: fixture_anchors[name] is not None for name in fixture_anchors
    }
    if len(set(fixture_anchor_presence.values())) != 1:
        raise GauntletError("fixture trust anchors must be pinned or absent together")
    if not any(fixture_anchor_presence.values()):
        if fixture_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored fixture contract state drifted")
    else:
        if fixture_contract["state"] != "dual_signed_fixture_admission":
            raise GauntletError("anchored fixture contract state drifted")
        for name, (expected_role, _) in expected_fixture_roles.items():
            anchor = fixture_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"fixture {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"fixture {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"fixture {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"fixture {name} trust-anchor role drifted")
        if (
            fixture_anchors["operator"]["key_id_sha256"]
            == fixture_anchors["reviewer"]["key_id_sha256"]
            or fixture_anchors["operator"]["path"]
            == fixture_anchors["reviewer"]["path"]
        ):
            raise GauntletError(
                "fixture operator and reviewer anchors must be distinct"
            )

    capture_contract = manifest["capture_contract"]
    required_capture_fields = {
        "boundary",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_counts",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(capture_contract, dict)
        or set(capture_contract) != required_capture_fields
    ):
        raise GauntletError("capture contract is not exact")
    if capture_contract["verifier"] != CAPTURE_VERIFIER:
        raise GauntletError("capture contract verifier path drifted")
    _safe_repo_path(capture_contract["verifier"], "capture contract verifier")
    if capture_contract["receipt_schema_version"] != capture.SCHEMA_VERSION:
        raise GauntletError("capture receipt schema version drifted")
    if capture_contract["receipt_kind"] != capture.RECEIPT_KIND:
        raise GauntletError("capture receipt kind drifted")
    if capture_contract["signature_algorithm"] != capture.SIGNATURE_ALGORITHM:
        raise GauntletError("capture signature algorithm drifted")
    expected_capture_counts = {
        **{kind: [1, 1] for kind in capture.SINGLE_EVIDENCE_KINDS},
        **{
            kind: [minimum, maximum]
            for kind, (minimum, maximum) in capture.MULTI_EVIDENCE_COUNTS.items()
        },
    }
    if capture_contract["required_evidence_counts"] != dict(
        sorted(expected_capture_counts.items())
    ):
        raise GauntletError("capture evidence-count contract drifted")
    capture_roles = capture_contract["roles"]
    if not isinstance(capture_roles, dict) or set(capture_roles) != {
        "operator",
        "reviewer",
    }:
        raise GauntletError("capture roles must contain exactly operator and reviewer")
    expected_capture_roles = {
        "operator": (capture.OPERATOR_ROLE, capture.OPERATOR_NAMESPACE),
        "reviewer": (capture.REVIEWER_ROLE, capture.REVIEWER_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_capture_roles.items():
        role = capture_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"capture {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"capture {name} role contract drifted")
    capture_anchors = capture_contract["trust_anchors"]
    if not isinstance(capture_anchors, dict) or set(capture_anchors) != {
        "operator",
        "reviewer",
    }:
        raise GauntletError(
            "capture trust anchors must contain exactly operator and reviewer"
        )
    capture_anchor_presence = {
        name: capture_anchors[name] is not None for name in capture_anchors
    }
    if len(set(capture_anchor_presence.values())) != 1:
        raise GauntletError("capture trust anchors must be pinned or absent together")
    if not any(capture_anchor_presence.values()):
        if capture_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored capture contract state drifted")
    else:
        if capture_contract["state"] != "dual_signed_p1_capture_admission":
            raise GauntletError("anchored capture contract state drifted")
        for name, (expected_role, _) in expected_capture_roles.items():
            anchor = capture_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"capture {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"capture {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"capture {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"capture {name} trust-anchor role drifted")
        if (
            capture_anchors["operator"]["key_id_sha256"]
            == capture_anchors["reviewer"]["key_id_sha256"]
            or capture_anchors["operator"]["path"]
            == capture_anchors["reviewer"]["path"]
        ):
            raise GauntletError(
                "capture operator and reviewer anchors must be distinct"
            )

    recovery_contract = manifest["recovery_contract"]
    _require_keys(
        recovery_contract,
        (
            "state",
            "verifier",
            "receipt_schema_version",
            "receipt_kind",
            "signature_algorithm",
            "roles",
            "trust_anchors",
            "boundary",
        ),
        "recovery contract",
    )
    if recovery_contract["verifier"] != RECOVERY_VERIFIER:
        raise GauntletError("recovery contract verifier path drifted")
    _safe_repo_path(recovery_contract["verifier"], "recovery contract verifier")
    if recovery_contract["receipt_schema_version"] != recovery.SCHEMA_VERSION:
        raise GauntletError("recovery receipt schema version drifted")
    if recovery_contract["receipt_kind"] != recovery.RECEIPT_KIND:
        raise GauntletError("recovery receipt kind drifted")
    if recovery_contract["signature_algorithm"] != recovery.SIGNATURE_ALGORITHM:
        raise GauntletError("recovery signature algorithm drifted")
    roles = recovery_contract["roles"]
    if not isinstance(roles, dict) or set(roles) != {"operator", "witness"}:
        raise GauntletError("recovery roles must contain exactly operator and witness")
    expected_roles = {
        "operator": (recovery.OPERATOR_ROLE, recovery.OPERATOR_NAMESPACE),
        "witness": (recovery.WITNESS_ROLE, recovery.WITNESS_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_roles.items():
        role = roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"recovery {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"recovery {name} role contract drifted")
    anchors = recovery_contract["trust_anchors"]
    if not isinstance(anchors, dict) or set(anchors) != {"operator", "witness"}:
        raise GauntletError(
            "recovery trust anchors must contain exactly operator and witness"
        )
    anchor_presence = {name: anchors[name] is not None for name in anchors}
    if len(set(anchor_presence.values())) != 1:
        raise GauntletError("recovery trust anchors must be pinned or absent together")
    if not any(anchor_presence.values()):
        if recovery_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored recovery contract state drifted")
    else:
        if recovery_contract["state"] != "dual_signed_stock_recovery_admission":
            raise GauntletError("anchored recovery contract state drifted")
        for name, (expected_role, _) in expected_roles.items():
            anchor = anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"recovery {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"recovery {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"recovery {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"recovery {name} trust-anchor role drifted")
        if (
            anchors["operator"]["key_id_sha256"] == anchors["witness"]["key_id_sha256"]
            or anchors["operator"]["path"] == anchors["witness"]["path"]
        ):
            raise GauntletError(
                "recovery operator and witness anchors must be distinct"
            )

    boot_contract = manifest["boot_policy_contract"]
    _require_keys(
        boot_contract,
        (
            "state",
            "verifier",
            "receipt_schema_version",
            "receipt_kind",
            "signature_algorithm",
            "roles",
            "trust_anchors",
            "required_evidence_kinds",
            "boundary",
        ),
        "boot-policy contract",
    )
    if set(boot_contract) != {
        "state",
        "verifier",
        "receipt_schema_version",
        "receipt_kind",
        "signature_algorithm",
        "roles",
        "trust_anchors",
        "required_evidence_kinds",
        "boundary",
    }:
        raise GauntletError("boot-policy contract contains unexpected fields")
    if boot_contract["verifier"] != BOOT_POLICY_VERIFIER:
        raise GauntletError("boot-policy contract verifier path drifted")
    _safe_repo_path(boot_contract["verifier"], "boot-policy contract verifier")
    if boot_contract["receipt_schema_version"] != boot_policy.SCHEMA_VERSION:
        raise GauntletError("boot-policy receipt schema version drifted")
    if boot_contract["receipt_kind"] != boot_policy.RECEIPT_KIND:
        raise GauntletError("boot-policy receipt kind drifted")
    if boot_contract["signature_algorithm"] != boot_policy.SIGNATURE_ALGORITHM:
        raise GauntletError("boot-policy signature algorithm drifted")
    if boot_contract["required_evidence_kinds"] != list(
        boot_policy.REQUIRED_EVIDENCE_KINDS
    ):
        raise GauntletError("boot-policy required-evidence vocabulary drifted")
    boot_roles = boot_contract["roles"]
    if not isinstance(boot_roles, dict) or set(boot_roles) != {"operator", "witness"}:
        raise GauntletError(
            "boot-policy roles must contain exactly operator and witness"
        )
    expected_boot_roles = {
        "operator": (boot_policy.OPERATOR_ROLE, boot_policy.OPERATOR_NAMESPACE),
        "witness": (boot_policy.WITNESS_ROLE, boot_policy.WITNESS_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_boot_roles.items():
        role = boot_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"boot-policy {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"boot-policy {name} role contract drifted")
    boot_anchors = boot_contract["trust_anchors"]
    if not isinstance(boot_anchors, dict) or set(boot_anchors) != {
        "operator",
        "witness",
    }:
        raise GauntletError(
            "boot-policy trust anchors must contain exactly operator and witness"
        )
    boot_anchor_presence = {
        name: boot_anchors[name] is not None for name in boot_anchors
    }
    if len(set(boot_anchor_presence.values())) != 1:
        raise GauntletError(
            "boot-policy trust anchors must be pinned or absent together"
        )
    if not any(boot_anchor_presence.values()):
        if boot_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored boot-policy contract state drifted")
    else:
        if boot_contract["state"] != "dual_signed_boot_policy_admission":
            raise GauntletError("anchored boot-policy contract state drifted")
        for name, (expected_role, _) in expected_boot_roles.items():
            anchor = boot_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"boot-policy {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"boot-policy {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"boot-policy {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"boot-policy {name} trust-anchor role drifted")
        if (
            boot_anchors["operator"]["key_id_sha256"]
            == boot_anchors["witness"]["key_id_sha256"]
            or boot_anchors["operator"]["path"] == boot_anchors["witness"]["path"]
        ):
            raise GauntletError(
                "boot-policy operator and witness anchors must be distinct"
            )

    replacement_contract = manifest["replacement_firmware_contract"]
    required_replacement_fields = {
        "boundary",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_kinds",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(replacement_contract, dict)
        or set(replacement_contract) != required_replacement_fields
    ):
        raise GauntletError("replacement-firmware contract is not exact")
    if replacement_contract["verifier"] != REPLACEMENT_VERIFIER:
        raise GauntletError("replacement-firmware verifier path drifted")
    _safe_repo_path(replacement_contract["verifier"], "replacement-firmware verifier")
    if replacement_contract["receipt_schema_version"] != replacement.SCHEMA_VERSION:
        raise GauntletError("replacement-firmware receipt schema version drifted")
    if replacement_contract["receipt_kind"] != replacement.RECEIPT_KIND:
        raise GauntletError("replacement-firmware receipt kind drifted")
    if replacement_contract["signature_algorithm"] != replacement.SIGNATURE_ALGORITHM:
        raise GauntletError("replacement-firmware signature algorithm drifted")
    if replacement_contract["required_evidence_kinds"] != sorted(
        replacement.EVIDENCE_KINDS
    ):
        raise GauntletError("replacement-firmware evidence vocabulary drifted")
    replacement_roles = replacement_contract["roles"]
    if not isinstance(replacement_roles, dict) or set(replacement_roles) != {
        "builder",
        "reviewer",
    }:
        raise GauntletError(
            "replacement-firmware roles must contain exactly builder and reviewer"
        )
    expected_replacement_roles = {
        "builder": (replacement.BUILDER_ROLE, replacement.BUILDER_NAMESPACE),
        "reviewer": (replacement.REVIEWER_ROLE, replacement.REVIEWER_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_replacement_roles.items():
        role = replacement_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(
                f"replacement-firmware {name} role contract is not exact"
            )
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"replacement-firmware {name} role contract drifted")
    replacement_anchors = replacement_contract["trust_anchors"]
    if not isinstance(replacement_anchors, dict) or set(replacement_anchors) != {
        "builder",
        "reviewer",
    }:
        raise GauntletError(
            "replacement-firmware trust anchors must contain builder and reviewer"
        )
    replacement_anchor_presence = {
        name: replacement_anchors[name] is not None for name in replacement_anchors
    }
    if len(set(replacement_anchor_presence.values())) != 1:
        raise GauntletError(
            "replacement-firmware anchors must be pinned or absent together"
        )
    if not any(replacement_anchor_presence.values()):
        if replacement_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored replacement-firmware state drifted")
    else:
        if replacement_contract["state"] != "dual_signed_route_replacement_admission":
            raise GauntletError("anchored replacement-firmware state drifted")
        for name, (expected_role, _) in expected_replacement_roles.items():
            anchor = replacement_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(
                    f"replacement-firmware {name} trust anchor is not exact"
                )
            _safe_repo_path(
                anchor["path"], f"replacement-firmware {name} trust anchor path"
            )
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(
                    f"replacement-firmware {name} key ID is not SHA-256"
                )
            if anchor["role"] != expected_role:
                raise GauntletError(
                    f"replacement-firmware {name} trust-anchor role drifted"
                )
        if (
            replacement_anchors["builder"]["key_id_sha256"]
            == replacement_anchors["reviewer"]["key_id_sha256"]
            or replacement_anchors["builder"]["path"]
            == replacement_anchors["reviewer"]["path"]
        ):
            raise GauntletError(
                "replacement-firmware builder and reviewer anchors must be distinct"
            )

    rollback_contract = manifest["rollback_contract"]
    required_rollback_fields = {
        "boundary",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_kinds",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(rollback_contract, dict)
        or set(rollback_contract) != required_rollback_fields
    ):
        raise GauntletError("rollback contract is not exact")
    if rollback_contract["verifier"] != ROLLBACK_VERIFIER:
        raise GauntletError("rollback contract verifier path drifted")
    _safe_repo_path(rollback_contract["verifier"], "rollback contract verifier")
    if rollback_contract["receipt_schema_version"] != rollback.SCHEMA_VERSION:
        raise GauntletError("rollback receipt schema version drifted")
    if rollback_contract["receipt_kind"] != rollback.RECEIPT_KIND:
        raise GauntletError("rollback receipt kind drifted")
    if rollback_contract["signature_algorithm"] != rollback.SIGNATURE_ALGORITHM:
        raise GauntletError("rollback signature algorithm drifted")
    if rollback_contract["required_evidence_kinds"] != sorted(rollback.EVIDENCE_KINDS):
        raise GauntletError("rollback evidence vocabulary drifted")
    rollback_roles = rollback_contract["roles"]
    if not isinstance(rollback_roles, dict) or set(rollback_roles) != {
        "operator",
        "witness",
    }:
        raise GauntletError("rollback roles must contain operator and witness")
    expected_rollback_roles = {
        "operator": (rollback.OPERATOR_ROLE, rollback.OPERATOR_NAMESPACE),
        "witness": (rollback.WITNESS_ROLE, rollback.WITNESS_NAMESPACE),
    }
    for name, (expected_role, expected_namespace) in expected_rollback_roles.items():
        role = rollback_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"rollback {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"rollback {name} role contract drifted")
    rollback_anchors = rollback_contract["trust_anchors"]
    if not isinstance(rollback_anchors, dict) or set(rollback_anchors) != {
        "operator",
        "witness",
    }:
        raise GauntletError("rollback trust anchors must contain operator and witness")
    rollback_anchor_presence = {
        name: rollback_anchors[name] is not None for name in rollback_anchors
    }
    if len(set(rollback_anchor_presence.values())) != 1:
        raise GauntletError("rollback anchors must be pinned or absent together")
    if not any(rollback_anchor_presence.values()):
        if rollback_contract["state"] != "dual_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored rollback state drifted")
    else:
        if rollback_contract["state"] != "dual_signed_route_rollback_admission":
            raise GauntletError("anchored rollback state drifted")
        for name, (expected_role, _) in expected_rollback_roles.items():
            anchor = rollback_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"rollback {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"rollback {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"rollback {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"rollback {name} trust-anchor role drifted")
        if (
            rollback_anchors["operator"]["key_id_sha256"]
            == rollback_anchors["witness"]["key_id_sha256"]
            or rollback_anchors["operator"]["path"]
            == rollback_anchors["witness"]["path"]
        ):
            raise GauntletError(
                "rollback operator and witness anchors must be distinct"
            )

    bench_endurance_contract = manifest["bench_endurance_contract"]
    required_bench_endurance_fields = {
        "boundary",
        "qualification_classes",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_kinds",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(bench_endurance_contract, dict)
        or set(bench_endurance_contract) != required_bench_endurance_fields
    ):
        raise GauntletError("bench/endurance contract is not exact")
    if bench_endurance_contract["verifier"] != BENCH_ENDURANCE_VERIFIER:
        raise GauntletError("bench/endurance verifier path drifted")
    _safe_repo_path(
        bench_endurance_contract["verifier"], "bench/endurance contract verifier"
    )
    if (
        bench_endurance_contract["receipt_schema_version"]
        != bench_endurance.SCHEMA_VERSION
    ):
        raise GauntletError("bench/endurance receipt schema version drifted")
    if bench_endurance_contract["receipt_kind"] != bench_endurance.RECEIPT_KIND:
        raise GauntletError("bench/endurance receipt kind drifted")
    if (
        bench_endurance_contract["signature_algorithm"]
        != bench_endurance.SIGNATURE_ALGORITHM
    ):
        raise GauntletError("bench/endurance signature algorithm drifted")
    expected_qualification_classes = [
        bench_endurance.QUALIFICATION_FIRST_LIGHT,
        bench_endurance.QUALIFICATION_BENCH,
        bench_endurance.QUALIFICATION_ENDURANCE,
    ]
    if (
        bench_endurance_contract["qualification_classes"]
        != expected_qualification_classes
    ):
        raise GauntletError("bench/endurance qualification-class order drifted")
    if bench_endurance_contract["required_evidence_kinds"] != sorted(
        bench_endurance.ALL_EVIDENCE_KINDS
    ):
        raise GauntletError("bench/endurance evidence vocabulary drifted")
    stage_role_bindings = {
        "first_light_operator": (
            bench_endurance.QUALIFICATION_FIRST_LIGHT,
            "operator",
        ),
        "first_light_protocol_reviewer": (
            bench_endurance.QUALIFICATION_FIRST_LIGHT,
            "protocol_reviewer",
        ),
        "first_light_safety_reviewer": (
            bench_endurance.QUALIFICATION_FIRST_LIGHT,
            "safety_reviewer",
        ),
        "bench_operator": (bench_endurance.QUALIFICATION_BENCH, "operator"),
        "bench_witness": (bench_endurance.QUALIFICATION_BENCH, "witness"),
        "endurance_operator": (
            bench_endurance.QUALIFICATION_ENDURANCE,
            "operator",
        ),
        "endurance_witness": (
            bench_endurance.QUALIFICATION_ENDURANCE,
            "witness",
        ),
    }
    stage_roles = bench_endurance_contract["roles"]
    if not isinstance(stage_roles, dict) or set(stage_roles) != set(
        stage_role_bindings
    ):
        raise GauntletError("bench/endurance roles are not exact")
    for name, (qualification_class, signer_role) in stage_role_bindings.items():
        expected_role, expected_namespace = bench_endurance.SIGNING_CONTRACTS[
            qualification_class
        ][signer_role]
        role = stage_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"bench/endurance {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"bench/endurance {name} role contract drifted")
    stage_anchors = bench_endurance_contract["trust_anchors"]
    if not isinstance(stage_anchors, dict) or set(stage_anchors) != set(
        stage_role_bindings
    ):
        raise GauntletError("bench/endurance trust anchors are not exact")
    stage_anchor_presence = {
        name: stage_anchors[name] is not None for name in stage_anchors
    }
    if len(set(stage_anchor_presence.values())) != 1:
        raise GauntletError(
            "bench/endurance trust anchors must be pinned or absent together"
        )
    if not any(stage_anchor_presence.values()):
        if (
            bench_endurance_contract["state"]
            != "multi_stage_signed_schema_no_trust_anchors"
        ):
            raise GauntletError("unanchored bench/endurance contract state drifted")
    else:
        if (
            bench_endurance_contract["state"]
            != "multi_stage_signed_bench_endurance_admission"
        ):
            raise GauntletError("anchored bench/endurance contract state drifted")
        for name, (qualification_class, signer_role) in stage_role_bindings.items():
            expected_role = bench_endurance.SIGNING_CONTRACTS[qualification_class][
                signer_role
            ][0]
            anchor = stage_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"bench/endurance {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"bench/endurance {name} anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"bench/endurance {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"bench/endurance {name} trust-anchor role drifted")
        if len({anchor["key_id_sha256"] for anchor in stage_anchors.values()}) != len(
            stage_anchors
        ) or len({anchor["path"] for anchor in stage_anchors.values()}) != len(
            stage_anchors
        ):
            raise GauntletError("bench/endurance trust anchors must all be distinct")

    release_contract = manifest["release_contract"]
    required_release_fields = {
        "boundary",
        "permitted_actions",
        "preauthorization_kind",
        "receipt_kind",
        "receipt_schema_version",
        "required_evidence_kinds",
        "roles",
        "signature_algorithm",
        "state",
        "trust_anchors",
        "verifier",
    }
    if (
        not isinstance(release_contract, dict)
        or set(release_contract) != required_release_fields
    ):
        raise GauntletError("release contract is not exact")
    if release_contract["verifier"] != RELEASE_VERIFIER:
        raise GauntletError("release verifier path drifted")
    _safe_repo_path(release_contract["verifier"], "release contract verifier")
    if release_contract["receipt_schema_version"] != release.SCHEMA_VERSION:
        raise GauntletError("release receipt schema version drifted")
    if release_contract["preauthorization_kind"] != release.PREAUTH_KIND:
        raise GauntletError("release preauthorization kind drifted")
    if release_contract["receipt_kind"] != release.RECEIPT_KIND:
        raise GauntletError("release receipt kind drifted")
    if release_contract["signature_algorithm"] != release.SIGNATURE_ALGORITHM:
        raise GauntletError("release signature algorithm drifted")
    if release_contract["permitted_actions"] != sorted(release.PERMITTED_ACTIONS):
        raise GauntletError("release permitted-action vocabulary drifted")
    if release_contract["required_evidence_kinds"] != sorted(release.EVIDENCE_KINDS):
        raise GauntletError("release evidence vocabulary drifted")
    expected_release_roles = {
        "preauthorizer": (
            release.PREAUTHORIZER_ROLE,
            release.PREAUTHORIZER_NAMESPACE,
        ),
        "reviewer": (release.REVIEWER_ROLE, release.REVIEWER_NAMESPACE),
        "installer": (release.INSTALLER_ROLE, release.INSTALLER_NAMESPACE),
        "witness": (release.WITNESS_ROLE, release.WITNESS_NAMESPACE),
    }
    release_roles = release_contract["roles"]
    if not isinstance(release_roles, dict) or set(release_roles) != set(
        expected_release_roles
    ):
        raise GauntletError("release roles are not exact")
    for name, (expected_role, expected_namespace) in expected_release_roles.items():
        role = release_roles[name]
        if not isinstance(role, dict) or set(role) != {"role", "namespace"}:
            raise GauntletError(f"release {name} role contract is not exact")
        if role["role"] != expected_role or role["namespace"] != expected_namespace:
            raise GauntletError(f"release {name} role contract drifted")
    release_anchors = release_contract["trust_anchors"]
    if not isinstance(release_anchors, dict) or set(release_anchors) != set(
        expected_release_roles
    ):
        raise GauntletError("release trust anchors are not exact")
    release_anchor_presence = {
        name: release_anchors[name] is not None for name in release_anchors
    }
    if len(set(release_anchor_presence.values())) != 1:
        raise GauntletError("release trust anchors must be pinned or absent together")
    if not any(release_anchor_presence.values()):
        if release_contract["state"] != "four_role_signed_schema_no_trust_anchors":
            raise GauntletError("unanchored release contract state drifted")
    else:
        if release_contract["state"] != "four_role_signed_release_admission":
            raise GauntletError("anchored release contract state drifted")
        for name, (expected_role, _) in expected_release_roles.items():
            anchor = release_anchors[name]
            if not isinstance(anchor, dict) or set(anchor) != {
                "key_id_sha256",
                "path",
                "role",
            }:
                raise GauntletError(f"release {name} trust anchor is not exact")
            _safe_repo_path(anchor["path"], f"release {name} trust anchor path")
            if not HEX64_RE.fullmatch(anchor["key_id_sha256"]):
                raise GauntletError(f"release {name} key ID is not SHA-256")
            if anchor["role"] != expected_role:
                raise GauntletError(f"release {name} trust-anchor role drifted")
        if len({anchor["key_id_sha256"] for anchor in release_anchors.values()}) != len(
            release_anchors
        ) or len({anchor["path"] for anchor in release_anchors.values()}) != len(
            release_anchors
        ):
            raise GauntletError("release trust anchors must all be distinct")

    transport = manifest["update_transport_contract"]
    _require_keys(
        transport,
        (
            "state",
            "transport",
            "api_command",
            "default_page_bytes",
            "prechecks",
            "transfer_behavior",
            "postconditions",
            "evidence",
            "boundary",
        ),
        "update transport contract",
    )
    if transport["state"] != "verified_offline_reference":
        raise GauntletError("update transport contract is not an offline reference")
    if transport["default_page_bytes"] != 888:
        raise GauntletError(
            "update transport default page size drifted from the held reference"
        )
    if not transport["evidence"]:
        raise GauntletError("update transport contract has no evidence")
    for index, evidence_path in enumerate(transport["evidence"]):
        _safe_repo_path(evidence_path, f"update transport evidence[{index}]")

    runtime = manifest["runtime_contract"]
    _require_keys(
        runtime,
        (
            "state",
            "crate",
            "safety_supervisor",
            "sentinel",
            "linker_script",
            "candidate_builder",
            "freestanding_target",
            "capabilities",
            "boundary",
        ),
        "runtime contract",
    )
    if runtime["state"] != "no_std_policy_core_and_safe_idle_pipeline":
        raise GauntletError(
            "runtime contract does not describe the bounded core and pipeline"
        )
    if runtime["freestanding_target"] != "riscv64gc-unknown-none-elf":
        raise GauntletError("runtime contract freestanding target drifted")
    _safe_repo_path(runtime["crate"], "runtime contract crate")
    _safe_repo_path(runtime["safety_supervisor"], "runtime contract safety supervisor")
    _safe_repo_path(runtime["sentinel"], "runtime contract sentinel")
    _safe_repo_path(runtime["linker_script"], "runtime contract linker script")
    _safe_repo_path(runtime["candidate_builder"], "runtime contract candidate builder")

    gate_ids = [gate.get("id") for gate in manifest["production_gates"]]
    if not gate_ids or len(gate_ids) != len(set(gate_ids)):
        raise GauntletError("production gate IDs must be present and unique")

    profiles: Dict[str, Mapping[str, Any]] = {}
    for profile in manifest["firmware_profiles"]:
        _require_keys(
            profile,
            (
                "id",
                "firmware_version",
                "asic_family",
                "hw_list",
                "sw_list",
                "source_zip",
                "source_zip_sha256",
                "summary",
                "aup",
                "aup_bytes",
                "aup_sha256",
                "payload_crc32",
                "header_crc32",
                "k210_app_size",
                "k210_sha256",
            ),
            "firmware profile",
        )
        profile_id = profile["id"]
        if not isinstance(profile_id, str) or not TARGET_ID_RE.fullmatch(profile_id):
            raise GauntletError(f"invalid firmware profile id {profile_id!r}")
        if profile_id in profiles:
            raise GauntletError(f"duplicate firmware profile {profile_id}")
        for field in ("source_zip", "summary", "aup"):
            _safe_repo_path(profile[field], f"profile {profile_id}.{field}")
        for field in ("source_zip_sha256", "aup_sha256", "k210_sha256"):
            if not HEX64_RE.fullmatch(profile[field]):
                raise GauntletError(
                    f"profile {profile_id}.{field} is not lowercase SHA-256"
                )
        for field in ("payload_crc32", "header_crc32"):
            if not re.fullmatch(r"0x[0-9a-f]{8}", profile[field]):
                raise GauntletError(
                    f"profile {profile_id}.{field} is not canonical CRC-32"
                )
        if profile["aup_bytes"] <= 0 or profile["k210_app_size"] <= 0:
            raise GauntletError(f"profile {profile_id} has non-positive byte counts")
        profiles[profile_id] = profile

    targets: Dict[str, Mapping[str, Any]] = {}
    referenced_profiles = set()
    for target in manifest["targets"]:
        _require_keys(
            target,
            (
                "id",
                "display_name",
                "kind",
                "generation",
                "controller_soc",
                "controller_evidence",
                "controller_source",
                "asic_family",
                "stock_profile",
                "bench_state",
            ),
            "target",
        )
        target_id = target["id"]
        if not isinstance(target_id, str) or not TARGET_ID_RE.fullmatch(target_id):
            raise GauntletError(f"invalid target id {target_id!r}")
        if target_id in targets:
            raise GauntletError(f"duplicate target {target_id}")
        if not str(target["controller_soc"]).startswith("K210"):
            raise GauntletError(f"target {target_id} escaped the K210 scope")
        if target["controller_evidence"] not in CONTROLLER_EVIDENCE:
            raise GauntletError(
                f"target {target_id} has unknown controller evidence state"
            )
        if target["bench_state"] not in BENCH_STATES:
            raise GauntletError(f"target {target_id} has unknown bench state")
        profile_id = target["stock_profile"]
        if profile_id is not None:
            if profile_id not in profiles:
                raise GauntletError(
                    f"target {target_id} cites unknown profile {profile_id}"
                )
            referenced_profiles.add(profile_id)
        targets[target_id] = target

    orphan_profiles = sorted(set(profiles) - referenced_profiles)
    if orphan_profiles:
        raise GauntletError(
            f"held profiles are not assigned to targets: {', '.join(orphan_profiles)}"
        )


def _profile_summary_matches(
    profile: Mapping[str, Any], summary: Mapping[str, Any]
) -> None:
    expected = {
        "model": profile["id"],
        "vendor": "canaan",
        "version": profile["firmware_version"],
        "soc_family": "K210",
        "asic_chip": profile["asic_family"],
        "source_sha256": profile["source_zip_sha256"],
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            raise GauntletError(
                f"profile {profile['id']} summary {key} mismatch: {summary.get(key)!r} != {value!r}"
            )
    aup = summary.get("aup", {})
    aup_expected = {
        "fmt_ver": 2,
        "firmware_ver": profile["firmware_version"],
        "hw_list": profile["hw_list"],
        "sw_list": profile["sw_list"],
        "payload_crc32": profile["payload_crc32"],
        "header_crc32": profile["header_crc32"],
        "k210_app_size": profile["k210_app_size"],
        "k210_sha256_trailer": profile["k210_sha256"],
        "header_crc_ok": True,
        "payload_crc_ok": True,
        "k210_sha256_ok": True,
        "aes_enable": 1,
    }
    for key, value in aup_expected.items():
        if aup.get(key) != value:
            raise GauntletError(
                f"profile {profile['id']} summary aup.{key} mismatch: {aup.get(key)!r} != {value!r}"
            )


def verify_runtime_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify tracked no_std and desk-only candidate-pipeline boundary files."""

    runtime = manifest["runtime_contract"]
    cargo_path = repo_root / runtime["crate"]
    source_path = cargo_path.parent / "src" / "lib.rs"
    safety_path = repo_root / runtime["safety_supervisor"]
    sentinel_path = repo_root / runtime["sentinel"]
    linker_path = repo_root / runtime["linker_script"]
    builder_path = repo_root / runtime["candidate_builder"]
    required_paths = {
        "Cargo manifest": cargo_path,
        "core source": source_path,
        "safety supervisor": safety_path,
        "sentinel source": sentinel_path,
        "linker script": linker_path,
        "candidate builder": builder_path,
    }
    for label, path in required_paths.items():
        if not path.is_file():
            raise GauntletError(f"runtime {label} is absent: {path}")
    try:
        cargo_text = cargo_path.read_text(encoding="utf-8")
        source_text = source_path.read_text(encoding="utf-8")
        safety_text = safety_path.read_text(encoding="utf-8")
        sentinel_text = sentinel_path.read_text(encoding="utf-8")
        linker_text = linker_path.read_text(encoding="utf-8")
        builder_text = builder_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"runtime boundary cannot be read: {exc}") from exc

    required_source_tokens = (
        "#![no_std]",
        "#![forbid(unsafe_code)]",
        f'pub const FREESTANDING_TARGET: &str = "{runtime["freestanding_target"]}";',
        "pub enum MutationDisposition",
    )
    for token in required_source_tokens:
        if token not in source_text:
            raise GauntletError(f"runtime core is missing boundary token {token!r}")
    if 'name = "dcent-avalon-k210-core"' not in cargo_text:
        raise GauntletError("runtime Cargo package identity drifted")
    boundary_tokens = (
        (source_text, "pub mod safety;", "core"),
        (safety_text, "pub struct SafetySupervisor", "safety supervisor"),
        (safety_text, "AwaitingIndependentReview", "safety supervisor"),
        (safety_text, "FaultLatched", "safety supervisor"),
        (safety_text, "IndependentCutoffNotAsserted", "safety supervisor"),
        (safety_text, "UnexpectedHashPower", "safety supervisor"),
        (sentinel_text, "#![no_std]", "sentinel"),
        (sentinel_text, "core::arch::global_asm!", "sentinel"),
        (linker_text, "ENTRY(_start)", "linker script"),
        (linker_text, "ORIGIN = 0x80000000", "linker script"),
        (builder_text, "inspect_k210_elf", "candidate builder"),
        (builder_text, "--experimental-aes0", "candidate builder"),
    )
    for text, token, label in boundary_tokens:
        if token not in text:
            raise GauntletError(f"runtime {label} is missing boundary token {token!r}")

    gate_ids = re.findall(r'Self::[A-Za-z0-9_]+\s*=>\s*"([a-z_]+)"', source_text)
    expected_gate_ids = [gate["id"] for gate in manifest["production_gates"]]
    if gate_ids != expected_gate_ids:
        raise GauntletError(
            f"runtime gate vocabulary drift: {gate_ids!r} != {expected_gate_ids!r}"
        )
    mutation_enum = re.search(
        r"pub enum MutationDisposition\s*\{(?P<body>.*?)\n\}", source_text, re.DOTALL
    )
    if mutation_enum is None or "Allow" in mutation_enum.group("body"):
        raise GauntletError(
            "runtime mutation disposition gained or obscured an allow path"
        )
    return {
        "state": "verified",
        "cargo_manifest": runtime["crate"],
        "source": str(Path(runtime["crate"]).parent / "src" / "lib.rs").replace(
            "\\", "/"
        ),
        "safety_supervisor": runtime["safety_supervisor"],
        "sentinel": runtime["sentinel"],
        "linker_script": runtime["linker_script"],
        "candidate_builder": runtime["candidate_builder"],
        "freestanding_target": runtime["freestanding_target"],
        "gate_ids": gate_ids,
        "mutation_allow_variant": False,
    }


def verify_discovery_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the local receipt schema boundary and optional pinned observer key."""

    contract = manifest["discovery_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"discovery verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"discovery verifier cannot be read: {exc}") from exc
    required_tokens = (
        "This tool has no miner transport.",
        "AUTHORITY_CEILING",
        "SIGNATURE_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(
                f"discovery verifier is missing boundary token {token!r}"
            )

    trust_anchor = contract["trust_anchor"]
    if trust_anchor is None:
        return {
            "state": "verified_schema_no_trust_anchor",
            "receipt_admission_enabled": False,
            "observer_key_id_sha256": None,
            "observer_key_path": None,
        }

    key_path = (repo_root / trust_anchor["path"]).resolve()
    if not key_path.is_relative_to(resolved_root):
        raise GauntletError("discovery trust anchor escaped the repository")
    try:
        key = discovery.inspect_public_key(key_path)
    except discovery.DiscoveryError as exc:
        raise GauntletError(f"discovery trust anchor is invalid: {exc}") from exc
    if key["key_id_sha256"] != trust_anchor["key_id_sha256"]:
        raise GauntletError("discovery trust-anchor key ID does not match its bytes")
    return {
        "state": "verified_pinned_observer_key",
        "receipt_admission_enabled": True,
        "observer_key_id_sha256": key["key_id_sha256"],
        "observer_key_path": trust_anchor["path"],
    }


def verify_discovery_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit signed bundles only through the manifest-pinned observer key."""

    validation = verify_discovery_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "discovery bundles cannot be admitted until an observer key is pinned in the manifest"
        )
    trust_anchor = manifest["discovery_contract"]["trust_anchor"]
    if not isinstance(trust_anchor, dict):
        raise GauntletError("discovery receipt admission lost its trust anchor")
    public_key = repo_root / trust_anchor["path"]
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    unit_fingerprints: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate discovery bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = discovery.verify_bundle(
                manifest,
                resolved_bundle,
                public_key,
                trust_anchor["key_id_sha256"],
            )
        except discovery.DiscoveryError as exc:
            raise GauntletError(
                f"discovery bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        if target_id in results:
            raise GauntletError(
                f"multiple discovery receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate discovery receipt ID")
        if result["unit_fingerprint_sha256"] in unit_fingerprints:
            raise GauntletError(
                "one exact-unit fingerprint was assigned to multiple target rows"
            )
        receipt_ids.add(result["receipt_id"])
        unit_fingerprints.add(result["unit_fingerprint_sha256"])
        results[target_id] = result
    return results


def verify_fixture_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the host-only fixture schema and optional pinned review keys."""

    contract = manifest["fixture_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"fixture verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"fixture verifier cannot be read: {exc}") from exc
    required_tokens = (
        "This tool is host-only",
        "AUTHORITY_CEILING",
        "OPERATOR_NAMESPACE",
        "REVIEWER_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(f"fixture verifier is missing boundary token {token!r}")

    anchors = contract["trust_anchors"]
    if anchors["operator"] is None and anchors["reviewer"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "operator_key_id_sha256": None,
            "operator_key_path": None,
            "reviewer_key_id_sha256": None,
            "reviewer_key_path": None,
        }

    observed: dict[str, dict[str, str]] = {}
    for name in ("operator", "reviewer"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"fixture {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(f"fixture {name} trust anchor escaped the repository")
        try:
            key = discovery.inspect_public_key(key_path)
        except discovery.DiscoveryError as exc:
            raise GauntletError(
                f"fixture {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"fixture {name} trust-anchor key ID does not match its bytes"
            )
        observed[name] = key
    if observed["operator"]["key_id_sha256"] == observed["reviewer"]["key_id_sha256"]:
        raise GauntletError("fixture trust keys are not role-separated")
    return {
        "state": "verified_pinned_operator_and_reviewer_keys",
        "receipt_admission_enabled": True,
        "operator_key_id_sha256": observed["operator"]["key_id_sha256"],
        "operator_key_path": anchors["operator"]["path"],
        "reviewer_key_id_sha256": observed["reviewer"]["key_id_sha256"],
        "reviewer_key_path": anchors["reviewer"]["path"],
    }


def verify_fixture_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit fixture proof only when it exact-joins admitted unit discovery."""

    validation = verify_fixture_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "fixture bundles cannot be admitted until operator and reviewer keys are pinned"
        )
    anchors = manifest["fixture_contract"]["trust_anchors"]
    operator_anchor = anchors["operator"]
    reviewer_anchor = anchors["reviewer"]
    if not isinstance(operator_anchor, dict) or not isinstance(reviewer_anchor, dict):
        raise GauntletError("fixture receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    evidence_sets: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate fixture bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = fixture.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / operator_anchor["path"],
                repo_root / reviewer_anchor["path"],
                operator_anchor["key_id_sha256"],
                reviewer_anchor["key_id_sha256"],
            )
        except (fixture.FixtureError, discovery.DiscoveryError) as exc:
            raise GauntletError(
                f"fixture bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        if discovered is None:
            raise GauntletError(
                f"fixture bundle for {target_id} has no admitted discovery receipt"
            )
        joins = {
            "discovery_receipt_id": "receipt_id",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "unit_label": "unit_label",
        }
        for fixture_key, discovery_key in joins.items():
            if result[fixture_key] != discovered[discovery_key]:
                raise GauntletError(
                    f"fixture bundle for {target_id} does not join discovery {fixture_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple fixture receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate fixture receipt ID")
        if result["fixture_evidence_set_sha256"] in evidence_sets:
            raise GauntletError("duplicate fixture evidence set")
        receipt_ids.add(result["receipt_id"])
        evidence_sets.add(result["fixture_evidence_set_sha256"])
        results[target_id] = result
    return results


def verify_capture_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the host-only P1 capture schema and optional pinned review keys."""

    contract = manifest["capture_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"capture verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"capture verifier cannot be read: {exc}") from exc
    required_tokens = (
        "This tool is host-only",
        "AUTHORITY_CEILING",
        "OPERATOR_NAMESPACE",
        "REVIEWER_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(f"capture verifier is missing boundary token {token!r}")
    anchors = contract["trust_anchors"]
    if anchors["operator"] is None and anchors["reviewer"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "operator_key_id_sha256": None,
            "operator_key_path": None,
            "reviewer_key_id_sha256": None,
            "reviewer_key_path": None,
        }
    observed: dict[str, dict[str, str]] = {}
    for name in ("operator", "reviewer"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"capture {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(f"capture {name} trust anchor escaped the repository")
        try:
            key = discovery.inspect_public_key(key_path)
        except discovery.DiscoveryError as exc:
            raise GauntletError(
                f"capture {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"capture {name} trust-anchor key ID does not match its bytes"
            )
        observed[name] = key
    if observed["operator"]["key_id_sha256"] == observed["reviewer"]["key_id_sha256"]:
        raise GauntletError("capture trust keys are not role-separated")
    return {
        "state": "verified_pinned_operator_and_reviewer_keys",
        "receipt_admission_enabled": True,
        "operator_key_id_sha256": observed["operator"]["key_id_sha256"],
        "operator_key_path": anchors["operator"]["path"],
        "reviewer_key_id_sha256": observed["reviewer"]["key_id_sha256"],
        "reviewer_key_path": anchors["reviewer"]["path"],
    }


def verify_capture_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    fixture_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit P1 captures only through exact discovery and fixture predecessors."""

    validation = verify_capture_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "capture bundles cannot be admitted until operator and reviewer keys are pinned"
        )
    anchors = manifest["capture_contract"]["trust_anchors"]
    operator_anchor = anchors["operator"]
    reviewer_anchor = anchors["reviewer"]
    if not isinstance(operator_anchor, dict) or not isinstance(reviewer_anchor, dict):
        raise GauntletError("capture receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    capture_sets: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate capture bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = capture.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / operator_anchor["path"],
                repo_root / reviewer_anchor["path"],
                operator_anchor["key_id_sha256"],
                reviewer_anchor["key_id_sha256"],
            )
        except (
            capture.CaptureReceiptError,
            fixture.FixtureError,
            discovery.DiscoveryError,
        ) as exc:
            raise GauntletError(
                f"capture bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        qualified = fixture_results.get(target_id)
        if discovered is None or qualified is None:
            raise GauntletError(
                f"capture bundle for {target_id} lacks admitted discovery or fixture proof"
            )
        discovery_joins = {
            "discovery_receipt_id": "receipt_id",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "unit_label": "unit_label",
            "variant_profile_id": "variant_profile_id",
        }
        for capture_key, discovery_key in discovery_joins.items():
            if result[capture_key] != discovered[discovery_key]:
                raise GauntletError(
                    f"capture bundle for {target_id} does not join discovery {capture_key}"
                )
        fixture_joins = {
            "fixture_evidence_set_sha256": "fixture_evidence_set_sha256",
            "fixture_receipt_id": "receipt_id",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "variant_profile_id": "variant_profile_id",
        }
        for capture_key, fixture_key in fixture_joins.items():
            if result[capture_key] != qualified[fixture_key]:
                raise GauntletError(
                    f"capture bundle for {target_id} does not join fixture {capture_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple capture receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate capture receipt ID")
        if result["capture_set_sha256"] in capture_sets:
            raise GauntletError("duplicate capture evidence set")
        receipt_ids.add(result["receipt_id"])
        capture_sets.add(result["capture_set_sha256"])
        results[target_id] = result
    return results


def verify_recovery_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the local dual-signature recovery schema and optional trust keys."""

    contract = manifest["recovery_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"recovery verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"recovery verifier cannot be read: {exc}") from exc
    required_tokens = (
        "This tool is host-only",
        "AUTHORITY_CEILING",
        "OPERATOR_NAMESPACE",
        "WITNESS_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(
                f"recovery verifier is missing boundary token {token!r}"
            )

    anchors = contract["trust_anchors"]
    if anchors["operator"] is None and anchors["witness"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "operator_key_id_sha256": None,
            "operator_key_path": None,
            "witness_key_id_sha256": None,
            "witness_key_path": None,
        }

    observed: dict[str, dict[str, str]] = {}
    for name in ("operator", "witness"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"recovery {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(f"recovery {name} trust anchor escaped the repository")
        try:
            key = recovery.discovery.inspect_public_key(key_path)
        except recovery.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"recovery {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"recovery {name} trust-anchor key ID does not match its bytes"
            )
        observed[name] = key
    if observed["operator"]["key_id_sha256"] == observed["witness"]["key_id_sha256"]:
        raise GauntletError("recovery trust keys are not role-separated")
    return {
        "state": "verified_pinned_operator_and_witness_keys",
        "receipt_admission_enabled": True,
        "operator_key_id_sha256": observed["operator"]["key_id_sha256"],
        "operator_key_path": anchors["operator"]["path"],
        "witness_key_id_sha256": observed["witness"]["key_id_sha256"],
        "witness_key_path": anchors["witness"]["path"],
    }


def verify_recovery_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit recovery proof only when it exact-joins admitted unit discovery."""

    validation = verify_recovery_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "recovery bundles cannot be admitted until operator and witness keys are pinned"
        )
    anchors = manifest["recovery_contract"]["trust_anchors"]
    operator_anchor = anchors["operator"]
    witness_anchor = anchors["witness"]
    if not isinstance(operator_anchor, dict) or not isinstance(witness_anchor, dict):
        raise GauntletError("recovery receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    backup_sets: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate recovery bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = recovery.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / operator_anchor["path"],
                repo_root / witness_anchor["path"],
                operator_anchor["key_id_sha256"],
                witness_anchor["key_id_sha256"],
            )
        except (
            recovery.RecoveryError,
            recovery.discovery.DiscoveryError,
        ) as exc:
            raise GauntletError(
                f"recovery bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        if discovered is None:
            raise GauntletError(
                f"recovery bundle for {target_id} has no admitted discovery receipt"
            )
        joins = {
            "discovery_receipt_id": "receipt_id",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "unit_label": "unit_label",
        }
        for recovery_key, discovery_key in joins.items():
            if result[recovery_key] != discovered[discovery_key]:
                raise GauntletError(
                    f"recovery bundle for {target_id} does not join discovery {recovery_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple recovery receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate recovery receipt ID")
        if result["stock_backup_set_sha256"] in backup_sets:
            raise GauntletError("one stock backup set was assigned to multiple targets")
        receipt_ids.add(result["receipt_id"])
        backup_sets.add(result["stock_backup_set_sha256"])
        results[target_id] = result
    return results


def verify_boot_policy_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the local dual-signature measurement schema and trust keys."""

    contract = manifest["boot_policy_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"boot-policy verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"boot-policy verifier cannot be read: {exc}") from exc
    required_tokens = (
        "This tool is host-only",
        "AUTHORITY_CEILING",
        "OPERATOR_NAMESPACE",
        "WITNESS_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(
                f"boot-policy verifier is missing boundary token {token!r}"
            )

    anchors = contract["trust_anchors"]
    if anchors["operator"] is None and anchors["witness"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "operator_key_id_sha256": None,
            "operator_key_path": None,
            "witness_key_id_sha256": None,
            "witness_key_path": None,
        }

    observed: dict[str, dict[str, str]] = {}
    for name in ("operator", "witness"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"boot-policy {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(
                f"boot-policy {name} trust anchor escaped the repository"
            )
        try:
            key = boot_policy.discovery.inspect_public_key(key_path)
        except boot_policy.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"boot-policy {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"boot-policy {name} trust-anchor key ID does not match its bytes"
            )
        observed[name] = key
    if observed["operator"]["key_id_sha256"] == observed["witness"]["key_id_sha256"]:
        raise GauntletError("boot-policy trust keys are not role-separated")
    return {
        "state": "verified_pinned_operator_and_witness_keys",
        "receipt_admission_enabled": True,
        "operator_key_id_sha256": observed["operator"]["key_id_sha256"],
        "operator_key_path": anchors["operator"]["path"],
        "witness_key_id_sha256": observed["witness"]["key_id_sha256"],
        "witness_key_path": anchors["witness"]["path"],
    }


def verify_boot_policy_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    recovery_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit a measurement only when it exact-joins discovery and recovery."""

    validation = verify_boot_policy_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "boot-policy bundles cannot be admitted until operator and witness keys are pinned"
        )
    anchors = manifest["boot_policy_contract"]["trust_anchors"]
    operator_anchor = anchors["operator"]
    witness_anchor = anchors["witness"]
    if not isinstance(operator_anchor, dict) or not isinstance(witness_anchor, dict):
        raise GauntletError("boot-policy receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate boot-policy bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = boot_policy.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / operator_anchor["path"],
                repo_root / witness_anchor["path"],
                operator_anchor["key_id_sha256"],
                witness_anchor["key_id_sha256"],
            )
        except (
            boot_policy.BootPolicyError,
            boot_policy.recovery.RecoveryError,
            boot_policy.discovery.DiscoveryError,
        ) as exc:
            raise GauntletError(
                f"boot-policy bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        recovered = recovery_results.get(target_id)
        if discovered is None:
            raise GauntletError(
                f"boot-policy bundle for {target_id} has no admitted discovery receipt"
            )
        if recovered is None:
            raise GauntletError(
                f"boot-policy bundle for {target_id} has no admitted recovery receipt"
            )
        discovery_joins = {
            "discovery_receipt_id": "receipt_id",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "unit_label": "unit_label",
        }
        for boot_key, discovery_key in discovery_joins.items():
            if result[boot_key] != discovered[discovery_key]:
                raise GauntletError(
                    f"boot-policy bundle for {target_id} does not join discovery {boot_key}"
                )
        recovery_joins = {
            "recovery_receipt_id": "receipt_id",
            "stock_backup_set_sha256": "stock_backup_set_sha256",
            "unit_fingerprint_sha256": "unit_fingerprint_sha256",
            "unit_label": "unit_label",
        }
        for boot_key, recovery_key in recovery_joins.items():
            if result[boot_key] != recovered[recovery_key]:
                raise GauntletError(
                    f"boot-policy bundle for {target_id} does not join recovery {boot_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple boot-policy receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate boot-policy receipt ID")
        receipt_ids.add(result["receipt_id"])
        results[target_id] = result
    return results


def verify_replacement_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the replacement-artifact schema and optional role trust keys."""

    contract = manifest["replacement_firmware_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"replacement-firmware verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(
            f"replacement-firmware verifier cannot be read: {exc}"
        ) from exc
    required_tokens = (
        "host-only successor",
        "AUTHORITY_CEILING",
        "BUILDER_NAMESPACE",
        "REVIEWER_NAMESPACE",
        "def verify_bundle(",
    )
    for token in required_tokens:
        if token not in verifier_text:
            raise GauntletError(
                f"replacement-firmware verifier is missing boundary token {token!r}"
            )
    anchors = contract["trust_anchors"]
    if anchors["builder"] is None and anchors["reviewer"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "builder_key_id_sha256": None,
            "builder_key_path": None,
            "reviewer_key_id_sha256": None,
            "reviewer_key_path": None,
        }
    observed: dict[str, dict[str, str]] = {}
    for name in ("builder", "reviewer"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"replacement-firmware {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(
                f"replacement-firmware {name} trust anchor escaped the repository"
            )
        try:
            key = replacement.discovery.inspect_public_key(key_path)
        except replacement.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"replacement-firmware {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"replacement-firmware {name} trust-anchor ID does not match its bytes"
            )
        observed[name] = key
    if observed["builder"]["key_id_sha256"] == observed["reviewer"]["key_id_sha256"]:
        raise GauntletError("replacement-firmware trust keys are not role-separated")
    return {
        "state": "verified_pinned_builder_and_reviewer_keys",
        "receipt_admission_enabled": True,
        "builder_key_id_sha256": observed["builder"]["key_id_sha256"],
        "builder_key_path": anchors["builder"]["path"],
        "reviewer_key_id_sha256": observed["reviewer"]["key_id_sha256"],
        "reviewer_key_path": anchors["reviewer"]["path"],
    }


def verify_replacement_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    recovery_results: Mapping[str, Mapping[str, Any]],
    boot_policy_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit a reproducible artifact only through all exact-unit predecessors."""

    validation = verify_replacement_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "replacement bundles cannot be admitted until builder and reviewer keys are pinned"
        )
    anchors = manifest["replacement_firmware_contract"]["trust_anchors"]
    builder_anchor = anchors["builder"]
    reviewer_anchor = anchors["reviewer"]
    if not isinstance(builder_anchor, dict) or not isinstance(reviewer_anchor, dict):
        raise GauntletError("replacement receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate replacement bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = replacement.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / builder_anchor["path"],
                repo_root / reviewer_anchor["path"],
                builder_anchor["key_id_sha256"],
                reviewer_anchor["key_id_sha256"],
            )
        except (
            replacement.RouteReplacementError,
            replacement.boot.BootPolicyError,
            replacement.recovery.RecoveryError,
            replacement.discovery.DiscoveryError,
        ) as exc:
            raise GauntletError(
                f"replacement bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        recovered = recovery_results.get(target_id)
        measured = boot_policy_results.get(target_id)
        if discovered is None or recovered is None or measured is None:
            raise GauntletError(
                f"replacement bundle for {target_id} lacks an admitted predecessor receipt"
            )
        joins = (
            ("discovery_receipt_id", discovered, "receipt_id"),
            ("recovery_receipt_id", recovered, "receipt_id"),
            ("boot_policy_receipt_id", measured, "receipt_id"),
            ("stock_backup_set_sha256", recovered, "stock_backup_set_sha256"),
            ("unit_fingerprint_sha256", discovered, "unit_fingerprint_sha256"),
            ("unit_label", discovered, "unit_label"),
        )
        for replacement_key, predecessor, predecessor_key in joins:
            if result[replacement_key] != predecessor[predecessor_key]:
                raise GauntletError(
                    f"replacement bundle for {target_id} does not join {replacement_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple replacement receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate replacement receipt ID")
        receipt_ids.add(result["receipt_id"])
        results[target_id] = result
    return results


def verify_rollback_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the exact-route rollback schema and optional role trust keys."""

    contract = manifest["rollback_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"rollback verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"rollback verifier cannot be read: {exc}") from exc
    for token in (
        "schema-2 host-only tool",
        "AUTHORITY_CEILING",
        "OPERATOR_NAMESPACE",
        "WITNESS_NAMESPACE",
        "def verify_bundle(",
    ):
        if token not in verifier_text:
            raise GauntletError(
                f"rollback verifier is missing boundary token {token!r}"
            )
    anchors = contract["trust_anchors"]
    if anchors["operator"] is None and anchors["witness"] is None:
        return {
            "state": "verified_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "operator_key_id_sha256": None,
            "operator_key_path": None,
            "witness_key_id_sha256": None,
            "witness_key_path": None,
        }
    observed: dict[str, dict[str, str]] = {}
    for name in ("operator", "witness"):
        anchor = anchors[name]
        if not isinstance(anchor, dict):
            raise GauntletError(f"rollback {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(f"rollback {name} trust anchor escaped the repository")
        try:
            key = rollback.discovery.inspect_public_key(key_path)
        except rollback.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"rollback {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"rollback {name} trust-anchor ID does not match its bytes"
            )
        observed[name] = key
    if observed["operator"]["key_id_sha256"] == observed["witness"]["key_id_sha256"]:
        raise GauntletError("rollback trust keys are not role-separated")
    return {
        "state": "verified_pinned_operator_and_witness_keys",
        "receipt_admission_enabled": True,
        "operator_key_id_sha256": observed["operator"]["key_id_sha256"],
        "operator_key_path": anchors["operator"]["path"],
        "witness_key_id_sha256": observed["witness"]["key_id_sha256"],
        "witness_key_path": anchors["witness"]["path"],
    }


def verify_rollback_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    recovery_results: Mapping[str, Mapping[str, Any]],
    boot_policy_results: Mapping[str, Mapping[str, Any]],
    replacement_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit rollback proof only through its exact-unit predecessor chain."""

    validation = verify_rollback_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "rollback bundles cannot be admitted until operator and witness keys are pinned"
        )
    anchors = manifest["rollback_contract"]["trust_anchors"]
    operator_anchor = anchors["operator"]
    witness_anchor = anchors["witness"]
    if not isinstance(operator_anchor, dict) or not isinstance(witness_anchor, dict):
        raise GauntletError("rollback receipt admission lost its trust anchors")
    results: Dict[str, Dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    restoration_sets: set[str] = set()
    bundle_paths: set[Path] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate rollback bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = rollback.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / operator_anchor["path"],
                repo_root / witness_anchor["path"],
                operator_anchor["key_id_sha256"],
                witness_anchor["key_id_sha256"],
            )
        except (
            rollback.RouteRollbackError,
            rollback.route_replacement.RouteReplacementError,
            rollback.boot.BootPolicyError,
            rollback.recovery.RecoveryError,
            rollback.discovery.DiscoveryError,
        ) as exc:
            raise GauntletError(
                f"rollback bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        discovered = discovery_results.get(target_id)
        recovered = recovery_results.get(target_id)
        measured = boot_policy_results.get(target_id)
        replaced = replacement_results.get(target_id)
        if any(
            predecessor is None
            for predecessor in (discovered, recovered, measured, replaced)
        ):
            raise GauntletError(
                f"rollback bundle for {target_id} lacks an admitted predecessor receipt"
            )
        joins = (
            ("discovery_receipt_id", discovered, "receipt_id"),
            ("recovery_receipt_id", recovered, "receipt_id"),
            ("boot_policy_receipt_id", measured, "receipt_id"),
            ("route_replacement_receipt_id", replaced, "receipt_id"),
            ("stock_backup_set_sha256", recovered, "stock_backup_set_sha256"),
            ("unit_fingerprint_sha256", discovered, "unit_fingerprint_sha256"),
            ("unit_label", discovered, "unit_label"),
        )
        for rollback_key, predecessor, predecessor_key in joins:
            if result[rollback_key] != predecessor[predecessor_key]:
                raise GauntletError(
                    f"rollback bundle for {target_id} does not join {rollback_key}"
                )
        for result_key, replacement_key in (
            ("artifact_set_sha256", "artifact_set_sha256"),
            ("interface_qualification_sha256", "interface_qualification_sha256"),
            ("route_adjudication_sha256", "route_adjudication_sha256"),
            ("selected_route", "selected_route"),
        ):
            if result[result_key] != replaced[replacement_key]:
                raise GauntletError(
                    f"rollback bundle for {target_id} does not join {result_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple rollback receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate rollback receipt ID")
        if result["stock_restoration_sha256"] in restoration_sets:
            raise GauntletError("duplicate rollback stock-restoration set")
        receipt_ids.add(result["receipt_id"])
        restoration_sets.add(result["stock_restoration_sha256"])
        results[target_id] = result
    return results


def verify_bench_endurance_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the three-stage schema and all optional role trust keys."""

    contract = manifest["bench_endurance_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"bench/endurance verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"bench/endurance verifier cannot be read: {exc}") from exc
    for token in (
        "This tool is host-only",
        "AUTHORITY_CEILING",
        "SIGNING_CONTRACTS",
        "QUALIFICATION_FIRST_LIGHT",
        "QUALIFICATION_BENCH",
        "QUALIFICATION_ENDURANCE",
        "def verify_bundle(",
    ):
        if token not in verifier_text:
            raise GauntletError(
                f"bench/endurance verifier is missing boundary token {token!r}"
            )
    anchors = contract["trust_anchors"]
    if all(anchor is None for anchor in anchors.values()):
        return {
            "state": "verified_multi_stage_schema_no_trust_anchors",
            "receipt_admission_enabled": False,
            "trust_anchor_key_ids_sha256": {name: None for name in anchors},
            "trust_anchor_paths": {name: None for name in anchors},
        }
    observed: Dict[str, Dict[str, str]] = {}
    for name, anchor in anchors.items():
        if not isinstance(anchor, dict):
            raise GauntletError(f"bench/endurance {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(
                f"bench/endurance {name} trust anchor escaped the repository"
            )
        try:
            key = bench_endurance.discovery.inspect_public_key(key_path)
        except bench_endurance.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"bench/endurance {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"bench/endurance {name} trust-anchor ID does not match its bytes"
            )
        observed[name] = key
    if len({item["key_id_sha256"] for item in observed.values()}) != len(observed):
        raise GauntletError("bench/endurance trust keys are not role-separated")
    return {
        "state": "verified_pinned_multi_stage_keys",
        "receipt_admission_enabled": True,
        "trust_anchor_key_ids_sha256": {
            name: item["key_id_sha256"] for name, item in observed.items()
        },
        "trust_anchor_paths": {name: anchors[name]["path"] for name in anchors},
    }


def verify_bench_endurance_bundles(
    manifest: Mapping[str, Any],
    first_light_bundles: Sequence[Path],
    bench_bundles: Sequence[Path],
    endurance_bundles: Sequence[Path],
    discovery_results: Mapping[str, Mapping[str, Any]],
    fixture_results: Mapping[str, Mapping[str, Any]],
    capture_results: Mapping[str, Mapping[str, Any]],
    recovery_results: Mapping[str, Mapping[str, Any]],
    boot_policy_results: Mapping[str, Mapping[str, Any]],
    replacement_results: Mapping[str, Mapping[str, Any]],
    rollback_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Admit each immutable stage only through its complete predecessor chain."""

    validation = verify_bench_endurance_contract(manifest, repo_root)
    by_class: Dict[str, Dict[str, Dict[str, Any]]] = {
        bench_endurance.QUALIFICATION_FIRST_LIGHT: {},
        bench_endurance.QUALIFICATION_BENCH: {},
        bench_endurance.QUALIFICATION_ENDURANCE: {},
    }
    supplied = (
        (bench_endurance.QUALIFICATION_FIRST_LIGHT, first_light_bundles),
        (bench_endurance.QUALIFICATION_BENCH, bench_bundles),
        (bench_endurance.QUALIFICATION_ENDURANCE, endurance_bundles),
    )
    if not any(bundles for _, bundles in supplied):
        return by_class
    if not validation["receipt_admission_enabled"]:
        raise GauntletError(
            "bench/endurance bundles cannot be admitted until all seven stage keys are pinned"
        )
    anchors = manifest["bench_endurance_contract"]["trust_anchors"]
    stage_anchor_names = {
        bench_endurance.QUALIFICATION_FIRST_LIGHT: {
            "operator": "first_light_operator",
            "protocol_reviewer": "first_light_protocol_reviewer",
            "safety_reviewer": "first_light_safety_reviewer",
        },
        bench_endurance.QUALIFICATION_BENCH: {
            "operator": "bench_operator",
            "witness": "bench_witness",
        },
        bench_endurance.QUALIFICATION_ENDURANCE: {
            "operator": "endurance_operator",
            "witness": "endurance_witness",
        },
    }
    bundle_paths: set[Path] = set()
    receipt_ids: set[str] = set()
    evidence_sets: set[str] = set()
    for qualification_class, bundles in supplied:
        for bundle in bundles:
            resolved_bundle = bundle.resolve()
            if resolved_bundle in bundle_paths:
                raise GauntletError(f"duplicate bench/endurance bundle path: {bundle}")
            bundle_paths.add(resolved_bundle)
            names = stage_anchor_names[qualification_class]
            operator_anchor = anchors[names["operator"]]
            if not isinstance(operator_anchor, dict):
                raise GauntletError("bench/endurance operator trust anchor is absent")
            try:
                if qualification_class == bench_endurance.QUALIFICATION_FIRST_LIGHT:
                    protocol_anchor = anchors[names["protocol_reviewer"]]
                    safety_anchor = anchors[names["safety_reviewer"]]
                    if not isinstance(protocol_anchor, dict) or not isinstance(
                        safety_anchor, dict
                    ):
                        raise GauntletError(
                            "first-light reviewer trust anchors are absent"
                        )
                    result = bench_endurance.verify_bundle(
                        manifest,
                        resolved_bundle,
                        repo_root / operator_anchor["path"],
                        expected_operator_key_id=operator_anchor["key_id_sha256"],
                        protocol_reviewer_public_key=(
                            repo_root / protocol_anchor["path"]
                        ),
                        safety_reviewer_public_key=repo_root / safety_anchor["path"],
                        expected_protocol_reviewer_key_id=protocol_anchor[
                            "key_id_sha256"
                        ],
                        expected_safety_reviewer_key_id=safety_anchor["key_id_sha256"],
                    )
                else:
                    witness_anchor = anchors[names["witness"]]
                    if not isinstance(witness_anchor, dict):
                        raise GauntletError(
                            "bench/endurance witness trust anchor is absent"
                        )
                    result = bench_endurance.verify_bundle(
                        manifest,
                        resolved_bundle,
                        repo_root / operator_anchor["path"],
                        repo_root / witness_anchor["path"],
                        operator_anchor["key_id_sha256"],
                        witness_anchor["key_id_sha256"],
                    )
            except bench_endurance.BenchEnduranceError as exc:
                raise GauntletError(
                    f"{qualification_class} bundle {bundle} is inadmissible: {exc}"
                ) from exc
            if result["qualification_class"] != qualification_class:
                raise GauntletError(
                    f"{qualification_class} option received a {result['qualification_class']} bundle"
                )
            target_id = result["target_id"]
            predecessors = {
                "discovery": discovery_results.get(target_id),
                "fixture": fixture_results.get(target_id),
                "capture": capture_results.get(target_id),
                "recovery": recovery_results.get(target_id),
                "boot_policy": boot_policy_results.get(target_id),
                "replacement": replacement_results.get(target_id),
                "rollback": rollback_results.get(target_id),
            }
            if any(item is None for item in predecessors.values()):
                raise GauntletError(
                    f"{qualification_class} bundle for {target_id} lacks an admitted predecessor receipt"
                )
            joins = (
                ("discovery_receipt_id", "discovery", "receipt_id"),
                ("unit_fingerprint_sha256", "discovery", "unit_fingerprint_sha256"),
                ("unit_label", "discovery", "unit_label"),
                ("fixture_receipt_id", "fixture", "receipt_id"),
                (
                    "fixture_evidence_set_sha256",
                    "fixture",
                    "fixture_evidence_set_sha256",
                ),
                ("controller_board_revision", "fixture", "controller_board_revision"),
                ("variant_profile_id", "fixture", "variant_profile_id"),
                ("capture_receipt_id", "capture", "receipt_id"),
                ("capture_set_sha256", "capture", "capture_set_sha256"),
                ("recovery_receipt_id", "recovery", "receipt_id"),
                ("stock_backup_set_sha256", "recovery", "stock_backup_set_sha256"),
                ("boot_policy_receipt_id", "boot_policy", "receipt_id"),
                ("route_replacement_receipt_id", "replacement", "receipt_id"),
                ("artifact_set_sha256", "replacement", "artifact_set_sha256"),
                (
                    "installed_artifact_sha256",
                    "replacement",
                    "installed_artifact_sha256",
                ),
                (
                    "interface_qualification_sha256",
                    "replacement",
                    "interface_qualification_sha256",
                ),
                (
                    "route_adjudication_sha256",
                    "replacement",
                    "route_adjudication_sha256",
                ),
                ("selected_route", "replacement", "selected_route"),
                (
                    "replacement_firmware_version",
                    "replacement",
                    "replacement_firmware_version",
                ),
                ("route_rollback_receipt_id", "rollback", "receipt_id"),
                ("no_clobber_sha256", "rollback", "no_clobber_sha256"),
                ("stock_restoration_sha256", "rollback", "stock_restoration_sha256"),
            )
            for result_key, predecessor_name, predecessor_key in joins:
                predecessor = predecessors[predecessor_name]
                if result[result_key] != predecessor[predecessor_key]:
                    raise GauntletError(
                        f"{qualification_class} bundle for {target_id} does not join {result_key}"
                    )
            if qualification_class == bench_endurance.QUALIFICATION_FIRST_LIGHT:
                if (
                    result["prior_stage_receipt_id"] is not None
                    or result["prior_stage_evidence_set_sha256"] is not None
                ):
                    raise GauntletError(
                        "first-light bundle has an unexpected prior stage"
                    )
            else:
                prior_class = (
                    bench_endurance.QUALIFICATION_FIRST_LIGHT
                    if qualification_class == bench_endurance.QUALIFICATION_BENCH
                    else bench_endurance.QUALIFICATION_BENCH
                )
                prior = by_class[prior_class].get(target_id)
                if prior is None:
                    raise GauntletError(
                        f"{qualification_class} bundle for {target_id} lacks its admitted prior stage"
                    )
                if (
                    result["prior_stage_receipt_id"] != prior["receipt_id"]
                    or result["prior_stage_evidence_set_sha256"]
                    != prior["evidence_set_sha256"]
                ):
                    raise GauntletError(
                        f"{qualification_class} bundle for {target_id} does not exact-join its prior stage"
                    )
            if target_id in by_class[qualification_class]:
                raise GauntletError(
                    f"multiple {qualification_class} receipts were supplied for target {target_id}"
                )
            if result["receipt_id"] in receipt_ids:
                raise GauntletError("duplicate bench/endurance receipt ID")
            if result["evidence_set_sha256"] in evidence_sets:
                raise GauntletError("duplicate bench/endurance evidence set")
            receipt_ids.add(result["receipt_id"])
            evidence_sets.add(result["evidence_set_sha256"])
            by_class[qualification_class][target_id] = result
    return by_class


def verify_release_contract(
    manifest: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> Dict[str, Any]:
    """Verify the two-phase release schema and four optional trust keys."""

    contract = manifest["release_contract"]
    verifier_path = (repo_root / contract["verifier"]).resolve()
    resolved_root = repo_root.resolve()
    if not verifier_path.is_relative_to(resolved_root) or not verifier_path.is_file():
        raise GauntletError(
            f"release verifier is absent or escaped the repository: {verifier_path}"
        )
    try:
        verifier_text = verifier_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GauntletError(f"release verifier cannot be read: {exc}") from exc
    for token in (
        "host-only evidence tool",
        "PREAUTHORITY_CEILING",
        "AUTHORITY_CEILING",
        "PREAUTHORIZER_NAMESPACE",
        "REVIEWER_NAMESPACE",
        "INSTALLER_NAMESPACE",
        "WITNESS_NAMESPACE",
        "def verify_preauthorization(",
        "def verify_bundle(",
    ):
        if token not in verifier_text:
            raise GauntletError(f"release verifier is missing boundary token {token!r}")
    anchors = contract["trust_anchors"]
    if all(anchor is None for anchor in anchors.values()):
        return {
            "state": "verified_two_phase_schema_no_trust_anchors",
            "preauthorization_admission_enabled": False,
            "release_admission_enabled": False,
            "trust_anchor_key_ids_sha256": {name: None for name in anchors},
            "trust_anchor_paths": {name: None for name in anchors},
        }
    observed: Dict[str, Dict[str, str]] = {}
    for name, anchor in anchors.items():
        if not isinstance(anchor, dict):
            raise GauntletError(f"release {name} trust anchor is absent")
        key_path = (repo_root / anchor["path"]).resolve()
        if not key_path.is_relative_to(resolved_root):
            raise GauntletError(f"release {name} trust anchor escaped the repository")
        try:
            key = release.discovery.inspect_public_key(key_path)
        except release.discovery.DiscoveryError as exc:
            raise GauntletError(
                f"release {name} trust anchor is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != anchor["key_id_sha256"]:
            raise GauntletError(
                f"release {name} trust-anchor ID does not match its bytes"
            )
        observed[name] = key
    if len({item["key_id_sha256"] for item in observed.values()}) != len(observed):
        raise GauntletError("release trust keys are not role-separated")
    return {
        "state": "verified_pinned_two_phase_release_keys",
        "preauthorization_admission_enabled": True,
        "release_admission_enabled": True,
        "trust_anchor_key_ids_sha256": {
            name: item["key_id_sha256"] for name, item in observed.items()
        },
        "trust_anchor_paths": {name: anchors[name]["path"] for name in anchors},
    }


def verify_release_preauthorization_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    endurance_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit exact-scope authority only after a passing endurance chain exists."""

    validation = verify_release_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["preauthorization_admission_enabled"]:
        raise GauntletError(
            "release preauthorization bundles cannot be admitted until all four release keys are pinned"
        )
    anchors = manifest["release_contract"]["trust_anchors"]
    preauthorizer_anchor = anchors["preauthorizer"]
    reviewer_anchor = anchors["reviewer"]
    if not isinstance(preauthorizer_anchor, dict) or not isinstance(
        reviewer_anchor, dict
    ):
        raise GauntletError("release preauthorization trust anchors are absent")
    results: Dict[str, Dict[str, Any]] = {}
    bundle_paths: set[Path] = set()
    preauthorization_ids: set[str] = set()
    scope_digests: set[str] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(
                f"duplicate release preauthorization bundle path: {bundle}"
            )
        bundle_paths.add(resolved_bundle)
        try:
            result = release.verify_preauthorization(
                resolved_bundle,
                repo_root / preauthorizer_anchor["path"],
                repo_root / reviewer_anchor["path"],
                preauthorizer_anchor["key_id_sha256"],
                reviewer_anchor["key_id_sha256"],
            )
        except release.ReleaseError as exc:
            raise GauntletError(
                f"release preauthorization bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        endured = endurance_results.get(target_id)
        if endured is None:
            raise GauntletError(
                f"release preauthorization for {target_id} lacks an admitted endurance receipt"
            )
        if (
            result.get("state") != "verified_exact_scope_preauthorization"
            or result.get("install_authority_scope_eligible") is not True
            or result.get("authority_granted") is not False
            or result.get("generic_future_authority_granted") is not False
        ):
            raise GauntletError(
                f"release preauthorization for {target_id} is not scope-eligible"
            )
        joins = (
            ("target_id", "target_id"),
            ("unit_fingerprint_sha256", "unit_fingerprint_sha256"),
            ("unit_label", "unit_label"),
            ("variant_profile_id", "variant_profile_id"),
            ("hardware_revision", "controller_board_revision"),
            ("endurance_receipt_id", "receipt_id"),
            ("endurance_evidence_set_sha256", "evidence_set_sha256"),
            ("artifact_set_sha256", "artifact_set_sha256"),
            ("installed_artifact_sha256", "installed_artifact_sha256"),
            ("interface_qualification_sha256", "interface_qualification_sha256"),
            ("no_clobber_sha256", "no_clobber_sha256"),
            ("route_replacement_receipt_id", "route_replacement_receipt_id"),
            ("route_adjudication_sha256", "route_adjudication_sha256"),
            ("selected_route", "selected_route"),
            ("firmware_version", "replacement_firmware_version"),
        )
        for result_key, endurance_key in joins:
            if result[result_key] != endured[endurance_key]:
                raise GauntletError(
                    f"release preauthorization for {target_id} does not join {result_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple release preauthorizations were supplied for target {target_id}"
            )
        if result["preauthorization_id"] in preauthorization_ids:
            raise GauntletError("duplicate release preauthorization ID")
        if result["release_scope_sha256"] in scope_digests:
            raise GauntletError("duplicate release scope digest")
        preauthorization_ids.add(result["preauthorization_id"])
        scope_digests.add(result["release_scope_sha256"])
        results[target_id] = result
    return results


def verify_release_bundles(
    manifest: Mapping[str, Any],
    bundles: Sequence[Path],
    preauthorization_results: Mapping[str, Mapping[str, Any]],
    endurance_results: Mapping[str, Mapping[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, Any]]:
    """Admit a final release only through its prior signed exact scope and stage."""

    validation = verify_release_contract(manifest, repo_root)
    if not bundles:
        return {}
    if not validation["release_admission_enabled"]:
        raise GauntletError(
            "release bundles cannot be admitted until all four release keys are pinned"
        )
    anchors = manifest["release_contract"]["trust_anchors"]
    stage_anchors = manifest["bench_endurance_contract"]["trust_anchors"]
    required_anchors = {
        "preauthorizer": anchors["preauthorizer"],
        "reviewer": anchors["reviewer"],
        "installer": anchors["installer"],
        "witness": anchors["witness"],
        "endurance_operator": stage_anchors["endurance_operator"],
        "endurance_witness": stage_anchors["endurance_witness"],
    }
    if any(not isinstance(anchor, dict) for anchor in required_anchors.values()):
        raise GauntletError(
            "release admission is missing a release or endurance trust anchor"
        )
    results: Dict[str, Dict[str, Any]] = {}
    bundle_paths: set[Path] = set()
    receipt_ids: set[str] = set()
    evidence_sets: set[str] = set()
    for bundle in bundles:
        resolved_bundle = bundle.resolve()
        if resolved_bundle in bundle_paths:
            raise GauntletError(f"duplicate release bundle path: {bundle}")
        bundle_paths.add(resolved_bundle)
        try:
            result = release.verify_bundle(
                manifest,
                resolved_bundle,
                repo_root / required_anchors["preauthorizer"]["path"],
                repo_root / required_anchors["reviewer"]["path"],
                repo_root / required_anchors["endurance_operator"]["path"],
                repo_root / required_anchors["endurance_witness"]["path"],
                repo_root / required_anchors["installer"]["path"],
                repo_root / required_anchors["witness"]["path"],
                required_anchors["preauthorizer"]["key_id_sha256"],
                required_anchors["reviewer"]["key_id_sha256"],
                required_anchors["endurance_operator"]["key_id_sha256"],
                required_anchors["endurance_witness"]["key_id_sha256"],
                required_anchors["installer"]["key_id_sha256"],
                required_anchors["witness"]["key_id_sha256"],
            )
        except release.ReleaseError as exc:
            raise GauntletError(
                f"release bundle {bundle} is inadmissible: {exc}"
            ) from exc
        target_id = result["target_id"]
        preauthorized = preauthorization_results.get(target_id)
        endured = endurance_results.get(target_id)
        if preauthorized is None or endured is None:
            raise GauntletError(
                f"release bundle for {target_id} lacks its admitted preauthorization or endurance receipt"
            )
        if (
            result.get("state") != "verified_exact_scope_release_capstone"
            or result.get("release_authority_gate_eligible") is not True
            or result.get("exact_scope_release_admitted") is not True
            or result.get("authority_granted") is not False
            or result.get("generic_future_authority_granted") is not False
            or result.get("preauthorization_id")
            != preauthorized.get("preauthorization_id")
            or result.get("preauthorization_sha256")
            != preauthorized.get("preauthorization_sha256")
            or result.get("release_scope_sha256")
            != preauthorized.get("release_scope_sha256")
        ):
            raise GauntletError(f"release bundle for {target_id} is not gate-eligible")
        joins = (
            ("target_id", "target_id"),
            ("unit_fingerprint_sha256", "unit_fingerprint_sha256"),
            ("unit_label", "unit_label"),
            ("variant_profile_id", "variant_profile_id"),
            ("controller_board_revision", "controller_board_revision"),
            ("discovery_receipt_id", "discovery_receipt_id"),
            ("fixture_receipt_id", "fixture_receipt_id"),
            ("fixture_evidence_set_sha256", "fixture_evidence_set_sha256"),
            ("capture_receipt_id", "capture_receipt_id"),
            ("capture_set_sha256", "capture_set_sha256"),
            ("recovery_receipt_id", "recovery_receipt_id"),
            ("boot_policy_receipt_id", "boot_policy_receipt_id"),
            ("route_replacement_receipt_id", "route_replacement_receipt_id"),
            ("route_rollback_receipt_id", "route_rollback_receipt_id"),
            ("artifact_set_sha256", "artifact_set_sha256"),
            ("installed_artifact_sha256", "installed_artifact_sha256"),
            ("interface_qualification_sha256", "interface_qualification_sha256"),
            ("no_clobber_sha256", "no_clobber_sha256"),
            ("route_adjudication_sha256", "route_adjudication_sha256"),
            ("selected_route", "selected_route"),
            ("stock_backup_set_sha256", "stock_backup_set_sha256"),
            ("stock_restoration_sha256", "stock_restoration_sha256"),
            ("endurance_receipt_id", "receipt_id"),
            ("endurance_evidence_set_sha256", "evidence_set_sha256"),
            ("prior_bench_receipt_id", "prior_stage_receipt_id"),
            ("prior_bench_evidence_set_sha256", "prior_stage_evidence_set_sha256"),
            ("firmware_version", "replacement_firmware_version"),
        )
        for result_key, endurance_key in joins:
            if result[result_key] != endured[endurance_key]:
                raise GauntletError(
                    f"release bundle for {target_id} does not join {result_key}"
                )
        if target_id in results:
            raise GauntletError(
                f"multiple release receipts were supplied for target {target_id}"
            )
        if result["receipt_id"] in receipt_ids:
            raise GauntletError("duplicate release receipt ID")
        if result["evidence_set_sha256"] in evidence_sets:
            raise GauntletError("duplicate release evidence set")
        receipt_ids.add(result["receipt_id"])
        evidence_sets.add(result["evidence_set_sha256"])
        results[target_id] = result
    return results


def verify_profile(
    profile: Mapping[str, Any], repo_root: Path = REPO_ROOT, corpus_policy: str = "auto"
) -> Dict[str, Any]:
    if corpus_policy not in CORPUS_POLICIES:
        raise GauntletError(f"unknown corpus policy {corpus_policy}")
    if corpus_policy == "skip":
        return {
            "profile": profile["id"],
            "state": "skipped",
            "held_bytes_verified": False,
        }

    paths = {
        "source_zip": repo_root / profile["source_zip"],
        "summary": repo_root / profile["summary"],
        "aup": repo_root / profile["aup"],
    }
    present = {name: path.is_file() for name, path in paths.items()}
    if not any(present.values()):
        if corpus_policy == "required":
            raise GauntletError(
                f"profile {profile['id']} held corpus is required but absent"
            )
        return {
            "profile": profile["id"],
            "state": "absent",
            "held_bytes_verified": False,
            "note": "ignored held corpus is not present in this checkout; pinned metadata was validated",
        }
    missing = sorted(name for name, exists in present.items() if not exists)
    if missing:
        raise GauntletError(
            f"profile {profile['id']} corpus is partial; missing {', '.join(missing)}"
        )

    if _sha256_file(paths["source_zip"]) != profile["source_zip_sha256"]:
        raise GauntletError(f"profile {profile['id']} source ZIP SHA-256 mismatch")
    try:
        summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GauntletError(
            f"profile {profile['id']} summary cannot be read: {exc}"
        ) from exc
    _profile_summary_matches(profile, summary)

    data = paths["aup"].read_bytes()
    if len(data) != profile["aup_bytes"]:
        raise GauntletError(f"profile {profile['id']} AUP byte count mismatch")
    if hashlib.sha256(data).hexdigest() != profile["aup_sha256"]:
        raise GauntletError(f"profile {profile['id']} AUP SHA-256 mismatch")
    observed = inspect_aup_bytes(data)
    expected = {
        "fmt_ver": 2,
        "firmware_version": profile["firmware_version"],
        "hw_list": profile["hw_list"],
        "sw_list": profile["sw_list"],
        "payload_crc32": profile["payload_crc32"],
        "header_crc32": profile["header_crc32"],
        "k210_app_size": profile["k210_app_size"],
        "k210_sha256": profile["k210_sha256"],
        "aes_enable": 1,
    }
    for key, value in expected.items():
        if observed[key] != value:
            raise GauntletError(
                f"profile {profile['id']} AUP {key} mismatch: {observed[key]!r} != {value!r}"
            )
    return {
        "profile": profile["id"],
        "state": "verified",
        "held_bytes_verified": True,
        "aup_sha256": profile["aup_sha256"],
        "source_zip_sha256": profile["source_zip_sha256"],
    }


def verify_profiles(
    manifest: Mapping[str, Any],
    repo_root: Path = REPO_ROOT,
    corpus_policy: str = "auto",
) -> Dict[str, Dict[str, Any]]:
    return {
        profile["id"]: verify_profile(profile, repo_root, corpus_policy)
        for profile in manifest["firmware_profiles"]
    }


def _gate(
    state: str, qualifies: bool, evidence: Sequence[str], blocker: str
) -> Dict[str, Any]:
    return {
        "state": state,
        "qualifies": qualifies,
        "evidence": list(evidence),
        "blocker": blocker,
    }


def evaluate_target(
    manifest: Mapping[str, Any],
    target: Mapping[str, Any],
    profile_results: Mapping[str, Mapping[str, Any]],
    discovery_result: Optional[Mapping[str, Any]] = None,
    recovery_result: Optional[Mapping[str, Any]] = None,
    boot_policy_result: Optional[Mapping[str, Any]] = None,
    replacement_result: Optional[Mapping[str, Any]] = None,
    fixture_result: Optional[Mapping[str, Any]] = None,
    capture_result: Optional[Mapping[str, Any]] = None,
    rollback_result: Optional[Mapping[str, Any]] = None,
    first_light_result: Optional[Mapping[str, Any]] = None,
    bench_result: Optional[Mapping[str, Any]] = None,
    endurance_result: Optional[Mapping[str, Any]] = None,
    release_preauthorization_result: Optional[Mapping[str, Any]] = None,
    release_result: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    profile_id = target["stock_profile"]
    profile_result = profile_results.get(profile_id) if profile_id else None
    exact_identity = (
        target["kind"] == "physical_model"
        and target["controller_evidence"] != "needs_exact_board_confirmation"
        and target["asic_family"] != "unknown"
    )
    if discovery_result is not None:
        if not exact_identity:
            raise GauntletError(
                f"target {target['id']} cannot admit exact-unit discovery before its model row is exact"
            )
        if (
            discovery_result.get("target_id") != target["id"]
            or discovery_result.get("state") != "verified_signed_exact_unit_discovery"
            or discovery_result.get("identity_gate_eligible") is not True
            or discovery_result.get("authority_granted") is not False
        ):
            raise GauntletError(
                f"discovery result for {target['id']} is not gate-eligible"
            )
        variant_rows = [
            row
            for row in manifest.get("a1246_variant_identity_contract", {}).get(
                "variants", []
            )
            if row.get("target_id") == target["id"]
        ]
        if variant_rows:
            variant_profile_id = discovery_result.get("variant_profile_id")
            matched_rows = [
                row
                for row in variant_rows
                if row.get("profile_id") == variant_profile_id
            ]
            if len(matched_rows) != 1:
                raise GauntletError(
                    f"discovery result for {target['id']} does not resolve one admitted variant profile"
                )
            variant_row = matched_rows[0]
            variant_profile = next(
                (
                    profile
                    for profile in manifest["firmware_profiles"]
                    if profile["id"] == variant_profile_id
                ),
                None,
            )
            if (
                variant_profile is None
                or discovery_result.get("variant_asic_family")
                != variant_profile["asic_family"]
                or discovery_result.get("variant_hashboard_count")
                != variant_row["hashboard_count"]
                or discovery_result.get("variant_hwtype")
                not in variant_profile["hw_list"]
            ):
                raise GauntletError(
                    f"discovery result for {target['id']} contradicts its admitted variant profile"
                )
            profile_id = variant_profile_id
            profile_result = profile_results.get(profile_id)
        identity = _gate(
            "signed_exact_unit_discovery",
            True,
            [
                f"receipt:{discovery_result['receipt_id']}",
                f"unit:{discovery_result['unit_fingerprint_sha256']}",
                f"observer-key:{discovery_result['observer_key_id_sha256']}",
                f"variant-profile:{profile_id}",
            ],
            "",
        )
    elif exact_identity:
        identity = _gate(
            "documentary_only",
            False,
            [target["controller_source"]],
            "exact physical-unit controller/board/PSU/cooling identity is not fixture-bound",
        )
    else:
        identity = _gate(
            "incomplete",
            False,
            [target["controller_source"]],
            "model or firmware-family identity is incomplete and not physical-unit bound",
        )

    if fixture_result is not None:
        if discovery_result is None:
            raise GauntletError(
                f"fixture result for {target['id']} has no discovery result"
            )
        if (
            fixture_result.get("target_id") != target["id"]
            or fixture_result.get("state") != "verified_signed_fixture_qualification"
            or fixture_result.get("fixture_qualification_eligible") is not True
            or fixture_result.get("authority_granted") is not False
            or fixture_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or fixture_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
        ):
            raise GauntletError(
                f"fixture result for {target['id']} is not admission-eligible"
            )

    if capture_result is not None:
        if discovery_result is None or fixture_result is None:
            raise GauntletError(
                f"capture result for {target['id']} lacks discovery or fixture"
            )
        if (
            capture_result.get("target_id") != target["id"]
            or capture_result.get("state") != "verified_signed_p1_passive_capture"
            or capture_result.get("p1_capture_admission_eligible") is not True
            or capture_result.get("authority_granted") is not False
            or capture_result.get("wire_contract_claimed") is not False
            or capture_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or capture_result.get("fixture_receipt_id")
            != fixture_result.get("receipt_id")
            or capture_result.get("fixture_evidence_set_sha256")
            != fixture_result.get("fixture_evidence_set_sha256")
            or capture_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
        ):
            raise GauntletError(
                f"capture result for {target['id']} is not admission-eligible"
            )

    if recovery_result is not None:
        if discovery_result is None:
            raise GauntletError(
                f"recovery result for {target['id']} has no discovery result"
            )
        if (
            recovery_result.get("target_id") != target["id"]
            or recovery_result.get("state") != "verified_signed_stock_recovery"
            or recovery_result.get("stock_restore_gate_eligible") is not True
            or recovery_result.get("authority_granted") is not False
            or recovery_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or recovery_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
        ):
            raise GauntletError(
                f"recovery result for {target['id']} is not gate-eligible"
            )
        stock_restore = _gate(
            "dual_path_stock_recovery_verified",
            True,
            [
                f"receipt:{recovery_result['receipt_id']}",
                f"backup-set:{recovery_result['stock_backup_set_sha256']}",
                f"operator-key:{recovery_result['operator_key_id_sha256']}",
                f"witness-key:{recovery_result['witness_key_id_sha256']}",
            ],
            "",
        )
    elif profile_result and profile_result["state"] == "verified":
        stock_restore = _gate(
            "held_package_verified",
            False,
            [profile_result["aup_sha256"], profile_result["source_zip_sha256"]],
            "held stock package is not an exact-unit backup and no restore/readback drill exists",
        )
    elif profile_result:
        stock_restore = _gate(
            "pinned_metadata_only",
            False,
            [f"profile:{profile_id}"],
            "held bytes are absent in this checkout and exact-unit restore is unproven",
        )
    else:
        stock_restore = _gate(
            "missing_stock_profile",
            False,
            [],
            "no exact stock firmware profile or exact-unit flash backup is held",
        )

    if boot_policy_result is not None:
        if discovery_result is None or recovery_result is None:
            raise GauntletError(
                f"boot-policy result for {target['id']} lacks discovery or recovery"
            )
        if (
            boot_policy_result.get("target_id") != target["id"]
            or boot_policy_result.get("state")
            != "verified_signed_boot_policy_measurement"
            or boot_policy_result.get("boot_policy_gate_eligible") is not True
            or boot_policy_result.get("authority_granted") is not False
            or boot_policy_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or boot_policy_result.get("recovery_receipt_id")
            != recovery_result.get("receipt_id")
            or boot_policy_result.get("stock_backup_set_sha256")
            != recovery_result.get("stock_backup_set_sha256")
            or boot_policy_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
            or not isinstance(boot_policy_result.get("plaintext_probe_performed"), bool)
            or boot_policy_result.get("plaintext_probe_result")
            not in boot_policy.PLAINTEXT_RESULTS
            or boot_policy_result.get("plaintext_boot_supported")
            != (boot_policy_result.get("plaintext_probe_result") == "booted")
        ):
            raise GauntletError(
                f"boot-policy result for {target['id']} is not gate-eligible"
            )
        boot_gate = _gate(
            "dual_signed_exact_unit_measurement",
            True,
            [
                f"receipt:{boot_policy_result['receipt_id']}",
                f"flash-policy:{boot_policy_result['flash_policy_sha256']}",
                f"force-decrypt:{boot_policy_result['force_decrypt_state']}",
                f"plaintext-probe:{boot_policy_result['plaintext_probe_result']}",
                f"rom-isp:{boot_policy_result['rom_isp_state']}",
                f"jtag:{boot_policy_result['jtag_state']}",
            ],
            "",
        )
    else:
        boot_gate = _gate(
            "missing_measurement",
            False,
            [],
            "force-decrypt, ISP/JTAG locks, flash map, load address, and recovery entry are unmeasured",
        )

    replacement_blocker = (
        "no dual-reviewed route-discriminated artifact joins the exact-unit boot "
        "measurement; AES0, SRAM-bootstrap, and replacement-controller branches remain "
        "non-admitted"
    )
    if boot_policy_result is not None:
        incompatibilities = []
        if boot_policy_result["force_decrypt_state"] == "enabled":
            incompatibilities.append("force-decrypt is enabled")
        if (
            boot_policy_result["plaintext_probe_result"]
            == "not_run_force_decrypt_enabled"
        ):
            incompatibilities.append("the AES0 probe was not run by policy")
        elif not boot_policy_result["plaintext_boot_supported"]:
            incompatibilities.append(
                "the controlled AES0 probe ended as "
                + boot_policy_result["plaintext_probe_result"]
            )
        if not boot_policy_result["candidate_load_contract_compatible"]:
            incompatibilities.append("the measured boot load address is incompatible")
        compatibility = (
            "; ".join(incompatibilities)
            if incompatibilities
            else "AES0 and the candidate load contract were measured compatible"
        )
        replacement_blocker = (
            f"{compatibility}; no explicitly reviewed route-specific artifact and "
            "qualification bundle is admitted"
        )

    if replacement_result is not None:
        if (
            discovery_result is None
            or recovery_result is None
            or boot_policy_result is None
        ):
            raise GauntletError(
                f"replacement result for {target['id']} lacks a predecessor result"
            )
        if (
            replacement_result.get("target_id") != target["id"]
            or replacement_result.get("state")
            != "verified_signed_route_replacement_firmware"
            or replacement_result.get("replacement_firmware_gate_eligible") is not True
            or replacement_result.get("authority_granted") is not False
            or replacement_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or replacement_result.get("recovery_receipt_id")
            != recovery_result.get("receipt_id")
            or replacement_result.get("boot_policy_receipt_id")
            != boot_policy_result.get("receipt_id")
            or replacement_result.get("stock_backup_set_sha256")
            != recovery_result.get("stock_backup_set_sha256")
            or replacement_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
        ):
            raise GauntletError(
                f"replacement result for {target['id']} is not gate-eligible"
            )
        replacement_gate = _gate(
            "dual_signed_route_discriminated_target_bound_artifact",
            True,
            [
                f"receipt:{replacement_result['receipt_id']}",
                f"artifact-set:{replacement_result['artifact_set_sha256']}",
                f"route:{replacement_result['selected_route']}",
                f"route-adjudication:{replacement_result['route_adjudication_sha256']}",
                f"interface-qualification:{replacement_result['interface_qualification_sha256']}",
                f"builder-key:{replacement_result['builder_key_id_sha256']}",
                f"reviewer-key:{replacement_result['reviewer_key_id_sha256']}",
            ],
            "",
        )
    else:
        replacement_gate = _gate(
            "packaged_safe_idle_pipeline_sentinel_only",
            False,
            [
                manifest["runtime_contract"]["crate"],
                manifest["runtime_contract"]["sentinel"],
                manifest["runtime_contract"]["candidate_builder"],
            ],
            replacement_blocker,
        )

    if rollback_result is not None:
        if (
            discovery_result is None
            or recovery_result is None
            or boot_policy_result is None
            or replacement_result is None
        ):
            raise GauntletError(
                f"rollback result for {target['id']} lacks a predecessor result"
            )
        if (
            rollback_result.get("target_id") != target["id"]
            or rollback_result.get("state") != "verified_signed_route_rollback"
            or rollback_result.get("rollback_recovery_gate_eligible") is not True
            or rollback_result.get("authority_granted") is not False
            or rollback_result.get("discovery_receipt_id")
            != discovery_result.get("receipt_id")
            or rollback_result.get("recovery_receipt_id")
            != recovery_result.get("receipt_id")
            or rollback_result.get("boot_policy_receipt_id")
            != boot_policy_result.get("receipt_id")
            or rollback_result.get("route_replacement_receipt_id")
            != replacement_result.get("receipt_id")
            or rollback_result.get("stock_backup_set_sha256")
            != recovery_result.get("stock_backup_set_sha256")
            or rollback_result.get("unit_fingerprint_sha256")
            != discovery_result.get("unit_fingerprint_sha256")
            or rollback_result.get("artifact_set_sha256")
            != replacement_result.get("artifact_set_sha256")
            or rollback_result.get("interface_qualification_sha256")
            != replacement_result.get("interface_qualification_sha256")
            or rollback_result.get("route_adjudication_sha256")
            != replacement_result.get("route_adjudication_sha256")
            or rollback_result.get("selected_route")
            != replacement_result.get("selected_route")
        ):
            raise GauntletError(
                f"rollback result for {target['id']} is not gate-eligible"
            )
        rollback_gate = _gate(
            "dual_signed_exact_route_stock_restoration",
            True,
            [
                f"receipt:{rollback_result['receipt_id']}",
                f"route:{rollback_result['selected_route']}",
                f"route-adjudication:{rollback_result['route_adjudication_sha256']}",
                f"stock-restoration:{rollback_result['stock_restoration_sha256']}",
                f"no-clobber:{rollback_result['no_clobber_sha256']}",
                f"operator-key:{rollback_result['operator_key_id_sha256']}",
                f"witness-key:{rollback_result['witness_key_id_sha256']}",
            ],
            "",
        )
    else:
        rollback_gate = _gate(
            "missing_hardware_proof",
            False,
            [],
            "interrupted-update, bad-image, brownout, watchdog, and rollback drills are absent",
        )

    def validate_stage_result(
        result: Mapping[str, Any],
        qualification_class: str,
        state: str,
        expected_eligibility: Tuple[bool, bool, bool],
        prior: Optional[Mapping[str, Any]],
    ) -> None:
        predecessors = (
            discovery_result,
            fixture_result,
            capture_result,
            recovery_result,
            boot_policy_result,
            replacement_result,
            rollback_result,
        )
        if any(item is None for item in predecessors):
            raise GauntletError(
                f"{qualification_class} result for {target['id']} lacks a predecessor result"
            )
        if (
            result.get("target_id") != target["id"]
            or result.get("qualification_class") != qualification_class
            or result.get("outcome") != "passed"
            or result.get("state") != state
            or result.get("authority_granted") is not False
            or result.get("first_light_gate_eligible") is not expected_eligibility[0]
            or result.get("bench_mining_gate_eligible") is not expected_eligibility[1]
            or result.get("endurance_faults_gate_eligible")
            is not expected_eligibility[2]
        ):
            raise GauntletError(
                f"{qualification_class} result for {target['id']} is not gate-eligible"
            )
        joins = (
            ("discovery_receipt_id", discovery_result, "receipt_id"),
            ("unit_fingerprint_sha256", discovery_result, "unit_fingerprint_sha256"),
            ("unit_label", discovery_result, "unit_label"),
            ("fixture_receipt_id", fixture_result, "receipt_id"),
            (
                "fixture_evidence_set_sha256",
                fixture_result,
                "fixture_evidence_set_sha256",
            ),
            ("controller_board_revision", fixture_result, "controller_board_revision"),
            ("variant_profile_id", fixture_result, "variant_profile_id"),
            ("capture_receipt_id", capture_result, "receipt_id"),
            ("capture_set_sha256", capture_result, "capture_set_sha256"),
            ("recovery_receipt_id", recovery_result, "receipt_id"),
            (
                "stock_backup_set_sha256",
                recovery_result,
                "stock_backup_set_sha256",
            ),
            ("boot_policy_receipt_id", boot_policy_result, "receipt_id"),
            ("route_replacement_receipt_id", replacement_result, "receipt_id"),
            ("artifact_set_sha256", replacement_result, "artifact_set_sha256"),
            (
                "installed_artifact_sha256",
                replacement_result,
                "installed_artifact_sha256",
            ),
            (
                "interface_qualification_sha256",
                replacement_result,
                "interface_qualification_sha256",
            ),
            (
                "route_adjudication_sha256",
                replacement_result,
                "route_adjudication_sha256",
            ),
            ("selected_route", replacement_result, "selected_route"),
            (
                "replacement_firmware_version",
                replacement_result,
                "replacement_firmware_version",
            ),
            ("route_rollback_receipt_id", rollback_result, "receipt_id"),
            ("no_clobber_sha256", rollback_result, "no_clobber_sha256"),
            (
                "stock_restoration_sha256",
                rollback_result,
                "stock_restoration_sha256",
            ),
        )
        for result_key, predecessor, predecessor_key in joins:
            if result.get(result_key) != predecessor.get(predecessor_key):
                raise GauntletError(
                    f"{qualification_class} result for {target['id']} does not join {result_key}"
                )
        if prior is None:
            if (
                result.get("prior_stage_receipt_id") is not None
                or result.get("prior_stage_evidence_set_sha256") is not None
            ):
                raise GauntletError(
                    f"{qualification_class} result for {target['id']} has an unexpected prior stage"
                )
        elif result.get("prior_stage_receipt_id") != prior.get(
            "receipt_id"
        ) or result.get("prior_stage_evidence_set_sha256") != prior.get(
            "evidence_set_sha256"
        ):
            raise GauntletError(
                f"{qualification_class} result for {target['id']} does not join its prior stage"
            )

    if first_light_result is not None:
        validate_stage_result(
            first_light_result,
            bench_endurance.QUALIFICATION_FIRST_LIGHT,
            "verified_staged_first_light",
            (True, False, False),
            None,
        )
        first_light_evidence = [
            f"receipt:{first_light_result['receipt_id']}",
            f"evidence-set:{first_light_result['evidence_set_sha256']}",
            f"installed-artifact:{first_light_result['installed_artifact_sha256']}",
            f"operator-key:{first_light_result['operator_key_id_sha256']}",
            f"protocol-reviewer-key:{first_light_result['protocol_reviewer_key_id_sha256']}",
            f"safety-reviewer-key:{first_light_result['safety_reviewer_key_id_sha256']}",
        ]
        asic_control_gate = _gate(
            "triple_signed_exact_chain_first_light", True, first_light_evidence, ""
        )
        thermal_safety_gate = _gate(
            "triple_signed_independent_safety_first_light",
            True,
            first_light_evidence,
            "",
        )
    else:
        asic_control_gate = _gate(
            "not_implemented",
            False,
            [""],
            "no admissible K210 chip-facing wire contract exists; discovery/reset/PLL/work/nonce are not independently implemented or hardware-validated",
        )
        thermal_safety_gate = _gate(
            "generic_fail_closed_supervisor_only",
            False,
            [manifest["runtime_contract"]["safety_supervisor"]],
            "the generic supervisor has no model limits or hardware I/O; independent hash cut, cooling/PSU/sensor custody, watchdog wiring, and fault polarity remain unproven",
        )

    if bench_result is not None:
        if first_light_result is None:
            raise GauntletError(
                f"bench result for {target['id']} lacks a first-light result"
            )
        validate_stage_result(
            bench_result,
            bench_endurance.QUALIFICATION_BENCH,
            "verified_bounded_first_light_and_bench_mining",
            (True, True, False),
            first_light_result,
        )
        bench_gate = _gate(
            "dual_signed_bounded_bench_mining",
            True,
            [
                f"receipt:{bench_result['receipt_id']}",
                f"evidence-set:{bench_result['evidence_set_sha256']}",
                f"prior-first-light:{bench_result['prior_stage_receipt_id']}",
                f"operator-key:{bench_result['operator_key_id_sha256']}",
                f"witness-key:{bench_result['witness_key_id_sha256']}",
            ],
            "",
        )
    else:
        bench_gate = _gate(
            "not_run",
            False,
            [],
            "no authorized DCENT K210 bounded-mining evidence receipt exists",
        )

    if endurance_result is not None:
        if bench_result is None:
            raise GauntletError(
                f"endurance result for {target['id']} lacks a bench result"
            )
        validate_stage_result(
            endurance_result,
            bench_endurance.QUALIFICATION_ENDURANCE,
            "verified_fault_and_endurance_qualification",
            (True, True, True),
            bench_result,
        )
        endurance_gate = _gate(
            "dual_signed_fault_and_endurance_qualification",
            True,
            [
                f"receipt:{endurance_result['receipt_id']}",
                f"evidence-set:{endurance_result['evidence_set_sha256']}",
                f"prior-bench:{endurance_result['prior_stage_receipt_id']}",
                f"operator-key:{endurance_result['operator_key_id_sha256']}",
                f"witness-key:{endurance_result['witness_key_id_sha256']}",
            ],
            "",
        )
    else:
        endurance_gate = _gate(
            "not_run",
            False,
            [],
            "no model-bound soak or injected-fault campaign exists",
        )

    if release_preauthorization_result is not None:
        if endurance_result is None:
            raise GauntletError(
                f"release preauthorization for {target['id']} lacks an endurance result"
            )
        preauth_joins = (
            ("target_id", "target_id"),
            ("unit_fingerprint_sha256", "unit_fingerprint_sha256"),
            ("unit_label", "unit_label"),
            ("variant_profile_id", "variant_profile_id"),
            ("hardware_revision", "controller_board_revision"),
            ("endurance_receipt_id", "receipt_id"),
            ("endurance_evidence_set_sha256", "evidence_set_sha256"),
            ("artifact_set_sha256", "artifact_set_sha256"),
            ("installed_artifact_sha256", "installed_artifact_sha256"),
            ("interface_qualification_sha256", "interface_qualification_sha256"),
            ("no_clobber_sha256", "no_clobber_sha256"),
            ("route_replacement_receipt_id", "route_replacement_receipt_id"),
            ("route_adjudication_sha256", "route_adjudication_sha256"),
            ("selected_route", "selected_route"),
            ("firmware_version", "replacement_firmware_version"),
        )
        if (
            release_preauthorization_result.get("state")
            != "verified_exact_scope_preauthorization"
            or release_preauthorization_result.get("install_authority_scope_eligible")
            is not True
            or release_preauthorization_result.get("authority_granted") is not False
            or release_preauthorization_result.get("generic_future_authority_granted")
            is not False
            or any(
                release_preauthorization_result.get(result_key)
                != endurance_result.get(endurance_key)
                for result_key, endurance_key in preauth_joins
            )
        ):
            raise GauntletError(
                f"release preauthorization for {target['id']} is not exact-scope eligible"
            )

    if release_result is not None:
        if release_preauthorization_result is None or endurance_result is None:
            raise GauntletError(
                f"release result for {target['id']} lacks preauthorization or endurance"
            )
        release_joins = (
            ("target_id", "target_id"),
            ("unit_fingerprint_sha256", "unit_fingerprint_sha256"),
            ("unit_label", "unit_label"),
            ("variant_profile_id", "variant_profile_id"),
            ("controller_board_revision", "controller_board_revision"),
            ("discovery_receipt_id", "discovery_receipt_id"),
            ("fixture_receipt_id", "fixture_receipt_id"),
            ("fixture_evidence_set_sha256", "fixture_evidence_set_sha256"),
            ("capture_receipt_id", "capture_receipt_id"),
            ("capture_set_sha256", "capture_set_sha256"),
            ("recovery_receipt_id", "recovery_receipt_id"),
            ("boot_policy_receipt_id", "boot_policy_receipt_id"),
            ("route_replacement_receipt_id", "route_replacement_receipt_id"),
            ("route_rollback_receipt_id", "route_rollback_receipt_id"),
            ("artifact_set_sha256", "artifact_set_sha256"),
            ("installed_artifact_sha256", "installed_artifact_sha256"),
            ("interface_qualification_sha256", "interface_qualification_sha256"),
            ("no_clobber_sha256", "no_clobber_sha256"),
            ("route_adjudication_sha256", "route_adjudication_sha256"),
            ("selected_route", "selected_route"),
            ("stock_backup_set_sha256", "stock_backup_set_sha256"),
            ("stock_restoration_sha256", "stock_restoration_sha256"),
            ("endurance_receipt_id", "receipt_id"),
            ("endurance_evidence_set_sha256", "evidence_set_sha256"),
            ("prior_bench_receipt_id", "prior_stage_receipt_id"),
            ("prior_bench_evidence_set_sha256", "prior_stage_evidence_set_sha256"),
            ("firmware_version", "replacement_firmware_version"),
        )
        if (
            release_result.get("state") != "verified_exact_scope_release_capstone"
            or release_result.get("release_authority_gate_eligible") is not True
            or release_result.get("exact_scope_release_admitted") is not True
            or release_result.get("authority_granted") is not False
            or release_result.get("generic_future_authority_granted") is not False
            or release_result.get("preauthorization_id")
            != release_preauthorization_result.get("preauthorization_id")
            or release_result.get("preauthorization_sha256")
            != release_preauthorization_result.get("preauthorization_sha256")
            or release_result.get("release_scope_sha256")
            != release_preauthorization_result.get("release_scope_sha256")
            or any(
                release_result.get(result_key) != endurance_result.get(endurance_key)
                for result_key, endurance_key in release_joins
            )
        ):
            raise GauntletError(
                f"release result for {target['id']} is not gate-eligible"
            )
        release_gate = _gate(
            "four_role_exact_scope_witnessed_install_capstone",
            True,
            [
                f"receipt:{release_result['receipt_id']}",
                f"evidence-set:{release_result['evidence_set_sha256']}",
                f"preauthorization:{release_result['preauthorization_id']}",
                f"scope:{release_result['release_scope_sha256']}",
                f"preauthorizer-key:{release_result['preauthorizer_key_id_sha256']}",
                f"reviewer-key:{release_result['reviewer_key_id_sha256']}",
                f"installer-key:{release_result['installer_key_id_sha256']}",
                f"witness-key:{release_result['witness_key_id_sha256']}",
            ],
            "",
        )
    else:
        release_gate = _gate(
            "exact_scope_preauthorized_install_pending"
            if release_preauthorization_result is not None
            else "not_admitted",
            False,
            (
                [
                    f"preauthorization:{release_preauthorization_result['preauthorization_id']}",
                    f"scope:{release_preauthorization_result['release_scope_sha256']}",
                ]
                if release_preauthorization_result is not None
                else []
            ),
            (
                "the exact scope is preauthorized, but no witnessed install capstone is admitted"
                if release_preauthorization_result is not None
                else "artifact custody, reproducibility, signing, SBOM/license, and release approval are open"
            ),
        )

    gates = {
        "exact_model_identity": identity,
        "stock_restore": stock_restore,
        "boot_policy": boot_gate,
        "replacement_firmware": replacement_gate,
        "asic_control": asic_control_gate,
        "thermal_power_safety": thermal_safety_gate,
        "rollback_recovery": rollback_gate,
        "bench_mining": bench_gate,
        "endurance_faults": endurance_gate,
        "release_authority": release_gate,
    }
    expected_gate_ids = [item["id"] for item in manifest["production_gates"]]
    if list(gates) != expected_gate_ids:
        raise GauntletError(f"gate implementation drift for {target['id']}")

    production_ready = all(gate["qualifies"] for gate in gates.values())
    first_blocker = (
        "none"
        if production_ready
        else next(gate_id for gate_id, gate in gates.items() if not gate["qualifies"])
    )
    return {
        "id": target["id"],
        "display_name": target["display_name"],
        "kind": target["kind"],
        "generation": target["generation"],
        "controller_soc": target["controller_soc"],
        "asic_family": target["asic_family"],
        "stock_profile": profile_id,
        "bench_state": target["bench_state"],
        "management_contract": "verified_offline_generic_not_live_model_proof",
        "update_transport_contract": "verified_offline_reference_not_install_authority",
        "runtime_contract": "generic_safety_supervisor_and_packaged_safe_idle_pipeline_not_hardware_authority",
        "unit_discovery": dict(discovery_result) if discovery_result else None,
        "fixture_qualification": dict(fixture_result) if fixture_result else None,
        "passive_capture_admission": dict(capture_result) if capture_result else None,
        "stock_recovery": dict(recovery_result) if recovery_result else None,
        "boot_policy_measurement": (
            dict(boot_policy_result) if boot_policy_result else None
        ),
        "replacement_firmware_artifact": (
            dict(replacement_result) if replacement_result else None
        ),
        "rollback_qualification": (dict(rollback_result) if rollback_result else None),
        "first_light_qualification": (
            dict(first_light_result) if first_light_result else None
        ),
        "bench_mining_qualification": dict(bench_result) if bench_result else None,
        "endurance_fault_qualification": (
            dict(endurance_result) if endurance_result else None
        ),
        "release_preauthorization": (
            dict(release_preauthorization_result)
            if release_preauthorization_result
            else None
        ),
        "release_capstone": dict(release_result) if release_result else None,
        "gates": gates,
        "first_blocker": first_blocker,
        "production_ready": production_ready,
    }


def build_report(
    manifest: Mapping[str, Any],
    repo_root: Path = REPO_ROOT,
    corpus_policy: str = "auto",
    discovery_bundles: Sequence[Path] = (),
    fixture_bundles: Sequence[Path] = (),
    capture_bundles: Sequence[Path] = (),
    recovery_bundles: Sequence[Path] = (),
    boot_policy_bundles: Sequence[Path] = (),
    replacement_bundles: Sequence[Path] = (),
    rollback_bundles: Sequence[Path] = (),
    first_light_bundles: Sequence[Path] = (),
    bench_bundles: Sequence[Path] = (),
    endurance_bundles: Sequence[Path] = (),
    release_preauthorization_bundles: Sequence[Path] = (),
    release_bundles: Sequence[Path] = (),
) -> Dict[str, Any]:
    discovery_validation = verify_discovery_contract(manifest, repo_root)
    discovery_results = verify_discovery_bundles(manifest, discovery_bundles, repo_root)
    fixture_validation = verify_fixture_contract(manifest, repo_root)
    fixture_results = verify_fixture_bundles(
        manifest, fixture_bundles, discovery_results, repo_root
    )
    capture_validation = verify_capture_contract(manifest, repo_root)
    capture_results = verify_capture_bundles(
        manifest,
        capture_bundles,
        discovery_results,
        fixture_results,
        repo_root,
    )
    recovery_validation = verify_recovery_contract(manifest, repo_root)
    recovery_results = verify_recovery_bundles(
        manifest, recovery_bundles, discovery_results, repo_root
    )
    boot_policy_validation = verify_boot_policy_contract(manifest, repo_root)
    boot_policy_results = verify_boot_policy_bundles(
        manifest,
        boot_policy_bundles,
        discovery_results,
        recovery_results,
        repo_root,
    )
    replacement_validation = verify_replacement_contract(manifest, repo_root)
    replacement_results = verify_replacement_bundles(
        manifest,
        replacement_bundles,
        discovery_results,
        recovery_results,
        boot_policy_results,
        repo_root,
    )
    rollback_validation = verify_rollback_contract(manifest, repo_root)
    rollback_results = verify_rollback_bundles(
        manifest,
        rollback_bundles,
        discovery_results,
        recovery_results,
        boot_policy_results,
        replacement_results,
        repo_root,
    )
    bench_endurance_validation = verify_bench_endurance_contract(manifest, repo_root)
    stage_results = verify_bench_endurance_bundles(
        manifest,
        first_light_bundles,
        bench_bundles,
        endurance_bundles,
        discovery_results,
        fixture_results,
        capture_results,
        recovery_results,
        boot_policy_results,
        replacement_results,
        rollback_results,
        repo_root,
    )
    first_light_results = stage_results[bench_endurance.QUALIFICATION_FIRST_LIGHT]
    bench_results = stage_results[bench_endurance.QUALIFICATION_BENCH]
    endurance_results = stage_results[bench_endurance.QUALIFICATION_ENDURANCE]
    release_validation = verify_release_contract(manifest, repo_root)
    release_preauthorization_results = verify_release_preauthorization_bundles(
        manifest,
        release_preauthorization_bundles,
        endurance_results,
        repo_root,
    )
    release_results = verify_release_bundles(
        manifest,
        release_bundles,
        release_preauthorization_results,
        endurance_results,
        repo_root,
    )
    runtime_validation = verify_runtime_contract(manifest, repo_root)
    profile_results = verify_profiles(manifest, repo_root, corpus_policy)
    models = [
        evaluate_target(
            manifest,
            target,
            profile_results,
            discovery_results.get(target["id"]),
            recovery_results.get(target["id"]),
            boot_policy_results.get(target["id"]),
            replacement_results.get(target["id"]),
            fixture_results.get(target["id"]),
            capture_results.get(target["id"]),
            rollback_results.get(target["id"]),
            first_light_results.get(target["id"]),
            bench_results.get(target["id"]),
            endurance_results.get(target["id"]),
            release_preauthorization_results.get(target["id"]),
            release_results.get(target["id"]),
        )
        for target in manifest["targets"]
    ]
    first_blockers = Counter(model["first_blocker"] for model in models)
    gate_order = [item["id"] for item in manifest["production_gates"]]
    blocker_counts = [
        {"gate": gate_id, "targets": first_blockers[gate_id]}
        for gate_id in gate_order
        if first_blockers[gate_id]
    ]
    corpus_counts = Counter(result["state"] for result in profile_results.values())
    return {
        "schema_version": 1,
        "scope": manifest["scope"],
        "safety_boundary": "host-only; local receipt-signature verification only; no contact, network, serial, USB, programmer, JTAG, ISP, flash, GPIO, power, or miner mutation",
        "management_contract": manifest["management_contract"],
        "discovery_contract": manifest["discovery_contract"],
        "discovery_validation": discovery_validation,
        "fixture_contract": manifest["fixture_contract"],
        "fixture_validation": fixture_validation,
        "capture_contract": manifest["capture_contract"],
        "capture_validation": capture_validation,
        "recovery_contract": manifest["recovery_contract"],
        "recovery_validation": recovery_validation,
        "boot_policy_contract": manifest["boot_policy_contract"],
        "boot_policy_validation": boot_policy_validation,
        "replacement_firmware_contract": manifest["replacement_firmware_contract"],
        "replacement_firmware_validation": replacement_validation,
        "rollback_contract": manifest["rollback_contract"],
        "rollback_validation": rollback_validation,
        "bench_endurance_contract": manifest["bench_endurance_contract"],
        "bench_endurance_validation": bench_endurance_validation,
        "release_contract": manifest["release_contract"],
        "release_validation": release_validation,
        "update_transport_contract": manifest["update_transport_contract"],
        "runtime_contract": manifest["runtime_contract"],
        "runtime_validation": runtime_validation,
        "counts": {
            "targets": len(models),
            "physical_models": sum(
                model["kind"] == "physical_model" for model in models
            ),
            "candidate_or_family_rows": sum(
                model["kind"] != "physical_model" for model in models
            ),
            "held_firmware_profiles": len(profile_results),
            "verified_held_profiles": corpus_counts["verified"],
            "verified_discovery_receipts": len(discovery_results),
            "verified_fixture_receipts": len(fixture_results),
            "verified_capture_receipts": len(capture_results),
            "verified_recovery_receipts": len(recovery_results),
            "verified_boot_policy_receipts": len(boot_policy_results),
            "verified_replacement_firmware_receipts": len(replacement_results),
            "verified_rollback_receipts": len(rollback_results),
            "verified_first_light_receipts": len(first_light_results),
            "verified_bench_mining_receipts": len(bench_results),
            "verified_endurance_fault_receipts": len(endurance_results),
            "verified_release_preauthorizations": len(release_preauthorization_results),
            "verified_release_receipts": len(release_results),
            "production_ready": sum(model["production_ready"] for model in models),
        },
        "corpus_states": dict(sorted(corpus_counts.items())),
        "first_blockers": blocker_counts,
        "models": models,
        "next_actions": [
            "Capture exact stock version/stats, control-board/PSU/cooling identity, UART/JTAG pads, and read-only flash geometry on an explicitly authorized reported-available K210 unit.",
            "Create two independent stock recovery media and prove full readback/restore before any custom write or use of the held stock update transport.",
            "Under exact named-unit authorization and controller-only isolation, measure K210 force-decrypt, full flash map/load address, ROM ISP, JTAG, and the controlled AES0 outcome; record even an incompatible outcome.",
            "Build the clean no_std DCENT K210 runtime and per-ASIC control behind measured model profiles, keeping all energizing paths fail-closed.",
            "Advance each physical model through first light, bounded mining, thermal/power fault injection, endurance, rollback, and signed release admission.",
        ],
    }


def matrix_payload(manifest: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "include": [
            {
                "model": target["id"],
                "generation": target["generation"],
                "kind": target["kind"],
                "profile": target["stock_profile"] or "none",
            }
            for target in manifest["targets"]
        ]
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Avalon K210 production-readiness gauntlet",
        "",
        f"Scope: `{report['scope']}`",
        "",
        f"Safety boundary: {report['safety_boundary']}",
        "",
        "Stock update transport: offline reference verified; no live client or install authority.",
        "",
        "Signed discovery: {state}; admitted exact-unit receipts: {receipts}.".format(
            state=report["discovery_validation"]["state"],
            receipts=counts["verified_discovery_receipts"],
        ),
        "",
        "Signed fixture qualification: {state}; admitted exact-unit receipts: {receipts}.".format(
            state=report["fixture_validation"]["state"],
            receipts=counts["verified_fixture_receipts"],
        ),
        "",
        "Signed P1 passive capture: {state}; admitted exact-unit receipts: {receipts}.".format(
            state=report["capture_validation"]["state"],
            receipts=counts["verified_capture_receipts"],
        ),
        "",
        "Signed stock recovery: {state}; admitted dual-path receipts: {receipts}.".format(
            state=report["recovery_validation"]["state"],
            receipts=counts["verified_recovery_receipts"],
        ),
        "",
        "Signed boot-policy measurement: {state}; admitted exact-unit receipts: {receipts}.".format(
            state=report["boot_policy_validation"]["state"],
            receipts=counts["verified_boot_policy_receipts"],
        ),
        "",
        "Signed replacement firmware: {state}; admitted target-bound artifacts: {receipts}.".format(
            state=report["replacement_firmware_validation"]["state"],
            receipts=counts["verified_replacement_firmware_receipts"],
        ),
        "",
        "Signed exact-route rollback: {state}; admitted exact-unit receipts: {receipts}.".format(
            state=report["rollback_validation"]["state"],
            receipts=counts["verified_rollback_receipts"],
        ),
        "",
        "Signed staged bench/endurance evidence: {state}; first-light={first_light}, bench={bench}, endurance={endurance}.".format(
            state=report["bench_endurance_validation"]["state"],
            first_light=counts["verified_first_light_receipts"],
            bench=counts["verified_bench_mining_receipts"],
            endurance=counts["verified_endurance_fault_receipts"],
        ),
        "",
        "Signed two-phase release: {state}; preauthorizations={preauthorizations}, capstones={capstones}.".format(
            state=report["release_validation"]["state"],
            preauthorizations=counts["verified_release_preauthorizations"],
            capstones=counts["verified_release_receipts"],
        ),
        "",
        "K210 runtime baseline: fail-closed no_std policy core and generic non-installable sentinel; admitted target-bound artifacts are counted separately.",
        f"Runtime contract validation: {report['runtime_validation']['state']}.",
        "",
        "## Summary",
        "",
        f"- Targets: {counts['targets']} ({counts['physical_models']} physical-model rows)",
        f"- Held firmware profiles: {counts['held_firmware_profiles']} ({counts['verified_held_profiles']} byte-verified in this run)",
        f"- Signed exact-unit discovery receipts: {counts['verified_discovery_receipts']}",
        f"- Signed fixture-qualification receipts: {counts['verified_fixture_receipts']}",
        f"- Signed P1 passive-capture receipts: {counts['verified_capture_receipts']}",
        f"- Signed stock-recovery receipts: {counts['verified_recovery_receipts']}",
        f"- Signed boot-policy receipts: {counts['verified_boot_policy_receipts']}",
        f"- Signed replacement-firmware receipts: {counts['verified_replacement_firmware_receipts']}",
        f"- Signed exact-route rollback receipts: {counts['verified_rollback_receipts']}",
        f"- Signed first-light receipts: {counts['verified_first_light_receipts']}",
        f"- Signed bounded bench-mining receipts: {counts['verified_bench_mining_receipts']}",
        f"- Signed fault/endurance receipts: {counts['verified_endurance_fault_receipts']}",
        f"- Signed release preauthorizations: {counts['verified_release_preauthorizations']}",
        f"- Signed witnessed-install capstones: {counts['verified_release_receipts']}",
        f"- Production-ready: {counts['production_ready']}",
        "",
        "## Model matrix",
        "",
        "| Target | Kind | ASIC | Stock profile | First blocker | Production |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for model in report["models"]:
        lines.append(
            "| {id} | {kind} | {asic} | {profile} | {blocker} | {ready} |".format(
                id=model["id"],
                kind=model["kind"],
                asic=model["asic_family"],
                profile=model["stock_profile"] or "missing",
                blocker=model["first_blocker"],
                ready="READY" if model["production_ready"] else "BLOCKED",
            )
        )
    lines.extend(["", "## Next actions", ""])
    lines.extend(
        f"{index}. {action}" for index, action in enumerate(report["next_actions"], 1)
    )
    lines.extend(
        [
            "",
            "> A green gauntlet execution validates the inventory/evidence computation only. It does not authorize hardware contact or claim production readiness.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _require_available_outputs(paths: Sequence[Path], overwrite: bool) -> None:
    resolved = [path.resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        raise GauntletError("candidate AUP and receipt outputs must be different paths")
    if not overwrite:
        existing = [str(path) for path in paths if path.exists()]
        if existing:
            raise GauntletError(
                f"refusing to overwrite existing output: {', '.join(existing)}"
            )


def _target_by_id(manifest: Mapping[str, Any], model_id: str) -> Mapping[str, Any]:
    for target in manifest["targets"]:
        if target["id"] == model_id:
            return target
    raise GauntletError(f"unknown K210 target {model_id!r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("matrix", help="emit the dynamic GitHub Actions matrix")

    check = subparsers.add_parser(
        "check", help="evaluate one target without contacting hardware"
    )
    check.add_argument("--model", required=True)
    check.add_argument("--corpus", choices=CORPUS_POLICIES, default="auto")
    check.add_argument(
        "--discovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a signed exact-unit discovery bundle using the manifest-pinned key",
    )
    check.add_argument(
        "--fixture-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-reviewed fixture bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--capture-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-reviewed P1 capture bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--recovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed stock-recovery bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--boot-policy-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed boot-policy bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--replacement-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed replacement-firmware bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--rollback-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed exact-route rollback bundle using manifest-pinned keys",
    )
    check.add_argument(
        "--first-light-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a triple-signed exact-chain first-light bundle",
    )
    check.add_argument(
        "--bench-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed bounded bench-mining bundle",
    )
    check.add_argument(
        "--endurance-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed fault/endurance bundle",
    )
    check.add_argument(
        "--release-preauthorization-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed exact-scope release preauthorization bundle",
    )
    check.add_argument(
        "--release-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a witnessed exact-scope install capstone bundle",
    )
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument("--require-production", action="store_true")

    report = subparsers.add_parser(
        "report", help="evaluate the complete K210 target matrix"
    )
    report.add_argument("--corpus", choices=CORPUS_POLICIES, default="auto")
    report.add_argument(
        "--discovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a signed exact-unit discovery bundle using the manifest-pinned key",
    )
    report.add_argument(
        "--fixture-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-reviewed fixture bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--capture-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-reviewed P1 capture bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--recovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed stock-recovery bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--boot-policy-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed boot-policy bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--replacement-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed replacement-firmware bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--rollback-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed exact-route rollback bundle using manifest-pinned keys",
    )
    report.add_argument(
        "--first-light-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a triple-signed exact-chain first-light bundle",
    )
    report.add_argument(
        "--bench-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed bounded bench-mining bundle",
    )
    report.add_argument(
        "--endurance-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed fault/endurance bundle",
    )
    report.add_argument(
        "--release-preauthorization-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a dual-signed exact-scope release preauthorization bundle",
    )
    report.add_argument(
        "--release-bundle",
        type=Path,
        action="append",
        default=[],
        help="admit a witnessed exact-scope install capstone bundle",
    )
    report.add_argument("--json-out", type=Path)
    report.add_argument("--markdown-out", type=Path)
    report.add_argument("--format", choices=("text", "json"), default="text")
    report.add_argument("--require-production", action="store_true")

    verify = subparsers.add_parser(
        "verify", help="verify manifest and available held corpus"
    )
    verify.add_argument("--corpus", choices=CORPUS_POLICIES, default="auto")
    verify.add_argument(
        "--discovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a signed exact-unit discovery bundle using the manifest-pinned key",
    )
    verify.add_argument(
        "--fixture-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-reviewed fixture bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--capture-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-reviewed P1 capture bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--recovery-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed stock-recovery bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--boot-policy-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed boot-policy bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--replacement-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed replacement-firmware bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--rollback-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed exact-route rollback bundle using manifest-pinned keys",
    )
    verify.add_argument(
        "--first-light-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a triple-signed exact-chain first-light bundle",
    )
    verify.add_argument(
        "--bench-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed bounded bench-mining bundle",
    )
    verify.add_argument(
        "--endurance-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed fault/endurance bundle",
    )
    verify.add_argument(
        "--release-preauthorization-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a dual-signed exact-scope release preauthorization bundle",
    )
    verify.add_argument(
        "--release-bundle",
        type=Path,
        action="append",
        default=[],
        help="verify a witnessed exact-scope install capstone bundle",
    )

    candidate = subparsers.add_parser(
        "candidate",
        help="build an offline AES0 K210/AUP candidate without contacting hardware",
    )
    candidate.add_argument("--model", required=True)
    candidate.add_argument("--app-bin", type=Path, required=True)
    candidate.add_argument("--firmware-version", required=True)
    candidate.add_argument("--aup-out", type=Path, required=True)
    candidate.add_argument("--receipt-out", type=Path, required=True)
    candidate.add_argument(
        "--experimental-aes0",
        action="store_true",
        help="acknowledge that target force-decrypt eFuse compatibility is unmeasured",
    )
    candidate.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        repo_root = args.repo_root.resolve()
        if args.command == "matrix":
            print(json.dumps(matrix_payload(manifest), separators=(",", ":")))
            return 0
        if args.command == "verify":
            discovery_result = verify_discovery_contract(manifest, repo_root)
            discovery_receipts = verify_discovery_bundles(
                manifest, args.discovery_bundle, repo_root
            )
            fixture_result = verify_fixture_contract(manifest, repo_root)
            fixture_receipts = verify_fixture_bundles(
                manifest,
                args.fixture_bundle,
                discovery_receipts,
                repo_root,
            )
            capture_result = verify_capture_contract(manifest, repo_root)
            capture_receipts = verify_capture_bundles(
                manifest,
                args.capture_bundle,
                discovery_receipts,
                fixture_receipts,
                repo_root,
            )
            recovery_result = verify_recovery_contract(manifest, repo_root)
            recovery_receipts = verify_recovery_bundles(
                manifest,
                args.recovery_bundle,
                discovery_receipts,
                repo_root,
            )
            boot_policy_result = verify_boot_policy_contract(manifest, repo_root)
            boot_policy_receipts = verify_boot_policy_bundles(
                manifest,
                args.boot_policy_bundle,
                discovery_receipts,
                recovery_receipts,
                repo_root,
            )
            replacement_result = verify_replacement_contract(manifest, repo_root)
            replacement_receipts = verify_replacement_bundles(
                manifest,
                args.replacement_bundle,
                discovery_receipts,
                recovery_receipts,
                boot_policy_receipts,
                repo_root,
            )
            rollback_result = verify_rollback_contract(manifest, repo_root)
            rollback_receipts = verify_rollback_bundles(
                manifest,
                args.rollback_bundle,
                discovery_receipts,
                recovery_receipts,
                boot_policy_receipts,
                replacement_receipts,
                repo_root,
            )
            bench_endurance_result = verify_bench_endurance_contract(
                manifest, repo_root
            )
            stage_receipts = verify_bench_endurance_bundles(
                manifest,
                args.first_light_bundle,
                args.bench_bundle,
                args.endurance_bundle,
                discovery_receipts,
                fixture_receipts,
                capture_receipts,
                recovery_receipts,
                boot_policy_receipts,
                replacement_receipts,
                rollback_receipts,
                repo_root,
            )
            first_light_receipts = stage_receipts[
                bench_endurance.QUALIFICATION_FIRST_LIGHT
            ]
            bench_receipts = stage_receipts[bench_endurance.QUALIFICATION_BENCH]
            endurance_receipts = stage_receipts[bench_endurance.QUALIFICATION_ENDURANCE]
            release_result = verify_release_contract(manifest, repo_root)
            release_preauthorizations = verify_release_preauthorization_bundles(
                manifest,
                args.release_preauthorization_bundle,
                endurance_receipts,
                repo_root,
            )
            release_receipts = verify_release_bundles(
                manifest,
                args.release_bundle,
                release_preauthorizations,
                endurance_receipts,
                repo_root,
            )
            runtime_result = verify_runtime_contract(manifest, repo_root)
            results = verify_profiles(manifest, repo_root, args.corpus)
            counts = Counter(item["state"] for item in results.values())
            print(
                f"K210_GAUNTLET_OK targets={len(manifest['targets'])} "
                f"profiles={len(results)} runtime={runtime_result['state']} "
                f"discovery={discovery_result['state']} "
                f"discovery_receipts={len(discovery_receipts)} "
                f"fixture={fixture_result['state']} "
                f"fixture_receipts={len(fixture_receipts)} "
                f"capture={capture_result['state']} "
                f"capture_receipts={len(capture_receipts)} "
                f"recovery={recovery_result['state']} "
                f"recovery_receipts={len(recovery_receipts)} "
                f"boot_policy={boot_policy_result['state']} "
                f"boot_policy_receipts={len(boot_policy_receipts)} "
                f"replacement={replacement_result['state']} "
                f"replacement_receipts={len(replacement_receipts)} "
                f"rollback={rollback_result['state']} "
                f"rollback_receipts={len(rollback_receipts)} "
                f"bench_endurance={bench_endurance_result['state']} "
                f"first_light_receipts={len(first_light_receipts)} "
                f"bench_receipts={len(bench_receipts)} "
                f"endurance_receipts={len(endurance_receipts)} "
                f"release={release_result['state']} "
                f"release_preauthorizations={len(release_preauthorizations)} "
                f"release_receipts={len(release_receipts)} "
                f"corpus={dict(sorted(counts.items()))}"
            )
            return 0
        if args.command == "candidate":
            if not args.experimental_aes0:
                raise GauntletError(
                    "candidate creation requires --experimental-aes0; target bootability is unmeasured"
                )
            verify_runtime_contract(manifest, repo_root)
            if not args.app_bin.is_file():
                raise GauntletError(f"candidate application is absent: {args.app_bin}")
            try:
                app = args.app_bin.read_bytes()
            except OSError as exc:
                raise GauntletError(
                    f"candidate application cannot be read: {exc}"
                ) from exc
            aup, receipt = build_candidate_package(
                manifest, args.model, app, args.firmware_version
            )
            receipt["source_app"] = str(args.app_bin)
            _require_available_outputs((args.aup_out, args.receipt_out), args.overwrite)
            args.aup_out.parent.mkdir(parents=True, exist_ok=True)
            args.aup_out.write_bytes(aup)
            _write_json(args.receipt_out, receipt)
            print(
                f"K210_CANDIDATE_BUILT model={args.model} aes_enable=0 "
                f"aup_bytes={len(aup)} disposition={receipt['disposition']}"
            )
            return 0

        report = build_report(
            manifest,
            repo_root,
            args.corpus,
            args.discovery_bundle,
            args.fixture_bundle,
            args.capture_bundle,
            args.recovery_bundle,
            args.boot_policy_bundle,
            args.replacement_bundle,
            args.rollback_bundle,
            args.first_light_bundle,
            args.bench_bundle,
            args.endurance_bundle,
            args.release_preauthorization_bundle,
            args.release_bundle,
        )
        if args.command == "check":
            target = _target_by_id(manifest, args.model)
            model = next(
                item for item in report["models"] if item["id"] == target["id"]
            )
            if args.format == "json":
                print(json.dumps(model, indent=2, sort_keys=True))
            else:
                print(
                    f"K210_MODEL_GATE_OK model={model['id']} "
                    f"production_ready={str(model['production_ready']).lower()} "
                    f"first_blocker={model['first_blocker']}"
                )
            if args.require_production and not model["production_ready"]:
                return 3
            return 0

        if args.json_out:
            _write_json(args.json_out, report)
        if args.markdown_out:
            args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
        if args.format == "json":
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            counts = report["counts"]
            print(
                f"K210_GAUNTLET_OK targets={counts['targets']} "
                f"profiles={counts['held_firmware_profiles']} "
                f"verified_profiles={counts['verified_held_profiles']} "
                f"discovery_receipts={counts['verified_discovery_receipts']} "
                f"fixture_receipts={counts['verified_fixture_receipts']} "
                f"capture_receipts={counts['verified_capture_receipts']} "
                f"recovery_receipts={counts['verified_recovery_receipts']} "
                f"boot_policy_receipts={counts['verified_boot_policy_receipts']} "
                f"replacement_receipts={counts['verified_replacement_firmware_receipts']} "
                f"rollback_receipts={counts['verified_rollback_receipts']} "
                f"first_light_receipts={counts['verified_first_light_receipts']} "
                f"bench_receipts={counts['verified_bench_mining_receipts']} "
                f"endurance_receipts={counts['verified_endurance_fault_receipts']} "
                f"release_preauthorizations={counts['verified_release_preauthorizations']} "
                f"release_receipts={counts['verified_release_receipts']} "
                f"production_ready={counts['production_ready']}"
            )
        if (
            args.require_production
            and report["counts"]["production_ready"] != report["counts"]["targets"]
        ):
            return 3
        return 0
    except GauntletError as exc:
        print(f"K210_GAUNTLET_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
