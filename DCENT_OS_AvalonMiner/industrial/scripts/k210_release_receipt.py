#!/usr/bin/env python3
"""Create and verify exact-scope A1246 release-capstone bundles.

This is a host-only evidence tool.  It deliberately separates the authority
needed for one capstone install from the evidence produced by that install:

* ``preauthorize`` creates an immutable object signed by a preauthorizer and
  an independent reviewer before contact;
* ``create`` consumes that already-signed object, snapshots a fully verified
  endurance bundle, and signs the completed install receipt with an installer
  and an independent witness.

The four release roles, keys, principals, and SSHSIG namespaces are distinct.
A verified final receipt can qualify only the exact release scope it names. It
does not grant generic future contact, installation, hashing, or release
authority and this module contains no hardware transport.
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
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 receipt primitive: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = _load_module("k210_bench_endurance_receipt.py", "k210_bench_endurance_receipt")
discovery = stage.discovery

SCHEMA_VERSION = 1
SCOPE = stage.SCOPE
ENDURANCE_RECEIPT_KIND = stage.RECEIPT_KIND
ENDURANCE_SCHEMA_VERSION = stage.SCHEMA_VERSION
ROUTE_REPLACEMENT_RECEIPT_KIND = stage.ROUTE_REPLACEMENT_RECEIPT_KIND
ROUTE_REPLACEMENT_SCHEMA_VERSION = stage.ROUTE_REPLACEMENT_SCHEMA_VERSION
ROUTE_ROLLBACK_RECEIPT_KIND = stage.ROUTE_ROLLBACK_RECEIPT_KIND
ROUTE_ROLLBACK_SCHEMA_VERSION = stage.ROUTE_ROLLBACK_SCHEMA_VERSION
ROUTES = stage.ROUTES
PREAUTH_DESCRIPTOR_KIND = "dcent_k210_release_preauthorization_descriptor"
PREAUTH_KIND = "dcent_k210_release_preauthorization"
DESCRIPTOR_KIND = "dcent_k210_release_capstone_descriptor"
RECEIPT_KIND = "dcent_k210_release_capstone_receipt"
PREAUTH_DISPOSITION = "one_time_exact_unit_capstone_authorization"
DISPOSITION = "completed_exact_scope_release_capstone_no_generic_future_authority"

PREAUTHORIZATION_NAME = "preauthorization.json"
RECEIPT_NAME = "receipt.json"
PREAUTHORIZER_SIGNATURE_NAME = "preauthorizer.sig"
REVIEWER_SIGNATURE_NAME = "reviewer.sig"
INSTALLER_SIGNATURE_NAME = "installer.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
AUTHORIZATION_DIRECTORY = "authorization"
EVIDENCE_DIRECTORY = "evidence"
PREDECESSOR_DIRECTORY = "predecessor/endurance_bundle"

PREAUTHORIZER_ROLE = "k210_release_preauthorizer"
REVIEWER_ROLE = "k210_release_reviewer"
INSTALLER_ROLE = "k210_release_installer"
WITNESS_ROLE = "k210_release_install_witness"
PREAUTHORIZER_NAMESPACE = "dcent-k210-release-preauthorizer-v1"
REVIEWER_NAMESPACE = "dcent-k210-release-reviewer-v1"
INSTALLER_NAMESPACE = "dcent-k210-release-installer-v1"
WITNESS_NAMESPACE = "dcent-k210-release-install-witness-v1"
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

RELEASE_NAMESPACES = {
    PREAUTHORIZER_NAMESPACE,
    REVIEWER_NAMESPACE,
    INSTALLER_NAMESPACE,
    WITNESS_NAMESPACE,
}
if len(RELEASE_NAMESPACES) != 4:
    raise RuntimeError("K210 release SSHSIG namespaces must be distinct")

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
SSHSIG_BEGIN = b"-----BEGIN SSH SIGNATURE-----\n"
SSHSIG_END = b"-----END SSH SIGNATURE-----\n"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

PERMITTED_ACTIONS = {
    "boot_exact_replacement",
    "exercise_upgrade_runbook",
    "install_exact_replacement_artifact",
    "restore_stock_on_failure",
    "run_postinstall_acceptance",
    "verify_full_readback",
    "verify_preflight",
    "verify_restore_runbook",
}

PREAUTHORITY_CEILING = {
    "authorizes_capstone_contact": True,
    "authorizes_capstone_install": True,
    "authorizes_generic_future_contact": False,
    "authorizes_generic_future_install": False,
    "authorizes_other_artifacts": False,
    "authorizes_other_units": False,
    "authorizes_production_hashing": False,
    "authorizes_release_publication": False,
    "exact_scope_only": True,
}

AUTHORITY_CEILING = {
    "authorizes_generic_future_contact": False,
    "authorizes_generic_future_install": False,
    "authorizes_other_artifacts": False,
    "authorizes_other_units": False,
    "authorizes_production_hashing": False,
    "authorizes_unscoped_release": False,
    "qualifies_exact_scope_release": True,
}

RELEASE_RESULT = {
    "exact_scope_release_admitted": True,
    "release_authority_gate_eligible": True,
    "state": "verified_exact_scope_release_capstone",
}

CHAIN_FIELDS = (
    "artifact_set_sha256",
    "boot_policy_receipt_id",
    "capture_receipt_id",
    "capture_set_sha256",
    "controller_board_revision",
    "discovery_receipt_id",
    "endurance_completed_at_utc",
    "endurance_evidence_set_sha256",
    "endurance_receipt_id",
    "fixture_evidence_set_sha256",
    "fixture_receipt_id",
    "installed_artifact_sha256",
    "interface_qualification_sha256",
    "no_clobber_sha256",
    "prior_bench_evidence_set_sha256",
    "prior_bench_receipt_id",
    "recovery_receipt_id",
    "replacement_firmware_version",
    "route_replacement_receipt_id",
    "route_rollback_receipt_id",
    "route_adjudication_sha256",
    "selected_route",
    "stock_backup_set_sha256",
    "stock_restoration_sha256",
    "target_id",
    "unit_fingerprint_sha256",
    "unit_label",
    "variant_profile_id",
)

RELEASE_SCOPE_FIELDS = {
    "artifact_set_sha256",
    "firmware_version",
    "hardware_revision",
    "installed_artifact_sha256",
    "interface_qualification_sha256",
    "no_clobber_sha256",
    "population",
    "predecessor_chain_sha256",
    "route_replacement_receipt_id",
    "route_adjudication_sha256",
    "selected_route",
    "target_id",
    "unit_fingerprint_sha256",
    "unit_label",
    "variant_profile_id",
}

EVIDENCE_KINDS = {
    "artifact_custody_record",
    "artifact_signing_record",
    "install_execution_record",
    "license_review_record",
    "postinstall_acceptance_record",
    "reproducibility_record",
    "restore_runbook_record",
    "sbom_record",
    "upgrade_runbook_record",
}
METHOD_BY_KIND = {
    **{
        kind: "offline_release_review"
        for kind in EVIDENCE_KINDS
        if kind not in {"install_execution_record", "postinstall_acceptance_record"}
    },
    "install_execution_record": "authorized_capstone_session",
    "postinstall_acceptance_record": "authorized_capstone_session",
}


class ReleaseError(RuntimeError):
    """A release descriptor, signature, join, or evidence invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str] | set[str], context: str
) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        missing = sorted(wanted - actual)
        extra = sorted(actual - wanted)
        raise ReleaseError(
            f"{context} fields are not exact; missing={missing} extra={extra}"
        )


def _text(value: Any, context: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReleaseError(f"{context} must be non-empty text no longer than {maximum}")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise ReleaseError(f"{context} must contain printable ASCII only")
    return value


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ReleaseError(f"{context} is not a canonical identifier")
    return value


def _principal(value: Any, context: str) -> str:
    try:
        return stage._principal(value, context)
    except stage.BenchEnduranceError as exc:
        raise ReleaseError(str(exc)) from exc


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise ReleaseError(f"{context} must be lowercase SHA-256")
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise ReleaseError(f"{context} must be canonical UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReleaseError(f"{context} is not a valid UTC instant") from exc


def _integer(value: Any, context: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ReleaseError(f"{context} must be an integer >= {minimum}")
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReleaseError(f"{context} must be a forward-slash relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(
            part in {"", ".", ".."}
            or not PATH_COMPONENT_RE.fullmatch(part)
            or part.endswith(".")
            for part in path.parts
        )
    ):
        raise ReleaseError(f"{context} is not a safe relative path")
    return path


def _regular(path: Path, context: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"{context} cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{context} must be a regular non-linked file")
    return metadata


def _source(root: Path, relative: PurePosixPath, context: str) -> Path:
    candidate = root.joinpath(*relative.parts)
    resolved_root = root.resolve()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ReleaseError(f"{context} cannot be resolved: {exc}") from exc
    if not resolved.is_relative_to(resolved_root):
        raise ReleaseError(f"{context} escapes its evidence root")
    _regular(candidate, context)
    return candidate


def _read_regular(path: Path, context: str, maximum: int) -> bytes:
    metadata = _regular(path, context)
    if metadata.st_size > maximum:
        raise ReleaseError(f"{context} exceeds {maximum} bytes")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseError(f"{context} cannot be read: {exc}") from exc
    if len(raw) > maximum:
        raise ReleaseError(f"{context} exceeds {maximum} bytes")
    return raw


def _load_json(path: Path, label: str, *, canonical: bool = True) -> dict[str, Any]:
    raw = _read_regular(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object")
    if canonical and raw != canonical_json_bytes(value):
        raise ReleaseError(f"{label} is not canonical JSON")
    return value


def _require_canonical_sshsig(path: Path, context: str) -> None:
    raw = _read_regular(path, context, MAX_SIGNATURE_BYTES)
    if (
        not raw.startswith(SSHSIG_BEGIN)
        or not raw.endswith(SSHSIG_END)
        or raw.count(SSHSIG_BEGIN) != 1
        or raw.count(SSHSIG_END) != 1
    ):
        raise ReleaseError(f"{context} is not canonical SSHSIG armor")


def _hash_source(path: Path, context: str) -> tuple[int, str]:
    raw = _read_regular(path, context, MAX_EVIDENCE_FILE_BYTES)
    return len(raw), hashlib.sha256(raw).hexdigest()


def _chain_sha(chain: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        b"DCENT-K210-RELEASE-PREDECESSOR-CHAIN-V1\x00" + canonical_json_bytes(chain)
    ).hexdigest()


def _scope_from_chain(chain: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "artifact_set_sha256": chain["artifact_set_sha256"],
        "firmware_version": chain["replacement_firmware_version"],
        "hardware_revision": chain["controller_board_revision"],
        "installed_artifact_sha256": chain["installed_artifact_sha256"],
        "interface_qualification_sha256": chain["interface_qualification_sha256"],
        "no_clobber_sha256": chain["no_clobber_sha256"],
        "population": {
            "kind": "exact_unit",
            "unit_fingerprint_sha256": chain["unit_fingerprint_sha256"],
            "unit_label": chain["unit_label"],
        },
        "predecessor_chain_sha256": _chain_sha(chain),
        "route_replacement_receipt_id": chain["route_replacement_receipt_id"],
        "route_adjudication_sha256": chain["route_adjudication_sha256"],
        "selected_route": chain["selected_route"],
        "target_id": chain["target_id"],
        "unit_fingerprint_sha256": chain["unit_fingerprint_sha256"],
        "unit_label": chain["unit_label"],
        "variant_profile_id": chain["variant_profile_id"],
    }


def _validate_chain(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError("predecessor_chain must be an object")
    _require_exact_keys(value, CHAIN_FIELDS, "predecessor_chain")
    for field in CHAIN_FIELDS:
        if field in {
            "controller_board_revision",
            "endurance_completed_at_utc",
            "replacement_firmware_version",
            "selected_route",
            "target_id",
            "unit_label",
            "variant_profile_id",
        }:
            continue
        _sha(value[field], f"predecessor_chain.{field}")
    _text(
        value["controller_board_revision"],
        "predecessor_chain.controller_board_revision",
        120,
    )
    _utc(
        value["endurance_completed_at_utc"],
        "predecessor_chain.endurance_completed_at_utc",
    )
    _text(
        value["replacement_firmware_version"],
        "predecessor_chain.replacement_firmware_version",
        96,
    )
    for field in ("selected_route", "target_id", "unit_label", "variant_profile_id"):
        _identifier(value[field], f"predecessor_chain.{field}")
    if value["selected_route"] not in ROUTES:
        raise ReleaseError("predecessor_chain.selected_route is unsupported")
    return dict(value)


def _validate_release_scope(value: Any, chain: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError("release_scope must be an object")
    _require_exact_keys(value, RELEASE_SCOPE_FIELDS, "release_scope")
    for field in (
        "artifact_set_sha256",
        "installed_artifact_sha256",
        "interface_qualification_sha256",
        "no_clobber_sha256",
        "predecessor_chain_sha256",
        "route_adjudication_sha256",
        "route_replacement_receipt_id",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], f"release_scope.{field}")
    _text(value["firmware_version"], "release_scope.firmware_version", 96)
    _text(value["hardware_revision"], "release_scope.hardware_revision", 120)
    for field in ("selected_route", "target_id", "unit_label", "variant_profile_id"):
        _identifier(value[field], f"release_scope.{field}")
    population = value["population"]
    if not isinstance(population, dict):
        raise ReleaseError("release_scope.population must be an object")
    _require_exact_keys(
        population,
        {"kind", "unit_fingerprint_sha256", "unit_label"},
        "release_scope.population",
    )
    if population["kind"] != "exact_unit":
        raise ReleaseError("release scope must name one exact unit")
    _sha(
        population["unit_fingerprint_sha256"],
        "release_scope.population.unit_fingerprint_sha256",
    )
    _identifier(population["unit_label"], "release_scope.population.unit_label")
    if value != _scope_from_chain(chain):
        raise ReleaseError(
            "release scope is broadened or does not exact-join endurance"
        )
    return dict(value)


def _stage_chain(
    manifest: Mapping[str, Any],
    bundle: Path,
    operator_public_key: Path,
    witness_public_key: Path,
    expected_operator_key_id: str | None = None,
    expected_witness_key_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        result = stage.verify_bundle(
            manifest,
            bundle,
            operator_public_key,
            witness_public_key,
            expected_operator_key_id,
            expected_witness_key_id,
        )
    except stage.BenchEnduranceError as exc:
        raise ReleaseError(f"endurance predecessor is invalid: {exc}") from exc
    if (
        result.get("qualification_class") != stage.QUALIFICATION_ENDURANCE
        or result.get("outcome") != "passed"
        or result.get("endurance_faults_gate_eligible") is not True
        or result.get("authority_granted") is not False
    ):
        raise ReleaseError(
            "predecessor is not a passing, non-authorizing endurance receipt"
        )
    receipt = _load_json(bundle / stage.RECEIPT_NAME, "endurance receipt")
    try:
        stage._validate_receipt(receipt)
    except stage.BenchEnduranceError as exc:
        raise ReleaseError(f"endurance receipt projection is invalid: {exc}") from exc
    if (
        receipt["qualification_class"] != stage.QUALIFICATION_ENDURANCE
        or receipt["outcome"] != "passed"
        or receipt["results"]["endurance_faults"]["eligible"] is not True
    ):
        raise ReleaseError("endurance receipt is not the final passing stage")
    chain = {
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "capture_receipt_id": receipt["capture_receipt_id"],
        "capture_set_sha256": receipt["capture_set_sha256"],
        "controller_board_revision": receipt["controller_board_revision"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "endurance_completed_at_utc": receipt["completed_at_utc"],
        "endurance_evidence_set_sha256": receipt["evidence_set_sha256"],
        "endurance_receipt_id": receipt["receipt_id"],
        "fixture_evidence_set_sha256": receipt["fixture_evidence_set_sha256"],
        "fixture_receipt_id": receipt["fixture_receipt_id"],
        "installed_artifact_sha256": receipt["installed_artifact_sha256"],
        "prior_bench_evidence_set_sha256": receipt["prior_stage_evidence_set_sha256"],
        "prior_bench_receipt_id": receipt["prior_stage_receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "no_clobber_sha256": receipt["no_clobber_sha256"],
        "replacement_firmware_version": receipt["replacement_firmware_version"],
        "route_replacement_receipt_id": receipt["route_replacement_receipt_id"],
        "route_rollback_receipt_id": receipt["route_rollback_receipt_id"],
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "selected_route": receipt["selected_route"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "stock_restoration_sha256": receipt["stock_restoration_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "variant_profile_id": receipt["variant_profile_id"],
    }
    result_field_by_chain_field = {
        "boot_policy_receipt_id": "boot_policy_receipt_id",
        "capture_receipt_id": "capture_receipt_id",
        "capture_set_sha256": "capture_set_sha256",
        "controller_board_revision": "controller_board_revision",
        "discovery_receipt_id": "discovery_receipt_id",
        "endurance_evidence_set_sha256": "evidence_set_sha256",
        "endurance_receipt_id": "receipt_id",
        "fixture_evidence_set_sha256": "fixture_evidence_set_sha256",
        "fixture_receipt_id": "fixture_receipt_id",
        "installed_artifact_sha256": "installed_artifact_sha256",
        "prior_bench_evidence_set_sha256": "prior_stage_evidence_set_sha256",
        "prior_bench_receipt_id": "prior_stage_receipt_id",
        "recovery_receipt_id": "recovery_receipt_id",
        "artifact_set_sha256": "artifact_set_sha256",
        "interface_qualification_sha256": "interface_qualification_sha256",
        "no_clobber_sha256": "no_clobber_sha256",
        "replacement_firmware_version": "replacement_firmware_version",
        "route_replacement_receipt_id": "route_replacement_receipt_id",
        "route_rollback_receipt_id": "route_rollback_receipt_id",
        "route_adjudication_sha256": "route_adjudication_sha256",
        "selected_route": "selected_route",
        "stock_backup_set_sha256": "stock_backup_set_sha256",
        "stock_restoration_sha256": "stock_restoration_sha256",
        "target_id": "target_id",
        "unit_fingerprint_sha256": "unit_fingerprint_sha256",
        "unit_label": "unit_label",
        "variant_profile_id": "variant_profile_id",
    }
    for chain_field, result_field in result_field_by_chain_field.items():
        if result.get(result_field) != chain[chain_field]:
            raise ReleaseError(
                f"endurance verifier result {result_field} does not exact-join receipt"
            )
    return receipt, _validate_chain(chain)


def _validate_signing(value: Any, contracts: Mapping[str, tuple[str, str]]) -> None:
    if not isinstance(value, dict):
        raise ReleaseError("signing must be an object")
    _require_exact_keys(value, set(contracts), "signing")
    key_ids = set()
    for role, (role_name, namespace) in contracts.items():
        item = value[role]
        if not isinstance(item, dict):
            raise ReleaseError(f"signing.{role} must be an object")
        _require_exact_keys(
            item,
            {"algorithm", "key_id_sha256", "namespace", "role"},
            f"signing.{role}",
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role_name
        ):
            raise ReleaseError(f"signing.{role} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{role}.key_id_sha256"))
    if len(key_ids) != len(contracts):
        raise ReleaseError("release signing keys must be distinct")


PREAUTH_SIGNING = {
    "preauthorizer": (PREAUTHORIZER_ROLE, PREAUTHORIZER_NAMESPACE),
    "reviewer": (REVIEWER_ROLE, REVIEWER_NAMESPACE),
}
INSTALL_SIGNING = {
    "installer": (INSTALLER_ROLE, INSTALLER_NAMESPACE),
    "witness": (WITNESS_ROLE, WITNESS_NAMESPACE),
}


def _validate_preauthorization_core(value: Mapping[str, Any], *, signed: bool) -> None:
    fields = {
        "issued_at_utc",
        "kind",
        "permitted_actions",
        "preauthorizer_id",
        "preauthorizer_signed_at_utc",
        "predecessor_chain",
        "release_scope",
        "reviewer_id",
        "reviewer_signed_at_utc",
        "schema_version",
        "scope",
        "valid_from_utc",
        "valid_until_utc",
    }
    signed_only = {"authority_ceiling", "disposition", "preauthorization_id", "signing"}
    _require_exact_keys(
        value, fields | signed_only if signed else fields, "preauthorization"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise ReleaseError("preauthorization schema or scope mismatch")
    if value["kind"] != (PREAUTH_KIND if signed else PREAUTH_DESCRIPTOR_KIND):
        raise ReleaseError("preauthorization kind mismatch")
    preauthorizer = _principal(value["preauthorizer_id"], "preauthorizer_id")
    reviewer = _principal(value["reviewer_id"], "reviewer_id")
    if preauthorizer == reviewer:
        raise ReleaseError("preauthorizer and reviewer principals must be distinct")
    if value["permitted_actions"] != sorted(PERMITTED_ACTIONS):
        raise ReleaseError("preauthorization permitted action set is not exact")
    chain = _validate_chain(value["predecessor_chain"])
    _validate_release_scope(value["release_scope"], chain)
    issued = _utc(value["issued_at_utc"], "issued_at_utc")
    preauthorizer_signed = _utc(
        value["preauthorizer_signed_at_utc"], "preauthorizer_signed_at_utc"
    )
    reviewer_signed = _utc(value["reviewer_signed_at_utc"], "reviewer_signed_at_utc")
    valid_from = _utc(value["valid_from_utc"], "valid_from_utc")
    valid_until = _utc(value["valid_until_utc"], "valid_until_utc")
    endurance_completed = _utc(
        chain["endurance_completed_at_utc"],
        "predecessor_chain.endurance_completed_at_utc",
    )
    if (
        issued < endurance_completed
        or issued > preauthorizer_signed
        or issued > reviewer_signed
        or preauthorizer_signed >= valid_from
        or reviewer_signed >= valid_from
        or valid_from >= valid_until
    ):
        raise ReleaseError("preauthorization chronology is invalid")
    if signed:
        if value["authority_ceiling"] != PREAUTHORITY_CEILING:
            raise ReleaseError("preauthorization authority ceiling drifted")
        if value["disposition"] != PREAUTH_DISPOSITION:
            raise ReleaseError("preauthorization disposition drifted")
        _sha(value["preauthorization_id"], "preauthorization_id")
        _validate_signing(value["signing"], PREAUTH_SIGNING)


def _preauthorization_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {"authority_ceiling", "disposition", "preauthorization_id", "signing"}
    result = {key: item for key, item in value.items() if key not in excluded}
    result["kind"] = PREAUTH_DESCRIPTOR_KIND
    return json.loads(json.dumps(result))


def _validate_preauthorization(value: Mapping[str, Any]) -> None:
    _validate_preauthorization_core(value, signed=True)
    without_id = {
        key: item for key, item in value.items() if key != "preauthorization_id"
    }
    expected = hashlib.sha256(
        b"DCENT-K210-RELEASE-PREAUTHORIZATION-ID-V1\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if value["preauthorization_id"] != expected:
        raise ReleaseError("preauthorization ID mismatch")


def build_preauthorization(
    descriptor: Mapping[str, Any],
    preauthorizer_private_key: Path,
    reviewer_private_key: Path,
) -> dict[str, Any]:
    _validate_preauthorization_core(descriptor, signed=False)
    try:
        preauthorizer_key = discovery.inspect_private_key(preauthorizer_private_key)
        reviewer_key = discovery.inspect_private_key(reviewer_private_key)
    except discovery.DiscoveryError as exc:
        raise ReleaseError(f"preauthorization signing key is invalid: {exc}") from exc
    if preauthorizer_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise ReleaseError("preauthorizer and reviewer keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["kind"] = PREAUTH_KIND
    value: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(PREAUTHORITY_CEILING),
        "disposition": PREAUTH_DISPOSITION,
        "signing": {
            "preauthorizer": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": preauthorizer_key["key_id_sha256"],
                "namespace": PREAUTHORIZER_NAMESPACE,
                "role": PREAUTHORIZER_ROLE,
            },
            "reviewer": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": reviewer_key["key_id_sha256"],
                "namespace": REVIEWER_NAMESPACE,
                "role": REVIEWER_ROLE,
            },
        },
    }
    value["preauthorization_id"] = hashlib.sha256(
        b"DCENT-K210-RELEASE-PREAUTHORIZATION-ID-V1\x00" + canonical_json_bytes(value)
    ).hexdigest()
    _validate_preauthorization(value)
    return value


def _verify_preauthorization_members(bundle: Path) -> None:
    expected = {
        PREAUTHORIZATION_NAME,
        PREAUTHORIZER_SIGNATURE_NAME,
        REVIEWER_SIGNATURE_NAME,
    }
    observed = set()
    try:
        entries = list(bundle.rglob("*"))
    except OSError as exc:
        raise ReleaseError(f"cannot enumerate preauthorization bundle: {exc}") from exc
    for entry in entries:
        relative = entry.relative_to(bundle).as_posix()
        metadata = entry.lstat()
        if discovery._is_link_or_reparse(metadata):
            raise ReleaseError(
                f"preauthorization bundle contains linked member: {relative}"
            )
        if stat.S_ISREG(metadata.st_mode):
            observed.add(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError(
                f"preauthorization bundle contains extra directory: {relative}"
            )
        else:
            raise ReleaseError(
                f"preauthorization bundle contains special member: {relative}"
            )
    if observed != expected:
        raise ReleaseError("preauthorization bundle member set is not exact")


def create_preauthorization_bundle(
    descriptor_path: Path,
    preauthorizer_private_key: Path,
    reviewer_private_key: Path,
    bundle_out: Path,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise ReleaseError(
            f"refusing to overwrite preauthorization bundle: {bundle_out}"
        )
    descriptor = _load_json(
        descriptor_path, "preauthorization descriptor", canonical=False
    )
    value = build_preauthorization(
        descriptor, preauthorizer_private_key, reviewer_private_key
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        path = temporary / PREAUTHORIZATION_NAME
        raw = canonical_json_bytes(value)
        path.write_bytes(raw)
        (temporary / PREAUTHORIZER_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(
                path, preauthorizer_private_key, PREAUTHORIZER_NAMESPACE
            )
        )
        (temporary / REVIEWER_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(path, reviewer_private_key, REVIEWER_NAMESPACE)
        )
        _verify_preauthorization_members(temporary)
        os.replace(temporary, bundle_out.resolve())
    except discovery.DiscoveryError as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        raise ReleaseError(str(exc)) from exc
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return value


def verify_preauthorization_bundle(
    bundle: Path,
    preauthorizer_public_key: Path,
    reviewer_public_key: Path,
    expected_preauthorizer_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise ReleaseError(
            f"preauthorization bundle cannot be inspected: {exc}"
        ) from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseError("preauthorization bundle must be a non-symlink directory")
    value = _load_json(bundle / PREAUTHORIZATION_NAME, "preauthorization")
    _validate_preauthorization(value)
    try:
        preauthorizer_key = discovery.inspect_public_key(preauthorizer_public_key)
        reviewer_key = discovery.inspect_public_key(reviewer_public_key)
        raw = _read_regular(
            bundle / PREAUTHORIZATION_NAME, "preauthorization", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise ReleaseError(f"preauthorization trust input is invalid: {exc}") from exc
    if preauthorizer_key["key_id_sha256"] == reviewer_key["key_id_sha256"]:
        raise ReleaseError("preauthorizer and reviewer trust keys must be distinct")
    checks = (
        (
            "preauthorizer",
            preauthorizer_key,
            expected_preauthorizer_key_id,
            PREAUTHORIZER_SIGNATURE_NAME,
            value["preauthorizer_id"],
            PREAUTHORIZER_NAMESPACE,
        ),
        (
            "reviewer",
            reviewer_key,
            expected_reviewer_key_id,
            REVIEWER_SIGNATURE_NAME,
            value["reviewer_id"],
            REVIEWER_NAMESPACE,
        ),
    )
    for role, key, pinned, signature_name, principal, namespace in checks:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise ReleaseError(f"{role} public key does not match its trust anchor")
        if value["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise ReleaseError(f"preauthorization {role} signer is not trusted")
        _require_canonical_sshsig(
            bundle / signature_name, f"preauthorization {role} signature"
        )
        try:
            discovery.verify_sshsig_bytes(
                raw,
                bundle / signature_name,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise ReleaseError(
                f"preauthorization {role} signature is invalid: {exc}"
            ) from exc
    _verify_preauthorization_members(bundle)
    release_scope_sha256 = hashlib.sha256(
        b"DCENT-K210-RELEASE-EXACT-SCOPE-V1\x00"
        + canonical_json_bytes(value["release_scope"])
    ).hexdigest()
    return {
        "actions": list(value["permitted_actions"]),
        "artifact_set_sha256": value["release_scope"]["artifact_set_sha256"],
        "authority_granted": False,
        "firmware_version": value["release_scope"]["firmware_version"],
        "generic_future_authority_granted": False,
        "hardware_revision": value["release_scope"]["hardware_revision"],
        "endurance_evidence_set_sha256": value["predecessor_chain"][
            "endurance_evidence_set_sha256"
        ],
        "endurance_receipt_id": value["predecessor_chain"]["endurance_receipt_id"],
        "install_authority_scope_eligible": True,
        "installed_artifact_sha256": value["release_scope"][
            "installed_artifact_sha256"
        ],
        "interface_qualification_sha256": value["release_scope"][
            "interface_qualification_sha256"
        ],
        "no_clobber_sha256": value["release_scope"]["no_clobber_sha256"],
        "preauthorization": value,
        "preauthorization_id": value["preauthorization_id"],
        "preauthorization_sha256": hashlib.sha256(raw).hexdigest(),
        "preauthorizer_signed_at_utc": value["preauthorizer_signed_at_utc"],
        "preauthorizer_key_id_sha256": preauthorizer_key["key_id_sha256"],
        "predecessor_chain_sha256": value["release_scope"]["predecessor_chain_sha256"],
        "release_scope_sha256": release_scope_sha256,
        "route_replacement_receipt_id": value["release_scope"][
            "route_replacement_receipt_id"
        ],
        "reviewer_key_id_sha256": reviewer_key["key_id_sha256"],
        "reviewer_signed_at_utc": value["reviewer_signed_at_utc"],
        "route_adjudication_sha256": value["release_scope"][
            "route_adjudication_sha256"
        ],
        "selected_route": value["release_scope"]["selected_route"],
        "state": "verified_exact_scope_preauthorization",
        "target_id": value["release_scope"]["target_id"],
        "unit_fingerprint_sha256": value["release_scope"]["unit_fingerprint_sha256"],
        "unit_label": value["release_scope"]["unit_label"],
        "valid_from_utc": value["valid_from_utc"],
        "valid_until_utc": value["valid_until_utc"],
        "variant_profile_id": value["release_scope"]["variant_profile_id"],
    }


def verify_preauthorization(
    bundle: Path,
    preauthorizer_public_key: Path,
    reviewer_public_key: Path,
    expected_preauthorizer_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    """Verify one immutable exact-scope preauthorization bundle.

    This public alias is intentionally independent of the later install and
    endurance trust inputs so a workflow lane can admit the signed scope
    before the final capstone begins.
    """

    return verify_preauthorization_bundle(
        bundle,
        preauthorizer_public_key,
        reviewer_public_key,
        expected_preauthorizer_key_id,
        expected_reviewer_key_id,
    )


def _validate_evidence(value: Any, *, hashed: bool) -> None:
    if not isinstance(value, list) or len(value) != len(EVIDENCE_KINDS):
        raise ReleaseError(
            f"evidence must contain exactly {len(EVIDENCE_KINDS)} records"
        )
    keys = {"acquired_at_utc", "id", "kind", "media_type", "method", "path"}
    if hashed:
        keys |= {"bytes", "sha256"}
    ids: set[str] = set()
    paths: set[str] = set()
    kinds: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ReleaseError(f"evidence[{index}] must be an object")
        _require_exact_keys(item, keys, f"evidence[{index}]")
        evidence_id = _identifier(item["id"], f"evidence[{index}].id")
        if evidence_id in ids:
            raise ReleaseError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = _identifier(item["kind"], f"evidence[{index}].kind")
        kinds.append(kind)
        if kind not in EVIDENCE_KINDS:
            raise ReleaseError(f"evidence kind {kind!r} is unsupported")
        if item["media_type"] != "application/json":
            raise ReleaseError(f"evidence {evidence_id} media type is invalid")
        if item["method"] != METHOD_BY_KIND[kind]:
            raise ReleaseError(f"evidence {evidence_id} method is invalid")
        relative = str(_safe_path(item["path"], f"evidence[{index}].path"))
        if relative in paths:
            raise ReleaseError("evidence paths must be unique")
        paths.add(relative)
        _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if hashed:
            _integer(item["bytes"], f"evidence[{index}].bytes", 1)
            if item["bytes"] > MAX_EVIDENCE_FILE_BYTES:
                raise ReleaseError(f"evidence[{index}] exceeds the per-file byte limit")
            _sha(item["sha256"], f"evidence[{index}].sha256")
    if set(kinds) != EVIDENCE_KINDS or len(kinds) != len(set(kinds)):
        raise ReleaseError("evidence kinds must occur exactly once")


def _validate_release_core(
    value: Mapping[str, Any],
    preauthorization: Mapping[str, Any],
    chain: Mapping[str, Any],
    *,
    receipt: bool,
) -> None:
    fields = {
        "actions_performed",
        "completed_at_utc",
        "endurance_bundle_path",
        "evidence",
        "installer_id",
        "installer_signed_at_utc",
        "kind",
        "preauthorization_id",
        "preauthorization_sha256",
        "predecessor_chain",
        "release_scope",
        "schema_version",
        "scope",
        "started_at_utc",
        "witness_id",
        "witness_signed_at_utc",
    }
    receipt_only = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "evidence_set_sha256",
        "receipt_id",
        "result",
        "signing",
    }
    _require_exact_keys(
        value, fields | receipt_only if receipt else fields, "release record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise ReleaseError("release schema or scope mismatch")
    if value["kind"] != (RECEIPT_KIND if receipt else DESCRIPTOR_KIND):
        raise ReleaseError("release record kind mismatch")
    installer = _principal(value["installer_id"], "installer_id")
    witness = _principal(value["witness_id"], "witness_id")
    release_principals = {
        preauthorization["preauthorizer_id"],
        preauthorization["reviewer_id"],
        installer,
        witness,
    }
    if len(release_principals) != 4:
        raise ReleaseError("all four release principals must be distinct")
    _sha(value["preauthorization_id"], "preauthorization_id")
    _sha(value["preauthorization_sha256"], "preauthorization_sha256")
    expected_preauth_sha = hashlib.sha256(
        canonical_json_bytes(preauthorization)
    ).hexdigest()
    if (
        value["preauthorization_id"] != preauthorization["preauthorization_id"]
        or value["preauthorization_sha256"] != expected_preauth_sha
    ):
        raise ReleaseError("release record does not exact-join preauthorization")
    normalized_chain = _validate_chain(value["predecessor_chain"])
    if (
        normalized_chain != chain
        or normalized_chain != preauthorization["predecessor_chain"]
    ):
        raise ReleaseError("release predecessor chain is spliced")
    _validate_release_scope(value["release_scope"], normalized_chain)
    if value["release_scope"] != preauthorization["release_scope"]:
        raise ReleaseError("release scope differs from signed preauthorization")
    if value["actions_performed"] != sorted(PERMITTED_ACTIONS):
        raise ReleaseError("release action record is incomplete or broadened")
    if value["endurance_bundle_path"] != PREDECESSOR_DIRECTORY:
        raise ReleaseError("endurance bundle path drifted")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    installer_signed = _utc(value["installer_signed_at_utc"], "installer_signed_at_utc")
    witness_signed = _utc(value["witness_signed_at_utc"], "witness_signed_at_utc")
    valid_from = _utc(
        preauthorization["valid_from_utc"], "preauthorization.valid_from_utc"
    )
    valid_until = _utc(
        preauthorization["valid_until_utc"], "preauthorization.valid_until_utc"
    )
    if not valid_from <= started < completed <= valid_until:
        raise ReleaseError("capstone is outside the signed authorization window")
    if not completed <= installer_signed <= valid_until or not (
        completed <= witness_signed <= valid_until
    ):
        raise ReleaseError(
            "completed receipt signing is outside the authorization window"
        )
    _validate_evidence(value["evidence"], hashed=receipt)
    for index, item in enumerate(value["evidence"]):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if acquired > completed:
            raise ReleaseError(
                f"evidence[{index}] was acquired after capstone completion"
            )
        if item["kind"] in {
            "install_execution_record",
            "postinstall_acceptance_record",
        }:
            if not started <= acquired <= completed:
                raise ReleaseError(f"evidence[{index}] is outside capstone execution")
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise ReleaseError("release authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise ReleaseError("release disposition drifted")
        if value["result"] != RELEASE_RESULT:
            raise ReleaseError("release result projection drifted")
        for field in ("descriptor_sha256", "evidence_set_sha256", "receipt_id"):
            _sha(value[field], field)
        _validate_signing(value["signing"], INSTALL_SIGNING)


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "evidence_set_sha256",
        "receipt_id",
        "result",
        "signing",
    }
    value = json.loads(
        json.dumps({key: item for key, item in receipt.items() if key not in excluded})
    )
    value["kind"] = DESCRIPTOR_KIND
    for item in value["evidence"]:
        item.pop("bytes", None)
        item.pop("sha256", None)
    return value


def _evidence_projection(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(item) for item in sorted(receipt["evidence"], key=lambda row: row["id"])
    ]


def _validate_receipt(
    receipt: Mapping[str, Any],
    preauthorization: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> None:
    _validate_release_core(receipt, preauthorization, chain, receipt=True)
    descriptor_sha = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    if receipt["descriptor_sha256"] != descriptor_sha:
        raise ReleaseError("release descriptor SHA-256 mismatch")
    evidence_sha = hashlib.sha256(
        b"DCENT-K210-RELEASE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    if receipt["evidence_set_sha256"] != evidence_sha:
        raise ReleaseError("release evidence-set SHA-256 mismatch")
    without_id = {key: item for key, item in receipt.items() if key != "receipt_id"}
    expected = hashlib.sha256(
        b"DCENT-K210-RELEASE-RECEIPT-ID-V1\x00" + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt["receipt_id"] != expected:
        raise ReleaseError("release receipt ID mismatch")


def _records_by_kind(
    receipt: Mapping[str, Any], root: Path
) -> dict[str, dict[str, Any]]:
    result = {}
    for item in receipt["evidence"]:
        source = _source(
            root,
            _safe_path(item["path"], f"evidence {item['id']} path"),
            f"evidence {item['id']}",
        )
        result[item["kind"]] = _load_json(source, f"evidence {item['id']}")
    return result


def _validate_evidence_semantics(
    receipt: Mapping[str, Any], records: Mapping[str, Mapping[str, Any]]
) -> None:
    scope = receipt["release_scope"]
    chain = receipt["predecessor_chain"]

    custody = records["artifact_custody_record"]
    _require_exact_keys(
        custody,
        {
            "artifact_set_sha256",
            "custody_complete",
            "custody_log_sha256",
            "firmware_version",
            "kind",
            "route_replacement_receipt_id",
            "unexplained_gaps",
        },
        "artifact custody record",
    )
    if (
        custody["kind"] != "dcent_k210_release_artifact_custody"
        or custody["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or custody["firmware_version"] != scope["firmware_version"]
        or custody["route_replacement_receipt_id"]
        != scope["route_replacement_receipt_id"]
        or custody["custody_complete"] is not True
        or custody["unexplained_gaps"] != []
    ):
        raise ReleaseError("artifact custody is incomplete or does not exact-join")
    _sha(custody["custody_log_sha256"], "artifact custody log SHA-256")

    reproducibility = records["reproducibility_record"]
    _require_exact_keys(
        reproducibility,
        {
            "artifact_bytes_match",
            "artifact_set_sha256",
            "build_inputs_pinned",
            "independent_build_count",
            "kind",
            "source_archive_sha256",
        },
        "reproducibility record",
    )
    if (
        reproducibility["kind"] != "dcent_k210_release_reproducibility_review"
        or reproducibility["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or _integer(
            reproducibility["independent_build_count"], "independent_build_count", 2
        )
        < 2
        or reproducibility["artifact_bytes_match"] is not True
        or reproducibility["build_inputs_pinned"] is not True
    ):
        raise ReleaseError("reproducibility review is incomplete")
    _sha(reproducibility["source_archive_sha256"], "source archive SHA-256")

    signing = records["artifact_signing_record"]
    _require_exact_keys(
        signing,
        {
            "artifact_set_sha256",
            "builder_key_id_sha256",
            "kind",
            "route_replacement_receipt_id",
            "reviewer_key_id_sha256",
            "signatures_verified",
        },
        "artifact signing record",
    )
    builder_key = _sha(signing["builder_key_id_sha256"], "builder key ID")
    reviewer_key = _sha(signing["reviewer_key_id_sha256"], "reviewer key ID")
    if (
        signing["kind"] != "dcent_k210_release_artifact_signing_review"
        or signing["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or signing["route_replacement_receipt_id"]
        != scope["route_replacement_receipt_id"]
        or signing["signatures_verified"] is not True
        or builder_key == reviewer_key
    ):
        raise ReleaseError("artifact signing review is incomplete")

    sbom = records["sbom_record"]
    _require_exact_keys(
        sbom,
        {"artifact_set_sha256", "complete", "kind", "sbom_sha256"},
        "SBOM record",
    )
    if (
        sbom["kind"] != "dcent_k210_release_sbom_review"
        or sbom["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or sbom["complete"] is not True
    ):
        raise ReleaseError("SBOM review is incomplete")
    _sha(sbom["sbom_sha256"], "SBOM SHA-256")

    license_review = records["license_review_record"]
    _require_exact_keys(
        license_review,
        {
            "approved",
            "artifact_set_sha256",
            "kind",
            "review_sha256",
            "restricted_vendor_code_included",
        },
        "license review record",
    )
    if (
        license_review["kind"] != "dcent_k210_release_license_review"
        or license_review["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or license_review["approved"] is not True
        or license_review["restricted_vendor_code_included"] is not False
    ):
        raise ReleaseError("license review is incomplete")
    _sha(license_review["review_sha256"], "license review SHA-256")

    upgrade = records["upgrade_runbook_record"]
    _require_exact_keys(
        upgrade,
        {
            "artifact_set_sha256",
            "kind",
            "rollback_on_failure",
            "runbook_sha256",
            "selected_route",
            "tested",
        },
        "upgrade runbook record",
    )
    if (
        upgrade["kind"] != "dcent_k210_release_upgrade_runbook"
        or upgrade["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or upgrade["selected_route"] != scope["selected_route"]
        or upgrade["tested"] is not True
        or upgrade["rollback_on_failure"] is not True
    ):
        raise ReleaseError("upgrade runbook is incomplete")
    _sha(upgrade["runbook_sha256"], "upgrade runbook SHA-256")

    restore = records["restore_runbook_record"]
    _require_exact_keys(
        restore,
        {
            "kind",
            "runbook_sha256",
            "selected_route",
            "stock_backup_set_sha256",
            "tested",
        },
        "restore runbook record",
    )
    if (
        restore["kind"] != "dcent_k210_release_restore_runbook"
        or restore["selected_route"] != scope["selected_route"]
        or restore["stock_backup_set_sha256"] != chain["stock_backup_set_sha256"]
        or restore["tested"] is not True
    ):
        raise ReleaseError("restore runbook is incomplete")
    _sha(restore["runbook_sha256"], "restore runbook SHA-256")

    install = records["install_execution_record"]
    _require_exact_keys(
        install,
        {
            "actions_performed",
            "artifact_set_sha256",
            "completed_at_utc",
            "errors",
            "full_readback_matches",
            "installed_artifact_sha256",
            "kind",
            "preauthorization_id",
            "started_at_utc",
            "unauthorized_actions_performed",
            "unit_fingerprint_sha256",
        },
        "install execution record",
    )
    if (
        install["kind"] != "dcent_k210_release_install_execution"
        or install["preauthorization_id"] != receipt["preauthorization_id"]
        or install["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or install["installed_artifact_sha256"] != scope["installed_artifact_sha256"]
        or install["unit_fingerprint_sha256"] != scope["unit_fingerprint_sha256"]
        or install["started_at_utc"] != receipt["started_at_utc"]
        or install["completed_at_utc"] != receipt["completed_at_utc"]
        or install["actions_performed"] != sorted(PERMITTED_ACTIONS)
        or install["full_readback_matches"] is not True
        or install["unauthorized_actions_performed"] is not False
        or install["errors"] != []
    ):
        raise ReleaseError("install execution evidence is incomplete or out of scope")

    acceptance = records["postinstall_acceptance_record"]
    _require_exact_keys(
        acceptance,
        {
            "accepted",
            "anomalies",
            "artifact_set_sha256",
            "boot_succeeded",
            "firmware_version",
            "kind",
            "rollback_ready",
            "runtime_identity_matches",
            "safety_controls_ready",
            "target_id",
            "telemetry_ready",
            "unit_fingerprint_sha256",
        },
        "postinstall acceptance record",
    )
    if (
        acceptance["kind"] != "dcent_k210_release_postinstall_acceptance"
        or acceptance["artifact_set_sha256"] != scope["artifact_set_sha256"]
        or acceptance["firmware_version"] != scope["firmware_version"]
        or acceptance["target_id"] != scope["target_id"]
        or acceptance["unit_fingerprint_sha256"] != scope["unit_fingerprint_sha256"]
        or any(
            acceptance[field] is not True
            for field in (
                "accepted",
                "boot_succeeded",
                "rollback_ready",
                "runtime_identity_matches",
                "safety_controls_ready",
                "telemetry_ready",
            )
        )
        or acceptance["anomalies"] != []
    ):
        raise ReleaseError("postinstall acceptance is incomplete")


def build_receipt(
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    preauthorization: Mapping[str, Any],
    chain: Mapping[str, Any],
    installer_private_key: Path,
    witness_private_key: Path,
    forbidden_release_key_ids: Sequence[str] = (),
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_preauthorization(preauthorization)
    normalized_chain = _validate_chain(chain)
    _validate_release_core(
        descriptor, preauthorization, normalized_chain, receipt=False
    )
    evidence = []
    sources = {}
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        source = _source(
            evidence_root,
            _safe_path(item["path"], f"evidence {item['id']} path"),
            f"evidence {item['id']}",
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise ReleaseError("release evidence exceeds the aggregate byte limit")
        evidence.append({**item, "bytes": size, "sha256": digest})
        sources[item["id"]] = source
    try:
        installer_key = discovery.inspect_private_key(installer_private_key)
        witness_key = discovery.inspect_private_key(witness_private_key)
    except discovery.DiscoveryError as exc:
        raise ReleaseError(f"install signing key is invalid: {exc}") from exc
    all_key_ids = set(forbidden_release_key_ids) | {
        installer_key["key_id_sha256"],
        witness_key["key_id_sha256"],
    }
    if len(all_key_ids) != len(set(forbidden_release_key_ids)) + 2:
        raise ReleaseError("all four release signing keys must be distinct")
    normalized = json.loads(json.dumps(descriptor))
    normalized["evidence"] = evidence
    normalized["kind"] = RECEIPT_KIND
    receipt: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "disposition": DISPOSITION,
        "result": dict(RELEASE_RESULT),
        "signing": {
            "installer": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": installer_key["key_id_sha256"],
                "namespace": INSTALLER_NAMESPACE,
                "role": INSTALLER_ROLE,
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
    receipt["evidence_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-RELEASE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-RELEASE-RECEIPT-ID-V1\x00" + canonical_json_bytes(receipt)
    ).hexdigest()
    _validate_receipt(receipt, preauthorization, normalized_chain)
    _validate_evidence_semantics(receipt, _records_by_kind(receipt, evidence_root))
    return receipt, sources


def _copy_tree(source: Path, destination: Path, label: str) -> None:
    try:
        root_meta = source.lstat()
    except OSError as exc:
        raise ReleaseError(f"{label} cannot be inspected for snapshot: {exc}") from exc
    if discovery._is_link_or_reparse(root_meta) or not stat.S_ISDIR(root_meta.st_mode):
        raise ReleaseError(f"{label} snapshot source must be a non-symlink directory")
    destination.mkdir()
    for entry in source.rglob("*"):
        relative = entry.relative_to(source)
        target = destination / relative
        metadata = entry.lstat()
        if discovery._is_link_or_reparse(metadata):
            raise ReleaseError(f"{label} contains linked member: {relative.as_posix()}")
        if stat.S_ISDIR(metadata.st_mode):
            target.mkdir(parents=True, exist_ok=True)
        elif stat.S_ISREG(metadata.st_mode):
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(entry, target)
        else:
            raise ReleaseError(
                f"{label} contains special member: {relative.as_posix()}"
            )


def _verify_release_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected_owned = {
        RECEIPT_NAME,
        INSTALLER_SIGNATURE_NAME,
        WITNESS_SIGNATURE_NAME,
        f"{AUTHORIZATION_DIRECTORY}/{PREAUTHORIZATION_NAME}",
        f"{AUTHORIZATION_DIRECTORY}/{PREAUTHORIZER_SIGNATURE_NAME}",
        f"{AUTHORIZATION_DIRECTORY}/{REVIEWER_SIGNATURE_NAME}",
    } | {f"{EVIDENCE_DIRECTORY}/{item['path']}" for item in receipt["evidence"]}
    observed_owned = set()
    expected_directories = {
        AUTHORIZATION_DIRECTORY,
        EVIDENCE_DIRECTORY,
        "predecessor",
        PREDECESSOR_DIRECTORY,
    }
    for item in receipt["evidence"]:
        relative = PurePosixPath(EVIDENCE_DIRECTORY) / _safe_path(
            item["path"], f"evidence {item['id']} path"
        )
        expected_directories.update(str(parent) for parent in relative.parents)
    expected_directories.discard(".")
    predecessor_prefix = PREDECESSOR_DIRECTORY + "/"
    predecessor_files = 0
    try:
        entries = list(bundle.rglob("*"))
    except OSError as exc:
        raise ReleaseError(f"cannot enumerate release bundle: {exc}") from exc
    for entry in entries:
        relative = entry.relative_to(bundle).as_posix()
        metadata = entry.lstat()
        if discovery._is_link_or_reparse(metadata):
            raise ReleaseError(f"release bundle contains linked member: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            if relative.startswith(predecessor_prefix):
                predecessor_files += 1
            else:
                observed_owned.add(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            if (
                not relative.startswith(predecessor_prefix)
                and relative not in expected_directories
            ):
                raise ReleaseError(
                    f"release bundle contains extra directory: {relative}"
                )
        else:
            raise ReleaseError(f"release bundle contains special member: {relative}")
        if relative.startswith("predecessor/") and not (
            relative == PREDECESSOR_DIRECTORY or relative.startswith(predecessor_prefix)
        ):
            raise ReleaseError(
                "release bundle contains an unexpected predecessor member"
            )
    if observed_owned != expected_owned or predecessor_files == 0:
        raise ReleaseError("release bundle member set is not exact")


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    preauthorization_bundle: Path,
    preauthorizer_public_key: Path,
    reviewer_public_key: Path,
    endurance_bundle: Path,
    endurance_operator_public_key: Path,
    endurance_witness_public_key: Path,
    installer_private_key: Path,
    witness_private_key: Path,
    bundle_out: Path,
    expected_preauthorizer_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
    expected_endurance_operator_key_id: str | None = None,
    expected_endurance_witness_key_id: str | None = None,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise ReleaseError(f"refusing to overwrite release bundle: {bundle_out}")
    preauth_result = verify_preauthorization_bundle(
        preauthorization_bundle,
        preauthorizer_public_key,
        reviewer_public_key,
        expected_preauthorizer_key_id,
        expected_reviewer_key_id,
    )
    _, chain = _stage_chain(
        manifest,
        endurance_bundle,
        endurance_operator_public_key,
        endurance_witness_public_key,
        expected_endurance_operator_key_id,
        expected_endurance_witness_key_id,
    )
    descriptor = _load_json(descriptor_path, "release descriptor", canonical=False)
    preauthorization = preauth_result["preauthorization"]
    receipt, sources = build_receipt(
        descriptor,
        evidence_root,
        preauthorization,
        chain,
        installer_private_key,
        witness_private_key,
        (
            preauth_result["preauthorizer_key_id_sha256"],
            preauth_result["reviewer_key_id_sha256"],
        ),
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        authorization_out = temporary / AUTHORIZATION_DIRECTORY
        _copy_tree(
            preauthorization_bundle,
            authorization_out,
            "preauthorization bundle",
        )
        evidence_out = temporary / EVIDENCE_DIRECTORY
        evidence_out.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = evidence_out.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_source(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise ReleaseError(f"evidence {item['id']} changed during snapshot")
        predecessor_parent = temporary / "predecessor"
        predecessor_parent.mkdir()
        copied_endurance = predecessor_parent / "endurance_bundle"
        _copy_tree(endurance_bundle, copied_endurance, "endurance bundle")
        copied_preauth = verify_preauthorization_bundle(
            authorization_out,
            preauthorizer_public_key,
            reviewer_public_key,
            expected_preauthorizer_key_id,
            expected_reviewer_key_id,
        )
        if copied_preauth["preauthorization"] != preauthorization:
            raise ReleaseError("preauthorization changed during snapshot")
        _, copied_chain = _stage_chain(
            manifest,
            copied_endurance,
            endurance_operator_public_key,
            endurance_witness_public_key,
            expected_endurance_operator_key_id,
            expected_endurance_witness_key_id,
        )
        if copied_chain != chain:
            raise ReleaseError("endurance predecessor changed during snapshot")
        receipt_path = temporary / RECEIPT_NAME
        raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(raw)
        (temporary / INSTALLER_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(
                receipt_path, installer_private_key, INSTALLER_NAMESPACE
            )
        )
        (temporary / WITNESS_SIGNATURE_NAME).write_bytes(
            discovery.sign_sshsig_file(
                receipt_path, witness_private_key, WITNESS_NAMESPACE
            )
        )
        _verify_release_members(temporary, receipt)
        os.replace(temporary, bundle_out.resolve())
    except discovery.DiscoveryError as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        raise ReleaseError(str(exc)) from exc
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return receipt


def verify_bundle(
    manifest: Mapping[str, Any],
    bundle: Path,
    preauthorizer_public_key: Path,
    reviewer_public_key: Path,
    endurance_operator_public_key: Path,
    endurance_witness_public_key: Path,
    installer_public_key: Path,
    witness_public_key: Path,
    expected_preauthorizer_key_id: str | None = None,
    expected_reviewer_key_id: str | None = None,
    expected_endurance_operator_key_id: str | None = None,
    expected_endurance_witness_key_id: str | None = None,
    expected_installer_key_id: str | None = None,
    expected_witness_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise ReleaseError(f"release bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseError("release bundle must be a non-symlink directory")
    preauth_result = verify_preauthorization_bundle(
        bundle / AUTHORIZATION_DIRECTORY,
        preauthorizer_public_key,
        reviewer_public_key,
        expected_preauthorizer_key_id,
        expected_reviewer_key_id,
    )
    _, chain = _stage_chain(
        manifest,
        bundle.joinpath(*PurePosixPath(PREDECESSOR_DIRECTORY).parts),
        endurance_operator_public_key,
        endurance_witness_public_key,
        expected_endurance_operator_key_id,
        expected_endurance_witness_key_id,
    )
    preauthorization = preauth_result["preauthorization"]
    receipt = _load_json(bundle / RECEIPT_NAME, "release receipt")
    _validate_receipt(receipt, preauthorization, chain)
    try:
        endurance_operator_key = discovery.inspect_public_key(
            endurance_operator_public_key
        )
        endurance_witness_key = discovery.inspect_public_key(
            endurance_witness_public_key
        )
        installer_key = discovery.inspect_public_key(installer_public_key)
        witness_key = discovery.inspect_public_key(witness_public_key)
        raw = _read_regular(bundle / RECEIPT_NAME, "release receipt", MAX_JSON_BYTES)
    except discovery.DiscoveryError as exc:
        raise ReleaseError(f"release trust input is invalid: {exc}") from exc
    release_key_ids = {
        preauth_result["preauthorizer_key_id_sha256"],
        preauth_result["reviewer_key_id_sha256"],
        installer_key["key_id_sha256"],
        witness_key["key_id_sha256"],
    }
    if len(release_key_ids) != 4:
        raise ReleaseError("all four release trust keys must be distinct")
    checks = (
        (
            "installer",
            installer_key,
            expected_installer_key_id,
            INSTALLER_SIGNATURE_NAME,
            receipt["installer_id"],
            INSTALLER_NAMESPACE,
        ),
        (
            "witness",
            witness_key,
            expected_witness_key_id,
            WITNESS_SIGNATURE_NAME,
            receipt["witness_id"],
            WITNESS_NAMESPACE,
        ),
    )
    for role, key, pinned, signature_name, principal, namespace in checks:
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise ReleaseError(f"{role} public key does not match its trust anchor")
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise ReleaseError(f"release {role} signer is not trusted")
        _require_canonical_sshsig(bundle / signature_name, f"release {role} signature")
        try:
            discovery.verify_sshsig_bytes(
                raw,
                bundle / signature_name,
                key["canonical_line"],
                principal,
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise ReleaseError(f"release {role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
            f"evidence {item['id']}",
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise ReleaseError("release evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise ReleaseError(f"evidence {item['id']} digest or size mismatch")
    _validate_evidence_semantics(
        receipt, _records_by_kind(receipt, bundle / EVIDENCE_DIRECTORY)
    )
    _verify_release_members(bundle, receipt)
    return {
        "authority_granted": False,
        "boot_policy_receipt_id": chain["boot_policy_receipt_id"],
        "capture_receipt_id": chain["capture_receipt_id"],
        "capture_set_sha256": chain["capture_set_sha256"],
        "completed_at_utc": receipt["completed_at_utc"],
        "controller_board_revision": chain["controller_board_revision"],
        "discovery_receipt_id": chain["discovery_receipt_id"],
        "endurance_evidence_set_sha256": chain["endurance_evidence_set_sha256"],
        "endurance_operator_key_id_sha256": endurance_operator_key["key_id_sha256"],
        "endurance_receipt_id": chain["endurance_receipt_id"],
        "endurance_witness_key_id_sha256": endurance_witness_key["key_id_sha256"],
        "evidence_set_sha256": receipt["evidence_set_sha256"],
        "exact_scope_release_admitted": True,
        "firmware_version": receipt["release_scope"]["firmware_version"],
        "fixture_evidence_set_sha256": chain["fixture_evidence_set_sha256"],
        "fixture_receipt_id": chain["fixture_receipt_id"],
        "generic_future_authority_granted": False,
        "installed_artifact_sha256": chain["installed_artifact_sha256"],
        "installer_key_id_sha256": installer_key["key_id_sha256"],
        "installer_signed_at_utc": receipt["installer_signed_at_utc"],
        "prior_bench_evidence_set_sha256": chain["prior_bench_evidence_set_sha256"],
        "prior_bench_receipt_id": chain["prior_bench_receipt_id"],
        "preauthorization_id": receipt["preauthorization_id"],
        "preauthorization_sha256": receipt["preauthorization_sha256"],
        "preauthorizer_key_id_sha256": preauth_result["preauthorizer_key_id_sha256"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": chain["recovery_receipt_id"],
        "reviewer_key_id_sha256": preauth_result["reviewer_key_id_sha256"],
        "release_authority_gate_eligible": True,
        "release_scope_sha256": preauth_result["release_scope_sha256"],
        "artifact_set_sha256": chain["artifact_set_sha256"],
        "interface_qualification_sha256": chain["interface_qualification_sha256"],
        "no_clobber_sha256": chain["no_clobber_sha256"],
        "route_replacement_receipt_id": chain["route_replacement_receipt_id"],
        "route_rollback_receipt_id": chain["route_rollback_receipt_id"],
        "route_adjudication_sha256": chain["route_adjudication_sha256"],
        "selected_route": chain["selected_route"],
        "state": RELEASE_RESULT["state"],
        "started_at_utc": receipt["started_at_utc"],
        "stock_backup_set_sha256": chain["stock_backup_set_sha256"],
        "stock_restoration_sha256": chain["stock_restoration_sha256"],
        "target_id": chain["target_id"],
        "unit_fingerprint_sha256": chain["unit_fingerprint_sha256"],
        "unit_label": chain["unit_label"],
        "variant_profile_id": chain["variant_profile_id"],
        "witness_signed_at_utc": receipt["witness_signed_at_utc"],
        "witness_key_id_sha256": witness_key["key_id_sha256"],
    }


def _template_evidence() -> list[dict[str, Any]]:
    return [
        {
            "acquired_at_utc": "2026-01-01T02:30:00Z",
            "id": kind.replace("_", "-"),
            "kind": kind,
            "media_type": "application/json",
            "method": METHOD_BY_KIND[kind],
            "path": f"records/{kind.replace('_record', '').replace('_', '-')}.json",
        }
        for kind in sorted(EVIDENCE_KINDS)
    ]


def _preauthorization_template(chain: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _validate_chain(chain)
    return {
        "issued_at_utc": "2026-01-01T02:00:00Z",
        "kind": PREAUTH_DESCRIPTOR_KIND,
        "permitted_actions": sorted(PERMITTED_ACTIONS),
        "preauthorizer_id": "replace-release-preauthorizer",
        "preauthorizer_signed_at_utc": "2026-01-01T02:01:00Z",
        "predecessor_chain": normalized,
        "release_scope": _scope_from_chain(normalized),
        "reviewer_id": "replace-release-reviewer",
        "reviewer_signed_at_utc": "2026-01-01T02:02:00Z",
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "valid_from_utc": "2026-01-01T02:10:00Z",
        "valid_until_utc": "2026-01-01T03:00:00Z",
    }


def _release_template(preauthorization: Mapping[str, Any]) -> dict[str, Any]:
    _validate_preauthorization(preauthorization)
    return {
        "actions_performed": sorted(PERMITTED_ACTIONS),
        "completed_at_utc": "2026-01-01T02:40:00Z",
        "endurance_bundle_path": PREDECESSOR_DIRECTORY,
        "evidence": _template_evidence(),
        "installer_id": "replace-release-installer",
        "installer_signed_at_utc": "2026-01-01T02:45:00Z",
        "kind": DESCRIPTOR_KIND,
        "preauthorization_id": preauthorization["preauthorization_id"],
        "preauthorization_sha256": hashlib.sha256(
            canonical_json_bytes(preauthorization)
        ).hexdigest(),
        "predecessor_chain": preauthorization["predecessor_chain"],
        "release_scope": preauthorization["release_scope"],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "started_at_utc": "2026-01-01T02:20:00Z",
        "witness_id": "replace-release-install-witness",
        "witness_signed_at_utc": "2026-01-01T02:46:00Z",
    }


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ReleaseError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "gauntlet"
        / "k210_models.json",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    pretemplate = commands.add_parser("preauthorize-template")
    pretemplate.add_argument("--endurance-bundle", type=Path, required=True)
    pretemplate.add_argument(
        "--endurance-operator-public-key", type=Path, required=True
    )
    pretemplate.add_argument("--endurance-witness-public-key", type=Path, required=True)
    pretemplate.add_argument("--expected-endurance-operator-key-id")
    pretemplate.add_argument("--expected-endurance-witness-key-id")
    pretemplate.add_argument("--out", type=Path, required=True)

    preauthorize = commands.add_parser("preauthorize")
    preauthorize.add_argument("--descriptor", type=Path, required=True)
    preauthorize.add_argument("--preauthorizer-private-key", type=Path, required=True)
    preauthorize.add_argument("--reviewer-private-key", type=Path, required=True)
    preauthorize.add_argument("--bundle-out", type=Path, required=True)

    verify_preauth = commands.add_parser("verify-preauthorization")
    verify_preauth.add_argument("--bundle", type=Path, required=True)
    verify_preauth.add_argument("--preauthorizer-public-key", type=Path, required=True)
    verify_preauth.add_argument("--reviewer-public-key", type=Path, required=True)
    verify_preauth.add_argument("--expected-preauthorizer-key-id")
    verify_preauth.add_argument("--expected-reviewer-key-id")

    template = commands.add_parser("template")
    template.add_argument("--preauthorization-bundle", type=Path, required=True)
    template.add_argument("--preauthorizer-public-key", type=Path, required=True)
    template.add_argument("--reviewer-public-key", type=Path, required=True)
    template.add_argument("--expected-preauthorizer-key-id")
    template.add_argument("--expected-reviewer-key-id")
    template.add_argument("--out", type=Path, required=True)

    create = commands.add_parser("create")
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--preauthorization-bundle", type=Path, required=True)
    create.add_argument("--preauthorizer-public-key", type=Path, required=True)
    create.add_argument("--reviewer-public-key", type=Path, required=True)
    create.add_argument("--endurance-bundle", type=Path, required=True)
    create.add_argument("--endurance-operator-public-key", type=Path, required=True)
    create.add_argument("--endurance-witness-public-key", type=Path, required=True)
    create.add_argument("--installer-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path, required=True)
    create.add_argument("--bundle-out", type=Path, required=True)
    create.add_argument("--expected-preauthorizer-key-id")
    create.add_argument("--expected-reviewer-key-id")
    create.add_argument("--expected-endurance-operator-key-id")
    create.add_argument("--expected-endurance-witness-key-id")

    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--preauthorizer-public-key", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    verify.add_argument("--endurance-operator-public-key", type=Path, required=True)
    verify.add_argument("--endurance-witness-public-key", type=Path, required=True)
    verify.add_argument("--installer-public-key", type=Path, required=True)
    verify.add_argument("--witness-public-key", type=Path, required=True)
    verify.add_argument("--expected-preauthorizer-key-id")
    verify.add_argument("--expected-reviewer-key-id")
    verify.add_argument("--expected-endurance-operator-key-id")
    verify.add_argument("--expected-endurance-witness-key-id")
    verify.add_argument("--expected-installer-key-id")
    verify.add_argument("--expected-witness-key-id")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "preauthorize-template":
            manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
            _, chain = _stage_chain(
                manifest,
                args.endurance_bundle,
                args.endurance_operator_public_key,
                args.endurance_witness_public_key,
                args.expected_endurance_operator_key_id,
                args.expected_endurance_witness_key_id,
            )
            value = _preauthorization_template(chain)
            _write_new_json(args.out, value)
            print(f"K210_RELEASE_PREAUTH_TEMPLATE_WRITTEN path={args.out}")
        elif args.command == "preauthorize":
            value = create_preauthorization_bundle(
                args.descriptor,
                args.preauthorizer_private_key,
                args.reviewer_private_key,
                args.bundle_out,
            )
            print(
                "K210_RELEASE_PREAUTHORIZED "
                f"preauthorization_id={value['preauthorization_id']} bundle={args.bundle_out}"
            )
        elif args.command == "verify-preauthorization":
            result = verify_preauthorization(
                args.bundle,
                args.preauthorizer_public_key,
                args.reviewer_public_key,
                args.expected_preauthorizer_key_id,
                args.expected_reviewer_key_id,
            )
            printable = {
                key: value for key, value in result.items() if key != "preauthorization"
            }
            print(json.dumps(printable, sort_keys=True, separators=(",", ":")))
        elif args.command == "template":
            result = verify_preauthorization_bundle(
                args.preauthorization_bundle,
                args.preauthorizer_public_key,
                args.reviewer_public_key,
                args.expected_preauthorizer_key_id,
                args.expected_reviewer_key_id,
            )
            _write_new_json(args.out, _release_template(result["preauthorization"]))
            print(f"K210_RELEASE_TEMPLATE_WRITTEN path={args.out}")
        elif args.command == "create":
            manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
            receipt = create_bundle(
                manifest,
                args.descriptor,
                args.evidence_root,
                args.preauthorization_bundle,
                args.preauthorizer_public_key,
                args.reviewer_public_key,
                args.endurance_bundle,
                args.endurance_operator_public_key,
                args.endurance_witness_public_key,
                args.installer_private_key,
                args.witness_private_key,
                args.bundle_out,
                args.expected_preauthorizer_key_id,
                args.expected_reviewer_key_id,
                args.expected_endurance_operator_key_id,
                args.expected_endurance_witness_key_id,
            )
            print(
                "K210_RELEASE_BUNDLE_CREATED "
                f"target={receipt['release_scope']['target_id']} receipt={receipt['receipt_id']}"
            )
        else:
            manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
            result = verify_bundle(
                manifest,
                args.bundle,
                args.preauthorizer_public_key,
                args.reviewer_public_key,
                args.endurance_operator_public_key,
                args.endurance_witness_public_key,
                args.installer_public_key,
                args.witness_public_key,
                args.expected_preauthorizer_key_id,
                args.expected_reviewer_key_id,
                args.expected_endurance_operator_key_id,
                args.expected_endurance_witness_key_id,
                args.expected_installer_key_id,
                args.expected_witness_key_id,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ReleaseError as exc:
        print(f"K210_RELEASE_ERROR: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
