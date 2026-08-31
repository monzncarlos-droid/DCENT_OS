#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Create and verify fail-closed S19k release-signing ceremony records.

The ceremony is deliberately split around the signature operation:

``prepare`` -> ``authorize`` -> external signer -> ``complete`` -> ``verify``.

Authorization binds one exact canonical unsigned manifest, expected capsule
basename, and baked public signing identity *before* the builder may invoke the
signer. Completion then binds the signed capsule to that preauthorization.
This tool never reads a private key, signs an artifact, contacts hardware, or
grants install/flash authority. The receipts are operator records, not a
substitute for organizational release authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xil_first_install import (  # noqa: E402
    _read_capsule_members,
)
from dcent_toolbox.core.install_package import (  # noqa: E402
    get_pinned_release_pubkey_hex,
)

import s19k_release_policy as policy  # noqa: E402


MAX_RECORD_BYTES = 1024 * 1024
EXPECTED_CAPSULE_RE = re.compile(
    r"^DCENT_FIRSTINSTALL_AM3_S19kPro_v[A-Za-z0-9._+:-]+\.tar\.gz$"
)
FALSE_AUTHORITY_FLAGS = (
    "install_authority_granted",
    "mutation_authority_granted",
    "nand_write_authorized",
    "live_hardware_contacted",
    "network_used",
)


class CeremonyError(ValueError):
    """A ceremony input or receipt failed closed."""


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"


def canonical_manifest(value: object) -> bytes:
    """Return the capsule builder's one canonical unsigned-manifest encoding."""

    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _with_receipt_id(receipt: dict[str, object]) -> dict[str, object]:
    result = dict(receipt)
    result.pop("receipt_id", None)
    result["receipt_id"] = digest(canonical_json(result))
    return result


def _false_authority() -> dict[str, bool]:
    return {name: False for name in FALSE_AUTHORITY_FLAGS}


def _validate_expected_capsule_name(name: str) -> str:
    if Path(name).name != name or not EXPECTED_CAPSULE_RE.fullmatch(name):
        raise CeremonyError(
            "expected capsule name must be the canonical "
            "DCENT_FIRSTINSTALL_AM3_S19kPro_v<version>.tar.gz basename"
        )
    return name


def _parse_utc(value: str, label: str) -> datetime:
    text = value.strip()
    if not text.endswith("Z"):
        raise CeremonyError(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise CeremonyError(f"{label} is not a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CeremonyError(f"{label} is not UTC")
    return parsed


def _read_manifest(path: Path) -> tuple[dict[str, object], bytes]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size <= 0
        or path.stat().st_size > MAX_RECORD_BYTES
    ):
        raise CeremonyError(f"unsigned manifest is missing, unsafe, or oversized: {path}")
    data = path.read_bytes()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CeremonyError(f"unsigned manifest is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CeremonyError("unsigned manifest is not an object")
    if data != canonical_manifest(value):
        raise CeremonyError("unsigned manifest is not in the builder's canonical encoding")
    return value, data


def _validate_production_manifest(manifest: dict[str, object]) -> None:
    if manifest.get("artifact_class") != policy.ARTIFACT_CLASS_PRODUCTION:
        raise CeremonyError("signing ceremony refuses non-production artifact_class")
    identity = manifest.get("signing_identity")
    if not isinstance(identity, dict) or set(identity) != {
        "profile",
        "key_id",
        "public_key_hex",
    }:
        raise CeremonyError("manifest signing_identity is missing or malformed")
    if identity.get("profile") != policy.SIGNING_PROFILE_PRODUCTION:
        raise CeremonyError("manifest signing identity is not production-release")
    if identity.get("public_key_hex") != get_pinned_release_pubkey_hex():
        raise CeremonyError("manifest signing identity differs from the baked release pin")
    if not str(identity.get("key_id") or "").strip():
        raise CeremonyError("manifest signing key_id is empty")

    attestation = manifest.get("production_image_attestation")
    if not isinstance(attestation, dict):
        raise CeremonyError("manifest production_image_attestation is missing")
    if attestation.get("member") != policy.PERSISTENT_IMAGE_MEMBER:
        raise CeremonyError("persistent-image attestation member path is invalid")
    if not re.fullmatch(
        r"[0-9a-f]{64}", str(attestation.get("verification_id") or "")
    ):
        raise CeremonyError("persistent-image verification_id is invalid")
    if attestation.get("release_manifest_public_key_hex") != identity.get(
        "public_key_hex"
    ):
        raise CeremonyError("persistent-image release key differs from signing identity")

    stage1 = manifest.get("transition_stage1")
    if not isinstance(stage1, dict):
        raise CeremonyError("manifest transition_stage1 is missing")
    if stage1.get("schema") != policy.STAGE1_SCHEMA:
        raise CeremonyError("manifest transition_stage1 schema mismatch")
    if stage1.get("member") != "transition/stage1.sh":
        raise CeremonyError("manifest transition_stage1 member mismatch")
    for field in ("sha256", "audit_receipt_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(stage1.get(field) or "")):
            raise CeremonyError(f"manifest transition_stage1 {field} is invalid")
    if not str(stage1.get("implementation_id") or "").strip():
        raise CeremonyError("manifest transition_stage1 implementation_id is empty")
    if not isinstance(stage1.get("bytes"), int) or stage1["bytes"] <= 0:
        raise CeremonyError("manifest transition_stage1 bytes is invalid")

    snapshot = manifest.get("source_snapshot")
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema",
        "commit",
        "tree",
        "commit_signature_verified",
        "clean_worktree_verified",
    }:
        raise CeremonyError("manifest source_snapshot is missing or malformed")
    if snapshot.get("schema") != policy.SOURCE_SNAPSHOT_SCHEMA:
        raise CeremonyError("manifest source_snapshot schema mismatch")
    for field in ("commit", "tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(snapshot.get(field) or "")):
            raise CeremonyError(f"manifest source_snapshot {field} is invalid")
    if snapshot.get("commit_signature_verified") is not True or snapshot.get(
        "clean_worktree_verified"
    ) is not True:
        raise CeremonyError("manifest source snapshot is not signed and clean")

    authorizer = manifest.get("transition_stage1_authorizer")
    if not isinstance(authorizer, dict) or set(authorizer) != {
        "schema",
        "member",
        "sha256",
        "bytes",
        "implementation_id",
        "target_kat_verified",
        "source_snapshot_commit",
    }:
        raise CeremonyError("manifest transition_stage1_authorizer is malformed")
    if authorizer.get("schema") != policy.STAGE1_AUTHORIZER_SCHEMA or authorizer.get(
        "member"
    ) != "transition/s19k-stage1-authorizer":
        raise CeremonyError("manifest stage1 authorizer schema/member mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", str(authorizer.get("sha256") or "")):
        raise CeremonyError("manifest stage1 authorizer sha256 is invalid")
    if not isinstance(authorizer.get("bytes"), int) or authorizer["bytes"] <= 0:
        raise CeremonyError("manifest stage1 authorizer bytes is invalid")
    if not str(authorizer.get("implementation_id") or "").strip():
        raise CeremonyError("manifest stage1 authorizer implementation_id is empty")
    if authorizer.get("target_kat_verified") is not True:
        raise CeremonyError("manifest stage1 authorizer target KAT is not verified")
    if authorizer.get("source_snapshot_commit") != snapshot.get("commit"):
        raise CeremonyError("manifest stage1 authorizer source commit mismatch")

    custody = manifest.get("install_custody")
    expected_custody_keys = {
        "schema",
        "protocol",
        "source_layouts",
        "target_identity_profiles",
        *policy.CUSTODY_MEMBER_BY_ROLE,
    }
    if not isinstance(custody, dict) or set(custody) != expected_custody_keys:
        raise CeremonyError("manifest install_custody key set is not exact")
    if (
        custody.get("schema") != policy.INSTALL_CUSTODY_SCHEMA
        or custody.get("protocol") != policy.INSTALL_CUSTODY_PROTOCOL
        or custody.get("source_layouts") != list(policy.INSTALL_CUSTODY_SOURCE_LAYOUTS)
        or custody.get("target_identity_profiles")
        != list(policy.INSTALL_CUSTODY_TARGET_IDENTITY_PROFILES)
    ):
        raise CeremonyError("manifest install_custody protocol/scope mismatch")
    accepted_sources = manifest.get("accepted_source_layouts")
    if (
        not isinstance(accepted_sources, list)
        or not accepted_sources
        or not set(accepted_sources).issubset(
            set(policy.INSTALL_CUSTODY_SOURCE_LAYOUTS)
        )
    ):
        raise CeremonyError("manifest accepted sources exceed install-custody scope")

    descriptors: list[dict[str, object]] = [
        {
            "member": str(attestation.get("image_member") or ""),
            "sha256": str(attestation.get("image_sha256") or ""),
            "bytes": attestation.get("image_bytes"),
        },
        {
            "member": str(stage1.get("member") or ""),
            "sha256": str(stage1.get("sha256") or ""),
            "bytes": stage1.get("bytes"),
        },
        {
            "member": str(authorizer.get("member") or ""),
            "sha256": str(authorizer.get("sha256") or ""),
            "bytes": authorizer.get("bytes"),
        },
    ]
    for role, expected_member in policy.CUSTODY_MEMBER_BY_ROLE.items():
        descriptor = custody.get(role)
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"member", "sha256", "bytes"}
            or descriptor.get("member") != expected_member
            or not re.fullmatch(r"[0-9a-f]{64}", str(descriptor.get("sha256") or ""))
            or not isinstance(descriptor.get("bytes"), int)
            or descriptor["bytes"] <= 0
        ):
            raise CeremonyError(f"manifest install_custody descriptor invalid: {role}")
        descriptors.append(descriptor)
    if any(
        descriptor["member"] not in {
            "payload/dcent-rootfs.img",
            "transition/stage1.sh",
            "transition/s19k-stage1-authorizer",
            *policy.CUSTODY_MEMBER_BY_ROLE.values(),
        }
        or not re.fullmatch(r"[0-9a-f]{64}", str(descriptor["sha256"]))
        or not isinstance(descriptor["bytes"], int)
        or descriptor["bytes"] <= 0
        for descriptor in descriptors
    ):
        raise CeremonyError("manifest target staging member descriptor is invalid")
    counted_members = sorted(descriptors, key=lambda item: str(item["member"]))
    coexisting_bytes = sum(int(item["bytes"]) for item in counted_members)
    expected_staging = {
        "schema": policy.TARGET_STAGING_BUDGET_SCHEMA,
        "rootfs_readback_mode": policy.TARGET_STAGING_ROOTFS_READBACK_MODE,
        "counted_members": counted_members,
        "coexisting_capsule_member_bytes": coexisting_bytes,
        "per_unit_inputs_budget_bytes": (
            policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
        ),
        "working_free_reserve_bytes": (
            policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
        ),
        "required_tmp_free_bytes": (
            coexisting_bytes
            + policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
            + policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
        ),
    }
    if manifest.get("target_staging_budget") != expected_staging:
        raise CeremonyError("manifest target_staging_budget is not exact")


def _read_capsule(
    capsule: Path,
) -> tuple[dict[str, object], dict[str, bytes], bytes, str, int]:
    if capsule.is_symlink() or not capsule.is_file():
        raise CeremonyError(f"capsule is missing or unsafe: {capsule}")
    files, capsule_sha, capsule_bytes = _read_capsule_members(capsule)
    manifest_bytes = files.get("manifest.json")
    if not files or manifest_bytes is None:
        raise CeremonyError("capsule is not safely readable or has no manifest.json")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CeremonyError(f"capsule manifest is invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest_bytes != canonical_manifest(manifest):
        raise CeremonyError("capsule manifest is not a canonical object")
    _validate_production_manifest(manifest)
    required_payload_members = {
        policy.PERSISTENT_IMAGE_MEMBER,
        "payload/dcent-rootfs.img",
        "transition/stage1.sh",
        "transition/s19k-stage1-authorizer",
        *policy.CUSTODY_MEMBER_BY_ROLE.values(),
    }
    for member in required_payload_members:
        if member not in files:
            raise CeremonyError(f"required production capsule member is missing: {member}")
    if set(files) != required_payload_members | {"manifest.json", "MANIFEST.sig"}:
        raise CeremonyError("production capsule has an unexplained or missing member")
    checksums = manifest.get("checksums")
    if not isinstance(checksums, dict) or set(checksums) != required_payload_members:
        raise CeremonyError("production capsule checksum member set is not exact")
    for member in sorted(required_payload_members):
        if checksums.get(member) != digest(files[member]):
            raise CeremonyError(f"production capsule member checksum mismatch: {member}")
    for declaration_name in ("transition_stage1", "transition_stage1_authorizer"):
        declaration = manifest[declaration_name]
        member_name = str(declaration["member"])
        member_bytes = files[member_name]
        if declaration.get("sha256") != digest(member_bytes) or declaration.get(
            "bytes"
        ) != len(member_bytes):
            raise CeremonyError(
                f"capsule {declaration_name} does not bind its exact member bytes"
            )
    custody = manifest["install_custody"]
    for role, member_name in policy.CUSTODY_MEMBER_BY_ROLE.items():
        declaration = custody[role]
        member_bytes = files[member_name]
        if declaration != {
            "member": member_name,
            "sha256": digest(member_bytes),
            "bytes": len(member_bytes),
        }:
            raise CeremonyError(f"capsule install custody mismatch: {role}")
    signature = files.get("MANIFEST.sig")
    if signature is None or len(signature) != 64:
        raise CeremonyError("capsule has no exact 64-byte MANIFEST.sig")
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(get_pinned_release_pubkey_hex())
        ).verify(signature, manifest_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise CeremonyError(
            "capsule manifest signature does not verify against the baked release pin"
        ) from exc
    return manifest, files, manifest_bytes, capsule_sha, capsule_bytes


def _read_receipt(path: Path) -> dict[str, object]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size <= 0
        or path.stat().st_size > MAX_RECORD_BYTES
    ):
        raise CeremonyError(f"receipt is missing, unsafe, or oversized: {path}")
    data = path.read_bytes()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CeremonyError(f"receipt is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CeremonyError("receipt is not an object")
    if data != canonical_json(value):
        raise CeremonyError("receipt is not canonical JSON")
    if value.get("receipt_id") != _with_receipt_id(value).get("receipt_id"):
        raise CeremonyError("receipt_id is invalid")
    return value


def _verify_preparation(receipt: dict[str, object]) -> dict[str, object]:
    if receipt.get("schema") != policy.SIGNING_PREPARATION_SCHEMA:
        raise CeremonyError("signing preparation schema mismatch")
    if receipt.get("status") != "prepared-awaiting-operator-authorization":
        raise CeremonyError("signing preparation is not awaiting authorization")
    if not str(receipt.get("ceremony_id") or "").strip():
        raise CeremonyError("signing preparation ceremony_id is empty")
    if receipt.get("operator_authorization") != {
        "release_signing_authorized": False
    }:
        raise CeremonyError("signing preparation must remain non-authorizing")
    if receipt.get("authority_scope") != "record-only-no-sign-install-or-flash-authority":
        raise CeremonyError("signing preparation authority scope is invalid")
    for name in FALSE_AUTHORITY_FLAGS:
        if receipt.get(name) is not False:
            raise CeremonyError(f"signing preparation forbidden flag is not false: {name}")
    return receipt


def prepare(
    manifest_path: Path,
    expected_capsule_name: str,
    output: Path,
    ceremony_id: str,
) -> dict[str, object]:
    manifest, manifest_bytes = _read_manifest(manifest_path)
    _validate_production_manifest(manifest)
    name = _validate_expected_capsule_name(expected_capsule_name)
    if not ceremony_id.strip():
        raise CeremonyError("ceremony_id must be non-empty")
    attestation = manifest["production_image_attestation"]
    receipt = _with_receipt_id(
        {
            "schema": policy.SIGNING_PREPARATION_SCHEMA,
            "status": "prepared-awaiting-operator-authorization",
            "ceremony_id": ceremony_id.strip(),
            "unsigned_manifest": {
                "sha256": digest(manifest_bytes),
                "bytes": len(manifest_bytes),
                "expected_capsule_name": name,
            },
            "signing_identity": manifest["signing_identity"],
            "persistent_image_verification_id": attestation["verification_id"],
            "transition_stage1": manifest["transition_stage1"],
            "operator_authorization": {"release_signing_authorized": False},
            "authority_scope": "record-only-no-sign-install-or-flash-authority",
            **_false_authority(),
        }
    )
    _write_no_replace(output, canonical_json(receipt))
    return receipt


def authorize(
    prepared_path: Path,
    output: Path,
    recorded_utc: str,
    authorized_by: str,
    authorization_reference: str,
) -> dict[str, object]:
    prepared = _verify_preparation(_read_receipt(prepared_path))
    _parse_utc(recorded_utc, "authorization recorded_utc")
    if not authorized_by.strip() or not authorization_reference.strip():
        raise CeremonyError("authorization requires authorizer and reference")
    receipt = _with_receipt_id(
        {
            "schema": policy.SIGNING_AUTHORIZATION_SCHEMA,
            "status": "authorized-before-signing",
            "ceremony_id": prepared["ceremony_id"],
            "prepared_receipt_id": prepared["receipt_id"],
            "recorded_utc": recorded_utc.strip(),
            "unsigned_manifest": prepared["unsigned_manifest"],
            "signing_identity": prepared["signing_identity"],
            "persistent_image_verification_id": prepared[
                "persistent_image_verification_id"
            ],
            "transition_stage1": prepared["transition_stage1"],
            "operator_authorization": {
                "release_signing_authorized": True,
                "authorized_by": authorized_by.strip(),
                "authorization_reference": authorization_reference.strip(),
            },
            "assertions": {
                "public_identity_confirmed_out_of_band": True,
                "exact_unsigned_manifest_reviewed": True,
            },
            "authority_scope": "one-exact-manifest-release-signing-only",
            **_false_authority(),
        }
    )
    _write_no_replace(output, canonical_json(receipt))
    return receipt


def verify_authorization(
    receipt_path: Path, manifest_bytes: bytes, expected_capsule_name: str
) -> dict[str, object]:
    """Verify the exact preauthorization the builder consumes before signing."""

    receipt = _read_receipt(receipt_path)
    if receipt.get("schema") != policy.SIGNING_AUTHORIZATION_SCHEMA:
        raise CeremonyError("signing authorization schema mismatch")
    if receipt.get("status") != "authorized-before-signing":
        raise CeremonyError("signing was not authorized before signing")
    _parse_utc(str(receipt.get("recorded_utc") or ""), "authorization recorded_utc")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CeremonyError(f"candidate unsigned manifest is invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest_bytes != canonical_manifest(manifest):
        raise CeremonyError("candidate unsigned manifest is not canonical")
    _validate_production_manifest(manifest)
    expected_binding = {
        "sha256": digest(manifest_bytes),
        "bytes": len(manifest_bytes),
        "expected_capsule_name": _validate_expected_capsule_name(expected_capsule_name),
    }
    if receipt.get("unsigned_manifest") != expected_binding:
        raise CeremonyError("authorization does not bind this exact unsigned manifest/name")
    if receipt.get("signing_identity") != manifest.get("signing_identity"):
        raise CeremonyError("authorization signing identity differs from manifest")
    if receipt.get("transition_stage1") != manifest.get("transition_stage1"):
        raise CeremonyError("authorization stage1 binding differs from manifest")
    attestation = manifest["production_image_attestation"]
    if receipt.get("persistent_image_verification_id") != attestation.get(
        "verification_id"
    ):
        raise CeremonyError("authorization persistent-image binding differs from manifest")
    authorization = receipt.get("operator_authorization")
    if not isinstance(authorization, dict) or authorization.get(
        "release_signing_authorized"
    ) is not True:
        raise CeremonyError("release signing is not explicitly preauthorized")
    if not str(authorization.get("authorized_by") or "").strip() or not str(
        authorization.get("authorization_reference") or ""
    ).strip():
        raise CeremonyError("signing authorization identity/reference is incomplete")
    if receipt.get("assertions") != {
        "public_identity_confirmed_out_of_band": True,
        "exact_unsigned_manifest_reviewed": True,
    }:
        raise CeremonyError("signing authorization assertions are incomplete")
    if receipt.get("authority_scope") != "one-exact-manifest-release-signing-only":
        raise CeremonyError("signing authorization scope is invalid")
    for name in FALSE_AUTHORITY_FLAGS:
        if receipt.get(name) is not False:
            raise CeremonyError(f"signing authorization forbidden flag is not false: {name}")
    return receipt


def complete(
    authorization_path: Path,
    capsule: Path,
    output: Path,
    recorded_utc: str,
    completed_by: str,
    completion_reference: str,
) -> dict[str, object]:
    manifest, _files, manifest_bytes, capsule_sha, capsule_bytes = _read_capsule(
        capsule
    )
    authorization = verify_authorization(
        authorization_path, manifest_bytes, capsule.name
    )
    authorized_at = _parse_utc(
        str(authorization["recorded_utc"]), "authorization recorded_utc"
    )
    completed_at = _parse_utc(recorded_utc, "completion recorded_utc")
    if completed_at < authorized_at:
        raise CeremonyError("completion timestamp predates signing authorization")
    if not completed_by.strip() or not completion_reference.strip():
        raise CeremonyError("completion requires operator and reference")
    receipt = _with_receipt_id(
        {
            "schema": policy.SIGNING_CEREMONY_SCHEMA,
            "status": "completed-after-signing",
            "ceremony_id": authorization["ceremony_id"],
            "signing_authorization_receipt_id": authorization["receipt_id"],
            "authorization_recorded_utc": authorization["recorded_utc"],
            "completion_recorded_utc": recorded_utc.strip(),
            "capsule": {
                "name": capsule.name,
                "sha256": capsule_sha,
                "bytes": capsule_bytes,
                "manifest_sha256": digest(manifest_bytes),
            },
            "signing_identity": manifest["signing_identity"],
            "persistent_image_verification_id": manifest[
                "production_image_attestation"
            ]["verification_id"],
            "transition_stage1": manifest["transition_stage1"],
            "operator_completion": {
                "completed_by": completed_by.strip(),
                "completion_reference": completion_reference.strip(),
            },
            "assertions": {
                "manifest_matches_preauthorized_unsigned_manifest": True,
                "signature_verifies_against_baked_release_identity": True,
                "private_key_remained_external_to_workspace": True,
                "private_key_material_not_logged": True,
            },
            "authority_scope": "release-signing-closeout-no-install-or-flash-authority",
            **_false_authority(),
        }
    )
    _write_no_replace(output, canonical_json(receipt))
    return receipt


def verify(
    authorization_path: Path, completion_path: Path, capsule: Path
) -> dict[str, object]:
    manifest, _files, manifest_bytes, capsule_sha, capsule_bytes = _read_capsule(
        capsule
    )
    authorization = verify_authorization(
        authorization_path, manifest_bytes, capsule.name
    )
    completion = _read_receipt(completion_path)
    if completion.get("schema") != policy.SIGNING_CEREMONY_SCHEMA:
        raise CeremonyError("signing completion schema mismatch")
    if completion.get("status") != "completed-after-signing":
        raise CeremonyError("signing completion is not completed-after-signing")
    if completion.get("ceremony_id") != authorization.get("ceremony_id"):
        raise CeremonyError("completion ceremony_id differs from authorization")
    if completion.get("signing_authorization_receipt_id") != authorization.get(
        "receipt_id"
    ):
        raise CeremonyError("completion does not bind the authorization receipt")
    authorized_at = _parse_utc(
        str(authorization["recorded_utc"]), "authorization recorded_utc"
    )
    if completion.get("authorization_recorded_utc") != authorization.get(
        "recorded_utc"
    ):
        raise CeremonyError("completion copied authorization timestamp differs")
    completed_at = _parse_utc(
        str(completion.get("completion_recorded_utc") or ""),
        "completion recorded_utc",
    )
    if completed_at < authorized_at:
        raise CeremonyError("completion timestamp predates signing authorization")
    expected_capsule = {
        "name": capsule.name,
        "sha256": capsule_sha,
        "bytes": capsule_bytes,
        "manifest_sha256": digest(manifest_bytes),
    }
    if completion.get("capsule") != expected_capsule:
        raise CeremonyError("completion does not bind the exact signed capsule")
    if completion.get("signing_identity") != manifest.get("signing_identity"):
        raise CeremonyError("completion signing identity differs from manifest")
    if completion.get("transition_stage1") != manifest.get("transition_stage1"):
        raise CeremonyError("completion stage1 binding differs from manifest")
    if completion.get("persistent_image_verification_id") != manifest[
        "production_image_attestation"
    ].get("verification_id"):
        raise CeremonyError("completion persistent-image binding differs from manifest")
    operator = completion.get("operator_completion")
    if not isinstance(operator, dict) or not str(
        operator.get("completed_by") or ""
    ).strip() or not str(operator.get("completion_reference") or "").strip():
        raise CeremonyError("completion operator/reference is incomplete")
    if completion.get("assertions") != {
        "manifest_matches_preauthorized_unsigned_manifest": True,
        "signature_verifies_against_baked_release_identity": True,
        "private_key_remained_external_to_workspace": True,
        "private_key_material_not_logged": True,
    }:
        raise CeremonyError("completion custody/signature assertions are incomplete")
    if completion.get(
        "authority_scope"
    ) != "release-signing-closeout-no-install-or-flash-authority":
        raise CeremonyError("completion authority scope is invalid")
    for name in FALSE_AUTHORITY_FLAGS:
        if completion.get(name) is not False:
            raise CeremonyError(f"signing completion forbidden flag is not false: {name}")
    return completion


def _write_no_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o644,
        )
    except FileExistsError as exc:
        raise CeremonyError(f"no-replace output already exists: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        try:
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass  # directory handles/fsync are unavailable on some host filesystems


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = result.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--manifest", type=Path, required=True)
    prep.add_argument("--expected-capsule-name", required=True)
    prep.add_argument("--ceremony-id", required=True)
    prep.add_argument("--output", type=Path, required=True)
    auth = sub.add_parser("authorize")
    auth.add_argument("--prepared", type=Path, required=True)
    auth.add_argument("--output", type=Path, required=True)
    auth.add_argument("--recorded-utc", required=True)
    auth.add_argument("--authorized-by", required=True)
    auth.add_argument("--authorization-reference", required=True)
    done = sub.add_parser("complete")
    done.add_argument("--authorization", type=Path, required=True)
    done.add_argument("--capsule", type=Path, required=True)
    done.add_argument("--output", type=Path, required=True)
    done.add_argument("--recorded-utc", required=True)
    done.add_argument("--completed-by", required=True)
    done.add_argument("--completion-reference", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--authorization", type=Path, required=True)
    check.add_argument("--completion", type=Path, required=True)
    check.add_argument("--capsule", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "prepare":
            receipt = prepare(
                args.manifest,
                args.expected_capsule_name,
                args.output,
                args.ceremony_id,
            )
        elif args.command == "authorize":
            receipt = authorize(
                args.prepared,
                args.output,
                args.recorded_utc,
                args.authorized_by,
                args.authorization_reference,
            )
        elif args.command == "complete":
            receipt = complete(
                args.authorization,
                args.capsule,
                args.output,
                args.recorded_utc,
                args.completed_by,
                args.completion_reference,
            )
        else:
            receipt = verify(args.authorization, args.completion, args.capsule)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (CeremonyError, OSError, ValueError) as exc:
        print(f"ERROR: S19k signing ceremony: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
