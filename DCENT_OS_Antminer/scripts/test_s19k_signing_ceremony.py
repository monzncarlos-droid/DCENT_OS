#!/usr/bin/env python3
"""Offline adversarial tests for the S19k preauthorization ceremony."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT = Path(__file__).with_name("s19k_signing_ceremony.py")
SPEC = importlib.util.spec_from_file_location("s19k_signing_ceremony", SCRIPT)
assert SPEC and SPEC.loader
CEREMONY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CEREMONY
SPEC.loader.exec_module(CEREMONY)

CAPSULE_NAME = "DCENT_FIRSTINSTALL_AM3_S19kPro_v0.0.0-pytest.tar.gz"
STAGE1_BYTES = b"#!/bin/sh\n# reviewed test target writer, never production\n"
AUTHORIZER_BYTES = b"authorizer-test-fixture"
ROOTFS_BYTES = b"uImage-fixture"
EVIDENCE_BYTES = b"{}\n"
CUSTODY_BYTES = {
    member: f"{role}-ceremony-fixture\n".encode("ascii")
    for role, member in CEREMONY.policy.CUSTODY_MEMBER_BY_ROLE.items()
}


def raw_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def manifest(key: Ed25519PrivateKey, artifact_class: str = "production") -> dict:
    production = artifact_class == "production"
    counted_bytes = {
        "payload/dcent-rootfs.img": ROOTFS_BYTES,
        "transition/stage1.sh": STAGE1_BYTES,
        "transition/s19k-stage1-authorizer": AUTHORIZER_BYTES,
        **CUSTODY_BYTES,
    }
    counted_members = [
        {
            "member": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        for name, data in sorted(counted_bytes.items())
    ]
    coexisting_bytes = sum(item["bytes"] for item in counted_members)
    value = {
        "artifact_class": artifact_class,
        "accepted_source_layouts": ["braiins-aml-s19k"],
        "signing_identity": {
            "profile": "production-release" if production else "test-only",
            "key_id": "pytest-production-identity",
            "public_key_hex": raw_hex(key),
        },
        "production_image_attestation": (
            {
                "member": CEREMONY.policy.PERSISTENT_IMAGE_MEMBER,
                "verification_id": "a" * 64,
                "image_member": "payload/dcent-rootfs.img",
                "image_sha256": hashlib.sha256(ROOTFS_BYTES).hexdigest(),
                "image_bytes": len(ROOTFS_BYTES),
                "release_key_sha256": "b" * 64,
                "release_manifest_public_key_hex": raw_hex(key),
            }
            if production
            else None
        ),
        "transition_stage1": {
            "schema": CEREMONY.policy.STAGE1_SCHEMA,
            "member": "transition/stage1.sh",
            "sha256": hashlib.sha256(STAGE1_BYTES).hexdigest(),
            "bytes": len(STAGE1_BYTES),
            "implementation_id": "pytest-reviewed-target-writer",
            "audit_receipt_sha256": "c" * 64,
        },
        "source_snapshot": (
            {
                "schema": CEREMONY.policy.SOURCE_SNAPSHOT_SCHEMA,
                "commit": "d" * 40,
                "tree": "e" * 40,
                "commit_signature_verified": True,
                "clean_worktree_verified": True,
            }
            if production
            else None
        ),
        "transition_stage1_authorizer": (
            {
                "schema": CEREMONY.policy.STAGE1_AUTHORIZER_SCHEMA,
                "member": "transition/s19k-stage1-authorizer",
                "sha256": hashlib.sha256(AUTHORIZER_BYTES).hexdigest(),
                "bytes": len(AUTHORIZER_BYTES),
                "implementation_id": "pytest-reviewed-armv7-authorizer",
                "target_kat_verified": True,
                "source_snapshot_commit": "d" * 40,
            }
            if production
            else {
                "schema": CEREMONY.policy.STAGE1_AUTHORIZER_SCHEMA,
                "member": "transition/s19k-stage1-authorizer",
                "sha256": hashlib.sha256(AUTHORIZER_BYTES).hexdigest(),
                "bytes": len(AUTHORIZER_BYTES),
                "implementation_id": "test-fixture-no-production-authority",
                "target_kat_verified": False,
                "source_snapshot_commit": None,
            }
        ),
        "install_custody": {
            "schema": CEREMONY.policy.INSTALL_CUSTODY_SCHEMA,
            "protocol": CEREMONY.policy.INSTALL_CUSTODY_PROTOCOL,
            "source_layouts": ["braiins-aml-s19k"],
            "target_identity_profiles": [
                "live88_two_bhb56903_slots_2_3"
            ],
            **{
                role: {
                    "member": member,
                    "sha256": hashlib.sha256(CUSTODY_BYTES[member]).hexdigest(),
                    "bytes": len(CUSTODY_BYTES[member]),
                }
                for role, member in CEREMONY.policy.CUSTODY_MEMBER_BY_ROLE.items()
            },
        },
        "target_staging_budget": {
            "schema": CEREMONY.policy.TARGET_STAGING_BUDGET_SCHEMA,
            "rootfs_readback_mode": "streaming_sha256_no_rootfs_copy",
            "counted_members": counted_members,
            "coexisting_capsule_member_bytes": coexisting_bytes,
            "per_unit_inputs_budget_bytes": 524288,
            "working_free_reserve_bytes": 8388608,
            "required_tmp_free_bytes": coexisting_bytes + 524288 + 8388608,
        },
        "checksums": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in {
                **counted_bytes,
                CEREMONY.policy.PERSISTENT_IMAGE_MEMBER: EVIDENCE_BYTES,
            }.items()
        },
    }
    return value


def write_manifest(tmp_path: Path, value: dict) -> Path:
    path = tmp_path / "unsigned-manifest.json"
    path.write_bytes(CEREMONY.canonical_manifest(value))
    return path


def capsule(tmp_path: Path, key: Ed25519PrivateKey, value: dict) -> Path:
    manifest_bytes = CEREMONY.canonical_manifest(value)
    path = tmp_path / CAPSULE_NAME
    path.write_bytes(
        tar_bytes(
            {
                "transition/stage1.sh": STAGE1_BYTES,
                "transition/s19k-stage1-authorizer": AUTHORIZER_BYTES,
                "payload/dcent-rootfs.img": ROOTFS_BYTES,
                CEREMONY.policy.PERSISTENT_IMAGE_MEMBER: EVIDENCE_BYTES,
                **CUSTODY_BYTES,
                "manifest.json": manifest_bytes,
                "MANIFEST.sig": key.sign(manifest_bytes),
            }
        )
    )
    return path


def authorize_manifest(tmp_path: Path, key: Ed25519PrivateKey) -> tuple[dict, Path, dict]:
    value = manifest(key)
    manifest_path = write_manifest(tmp_path, value)
    prepared_path = tmp_path / "prepared.json"
    prepared = CEREMONY.prepare(
        manifest_path, CAPSULE_NAME, prepared_path, "ceremony-test-1"
    )
    authorization_path = tmp_path / "authorization.json"
    authorization = CEREMONY.authorize(
        prepared_path,
        authorization_path,
        "2026-08-29T22:00:00Z",
        "authorized-test-operator",
        "offline-unit-test-reference",
    )
    return value, authorization_path, authorization


def test_prepare_is_non_authorizing_and_authorization_binds_unsigned_manifest(
    tmp_path: Path, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value = manifest(key)
    manifest_path = write_manifest(tmp_path, value)
    prepared_path = tmp_path / "prepared.json"
    prepared = CEREMONY.prepare(
        manifest_path, CAPSULE_NAME, prepared_path, "ceremony-test-1"
    )
    assert prepared["status"] == "prepared-awaiting-operator-authorization"
    assert prepared["operator_authorization"]["release_signing_authorized"] is False

    authorization_path = tmp_path / "authorization.json"
    authorization = CEREMONY.authorize(
        prepared_path,
        authorization_path,
        "2026-08-29T22:00:00Z",
        "authorized-test-operator",
        "offline-unit-test-reference",
    )
    assert authorization["status"] == "authorized-before-signing"
    assert CEREMONY.verify_authorization(
        authorization_path, manifest_path.read_bytes(), CAPSULE_NAME
    ) == authorization
    assert authorization["install_authority_granted"] is False
    assert authorization["nand_write_authorized"] is False


def test_prepare_refuses_drifted_target_staging_budget(
    tmp_path: Path, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value = manifest(key)
    value["target_staging_budget"]["required_tmp_free_bytes"] += 1
    with pytest.raises(CEREMONY.CeremonyError, match="target_staging_budget"):
        CEREMONY.prepare(
            write_manifest(tmp_path, value),
            CAPSULE_NAME,
            tmp_path / "prepared.json",
            "ceremony-test-drift",
        )


def test_authorization_is_exact_to_manifest_and_output_name(tmp_path: Path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value, authorization_path, _ = authorize_manifest(tmp_path, key)
    changed = dict(value)
    changed["version"] = "forged-after-authorization"
    with pytest.raises(CEREMONY.CeremonyError, match="does not bind"):
        CEREMONY.verify_authorization(
            authorization_path, CEREMONY.canonical_manifest(changed), CAPSULE_NAME
        )
    with pytest.raises(CEREMONY.CeremonyError, match="does not bind"):
        CEREMONY.verify_authorization(
            authorization_path,
            CEREMONY.canonical_manifest(value),
            "DCENT_FIRSTINSTALL_AM3_S19kPro_vdifferent.tar.gz",
        )


def test_completion_is_post_signing_closeout_and_binds_preauthorization(
    tmp_path: Path, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value, authorization_path, authorization = authorize_manifest(tmp_path, key)
    candidate = capsule(tmp_path, key, value)
    completion_path = tmp_path / "completion.json"
    completion = CEREMONY.complete(
        authorization_path,
        candidate,
        completion_path,
        "2026-08-29T22:05:00Z",
        "completion-test-operator",
        "offline-completion-reference",
    )
    assert completion["status"] == "completed-after-signing"
    assert completion["signing_authorization_receipt_id"] == authorization["receipt_id"]
    assert CEREMONY.verify(authorization_path, completion_path, candidate) == completion
    assert completion["mutation_authority_granted"] is False


def test_completion_refuses_retroactive_timestamp(tmp_path: Path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value, authorization_path, _ = authorize_manifest(tmp_path, key)
    candidate = capsule(tmp_path, key, value)
    with pytest.raises(CEREMONY.CeremonyError, match="predates"):
        CEREMONY.complete(
            authorization_path,
            candidate,
            tmp_path / "completion.json",
            "2026-08-29T21:59:59Z",
            "completion-test-operator",
            "offline-completion-reference",
        )


def test_prepare_refuses_fixture_noncanonical_input_and_no_replace(
    tmp_path: Path, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    fixture_path = write_manifest(tmp_path, manifest(key, artifact_class="test-fixture"))
    with pytest.raises(CEREMONY.CeremonyError, match="non-production"):
        CEREMONY.prepare(fixture_path, CAPSULE_NAME, tmp_path / "receipt.json", "id")

    production = manifest(key)
    manifest_path = write_manifest(tmp_path, production)
    output = tmp_path / "prepared.json"
    CEREMONY.prepare(manifest_path, CAPSULE_NAME, output, "ceremony-test-3")
    with pytest.raises(CEREMONY.CeremonyError, match="no-replace"):
        CEREMONY.prepare(manifest_path, CAPSULE_NAME, output, "ceremony-test-3")

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(production), encoding="utf-8")
    with pytest.raises(CEREMONY.CeremonyError, match="canonical"):
        CEREMONY.prepare(noncanonical, CAPSULE_NAME, tmp_path / "other.json", "id")


def test_tampered_completion_or_capsule_is_rejected(tmp_path: Path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value, authorization_path, _ = authorize_manifest(tmp_path, key)
    candidate = capsule(tmp_path, key, value)
    completion_path = tmp_path / "completion.json"
    CEREMONY.complete(
        authorization_path,
        candidate,
        completion_path,
        "2026-08-29T22:05:00Z",
        "completion-test-operator",
        "offline-completion-reference",
    )
    forged = json.loads(completion_path.read_text())
    forged["operator_completion"]["completion_reference"] = "forged"
    completion_path.write_bytes(CEREMONY.canonical_json(forged))
    with pytest.raises(CEREMONY.CeremonyError, match="receipt_id"):
        CEREMONY.verify(authorization_path, completion_path, candidate)


def test_private_key_bytes_are_never_part_of_any_receipt(tmp_path: Path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(CEREMONY, "get_pinned_release_pubkey_hex", lambda: raw_hex(key))
    value, authorization_path, _ = authorize_manifest(tmp_path, key)
    candidate = capsule(tmp_path, key, value)
    completion_path = tmp_path / "completion.json"
    CEREMONY.complete(
        authorization_path,
        candidate,
        completion_path,
        "2026-08-29T22:05:00Z",
        "completion-test-operator",
        "offline-completion-reference",
    )
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert private not in authorization_path.read_bytes()
    assert private not in completion_path.read_bytes()
