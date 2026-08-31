#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Offline tests for the S19k Pro release gate (fail-closed composition).

Discipline: fully offline, deterministic tmp fixtures, dev Ed25519 keys
generated in tmp (never committed), and no miner/network contact. The only
real-workspace touches are the two stable integrations the gate exists to
guard: the Rust contract files and the retained attempt-10 evidence node.
The live SUPPORT_MATRIX.md row is deliberately NOT asserted here — it is
volatile (owned by another lane); the check is tested against fixtures.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SCRIPT = Path(__file__).with_name("s19k_release_gate.py")
SPEC = importlib.util.spec_from_file_location("s19k_release_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules["s19k_release_gate"] = GATE  # dataclasses needs a resolvable module
SPEC.loader.exec_module(GATE)

# The public RFC 8032 test-vector-1 keypair IS the SEC-PIN-1 placeholder:
# anyone can hold this private key, so the gate must refuse it in the trust
# slot even when the signature itself verifies.
PLACEHOLDER_PRIVATE_HEX = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
PLACEHOLDER_PUBLIC_HEX = GATE.PLACEHOLDER_PUBKEY_HEX


def _raw_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class GateTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # Env hygiene: tests control the release-key environment explicitly.
        env = {k: v for k, v in os.environ.items()
               if k not in ("DCENT_RELEASE_PUBKEY_HEX",
                            "DCENT_RELEASE_PUBKEY_FILE",
                            "DCENT_RELEASE_IMAGE")}
        self._patcher = patch.dict(os.environ, env, clear=True)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        prior_custody = dict(
            GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY
        )
        GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY.clear()

        def restore_custody_registry() -> None:
            GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY.clear()
            GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY.update(
                prior_custody
            )

        self.addCleanup(restore_custody_registry)

    def sfi(self):
        return GATE._import_toolbox()

    def dev_key(self) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        os.environ["DCENT_RELEASE_PUBKEY_HEX"] = _raw_hex(key)
        return key

    def build_capsule(
        self,
        path: Path,
        key: Ed25519PrivateKey,
    ) -> Path:
        sfi = self.sfi()
        members = {
            "transition/stage1.sh":
                b"#!/bin/sh\n# on-target mtd5 window transition (gate test)\n",
            "payload/dcent-rootfs.img":
                b"S19K-AML-ROOTFS-GATE-TEST-BYTES" * 16,
        }
        manifest = {
            "schema": sfi.CAPSULE_SCHEMA,
            "package_type": sfi.CAPSULE_PACKAGE_TYPE,
            "version": "v0.1.0-gate-test",
            "board_target": sfi.S19K_AML_TARGET,
            "accepted_source_layouts": [sfi.SOURCE_BRAIINS_AML_S19K],
            "transition_mechanism":
                sfi.MECHANISM_MTD5_ROOTFS_WINDOW_FLAG_COMMIT,
            "nand_geometry": sfi.s19k_aml_geometry_pins(),
            "post_install_artifact": "sysupgrade-am3-s19k-gatetest.tar",
            "migration_scope": "gate test",
            "artifact_class": "test-fixture",
            "production_image_attestation": None,
            "transition_stage1": {
                "schema": GATE.release_policy.STAGE1_SCHEMA,
                "member": "transition/stage1.sh",
                "sha256": hashlib.sha256(
                    members["transition/stage1.sh"]
                ).hexdigest(),
                "bytes": len(members["transition/stage1.sh"]),
                "implementation_id": "test-fixture-no-production-authority",
                "audit_receipt_sha256": None,
            },
            "signing_identity": {
                "profile": "test-only",
                "key_id": "release-gate-unit-test",
                "public_key_hex": _raw_hex(key),
            },
            "checksums": {
                name: hashlib.sha256(data).hexdigest()
                for name, data in members.items()
            },
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        files = {"manifest.json": manifest_bytes, **members}
        files["MANIFEST.sig"] = key.sign(manifest_bytes)
        path.write_bytes(_tar(files))
        return path

    # --- fixtures for non-capsule checks --------------------------------

    def rust_root(self, *, clear_for_flash: str = "false",
                  offsets: bool = True) -> Path:
        root = self.tmp / "rustroot"
        base = root / "DCENT_OS_Antminer/dcentrald/dcentrald-common/src"
        base.mkdir(parents=True)
        body = f"pub const CLEAR_FOR_FLASH: bool = {clear_for_flash};\n"
        if offsets:
            body += "// rootfs window local 0x05100000 size 0x02800000\n"
        (base / "s19k_am3_install.rs").write_text(body, encoding="utf-8")
        (base / "s19k_nand_env.rs").write_text(
            "// env pins\n", encoding="utf-8")
        return root

    def evidence_node(self, content: bytes) -> Path:
        node = self.tmp / "evidence"
        node.mkdir()
        (node / "runtime_active").write_bytes(content)
        return node


class CapsuleCheckTests(GateTestBase):
    def test_missing_capsule_fails_closed(self) -> None:
        result = GATE.check_capsule(None, "11" * 32)
        self.assertFalse(result.passed)
        self.assertIn("capsule_missing", result.reason)

    def test_absent_capsule_path_fails_closed(self) -> None:
        result = GATE.check_capsule(self.tmp / "nope.tar.gz", "11" * 32)
        self.assertFalse(result.passed)
        self.assertIn("capsule_missing", result.reason)

    def test_test_fixture_signature_passes_only_in_artifact_scope(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        result = GATE.check_capsule(
            capsule, _raw_hex(key), allow_test_fixture=True
        )
        self.assertTrue(result.passed, result.reason)
        self.assertIn("signature/accounting only", result.reason)
        production = GATE.check_capsule(capsule, _raw_hex(key))
        self.assertFalse(production.passed)

    def test_wrong_signing_key_is_untrusted(self) -> None:
        pinned = self.dev_key()
        other = Ed25519PrivateKey.generate()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", other)
        result = GATE.check_capsule(capsule, _raw_hex(pinned))
        self.assertFalse(result.passed)
        self.assertIn("capsule_signature_untrusted", result.reason)

    def test_placeholder_key_fails_closed_even_when_signature_verifies(
        self,
    ) -> None:
        placeholder = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(PLACEHOLDER_PRIVATE_HEX)
        )
        self.assertEqual(_raw_hex(placeholder), PLACEHOLDER_PUBLIC_HEX)
        os.environ["DCENT_RELEASE_PUBKEY_HEX"] = PLACEHOLDER_PUBLIC_HEX
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", placeholder)
        result = GATE.check_capsule(
            capsule, PLACEHOLDER_PUBLIC_HEX, allow_test_fixture=True
        )
        self.assertFalse(result.passed)
        self.assertIn("placeholder_in_trust_slot", result.reason)

    def test_anchor_mismatch_fails_closed(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        result = GATE.check_capsule(
            capsule,
            GATE.DEFAULT_EXPECTED_PUBKEY_HEX,
            allow_test_fixture=True,
        )
        self.assertFalse(result.passed)
        self.assertIn("anchor_mismatch", result.reason)

    def test_malformed_env_override_fails_closed(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        os.environ["DCENT_RELEASE_PUBKEY_HEX"] = "not-hex"
        result = GATE.check_capsule(capsule, _raw_hex(key))
        self.assertFalse(result.passed)
        self.assertTrue(
            result.reason.startswith("capsule_signature_untrusted")
            or result.reason.startswith("release_pubkey_unresolvable"),
            result.reason,
        )

    def test_signed_structural_fixture_cannot_satisfy_production_binding(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        result = GATE.check_production_capsule_binding(
            capsule, self.tmp, _raw_hex(key)
        )
        self.assertFalse(result.passed)
        self.assertIn("artifact_class_not_production", result.reason)


class GeometryCheckTests(GateTestBase):
    def test_real_workspace_contracts_pass(self) -> None:
        result = GATE.check_geometry(GATE.WORKSPACE_ROOT)
        self.assertTrue(result.passed, result.reason)

    def test_flipped_rust_pin_fails_closed(self) -> None:
        result = GATE.check_geometry(
            self.rust_root(clear_for_flash="true"))
        self.assertFalse(result.passed)
        self.assertIn("clear_for_flash_mismatch", result.reason)

    def test_missing_offset_fails_closed(self) -> None:
        result = GATE.check_geometry(self.rust_root(offsets=False))
        self.assertFalse(result.passed)
        self.assertIn("geometry_pin_absent_from_rust", result.reason)

    def test_missing_contract_file_fails_closed(self) -> None:
        empty = self.tmp / "empty"
        empty.mkdir()
        result = GATE.check_geometry(empty)
        self.assertFalse(result.passed)
        self.assertIn("contract_file_missing", result.reason)


class SupportMatrixCheckTests(GateTestBase):
    def matrix(self, text: str) -> Path:
        path = self.tmp / "SUPPORT_MATRIX.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_current_row_passes(self) -> None:
        path = self.matrix(
            "| vendor | model | target |\n"
            "| antminer | S19kPro | am3-s19k | bounded-work proof 2-of-2 "
            "UARTs; FLASH NOT_YET |\n"
        )
        self.assertTrue(GATE.check_support_matrix(path).passed)

    def test_stale_marker_fails_closed(self) -> None:
        path = self.matrix(
            "| antminer | S19kPro | am3-s19k | ttyS2 work-phase RX is the "
            "last open mining defect |\n"
        )
        result = GATE.check_support_matrix(path)
        self.assertFalse(result.passed)
        self.assertIn("stale_row_claim", result.reason)

    def test_missing_row_fails_closed(self) -> None:
        path = self.matrix("| antminer | S9 | am1-s9 |\n")
        result = GATE.check_support_matrix(path)
        self.assertFalse(result.passed)
        self.assertIn("s19kpro_row_missing", result.reason)


class EvidenceCheckTests(GateTestBase):
    def test_real_attempt10_node_passes(self) -> None:
        node = GATE.WORKSPACE_ROOT / GATE.DEFAULT_EVIDENCE_NODE_REL
        result = GATE.check_evidence(node, GATE.DEFAULT_EVIDENCE_PINS)
        self.assertTrue(result.passed, result.reason)

    def test_hash_mismatch_fails_closed(self) -> None:
        node = self.tmp / "node"
        node.mkdir()
        name = "runtime_active"
        (node / name).write_bytes(b"tampered")
        result = GATE.check_evidence(node, {name: "00" * 32})
        self.assertFalse(result.passed)
        self.assertIn("evidence_hash_mismatch", result.reason)

    def test_missing_file_fails_closed(self) -> None:
        node = self.tmp / "node"
        node.mkdir()
        result = GATE.check_evidence(node, {"runtime_active": "11" * 32})
        self.assertFalse(result.passed)
        self.assertIn("evidence_file_missing", result.reason)


class ProductionBindingCheckTests(GateTestBase):
    def production_fixture(self):
        stage_bytes = b"#!/bin/sh\n# reviewed production-shaped test writer\n"
        authorizer_bytes = b"pytest-armv7-stage1-authorizer\n"
        image = b"production-shaped-image-fixture"
        custody_bytes = {
            member: f"{role}-production-shaped-fixture\n".encode("ascii")
            for role, member in GATE.release_policy.CUSTODY_MEMBER_BY_ROLE.items()
        }
        GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY[
            GATE.release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID
        ] = tuple(
            (
                member,
                hashlib.sha256(custody_bytes[member]).hexdigest(),
                len(custody_bytes[member]),
            )
            for member in sorted(GATE.release_policy.CUSTODY_MEMBER_BY_ROLE.values())
        )
        verified = {
            "schema": GATE.release_policy.PERSISTENT_IMAGE_SCHEMA,
            "phase_id": "persistent-image",
            "classification": "verified",
            "installable": True,
            "board": "am3-s19k",
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "image_bytes": len(image),
            "package_sha256": "1" * 64,
            "package_bytes": len(image) + 4096,
            "unsigned_package_sha256": "2" * 64,
            "unsigned_package_bytes": len(image) + 2048,
            "a_b_unsigned_equality_verified": True,
            "private_key_excluded_from_builds": True,
            "isolated_post_ab_signing_verified": False,
            "post_ab_derivation_and_runtime_metadata_verified": True,
            "isolated_post_ab_signing_nonclaim": (
                GATE.release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
            ),
            "post_ab_signing_id": "3" * 64,
            "post_ab_signing_receipt_sha256": "4" * 64,
            "host_preflight_id": "5" * 64,
            "host_preflight_receipt_sha256": "6" * 64,
            "host_preflight_component_sha256": "7" * 64,
            "isolated_signer_runtime_id": "8" * 64,
            "isolated_signer_runtime_receipt_sha256": "9" * 64,
            "isolated_signer_private_key_custody_id": "a" * 64,
            "source_commit": "e" * 40,
            "source_date_epoch": 1_700_000_000,
            "release_key_sha256": "b" * 64,
            "release_key_id": "c" * 64,
            "release_manifest_public_key_hex": "c" * 64,
            "signed_manifest_sha256": "c" * 64,
            "persistent_image_contract_sha256": "d" * 64,
            "native_owner_verification_id": "e" * 64,
            "native_owner_receipt_sha256": "f" * 64,
            "native_owner_artifact_sha256": "1" * 64,
            "native_owner_source_files_sha256": "2" * 64,
            "native_owner_aarch64_compile_contract_bound": True,
            "reproducible_builds_verified": True,
            "signed_manifest_verified": True,
            "native_owner_artifact_bound": True,
            "stock_recovery_receipt_bound": True,
            "native_owner_source_artifact_build_binding_verified": True,
            "native_owner_clean_source_commit_bound": True,
            "stock_recovery_verification_id": "3" * 64,
            "stock_recovery_receipt_sha256": "4" * 64,
            "stock_recovery_device_id": "s19kpro-78",
            "aml_rootfs_geometry": {},
            "safeoff_boot_baseline": {},
            "install_authority_granted": False,
            "mutation_authority_granted": False,
            "nand_write_authorized": False,
            "live_hardware_contacted": False,
            "network_used": False,
            "verification_id": "a" * 64,
        }
        approval = GATE.release_policy.Stage1Approval(
            "pytest-reviewed-stage1", "pytest-audit.json", "d" * 64
        )
        authorizer_approval = GATE.release_policy.Stage1AuthorizerApproval(
            implementation_id="pytest-reviewed-armv7-authorizer",
            source_snapshot_commit="e" * 40,
            audit_receipt_path="pytest-authorizer-audit.json",
            audit_receipt_sha256="8" * 64,
            target_kat_verified=True,
        )
        counted_bytes = {
            "payload/dcent-rootfs.img": image,
            "transition/stage1.sh": stage_bytes,
            "transition/s19k-stage1-authorizer": authorizer_bytes,
            **custody_bytes,
        }
        counted_members = [
            {
                "member": name,
                "sha256": hashlib.sha256(counted_bytes[name]).hexdigest(),
                "bytes": len(counted_bytes[name]),
            }
            for name in sorted(counted_bytes)
        ]
        coexisting_bytes = sum(item["bytes"] for item in counted_members)
        manifest = {
            "artifact_class": "production",
            "accepted_source_layouts": ["braiins-aml-s19k"],
            "signing_identity": {
                "profile": "production-release",
                "key_id": "c" * 64,
                "public_key_hex": "c" * 64,
            },
            "source_snapshot": {
                "schema": GATE.release_policy.SOURCE_SNAPSHOT_SCHEMA,
                "commit": "e" * 40,
                "tree": "f" * 40,
                "commit_signature_verified": True,
                "clean_worktree_verified": True,
            },
            "production_image_attestation": {
                "member": GATE.release_policy.PERSISTENT_IMAGE_MEMBER,
                "verification_id": verified["verification_id"],
                "image_member": "payload/dcent-rootfs.img",
                "image_sha256": verified["image_sha256"],
                "image_bytes": verified["image_bytes"],
                "release_key_sha256": verified["release_key_sha256"],
                "release_manifest_public_key_hex": "c" * 64,
            },
            "transition_stage1": {
                "schema": GATE.release_policy.STAGE1_SCHEMA,
                "member": "transition/stage1.sh",
                "sha256": hashlib.sha256(stage_bytes).hexdigest(),
                "bytes": len(stage_bytes),
                "implementation_id": approval.implementation_id,
                "audit_receipt_sha256": approval.audit_receipt_sha256,
            },
            "transition_stage1_authorizer": {
                "schema": GATE.release_policy.STAGE1_AUTHORIZER_SCHEMA,
                "member": "transition/s19k-stage1-authorizer",
                "sha256": hashlib.sha256(authorizer_bytes).hexdigest(),
                "bytes": len(authorizer_bytes),
                "implementation_id": authorizer_approval.implementation_id,
                "target_kat_verified": True,
                "source_snapshot_commit": "e" * 40,
            },
            "install_custody": {
                "schema": GATE.release_policy.INSTALL_CUSTODY_SCHEMA,
                "implementation_id": (
                    GATE.release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID
                ),
                "protocol": GATE.release_policy.INSTALL_CUSTODY_PROTOCOL,
                "mode": GATE.release_policy.INSTALL_CUSTODY_MODE,
                "daemon_flag": GATE.release_policy.INSTALL_CUSTODY_DAEMON_FLAG,
                "physical_safeoff_contract": (
                    GATE.release_policy.INSTALL_CUSTODY_PHYSICAL_SAFEOFF_CONTRACT
                ),
                "reset_contract": GATE.release_policy.INSTALL_CUSTODY_RESET_CONTRACT,
                "transcript_schema": (
                    GATE.release_policy.INSTALL_CUSTODY_TRANSCRIPT_SCHEMA
                ),
                "terminal_receipt_schema": (
                    GATE.release_policy.INSTALL_CUSTODY_TERMINAL_RECEIPT_SCHEMA
                ),
                "safeoff_receipt_schema": (
                    GATE.release_policy.INSTALL_CUSTODY_SAFEOFF_RECEIPT_SCHEMA
                ),
                "pending_receipt_schema": (
                    GATE.release_policy.INSTALL_CUSTODY_PENDING_RECEIPT_SCHEMA
                ),
                "target_reference_config_path": (
                    GATE.release_policy.INSTALL_CUSTODY_TARGET_REFERENCE_CONFIG_PATH
                ),
                "staged_config_basename": (
                    GATE.release_policy.INSTALL_CUSTODY_STAGED_CONFIG_BASENAME
                ),
                "source_layouts": ["braiins-aml-s19k"],
                "target_identity_profiles": [
                    "live88_two_bhb56903_slots_2_3"
                ],
                **{
                    role: {
                        "member": member,
                        "sha256": hashlib.sha256(custody_bytes[member]).hexdigest(),
                        "bytes": len(custody_bytes[member]),
                    }
                    for role, member in (
                        GATE.release_policy.CUSTODY_MEMBER_BY_ROLE.items()
                    )
                },
            },
            "target_staging_budget": {
                "schema": GATE.release_policy.TARGET_STAGING_BUDGET_SCHEMA,
                "rootfs_readback_mode": "streaming_sha256_no_rootfs_copy",
                "counted_members": counted_members,
                "coexisting_capsule_member_bytes": coexisting_bytes,
                "per_unit_inputs_budget_bytes": 524288,
                "working_free_reserve_bytes": 8388608,
                "required_tmp_free_bytes": coexisting_bytes + 524288 + 8388608,
            },
        }
        files = {
            GATE.release_policy.PERSISTENT_IMAGE_MEMBER:
                GATE.persistent_image.canonical_json(verified),
            "payload/dcent-rootfs.img": image,
            "transition/stage1.sh": stage_bytes,
            "transition/s19k-stage1-authorizer": authorizer_bytes,
            **custody_bytes,
        }
        return manifest, files, verified, approval, authorizer_approval

    def binding_result(
        self,
        manifest,
        files,
        verified,
        approval,
        authorizer_approval,
    ):
        files[GATE.release_policy.PERSISTENT_IMAGE_MEMBER] = (
            GATE.persistent_image.canonical_json(verified)
        )
        with (
            patch.object(
                GATE,
                "_capsule_manifest_and_files",
                return_value=(manifest, files),
            ),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(
                GATE.persistent_image,
                "verify_evidence",
                return_value=verified,
            ),
            patch.object(
                GATE.release_policy,
                "approved_stage1",
                return_value=approval,
            ),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=authorizer_approval,
            ),
        ):
            return GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
                100 * 1024 * 1024,
                "live88_two_bhb56903_slots_2_3",
            )

    def test_current_v4_binding_refuses_missing_independent_signer_boundary(
        self,
    ) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        observed = []

        def verify(_directory, *, expected_release_key_sha256=None):
            observed.append(expected_release_key_sha256)
            return verified

        os.environ["DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256"] = "0" * 64
        with (
            patch.object(GATE, "_capsule_manifest_and_files", return_value=(manifest, files)),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(GATE.persistent_image, "verify_evidence", side_effect=verify),
            patch.object(GATE.release_policy, "approved_stage1", return_value=approval),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=authorizer_approval,
            ),
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
                100 * 1024 * 1024,
                "live88_two_bhb56903_slots_2_3",
            )
        self.assertFalse(result.passed)
        self.assertIn(
            "independently authenticated signer-boundary projection",
            result.reason,
        )
        self.assertEqual(observed, ["9" * 64])

    def test_production_binding_rejects_stale_v3_receipt(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        verified["schema"] = "dcentos.s19k-persistent-image-verification/v3"
        result = self.binding_result(
            manifest, files, verified, approval, authorizer_approval
        )
        self.assertFalse(result.passed)
        self.assertIn("persistent_image_schema_mismatch", result.reason)

    def test_production_binding_rejects_missing_v4_field(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        del verified["host_preflight_component_sha256"]
        result = self.binding_result(
            manifest, files, verified, approval, authorizer_approval
        )
        self.assertFalse(result.passed)
        self.assertIn("persistent_image_v4_key_set_mismatch", result.reason)

    def test_production_binding_preserves_signing_isolation_nonclaim(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        verified["isolated_post_ab_signing_nonclaim"] = "isolation-proven"
        result = self.binding_result(
            manifest, files, verified, approval, authorizer_approval
        )
        self.assertFalse(result.passed)
        self.assertIn("signing_isolation_nonclaim_mismatch", result.reason)

    def test_production_binding_exact_joins_v4_release_key_id(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        verified["release_key_id"] = "d" * 64
        result = self.binding_result(
            manifest, files, verified, approval, authorizer_approval
        )
        self.assertFalse(result.passed)
        self.assertIn("persistent_image_release_key_id_mismatch", result.reason)

    def test_ambient_key_digest_cannot_replace_explicit_pin(self) -> None:
        manifest, files, _verified, _approval, _authorizer_approval = (
            self.production_fixture()
        )
        os.environ["DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256"] = "9" * 64
        with patch.object(
            GATE, "_capsule_manifest_and_files", return_value=(manifest, files)
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz", self.tmp, "c" * 64
            )
        self.assertFalse(result.passed)
        self.assertIn("expected_release_key_sha256_missing", result.reason)

    def test_signed_staging_budget_refuses_insufficient_live_tmp(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        required = manifest["target_staging_budget"]["required_tmp_free_bytes"]
        with (
            patch.object(GATE, "_capsule_manifest_and_files", return_value=(manifest, files)),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(GATE.persistent_image, "verify_evidence", return_value=verified),
            patch.object(GATE.release_policy, "approved_stage1", return_value=approval),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=authorizer_approval,
            ),
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
                required - 1,
                "live88_two_bhb56903_slots_2_3",
            )
        self.assertFalse(result.passed)
        self.assertIn("target_tmp_capacity_insufficient", result.reason)

    def test_luxos_cannot_claim_braiins_install_custody(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        manifest["accepted_source_layouts"] = ["luxos-aml-s19k"]
        with (
            patch.object(GATE, "_capsule_manifest_and_files", return_value=(manifest, files)),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(GATE.persistent_image, "verify_evidence", return_value=verified),
            patch.object(GATE.release_policy, "approved_stage1", return_value=approval),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=authorizer_approval,
            ),
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
                100 * 1024 * 1024,
                "live88_two_bhb56903_slots_2_3",
            )
        self.assertFalse(result.passed)
        self.assertIn("install_custody_source_scope_mismatch", result.reason)

    def test_install_custody_mode_and_physical_contract_are_exact(self) -> None:
        for field, value in (
            ("mode", "handoff-no-work"),
            ("physical_safeoff_contract", "ResetThenGpio437Cut"),
            ("reset_contract", "454:0,455:0,456:0"),
        ):
            with self.subTest(field=field):
                manifest, files, verified, approval, authorizer_approval = (
                    self.production_fixture()
                )
                manifest["install_custody"][field] = value
                with (
                    patch.object(
                        GATE,
                        "_capsule_manifest_and_files",
                        return_value=(manifest, files),
                    ),
                    patch.object(GATE, "_source_snapshot_problem", return_value=None),
                    patch.object(
                        GATE.persistent_image,
                        "verify_evidence",
                        return_value=verified,
                    ),
                    patch.object(
                        GATE.release_policy,
                        "approved_stage1",
                        return_value=approval,
                    ),
                    patch.object(
                        GATE.release_policy,
                        "approved_stage1_authorizer",
                        return_value=authorizer_approval,
                    ),
                ):
                    result = GATE.check_production_capsule_binding(
                        self.tmp / "capsule.tar.gz",
                        self.tmp,
                        "c" * 64,
                        "9" * 64,
                        self.tmp,
                        100 * 1024 * 1024,
                        "live88_two_bhb56903_slots_2_3",
                    )
                self.assertFalse(result.passed)
                self.assertIn("install_custody_scope_or_protocol_mismatch", result.reason)

    def test_install_custody_bundle_requires_reviewed_exact_pins(self) -> None:
        manifest, files, verified, approval, authorizer_approval = (
            self.production_fixture()
        )
        GATE.release_policy.APPROVED_PRODUCTION_INSTALL_CUSTODY.clear()
        with (
            patch.object(GATE, "_capsule_manifest_and_files", return_value=(manifest, files)),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(GATE.persistent_image, "verify_evidence", return_value=verified),
            patch.object(GATE.release_policy, "approved_stage1", return_value=approval),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=authorizer_approval,
            ),
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
                100 * 1024 * 1024,
                "live88_two_bhb56903_slots_2_3",
            )
        self.assertFalse(result.passed)
        self.assertIn("install_custody_bundle_unapproved", result.reason)

    def test_unapproved_authorizer_cannot_satisfy_production_binding(self) -> None:
        manifest, files, verified, approval, _authorizer_approval = (
            self.production_fixture()
        )

        with (
            patch.object(GATE, "_capsule_manifest_and_files", return_value=(manifest, files)),
            patch.object(GATE, "_source_snapshot_problem", return_value=None),
            patch.object(
                GATE.persistent_image,
                "verify_evidence",
                return_value=verified,
            ),
            patch.object(GATE.release_policy, "approved_stage1", return_value=approval),
            patch.object(
                GATE.release_policy,
                "approved_stage1_authorizer",
                return_value=None,
            ),
        ):
            result = GATE.check_production_capsule_binding(
                self.tmp / "capsule.tar.gz",
                self.tmp,
                "c" * 64,
                "9" * 64,
                self.tmp,
            )

        self.assertFalse(result.passed)
        self.assertIn("transition_stage1_authorizer_unapproved", result.reason)


class CeremonyGateTests(GateTestBase):
    def test_both_pre_and_post_signing_receipts_are_required(self) -> None:
        result = GATE.check_signing_ceremony(
            self.tmp / "capsule.tar.gz", self.tmp / "authorization.json", None
        )
        self.assertFalse(result.passed)
        self.assertIn("pre-signing authorization", result.reason)


class ExecutorGateTests(GateTestBase):
    def test_exact_executor_and_cli_sources_are_externally_bound(self) -> None:
        root = self.rust_root(clear_for_flash="true")
        rust = root / GATE.RUST_CONTRACT_RELS[0]
        executor_source = root / (
            "projects/dcent-toolbox/src/dcent_toolbox/core/"
            "s19k_aml_install_executor.py"
        )
        cli_source = root / (
            "projects/dcent-toolbox/src/dcent_toolbox/cli/commands/"
            "s19k_aml_first_install.py"
        )
        executor_source.parent.mkdir(parents=True, exist_ok=True)
        cli_source.parent.mkdir(parents=True, exist_ok=True)
        executor_source.write_bytes(b"reviewed executor fixture\n")
        cli_source.write_bytes(b"reviewed cli fixture\n")
        safeoff_source = root / "DCENT_OS_Antminer/scripts/safeoff-fixture.sh"
        restart_source = root / "DCENT_OS_Antminer/scripts/restart-fixture.sh"
        witness_source = root / "DCENT_OS_Antminer/scripts/witness-fixture.py"
        safeoff_source.parent.mkdir(parents=True, exist_ok=True)
        safeoff_source.write_bytes(b"reviewed safeoff fixture\n")
        restart_source.write_bytes(b"reviewed restart fixture\n")
        witness_source.write_bytes(b"reviewed witness fixture\n")
        sfi = self.sfi()
        from dcent_toolbox.core import s19k_aml_install_executor as executor

        contract = {
            "schema": "dcent-toolbox.s19k-aml-production-executor/v1",
            "implementation_id": "dcent-toolbox-s19k-aml-executor-posix-ssh-v1",
            "executor_source": str(executor_source.relative_to(root)).replace("\\", "/"),
            "cli_source": str(cli_source.relative_to(root)).replace("\\", "/"),
            "implemented": True,
            "authorizes_execution": False,
            "dual_interlock_independent": True,
            "online_release_private_key_loaded": False,
            "offline_detached_stage1_authorization_required": True,
            "safeoff_custody_transition_implemented": True,
            "pre_mutation_stock_restart_recovery_implemented": True,
            "scoped_postinstall_witness_implemented": True,
            "production_execution_ready": True,
            "safeoff_runner_source": str(safeoff_source.relative_to(root)).replace("\\", "/"),
            "stock_restart_source": str(restart_source.relative_to(root)).replace("\\", "/"),
            "postinstall_witness_source": str(witness_source.relative_to(root)).replace("\\", "/"),
            "dcentos_mutation_contract": {
                "relative_source": GATE.RUST_CONTRACT_RELS[0],
                "source_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                "clear_for_flash": True,
            },
        }
        executor_sha = hashlib.sha256(executor_source.read_bytes()).hexdigest()
        cli_sha = hashlib.sha256(cli_source.read_bytes()).hexdigest()
        safeoff_sha = hashlib.sha256(safeoff_source.read_bytes()).hexdigest()
        restart_sha = hashlib.sha256(restart_source.read_bytes()).hexdigest()
        witness_sha = hashlib.sha256(witness_source.read_bytes()).hexdigest()
        with (
            patch.object(sfi, "CLEAR_FOR_FLASH", True),
            patch.object(executor, "PRODUCTION_EXECUTOR_IMPLEMENTED", True),
            patch.object(
                executor, "production_executor_contract", return_value=contract
            ) as contract_reader,
        ):
            result = GATE.check_flash_authority_and_executor(
                root,
                executor_sha,
                cli_sha,
                safeoff_sha,
                restart_sha,
                witness_sha,
            )
            stale = GATE.check_flash_authority_and_executor(
                root,
                executor_sha,
                "0" * 64,
                safeoff_sha,
                restart_sha,
                witness_sha,
            )
            contract_reader.return_value = {
                **contract,
                "safeoff_custody_transition_implemented": False,
                "production_execution_ready": False,
            }
            missing_live_rail = GATE.check_flash_authority_and_executor(
                root,
                executor_sha,
                cli_sha,
                safeoff_sha,
                restart_sha,
                witness_sha,
            )
        self.assertTrue(result.passed, result.reason)
        self.assertFalse(stale.passed)
        self.assertIn("executor_cli_source_identity_mismatch", stale.reason)
        self.assertFalse(missing_live_rail.passed)
        self.assertIn("safeoff_custody_transition_implemented", missing_live_rail.reason)


class CampaignTerminalCheckTests(GateTestBase):
    def controller(self, output: str) -> tuple[Path, Path]:
        root = self.tmp / "workspace"
        script = root / "DCENT_OS_Antminer/scripts/s19k_gauntlet_workflow.py"
        script.parent.mkdir(parents=True)
        script.write_text(f"print({output!r})\n", encoding="utf-8")
        manifest = self.tmp / "campaign.json"
        manifest.write_text("{}\n", encoding="utf-8")
        return root, manifest

    def test_exact_terminal_lines_pass(self) -> None:
        root, manifest = self.controller(
            "complete=true\ncomplete-dcentos-enablement: verified witness=pytest"
        )
        result = GATE.check_campaign_terminal_completion(
            root, manifest, None, None
        )
        self.assertTrue(result.passed, result.reason)

    def test_substring_cannot_spoof_terminal_completion(self) -> None:
        root, manifest = self.controller(
            "incomplete=true\ncomplete-dcentos-enablement: unverified"
        )
        result = GATE.check_campaign_terminal_completion(
            root, manifest, None, None
        )
        self.assertFalse(result.passed)
        self.assertIn("campaign_incomplete", result.reason)


class RunGateTests(GateTestBase):
    def gate_args(self, **overrides) -> list[str]:
        args = [
            "--support-matrix", str(self._matrix),
            "--evidence-node", str(GATE.WORKSPACE_ROOT
                                   / GATE.DEFAULT_EVIDENCE_NODE_REL),
            "--dcentos-root", str(GATE.WORKSPACE_ROOT),
        ]
        for key, value in overrides.items():
            flag = f"--{key.replace('_', '-')}"
            if isinstance(value, bool):
                if value:
                    args.append(flag)
            else:
                args.extend([flag, str(value)])
        return args

    def setUp(self) -> None:
        super().setUp()
        self._matrix = self.tmp / "SUPPORT_MATRIX.md"
        self._matrix.write_text(
            "| antminer | S19kPro | am3-s19k | current |\n",
            encoding="utf-8",
        )

    def test_artifact_only_pass_returns_zero_but_is_not_production(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        self.assertEqual(
            GATE.main(self.gate_args(capsule=capsule,
                                     expected_pubkey=_raw_hex(key),
                                     artifact_only=True)),
            0,
        )

    def test_default_production_scope_cannot_green_on_test_fixture(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        self.assertEqual(
            GATE.main(self.gate_args(capsule=capsule,
                                     expected_pubkey=_raw_hex(key))),
            1,
        )

    def test_fixture_controlled_production_happy_path_composes_all_eight(self) -> None:
        args = GATE.parser().parse_args([])
        passes = {
            check_id: GATE.GateResult(check_id, "pass", "fixture-controlled")
            for check_id in GATE.CHECK_IDS
        }
        with (
            patch.object(GATE, "check_capsule", return_value=passes[GATE.CHECK_IDS[0]]),
            patch.object(GATE, "check_geometry", return_value=passes[GATE.CHECK_IDS[1]]),
            patch.object(GATE, "check_support_matrix", return_value=passes[GATE.CHECK_IDS[2]]),
            patch.object(GATE, "check_evidence", return_value=passes[GATE.CHECK_IDS[3]]),
            patch.object(
                GATE,
                "check_production_capsule_binding",
                return_value=passes[GATE.CHECK_IDS[4]],
            ),
            patch.object(
                GATE,
                "check_signing_ceremony",
                return_value=passes[GATE.CHECK_IDS[5]],
            ),
            patch.object(
                GATE,
                "check_flash_authority_and_executor",
                return_value=passes[GATE.CHECK_IDS[6]],
            ),
            patch.object(
                GATE,
                "check_campaign_terminal_completion",
                return_value=passes[GATE.CHECK_IDS[7]],
            ),
        ):
            results = GATE.run_gate(args)
        self.assertEqual(tuple(result.check_id for result in results), GATE.CHECK_IDS)
        self.assertTrue(all(result.passed for result in results))

    def test_any_failure_returns_one(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        self._matrix.write_text("| antminer | S9 | am1-s9 |\n",
                                encoding="utf-8")
        self.assertEqual(
            GATE.main(self.gate_args(capsule=capsule,
                                     expected_pubkey=_raw_hex(key),
                                     artifact_only=True)),
            1,
        )

    def test_ledger_emission_requires_full_pass_and_no_replace(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        ledger = self.tmp / "SHA256LEDGER.txt"
        rc = GATE.main(self.gate_args(
            capsule=capsule,
            expected_pubkey=_raw_hex(key),
            artifact_only=True,
            emit_ledger=ledger,
            recorded_utc="2026-08-29T00:00:00Z",
            git_head="testhead",
        ))
        self.assertEqual(rc, 0)
        text = ledger.read_text(encoding="utf-8")
        self.assertIn(GATE.LEDGER_SCHEMA, text)
        self.assertIn("capsule", text)
        self.assertIn("# scope: artifact-only", text)
        self.assertIn("# production_ready: false", text)
        # no-replace: a second emission over the same path is refused
        with self.assertRaises(SystemExit):
            GATE.main(self.gate_args(
                capsule=capsule,
                expected_pubkey=_raw_hex(key),
                artifact_only=True,
                emit_ledger=ledger,
            ))

    def test_ledger_refused_while_failing(self) -> None:
        ledger = self.tmp / "SHA256LEDGER.txt"
        rc = GATE.main(self.gate_args(emit_ledger=ledger))
        self.assertEqual(rc, 1)
        self.assertFalse(ledger.exists())

    def test_json_report_is_durable_no_replace(self) -> None:
        key = self.dev_key()
        capsule = self.build_capsule(self.tmp / "capsule.tar.gz", key)
        report = self.tmp / "gate-report.json"
        args = self.gate_args(
            capsule=capsule,
            expected_pubkey=_raw_hex(key),
            artifact_only=True,
            json_report=report,
        )
        self.assertEqual(GATE.main(args), 0)
        self.assertTrue(report.is_file())
        with self.assertRaises(SystemExit):
            GATE.main(args)


class CheckIdConstantTests(GateTestBase):
    def test_check_ids_include_artifact_and_production_checks(self) -> None:
        self.assertEqual(
            GATE.CHECK_IDS,
            (
                "capsule_signature_pinned_anchor",
                "manifest_geometry_vs_rust_contracts",
                "support_matrix_row_currency",
                "evidence_node_hash_presence",
                "production_capsule_image_and_stage1_binding",
                "signing_ceremony_receipt",
                "flash_authority_and_executor",
                "campaign_terminal_completion",
            ),
        )

    def test_list_checks_prints_ids(self) -> None:
        self.assertEqual(GATE.main(["--list-checks"]), 0)

    def test_production_ledger_policy_sources_bind_authorizer_and_custody_contracts(self) -> None:
        self.assertIn(
            "DCENT_OS_Antminer/dcentrald/s19k-stage1-authorizer/src/main.rs",
            GATE.PRODUCTION_LEDGER_POLICY_SOURCE_RELS,
        )
        self.assertIn(
            "DCENT_OS_Antminer/",
            GATE.PRODUCTION_LEDGER_POLICY_SOURCE_RELS,
        )
        self.assertIn(
            "DCENT_OS_Antminer/",
            GATE.PRODUCTION_LEDGER_POLICY_SOURCE_RELS,
        )


if __name__ == "__main__":
    unittest.main()
