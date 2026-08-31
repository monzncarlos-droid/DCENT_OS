#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Fail-closed S19k production-capsule policy shared by desk tooling.

This module is deliberately data-only.  It grants no signing, install, or
flash authority.  In particular, the production stage-1 registry starts
empty: the current root-level ``stage1.sh`` is a synthetic no-I/O fixture,
and the host-side ``install_amlogic_persistent.sh`` is not an on-target
stage-1 implementation.  A real target-side implementation must be reviewed,
mechanically converged with the host writer contract, and added here together
with a hash-bound audit receipt before a production capsule can be built.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ARTIFACT_CLASS_PRODUCTION = "production"
ARTIFACT_CLASS_TEST_FIXTURE = "test-fixture"
ARTIFACT_CLASSES = frozenset(
    {ARTIFACT_CLASS_PRODUCTION, ARTIFACT_CLASS_TEST_FIXTURE}
)

SIGNING_PROFILE_PRODUCTION = "production-release"
SIGNING_PROFILE_TEST = "test-only"

PERSISTENT_IMAGE_MEMBER = "evidence/persistent-image-verification.json"
PERSISTENT_IMAGE_SCHEMA = "dcentos.s19k-persistent-image-verification/v4"
PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM = (
    "retained-runtime-metadata-is-not-joined-to-independent-source-"
    "authority-and-exact-oci-boundary"
)
PERSISTENT_IMAGE_PRODUCTION_SIGNER_BOUNDARY_REFUSAL = (
    "production release refused: the v4 persistent-image receipt does not "
    "contain an independently authenticated signer-boundary projection"
)
PERSISTENT_IMAGE_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "phase_id",
        "classification",
        "installable",
        "board",
        "image_sha256",
        "image_bytes",
        "package_sha256",
        "package_bytes",
        "unsigned_package_sha256",
        "unsigned_package_bytes",
        "a_b_unsigned_equality_verified",
        "private_key_excluded_from_builds",
        "isolated_post_ab_signing_verified",
        "post_ab_derivation_and_runtime_metadata_verified",
        "isolated_post_ab_signing_nonclaim",
        "post_ab_signing_id",
        "post_ab_signing_receipt_sha256",
        "host_preflight_id",
        "host_preflight_receipt_sha256",
        "host_preflight_component_sha256",
        "isolated_signer_runtime_id",
        "isolated_signer_runtime_receipt_sha256",
        "isolated_signer_private_key_custody_id",
        "source_commit",
        "source_date_epoch",
        "release_key_sha256",
        "release_key_id",
        "release_manifest_public_key_hex",
        "signed_manifest_sha256",
        "persistent_image_contract_sha256",
        "native_owner_verification_id",
        "native_owner_receipt_sha256",
        "native_owner_artifact_sha256",
        "native_owner_source_files_sha256",
        "native_owner_aarch64_compile_contract_bound",
        "native_owner_source_artifact_build_binding_verified",
        "native_owner_clean_source_commit_bound",
        "stock_recovery_verification_id",
        "stock_recovery_receipt_sha256",
        "stock_recovery_device_id",
        "aml_rootfs_geometry",
        "safeoff_boot_baseline",
        "reproducible_builds_verified",
        "signed_manifest_verified",
        "native_owner_artifact_bound",
        "stock_recovery_receipt_bound",
        "install_authority_granted",
        "mutation_authority_granted",
        "nand_write_authorized",
        "live_hardware_contacted",
        "network_used",
        "verification_id",
    }
)
STAGE1_SCHEMA = "dcentos.s19k-mtd5-rootfs-window-stage1/v1"
STAGE1_AUTHORIZER_SCHEMA = "dcentos.s19k-stage1-authorizer/v1"
INSTALL_CUSTODY_SCHEMA = "dcentos.s19k-install-custody/v2"
INSTALL_CUSTODY_IMPLEMENTATION_ID = "dcentos-s19k-install-custody-safeoff-v1"
INSTALL_CUSTODY_PROTOCOL = (
    "track1-install-custody-safeoff-terminal-safeoff-stock-restart-pending"
)
INSTALL_CUSTODY_MODE = "install-custody-safeoff"
INSTALL_CUSTODY_DAEMON_FLAG = "--s19k-install-custody-safeoff"
INSTALL_CUSTODY_PHYSICAL_SAFEOFF_CONTRACT = "InstallCustodyGpio437Only"
INSTALL_CUSTODY_RESET_CONTRACT = "not-attempted"
INSTALL_CUSTODY_TRANSCRIPT_SCHEMA = "dcentos.s19k-install-custody-transcript/v1"
INSTALL_CUSTODY_TERMINAL_RECEIPT_SCHEMA = (
    "dcentos.s19k-install-custody-terminal-safeoff/v1"
)
INSTALL_CUSTODY_SAFEOFF_RECEIPT_SCHEMA = "dcentos.s19k-install-custody-safeoff/v1"
INSTALL_CUSTODY_PENDING_RECEIPT_SCHEMA = (
    "dcentos.s19k-install-custody-stock-restart-pending/v1"
)
INSTALL_CUSTODY_TARGET_REFERENCE_CONFIG_PATH = (
    "/usr/share/dcentos/install-custody/dcentrald_s19k.toml"
)
INSTALL_CUSTODY_STAGED_CONFIG_BASENAME = "dcentrald_s19k.toml"
INSTALL_CUSTODY_SOURCE_LAYOUTS = ("braiins-aml-s19k",)
INSTALL_CUSTODY_TARGET_IDENTITY_PROFILES = (
    "live88_two_bhb56903_slots_2_3",
)
TARGET_STAGING_BUDGET_SCHEMA = "dcentos.s19k-target-staging-budget/v1"
TARGET_STAGING_ROOTFS_READBACK_MODE = "streaming_sha256_no_rootfs_copy"
TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES = 512 * 1024
TARGET_STAGING_WORKING_FREE_RESERVE_BYTES = 8 * 1024 * 1024
SOURCE_SNAPSHOT_SCHEMA = "dcentos.s19k-source-snapshot/v1"
SIGNING_PREPARATION_SCHEMA = "dcentos.s19k-signing-preparation/v1"
SIGNING_AUTHORIZATION_SCHEMA = "dcentos.s19k-signing-authorization/v1"
SIGNING_CEREMONY_SCHEMA = "dcentos.s19k-signing-ceremony/v2"

CUSTODY_MEMBER_BY_ROLE = {
    "safeoff_dcentrald": "transition/safeoff/dcentrald",
    "safeoff_runner": "transition/safeoff/run_trial",
    "safeoff_custody_observer": "transition/safeoff/supervisor_custody_observer",
    "stock_restart_helper": "transition/safeoff/stock_restart_helper",
    "safeoff_config": "transition/safeoff/dcentrald_s19k.toml",
}

# Mapping: implementation_id -> exact five-member capsule identities sorted
# by member path.  Deliberately empty until the fresh ARMv7 owner build and
# its four companion assets are reviewed as one live-proven bundle.
APPROVED_PRODUCTION_INSTALL_CUSTODY: dict[
    str, tuple[tuple[str, str, int], ...]
] = {}


def approved_install_custody(
    implementation_id: str,
    observed_members: tuple[tuple[str, str, int], ...],
) -> tuple[tuple[str, str, int], ...] | None:
    """Return the exact reviewed custody bundle, otherwise ``None``."""

    approved = APPROVED_PRODUCTION_INSTALL_CUSTODY.get(implementation_id)
    if approved is None or approved != observed_members:
        return None
    return approved


@dataclass(frozen=True)
class Stage1Approval:
    """Reviewed production stage-1 identity.

    ``audit_receipt_path`` is workspace-relative and its exact digest is
    recorded separately.  Keeping both prevents an unreviewed script or a
    rewritten review record from entering a production capsule by name alone.
    """

    implementation_id: str
    audit_receipt_path: str
    audit_receipt_sha256: str


# Intentionally empty on 2026-08-29.  Do not populate this with a test fixture
# or with the host-side SSH writer.  The reviewed change that adds the real
# target-side stage1 must add its exact script SHA-256 here.
APPROVED_PRODUCTION_STAGE1: dict[str, Stage1Approval] = {}


@dataclass(frozen=True)
class Stage1AuthorizerApproval:
    """Reviewed live-target detached-signature verifier identity."""

    implementation_id: str
    source_snapshot_commit: str
    audit_receipt_path: str
    audit_receipt_sha256: str
    target_kat_verified: bool


# Intentionally empty. The 467,976-byte desk binary observed on 2026-08-29
# came from a dirty, unsigned source checkout and has no target KAT. Its hash
# must not be admitted merely because host-side known-answer tests pass.
APPROVED_PRODUCTION_STAGE1_AUTHORIZERS: dict[
    str, Stage1AuthorizerApproval
] = {}


def approved_stage1(
    sha256: str,
    workspace_root: Path,
) -> Stage1Approval | None:
    """Return a still-hash-valid approval, otherwise ``None``."""

    approval = APPROVED_PRODUCTION_STAGE1.get(sha256.lower())
    if approval is None:
        return None
    receipt = workspace_root / approval.audit_receipt_path
    if not receipt.is_file() or receipt.is_symlink():
        return None
    import hashlib

    if hashlib.sha256(receipt.read_bytes()).hexdigest() != approval.audit_receipt_sha256:
        return None
    return approval


def approved_stage1_authorizer(
    sha256: str,
    workspace_root: Path,
    source_snapshot_commit: str,
) -> Stage1AuthorizerApproval | None:
    """Return an exact source/KAT/audit-bound target verifier approval."""

    approval = APPROVED_PRODUCTION_STAGE1_AUTHORIZERS.get(sha256.lower())
    if (
        approval is None
        or approval.target_kat_verified is not True
        or approval.source_snapshot_commit != source_snapshot_commit
    ):
        return None
    receipt = workspace_root / approval.audit_receipt_path
    if not receipt.is_file() or receipt.is_symlink():
        return None
    import hashlib

    if hashlib.sha256(receipt.read_bytes()).hexdigest() != approval.audit_receipt_sha256:
        return None
    return approval
