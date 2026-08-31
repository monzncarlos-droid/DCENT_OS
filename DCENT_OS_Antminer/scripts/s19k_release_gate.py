#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""S19k Pro release gate — fail-closed composition check (release wave 2026-08-29).

This gate COMPOSES the existing verifiers; it duplicates none of them:

* capsule signature/trust is delegated to the toolbox inspector
  ``inspect_s19k_aml_capsule`` (signature FIRST against the pinned
  D-Central release key; self-certifying keys rejected);
* geometry authority stays with the toolbox pins
  ``s19k_aml_geometry_pins()`` (themselves pinned to the dcentos Rust
  contracts by the toolbox convergence test) — this gate only re-states the
  coherent Rust/Toolbox ``CLEAR_FOR_FLASH`` values and pinned rootfs-window
  offsets; the separate production check requires both interlocks true;
* the evidence-node hashes re-hash the retained attempt-10 files.

Artifact-accounting checks (use ``--artifact-only`` only for a candidate
seal; its success sentinel is explicitly NOT production GO):

  capsule_signature_pinned_anchor
      PASS only when the capsule inspects ``capsule_ready`` AND the
      effective release pubkey (env override honored, placeholder refused)
      equals the expected anchor (default: the XIL-beta release key that
      also pinned the public-beta artifacts).
  manifest_geometry_vs_rust_contracts
      PASS only when ``s19k_am3_install.rs`` and the Toolbox mirror agree on
      the interlock value and the pinned rootfs-window offsets remain present.
  support_matrix_row_currency
      PASS only when the S19kPro row exists and no stale marker contradicts
      the retained attempt-10 evidence (2-of-2 UART bounded-work proof).
  evidence_node_hash_presence
      PASS only when every pinned attempt-10 evidence file exists and
      re-hashes to its ledger value.

Production-readiness additionally requires an exact v4 persistent-image
attestation embedded in the capsule, an authenticated signed source snapshot,
separate pre-signing authorization and post-signing completion receipts, the
reviewed stage1 registry, both CLEAR_FOR_FLASH pins, exact externally pinned
Toolbox executor/CLI sources, and terminal completion from the evidence-derived
campaign controller. A structurally valid or dev-signed fixture can never
satisfy those checks.

Exit codes: 0 = every check in the selected scope passed; 1 = at least one check failed;
2 = invocation error (missing input, bad ledger, unusable environment).
The gate never contacts a miner, never mutates artifacts, and never
grants install/flash authority. It is evidence accounting, not authority.

Usage:
  python3 s19k_release_gate.py [--capsule DCENT_FIRSTINSTALL_AM3_S19kPro_vX.Y.Z.tar.gz]
      [--expected-pubkey 64hex] [--workspace-root DIR] [--support-matrix FILE]
      [--evidence-node DIR] [--evidence-pins FILE.json]
      [--observed-target-tmp-free-bytes N] [--target-identity-profile PROFILE]
      [--json-report FILE] [--emit-ledger FILE] [--list-checks]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import s19k_persistent_image_verify as persistent_image
import s19k_release_policy as release_policy
import s19k_signing_ceremony as signing_ceremony

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"

#: The release trust anchor in force (beta public-release Ed25519 key; the
#: same key that signed the XIL public-beta artifacts and is baked into the
#: toolbox pin ``install_package.DEFAULT_RELEASE_PUBKEY_HEX``).
DEFAULT_EXPECTED_PUBKEY_HEX = (
    "26985575eae77d56c490ceeb9054af012eab5ae59119cd20eaa70dd7e722df83"
)

#: SEC-PIN-1 placeholder (public RFC/test-vector key) — must never occupy
#: the trust slot via pin or env override (dcent audit self SELF-001).
PLACEHOLDER_PUBKEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

#: Stale SUPPORT_MATRIX claims superseded by the retained attempt-10
#: evidence node (bounded-work proof credited BOTH UARTs 2026-08-29).
STALE_S19KPRO_MARKERS = (
    "ttyS2 work-phase RX is the last open mining defect",
)

DEFAULT_EVIDENCE_NODE_REL = (
    "artifacts/s19k-office-gauntlet/attempt10-bounded-work-proof-20260829"
    "/trial-extract/dcentrald_bench_t1_20260829144101_38851"
)

#: Retained attempt-10 evidence pins (verified on disk 2026-08-29; bound by
#: SESSION_LOG_20260829.md and the node README).
DEFAULT_EVIDENCE_PINS = {
    ".startup_daemon_transcript.3477.70111":
        "cf128c776264003e23b3b7e14a858e0b393c3b02b1aced75462c0d40f8815a77",
    "runtime_active":
        "95dbfa9af7358baa02b25e6394bc192d6f7da4ef90db92526b3ffb8ce2b87a91",
    "runtime_safeoff_terminal_receipt":
        "b3c8075a63a229d942bf78dc78e7eeaac7060c77acea56885313205b94aa3f12",
}

RUST_CONTRACT_RELS = (
    "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/s19k_am3_install.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/s19k_nand_env.rs",
)

PRODUCTION_LEDGER_POLICY_SOURCE_RELS = (
    "DCENT_OS_Antminer/scripts/s19k_release_gate.py",
    "DCENT_OS_Antminer/scripts/s19k_release_policy.py",
    "DCENT_OS_Antminer/scripts/s19k_signing_ceremony.py",
    "DCENT_OS_Antminer/scripts/s19k_persistent_image_verify.py",
    "DCENT_OS_Antminer/scripts/build_s19k_aml_transition_capsule.py",
    "DCENT_OS_Antminer/scripts/release_capsule_target_policy.py",
    "DCENT_OS_Antminer/scripts/s19k_gauntlet_workflow.py",
    "DCENT_OS_Antminer/",
    "DCENT_OS_Antminer/",
    "DCENT_OS_Antminer/dcentrald/Cargo.toml",
    "DCENT_OS_Antminer/dcentrald/Cargo.lock",
    "DCENT_OS_Antminer/dcentrald/s19k-stage1-authorizer/Cargo.toml",
    "DCENT_OS_Antminer/dcentrald/s19k-stage1-authorizer/src/main.rs",
    "projects/dcent-toolbox/src/dcent_toolbox/core/s19k_aml_first_install.py",
    "projects/dcent-toolbox/src/dcent_toolbox/core/install_package.py",
)

LEDGER_SCHEMA = "dcentos.s19k-release-ledger/v2"

ARTIFACT_CHECK_IDS = (
    "capsule_signature_pinned_anchor",
    "manifest_geometry_vs_rust_contracts",
    "support_matrix_row_currency",
    "evidence_node_hash_presence",
)

PRODUCTION_CHECK_IDS = (
    "production_capsule_image_and_stage1_binding",
    "signing_ceremony_receipt",
    "flash_authority_and_executor",
    "campaign_terminal_completion",
)

CHECK_IDS = ARTIFACT_CHECK_IDS + PRODUCTION_CHECK_IDS


@dataclass(frozen=True)
class GateResult:
    check_id: str
    status: str  # "pass" | "fail"
    reason: str

    @property
    def passed(self) -> bool:
        return self.status == "pass"


def _fail(check_id: str, reason: str) -> GateResult:
    return GateResult(check_id=check_id, status="fail", reason=reason)


def _pass(check_id: str, reason: str) -> GateResult:
    return GateResult(check_id=check_id, status="pass", reason=reason)


def _import_toolbox():
    """Import the toolbox modules this gate composes (path-injected)."""

    if str(TOOLBOX_SOURCE) not in sys.path:
        sys.path.insert(0, str(TOOLBOX_SOURCE))
    from dcent_toolbox.core import s19k_aml_first_install as sfi

    return sfi


# --- effective release pubkey (env override honored, placeholder refused) ----


def resolve_effective_pubkey_hex() -> tuple[str, str | None]:
    """Resolve the effective release pubkey hex (env override > baked pin).

    Mirrors the documented resolution order in
    ``dcent_toolbox.core.install_package`` (DCENT_RELEASE_PUBKEY_HEX, then
    DCENT_RELEASE_PUBKEY_FILE, then the baked-in pin). Returns
    ``(hex, problem)``; exactly one is empty.
    """

    env_hex = (os.environ.get("DCENT_RELEASE_PUBKEY_HEX") or "").strip()
    env_file = (os.environ.get("DCENT_RELEASE_PUBKEY_FILE") or "").strip()
    if env_hex:
        candidate = env_hex.replace(" ", "").replace("\n", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", candidate):
            return "", "DCENT_RELEASE_PUBKEY_HEX is not 64 hex chars"
        return candidate, None
    if env_file:
        path = Path(env_file)
        if not path.is_file():
            return "", f"DCENT_RELEASE_PUBKEY_FILE not found: {env_file}"
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if re.fullmatch(r"[0-9a-fA-F]{64}", text.replace(" ", "")):
            return text.replace(" ", "").lower(), None
        if "BEGIN PUBLIC KEY" in text:
            try:
                from cryptography.hazmat.primitives import serialization

                key = serialization.load_pem_public_key(text.encode())
                raw = key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                return raw.hex(), None
            except Exception as exc:  # noqa: BLE001 - typed below
                return "", f"DCENT_RELEASE_PUBKEY_FILE PEM unusable: {exc}"
        return "", "DCENT_RELEASE_PUBKEY_FILE is neither 64-hex nor PEM"
    from dcent_toolbox.core.install_package import (
        get_pinned_release_pubkey_hex,
    )

    pinned = get_pinned_release_pubkey_hex()
    if not pinned:
        return "", "no env override and the baked-in pin is empty"
    return pinned, None


# --- check 1: capsule signature against the pinned anchor ---------------------


def check_capsule(
    capsule: Path | None,
    expected_hex: str,
    *,
    allow_test_fixture: bool = False,
) -> GateResult:
    if capsule is None:
        return _fail(
            "capsule_signature_pinned_anchor",
            "capsule_missing: no --capsule given; the release cannot be "
            "gated without the exact artifact it ships",
        )
    sfi = _import_toolbox()
    report = sfi.inspect_s19k_aml_capsule(capsule)
    accepted_verdicts = {"capsule_ready"}
    if allow_test_fixture:
        accepted_verdicts.add("capsule_test_fixture")
    if report.verdict not in accepted_verdicts:
        failures = "; ".join(report.failures) or "no failure detail"
        return _fail(
            "capsule_signature_pinned_anchor",
            f"{report.verdict}: {failures}",
        )
    effective, problem = resolve_effective_pubkey_hex()
    if problem:
        return _fail(
            "capsule_signature_pinned_anchor",
            f"release_pubkey_unresolvable: {problem}",
        )
    if effective == PLACEHOLDER_PUBKEY_HEX:
        return _fail(
            "capsule_signature_pinned_anchor",
            "placeholder_in_trust_slot: the SEC-PIN-1 placeholder key must "
            "never occupy the release trust slot (SELF-001)",
        )
    if effective != expected_hex.strip().lower():
        return _fail(
            "capsule_signature_pinned_anchor",
            "anchor_mismatch: effective release pubkey "
            f"{effective} != expected anchor {expected_hex.strip().lower()}",
        )
    return _pass(
        "capsule_signature_pinned_anchor",
        f"{report.verdict} signature/accounting only (sha256 {report.capsule_sha256}, "
        f"{report.capsule_bytes} B) verified against anchor {effective}",
    )


# --- check 2: geometry vs the Rust contracts ----------------------------------


def check_geometry(dcentos_root: Path) -> GateResult:
    rust_texts: dict[str, str] = {}
    for rel in RUST_CONTRACT_RELS:
        path = dcentos_root / rel
        if not path.is_file():
            return _fail(
                "manifest_geometry_vs_rust_contracts",
                f"contract_file_missing: {path}",
            )
        rust_texts[rel] = path.read_text(encoding="utf-8", errors="replace")

    install_rs = rust_texts[RUST_CONTRACT_RELS[0]]
    match = re.search(r"CLEAR_FOR_FLASH\s*:\s*bool\s*=\s*(true|false)", install_rs)
    if match is None:
        return _fail(
            "manifest_geometry_vs_rust_contracts",
            "clear_for_flash_unreadable: CLEAR_FOR_FLASH pin not found in "
            f"{RUST_CONTRACT_RELS[0]}",
        )
    sfi = _import_toolbox()
    rust_clear = match.group(1) == "true"
    if bool(sfi.CLEAR_FOR_FLASH) != rust_clear:
        return _fail(
            "manifest_geometry_vs_rust_contracts",
            "clear_for_flash_mismatch: Rust and Toolbox authority pins do "
            "not agree; a dual-flip review has not landed coherently",
        )

    pins = sfi.s19k_aml_geometry_pins()
    combined = "\n".join(rust_texts.values()).lower()
    for key in ("rootfs_local_offset_hex", "rootfs_window_hex"):
        value = str(pins[key]).lower()
        if value not in combined:
            return _fail(
                "manifest_geometry_vs_rust_contracts",
                f"geometry_pin_absent_from_rust: {key}={value} not found in "
                "the dcentos contract text",
            )
    return _pass(
        "manifest_geometry_vs_rust_contracts",
        f"CLEAR_FOR_FLASH={str(rust_clear).lower()} in both Rust and Toolbox; rootfs "
        f"window {pins['rootfs_local_offset_hex']}+{pins['rootfs_window_hex']} "
        "present in the Rust contracts",
    )


# --- check 3: SUPPORT_MATRIX row currency -------------------------------------


def check_support_matrix(matrix_path: Path) -> GateResult:
    if not matrix_path.is_file():
        return _fail(
            "support_matrix_row_currency",
            f"support_matrix_missing: {matrix_path}",
        )
    text = matrix_path.read_text(encoding="utf-8", errors="replace")
    if "S19kPro" not in text:
        return _fail(
            "support_matrix_row_currency",
            "s19kpro_row_missing: no S19kPro row in the support matrix",
        )
    for marker in STALE_S19KPRO_MARKERS:
        if marker in text:
            return _fail(
                "support_matrix_row_currency",
                f"stale_row_claim: row still claims \"{marker}\" — "
                "superseded by attempt 10 (bounded-work proof credited BOTH "
                "UARTs; SESSION_LOG_20260829.md)",
            )
    return _pass(
        "support_matrix_row_currency",
        "S19kPro row present with no stale markers",
    )


# --- check 4: evidence-node hash presence --------------------------------------


def check_evidence(node: Path, pins: dict[str, str]) -> GateResult:
    if not node.is_dir():
        return _fail(
            "evidence_node_hash_presence",
            f"evidence_node_missing: {node}",
        )
    for name, expected in sorted(pins.items()):
        member = node / name
        if not member.is_file():
            return _fail(
                "evidence_node_hash_presence",
                f"evidence_file_missing: {member}",
            )
        actual = hashlib.sha256(member.read_bytes()).hexdigest()
        if actual != expected.strip().lower():
            return _fail(
                "evidence_node_hash_presence",
                f"evidence_hash_mismatch: {name} is {actual}, ledger pins "
                f"{expected.strip().lower()}",
            )
    return _pass(
        "evidence_node_hash_presence",
        f"{len(pins)} pinned attempt-10 evidence files re-hashed exactly",
    )


# --- production-only checks ----------------------------------------------------


def _capsule_manifest_and_files(
    capsule: Path | None,
) -> tuple[dict[str, object], dict[str, bytes]]:
    if capsule is None or capsule.is_symlink() or not capsule.is_file():
        raise ValueError("production capsule is missing or unsafe")
    sfi = _import_toolbox()
    files, _sha256, _size = sfi._read_capsule_members(capsule)  # noqa: SLF001
    raw = files.get(sfi.MANIFEST_MEMBER)
    if not files or raw is None:
        raise ValueError("production capsule is not safely readable")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("production capsule manifest is not an object")
    return value, files


def _source_snapshot_problem(
    snapshot: object, workspace_root: Path
) -> str | None:
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema",
        "commit",
        "tree",
        "commit_signature_verified",
        "clean_worktree_verified",
    }:
        return "source_snapshot_missing_or_malformed"
    if snapshot.get("schema") != release_policy.SOURCE_SNAPSHOT_SCHEMA:
        return "source_snapshot_schema_mismatch"
    commit = str(snapshot.get("commit") or "")
    tree = str(snapshot.get("tree") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        return "source_snapshot_commit_or_tree_invalid"
    if snapshot.get("commit_signature_verified") is not True or snapshot.get(
        "clean_worktree_verified"
    ) is not True:
        return "source_snapshot_builder_assertions_not_true"
    verify = subprocess.run(
        ["git", "verify-commit", commit],
        cwd=workspace_root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if verify.returncode != 0:
        return "source_snapshot_commit_signature_not_trusted"
    observed = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=workspace_root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if observed.returncode != 0 or observed.stdout.strip().lower() != tree:
        return "source_snapshot_tree_identity_mismatch"
    return None


def check_production_capsule_binding(
    capsule: Path | None,
    evidence_dir: Path | None,
    expected_pubkey_hex: str,
    expected_release_key_sha256: str | None = None,
    workspace_root: Path = WORKSPACE_ROOT,
    observed_target_tmp_free_bytes: int | None = None,
    target_identity_profile: str | None = None,
) -> GateResult:
    check_id = "production_capsule_image_and_stage1_binding"
    if evidence_dir is None:
        return _fail(
            check_id,
            "persistent_image_evidence_missing: production readiness requires "
            "the complete evidence directory, not a receipt-shaped assertion",
        )
    try:
        manifest, files = _capsule_manifest_and_files(capsule)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _fail(check_id, f"production_capsule_unreadable: {exc}")
    if manifest.get("artifact_class") != release_policy.ARTIFACT_CLASS_PRODUCTION:
        return _fail(
            check_id,
            "artifact_class_not_production: test fixtures and unclassified "
            "capsules never satisfy production readiness",
        )
    if not expected_release_key_sha256 or not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_release_key_sha256
    ):
        return _fail(
            check_id,
            "expected_release_key_sha256_missing: production verification "
            "requires an explicit non-ambient public-key file digest pin",
        )
    identity = manifest.get("signing_identity")
    if not isinstance(identity, dict):
        return _fail(check_id, "signing_identity_missing")
    if identity.get("profile") != release_policy.SIGNING_PROFILE_PRODUCTION:
        return _fail(check_id, "signing_profile_not_production_release")
    if identity.get("public_key_hex") != expected_pubkey_hex.lower():
        return _fail(check_id, "signed_manifest_release_identity_mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("key_id") or "")):
        return _fail(check_id, "signed_manifest_key_id_missing")
    source_problem = _source_snapshot_problem(
        manifest.get("source_snapshot"), workspace_root
    )
    if source_problem:
        return _fail(check_id, source_problem)

    try:
        verified = persistent_image.verify_evidence(
            evidence_dir,
            expected_release_key_sha256=expected_release_key_sha256.lower(),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        return _fail(check_id, f"persistent_image_verifier_refused: {exc}")
    canonical = persistent_image.canonical_json(verified)
    if set(verified) != release_policy.PERSISTENT_IMAGE_RECEIPT_KEYS:
        return _fail(check_id, "persistent_image_v4_key_set_mismatch")
    embedded = files.get(release_policy.PERSISTENT_IMAGE_MEMBER)
    if embedded != canonical:
        return _fail(
            check_id,
            "persistent_image_receipt_mismatch: capsule does not embed the "
            "exact canonical v4 verifier result",
        )
    if verified.get("schema") != release_policy.PERSISTENT_IMAGE_SCHEMA:
        return _fail(check_id, "persistent_image_schema_mismatch")
    if verified.get("release_key_id") != identity.get("key_id"):
        return _fail(check_id, "persistent_image_release_key_id_mismatch")
    required_true = (
        "installable",
        "a_b_unsigned_equality_verified",
        "private_key_excluded_from_builds",
        "post_ab_derivation_and_runtime_metadata_verified",
        "reproducible_builds_verified",
        "signed_manifest_verified",
        "native_owner_artifact_bound",
        "stock_recovery_receipt_bound",
        "native_owner_source_artifact_build_binding_verified",
    )
    if verified.get("classification") != "verified" or any(
        verified.get(name) is not True for name in required_true
    ):
        return _fail(check_id, "persistent_image_required_bindings_not_verified")
    snapshot = manifest.get("source_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("commit") != verified.get(
        "source_commit"
    ):
        return _fail(check_id, "persistent_image_source_snapshot_commit_mismatch")
    for name in (
        "install_authority_granted",
        "mutation_authority_granted",
        "nand_write_authorized",
        "live_hardware_contacted",
        "network_used",
    ):
        if verified.get(name) is not False:
            return _fail(check_id, f"persistent_image_forbidden_flag_not_false: {name}")
    if verified.get("isolated_post_ab_signing_verified") is not False:
        return _fail(
            check_id,
            "persistent_image_signing_isolation_claim_must_remain_false",
        )
    if (
        verified.get("isolated_post_ab_signing_nonclaim")
        != release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
    ):
        return _fail(check_id, "persistent_image_signing_isolation_nonclaim_mismatch")

    attestation = manifest.get("production_image_attestation")
    image_member = "payload/dcent-rootfs.img"
    image = files.get(image_member)
    if not isinstance(attestation, dict) or image is None:
        return _fail(check_id, "production_image_attestation_or_rootfs_missing")
    expected_attestation = {
        "member": release_policy.PERSISTENT_IMAGE_MEMBER,
        "verification_id": verified.get("verification_id"),
        "image_member": image_member,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_bytes": len(image),
        "release_key_sha256": verified.get("release_key_sha256"),
        "release_manifest_public_key_hex": expected_pubkey_hex.lower(),
    }
    if attestation != expected_attestation:
        return _fail(check_id, "production_image_manifest_binding_mismatch")
    if (
        verified.get("image_sha256") != expected_attestation["image_sha256"]
        or verified.get("image_bytes") != expected_attestation["image_bytes"]
        or verified.get("release_manifest_public_key_hex")
        != expected_pubkey_hex.lower()
    ):
        return _fail(check_id, "persistent_image_exact_bytes_or_release_key_mismatch")

    stage = manifest.get("transition_stage1")
    stage_bytes = files.get("transition/stage1.sh")
    if not isinstance(stage, dict) or stage_bytes is None:
        return _fail(check_id, "transition_stage1_binding_or_member_missing")
    stage_sha = hashlib.sha256(stage_bytes).hexdigest()
    approval = release_policy.approved_stage1(stage_sha, workspace_root)
    if approval is None:
        return _fail(
            check_id,
            "transition_stage1_unapproved: no reviewed target-side writer "
            "approval binds these exact bytes",
        )
    expected_stage = {
        "schema": release_policy.STAGE1_SCHEMA,
        "member": "transition/stage1.sh",
        "sha256": stage_sha,
        "bytes": len(stage_bytes),
        "implementation_id": approval.implementation_id,
        "audit_receipt_sha256": approval.audit_receipt_sha256,
    }
    if stage != expected_stage:
        return _fail(check_id, "transition_stage1_manifest_binding_mismatch")
    authorizer = manifest.get("transition_stage1_authorizer")
    authorizer_bytes = files.get("transition/s19k-stage1-authorizer")
    if not isinstance(authorizer, dict) or authorizer_bytes is None:
        return _fail(check_id, "transition_stage1_authorizer_binding_or_member_missing")
    authorizer_sha = hashlib.sha256(authorizer_bytes).hexdigest()
    snapshot = manifest.get("source_snapshot")
    source_commit = (
        str(snapshot.get("commit") or "") if isinstance(snapshot, dict) else ""
    )
    authorizer_approval = release_policy.approved_stage1_authorizer(
        authorizer_sha,
        workspace_root,
        source_commit,
    )
    if authorizer_approval is None:
        return _fail(
            check_id,
            "transition_stage1_authorizer_unapproved: exact ARMv7 member lacks "
            "a source-bound target KAT approval",
        )
    expected_authorizer = {
        "schema": release_policy.STAGE1_AUTHORIZER_SCHEMA,
        "member": "transition/s19k-stage1-authorizer",
        "sha256": authorizer_sha,
        "bytes": len(authorizer_bytes),
        "implementation_id": authorizer_approval.implementation_id,
        "target_kat_verified": True,
        "source_snapshot_commit": authorizer_approval.source_snapshot_commit,
    }
    if authorizer != expected_authorizer:
        return _fail(check_id, "transition_stage1_authorizer_manifest_binding_mismatch")

    custody = manifest.get("install_custody")
    expected_custody_keys = {
        "schema",
        "implementation_id",
        "protocol",
        "mode",
        "daemon_flag",
        "physical_safeoff_contract",
        "reset_contract",
        "transcript_schema",
        "terminal_receipt_schema",
        "safeoff_receipt_schema",
        "pending_receipt_schema",
        "target_reference_config_path",
        "staged_config_basename",
        "source_layouts",
        "target_identity_profiles",
        *release_policy.CUSTODY_MEMBER_BY_ROLE,
    }
    if not isinstance(custody, dict) or set(custody) != expected_custody_keys:
        return _fail(check_id, "install_custody_missing_or_key_set_not_exact")
    if (
        custody.get("schema") != release_policy.INSTALL_CUSTODY_SCHEMA
        or custody.get("implementation_id")
        != release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID
        or custody.get("protocol") != release_policy.INSTALL_CUSTODY_PROTOCOL
        or custody.get("mode") != release_policy.INSTALL_CUSTODY_MODE
        or custody.get("daemon_flag") != release_policy.INSTALL_CUSTODY_DAEMON_FLAG
        or custody.get("physical_safeoff_contract")
        != release_policy.INSTALL_CUSTODY_PHYSICAL_SAFEOFF_CONTRACT
        or custody.get("reset_contract")
        != release_policy.INSTALL_CUSTODY_RESET_CONTRACT
        or custody.get("transcript_schema")
        != release_policy.INSTALL_CUSTODY_TRANSCRIPT_SCHEMA
        or custody.get("terminal_receipt_schema")
        != release_policy.INSTALL_CUSTODY_TERMINAL_RECEIPT_SCHEMA
        or custody.get("safeoff_receipt_schema")
        != release_policy.INSTALL_CUSTODY_SAFEOFF_RECEIPT_SCHEMA
        or custody.get("pending_receipt_schema")
        != release_policy.INSTALL_CUSTODY_PENDING_RECEIPT_SCHEMA
        or custody.get("target_reference_config_path")
        != release_policy.INSTALL_CUSTODY_TARGET_REFERENCE_CONFIG_PATH
        or custody.get("staged_config_basename")
        != release_policy.INSTALL_CUSTODY_STAGED_CONFIG_BASENAME
        or custody.get("source_layouts")
        != list(release_policy.INSTALL_CUSTODY_SOURCE_LAYOUTS)
        or custody.get("target_identity_profiles")
        != list(release_policy.INSTALL_CUSTODY_TARGET_IDENTITY_PROFILES)
    ):
        return _fail(check_id, "install_custody_scope_or_protocol_mismatch")
    accepted_sources = manifest.get("accepted_source_layouts")
    if (
        not isinstance(accepted_sources, list)
        or not accepted_sources
        or not set(accepted_sources).issubset(
            set(release_policy.INSTALL_CUSTODY_SOURCE_LAYOUTS)
        )
    ):
        return _fail(
            check_id,
            "install_custody_source_scope_mismatch: LuxOS has no reviewed "
            "owner/stop/restart protocol",
        )
    if target_identity_profile not in release_policy.INSTALL_CUSTODY_TARGET_IDENTITY_PROFILES:
        return _fail(
            check_id,
            "install_custody_target_identity_profile_missing_or_unapproved",
        )

    expected_counted_names = {
        "payload/dcent-rootfs.img",
        "transition/stage1.sh",
        "transition/s19k-stage1-authorizer",
        *release_policy.CUSTODY_MEMBER_BY_ROLE.values(),
    }
    observed_custody_identities = []
    for role, member_name in release_policy.CUSTODY_MEMBER_BY_ROLE.items():
        member_bytes = files.get(member_name)
        if member_bytes is None:
            return _fail(check_id, f"install_custody_member_missing: {member_name}")
        descriptor = {
            "member": member_name,
            "sha256": hashlib.sha256(member_bytes).hexdigest(),
            "bytes": len(member_bytes),
        }
        if custody.get(role) != descriptor:
            return _fail(check_id, f"install_custody_descriptor_mismatch: {role}")
        observed_custody_identities.append(
            (member_name, descriptor["sha256"], descriptor["bytes"])
        )
    observed_custody_identities.sort(key=lambda item: item[0])
    if release_policy.approved_install_custody(
        str(custody.get("implementation_id") or ""),
        tuple(observed_custody_identities),
    ) is None:
        return _fail(
            check_id,
            "install_custody_bundle_unapproved_or_identity_drifted",
        )
    expected_counted_members = []
    for member_name in sorted(expected_counted_names):
        member_bytes = files.get(member_name)
        if member_bytes is None:
            return _fail(check_id, f"target_staging_counted_member_missing: {member_name}")
        expected_counted_members.append(
            {
                "member": member_name,
                "sha256": hashlib.sha256(member_bytes).hexdigest(),
                "bytes": len(member_bytes),
            }
        )
    coexisting_bytes = sum(
        int(descriptor["bytes"]) for descriptor in expected_counted_members
    )
    required_tmp_free_bytes = (
        coexisting_bytes
        + release_policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
        + release_policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
    )
    expected_staging = {
        "schema": release_policy.TARGET_STAGING_BUDGET_SCHEMA,
        "rootfs_readback_mode": (
            release_policy.TARGET_STAGING_ROOTFS_READBACK_MODE
        ),
        "counted_members": expected_counted_members,
        "coexisting_capsule_member_bytes": coexisting_bytes,
        "per_unit_inputs_budget_bytes": (
            release_policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
        ),
        "working_free_reserve_bytes": (
            release_policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
        ),
        "required_tmp_free_bytes": required_tmp_free_bytes,
    }
    if manifest.get("target_staging_budget") != expected_staging:
        return _fail(check_id, "target_staging_budget_manifest_binding_mismatch")
    if (
        not isinstance(observed_target_tmp_free_bytes, int)
        or isinstance(observed_target_tmp_free_bytes, bool)
        or observed_target_tmp_free_bytes < required_tmp_free_bytes
    ):
        observed = (
            "missing" if observed_target_tmp_free_bytes is None
            else str(observed_target_tmp_free_bytes)
        )
        return _fail(
            check_id,
            "target_tmp_capacity_insufficient_or_missing: "
            f"required={required_tmp_free_bytes} observed={observed}",
        )
    if verified.get("isolated_post_ab_signing_verified") is not True:
        return _fail(
            check_id,
            release_policy.PERSISTENT_IMAGE_PRODUCTION_SIGNER_BOUNDARY_REFUSAL,
        )
    return _pass(
        check_id,
        "production capsule embeds exact canonical persistent-image v4 "
        f"receipt {verified.get('verification_id')}, approved stage1 {stage_sha}, "
        f"target-KAT authorizer {authorizer_sha}, exact install custody, and "
        f"target /tmp capacity required={required_tmp_free_bytes} "
        f"observed={observed_target_tmp_free_bytes}; identity_profile="
        f"{target_identity_profile}",
    )


def check_signing_ceremony(
    capsule: Path | None,
    authorization_receipt: Path | None,
    completion_receipt: Path | None,
) -> GateResult:
    check_id = "signing_ceremony_receipt"
    if capsule is None or authorization_receipt is None or completion_receipt is None:
        return _fail(
            check_id,
            "ceremony_missing: exact capsule, pre-signing authorization, and "
            "post-signing completion receipts are required",
        )
    try:
        receipt = signing_ceremony.verify(
            authorization_receipt, completion_receipt, capsule
        )
    except (OSError, ValueError, signing_ceremony.CeremonyError) as exc:
        return _fail(check_id, f"ceremony_refused: {exc}")
    return _pass(
        check_id,
        "preauthorized-before-signing ceremony completed for exact capsule; "
        f"completion receipt {receipt['receipt_id']}",
    )


def check_flash_authority_and_executor(
    workspace_root: Path,
    expected_executor_sha256: str | None = None,
    expected_executor_cli_sha256: str | None = None,
    expected_safeoff_runner_sha256: str | None = None,
    expected_stock_restart_sha256: str | None = None,
    expected_postinstall_witness_sha256: str | None = None,
) -> GateResult:
    check_id = "flash_authority_and_executor"
    install_path = workspace_root / RUST_CONTRACT_RELS[0]
    if not install_path.is_file():
        return _fail(check_id, f"rust_flash_contract_missing: {install_path}")
    text = install_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"CLEAR_FOR_FLASH\s*:\s*bool\s*=\s*(true|false)", text)
    if match is None:
        return _fail(check_id, "rust_clear_for_flash_unreadable")
    sfi = _import_toolbox()
    try:
        from dcent_toolbox.core import s19k_aml_install_executor as executor

        executor_ready = getattr(executor, "PRODUCTION_EXECUTOR_IMPLEMENTED", False)
    except ImportError:
        executor_ready = False
    if match.group(1) != "true" or sfi.CLEAR_FOR_FLASH is not True:
        return _fail(
            check_id,
            "clear_for_flash_false: Rust and Toolbox master interlocks must "
            "both be true in one reviewed change before production GO",
        )
    if executor_ready is not True:
        return _fail(
            check_id,
            "toolbox_executor_not_production_implemented: run-dry/planning is not install",
        )
    contract = executor.production_executor_contract()
    if contract.get("schema") != "dcent-toolbox.s19k-aml-production-executor/v1" or (
        contract.get("implementation_id")
        != "dcent-toolbox-s19k-aml-executor-posix-ssh-v1"
    ):
        return _fail(check_id, "toolbox_executor_contract_identity_mismatch")
    if contract.get("authorizes_execution") is not False or contract.get(
        "dual_interlock_independent"
    ) is not True:
        return _fail(check_id, "toolbox_executor_contract_authority_or_interlock_invalid")
    if contract.get("online_release_private_key_loaded") is not False or contract.get(
        "offline_detached_stage1_authorization_required"
    ) is not True:
        return _fail(
            check_id,
            "stage1_authorization_custody_invalid: online execution must consume "
            "offline detached signatures and must never load the release private key",
        )
    rail_fields = (
        "safeoff_custody_transition_implemented",
        "pre_mutation_stock_restart_recovery_implemented",
        "scoped_postinstall_witness_implemented",
    )
    for field in rail_fields:
        if contract.get(field) is not True:
            return _fail(check_id, f"executor_live_rail_unimplemented: {field}")
    if contract.get("production_execution_ready") is not True:
        return _fail(check_id, "executor_contract_not_production_execution_ready")
    mutation_contract = contract.get("dcentos_mutation_contract")
    if not isinstance(mutation_contract, dict) or mutation_contract.get(
        "clear_for_flash"
    ) is not True:
        return _fail(check_id, "executor_compiled_dcentos_interlock_is_not_true")
    if mutation_contract.get("relative_source") != RUST_CONTRACT_RELS[0]:
        return _fail(check_id, "executor_compiled_dcentos_source_path_mismatch")
    if mutation_contract.get("source_sha256") != hashlib.sha256(
        install_path.read_bytes()
    ).hexdigest():
        return _fail(check_id, "executor_compiled_dcentos_source_identity_stale")

    expected_pins = {
        "executor": expected_executor_sha256,
        "executor_cli": expected_executor_cli_sha256,
    }
    for label, pin in expected_pins.items():
        if not pin or not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
            return _fail(
                check_id,
                f"{label}_sha256_pin_missing: exact reviewed source identity is required",
            )
    source_paths = {
        "executor": workspace_root / str(contract.get("executor_source") or ""),
        "executor_cli": workspace_root / str(contract.get("cli_source") or ""),
    }
    for label, path in source_paths.items():
        if path.is_symlink() or not path.is_file():
            return _fail(check_id, f"{label}_source_missing_or_unsafe: {path}")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != str(expected_pins[label]).lower():
            return _fail(
                check_id,
                f"{label}_source_identity_mismatch: {observed}",
            )
    live_source_pins = {
        "safeoff_runner": (
            contract.get("safeoff_runner_source"),
            expected_safeoff_runner_sha256,
        ),
        "stock_restart": (
            contract.get("stock_restart_source"),
            expected_stock_restart_sha256,
        ),
        "postinstall_witness": (
            contract.get("postinstall_witness_source"),
            expected_postinstall_witness_sha256,
        ),
    }
    for label, (relative, pin) in live_source_pins.items():
        if not isinstance(relative, str) or not relative or not pin or not re.fullmatch(
            r"[0-9a-fA-F]{64}", pin
        ):
            return _fail(
                check_id,
                f"{label}_source_or_sha256_pin_missing",
            )
        path = workspace_root / relative
        if path.is_symlink() or not path.is_file():
            return _fail(check_id, f"{label}_source_missing_or_unsafe: {path}")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != pin.lower():
            return _fail(check_id, f"{label}_source_identity_mismatch: {observed}")
    return _pass(
        check_id,
        "dual flash interlock true; compiled Rust identity current; exact "
        "executor and CLI source identities externally pinned",
    )


def check_campaign_terminal_completion(
    workspace_root: Path,
    manifest: Path,
    evidence_root: Path | None,
    artifact_root: Path | None,
) -> GateResult:
    check_id = "campaign_terminal_completion"
    controller = workspace_root / "DCENT_OS_Antminer/scripts/s19k_gauntlet_workflow.py"
    if not controller.is_file() or not manifest.is_file():
        return _fail(check_id, "campaign_controller_or_manifest_missing")
    command = [
        sys.executable,
        str(controller),
        "--manifest",
        str(manifest),
    ]
    if evidence_root is not None:
        command.extend(["--evidence-root", str(evidence_root)])
    if artifact_root is not None:
        command.extend(["--artifact-root", str(artifact_root)])
    command.append("status")
    run = subprocess.run(
        command,
        cwd=workspace_root,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = (run.stdout or "") + (run.stderr or "")
    if run.returncode != 0:
        return _fail(check_id, f"campaign_controller_failed: exit={run.returncode}")
    output_lines = [line.strip() for line in output.splitlines()]
    if "complete=true" not in output_lines:
        frontier = next(
            (line for line in output.splitlines() if line.startswith("frontier=")),
            "frontier=unknown",
        )
        return _fail(
            check_id,
            "campaign_incomplete: terminal live/persistent evidence is not "
            f"verified ({frontier})",
        )
    terminal = next(
        (
            line
            for line in output_lines
            if line.startswith("complete-dcentos-enablement:")
        ),
        "",
    )
    if not re.fullmatch(
        r"complete-dcentos-enablement:\s+verified(?:\s+.*)?", terminal
    ):
        return _fail(check_id, "campaign_terminal_phase_not_verified")
    return _pass(check_id, "campaign controller reports complete=true and terminal phase verified")


# --- ledger emission ------------------------------------------------------------


def emit_ledger(
    output: Path,
    capsule: Path | None,
    recorded_utc: str,
    git_head: str,
    extra_files: list[Path],
    *,
    scope: str,
    production_ready: bool,
    signer_pubkey_hex: str = DEFAULT_EXPECTED_PUBKEY_HEX,
) -> None:
    """Write a durable no-replace SHA256LEDGER.txt (ledger schema v2)."""

    rows: list[tuple[str, str, str, str]] = []
    candidates: list[tuple[str, Path]] = []
    if capsule is not None:
        candidates.append(("capsule", capsule))
        sig = capsule.with_name(capsule.name + ".sig")
        if sig.is_file():
            candidates.append(("capsule_sig", sig))
    for role, path in candidates:
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"ledger error: {role} file missing or unsafe: {path}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        rows.append((digest, str(len(data)), role, str(path)))
    for path in extra_files:
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"ledger error: artifact missing or unsafe: {path}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        rows.append((digest, str(len(data)), "artifact", str(path)))
    rows.sort(key=lambda row: row[3].lower())
    lines = [
        "# DCENT_OS S19k Pro release hash ledger",
        f"# schema: {LEDGER_SCHEMA}",
        "# campaign_id: s19k-pro-complete-enablement-20260823",
        f"# recorded_utc: {recorded_utc}",
        f"# git_head: {git_head}",
        f"# scope: {scope}",
        f"# production_ready: {str(production_ready).lower()}",
        "# authority: evidence-accounting-only; no install/flash authority",
        f"# signer_pubkey_hex: {signer_pubkey_hex.lower()}",
        "sha256  bytes  role  path",
    ]
    lines.extend(f"{d} {b} {r} {p}" for d, b, r, p in rows)
    data = ("\n".join(lines) + "\n").encode("utf-8")
    _durable_no_replace(output, data, "ledger")


def _durable_no_replace(path: Path, data: bytes, label: str) -> None:
    """Create, file-fsync, and where supported directory-fsync one exact file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o644,
        )
    except FileExistsError as exc:
        raise SystemExit(f"{label} error: no-replace violated: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    # POSIX durability requires syncing the parent directory entry as well.
    # Windows does not expose directory handles through os.open; fail only on
    # file create/fsync and treat directory fsync as unavailable there.
    try:
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        return


# --- driver ---------------------------------------------------------------------


def run_gate(args: argparse.Namespace) -> list[GateResult]:
    root = Path(
        getattr(args, "workspace_root", getattr(args, "dcentos_root", WORKSPACE_ROOT))
    ).resolve()
    results = [
        check_capsule(
            Path(args.capsule).resolve() if args.capsule else None,
            args.expected_pubkey,
            allow_test_fixture=args.artifact_only,
        ),
        check_geometry(root),
        check_support_matrix(Path(args.support_matrix).resolve()),
        check_evidence(
            Path(args.evidence_node).resolve(),
            json.loads(Path(args.evidence_pins).read_text(encoding="utf-8"))
            if args.evidence_pins
            else DEFAULT_EVIDENCE_PINS,
        ),
    ]
    if not args.artifact_only:
        results.extend(
            [
                check_production_capsule_binding(
                    Path(args.capsule).resolve() if args.capsule else None,
                    (
                        Path(args.persistent_image_evidence_dir).resolve()
                        if args.persistent_image_evidence_dir
                        else None
                    ),
                    args.expected_pubkey,
                    getattr(args, "expected_release_key_sha256", None),
                    root,
                    getattr(args, "observed_target_tmp_free_bytes", None),
                    getattr(args, "target_identity_profile", None),
                ),
                check_signing_ceremony(
                    Path(args.capsule).resolve() if args.capsule else None,
                    (
                        Path(args.signing_authorization_receipt).resolve()
                        if getattr(args, "signing_authorization_receipt", None)
                        else None
                    ),
                    (
                        Path(args.signing_completion_receipt).resolve()
                        if getattr(args, "signing_completion_receipt", None)
                        else None
                    ),
                ),
                check_flash_authority_and_executor(
                    root,
                    getattr(args, "expected_executor_sha256", None),
                    getattr(args, "expected_executor_cli_sha256", None),
                    getattr(args, "expected_safeoff_runner_sha256", None),
                    getattr(args, "expected_stock_restart_sha256", None),
                    getattr(args, "expected_postinstall_witness_sha256", None),
                ),
                check_campaign_terminal_completion(
                    root,
                    Path(args.campaign_manifest).resolve(),
                    (
                        Path(args.campaign_evidence_root).resolve()
                        if args.campaign_evidence_root
                        else None
                    ),
                    (
                        Path(args.campaign_artifact_root).resolve()
                        if args.campaign_artifact_root
                        else None
                    ),
                ),
            ]
        )
    all_passed = all(r.passed for r in results)
    report = {
        "schema": "dcentos.s19k-release-gate/v1",
        "scope": "artifact-only" if args.artifact_only else "production-readiness",
        "all_passed": all_passed,
        "production_ready": all_passed and not args.artifact_only,
        "authority_granted": False,
        "results": [asdict(r) for r in results],
    }
    if args.json_report:
        _durable_no_replace(
            Path(args.json_report).resolve(),
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            "JSON report",
        )
    for result in results:
        print(f"{result.check_id}: {result.status.upper()} — {result.reason}")
    if args.artifact_only:
        print(
            "ARTIFACT GATE: " + ("PASS" if all_passed else "FAIL")
            + " — NOT PRODUCTION GO; no install/flash authority"
        )
    else:
        print(
            "PRODUCTION RELEASE GATE: " + ("PASS" if all_passed else "FAIL")
            + " (evidence verdict only; operator authority remains separate)"
        )
    return results


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    result.add_argument("--capsule", help="transition capsule .tar.gz")
    result.add_argument(
        "--expected-pubkey",
        default=DEFAULT_EXPECTED_PUBKEY_HEX,
        help="64-hex release anchor the effective pubkey must equal",
    )
    result.add_argument(
        "--workspace-root",
        "--dcentos-root",
        dest="workspace_root",
        default=str(WORKSPACE_ROOT),
        help="workspace root (--dcentos-root is a retained compatibility alias)",
    )
    result.add_argument(
        "--support-matrix",
        default=str(WORKSPACE_ROOT / "SUPPORT_MATRIX.md"),
    )
    result.add_argument(
        "--evidence-node",
        default=str(WORKSPACE_ROOT / DEFAULT_EVIDENCE_NODE_REL),
    )
    result.add_argument(
        "--evidence-pins",
        help="JSON file mapping evidence filename -> pinned sha256",
    )
    result.add_argument("--json-report")
    result.add_argument("--emit-ledger")
    result.add_argument(
        "--artifact-only",
        action="store_true",
        help=(
            "run/seal candidate artifact-accounting checks only; success is "
            "explicitly NOT production GO"
        ),
    )
    result.add_argument("--persistent-image-evidence-dir")
    result.add_argument(
        "--expected-release-key-sha256",
        help=(
            "explicit SHA-256 of the trusted public-key file embedded in the "
            "persistent-image evidence; ambient environment values are ignored"
        ),
    )
    result.add_argument(
        "--observed-target-tmp-free-bytes",
        type=int,
        help=(
            "fresh strict df -Pk available capacity converted to exact bytes; "
            "must meet the signed target_staging_budget before upload"
        ),
    )
    result.add_argument(
        "--target-identity-profile",
        help=(
            "exact live custody identity profile; current capsule custody is "
            "scoped only to live88_two_bhb56903_slots_2_3"
        ),
    )
    result.add_argument("--signing-authorization-receipt")
    result.add_argument("--signing-completion-receipt")
    result.add_argument(
        "--expected-executor-sha256",
        help="external SHA-256 pin for the reviewed Toolbox S19k executor source",
    )
    result.add_argument(
        "--expected-executor-cli-sha256",
        help="external SHA-256 pin for the reviewed Toolbox S19k CLI source",
    )
    result.add_argument(
        "--expected-safeoff-runner-sha256",
        help="external SHA-256 pin for the reviewed SafeOff custody runner",
    )
    result.add_argument(
        "--expected-stock-restart-sha256",
        help="external SHA-256 pin for the pre-mutation stock-restart recovery rail",
    )
    result.add_argument(
        "--expected-postinstall-witness-sha256",
        help="external SHA-256 pin for the scoped post-install witness implementation",
    )
    result.add_argument(
        "--campaign-manifest",
        default=str(
            WORKSPACE_ROOT
            / ""
        ),
    )
    result.add_argument("--campaign-evidence-root")
    result.add_argument("--campaign-artifact-root")
    result.add_argument(
        "--ledger-artifact",
        action="append",
        default=[],
        help="extra file to bind into the emitted ledger (repeatable)",
    )
    result.add_argument("--recorded-utc", default="", help="ledger header UTC")
    result.add_argument("--git-head", default="", help="ledger header git head")
    result.add_argument(
        "--list-checks", action="store_true", help="print check ids and exit 0"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.list_checks:
        for check_id in CHECK_IDS:
            print(check_id)
        return 0
    try:
        results = run_gate(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed, typed
        print(f"RELEASE GATE: FAIL — gate_error: {exc}", file=sys.stderr)
        return 2
    if args.emit_ledger:
        if not all(r.passed for r in results):
            print(
                "RELEASE GATE: FAIL — ledger_refused: cannot emit a ledger "
                "while any check fails",
                file=sys.stderr,
            )
            return 1
        if not args.artifact_only and not args.json_report:
            print(
                "RELEASE GATE: FAIL — ledger_refused: production ledger requires "
                "--json-report so the exact eight-check terminal verdict is bound",
                file=sys.stderr,
            )
            return 2
        if not args.artifact_only and not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            args.recorded_utc,
        ):
            print(
                "RELEASE GATE: FAIL — ledger_refused: production ledger requires "
                "an explicit RFC3339-Z --recorded-utc",
                file=sys.stderr,
            )
            return 2
        ledger_artifacts = [Path(p).resolve() for p in args.ledger_artifact]
        ledger_git_head = args.git_head or "unrecorded"
        if args.signing_authorization_receipt:
            ledger_artifacts.append(
                Path(args.signing_authorization_receipt).resolve()
            )
        if args.signing_completion_receipt:
            ledger_artifacts.append(Path(args.signing_completion_receipt).resolve())
        if args.persistent_image_evidence_dir:
            ledger_artifacts.append(
                (
                    Path(args.persistent_image_evidence_dir)
                    / persistent_image.VERIFICATION_FILE
                ).resolve()
            )
        if not args.artifact_only:
            workspace_root = Path(args.workspace_root).resolve()
            manifest, files = _capsule_manifest_and_files(
                Path(args.capsule).resolve() if args.capsule else None
            )
            stage = manifest.get("transition_stage1")
            stage_bytes = files.get("transition/stage1.sh")
            if not isinstance(stage, dict) or stage_bytes is None:
                print(
                    "RELEASE GATE: FAIL — ledger_refused: stage1 binding disappeared",
                    file=sys.stderr,
                )
                return 2
            snapshot = manifest.get("source_snapshot")
            source_commit = (
                str(snapshot.get("commit") or "")
                if isinstance(snapshot, dict)
                else ""
            )
            if not re.fullmatch(r"[0-9a-f]{40}", source_commit) or (
                args.git_head and args.git_head.lower() != source_commit
            ):
                print(
                    "RELEASE GATE: FAIL — ledger_refused: --git-head must be "
                    "empty or equal the capsule's authenticated source commit",
                    file=sys.stderr,
                )
                return 2
            ledger_git_head = source_commit
            approval = release_policy.approved_stage1(
                hashlib.sha256(stage_bytes).hexdigest(), workspace_root
            )
            if approval is None:
                print(
                    "RELEASE GATE: FAIL — ledger_refused: stage1 approval disappeared",
                    file=sys.stderr,
                )
                return 2
            ledger_artifacts.append(
                (workspace_root / approval.audit_receipt_path).resolve()
            )
            authorizer = manifest.get("transition_stage1_authorizer")
            authorizer_bytes = files.get("transition/s19k-stage1-authorizer")
            authorizer_approval = (
                release_policy.approved_stage1_authorizer(
                    hashlib.sha256(authorizer_bytes).hexdigest(),
                    workspace_root,
                    source_commit,
                )
                if isinstance(authorizer, dict) and authorizer_bytes is not None
                else None
            )
            if authorizer_approval is None:
                print(
                    "RELEASE GATE: FAIL — ledger_refused: authorizer approval disappeared",
                    file=sys.stderr,
                )
                return 2
            ledger_artifacts.append(
                (workspace_root / authorizer_approval.audit_receipt_path).resolve()
            )
            ledger_artifacts.append(Path(args.campaign_manifest).resolve())
            ledger_artifacts.extend(
                (workspace_root / relative).resolve()
                for relative in PRODUCTION_LEDGER_POLICY_SOURCE_RELS
            )
            from dcent_toolbox.core import s19k_aml_install_executor as executor

            executor_contract = executor.production_executor_contract()
            ledger_artifacts.extend(
                [
                    (
                        workspace_root
                        / str(executor_contract["executor_source"])
                    ).resolve(),
                    (
                        workspace_root / str(executor_contract["cli_source"])
                    ).resolve(),
                ]
            )
            ledger_artifacts.extend(
                (
                    workspace_root
                    / str(executor_contract[field])
                ).resolve()
                for field in (
                    "safeoff_runner_source",
                    "stock_restart_source",
                    "postinstall_witness_source",
                )
            )
        if args.json_report:
            ledger_artifacts.append(Path(args.json_report).resolve())
        # Bind each exact file once even if the operator also supplied it as
        # --ledger-artifact.
        ledger_artifacts = list(dict.fromkeys(ledger_artifacts))
        emit_ledger(
            Path(args.emit_ledger).resolve(),
            Path(args.capsule).resolve() if args.capsule else None,
            args.recorded_utc or "unrecorded",
            ledger_git_head,
            ledger_artifacts,
            scope="artifact-only" if args.artifact_only else "production-readiness",
            production_ready=not args.artifact_only,
            signer_pubkey_hex=args.expected_pubkey,
        )
        print(f"ledger emitted: {args.emit_ledger}")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
