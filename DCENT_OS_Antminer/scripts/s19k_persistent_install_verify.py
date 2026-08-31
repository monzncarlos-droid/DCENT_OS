#!/usr/bin/env python3
"""Offline verifier for one explicitly authorized S19k persistent install."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import s19k_native_live_common as common
import s19k_release_policy as release_policy


SCHEMA = "dcentos.s19k-persistent-install-capture/v1"
RESULT_SCHEMA = "dcentos.s19k-persistent-install-verification/v2"
PHASE = "persistent-install"
FILES = (
    "recovery-verification.json",
    "image-verification.json",
    "mutation-authority.json",
    "install-transaction.json",
    "independent-witness.json",
)
EXTRA_KEYS = (
    "device_id",
    "recovery_verification_sha256",
    "image_verification_sha256",
)


def _load(payload: dict[str, bytes], name: str) -> dict[str, Any]:
    return common.validate_embedded_receipt(payload[name], name)


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    manifest_data, manifest, payload = common.verify_manifest(
        evidence_dir,
        schema=SCHEMA,
        phase=PHASE,
        payload_files=FILES,
        extra_keys=EXTRA_KEYS,
    )
    device_id = common.token(manifest["device_id"], "persistent device_id")
    recovery_sha = common.digest(manifest["recovery_verification_sha256"], "recovery verification")
    image_sha = common.digest(manifest["image_verification_sha256"], "image verification")
    if common.sha256(payload["recovery-verification.json"]) != recovery_sha:
        common.fail("persistent install recovery receipt is not manifest-bound")
    if common.sha256(payload["image-verification.json"]) != image_sha:
        common.fail("persistent install image receipt is not manifest-bound")
    recovery = _load(payload, "recovery-verification.json")
    image = _load(payload, "image-verification.json")
    authority = _load(payload, "mutation-authority.json")
    install = _load(payload, "install-transaction.json")
    witness = _load(payload, "independent-witness.json")
    if recovery.get("schema") != "dcentos.s19k-persistent-recovery-verification/v1":
        common.fail("persistent install has the wrong recovery-verification schema")
    if not all(recovery.get(key) is True for key in ("stock_restore_rehearsal_verified", "original_bytes_restored", "terminal_safeoff_verified")):
        common.fail("persistent install lacks a completed stock recovery rehearsal")
    if recovery.get("device_id") != device_id:
        common.fail("persistent recovery receipt targets a different device")
    common.exact_object(
        image,
        release_policy.PERSISTENT_IMAGE_RECEIPT_KEYS,
        "persistent image verification",
    )
    image_verification_id = common.digest(
        image.get("verification_id"), "persistent image verification_id"
    )
    image_body = dict(image)
    del image_body["verification_id"]
    if common.sha256(common.canonical_json(image_body)) != image_verification_id:
        common.fail("persistent image verification_id does not bind the exact receipt")
    if (
        image.get("schema") != release_policy.PERSISTENT_IMAGE_SCHEMA
        or image.get("classification") != "verified"
        or image.get("board") != "am3-s19k"
        or image.get("installable") is not True
        or image.get("a_b_unsigned_equality_verified") is not True
        or image.get("private_key_excluded_from_builds") is not True
        or image.get("post_ab_derivation_and_runtime_metadata_verified") is not True
        or image.get("isolated_post_ab_signing_verified") is not False
        or image.get("isolated_post_ab_signing_nonclaim")
        != release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
        or image.get("reproducible_builds_verified") is not True
        or image.get("signed_manifest_verified") is not True
        or image.get("native_owner_source_artifact_build_binding_verified") is not True
        or image.get("native_owner_clean_source_commit_bound") is not True
        or image.get("stock_recovery_receipt_bound") is not True
        or image.get("install_authority_granted") is not False
        or image.get("mutation_authority_granted") is not False
        or image.get("nand_write_authorized") is not False
        or image.get("live_hardware_contacted") is not False
        or image.get("network_used") is not False
    ):
        common.fail("persistent install lacks an installable image verification")
    for field_name in (
        "package_sha256",
        "unsigned_package_sha256",
        "release_key_sha256",
        "signed_manifest_sha256",
        "persistent_image_contract_sha256",
        "post_ab_signing_id",
        "post_ab_signing_receipt_sha256",
        "host_preflight_id",
        "host_preflight_receipt_sha256",
        "host_preflight_component_sha256",
        "isolated_signer_runtime_id",
        "isolated_signer_runtime_receipt_sha256",
        "isolated_signer_private_key_custody_id",
        "native_owner_verification_id",
        "native_owner_receipt_sha256",
        "native_owner_artifact_sha256",
        "native_owner_source_files_sha256",
        "stock_recovery_verification_id",
        "stock_recovery_receipt_sha256",
    ):
        common.digest(image.get(field_name), f"persistent image {field_name}")
    common.canonical_uint(
        image.get("unsigned_package_bytes"),
        "persistent unsigned image package bytes",
        positive=True,
    )
    recovery_verification_id = common.digest(
        recovery.get("verification_id"), "persistent recovery verification_id"
    )
    if (
        image.get("stock_recovery_verification_id") != recovery_verification_id
        or image.get("stock_recovery_receipt_sha256") != recovery_sha
        or image.get("stock_recovery_device_id") != device_id
    ):
        common.fail(
            "persistent image is bound to a different recovery receipt or device"
        )
    image_digest = common.digest(image.get("image_sha256"), "persistent image SHA-256")
    image_bytes = common.canonical_uint(image.get("image_bytes"), "persistent image bytes", positive=True)
    common.exact_object(
        authority,
        ("schema", "authority_id", "device_id", "scope", "image_sha256", "not_before_unix_s", "not_after_unix_s", "single_use", "operator", "recovery_verification_sha256", "install_authorized"),
        "persistent mutation authority",
    )
    if authority["schema"] != "dcentos.s19k-persistent-install-authority/v1" or authority["device_id"] != device_id:
        common.fail("persistent mutation authority targets the wrong schema/device")
    authority_id = common.token(authority["authority_id"], "persistent authority_id")
    operator = common.token(authority["operator"], "persistent operator")
    if authority["scope"] != "single-s19k-dcentos-image-install" or authority["single_use"] is not True or authority["install_authorized"] is not True:
        common.fail("persistent mutation authority is not exact, single-use, and affirmative")
    if authority["image_sha256"] != image_digest or authority["recovery_verification_sha256"] != recovery_sha:
        common.fail("persistent authority does not bind the admitted image/recovery route")
    not_before = common.canonical_uint(authority["not_before_unix_s"], "authority not-before", positive=True)
    not_after = common.canonical_uint(authority["not_after_unix_s"], "authority not-after", positive=True)
    if not_before >= not_after or not_after - not_before > 3_600:
        common.fail("persistent mutation authority is not narrowly time-bounded")
    common.exact_object(
        install,
        ("schema", "session_id", "device_id", "authority_id", "image_sha256", "image_bytes", "started_unix_s", "completed_unix_s", "write_count", "readback_sha256", "readback_bytes", "bad_block_count", "safeoff_before", "safeoff_after", "stock_recovery_held", "authority_consumed", "outcome"),
        "persistent install transaction",
    )
    if install["schema"] != "dcentos.s19k-persistent-install-transaction/v1" or install["device_id"] != device_id or install["authority_id"] != authority_id:
        common.fail("persistent install transaction schema/device/authority mismatch")
    session_id = common.token(install["session_id"], "persistent install session_id")
    started = common.canonical_uint(install["started_unix_s"], "install start", positive=True)
    completed = common.canonical_uint(install["completed_unix_s"], "install completion", positive=True)
    if not not_before <= started <= completed <= not_after:
        common.fail("persistent install occurred outside its authority window")
    if install["image_sha256"] != image_digest or install["readback_sha256"] != image_digest:
        common.fail("persistent install readback is not byte-identical to the admitted image")
    if install["image_bytes"] != image_bytes or install["readback_bytes"] != image_bytes:
        common.fail("persistent install/readback byte counts do not match the image")
    if install["write_count"] != 1 or install["bad_block_count"] != 0:
        common.fail("persistent install was not one stable exact write")
    if not all(install.get(key) is True for key in ("safeoff_before", "safeoff_after", "stock_recovery_held", "authority_consumed")) or install["outcome"] != "installed-readback-exact":
        common.fail("persistent install lacks SafeOff, recovery custody, or exact completion")
    common.exact_object(
        witness,
        ("schema", "session_id", "device_id", "authority_id", "operator", "witness", "install_transaction_sha256", "readback_observed", "safeoff_observed", "recovery_route_observed"),
        "persistent install witness",
    )
    if witness["schema"] != "dcentos.s19k-persistent-install-witness/v1" or witness["session_id"] != session_id or witness["device_id"] != device_id or witness["authority_id"] != authority_id:
        common.fail("persistent witness does not join the transaction")
    witness_name = common.token(witness["witness"], "persistent witness")
    if witness["operator"] != operator or witness_name == operator:
        common.fail("persistent install witness is not independent of the operator")
    if witness["install_transaction_sha256"] != common.sha256(payload["install-transaction.json"]):
        common.fail("persistent witness does not bind the install transaction")
    if not all(witness.get(key) is True for key in ("readback_observed", "safeoff_observed", "recovery_route_observed")):
        common.fail("persistent witness did not observe every safety boundary")
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "device_id": device_id,
        "session_id": session_id,
        "authority_id": authority_id,
        "image_sha256": image_digest,
        "image_bytes": image_bytes,
        "recovery_verification_sha256": recovery_sha,
        "recovery_verification_id": recovery_verification_id,
        "image_verification_sha256": image_sha,
        "install_transaction_sha256": common.sha256(payload["install-transaction.json"]),
        "independent_witness_sha256": common.sha256(payload["independent-witness.json"]),
        "capture_manifest_sha256": common.sha256(manifest_data),
        "single_authorized_write_verified": True,
        "immediate_readback_verified": True,
        "stock_recovery_held": True,
        "image_recovery_binding_verified": True,
        "terminal_safeoff_verified": True,
        "mutation_authority_granted": False,
    }
    return common.add_verification_id(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_workflow_evidence(args.evidence_dir.resolve(strict=True))
    except (OSError, common.NativeLiveEvidenceError) as error:
        print(f"S19K_PERSISTENT_INSTALL_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(common.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
