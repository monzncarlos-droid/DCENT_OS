#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Build a path-free, non-authorizing Nano 3 W1 rollback custody manifest.

This command is offline.  It admits only the exact held Nano 3 donor, the
historical factory-restore KDIMG whose bytes were used in the 2026-08-21 live
restore, the exact W1 v19 rootfs mutation, and pinned historical evidence.  It
does not run the flash CLI, open USB, contact a miner, or grant authorization.

The current flash CLI requires a signed release bundle for every KDIMG,
including the factory restore.  Until a separately reviewed, signed recovery
rail exists, this manifest records the exact rollback command as blocked.  An
unexpected release-manifest/signature sibling also fails closed for review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from prepare_nano3_user_donor_restore import (  # noqa: E402
    HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
    canonical_receipt_bytes as canonical_restore_receipt_bytes,
    verify_restore_bytes,
)
from verify_nano3_user_donor_mutation import (  # noqa: E402
    canonical_receipt_bytes as canonical_mutation_receipt_bytes,
    verify_mutation_bytes,
)


SCHEMA = "dcent.nano3.w1.rollback-custody-manifest.v1"
EXPECTED_RESTORE_SIZE = 55_660_970
EXPECTED_DONOR_SIZE = 134_217_728
EXPECTED_DONOR_SHA256 = (
    "b99a2358592224b07b4ef9428181715d0dd8ed15585044a94d01e8c78fb830be"
)
EXPECTED_RESTORE_RECEIPT_SIZE = 5_041
EXPECTED_RESTORE_RECEIPT_SHA256 = (
    "f31eb882baaac22a278ad8d518c36838d2ae6c079c196f433632b979c034e244"
)
EXPECTED_V19_SIZE = 38_536_192
EXPECTED_V19_SHA256 = (
    "3c80c1b5d58edb733a125ea5cc33399d5fbcf4e7051310a3a5a5da3199516951"
)
EXPECTED_V19_RECEIPT_SIZE = 2_276
EXPECTED_V19_RECEIPT_SHA256 = (
    "bf18ff8eb27dbfb8618bae2fe1accfbc827e1757ecb82278b165de4e26e4c266"
)
EXPECTED_FLASH_TOOL_SIZE = 89_466
EXPECTED_FLASH_TOOL_SHA256 = (
    "0bb15a67cc8d66e278b1c98c64374de055ccff1dca462f26398c29d13218ec0b"
)
DATA_OFFSET = 0x06400000
NAND_CAPACITY = 0x08000000


class Nano3RollbackCustodyError(ValueError):
    """An exact rollback custody input or output failed closed."""


@dataclass(frozen=True)
class EvidenceSpec:
    """Pinned public historical evidence admitted into the custody manifest."""

    evidence_id: str
    size_bytes: int
    sha256: str
    required_text: tuple[str, ...]
    proof_scope: str


EVIDENCE_SPECS = {
    "r0_transcript": EvidenceSpec(
        evidence_id="r0-stock-restore-write-transcript-2026-08-21",
        size_bytes=38_953,
        sha256="6e42ee27c86bc1172f820dabde3db18219b3411db95330e0eac808e793414262",
        required_text=(
            HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
            "flashed spl_1, spl_2, uboot_1, uboot_2, uboot_env_1, uboot_env_2",
            "rootfs_1, rootfs_2, app_1, app_2",
            "0x6400000 bytes written",
            "proof_scope=image_written_only",
            "boot proof pending",
            "exit=0",
        ),
        proof_scope="machine-recorded-write-complete-boot-pending",
    ),
    "g2_transcript": EvidenceSpec(
        evidence_id="g2-stock-roundtrip-write-transcript-2026-08-21",
        size_bytes=39_098,
        sha256="309cfcf247ac5a9fbc899018790a87283d9f499883c216942682bd99a38196c3",
        required_text=(
            HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
            "flashed spl_1, spl_2, uboot_1, uboot_2, uboot_env_1, uboot_env_2",
            "rootfs_1, rootfs_2, app_1, app_2",
            "0x6400000 bytes written",
            "proof_scope=image_written_only",
            "boot proof pending",
            "exit=0",
        ),
        proof_scope="machine-recorded-roundtrip-write-complete-boot-pending",
    ),
    "stock_boot_record": EvidenceSpec(
        evidence_id="first-contact-operator-stock-boot-record",
        size_bytes=74_478,
        sha256="e18f7e3b464a4adba728a8f49cb65141378f1ad36fcb3c876709823b3a77c9b9",
        required_text=(
            "restored all 12 factory NAND slots",
            "operator confirmed\n   a normal stock boot",
            "restore path is therefore live-proven",
        ),
        proof_scope="operator-recorded-normal-stock-boot",
    ),
    "restore_workflow_record": EvidenceSpec(
        evidence_id="user-owned-donor-restore-workflow-v13",
        size_bytes=6_668,
        sha256="27d1a1277111f2bea43ba40f92ffbeb7c8a046a214ea5a87a147632dae431196",
        required_text=(
            "RESULT: PASS (desk-side packaging and verification only)",
            HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
            EXPECTED_RESTORE_RECEIPT_SHA256,
            "bytes_after_512_equal=true",
        ),
        proof_scope="desk-side-donor-restore-verification",
    ),
    "v19_image_report": EvidenceSpec(
        evidence_id="w1-v19-image-wright-report",
        size_bytes=14_291,
        sha256="0a7b359898e205aedd01ed6c76ba6ff63c36d96cd6f26d0a26f70948c6e0d622",
        required_text=(
            "PASS for the W1 image-artifact sub-gate; NO LIVE AUTHORITY",
            EXPECTED_V19_SHA256,
            EXPECTED_V19_RECEIPT_SHA256,
            "v19 is local, unsigned, unpromoted, factory-derived, and unflashed",
        ),
        proof_scope="desk-side-v19-image-round-trip",
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_exact_stable(path: Path, expected_size: int, label: str) -> bytes:
    """Read one exact-size regular file while rejecting identity drift."""
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise Nano3RollbackCustodyError(f"cannot inspect {label}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise Nano3RollbackCustodyError(
            f"{label} must be a regular, non-symlink file"
        )
    if before_path.st_size != expected_size:
        raise Nano3RollbackCustodyError(
            f"{label} has size {before_path.st_size}; expected {expected_size}"
        )

    try:
        with path.open("rb") as handle:
            before_fd = os.fstat(handle.fileno())
            data = handle.read(expected_size + 1)
            after_fd = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise Nano3RollbackCustodyError(f"cannot read {label}") from exc

    identities = (
        (before_path.st_dev, before_path.st_ino, before_path.st_size, before_path.st_mtime_ns),
        (before_fd.st_dev, before_fd.st_ino, before_fd.st_size, before_fd.st_mtime_ns),
        (after_fd.st_dev, after_fd.st_ino, after_fd.st_size, after_fd.st_mtime_ns),
        (after_path.st_dev, after_path.st_ino, after_path.st_size, after_path.st_mtime_ns),
    )
    if len(set(identities)) != 1 or len(data) != expected_size:
        raise Nano3RollbackCustodyError(f"{label} changed while it was being read")
    return data


def _verify_exact_json_receipt(
    data: bytes,
    *,
    expected_sha256: str,
    expected_canonical: bytes,
    label: str,
) -> None:
    if _sha256(data) != expected_sha256:
        raise Nano3RollbackCustodyError(f"{label} SHA-256 mismatch")
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Nano3RollbackCustodyError(f"{label} is not canonical JSON") from exc
    recanonical = (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if data != recanonical or data != expected_canonical:
        raise Nano3RollbackCustodyError(
            f"{label} does not exactly match regenerated verification facts"
        )


def _verify_evidence(data: bytes, spec: EvidenceSpec) -> dict[str, Any]:
    if len(data) != spec.size_bytes or _sha256(data) != spec.sha256:
        raise Nano3RollbackCustodyError(
            f"historical evidence {spec.evidence_id} size/SHA-256 mismatch"
        )
    text = data.decode("utf-8", errors="replace")
    for required in spec.required_text:
        if required not in text:
            raise Nano3RollbackCustodyError(
                f"historical evidence {spec.evidence_id} lacks required proof text"
            )
    return {
        "evidence_id": spec.evidence_id,
        "proof_scope": spec.proof_scope,
        "sha256": spec.sha256,
        "size_bytes": spec.size_bytes,
    }


def _assert_blocked_command_state(rollback_path: Path, flash_tool: bytes) -> None:
    """Pin the reviewed CLI and refuse any unreviewed adjacent signing state."""
    if len(flash_tool) != EXPECTED_FLASH_TOOL_SIZE or _sha256(flash_tool) != EXPECTED_FLASH_TOOL_SHA256:
        raise Nano3RollbackCustodyError("K230 flash tool size/SHA-256 mismatch")
    manifest_path = rollback_path.with_name(rollback_path.name + ".release.json")
    signature_path = manifest_path.with_name(manifest_path.name + ".sig")
    if manifest_path.exists() or manifest_path.is_symlink():
        raise Nano3RollbackCustodyError(
            "unexpected restore release manifest requires separate signed-bundle review"
        )
    if signature_path.exists() or signature_path.is_symlink():
        raise Nano3RollbackCustodyError(
            "unexpected restore release signature requires separate signed-bundle review"
        )


def build_manifest(
    *,
    donor: bytes,
    restore: bytes,
    restore_receipt: bytes,
    candidate: bytes,
    candidate_receipt: bytes,
    evidence: dict[str, bytes],
    flash_tool: bytes,
) -> dict[str, Any]:
    """Verify every custody input and return a public-safe manifest."""
    restore_facts = verify_restore_bytes(donor, restore)
    if (
        len(restore) != EXPECTED_RESTORE_SIZE
        or restore_facts["restore"]["sha256"]
        != HISTORICAL_LIVE_PROVEN_RESTORE_SHA256
        or restore_facts["restore"]["container_profile"]
        != "live-proven-2026-08-21"
    ):
        raise Nano3RollbackCustodyError("rollback is not the historical live-proven bytes")
    _verify_exact_json_receipt(
        restore_receipt,
        expected_sha256=EXPECTED_RESTORE_RECEIPT_SHA256,
        expected_canonical=canonical_restore_receipt_bytes(restore_facts),
        label="historical restore receipt",
    )

    if len(candidate) != EXPECTED_V19_SIZE or _sha256(candidate) != EXPECTED_V19_SHA256:
        raise Nano3RollbackCustodyError("candidate is not the exact W1 v19 image")
    mutation_facts = verify_mutation_bytes(donor, candidate)
    _verify_exact_json_receipt(
        candidate_receipt,
        expected_sha256=EXPECTED_V19_RECEIPT_SHA256,
        expected_canonical=canonical_mutation_receipt_bytes(mutation_facts),
        label="W1 v19 mutation receipt",
    )

    if set(evidence) != set(EVIDENCE_SPECS):
        raise Nano3RollbackCustodyError("historical evidence set is incomplete or unexpected")
    evidence_rows = [
        _verify_evidence(evidence[key], EVIDENCE_SPECS[key])
        for key in EVIDENCE_SPECS
    ]

    slots = restore_facts["slots"]
    expected_slots = [
        "spl_1",
        "spl_2",
        "uboot_1",
        "uboot_2",
        "uboot_env_1",
        "uboot_env_2",
        "linux_1",
        "linux_2",
        "rootfs_1",
        "rootfs_2",
        "app_1",
        "app_2",
    ]
    if [row["name"] for row in slots] != expected_slots:
        raise Nano3RollbackCustodyError("rollback write set is not the exact 12-slot order")
    if slots[-1]["nand_offset"] + slots[-1]["slot_size"] != DATA_OFFSET:
        raise Nano3RollbackCustodyError("rollback write set does not stop at data boundary")
    if restore_facts["restore"]["persistent_data_size"] != NAND_CAPACITY - DATA_OFFSET:
        raise Nano3RollbackCustodyError("persistent-data geometry differs from Nano 3 profile")
    if len(flash_tool) != EXPECTED_FLASH_TOOL_SIZE or _sha256(flash_tool) != EXPECTED_FLASH_TOOL_SHA256:
        raise Nano3RollbackCustodyError("K230 flash tool size/SHA-256 mismatch")

    return {
        "schema": SCHEMA,
        "model": "nano3",
        "candidate": {
            "artifact_revision": "nano3-user-donor-mutation-v19",
            "sha256": EXPECTED_V19_SHA256,
            "size_bytes": EXPECTED_V19_SIZE,
            "exact_write_slots": mutation_facts["mutation"]["exact_write_slots"],
            "persistent_data_included": False,
            "live_flash_performed": False,
        },
        "donor": restore_facts["donor"],
        "rollback": {
            "artifact_revision": "historical-live-proven-2026-08-21",
            "sha256": HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
            "size_bytes": EXPECTED_RESTORE_SIZE,
            "container_profile": "live-proven-2026-08-21",
            "exact_write_slots": expected_slots,
            "partition_count": len(slots),
            "all_partition_payloads_exact_donor_slices": True,
            "last_nand_end": DATA_OFFSET,
            "historical_live_restore_performed": True,
            "historical_normal_stock_boot_operator_recorded": True,
            "rollback_from_v19_performed": False,
        },
        "persistent_data_boundary": {
            "policy": "preserve",
            "required_cli_flag": "--no-data-erase",
            "erase_data_flag_forbidden": True,
            "offset": DATA_OFFSET,
            "size_bytes": NAND_CAPACITY - DATA_OFFSET,
            "end": NAND_CAPACITY,
            "included_in_rollback_artifact": False,
            "factory_reset_performed": False,
            "factory_reset_requires_separate_authorization": True,
        },
        "historical_evidence": evidence_rows,
        "receipts": {
            "historical_restore_receipt_sha256": EXPECTED_RESTORE_RECEIPT_SHA256,
            "w1_v19_mutation_receipt_sha256": EXPECTED_V19_RECEIPT_SHA256,
        },
        "tooling": {
            "custody_verifier": Path(__file__).name,
            "custody_verifier_sha256": _sha256(Path(__file__).read_bytes()),
            "restore_verifier": restore_facts["tooling"]["entry_point"],
            "restore_verifier_sha256": restore_facts["tooling"][
                "entry_point_sha256"
            ],
            "mutation_verifier": mutation_facts["tooling"]["entry_point"],
            "mutation_verifier_sha256": mutation_facts["tooling"][
                "entry_point_sha256"
            ],
        },
        "current_command_state": {
            "flash_tool": "flash.py",
            "flash_tool_sha256": EXPECTED_FLASH_TOOL_SHA256,
            "flash_tool_size_bytes": EXPECTED_FLASH_TOOL_SIZE,
            "desk_dry_run_observed_exit": 2,
            "desk_dry_run_proof_scope": "not_target_contacted",
            "status": "blocked",
            "reason": "signed-restore-release-bundle-required-and-not-held",
            "exact_rollback_command_currently_admitted": False,
        },
        "claims": {
            "manifest_contains_factory_payload_bytes": False,
            "manifest_contains_local_paths": False,
            "manifest_contains_credentials": False,
            "manifest_contains_private_keys": False,
            "restore_must_remain_operator_local": True,
            "redistribution_authorized": False,
            "authorization_a_granted": False,
            "hardware_contact_authorized": False,
            "flash_authorized": False,
            "reboot_authorized": False,
            "energization_authorized": False,
            "hardware_action_performed_by_this_verifier": False,
        },
    }


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Encode a deterministic receipt without paths, payloads, or secrets."""
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_new(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise Nano3RollbackCustodyError("refusing to overwrite manifest")
    if not path.parent.is_dir():
        raise Nano3RollbackCustodyError("manifest parent directory does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise Nano3RollbackCustodyError("cannot create manifest") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor", type=Path, required=True)
    parser.add_argument("--rollback", type=Path, required=True)
    parser.add_argument("--rollback-receipt", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-receipt", type=Path, required=True)
    parser.add_argument("--r0-transcript", type=Path, required=True)
    parser.add_argument("--g2-transcript", type=Path, required=True)
    parser.add_argument("--stock-boot-record", type=Path, required=True)
    parser.add_argument("--restore-workflow-record", type=Path, required=True)
    parser.add_argument("--v19-image-report", type=Path, required=True)
    parser.add_argument("--flash-tool", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.manifest.exists() or args.manifest.is_symlink():
            raise Nano3RollbackCustodyError("refusing to overwrite manifest")
        donor = _read_exact_stable(
            args.donor, EXPECTED_DONOR_SIZE, "Nano 3 factory donor"
        )
        if _sha256(donor) != EXPECTED_DONOR_SHA256:
            raise Nano3RollbackCustodyError("Nano 3 factory donor SHA-256 mismatch")
        restore = _read_exact_stable(args.rollback, EXPECTED_RESTORE_SIZE, "rollback")
        restore_receipt = _read_exact_stable(
            args.rollback_receipt,
            EXPECTED_RESTORE_RECEIPT_SIZE,
            "rollback receipt",
        )
        candidate = _read_exact_stable(args.candidate, EXPECTED_V19_SIZE, "W1 v19 candidate")
        candidate_receipt = _read_exact_stable(
            args.candidate_receipt,
            EXPECTED_V19_RECEIPT_SIZE,
            "W1 v19 receipt",
        )
        flash_tool = _read_exact_stable(
            args.flash_tool,
            EXPECTED_FLASH_TOOL_SIZE,
            "K230 flash tool",
        )
        _assert_blocked_command_state(args.rollback, flash_tool)
        evidence = {
            "r0_transcript": _read_exact_stable(
                args.r0_transcript,
                EVIDENCE_SPECS["r0_transcript"].size_bytes,
                "R0 restore transcript",
            ),
            "g2_transcript": _read_exact_stable(
                args.g2_transcript,
                EVIDENCE_SPECS["g2_transcript"].size_bytes,
                "G2 restore transcript",
            ),
            "stock_boot_record": _read_exact_stable(
                args.stock_boot_record,
                EVIDENCE_SPECS["stock_boot_record"].size_bytes,
                "stock boot record",
            ),
            "restore_workflow_record": _read_exact_stable(
                args.restore_workflow_record,
                EVIDENCE_SPECS["restore_workflow_record"].size_bytes,
                "restore workflow record",
            ),
            "v19_image_report": _read_exact_stable(
                args.v19_image_report,
                EVIDENCE_SPECS["v19_image_report"].size_bytes,
                "W1 v19 image report",
            ),
        }
        manifest = build_manifest(
            donor=donor,
            restore=restore,
            restore_receipt=restore_receipt,
            candidate=candidate,
            candidate_receipt=candidate_receipt,
            evidence=evidence,
            flash_tool=flash_tool,
        )
        encoded = canonical_manifest_bytes(manifest)
        _write_new(args.manifest, encoded)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "manifest_sha256": _sha256(encoded),
                    "rollback_sha256": HISTORICAL_LIVE_PROVEN_RESTORE_SHA256,
                    "candidate_sha256": EXPECTED_V19_SHA256,
                    "persistent_data_included": False,
                    "current_rollback_command_state": "blocked",
                    "authorization_a_granted": False,
                    "hardware_action_performed": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except Nano3RollbackCustodyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("error: local file operation failed", file=sys.stderr)
        return 2
    except ValueError:
        print("error: dependent image/receipt verification failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
