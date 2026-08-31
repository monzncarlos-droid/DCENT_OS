#!/usr/bin/env python3
"""Replay and verify the four required S19k board-population product trials."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
from typing import Any

import s19k_native_live_common as common
import s19k_native_population_coverage_verify as population_coverage
import s19k_persistent_acceptance_verify as acceptance_verify
import s19k_persistent_install_verify as install_verify


RESULT_SCHEMA = "dcentos.s19k-board-population-matrix-verification/v2"
REVIEW_SCHEMA = "dcentos.s19k-board-population-matrix-review/v1"
PHASE = "persistent-board-population-matrix"
RECEIPT_NAME = "verification.json"
REVIEW_NAME = "independent-review.json"
PROFILES = acceptance_verify.PROFILES


def _directory_members(directory: Path, expected: set[str], label: str) -> None:
    if not directory.is_dir() or directory.is_symlink():
        common.fail(f"{label} must be a real directory")
    observed: set[str] = set()
    try:
        for child in directory.iterdir():
            metadata = os.lstat(child)
            if stat.S_ISLNK(metadata.st_mode):
                common.fail(f"{label} contains a symlink")
            observed.add(child.name)
    except OSError as error:
        common.fail(f"cannot enumerate {label}: {error}")
    if observed != expected:
        common.fail(f"{label} has an incomplete or extra member set")


def _load_run_id(directory: Path, label: str) -> str:
    _, manifest = common.load_canonical_json(
        directory / "capture-manifest.json", f"{label} capture manifest"
    )
    return common.token(manifest.get("run_id"), f"{label} run_id")


def _verify_matrix(evidence_dir: Path) -> dict[str, Any]:
    coverage = population_coverage.audit_source_tree()
    if coverage.get("classification") != "ready":
        common.fail(
            "native population coverage is blocked: "
            + str(coverage.get("blocker"))
        )
    expected_root = {REVIEW_NAME, *PROFILES}
    if (evidence_dir / RECEIPT_NAME).exists():
        expected_root.add(RECEIPT_NAME)
    _directory_members(evidence_dir, expected_root, "board-population matrix")

    rows: dict[str, dict[str, Any]] = {}
    image_digests: set[str] = set()
    install_ids: set[str] = set()
    acceptance_ids: set[str] = set()
    all_run_ids: set[str] = set()
    principals: set[str] = set()

    for profile in PROFILES:
        row_dir = evidence_dir / profile
        _directory_members(row_dir, {"install", "acceptance"}, f"{profile} row")
        install_dir = row_dir / "install"
        acceptance_dir = row_dir / "acceptance"

        installed = install_verify.verify_workflow_evidence(install_dir)
        accepted = acceptance_verify.verify_workflow_evidence(acceptance_dir)
        common.verify_workflow_receipt(install_dir, installed)
        common.verify_workflow_receipt(acceptance_dir, accepted)

        install_receipt = common.stable_file(
            install_dir / RECEIPT_NAME,
            f"{profile} install verification receipt",
            common.MAX_JSON_BYTES,
        )
        acceptance_receipt = common.stable_file(
            acceptance_dir / RECEIPT_NAME,
            f"{profile} acceptance verification receipt",
            common.MAX_JSON_BYTES,
        )
        embedded_install = common.stable_file(
            acceptance_dir / "install-verification.json",
            f"{profile} acceptance install receipt",
            common.MAX_JSON_BYTES,
        )
        if embedded_install != install_receipt:
            common.fail(f"{profile} acceptance does not embed its replayed install")
        install_authority = common.validate_embedded_receipt(
            common.stable_file(
                install_dir / "mutation-authority.json",
                f"{profile} install authority",
                common.MAX_JSON_BYTES,
            ),
            f"{profile} install authority",
        )
        install_witness = common.validate_embedded_receipt(
            common.stable_file(
                install_dir / "independent-witness.json",
                f"{profile} install witness",
                common.MAX_JSON_BYTES,
            ),
            f"{profile} install witness",
        )
        if (
            accepted.get("acceptance_profile") != profile
            or accepted.get("install_verification_id") != installed.get("verification_id")
            or accepted.get("device_id") != installed.get("device_id")
            or accepted.get("image_sha256") != installed.get("image_sha256")
        ):
            common.fail(f"{profile} install and acceptance receipts do not join")
        if not all(
            accepted.get(key) is True
            for key in (
                "stock_restore_and_cold_boot_verified",
                "dcentos_reinstall_and_cold_boot_verified",
                "independent_acceptance_verified",
            )
        ):
            common.fail(f"{profile} lacks actual restore/reinstall acceptance")

        install_run_id = _load_run_id(install_dir, f"{profile} install")
        acceptance_run_id = _load_run_id(acceptance_dir, f"{profile} acceptance")
        if install_run_id == acceptance_run_id:
            common.fail(f"{profile} reuses one run_id for install and acceptance")
        if install_run_id in all_run_ids or acceptance_run_id in all_run_ids:
            common.fail("board-population matrix run_ids are not distinct")
        all_run_ids.update((install_run_id, acceptance_run_id))

        install_id = common.digest(
            installed.get("verification_id"), f"{profile} install verification_id"
        )
        acceptance_id = common.digest(
            accepted.get("verification_id"),
            f"{profile} acceptance verification_id",
        )
        if install_id in install_ids or acceptance_id in acceptance_ids:
            common.fail("board-population matrix verification_ids are not distinct")
        install_ids.add(install_id)
        acceptance_ids.add(acceptance_id)
        image_digests.add(
            common.digest(installed.get("image_sha256"), f"{profile} image SHA-256")
        )
        principals.update(
            (
                common.token(
                    install_authority.get("operator"), f"{profile} install operator"
                ),
                common.token(
                    install_witness.get("witness"), f"{profile} install witness"
                ),
                common.token(accepted.get("operator"), f"{profile} operator"),
                common.token(accepted.get("witness"), f"{profile} witness"),
            )
        )

        rows[profile] = {
            "device_id": common.token(
                installed.get("device_id"), f"{profile} device_id"
            ),
            "install_run_id": install_run_id,
            "acceptance_run_id": acceptance_run_id,
            "install_verification_id": install_id,
            "install_verification_sha256": common.sha256(install_receipt),
            "acceptance_verification_id": acceptance_id,
            "acceptance_verification_sha256": common.sha256(acceptance_receipt),
            "native_uart_paths": accepted["native_uart_paths"],
            "physical_slots": accepted["physical_slots"],
            "board_names": accepted["board_names"],
            "cold_boot_count": accepted["cold_boot_count"],
            "accepted_share_total": accepted["accepted_share_total"],
            "actual_stock_restore_and_dcentos_reinstall_verified": True,
        }

    if len(image_digests) != 1:
        common.fail("board-population matrix does not use one exact DCENT_OS image")

    review_data, review = common.load_canonical_json(
        evidence_dir / REVIEW_NAME, "board-population independent review"
    )
    common.exact_object(
        review,
        (
            "schema",
            "reviewer",
            "profiles",
            "all_profiles_independently_replayed",
            "actual_restore_reinstall_observed",
            "terminal_claim_authorized",
        ),
        "board-population independent review",
    )
    reviewer = common.token(review["reviewer"], "board-population reviewer")
    if reviewer in principals:
        common.fail("board-population reviewer is not independent")
    if (
        review["schema"] != REVIEW_SCHEMA
        or review["all_profiles_independently_replayed"] is not True
        or review["actual_restore_reinstall_observed"] is not True
        or review["terminal_claim_authorized"] is not False
    ):
        common.fail("board-population review assertions are not exact")
    review_profiles = common.exact_object(
        review["profiles"], PROFILES, "board-population reviewed profiles"
    )
    for profile in PROFILES:
        reviewed = common.exact_object(
            review_profiles[profile],
            (
                "install_verification_id",
                "install_verification_sha256",
                "acceptance_verification_id",
                "acceptance_verification_sha256",
                "install_and_acceptance_replayed",
                "actual_restore_reinstall_observed",
            ),
            f"{profile} independent review",
        )
        row = rows[profile]
        if (
            reviewed["install_verification_id"] != row["install_verification_id"]
            or reviewed["install_verification_sha256"]
            != row["install_verification_sha256"]
            or reviewed["acceptance_verification_id"]
            != row["acceptance_verification_id"]
            or reviewed["acceptance_verification_sha256"]
            != row["acceptance_verification_sha256"]
            or reviewed["install_and_acceptance_replayed"] is not True
            or reviewed["actual_restore_reinstall_observed"] is not True
        ):
            common.fail(f"{profile} independent review does not bind the row")

    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "claim": "four-profile BHB56902/BHB56903 population matrix replayed from raw persistent install and acceptance evidence after profile-aware native runtime source admission",
        "profiles": list(PROFILES),
        "profile_count": len(PROFILES),
        "image_sha256": next(iter(image_digests)),
        "rows": rows,
        "native_population_coverage_sha256": common.sha256(
            common.canonical_json(coverage)
        ),
        "native_population_profiles": coverage["required_profiles"],
        "independent_reviewer": reviewer,
        "independent_review_sha256": common.sha256(review_data),
        "product_matrix_complete": True,
        "actual_stock_restore_and_dcentos_reinstall_all_profiles": True,
        "independent_review_verified": True,
        "terminal_claim_authorized": False,
        "release_authority_granted": False,
        "install_authority_granted": False,
        "mutation_authority_granted": False,
        "live_hardware_contact_authority_granted": False,
    }
    return common.add_verification_id(result)


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    """Entry point consumed by the campaign workflow."""

    return _verify_matrix(evidence_dir)


def stage_receipt(evidence_dir: Path) -> dict[str, Any]:
    """Publish the replayed matrix receipt without overwriting different bytes."""

    result = _verify_matrix(evidence_dir)
    expected = common.canonical_json(result)
    receipt = evidence_dir / RECEIPT_NAME
    if receipt.exists():
        observed = common.stable_file(
            receipt, "board-population verification receipt", common.MAX_JSON_BYTES
        )
        if observed != expected:
            common.fail("refusing to overwrite a stale board-population receipt")
    else:
        try:
            with receipt.open("xb") as handle:
                handle.write(expected)
        except FileExistsError:
            common.fail("board-population verification receipt appeared during staging")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "stage"))
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence_dir = args.evidence_dir.absolute()
        if args.command == "stage":
            result = stage_receipt(evidence_dir)
        else:
            result = verify_workflow_evidence(evidence_dir)
            common.verify_workflow_receipt(evidence_dir, result)
    except (OSError, common.NativeLiveEvidenceError) as error:
        print(f"S19K_BOARD_POPULATION_MATRIX_REFUSED: {error}", file=sys.stderr)
        return 1
    print(
        "S19K_BOARD_POPULATION_MATRIX_OK "
        f"profiles={result['profile_count']} "
        f"image_sha256={result['image_sha256']} "
        f"verification_id={result['verification_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
