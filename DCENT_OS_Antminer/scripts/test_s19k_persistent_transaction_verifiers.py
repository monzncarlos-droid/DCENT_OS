#!/usr/bin/env python3
"""Tests for the post-recovery persistent install and acceptance receipts."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
common = importlib.import_module("s19k_native_live_common")
install_verify = importlib.import_module("s19k_persistent_install_verify")
accept_verify = importlib.import_module("s19k_persistent_acceptance_verify")


DEVICE = "s19k-live88-test"
IMAGE_SHA = "a" * 64
IMAGE_BYTES = 12_345_678


def write(path: Path, data: bytes | str) -> bytes:
    encoded = data.encode("ascii") if isinstance(data, str) else data
    path.write_bytes(encoded)
    return encoded


def reseal_manifest_file(directory: Path, name: str) -> None:
    manifest_path = directory / "capture-manifest.json"
    _, value = common.load_canonical_json(manifest_path, "test capture manifest")
    data = (directory / name).read_bytes()
    value["files"][name] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
    write(manifest_path, common.canonical_json(value))


def manifest(
    directory: Path,
    *,
    schema: str,
    phase: str,
    files: tuple[str, ...],
    extras: dict[str, object],
    run_id: str = "persistent-test-001",
    common_clock_id: str = "persistent-clock-001",
) -> None:
    identities = {}
    for name in files:
        data = (directory / name).read_bytes()
        identities[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
    write(
        directory / "capture-manifest.json",
        common.canonical_json(
            {
                "schema": schema,
                "phase": phase,
                "run_id": run_id,
                "common_clock_id": common_clock_id,
                "files": identities,
                **extras,
            }
        ),
    )
    write(directory / "verification.json", b"{}\n")


def install_fixture(
    directory: Path,
    *,
    run_id: str = "persistent-test-001",
    image_recovery_verification_id: str | None = None,
    image_overrides: dict[str, object] | None = None,
    image_remove: tuple[str, ...] = (),
) -> dict[str, object]:
    recovery = common.add_verification_id({
        "schema": "dcentos.s19k-persistent-recovery-verification/v1",
        "device_id": DEVICE,
        "stock_restore_rehearsal_verified": True,
        "original_bytes_restored": True,
        "terminal_safeoff_verified": True,
    })
    recovery_data = write(
        directory / "recovery-verification.json", common.canonical_json(recovery)
    )
    recovery_sha = hashlib.sha256(recovery_data).hexdigest()
    image = {
        "schema": install_verify.release_policy.PERSISTENT_IMAGE_SCHEMA,
        "phase_id": "persistent-image",
        "classification": "verified",
        "board": "am3-s19k",
        "installable": True,
        "image_sha256": IMAGE_SHA,
        "image_bytes": IMAGE_BYTES,
        "package_sha256": "1" * 64,
        "package_bytes": IMAGE_BYTES + 4096,
        "unsigned_package_sha256": "2" * 64,
        "unsigned_package_bytes": IMAGE_BYTES + 2048,
        "a_b_unsigned_equality_verified": True,
        "private_key_excluded_from_builds": True,
        "isolated_post_ab_signing_verified": False,
        "post_ab_derivation_and_runtime_metadata_verified": True,
        "isolated_post_ab_signing_nonclaim": (
            install_verify.release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
        ),
        "post_ab_signing_id": "3" * 64,
        "post_ab_signing_receipt_sha256": "4" * 64,
        "host_preflight_id": "5" * 64,
        "host_preflight_receipt_sha256": "6" * 64,
        "host_preflight_component_sha256": "7" * 64,
        "isolated_signer_runtime_id": "8" * 64,
        "isolated_signer_runtime_receipt_sha256": "9" * 64,
        "isolated_signer_private_key_custody_id": "a" * 64,
        "source_commit": "b" * 40,
        "source_date_epoch": 1_700_000_000,
        "release_key_sha256": "b" * 64,
        "release_key_id": "c" * 64,
        "release_manifest_public_key_hex": "d" * 64,
        "signed_manifest_sha256": "e" * 64,
        "persistent_image_contract_sha256": "f" * 64,
        "native_owner_verification_id": "1" * 64,
        "native_owner_receipt_sha256": "2" * 64,
        "native_owner_artifact_sha256": "3" * 64,
        "native_owner_source_files_sha256": "4" * 64,
        "native_owner_aarch64_compile_contract_bound": True,
        "reproducible_builds_verified": True,
        "signed_manifest_verified": True,
        "native_owner_artifact_bound": True,
        "native_owner_source_artifact_build_binding_verified": True,
        "native_owner_clean_source_commit_bound": True,
        "stock_recovery_receipt_bound": True,
        "stock_recovery_verification_id": (
            recovery["verification_id"]
            if image_recovery_verification_id is None
            else image_recovery_verification_id
        ),
        "stock_recovery_receipt_sha256": recovery_sha,
        "stock_recovery_device_id": DEVICE,
        "aml_rootfs_geometry": {
            "mtd": "/dev/mtd5",
            "offset_hex": "0x05100000",
            "offset_bytes": 0x05100000,
            "window_hex": "0x02800000",
            "window_bytes": 0x02800000,
            "erase_size_bytes": 131072,
            "erase_count": 320,
        },
        "safeoff_boot_baseline": {
            "platform": "am3-aml-s19k",
            "board_target": "am3-s19k",
            "rail_gpio": 437,
            "safeoff_value": 1,
            "mining_enabled_at_boot": False,
            "board_setup_sha256": "5" * 64,
            "daemon_init_sha256": "6" * 64,
            "mutation_policy_sha256": "7" * 64,
            "embedded_release_key_sha256": "b" * 64,
            "release_image_marker_sha256": "8" * 64,
        },
        "install_authority_granted": False,
        "mutation_authority_granted": False,
        "nand_write_authorized": False,
        "live_hardware_contacted": False,
        "network_used": False,
    }
    image.update(image_overrides or {})
    for field_name in image_remove:
        image.pop(field_name, None)
    common.add_verification_id(image)
    image_data = write(
        directory / "image-verification.json", common.canonical_json(image)
    )
    authority = {
        "schema": "dcentos.s19k-persistent-install-authority/v1",
        "authority_id": "authority-test-001",
        "device_id": DEVICE,
        "scope": "single-s19k-dcentos-image-install",
        "image_sha256": IMAGE_SHA,
        "not_before_unix_s": 2_000_000_000,
        "not_after_unix_s": 2_000_000_600,
        "single_use": True,
        "operator": "operator-one",
        "recovery_verification_sha256": recovery_sha,
        "install_authorized": True,
    }
    write(directory / "mutation-authority.json", common.canonical_json(authority))
    transaction = {
        "schema": "dcentos.s19k-persistent-install-transaction/v1",
        "session_id": "install-test-001",
        "device_id": DEVICE,
        "authority_id": authority["authority_id"],
        "image_sha256": IMAGE_SHA,
        "image_bytes": IMAGE_BYTES,
        "started_unix_s": 2_000_000_100,
        "completed_unix_s": 2_000_000_500,
        "write_count": 1,
        "readback_sha256": IMAGE_SHA,
        "readback_bytes": IMAGE_BYTES,
        "bad_block_count": 0,
        "safeoff_before": True,
        "safeoff_after": True,
        "stock_recovery_held": True,
        "authority_consumed": True,
        "outcome": "installed-readback-exact",
    }
    transaction_data = write(
        directory / "install-transaction.json", common.canonical_json(transaction)
    )
    witness = {
        "schema": "dcentos.s19k-persistent-install-witness/v1",
        "session_id": transaction["session_id"],
        "device_id": DEVICE,
        "authority_id": authority["authority_id"],
        "operator": authority["operator"],
        "witness": "witness-two",
        "install_transaction_sha256": hashlib.sha256(transaction_data).hexdigest(),
        "readback_observed": True,
        "safeoff_observed": True,
        "recovery_route_observed": True,
    }
    write(directory / "independent-witness.json", common.canonical_json(witness))
    manifest(
        directory,
        schema=install_verify.SCHEMA,
        phase=install_verify.PHASE,
        files=install_verify.FILES,
        extras={
            "device_id": DEVICE,
            "recovery_verification_sha256": recovery_sha,
            "image_verification_sha256": hashlib.sha256(image_data).hexdigest(),
        },
        run_id=run_id,
    )
    result = install_verify.verify_workflow_evidence(directory)
    write(directory / "verification.json", common.canonical_json(result))
    return result


def acceptance_fixture(
    directory: Path,
    install: dict[str, object],
    *,
    profile: str = "bhb56902-only",
    uart_paths: tuple[str, ...] = ("/dev/ttyS1", "/dev/ttyS2"),
    board_names: tuple[str, ...] = ("BHB56902", "BHB56902"),
    run_id: str = "persistent-acceptance-test-001",
) -> dict[str, object]:
    if len(uart_paths) != len(board_names):
        raise AssertionError("fixture UART and board populations must align")
    install_data = write(
        directory / "install-verification.json", common.canonical_json(install)
    )
    boots = [",".join(accept_verify.BOOT_HEADER)]
    management = [",".join(accept_verify.MANAGEMENT_HEADER)]
    inventory = [",".join(accept_verify.BOARD_HEADER)]
    mining = [",".join(accept_verify.MINING_HEADER)]
    for boot in range(1, 4):
        boots.append(
            f"{boot},true,DCENT_OS-am3-s19k,{IMAGE_SHA},checked,true,pass"
        )
        management.append(f"{boot},pass,pass,pass,pass,pass")
        for slot, (path, board_name) in enumerate(
            zip(uart_paths, board_names), 1
        ):
            inventory.append(
                f"{boot},{slot},{path},{board_name},0x1366,77,true,"
                f"serial-{slot:02d},stock-runtime+eeprom-or-model-joined"
            )
            mining.append(f"{boot},{path},77,1,true,true,true")
    files = {
        "cold-boots.csv": "\n".join(boots) + "\n",
        "management.csv": "\n".join(management) + "\n",
        "board-inventory.csv": "\n".join(inventory) + "\n",
        "mining.csv": "\n".join(mining) + "\n",
        "safeoff-recovery.csv": (
            ",".join(accept_verify.RECOVERY_HEADER)
            + "\n0,dcentos-safeoff,pass,true,true\n"
            + "1,stock-restore-executed,pass,true,true\n"
            + "2,stock-cold-boot-verified,pass,true,true\n"
            + "3,dcentos-reinstall-executed,pass,true,true\n"
            + "4,dcentos-cold-boot-after-reinstall,pass,true,true\n"
        ),
    }
    payloads: dict[str, bytes] = {}
    for name, text in files.items():
        payloads[name] = write(directory / name, text)
    witness = {
        "schema": "dcentos.s19k-persistent-acceptance-witness/v2",
        "device_id": DEVICE,
        "install_verification_id": install["verification_id"],
        "operator": "operator-one",
        "witness": "witness-two",
        "cold_boots_sha256": hashlib.sha256(payloads["cold-boots.csv"]).hexdigest(),
        "management_sha256": hashlib.sha256(payloads["management.csv"]).hexdigest(),
        "board_inventory_sha256": hashlib.sha256(
            payloads["board-inventory.csv"]
        ).hexdigest(),
        "mining_sha256": hashlib.sha256(payloads["mining.csv"]).hexdigest(),
        "safeoff_recovery_sha256": hashlib.sha256(
            payloads["safeoff-recovery.csv"]
        ).hexdigest(),
        "terminal_claim_observed": True,
    }
    write(directory / "independent-witness.json", common.canonical_json(witness))
    manifest(
        directory,
        schema=accept_verify.SCHEMA,
        phase=accept_verify.PHASE,
        files=accept_verify.FILES,
        extras={
            "device_id": DEVICE,
            "install_verification_id": install["verification_id"],
            "install_verification_sha256": hashlib.sha256(install_data).hexdigest(),
            "expected_image_sha256": IMAGE_SHA,
            "acceptance_profile": profile,
            "expected_uart_paths": list(uart_paths),
        },
        run_id=run_id,
    )
    result = accept_verify.verify_workflow_evidence(directory)
    write(directory / "verification.json", common.canonical_json(result))
    return result


class PersistentTransactionVerifierTests(unittest.TestCase):
    def test_positive_install_and_acceptance_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            accepted = acceptance_fixture(acceptance_dir, installed)
            self.assertTrue(installed["immediate_readback_verified"])
            self.assertEqual(accepted["cold_boot_count"], 3)
            self.assertEqual(accepted["accepted_share_total"], 6)
            self.assertEqual(accepted["acceptance_profile"], "bhb56902-only")
            self.assertTrue(accepted["stock_restore_and_cold_boot_verified"])

    def test_install_rejects_image_bound_to_different_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError,
                "different recovery receipt or device",
            ):
                install_fixture(
                    Path(temporary),
                    image_recovery_verification_id="f" * 64,
                )

    def test_install_rejects_stale_v3_image_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError,
                "lacks an installable image verification",
            ):
                install_fixture(
                    Path(temporary),
                    image_overrides={
                        "schema": "dcentos.s19k-persistent-image-verification/v3"
                    },
                )

    def test_install_rejects_missing_v4_image_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError,
                "inexact key set",
            ):
                install_fixture(
                    Path(temporary),
                    image_remove=("host_preflight_component_sha256",),
                )

    def test_install_preserves_v4_signing_isolation_nonclaim(self) -> None:
        cases = (
            {"isolated_post_ab_signing_verified": True},
            {"isolated_post_ab_signing_nonclaim": "isolation-proven"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(
                    common.NativeLiveEvidenceError,
                    "lacks an installable image verification",
                ):
                    install_fixture(Path(temporary), image_overrides=overrides)

    def test_install_rejects_non_independent_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            install_fixture(directory)
            witness_path = directory / "independent-witness.json"
            witness = common.validate_embedded_receipt(
                witness_path.read_bytes(), "test witness"
            )
            witness["witness"] = witness["operator"]
            write(witness_path, common.canonical_json(witness))
            with self.assertRaises(common.NativeLiveEvidenceError):
                install_verify.verify_workflow_evidence(directory)

    def test_acceptance_rejects_missing_uart_boot_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            acceptance_fixture(acceptance_dir, installed)
            path = acceptance_dir / "mining.csv"
            rows = path.read_text(encoding="ascii").splitlines()
            write(path, "\n".join(rows[:-1]) + "\n")
            reseal_manifest_file(acceptance_dir, "mining.csv")
            with self.assertRaises(common.NativeLiveEvidenceError):
                accept_verify.verify_workflow_evidence(acceptance_dir)

    def test_acceptance_rejects_board_identity_drift_across_boots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            acceptance_fixture(acceptance_dir, installed)
            path = acceptance_dir / "board-inventory.csv"
            text = path.read_text(encoding="ascii")
            write(path, text.replace("3,2,/dev/ttyS2,BHB56902,0x1366,77,true,serial-02", "3,2,/dev/ttyS2,BHB56902,0x1366,77,true,serial-drift"))
            reseal_manifest_file(acceptance_dir, "board-inventory.csv")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "drifted across cold boots"
            ):
                accept_verify.verify_workflow_evidence(acceptance_dir)

    def test_acceptance_rejects_historical_dry_run_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            acceptance_fixture(acceptance_dir, installed)
            path = acceptance_dir / "safeoff-recovery.csv"
            write(
                path,
                ",".join(accept_verify.RECOVERY_HEADER)
                + "\n0,dcentos-safeoff,pass,true,true\n"
                + "1,stock-restore-dry-run,pass,true,true\n",
            )
            reseal_manifest_file(acceptance_dir, "safeoff-recovery.csv")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "sequence is inexact"
            ):
                accept_verify.verify_workflow_evidence(acceptance_dir)

    def test_three_uart_population_is_admitted_only_with_three_slots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            accepted = acceptance_fixture(
                acceptance_dir,
                installed,
                profile="all-three-uarts-populated",
                uart_paths=("/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"),
                board_names=("BHB56902", "BHB56903", "BHB56902"),
            )
            self.assertEqual(len(accepted["native_uart_paths"]), 3)
            self.assertEqual(accepted["physical_slots"], [1, 2, 3])
            self.assertEqual(accepted["accepted_share_total"], 9)

    def test_profile_cannot_relabel_a_mixed_inventory_as_902_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_dir = root / "install"
            acceptance_dir = root / "acceptance"
            install_dir.mkdir()
            acceptance_dir.mkdir()
            installed = install_fixture(install_dir)
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "BHB56902-only"
            ):
                acceptance_fixture(
                    acceptance_dir,
                    installed,
                    profile="bhb56902-only",
                    board_names=("BHB56902", "BHB56903"),
                )


if __name__ == "__main__":
    unittest.main()
