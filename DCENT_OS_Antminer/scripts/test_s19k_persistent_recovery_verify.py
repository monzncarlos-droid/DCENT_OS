#!/usr/bin/env python3
"""Adversarial host-only tests for the S19k persistent-recovery verifier."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import warnings


SCRIPT = Path(__file__).with_name("s19k_persistent_recovery_verify.py")
SPEC = importlib.util.spec_from_file_location(
    "s19k_persistent_recovery_verify", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
recovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def timestamp(second: int) -> str:
    base = datetime(2026, 8, 24, tzinfo=timezone.utc)
    return (base + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.partitions = (
            recovery.PartitionSpec(0, "bootloader", 0, 4, 4),
            recovery.PartitionSpec(1, "system", 8, 4, 4),
        )
        stock_bytes = b"signed-stock-fixture"
        self.stock = recovery.StockBmuContract(
            filename="stock.bmu",
            size=len(stock_bytes),
            sha256=digest(stock_bytes),
            aml_record_size=7,
            aml_record_sha256=digest(b"aml-record-fixture"),
        )
        self.session_id = "1" * 64
        self.device_id = "2" * 64
        self.authority_id = "3" * 64
        self.operator_id = "operator.fixture"
        self.observer_id = "reviewer.fixture"
        (root / recovery.BACKUP_DIR).mkdir(parents=True)
        (root / recovery.READBACK_DIR).mkdir()
        (root / self.stock.filename).write_bytes(stock_bytes)
        for part in self.partitions:
            data = bytes([0x30 + part.index]) * part.size
            (root / recovery.BACKUP_DIR / part.backup_name).write_bytes(data)
            (root / recovery.READBACK_DIR / part.backup_name).write_bytes(data)
        (root / recovery.PROC_MTD_FILE).write_bytes(
            recovery._proc_mtd_bytes(self.partitions)
        )
        self._write_initial_json()
        self.seal()

    @staticmethod
    def fake_stock_verifier(
        _path: Path, stock: recovery.StockBmuContract
    ) -> dict[str, object]:
        return {
            "signature_classification": (
                "bitmain-rsa-aml-internal-chain-plus-device-fileparser"
            ),
            "merge_crc32_verified": True,
            "three_control_board_records_verified": True,
            "aml_record_sha256": stock.aml_record_sha256,
            "aml_component_signatures_verified": True,
            "aml_bmu_signature_verified": True,
            "aml_root_anchor_held": False,
        }

    def write_json(self, name: str, value: dict[str, object]) -> None:
        (self.root / name).write_bytes(recovery.canonical_json(value))

    def read_json(self, name: str) -> dict[str, object]:
        return json.loads((self.root / name).read_text(encoding="ascii"))

    def _write_initial_json(self) -> None:
        self.write_json(
            recovery.DEVICE_FILE,
            {
                "schema": recovery.DEVICE_SCHEMA,
                "session_id": self.session_id,
                "device_id": self.device_id,
                "serial": "S19K-FIXTURE-001",
                "model": "Antminer S19k Pro",
                "platform": "am3-aml-s19k",
                "board_target": "am3-s19k",
                "soc": "A113D/AXG",
                "pcb": "C81",
                "nand_device": "raw-nand",
                "nand_total_bytes": 12,
                "nand_identity_sha256": "4" * 64,
            },
        )
        self.write_json(
            recovery.AUTHORITY_FILE,
            {
                "schema": recovery.AUTHORITY_SCHEMA,
                "session_id": self.session_id,
                "device_id": self.device_id,
                "authority_id": self.authority_id,
                "operator_id": self.operator_id,
                "scope": "signed-stock-recovery-rehearsal-only",
                "issued_utc": timestamp(0),
                "expires_utc": timestamp(60),
                "single_use": True,
                "rehearsal_mutation_authorized": True,
                "separate_from_dcentos_install": True,
                "dcentos_write_authorized": False,
                "persistent_install_authorized": False,
            },
        )
        layout = {
            "schema": recovery.LAYOUT_SCHEMA,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "source": "captured-proc-mtd-plus-global-offset-map",
            "proc_mtd_file": recovery.PROC_MTD_FILE,
            "proc_mtd_sha256": digest(
                (self.root / recovery.PROC_MTD_FILE).read_bytes()
            ),
            "nand_total_bytes": 12,
            "holes": [{"offset": 4, "bytes": 4}],
            "partitions": [
                {
                    "index": part.index,
                    "name": part.name,
                    "device": f"mtd{part.index}",
                    "offset": part.offset,
                    "bytes": part.size,
                    "erasesize": part.erasesize,
                }
                for part in self.partitions
            ],
        }
        self.write_json(recovery.LAYOUT_FILE, layout)
        backup_rows = []
        for part in self.partitions:
            backup_name = f"{recovery.BACKUP_DIR}/{part.backup_name}"
            backup_sha = digest((self.root / backup_name).read_bytes())
            backup_rows.append(
                {
                    "index": part.index,
                    "name": part.name,
                    "offset": part.offset,
                    "bytes": part.size,
                    "erasesize": part.erasesize,
                    "bad_blocks_before": 0,
                    "bad_blocks_after": 0,
                    "backup_file": backup_name,
                    "backup_sha256": backup_sha,
                    "duplicate_read_sha256": backup_sha,
                }
            )
        self.write_json(
            recovery.BACKUP_FILE,
            {
                "schema": recovery.BACKUP_SCHEMA,
                "session_id": self.session_id,
                "device_id": self.device_id,
                "capture_mode": "nanddump-padbad",
                "logical_offsets_preserved": True,
                "oob": "omitted-ecc-regenerated",
                "duplicate_streams": True,
                "stable_zero_bad_blocks_required": True,
                "backup_complete_before_dcentos_write": True,
                "dcentos_write_count_at_capture": 0,
                "partitions": backup_rows,
            },
        )
        authority_sha = digest((self.root / recovery.AUTHORITY_FILE).read_bytes())
        layout_sha = digest((self.root / recovery.LAYOUT_FILE).read_bytes())
        backup_sha = digest((self.root / recovery.BACKUP_FILE).read_bytes())
        self.write_json(
            recovery.REHEARSAL_FILE,
            {
                "schema": recovery.REHEARSAL_SCHEMA,
                "session_id": self.session_id,
                "device_id": self.device_id,
                "authority_id": self.authority_id,
                "authority_sha256": authority_sha,
                "layout_sha256": layout_sha,
                "backup_manifest_sha256": backup_sha,
                "stock_bmu_file": self.stock.filename,
                "stock_bmu_sha256": self.stock.sha256,
                "stock_bmu_bytes": self.stock.size,
                "stock_fileparser_subtype": "AMLCtrl_BHB56XXX",
                "stock_fileparser_signature_verified": True,
                "stock_restore_completed": True,
                "stock_boot_model": "Antminer S19k Pro",
                "stock_boot_platform": "am3-aml-s19k",
                "original_restore_method": (
                    "erase-write-each-partition-then-padbad-readback"
                ),
                "original_restore_completed": True,
                "original_stock_boot_verified": True,
                "terminal_safeoff_verified": True,
                "dcentos_write_attempted": False,
                "dcentos_write_count": 0,
                "events": [
                    {
                        "sequence": sequence,
                        "name": name,
                        "utc": timestamp(sequence),
                        "dcentos_write_count": 0,
                    }
                    for sequence, name in enumerate(recovery.EVENTS, start=1)
                ],
            },
        )
        rehearsal_sha = digest((self.root / recovery.REHEARSAL_FILE).read_bytes())
        self.write_json(
            recovery.WITNESS_FILE,
            {
                "schema": recovery.WITNESS_SCHEMA,
                "session_id": self.session_id,
                "device_id": self.device_id,
                "authority_id": self.authority_id,
                "operator_id": self.operator_id,
                "observer_id": self.observer_id,
                "authority_sha256": authority_sha,
                "layout_sha256": layout_sha,
                "backup_manifest_sha256": backup_sha,
                "rehearsal_sha256": rehearsal_sha,
                "stock_bmu_sha256": self.stock.sha256,
                "stock_fileparser_signature_verified": True,
                "restored_readbacks": {
                    f"{recovery.READBACK_DIR}/{part.backup_name}": digest(
                        (
                            self.root
                            / recovery.READBACK_DIR
                            / part.backup_name
                        ).read_bytes()
                    )
                    for part in self.partitions
                },
                "stock_boot_model": "Antminer S19k Pro",
                "stock_boot_platform": "am3-aml-s19k",
                "rehearsal_complete": True,
                "original_bytes_restored": True,
                "terminal_safeoff_verified": True,
                "dcentos_write_observed": False,
                "mutation_authority_granted": False,
            },
        )

    def seal(self) -> None:
        files = {}
        for name in sorted(recovery._leaf_names(self.partitions, self.stock)):
            raw = (self.root / Path(name)).read_bytes()
            files[name] = {"bytes": len(raw), "sha256": digest(raw)}
        self.write_json(
            recovery.CONTRACT_FILE,
            {
                "schema": recovery.CONTRACT_SCHEMA,
                "session_id": self.session_id,
                "claim": "pre-dcentos-write-stock-recovery-rehearsal",
                "publication": "post-rehearsal-content-manifest",
                "dcentos_write_attempted": False,
                "dcentos_write_count": 0,
                "files": files,
            },
        )

    def verify(self, stock_verifier=None) -> dict[str, object]:
        return recovery.verify_evidence(
            self.root,
            partitions=self.partitions,
            stock=self.stock,
            stock_verifier=stock_verifier or self.fake_stock_verifier,
        )


class PersistentRecoveryVerifierTests(unittest.TestCase):
    def fixture(self, root: Path) -> Fixture:
        return Fixture(root)

    def test_complete_bundle_proves_recovery_but_grants_no_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            result = fixture.verify()
            self.assertEqual(result["schema"], recovery.RESULT_SCHEMA)
            self.assertTrue(result["separate_mutation_authority_verified"])
            self.assertTrue(result["stock_restore_rehearsal_verified"])
            self.assertTrue(result["original_bytes_restored"])
            self.assertFalse(result["dcentos_write_observed"])
            self.assertFalse(result["dcentos_write_authorized"])
            self.assertFalse(result["mutation_authority_granted"])
            self.assertRegex(result["verification_id"], r"^[0-9a-f]{64}$")
            self.assertEqual(result, fixture.verify())

    def test_workflow_receipt_must_be_a_fresh_canonical_recomputation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            result = fixture.verify()
            receipt = fixture.root / recovery.VERIFICATION_FILE
            receipt.write_bytes(recovery.canonical_json(result))
            self.assertEqual(result, fixture.verify())
            receipt.write_bytes(recovery.canonical_json({"stale": True}))
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "stale or noncanonical"
            ):
                fixture.verify()

    def test_authority_claim_alone_cannot_replace_physical_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            part = fixture.partitions[0]
            (fixture.root / recovery.READBACK_DIR / part.backup_name).unlink()
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "entry set is inexact"
            ):
                fixture.verify()

    def test_authority_is_separate_single_scope_and_never_dcentos_authority(self) -> None:
        mutations = (
            ("scope", "persistent-install"),
            ("single_use", False),
            ("separate_from_dcentos_install", False),
            ("dcentos_write_authorized", True),
            ("persistent_install_authorized", True),
        )
        for key, value in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                fixture = self.fixture(Path(raw))
                authority = fixture.read_json(recovery.AUTHORITY_FILE)
                authority[key] = value
                fixture.write_json(recovery.AUTHORITY_FILE, authority)
                fixture.seal()
                with self.assertRaises(recovery.PersistentRecoveryError):
                    fixture.verify()

    def test_authority_window_is_narrow(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            authority = fixture.read_json(recovery.AUTHORITY_FILE)
            authority["expires_utc"] = timestamp(
                recovery.MAX_AUTHORITY_WINDOW_SECONDS + 1
            )
            fixture.write_json(recovery.AUTHORITY_FILE, authority)
            fixture.seal()
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "window exceeds one hour"
            ):
                fixture.verify()

    def test_hard_link_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            source = fixture.root / recovery.PROC_MTD_FILE
            alias = fixture.root.with_name(f"{fixture.root.name}.proc-mtd-hardlink")
            try:
                os.link(source, alias)
            except OSError:
                self.skipTest("hard-link creation is unavailable")
            try:
                fixture.seal()
                with self.assertRaisesRegex(
                    recovery.PersistentRecoveryError, "single-link file"
                ):
                    fixture.verify()
            finally:
                alias.unlink(missing_ok=True)

    def test_partition_layout_rejects_offset_and_equal_sum_relabeling(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            layout = fixture.read_json(recovery.LAYOUT_FILE)
            layout["partitions"][0]["offset"] = 4
            layout["partitions"][0]["bytes"] = 2
            layout["partitions"][1]["bytes"] = 6
            fixture.write_json(recovery.LAYOUT_FILE, layout)
            fixture.seal()
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "layout row"
            ):
                fixture.verify()

    def test_duplicate_capture_hash_and_zero_badblock_policy_are_mandatory(self) -> None:
        mutations = (
            ("duplicate_read_sha256", "f" * 64),
            ("bad_blocks_before", 1),
            ("bad_blocks_after", 1),
        )
        for key, value in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                fixture = self.fixture(Path(raw))
                backup = fixture.read_json(recovery.BACKUP_FILE)
                backup["partitions"][0][key] = value
                fixture.write_json(recovery.BACKUP_FILE, backup)
                fixture.seal()
                with self.assertRaisesRegex(
                    recovery.PersistentRecoveryError, "backup manifest row"
                ):
                    fixture.verify()

    def test_restored_readback_must_equal_the_actual_backup_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            part = fixture.partitions[1]
            (fixture.root / recovery.READBACK_DIR / part.backup_name).write_bytes(
                b"XXXX"
            )
            fixture.seal()
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "readback does not equal"
            ):
                fixture.verify()

    def test_signed_stock_identity_and_signature_result_both_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            (fixture.root / fixture.stock.filename).write_bytes(
                b"X" * fixture.stock.size
            )
            fixture.seal()
            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "signed stock BMU identity"
            ):
                fixture.verify()
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))

            def refused(_path, stock):
                result = fixture.fake_stock_verifier(_path, stock)
                result["aml_bmu_signature_verified"] = False
                return result

            with self.assertRaisesRegex(
                recovery.PersistentRecoveryError, "did not prove"
            ):
                fixture.verify(refused)

    def test_event_order_window_and_zero_dcentos_write_count_are_bound(self) -> None:
        mutations = ("wrong-order", "expired", "dcentos-write")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                fixture = self.fixture(Path(raw))
                rehearsal = fixture.read_json(recovery.REHEARSAL_FILE)
                if mutation == "wrong-order":
                    rehearsal["events"][4]["name"] = recovery.EVENTS[5]
                elif mutation == "expired":
                    rehearsal["events"][-1]["utc"] = timestamp(61)
                else:
                    rehearsal["events"][4]["dcentos_write_count"] = 1
                fixture.write_json(recovery.REHEARSAL_FILE, rehearsal)
                fixture.seal()
                with self.assertRaises(recovery.PersistentRecoveryError):
                    fixture.verify()

    def test_witness_is_independent_and_cannot_grant_authority(self) -> None:
        mutations = (
            ("observer_id", "operator.fixture"),
            ("mutation_authority_granted", True),
            ("dcentos_write_observed", True),
        )
        for key, value in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                fixture = self.fixture(Path(raw))
                witness = fixture.read_json(recovery.WITNESS_FILE)
                witness[key] = value
                fixture.write_json(recovery.WITNESS_FILE, witness)
                fixture.seal()
                with self.assertRaises(recovery.PersistentRecoveryError):
                    fixture.verify()

    def test_bundle_is_canonical_exact_and_rejects_symlink_or_extra_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            (fixture.root / "unexpected.txt").write_text("no", encoding="ascii")
            with self.assertRaisesRegex(recovery.PersistentRecoveryError, "extra"):
                fixture.verify()
        with tempfile.TemporaryDirectory() as raw:
            fixture = self.fixture(Path(raw))
            target = fixture.root / recovery.BACKUP_DIR / fixture.partitions[0].backup_name
            original = target.read_bytes()
            target.unlink()
            source = fixture.root / "outside.bin"
            source.write_bytes(original)
            try:
                os.symlink(source, target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(recovery.PersistentRecoveryError):
                fixture.verify()

    def test_production_layout_and_stock_artifact_are_exactly_pinned(self) -> None:
        self.assertEqual(len(recovery.PARTITIONS), 6)
        self.assertEqual(
            [part.offset for part in recovery.PARTITIONS],
            [
                0x00000000,
                0x00800000,
                0x01000000,
                0x04200000,
                0x04700000,
                0x06700000,
            ],
        )
        self.assertEqual(recovery.PARTITIONS[5].offset, 0x06700000)
        self.assertEqual(recovery.PARTITIONS[5].size, 0x09900000)
        self.assertEqual(recovery._holes(recovery.PARTITIONS), [
            {"offset": 0x00200000, "bytes": 0x00600000}
        ])
        self.assertEqual(recovery.STOCK_BMU.size, 43_786_317)
        self.assertEqual(
            recovery.STOCK_BMU.sha256,
            "286cd2eb8a1940ba3dfa6211fb96bfb5d68329acd69fd78891af8b4d74ef3fbe",
        )

    def test_held_signed_stock_chain_if_present(self) -> None:
        held = (
            SCRIPT.parents[3]
            / ""
            / recovery.STOCK_BMU.filename
        )
        if not held.is_file():
            self.skipTest("optional held signed stock BMU is absent")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            result = recovery.verify_signed_stock_bmu(held)
        self.assertTrue(result["merge_crc32_verified"])
        self.assertTrue(result["aml_component_signatures_verified"])
        self.assertTrue(result["aml_bmu_signature_verified"])

    def test_workflow_api_is_offline_only_and_authority_denying(self) -> None:
        self.assertTrue(callable(recovery.verify_workflow_evidence))
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import requests",
            "import paramiko",
            "urllib.request",
            "subprocess.",
            "os.system(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"mutation_authority_granted": False', source)
        self.assertIn('"dcentos_write_authorized": False', source)


if __name__ == "__main__":
    unittest.main()
