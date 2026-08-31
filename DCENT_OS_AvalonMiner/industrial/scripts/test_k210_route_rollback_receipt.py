#!/usr/bin/env python3
"""Tests for route-aware K210 rollback qualification receipts."""

from __future__ import annotations

import importlib.util
import json
import shutil
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_route_rollback_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_route_rollback_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
route_rollback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(route_rollback)

UPSTREAM_TEST_SCRIPT = Path(__file__).with_name(
    "test_k210_route_replacement_receipt.py"
)
UPSTREAM_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_route_replacement_fixture_for_rollback", UPSTREAM_TEST_SCRIPT
)
assert UPSTREAM_TEST_SPEC is not None and UPSTREAM_TEST_SPEC.loader is not None
upstream_test = importlib.util.module_from_spec(UPSTREAM_TEST_SPEC)
UPSTREAM_TEST_SPEC.loader.exec_module(upstream_test)


class K210RouteRollbackReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        upstream_test.K210RouteReplacementReceiptTests.setUpClass()

    def setUp(self) -> None:
        self.upstream = upstream_test.K210RouteReplacementReceiptTests(
            methodName="runTest"
        )
        self.upstream.setUp()

    def tearDown(self) -> None:
        self.upstream.tearDown()

    def _add(
        self,
        evidence: list[dict[str, object]],
        evidence_id: str,
        kind: str,
        path: str,
        content: bytes,
    ) -> None:
        destination = self.evidence_root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        evidence.append(
            {
                "acquired_at_utc": "2026-08-24T18:30:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": (
                    "application/octet-stream"
                    if kind == "full_readback_image"
                    else "application/json"
                ),
                "method": (
                    "offline_artifact"
                    if kind in route_rollback.PREDECESSOR_KINDS
                    else "completed_route_rollback_qualification"
                ),
                "path": path,
                "redaction": "none",
            }
        )

    def _case(self, route: str) -> None:
        self.upstream._case(route)
        self.replacement_bundle = self.upstream._bundle()
        self.root = self.upstream.root
        self.manifest = self.upstream.manifest
        self.discovery_bundle = self.upstream.discovery_bundle
        self.recovery_bundle = self.upstream.recovery_bundle
        self.boot_bundle = self.upstream.boot_bundle
        self.discovery_receipt = self.upstream.discovery_receipt
        self.recovery_receipt = self.upstream.recovery_receipt
        self.boot_receipt = self.upstream.boot_receipt
        self.route_record = self.upstream.route_record
        self.replacement_receipt = json.loads(
            (
                self.replacement_bundle / route_rollback.route_replacement.RECEIPT_NAME
            ).read_text(encoding="ascii")
        )
        self.evidence_root = self.root / "route-rollback-evidence"
        self.evidence_root.mkdir()
        self.descriptor_path = self.root / "route-rollback-descriptor.json"
        self.operator_private, self.operator_public = (
            self.upstream.recovery_fixture._new_key("route-rollback-operator")
        )
        self.witness_private, self.witness_public = (
            self.upstream.recovery_fixture._new_key("route-rollback-witness")
        )
        evidence: list[dict[str, object]] = []
        copies = (
            (
                "discovery-receipt",
                "discovery_receipt_copy",
                "predecessors/discovery.json",
                route_rollback.canonical_json_bytes(self.discovery_receipt),
            ),
            (
                "recovery-receipt",
                "recovery_receipt_copy",
                "predecessors/recovery.json",
                route_rollback.canonical_json_bytes(self.recovery_receipt),
            ),
            (
                "boot-policy-receipt",
                "boot_policy_receipt_copy",
                "predecessors/boot-policy.json",
                route_rollback.canonical_json_bytes(self.boot_receipt),
            ),
            (
                "route-adjudication",
                "boot_route_adjudication_copy",
                "predecessors/route.json",
                route_rollback.canonical_json_bytes(self.route_record),
            ),
            (
                "route-replacement-receipt",
                "route_replacement_receipt_copy",
                "predecessors/route-replacement.json",
                route_rollback.canonical_json_bytes(self.replacement_receipt),
            ),
        )
        for item in copies:
            self._add(evidence, *item)

        readbacks = []
        recovery_evidence = {
            item["id"]: item for item in self.recovery_receipt["evidence"]
        }
        for device in self.recovery_receipt["flash_devices"]:
            baseline_id = sorted(
                item["artifact_evidence_id"] for item in device["backup_reads"]
            )[0]
            baseline = recovery_evidence[baseline_id]
            source = (
                self.recovery_bundle
                / route_rollback.recovery.EVIDENCE_DIRECTORY
                / baseline["path"]
            )
            evidence_id = f"stock-readback-{device['id']}"
            self._add(
                evidence,
                evidence_id,
                "full_readback_image",
                f"readbacks/{device['id']}.bin",
                source.read_bytes(),
            )
            readbacks.append(
                {
                    "baseline_backup_evidence_id": baseline_id,
                    "flash_device_id": device["id"],
                    "full_device_readback": True,
                    "readback_evidence_id": evidence_id,
                    "readback_matches_stock": True,
                }
            )
        external_path = next(
            item
            for item in self.recovery_receipt["restore_paths"]
            if item["mechanism_class"] == "external_memory_programmer"
        )["id"]

        if route == "native_aes0_flash":
            assertions = {
                "full_stock_restore_completed": True,
                "interrupted_update_after_bytes": 8,
                "interrupted_update_observed": True,
                "stock_flash_restored": True,
            }
        elif route in route_rollback.SRAM_ROUTES:
            assertions = {
                "bootstrap_aborted": True,
                "candidate_persisted_to_flash": False,
                "sram_volatile_reset_performed": True,
                "stock_flash_unchanged": True,
                "transport": route,
                "volatile_reset_evidence_id": "volatile-reset",
            }
        else:
            assertions = {
                "disconnect_evidence_id": "controller-disconnect",
                "power_isolation_verified": True,
                "reconnect_evidence_id": "controller-reconnect",
                "replacement_controller_disconnected": True,
                "signal_isolation_verified": True,
                "stock_controller_reconnected": True,
                "stock_flash_unchanged": True,
            }
        contract = {
            "artifact_absent_after_rollback": True,
            "cold_boot_evidence_id": "stock-boot",
            "execution_evidence_id": "rollback-execution",
            "full_stock_readbacks": readbacks,
            "interruption_evidence_id": "rollback-interruption",
            "interruption_kind": "power_loss",
            "no_clobber_verified": True,
            "recovered_by_restore_path_id": external_path,
            "recovery_path_exercised": True,
            "route_assertions": assertions,
            "route_id": route,
            "stock_booted": True,
            "stock_identity_evidence_id": "stock-identity",
            "stock_identity_matched": True,
        }
        stock_identity = {
            key: self.discovery_receipt["identity"][key]
            for key in (
                "stock_dna",
                "stock_firmware_version",
                "stock_hwtype",
                "stock_swtype",
            )
        }
        common = {
            "artifact_set_sha256": self.replacement_receipt["artifact_set_sha256"],
            "authority_granted": False,
            "interface_qualification_sha256": self.replacement_receipt[
                "interface_qualification_sha256"
            ],
            "route_adjudication_sha256": self.route_record["adjudication_sha256"],
            "route_replacement_receipt_id": self.replacement_receipt["receipt_id"],
            "selected_route": route,
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
        }
        execution = {
            **common,
            "artifact_absent_after_rollback": True,
            "kind": "dcent_k210_route_rollback_execution",
            "no_clobber_verified": True,
            "recovered_by_restore_path_id": external_path,
            "recovery_path_exercised": True,
            "stock_booted": True,
            "stock_identity_matched": True,
        }
        interruption = {
            **common,
            "interruption_kind": "power_loss",
            "interruption_observed": True,
            "kind": "dcent_k210_route_rollback_interruption",
            "route_assertions": assertions,
        }
        boot_record = {
            "authority_granted": False,
            "kind": "dcent_k210_stock_cold_boot_observation",
            "production_hashing_commanded": False,
            "stock_booted": True,
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
        }
        identity_record = {
            "authority_granted": False,
            "identity": stock_identity,
            "kind": "dcent_k210_stock_identity_observation",
            "stock_identity_matched": True,
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
        }
        records = (
            (
                "rollback-execution",
                "route_rollback_execution_record",
                "records/execution.json",
                execution,
            ),
            (
                "rollback-interruption",
                "route_rollback_interruption_record",
                "records/interruption.json",
                interruption,
            ),
            (
                "stock-boot",
                "stock_cold_boot_record",
                "records/stock-boot.json",
                boot_record,
            ),
            (
                "stock-identity",
                "stock_identity_record",
                "records/stock-identity.json",
                identity_record,
            ),
        )
        for evidence_id, kind, path, value in records:
            self._add(
                evidence,
                evidence_id,
                kind,
                path,
                route_rollback.canonical_json_bytes(value),
            )
        if route in route_rollback.SRAM_ROUTES:
            reset = {
                **common,
                "candidate_persisted_to_flash": False,
                "kind": "dcent_k210_sram_volatile_reset",
                "sram_volatile_state_cleared": True,
                "stock_flash_unchanged": True,
            }
            self._add(
                evidence,
                "volatile-reset",
                "sram_volatile_reset_record",
                "records/volatile-reset.json",
                route_rollback.canonical_json_bytes(reset),
            )
        elif route == "clean_replacement_controller":
            disconnect = {
                **common,
                "connector_isolated": True,
                "kind": "dcent_k210_replacement_controller_disconnect",
                "power_isolated": True,
                "replacement_controller_disconnected": True,
                "signals_isolated": True,
            }
            reconnect = {
                **common,
                "kind": "dcent_k210_stock_controller_reconnect",
                "stock_controller_reconnected": True,
                "stock_flash_unchanged": True,
            }
            self._add(
                evidence,
                "controller-disconnect",
                "controller_disconnect_record",
                "records/controller-disconnect.json",
                route_rollback.canonical_json_bytes(disconnect),
            )
            self._add(
                evidence,
                "controller-reconnect",
                "controller_reconnect_record",
                "records/controller-reconnect.json",
                route_rollback.canonical_json_bytes(reconnect),
            )
        self.descriptor = {
            "actions_performed": dict(route_rollback.ACTIONS_PERFORMED),
            "artifact_set_sha256": self.replacement_receipt["artifact_set_sha256"],
            "authorization": {
                "authorized_actions": sorted(
                    route_rollback.COMMON_ACTIONS | {route_rollback.ROUTE_ACTION[route]}
                ),
                "operator_reference": "route-rollback-test-authorization",
                "valid_from_utc": "2026-08-24T18:00:00Z",
                "valid_until_utc": "2026-08-24T19:00:00Z",
            },
            "boot_policy_receipt_id": self.boot_receipt["receipt_id"],
            "completed_at_utc": "2026-08-24T18:40:00Z",
            "discovery_receipt_id": self.discovery_receipt["receipt_id"],
            "evidence": evidence,
            "interface_qualification_sha256": self.replacement_receipt[
                "interface_qualification_sha256"
            ],
            "kind": route_rollback.DESCRIPTOR_KIND,
            "operator_id": "route-rollback-test-operator",
            "recovery_receipt_id": self.recovery_receipt["receipt_id"],
            "rollback_contract": contract,
            "route_adjudication_sha256": self.route_record["adjudication_sha256"],
            "route_replacement_receipt_id": self.replacement_receipt["receipt_id"],
            "schema_version": route_rollback.SCHEMA_VERSION,
            "scope": route_rollback.SCOPE,
            "selected_route": route,
            "started_at_utc": "2026-08-24T18:05:00Z",
            "stock_backup_set_sha256": self.recovery_receipt["stock_backup_set_sha256"],
            "stock_identity": stock_identity,
            "target_id": "a1246",
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
            "unit_label": self.discovery_receipt["unit_label"],
            "witness_id": "route-rollback-test-witness",
        }

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "route-rollback-bundle"
        route_rollback.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.witness_private,
            bundle,
        )
        return bundle

    def _verify(self) -> dict[str, object]:
        return route_rollback.verify_bundle(
            self.manifest,
            self._bundle(),
            self.operator_public,
            self.witness_public,
        )

    def test_aes0_interrupted_update_full_restore_round_trip(self) -> None:
        self._case("native_aes0_flash")
        result = self._verify()
        self.assertEqual(result["selected_route"], "native_aes0_flash")
        self.assertTrue(result["rollback_recovery_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(len(result["no_clobber_sha256"]), 64)
        self.assertEqual(
            result["artifact_set_sha256"],
            self.replacement_receipt["artifact_set_sha256"],
        )

    def test_rom_isp_abort_volatile_reset_and_unchanged_flash_round_trip(self) -> None:
        self._case("rom_isp_sram_bootstrap")
        result = self._verify()
        self.assertEqual(result["selected_route"], "rom_isp_sram_bootstrap")

    def test_jtag_abort_volatile_reset_and_unchanged_flash_round_trip(self) -> None:
        self._case("jtag_sram_bootstrap")
        result = self._verify()
        self.assertEqual(result["selected_route"], "jtag_sram_bootstrap")

    def test_controller_disconnect_reconnect_and_unchanged_flash_round_trip(
        self,
    ) -> None:
        self._case("clean_replacement_controller")
        result = self._verify()
        self.assertEqual(result["selected_route"], "clean_replacement_controller")
        self.assertEqual(
            result["interface_qualification_sha256"],
            self.replacement_receipt["interface_qualification_sha256"],
        )

    def test_cross_route_cross_unit_and_digest_splices_are_rejected(self) -> None:
        self._case("rom_isp_sram_bootstrap")
        self.descriptor["rollback_contract"]["route_id"] = "jtag_sram_bootstrap"
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "selected route"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["rollback_contract"]["route_id"] = "rom_isp_sram_bootstrap"
        self.descriptor["unit_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "does not match rollback"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["unit_fingerprint_sha256"] = self.discovery_receipt[
            "unit_fingerprint_sha256"
        ]
        self.descriptor["artifact_set_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "does not match rollback"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_persistence_no_clobber_and_interruption_claims_are_rejected(self) -> None:
        self._case("rom_isp_sram_bootstrap")
        receipt, _ = route_rollback.build_receipt(
            self.manifest,
            self.descriptor,
            self.evidence_root,
            self.operator_private,
            self.witness_private,
        )
        receipt["no_clobber_sha256"] = "0" * 64
        with self.assertRaisesRegex(route_rollback.RouteRollbackError, "no-clobber"):
            route_rollback._validate_receipt(receipt, self.manifest)
        assertions = self.descriptor["rollback_contract"]["route_assertions"]
        assertions["candidate_persisted_to_flash"] = True
        with self.assertRaisesRegex(route_rollback.RouteRollbackError, "persistence"):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        assertions["candidate_persisted_to_flash"] = False
        self.descriptor["rollback_contract"]["no_clobber_verified"] = False
        with self.assertRaisesRegex(route_rollback.RouteRollbackError, "no_clobber"):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["rollback_contract"]["no_clobber_verified"] = True
        assertions["bootstrap_aborted"] = False
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "bootstrap_aborted"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )

    def test_readback_signer_path_and_member_attacks_are_rejected(self) -> None:
        self._case("native_aes0_flash")
        readback = next(
            item
            for item in self.descriptor["evidence"]
            if item["kind"] == "full_readback_image"
        )
        path = self.evidence_root / readback["path"]
        path.write_bytes(path.read_bytes() + b"clobber")
        with self.assertRaisesRegex(route_rollback.RouteRollbackError, "do not match"):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        baseline = next(
            item
            for item in self.recovery_receipt["evidence"]
            if item["id"]
            == self.descriptor["rollback_contract"]["full_stock_readbacks"][0][
                "baseline_backup_evidence_id"
            ]
        )
        source = (
            self.recovery_bundle
            / route_rollback.recovery.EVIDENCE_DIRECTORY
            / baseline["path"]
        )
        path.write_bytes(source.read_bytes())
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "keys must be distinct"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )
        self.descriptor["evidence"][0]["path"] = "../escape.json"
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "unsafe segment"
        ):
            route_rollback.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.witness_private,
            )
        self.descriptor["evidence"][0]["path"] = "predecessors/discovery.json"
        bundle = self._bundle()
        (bundle / "unsigned.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(
            route_rollback.RouteRollbackError, "member set is not exact"
        ):
            route_rollback.verify_bundle(
                self.manifest,
                bundle,
                self.operator_public,
                self.witness_public,
            )


if __name__ == "__main__":
    unittest.main()
