#!/usr/bin/env python3
"""Regression tests for exact-SKU DCENTaxe production-promotion receipts."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from hardware_evidence import (  # noqa: E402
    SEMANTIC_GATES,
    _validate_gate_measurements,
    load_evidence_index,
    production_claim_errors,
    promotion_status,
    required_production_gates,
    sha256_file,
    validate_evidence_index,
)
from target_matrix import ROOT, load_manifest  # noqa: E402
from production_gauntlet import readiness  # noqa: E402
from promotion_candidate import candidate_id  # noqa: E402


def sample_matrix() -> dict:
    return {
        "schema": 1,
        "production_gate_contract": {
            "artifact_schema": 1,
            "artifact_authority": "observed-exact-sku-hardware-gate",
            "minimum_soak_seconds": 259_200,
            "required": [
                "exact-sku-identity",
                "safe-boot",
                "fail-safe-power-cut",
                "trusted-thermal",
                "accepted-share",
                "ota-rollback",
                "sustained-soak",
                "mqtt-command-roundtrip",
            ],
            "family_additions": {},
            "target_additions": {},
        },
        "targets": [
            {
                "board_target": "sample-board",
                "feature": "sample-board",
                "device_model": "sample_model",
                "model_variant": "SampleBoard",
                "hardware_family": "bitaxe",
                "asic": "BM1366",
                "chip_count": 1,
                "flash_layout": "standard",
                "support_tier": "production",
                "evidence_level": "sustained-soak",
                "runtime_mode": "mining",
                "install_policy": "production",
                "release_scope": "public",
                "package_policy": "public",
                "blockers": [],
                "promotion_receipt_id": "sample-board-unit-a-20260823",
            }
        ],
    }


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence_root = root / "hardware-evidence"
        self.receipts = self.evidence_root / "receipts"
        self.artifacts = self.evidence_root / "artifacts"
        self.receipts.mkdir(parents=True)
        self.artifacts.mkdir()
        self.matrix = sample_matrix()
        self.target = self.matrix["targets"][0]
        self.receipt_path = self.receipts / "sample-board-unit-a-20260823.json"
        gates = {}
        self.gate_artifacts: dict[str, Path] = {}
        for gate_name in required_production_gates(self.matrix, self.target):
            artifact = self.artifacts / f"{gate_name}.json"
            artifact.write_text(
                json.dumps(self.gate_artifact(gate_name), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.gate_artifacts[gate_name] = artifact
            gates[gate_name] = {
                "passed": True,
                "artifact": f"artifacts/{artifact.name}",
                "sha256": sha256_file(artifact),
            }
        candidate = {
            "schema": 1,
            "product": "DCENT_OS for ESP",
            "authority": "unreleased-exact-binary-promotion-candidate",
            "disposition": "qualification-only-not-publishable",
            "publishable": False,
            "board_target": self.target["board_target"],
            "receipt_id": self.target["promotion_receipt_id"],
            "source": {
                "git_commit": "e" * 40,
                "source_date_epoch": "1786482223",
                "registry_sha256": "f" * 64,
                "firmware_version": "1.0.0",
                "git_dirty": False,
            },
            "registry_row": self.target,
            "required_gates": required_production_gates(self.matrix, self.target),
        }
        candidate["candidate_id"] = candidate_id(candidate)
        self.candidate_path = self.artifacts / "promotion-candidate.json"
        self.candidate_path.write_text(
            json.dumps(candidate, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt = {
            "schema": 1,
            "receipt_id": self.target["promotion_receipt_id"],
            "board_target": self.target["board_target"],
            "device_model": self.target["device_model"],
            "unit_fingerprint_sha256": "a" * 64,
            "firmware": {"version": "1.0.0", "update_sha256": "b" * 64},
            "promotion_candidate": {
                "candidate_id": candidate["candidate_id"],
                "descriptor_sha256": sha256_file(self.candidate_path),
                "descriptor_artifact": "artifacts/promotion-candidate.json",
                "source_git_commit": "e" * 40,
                "source_date_epoch": "1786482223",
                "source_registry_sha256": "f" * 64,
            },
            "operator": "operator@example.invalid",
            "witness": "witness@example.invalid",
            "live_device_contact": True,
            "session": {
                "started_at": "2026-08-20T00:00:00Z",
                "finished_at": "2026-08-23T00:00:00Z",
                "duration_seconds": 259_200,
            },
            "gates": gates,
        }
        self.index = {
            "schema": 1,
            "product": "DCENT_OS for ESP",
            "authority": "retained-exact-sku-hardware-receipts",
            "receipts": [],
        }
        self.reindex()

    def gate_artifact(self, gate_name: str) -> dict:
        measurements = {
            "exact-sku-identity": {
                "reported_board_target": self.target["board_target"],
                "reported_device_model": self.target["device_model"],
                "reported_asic": self.target["asic"],
                "reported_chip_count": self.target["chip_count"],
                "reported_board_version": "sample-rev-a",
                "reported_promotion_receipt_id": self.target["promotion_receipt_id"],
                "physical_label_verified": True,
                "runtime_identity_consistent": True,
            },
            "safe-boot": {
                "identity_gate_passed": True,
                "boot_completed": True,
                "sensors_ok": True,
                "boot_log_retained": True,
                "unexpected_reboots": 0,
                "uptime_seconds": 120,
            },
            "fail-safe-power-cut": {
                "trigger": "thermal-emergency",
                "hash_work_stopped": True,
                "rail_cut_observed": True,
                "independent_measurement": True,
                "within_board_limit": True,
                "recovery_required_owner_action": True,
                "cut_latency_ms": 250,
            },
            "trusted-thermal": {
                "sensor_source": "asic-die-and-regulator",
                "coverage_complete": True,
                "fault_injected": True,
                "mining_cut_observed": True,
                "rail_cut_observed": True,
                "full_fan_observed": True,
                "within_board_limit": True,
                "max_temperature_c": 78.5,
            },
            "accepted-share": {
                "accepted_share_delta": 4,
                "hashrate_5m_ghs": 500.0,
                "pool_response_observed": True,
                "post_update": True,
            },
            "ota-rollback": {
                "signed_update_accepted": True,
                "bad_signature_rejected": True,
                "rollback_exercised": True,
                "previous_slot_restored": True,
                "recovery_boot_verified": True,
                "candidate_restored_after_test": True,
                "accepted_share_after_recovery": True,
            },
            "sustained-soak": {
                "duration_seconds": 259_200,
                "uptime_reset_count": 0,
                "sensor_failure_count": 0,
                "thermal_cut_count": 0,
                "successful_samples": 17_280,
                "accepted_share_delta": 100,
                "rejection_rate_pct": 0.5,
                "absolute_heap_drift_bytes": 4096,
                "minimum_hashrate_ghs": 450.0,
            },
            "mqtt-command-roundtrip": {
                "telemetry_received": True,
                "target_watts_applied": True,
                "autotune_mode_applied": True,
                "target_temp_applied": True,
                "invalid_command_rejected": True,
                "denied_policy_read_only_verified": True,
                "stale_discovery_removed": True,
                "broker": "isolated-bench-broker",
            },
            "register-command-capture": {
                "command_capture_retained": True,
                "asic_init_observed": True,
                "reset_path_observed": True,
                "independent_decode_review": True,
                "capture_format": "logic-analyzer-vcd",
            },
            "dual-fan-proof": {
                "fan_count": 2,
                "fan_1_tach_observed": True,
                "fan_2_tach_observed": True,
                "fan_1_stall_safe_action": True,
                "fan_2_stall_safe_action": True,
            },
            "hardware-first-article": {
                "schematic_revision": "rev-a",
                "physical_article_inspected": True,
                "power_envelope_validated": True,
                "thermal_path_validated": True,
                "mining_path_validated": True,
            },
            "accessory-first-article": {
                "accessory_identity": "sample-accessory",
                "accessory_detected": True,
                "base_mining_unaffected": True,
                "disconnect_safe": True,
                "owner_safety_ack_verified": True,
            },
            "revision-identity": {
                "physical_revision": "rev-a",
                "reported_revision": "rev-a",
                "revision_match": True,
                "ambiguous_revision_refused": True,
            },
        }[gate_name]
        return {
            "schema": 1,
            "authority": "observed-exact-sku-hardware-gate",
            "gate": gate_name,
            "receipt_id": self.target["promotion_receipt_id"],
            "board_target": self.target["board_target"],
            "device_model": self.target["device_model"],
            "unit_fingerprint_sha256": "a" * 64,
            "firmware": {"version": "1.0.0", "update_sha256": "b" * 64},
            "operator": "operator@example.invalid",
            "witness": "witness@example.invalid",
            "live_device_contact": True,
            "observed_at": "2026-08-22T00:00:00Z",
            "passed": True,
            "measurements": measurements,
        }

    def reindex(self) -> None:
        self.receipt_path.write_text(
            json.dumps(self.receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.index["receipts"] = [
            {
                "receipt_id": self.receipt["receipt_id"],
                "path": f"receipts/{self.receipt_path.name}",
                "sha256": sha256_file(self.receipt_path),
            }
        ]


class HardwareEvidenceTests(unittest.TestCase):
    def test_every_semantic_gate_has_a_passing_typed_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            contract = fixture.matrix["production_gate_contract"]
            for gate_name in sorted(SEMANTIC_GATES):
                artifact = fixture.gate_artifact(gate_name)
                self.assertEqual(
                    _validate_gate_measurements(
                        gate_name,
                        artifact["measurements"],
                        fixture.target,
                        contract,
                    ),
                    [],
                    gate_name,
                )

    def test_current_registry_has_no_unbacked_production_claim(self) -> None:
        matrix = load_manifest()
        index = load_evidence_index()
        self.assertEqual(production_claim_errors(matrix, index, ROOT), [])
        self.assertFalse(any(target["blockers"] == [] for target in matrix["targets"]))
        self.assertFalse(any(target["support_tier"] == "production" for target in matrix["targets"]))

    def test_metadata_only_production_claim_is_refused(self) -> None:
        matrix = sample_matrix()
        empty = {
            "schema": 1,
            "product": "DCENT_OS for ESP",
            "authority": "retained-exact-sku-hardware-receipts",
            "receipts": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hardware-evidence").mkdir()
            errors = production_claim_errors(matrix, empty, root)
        self.assertTrue(any("absent from the evidence index" in error for error in errors))

    def test_valid_exact_sku_receipt_qualifies_production(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            self.assertEqual(
                validate_evidence_index(fixture.index, fixture.matrix, fixture.root), []
            )
            status = promotion_status(
                fixture.index, fixture.matrix, fixture.target, fixture.root
            )
            self.assertTrue(status["qualified"])
            self.assertEqual(
                production_claim_errors(fixture.matrix, fixture.index, fixture.root), []
            )
            ready = readiness(
                fixture.target,
                True,
                fixture.matrix,
                fixture.index,
                fixture.receipt["firmware"]["update_sha256"],
                fixture.receipt["firmware"]["version"],
                True,
                fixture.root,
            )
            self.assertTrue(ready["production_ready"])

    def test_stale_or_unsigned_package_cannot_reuse_a_valid_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            stale = readiness(
                fixture.target,
                True,
                fixture.matrix,
                fixture.index,
                "c" * 64,
                fixture.receipt["firmware"]["version"],
                True,
                fixture.root,
            )
            self.assertFalse(stale["production_ready"])
            self.assertFalse(stale["receipt_firmware_matches_package"])
            relabeled = readiness(
                fixture.target,
                True,
                fixture.matrix,
                fixture.index,
                fixture.receipt["firmware"]["update_sha256"],
                "1.0.1",
                True,
                fixture.root,
            )
            self.assertFalse(relabeled["production_ready"])
            self.assertFalse(relabeled["receipt_firmware_matches_package"])
            unsigned = readiness(
                fixture.target,
                True,
                fixture.matrix,
                fixture.index,
                fixture.receipt["firmware"]["update_sha256"],
                fixture.receipt["firmware"]["version"],
                False,
                fixture.root,
            )
            self.assertFalse(unsigned["production_ready"])
            self.assertFalse(unsigned["production_signatures_verified"])

    def test_tampered_gate_artifact_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            fixture.gate_artifacts["accepted-share"].write_text(
                "tampered\n", encoding="utf-8"
            )
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(any("accepted-share artifact sha256 mismatch" in error for error in errors))

    def test_opaque_or_semantically_empty_artifact_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            artifact = fixture.gate_artifacts["accepted-share"]
            value = fixture.gate_artifact("accepted-share")
            value["measurements"] = {}
            artifact.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            fixture.receipt["gates"]["accepted-share"]["sha256"] = sha256_file(artifact)
            fixture.reindex()
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(
                any("accepted_share_delta must be at least one" in error for error in errors)
            )

    def test_receipt_cannot_be_rebound_to_another_device_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            fixture.receipt["device_model"] = "some_other_model"
            fixture.reindex()
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(any("device_model does not match" in error for error in errors))

    def test_short_soak_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            fixture.receipt["session"] = {
                "started_at": "2026-08-22T00:00:00Z",
                "finished_at": "2026-08-23T00:00:00Z",
                "duration_seconds": 86_400,
            }
            fixture.reindex()
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(any("sustained soak must be at least" in error for error in errors))

    def test_failed_gate_cannot_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            fixture.receipt["gates"]["ota-rollback"]["passed"] = False
            fixture.reindex()
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(any("gate ota-rollback must pass" in error for error in errors))

    def test_receipt_and_artifact_paths_cannot_escape_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = EvidenceFixture(Path(directory))
            fixture.index["receipts"][0]["path"] = "../outside.json"
            errors = validate_evidence_index(fixture.index, fixture.matrix, fixture.root)
            self.assertTrue(any("must stay under receipts/" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
