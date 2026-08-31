#!/usr/bin/env python3
"""Host-only tests for immutable A1246 first-light/bench/endurance receipts."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("k210_bench_endurance_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_bench_endurance_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class K210BenchEnduranceReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest: dict[str, object] = {}
        self.target_id = "a1246"
        self.unit_label = "a1246-test-unit"
        self.fingerprint = "1" * 64
        self.variant = "a1246-a3200lc-plus-x2"
        self.bundle_index = 0
        self.ids = {
            "discovery": "2" * 64,
            "fixture": "3" * 64,
            "fixture_set": "4" * 64,
            "capture": "5" * 64,
            "capture_set": "6" * 64,
            "recovery": "7" * 64,
            "stock_set": "8" * 64,
            "boot": "9" * 64,
            "replacement": "a" * 64,
            "artifact_set": "b" * 64,
            "artifact": "c" * 64,
            "route_adjudication": "d" * 64,
            "restoration": "e" * 64,
            "rollback": "f" * 64,
            "interface": "0" * 64,
            "no_clobber": "1" * 64,
        }
        self.selected_route = "native_aes0_flash"
        self.controller_board_revision = "mm3v2-x2-rev-test"
        self.replacement_firmware_version = "20260824_dcent_test"
        self.predecessors = self._predecessors()
        self.validator_patches = []
        for module in (
            bench.discovery,
            bench.fixture,
            bench.capture,
            bench.recovery,
            bench.boot,
            bench.route_replacement,
            bench.route_rollback,
        ):
            validator_patch = patch.object(
                module, "_validate_receipt", return_value=None
            )
            validator_patch.start()
            self.validator_patches.append(validator_patch)

    def tearDown(self) -> None:
        for validator_patch in reversed(self.validator_patches):
            validator_patch.stop()
        self.temporary.cleanup()

    def _key(self, name: str) -> tuple[Path, Path]:
        private = self.root / name
        process = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"{name}@test.invalid",
                "-f",
                str(private),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        return private, Path(f"{private}.pub")

    def _stage_keys(
        self, qualification_class: str, prefix: str
    ) -> tuple[dict[str, Path], dict[str, Path]]:
        private: dict[str, Path] = {}
        public: dict[str, Path] = {}
        for role in bench.SIGNING_CONTRACTS[qualification_class]:
            private[role], public[role] = self._key(f"{prefix}-{role}-key")
        return private, public

    def _verify(self, bundle: Path, public: dict[str, Path]) -> dict[str, object]:
        return bench.verify_bundle(
            self.manifest,
            bundle,
            public["operator"],
            public.get("witness"),
            protocol_reviewer_public_key=public.get("protocol_reviewer"),
            safety_reviewer_public_key=public.get("safety_reviewer"),
        )

    def _common(self) -> dict[str, object]:
        return {
            "target_id": self.target_id,
            "unit_fingerprint_sha256": self.fingerprint,
            "unit_label": self.unit_label,
        }

    def _rollback(self) -> dict[str, object]:
        return {
            "artifact_set_sha256": self.ids["artifact_set"],
            "boot_policy_receipt_id": self.ids["boot"],
            "discovery_receipt_id": self.ids["discovery"],
            "interface_qualification_sha256": self.ids["interface"],
            "receipt_id": self.ids["rollback"],
            "recovery_receipt_id": self.ids["recovery"],
            "route_replacement_receipt_id": self.ids["replacement"],
            "route_adjudication_sha256": self.ids["route_adjudication"],
            "selected_route": self.selected_route,
            "stock_backup_set_sha256": self.ids["stock_set"],
            "no_clobber_sha256": self.ids["no_clobber"],
            "stock_restoration_sha256": self.ids["restoration"],
            **self._common(),
        }

    def _installed_artifact_kind(self) -> str:
        if self.selected_route == "native_aes0_flash":
            return "firmware_aup"
        if self.selected_route in {
            "rom_isp_sram_bootstrap",
            "jtag_sram_bootstrap",
        }:
            return "firmware_raw"
        return "controller_firmware_artifact"

    def _installed_artifact_member(self) -> str:
        if self.selected_route == "native_aes0_flash":
            return "aup"
        if self.selected_route in {
            "rom_isp_sram_bootstrap",
            "jtag_sram_bootstrap",
        }:
            return "raw"
        return "controller"

    def _predecessors(self) -> dict[str, dict[str, object]]:
        common = self._common()
        values = {
            "discovery_receipt_copy": {
                "receipt_id": self.ids["discovery"],
                **common,
            },
            "fixture_receipt_copy": {
                "discovery_receipt_id": self.ids["discovery"],
                "fixture_evidence_set_sha256": self.ids["fixture_set"],
                "fixture_identity": {
                    "controller_board_revision": self.controller_board_revision,
                    "variant_profile_id": self.variant,
                },
                "receipt_id": self.ids["fixture"],
                **common,
            },
            "capture_receipt_copy": {
                "capture_set_sha256": self.ids["capture_set"],
                "discovery_receipt_id": self.ids["discovery"],
                "fixture_receipt_id": self.ids["fixture"],
                "receipt_id": self.ids["capture"],
                "variant_profile_id": self.variant,
                **common,
            },
            "recovery_receipt_copy": {
                "discovery_receipt_id": self.ids["discovery"],
                "receipt_id": self.ids["recovery"],
                "stock_backup_set_sha256": self.ids["stock_set"],
                **common,
            },
            "boot_policy_receipt_copy": {
                "discovery_receipt_id": self.ids["discovery"],
                "receipt_id": self.ids["boot"],
                "recovery_receipt_id": self.ids["recovery"],
                "stock_backup_set_sha256": self.ids["stock_set"],
                **common,
            },
            "route_replacement_receipt_copy": {
                "artifact_set_sha256": self.ids["artifact_set"],
                "boot_policy_receipt_id": self.ids["boot"],
                "builds": [
                    {"artifacts": {self._installed_artifact_member(): "deployable-a"}},
                    {"artifacts": {self._installed_artifact_member(): "deployable-b"}},
                ],
                "discovery_receipt_id": self.ids["discovery"],
                "evidence": [
                    {
                        "id": "deployable-a",
                        "kind": self._installed_artifact_kind(),
                        "sha256": self.ids["artifact"],
                    },
                    {
                        "id": "deployable-b",
                        "kind": self._installed_artifact_kind(),
                        "sha256": self.ids["artifact"],
                    },
                ],
                "firmware": {
                    "firmware_version": self.replacement_firmware_version,
                },
                "interface_qualification_sha256": self.ids["interface"],
                "receipt_id": self.ids["replacement"],
                "recovery_receipt_id": self.ids["recovery"],
                "route_selection": {
                    "adjudication_sha256": self.ids["route_adjudication"],
                    "selected_route": self.selected_route,
                },
                "stock_backup_set_sha256": self.ids["stock_set"],
                **common,
            },
        }
        values["route_rollback_receipt_copy"] = self._rollback()
        return values

    def _set_route(self, selected_route: str) -> None:
        self.selected_route = selected_route
        self.predecessors = self._predecessors()

    def _times(self, qualification_class: str) -> tuple[datetime, datetime]:
        if qualification_class == bench.QUALIFICATION_FIRST_LIGHT:
            started = datetime(2026, 8, 24, 18, 0, 0)
            return started, started + timedelta(minutes=10)
        if qualification_class == bench.QUALIFICATION_BENCH:
            started = datetime(2026, 8, 24, 19, 0, 0)
            return started, started + timedelta(hours=1)
        started = datetime(2026, 8, 24, 21, 0, 0)
        return started, started + timedelta(hours=6)

    @staticmethod
    def _utc(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _records(
        self,
        qualification_class: str,
        descriptor: dict[str, object],
        prior_receipt: dict[str, object] | None,
    ) -> dict[str, object]:
        started, completed = self._times(qualification_class)
        authorization = descriptor["authorization"]
        assert isinstance(authorization, dict)
        session_id = descriptor["session_id"]
        actions = bench.ACTION_SEQUENCES[qualification_class]
        records: dict[str, object] = {
            **deepcopy(self.predecessors),
            "authorization_record": deepcopy(authorization),
            "session_log": {
                "authorization_reference": authorization["operator_reference"],
                "deviations": [],
                "events": [
                    {
                        "action": action,
                        "detail": f"completed authorized {action}",
                        "time_utc": self._utc(started + timedelta(seconds=index + 1)),
                    }
                    for index, action in enumerate(actions)
                ],
                "faults": [],
                "session_id": session_id,
                "stop_events": [],
            },
            "safety_record": {
                "closed_chassis": True,
                "cooling_ready_before_hash_power": True,
                "cutoff_feedback_available": True,
                "emergency_stop_owner": authorization["emergency_stop_owner"],
                "fixture_receipt_id": self.ids["fixture"],
                "independent_cutoff_available": True,
                "route_rollback_receipt_id": self.ids["rollback"],
                "safe_terminal_state_confirmed": True,
                "watchdog_active": True,
            },
            "cooling_telemetry_record": {
                "cooling_faults": [],
                "cooling_ready_before_hash_power": True,
                "fan_or_pump_count": 4,
                "fresh_throughout": True,
                "max_gap_ms": 100,
                "max_temperature_millicelsius": 65000,
                "sample_count": 100,
                "session_id": session_id,
                "temperature_limit_millicelsius": 85000,
            },
            "cutoff_telemetry_record": {
                "assertion_tested_before_session": True,
                "cooling_continued_after_cutoff": True,
                "feedback_fresh_throughout": True,
                "hash_power_default_off": True,
                "independent_cutoff_available": True,
                "latched_faults": [],
                "measured_cutoff_response_ms": 100,
                "rail_feedback_off_at_end": True,
                "session_id": session_id,
            },
            "runtime_telemetry_record": {
                "board_count": 2,
                "firmware_artifact_sha256": self.ids["artifact"],
                "max_gap_ms": 100,
                "sample_count": 100,
                "sensor_read_errors": 0,
                "session_id": session_id,
                "stale_samples": 0,
                "unexpected_restarts": 0,
                "uptime_seconds": int((completed - started).total_seconds()),
                "watchdog_faults": 0,
            },
            "pool_session_record": {
                "connected_at_utc": self._utc(started + timedelta(seconds=30)),
                "credentials_redacted": True,
                "disconnected_at_utc": self._utc(completed - timedelta(seconds=30)),
                "endpoint_id": authorization["pool_endpoint_id"],
                "jobs_received": 10,
                "network_scope": "operator_controlled_isolated_bench",
                "session_id": session_id,
                "transport_errors": 0,
                "unexpected_reconnects": 0,
            },
            "share_accounting_record": {
                "accepted": 2,
                "duplicate": 0,
                "endpoint_id": authorization["pool_endpoint_id"],
                "first_accepted_at_utc": self._utc(started + timedelta(minutes=2)),
                "invalid": 0,
                "last_accepted_at_utc": self._utc(started + timedelta(minutes=3)),
                "pool_accepted": 2,
                "rejected": 0,
                "session_id": session_id,
                "stale": 0,
                "submitted": 2,
            },
        }
        if qualification_class == bench.QUALIFICATION_FIRST_LIGHT:
            records["first_light_record"] = {
                "accepted_share_observed": True,
                "cooling_preceded_hash_power": True,
                "cutoff_feedback_confirmed_before_hash_power": True,
                "duration_seconds": 300,
                "first_hash_at_utc": self._utc(started + timedelta(minutes=1)),
                "first_share_at_utc": self._utc(started + timedelta(minutes=2)),
                "hash_enable_after_prerequisites": True,
                "hash_power_started": True,
                "max_power_w": 1000,
                "max_temperature_millicelsius": 60000,
                "safe_idle_observed": True,
                "sensors_fresh_before_hash_power": True,
                "session_id": session_id,
                "watchdog_confirmed_before_hash_power": True,
            }
        elif qualification_class == bench.QUALIFICATION_BENCH:
            records["bounded_mining_record"] = {
                "accepted_shares": 2,
                "configuration_persisted_after_reboot": True,
                "controlled_reboot_passed": True,
                "duration_seconds": 300,
                "max_power_w": 1000,
                "max_temperature_millicelsius": 60000,
                "session_id": session_id,
                "unexpected_errors": 0,
            }
            records["prior_first_light_receipt_copy"] = prior_receipt
        else:
            records["fault_campaign_record"] = {
                "faults": [
                    {
                        "cutoff_confirmed": True,
                        "detected": True,
                        "fault_type": fault_type,
                        "latched": True,
                        "recovered": True,
                        "response_ms": 100,
                        "safe_state_reached": True,
                    }
                    for fault_type in sorted(bench.REQUIRED_FAULT_TYPES)
                ],
                "session_id": session_id,
            }
            records["endurance_record"] = {
                "accepted_shares": 2,
                "duration_seconds": bench.MIN_ENDURANCE_DURATION_SECONDS,
                "max_power_w": 1000,
                "max_temperature_millicelsius": 65000,
                "memory_growth_bytes": 0,
                "phase_names": ["cold", "steady", "hot_soak", "recovery"],
                "session_id": session_id,
                "unexpected_errors": 0,
                "unexpected_restarts": 0,
            }
            records["prior_bench_receipt_copy"] = prior_receipt
        return records

    def _descriptor(
        self,
        qualification_class: str,
        evidence_root: Path,
        prior_receipt: dict[str, object] | None = None,
    ) -> dict[str, object]:
        started, completed = self._times(qualification_class)
        maximum_duration = int((completed - started).total_seconds())
        descriptor: dict[str, object] = {
            "actions_performed": dict(bench.POSITIVE_ACTIONS[qualification_class]),
            "authorization": {
                "authorized_actions": sorted(
                    bench._actions_for_class(qualification_class)
                ),
                "emergency_stop_owner": f"{qualification_class}-operator",
                "issued_at_utc": self._utc(started - timedelta(minutes=10)),
                "maximum_cutoff_response_ms": 500,
                "maximum_duration_seconds": maximum_duration,
                "maximum_hash_power_w": 3500,
                "maximum_telemetry_gap_ms": 1000,
                "maximum_temperature_millicelsius": 85000,
                "operator_reference": f"authorized-{qualification_class}",
                "pool_endpoint_id": "isolated-pool-01",
                "valid_from_utc": self._utc(started - timedelta(minutes=5)),
                "valid_until_utc": self._utc(completed + timedelta(minutes=5)),
            },
            "boot_policy_receipt_id": self.ids["boot"],
            "capture_receipt_id": self.ids["capture"],
            "capture_set_sha256": self.ids["capture_set"],
            "completed_at_utc": self._utc(completed),
            "controller_board_revision": self.controller_board_revision,
            "discovery_receipt_id": self.ids["discovery"],
            "evidence": bench._template_evidence(qualification_class),
            "fixture_evidence_set_sha256": self.ids["fixture_set"],
            "fixture_receipt_id": self.ids["fixture"],
            "installed_artifact_sha256": self.ids["artifact"],
            "kind": bench.DESCRIPTOR_KIND,
            "operator_id": f"{qualification_class}-operator",
            "outcome": "passed",
            "prior_stage_receipt_id": (
                prior_receipt["receipt_id"] if prior_receipt is not None else None
            ),
            "prior_stage_evidence_set_sha256": (
                prior_receipt["evidence_set_sha256"]
                if prior_receipt is not None
                else None
            ),
            "qualification_class": qualification_class,
            "protocol_reviewer_id": (
                f"{qualification_class}-protocol-reviewer"
                if qualification_class == bench.QUALIFICATION_FIRST_LIGHT
                else None
            ),
            "recovery_receipt_id": self.ids["recovery"],
            "artifact_set_sha256": self.ids["artifact_set"],
            "interface_qualification_sha256": self.ids["interface"],
            "route_replacement_receipt_id": self.ids["replacement"],
            "replacement_firmware_version": self.replacement_firmware_version,
            "route_rollback_receipt_id": self.ids["rollback"],
            "route_adjudication_sha256": self.ids["route_adjudication"],
            "schema_version": bench.SCHEMA_VERSION,
            "scope": bench.SCOPE,
            "safety_reviewer_id": (
                f"{qualification_class}-safety-reviewer"
                if qualification_class == bench.QUALIFICATION_FIRST_LIGHT
                else None
            ),
            "selected_route": self.selected_route,
            "session_id": f"{qualification_class}-session",
            "started_at_utc": self._utc(started),
            "stock_backup_set_sha256": self.ids["stock_set"],
            "no_clobber_sha256": self.ids["no_clobber"],
            "stock_restoration_sha256": self.ids["restoration"],
            "target_id": self.target_id,
            "unit_fingerprint_sha256": self.fingerprint,
            "unit_label": self.unit_label,
            "variant_profile_id": self.variant,
            "witness_id": (
                None
                if qualification_class == bench.QUALIFICATION_FIRST_LIGHT
                else f"{qualification_class}-witness"
            ),
        }
        records = self._records(qualification_class, descriptor, prior_receipt)
        for item in descriptor["evidence"]:
            path = evidence_root / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bench.canonical_json_bytes(records[item["kind"]]))
        return descriptor

    def _bundle(
        self,
        qualification_class: str,
        prior_receipt: dict[str, object] | None = None,
    ) -> tuple[Path, dict[str, object], dict[str, Path]]:
        self.bundle_index += 1
        stage = f"{qualification_class.replace('_', '-')}-{self.bundle_index}"
        evidence_root = self.root / f"{stage}-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(qualification_class, evidence_root, prior_receipt)
        descriptor_path = self.root / f"{stage}-descriptor.json"
        descriptor_path.write_bytes(bench.canonical_json_bytes(descriptor))
        private, public = self._stage_keys(qualification_class, stage)
        bundle = self.root / f"{stage}-bundle"
        receipt = bench.create_bundle(
            self.manifest,
            descriptor_path,
            evidence_root,
            private["operator"],
            bundle,
            private.get("witness"),
            protocol_reviewer_private_key=private.get("protocol_reviewer"),
            safety_reviewer_private_key=private.get("safety_reviewer"),
        )
        return bundle, receipt, public

    def test_three_immutable_stage_receipts_and_gate_progression(self) -> None:
        first_bundle, first, first_keys = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        first_result = self._verify(first_bundle, first_keys)
        self.assertTrue(first_result["first_light_gate_eligible"])
        self.assertFalse(first_result["bench_mining_gate_eligible"])
        self.assertFalse(first_result["endurance_faults_gate_eligible"])

        bench_bundle, bounded, bench_keys = self._bundle(
            bench.QUALIFICATION_BENCH, first
        )
        bench_result = self._verify(bench_bundle, bench_keys)
        self.assertTrue(bench_result["first_light_gate_eligible"])
        self.assertTrue(bench_result["bench_mining_gate_eligible"])
        self.assertFalse(bench_result["endurance_faults_gate_eligible"])

        endurance_bundle, _, endurance_keys = self._bundle(
            bench.QUALIFICATION_ENDURANCE, bounded
        )
        endurance_result = self._verify(endurance_bundle, endurance_keys)
        self.assertTrue(endurance_result["first_light_gate_eligible"])
        self.assertTrue(endurance_result["bench_mining_gate_eligible"])
        self.assertTrue(endurance_result["endurance_faults_gate_eligible"])
        self.assertFalse(endurance_result["authority_granted"])
        self.assertEqual(endurance_result["selected_route"], self.selected_route)
        self.assertEqual(
            endurance_result["route_adjudication_sha256"],
            self.ids["route_adjudication"],
        )
        self.assertEqual(
            endurance_result["stock_restoration_sha256"], self.ids["restoration"]
        )
        self.assertEqual(
            endurance_result["route_replacement_receipt_id"],
            self.ids["replacement"],
        )
        self.assertEqual(
            endurance_result["route_rollback_receipt_id"], self.ids["rollback"]
        )
        self.assertEqual(
            endurance_result["artifact_set_sha256"], self.ids["artifact_set"]
        )
        self.assertEqual(
            endurance_result["interface_qualification_sha256"],
            self.ids["interface"],
        )
        self.assertEqual(endurance_result["no_clobber_sha256"], self.ids["no_clobber"])
        self.assertEqual(
            endurance_result["replacement_firmware_version"],
            self.replacement_firmware_version,
        )
        self.assertEqual(
            endurance_result["controller_board_revision"],
            self.controller_board_revision,
        )
        self.assertEqual(
            endurance_result["prior_stage_receipt_id"], bounded["receipt_id"]
        )
        self.assertEqual(
            endurance_result["prior_stage_evidence_set_sha256"],
            bounded["evidence_set_sha256"],
        )
        self.assertEqual(
            set(first["signing"]),
            {
                "operator",
                "protocol_reviewer",
                "safety_reviewer",
            },
        )
        self.assertIsNone(first_result["witness_key_id_sha256"])
        self.assertIsNotNone(first_result["protocol_reviewer_key_id_sha256"])
        self.assertIsNotNone(first_result["safety_reviewer_key_id_sha256"])

        self.assertNotEqual(
            first["signing"]["operator"]["namespace"],
            bounded["signing"]["operator"]["namespace"],
        )

    def test_non_aes_rom_isp_full_progression(self) -> None:
        self._set_route("rom_isp_sram_bootstrap")
        first_bundle, first, first_keys = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        self.assertTrue(
            self._verify(first_bundle, first_keys)["first_light_gate_eligible"]
        )
        bounded_bundle, bounded, bounded_keys = self._bundle(
            bench.QUALIFICATION_BENCH, first
        )
        self.assertTrue(
            self._verify(bounded_bundle, bounded_keys)["bench_mining_gate_eligible"]
        )
        endurance_bundle, _, endurance_keys = self._bundle(
            bench.QUALIFICATION_ENDURANCE, bounded
        )
        result = self._verify(endurance_bundle, endurance_keys)
        self.assertTrue(result["endurance_faults_gate_eligible"])
        self.assertEqual(result["selected_route"], "rom_isp_sram_bootstrap")
        self.assertEqual(result["installed_artifact_sha256"], self.ids["artifact"])

    def test_each_canonical_route_admits_its_qualified_artifact_kind(self) -> None:
        for route in bench.ROUTES:
            with self.subTest(route=route):
                self._set_route(route)
                bundle, _, keys = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
                result = self._verify(bundle, keys)
                self.assertTrue(result["first_light_gate_eligible"])
                self.assertEqual(result["selected_route"], route)
                self.assertEqual(
                    result["installed_artifact_sha256"], self.ids["artifact"]
                )

    def test_first_light_rejects_hash_enable_before_safety_prerequisites(self) -> None:
        evidence_root = self.root / "bad-first-light-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(bench.QUALIFICATION_FIRST_LIGHT, evidence_root)
        record_path = evidence_root / "records/first-light.json"
        record = json.loads(record_path.read_text(encoding="ascii"))
        record["hash_enable_after_prerequisites"] = False
        record_path.write_bytes(bench.canonical_json_bytes(record))
        private, _ = self._stage_keys(bench.QUALIFICATION_FIRST_LIGHT, "bad-first")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "first-light"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                private["operator"],
                protocol_reviewer_private_key=private["protocol_reviewer"],
                safety_reviewer_private_key=private["safety_reviewer"],
            )
        record["hash_enable_after_prerequisites"] = True
        record_path.write_bytes(bench.canonical_json_bytes(record))
        log_path = evidence_root / "records/session-log.json"
        session_log = json.loads(log_path.read_text(encoding="ascii"))
        events = session_log["events"]
        hash_index = next(
            index
            for index, item in enumerate(events)
            if item["action"] == "hash_enable_after_safety_prerequisites"
        )
        idle_index = next(
            index
            for index, item in enumerate(events)
            if item["action"] == "staged_safe_idle"
        )
        events[hash_index]["action"], events[idle_index]["action"] = (
            events[idle_index]["action"],
            events[hash_index]["action"],
        )
        log_path.write_bytes(bench.canonical_json_bytes(session_log))
        with self.assertRaisesRegex(bench.BenchEnduranceError, "session log"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                private["operator"],
                protocol_reviewer_private_key=private["protocol_reviewer"],
                safety_reviewer_private_key=private["safety_reviewer"],
            )

    def test_bench_rejects_non_immediate_or_failed_predecessor(self) -> None:
        stopped_root = self.root / "stopped-prior-evidence"
        stopped_root.mkdir()
        stopped_descriptor = self._descriptor(
            bench.QUALIFICATION_FIRST_LIGHT, stopped_root
        )
        stopped_descriptor["outcome"] = "stopped"
        stopped_log_path = stopped_root / "records/session-log.json"
        stopped_log = json.loads(stopped_log_path.read_text(encoding="ascii"))
        stopped_log["stop_events"] = [
            {
                "code": "operator_stop",
                "detail": "first-light stopped before qualification",
                "time_utc": "2026-08-24T18:05:00Z",
            }
        ]
        stopped_log_path.write_bytes(bench.canonical_json_bytes(stopped_log))
        stopped_private, _ = self._stage_keys(
            bench.QUALIFICATION_FIRST_LIGHT, "stopped-prior"
        )
        failed, _ = bench.build_receipt(
            self.manifest,
            stopped_descriptor,
            stopped_root,
            stopped_private["operator"],
            protocol_reviewer_private_key=stopped_private["protocol_reviewer"],
            safety_reviewer_private_key=stopped_private["safety_reviewer"],
        )
        evidence_root = self.root / "bad-bench-predecessor"
        evidence_root.mkdir()
        descriptor = self._descriptor(bench.QUALIFICATION_BENCH, evidence_root, failed)
        operator_private, _ = self._key("bad-bench-operator")
        witness_private, _ = self._key("bad-bench-witness")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "immediate predecessor"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                operator_private,
                witness_private,
            )

    def test_route_adjudication_restoration_and_predecessor_splices_fail(self) -> None:
        mutations = {
            "selected_route": "rom_isp_sram_bootstrap",
            "route_adjudication_sha256": "0" * 64,
            "artifact_set_sha256": "0" * 64,
            "interface_qualification_sha256": "2" * 64,
            "no_clobber_sha256": "2" * 64,
            "stock_restoration_sha256": "0" * 64,
            "route_replacement_receipt_id": "0" * 64,
            "installed_artifact_sha256": "0" * 64,
        }
        private, _ = self._stage_keys(
            bench.QUALIFICATION_FIRST_LIGHT, "predecessor-splice"
        )
        for field, value in mutations.items():
            with self.subTest(field=field):
                evidence_root = self.root / f"splice-{field}-evidence"
                evidence_root.mkdir()
                descriptor = self._descriptor(
                    bench.QUALIFICATION_FIRST_LIGHT, evidence_root
                )
                descriptor[field] = value
                with self.assertRaisesRegex(bench.BenchEnduranceError, "exact-join"):
                    bench.build_receipt(
                        self.manifest,
                        descriptor,
                        evidence_root,
                        private["operator"],
                        protocol_reviewer_private_key=private["protocol_reviewer"],
                        safety_reviewer_private_key=private["safety_reviewer"],
                    )

        _, first, _ = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        evidence_root = self.root / "prior-stage-splice-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(bench.QUALIFICATION_BENCH, evidence_root, first)
        descriptor["prior_stage_evidence_set_sha256"] = "0" * 64
        bench_private, _ = self._stage_keys(
            bench.QUALIFICATION_BENCH, "prior-stage-splice"
        )
        with self.assertRaisesRegex(bench.BenchEnduranceError, "exact-join"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                bench_private["operator"],
                bench_private["witness"],
            )

    def test_stopped_first_light_is_signed_negative_evidence(self) -> None:
        evidence_root = self.root / "stopped-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(bench.QUALIFICATION_FIRST_LIGHT, evidence_root)
        descriptor["outcome"] = "stopped"
        log_path = evidence_root / "records/session-log.json"
        log = json.loads(log_path.read_text(encoding="ascii"))
        log["stop_events"] = [
            {
                "code": "temperature_limit",
                "detail": "operator stopped before further work",
                "time_utc": "2026-08-24T18:05:00Z",
            }
        ]
        log_path.write_bytes(bench.canonical_json_bytes(log))
        descriptor_path = self.root / "stopped-descriptor.json"
        descriptor_path.write_bytes(bench.canonical_json_bytes(descriptor))
        private, public = self._stage_keys(bench.QUALIFICATION_FIRST_LIGHT, "stopped")
        bundle = self.root / "stopped-bundle"
        bench.create_bundle(
            self.manifest,
            descriptor_path,
            evidence_root,
            private["operator"],
            bundle,
            protocol_reviewer_private_key=private["protocol_reviewer"],
            safety_reviewer_private_key=private["safety_reviewer"],
        )
        result = self._verify(bundle, public)
        self.assertEqual(result["outcome"], "stopped")
        self.assertFalse(result["first_light_gate_eligible"])
        self.assertFalse(result["authority_granted"])

    def test_endurance_requires_every_fault_and_tamper_is_rejected(self) -> None:
        _, first, _ = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        _, bounded, _ = self._bundle(bench.QUALIFICATION_BENCH, first)
        evidence_root = self.root / "bad-endurance-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(
            bench.QUALIFICATION_ENDURANCE, evidence_root, bounded
        )
        fault_path = evidence_root / "records/fault-campaign.json"
        faults = json.loads(fault_path.read_text(encoding="ascii"))
        faults["faults"].pop()
        fault_path.write_bytes(bench.canonical_json_bytes(faults))
        operator_private, _ = self._key("bad-endurance-operator")
        witness_private, _ = self._key("bad-endurance-witness")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "fault campaign"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                operator_private,
                witness_private,
            )

        first_bundle, _, first_keys = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        pool_path = (
            first_bundle / bench.EVIDENCE_DIRECTORY / "records/pool-session.json"
        )
        pool_path.write_bytes(b"{}")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "digest or size"):
            self._verify(first_bundle, first_keys)

    def test_same_key_and_extra_member_fail_closed(self) -> None:
        evidence_root = self.root / "same-key-evidence"
        evidence_root.mkdir()
        descriptor = self._descriptor(bench.QUALIFICATION_FIRST_LIGHT, evidence_root)
        private, _ = self._key("same-key")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "keys must be distinct"):
            bench.build_receipt(
                self.manifest,
                descriptor,
                evidence_root,
                private,
                protocol_reviewer_private_key=private,
                safety_reviewer_private_key=private,
            )

        bundle, _, public = self._bundle(bench.QUALIFICATION_FIRST_LIGHT)
        (bundle / "extra.txt").write_text("unexpected", encoding="ascii")
        with self.assertRaisesRegex(bench.BenchEnduranceError, "member set"):
            self._verify(bundle, public)


if __name__ == "__main__":
    unittest.main()
