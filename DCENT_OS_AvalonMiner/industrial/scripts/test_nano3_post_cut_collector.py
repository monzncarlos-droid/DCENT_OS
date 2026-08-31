#!/usr/bin/env python3
"""Adversarial tests for the Nano 3 post-cut receipt compiler."""

from __future__ import annotations

import contextlib
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT = Path(__file__).with_name("nano3_post_cut_collector.py")
SPEC = importlib.util.spec_from_file_location("nano3_post_cut_collector", SCRIPT)
assert SPEC and SPEC.loader
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)


def h(byte: str) -> str:
    return hashlib.sha256(byte.encode()).hexdigest()


def approved_plan() -> dict:
    return {
        "schema": collector.PLAN_SCHEMA,
        "status": collector.APPROVED_STATUS,
        "session": {
            "session_id": "nano3-post-cut-test-001",
            "session_nonce_sha256": h("nonce"),
            "authorization_ref": "AUTH-A-TEST-001",
            "authorized_from_utc": "2026-08-24T00:00:00Z",
            "authorized_until_utc": "2026-08-24T01:00:00Z",
            "exact_unit_fingerprint_sha256": h("unit"),
            "operator_public_key_sha256": h("operator"),
            "action": collector.ACTION,
        },
        "sources": {
            "capture_adapter": {
                "public_key_sha256": h("adapter"),
                "identity_record_sha256": h("adapter-identity"),
                "channel_contract_record_sha256": h("adapter-channel"),
                "powered_independently_of_nano": True,
                "method": "signed_external_multichannel_export_v1",
            },
            "sensor": {
                "asset_record_sha256": h("sensor"),
                "calibration_record_sha256": h("sensor-calibration"),
                "placement_record_sha256": h("sensor-placement"),
                "identity_label": "sensor-fixture-001",
                "powered_independently_of_nano": True,
                "role": "external_hotspot_temperature",
                "channel": "temperature_c",
                "units": "degree_celsius",
                "coverage": "qualified_worst_case_hotspot_external",
            },
            "wall_meter": {
                "asset_record_sha256": h("meter"),
                "calibration_record_sha256": h("meter-calibration"),
                "channel_contract_record_sha256": h("meter-channel"),
                "identity_label": "meter-fixture-001",
                "powered_independently_of_nano": True,
                "role": "whole_unit_input_power",
                "channel": "wall_w",
                "units": "watt",
            },
        },
        "envelope": {
            "baseline_sample_count": 3,
            "minimum_observation_seconds": 120,
            "maximum_first_post_cut_delay_seconds": 1,
            "maximum_sample_gap_seconds": 11,
            "maximum_utc_monotonic_drift_seconds": 0.1,
            "maximum_temperature_c": 80,
            "maximum_post_cut_temperature_rise_c": 5,
            "maximum_positive_trend_c_per_minute": 2,
            "temperature_uncertainty_c": 0.1,
            "wall_zero_maximum_w": 1,
            "wall_uncertainty_w": 0.1,
            "wall_zero_grace_seconds": 10,
            "wall_zero_hold_seconds": 100,
            "voltage_uncertainty_v": 0.05,
            "input_absent_maximum_v": 0.5,
            "fan_supply_absent_maximum_v": 0.5,
            "api_supply_absent_maximum_v": 0.5,
        },
        "reviews": {
            "thermal_reviewer_public_key_sha256": h("thermal-reviewer"),
            "electrical_reviewer_public_key_sha256": h("electrical-reviewer"),
            "distinct_reviewers": True,
            "engineering_envelope_approved": True,
            "source_calibration_approved": True,
            "post_cut_method_approved": True,
        },
        "claims": {key: False for key in sorted(collector.FALSE_CLAIMS)},
    }


def ack_for(plan: dict) -> dict:
    session = plan["session"]
    return {
        "schema": collector.ACK_SCHEMA,
        "session_id": session["session_id"],
        "session_nonce_sha256": session["session_nonce_sha256"],
        "authorization_ref": session["authorization_ref"],
        "exact_unit_fingerprint_sha256": session["exact_unit_fingerprint_sha256"],
        "operator_public_key_sha256": session["operator_public_key_sha256"],
        "action": session["action"],
        "acknowledged_at_utc": "2026-08-24T00:00:04Z",
        "monotonic_ms": 4000,
        "input_power_removed": True,
        "stock_fan_power_lost_acknowledged": True,
        "stock_api_power_lost_acknowledged": True,
        "continue_external_observation": True,
        "reenergization_forbidden_during_window": True,
    }


def sample_rows(plan: dict) -> list[dict[str, str]]:
    sensor = plan["sources"]["sensor"]["asset_record_sha256"]
    meter = plan["sources"]["wall_meter"]["asset_record_sha256"]
    rows: list[dict[str, str]] = []

    def add(ms: int, temp: str, wall: str, voltage: str) -> None:
        seconds = ms // 1000
        rows.append(
            {
                "sequence": str(len(rows)),
                "monotonic_ms": str(ms),
                "captured_at_utc": f"2026-08-24T00:{seconds // 60:02d}:{seconds % 60:02d}Z",
                "sensor_asset_record_sha256": sensor,
                "meter_asset_record_sha256": meter,
                "temperature_c": temp,
                "wall_w": wall,
                "input_voltage_v": voltage,
                "fan_supply_voltage_v": voltage,
                "api_supply_voltage_v": voltage,
            }
        )

    add(1000, "70.0", "95.0", "12.0")
    add(2000, "70.0", "95.0", "12.0")
    add(3000, "70.0", "95.0", "12.0")
    for ms in range(4000, 135000, 10000):
        add(ms, "70.0", "0.1", "0.1")
    return rows


class PostCutCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.plan = approved_plan()
        self.ack = ack_for(self.plan)
        self.rows = sample_rows(self.plan)
        self.plan_path = self.root / "plan.json"
        self.ack_path = self.root / "ack.json"
        self.samples_path = self.root / "samples.csv"
        self.adapter_envelope_path = self.root / "adapter-envelope.json"
        self.receipt_path = self.root / "receipt.json"
        self.ledger = self.root / "ledger"
        self.ledger.mkdir(mode=0o700)
        self.keys = {
            name: Ed25519PrivateKey.generate()
            for name in ("thermal", "electrical", "operator", "adapter")
        }
        self.key_paths: dict[str, Path] = {}
        for name, private_key in self.keys.items():
            raw = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            path = self.root / f"{name}.pub"
            path.write_bytes(raw)
            self.key_paths[name] = path
        self.plan["reviews"]["thermal_reviewer_public_key_sha256"] = hashlib.sha256(
            self.key_paths["thermal"].read_bytes()
        ).hexdigest()
        self.plan["reviews"]["electrical_reviewer_public_key_sha256"] = hashlib.sha256(
            self.key_paths["electrical"].read_bytes()
        ).hexdigest()
        self.plan["session"]["operator_public_key_sha256"] = hashlib.sha256(
            self.key_paths["operator"].read_bytes()
        ).hexdigest()
        self.plan["sources"]["capture_adapter"]["public_key_sha256"] = hashlib.sha256(
            self.key_paths["adapter"].read_bytes()
        ).hexdigest()
        self.nonce_path = self.root / "nonce.bin"
        self.nonce_path.write_bytes(b"N" * 32)
        self.plan["session"]["session_nonce_sha256"] = hashlib.sha256(
            self.nonce_path.read_bytes()
        ).hexdigest()
        self.records: dict[str, Path] = {}
        for name in (
            "adapter_identity",
            "adapter_channel",
            "sensor_asset",
            "sensor_calibration",
            "sensor_placement",
            "meter_asset",
            "meter_calibration",
            "meter_channel",
        ):
            path = self.root / f"{name}.json"
            path.write_bytes((f'{{"fixture":"{name}"}}\n').encode())
            self.records[name] = path
        self.plan["sources"]["capture_adapter"]["identity_record_sha256"] = self.file_hash(
            self.records["adapter_identity"]
        )
        self.plan["sources"]["capture_adapter"]["channel_contract_record_sha256"] = self.file_hash(
            self.records["adapter_channel"]
        )
        self.plan["sources"]["sensor"]["asset_record_sha256"] = self.file_hash(
            self.records["sensor_asset"]
        )
        self.plan["sources"]["sensor"]["calibration_record_sha256"] = self.file_hash(
            self.records["sensor_calibration"]
        )
        self.plan["sources"]["sensor"]["placement_record_sha256"] = self.file_hash(
            self.records["sensor_placement"]
        )
        self.plan["sources"]["wall_meter"]["asset_record_sha256"] = self.file_hash(
            self.records["meter_asset"]
        )
        self.plan["sources"]["wall_meter"]["calibration_record_sha256"] = self.file_hash(
            self.records["meter_calibration"]
        )
        self.plan["sources"]["wall_meter"]["channel_contract_record_sha256"] = self.file_hash(
            self.records["meter_channel"]
        )
        self.ack = ack_for(self.plan)
        self.rows = sample_rows(self.plan)
        self.write_inputs()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def sign(self, name: str, domain: bytes, payload: bytes) -> Path:
        signature = self.keys[name].sign(domain + b"\0" + hashlib.sha256(payload).digest())
        path = self.root / f"{name}-{domain.decode().replace('.', '-')}.sig"
        path.write_bytes(signature)
        return path

    def write_inputs(self) -> None:
        self.plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        self.ack_path.write_text(json.dumps(self.ack), encoding="utf-8")
        with self.samples_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=collector.CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows)
        adapter_envelope = {
            "schema": collector.ADAPTER_ENVELOPE_SCHEMA,
            "session_id": self.plan["session"]["session_id"],
            "session_nonce_sha256": self.plan["session"]["session_nonce_sha256"],
            "authorization_ref": self.plan["session"]["authorization_ref"],
            "exact_unit_fingerprint_sha256": self.plan["session"]["exact_unit_fingerprint_sha256"],
            "plan_sha256": self.file_hash(self.plan_path),
            "ack_sha256": self.file_hash(self.ack_path),
            "samples_sha256": self.file_hash(self.samples_path),
            "samples_size_bytes": self.samples_path.stat().st_size,
            "monotonic_clock_domain_sha256": h("fixture-clock-domain"),
            "cut_event_monotonic_ms": self.ack["monotonic_ms"],
            "cut_event_utc": self.ack["acknowledged_at_utc"],
            "first_sample_monotonic_ms": int(self.rows[0]["monotonic_ms"]),
            "last_sample_monotonic_ms": int(self.rows[-1]["monotonic_ms"]),
        }
        self.adapter_envelope_path.write_bytes(collector.canonical_json_bytes(adapter_envelope))
        self.signature_paths = {
            "thermal": self.sign(
                "thermal", b"dcent.nano3.post-cut.plan.thermal.v1", self.plan_path.read_bytes()
            ),
            "electrical": self.sign(
                "electrical", b"dcent.nano3.post-cut.plan.electrical.v1", self.plan_path.read_bytes()
            ),
            "operator": self.sign(
                "operator", b"dcent.nano3.post-cut.ack.operator.v1", self.ack_path.read_bytes()
            ),
            "adapter_samples": self.sign(
                "adapter", b"dcent.nano3.post-cut.samples.adapter.v1", self.samples_path.read_bytes()
            ),
            "adapter_envelope": self.sign(
                "adapter",
                b"dcent.nano3.post-cut.adapter-envelope.v1",
                self.adapter_envelope_path.read_bytes(),
            ),
        }

    def invoke(self, *extra: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collector.main(list(extra))
        return code, stdout.getvalue(), stderr.getvalue()

    def compile_args(self) -> list[str]:
        plan_hash = hashlib.sha256(self.plan_path.read_bytes()).hexdigest()
        return [
            "compile",
            "--plan",
            str(self.plan_path),
            "--plan-sha256",
            plan_hash,
            "--session-id",
            self.plan["session"]["session_id"],
            "--authorization-ref",
            self.plan["session"]["authorization_ref"],
            "--ack",
            str(self.ack_path),
            "--samples",
            str(self.samples_path),
            "--receipt",
            str(self.receipt_path),
            "--session-nonce",
            str(self.nonce_path),
            "--consumption-ledger",
            str(self.ledger),
            "--thermal-reviewer-public-key",
            str(self.key_paths["thermal"]),
            "--thermal-plan-signature",
            str(self.signature_paths["thermal"]),
            "--electrical-reviewer-public-key",
            str(self.key_paths["electrical"]),
            "--electrical-plan-signature",
            str(self.signature_paths["electrical"]),
            "--operator-public-key",
            str(self.key_paths["operator"]),
            "--operator-ack-signature",
            str(self.signature_paths["operator"]),
            "--adapter-public-key",
            str(self.key_paths["adapter"]),
            "--adapter-samples-signature",
            str(self.signature_paths["adapter_samples"]),
            "--adapter-capture-envelope",
            str(self.adapter_envelope_path),
            "--adapter-capture-signature",
            str(self.signature_paths["adapter_envelope"]),
            "--adapter-identity-record",
            str(self.records["adapter_identity"]),
            "--adapter-channel-contract",
            str(self.records["adapter_channel"]),
            "--sensor-asset-record",
            str(self.records["sensor_asset"]),
            "--sensor-calibration-record",
            str(self.records["sensor_calibration"]),
            "--sensor-placement-record",
            str(self.records["sensor_placement"]),
            "--meter-asset-record",
            str(self.records["meter_asset"]),
            "--meter-calibration-record",
            str(self.records["meter_calibration"]),
            "--meter-channel-contract",
            str(self.records["meter_channel"]),
        ]

    def test_valid_evidence_compiles_non_authorizing_receipt(self) -> None:
        code, stdout, stderr = self.invoke(*self.compile_args())
        self.assertEqual(0, code, stderr)
        self.assertIn("authorization_a=false", stdout)
        self.assertNotIn(str(self.root), stdout)
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("PASS_SIGNED_FORMAT_AND_ENVELOPE_ONLY", receipt["result"])
        self.assertTrue(all(value is False for value in receipt["claims"].values()))
        self.assertFalse(receipt["scope"]["collector_opened_hardware_or_network"])
        self.assertTrue(
            receipt["metrics"]["stock_fan_power_absence_derived_from_voltage_for_all_post_cut_samples"]
        )
        self.assertFalse(receipt["scope"]["physical_source_authenticity_verified_by_compiler"])
        self.assertTrue(receipt["scope"]["plan_reviewer_signatures_verified"])
        self.assertFalse(receipt["scope"]["reviewer_key_authority_verified_by_compiler"])
        self.assertFalse(receipt["scope"]["operator_key_authority_verified_by_compiler"])
        self.assertFalse(receipt["scope"]["adapter_key_authority_verified_by_compiler"])
        self.assertIn("adapter_capture_envelope_signature", receipt["cryptographic_provenance"]["signatures"])

    def test_checked_in_template_validates_but_cannot_compile(self) -> None:
        template = SCRIPT.with_name("nano3_post_cut_plan.template.json")
        code, stdout, stderr = self.invoke("validate-plan", "--plan", str(template))
        self.assertEqual(0, code, stderr)
        self.assertIn(collector.TEMPLATE_STATUS, stdout)
        self.plan = json.loads(template.read_text(encoding="utf-8"))
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("not approved", stderr)

    def test_plan_pin_session_and_authorization_are_all_required(self) -> None:
        variants = [
            ("--plan-sha256", h("wrong"), "plan SHA-256"),
            ("--session-id", "wrong-session", "session id"),
            ("--authorization-ref", "AUTH-WRONG", "authorization reference"),
        ]
        for flag, value, message in variants:
            with self.subTest(flag=flag):
                args = self.compile_args()
                args[args.index(flag) + 1] = value
                code, _, stderr = self.invoke(*args)
                self.assertEqual(2, code)
                self.assertIn(message, stderr)

    def test_plan_cannot_promote_authority_or_collapse_reviews(self) -> None:
        cases = []
        promoted = copy.deepcopy(self.plan)
        promoted["claims"]["authorization_a_granted"] = True
        cases.append(promoted)
        same_reviewer = copy.deepcopy(self.plan)
        same_reviewer["reviews"]["electrical_reviewer_public_key_sha256"] = same_reviewer["reviews"][
            "thermal_reviewer_public_key_sha256"
        ]
        cases.append(same_reviewer)
        dependent = copy.deepcopy(self.plan)
        dependent["sources"]["sensor"]["powered_independently_of_nano"] = False
        cases.append(dependent)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.plan = candidate
                self.write_inputs()
                code, _, _ = self.invoke(*self.compile_args())
                self.assertEqual(2, code)

    def test_ack_must_match_and_acknowledge_every_cut_consequence(self) -> None:
        for key, value in (
            ("session_nonce_sha256", h("wrong")),
            ("input_power_removed", False),
            ("stock_fan_power_lost_acknowledged", False),
            ("continue_external_observation", False),
            ("reenergization_forbidden_during_window", False),
        ):
            with self.subTest(key=key):
                self.ack = ack_for(self.plan)
                self.ack[key] = value
                self.write_inputs()
                code, _, _ = self.invoke(*self.compile_args())
                self.assertEqual(2, code)

    def test_wrong_sensor_or_meter_identity_is_refused(self) -> None:
        for key in ("sensor_asset_record_sha256", "meter_asset_record_sha256"):
            with self.subTest(key=key):
                self.rows = sample_rows(self.plan)
                self.rows[5][key] = h("wrong-source")
                self.write_inputs()
                code, _, stderr = self.invoke(*self.compile_args())
                self.assertEqual(2, code)
                self.assertIn("identity mismatch", stderr)

    def test_sample_sequence_time_gap_and_clock_drift_fail_closed(self) -> None:
        mutations = []
        sequence = sample_rows(self.plan)
        sequence[4]["sequence"] = "99"
        mutations.append(sequence)
        monotonic = sample_rows(self.plan)
        monotonic[5]["monotonic_ms"] = monotonic[4]["monotonic_ms"]
        mutations.append(monotonic)
        gap = sample_rows(self.plan)
        gap[5]["monotonic_ms"] = "25000"
        mutations.append(gap)
        drift = sample_rows(self.plan)
        drift[5]["captured_at_utc"] = "2026-08-24T00:00:30Z"
        mutations.append(drift)
        for rows in mutations:
            with self.subTest(rows=rows[4:6]):
                self.rows = rows
                self.write_inputs()
                code, _, _ = self.invoke(*self.compile_args())
                self.assertEqual(2, code)

    def test_any_post_cut_power_or_reenergization_signal_is_refused(self) -> None:
        for key in ("input_voltage_v", "fan_supply_voltage_v", "api_supply_voltage_v"):
            with self.subTest(key=key):
                self.rows = sample_rows(self.plan)
                self.rows[8][key] = "12.0"
                self.write_inputs()
                code, _, stderr = self.invoke(*self.compile_args())
                self.assertEqual(2, code)
                self.assertIn("re-energization", stderr)

    def test_uncertainty_adjusted_temperature_limits_are_load_bearing(self) -> None:
        variants = []
        peak = copy.deepcopy(self.plan)
        peak["envelope"]["maximum_temperature_c"] = 70.05
        variants.append(peak)
        rise = copy.deepcopy(self.plan)
        rise["envelope"]["maximum_post_cut_temperature_rise_c"] = 0.1
        variants.append(rise)
        trend = copy.deepcopy(self.plan)
        trend["envelope"]["maximum_positive_trend_c_per_minute"] = 1.0
        variants.append(trend)
        for candidate in variants:
            with self.subTest(envelope=candidate["envelope"]):
                self.plan = candidate
                self.rows = sample_rows(self.plan)
                self.ack = ack_for(self.plan)
                self.write_inputs()
                code, _, _ = self.invoke(*self.compile_args())
                self.assertEqual(2, code)

    def test_wall_zero_includes_uncertainty_grace_and_hold(self) -> None:
        wall = sample_rows(self.plan)
        wall[8]["wall_w"] = "0.95"
        self.rows = wall
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("wall power", stderr)

        self.plan = approved_plan()
        self.plan["envelope"]["wall_zero_hold_seconds"] = 140
        self.rows = sample_rows(self.plan)
        self.ack = ack_for(self.plan)
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("hold", stderr)

    def test_baseline_observation_and_authorization_window_are_required(self) -> None:
        self.rows = sample_rows(self.plan)[1:]
        for index, row in enumerate(self.rows):
            row["sequence"] = str(index)
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("baseline", stderr)

        self.plan = approved_plan()
        self.rows = sample_rows(self.plan)[:-2]
        self.ack = ack_for(self.plan)
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("too short", stderr)

        self.plan = approved_plan()
        self.plan["session"]["authorized_until_utc"] = "2026-08-24T00:01:00Z"
        self.rows = sample_rows(self.plan)
        self.ack = ack_for(self.plan)
        self.write_inputs()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("authorization window", stderr)

    def test_malformed_duplicate_nonfinite_and_extra_csv_inputs_are_refused(self) -> None:
        self.plan_path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
        code, _, stderr = self.invoke("validate-plan", "--plan", str(self.plan_path))
        self.assertEqual(2, code)
        self.assertIn("duplicate JSON key", stderr)

        self.write_inputs()
        self.ack_path.write_text('{"value":NaN}', encoding="utf-8")
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("non-finite", stderr)

        self.ack = ack_for(self.plan)
        self.write_inputs()
        text = self.samples_path.read_text(encoding="utf-8")
        self.samples_path.write_text(text.replace("sequence,", "extra,sequence,", 1), encoding="utf-8")
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("columns/order", stderr)

    def test_receipt_is_create_new_and_symlink_inputs_are_refused(self) -> None:
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(0, code, stderr)
        before = self.receipt_path.read_bytes()
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("overwrite", stderr)
        self.assertEqual(before, self.receipt_path.read_bytes())

        link = self.root / "plan-link.json"
        try:
            os.symlink(self.plan_path, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        code, _, stderr = self.invoke("validate-plan", "--plan", str(link))
        self.assertEqual(2, code)
        self.assertIn("non-symlink", stderr)

    def test_every_detached_signature_and_public_key_binding_is_load_bearing(self) -> None:
        for name in ("thermal", "electrical", "operator", "adapter_samples", "adapter_envelope"):
            with self.subTest(signature=name):
                self.write_inputs()
                signature_path = self.signature_paths[name]
                damaged = bytearray(signature_path.read_bytes())
                damaged[0] ^= 1
                signature_path.write_bytes(damaged)
                code, _, stderr = self.invoke(*self.compile_args())
                self.assertEqual(2, code)
                self.assertIn("signature verification failed", stderr)

        self.write_inputs()
        wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_paths["adapter"].write_bytes(wrong_key)
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("public key SHA-256 mismatch", stderr)

    def test_bound_source_records_and_nonce_reveal_are_verified_from_bytes(self) -> None:
        for name in (
            "adapter_identity",
            "adapter_channel",
            "sensor_asset",
            "sensor_calibration",
            "sensor_placement",
            "meter_asset",
            "meter_calibration",
            "meter_channel",
        ):
            with self.subTest(record=name):
                self.write_inputs()
                self.records[name].write_bytes(self.records[name].read_bytes() + b"x")
                code, _, stderr = self.invoke(*self.compile_args())
                self.assertEqual(2, code)
                self.assertIn("SHA-256 mismatch", stderr)
                self.records[name].write_bytes(self.records[name].read_bytes()[:-1])

        self.write_inputs()
        self.nonce_path.write_bytes(b"X" * 32)
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("nonce reveal SHA-256 mismatch", stderr)

    def test_session_nonce_has_local_one_shot_consumption_across_output_paths(self) -> None:
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(0, code, stderr)
        self.receipt_path = self.root / "second-receipt.json"
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("overwrite", stderr)
        self.assertFalse(self.receipt_path.exists())

    def test_adapter_envelope_prevents_cross_session_sample_replay(self) -> None:
        old_envelope = self.adapter_envelope_path.read_bytes()
        old_signature = self.signature_paths["adapter_envelope"].read_bytes()
        self.plan["session"]["session_id"] = "nano3-post-cut-test-002"
        self.plan["session"]["authorization_ref"] = "AUTH-A-TEST-002"
        self.plan["session"]["exact_unit_fingerprint_sha256"] = h("unit-002")
        self.nonce_path.write_bytes(b"R" * 32)
        self.plan["session"]["session_nonce_sha256"] = self.file_hash(self.nonce_path)
        self.ack = ack_for(self.plan)
        self.rows = sample_rows(self.plan)
        self.write_inputs()
        self.adapter_envelope_path.write_bytes(old_envelope)
        self.signature_paths["adapter_envelope"].write_bytes(old_signature)
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("does not match the plan", stderr)

    def test_adapter_envelope_rejects_foreign_clock_cut_ack(self) -> None:
        old_envelope = self.adapter_envelope_path.read_bytes()
        old_signature = self.signature_paths["adapter_envelope"].read_bytes()
        self.ack["monotonic_ms"] = 5000
        self.write_inputs()
        self.adapter_envelope_path.write_bytes(old_envelope)
        self.signature_paths["adapter_envelope"].write_bytes(old_signature)
        code, _, stderr = self.invoke(*self.compile_args())
        self.assertEqual(2, code)
        self.assertIn("ack_sha256 mismatch", stderr)


if __name__ == "__main__":
    unittest.main()
