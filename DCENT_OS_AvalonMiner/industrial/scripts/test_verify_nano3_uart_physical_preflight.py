#!/usr/bin/env python3
"""Adversarial tests for the file-only Nano 3 UART preflight rail."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import shutil
import struct
import sys
import tempfile
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import verify_nano3_uart_physical_preflight as rail  # noqa: E402


def canonical(value: object) -> bytes:
    return rail.canonical_json(value)


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def png_bytes(
    seed: str,
    width: int = rail.MIN_PHOTO_WIDTH,
    height: int = rail.MIN_PHOTO_HEIGHT,
) -> bytes:
    pixel = hashlib.sha256(seed.encode("ascii")).digest()[:3]
    scanline = b"\x00" + pixel * width

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanline * height))
        + chunk(b"IEND", b"")
    )


class Bundle:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.operator_private = Ed25519PrivateKey.generate()
        self.reviewer_private = Ed25519PrivateKey.generate()
        self.operator_public = self.operator_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.reviewer_public = self.reviewer_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.valid_from = now - timedelta(minutes=30)
        self.valid_until = now + timedelta(minutes=30)
        self.phase_times: dict[str, tuple[datetime, datetime]] = {}
        offset = 120
        for phase_name in rail.PHASE_ORDER:
            if phase_name == "capture_energization":
                continue
            began = self.valid_from + timedelta(seconds=offset)
            ended = began + timedelta(seconds=60)
            self.phase_times[phase_name] = (began, ended)
            offset += 120

        self.evidence_raw: dict[str, bytes] = {}
        self.evidence_time: dict[str, datetime] = {}
        for evidence_type in rail.REQUIRED_EVIDENCE_TYPES:
            if evidence_type in rail.PHOTO_EVIDENCE_TYPES:
                raw = png_bytes(evidence_type)
            else:
                raw = canonical(
                    {
                        "evidence_type": evidence_type,
                        "fixture": "opaque-file-bytes",
                    }
                )
            self.evidence_raw[evidence_type] = raw
            if evidence_type in rail.SESSION_EVIDENCE_TYPES:
                captured = self.valid_from + timedelta(seconds=30)
            elif evidence_type in rail.PHASE_AUTHORIZATION_EVIDENCE.values():
                captured = self.valid_from + timedelta(seconds=60)
            else:
                phase = next(
                    name
                    for name, kinds in rail.PHASE_EVIDENCE_TYPES.items()
                    if evidence_type in kinds
                )
                captured = self.phase_times[phase][0] + timedelta(seconds=30)
            self.evidence_time[evidence_type] = captured

        target = {
            "model": rail.TARGET_MODEL,
            "nano3s_substitution_forbidden": True,
            "unit_asset_id": "nano3-unit-opaque-001",
            "unit_fingerprint_sha256": "1" * 64,
            "board_revision": "nano3-nons-board-rev-a",
            "board_revision_evidence_type": "board_revision_record",
        }
        roles = {
            "operator": {
                "identity": "operator-opaque-001",
                "public_key_sha256": rail.sha256_bytes(self.operator_public),
                "custody_evidence_type": "operator_key_custody_record",
            },
            "electrical_reviewer": {
                "identity": "reviewer-opaque-002",
                "public_key_sha256": rail.sha256_bytes(self.reviewer_public),
                "custody_evidence_type": "electrical_reviewer_key_custody_record",
            },
            "independent": True,
        }
        calibration_end = utc(self.valid_until + timedelta(days=1))
        instruments = {
            "oscilloscope": {
                "asset_id": "scope-asset-001",
                "model": "isolated-scope-model",
                "hardware_revision": "scope-rev-a",
                "serial_fingerprint_sha256": "2" * 64,
                "identity_evidence_type": "scope_identity_record",
                "calibration_evidence_type": "scope_calibration_record",
                "calibration_valid_until_utc": calibration_end,
                "input_rating_v": 20.0,
                "protective_earth_class": "battery_isolated",
            },
            "scope_probe": {
                "asset_id": "probe-asset-001",
                "model": "passive-probe-model",
                "hardware_revision": "probe-rev-a",
                "serial_fingerprint_sha256": "3" * 64,
                "identity_evidence_type": "probe_identity_record",
                "calibration_evidence_type": "probe_calibration_record",
                "calibration_valid_until_utc": calibration_end,
                "input_rating_v": 20.0,
                "input_impedance_ohm": 10_000_000.0,
                "probe_kind": "passive_high_impedance",
                "attenuation_ratio": 10.0,
            },
            "logic_analyzer": {
                "asset_id": "analyzer-asset-001",
                "model": "receive-only-analyzer-model",
                "hardware_revision": "analyzer-rev-a",
                "serial_fingerprint_sha256": "4" * 64,
                "identity_evidence_type": "analyzer_identity_record",
                "calibration_evidence_type": "analyzer_calibration_record",
                "calibration_valid_until_utc": calibration_end,
                "software_version": "analyzer-software-1.0",
                "software_sha256": "5" * 64,
                "absolute_max_input_v": 5.5,
                "input_impedance_ohm": 10_000_000.0,
                "receive_only": True,
                "tx_connected": False,
                "pullup_enabled": False,
                "power_output_enabled": False,
                "shared_usb_power_to_target": False,
            },
            "deenergization_meter": {
                "asset_id": "dmm-asset-001",
                "model": "battery-handheld-dmm-model",
                "hardware_revision": "dmm-rev-a",
                "serial_fingerprint_sha256": "7" * 64,
                "identity_evidence_type": "deenergization_meter_identity_record",
                "calibration_evidence_type": "deenergization_meter_calibration_record",
                "calibration_valid_until_utc": calibration_end,
                "input_rating_v": 600.0,
                "input_impedance_ohm": 10_000_000.0,
                "measurement_kind": "dc_voltage_true_rms_bounded",
                "power_class": "battery_isolated",
                "probe_attachment_method": "rated_handheld_noninvasive_probes",
                "independently_attachable_while_deenergized": True,
            },
        }
        phase_scopes: dict[str, object] = {}
        for index, phase_name in enumerate(rail.PHASE_ORDER):
            if phase_name == "capture_energization":
                phase_scopes[phase_name] = {
                    "authorization_id": None,
                    "authorization_nonce_sha256": None,
                    "authorization_evidence_type": None,
                    "authorization_receipt_sha256": None,
                    "authorized": False,
                    "performed_by_plan": False,
                    "authorized_from_utc": None,
                    "authorized_until_utc": None,
                    "actions": [],
                }
                continue
            authorization_type = rail.PHASE_AUTHORIZATION_EVIDENCE[phase_name]
            phase_scopes[phase_name] = {
                "authorization_id": f"phase-authorization-{index:02d}",
                "authorization_nonce_sha256": f"{index + 5:x}" * 64,
                "authorization_evidence_type": authorization_type,
                "authorization_receipt_sha256": rail.sha256_bytes(
                    self.evidence_raw[authorization_type]
                ),
                "authorized": True,
                "performed_by_plan": False,
                "authorized_from_utc": utc(self.valid_from),
                "authorized_until_utc": utc(self.valid_until),
                "actions": copy.deepcopy(rail.EXPECTED_PHASE_ACTIONS[phase_name]),
            }
        claims = {claim: False for claim in rail.FALSE_CLAIMS}
        self.plan = {
            "schema": rail.PLAN_SCHEMA,
            "status": rail.PLAN_STATUS,
            "purpose": "non_s_nano3_uart_physical_electrical_preflight_only",
            "preflight": {
                "preflight_id": "nano3-uart-preflight-opaque-001",
                "session_nonce_sha256": "a" * 64,
                "issued_at_utc": utc(self.valid_from + timedelta(seconds=90)),
                "valid_from_utc": utc(self.valid_from),
                "valid_until_utc": utc(self.valid_until),
                "clock_source_evidence_type": "clock_source_record",
                "clock_source_kind": "operator_asserted_utc",
                "clock_source_fingerprint_sha256": "6" * 64,
                "clock_independently_trusted": False,
                "maximum_clock_uncertainty_ms": 100.0,
                "one_shot_same_host_ledger": True,
            },
            "target": target,
            "roles": roles,
            "phase_scopes": phase_scopes,
            "intended_instruments": instruments,
            "electrical_method": {
                "isolation_strategy": "battery_isolated_scope",
                "maximum_reviewed_ground_potential_v": 0.05,
                "maximum_zero_energy_v": 0.05,
                "maximum_signal_continuity_ohm": 10.0,
                "maximum_ground_continuity_ohm": 1.0,
                "minimum_voltage_rating_margin_v": 0.5,
                "minimum_analyzer_input_impedance_ohm": 1_000_000.0,
                "scope_attach_order": [
                    "proven_signal_ground",
                    "host_to_controller",
                    "controller_to_host",
                ],
                "scope_detach_order": [
                    "host_to_controller",
                    "controller_to_host",
                    "proven_signal_ground",
                ],
                "analyzer_attach_order": [
                    "proven_signal_ground",
                    "host_to_controller",
                    "controller_to_host",
                ],
                "analyzer_detach_order": [
                    "host_to_controller",
                    "controller_to_host",
                    "proven_signal_ground",
                ],
                "esd_controls_required": True,
                "direct_single_ended_earth_reference_forbidden": True,
            },
            "required_evidence_types": list(rail.REQUIRED_EVIDENCE_TYPES),
            "claims": claims,
        }
        evidence_index = {
            evidence_type: index
            for index, evidence_type in enumerate(rail.REQUIRED_EVIDENCE_TYPES)
        }
        for phase_name in rail.AUTHORIZED_PHASES:
            planned = phase_scopes[phase_name]
            assert isinstance(planned, dict)
            evidence_type = rail.PHASE_AUTHORIZATION_EVIDENCE[phase_name]
            index = evidence_index[evidence_type]
            authorization_record = {
                "schema": rail.EVIDENCE_RECORD_SCHEMA,
                "evidence_type": evidence_type,
                "evidence_id": f"evidence-{index:02d}-{evidence_type}",
                "captured_at_utc": utc(self.evidence_time[evidence_type]),
                "unit_fingerprint_sha256": target["unit_fingerprint_sha256"],
                "session_nonce_sha256": self.plan["preflight"][
                    "session_nonce_sha256"
                ],
                "phase_name": phase_name,
                "phase_authorization_nonce_sha256": planned[
                    "authorization_nonce_sha256"
                ],
                "facts": rail._authorization_projection(phase_name, self.plan),
            }
            self.evidence_raw[evidence_type] = canonical(authorization_record)
            planned["authorization_receipt_sha256"] = rail.sha256_bytes(
                self.evidence_raw[evidence_type]
            )
        phase_receipts: dict[str, object] = {}
        zero_type = {
            "deenergized_enclosure_continuity_scope_attach": "zero_energy_before_scope_attach_record",
            "deenergized_scope_detach": "zero_energy_before_scope_detach_record",
            "deenergized_analyzer_attach": "zero_energy_before_analyzer_attach_record",
            "deenergized_analyzer_detach": "zero_energy_before_analyzer_detach_record",
        }
        for phase_name in rail.PHASE_ORDER:
            if phase_name == "capture_energization":
                phase_receipts[phase_name] = {
                    "authorization_id": None,
                    "authorized": False,
                    "performed": False,
                    "began_at_utc": None,
                    "ended_at_utc": None,
                }
                continue
            planned = phase_scopes[phase_name]
            assert isinstance(planned, dict)
            began, ended = self.phase_times[phase_name]
            zero_energy = None
            if phase_name in zero_type:
                zero_energy = {
                    "power_disconnect_asset_id": "power-disconnect-asset-001",
                    "power_disconnect_evidence_type": "power_disconnect_record",
                    "power_disconnected_at_utc": utc(began - timedelta(seconds=30)),
                    "observation_started_at_utc": utc(began + timedelta(seconds=5)),
                    "observation_ended_at_utc": utc(began + timedelta(seconds=7)),
                    "minimum_observation_duration_ms": 2_000.0,
                    "measurement_points": [
                        "uart_signal_ground_to_chassis",
                        "uart_signal_ground_to_host_to_controller",
                        "uart_signal_ground_to_controller_to_host",
                        "target_power_rail_to_uart_signal_ground",
                    ],
                    "measurement_instrument_asset_id": "dmm-asset-001",
                    "evidence_type": zero_type[phase_name],
                    "maximum_observed_abs_v": 0.01,
                    "measurement_uncertainty_v": 0.01,
                    "reviewed_limit_v": 0.05,
                    "passed": True,
                }
            phase_receipts[phase_name] = {
                "authorization_id": planned["authorization_id"],
                "authorization_nonce_sha256": planned[
                    "authorization_nonce_sha256"
                ],
                "authorization_evidence_type": planned[
                    "authorization_evidence_type"
                ],
                "authorization_receipt_sha256": planned[
                    "authorization_receipt_sha256"
                ],
                "performed": True,
                "began_at_utc": utc(began),
                "ended_at_utc": utc(ended),
                "clock_source_evidence_type": "clock_source_record",
                "clock_uncertainty_ms": 100.0,
                "zero_energy": zero_energy,
                "evidence_types": rail.PHASE_EVIDENCE_TYPES[phase_name],
            }
        evidence = []
        for index, evidence_type in enumerate(rail.REQUIRED_EVIDENCE_TYPES):
            raw = self.evidence_raw[evidence_type]
            is_photo = evidence_type in rail.PHOTO_EVIDENCE_TYPES
            evidence.append(
                {
                    "evidence_type": evidence_type,
                    "evidence_id": f"evidence-{index:02d}-{evidence_type}",
                    "filename": f"evidence-{index:02d}.{'png' if is_photo else 'json'}",
                    "sha256": rail.sha256_bytes(raw),
                    "size_bytes": len(raw),
                    "media_type": "image/png" if is_photo else "application/json",
                    "captured_at_utc": utc(self.evidence_time[evidence_type]),
                }
            )
        mapping = {
            "host_to_controller": {
                "tap_id": "tap-host-to-controller",
                "source_endpoint": "k230_uart_tx",
                "destination_endpoint": "mining_controller_uart_rx",
                "basis": "deenergized_continuity_to_named_endpoints",
                "silkscreen_inference_used": False,
                "continuity_resistance_ohm": 0.4,
                "measurement_uncertainty_ohm": 0.1,
                "evidence_type": "host_to_controller_continuity_record",
            },
            "controller_to_host": {
                "tap_id": "tap-controller-to-host",
                "source_endpoint": "mining_controller_uart_tx",
                "destination_endpoint": "k230_uart_rx",
                "basis": "deenergized_continuity_to_named_endpoints",
                "silkscreen_inference_used": False,
                "continuity_resistance_ohm": 0.4,
                "measurement_uncertainty_ohm": 0.1,
                "evidence_type": "controller_to_host_continuity_record",
            },
            "signal_ground": {
                "tap_id": "tap-signal-ground",
                "source_endpoint": "uart_signal_ground_tap",
                "destination_endpoint": "known_board_signal_ground",
                "basis": "deenergized_continuity_to_named_endpoints",
                "silkscreen_inference_used": False,
                "continuity_resistance_ohm": 0.2,
                "measurement_uncertainty_ohm": 0.1,
                "evidence_type": "signal_ground_continuity_record",
            },
        }
        line = {
            "low_min_v": 0.0,
            "low_max_v": 0.2,
            "high_min_v": 3.1,
            "high_max_v": 3.3,
            "overshoot_min_v": -0.1,
            "overshoot_max_v": 3.4,
            "idle_state": "logic_high",
            "polarity": "non_inverted",
            "drive_mode": "push_pull",
            "direct_logic_input_compatible": True,
        }
        measured = {
            "host_to_controller": copy.deepcopy(line),
            "controller_to_host": copy.deepcopy(line),
            "analyzer_threshold_v": 1.5,
            "measurement_uncertainty_v": 0.05,
            "threshold_margin_v": 0.3,
            "ground_potential_v": 0.01,
            "ground_potential_uncertainty_v": 0.01,
            "isolation_strategy": "battery_isolated_scope",
            "usb_earth_relationship": "no_usb_connection",
            "compatibility_decision": "accepted_for_passive_receive_only_attachment",
            "decision_evidence_type": "electrical_compatibility_review_record",
        }
        procedure = {
            "scope_attach_order": self.plan["electrical_method"]["scope_attach_order"],
            "scope_detach_order": self.plan["electrical_method"]["scope_detach_order"],
            "analyzer_attach_order": self.plan["electrical_method"][
                "analyzer_attach_order"
            ],
            "analyzer_detach_order": self.plan["electrical_method"][
                "analyzer_detach_order"
            ],
            "ground_continuity_reverified_before_analyzer": True,
            "esd_controls_observed": True,
            "analyzer_receive_only_confirmed": True,
            "analyzer_tx_absent": True,
            "analyzer_pullup_absent": True,
            "analyzer_power_output_absent": True,
            "shared_usb_power_absent": True,
            "unexpected_voltage_or_reset_observed": False,
            "stock_behavior_changed": False,
        }
        review = {
            "decision": "accept_file_bundle_for_preflight_record_only",
            "decision_domain": "post-evidence-electrical-review-not-capture-authorization",
            "every_raw_evidence_hash_reviewed": True,
            "numeric_values_and_uncertainty_reviewed": True,
            "phase_scope_and_time_windows_reviewed": True,
            "instrument_rating_and_calibration_reviewed": True,
            "usb_earth_ground_and_isolation_reviewed": True,
            "compatibility_evidence_type": "electrical_compatibility_review_record",
        }
        self.receipt = {
            "schema": rail.RECEIPT_SCHEMA,
            "status": rail.RECEIPT_STATUS,
            "purpose": "validate_completed_non_s_uart_preflight_evidence_only",
            "plan_binding": {},
            "completed_at_utc": utc(self.valid_from + timedelta(seconds=800)),
            "target": copy.deepcopy(target),
            "instruments": copy.deepcopy(instruments),
            "phase_receipts": phase_receipts,
            "evidence": evidence,
            "signal_mapping": mapping,
            "measured_levels": measured,
            "procedure_observations": procedure,
            "post_evidence_review": review,
            "claims": copy.deepcopy(claims),
        }
        authorization_types = set(rail.PHASE_AUTHORIZATION_EVIDENCE.values())
        for entry in self.receipt["evidence"]:
            evidence_type = entry["evidence_type"]
            if (
                evidence_type in rail.PHOTO_EVIDENCE_TYPES
                or evidence_type in authorization_types
            ):
                continue
            phase_name = rail._evidence_phase(evidence_type)
            phase_nonce = (
                None
                if phase_name == "pre_action_session"
                else self.plan["phase_scopes"][phase_name][
                    "authorization_nonce_sha256"
                ]
            )
            record = {
                "schema": rail.EVIDENCE_RECORD_SCHEMA,
                "evidence_type": evidence_type,
                "evidence_id": entry["evidence_id"],
                "captured_at_utc": entry["captured_at_utc"],
                "unit_fingerprint_sha256": target["unit_fingerprint_sha256"],
                "session_nonce_sha256": self.plan["preflight"][
                    "session_nonce_sha256"
                ],
                "phase_name": phase_name,
                "phase_authorization_nonce_sha256": phase_nonce,
                "facts": rail._expected_evidence_facts(
                    evidence_type, self.plan, self.receipt
                ),
            }
            raw = canonical(record)
            self.evidence_raw[evidence_type] = raw
            entry["sha256"] = rail.sha256_bytes(raw)
            entry["size_bytes"] = len(raw)

    def write(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        evidence_root = self.root / rail.EVIDENCE_DIRECTORY_NAME
        evidence_root.mkdir(exist_ok=True)
        for entry in self.receipt["evidence"]:
            raw = self.evidence_raw[entry["evidence_type"]]
            (evidence_root / entry["filename"]).write_bytes(raw)
        plan_raw = canonical(self.plan)
        plan_operator_signature = self.operator_private.sign(
            rail.PLAN_OPERATOR_DOMAIN + plan_raw
        )
        plan_reviewer_signature = self.reviewer_private.sign(
            rail.PLAN_REVIEWER_DOMAIN + plan_raw
        )
        self.receipt["plan_binding"] = {
            "plan_sha256": rail.sha256_bytes(plan_raw),
            "plan_operator_signature_sha256": rail.sha256_bytes(
                plan_operator_signature
            ),
            "plan_reviewer_signature_sha256": rail.sha256_bytes(
                plan_reviewer_signature
            ),
            "preflight_id": self.plan["preflight"]["preflight_id"],
            "session_nonce_sha256": self.plan["preflight"]["session_nonce_sha256"],
        }
        receipt_raw = canonical(self.receipt)
        files = {
            rail.PLAN_NAME: plan_raw,
            rail.PLAN_OPERATOR_SIGNATURE_NAME: plan_operator_signature,
            rail.PLAN_REVIEWER_SIGNATURE_NAME: plan_reviewer_signature,
            rail.RECEIPT_NAME: receipt_raw,
            rail.RECEIPT_OPERATOR_SIGNATURE_NAME: self.operator_private.sign(
                rail.RECEIPT_OPERATOR_DOMAIN + receipt_raw
            ),
            rail.RECEIPT_REVIEWER_SIGNATURE_NAME: self.reviewer_private.sign(
                rail.RECEIPT_REVIEWER_DOMAIN + receipt_raw
            ),
            rail.OPERATOR_PUBLIC_KEY_NAME: self.operator_public,
            rail.REVIEWER_PUBLIC_KEY_NAME: self.reviewer_public,
        }
        for name, raw in files.items():
            (self.root / name).write_bytes(raw)


class UartPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.bundle = Bundle(self.base / "bundle")
        self.bundle.write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self) -> dict[str, object]:
        return rail.validate_bundle(
            self.bundle.root,
            verification_time_utc=datetime.now(timezone.utc),
        )

    def rewrite(self) -> None:
        shutil.rmtree(self.bundle.root)
        self.bundle.write()

    def assert_rejected(self) -> None:
        with self.assertRaises(rail.PreflightError):
            self.validate()

    def test_valid_bundle_is_file_only_and_authority_false(self) -> None:
        result = self.validate()
        self.assertTrue(result["preflight_file_contract_valid"])
        self.assertFalse(result["authorization_c_granted"])
        self.assertFalse(result["capture_energization_authorized"])
        self.assertFalse(result["physical_provenance_proven"])
        self.assertFalse(result["trusted_time_provenance"])
        self.assertFalse(result["global_replay_resistance"])
        self.assertEqual(result["evidence_count"], len(rail.REQUIRED_EVIDENCE_TYPES))
        public = canonical(result).decode("ascii")
        self.assertNotIn(str(self.base), public)
        self.assertNotIn("unit_asset_id", result)
        self.assertNotIn("evidence_id", public)

    def test_validator_has_no_contact_or_process_modules(self) -> None:
        tree = ast.parse(
            (SCRIPT_DIR / "verify_nano3_uart_physical_preflight.py").read_text(
                encoding="utf-8"
            )
        )
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertTrue(
            imports.isdisjoint(
                {
                    "serial",
                    "socket",
                    "subprocess",
                    "requests",
                    "urllib",
                    "http",
                    "ftplib",
                    "telnetlib",
                    "usb",
                }
            )
        )

    def test_cli_consumes_same_host_nonce_and_refuses_overwrite(self) -> None:
        output = self.base / "public" / "receipt.json"
        ledger = self.base / "private" / "ledger"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = rail.main(
                [
                    "--bundle",
                    str(self.bundle.root),
                    "--output",
                    str(output),
                    "--ledger-root",
                    str(ledger),
                ]
            )
        self.assertEqual(code, 0)
        before = hashlib.sha256(output.read_bytes()).hexdigest()
        self.assertNotIn(str(self.base), output.read_text(encoding="ascii"))
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            second = rail.main(
                [
                    "--bundle",
                    str(self.bundle.root),
                    "--output",
                    str(output),
                    "--ledger-root",
                    str(self.base / "unused-ledger"),
                ]
            )
        self.assertEqual(second, 2)
        self.assertEqual(before, hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertNotIn(str(self.base), stderr.getvalue())

    def test_same_host_replay_blocks_new_output(self) -> None:
        ledger = self.base / "ledger"
        first = self.base / "first.json"
        second = self.base / "second.json"
        self.assertEqual(
            rail.main(
                ["--bundle", str(self.bundle.root), "--output", str(first), "--ledger-root", str(ledger)]
            ),
            0,
        )
        with redirect_stderr(io.StringIO()):
            code = rail.main(
                ["--bundle", str(self.bundle.root), "--output", str(second), "--ledger-root", str(ledger)]
            )
        self.assertEqual(code, 2)
        self.assertFalse(second.exists())

    def test_invalid_template_cannot_substitute_for_plan(self) -> None:
        template = SCRIPT_DIR / "nano3_uart_physical_preflight.template.json"
        (self.bundle.root / rail.PLAN_NAME).write_bytes(template.read_bytes())
        self.assert_rejected()

    def test_wrong_model_nano3s_and_role_collapse_fail(self) -> None:
        mutations = [
            lambda plan: plan["target"].__setitem__("model", "canaan-avalon-nano3s"),
            lambda plan: plan["target"].__setitem__("nano3s_substitution_forbidden", False),
            lambda plan: plan["roles"]["electrical_reviewer"].__setitem__(
                "identity", plan["roles"]["operator"]["identity"]
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fresh = Bundle(self.base / f"mutation-{len(list(self.base.iterdir()))}")
                mutation(fresh.plan)
                fresh.write()
                with self.assertRaises(rail.PreflightError):
                    rail.validate_bundle(fresh.root, verification_time_utc=datetime.now(timezone.utc))

    def test_expired_calibration_fails_at_plan_admission(self) -> None:
        self.bundle.plan["intended_instruments"]["logic_analyzer"][
            "calibration_valid_until_utc"
        ] = utc(self.bundle.valid_until - timedelta(seconds=1))
        self.rewrite()
        self.assert_rejected()

    def test_hard_electrical_bounds_reject_signed_typos(self) -> None:
        mutations = [
            ("maximum_zero_energy_v", rail.HARD_MAX_ZERO_ENERGY_V + 0.001),
            (
                "maximum_reviewed_ground_potential_v",
                rail.HARD_MAX_GROUND_POTENTIAL_V + 0.001,
            ),
            (
                "minimum_voltage_rating_margin_v",
                rail.HARD_MIN_VOLTAGE_RATING_MARGIN_V - 0.001,
            ),
            (
                "minimum_analyzer_input_impedance_ohm",
                rail.HARD_MIN_ANALYZER_INPUT_IMPEDANCE_OHM - 1,
            ),
            (
                "maximum_signal_continuity_ohm",
                rail.HARD_MAX_SIGNAL_CONTINUITY_OHM + 0.001,
            ),
            (
                "maximum_ground_continuity_ohm",
                rail.HARD_MAX_GROUND_CONTINUITY_OHM + 0.001,
            ),
        ]
        for index, (field, value) in enumerate(mutations):
            with self.subTest(field=field):
                fresh = Bundle(self.base / f"hard-bound-{index}")
                fresh.plan["electrical_method"][field] = value
                fresh.write()
                with self.assertRaises(rail.PreflightError):
                    rail.validate_bundle(
                        fresh.root, verification_time_utc=datetime.now(timezone.utc)
                    )

    def test_continuity_and_isolation_must_be_electrically_consistent(self) -> None:
        self.bundle.receipt["signal_mapping"]["signal_ground"][
            "continuity_resistance_ohm"
        ] = 0.95
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "isolation-mismatch")
        self.bundle.plan["intended_instruments"]["oscilloscope"][
            "protective_earth_class"
        ] = "earth_referenced"
        self.bundle.write()
        self.assert_rejected()

    def test_phase_scope_cannot_bleed_into_capture_or_change_action(self) -> None:
        capture = self.bundle.plan["phase_scopes"]["capture_energization"]
        capture["authorized"] = True
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "action-broadened")
        self.bundle.plan["phase_scopes"][
            "deenergized_analyzer_attach"
        ]["actions"].append("energize_for_capture")
        self.bundle.write()
        self.assert_rejected()

    def test_stale_or_wrong_phase_evidence_fails(self) -> None:
        entry = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["evidence_type"] == "voltage_measurement_record"
        )
        entry["captured_at_utc"] = utc(self.bundle.valid_from + timedelta(seconds=10))
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "phase-set-mutated")
        self.bundle.receipt["phase_receipts"][
            "bounded_energized_scope_measurement"
        ]["evidence_types"] = ["voltage_measurement_record"]
        self.bundle.write()
        self.assert_rejected()

    def test_authorization_receipt_byte_hash_is_bound_before_action(self) -> None:
        phase = "bounded_energized_scope_measurement"
        evidence_type = rail.PHASE_AUTHORIZATION_EVIDENCE[phase]
        entry = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["evidence_type"] == evidence_type
        )
        entry["captured_at_utc"] = utc(self.bundle.phase_times[phase][0] + timedelta(seconds=1))
        self.rewrite()
        self.assert_rejected()

    def test_zero_energy_and_disconnect_evidence_are_fail_closed(self) -> None:
        phase = self.bundle.receipt["phase_receipts"][
            "deenergized_analyzer_attach"
        ]
        phase["zero_energy"]["maximum_observed_abs_v"] = 0.05
        self.rewrite()
        self.assert_rejected()

    def test_zero_energy_duration_points_instrument_and_chronology_fail(self) -> None:
        mutations = [
            lambda zero, began: zero.__setitem__(
                "observation_ended_at_utc", utc(began + timedelta(seconds=5, milliseconds=500))
            ),
            lambda zero, began: zero.__setitem__(
                "measurement_points", ["uart_signal_ground_to_chassis"]
            ),
            lambda zero, began: zero.__setitem__(
                "measurement_instrument_asset_id", "unreviewed-meter"
            ),
            lambda zero, began: zero.__setitem__(
                "power_disconnected_at_utc", utc(began + timedelta(seconds=6))
            ),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                fresh = Bundle(self.base / f"zero-detail-{index}")
                phase_name = "deenergized_scope_detach"
                zero = fresh.receipt["phase_receipts"][phase_name]["zero_energy"]
                mutation(zero, fresh.phase_times[phase_name][0])
                fresh.write()
                with self.assertRaises(rail.PreflightError):
                    rail.validate_bundle(
                        fresh.root, verification_time_utc=datetime.now(timezone.utc)
                    )

    def test_completion_must_follow_final_evidence_and_precede_verifier_clock(self) -> None:
        final_end = self.bundle.phase_times["deenergized_analyzer_detach"][1]
        self.bundle.receipt["completed_at_utc"] = utc(final_end)
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "future-completion")
        self.bundle.receipt["completed_at_utc"] = utc(datetime.now(timezone.utc) + timedelta(minutes=1))
        self.bundle.write()
        self.assert_rejected()

    def test_direction_ground_and_silkscreen_inference_fail(self) -> None:
        mapping = self.bundle.receipt["signal_mapping"]["host_to_controller"]
        mapping["destination_endpoint"] = "k230_uart_rx"
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "silkscreen")
        self.bundle.receipt["signal_mapping"]["signal_ground"][
            "silkscreen_inference_used"
        ] = True
        self.bundle.write()
        self.assert_rejected()

    def test_levels_rating_usb_and_drive_mode_are_fail_closed(self) -> None:
        mutations = [
            lambda receipt: receipt["measured_levels"].__setitem__(
                "analyzer_threshold_v", 3.0
            ),
            lambda receipt: receipt["measured_levels"].__setitem__(
                "usb_earth_relationship", "unknown"
            ),
            lambda receipt: receipt["measured_levels"]["controller_to_host"].__setitem__(
                "drive_mode", "unknown"
            ),
            lambda receipt: receipt["instruments"]["logic_analyzer"].__setitem__(
                "tx_connected", True
            ),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                fresh = Bundle(self.base / f"electrical-{index}")
                mutation(fresh.receipt)
                fresh.write()
                with self.assertRaises(rail.PreflightError):
                    rail.validate_bundle(fresh.root, verification_time_utc=datetime.now(timezone.utc))

    def test_attach_remove_esd_and_post_review_are_fail_closed(self) -> None:
        mutations = [
            lambda receipt: receipt["procedure_observations"].__setitem__(
                "scope_attach_order",
                ["host_to_controller", "proven_signal_ground", "controller_to_host"],
            ),
            lambda receipt: receipt["procedure_observations"].__setitem__(
                "esd_controls_observed", False
            ),
            lambda receipt: receipt["post_evidence_review"].__setitem__(
                "every_raw_evidence_hash_reviewed", False
            ),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                fresh = Bundle(self.base / f"procedure-{index}")
                mutation(fresh.receipt)
                fresh.write()
                with self.assertRaises(rail.PreflightError):
                    rail.validate_bundle(fresh.root, verification_time_utc=datetime.now(timezone.utc))

    def test_raw_evidence_tamper_unexpected_sibling_and_cross_domain_signature_fail(self) -> None:
        entry = self.bundle.receipt["evidence"][0]
        (self.bundle.root / rail.EVIDENCE_DIRECTORY_NAME / entry["filename"]).write_bytes(
            b"tampered"
        )
        self.assert_rejected()
        self.bundle = Bundle(self.base / "sibling")
        self.bundle.write()
        (self.bundle.root / "unexpected.private").write_bytes(b"x")
        self.assert_rejected()
        self.bundle = Bundle(self.base / "cross-domain")
        self.bundle.write()
        shutil.copyfile(
            self.bundle.root / rail.PLAN_REVIEWER_SIGNATURE_NAME,
            self.bundle.root / rail.RECEIPT_REVIEWER_SIGNATURE_NAME,
        )
        self.assert_rejected()

    def test_truncated_png_and_unstructured_json_are_rejected(self) -> None:
        photo = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["evidence_type"] in rail.PHOTO_EVIDENCE_TYPES
        )
        raw = b"\x89PNG\r\n\x1a\n"
        self.bundle.evidence_raw[photo["evidence_type"]] = raw
        photo["sha256"] = rail.sha256_bytes(raw)
        photo["size_bytes"] = len(raw)
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "dummy-json")
        record = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["media_type"] == "application/json"
            and item["evidence_type"]
            not in rail.PHASE_AUTHORIZATION_EVIDENCE.values()
        )
        raw = canonical({"dummy": True})
        self.bundle.evidence_raw[record["evidence_type"]] = raw
        record["sha256"] = rail.sha256_bytes(raw)
        record["size_bytes"] = len(raw)
        self.bundle.write()
        self.assert_rejected()

    def test_one_pixel_photo_is_not_evidence(self) -> None:
        photo = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["evidence_type"] in rail.PHOTO_EVIDENCE_TYPES
        )
        raw = png_bytes("one-pixel-is-not-a-photo", 1, 1)
        self.bundle.evidence_raw[photo["evidence_type"]] = raw
        photo["sha256"] = rail.sha256_bytes(raw)
        photo["size_bytes"] = len(raw)
        self.rewrite()
        self.assert_rejected()

    def test_type_specific_record_facts_cannot_be_self_asserted_or_backdated(self) -> None:
        entry = next(
            item
            for item in self.bundle.receipt["evidence"]
            if item["evidence_type"] == "voltage_measurement_record"
        )
        raw = rail.read_regular(
            self.bundle.root / rail.EVIDENCE_DIRECTORY_NAME / entry["filename"],
            rail.MAX_EVIDENCE_FILE_BYTES,
            "test evidence",
        )
        record = json.loads(raw.decode("ascii"))
        record["facts"]["measurement_uncertainty_v"] = 99.0
        changed = canonical(record)
        self.bundle.evidence_raw[entry["evidence_type"]] = changed
        entry["sha256"] = rail.sha256_bytes(changed)
        entry["size_bytes"] = len(changed)
        self.rewrite()
        self.assert_rejected()

    def test_capture_performed_and_authority_claims_fail(self) -> None:
        self.bundle.receipt["phase_receipts"]["capture_energization"][
            "performed"
        ] = True
        self.rewrite()
        self.assert_rejected()
        self.bundle = Bundle(self.base / "authority-claim")
        self.bundle.receipt["claims"]["authorization_c_granted"] = True
        self.bundle.write()
        self.assert_rejected()

    def test_symlink_evidence_and_output_parent_are_rejected(self) -> None:
        source = self.base / "source.bin"
        source.write_bytes(b"x")
        entry = self.bundle.receipt["evidence"][0]
        evidence_path = self.bundle.root / rail.EVIDENCE_DIRECTORY_NAME / entry["filename"]
        evidence_path.unlink()
        try:
            evidence_path.symlink_to(source)
        except OSError:
            self.skipTest("symlink creation is not available")
        self.assert_rejected()

        self.bundle = Bundle(self.base / "alias-parent-bundle")
        self.bundle.write()
        real = self.base / "real-output"
        real.mkdir()
        alias = self.base / "alias-output"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink creation is not available")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = rail.main(
                [
                    "--bundle",
                    str(self.bundle.root),
                    "--output",
                    str(alias / "receipt.json"),
                    "--ledger-root",
                    str(self.base / "should-not-exist"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertFalse((real / "receipt.json").exists())
        self.assertFalse((self.base / "should-not-exist").exists())
        self.assertNotIn(str(self.base), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
