#!/usr/bin/env python3
"""Adversarial host-only tests for the S19k endurance evidence lane."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import s19k_endurance_collect as collector
import s19k_endurance_baseline as baseline_builder
import s19k_endurance_verify as verifier
import s19k_phase3_physical_verify as phase3_physical
import s19k_phase12_normalize as phase3_normalizer
from test_s19k_no_work_verify import (
    LIVE_SHA,
    instrument_csv,
    normalization_config_data,
    preflight_data,
)


def write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def kv(items: list[tuple[str, object]]) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in items).encode("ascii")


def lineage(path: str, elapsed_s: int) -> bytes:
    items = (
        ("elapsed_s", str(elapsed_s)),
        ("accepted", "true"),
        ("path", path),
        ("attribution", "exact-uart-origin"),
        ("work_generation", "1"),
        ("worker_name", "worker"),
        ("job_id", "job"),
        ("extranonce2", "00000001"),
        ("ntime", "65000000"),
        ("nonce", "00000001"),
        ("version_bits", "none"),
        ("version", "20000000"),
    )
    output = bytearray()
    for key, value in items:
        key_bytes = key.encode()
        value_bytes = value.encode()
        output.extend(struct.pack(">I", len(key_bytes)))
        output.extend(key_bytes)
        output.extend(struct.pack(">I", len(value_bytes)))
        output.extend(value_bytes)
    return bytes(output)


def phase3_provenance_contents() -> dict[str, bytes]:
    plan = b"phase3-live-plan\n"
    transcript = b"phase3 transcript\n"
    receipt = b"phase3 receipt\n"
    meter = b"wall_unix_ms,power_mw\n1000,3000000\n61000,3000000\n"
    verification = {
        "accepted_paths": list(verifier.REQUIRED_PATHS),
        "plan_sha256": hashlib.sha256(plan).hexdigest(),
        "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        "required_paths": list(verifier.REQUIRED_PATHS),
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
        "verification_id": "7" * 64,
    }
    physical_manifest = b"phase3 physical manifest\n"
    physical_preflight = b"phase3 preflight\n"
    physical_normalization_config = b"phase3 normalization config\n"
    physical_source = b"phase3 raw instrument export\n"
    physical_normalization_receipt = b"phase3 normalization receipt\n"
    physical_capture = b"phase3 safeoff capture\n"
    physical_verifier = b"# phase3 physical verifier\n"
    physical_verification = {
        "schema": phase3_physical.RESULT_SCHEMA,
        "plan_sha256": hashlib.sha256(plan).hexdigest(),
        "bounded_verification_id": "7" * 64,
        "manifest_sha256": hashlib.sha256(physical_manifest).hexdigest(),
        "preflight_sha256": hashlib.sha256(physical_preflight).hexdigest(),
        "normalization_config_sha256": hashlib.sha256(
            physical_normalization_config
        ).hexdigest(),
        "instrument_source_sha256": hashlib.sha256(physical_source).hexdigest(),
        "normalization_receipt_sha256": hashlib.sha256(
            physical_normalization_receipt
        ).hexdigest(),
        "capture_sha256": hashlib.sha256(physical_capture).hexdigest(),
        "rail_decay_confirmed_ms": 10_000,
        "capture_end_ms": 15_000,
        "verification_id": "6" * 64,
    }
    return {
        "phase3_plan.kv": plan,
        "phase3_transcript.log": transcript,
        "phase3_receipt.kv": receipt,
        "phase3_wall_power.csv": meter,
        "phase3_verifier.py": b"# phase3 verifier\n",
        "phase3_baseline_builder.py": b"# baseline builder\n",
        "phase3_host_verification.json": (
            json.dumps(verification, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii"),
        "phase3_safeoff_manifest.kv": physical_manifest,
        "instrumentation_preflight.kv": physical_preflight,
        "phase3_normalization_config.json": physical_normalization_config,
        "phase3_instrument_source.raw": physical_source,
        "phase3_normalization_receipt": physical_normalization_receipt,
        "phase3_safeoff.csv": physical_capture,
        "phase3_physical_verifier.py": physical_verifier,
        "phase3_safeoff_parser.py": b"# shared safeoff parser\n",
        "phase3_normalizer.py": b"# phase3 normalizer\n",
        "phase3_physical_verification.json": (
            json.dumps(
                physical_verification, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii"),
    }


def make_baseline(path: Path, evidence: Path | None = None) -> bytes:
    contents = phase3_provenance_contents()
    values: dict[str, object] = {
        "schema": verifier.BASELINE_SCHEMA,
        "phase3_wall_power_sample_count": 2,
        "phase3_wall_power_first_unix_ms": 1000,
        "phase3_wall_power_last_unix_ms": 61000,
        "phase3_verification_id": "7" * 64,
        "phase3_physical_verification_id": "6" * 64,
        "hashrate_min_millighs": 90_000_000,
        "hashrate_max_millighs": 110_000_000,
        "reject_rate_max_ppm": 0,
        "wall_power_min_mw": 2_000_000,
        "wall_power_max_mw": 4_000_000,
        "safeoff_wall_power_max_mw": 100_000,
        "warmup_intervals": 0,
        "autotuner": "disabled",
        "declared_before_launch_unix_s": 62,
        "publication": "no-clobber-hard-link-after-fsync",
    }
    for filename, hash_key, size_key, _ in verifier.PHASE3_PROVENANCE_FILES:
        values[hash_key] = hashlib.sha256(contents[filename]).hexdigest()
        values[size_key] = len(contents[filename])
    data = kv([(key, values[key]) for key in verifier.BASELINE_KEYS])
    write(path, data)
    if evidence is not None:
        provenance = evidence / "phase3_provenance"
        provenance.mkdir()
        for filename, content in contents.items():
            write(provenance / filename, content)
    return data


def make_complete_fixture(root: Path) -> tuple[Path, Path, Path]:
    evidence = root / "evidence"
    segments = evidence / "segments"
    manifests = evidence / "manifests"
    final = evidence / "final"
    segments.mkdir(parents=True)
    manifests.mkdir()
    final.mkdir()
    baseline_path = root / "baseline.kv"
    baseline_data = make_baseline(baseline_path, evidence)
    meter_path = root / "meter.csv"

    source_runtime_data = kv([
        ("schema", "dcentos.s19k-tmp-runtime/v5"),
        ("deploy_mode", "endurance-work-proof"),
        ("persistent_mutation", "false"),
    ])
    pending_runtime_data = kv([
        ("schema", "dcentos.s19k-stock-restart-pending/v4"),
        ("disposition", "checked-safeoff-stock-restart-pending"),
    ])
    runtime_sha = hashlib.sha256(source_runtime_data).hexdigest()
    runtime_bytes = len(source_runtime_data)
    identity_sha = "b" * 64
    predecessor_segment = verifier.genesis_sha256(runtime_sha, runtime_bytes, identity_sha)
    predecessor_manifest = verifier.EMPTY_SHA256
    wall_origin = 1_700_000_000_000
    write(evidence / "COLLECTION_START.kv", kv([
        ("schema", "dcentos.s19k-endurance-collection-start/v1"),
        ("started_wall_unix_ms", wall_origin - 1_000),
        ("miner_target_sha256", "d" * 64),
        ("ssh_host_key_sha256", "SHA256:" + "A" * 43),
        ("launch_plan_sha256", "e" * 64),
        ("baseline_sha256", hashlib.sha256(baseline_data).hexdigest()),
        ("publication", "host-create-new-fsync"),
    ]))
    accepted_totals = {path: 0 for path in verifier.REQUIRED_PATHS}
    accepted_bits = {path: 0 for path in verifier.REQUIRED_PATHS}
    acceptance_sequences = {0: 0, 360: 1, 720: 2, 1080: 3}
    last_segment = b""
    last_manifest = b""
    meter_lines = ["wall_unix_ms,power_mw\n"]

    for sequence in range(1440):
        mono_start = sequence * 60_000
        mono_end = mono_start + 60_000
        wall_start = wall_origin + mono_start
        wall_end = wall_origin + mono_end
        accepted_this = 1 if sequence in acceptance_sequences else 0
        lineages: list[bytes] = []
        if accepted_this:
            window = acceptance_sequences[sequence]
            elapsed_s = window * 21_600 + 1
            for path in verifier.REQUIRED_PATHS:
                accepted_totals[path] += 1
                accepted_bits[path] |= 1 << window
                lineages.append(lineage(path, elapsed_s))
        fields: list[tuple[str, object]] = [
            ("schema", verifier.SEGMENT_SCHEMA),
            ("sequence", sequence),
            ("segment_kind", "terminal-pass" if sequence == 1439 else "minute"),
            ("predecessor_sha256", predecessor_segment),
            ("genesis_sha256", verifier.genesis_sha256(runtime_sha, runtime_bytes, identity_sha)),
            ("runtime_active_sha256", runtime_sha),
            ("runtime_active_bytes", runtime_bytes),
            ("live_identity_sha256", identity_sha),
            ("interval_monotonic_start_ms", mono_start),
            ("interval_monotonic_end_ms", mono_end),
            ("interval_duration_ms", 60_000),
            ("interval_wall_start_unix_ms", wall_start),
            ("interval_wall_end_unix_ms", wall_end),
            ("interval_wall_duration_ms", 60_000),
            ("pool_state_hex", b"Alive".hex()),
            ("aggregate_hashrate_millighs", 100_000_000),
            ("hottest_temp_millic", 65_000),
            ("dangerous_temp_millic", 90_000),
            ("fan_pwm", 100),
            ("fan_readings", "0:3000,1:3010,2:3020,3:3030"),
            ("gpio437", 0),
            ("required_path_count", 2),
        ]
        for index, path in enumerate(verifier.REQUIRED_PATHS):
            fields.extend([
                (f"path_{index}_hex", path.encode().hex()),
                (f"path_{index}_chips", 77),
                (f"path_{index}_complete77", "true"),
                (f"path_{index}_tx_frames_total", sequence + 1),
                (f"path_{index}_tx_frames_delta", 1),
                (f"path_{index}_rx_wire_bytes_total", (sequence + 1) * 10),
                (f"path_{index}_rx_wire_bytes_delta", 10),
                (f"path_{index}_rx_frames_total", sequence + 1),
                (f"path_{index}_rx_frames_delta", 1),
                (f"path_{index}_valid_nonces_total", sequence + 1),
                (f"path_{index}_valid_nonces_delta", 1),
                (f"path_{index}_shares_submitted_total", accepted_totals[path]),
                (f"path_{index}_shares_submitted_delta", accepted_this),
                (f"path_{index}_shares_accepted_total", accepted_totals[path]),
                (f"path_{index}_shares_accepted_delta", accepted_this),
                (f"path_{index}_shares_rejected_total", 0),
                (f"path_{index}_shares_rejected_delta", 0),
                (f"path_{index}_accepted_window_bits", f"{accepted_bits[path]:04b}"),
            ])
        fields.append(("event_count", 0))
        fields.append(("share_lineage_count", len(lineages)))
        fields.extend((f"share_lineage_{index}_hex", value.hex()) for index, value in enumerate(lineages))
        fields.extend([
            ("acceptance_complete", "true" if sequence >= 1080 else "false"),
            ("collector_ack_timeout_s", 300),
            ("collector_max_unacked_segments", 6),
            ("collector_max_unacked_bytes", 524288),
            ("publication", "no-clobber-hard-link-after-fsync"),
        ])
        segment_data = kv(fields)
        write(segments / f"segment.{sequence:06}.kv", segment_data)
        manifest_data = collector.manifest_entry(sequence, segment_data, predecessor_manifest, wall_end)
        write(manifests / f"manifest.{sequence:06}.kv", manifest_data)
        predecessor_segment = hashlib.sha256(segment_data).hexdigest()
        predecessor_manifest = hashlib.sha256(manifest_data).hexdigest()
        last_segment = segment_data
        last_manifest = manifest_data
        meter_lines.append(f"{wall_end},3000000\n")
    daemon_data = kv([
        ("schema", verifier.DAEMON_TERMINAL_SCHEMA),
        ("outcome", "pass-pending-runner-safeoff"),
        ("elapsed_s", 86400),
        ("minimum_s", 86400),
        ("maximum_s", 93600),
        ("segment_count", 1440),
        ("terminal_sequence", 1439),
        ("segment_chain_head_sha256", hashlib.sha256(last_segment).hexdigest()),
        ("off_target_manifest_sha256", hashlib.sha256(last_manifest).hexdigest()),
        ("off_target_manifest_bytes", len(last_manifest)),
        ("runtime_active_sha256", runtime_sha),
        ("runtime_active_bytes", runtime_bytes),
        ("live_identity_sha256", identity_sha),
        ("acceptance_windows", "4x6h-per-required-uart"),
        ("publication", "no-clobber-hard-link-after-fsync"),
    ])
    terminal_handoff_data = kv([
        ("schema", "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1"),
        ("disposition", "terminal-safeoff-partial-stock-owner"),
        ("runtime_active_sha256", runtime_sha),
        ("runtime_active_bytes", runtime_bytes),
        ("terminal_safeoff", "true"),
        ("resets", "454:0,455:0,456:0"),
    ])
    safeoff_data = (
        "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
        f"schema=dcentos.s19k-track1-safeoff/v1 live_identity_sha256={identity_sha} "
        f"live_identity_profile=live88_two_bhb56903_slots_2_3 live_identity_model_sha256={'c' * 64} "
        "live_identity_board_count=2 live_identity_physical_addresses=2,3 "
        "live_identity_board_names=BHB56903,BHB56903 "
        "live_identity_eeprom=0x50=absent,0x51=05:11,0x52=05:11 "
        "resets=454:0,455:0,456:0 psu=437:1\n"
    ).encode("ascii")
    target_values = {
        "schema": verifier.TARGET_RECEIPT_SCHEMA,
        "deploy_mode": "endurance-work-proof",
        "daemon_terminal_path": "/tmp/trial/endurance_evidence/daemon_terminal",
        "daemon_terminal_sha256": hashlib.sha256(daemon_data).hexdigest(),
        "daemon_terminal_bytes": len(daemon_data),
        "segment_count": 1440,
        "terminal_sequence": 1439,
        "segment_chain_head_sha256": hashlib.sha256(last_segment).hexdigest(),
        "off_target_manifest_sha256": hashlib.sha256(last_manifest).hexdigest(),
        "off_target_manifest_bytes": len(last_manifest),
        "source_runtime_active_schema": "dcentos.s19k-tmp-runtime/v5",
        "source_runtime_active_path": "/tmp/trial/runtime_active_pre_safeoff",
        "source_runtime_active_sha256": runtime_sha,
        "source_runtime_active_bytes": runtime_bytes,
        "pending_runtime_schema": "dcentos.s19k-stock-restart-pending/v4",
        "pending_runtime_path": "/tmp/trial/runtime_active",
        "pending_runtime_sha256": hashlib.sha256(pending_runtime_data).hexdigest(),
        "pending_runtime_bytes": len(pending_runtime_data),
        "terminal_handoff_receipt_schema": "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
        "terminal_handoff_receipt_path": "/tmp/trial/runtime_terminal_safeoff",
        "terminal_handoff_receipt_sha256": hashlib.sha256(terminal_handoff_data).hexdigest(),
        "terminal_handoff_receipt_bytes": len(terminal_handoff_data),
        "safeoff_receipt_schema": "dcentos.s19k-track1-safeoff/v1",
        "safeoff_receipt_path": "/tmp/trial/runtime_safeoff_terminal_receipt",
        "safeoff_receipt_sha256": hashlib.sha256(safeoff_data).hexdigest(),
        "safeoff_receipt_bytes": len(safeoff_data),
        "binary_sha256": "1" * 64,
        "binary_bytes": 1,
        "config_sha256": "2" * 64,
        "config_bytes": 2,
        "runner_sha256": "3" * 64,
        "runner_bytes": 3,
        "custody_observer_sha256": "4" * 64,
        "custody_observer_bytes": 4,
        "stock_restart_helper_sha256": "5" * 64,
        "stock_restart_helper_bytes": 5,
        "live_identity_schema": "dcentos.s19k-braiins-live-identity/v2",
        "live_identity_profile": "live88_two_bhb56903_slots_2_3",
        "live_identity_sha256": identity_sha,
        "wrapper_exit_status": 0,
        "semantic_verification": "host-required",
        "persistent_mutation": "false",
        "publication": "no-clobber-hard-link-after-fsync",
    }
    target_data = kv([(key, target_values[key]) for key in verifier.TARGET_RECEIPT_KEYS])
    write(final / "daemon_terminal", daemon_data)
    write(final / "terminal_handoff", terminal_handoff_data)
    write(final / "safeoff", safeoff_data)
    write(final / "endurance_receipt", target_data)
    write(final / "runtime_active_pre_safeoff", source_runtime_data)
    write(final / "runtime_pending", pending_runtime_data)
    final_collected_ms = wall_origin + 86_400_000 + 1_000
    final_collection_data = kv([
        ("schema", "dcentos.s19k-endurance-final-collection/v1"),
        ("daemon_terminal_sha256", hashlib.sha256(daemon_data).hexdigest()),
        ("terminal_handoff_sha256", hashlib.sha256(terminal_handoff_data).hexdigest()),
        ("safeoff_sha256", hashlib.sha256(safeoff_data).hexdigest()),
        ("endurance_receipt_sha256", hashlib.sha256(target_data).hexdigest()),
        ("runtime_active_pre_safeoff_sha256", hashlib.sha256(source_runtime_data).hexdigest()),
        ("runtime_pending_sha256", hashlib.sha256(pending_runtime_data).hexdigest()),
        ("collected_wall_unix_ms", final_collected_ms),
        ("publication", "host-create-new-fsync"),
    ])
    write(evidence / "FINAL_COLLECTION.kv", final_collection_data)
    meter_lines.append(f"{final_collected_ms + 10_000},50000\n")
    meter_lines.append(f"{final_collected_ms + 15_000},50000\n")
    write(meter_path, "".join(meter_lines).encode("ascii"))
    return evidence, baseline_path, meter_path


def make_failure_fixture(root: Path) -> tuple[Path, Path, Path]:
    evidence = root / "failure-evidence"
    (evidence / "segments").mkdir(parents=True)
    (evidence / "manifests").mkdir()
    final = evidence / "final"
    final.mkdir()
    baseline_path = root / "failure-baseline.kv"
    baseline_data = make_baseline(baseline_path, evidence)
    meter_path = root / "failure-meter.csv"
    source_data = kv([
        ("schema", "dcentos.s19k-tmp-runtime/v5"),
        ("deploy_mode", "endurance-work-proof"),
        ("persistent_mutation", "false"),
    ])
    pending_data = kv([
        ("schema", "dcentos.s19k-stock-restart-pending/v4"),
        ("disposition", "checked-safeoff-stock-restart-pending"),
    ])
    runtime_sha = hashlib.sha256(source_data).hexdigest()
    identity_sha = "b" * 64
    reason_hex = b"collector acknowledgement timeout".hex()
    write(evidence / "COLLECTION_START.kv", kv([
        ("schema", "dcentos.s19k-endurance-collection-start/v1"),
        ("started_wall_unix_ms", 1_699_999_999_000),
        ("miner_target_sha256", "d" * 64),
        ("ssh_host_key_sha256", "SHA256:" + "A" * 43),
        ("launch_plan_sha256", "e" * 64),
        ("baseline_sha256", hashlib.sha256(baseline_data).hexdigest()),
        ("publication", "host-create-new-fsync"),
    ]))
    daemon_data = kv([
        ("schema", verifier.DAEMON_FAILURE_SCHEMA),
        ("outcome", "fail-after-checked-safeoff"),
        ("elapsed_s", 61),
        ("segment_count", 0),
        ("acknowledged_segments", 0),
        ("unacknowledged_segments", 0),
        ("unacknowledged_bytes", 0),
        ("segment_chain_head_sha256", verifier.genesis_sha256(runtime_sha, len(source_data), identity_sha)),
        ("off_target_manifest_sha256", verifier.EMPTY_SHA256),
        ("off_target_manifest_bytes", 0),
        ("runtime_active_sha256", runtime_sha),
        ("runtime_active_bytes", len(source_data)),
        ("live_identity_sha256", identity_sha),
        ("checked_safeoff", "true"),
        ("failure_reason_utf8_hex", reason_hex),
        ("publication", "no-clobber-hard-link-after-fsync"),
    ])
    terminal_handoff_data = kv([
        ("schema", "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1"),
        ("disposition", "terminal-safeoff-partial-stock-owner"),
        ("runtime_active_sha256", runtime_sha),
        ("runtime_active_bytes", len(source_data)),
        ("terminal_safeoff", "true"),
        ("resets", "454:0,455:0,456:0"),
    ])
    safeoff_data = (
        "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
        f"schema=dcentos.s19k-track1-safeoff/v1 live_identity_sha256={identity_sha} "
        f"live_identity_profile=live88_two_bhb56903_slots_2_3 live_identity_model_sha256={'c' * 64} "
        "live_identity_board_count=2 live_identity_physical_addresses=2,3 "
        "live_identity_board_names=BHB56903,BHB56903 "
        "live_identity_eeprom=0x50=absent,0x51=05:11,0x52=05:11 "
        "resets=454:0,455:0,456:0 psu=437:1\n"
    ).encode("ascii")
    target_values = {
        "schema": verifier.TARGET_FAILURE_RECEIPT_SCHEMA,
        "deploy_mode": "endurance-work-proof",
        "outcome": "fail-after-checked-safeoff",
        "daemon_failure_path": "/tmp/trial/endurance_evidence/daemon_failure",
        "daemon_failure_sha256": hashlib.sha256(daemon_data).hexdigest(),
        "daemon_failure_bytes": len(daemon_data),
        "elapsed_s": 61,
        "segment_count": 0,
        "acknowledged_segments": 0,
        "unacknowledged_segments": 0,
        "unacknowledged_bytes": 0,
        "segment_chain_head_sha256": verifier.genesis_sha256(runtime_sha, len(source_data), identity_sha),
        "off_target_manifest_sha256": verifier.EMPTY_SHA256,
        "off_target_manifest_bytes": 0,
        "failure_reason_utf8_hex": reason_hex,
        "source_runtime_active_schema": "dcentos.s19k-tmp-runtime/v5",
        "source_runtime_active_path": "/tmp/trial/runtime_active_pre_safeoff",
        "source_runtime_active_sha256": runtime_sha,
        "source_runtime_active_bytes": len(source_data),
        "pending_runtime_schema": "dcentos.s19k-stock-restart-pending/v4",
        "pending_runtime_path": "/tmp/trial/runtime_active",
        "pending_runtime_sha256": hashlib.sha256(pending_data).hexdigest(),
        "pending_runtime_bytes": len(pending_data),
        "terminal_handoff_receipt_schema": "dcentos.s19k-terminal-safeoff-partial-stock-owner/v1",
        "terminal_handoff_receipt_path": "/tmp/trial/runtime_terminal_safeoff",
        "terminal_handoff_receipt_sha256": hashlib.sha256(terminal_handoff_data).hexdigest(),
        "terminal_handoff_receipt_bytes": len(terminal_handoff_data),
        "safeoff_receipt_schema": "dcentos.s19k-track1-safeoff/v1",
        "safeoff_receipt_path": "/tmp/trial/runtime_safeoff_terminal_receipt",
        "safeoff_receipt_sha256": hashlib.sha256(safeoff_data).hexdigest(),
        "safeoff_receipt_bytes": len(safeoff_data),
        "binary_sha256": "1" * 64,
        "binary_bytes": 1,
        "config_sha256": "2" * 64,
        "config_bytes": 2,
        "runner_sha256": "3" * 64,
        "runner_bytes": 3,
        "custody_observer_sha256": "4" * 64,
        "custody_observer_bytes": 4,
        "stock_restart_helper_sha256": "5" * 64,
        "stock_restart_helper_bytes": 5,
        "live_identity_schema": "dcentos.s19k-braiins-live-identity/v2",
        "live_identity_profile": "live88_two_bhb56903_slots_2_3",
        "live_identity_sha256": identity_sha,
        "wrapper_exit_status": 1,
        "semantic_verification": "host-required",
        "persistent_mutation": "false",
        "publication": "no-clobber-hard-link-after-fsync",
    }
    target_data = kv([(key, target_values[key]) for key in verifier.TARGET_FAILURE_RECEIPT_KEYS])
    write(final / "daemon_failure", daemon_data)
    write(final / "terminal_handoff", terminal_handoff_data)
    write(final / "safeoff", safeoff_data)
    write(final / "endurance_failure_receipt", target_data)
    write(final / "runtime_active_pre_safeoff", source_data)
    write(final / "runtime_pending", pending_data)
    collected_ms = 1_700_000_000_000
    collection_data = kv([
        ("schema", "dcentos.s19k-endurance-failure-final-collection/v1"),
        ("daemon_failure_sha256", hashlib.sha256(daemon_data).hexdigest()),
        ("terminal_handoff_sha256", hashlib.sha256(terminal_handoff_data).hexdigest()),
        ("safeoff_sha256", hashlib.sha256(safeoff_data).hexdigest()),
        ("endurance_failure_receipt_sha256", hashlib.sha256(target_data).hexdigest()),
        ("runtime_active_pre_safeoff_sha256", hashlib.sha256(source_data).hexdigest()),
        ("runtime_pending_sha256", hashlib.sha256(pending_data).hexdigest()),
        ("collected_wall_unix_ms", collected_ms),
        ("publication", "host-create-new-fsync"),
    ])
    write(evidence / "FAILURE_COLLECTION.kv", collection_data)
    write(
        meter_path,
        (
            "wall_unix_ms,power_mw\n"
            f"{collected_ms + 10_000},50000\n"
            f"{collected_ms + 15_000},50000\n"
        ).encode("ascii"),
    )
    return evidence, baseline_path, meter_path


class EnduranceVerifierTests(unittest.TestCase):
    def test_baseline_builder_reverifies_and_binds_phase3_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "phase3-plan.kv"
            trial = root / "phase3-trial"
            meter = root / "phase3-meter.csv"
            physical_dir = root / "phase3-physical"
            trial.mkdir()
            physical_dir.mkdir()
            plan_data = (
                b"ssh_host_key_sha256="
                b"SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg\n"
            )
            receipt_data = b"verified Phase-3 receipt\n"
            transcript_name = ".startup_daemon_transcript.1.2"
            transcript_data = b"verified Phase-3 transcript\n"
            meter_data = b"wall_unix_ms,power_mw\n1000,3000000\n61000,3000000\n"
            write(plan, plan_data)
            write(trial / "runtime_bounded_work_transcript", receipt_data)
            write(trial / transcript_name, transcript_data)
            write(
                trial / "dcentrald_s19k.toml",
                b"[thermal]\ndangerous_temp_c = 80\n",
            )
            write(meter, meter_data)
            result = {
                "required_paths": list(verifier.REQUIRED_PATHS),
                "accepted_paths": list(verifier.REQUIRED_PATHS),
                "transcript_file": transcript_name,
                "plan_sha256": hashlib.sha256(plan_data).hexdigest(),
                "receipt_sha256": hashlib.sha256(receipt_data).hexdigest(),
                "transcript_sha256": hashlib.sha256(transcript_data).hexdigest(),
                "verification_id": "8" * 64,
                "live_identity_sha256": LIVE_SHA,
            }
            physical_preflight = preflight_data()
            physical_normalization_config = normalization_config_data()
            physical_source = instrument_csv()
            physical_capture = instrument_csv()
            write(
                physical_dir / phase3_physical.PREFLIGHT_FILENAME,
                physical_preflight,
            )
            write(
                physical_dir / phase3_physical.NORMALIZATION_CONFIG_FILENAME,
                physical_normalization_config,
            )
            write(
                physical_dir / phase3_physical.SOURCE_FILENAME,
                physical_source,
            )
            config = json.loads(physical_normalization_config.decode("ascii"))
            physical_normalization_values = phase3_normalizer._instrument_receipt_values(
                config_sha256=hashlib.sha256(
                    physical_normalization_config
                ).hexdigest(),
                config_bytes=len(physical_normalization_config),
                instrument_source_sha256=hashlib.sha256(physical_source).hexdigest(),
                instrument_source_bytes=len(physical_source),
                instrument_csv_sha256=hashlib.sha256(physical_capture).hexdigest(),
                instrument_csv_bytes=len(physical_capture),
                instrument_row_count=15,
                config=config,
            )
            physical_normalization_receipt = phase3_normalizer._kv_bytes(
                phase3_normalizer.INSTRUMENT_ONLY_RECEIPT_KEYS,
                physical_normalization_values,
            )
            write(
                physical_dir / phase3_physical.NORMALIZATION_RECEIPT_FILENAME,
                physical_normalization_receipt,
            )
            write(
                physical_dir / phase3_physical.CAPTURE_FILENAME,
                physical_capture,
            )
            physical_manifest_values = {
                "schema": phase3_physical.SCHEMA,
                "claim": "independent-terminal-safeoff-after-bounded-work",
                "plan_sha256": hashlib.sha256(plan_data).hexdigest(),
                "bounded_verification_id": "8" * 64,
                "preflight_file": phase3_physical.PREFLIGHT_FILENAME,
                "preflight_sha256": hashlib.sha256(physical_preflight).hexdigest(),
                "preflight_bytes": str(len(physical_preflight)),
                "normalization_config_file": phase3_physical.NORMALIZATION_CONFIG_FILENAME,
                "normalization_config_sha256": hashlib.sha256(
                    physical_normalization_config
                ).hexdigest(),
                "normalization_config_bytes": str(len(physical_normalization_config)),
                "instrument_source_file": phase3_physical.SOURCE_FILENAME,
                "instrument_source_sha256": hashlib.sha256(
                    physical_source
                ).hexdigest(),
                "instrument_source_bytes": str(len(physical_source)),
                "normalization_receipt_file": phase3_physical.NORMALIZATION_RECEIPT_FILENAME,
                "normalization_receipt_sha256": hashlib.sha256(
                    physical_normalization_receipt
                ).hexdigest(),
                "normalization_receipt_bytes": str(
                    len(physical_normalization_receipt)
                ),
                "capture_file": phase3_physical.CAPTURE_FILENAME,
                "capture_sha256": hashlib.sha256(physical_capture).hexdigest(),
                "capture_bytes": str(len(physical_capture)),
                "common_clock_id": "scope-logic-common-clock-001",
                "rail_signal": "rail-millivolts",
                "created_utc": "2026-08-22T12:00:00Z",
                "publication": "post-run-content-manifest",
            }
            write(
                physical_dir / phase3_physical.MANIFEST_FILENAME,
                kv(
                    [
                        (key, physical_manifest_values[key])
                        for key in phase3_physical.MANIFEST_KEYS
                    ]
                ),
            )
            policy = {
                "hashrate_min_millighs": 90_000_000,
                "hashrate_max_millighs": 110_000_000,
                "reject_rate_max_ppm": 1000,
                "wall_power_min_mw": 2_000_000,
                "wall_power_max_mw": 4_000_000,
                "safeoff_wall_power_max_mw": 100_000,
                "warmup_intervals": 2,
            }
            with mock.patch.object(baseline_builder.bounded, "verify", return_value=result):
                data, files = baseline_builder.build_baseline_bytes(
                    plan,
                    trial,
                    meter,
                    physical_dir,
                    policy,
                    declared_unix_s=62,
                )
                baseline_path = root / "baseline.kv"
                write(baseline_path, data)
                fields, parsed = verifier.parse_baseline(baseline_path)
                self.assertEqual(parsed, data)
                self.assertEqual(fields["phase3_verification_id"], "8" * 64)
                self.assertEqual(files["phase3_transcript.log"], transcript_data)
                if os.name != "nt":
                    published_baseline = root / "published-baseline.kv"
                    baseline_builder.publish_new(published_baseline, data)
                    self.assertEqual(published_baseline.read_bytes(), data)
                    published_receipt = root / "published-host-receipt.kv"
                    verifier.publish_new(published_receipt, b"receipt\n")
                    self.assertEqual(published_receipt.read_bytes(), b"receipt\n")
                    self.assertFalse(any(child.name.startswith(".") for child in root.iterdir()))
                self.assertEqual(
                    baseline_builder.verify_against_baseline(
                        fields,
                        plan,
                        trial,
                        meter,
                        physical_dir,
                    ),
                    files,
                )
                write(
                    meter,
                    b"wall_unix_ms,power_mw\n1000,5000000\n61000,5000000\n",
                )
                with self.assertRaises(baseline_builder.BaselineBuildError):
                    baseline_builder.verify_against_baseline(
                        fields,
                        plan,
                        trial,
                        meter,
                        physical_dir,
                    )

    def test_target_failure_receipt_key_order_matches_host_verifier(self) -> None:
        runner = (
            Path(__file__).resolve().parent / "dcentrald_s19k_tmp_remote_run.sh"
        ).read_text(encoding="utf-8")
        function = runner.split("publish_endurance_failure_receipt() {", 1)[1].split(
            "\npublish_endurance_work_receipt() {", 1
        )[0]
        keys: list[str] = []
        for format_text in re.findall(r"printf '([^']*)'", function):
            for line in format_text.split(r"\n"):
                match = re.fullmatch(r"([a-z][a-z0-9_]*)=.*", line)
                if match:
                    keys.append(match.group(1))
        self.assertEqual(tuple(keys), verifier.TARGET_FAILURE_RECEIPT_KEYS)

    def test_controlled_failure_receipt_binds_safeoff_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, baseline, meter = make_failure_fixture(Path(directory))
            result = verifier.verify_evidence(
                evidence,
                baseline,
                meter,
                expected_failure=True,
            )
            self.assertEqual(result["outcome"], "controlled-failure-evidence-pass")
            self.assertEqual(result["segment_count"], 0)
            daemon = evidence / "final" / "daemon_failure"
            daemon.write_bytes(daemon.read_bytes().replace(b"checked_safeoff=true", b"checked_safeoff=false"))
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.verify_evidence(
                    evidence,
                    baseline,
                    meter,
                    expected_failure=True,
                )

    def test_complete_gate_and_chain_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, baseline, meter = make_complete_fixture(Path(directory))
            result = verifier.verify_evidence(evidence, baseline, meter)
            self.assertEqual(result["outcome"], "pass")
            self.assertEqual(result["segment_count"], 1440)
            self.assertEqual(result["ttyS1_acceptance_windows"], "1111")
            phase3_plan = evidence / "phase3_provenance" / "phase3_plan.kv"
            phase3_original = phase3_plan.read_bytes()
            phase3_plan.write_bytes(phase3_original + b"tamper\n")
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.verify_evidence(evidence, baseline, meter)
            phase3_plan.write_bytes(phase3_original)
            manifest = evidence / "manifests" / "manifest.000000.kv"
            original = manifest.read_bytes()
            manifest.write_bytes(original.replace(b"segment_bytes=", b"segment_bytes=0", 1))
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.verify_evidence(evidence, baseline, meter)
            manifest.write_bytes(
                original.replace(
                    b"collected_wall_unix_ms=1700000060000",
                    b"collected_wall_unix_ms=1",
                    1,
                )
            )
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.verify_evidence(evidence, baseline, meter)

    def test_baseline_is_exact_and_predeclared(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.kv"
            original = make_baseline(path)
            fields, admitted = verifier.parse_baseline(path)
            self.assertEqual(admitted, original)
            self.assertEqual(fields["autotuner"], "disabled")
            path.write_bytes(
                original.replace(
                    b"safeoff_wall_power_max_mw=100000",
                    b"safeoff_wall_power_max_mw=300000",
                )
            )
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.parse_baseline(path)
            path.write_bytes(original + b"unexpected=true\n")
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.parse_baseline(path)

    def test_runner_command_geometry_and_manifest_are_canonical(self) -> None:
        tokens = [
            "/tmp/dcentrald_bench_t1_TEST/run_trial", "run",
            "/tmp/dcentrald_bench_t1_TEST", "am3-s19k", "endurance-work-proof",
            "a" * 64, "1", "b" * 64, "2", "c" * 64, "3",
            "d" * 64, "4", "e" * 64, "5",
        ]
        plan = {"launch": " ".join(tokens), "remote_dir": tokens[2]}
        self.assertEqual(collector.runner_tokens(plan), tokens)
        command = collector.remote_command(tokens, "endurance-read", 17)
        self.assertIn(" endurance-read ", command)
        self.assertTrue(command.endswith(" 17"))
        manifest = collector.manifest_entry(0, b"segment\n", verifier.EMPTY_SHA256, 1)
        fields, order = verifier.parse_kv_bytes(manifest, "manifest", verifier.MANIFEST_KEYS)
        self.assertEqual(order, verifier.MANIFEST_KEYS)
        self.assertEqual(fields["segment_bytes"], "8")

    def test_resume_chain_rejects_local_manifest_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "segments").mkdir()
            (evidence / "manifests").mkdir()
            segment = kv([
                ("schema", verifier.SEGMENT_SCHEMA),
                ("sequence", 0),
            ])
            manifest = collector.manifest_entry(
                0,
                segment,
                verifier.EMPTY_SHA256,
                1,
            )
            write(evidence / "segments" / "segment.000000.kv", segment)
            write(evidence / "manifests" / "manifest.000000.kv", manifest)
            count, head, rows, pending = collector.resume_local_manifest_chain(evidence)
            self.assertEqual(count, 1)
            self.assertEqual(head, hashlib.sha256(manifest).hexdigest())
            self.assertEqual(rows[0][0], segment)
            self.assertIsNone(pending)
            bad = manifest.replace(b"segment_bytes=", b"segment_bytes=0", 1)
            write(evidence / "manifests" / "manifest.000000.kv", bad)
            with self.assertRaises(collector.EnduranceCollectionError):
                collector.resume_local_manifest_chain(evidence)

    def test_resume_chain_admits_only_one_manifest_first_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "segments").mkdir()
            (evidence / "manifests").mkdir()
            segment = kv([
                ("schema", verifier.SEGMENT_SCHEMA),
                ("sequence", 0),
            ])
            manifest = collector.manifest_entry(
                0,
                segment,
                verifier.EMPTY_SHA256,
                1234,
            )
            write(evidence / "manifests" / "manifest.000000.kv", manifest)
            count, head, rows, pending = collector.resume_local_manifest_chain(evidence)
            self.assertEqual((count, head, rows), (0, verifier.EMPTY_SHA256, []))
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending[0], manifest)
            self.assertEqual(pending[1], 1234)
            self.assertEqual(pending[2], verifier.EMPTY_SHA256)
            self.assertEqual(pending[3], hashlib.sha256(segment).hexdigest())
            self.assertEqual(pending[4], len(segment))

            (evidence / "manifests" / "manifest.000000.kv").unlink()
            write(evidence / "segments" / "segment.000000.kv", segment)
            with self.assertRaises(collector.EnduranceCollectionError):
                collector.resume_local_manifest_chain(evidence)

    def test_atomic_publication_scratch_is_exactly_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            directory_sync = (
                mock.patch.object(collector, "fsync_directory", return_value=None)
                if os.name == "nt"
                else mock.patch.object(
                    collector,
                    "fsync_directory",
                    wraps=collector.fsync_directory,
                )
            )
            with directory_sync:
                target = parent / "segment.000000.kv"
                collector.publish_new(target, b"complete\n")
                self.assertEqual(target.read_bytes(), b"complete\n")
                self.assertEqual(os.lstat(target).st_nlink, 1)
                self.assertFalse(any(child.name.startswith(".") for child in parent.iterdir()))

                incomplete = parent / ".segment.000001.kv.tmp.1234.aaaaaaaaaaaaaaaa"
                incomplete.write_bytes(b"partial")
                os.chmod(incomplete, 0o600)
                collector.clean_stale_publication_scratch(parent, "test evidence")
                self.assertFalse(incomplete.exists())

                linked_scratch = parent / ".segment.000002.kv.tmp.1234.bbbbbbbbbbbbbbbb"
                linked_target = parent / "segment.000002.kv"
                linked_scratch.write_bytes(b"complete-two\n")
                os.chmod(linked_scratch, 0o600)
                os.link(linked_scratch, linked_target)
                self.assertEqual(os.lstat(linked_target).st_nlink, 2)
                collector.clean_stale_publication_scratch(parent, "test evidence")
                self.assertFalse(linked_scratch.exists())
                self.assertEqual(linked_target.read_bytes(), b"complete-two\n")
                self.assertEqual(os.lstat(linked_target).st_nlink, 1)

    def test_host_plan_parser_binds_exact_runner_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            remote = "/tmp/dcentrald_bench_t1_TEST"
            hashes = {name: str(index) * 64 for index, name in enumerate((
                "sha256", "config_sha256", "runner_sha256", "custody_observer_sha256",
                "stock_restart_helper_sha256", "endurance_collector_sha256",
                "endurance_verifier_sha256", "endurance_baseline_sha256",
                "miner_target_sha256",
            ), 1)}
            sizes = {
                "sha256": 1,
                "config_sha256": 2,
                "runner_sha256": 3,
                "custody_observer_sha256": 4,
                "stock_restart_helper_sha256": 5,
                "endurance_collector_sha256": 6,
                "endurance_verifier_sha256": 7,
                "endurance_baseline_sha256": 8,
            }
            launch = " ".join((
                f"{remote}/run_trial", "run", remote, "am3-s19k", "endurance-work-proof",
                hashes["sha256"], "1", hashes["config_sha256"], "2",
                hashes["runner_sha256"], "3", hashes["custody_observer_sha256"], "4",
                hashes["stock_restart_helper_sha256"], "5",
            ))
            items: list[tuple[str, object]] = [
                ("schema", verifier.PLAN_SCHEMA),
                ("operator_artifact_pin", "required-and-matched"),
                ("expected_artifact_sha256", hashes["sha256"]),
                ("expected_artifact_bytes", 1),
                ("dry_run", "false"),
                ("mode", "endurance-work-proof"),
                ("explicit_loud_authority", "true"),
                ("work_authority", "endurance-proof"),
                ("endurance_work_proof_flag", "--s19k-track1-endurance-work-proof"),
                ("endurance_minimum_s", 86400),
                ("endurance_maximum_s", 93600),
                ("endurance_interval_s", 60),
                ("endurance_acceptance_windows", "4x6h-per-required-uart"),
                ("endurance_collector_ack_timeout_s", 300),
                ("endurance_max_unacked_segments", 6),
                ("endurance_max_unacked_bytes", 524288),
                ("ssh_host_key_admission", "exact-operator-pin"),
                ("ssh_global_known_hosts", "disabled-on-contact"),
                ("ssh_host_key_sha256", "SHA256:" + "A" * 43),
                ("persistent_mutation", "false"),
                ("clear_for_flash", "false"),
                ("native_bm1366", "refused"),
                ("runtime_receipt_schema", "dcentos.s19k-tmp-runtime/v5"),
                ("remote_dir", remote),
                ("launch", launch),
            ]
            for name, digest in hashes.items():
                items.append((name, digest))
                if name != "miner_target_sha256":
                    items.append(("bytes" if name == "sha256" else name.replace("sha256", "bytes"), sizes[name]))
            path = Path(directory) / "plan.kv"
            path.write_bytes(kv(items))
            fields, _ = verifier.parse_plan(path)
            self.assertEqual(fields["launch"], launch)
            path.write_bytes(kv([
                (key, "true" if key == "dry_run" else value)
                for key, value in items
            ]))
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.parse_plan(path)
            path.write_bytes(kv([
                (
                    key,
                    "0" * 64 if key == "expected_artifact_sha256" else value,
                )
                for key, value in items
            ]))
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.parse_plan(path)
            path.write_bytes(kv([(key, value) for key, value in items if key != "launch"] + [("launch", launch.replace(hashes["config_sha256"], "f" * 64))]))
            with self.assertRaises(verifier.EnduranceVerificationError):
                verifier.parse_plan(path)

    def test_collector_requires_independent_post_safeoff_decay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            meter = Path(directory) / "meter.csv"
            meter.write_bytes(
                b"wall_unix_ms,power_mw\n11000,50000\n16000,50000\n"
            )
            collector.wait_for_independent_safeoff_decay(meter, 1000, 100000, 0.1)
            meter.write_bytes(b"wall_unix_ms,power_mw\n11000,50000\n")
            with self.assertRaises(collector.EnduranceCollectionError):
                collector.wait_for_independent_safeoff_decay(meter, 1000, 100000, 0)

    def test_post_safeoff_decay_rejects_rebound_late_power_and_sparse_capture(self) -> None:
        valid = [(11_000, 50_000), (16_000, 50_000)]
        self.assertEqual(
            verifier.verify_contiguous_post_safeoff_decay(
                valid, 1_000, 100_000, "test decay"
            ),
            2,
        )
        invalid = (
            [(11_000, 50_000), (13_000, 150_000), (16_000, 50_000)],
            [(11_000, 50_000), (16_000, 50_000), (17_000, 150_000)],
            [(11_000, 50_000), (17_000, 50_000)],
            [(17_000, 50_000), (22_000, 50_000)],
        )
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(
                verifier.EnduranceVerificationError
            ):
                verifier.verify_contiguous_post_safeoff_decay(
                    rows, 1_000, 100_000, "test decay"
                )


if __name__ == "__main__":
    unittest.main()
