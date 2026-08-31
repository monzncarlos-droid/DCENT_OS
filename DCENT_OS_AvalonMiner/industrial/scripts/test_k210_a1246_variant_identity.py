#!/usr/bin/env python3
"""Host-only regression tests for revision-bound A1246 identity admission."""

from __future__ import annotations

import importlib.util
import json
import struct
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_discovery_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_discovery_receipt_variant", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)

MANIFEST = SCRIPT.parent.parent / "gauntlet" / "k210_models.json"


def photo_png(width: int = 640, height: int = 480) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    scanline = b"\x00" + b"\x40\x80\xc0" * width
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanline * height))
        + chunk(b"IEND", b"")
    )


class A1246VariantIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def fixture(
        self, profile_id: str, target_id: str
    ) -> tuple[dict[str, object], dict[str, object]]:
        target = next(
            row for row in self.manifest["targets"] if row["id"] == target_id
        )
        profile = next(
            row
            for row in self.manifest["firmware_profiles"]
            if row["id"] == profile_id
        )
        contract_row = next(
            row
            for row in self.manifest["a1246_variant_identity_contract"]["variants"]
            if row["profile_id"] == profile_id and row["target_id"] == target_id
        )
        count = contract_row["hashboard_count"]
        identifiers = [f"{profile_id}-board-{index}" for index in range(1, count + 1)]
        evidence_metadata = []
        evidence: dict[str, object] = {}
        for index, kind in enumerate(discovery.REQUIRED_EVIDENCE_KINDS, 1):
            if kind in discovery.PHOTO_KINDS:
                method, media_type, suffix = "visual_inspection", "image/png", ".png"
                evidence[kind] = discovery._inspect_photo(
                    photo_png(), kind, media_type
                )
            elif kind in discovery.STOCK_RESPONSE_KINDS:
                method, media_type, suffix = (
                    "stock_read_only_management",
                    "application/json",
                    ".json",
                )
            else:
                method, media_type, suffix = "offline_record", "application/json", ".json"
            evidence_metadata.append(
                {
                    "acquired_at_utc": "2026-08-23T15:05:00Z",
                    "id": f"e{index:02d}-{kind.replace('_', '-')}",
                    "kind": kind,
                    "media_type": media_type,
                    "method": method,
                    "path": f"records/{kind}{suffix}",
                    "redaction": "none",
                }
            )

        evidence["stock_version_response"] = {
            "STATUS": [{"Status": "S"}],
            "VERSION": [
                {
                    "VERSION": profile["firmware_version"],
                    "HWTYPE": profile["hw_list"][0],
                    "SWTYPE": profile["sw_list"][0],
                    "PROD": target["display_name"],
                    "DNA": f"dna-{target_id}-unit-001",
                    "MAC": "02:00:00:00:00:01",
                    "UPAPI": 5,
                }
            ],
        }
        stats = {"MM Count": count}
        stats.update({f"MM ID{index}": f"module-{index}" for index in range(count)})
        evidence["stock_stats_response"] = {
            "STATUS": [{"Status": "S"}],
            "STATS": [stats],
        }
        evidence["hashboard_topology_record"] = {
            "hashboard_count": count,
            "hashboard_identifiers": identifiers,
            "controller_data_connectors": [f"J{index}" for index in range(count)],
        }
        evidence["collection_log"] = {
            "session": f"{target_id} revision-bound read-only discovery",
            "operator": "bench-operator",
            "authorization_reference": "test-a1246-read-only-authorization",
            "events": [
                {
                    "time_utc": "2026-08-23T15:05:00Z",
                    "event": "completed deenergized_visual_inspection_power_down, visual_identity_inspection, closed_chassis_stock_power_restoration, and stock_read_only_management_queries with no mutation",
                }
            ],
            "stopped_reason": None,
            "anomalies": [],
        }
        capture: dict[str, object] = {
            "actions_performed": dict(discovery.ACTIONS_PERFORMED),
            "authorization": {
                "authorized_actions": sorted(discovery.AUTHORIZED_ACTIONS),
                "operator_reference": "test-a1246-read-only-authorization",
                "valid_from_utc": "2026-08-23T15:00:00Z",
                "valid_until_utc": "2026-08-23T15:30:00Z",
            },
            "capture_session_id": "7b624544-cb80-4bd1-9e58-c97a9d8d1559",
            "evidence": evidence_metadata,
            "identity": {
                "asic_family": profile["asic_family"],
                "controller_board_model": "MM3v2",
                "controller_board_revision": "rev-2.1",
                "controller_serial": "controller-001",
                "controller_soc": "K210",
                "cooling_class": "air",
                "cooling_controller": "stock-fan-controller",
                "fan_or_pump_count": 4,
                "hashboard_count": count,
                "hashboard_identifiers": identifiers,
                "manufacturer": "Canaan",
                "marketing_model": target["display_name"],
                "miner_serial": f"miner-{target_id}-001",
                "psu_model": "P3600W",
                "psu_rated_watts": 3600,
                "psu_serial": "psu-001",
                "stock_dna": f"dna-{target_id}-unit-001",
                "stock_firmware_version": profile["firmware_version"],
                "stock_hwtype": profile["hw_list"][0],
                "stock_swtype": profile["sw_list"][0],
            },
            "kind": discovery.CAPTURE_KIND,
            "observed_at_utc": "2026-08-23T15:10:00Z",
            "observer_id": "test-observer",
            "schema_version": discovery.SCHEMA_VERSION,
            "scope": discovery.SCOPE,
            "target_id": target_id,
            "unit_label": f"{target_id}-unit-001",
        }
        return capture, evidence

    def admit(self, profile_id: str, target_id: str) -> dict[str, object]:
        capture, evidence = self.fixture(profile_id, target_id)
        discovery._validate_capture(capture, self.manifest)
        variant = discovery._validate_evidence_semantics(
            self.manifest, capture, evidence
        )
        self.assertIsNotNone(variant)
        return variant

    def test_manifest_preserves_corpus_and_names_all_held_a1246_variants(self) -> None:
        self.assertEqual(len(self.manifest["targets"]), 21)
        self.assertEqual(len(self.manifest["firmware_profiles"]), 12)
        rows = self.manifest["a1246_variant_identity_contract"]["variants"]
        self.assertEqual(
            {row["profile_id"] for row in rows},
            {
                "a1246-a3200lc-2hash",
                "a1246-a3201-2hash",
                "a1246-a3201-temp65",
                "a1246n",
            },
        )
        kinds = {
            row["id"]: row["kind"]
            for row in self.manifest["targets"]
            if row["id"].startswith("a1246")
        }
        self.assertEqual(kinds["a1246"], "physical_model")
        self.assertEqual(kinds["a1246n"], "physical_model")
        self.assertEqual(kinds["a1246-a3201-2hash"], "firmware_family")
        self.assertEqual(kinds["a1246-a3201-temp65"], "firmware_family")

    def test_all_four_held_revision_contracts_resolve_exactly(self) -> None:
        cases = (
            ("a1246-a3200lc-2hash", "a1246", "A3200LC-Plus", 2),
            ("a1246-a3201-2hash", "a1246", "A3201-Plus", 2),
            ("a1246-a3201-temp65", "a1246", "A3201-Plus", 3),
            ("a1246n", "a1246n", "A3200-Plus", 3),
        )
        for profile_id, target_id, asic_family, count in cases:
            with self.subTest(profile_id=profile_id):
                variant = self.admit(profile_id, target_id)
                self.assertEqual(variant["profile_id"], profile_id)
                self.assertEqual(variant["asic_family"], asic_family)
                self.assertEqual(variant["hashboard_count"], count)

    def test_legacy_verion_spelling_is_semantically_accepted(self) -> None:
        capture, evidence = self.fixture("a1246-a3200lc-2hash", "a1246")
        version = evidence["stock_version_response"]["VERSION"][0]
        version["VERION"] = version.pop("VERSION")
        variant = discovery._validate_evidence_semantics(
            self.manifest, capture, evidence
        )
        self.assertEqual(variant["profile_id"], "a1246-a3200lc-2hash")

    def test_generic_target_asic_label_is_rejected(self) -> None:
        capture, _ = self.fixture("a1246-a3200lc-2hash", "a1246")
        capture["identity"]["asic_family"] = "A3200"
        with self.assertRaisesRegex(discovery.DiscoveryError, "generic target-family"):
            discovery._validate_capture(capture, self.manifest)

    def test_unknown_stock_tuple_cannot_be_forced_by_x2_topology(self) -> None:
        capture, evidence = self.fixture("a1246-a3200lc-2hash", "a1246")
        unknown = "99010101_deadbee_deadbee"
        capture["identity"]["stock_firmware_version"] = unknown
        evidence["stock_version_response"]["VERSION"][0]["VERSION"] = unknown
        with self.assertRaisesRegex(discovery.DiscoveryError, "generic or topology-forced"):
            discovery._validate_evidence_semantics(self.manifest, capture, evidence)

    def test_contradictory_stats_or_model_label_is_rejected(self) -> None:
        capture, evidence = self.fixture("a1246-a3201-temp65", "a1246")
        evidence["stock_stats_response"]["STATS"][0]["MM Count"] = 2
        with self.assertRaisesRegex(discovery.DiscoveryError, "contradictory"):
            discovery._validate_evidence_semantics(self.manifest, capture, evidence)

        capture, evidence = self.fixture("a1246-a3200lc-2hash", "a1246")
        evidence["stock_version_response"]["VERSION"][0]["PROD"] = (
            "AvalonMiner A1246N"
        )
        with self.assertRaisesRegex(discovery.DiscoveryError, "contradicts"):
            discovery._validate_evidence_semantics(self.manifest, capture, evidence)

    def test_placeholder_arbitrary_image_and_topology_label_are_rejected(self) -> None:
        capture, evidence = self.fixture("a1246-a3200lc-2hash", "a1246")
        capture["identity"]["controller_board_revision"] = "REPLACE"
        with self.assertRaisesRegex(discovery.DiscoveryError, "placeholder"):
            discovery._validate_capture(capture, self.manifest)

        with self.assertRaisesRegex(discovery.DiscoveryError, "canonical image/png"):
            discovery._inspect_photo(
                b"not-a-real-photo" * 20,
                "controller_front_photo",
                "image/jpeg",
            )

        capture, evidence = self.fixture("a1246-a3200lc-2hash", "a1246")
        evidence["hashboard_topology_record"]["asic_family"] = "A3200LC-Plus"
        with self.assertRaisesRegex(discovery.DiscoveryError, "cannot supply or force"):
            discovery._validate_evidence_semantics(self.manifest, capture, evidence)


if __name__ == "__main__":
    unittest.main()
