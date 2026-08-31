"""Host-only regression tests for the canonical K210 capture artifact."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "k210_capture_ingest.py"
spec = importlib.util.spec_from_file_location("k210_capture_ingest", SCRIPT)
cap = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["k210_capture_ingest"] = cap
spec.loader.exec_module(cap)


def provenance() -> dict[str, object]:
    return {
        "asic_family": "A3200LC-Plus",
        "authorization_reference": "operator-ticket-A1246-readonly",
        "capture_end_s": "0.000000005",
        "capture_session_id": "a1246-fixture-session",
        "capture_state": "safe_idle_detection",
        "controller_revision": "MM3v2_X2",
        "hashboard_revision": "S-A3200-fixture",
        "model": "AvalonMiner A1246",
        "operator": "fixture-operator",
        "sample_rate_hz": 100_000_000,
        "stock_firmware_build": "22062202_be77c30_a769bbf",
        "stock_aup_sha256": "6" * 64,
        "unit_serial": "fixture-unit",
    }


def normalized_capture():
    forward = cap.DigitalCsvTrack("CI", 0)
    forward.observations = [(0, 0), (1_000, 1), (3_000, 0)]
    reverse = cap.DigitalCsvTrack("CKO", 1)
    reverse.observations = [(0, 1), (2_000, 0), (4_000, 1)]
    return cap._merge_and_normalize(
        [forward, reverse], capture_end_ps=5_000,
        sample_rate_hz=100_000_000, source_count=1,
    )


class DecimalParserTests(unittest.TestCase):
    def test_decimal_seconds_are_rounded_to_picoseconds(self) -> None:
        self.assertEqual(cap._parse_seconds_to_ps("0.000000001"), 1_000)
        self.assertEqual(cap._parse_seconds_to_ps("5e-12"), 5)
        self.assertEqual(cap._parse_seconds_to_ps("0.0000000000005"), 1)

    def test_non_decimal_and_runaway_values_are_refused(self) -> None:
        for value in ("", "NaN", "0x10", "1e31", "1.2.3"):
            with self.subTest(value=value), self.assertRaises(cap.CaptureIngestError):
                cap._parse_seconds_to_ps(value)


class ArtifactTests(unittest.TestCase):
    def test_round_trip_is_canonical_and_direction_preserving(self) -> None:
        artifact = cap.encode_artifact(provenance(), normalized_capture())
        decoded = cap.decode_artifact(artifact)
        self.assertEqual(decoded.signal_names(), ["CI", "CKO"])
        self.assertEqual(decoded.events, [(1_000, 0, 1), (2_000, 1, 0),
                                          (3_000, 0, 0), (4_000, 1, 1)])
        self.assertEqual(decoded.ended_ps, 5_000)
        self.assertEqual(cap.encode_artifact(decoded.provenance, normalized_capture()), artifact)

    def test_corruption_trailing_bytes_and_reserved_bytes_are_refused(self) -> None:
        artifact = bytearray(cap.encode_artifact(provenance(), normalized_capture()))
        corrupt = bytearray(artifact)
        corrupt[-1] ^= 1
        with self.assertRaises(cap.CaptureIngestError):
            cap.decode_artifact(bytes(corrupt))
        with self.assertRaises(cap.CaptureIngestError):
            cap.decode_artifact(bytes(artifact) + b"x")
        artifact[cap.OFFSET_RESERVED2] = 1
        with self.assertRaises(cap.CaptureIngestError):
            cap.decode_artifact(bytes(artifact))

    def test_cross_direction_timestamp_tie_is_refused(self) -> None:
        forward = cap.DigitalCsvTrack("CI", 0)
        forward.observations = [(0, 0), (1_000, 1)]
        reverse = cap.DigitalCsvTrack("CKO", 1)
        reverse.observations = [(0, 1), (1_000, 0)]
        with self.assertRaisesRegex(cap.CaptureIngestError, "cross-direction"):
            cap._merge_and_normalize(
                [forward, reverse], 2_000, 100_000_000, 1
            )


class MappingAndCsvTests(unittest.TestCase):
    def test_mapping_rejects_unknown_signals_and_duplicate_channels(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "map.json"
            for channels in ({"TO": 0}, {"CI": 0, "CKO": 0}):
                path.write_text(json.dumps({
                    "format": cap.MAPPING_FORMAT,
                    "channels": channels,
                    "provenance": provenance(),
                }), encoding="utf-8")
                with self.subTest(channels=channels), self.assertRaises(cap.CaptureIngestError):
                    cap._load_mapping(path)

    def test_csv_requires_explicit_initial_levels(self) -> None:
        data = b"Time [s],Channel 0\n0,\n0.000000001,1\n"
        with self.assertRaisesRegex(cap.CaptureIngestError, "initial level"):
            cap._parse_digital_csv(data, Path("fixture.csv"), "digital CSV", {"CI": 0})

    def test_csv_carry_forward_reduces_to_real_edges(self) -> None:
        data = (
            b"Time [s],Channel 0,Channel 1\n"
            b"0,0,1\n"
            b"0.000000001,1,\n"
            b"0.000000002,,0\n"
        )
        tracks = cap._parse_digital_csv(
            data, Path("fixture.csv"), "digital CSV", {"CI": 0, "CKO": 1}
        )
        merged = cap._merge_and_normalize(tracks, 3_000, 100_000_000, 1)
        self.assertEqual(merged.events, [(1_000, 0, 1), (2_000, 1, 0)])


class CliTests(unittest.TestCase):
    def test_ingest_validate_stats_inventory_and_extract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mapping = root / "map.json"
            csv_path = root / "digital.csv"
            artifact = root / "capture.k210cap"
            excerpt = root / "excerpt.k210cap"
            mapping.write_text(json.dumps({
                "format": cap.MAPPING_FORMAT,
                "channels": {"CI": 0, "CKO": 1},
                "provenance": provenance(),
            }), encoding="utf-8")
            csv_path.write_text(
                "Time [s],Channel 0,Channel 1\n"
                "0,0,1\n"
                "0.000000001,1,\n"
                "0.000000002,,0\n"
                "0.000000003,0,\n"
                "0.000000004,,1\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(cap.main([
                    "ingest", "--map", str(mapping), "--csv", str(csv_path),
                    "--output", str(artifact),
                ]), 0)
            self.assertIn("wire_contract_claimed=false", stdout.getvalue())
            self.assertTrue(artifact.is_file())

            for command in ("validate", "inventory", "stats"):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(cap.main([command, "--input", str(artifact)]), 0)
                self.assertIn("authorizes_device=false", stdout.getvalue())

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(cap.main([
                    "extract", "--input", str(artifact), "--first-event", "1",
                    "--event-count", "2", "--output", str(excerpt),
                ]), 0)
            self.assertEqual(len(cap.decode_artifact(excerpt.read_bytes()).events), 2)

    def test_ingest_refuses_to_overwrite_an_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.k210cap"
            path.write_bytes(b"existing")
            with self.assertRaises(cap.CaptureIngestError):
                cap._prepare_output(path)


if __name__ == "__main__":
    unittest.main()
