#!/usr/bin/env python3
"""Adversarial tests for S19k Phase 1+2 raw capture schema v2."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

import s19k_phase12_capture_verify as capture


def rle_bit(value: int, count: int) -> str:
    return (bytes((value,)) + count.to_bytes(4, "little")).hex()


def rle_u16(value: int, count: int) -> str:
    return (value.to_bytes(2, "little") + count.to_bytes(4, "little")).hex()


class CaptureFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.clock = "logic-a-clock-7"
        self.contract = {
            "schema": capture.CONTRACT_SCHEMA,
            "common_clock_id": self.clock,
            "window_start_ns": 0,
            "window_end_ns": 1_000_000,
            "rail_signal": "rail-millivolts",
            "populated_uart_paths": ["/dev/ttyS1", "/dev/ttyS2"],
        }
        self.rows: list[list[str]] = []
        for channel in capture._required_channels(
            self.contract["populated_uart_paths"]
        ):
            channel_class = capture._channel_class(channel)
            period = capture.PERIOD_LIMIT_NS[channel_class]
            count = 1_000_000 // period
            if channel_class == "rail":
                encoding = "rle-u16le-v1"
                payload = rle_u16(12_000, count)
            else:
                encoding = "rle-bit-v1"
                payload = rle_bit(0, count)
            self.rows.append(
                [
                    self.clock,
                    "0",
                    channel,
                    "0",
                    str(period),
                    str(count),
                    encoding,
                    payload,
                ]
            )
        self.write()

    def write(self) -> None:
        (self.root / capture.CONTRACT_NAME).write_bytes(
            capture.canonical_json(self.contract)
        )
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(capture.HEADER)
        writer.writerows(self.rows)
        (self.root / capture.BLOCKS_NAME).write_text(
            output.getvalue(), encoding="ascii", newline=""
        )

    def row(self, channel: str) -> list[str]:
        return next(item for item in self.rows if item[2] == channel)


class RawCaptureVerificationTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], CaptureFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, CaptureFixture(Path(temporary.name))

    def test_complete_raw_block_capture_stages_and_verifies(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            result = capture.stage_receipt(fixture.root)
            self.assertEqual(result, capture.verify_workflow_evidence(fixture.root))
            self.assertTrue(result["both_populated_rail_feeds_retained"])
            self.assertTrue(result["rates_and_gaps_computed_from_raw_blocks"])
            self.assertFalse(result["decoded_uart_frames_sufficient_without_raw_blocks"])
            self.assertFalse(result["safeoff_proven"])
            self.assertEqual(len(result["channels"]), 14)

    def test_missing_second_rail_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.rows.remove(fixture.row("rail-slot3"))
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "missing required raw channel rail-slot3"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_declared_preflight_rate_cannot_replace_slow_raw_blocks(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            row = fixture.row("gpio437")
            row[4] = "10001"
            row[5] = "100"
            row[7] = rle_bit(0, 100)
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "measured gpio rate is too low"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_unmeasured_gap_between_blocks_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            original = fixture.row("gpio437")
            fixture.rows.remove(original)
            fixture.rows.extend(
                [
                    [fixture.clock, "0", "gpio437", "0", "10000", "40", "rle-bit-v1", rle_bit(0, 40)],
                    [fixture.clock, "1", "gpio437", "500000", "10000", "50", "rle-bit-v1", rle_bit(1, 50)],
                ]
            )
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "unmeasured sample gap"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_malformed_rle_sample_total_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.row("fan0-tach")[7] = rle_bit(0, 9)
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "sample total"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_clock_mismatch_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.row("ttyS1-rx")[0] = "different-clock"
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "different common clock"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_unpopulated_uart_channel_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.rows.append(
                [fixture.clock, "0", "ttyS3-rx", "0", "10", "100000", "rle-bit-v1", rle_bit(0, 100000)]
            )
            fixture.write()
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "undeclared or unpopulated"
            ):
                capture.build_result(
                    fixture.root / capture.CONTRACT_NAME,
                    fixture.root / capture.BLOCKS_NAME,
                )

    def test_stale_receipt_and_extra_file_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            capture.stage_receipt(fixture.root)
            receipt = fixture.root / capture.RECEIPT_NAME
            value = json.loads(receipt.read_bytes())
            value["safeoff_proven"] = True
            receipt.write_bytes(capture.canonical_json(value))
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "stale"
            ):
                capture.verify_workflow_evidence(fixture.root)
            receipt.write_bytes(
                capture.canonical_json(
                    capture.build_result(
                        fixture.root / capture.CONTRACT_NAME,
                        fixture.root / capture.BLOCKS_NAME,
                    )
                )
            )
            (fixture.root / "unexpected").write_text("no\n", encoding="ascii")
            with self.assertRaisesRegex(
                capture.CaptureVerificationError, "file set"
            ):
                capture.verify_workflow_evidence(fixture.root)


if __name__ == "__main__":
    unittest.main()
