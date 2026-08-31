#!/usr/bin/env python3
"""Adversarial tests for deterministic S19k Phase-1/2 capture normalization."""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_phase12_normalize as normalizer  # noqa: E402


def scaled(
    column: str,
    *,
    multiply: int = 1,
    divide: int = 1,
    add: int = 0,
) -> dict[str, object]:
    return {
        "column": column,
        "kind": "scaled-decimal",
        "multiply": multiply,
        "divide": divide,
        "add": add,
    }


def enum(column: str, values: dict[str, str]) -> dict[str, object]:
    return {"column": column, "kind": "enum", "values": values}


def config_object() -> dict[str, object]:
    instrument_fields: dict[str, object] = {
        "event": enum("marker", {"base": "sample", "start": "run-start"}),
        "rail_value": scaled("rail_v", multiply=1000),
        "fan0_rpm": scaled("fan_a"),
        "fan1_rpm": scaled("fan_b"),
        "fan2_rpm": scaled("fan_c"),
        "fan3_rpm": scaled("fan_d"),
        "slot2_inlet_millic": scaled("s2_in_c", multiply=1000),
        "slot2_outlet_millic": scaled("s2_out_c", multiply=1000),
        "slot3_inlet_millic": scaled("s3_in_c", multiply=1000),
        "slot3_outlet_millic": scaled("s3_out_c", multiply=1000),
        "gpio437_raw": enum("pwr", {"H": "1", "L": "0"}),
        "gpio454_raw": enum("rst_a", {"H": "1", "L": "0"}),
        "gpio455_raw": enum("rst_b", {"H": "1", "L": "0"}),
        "gpio456_raw": enum("rst_c", {"H": "1", "L": "0"}),
    }
    return {
        "schema": normalizer.CONFIG_SCHEMA,
        "common_clock_id": "scope-logic-common-clock-001",
        "rail_signal": "rail-millivolts",
        "instrument": {
            "delimiter": ";",
            "trim_whitespace": True,
            "timestamp": {
                "column": "time_s",
                "unit": "s",
                "offset_ms": 0,
                "rounding": "exact",
            },
            "fields": instrument_fields,
        },
        "uart": {
            "delimiter": ",",
            "trim_whitespace": True,
            "timestamp": {
                "column": "time_us",
                "unit": "us",
                "offset_ms": 0,
                "rounding": "exact",
            },
            "fields": {
                "path": enum(
                    "channel",
                    {
                        "A": "/dev/ttyS1",
                        "B": "/dev/ttyS2",
                        "C": "/dev/ttyS3",
                    },
                ),
                "direction": enum("flow", {"Read": "rx", "Write": "tx"}),
                "frame_hex": {"column": "data", "kind": "hex-bytes"},
            },
        },
    }


def canonical_json(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def raw_instrument_csv() -> bytes:
    header = (
        "time_s;marker;rail_v;fan_a;fan_b;fan_c;fan_d;"
        "s2_in_c;s2_out_c;s3_in_c;s3_out_c;pwr;rst_a;rst_b;rst_c"
    )
    rows: list[str] = []
    rail = {
        0: "14.000",
        1: "14.050",
        2: "13.950",
        3: "14.000",
        4: "13.900",
        5: "12.000",
        6: "7.000",
        7: "2.000",
        8: "0.600",
    }
    for second in range(15):
        marker = "start" if second == 3 else "base"
        if second < 4:
            gpios = ("L", "L", "H", "H")
        elif second < 5:
            gpios = ("L", "L", "L", "L")
        else:
            gpios = ("H", "L", "L", "L")
        values = [
            str(second),
            marker,
            rail.get(second, "0.300"),
            "3050",
            "3040",
            "3030",
            "3020",
            "55.000",
            "61.000",
            "54.000",
            "60.000",
            *gpios,
        ]
        rows.append(";".join(values))
    return (header + "\n" + "\n".join(rows) + "\n").encode("utf-8")


def raw_uart_csv() -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("time_us", "channel", "flow", "data"))
    writer.writerows(
        (
            (3_200_000, "A", "Write", "0x55 0xaa 0x51 0x09 00 28 00 00 30 11 12"),
            (3_300_000, "A", "Read", "aa:55:01:02:03:04:05:06:07:08:09"),
            (3_400_000, "B", "Write", "55-aa-51-09-00-28-00-00-30-11-12"),
            (3_500_000, "B", "Read", "AA55010203040506070809"),
            (3_600_000, "C", "Write", "55 AA 51 09 00 28 00 00 30 11 12"),
        )
    )
    return output.getvalue().encode("utf-8")


class NormalizationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.config = root / "normalization.json"
        self.instrument_source = root / "instrument-native.csv"
        self.uart_source = root / "uart-native.csv"
        self.instrument_csv = root / "instrument.csv"
        self.uart_csv = root / "uart.csv"
        self.receipt = root / normalizer.RECEIPT_OUTPUT
        self.config.write_bytes(canonical_json(config_object()))
        self.instrument_source.write_bytes(raw_instrument_csv())
        self.uart_source.write_bytes(raw_uart_csv())
        self.rebuild()

    def rebuild(self) -> None:
        for path in (self.instrument_csv, self.uart_csv, self.receipt):
            if path.exists():
                path.unlink()
        derived = normalizer._derive_files(
            self.config,
            self.instrument_source,
            self.uart_source,
            self.instrument_csv,
            self.uart_csv,
        )
        config_sha, config_bytes = normalizer._stable_digest(
            self.config, "fixture config"
        )
        instrument_sha, instrument_bytes = normalizer._stable_digest(
            self.instrument_source, "fixture instrument source"
        )
        uart_sha, uart_bytes = normalizer._stable_digest(
            self.uart_source, "fixture UART source"
        )
        values = normalizer._receipt_values(
            config_sha256=config_sha,
            config_bytes=config_bytes,
            instrument_source_sha256=instrument_sha,
            instrument_source_bytes=instrument_bytes,
            uart_source_sha256=uart_sha,
            uart_source_bytes=uart_bytes,
            derived=derived,
        )
        self.receipt.write_bytes(normalizer._kv_bytes(normalizer.RECEIPT_KEYS, values))

    def verify(self) -> dict[str, str]:
        return normalizer.verify_normalization(
            config_path=self.config,
            instrument_source=self.instrument_source,
            uart_source=self.uart_source,
            instrument_csv=self.instrument_csv,
            uart_csv=self.uart_csv,
            receipt_path=self.receipt,
        )


class Phase12NormalizationTests(unittest.TestCase):
    def fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], NormalizationFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, NormalizationFixture(Path(temporary.name))

    def test_derives_and_replays_byte_identical_outputs(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = fixture.verify()
        instrument = fixture.instrument_csv.read_text(encoding="ascii")
        uart = fixture.uart_csv.read_text(encoding="ascii")
        self.assertIn("0,sample,14000,3050,3040,3030,3020,55000", instrument)
        self.assertIn("3000,run-start,14000", instrument)
        self.assertIn("3200,/dev/ttyS1,tx,55AA510900280000301112", uart)
        self.assertIn("3300,/dev/ttyS1,rx,AA55010203040506070809", uart)
        self.assertEqual(result["instrument_row_count"], "15")
        self.assertEqual(result["uart_row_count"], "5")
        self.assertRegex(result["normalization_id"], r"^[0-9a-f]{64}$")

    def test_rejects_manual_canonical_instrument_edit(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.instrument_csv.write_bytes(
            fixture.instrument_csv.read_bytes().replace(b"14000", b"14001", 1)
        )
        with self.assertRaisesRegex(
            normalizer.NormalizationError,
            "not the deterministic raw-source derivation",
        ):
            fixture.verify()

    def test_rejects_manual_canonical_uart_edit(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_csv.write_bytes(
            fixture.uart_csv.read_bytes().replace(b"55AA51", b"55AA50", 1)
        )
        with self.assertRaisesRegex(
            normalizer.NormalizationError,
            "not the deterministic raw-source derivation",
        ):
            fixture.verify()

    def test_rejects_raw_source_changed_after_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.instrument_source.write_bytes(
            fixture.instrument_source.read_bytes().replace(b"14.000", b"14.001", 1)
        )
        with self.assertRaises(normalizer.NormalizationError):
            fixture.verify()

    def test_rejects_rehashed_but_semantically_forged_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.receipt.read_text(encoding="ascii")
        forged = hashlib.sha256(b"forged").hexdigest()
        fixture.receipt.write_text(
            text.replace(
                next(
                    line.split("=", 1)[1]
                    for line in text.splitlines()
                    if line.startswith("instrument_source_sha256=")
                ),
                forged,
                1,
            ),
            encoding="ascii",
            newline="",
        )
        with self.assertRaisesRegex(
            normalizer.NormalizationError,
            "does not match replay",
        ):
            fixture.verify()

    def test_rejects_noncanonical_config_serialization(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        parsed = json.loads(fixture.config.read_text(encoding="ascii"))
        fixture.config.write_text(json.dumps(parsed, indent=2) + "\n", encoding="ascii")
        with self.assertRaisesRegex(normalizer.NormalizationError, "not canonical"):
            fixture.rebuild()

    def test_rejects_duplicate_config_key(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        data = fixture.config.read_text(encoding="ascii")
        fixture.config.write_text(
            data.replace(
                '"schema":"dcentos.s19k-phase12-normalization-config/v1"',
                '"schema":"bad","schema":"dcentos.s19k-phase12-normalization-config/v1"',
            ),
            encoding="ascii",
            newline="",
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "repeats JSON key"):
            fixture.rebuild()

    def test_rejects_unmapped_uart_channel(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_source.write_bytes(
            fixture.uart_source.read_bytes().replace(b",A,", b",D,", 1)
        )
        with self.assertRaisesRegex(
            normalizer.NormalizationError, "unmapped raw value"
        ):
            fixture.rebuild()

    def test_rejects_fractional_timestamp_under_exact_policy(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_source.write_bytes(
            fixture.uart_source.read_bytes().replace(b"3200000", b"3200001", 1)
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "exact millisecond"):
            fixture.rebuild()

    def test_explicit_floor_timestamp_policy_is_deterministic(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        config = json.loads(fixture.config.read_text(encoding="ascii"))
        config["uart"]["timestamp"]["rounding"] = "floor"
        fixture.config.write_bytes(canonical_json(config))
        fixture.uart_source.write_bytes(
            fixture.uart_source.read_bytes().replace(b"3200000", b"3200999", 1)
        )
        fixture.rebuild()
        self.assertIn(
            "3200,/dev/ttyS1,tx,",
            fixture.uart_csv.read_text(encoding="ascii"),
        )
        fixture.verify()

    def test_rejects_multiple_fields_aliased_to_one_source_column(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        config = json.loads(fixture.config.read_text(encoding="ascii"))
        config["instrument"]["fields"]["fan1_rpm"]["column"] = "fan_a"
        fixture.config.write_bytes(canonical_json(config))
        with self.assertRaisesRegex(normalizer.NormalizationError, "aliases"):
            fixture.rebuild()

    def test_rejects_nonintegral_scaled_measurement(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.instrument_source.write_bytes(
            fixture.instrument_source.read_bytes().replace(b"55.000", b"55.0001", 1)
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "exact integer"):
            fixture.rebuild()

    def test_rejects_malformed_uart_byte_tokens(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_source.write_bytes(
            fixture.uart_source.read_bytes().replace(b"0x55 0xaa", b"0x55 0xGG", 1)
        )
        with self.assertRaisesRegex(normalizer.NormalizationError, "non-byte hex"):
            fixture.rebuild()

    def test_rejects_inode_alias_between_source_and_output(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_csv.unlink()
        os.link(fixture.uart_source, fixture.uart_csv)
        with self.assertRaisesRegex(normalizer.NormalizationError, "distinct inodes"):
            fixture.verify()

    @unittest.skipUnless(os.name == "posix", "publication is a Linux/WSL gate")
    def test_publishes_exact_three_file_directory_and_cli_sentinel(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        output = fixture.root / "normalized"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = normalizer.main(
                [
                    "--config",
                    str(fixture.config),
                    "--instrument-source",
                    str(fixture.instrument_source),
                    "--uart-source",
                    str(fixture.uart_source),
                    "--output-dir",
                    str(output),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("S19K_PHASE12_NORMALIZATION_OK", stdout.getvalue())
        self.assertEqual(
            {entry.name for entry in output.iterdir()},
            {
                normalizer.INSTRUMENT_OUTPUT,
                normalizer.UART_OUTPUT,
                normalizer.RECEIPT_OUTPUT,
            },
        )
        for entry in output.iterdir():
            self.assertTrue(entry.is_file())
            self.assertFalse(entry.is_symlink())
            self.assertEqual(entry.stat().st_nlink, 1)

    @unittest.skipUnless(os.name == "posix", "publication is a Linux/WSL gate")
    def test_refuses_existing_output_without_clobbering(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        output = fixture.root / "normalized"
        output.mkdir()
        marker = output / "operator-data"
        marker.write_text("preserve\n", encoding="ascii")
        with self.assertRaisesRegex(normalizer.NormalizationError, "already exists"):
            normalizer.normalize(
                config_path=fixture.config,
                instrument_source=fixture.instrument_source,
                uart_source=fixture.uart_source,
                output_dir=output,
            )
        self.assertEqual(marker.read_text(encoding="ascii"), "preserve\n")


if __name__ == "__main__":
    unittest.main()
