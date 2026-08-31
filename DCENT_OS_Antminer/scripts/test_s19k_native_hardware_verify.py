#!/usr/bin/env python3
"""Adversarial tests for the host-only S19k native hardware verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_native_hardware_verify as native  # noqa: E402
import s19k_phase12_normalize as normalizer  # noqa: E402
from test_s19k_no_work_verify import (  # noqa: E402
    EvidenceFixture as Phase12Fixture,
    kv_bytes,
    normalization_config_data,
    preflight_data,
)


def instrument_csv() -> bytes:
    from s19k_no_work_verify import INSTRUMENT_HEADER

    rows: list[str] = []
    for timestamp in range(0, 26_000, 1_000):
        event = "run-start" if timestamp == 3_000 else "sample"
        if timestamp < 5_000:
            gpios = (0, 0, 1, 1)
        elif timestamp < 8_000:
            gpios = (0, 0, 0, 1)
        elif timestamp < 10_000:
            gpios = (0, 0, 1, 1)
        elif timestamp < 13_000:
            gpios = (0, 0, 1, 0)
        elif timestamp < 15_000:
            gpios = (0, 0, 1, 1)
        elif timestamp < 16_000:
            gpios = (0, 0, 0, 0)
        else:
            gpios = (1, 0, 0, 0)
        rail = {
            0: 14_000,
            1_000: 14_050,
            2_000: 13_950,
            16_000: 12_000,
            17_000: 7_000,
            18_000: 2_000,
            19_000: 600,
        }.get(timestamp, 300 if timestamp >= 20_000 else 14_000)
        step = (timestamp // 1_000) % 2
        values = [
            str(timestamp),
            event,
            str(rail),
            "3050",
            "3040",
            "3030",
            "3020",
            str(55_000 + step * 100),
            str(61_000 + step * 100),
            str(54_000 + step * 100),
            str(60_000 + step * 100),
            *(str(value) for value in gpios),
        ]
        rows.append(",".join(values))
    return (",".join(INSTRUMENT_HEADER) + "\n" + "\n".join(rows) + "\n").encode(
        "ascii"
    )


def uart_csv() -> bytes:
    from s19k_no_work_verify import UART_HEADER

    probe = native.GETADDRESS_PROBE.hex().upper()
    rx = "AA55010203040506070809"
    rows = [
        # Both boards respond before isolation.
        f"3200,/dev/ttyS1,tx,{probe}",
        f"3250,/dev/ttyS1,rx,{rx}",
        f"3300,/dev/ttyS2,tx,{probe}",
        f"3350,/dev/ttyS2,rx,{rx}",
        # GPIO455 assertion uniquely silences ttyS2 (physical address 2).
        f"5100,/dev/ttyS1,tx,{probe}",
        f"5150,/dev/ttyS1,rx,{rx}",
        f"5200,/dev/ttyS2,tx,{probe}",
        f"6100,/dev/ttyS1,tx,{probe}",
        f"6150,/dev/ttyS1,rx,{rx}",
        f"6200,/dev/ttyS2,tx,{probe}",
        # Both boards recover between assertions.
        f"8200,/dev/ttyS1,tx,{probe}",
        f"8250,/dev/ttyS1,rx,{rx}",
        f"8300,/dev/ttyS2,tx,{probe}",
        f"8350,/dev/ttyS2,rx,{rx}",
        # GPIO456 assertion uniquely silences ttyS1 (physical address 3).
        f"10100,/dev/ttyS1,tx,{probe}",
        f"10200,/dev/ttyS2,tx,{probe}",
        f"10250,/dev/ttyS2,rx,{rx}",
        f"11100,/dev/ttyS1,tx,{probe}",
        f"11200,/dev/ttyS2,tx,{probe}",
        f"11250,/dev/ttyS2,rx,{rx}",
        # Both boards recover before the terminal all-low reset.
        f"13200,/dev/ttyS1,tx,{probe}",
        f"13250,/dev/ttyS1,rx,{rx}",
        f"13300,/dev/ttyS2,tx,{probe}",
        f"13350,/dev/ttyS2,rx,{rx}",
        f"14000,/dev/ttyS3,tx,{probe}",
    ]
    return (",".join(UART_HEADER) + "\n" + "\n".join(rows) + "\n").encode(
        "ascii"
    )


class Fixture:
    def __init__(self, root: Path) -> None:
        phase12_root = root / "phase12"
        phase12_root.mkdir()
        phase12_fixture = Phase12Fixture(phase12_root)
        self.plan_data = phase12_fixture.plan.read_bytes()
        self.phase12_result = json.loads(
            (
                phase12_fixture.evidence / "phase12_host_verification.json"
            ).read_text(encoding="ascii")
        )

        self.root = root / "native"
        self.root.mkdir()
        self.paths = {
            prefix: self.root / filename
            for prefix, filename in native.PREFIX_FILENAMES.items()
        }
        self.manifest = self.root / native.MANIFEST_FILENAME
        self.receipt = self.root / native.WORKFLOW_RECEIPT_FILENAME
        self.paths["adopted_plan"].write_bytes(self.plan_data)
        self.paths["adopted_phase12_verification"].write_bytes(
            native.canonical_json(self.phase12_result)
        )
        self.paths["preflight"].write_bytes(preflight_data())
        self.paths["normalization_config"].write_bytes(normalization_config_data())
        self.paths["instrument_source"].write_bytes(instrument_csv())
        self.paths["uart_source"].write_bytes(uart_csv())
        self.normalize()
        self.write_mapping()
        self.write_manifest()
        result = native.verify_evidence(self.root, require_workflow_receipt=False)
        self.receipt.write_bytes(native.canonical_json(result))

    def normalize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            generated_instrument = temporary_root / "instrument.csv"
            generated_uart = temporary_root / "uart.csv"
            derived = normalizer._derive_files(
                self.paths["normalization_config"],
                self.paths["instrument_source"],
                self.paths["uart_source"],
                generated_instrument,
                generated_uart,
            )
            self.paths["instrument_csv"].write_bytes(generated_instrument.read_bytes())
            self.paths["uart_csv"].write_bytes(generated_uart.read_bytes())
        values = normalizer._receipt_values(
            config_sha256=hashlib.sha256(
                self.paths["normalization_config"].read_bytes()
            ).hexdigest(),
            config_bytes=self.paths["normalization_config"].stat().st_size,
            instrument_source_sha256=hashlib.sha256(
                self.paths["instrument_source"].read_bytes()
            ).hexdigest(),
            instrument_source_bytes=self.paths["instrument_source"].stat().st_size,
            uart_source_sha256=hashlib.sha256(
                self.paths["uart_source"].read_bytes()
            ).hexdigest(),
            uart_source_bytes=self.paths["uart_source"].stat().st_size,
            derived=derived,
        )
        self.normalization_values = values
        self.paths["normalization_receipt"].write_bytes(
            normalizer._kv_bytes(normalizer.RECEIPT_KEYS, values)
        )

    def write_mapping(self, **overrides: str) -> None:
        values = {
            "schema": native.MAPPING_SCHEMA,
            "claim": "physical-reset-isolation-common-clock-correlation",
            "live_identity_profile": native.LIVE_PROFILE,
            "live_identity_sha256": str(self.phase12_result["live_identity_sha256"]),
            "board_target": "am3-s19k",
            "board_revision": "BHB56903-revision-reviewed",
            "board_name": "BHB56903",
            "populated_physical_addresses": "2,3",
            "physical_address_2_uart": "/dev/ttyS2",
            "physical_address_2_reset_gpio": "455",
            "physical_address_3_uart": "/dev/ttyS1",
            "physical_address_3_reset_gpio": "456",
            "absent_physical_address": "1",
            "absent_reset_gpio": "454",
            "unpopulated_uart": "/dev/ttyS3",
            "mapping_method": "common-clock-reset-isolation-repeated-getaddress",
            "gpio437_energized_raw": "0",
            "gpio437_safeoff_raw": "1",
            "reset_polarity": "raw1-released-raw0-asserted",
            "fan_channels": "fan0,fan1,fan2,fan3",
            "temperature_channels": (
                "slot2-inlet,slot2-outlet,slot3-inlet,slot3-outlet"
            ),
            "instrument_csv_sha256": hashlib.sha256(
                self.paths["instrument_csv"].read_bytes()
            ).hexdigest(),
            "uart_csv_sha256": hashlib.sha256(
                self.paths["uart_csv"].read_bytes()
            ).hexdigest(),
            "normalization_id": self.normalization_values["normalization_id"],
            "mapping_id": "0" * 64,
            "publication": "post-capture-content-bound-receipt",
        }
        values.update(overrides)
        values["mapping_id"] = native._mapping_id(values)
        self.paths["mapping"].write_bytes(
            kv_bytes([(key, values[key]) for key in native.MAPPING_KEYS])
        )

    def write_manifest(self) -> None:
        values: dict[str, str] = {
            "schema": native.MANIFEST_SCHEMA,
            "claim": native.CLAIM,
            "phase12_verification_id": str(self.phase12_result["verification_id"]),
            "common_clock_id": "scope-logic-common-clock-001",
            "rail_signal": "rail-millivolts",
            "created_utc": "2026-08-22T12:00:00Z",
            "publication": "post-run-content-manifest",
        }
        for prefix, filename in native.PREFIX_FILENAMES.items():
            data = self.paths[prefix].read_bytes()
            values[f"{prefix}_file"] = filename
            values[f"{prefix}_sha256"] = hashlib.sha256(data).hexdigest()
            values[f"{prefix}_bytes"] = str(len(data))
        self.manifest.write_bytes(
            kv_bytes([(key, values[key]) for key in native.MANIFEST_KEYS])
        )

    def refresh_after_capture_change(self) -> None:
        self.normalize()
        self.write_mapping()
        self.write_manifest()

    def verify(self) -> dict[str, object]:
        return native.verify_workflow_evidence(self.root)


class NativeHardwareTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Fixture(Path(temporary.name))

    def test_accepts_exact_content_bound_native_hardware_contract(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = fixture.verify()
        self.assertFalse(result["authority_granted"])
        self.assertEqual(
            result["tty_to_physical_address"], {"/dev/ttyS1": 3, "/dev/ttyS2": 2}
        )
        self.assertEqual(result["fan_channels_verified"], 4)
        self.assertEqual(result["temperature_channels_fresh"], 4)

    def test_rejects_missing_workflow_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.receipt.unlink()
        with self.assertRaisesRegex(native.NativeHardwareError, "inexact entry set"):
            fixture.verify()

    def test_rejects_extra_evidence_entry(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        (fixture.root / "operator-note.txt").write_text("not admitted\n", encoding="ascii")
        with self.assertRaisesRegex(native.NativeHardwareError, "inexact entry set"):
            fixture.verify()

    def test_rejects_raw_export_edit_even_when_manifest_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.paths["instrument_source"].write_bytes(
            fixture.paths["instrument_source"].read_bytes().replace(
                b"25000,sample,300", b"25000,sample,301", 1
            )
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(native.NativeHardwareError, "normalization provenance"):
            fixture.verify()

    def test_rejects_mapping_receipt_that_swaps_physical_boards(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.write_mapping(
            physical_address_2_uart="/dev/ttyS1",
            physical_address_3_uart="/dev/ttyS2",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(native.NativeHardwareError, "physical_address_2_uart"):
            fixture.verify()

    def test_rejects_rx_on_uart_while_its_reset_is_asserted(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        data = fixture.paths["uart_source"].read_bytes()
        data = data.replace(
            b"6200,/dev/ttyS2,tx,55AA510900280000301112\n",
            b"6200,/dev/ttyS2,tx,55AA510900280000301112\n"
            b"6250,/dev/ttyS2,rx,AA55010203040506070809\n",
            1,
        )
        fixture.paths["uart_source"].write_bytes(data)
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "does not uniquely silence"):
            fixture.verify()

    def test_rejects_loss_of_any_one_cooling_channel(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        data = fixture.paths["instrument_source"].read_bytes().replace(
            b"13000,sample,14000,3050,3040,3030,3020",
            b"13000,sample,14000,3050,3040,1999,3020",
            1,
        )
        fixture.paths["instrument_source"].write_bytes(data)
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "four-channel cooling"):
            fixture.verify()

    def test_rejects_static_temperature_channel_as_stale(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.paths["instrument_source"].read_text(encoding="ascii")
        lines = text.splitlines()
        rewritten = [lines[0]]
        for line in lines[1:]:
            columns = line.split(",")
            columns[7] = "55000"
            rewritten.append(",".join(columns))
        fixture.paths["instrument_source"].write_text(
            "\n".join(rewritten) + "\n", encoding="ascii", newline=""
        )
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "fresh samples"):
            fixture.verify()

    def test_rejects_rail_sample_outside_reviewed_preflight_range(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        data = fixture.paths["instrument_source"].read_bytes().replace(
            b"13000,sample,14000", b"13000,sample,15001", 1
        )
        fixture.paths["instrument_source"].write_bytes(data)
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "reviewed range"):
            fixture.verify()

    def test_rejects_gpio437_raw_zero_without_energized_rail(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        data = fixture.paths["instrument_source"].read_bytes().replace(
            b"13000,sample,14000", b"13000,sample,500", 1
        )
        fixture.paths["instrument_source"].write_bytes(data)
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "not continuously correlated"):
            fixture.verify()

    def test_rejects_missing_two_uart_recovery_between_reset_assertions(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        lines = fixture.paths["uart_source"].read_bytes().splitlines(keepends=True)
        fixture.paths["uart_source"].write_bytes(
            b"".join(line for line in lines if not line.startswith((b"8200,", b"8250,")))
        )
        fixture.refresh_after_capture_change()
        with self.assertRaisesRegex(native.NativeHardwareError, "between-isolation"):
            fixture.verify()

    def test_rejects_preflight_bound_to_another_miner(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        live_sha = str(fixture.phase12_result["live_identity_sha256"]).encode("ascii")
        fixture.paths["preflight"].write_bytes(
            fixture.paths["preflight"].read_bytes().replace(live_sha, b"e" * 64, 1)
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(
            native.NativeHardwareError, "authorized_miner_identity_sha256"
        ):
            fixture.verify()

    def test_source_has_no_live_contact_or_mutation_primitives(self) -> None:
        source = Path(native.__file__).read_text(encoding="utf-8")
        forbidden = (
            "import socket",
            "import subprocess",
            "from socket",
            "from subprocess",
            "urlopen(",
            "requests.",
            "os.system(",
            "os.popen(",
            "paramiko",
        )
        self.assertFalse([token for token in forbidden if token in source])


if __name__ == "__main__":
    unittest.main()
