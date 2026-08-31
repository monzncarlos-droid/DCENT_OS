from __future__ import annotations

import ast
import dataclasses
import hashlib
from pathlib import Path

import pytest

import s21xp_air_topology_evidence as subject
from s21xp_air_topology_evidence import (
    ArtifactReceipt,
    S21XpAirAuthority,
    inspect_s21xp_air_evidence,
)


_WORKSPACE = Path(__file__).resolve().parents[3]
_PATHS = {
    "bosminer_model_list": _WORKSPACE
    / "",
    "bosminer_unpacked": _WORKSPACE
    / "",
    "vnish_devicetree": _WORKSPACE
    / "",
    "vnish_s11board": _WORKSPACE
    / "",
    "bitmain_single_board_test": Path.home()
    / "Downloads/bitmain_antminer_binaries-main/bitmain_antminer_binaries-main/S21xp/single_board_test",
    "epic_hashboard_topology": _WORKSPACE
    / "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/hashboard_topology_v1_22_0.json",
}
_HELD_AVAILABLE = all(path.is_file() for path in _PATHS.values())


@pytest.fixture(scope="session")
def held_raw():
    if not _HELD_AVAILABLE:
        pytest.skip("held S21 XP air evidence corpus not mounted")
    return {name: path.read_bytes() for name, path in _PATHS.items()}


@pytest.fixture(scope="session")
def held_inspection(held_raw):
    return inspect_s21xp_air_evidence(**held_raw)


def test_held_census_and_exact_routes(held_inspection):
    inspection = held_inspection
    assert inspection.inspection_verified is True
    assert len(inspection.artifacts) == 6
    assert all(item.caller_supplied for item in inspection.artifacts)
    assert all(item.verified_by_inspector for item in inspection.artifacts)
    assert inspection.model_row_duplicate_count == 2
    assert inspection.bosminer_control_boards == (
        "zynq-bm3-am2",
        "am3-bbb",
        "am3-aml",
        "cvitek-bm1-am2",
        "stm32mp157c-ii1-am2",
    )
    assert tuple(
        (lane.bosminer_hashchain_index, lane.device)
        for lane in inspection.direct_uart_lanes
    ) == (
        (1, "/dev/ttyS3"),
        (2, "/dev/ttyS2"),
        (3, "/dev/ttyS1"),
    )
    assert tuple((node.alias, node.status) for node in inspection.dtb_uart_nodes) == (
        ("serial0", "okay"),
        ("serial1", "okay"),
        ("serial2", "okay"),
        ("serial3", "okay"),
    )
    assert inspection.three_safe_runtime_actors_proved is False
    assert "ttyS4" in inspection.runtime_route_conflict


def test_held_gpio_fan_fpga_and_hashboard_receipts(held_inspection):
    inspection = held_inspection
    assert tuple(
        (lane.script_chain_index, lane.plug_gpio, lane.reset_gpio)
        for lane in inspection.gpio_lanes
    ) == (
        (0, 439, 454),
        (1, 440, 455),
        (2, 441, 456),
    )
    assert inspection.power_enable_gpio == 437
    assert inspection.fan_tach_gpios == (447, 448, 449, 450)
    assert inspection.fan_pwm_channels == (0, 1)
    assert inspection.fan_pwm_period_and_initial_duty == (100_000, 100_000)
    assert len(inspection.factory_fpga_lanes) == 14
    assert (
        inspection.factory_fpga_lanes[0].read_control_register,
        inspection.factory_fpga_lanes[0].read_data_register,
    ) == (96, 97)
    assert (
        inspection.factory_fpga_lanes[9].read_control_register,
        inspection.factory_fpga_lanes[9].read_data_register,
    ) == (114, 115)
    assert (
        inspection.factory_fpga_lanes[10].read_control_register,
        inspection.factory_fpga_lanes[10].read_data_register,
    ) == (124, 125)
    assert (
        inspection.factory_fpga_lanes[13].read_control_register,
        inspection.factory_fpga_lanes[13].read_data_register,
    ) == (130, 131)
    assert inspection.hashboard.sku == "A3HB70501"
    assert inspection.hashboard.vendor_declared_pic == "PIC1704"
    assert inspection.hashboard.switched_sensor_address_and_indices == (
        (76, 3),
        (76, 2),
        (76, 0),
        (76, 1),
    )


def test_held_elf_va_file_mappings_symbols_and_windows(held_inspection, held_raw):
    inspection = held_inspection
    assert dataclasses.astuple(inspection.bosminer_elf_load) == (
        183,
        0,
        0x400000,
        0x1375388,
        5,
        0x10000,
    )
    assert dataclasses.astuple(inspection.bosminer_aml_function) == (
        "bosminer am3-aml hashchain tty formatter",
        0x8DAE30,
        0x4DAE30,
        "71568ea9034ea4af4cd22081f8f32d406f1aec56344bfb3053d6b483af4f1391",
    )
    assert (
        hashlib.sha256(held_raw["bosminer_unpacked"][0x4DAE30:0x4DAE90]).hexdigest()
        == inspection.bosminer_aml_function.window_sha256
    )

    assert dataclasses.astuple(inspection.factory_jig_elf_load) == (
        40,
        0,
        0x10000,
        0x2470CC,
        5,
        0x10000,
    )
    assert tuple(
        dataclasses.astuple(item) for item in inspection.function_receipts
    ) == (
        (
            "fpga_init.part.0",
            0xCD1A9,
            350,
            0xCD1A8,
            0xBD1A8,
            "0dea01e60f2b676832aa9f1b17e6b9b8b08f31a785192ffb1d94e99aad6fae6a",
        ),
        (
            "read_uart_data_in_fpga",
            0xCE43D,
            360,
            0xCE43C,
            0xBE43C,
            "60cc22263ee8774f580ee70c7ba8794dae5dbe5c7f7aaaeeea0b84a9b57fee2f",
        ),
        (
            "chain_reset_low",
            0xD1BB1,
            42,
            0xD1BB0,
            0xC1BB0,
            "6cd091edc6ec45cfc075f92b53009ee4b758808d853514ec71e40012d6f9fe1f",
        ),
    )
    jig = held_raw["bitmain_single_board_test"]
    for receipt in inspection.function_receipts:
        assert receipt.analysis_address - receipt.window_file_offset == 0x10000
        window = jig[receipt.window_file_offset : receipt.window_file_offset + 64]
        assert hashlib.sha256(window).hexdigest() == receipt.window_sha256


@pytest.mark.parametrize(
    "name",
    (
        "bosminer_model_list",
        "bosminer_unpacked",
        "vnish_devicetree",
        "vnish_s11board",
        "bitmain_single_board_test",
        "epic_hashboard_topology",
    ),
)
def test_every_artifact_is_exact_hash_gated(held_raw, name):
    forged = dict(held_raw)
    changed = bytearray(forged[name])
    changed[len(changed) // 2] ^= 1
    forged[name] = bytes(changed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inspect_s21xp_air_evidence(**forged)


def test_absent_truncated_and_nonbytes_reject(held_raw):
    truncated = dict(held_raw)
    truncated["vnish_s11board"] = truncated["vnish_s11board"][:-1]
    with pytest.raises(ValueError, match="size mismatch"):
        inspect_s21xp_air_evidence(**truncated)

    nonbytes = dict(held_raw)
    nonbytes["vnish_s11board"] = bytearray(nonbytes["vnish_s11board"])
    with pytest.raises(TypeError, match="exact bytes"):
        inspect_s21xp_air_evidence(**nonbytes)

    with pytest.raises(TypeError, match="unexpected keyword"):
        inspect_s21xp_air_evidence(
            **held_raw,
            _specs=(("forged", len(held_raw["bosminer_model_list"]), "0" * 64),),
        )


def test_authority_is_all_false_and_not_constructor_or_replace_settable(
    held_inspection,
):
    authority = S21XpAirAuthority()
    assert len(dataclasses.fields(authority)) == 19
    assert all(
        getattr(authority, item.name) is False for item in dataclasses.fields(authority)
    )
    with pytest.raises(TypeError):
        S21XpAirAuthority(device_open=True)
    with pytest.raises(ValueError):
        dataclasses.replace(authority, uart_transmit=True)

    inspection = held_inspection
    assert all(
        getattr(inspection.authority, item.name) is False
        for item in dataclasses.fields(inspection.authority)
    )
    with pytest.raises(ValueError):
        dataclasses.replace(inspection, authority=S21XpAirAuthority())


def test_trust_resets_on_semantic_replace_and_receipt_forgery(held_inspection):
    inspection = held_inspection
    forged_inspection = dataclasses.replace(
        inspection, three_safe_runtime_actors_proved=True
    )
    assert forged_inspection.inspection_verified is False
    assert forged_inspection.three_safe_runtime_actors_proved is True

    genuine = inspection.artifacts[0]
    forged_receipt = dataclasses.replace(genuine, sha256="0" * 64)
    assert forged_receipt.verified_by_inspector is False
    direct = ArtifactReceipt("forged", 1, "0" * 64)
    assert direct.verified_by_inspector is False


def test_prior_receipt_poisoning_cannot_change_fresh_verified_output(held_raw):
    prior = inspect_s21xp_air_evidence(**held_raw)
    object.__setattr__(prior.artifacts[0], "artifact_id", "poisoned")
    object.__setattr__(prior.bosminer_elf_load, "segment_virtual_address", 0)
    object.__setattr__(prior.bosminer_aml_function, "window_file_offset", 0)
    object.__setattr__(prior.direct_uart_lanes[0], "device", "/dev/poison")
    object.__setattr__(prior.dtb_uart_nodes[0], "path", "/poison")
    object.__setattr__(prior.gpio_lanes[0], "plug_gpio", 999)
    object.__setattr__(prior.factory_fpga_lanes[0], "read_control_register", 999)
    object.__setattr__(prior.factory_jig_elf_load, "segment_virtual_address", 0)
    object.__setattr__(prior.function_receipts[0], "window_file_offset", 0)
    object.__setattr__(prior.hashboard, "sku", "poisoned")
    object.__setattr__(prior.authority, "device_open", True)

    fresh = inspect_s21xp_air_evidence(**held_raw)
    assert fresh.inspection_verified is True
    assert fresh.artifacts[0].artifact_id == "bosminer-model-list"
    assert fresh.bosminer_elf_load.segment_virtual_address == 0x400000
    assert fresh.bosminer_aml_function.window_file_offset == 0x4DAE30
    assert fresh.direct_uart_lanes[0].device == "/dev/ttyS3"
    assert fresh.dtb_uart_nodes[0].path == "/soc/aobus@ff800000/serial@3000"
    assert fresh.gpio_lanes[0].plug_gpio == 439
    assert fresh.factory_fpga_lanes[0].read_control_register == 96
    assert fresh.factory_jig_elf_load.segment_virtual_address == 0x10000
    assert fresh.function_receipts[0].window_file_offset == 0xBD1A8
    assert fresh.hashboard.sku == "A3HB70501"
    assert fresh.authority.device_open is False

    nested_pairs = (
        (prior.artifacts[0], fresh.artifacts[0]),
        (prior.bosminer_elf_load, fresh.bosminer_elf_load),
        (prior.bosminer_aml_function, fresh.bosminer_aml_function),
        (prior.direct_uart_lanes[0], fresh.direct_uart_lanes[0]),
        (prior.dtb_uart_nodes[0], fresh.dtb_uart_nodes[0]),
        (prior.gpio_lanes[0], fresh.gpio_lanes[0]),
        (prior.factory_fpga_lanes[0], fresh.factory_fpga_lanes[0]),
        (prior.factory_jig_elf_load, fresh.factory_jig_elf_load),
        (prior.function_receipts[0], fresh.function_receipts[0]),
        (prior.hashboard, fresh.hashboard),
        (prior.authority, fresh.authority),
    )
    assert all(before is not after for before, after in nested_pairs)


def test_closed_admission_rejects_mutated_s11board_despite_public_spec_shadow(
    held_raw, monkeypatch
):
    forged = dict(held_raw)
    changed = bytearray(forged["vnish_s11board"])
    changed[changed.index(b"pwr_en")] ^= 1
    forged["vnish_s11board"] = bytes(changed)

    public_specs = list(subject._ARTIFACT_SPECS)
    artifact_id, size, _ = public_specs[3]
    public_specs[3] = (
        artifact_id,
        size,
        hashlib.sha256(forged["vnish_s11board"]).hexdigest(),
    )
    monkeypatch.setattr(subject, "_ARTIFACT_SPECS", tuple(public_specs))
    monkeypatch.setattr(subject, "_CONTROL_BOARDS", ("forged",))
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        subject.inspect_s21xp_air_evidence(**forged)


def test_closed_semantics_ignore_empty_windows_and_all_module_global_shadows(
    held_raw, monkeypatch
):
    forged = dict(held_raw)
    changed = bytearray(forged["bitmain_single_board_test"])
    changed[0xBD1A8] ^= 1
    forged["bitmain_single_board_test"] = bytes(changed)
    public_specs = list(subject._ARTIFACT_SPECS)
    artifact_id, size, _ = public_specs[4]
    public_specs[4] = (
        artifact_id,
        size,
        hashlib.sha256(forged["bitmain_single_board_test"]).hexdigest(),
    )

    shadows = {
        "_ARTIFACT_SPECS": tuple(public_specs),
        "_BOSMINER_AML_WINDOW": b"",
        "_BOSMINER_AML_ANALYSIS_ADDRESS": 0,
        "_BOSMINER_AML_WINDOW_OFFSET": 0,
        "_BOSMINER_TTYS_OFFSET": 0,
        "_BOSMINER_INDEX_ERROR_OFFSET": 0,
        "_BOSMINER_AML_SOURCE_OFFSET": 0,
        "_JIG_WINDOWS": (),
        "_SERIAL_ALIASES": (),
        "_CONTROL_BOARDS": ("forged",),
        "_validate_artifact": lambda *_: None,
        "_validate_model_list": lambda *_: 999,
        "_validate_bosminer": lambda *_: ((), None, None),
        "_validate_bosminer_elf": lambda *_: None,
        "_validate_dtb": lambda *_: (),
        "_parse_fdt_properties": lambda *_: ({}, {}),
        "_require_script_lines": lambda *_: None,
        "_validate_jig": lambda *_: ((), (), None),
        "_validate_jig_elf": lambda *_: None,
        "_validate_epic_topology": lambda *_: None,
        "_verified_receipt": lambda *_: None,
        "_nul_text": lambda *_: "forged",
        "ArtifactReceipt": object,
        "DirectUartLane": object,
        "DtbUartNode": object,
        "GpioLane": object,
        "FactoryFpgaLane": object,
        "FunctionReceipt": object,
        "ElfLoadReceipt": object,
        "StrippedFunctionReceipt": object,
        "HashboardReceipt": object,
        "S21XpAirEvidenceInspection": object,
        "S21XpAirAuthority": object,
        "hashlib": None,
        "json": None,
        "struct": None,
    }
    for name, value in shadows.items():
        monkeypatch.setattr(subject, name, value)

    exact = subject.inspect_s21xp_air_evidence(**held_raw)
    assert exact.inspection_verified is True
    assert tuple(lane.device for lane in exact.direct_uart_lanes) == (
        "/dev/ttyS3",
        "/dev/ttyS2",
        "/dev/ttyS1",
    )
    assert len(exact.factory_fpga_lanes) == 14
    assert exact.function_receipts[0].window_file_offset == 0xBD1A8
    assert all(
        getattr(exact.authority, item.name) is False
        for item in dataclasses.fields(exact.authority)
    )
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        subject.inspect_s21xp_air_evidence(**forged)


def test_module_is_pure_bytes_only_and_has_no_action_surface():
    source_path = Path(__file__).with_name("s21xp_air_topology_evidence.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
    assert imports == {
        "__future__",
        "hashlib",
        "json",
        "struct",
        "dataclasses",
        "typing",
    }

    forbidden = {
        "open",
        "read",
        "read_bytes",
        "read_text",
        "write",
        "write_bytes",
        "write_text",
        "Path",
        "Popen",
        "run",
        "system",
        "socket",
        "connect",
        "send",
        "recv",
        "ioctl",
        "mount",
        "umount",
    }
    called = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            called.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            called.add(node.func.attr)
    assert not (called & forbidden)
