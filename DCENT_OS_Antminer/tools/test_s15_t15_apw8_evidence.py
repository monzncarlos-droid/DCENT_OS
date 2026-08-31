from __future__ import annotations

import ast
import dataclasses
import dis
import hashlib
import types
from pathlib import Path

import pytest

import s15_t15_apw8_evidence as evidence


WORKSPACE = Path(__file__).resolve().parents[3]
S15_PACKAGE = (
    WORKSPACE
    / "Latest Bitmain FW"
    / "Antminer-S15-user-OM-201912131535-sig_4864.tar.gz"
)
T15_PACKAGE = (
    WORKSPACE
    / "Latest Bitmain FW"
    / "Antminer-T15-user-OM-201912131546-sig_4867.tar.gz"
)
S15_CGMINER = WORKSPACE / "tmp" / "bm1391-evidence" / "s15-cgminer"
T15_CGMINER = WORKSPACE / "tmp" / "bm1391-evidence" / "t15-cgminer"
GUIDE = (
    WORKSPACE
    / "knowledge-base"
    / "extractions"
    / "maintenance-guides"
    / "misc"
    / "S15 Maintenance Guide.pdf"
)
APW8_GUIDE = (
    WORKSPACE
    / "knowledge-base"
    / "extractions"
    / "maintenance-guides"
    / "psu"
    / "APW8 Power Supply Maintenance Guide.pdf"
)


@pytest.fixture(scope="module")
def held():
    paths = (
        S15_PACKAGE,
        S15_CGMINER,
        T15_PACKAGE,
        T15_CGMINER,
        GUIDE,
        APW8_GUIDE,
    )
    if not all(path.is_file() for path in paths):
        pytest.skip("held S15/T15/APW8 corpus is not present")
    return tuple(path.read_bytes() for path in paths)


def inspect(raw):
    return evidence.inspect_s15_t15_apw8_evidence(
        s15_package=raw[0],
        s15_cgminer=raw[1],
        t15_package=raw[2],
        t15_cgminer=raw[3],
        s15_maintenance_guide=raw[4],
        apw8_maintenance_guide=raw[5],
    )


def test_exact_held_receipt_and_protocol_boundary(held):
    receipt = inspect(held)
    assert receipt.inspection_verified is True
    assert tuple((item.size, item.sha256) for item in receipt.artifacts) == (
        (
            24_962_829,
            "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
        ),
        (
            691_180,
            "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8",
        ),
        (
            23_696_441,
            "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
        ),
        (
            691_180,
            "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01",
        ),
        (
            3_800_577,
            "4496807c14291da95bdc4ba399097f8a3d5f1c15d0cab882dcd57c10e5e2ab27",
        ),
        (
            1_853_200,
            "a8694c6eff734784c91c71a6e6d7ceff0cf25b8e98494d8d535cc8ecfdd43214",
        ),
    )
    for model in receipt.models:
        assert (
            model.fpga_register_offset,
            model.i2c_device_address,
            model.fpga_bus_selector,
            model.read_direction,
            model.register_prefix_enabled,
            model.register_address,
            model.payload_bytes,
            model.packed_command_base_without_payload,
        ) == (0x30, 0x10, 1, False, True, 0x02, 1, 0x05200200)
        assert model.raw_byte_bounds == (0, 255)
        assert model.poll_iterations == 101
        assert model.poll_interval_microseconds == 5_000
        assert model.wrapper_pre_delay_microseconds == 100_000
        assert model.caller_post_delay_microseconds == 300_000
        assert model.helper_result_consumed is False
        assert model.write_readback_observed is False
        assert model.userspace_checksum_bytes_observed == 0
        assert model.wire_checksum_rule_verified is False


def test_elf_mapping_and_exact_semantic_windows(held):
    receipt = inspect(held)
    s15, t15 = receipt.models
    assert tuple((x.file_offset, x.virtual_address) for x in s15.elf_loads) == (
        (0, 0x8000),
        (0xA4000, 0xB4000),
    )
    assert tuple((x.file_offset, x.virtual_address) for x in t15.elf_loads) == (
        (0, 0x8000),
        (0xA4000, 0xB4000),
    )
    assert {x.name: x.analysis_address for x in s15.functions}[
        "FPGA general-I2C command helper"
    ] == 0x86AEC
    assert {x.name: x.window_file_offset for x in s15.functions}[
        "FPGA general-I2C command helper"
    ] == 0x7EAEC
    assert {x.name: x.analysis_address for x in t15.functions}[
        "FPGA general-I2C command helper"
    ] == 0x86A0C
    for model, raw in zip(receipt.models, (held[1], held[3])):
        for function in model.functions:
            window = raw[
                function.window_file_offset : function.window_file_offset
                + function.window_size
            ]
            assert hashlib.sha256(window).hexdigest() == function.window_sha256


def test_guide_observation_does_not_join_gpio_or_safe_limits(held):
    receipt = inspect(held)
    guide = receipt.guide
    assert guide.named_psu == "APW8"
    assert guide.apw8_named_products == ("S15", "T15")
    assert guide.adjustable_output_range_volts == (16.32, 20.04)
    assert guide.adjustable_output_max_current_amperes == 95.0
    assert guide.fixed_output_volts == 12.0
    assert guide.fixed_output_max_current_amperes == 5.0
    assert guide.documented_values_are_runtime_safe_limits is False
    assert guide.apw8_control_signals == ("SDA", "SCL", "EN")
    assert guide.sda_scl_documented_as_i2c is True
    assert guide.en_documented_effective_level == 0
    assert guide.guide_en_polarity_bound_to_gpio907 is False
    assert guide.controller_label == "Ctrl_C43"
    assert guide.controller_revision == "V1.2011"
    assert guide.j11_signal_names == ("PWR_I2C_SDA", "PWR_I2C_SCL", "PWR_EN")
    assert guide.linux_gpio_number_printed_for_pwr_en is False
    assert guide.topology_internally_consistent is False
    assert guide.exact_release_controller_binding_verified is False
    assert receipt.package_membership_parsed_by_this_inspector is False
    assert receipt.publisher_authenticity_verified is False
    assert receipt.electrical_apw8_identity_verified_for_exact_release is False
    assert receipt.resident_linux_dtb_presence_verified_by_this_inspector is False
    assert receipt.resident_linux_dtb_association_verified is False
    assert receipt.t15_physical_topology_verified is False


def test_heartbeat_is_not_promoted_to_electrical_safe_off(held):
    for model in inspect(held).models:
        assert model.heartbeat_frame == (0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A)
        assert model.heartbeat_expected_reply == (0x16, 0x01)
        assert model.heartbeat_attempts == 3
        assert model.heartbeat_caller_period_seconds == 10
        assert model.heartbeat_failure_action_observed == "retry/log only"
        assert model.heartbeat_electrical_safe_off_verified is False
        assert model.gpio907_physical_binding_verified is False


def test_every_operational_authority_is_false(held):
    authority = inspect(held).authority
    assert all(value is False for value in dataclasses.astuple(authority))


@pytest.mark.parametrize("index", range(6))
def test_wrong_size_rejected_before_public_hash_shadow(held, index, monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("public hashlib shadow must not be reached")

    monkeypatch.setattr(evidence.hashlib, "sha256", spy)
    raw = list(held)
    raw[index] = raw[index] + b"x"
    with pytest.raises(ValueError, match="size mismatch"):
        inspect(raw)
    assert calls == []


def test_tamper_hash_and_non_bytes_rejected(held):
    tampered = list(held)
    changed = bytearray(tampered[1])
    changed[0x723B0] ^= 1
    tampered[1] = bytes(changed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inspect(tampered)
    wrong_type = list(held)
    wrong_type[0] = bytearray(wrong_type[0])
    with pytest.raises(TypeError, match="exact bytes"):
        inspect(wrong_type)


def test_direct_replace_same_object_and_prior_poisoning(held):
    genuine = inspect(held)
    values = {
        item.name: getattr(genuine, item.name)
        for item in dataclasses.fields(genuine)
        if item.init
    }
    direct = evidence.S15T15Apw8Inspection(**values)
    assert direct.inspection_verified is False
    replaced = dataclasses.replace(genuine, publisher_authenticity_verified=True)
    assert replaced.inspection_verified is False

    object.__setattr__(genuine.models[0], "register_address", 0x99)
    assert genuine.inspection_verified is False
    fresh = inspect(held)
    assert fresh.inspection_verified is True
    assert fresh.models[0].register_address == 0x02


def test_public_global_shadowing_cannot_change_exact_admission(held, monkeypatch):
    baseline = inspect(held)
    monkeypatch.setattr(evidence, "_ARTIFACT_SPECS", (("forged", 1, "0" * 64),))
    monkeypatch.setattr(evidence, "_S15_FUNCTIONS", ())
    monkeypatch.setattr(evidence, "_T15_FUNCTIONS", ())
    monkeypatch.setattr(evidence, "_LOAD_SEGMENTS", ())
    monkeypatch.setattr(evidence, "_T15_LOAD_SEGMENTS", ())
    fresh = inspect(held)
    assert fresh.inspection_verified is True
    assert fresh.models == baseline.models


def test_sensitive_closure_bytecode_has_no_global_or_name_loads():
    pending = [
        evidence.inspect_s15_t15_apw8_evidence,
        evidence.S15T15Apw8Inspection.inspection_verified.fget,
    ]
    visited = set()
    while pending:
        function = pending.pop()
        if id(function) in visited:
            continue
        visited.add(id(function))
        assert function.__defaults__ in (None, ())
        assert function.__kwdefaults__ in (None, {})
        assert all(
            instruction.opname not in {"LOAD_GLOBAL", "LOAD_NAME"}
            for instruction in dis.get_instructions(function)
        )
        for cell in function.__closure__ or ():
            value = cell.cell_contents
            if isinstance(value, types.FunctionType):
                pending.append(value)


def test_property_refuses_same_object_authority_poison(held):
    receipt = inspect(held)
    object.__setattr__(receipt.authority, "i2c_write", True)
    assert receipt.inspection_verified is False


def test_equality_spoof_cannot_preserve_verification(held):
    class EqualToEverything:
        def __eq__(self, other):
            return True

    forged_register = EqualToEverything()
    receipt = inspect(held)
    object.__setattr__(receipt.models[0], "register_address", forged_register)
    assert receipt.models[0].register_address is forged_register
    assert receipt.inspection_verified is False

    forged_authority = EqualToEverything()
    receipt = inspect(held)
    object.__setattr__(receipt.authority, "i2c_write", forged_authority)
    assert receipt.authority.i2c_write is forged_authority
    assert receipt.inspection_verified is False


@pytest.mark.parametrize(
    ("target", "field_name", "forged_value"),
    (
        ("authority", "i2c_write", 0),
        ("model", "register_prefix_enabled", 1),
        ("guide", "adjustable_output_max_current_amperes", 95),
    ),
)
def test_builtin_cross_type_equality_cannot_preserve_verification(
    held, target, field_name, forged_value
):
    receipt = inspect(held)
    if target == "authority":
        nested = receipt.authority
    elif target == "model":
        nested = receipt.models[0]
    else:
        nested = receipt.guide
    object.__setattr__(nested, field_name, forged_value)
    assert getattr(nested, field_name) == forged_value
    assert receipt.inspection_verified is False


def test_ast_purity_gate():
    tree = ast.parse(Path(evidence.__file__).read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert imports == {
        "__future__",
        "hashlib",
        "math",
        "struct",
        "weakref",
        "dataclasses",
        "typing",
    }
    forbidden = {
        "open",
        "read",
        "read_bytes",
        "write",
        "write_bytes",
        "system",
        "run",
        "Popen",
        "socket",
        "connect",
        "send",
        "recv",
        "ioctl",
        "mount",
        "umount",
    }
    assert calls.isdisjoint(forbidden)
