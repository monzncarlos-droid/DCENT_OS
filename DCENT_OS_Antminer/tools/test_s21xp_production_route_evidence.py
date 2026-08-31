from __future__ import annotations

import ast
import dataclasses
import hashlib
import struct
from pathlib import Path

import pytest

import s21xp_production_route_evidence as subject
from s21xp_production_route_evidence import (
    ArtifactReceipt,
    BinaryRouteReceipt,
    ProductionRouteAuthority,
    S21XpProductionRouteInspection,
    inspect_s21xp_production_route,
)


_WORKSPACE = Path(__file__).resolve().parents[3]
_ROOTFS = (
    _WORKSPACE
    / ""
    / "vnish-1.2.7-s21xp-aml-nand-v1.2.7-install/rootfs"
)
_PATHS = {
    "hwscan": _ROOTFS / "usr/bin/hwscan",
    "cgminer": _ROOTFS / "usr/bin/cgminer",
    "fw_info": _ROOTFS / "etc/fw-info",
    "s12hwscan": _ROOTFS / "etc/init.d/S12hwscan",
    "s11board": _ROOTFS / "etc/init.d/S11board",
}
_HELD_AVAILABLE = all(path.is_file() for path in _PATHS.values())


@pytest.fixture(scope="session")
def held_raw():
    if not _HELD_AVAILABLE:
        pytest.skip("held S21 XP VNish 1.2.7 rootfs is not mounted")
    return {name: path.read_bytes() for name, path in _PATHS.items()}


@pytest.fixture(scope="session")
def held_inspection(held_raw):
    return inspect_s21xp_production_route(**held_raw)


def test_exact_held_census_and_package_association(held_inspection):
    inspection = held_inspection
    assert inspection.inspection_verified is True
    assert inspection.production_association_verified is True
    assert tuple((item.size, item.sha256) for item in inspection.artifacts) == (
        (
            4_574_504,
            "9cfd4593fab33a58442fed55ff5c6205b6b07283a56677926b03b8ea1166a396",
        ),
        (
            5_798_548,
            "d71f268b8ec18f29f45a9cb20b34ed3976e2011d1ca6268c61cd2f8a7ac39e3b",
        ),
        (
            295,
            "899e9bde7780b0ec53406d01c7f08e4bf947617259d543aea820116a3abae531",
        ),
        (
            493,
            "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
        ),
        (
            2_928,
            "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
        ),
    )
    assert all(item.verified_by_inspector for item in inspection.artifacts)
    assert (
        inspection.firmware_name,
        inspection.firmware_version,
        inspection.miner,
        inspection.model,
        inspection.platform,
        inspection.install_type,
    ) == ("Vnish", "1.2.7", "Antminer S21 XP", "s21xp", "aml", "nand")
    assert inspection.hwscan_command == (
        "hwscan --platform aml --gen-model-info s21xp --gen-def-conf s21xp"
    )


def test_hwscan_exact_elf_functions_tables_and_mapping(held_inspection, held_raw):
    route = held_inspection.hwscan_route
    assert route.route_verified is True
    assert (route.elf_machine, route.elf_entry) == (40, 0x11EB8)
    assert tuple(dataclasses.astuple(item) for item in route.load_segments) == (
        (0, 0x10000, 0x4417D4, 0x4417D4, 5, 0x10000),
        (0x441998, 0x461998, 0x1AF94, 0x2C430, 6, 0x10000),
    )
    assert dataclasses.astuple(route.mapper) == (
        "AML chain UART mapper",
        0x11FE2C,
        0x10FE2C,
        0x28,
        "e94dd99f0445077914149e03ec94c296683390da081a56916e19ec0e9b1de06a",
    )
    assert (
        route.mapper_table_virtual_address,
        route.mapper_table_file_offset,
        route.mapper_table_sha256,
    ) == (
        0x463330,
        0x443330,
        "eac6e2a3638d09aefcb767e359ef6905b3b1ccb371f0a6115dc9e0f06f4ffcc6",
    )
    assert (
        route.vtable_mapper_pointer_virtual_address,
        route.vtable_mapper_pointer_file_offset,
        route.vtable_window_sha256,
    ) == (
        0x465688,
        0x445688,
        "dc281fc1b7ac5c5f6d5bb46ec5ef65c444e8f19fa010eff6ad62f32876275f8b",
    )
    raw = held_raw["hwscan"]
    assert struct.unpack_from("<3I", raw, 0x443330) == (
        0x4375FD,
        0x437608,
        0x437613,
    )
    for function in route.functions:
        assert function.virtual_address - function.file_offset == 0x10000
        window = raw[function.file_offset : function.file_offset + function.size]
        assert hashlib.sha256(window).hexdigest() == function.sha256


def test_cgminer_independent_exact_route_and_xor_strings(held_inspection, held_raw):
    route = held_inspection.cgminer_route
    assert route.route_verified is True
    assert (route.elf_machine, route.elf_entry) == (40, 0x1012C)
    assert tuple(dataclasses.astuple(item) for item in route.load_segments) == (
        (0, 0x10000, 0x553670, 0x553670, 5, 0x10000),
        (0x5542E4, 0x5742E4, 0x333E8, 0x7FEC0, 6, 0x10000),
    )
    assert dataclasses.astuple(route.mapper) == (
        "AML chain UART mapper",
        0x10AFB4,
        0x0FAFB4,
        0x28,
        "d5bf21f4545b5446d450927a32fc02ec4929c35e99a67961346717e2ea6c9317",
    )
    assert (
        route.mapper_table_virtual_address,
        route.mapper_table_file_offset,
        route.mapper_table_sha256,
    ) == (
        0x57475C,
        0x55475C,
        "59e02a16f1dde0076171b241e3e28a6c91c7dc46d356ac8c853523ac3659a4a1",
    )
    assert (
        route.vtable_mapper_pointer_virtual_address,
        route.vtable_mapper_pointer_file_offset,
        route.vtable_window_sha256,
    ) == (
        0x5779D8,
        0x5579D8,
        "8598c6a342bb1211d323b22adb521d4cfe23bc37873a15ef2a171bc29cc614d9",
    )
    raw = held_raw["cgminer"]
    observations = (
        (0x566EA8, 0xBC, "/dev/ttyS3"),
        (0x566EB3, 0xB5, "/dev/ttyS2"),
        (0x566EBE, 0x2C, "/dev/ttyS1"),
    )
    assert tuple(
        bytes(value ^ key for value in raw[offset : offset + 10]).decode("ascii")
        for offset, key, _ in observations
    ) == tuple(cleartext for _, _, cleartext in observations)
    assert route.chain_devices == held_inspection.hwscan_route.chain_devices


def test_zero_based_production_gpio_route_and_residuals(held_inspection):
    inspection = held_inspection
    assert tuple(dataclasses.astuple(item) for item in inspection.chains) == (
        (0, "/dev/ttyS3", 439, 454, True),
        (1, "/dev/ttyS2", 440, 455, True),
        (2, "/dev/ttyS1", 441, 456, True),
    )
    assert inspection.production_route_kind == (
        "AML direct UART; not factory FPGA transport"
    )
    assert inspection.factory_fpga_route_is_distinct is True
    assert dataclasses.astuple(inspection.psu) == (
        "board-global observation only",
        437,
        (477, 476),
        "i2c:psu-bus",
        False,
        False,
        False,
    )
    assert inspection.pic_runtime_identity_verified is False
    assert any("PIC presence" in item for item in inspection.unresolved)
    assert any("PSU family" in item for item in inspection.unresolved)


@pytest.mark.parametrize("name", tuple(_PATHS))
def test_every_input_is_exact_hash_gated(held_raw, name):
    forged = dict(held_raw)
    changed = bytearray(forged[name])
    changed[len(changed) // 2] ^= 1
    forged[name] = bytes(changed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inspect_s21xp_production_route(**forged)


def test_wrong_size_and_nonbytes_reject_before_hash(held_raw, monkeypatch):
    wrong = dict(held_raw)
    wrong["hwscan"] += b"x"
    calls = 0

    def forbidden_hash(_):
        nonlocal calls
        calls += 1
        raise AssertionError("wrong-size value must not be hashed")

    monkeypatch.setattr(subject.hashlib, "sha256", forbidden_hash)
    with pytest.raises(ValueError, match="size mismatch"):
        inspect_s21xp_production_route(**wrong)
    assert calls == 0

    nonbytes = dict(held_raw)
    nonbytes["hwscan"] = bytearray(nonbytes["hwscan"])
    with pytest.raises(TypeError, match="exact bytes"):
        inspect_s21xp_production_route(**nonbytes)


def test_authority_and_trust_are_false_by_default_and_replace_safe(
    held_inspection,
):
    authority = ProductionRouteAuthority()
    assert len(dataclasses.fields(authority)) == 17
    assert all(
        getattr(authority, item.name) is False for item in dataclasses.fields(authority)
    )
    with pytest.raises(TypeError):
        ProductionRouteAuthority(device_open=True)
    with pytest.raises(ValueError):
        dataclasses.replace(authority, gpio_write=True)

    direct_artifact = ArtifactReceipt("forged", 1, "0" * 64)
    assert direct_artifact.verified_by_inspector is False
    direct_route = BinaryRouteReceipt(
        "forged",
        40,
        0,
        (),
        held_inspection.hwscan_route.mapper,
        0,
        0,
        "",
        0,
        0,
        "",
        (),
        (),
    )
    assert direct_route.route_verified is False
    forged_inspection = dataclasses.replace(held_inspection, model="forged")
    assert forged_inspection.inspection_verified is False
    assert forged_inspection.production_association_verified is False
    assert (
        dataclasses.replace(
            held_inspection.hwscan_route, artifact_id="forged"
        ).route_verified
        is False
    )


def test_prior_nested_poisoning_cannot_change_fresh_receipt(held_raw):
    prior = inspect_s21xp_production_route(**held_raw)
    object.__setattr__(prior.artifacts[0], "artifact_id", "poison")
    object.__setattr__(prior.hwscan_route.mapper, "file_offset", 0)
    object.__setattr__(prior.hwscan_route.load_segments[0], "virtual_address", 0)
    object.__setattr__(prior.hwscan_route, "chain_devices", ("poison",))
    object.__setattr__(prior.cgminer_route.mapper, "file_offset", 0)
    object.__setattr__(prior.chains[0], "uart_device", "poison")
    object.__setattr__(prior.psu, "power_enable_gpio", 0)
    object.__setattr__(prior.authority, "device_open", True)
    object.__setattr__(prior, "inspection_verified", False)

    fresh = inspect_s21xp_production_route(**held_raw)
    assert fresh.inspection_verified is True
    assert fresh.artifacts[0].artifact_id == "vnish-s21xp-1.2.7-hwscan"
    assert fresh.hwscan_route.mapper.file_offset == 0x10FE2C
    assert fresh.hwscan_route.load_segments[0].virtual_address == 0x10000
    assert fresh.hwscan_route.chain_devices == (
        "/dev/ttyS3",
        "/dev/ttyS2",
        "/dev/ttyS1",
    )
    assert fresh.cgminer_route.mapper.file_offset == 0x0FAFB4
    assert fresh.chains[0].uart_device == "/dev/ttyS3"
    assert fresh.psu.power_enable_gpio == 437
    assert fresh.authority.device_open is False
    pairs = (
        (prior.artifacts[0], fresh.artifacts[0]),
        (prior.hwscan_route, fresh.hwscan_route),
        (prior.hwscan_route.mapper, fresh.hwscan_route.mapper),
        (prior.hwscan_route.load_segments[0], fresh.hwscan_route.load_segments[0]),
        (prior.cgminer_route, fresh.cgminer_route),
        (prior.chains[0], fresh.chains[0]),
        (prior.psu, fresh.psu),
        (prior.authority, fresh.authority),
    )
    assert all(before is not after for before, after in pairs)


def test_public_global_shadow_cannot_forge_admission_or_semantics(
    held_raw, monkeypatch
):
    forged = dict(held_raw)
    changed = bytearray(forged["hwscan"])
    changed[0x10FE2C] ^= 1
    forged["hwscan"] = bytes(changed)
    specs = list(subject._ARTIFACT_SPECS)
    specs[0] = (
        specs[0][0],
        len(forged["hwscan"]),
        hashlib.sha256(forged["hwscan"]).hexdigest(),
    )
    shadows = {
        "_ARTIFACT_SPECS": tuple(specs),
        "_HWSCAN_LOADS": (),
        "_CGMINER_LOADS": (),
        "_HWSCAN_FUNCTIONS": (),
        "_CGMINER_FUNCTIONS": (),
        "_HWSCAN_MAPPER_WINDOW": b"",
        "_HWSCAN_MAPPER_TABLE": b"",
        "_HWSCAN_ROUTE_TABLES": b"",
        "_HWSCAN_MAPPER_VTABLE_WINDOW": b"",
        "_HWSCAN_PLATFORM_LITERALS": b"",
        "_HWSCAN_PLATFORM_ENUM_TABLE": b"",
        "_HWSCAN_UART_RODATA": b"",
        "_HWSCAN_PLUG_TABLE": b"",
        "_HWSCAN_RESET_TABLE": b"",
        "_HWSCAN_PSU_SOURCE": b"",
        "_HWSCAN_PSU_LABEL": b"",
        "_CGMINER_MAPPER_WINDOW": b"",
        "_CGMINER_MAPPER_TABLE": b"",
        "_CGMINER_MAPPER_VTABLE_WINDOW": b"",
        "_CGMINER_ENCRYPTED_UARTS": (),
        "ArtifactReceipt": object,
        "ElfLoadSegment": object,
        "FunctionReceipt": object,
        "BinaryRouteReceipt": object,
        "ProductionChainRoute": object,
        "PsuObservation": object,
        "ProductionRouteAuthority": object,
        "S21XpProductionRouteInspection": object,
        "hashlib": None,
        "json": None,
        "struct": None,
    }
    injected_builtin_shadows = {
        "bytes": lambda *_: b"poison",
        "tuple": lambda *_: ("poison",),
        "len": lambda *_: 0,
        "type": lambda *_: object,
        "any": lambda *_: False,
        "zip": lambda *_: (),
        "enumerate": lambda *_: (),
        "isinstance": lambda *_: False,
        "dict": object,
        "range": lambda *_: (),
    }
    for name, value in shadows.items():
        monkeypatch.setattr(subject, name, value)
    for name, value in injected_builtin_shadows.items():
        monkeypatch.setattr(subject, name, value, raising=False)

    exact = subject.inspect_s21xp_production_route(**held_raw)
    assert exact.inspection_verified is True
    assert exact.hwscan_route.route_verified is True
    assert exact.cgminer_route.route_verified is True
    assert exact.chains[0].uart_device == "/dev/ttyS3"
    assert exact.authority.device_open is False
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        subject.inspect_s21xp_production_route(**forged)


def test_module_is_bytes_only_pure_and_has_no_action_surface():
    path = Path(__file__).with_name("s21xp_production_route_evidence.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
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


def test_inspector_rejects_unexpected_control_arguments(held_raw):
    with pytest.raises(TypeError, match="unexpected keyword"):
        inspect_s21xp_production_route(**held_raw, device="/dev/ttyS3")


def test_normal_construction_cannot_set_inspection_trust(held_inspection):
    values = {
        item.name: getattr(held_inspection, item.name)
        for item in dataclasses.fields(S21XpProductionRouteInspection)
        if item.init
    }
    with pytest.raises(TypeError):
        S21XpProductionRouteInspection(**values, inspection_verified=True)
