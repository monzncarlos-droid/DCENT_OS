from __future__ import annotations

import ast
import dataclasses
import hashlib
import struct
from pathlib import Path

import pytest

import t21_production_route_evidence as subject
from t21_production_route_evidence import (
    ArtifactReceipt,
    BinaryRouteReceipt,
    ProductionRouteAuthority,
    T21ProductionRouteInspection,
    inspect_t21_production_route,
)


_WORKSPACE = Path(__file__).resolve().parents[3]
_ROOTFS = (
    _WORKSPACE
    / ""
    / "awesome-1.2.6-aml-nand-install/rootfs"
)
_PATHS = {
    "hwscan": _ROOTFS / "usr/bin/hwscan",
    "cgminer": _ROOTFS / "usr/bin/cgminer",
    "fw_info": _ROOTFS / "etc/fw-info",
    "s12hwscan": _ROOTFS / "etc/init.d/S12hwscan",
    "s11board": _ROOTFS / "etc/init.d/S11board",
}


@pytest.fixture(scope="session")
def held_raw():
    missing = tuple(str(path) for path in _PATHS.values() if not path.is_file())
    if missing:
        pytest.skip(f"held T21 production rootfs is not mounted: {missing!r}")
    return {name: path.read_bytes() for name, path in _PATHS.items()}


@pytest.fixture(scope="session")
def held_inspection(held_raw):
    return inspect_t21_production_route(**held_raw)


def test_exact_held_census_and_package_association(held_inspection):
    inspection = held_inspection
    assert inspection.inspection_verified is True
    assert inspection.production_association_verified is True
    assert tuple((item.size, item.sha256) for item in inspection.artifacts) == (
        (
            4_001_996,
            "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f",
        ),
        (
            5_384_168,
            "da66295ab17273d7e6a8805958c9e47ee364e57a55c38528e801240a5e7c0735",
        ),
        (
            265,
            "60638646b5fc4807498d10240bbce8461ca9f5aa7b343d25089217186474e7db",
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
    ) == ("Awesome", "1.2.6", "Antminer T21", "t21", "aml", "nand")
    assert inspection.hwscan_command == (
        "hwscan --platform aml --gen-model-info t21 --gen-def-conf t21"
    )


def test_hwscan_exact_elf_functions_tables_and_mapping(held_inspection, held_raw):
    route = held_inspection.hwscan_route
    raw = held_raw["hwscan"]
    assert route.route_verified is True
    assert (route.elf_machine, route.elf_entry) == (40, 0x11EB8)
    assert tuple(dataclasses.astuple(item) for item in route.load_segments) == (
        (0, 0x10000, 0x3BA668, 0x3BA668, 5, 0x10000),
        (0x3BABC8, 0x3DABC8, 0x16108, 0x26200, 6, 0x10000),
    )
    assert dataclasses.astuple(route.mapper) == (
        "AML chain UART mapper",
        0x0FACF8,
        0x0EACF8,
        0x28,
        "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac",
    )
    assert (
        route.mapper_table_virtual_address,
        route.mapper_table_file_offset,
        route.vtable_mapper_pointer_virtual_address,
        route.vtable_mapper_pointer_file_offset,
    ) == (0x3DC558, 0x3BC558, 0x3DE6C0, 0x3BE6C0)
    assert struct.unpack_from("<3I", raw, 0x3BC558) == (
        0x3B388D,
        0x3B3898,
        0x3B38A3,
    )
    assert struct.unpack_from("<3I", raw, 0x3A384C) == (439, 440, 441)
    assert struct.unpack_from("<3I", raw, 0x3A3858) == (454, 455, 456)
    assert raw[0xEAA74 + 0x5C : 0xEAA74 + 0x60] == bytes.fromhex("011021e2")
    for function in route.functions:
        assert function.virtual_address - function.file_offset == 0x10000
        window = raw[function.file_offset : function.file_offset + function.size]
        assert hashlib.sha256(window).hexdigest() == function.sha256


def test_cgminer_independent_exact_route_and_xor_strings(held_inspection, held_raw):
    route = held_inspection.cgminer_route
    raw = held_raw["cgminer"]
    assert route.route_verified is True
    assert (route.elf_machine, route.elf_entry) == (40, 0x1012C)
    assert tuple(dataclasses.astuple(item) for item in route.load_segments) == (
        (0, 0x10000, 0x4F0F44, 0x4F0F44, 5, 0x10000),
        (0x4F0F68, 0x510F68, 0x314B8, 0x7D0DC, 6, 0x10000),
    )
    assert dataclasses.astuple(route.mapper) == (
        "AML chain UART mapper",
        0x107E34,
        0x0F7E34,
        0x28,
        "2898396347770a76c65f6f32a55c804b776d360ab1443e2e9bf712b907e80af5",
    )
    assert (
        route.mapper_table_virtual_address,
        route.mapper_table_file_offset,
        route.vtable_mapper_pointer_virtual_address,
        route.vtable_mapper_pointer_file_offset,
    ) == (0x511450, 0x4F1450, 0x514238, 0x4F4238)
    assert struct.unpack_from("<3I", raw, 0x4F1450) == (
        0x5235EC,
        0x5235F7,
        0x523602,
    )
    observations = (
        (0x5035EC, 0xDA, "/dev/ttyS3"),
        (0x5035F7, 0x1A, "/dev/ttyS2"),
        (0x503602, 0x70, "/dev/ttyS1"),
    )
    assert tuple(
        bytes(value ^ key for value in raw[offset : offset + 10]).decode("ascii")
        for offset, key, _ in observations
    ) == tuple(cleartext for _, _, cleartext in observations)
    assert route.chain_devices == held_inspection.hwscan_route.chain_devices


def test_zero_based_route_psu_boundary_and_residuals(held_inspection):
    inspection = held_inspection
    assert tuple(dataclasses.astuple(item) for item in inspection.chains) == (
        (0, "/dev/ttyS3", 439, 454, True),
        (1, "/dev/ttyS2", 440, 455, True),
        (2, "/dev/ttyS1", 441, 456, True),
    )
    assert inspection.production_route_kind == (
        "AML direct UART; not Cvitek uart_trans or Zynq FPGA"
    )
    assert inspection.cvitek_route_is_distinct is True
    assert inspection.zynq_fpga_route_is_distinct is True
    assert dataclasses.astuple(inspection.psu) == (
        "board-global code and init-script observation only",
        437,
        1,
        (477, 476),
        "i2c:psu-bus",
        True,
        False,
        False,
        False,
        False,
    )
    assert inspection.pic_runtime_identity_verified is False
    assert any("PIC implementation" in item for item in inspection.unresolved)
    assert any("PSU family" in item for item in inspection.unresolved)
    assert any("EEPROM" in item for item in inspection.unresolved)


def test_exact_board_gpio_observations_do_not_claim_setup_safety(held_inspection):
    assert dataclasses.astuple(held_inspection.board_io) == (
        446,
        445,
        437,
        1,
        (439, 440, 441),
        True,
        (454, 455, 456),
        True,
        453,
        438,
        False,
        False,
        False,
        False,
    )


def test_exact_fan_setup_observation_does_not_claim_cooling(held_inspection):
    assert dataclasses.astuple(held_inspection.fans) == (
        (447, 448),
        (449, 450),
        "falling",
        0,
        0,
        1,
        100_000,
        100_000,
        True,
        False,
        False,
        False,
    )


@pytest.mark.parametrize("name", tuple(_PATHS))
def test_every_input_is_exact_hash_gated(held_raw, name):
    forged = dict(held_raw)
    changed = bytearray(forged[name])
    changed[len(changed) // 2] ^= 1
    forged[name] = bytes(changed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inspect_t21_production_route(**forged)


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
        inspect_t21_production_route(**wrong)
    assert calls == 0

    nonbytes = dict(held_raw)
    nonbytes["hwscan"] = bytearray(nonbytes["hwscan"])
    with pytest.raises(TypeError, match="exact bytes"):
        inspect_t21_production_route(**nonbytes)


def test_authority_and_trust_are_false_by_default_and_replace_safe(held_inspection):
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
        2,
        held_inspection.hwscan_route.mapper,
        0,
        0,
        0,
        0,
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
    prior = inspect_t21_production_route(**held_raw)
    object.__setattr__(prior.artifacts[0], "artifact_id", "poison")
    object.__setattr__(prior.hwscan_route.mapper, "file_offset", 0)
    object.__setattr__(prior.hwscan_route.load_segments[0], "virtual_address", 0)
    object.__setattr__(prior.hwscan_route, "chain_devices", ("poison",))
    object.__setattr__(prior.cgminer_route.mapper, "file_offset", 0)
    object.__setattr__(prior.chains[0], "uart_device", "poison")
    object.__setattr__(prior.board_io, "power_enable_gpio", 0)
    object.__setattr__(prior.fans, "pwm_period_ns", 0)
    object.__setattr__(prior.psu, "power_enable_gpio", 0)
    object.__setattr__(prior.authority, "device_open", True)
    object.__setattr__(prior, "inspection_verified", False)

    fresh = inspect_t21_production_route(**held_raw)
    assert fresh.inspection_verified is True
    assert fresh.artifacts[0].artifact_id == "vnish-t21-1.2.6-hwscan"
    assert fresh.hwscan_route.mapper.file_offset == 0x0EACF8
    assert fresh.hwscan_route.load_segments[0].virtual_address == 0x10000
    assert fresh.hwscan_route.chain_devices == (
        "/dev/ttyS3",
        "/dev/ttyS2",
        "/dev/ttyS1",
    )
    assert fresh.cgminer_route.mapper.file_offset == 0x0F7E34
    assert fresh.chains[0].uart_device == "/dev/ttyS3"
    assert fresh.board_io.power_enable_gpio == 437
    assert fresh.fans.pwm_period_ns == 100_000
    assert fresh.psu.power_enable_gpio == 437
    assert fresh.authority.device_open is False
    pairs = (
        (prior.artifacts[0], fresh.artifacts[0]),
        (prior.hwscan_route, fresh.hwscan_route),
        (prior.hwscan_route.mapper, fresh.hwscan_route.mapper),
        (prior.hwscan_route.load_segments[0], fresh.hwscan_route.load_segments[0]),
        (prior.cgminer_route, fresh.cgminer_route),
        (prior.chains[0], fresh.chains[0]),
        (prior.board_io, fresh.board_io),
        (prior.fans, fresh.fans),
        (prior.psu, fresh.psu),
        (prior.authority, fresh.authority),
    )
    assert all(before is not after for before, after in pairs)


def test_public_global_and_builtin_shadow_cannot_forge(held_raw, monkeypatch):
    forged = dict(held_raw)
    changed = bytearray(forged["hwscan"])
    changed[0xEACF8] ^= 1
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
        "_HWSCAN_PLATFORM_POINTERS": (),
        "_HWSCAN_PLATFORM_NAMES": (),
        "_HWSCAN_ROUTE_POINTERS": (),
        "_HWSCAN_ROUTE_TABLE_OFFSET": 0,
        "_HWSCAN_AML_VTABLE_OFFSET": 0,
        "_HWSCAN_PLUG_TABLE_OFFSET": 0,
        "_HWSCAN_RESET_TABLE_OFFSET": 0,
        "_CGMINER_ROUTE_POINTERS": (),
        "_CGMINER_ROUTE_TABLE_OFFSET": 0,
        "_CGMINER_AML_VTABLE_OFFSET": 0,
        "_CGMINER_ENCRYPTED_UARTS": (),
        "ArtifactReceipt": object,
        "ElfLoadSegment": object,
        "FunctionReceipt": object,
        "BinaryRouteReceipt": object,
        "ProductionChainRoute": object,
        "BoardGpioObservation": object,
        "FanObservation": object,
        "PsuObservation": object,
        "ProductionRouteAuthority": object,
        "T21ProductionRouteInspection": object,
        "hashlib": None,
        "struct": None,
    }
    builtin_shadows = {
        "bytes": lambda *_: b"poison",
        "tuple": lambda *_: ("poison",),
        "len": lambda *_: 0,
        "type": lambda *_: object,
        "any": lambda *_: False,
        "zip": lambda *_: (),
        "enumerate": lambda *_: (),
        "isinstance": lambda *_: False,
        "range": lambda *_: (),
    }
    for name, value in shadows.items():
        monkeypatch.setattr(subject, name, value)
    for name, value in builtin_shadows.items():
        monkeypatch.setattr(subject, name, value, raising=False)

    exact = subject.inspect_t21_production_route(**held_raw)
    assert exact.inspection_verified is True
    assert exact.hwscan_route.chain_devices == (
        "/dev/ttyS3",
        "/dev/ttyS2",
        "/dev/ttyS1",
    )
    assert exact.authority.device_open is False
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        subject.inspect_t21_production_route(**forged)


def test_module_is_bytes_only_pure_and_has_no_action_surface():
    path = Path(__file__).with_name("t21_production_route_evidence.py")
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


def test_inspector_rejects_control_arguments_and_trust_injection(
    held_raw, held_inspection
):
    with pytest.raises(TypeError, match="unexpected keyword"):
        inspect_t21_production_route(**held_raw, device="/dev/ttyS3")
    values = {
        item.name: getattr(held_inspection, item.name)
        for item in dataclasses.fields(T21ProductionRouteInspection)
        if item.init
    }
    with pytest.raises(TypeError):
        T21ProductionRouteInspection(**values, inspection_verified=True)
