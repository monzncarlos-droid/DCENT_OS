from __future__ import annotations

import ast
import dataclasses
import hashlib
import struct
from pathlib import Path

import pytest

import x19_aml_production_route_evidence as subject
from x19_aml_production_route_evidence import (
    ArtifactReceipt,
    BinaryRouteReceipt,
    ProductionRouteAuthority,
    X19AmlProductionRouteInspection,
    inspect_x19_aml_production_routes,
)


_WORKSPACE = Path(__file__).resolve().parents[3]
_ROOT = _WORKSPACE / ""
_ROOTS = {
    "s19xp": _ROOT / "s19xp/awesome-1.2.6-aml-nand-install/rootfs",
    "s19jxp": _ROOT / "s19j-xp/awesome-1.2.6-aml-nand-install/rootfs",
}
_PATHS = {
    f"{prefix}_{name}": root / relative
    for prefix, root in _ROOTS.items()
    for name, relative in {
        "hwscan": "usr/bin/hwscan",
        "cgminer": "usr/bin/cgminer",
        "fw_info": "etc/fw-info",
        "s12hwscan": "etc/init.d/S12hwscan",
        "s11board": "etc/init.d/S11board",
    }.items()
}


@pytest.fixture(scope="session")
def held_raw():
    missing = tuple(str(path) for path in _PATHS.values() if not path.is_file())
    if missing:
        pytest.skip(f"held X19 AML production rootfs is not mounted: {missing!r}")
    return {name: path.read_bytes() for name, path in _PATHS.items()}


@pytest.fixture(scope="session")
def held_inspection(held_raw):
    return inspect_x19_aml_production_routes(**held_raw)


def test_two_exact_rootfs_sets_are_model_bound(held_inspection):
    inspection = held_inspection
    assert inspection.inspection_verified is True
    assert tuple(
        (
            item.miner,
            item.model,
            item.platform,
            item.install_type,
            item.hwscan_command,
            item.production_association_verified,
        )
        for item in inspection.models
    ) == (
        (
            "Antminer S19 XP",
            "s19xp",
            "aml",
            "nand",
            "hwscan --platform aml --gen-model-info s19xp --gen-def-conf s19xp",
            True,
        ),
        (
            "Antminer S19j XP",
            "s19j-xp",
            "aml",
            "nand",
            "hwscan --platform aml --gen-model-info s19j-xp --gen-def-conf s19j-xp",
            True,
        ),
    )
    assert tuple(tuple((a.size, a.sha256) for a in item.artifacts) for item in inspection.models) == (
        (
            (4_001_996, "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f"),
            (5_400_552, "6f90b49d4047f9e329140ae5bc0918129aa36be1de8262fb6aeeb7ea69f489e1"),
            (270, "644c9cc6d24b6a915e98d699a2b40f7f673f1c1623eb17de474aacbf50b115ed"),
            (493, "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8"),
            (2_928, "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4"),
        ),
        (
            (3_993_804, "425e99950e9f8539caa209f88b472090c400d27dbe6555124e8e69537ab96909"),
            (5_363_624, "49f0784c7fd181250ac5ff4dfbea1ecb866d56e63f8da48c3b38004757d51059"),
            (273, "2a430a185a224bc719ff9afacc5e8d017f965afa15e7bc22ce82dbfcad2edaf5"),
            (493, "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8"),
            (2_928, "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4"),
        ),
    )
    assert all(
        artifact.verified_by_inspector
        for model in inspection.models
        for artifact in model.artifacts
    )


def test_s19xp_two_independent_mapper_receipts_are_exact(held_inspection, held_raw):
    model = held_inspection.models[0]
    hwscan = model.hwscan_route
    cgminer = model.cgminer_route
    assert (hwscan.elf_machine, hwscan.elf_entry) == (40, 0x11EB8)
    assert dataclasses.astuple(hwscan.mapper) == (
        "AML chain UART mapper",
        0x0FACF8,
        0x0EACF8,
        0x28,
        "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac",
    )
    assert (
        hwscan.mapper_table_virtual_address,
        hwscan.mapper_table_file_offset,
        hwscan.vtable_mapper_pointer_virtual_address,
        hwscan.vtable_mapper_pointer_file_offset,
    ) == (0x3DC558, 0x3BC558, 0x3DE6C0, 0x3BE6C0)
    assert (cgminer.elf_machine, cgminer.elf_entry) == (40, 0x1012C)
    assert dataclasses.astuple(cgminer.mapper) == (
        "AML chain UART mapper",
        0x10AEAC,
        0x0FAEAC,
        0x28,
        "8c351233f54143a9adfea921761b9bc29b1d11107c96fda4ca4d7cbac9998468",
    )
    assert (
        cgminer.mapper_table_virtual_address,
        cgminer.mapper_table_file_offset,
        cgminer.vtable_mapper_pointer_virtual_address,
        cgminer.vtable_mapper_pointer_file_offset,
    ) == (0x515450, 0x4F5450, 0x518238, 0x4F8238)
    assert struct.unpack_from("<3I", held_raw["s19xp_cgminer"], 0x4F5450) == (
        0x527614,
        0x52761F,
        0x52762A,
    )
    assert hwscan.chain_devices == cgminer.chain_devices


def test_s19jxp_two_independent_mapper_receipts_are_exact(held_inspection, held_raw):
    model = held_inspection.models[1]
    hwscan = model.hwscan_route
    cgminer = model.cgminer_route
    assert (hwscan.elf_machine, hwscan.elf_entry) == (40, 0x11EB8)
    assert tuple(dataclasses.astuple(item) for item in hwscan.load_segments) == (
        (0, 0x10000, 0x3B7E08, 0x3B7E08, 5, 0x10000),
        (0x3B8BC8, 0x3D8BC8, 0x16108, 0x26200, 6, 0x10000),
    )
    assert dataclasses.astuple(hwscan.mapper) == (
        "AML chain UART mapper",
        0x0FACF8,
        0x0EACF8,
        0x28,
        "8fefcfc1b22b57ba292dfc13c2529fb5b81ed8ec13c8077e0ee7f3ca79fee718",
    )
    assert (
        hwscan.mapper_table_virtual_address,
        hwscan.mapper_table_file_offset,
        hwscan.vtable_mapper_pointer_virtual_address,
        hwscan.vtable_mapper_pointer_file_offset,
    ) == (0x3DA558, 0x3BA558, 0x3DC6C0, 0x3BC6C0)
    assert dataclasses.astuple(cgminer.mapper) == (
        "AML chain UART mapper",
        0x107E8C,
        0x0F7E8C,
        0x28,
        "e4807988de8605506d9daadc5fcb438cc063efe63465602efce1a42ab8b865e1",
    )
    assert (
        cgminer.mapper_table_virtual_address,
        cgminer.mapper_table_file_offset,
        cgminer.vtable_mapper_pointer_virtual_address,
        cgminer.vtable_mapper_pointer_file_offset,
    ) == (0x50C450, 0x4EC450, 0x50F230, 0x4EF230)
    assert struct.unpack_from("<3I", held_raw["s19jxp_cgminer"], 0x4EC450) == (
        0x51E5D4,
        0x51E5DF,
        0x51E5EA,
    )
    assert hwscan.chain_devices == cgminer.chain_devices


def test_all_four_binaries_agree_but_models_remain_distinct(held_inspection):
    expected = ("/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1")
    assert all(
        route.chain_devices == expected
        for model in held_inspection.models
        for route in (model.hwscan_route, model.cgminer_route)
    )
    assert held_inspection.models[0].artifacts[1].sha256 != held_inspection.models[1].artifacts[1].sha256
    assert held_inspection.models[0].hwscan_route.mapper.sha256 != held_inspection.models[1].hwscan_route.mapper.sha256
    assert held_inspection.controller_routes_are_distinct is True
    assert held_inspection.model_bound_hashboard_identity_verified is False


def test_gpio_fan_psu_observations_do_not_claim_lifecycle_safety(held_inspection):
    assert tuple(dataclasses.astuple(item) for item in held_inspection.chains) == (
        (0, "/dev/ttyS3", 439, 454, True),
        (1, "/dev/ttyS2", 440, 455, True),
        (2, "/dev/ttyS1", 441, 456, True),
    )
    assert dataclasses.astuple(held_inspection.board_io) == (
        446,
        445,
        437,
        1,
        (439, 440, 441),
        (454, 455, 456),
        453,
        438,
        False,
        False,
        False,
        False,
    )
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
    )
    assert dataclasses.astuple(held_inspection.psu) == (
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
    assert any("hashboard identity" in item for item in held_inspection.unresolved)
    assert any("PIC or NoPic" in item for item in held_inspection.unresolved)


@pytest.mark.parametrize("name", tuple(_PATHS))
def test_every_input_is_exact_hash_gated(held_raw, name):
    forged = dict(held_raw)
    changed = bytearray(forged[name])
    changed[len(changed) // 2] ^= 1
    forged[name] = bytes(changed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        inspect_x19_aml_production_routes(**forged)


def test_wrong_size_and_nonbytes_reject_before_hash(held_raw, monkeypatch):
    wrong = dict(held_raw)
    wrong["s19xp_hwscan"] += b"x"
    calls = 0

    def forbidden_hash(_):
        nonlocal calls
        calls += 1
        raise AssertionError("wrong-size value must not be hashed")

    monkeypatch.setattr(subject.hashlib, "sha256", forbidden_hash)
    with pytest.raises(ValueError, match="size mismatch"):
        inspect_x19_aml_production_routes(**wrong)
    assert calls == 0

    nonbytes = dict(held_raw)
    nonbytes["s19jxp_hwscan"] = bytearray(nonbytes["s19jxp_hwscan"])
    with pytest.raises(TypeError, match="exact bytes"):
        inspect_x19_aml_production_routes(**nonbytes)


def test_authority_and_receipt_trust_are_constructor_closed(held_inspection):
    authority = ProductionRouteAuthority()
    assert len(dataclasses.fields(authority)) == 17
    assert all(getattr(authority, item.name) is False for item in dataclasses.fields(authority))
    with pytest.raises(TypeError):
        ProductionRouteAuthority(device_open=True)
    with pytest.raises(ValueError):
        dataclasses.replace(authority, gpio_write=True)

    artifact = ArtifactReceipt("forged", 1, "0" * 64)
    assert artifact.verified_by_inspector is False
    route = BinaryRouteReceipt(
        "forged",
        40,
        0,
        (),
        held_inspection.models[0].hwscan_route.mapper,
        0,
        0,
        0,
        0,
        (),
        (),
    )
    assert route.route_verified is False
    replaced = dataclasses.replace(held_inspection, model_bound_hashboard_identity_verified=True)
    assert replaced.inspection_verified is False


def test_prior_nested_poisoning_cannot_change_fresh_receipt(held_raw):
    prior = inspect_x19_aml_production_routes(**held_raw)
    object.__setattr__(prior.models[0].artifacts[0], "artifact_id", "poison")
    object.__setattr__(prior.models[0].hwscan_route.mapper, "file_offset", 0)
    object.__setattr__(prior.models[1].cgminer_route, "chain_devices", ("poison",))
    object.__setattr__(prior.chains[0], "uart_device", "poison")
    object.__setattr__(prior.board_io, "power_enable_gpio", 0)
    object.__setattr__(prior.authority, "device_open", True)
    object.__setattr__(prior, "inspection_verified", False)

    fresh = inspect_x19_aml_production_routes(**held_raw)
    assert fresh.inspection_verified is True
    assert fresh.models[0].artifacts[0].artifact_id == "vnish-s19xp-1.2.6-hwscan"
    assert fresh.models[0].hwscan_route.mapper.file_offset == 0x0EACF8
    assert fresh.models[1].cgminer_route.chain_devices == (
        "/dev/ttyS3",
        "/dev/ttyS2",
        "/dev/ttyS1",
    )
    assert fresh.chains[0].uart_device == "/dev/ttyS3"
    assert fresh.board_io.power_enable_gpio == 437
    assert fresh.authority.device_open is False


def test_public_global_shadow_cannot_forge(held_raw, monkeypatch):
    forged = dict(held_raw)
    changed = bytearray(forged["s19jxp_cgminer"])
    changed[0xF7E8C] ^= 1
    forged["s19jxp_cgminer"] = bytes(changed)
    specs = list(subject._S19JXP_ARTIFACT_SPECS)
    specs[1] = (specs[1][0], len(forged["s19jxp_cgminer"]), hashlib.sha256(forged["s19jxp_cgminer"]).hexdigest())
    monkeypatch.setattr(subject, "_S19JXP_ARTIFACT_SPECS", tuple(specs))
    monkeypatch.setattr(subject, "_CGMINER_S19JXP", ())
    monkeypatch.setattr(subject, "ArtifactReceipt", object)
    monkeypatch.setattr(subject, "hashlib", None)
    monkeypatch.setattr(subject, "struct", None)

    exact = subject.inspect_x19_aml_production_routes(**held_raw)
    assert exact.inspection_verified is True
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        subject.inspect_x19_aml_production_routes(**forged)


def test_module_is_bytes_only_and_has_no_action_surface():
    path = Path(__file__).with_name("x19_aml_production_route_evidence.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
    assert imports == {"__future__", "hashlib", "struct", "dataclasses", "typing"}
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


def test_inspector_rejects_control_arguments_and_trust_injection(held_raw, held_inspection):
    with pytest.raises(TypeError, match="unexpected keyword"):
        inspect_x19_aml_production_routes(**held_raw, device="/dev/ttyS3")
    values = {
        item.name: getattr(held_inspection, item.name)
        for item in dataclasses.fields(X19AmlProductionRouteInspection)
        if item.init
    }
    with pytest.raises(TypeError):
        X19AmlProductionRouteInspection(**values, inspection_verified=True)
