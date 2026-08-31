#!/usr/bin/env python3
"""Verify the offline BHB56902/BHB56903 controller-interface join.

This module reads only hash-pinned repository evidence. It has no network,
miner, GPIO, serial, power, probe, or mutation capability and grants none.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any, Mapping, NoReturn


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent
SCHEMA = "dcentos.s19k-shared-bhb5690x-interface-verification/v2"
INPUT_SCHEMA = "dcentos.s19k-shared-bhb5690x-interface-input/v2"
MAX_BYTES = 8 * 1024 * 1024

TOPOLOGY_902 = (
    ""
    "merge-extracted/zynq_rootfs/tree/etc/topol_BHB56902.conf"
)
TOPOLOGY_903 = (
    ""
    "merge-extracted/zynq_rootfs/tree/etc/topol_BHB56903.conf"
)
LEVELS = (
    ""
    "merge-extracted/zynq_rootfs/tree/etc/levels.json"
)
VNISH_ROOT = (
    ""
    "vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install"
)
VNISH_FW_INFO = f"{VNISH_ROOT}/rootfs/etc/fw-info"
VNISH_HWSCAN_INIT = f"{VNISH_ROOT}/rootfs/etc/init.d/S12hwscan"
VNISH_BOARD_SETUP = f"{VNISH_ROOT}/rootfs/etc/init.d/S11board"
VNISH_HWSCAN = f"{VNISH_ROOT}/rootfs/usr/bin/hwscan"
VNISH_CGMINER = f"{VNISH_ROOT}/rootfs/usr/bin/cgminer"
VNISH_DTB = f"{VNISH_ROOT}/devicetree.dtb"
INPUT = (
    ""
    "BHB5690X_SHARED_INTERFACE_INPUT.json"
)

EXPECTED_IDENTITIES = {
    TOPOLOGY_902: (
        "28b138cb8cc27e939933ca89d3027a08434c4615ad86d2fdf7d17525fe26b056",
        3798,
    ),
    TOPOLOGY_903: (
        "823084a4fdbc5ea554514262acbf242e1236ca74001ca23cf9f3d2d493d0c5df",
        3798,
    ),
    LEVELS: (
        "867047bd18aa9bcc5f8fbf4e053d78c688751d13fd2e99ad865608d93f0035b2",
        523,
    ),
    VNISH_BOARD_SETUP: (
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
        2928,
    ),
    VNISH_FW_INFO: (
        "e9a976cef48abced73e240afbd70d7c15310f7fe65c1d83b9910d1545b0bec0a",
        299,
    ),
    VNISH_HWSCAN_INIT: (
        "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
        493,
    ),
    VNISH_HWSCAN: (
        "9cfd4593fab33a58442fed55ff5c6205b6b07283a56677926b03b8ea1166a396",
        4_574_504,
    ),
    VNISH_CGMINER: (
        "656452b7570293b0c73737b4124129ef4e8f0d5bc12210bb75c23f87299d9b0e",
        5_790_164,
    ),
    VNISH_DTB: (
        "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
        20945,
    ),
}

EXPECTED_DIFF_PATHS = {"/machine", "/mix_boardnames/0"}
EXPECTED_GUIDE_PINS = {
    "3": "RST",
    "4": "VCC",
    "7": "TXD_COMMAND",
    "8": "RXD",
    "13": "PLUG",
    "15": "SDA",
    "16": "SCL",
}
HWSCAN_LOADS = (
    (0, 0x10000, 0x4417D4, 0x4417D4, 5, 0x10000),
    (0x441998, 0x461998, 0x1AF94, 0x2C430, 6, 0x10000),
)
CGMINER_LOADS = (
    (0, 0x10000, 0x551D18, 0x551D18, 5, 0x10000),
    (0x5522DC, 0x5722DC, 0x33330, 0x7FDD0, 6, 0x10000),
)
CGMINER_ENCRYPTED_UARTS = (
    (0x564DE0, 0x4E, bytes.fromhex("612a2b38613a3a371d7d"), "/dev/ttyS3"),
    (0x564DEB, 0x88, bytes.fromhex("a7ecedfea7fcfcf1dbba"), "/dev/ttyS2"),
    (0x564DF6, 0x99, bytes.fromhex("b6fdfcefb6edede0caa8"), "/dev/ttyS1"),
)


class InterfaceEvidenceError(ValueError):
    """The held corpus does not prove the bounded interface classification."""


def fail(message: str) -> NoReturn:
    raise InterfaceEvidenceError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _read_regular(path: Path, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size > MAX_BYTES:
        fail(f"{label} exceeds {MAX_BYTES} bytes: {path}")
    return path.read_bytes()


def _load_json(path: Path, label: str) -> Any:
    raw = _read_regular(path, label)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not UTF-8 JSON: {error}")


def _verify_identity(repo_root: Path, logical: str) -> dict[str, Any]:
    path = repo_root / logical
    raw = _read_regular(path, logical)
    actual = (hashlib.sha256(raw).hexdigest(), len(raw))
    expected = EXPECTED_IDENTITIES[logical]
    if actual != expected:
        fail(
            f"identity mismatch for {logical}: sha256={actual[0]} bytes={actual[1]}"
        )
    return {"path": logical, "sha256": actual[0], "bytes": actual[1]}


def _require_window(raw: bytes, offset: int, expected: bytes, label: str) -> None:
    if offset < 0 or offset + len(expected) > len(raw):
        fail(f"{label} is outside the exact artifact")
    if raw[offset : offset + len(expected)] != expected:
        fail(f"{label} byte window drifted")


def _function_receipt(
    raw: bytes, *, name: str, virtual_address: int, file_offset: int,
    size: int, expected_sha256: str
) -> dict[str, Any]:
    if file_offset < 0 or file_offset + size > len(raw):
        fail(f"{name} is outside the exact artifact")
    observed = hashlib.sha256(raw[file_offset : file_offset + size]).hexdigest()
    if observed != expected_sha256:
        fail(f"{name} exact function window drifted")
    return {
        "name": name,
        "virtual_address": virtual_address,
        "file_offset": file_offset,
        "bytes": size,
        "sha256": observed,
    }


def _elf_loads(
    raw: bytes, *, label: str, expected_entry: int,
    expected_loads: tuple[tuple[int, int, int, int, int, int], ...]
) -> dict[str, Any]:
    if raw[:16] != b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8:
        fail(f"{label} is not exact ELF32 little-endian System V")
    header = struct.unpack_from("<HHIIIIIHHHHHH", raw, 16)
    (
        elf_type, machine, version, entry, program_offset, _, _, header_size,
        program_entry_size, program_count, _, _, _,
    ) = header
    if (
        elf_type != 2
        or machine != 40
        or version != 1
        or entry != expected_entry
        or header_size != 52
        or program_entry_size != 32
        or program_offset + program_count * program_entry_size > len(raw)
    ):
        fail(f"{label} ELF identity or program-header bounds drifted")
    loads: list[tuple[int, int, int, int, int, int]] = []
    for index in range(program_count):
        item = struct.unpack_from("<IIIIIIII", raw, program_offset + index * 32)
        if item[0] == 1:
            _, file_offset, address, _, file_size, memory_size, flags, alignment = item
            loads.append(
                (file_offset, address, file_size, memory_size, flags, alignment)
            )
    if tuple(loads) != expected_loads:
        fail(f"{label} PT_LOAD geometry drifted")
    if any(offset + size > len(raw) for offset, _, size, _, _, _ in loads):
        fail(f"{label} PT_LOAD extends beyond the exact artifact")
    return {
        "elf_machine": machine,
        "elf_entry": entry,
        "load_segments": [
            {
                "file_offset": offset,
                "virtual_address": address,
                "file_bytes": file_size,
                "memory_bytes": memory_size,
                "flags": flags,
                "alignment": alignment,
            }
            for offset, address, file_size, memory_size, flags, alignment in loads
        ],
    }


def _validate_vnish_five_file_route(repo_root: Path) -> dict[str, Any]:
    paths = {
        "fw_info": VNISH_FW_INFO,
        "s12hwscan": VNISH_HWSCAN_INIT,
        "s11board": VNISH_BOARD_SETUP,
        "hwscan": VNISH_HWSCAN,
        "cgminer": VNISH_CGMINER,
    }
    raw = {
        name: _read_regular(repo_root / logical, logical)
        for name, logical in paths.items()
    }
    for name, logical in paths.items():
        expected_sha256, expected_bytes = EXPECTED_IDENTITIES[logical]
        if (
            len(raw[name]) != expected_bytes
            or hashlib.sha256(raw[name]).hexdigest() != expected_sha256
        ):
            fail(f"exact VNish five-file identity mismatch: {logical}")
    try:
        fw_info = json.loads(raw["fw_info"].decode("ascii"))
        s12 = raw["s12hwscan"].decode("ascii")
        s11 = raw["s11board"].decode("ascii")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"exact VNish production-association files are malformed: {error}")
    if fw_info != {
        "fw_name": "Vnish",
        "fw_version": "1.2.7",
        "platform": "aml",
        "install_type": "nand",
        "build_time": "2025-12-22 20:12:18",
        "build_name": "vnishfirmwarecom",
        "build_uuid": "a718957a-762f-4626-80d0-dba0c3926b7c",
        "miner": "Antminer S19k Pro",
        "model": "s19kpro",
    }:
        fail("exact VNish fw-info S19k production association drifted")
    for anchor in (
        "MINER_MODEL=$(fwinfo model)",
        "MINER_PLATFORM=$(fwinfo platform)",
        'HWSCAN_ARGS="--platform $MINER_PLATFORM --gen-model-info $MINER_MODEL --gen-def-conf $MINER_MODEL"',
        "if hwscan $HWSCAN_ARGS; then",
    ):
        if anchor not in s12:
            fail(f"exact S12hwscan production association lost: {anchor}")
    for anchor in (
        "# pwr_en 437", "echo 1 > /sys/class/gpio/gpio437/value",
        "# ch0_plug 439", "# ch1_plug 440", "# ch2_plug 441",
        "# ch0_rst 454", "# ch1_rst 455", "# ch2_rst 456",
        "# fan_front_speed0 447", "# fan_front_speed1 448",
        "# fan_rear_speed0 449", "# fan_rear_speed1 450",
    ):
        if anchor not in s11:
            fail(f"exact S11board GPIO association lost: {anchor}")

    hwscan = raw["hwscan"]
    hwscan_elf = _elf_loads(
        hwscan, label="VNish hwscan", expected_entry=0x11EB8,
        expected_loads=HWSCAN_LOADS,
    )
    hwscan_functions = [
        _function_receipt(
            hwscan, name="AML plug GPIO read", virtual_address=0x11FA44,
            file_offset=0x10FA44, size=0x9C,
            expected_sha256="9235f0bfedefd3a7e9593ee7f8b873d3d865bf6e5e2b39b1f6e1ec362aba7825",
        ),
        _function_receipt(
            hwscan, name="AML active-low reset GPIO write",
            virtual_address=0x11FAF4, file_offset=0x10FAF4, size=0x74,
            expected_sha256="bc7a4bea5fa47f0458f58fed20c997ac6b6ea7b8d2f7238dc1aa6452b5a57a10",
        ),
        _function_receipt(
            hwscan, name="AML reset-all low", virtual_address=0x11FDE4,
            file_offset=0x10FDE4, size=0x38,
            expected_sha256="5496b515766e955b07f76c35ba095346b848ad0158fda3f088e331df2ec9cc91",
        ),
        _function_receipt(
            hwscan, name="AML chain UART mapper", virtual_address=0x11FE2C,
            file_offset=0x10FE2C, size=0x28,
            expected_sha256="e94dd99f0445077914149e03ec94c296683390da081a56916e19ec0e9b1de06a",
        ),
    ]
    _require_window(
        hwscan, 0x443330, bytes.fromhex("fd7543000876430013764300"),
        "hwscan route-pointer table",
    )
    _require_window(
        hwscan, 0x4275EA,
        b"src/aml/platform.c\x00/dev/ttyS3\x00/dev/ttyS2\x00/dev/ttyS1\x00/tmp/",
        "hwscan clear UART route strings",
    )
    _require_window(
        hwscan, 0x4275BC, bytes.fromhex("b7010000b8010000b9010000"),
        "hwscan plug GPIO table",
    )
    _require_window(
        hwscan, 0x4275C8, bytes.fromhex("c6010000c7010000c8010000"),
        "hwscan reset GPIO table",
    )
    if struct.unpack_from("<3I", hwscan, 0x443330) != (
        0x4375FD, 0x437608, 0x437613
    ):
        fail("hwscan route-pointer decode drifted")

    cgminer = raw["cgminer"]
    cgminer_elf = _elf_loads(
        cgminer, label="VNish cgminer", expected_entry=0x1012C,
        expected_loads=CGMINER_LOADS,
    )
    cgminer_functions = [
        _function_receipt(
            cgminer, name="AML UART string decoder", virtual_address=0x109BB8,
            file_offset=0x0F9BB8, size=0x2E4,
            expected_sha256="17ba2bcf584b61f94cf0b84d9839da3913d23d304d42b1beb0762577dec210a5",
        ),
        _function_receipt(
            cgminer, name="AML chain UART mapper", virtual_address=0x1099CC,
            file_offset=0x0F99CC, size=0x28,
            expected_sha256="950b79a273a8552b70c148e68a317ded999cfd1ca6fd7ccfcaacb5e9a1fcd124",
        ),
    ]
    _require_window(
        cgminer, 0x552754, bytes.fromhex("e04d5800eb4d5800f64d5800"),
        "cgminer route-pointer table",
    )
    _require_window(
        cgminer, 0x539D2C,
        bytes.fromhex("b7010000b8010000b9010000c6010000c7010000c8010000"),
        "cgminer plug/reset GPIO tables",
    )
    if struct.unpack_from("<3I", cgminer, 0x552754) != (
        0x584DE0, 0x584DEB, 0x584DF6
    ):
        fail("cgminer route-pointer decode drifted")
    decoded: list[str] = []
    for offset, key, ciphertext, cleartext in CGMINER_ENCRYPTED_UARTS:
        _require_window(cgminer, offset, ciphertext, "cgminer encrypted UART")
        value = bytes(item ^ key for item in ciphertext).decode("ascii")
        if value != cleartext:
            fail("cgminer UART XOR decode drifted")
        decoded.append(value)
    if decoded != ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]:
        fail("cgminer production route order drifted")

    routes = [
        {
            "zero_based_chain_index": index,
            "uart_device": device,
            "plug_gpio": 439 + index,
            "reset_gpio": 454 + index,
            "reset_active_low": True,
        }
        for index, device in enumerate(decoded)
    ]
    return {
        "firmware": {
            "name": fw_info["fw_name"],
            "version": fw_info["fw_version"],
            "miner": fw_info["miner"],
            "model": fw_info["model"],
            "platform": fw_info["platform"],
            "install_type": fw_info["install_type"],
        },
        "production_command": (
            "hwscan --platform aml --gen-model-info s19kpro --gen-def-conf s19kpro"
        ),
        "hwscan": {**hwscan_elf, "functions": hwscan_functions},
        "cgminer": {**cgminer_elf, "functions": cgminer_functions},
        "routes": routes,
        "independent_route_implementations_agree": True,
        "production_association_verified": True,
        "route_activation_authority": False,
        "physical_connector_mapping_proven": False,
    }


def _diff_paths(left: Any, right: Any, path: str = "") -> set[str]:
    if type(left) is not type(right):
        return {path or "/"}
    if isinstance(left, dict):
        if set(left) != set(right):
            return {path or "/"}
        result: set[str] = set()
        for key in sorted(left):
            result.update(_diff_paths(left[key], right[key], f"{path}/{key}"))
        return result
    if isinstance(left, list):
        if len(left) != len(right):
            return {path or "/"}
        result = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            result.update(
                _diff_paths(left_item, right_item, f"{path}/{index}")
            )
        return result
    return set() if left == right else {path or "/"}


def _validate_topologies(topology_902: Any, topology_903: Any) -> dict[str, Any]:
    if not isinstance(topology_902, dict) or not isinstance(topology_903, dict):
        fail("topology roots must be objects")
    if topology_902.get("machine") != "BHB56902":
        fail("BHB56902 topology has wrong machine")
    if topology_903.get("machine") != "BHB56903":
        fail("BHB56903 topology has wrong machine")
    if topology_902.get("mix_boardnames") != ["BHB56902"]:
        fail("BHB56902 topology has wrong mix_boardnames")
    if topology_903.get("mix_boardnames") != ["BHB56903"]:
        fail("BHB56903 topology has wrong mix_boardnames")
    differences = _diff_paths(topology_902, topology_903)
    if differences != EXPECTED_DIFF_PATHS:
        fail(f"topology diff escaped model-name fields: {sorted(differences)}")

    expected_asic = {
        "asic_id": "BM1366",
        "asic_addr": "0x1366",
        "asic_core_num": 112,
        "asic_small_core_num": 894,
        "core_small_core_num": 8,
        "asic_domain_num": 1,
        "asic_addr_interval": 2,
    }
    if topology_902.get("asic") != expected_asic:
        fail("shared ASIC contract drifted")
    chain = topology_902.get("chain")
    if not isinstance(chain, dict):
        fail("shared chain contract is absent")
    expected_geometry = {
        "chain_num": 3,
        "chain_row": 11,
        "chain_column": 7,
        "chain_domain_num": 11,
        "chain_asic_num": 77,
        "domain_asic_num": 7,
    }
    for key, expected in expected_geometry.items():
        if chain.get(key) != expected:
            fail(f"shared chain field {key} drifted")
    topology = chain.get("tpl")
    flattened = [item for row in topology or [] for item in row]
    if len(flattened) != 77 or set(flattened) != set(range(1, 78)):
        fail("shared 77-chip topology is incomplete or duplicated")
    power = topology_902.get("power")
    if not isinstance(power, dict) or power.get("type") != "APW12":
        fail("shared APW12 power class is absent")
    return {
        "diff_paths": sorted(differences),
        "asic": "BM1366",
        "chains": 3,
        "chips_per_chain": 77,
        "domains_per_chain": 11,
        "chips_per_domain": 7,
        "power_class": "APW12",
    }


def _validate_levels(levels: Any) -> list[dict[str, int]]:
    if not isinstance(levels, dict) or not isinstance(levels.get("config"), list):
        fail("stock levels root is malformed")
    by_miner = {
        item.get("miner"): item.get("levels")
        for item in levels["config"]
        if isinstance(item, dict)
    }
    if by_miner.get("BHB56902") != by_miner.get("BHB56903"):
        fail("BHB56902/BHB56903 stock levels differ")
    expected = [
        {"frequency": 670, "voltage": 1440},
        {"frequency": 540, "voltage": 1320},
    ]
    if by_miner.get("BHB56902") != expected:
        fail("shared stock operating levels drifted")
    return expected


def _validate_input(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != INPUT_SCHEMA:
        fail(f"operator input must use schema {INPUT_SCHEMA}")
    statement = document.get("operator_statement")
    expected_statement = (
        "Well if it helps, we regularly mix 902 and 903 boards on the same "
        "units.\u00e0"
    )
    if statement != expected_statement:
        fail("operator statement is not the exact recorded text")
    attestation = document.get("operator_attestation")
    if not isinstance(attestation, dict):
        fail("operator attestation is absent")
    if attestation.get("regular_mixed_same_unit_operation") is not True:
        fail("regular mixed same-unit operation is not attested")
    if attestation.get("standard_unmodified_keyed_harness") is not None:
        fail("unmodified keyed harness must remain unasserted")
    if attestation.get("adapter_or_remap_used") is not None:
        fail("adapter/remap use must remain unasserted")
    if attestation.get("per_unit_service_records_supplied") is not False:
        fail("per-unit service records must remain explicitly absent")
    guide = document.get("guide")
    if not isinstance(guide, dict) or guide.get("board") != "BHB56902":
        fail("guide source board must remain BHB56902")
    if guide.get("j450_candidate_pins") != EXPECTED_GUIDE_PINS:
        fail("guide J450 candidate map drifted")
    return {
        "statement_sha256": hashlib.sha256(statement.encode("utf-8")).hexdigest(),
        "regular_mixed_same_unit_operation": True,
        "standard_unmodified_keyed_harness": None,
        "adapter_or_remap_used": None,
        "per_unit_service_records_supplied": False,
    }


def verify_static_interface(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    identities = [
        _verify_identity(repo_root, logical) for logical in EXPECTED_IDENTITIES
    ]
    topology_902 = _load_json(repo_root / TOPOLOGY_902, "BHB56902 topology")
    topology_903 = _load_json(repo_root / TOPOLOGY_903, "BHB56903 topology")
    topology = _validate_topologies(topology_902, topology_903)
    levels = _validate_levels(_load_json(repo_root / LEVELS, "stock levels"))
    operator = _validate_input(_load_json(repo_root / INPUT, "operator input"))
    vnish_route = _validate_vnish_five_file_route(repo_root)

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "classification": "shared-controller-interface-static-proof",
        "source_identities": identities,
        "stock_topology": topology,
        "stock_operating_levels": levels,
        "vnish_exact_five_file_route_inspection": vnish_route,
        "operator_field_evidence": operator,
        "guide_j450_candidate_pins": EXPECTED_GUIDE_PINS,
        "shared_controller_facing_functional_compatibility": True,
        "shared_stock_power_feed_class": True,
        "shared_keyed_harness_pin_contract": False,
        "internal_layout_equivalence": False,
        "electrical_levels_proven": False,
        "probe_authority": False,
        "instrumentation_gate_satisfied": False,
        "live_contact_authority": False,
        "persistent_mutation_authority": False,
    }
    result["verification_id"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def audit_source_tree(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    try:
        result = verify_static_interface(repo_root)
    except Exception as error:
        return {"classification": "blocked_tooling", "blocker": str(error)}
    return {
        "classification": "ready",
        "blocker": None,
        "verification_id": result["verification_id"],
    }


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"evidence directory must be a real directory: {evidence_dir}")
    names = {path.name for path in evidence_dir.iterdir()}
    unexpected = names - {"verification.json"}
    if unexpected:
        fail(f"unexpected static-interface evidence leaves: {sorted(unexpected)}")
    return verify_static_interface()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("audit", "verify"))
    args = parser.parse_args(argv)
    if args.command == "audit":
        result = audit_source_tree()
    else:
        result = verify_static_interface()
    sys.stdout.buffer.write(canonical_json(result))
    return 0 if result.get("classification") != "blocked_tooling" else 1


if __name__ == "__main__":
    raise SystemExit(main())
