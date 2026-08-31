"""Exact, bytes-only S21 XP production carrier-route evidence.

This module admits five exact files from the held VNish 1.2.7 S21 XP AML
root filesystem.  It records two independent userspace implementations of the
same zero-based hashchain-to-UART route.  It does not open paths or devices,
construct a runtime driver, or authorize GPIO, UART, PIC, PSU, mining, or
firmware operations.

The exact ``hwscan`` image was inspected as ARM ELF32 in Ghidra.  Its platform
parser at VA 0x000fa320 maps the literal ``aml`` to control-board enum 2.  The
enum-2 vtable selects the mapper at VA 0x0011fe2c, whose bounded table maps
indices 0/1/2 to ``/dev/ttyS3``, ``/dev/ttyS2``, and ``/dev/ttyS1``.  The exact
``cgminer`` image independently carries the same mapper at VA 0x0010afb4 and
an XOR-obfuscated table with the same three strings.  All VAs and file offsets
below are rechecked against exact PT_LOAD geometry before a receipt is minted.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Final, Tuple


_ARTIFACT_SPECS: Final[Tuple[Tuple[str, int, str], ...]] = (
    (
        "vnish-s21xp-1.2.7-hwscan",
        4_574_504,
        "9cfd4593fab33a58442fed55ff5c6205b6b07283a56677926b03b8ea1166a396",
    ),
    (
        "vnish-s21xp-1.2.7-cgminer",
        5_798_548,
        "d71f268b8ec18f29f45a9cb20b34ed3976e2011d1ca6268c61cd2f8a7ac39e3b",
    ),
    (
        "vnish-s21xp-1.2.7-fw-info",
        295,
        "899e9bde7780b0ec53406d01c7f08e4bf947617259d543aea820116a3abae531",
    ),
    (
        "vnish-s21xp-1.2.7-s12hwscan",
        493,
        "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    ),
    (
        "vnish-s21xp-1.2.7-s11board",
        2_928,
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    ),
)

_HWSCAN_LOADS: Final[Tuple[Tuple[int, int, int, int, int, int], ...]] = (
    (0, 0x10000, 0x4417D4, 0x4417D4, 5, 0x10000),
    (0x441998, 0x461998, 0x1AF94, 0x2C430, 6, 0x10000),
)
_CGMINER_LOADS: Final[Tuple[Tuple[int, int, int, int, int, int], ...]] = (
    (0, 0x10000, 0x553670, 0x553670, 5, 0x10000),
    (0x5542E4, 0x5742E4, 0x333E8, 0x7FEC0, 6, 0x10000),
)

# name, VA, file offset, size, SHA-256
_HWSCAN_FUNCTIONS: Final[Tuple[Tuple[str, int, int, int, str], ...]] = (
    (
        "platform CLI parser (aml -> enum 2)",
        0x0FA320,
        0x0EA320,
        0x3E0,
        "e2d4827bd704e8d2c42efa592b5bf550ca8ba11a2a235a14f79bba2ade3dec02",
    ),
    (
        "AML plug GPIO read",
        0x11FA44,
        0x10FA44,
        0x9C,
        "9235f0bfedefd3a7e9593ee7f8b873d3d865bf6e5e2b39b1f6e1ec362aba7825",
    ),
    (
        "AML active-low reset GPIO write",
        0x11FAF4,
        0x10FAF4,
        0x74,
        "bc7a4bea5fa47f0458f58fed20c997ac6b6ea7b8d2f7238dc1aa6452b5a57a10",
    ),
    (
        "AML reset-all low",
        0x11FDE4,
        0x10FDE4,
        0x38,
        "5496b515766e955b07f76c35ba095346b848ad0158fda3f088e331df2ec9cc91",
    ),
    (
        "AML chain UART mapper",
        0x11FE2C,
        0x10FE2C,
        0x28,
        "e94dd99f0445077914149e03ec94c296683390da081a56916e19ec0e9b1de06a",
    ),
    (
        "AML PSU interface initialize",
        0x11FF18,
        0x10FF18,
        0x14C,
        "951412185ca1c1d0f9bad69a2c4f75a942d19475341e183aa2f16f950d8c4d95",
    ),
    (
        "AML PSU power-enable low",
        0x1200B0,
        0x1100B0,
        0x84,
        "994db550f436aa5018e2871677b8468fa56d5ff757d7dda2cdd197332de5ab9b",
    ),
    (
        "AML PSU power-enable high",
        0x120148,
        0x110148,
        0x80,
        "88c5e00dfefbe35d6c4fc3115ee8c53846540de2cd59b01b9af779e2fc55e0ac",
    ),
    (
        "AML PSU interface cleanup",
        0x1201DC,
        0x1101DC,
        0x48,
        "927391468e7f5c6226fc8f784b01b1c7341d5ed8f8b980e62ae06ed3a59a5ecf",
    ),
)

_HWSCAN_MAPPER_WINDOW: Final[bytes] = bytes.fromhex(
    "020050e318009f8500008f801eff2f8108109fe501108fe0000191e71eff2fe1e834340072323200"
)
_HWSCAN_MAPPER_TABLE: Final[bytes] = bytes.fromhex("fd7543000876430013764300")
_HWSCAN_ROUTE_TABLES: Final[bytes] = bytes.fromhex(
    "2f7043003a7043004570430050704300fd7543000876430013764300a4774300"
    "af774300ba774300c57743001376430008764300fd7543004c7d4300"
)
_HWSCAN_MAPPER_VTABLE_WINDOW: Final[bytes] = bytes.fromhex(
    "2cfe110050661000a4eb0f009091480070c51000d8181000248b4800d4031200"
)
_HWSCAN_PLATFORM_LITERALS: Final[bytes] = b"aml\x00bb\x00cv\x00stm\x00xil\x00he"
_HWSCAN_PLATFORM_ENUM_TABLE: Final[bytes] = bytes.fromhex(
    "5a304300503043004c3043005330430056304300"
)
_HWSCAN_UART_RODATA: Final[bytes] = (
    b"src/aml/platform.c\x00/dev/ttyS3\x00/dev/ttyS2\x00/dev/ttyS1\x00/tmp/"
)
_HWSCAN_PLUG_TABLE: Final[bytes] = bytes.fromhex("b7010000b8010000b9010000")
_HWSCAN_RESET_TABLE: Final[bytes] = bytes.fromhex("c6010000c7010000c8010000")
_HWSCAN_PSU_SOURCE: Final[bytes] = b"src/aml/psu.c\x00"
_HWSCAN_PSU_LABEL: Final[bytes] = b"i2c:psu-bus\x00"

_CGMINER_FUNCTIONS: Final[Tuple[Tuple[str, int, int, int, str], ...]] = (
    (
        "AML chain UART mapper",
        0x10AFB4,
        0x0FAFB4,
        0x28,
        "d5bf21f4545b5446d450927a32fc02ec4929c35e99a67961346717e2ea6c9317",
    ),
)
_CGMINER_MAPPER_WINDOW: Final[bytes] = bytes.fromhex(
    "020050e318009f8500008f801eff2f8108109fe501108fe0000191e71eff2fe18c974600cbfe4400"
)
_CGMINER_MAPPER_TABLE: Final[bytes] = bytes.fromhex("a86e5800b36e5800be6e5800")
_CGMINER_MAPPER_VTABLE_WINDOW: Final[bytes] = bytes.fromhex(
    "b4af10005cf25e0060f25e00d8ec5e0030f85e000cf45e00e0ec5e0084e85e00"
)
_CGMINER_ENCRYPTED_UARTS: Final[Tuple[Tuple[int, int, bytes, str], ...]] = (
    (0x566EA8, 0xBC, bytes.fromhex("93d8d9ca93c8c8c5ef8f"), "/dev/ttyS3"),
    (0x566EB3, 0xB5, bytes.fromhex("9ad1d0c39ac1c1cce687"), "/dev/ttyS2"),
    (0x566EBE, 0x2C, bytes.fromhex("0348495a035858557f1d"), "/dev/ttyS1"),
)


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    size: int
    sha256: str
    caller_supplied: bool = True
    verified_by_inspector: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ElfLoadSegment:
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class FunctionReceipt:
    name: str
    virtual_address: int
    file_offset: int
    size: int
    sha256: str


@dataclass(frozen=True)
class BinaryRouteReceipt:
    artifact_id: str
    elf_machine: int
    elf_entry: int
    load_segments: Tuple[ElfLoadSegment, ...]
    mapper: FunctionReceipt
    mapper_table_virtual_address: int
    mapper_table_file_offset: int
    mapper_table_sha256: str
    vtable_mapper_pointer_virtual_address: int
    vtable_mapper_pointer_file_offset: int
    vtable_window_sha256: str
    chain_devices: Tuple[str, ...]
    functions: Tuple[FunctionReceipt, ...]
    route_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ProductionChainRoute:
    zero_based_chain_index: int
    uart_device: str
    plug_gpio: int
    reset_gpio: int
    reset_active_low: bool


@dataclass(frozen=True)
class PsuObservation:
    scope: str
    power_enable_gpio: int
    software_i2c_gpios: Tuple[int, int]
    interface_label: str
    psu_family_identified: bool
    protocol_identified: bool
    safe_energization_order_verified: bool


@dataclass(frozen=True)
class ProductionRouteAuthority:
    path_open: bool = field(default=False, init=False)
    device_open: bool = field(default=False, init=False)
    runtime_construction: bool = field(default=False, init=False)
    route_activation: bool = field(default=False, init=False)
    uart_read: bool = field(default=False, init=False)
    uart_write: bool = field(default=False, init=False)
    gpio_read: bool = field(default=False, init=False)
    gpio_write: bool = field(default=False, init=False)
    reset_control: bool = field(default=False, init=False)
    hotplug_read: bool = field(default=False, init=False)
    pic_access: bool = field(default=False, init=False)
    psu_access: bool = field(default=False, init=False)
    power_enable: bool = field(default=False, init=False)
    mining_start: bool = field(default=False, init=False)
    firmware_install: bool = field(default=False, init=False)
    factory_execution: bool = field(default=False, init=False)
    live_validation: bool = field(default=False, init=False)


@dataclass(frozen=True)
class S21XpProductionRouteInspection:
    artifacts: Tuple[ArtifactReceipt, ...]
    firmware_name: str
    firmware_version: str
    miner: str
    model: str
    platform: str
    install_type: str
    hwscan_command: str
    hwscan_route: BinaryRouteReceipt
    cgminer_route: BinaryRouteReceipt
    chains: Tuple[ProductionChainRoute, ...]
    psu: PsuObservation
    production_route_kind: str
    factory_fpga_route_is_distinct: bool
    pic_runtime_identity_verified: bool
    unresolved: Tuple[str, ...]
    authority: ProductionRouteAuthority = field(
        default_factory=ProductionRouteAuthority, init=False
    )
    production_association_verified: bool = field(default=False, init=False)
    inspection_verified: bool = field(default=False, init=False)


def _build_inspector(
    _artifact_specs=_ARTIFACT_SPECS,
    _hwscan_loads=_HWSCAN_LOADS,
    _cgminer_loads=_CGMINER_LOADS,
    _hwscan_functions=_HWSCAN_FUNCTIONS,
    _cgminer_functions=_CGMINER_FUNCTIONS,
    _hwscan_mapper_window=_HWSCAN_MAPPER_WINDOW,
    _hwscan_mapper_table=_HWSCAN_MAPPER_TABLE,
    _hwscan_route_tables=_HWSCAN_ROUTE_TABLES,
    _hwscan_vtable_window=_HWSCAN_MAPPER_VTABLE_WINDOW,
    _hwscan_platform_literals=_HWSCAN_PLATFORM_LITERALS,
    _hwscan_platform_enum_table=_HWSCAN_PLATFORM_ENUM_TABLE,
    _hwscan_uart_rodata=_HWSCAN_UART_RODATA,
    _hwscan_plug_table=_HWSCAN_PLUG_TABLE,
    _hwscan_reset_table=_HWSCAN_RESET_TABLE,
    _hwscan_psu_source=_HWSCAN_PSU_SOURCE,
    _hwscan_psu_label=_HWSCAN_PSU_LABEL,
    _cgminer_mapper_window=_CGMINER_MAPPER_WINDOW,
    _cgminer_mapper_table=_CGMINER_MAPPER_TABLE,
    _cgminer_vtable_window=_CGMINER_MAPPER_VTABLE_WINDOW,
    _cgminer_encrypted_uarts=_CGMINER_ENCRYPTED_UARTS,
    _artifact_type=ArtifactReceipt,
    _segment_type=ElfLoadSegment,
    _function_type=FunctionReceipt,
    _binary_route_type=BinaryRouteReceipt,
    _chain_type=ProductionChainRoute,
    _psu_type=PsuObservation,
    _inspection_type=S21XpProductionRouteInspection,
    _sha256=hashlib.sha256,
    _json_loads=json.loads,
    _unpack_from=struct.unpack_from,
    _setattr=object.__setattr__,
    _bytes=bytes,
    _tuple=tuple,
    _len=len,
    _type=type,
    _any=any,
    _zip=zip,
    _enumerate=enumerate,
    _isinstance=isinstance,
    _dict=dict,
    _range=range,
):
    artifact_specs = _tuple(_tuple(item) for item in _artifact_specs)
    hwscan_loads = _tuple(_tuple(item) for item in _hwscan_loads)
    cgminer_loads = _tuple(_tuple(item) for item in _cgminer_loads)
    hwscan_functions = _tuple(_tuple(item) for item in _hwscan_functions)
    cgminer_functions = _tuple(_tuple(item) for item in _cgminer_functions)
    hwscan_mapper_window = _bytes(_hwscan_mapper_window)
    hwscan_mapper_table = _bytes(_hwscan_mapper_table)
    hwscan_route_tables = _bytes(_hwscan_route_tables)
    hwscan_vtable_window = _bytes(_hwscan_vtable_window)
    hwscan_platform_literals = _bytes(_hwscan_platform_literals)
    hwscan_platform_enum_table = _bytes(_hwscan_platform_enum_table)
    hwscan_uart_rodata = _bytes(_hwscan_uart_rodata)
    hwscan_plug_table = _bytes(_hwscan_plug_table)
    hwscan_reset_table = _bytes(_hwscan_reset_table)
    hwscan_psu_source = _bytes(_hwscan_psu_source)
    hwscan_psu_label = _bytes(_hwscan_psu_label)
    cgminer_mapper_window = _bytes(_cgminer_mapper_window)
    cgminer_mapper_table = _bytes(_cgminer_mapper_table)
    cgminer_vtable_window = _bytes(_cgminer_vtable_window)
    cgminer_encrypted_uarts = _tuple(
        (offset, key, _bytes(ciphertext), cleartext)
        for offset, key, ciphertext, cleartext in _cgminer_encrypted_uarts
    )
    route_devices = ("/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1")
    hwscan_command = "hwscan --platform aml --gen-model-info s21xp --gen-def-conf s21xp"
    unresolved = (
        "PIC presence, implementation, address, and production selection are not proved by the admitted package",
        "PSU family, wire protocol, retry behavior, limits, and safe energization order remain unresolved",
        "live carrier revision and electrical validation remain pending",
        "the separate XIL/FPGA vtable is not a production AML hashchain route",
    )

    def validate_artifact(raw: bytes, spec: Tuple[str, int, str]) -> ArtifactReceipt:
        if _type(raw) is not _bytes:
            raise TypeError(f"{spec[0]} must be exact bytes")
        artifact_id, size, expected_digest = spec
        if _len(raw) != size:
            raise ValueError(f"{artifact_id} size mismatch")
        if _sha256(raw).hexdigest() != expected_digest:
            raise ValueError(f"{artifact_id} SHA-256 mismatch")
        receipt = _artifact_type(artifact_id, size, expected_digest)
        _setattr(receipt, "verified_by_inspector", True)
        return receipt

    def parse_elf(
        raw: bytes,
        expected_entry: int,
        expected_loads: Tuple[Tuple[int, int, int, int, int, int], ...],
    ) -> Tuple[int, int, Tuple[ElfLoadSegment, ...]]:
        if raw[:16] != b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8:
            raise ValueError("binary is not exact ELF32 little-endian System V")
        header = _unpack_from("<HHIIIIIHHHHHH", raw, 16)
        (
            elf_type,
            machine,
            version,
            entry,
            program_offset,
            _,
            _,
            header_size,
            program_entry_size,
            program_count,
            _,
            _,
            _,
        ) = header
        if (
            elf_type != 2
            or machine != 40
            or version != 1
            or entry != expected_entry
            or header_size != 52
            or program_entry_size != 32
        ):
            raise ValueError("ELF identity mismatch")
        if program_offset + program_count * program_entry_size > _len(raw):
            raise ValueError("ELF program headers out of bounds")
        loads = []
        for index in _range(program_count):
            item = _unpack_from("<IIIIIIII", raw, program_offset + index * 32)
            if item[0] != 1:
                continue
            _, file_offset, va, _, file_size, memory_size, flags, alignment = item
            loads.append((file_offset, va, file_size, memory_size, flags, alignment))
        if _tuple(loads) != expected_loads:
            raise ValueError("ELF PT_LOAD geometry mismatch")
        if _any(offset + size > _len(raw) for offset, _, size, _, _, _ in loads):
            raise ValueError("ELF PT_LOAD extends beyond artifact")
        return machine, entry, _tuple(_segment_type(*item) for item in loads)

    def require_window(raw: bytes, offset: int, expected: bytes, label: str) -> None:
        if offset < 0 or offset + _len(expected) > _len(raw):
            raise ValueError(f"{label} out of bounds")
        if raw[offset : offset + _len(expected)] != expected:
            raise ValueError(f"{label} mismatch")

    def make_functions(
        raw: bytes,
        specs: Tuple[Tuple[str, int, int, int, str], ...],
        loads: Tuple[Tuple[int, int, int, int, int, int], ...],
    ) -> Tuple[FunctionReceipt, ...]:
        result = []
        for name, va, offset, size, expected_digest in specs:
            if offset < 0 or offset + size > _len(raw):
                raise ValueError(f"{name} window out of bounds")
            mapped = False
            for load_offset, load_va, file_size, _, _, _ in loads:
                if load_offset <= offset and offset + size <= load_offset + file_size:
                    if load_va + offset - load_offset != va:
                        raise ValueError(f"{name} VA/file mapping mismatch")
                    mapped = True
                    break
            if not mapped:
                raise ValueError(f"{name} is outside PT_LOAD")
            digest = _sha256(raw[offset : offset + size]).hexdigest()
            if digest != expected_digest:
                raise ValueError(f"{name} window SHA-256 mismatch")
            result.append(_function_type(name, va, offset, size, expected_digest))
        return _tuple(result)

    def validate_hwscan(raw: bytes) -> BinaryRouteReceipt:
        machine, entry, segments = parse_elf(raw, 0x11EB8, hwscan_loads)
        functions = make_functions(raw, hwscan_functions, hwscan_loads)
        mapper = functions[4]
        require_window(raw, 0x10FE2C, hwscan_mapper_window, "hwscan mapper")
        require_window(raw, 0x443330, hwscan_mapper_table, "hwscan route table")
        require_window(raw, 0x443320, hwscan_route_tables, "hwscan route tables")
        require_window(raw, 0x445688, hwscan_vtable_window, "hwscan AML vtable")
        require_window(
            raw, 0x42304C, hwscan_platform_literals, "hwscan platform literals"
        )
        require_window(
            raw, 0x4432EC, hwscan_platform_enum_table, "hwscan platform enum table"
        )
        require_window(raw, 0x4275EA, hwscan_uart_rodata, "hwscan AML UART rodata")
        require_window(raw, 0x4275BC, hwscan_plug_table, "hwscan plug table")
        require_window(raw, 0x4275C8, hwscan_reset_table, "hwscan reset table")
        require_window(raw, 0x427634, hwscan_psu_source, "hwscan PSU source")
        require_window(raw, 0x4265BA, hwscan_psu_label, "hwscan PSU label")
        if _unpack_from("<I", raw, 0x445688)[0] != 0x11FE2C:
            raise ValueError("hwscan AML vtable mapper pointer mismatch")
        expected_pointers = (0x4375FD, 0x437608, 0x437613)
        if _unpack_from("<3I", raw, 0x443330) != expected_pointers:
            raise ValueError("hwscan AML route pointers mismatch")
        receipt = _binary_route_type(
            artifact_id=artifact_specs[0][0],
            elf_machine=machine,
            elf_entry=entry,
            load_segments=segments,
            mapper=mapper,
            mapper_table_virtual_address=0x463330,
            mapper_table_file_offset=0x443330,
            mapper_table_sha256=_sha256(hwscan_mapper_table).hexdigest(),
            vtable_mapper_pointer_virtual_address=0x465688,
            vtable_mapper_pointer_file_offset=0x445688,
            vtable_window_sha256=_sha256(hwscan_vtable_window).hexdigest(),
            chain_devices=route_devices,
            functions=functions,
        )
        _setattr(receipt, "route_verified", True)
        return receipt

    def validate_cgminer(raw: bytes) -> BinaryRouteReceipt:
        machine, entry, segments = parse_elf(raw, 0x1012C, cgminer_loads)
        functions = make_functions(raw, cgminer_functions, cgminer_loads)
        mapper = functions[0]
        require_window(raw, 0x0FAFB4, cgminer_mapper_window, "cgminer mapper")
        require_window(raw, 0x55475C, cgminer_mapper_table, "cgminer route table")
        require_window(raw, 0x5579D8, cgminer_vtable_window, "cgminer AML vtable")
        if _unpack_from("<I", raw, 0x5579D8)[0] != 0x10AFB4:
            raise ValueError("cgminer AML vtable mapper pointer mismatch")
        expected_pointers = (0x586EA8, 0x586EB3, 0x586EBE)
        if _unpack_from("<3I", raw, 0x55475C) != expected_pointers:
            raise ValueError("cgminer AML route pointers mismatch")
        decoded = []
        for offset, key, ciphertext, cleartext in cgminer_encrypted_uarts:
            require_window(raw, offset, ciphertext, "cgminer encrypted UART")
            decoded.append(_bytes(value ^ key for value in ciphertext).decode("ascii"))
            if decoded[-1] != cleartext:
                raise ValueError("cgminer UART decode mismatch")
        if _tuple(decoded) != route_devices:
            raise ValueError("cgminer production route mismatch")
        receipt = _binary_route_type(
            artifact_id=artifact_specs[1][0],
            elf_machine=machine,
            elf_entry=entry,
            load_segments=segments,
            mapper=mapper,
            mapper_table_virtual_address=0x57475C,
            mapper_table_file_offset=0x55475C,
            mapper_table_sha256=_sha256(cgminer_mapper_table).hexdigest(),
            vtable_mapper_pointer_virtual_address=0x5779D8,
            vtable_mapper_pointer_file_offset=0x5579D8,
            vtable_window_sha256=_sha256(cgminer_vtable_window).hexdigest(),
            chain_devices=route_devices,
            functions=functions,
        )
        _setattr(receipt, "route_verified", True)
        return receipt

    def validate_fw_info(raw: bytes) -> Tuple[str, str, str, str, str, str]:
        value = _json_loads(raw.decode("ascii"))
        if not _isinstance(value, _dict):
            raise ValueError("fw-info must be an object")
        expected = {
            "fw_name": "Vnish",
            "fw_version": "1.2.7",
            "platform": "aml",
            "install_type": "nand",
            "build_time": "2025-12-22 20:18:59",
            "build_name": "vnishfirmwarecom",
            "build_uuid": "2a02479b-05f3-4cc6-80bc-97633db194a8",
            "miner": "Antminer S21 XP",
            "model": "s21xp",
        }
        if value != expected:
            raise ValueError("fw-info identity mismatch")
        return (
            value["fw_name"],
            value["fw_version"],
            value["miner"],
            value["model"],
            value["platform"],
            value["install_type"],
        )

    def validate_scripts(s12hwscan: bytes, s11board: bytes) -> None:
        s12 = s12hwscan.decode("ascii")
        required_s12 = (
            "MINER_MODEL=$(fwinfo model)",
            "MINER_PLATFORM=$(fwinfo platform)",
            'HWSCAN_ARGS="--platform $MINER_PLATFORM --gen-model-info $MINER_MODEL --gen-def-conf $MINER_MODEL"',
            "if hwscan $HWSCAN_ARGS; then",
        )
        if _any(line not in s12 for line in required_s12):
            raise ValueError("S12hwscan production association mismatch")
        s11 = s11board.decode("ascii")
        required_s11 = (
            "# pwr_en 437",
            "echo 1 > /sys/class/gpio/gpio437/value",
            "# ch0_plug 439",
            "# ch1_plug 440",
            "# ch2_plug 441",
            "# ch0_rst 454",
            "# ch1_rst 455",
            "# ch2_rst 456",
        )
        if _any(line not in s11 for line in required_s11):
            raise ValueError("S11board production GPIO association mismatch")

    def inspect_s21xp_production_route(
        *,
        hwscan: bytes,
        cgminer: bytes,
        fw_info: bytes,
        s12hwscan: bytes,
        s11board: bytes,
    ) -> S21XpProductionRouteInspection:
        """Admit the exact held package evidence and return observations only."""

        raw_artifacts = (hwscan, cgminer, fw_info, s12hwscan, s11board)
        if _len(raw_artifacts) != _len(artifact_specs):
            raise ValueError("internal artifact census mismatch")
        artifacts = _tuple(
            validate_artifact(raw, spec)
            for raw, spec in _zip(raw_artifacts, artifact_specs)
        )
        firmware = validate_fw_info(fw_info)
        validate_scripts(s12hwscan, s11board)
        hwscan_route = validate_hwscan(hwscan)
        cgminer_route = validate_cgminer(cgminer)
        if hwscan_route.chain_devices != cgminer_route.chain_devices:
            raise ValueError("independent production route implementations disagree")
        chains = _tuple(
            _chain_type(index, device, 439 + index, 454 + index, True)
            for index, device in _enumerate(route_devices)
        )
        psu = _psu_type(
            scope="board-global observation only",
            power_enable_gpio=437,
            software_i2c_gpios=(477, 476),
            interface_label="i2c:psu-bus",
            psu_family_identified=False,
            protocol_identified=False,
            safe_energization_order_verified=False,
        )
        inspection = _inspection_type(
            artifacts=artifacts,
            firmware_name=firmware[0],
            firmware_version=firmware[1],
            miner=firmware[2],
            model=firmware[3],
            platform=firmware[4],
            install_type=firmware[5],
            hwscan_command=hwscan_command,
            hwscan_route=hwscan_route,
            cgminer_route=cgminer_route,
            chains=chains,
            psu=psu,
            production_route_kind="AML direct UART; not factory FPGA transport",
            factory_fpga_route_is_distinct=True,
            pic_runtime_identity_verified=False,
            unresolved=unresolved,
        )
        _setattr(inspection, "production_association_verified", True)
        _setattr(inspection, "inspection_verified", True)
        return inspection

    return inspect_s21xp_production_route


inspect_s21xp_production_route = _build_inspector()
del _build_inspector
