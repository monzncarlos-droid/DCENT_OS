"""Pure, non-authorizing inspection of held S21 XP air topology evidence.

The inspector accepts caller-supplied bytes only.  It never opens a path or a
device and it deliberately does not construct a runnable platform mapping.
Exact artifact hashes and internal structure checks prevent observations from
being projected onto a different firmware build or miner variant.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Dict, Final, Mapping, Tuple


_ARTIFACT_SPECS: Final[Tuple[Tuple[str, int, str], ...]] = (
    (
        "bosminer-model-list",
        16_854,
        "c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0",
    ),
    (
        "bosminer-unpacked",
        23_963_080,
        "5a49dcbe2e2d9f4fb047eca856e71440bd73fc020a817e808b5af3b45a7c8707",
    ),
    (
        "vnish-s21xp-air-devicetree",
        20_945,
        "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
    ),
    (
        "vnish-s21xp-air-s11board",
        2_928,
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    ),
    (
        "bitmain-s21xp-single-board-test",
        4_073_320,
        "4b4e08d1f206836749b71b2a01822a66127fbf7d9904d0ba91427e28fd4f3f61",
    ),
    (
        "epic-v1.22.0-hashboard-topology",
        72_339,
        "fec8360ac48ae46938c41037daf93907ac556b84432e07111a237b6bd9b5cbfa",
    ),
)

_BOSMINER_AML_WINDOW: Final[bytes] = bytes.fromhex(
    "ffc301d1fe4f06a9090400d13f0d00f1820200546a008052eb030091e0830091"
    "4901094baa8f00b04a6147f9e90300b9698700b029e11391eb2b05a92a008052"
    "e92b02a9e9430191eaff03a9e91b00f9c3d92794fe4f46a9ffc30191c0035fd6"
)
_BOSMINER_AML_ANALYSIS_ADDRESS: Final[int] = 0x8DAE30
_BOSMINER_AML_WINDOW_OFFSET: Final[int] = 0x4DAE30
_BOSMINER_TTYS_OFFSET: Final[int] = 0xF22E78
_BOSMINER_INDEX_ERROR_OFFSET: Final[int] = 0xF22E81
_BOSMINER_AML_SOURCE_OFFSET: Final[int] = 0xF22DB6

_JIG_WINDOWS: Final[Tuple[Tuple[str, int, int, int, bytes], ...]] = (
    (
        "fpga_init.part.0",
        0xCD1A9,
        350,
        0xBD1A8,
        bytes.fromhex(
            "49f2bc1070b50221adf6080dc0f2200044f2045549f714e80028c0f20b252860"
            "39db002401238de81100032220464ff4905149f72ce80646686000285dd049f2"
        ),
    ),
    (
        "read_uart_data_in_fpga",
        0xCE43D,
        360,
        0xBE43C,
        bytes.fromhex(
            "2de9f0470023adf5016d04468946174603930d2872d8dfe800f0545707333639"
            "3c3f4245484b4e5165256420c7f3090141f00041fef7c6ff5fea970a5cd04fea"
        ),
    ),
    (
        "chain_reset_low",
        0xD1BB1,
        42,
        0xC1BB0,
        bytes.fromhex(
            "10b582b002a9002304460d2041f8043dfbf7f0fb019a0123a3400d2013431946"
            "0193fbf715fc02b010bd00bf10b582b002a9002304460d2041f8043dfbf7dafb"
        ),
    ),
)

_SERIAL_ALIASES: Final[Tuple[Tuple[str, str], ...]] = (
    ("serial0", "/soc/aobus@ff800000/serial@3000"),
    ("serial1", "/serial@ffd24000"),
    ("serial2", "/serial@ffd23000"),
    ("serial3", "/soc/aobus@ff800000/serial@4000"),
)

_CONTROL_BOARDS: Final[Tuple[str, ...]] = (
    "zynq-bm3-am2",
    "am3-bbb",
    "am3-aml",
    "cvitek-bm1-am2",
    "stm32mp157c-ii1-am2",
)


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    size: int
    sha256: str
    caller_supplied: bool = True
    verified_by_inspector: bool = field(default=False, init=False)


@dataclass(frozen=True)
class S21XpAirAuthority:
    runtime_construction: bool = field(default=False, init=False)
    device_open: bool = field(default=False, init=False)
    uart_transmit: bool = field(default=False, init=False)
    uart_receive: bool = field(default=False, init=False)
    gpio_read: bool = field(default=False, init=False)
    gpio_write: bool = field(default=False, init=False)
    reset_control: bool = field(default=False, init=False)
    hotplug_read: bool = field(default=False, init=False)
    fan_control: bool = field(default=False, init=False)
    thermal_control: bool = field(default=False, init=False)
    pic_access: bool = field(default=False, init=False)
    psu_control: bool = field(default=False, init=False)
    sensor_access: bool = field(default=False, init=False)
    power_enable: bool = field(default=False, init=False)
    mining_start: bool = field(default=False, init=False)
    firmware_install: bool = field(default=False, init=False)
    factory_execution: bool = field(default=False, init=False)
    live_validation: bool = field(default=False, init=False)
    route_activation: bool = field(default=False, init=False)


@dataclass(frozen=True)
class DirectUartLane:
    bosminer_hashchain_index: int
    device: str


@dataclass(frozen=True)
class DtbUartNode:
    alias: str
    path: str
    status: str


@dataclass(frozen=True)
class GpioLane:
    script_chain_index: int
    plug_gpio: int
    reset_gpio: int


@dataclass(frozen=True)
class FactoryFpgaLane:
    fpga_uart_index: int
    read_control_register: int
    read_data_register: int
    reset_register: int
    reset_bit: int


@dataclass(frozen=True)
class FunctionReceipt:
    name: str
    symbol_value: int
    symbol_size: int
    analysis_address: int
    window_file_offset: int
    window_sha256: str


@dataclass(frozen=True)
class ElfLoadReceipt:
    machine: int
    segment_file_offset: int
    segment_virtual_address: int
    segment_file_size: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class StrippedFunctionReceipt:
    name: str
    analysis_address: int
    window_file_offset: int
    window_sha256: str


@dataclass(frozen=True)
class HashboardReceipt:
    sku: str
    asic: str
    chains_per_unit: int
    chips_per_chain: int
    domains_per_chain: int
    chips_per_domain: int
    eeprom_device: str
    eeprom_address: int
    vendor_declared_pic: str
    vendor_declared_pic_address: int
    board_sensor_addresses: Tuple[int, ...]
    switched_sensor_address_and_indices: Tuple[Tuple[int, int], ...]


@dataclass(frozen=True)
class S21XpAirEvidenceInspection:
    artifacts: Tuple[ArtifactReceipt, ...]
    model_row_duplicate_count: int
    bosminer_control_boards: Tuple[str, ...]
    bosminer_elf_load: ElfLoadReceipt
    bosminer_aml_function: StrippedFunctionReceipt
    direct_uart_lanes: Tuple[DirectUartLane, ...]
    dtb_uart_nodes: Tuple[DtbUartNode, ...]
    gpio_lanes: Tuple[GpioLane, ...]
    power_enable_gpio: int
    fan_tach_gpios: Tuple[int, ...]
    fan_pwm_channels: Tuple[int, ...]
    fan_pwm_period_and_initial_duty: Tuple[int, int]
    factory_fpga_lanes: Tuple[FactoryFpgaLane, ...]
    factory_jig_elf_load: ElfLoadReceipt
    function_receipts: Tuple[FunctionReceipt, ...]
    hashboard: HashboardReceipt
    three_safe_runtime_actors_proved: bool
    runtime_route_conflict: str
    unresolved: Tuple[str, ...]
    authority: S21XpAirAuthority = field(default_factory=S21XpAirAuthority, init=False)
    inspection_verified: bool = field(default=False, init=False)


def _verified_receipt(
    artifact_id: str,
    raw: bytes,
    expected_sha256: str,
    _receipt_type=ArtifactReceipt,
    _setattr=object.__setattr__,
) -> ArtifactReceipt:
    receipt = _receipt_type(artifact_id, len(raw), expected_sha256)
    _setattr(receipt, "verified_by_inspector", True)
    return receipt


def _validate_artifact(
    raw: bytes,
    spec: Tuple[str, int, str],
    _sha256=hashlib.sha256,
    _make_receipt=_verified_receipt,
) -> ArtifactReceipt:
    if type(raw) is not bytes:
        raise TypeError(f"{spec[0]} must be exact bytes")
    artifact_id, expected_size, expected_sha256 = spec
    if len(raw) != expected_size:
        raise ValueError(f"{artifact_id} size mismatch")
    if _sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"{artifact_id} SHA-256 mismatch")
    return _make_receipt(artifact_id, raw, expected_sha256)


def _nul_text(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("ascii")


def _parse_fdt_properties(
    raw: bytes,
    _unpack_from=struct.unpack_from,
    _decode_nul=_nul_text,
) -> Tuple[Mapping[str, bytes], Mapping[str, str]]:
    if len(raw) < 40:
        raise ValueError("truncated FDT header")
    header = _unpack_from(">10I", raw, 0)
    (
        magic,
        total_size,
        off_struct,
        off_strings,
        _,
        version,
        last_version,
        _,
        strings_size,
        struct_size,
    ) = header
    if magic != 0xD00DFEED or total_size != len(raw):
        raise ValueError("invalid FDT identity")
    if version < 17 or last_version > version:
        raise ValueError("unsupported FDT version")
    struct_end = off_struct + struct_size
    strings_end = off_strings + strings_size
    if struct_end > len(raw) or strings_end > len(raw):
        raise ValueError("FDT block out of bounds")

    aliases: Dict[str, bytes] = {}
    statuses: Dict[str, str] = {}
    stack = []
    cursor = off_struct
    saw_end = False
    while cursor + 4 <= struct_end:
        tag = _unpack_from(">I", raw, cursor)[0]
        cursor += 4
        if tag == 1:
            end = raw.find(b"\x00", cursor, struct_end)
            if end < 0:
                raise ValueError("unterminated FDT node")
            stack.append(raw[cursor:end].decode("ascii"))
            cursor = (end + 4) & ~3
        elif tag == 2:
            if not stack:
                raise ValueError("unbalanced FDT node")
            stack.pop()
        elif tag == 3:
            if cursor + 8 > struct_end:
                raise ValueError("truncated FDT property")
            length, name_offset = _unpack_from(">II", raw, cursor)
            cursor += 8
            value_end = cursor + length
            if value_end > struct_end or name_offset >= strings_size:
                raise ValueError("FDT property out of bounds")
            name_start = off_strings + name_offset
            name_end = raw.find(b"\x00", name_start, strings_end)
            if name_end < 0:
                raise ValueError("unterminated FDT property name")
            name = raw[name_start:name_end].decode("ascii")
            value = raw[cursor:value_end]
            cursor = (value_end + 3) & ~3
            path = "/" + "/".join(part for part in stack if part)
            if path == "/aliases" and name.startswith("serial"):
                aliases[name] = value
            if name == "status":
                statuses[path] = _decode_nul(value)
        elif tag == 4:
            continue
        elif tag == 9:
            saw_end = True
            break
        else:
            raise ValueError(f"unknown FDT tag {tag}")
    if not saw_end or stack:
        raise ValueError("incomplete FDT structure")
    return aliases, statuses


def _validate_model_list(
    raw: bytes,
    _loads=json.loads,
    _control_boards=_CONTROL_BOARDS,
) -> int:
    decoded = _loads(raw.decode("utf-8"))
    if not isinstance(decoded, list):
        raise ValueError("Bosminer model list is not a list")
    matches = [row for row in decoded if row.get("name") == "Antminer S21 XP"]
    if len(matches) != 2 or matches[0] != matches[1]:
        raise ValueError("S21 XP model rows are absent or ambiguous")
    row = matches[0]
    if tuple(row.get("control_boards", ())) != _control_boards:
        raise ValueError("S21 XP control-board roster mismatch")
    if row.get("hashboards") != ["A3HB70501"]:
        raise ValueError("S21 XP hashboard roster mismatch")
    if row.get("chips_layout") != {
        "name": "BM1370",
        "num_domains": 13,
        "num_per_hb": 91,
        "num_per_domain": 7,
    }:
        raise ValueError("S21 XP chip layout mismatch")
    return len(matches)


def _validate_bosminer_elf(
    raw: bytes,
    analysis_address: int,
    expected_file_offset: int,
    _unpack_from=struct.unpack_from,
    _load_type=ElfLoadReceipt,
) -> ElfLoadReceipt:
    if raw[:16] != b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8:
        raise ValueError("Bosminer is not exact ELF64 little-endian System V")
    (
        elf_type,
        machine,
        version,
        _,
        program_offset,
        _,
        _,
        elf_header_size,
        program_entry_size,
        program_count,
        _,
        _,
        _,
    ) = _unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if (
        elf_type != 2
        or machine != 183
        or version != 1
        or elf_header_size != 64
        or program_entry_size != 56
    ):
        raise ValueError("Bosminer ELF header mismatch")
    if program_offset + program_count * program_entry_size > len(raw):
        raise ValueError("Bosminer program headers out of bounds")
    load_segments = []
    for index in range(program_count):
        item = _unpack_from("<IIQQQQQQ", raw, program_offset + index * 56)
        if item[0] == 1:
            load_segments.append(item)
    if not load_segments:
        raise ValueError("Bosminer has no PT_LOAD")
    first = load_segments[0]
    _, flags, file_offset, virtual_address, _, file_size, _, alignment = first
    if (file_offset, virtual_address, file_size, flags, alignment) != (
        0,
        0x400000,
        0x1375388,
        5,
        0x10000,
    ):
        raise ValueError("Bosminer executable PT_LOAD mapping mismatch")
    if analysis_address - virtual_address + file_offset != expected_file_offset:
        raise ValueError("Bosminer AML VA/file mapping mismatch")
    return _load_type(
        machine, file_offset, virtual_address, file_size, flags, alignment
    )


def _validate_bosminer(
    raw: bytes,
    _window=_BOSMINER_AML_WINDOW,
    _analysis_address=_BOSMINER_AML_ANALYSIS_ADDRESS,
    _window_offset=_BOSMINER_AML_WINDOW_OFFSET,
    _ttys_offset=_BOSMINER_TTYS_OFFSET,
    _index_error_offset=_BOSMINER_INDEX_ERROR_OFFSET,
    _source_offset=_BOSMINER_AML_SOURCE_OFFSET,
    _validate_elf=_validate_bosminer_elf,
    _sha256=hashlib.sha256,
    _lane_type=DirectUartLane,
    _function_type=StrippedFunctionReceipt,
) -> Tuple[Tuple[DirectUartLane, ...], ElfLoadReceipt, StrippedFunctionReceipt]:
    load_receipt = _validate_elf(raw, _analysis_address, _window_offset)
    offset = _window_offset
    if raw[offset : offset + len(_window)] != _window:
        raise ValueError("Bosminer AML route function window mismatch")
    if raw[_ttys_offset : _ttys_offset + 9] != b"/dev/ttyS":
        raise ValueError("Bosminer AML tty prefix mismatch")
    error = b"BUG: hashchain_index out of range:"
    if raw[_index_error_offset : _index_error_offset + len(error)] != error:
        raise ValueError("Bosminer AML index guard string mismatch")
    source = b"open/bosminer/bosminer-am2-s17/src/hardware/antminer/controlboard/aml.rs"
    if raw[_source_offset : _source_offset + len(source)] != source:
        raise ValueError("Bosminer AML source association mismatch")
    lanes = tuple(_lane_type(index, f"/dev/ttyS{4 - index}") for index in range(1, 4))
    function = _function_type(
        "bosminer am3-aml hashchain tty formatter",
        _analysis_address,
        _window_offset,
        _sha256(_window).hexdigest(),
    )
    return lanes, load_receipt, function


def _validate_dtb(
    raw: bytes,
    _parse=_parse_fdt_properties,
    _serial_aliases=_SERIAL_ALIASES,
    _decode_nul=_nul_text,
    _node_type=DtbUartNode,
) -> Tuple[DtbUartNode, ...]:
    aliases, statuses = _parse(raw)
    nodes = []
    if set(aliases) != {alias for alias, _ in _serial_aliases}:
        raise ValueError("DTB serial alias set mismatch")
    for alias, path in _serial_aliases:
        if _decode_nul(aliases[alias]) != path:
            raise ValueError(f"DTB {alias} target mismatch")
        if statuses.get(path) != "okay":
            raise ValueError(f"DTB {alias} is not enabled")
        nodes.append(_node_type(alias, path, "okay"))
    return tuple(nodes)


def _require_script_lines(raw: bytes) -> None:
    text = raw.decode("ascii")
    required = (
        "# pwr_en 437",
        "echo 1 > /sys/class/gpio/gpio437/value",
        "# ch0_plug 439",
        "# ch1_plug 440",
        "# ch2_plug 441",
        "# ch0_rst 454",
        "# ch1_rst 455",
        "# ch2_rst 456",
        "# fan_front_speed0 447",
        "# fan_front_speed1 448",
        "# fan_rear_speed0 449",
        "# fan_rear_speed1 450",
        "echo 100000 > /sys/class/pwm/pwmchip0/pwm0/period",
        "echo 100000 > /sys/class/pwm/pwmchip0/pwm0/duty_cycle",
        "echo 100000 > /sys/class/pwm/pwmchip0/pwm1/period",
        "echo 100000 > /sys/class/pwm/pwmchip0/pwm1/duty_cycle",
    )
    if any(line not in text for line in required):
        raise ValueError("VNish S11board topology line missing")


def _validate_jig_elf(
    raw: bytes,
    expected_symbols: Tuple[Tuple[str, int, int, int, bytes], ...],
    _unpack_from=struct.unpack_from,
    _load_type=ElfLoadReceipt,
) -> ElfLoadReceipt:
    if raw[:16] != b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8:
        raise ValueError("Bitmain jig is not exact ELF32 little-endian System V")
    (
        elf_type,
        machine,
        version,
        _,
        program_offset,
        section_offset,
        _,
        elf_header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        _,
    ) = _unpack_from("<HHIIIIIHHHHHH", raw, 16)
    if (
        elf_type != 2
        or machine != 40
        or version != 1
        or elf_header_size != 52
        or program_entry_size != 32
        or section_entry_size != 40
    ):
        raise ValueError("Bitmain jig ELF header mismatch")
    if program_offset + program_count * program_entry_size > len(raw):
        raise ValueError("Bitmain jig program headers out of bounds")
    if section_offset + section_count * section_entry_size > len(raw):
        raise ValueError("Bitmain jig section headers out of bounds")

    load_segments = []
    for index in range(program_count):
        item = _unpack_from("<IIIIIIII", raw, program_offset + index * 32)
        if item[0] == 1:
            load_segments.append(item)
    if not load_segments:
        raise ValueError("Bitmain jig has no PT_LOAD")
    first = load_segments[0]
    _, file_offset, virtual_address, _, file_size, _, flags, alignment = first
    if (file_offset, virtual_address, file_size, flags, alignment) != (
        0,
        0x10000,
        0x2470CC,
        5,
        0x10000,
    ):
        raise ValueError("Bitmain jig executable PT_LOAD mapping mismatch")

    section_headers = tuple(
        _unpack_from("<IIIIIIIIII", raw, section_offset + index * 40)
        for index in range(section_count)
    )
    symbols = {}
    for section in section_headers:
        _, section_type, _, _, sym_offset, sym_size, link, _, _, entry_size = section
        if section_type != 2:
            continue
        if entry_size != 16 or link >= section_count:
            raise ValueError("Bitmain jig symbol table layout mismatch")
        string_section = section_headers[link]
        strings_offset, strings_size = string_section[4], string_section[5]
        if sym_offset + sym_size > len(raw) or strings_offset + strings_size > len(raw):
            raise ValueError("Bitmain jig symbol table out of bounds")
        strings_end = strings_offset + strings_size
        for cursor in range(sym_offset, sym_offset + sym_size, entry_size):
            name_offset, value, size, info, _, section_index = _unpack_from(
                "<IIIBBH", raw, cursor
            )
            if name_offset >= strings_size:
                raise ValueError("Bitmain jig symbol name out of bounds")
            name_start = strings_offset + name_offset
            name_end = raw.find(b"\x00", name_start, strings_end)
            if name_end < 0:
                raise ValueError("unterminated Bitmain jig symbol")
            name = raw[name_start:name_end].decode("ascii")
            if name:
                symbols[name] = (value, size, info, section_index)

    for name, symbol_value, symbol_size, expected_file_offset, _ in expected_symbols:
        observed = symbols.get(name)
        if observed is None or observed[:2] != (symbol_value, symbol_size):
            raise ValueError(f"Bitmain jig {name} symbol mismatch")
        if observed[2] & 0x0F != 2 or observed[3] == 0:
            raise ValueError(f"Bitmain jig {name} is not a defined function")
        analysis_address = symbol_value & ~1
        mapped_offset = analysis_address - virtual_address + file_offset
        if mapped_offset != expected_file_offset:
            raise ValueError(f"Bitmain jig {name} VA/file mapping mismatch")

    return _load_type(
        machine, file_offset, virtual_address, file_size, flags, alignment
    )


def _validate_jig(
    raw: bytes,
    _windows=_JIG_WINDOWS,
    _validate_elf=_validate_jig_elf,
    _sha256=hashlib.sha256,
    _function_type=FunctionReceipt,
    _lane_type=FactoryFpgaLane,
) -> Tuple[Tuple[FactoryFpgaLane, ...], Tuple[FunctionReceipt, ...], ElfLoadReceipt]:
    if raw[0x1F91BC : 0x1F91BC + 18] != b"/dev/axi_fpga_dev\x00":
        raise ValueError("Bitmain jig FPGA device anchor mismatch")
    if raw[0x1F9228 : 0x1F9228 + 14] != b"/dev/fpga_mem\x00":
        raise ValueError("Bitmain jig FPGA memory anchor mismatch")
    load_receipt = _validate_elf(raw, _windows)
    functions = []
    for name, symbol_value, symbol_size, file_offset, window in _windows:
        if raw[file_offset : file_offset + len(window)] != window:
            raise ValueError(f"Bitmain jig {name} window mismatch")
        functions.append(
            _function_type(
                name,
                symbol_value,
                symbol_size,
                symbol_value & ~1,
                file_offset,
                _sha256(window).hexdigest(),
            )
        )
    lanes = []
    for index in range(14):
        control = 96 + index * 2 if index < 10 else 124 + (index - 10) * 2
        lanes.append(_lane_type(index, control, control + 1, 13, index))
    return tuple(lanes), tuple(functions), load_receipt


def _validate_epic_topology(
    raw: bytes,
    _loads=json.loads,
    _receipt_type=HashboardReceipt,
) -> HashboardReceipt:
    decoded = _loads(raw.decode("utf-8"))
    if decoded.get("schema") != "dcent-hashboard-topology-v1":
        raise ValueError("ePIC topology schema mismatch")
    rows = [row for row in decoded.get("boards", ()) if row.get("sku") == "A3HB70501"]
    if len(rows) != 1:
        raise ValueError("A3HB70501 topology row absent or ambiguous")
    row = rows[0]
    chip, chain = row["chip"], row["chain"]
    eeprom, pic = row["eeprom"], row["vendor_declared_pic"]
    if (
        chip["name"] != "BM1370"
        or chain["chains_per_unit"] != 3
        or chain["chips_per_chain"] != 91
        or chain["domains_per_chain"] != 13
        or chain["chips_per_domain"] != 7
    ):
        raise ValueError("A3HB70501 geometry mismatch")
    board_sensor_addresses = tuple(item["i2c_addr"] for item in row["board_sensors"])
    switched = tuple(
        (item["i2c_addr"], item["index"]) for item in row["switch_sensors"]
    )
    if board_sensor_addresses != (72, 73, 74, 75):
        raise ValueError("A3HB70501 board-sensor map mismatch")
    if switched != ((76, 3), (76, 2), (76, 0), (76, 1)):
        raise ValueError("A3HB70501 switched-sensor map mismatch")
    return _receipt_type(
        "A3HB70501",
        chip["name"],
        chain["chains_per_unit"],
        chain["chips_per_chain"],
        chain["domains_per_chain"],
        chain["chips_per_domain"],
        eeprom["device"],
        eeprom["i2c_addr"],
        pic["device"],
        pic["i2c_addr"],
        board_sensor_addresses,
        switched,
    )


def _build_inspector(
    _specs=_ARTIFACT_SPECS,
    _control_boards=_CONTROL_BOARDS,
    _validate_artifact_fn=_validate_artifact,
    _validate_model_fn=_validate_model_list,
    _validate_bosminer_fn=_validate_bosminer,
    _validate_dtb_fn=_validate_dtb,
    _validate_script_fn=_require_script_lines,
    _validate_jig_fn=_validate_jig,
    _validate_epic_fn=_validate_epic_topology,
    _gpio_type=GpioLane,
    _inspection_type=S21XpAirEvidenceInspection,
    _setattr=object.__setattr__,
):
    specs = tuple(tuple(item) for item in _specs)
    control_boards = tuple(_control_boards)
    gpio_specs = tuple((index, 439 + index, 454 + index) for index in range(3))
    fan_tach_gpios = (447, 448, 449, 450)
    fan_pwm_channels = (0, 1)
    fan_pwm_values = (100_000, 100_000)
    runtime_route_conflict = (
        "held Bosminer am3-aml maps hashchain 1/2/3 to ttyS3/ttyS2/ttyS1; "
        "current DCENT shared S21 descriptor selects ttyS1/ttyS2/ttyS4"
    )
    unresolved = (
        "logical DCENT chain numbering versus Bosminer one-based physical indices",
        "the fourth enabled DTB UART's non-chain role",
        "controller-specific routes for zynq-bm3-am2, am3-bbb, cvitek-bm1-am2, and stm32mp157c-ii1-am2",
        "PIC1704 declaration versus current no-PIC runtime assumption",
        "production PSU protocol and safe energization order",
        "factory FPGA carrier routes versus production Amlogic direct-UART routes",
    )

    def inspect_s21xp_air_evidence(
        *,
        bosminer_model_list: bytes,
        bosminer_unpacked: bytes,
        vnish_devicetree: bytes,
        vnish_s11board: bytes,
        bitmain_single_board_test: bytes,
        epic_hashboard_topology: bytes,
    ) -> S21XpAirEvidenceInspection:
        """Inspect the exact held bundle without granting hardware authority."""

        raw_artifacts = (
            bosminer_model_list,
            bosminer_unpacked,
            vnish_devicetree,
            vnish_s11board,
            bitmain_single_board_test,
            epic_hashboard_topology,
        )
        if len(specs) != len(raw_artifacts):
            raise ValueError("internal artifact census mismatch")
        receipts = tuple(
            _validate_artifact_fn(raw, spec) for raw, spec in zip(raw_artifacts, specs)
        )
        duplicate_count = _validate_model_fn(bosminer_model_list)
        direct_lanes, bosminer_load, bosminer_function = _validate_bosminer_fn(
            bosminer_unpacked
        )
        uart_nodes = _validate_dtb_fn(vnish_devicetree)
        _validate_script_fn(vnish_s11board)
        factory_lanes, functions, jig_load = _validate_jig_fn(bitmain_single_board_test)
        hashboard = _validate_epic_fn(epic_hashboard_topology)

        inspection = _inspection_type(
            artifacts=receipts,
            model_row_duplicate_count=duplicate_count,
            bosminer_control_boards=control_boards,
            bosminer_elf_load=bosminer_load,
            bosminer_aml_function=bosminer_function,
            direct_uart_lanes=direct_lanes,
            dtb_uart_nodes=uart_nodes,
            gpio_lanes=tuple(_gpio_type(*item) for item in gpio_specs),
            power_enable_gpio=437,
            fan_tach_gpios=fan_tach_gpios,
            fan_pwm_channels=fan_pwm_channels,
            fan_pwm_period_and_initial_duty=fan_pwm_values,
            factory_fpga_lanes=factory_lanes,
            factory_jig_elf_load=jig_load,
            function_receipts=functions,
            hashboard=hashboard,
            three_safe_runtime_actors_proved=False,
            runtime_route_conflict=runtime_route_conflict,
            unresolved=unresolved,
        )
        _setattr(inspection, "inspection_verified", True)
        return inspection

    return inspect_s21xp_air_evidence


inspect_s21xp_air_evidence = _build_inspector()
del _build_inspector
