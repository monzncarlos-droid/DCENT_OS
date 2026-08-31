"""Exact, bytes-only T21 Amlogic production-route evidence.

The inspector admits five exact files from the held VNish/Awesome 1.2.6 T21
Amlogic NAND root filesystem.  Two independent ARM32 executables map
zero-based chain indices 0/1/2 to ``/dev/ttyS3``, ``/dev/ttyS2``, and
``/dev/ttyS1``.  The admitted init scripts bind those binaries to
``model=t21``, ``platform=aml`` and record the three plug/reset GPIOs.

This is an observation contract only.  It does not open paths or devices,
construct a transport, select a PIC or PSU protocol, energize a rail, start
mining, install firmware, or authorize recovery.  The Cvitek ``uart_trans``
and Zynq/FPGA T21 routes remain separate controller variants.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Final, Tuple


_ARTIFACT_SPECS: Final[Tuple[Tuple[str, int, str], ...]] = (
    (
        "vnish-t21-1.2.6-hwscan",
        4_001_996,
        "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f",
    ),
    (
        "vnish-t21-1.2.6-cgminer",
        5_384_168,
        "da66295ab17273d7e6a8805958c9e47ee364e57a55c38528e801240a5e7c0735",
    ),
    (
        "vnish-t21-1.2.6-fw-info",
        265,
        "60638646b5fc4807498d10240bbce8461ca9f5aa7b343d25089217186474e7db",
    ),
    (
        "vnish-t21-1.2.6-s12hwscan",
        493,
        "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    ),
    (
        "vnish-t21-1.2.6-s11board",
        2_928,
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    ),
)

_HWSCAN_LOADS: Final[Tuple[Tuple[int, int, int, int, int, int], ...]] = (
    (0, 0x10000, 0x3BA668, 0x3BA668, 5, 0x10000),
    (0x3BABC8, 0x3DABC8, 0x16108, 0x26200, 6, 0x10000),
)
_CGMINER_LOADS: Final[Tuple[Tuple[int, int, int, int, int, int], ...]] = (
    (0, 0x10000, 0x4F0F44, 0x4F0F44, 5, 0x10000),
    (0x4F0F68, 0x510F68, 0x314B8, 0x7D0DC, 6, 0x10000),
)

# name, virtual address, file offset, size, SHA-256
_HWSCAN_FUNCTIONS: Final[Tuple[Tuple[str, int, int, int, str], ...]] = (
    (
        "platform parser (aml -> enum 2)",
        0x0D6AF0,
        0x0C6AF0,
        0x3E8,
        "4ca12487387d325e4af760f91193c4955e3141a3f68113e84fb8e2b43552a353",
    ),
    (
        "AML plug GPIO read",
        0x0FA9C4,
        0x0EA9C4,
        0x09C,
        "98fd3a6e7ad978cfc7b1f623a615984da97a97bdb31af41fcfc8690e1997bead",
    ),
    (
        "AML active-low reset GPIO write",
        0x0FAA74,
        0x0EAA74,
        0x074,
        "e148fed7938d569e6cc38165693e8d67a16bbaa7d0d6a720abd2d5a72f0c7f5e",
    ),
    (
        "AML chain UART mapper",
        0x0FACF8,
        0x0EACF8,
        0x028,
        "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac",
    ),
    (
        "AML PSU interface initialize",
        0x0FADC4,
        0x0EADC4,
        0x13C,
        "61e0237a53b8e234003e17ec4c5b82647ca87e516f9b42a8a68116d4a7ba86e7",
    ),
    (
        "AML GPIO437 write low",
        0x0FAF4C,
        0x0EAF4C,
        0x080,
        "89831303fc9f1265ec046a8826dc19f30539333d4a05f23aceb712eddb8b824a",
    ),
    (
        "AML GPIO437 write high",
        0x0FAFE0,
        0x0EAFE0,
        0x07C,
        "4e1499250ce992ec2f0c7d867e58c12dd1e663e2176fecf9a685b77cd3b073c2",
    ),
    (
        "AML PSU interface cleanup",
        0x0FB070,
        0x0EB070,
        0x048,
        "26b0991aa7e3ca6632c885a93d6efbc204fe845b958c40c5ac6bec990eb468ab",
    ),
)
_CGMINER_FUNCTIONS: Final[Tuple[Tuple[str, int, int, int, str], ...]] = (
    (
        "AML chain UART mapper",
        0x107E34,
        0x0F7E34,
        0x028,
        "2898396347770a76c65f6f32a55c804b776d360ab1443e2e9bf712b907e80af5",
    ),
)

_HWSCAN_PLATFORM_POINTERS = (0x3AF5CC, 0x3AF5C2, 0x3AF5BE, 0x3AF5C5, 0x3AF5C8)
_HWSCAN_PLATFORM_NAMES = ("xil", "bb", "aml", "cv", "stm")
_HWSCAN_ROUTE_POINTERS = (0x3B388D, 0x3B3898, 0x3B38A3)
_HWSCAN_ROUTE_TABLE_OFFSET = 0x3BC558
_HWSCAN_AML_VTABLE_OFFSET = 0x3BE6C0
_HWSCAN_PLUG_TABLE_OFFSET = 0x3A384C
_HWSCAN_RESET_TABLE_OFFSET = 0x3A3858
_HWSCAN_AML_SOURCE_OFFSET = 0x3A387A
_HWSCAN_PSU_SOURCE_OFFSET = 0x3A38C4
_HWSCAN_PSU_LABEL_OFFSET = 0x3A284A

_CGMINER_ROUTE_POINTERS = (0x5235EC, 0x5235F7, 0x523602)
_CGMINER_ROUTE_TABLE_OFFSET = 0x4F1450
_CGMINER_AML_VTABLE_OFFSET = 0x4F4238
_CGMINER_ENCRYPTED_UARTS = (
    (0x5035EC, 0xDA, bytes.fromhex("f5bebfacf5aeaea389e9"), "/dev/ttyS3"),
    (0x5035F7, 0x1A, bytes.fromhex("357e7f6c356e6e634928"), "/dev/ttyS2"),
    (0x503602, 0x70, bytes.fromhex("5f1415065f0404092341"), "/dev/ttyS1"),
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
    platform_enum: int
    mapper: FunctionReceipt
    mapper_table_virtual_address: int
    mapper_table_file_offset: int
    vtable_mapper_pointer_virtual_address: int
    vtable_mapper_pointer_file_offset: int
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
class BoardGpioObservation:
    recovery_input_gpio: int
    ip_report_input_gpio: int
    power_enable_gpio: int
    power_enable_startup_value: int
    plug_input_gpios: Tuple[int, int, int]
    plug_pull_down_requested: bool
    reset_output_gpios: Tuple[int, int, int]
    reset_active_low: bool
    green_led_output_gpio: int
    red_led_output_gpio: int
    script_has_errexit: bool
    setup_failures_are_fatal: bool
    output_readback_verified: bool
    stop_teardown_present: bool


@dataclass(frozen=True)
class FanObservation:
    front_tach_input_gpios: Tuple[int, int]
    rear_tach_input_gpios: Tuple[int, int]
    tach_edge: str
    pwm_chip: int
    rear_pwm_channel: int
    front_pwm_channel: int
    pwm_period_ns: int
    startup_duty_cycle_ns: int
    startup_enabled: bool
    tach_readback_verified: bool
    airflow_verified: bool
    setup_failures_are_fatal: bool


@dataclass(frozen=True)
class PsuObservation:
    scope: str
    power_enable_gpio: int
    startup_value: int
    software_i2c_gpios: Tuple[int, int]
    interface_label: str
    low_and_high_write_functions_observed: bool
    psu_family_identified: bool
    protocol_identified: bool
    safe_off_value_verified: bool
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
    recovery_execution: bool = field(default=False, init=False)
    live_validation: bool = field(default=False, init=False)


@dataclass(frozen=True)
class T21ProductionRouteInspection:
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
    board_io: BoardGpioObservation
    fans: FanObservation
    psu: PsuObservation
    production_route_kind: str
    cvitek_route_is_distinct: bool
    zynq_fpga_route_is_distinct: bool
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
    _hw_platform_ptrs=_HWSCAN_PLATFORM_POINTERS,
    _hw_platform_names=_HWSCAN_PLATFORM_NAMES,
    _hw_route_ptrs=_HWSCAN_ROUTE_POINTERS,
    _hw_route_offset=_HWSCAN_ROUTE_TABLE_OFFSET,
    _hw_vtable_offset=_HWSCAN_AML_VTABLE_OFFSET,
    _hw_plug_offset=_HWSCAN_PLUG_TABLE_OFFSET,
    _hw_reset_offset=_HWSCAN_RESET_TABLE_OFFSET,
    _hw_aml_source_offset=_HWSCAN_AML_SOURCE_OFFSET,
    _hw_psu_source_offset=_HWSCAN_PSU_SOURCE_OFFSET,
    _hw_psu_label_offset=_HWSCAN_PSU_LABEL_OFFSET,
    _cg_route_ptrs=_CGMINER_ROUTE_POINTERS,
    _cg_route_offset=_CGMINER_ROUTE_TABLE_OFFSET,
    _cg_vtable_offset=_CGMINER_AML_VTABLE_OFFSET,
    _cg_encrypted_uarts=_CGMINER_ENCRYPTED_UARTS,
    _artifact_type=ArtifactReceipt,
    _segment_type=ElfLoadSegment,
    _function_type=FunctionReceipt,
    _route_type=BinaryRouteReceipt,
    _chain_type=ProductionChainRoute,
    _board_gpio_type=BoardGpioObservation,
    _fan_type=FanObservation,
    _psu_type=PsuObservation,
    _inspection_type=T21ProductionRouteInspection,
    _sha256=hashlib.sha256,
    _unpack_from=struct.unpack_from,
    _setattr=object.__setattr__,
    _bytes=bytes,
    _tuple=tuple,
    _len=len,
    _type=type,
    _zip=zip,
    _enumerate=enumerate,
    _range=range,
    _any=any,
    _isinstance=isinstance,
):
    artifact_specs = _tuple(_tuple(item) for item in _artifact_specs)
    hwscan_loads = _tuple(_tuple(item) for item in _hwscan_loads)
    cgminer_loads = _tuple(_tuple(item) for item in _cgminer_loads)
    hwscan_functions = _tuple(_tuple(item) for item in _hwscan_functions)
    cgminer_functions = _tuple(_tuple(item) for item in _cgminer_functions)
    hw_platform_ptrs = _tuple(_hw_platform_ptrs)
    hw_platform_names = _tuple(_hw_platform_names)
    hw_route_ptrs = _tuple(_hw_route_ptrs)
    cg_route_ptrs = _tuple(_cg_route_ptrs)
    cg_encrypted_uarts = _tuple(
        (offset, key, _bytes(ciphertext), cleartext)
        for offset, key, ciphertext, cleartext in _cg_encrypted_uarts
    )
    route_devices = ("/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1")
    unresolved = (
        "PIC implementation, address, command effects, and T21 production selection are not proved",
        "PSU family, wire protocol, limits, retry behavior, safe-off value, and safe ordering remain unresolved",
        "no exact T21 EEPROM page or live miner-model/hw-info result is admitted",
        "controller revision, carrier electrical validation, cold initialization, and live chain enumeration remain pending",
        "Cvitek uart_trans and Zynq/FPGA are separate controller routes and are not interchangeable with this AML receipt",
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

    def parse_elf(raw: bytes, expected_entry: int, expected_loads):
        if raw[:16] != b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8:
            raise ValueError("binary is not exact ELF32 little-endian System V")
        header = _unpack_from("<HHIIIIIHHHHHH", raw, 16)
        elf_type, machine, version, entry = header[:4]
        program_offset, header_size = header[4], header[7]
        program_entry_size, program_count = header[8], header[9]
        if (
            elf_type != 2
            or machine != 40
            or version != 1
            or entry != expected_entry
            or header_size != 52
            or program_entry_size != 32
            or program_offset + program_count * program_entry_size > _len(raw)
        ):
            raise ValueError("ELF identity or program-header bounds mismatch")
        loads = []
        for index in _range(program_count):
            item = _unpack_from("<IIIIIIII", raw, program_offset + index * 32)
            if item[0] == 1:
                loads.append((item[1], item[2], item[4], item[5], item[6], item[7]))
        if _tuple(loads) != expected_loads:
            raise ValueError("ELF PT_LOAD geometry mismatch")
        if _any(offset + size > _len(raw) for offset, _, size, _, _, _ in loads):
            raise ValueError("ELF PT_LOAD extends beyond artifact")
        return machine, entry, _tuple(_segment_type(*item) for item in loads)

    def va_to_file(virtual_address: int, loads) -> int:
        for file_offset, load_va, file_size, _, _, _ in loads:
            if load_va <= virtual_address < load_va + file_size:
                return file_offset + virtual_address - load_va
        raise ValueError("virtual address is outside file-backed PT_LOAD ranges")

    def make_functions(raw: bytes, specs, loads):
        result = []
        for name, va, offset, size, expected_digest in specs:
            if offset < 0 or offset + size > _len(raw):
                raise ValueError(f"{name} window out of bounds")
            if va_to_file(va, loads) != offset:
                raise ValueError(f"{name} VA/file mapping mismatch")
            if _sha256(raw[offset : offset + size]).hexdigest() != expected_digest:
                raise ValueError(f"{name} window SHA-256 mismatch")
            result.append(_function_type(name, va, offset, size, expected_digest))
        return _tuple(result)

    def require(raw: bytes, offset: int, expected: bytes, label: str) -> None:
        if offset < 0 or offset + _len(expected) > _len(raw):
            raise ValueError(f"{label} out of bounds")
        if raw[offset : offset + _len(expected)] != expected:
            raise ValueError(f"{label} mismatch")

    def c_string(raw: bytes, offset: int) -> str:
        end = raw.find(b"\x00", offset, offset + 64)
        if end < 0:
            raise ValueError("bounded string terminator missing")
        return raw[offset:end].decode("ascii")

    def validate_hwscan(raw: bytes) -> BinaryRouteReceipt:
        machine, entry, segments = parse_elf(raw, 0x11EB8, hwscan_loads)
        functions = make_functions(raw, hwscan_functions, hwscan_loads)
        parser, plug, reset, mapper = functions[:4]
        if parser.name != "platform parser (aml -> enum 2)":
            raise ValueError("platform parser receipt mismatch")
        if _unpack_from("<5I", raw, 0x3BC514) != hw_platform_ptrs:
            raise ValueError("platform name pointer table mismatch")
        platform_names = _tuple(
            c_string(raw, va_to_file(pointer, hwscan_loads))
            for pointer in hw_platform_ptrs
        )
        if platform_names != hw_platform_names or platform_names[2] != "aml":
            raise ValueError("AML platform enum mapping mismatch")
        if _unpack_from("<3I", raw, _hw_route_offset) != hw_route_ptrs:
            raise ValueError("hwscan route pointer table mismatch")
        devices = _tuple(
            c_string(raw, va_to_file(pointer, hwscan_loads))
            for pointer in hw_route_ptrs
        )
        if devices != route_devices:
            raise ValueError("hwscan UART route mismatch")
        if _unpack_from("<I", raw, _hw_vtable_offset)[0] != mapper.virtual_address:
            raise ValueError("hwscan AML vtable mapper pointer mismatch")
        if _unpack_from("<3I", raw, _hw_plug_offset) != (439, 440, 441):
            raise ValueError("hwscan plug GPIO table mismatch")
        if _unpack_from("<3I", raw, _hw_reset_offset) != (454, 455, 456):
            raise ValueError("hwscan reset GPIO table mismatch")
        require(raw, _hw_aml_source_offset, b"src/aml/platform.c\x00", "AML source")
        require(raw, _hw_psu_source_offset, b"src/aml/psu.c\x00", "PSU source")
        require(raw, _hw_psu_label_offset, b"i2c:psu-bus\x00", "PSU label")
        # The exact reset function contains ARM ``eor r1, r1, #1`` before the
        # table-indexed write; preserve that narrow active-low observation.
        require(raw, reset.file_offset + 0x5C, b"\x01\x10\x21\xe2", "reset XOR")
        route = _route_type(
            artifact_id=artifact_specs[0][0],
            elf_machine=machine,
            elf_entry=entry,
            load_segments=segments,
            platform_enum=2,
            mapper=mapper,
            mapper_table_virtual_address=0x3DC558,
            mapper_table_file_offset=_hw_route_offset,
            vtable_mapper_pointer_virtual_address=0x3DE6C0,
            vtable_mapper_pointer_file_offset=_hw_vtable_offset,
            chain_devices=devices,
            functions=functions,
        )
        _setattr(route, "route_verified", True)
        return route

    def validate_cgminer(raw: bytes) -> BinaryRouteReceipt:
        machine, entry, segments = parse_elf(raw, 0x1012C, cgminer_loads)
        functions = make_functions(raw, cgminer_functions, cgminer_loads)
        mapper = functions[0]
        if _unpack_from("<3I", raw, _cg_route_offset) != cg_route_ptrs:
            raise ValueError("cgminer route pointer table mismatch")
        if _unpack_from("<I", raw, _cg_vtable_offset)[0] != mapper.virtual_address:
            raise ValueError("cgminer AML vtable mapper pointer mismatch")
        decoded = []
        for offset, key, ciphertext, cleartext in cg_encrypted_uarts:
            require(raw, offset, ciphertext, "cgminer encoded UART")
            value = _bytes(item ^ key for item in ciphertext).decode("ascii")
            if value != cleartext:
                raise ValueError("cgminer UART decode mismatch")
            decoded.append(value)
        devices = _tuple(decoded)
        if devices != route_devices:
            raise ValueError("cgminer production route mismatch")
        route = _route_type(
            artifact_id=artifact_specs[1][0],
            elf_machine=machine,
            elf_entry=entry,
            load_segments=segments,
            platform_enum=2,
            mapper=mapper,
            mapper_table_virtual_address=0x511450,
            mapper_table_file_offset=_cg_route_offset,
            vtable_mapper_pointer_virtual_address=0x514238,
            vtable_mapper_pointer_file_offset=_cg_vtable_offset,
            chain_devices=devices,
            functions=functions,
        )
        _setattr(route, "route_verified", True)
        return route

    def validate_fw_info(raw: bytes):
        # Whole-file exact admission already pins the JSON grammar and every
        # value.  Keep the semantic return independent from the mutable public
        # ``json.loads`` function object, while still requiring the exact
        # canonical serialization bytes here as a second local association.
        expected = (
            b'{\n  "build_name": "awesome",\n'
            b'  "build_time": "2025-05-31 07:28:00",\n'
            b'  "build_uuid": "99507f48-2f90-4e55-860f-d70facf0f820",\n'
            b'  "fw_name": "Awesome",\n'
            b'  "fw_version": "1.2.6",\n'
            b'  "install_type": "nand",\n'
            b'  "miner": "Antminer T21",\n'
            b'  "model": "t21",\n'
            b'  "platform": "aml"\n}'
        )
        if raw != expected:
            raise ValueError("fw-info identity mismatch")
        return (
            "Awesome",
            "1.2.6",
            "Antminer T21",
            "t21",
            "aml",
            "nand",
        )

    def validate_scripts(s12hwscan: bytes, s11board: bytes) -> None:
        s12 = s12hwscan.decode("ascii")
        required_s12 = (
            "MINER_MODEL=$(fwinfo model)",
            "MINER_PLATFORM=$(fwinfo platform)",
            'HWSCAN_ARGS="--platform $MINER_PLATFORM --gen-model-info $MINER_MODEL --gen-def-conf $MINER_MODEL"',
            "if hwscan $HWSCAN_ARGS; then",
        )
        if _any(item not in s12 for item in required_s12):
            raise ValueError("S12hwscan production association mismatch")
        s11 = s11board.decode("ascii")
        required_s11 = (
            "# gpio_recovery 446",
            "# gpio_ip_get 445",
            "# pwr_en 437",
            "echo 1 > /sys/class/gpio/gpio437/value",
            "# ch0_plug 439",
            "# ch1_plug 440",
            "# ch2_plug 441",
            "# ch0_rst 454",
            "# ch1_rst 455",
            "# ch2_rst 456",
            "# gpio_led_green 453",
            "# gpio_led_red 438",
            "# fan_front_speed0 447",
            "# fan_front_speed1 448",
            "# fan_rear_speed0 449",
            "# fan_rear_speed1 450",
            "echo falling > /sys/class/gpio/gpio447/edge",
            "echo falling > /sys/class/gpio/gpio448/edge",
            "echo falling > /sys/class/gpio/gpio449/edge",
            "echo falling > /sys/class/gpio/gpio450/edge",
            "echo 100000 > /sys/class/pwm/pwmchip0/pwm0/period",
            "echo 100000 > /sys/class/pwm/pwmchip0/pwm0/duty_cycle",
            "echo 1 > /sys/class/pwm/pwmchip0/pwm0/enable",
            "echo 100000 > /sys/class/pwm/pwmchip0/pwm1/period",
            "echo 100000 > /sys/class/pwm/pwmchip0/pwm1/duty_cycle",
            "echo 1 > /sys/class/pwm/pwmchip0/pwm1/enable",
        )
        if _any(item not in s11 for item in required_s11):
            raise ValueError("S11board production GPIO association mismatch")
        if "set -e" in s11:
            raise ValueError("S11board failure-semantics association mismatch")

    def inspect_t21_production_route(
        *,
        hwscan: bytes,
        cgminer: bytes,
        fw_info: bytes,
        s12hwscan: bytes,
        s11board: bytes,
    ) -> T21ProductionRouteInspection:
        """Admit exact held bytes and return non-authorizing observations."""

        raw_artifacts = (hwscan, cgminer, fw_info, s12hwscan, s11board)
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
        board_io = _board_gpio_type(
            recovery_input_gpio=446,
            ip_report_input_gpio=445,
            power_enable_gpio=437,
            power_enable_startup_value=1,
            plug_input_gpios=(439, 440, 441),
            plug_pull_down_requested=True,
            reset_output_gpios=(454, 455, 456),
            reset_active_low=True,
            green_led_output_gpio=453,
            red_led_output_gpio=438,
            script_has_errexit=False,
            setup_failures_are_fatal=False,
            output_readback_verified=False,
            stop_teardown_present=False,
        )
        fans = _fan_type(
            front_tach_input_gpios=(447, 448),
            rear_tach_input_gpios=(449, 450),
            tach_edge="falling",
            pwm_chip=0,
            rear_pwm_channel=0,
            front_pwm_channel=1,
            pwm_period_ns=100_000,
            startup_duty_cycle_ns=100_000,
            startup_enabled=True,
            tach_readback_verified=False,
            airflow_verified=False,
            setup_failures_are_fatal=False,
        )
        psu = _psu_type(
            scope="board-global code and init-script observation only",
            power_enable_gpio=437,
            startup_value=1,
            software_i2c_gpios=(477, 476),
            interface_label="i2c:psu-bus",
            low_and_high_write_functions_observed=True,
            psu_family_identified=False,
            protocol_identified=False,
            safe_off_value_verified=False,
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
            hwscan_command="hwscan --platform aml --gen-model-info t21 --gen-def-conf t21",
            hwscan_route=hwscan_route,
            cgminer_route=cgminer_route,
            chains=chains,
            board_io=board_io,
            fans=fans,
            psu=psu,
            production_route_kind="AML direct UART; not Cvitek uart_trans or Zynq FPGA",
            cvitek_route_is_distinct=True,
            zynq_fpga_route_is_distinct=True,
            pic_runtime_identity_verified=False,
            unresolved=unresolved,
        )
        _setattr(inspection, "production_association_verified", True)
        _setattr(inspection, "inspection_verified", True)
        return inspection

    return inspect_t21_production_route


inspect_t21_production_route = _build_inspector()
del _build_inspector
