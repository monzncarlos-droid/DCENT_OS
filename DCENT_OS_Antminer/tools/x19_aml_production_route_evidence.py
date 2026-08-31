"""Exact, bytes-only S19 XP / S19j XP Amlogic production-route evidence.

The inspector admits ten exact files from two held Awesome 1.2.6 AML NAND
root filesystems.  For each model, independent ARM32 ``hwscan`` and ``cgminer``
implementations map zero-based chains 0/1/2 to ``/dev/ttyS3``,
``/dev/ttyS2``, and ``/dev/ttyS1``.  The common init script records GPIO/PWM
setup intent but no checked lifecycle or electrical safe-off proof.

This module accepts bytes only and exposes no path, device, transport, power,
mining, installation, or recovery operation.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Final, Tuple


_S19XP_ARTIFACT_SPECS: Final[Tuple[Tuple[str, int, str], ...]] = (
    (
        "vnish-s19xp-1.2.6-hwscan",
        4_001_996,
        "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f",
    ),
    (
        "vnish-s19xp-1.2.6-cgminer",
        5_400_552,
        "6f90b49d4047f9e329140ae5bc0918129aa36be1de8262fb6aeeb7ea69f489e1",
    ),
    (
        "vnish-s19xp-1.2.6-fw-info",
        270,
        "644c9cc6d24b6a915e98d699a2b40f7f673f1c1623eb17de474aacbf50b115ed",
    ),
    (
        "vnish-s19xp-1.2.6-s12hwscan",
        493,
        "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    ),
    (
        "vnish-s19xp-1.2.6-s11board",
        2_928,
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    ),
)

_S19JXP_ARTIFACT_SPECS: Final[Tuple[Tuple[str, int, str], ...]] = (
    (
        "vnish-s19jxp-1.2.6-hwscan",
        3_993_804,
        "425e99950e9f8539caa209f88b472090c400d27dbe6555124e8e69537ab96909",
    ),
    (
        "vnish-s19jxp-1.2.6-cgminer",
        5_363_624,
        "49f0784c7fd181250ac5ff4dfbea1ecb866d56e63f8da48c3b38004757d51059",
    ),
    (
        "vnish-s19jxp-1.2.6-fw-info",
        273,
        "2a430a185a224bc719ff9afacc5e8d017f965afa15e7bc22ce82dbfcad2edaf5",
    ),
    (
        "vnish-s19jxp-1.2.6-s12hwscan",
        493,
        "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    ),
    (
        "vnish-s19jxp-1.2.6-s11board",
        2_928,
        "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    ),
)

_S19XP_FW_INFO = (
    b'{\n  "build_name": "awesome",\n'
    b'  "build_time": "2025-05-31 07:26:01",\n'
    b'  "build_uuid": "b6f586e4-2e05-4a1e-b787-bdb3d5818953",\n'
    b'  "fw_name": "Awesome",\n'
    b'  "fw_version": "1.2.6",\n'
    b'  "install_type": "nand",\n'
    b'  "miner": "Antminer S19 XP",\n'
    b'  "model": "s19xp",\n'
    b'  "platform": "aml"\n}'
)
_S19JXP_FW_INFO = (
    b'{\n  "build_name": "awesome",\n'
    b'  "build_time": "2025-05-31 07:22:01",\n'
    b'  "build_uuid": "e1894a48-ea52-4b9e-939c-ac1d5677fca6",\n'
    b'  "fw_name": "Awesome",\n'
    b'  "fw_version": "1.2.6",\n'
    b'  "install_type": "nand",\n'
    b'  "miner": "Antminer S19j XP",\n'
    b'  "model": "s19j-xp",\n'
    b'  "platform": "aml"\n}'
)

_HWSCAN_S19XP = (
    0x11EB8,
    (
        (0, 0x10000, 0x3BA668, 0x3BA668, 5, 0x10000),
        (0x3BABC8, 0x3DABC8, 0x16108, 0x26200, 6, 0x10000),
    ),
    (
        ("AML plug GPIO read", 0x0FA9C4, 0x0EA9C4, 0x09C, "98fd3a6e7ad978cfc7b1f623a615984da97a97bdb31af41fcfc8690e1997bead"),
        ("AML active-low reset GPIO write", 0x0FAA74, 0x0EAA74, 0x074, "e148fed7938d569e6cc38165693e8d67a16bbaa7d0d6a720abd2d5a72f0c7f5e"),
        ("AML chain UART mapper", 0x0FACF8, 0x0EACF8, 0x028, "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac"),
        ("AML PSU interface initialize", 0x0FADC4, 0x0EADC4, 0x13C, "61e0237a53b8e234003e17ec4c5b82647ca87e516f9b42a8a68116d4a7ba86e7"),
        ("AML GPIO437 write low", 0x0FAF4C, 0x0EAF4C, 0x080, "89831303fc9f1265ec046a8826dc19f30539333d4a05f23aceb712eddb8b824a"),
        ("AML GPIO437 write high", 0x0FAFE0, 0x0EAFE0, 0x07C, "4e1499250ce992ec2f0c7d867e58c12dd1e663e2176fecf9a685b77cd3b073c2"),
    ),
    (0x3B388D, 0x3B3898, 0x3B38A3),
    0x3DC558,
    0x3BC558,
    0x3DE6C0,
    0x3BE6C0,
    0x3A384C,
    0x3A3858,
    0x3A387A,
    0x3A38C4,
    0x3A284A,
)

_HWSCAN_S19JXP = (
    0x11EB8,
    (
        (0, 0x10000, 0x3B7E08, 0x3B7E08, 5, 0x10000),
        (0x3B8BC8, 0x3D8BC8, 0x16108, 0x26200, 6, 0x10000),
    ),
    (
        ("AML plug GPIO read", 0x0FA9C4, 0x0EA9C4, 0x09C, "98fd3a6e7ad978cfc7b1f623a615984da97a97bdb31af41fcfc8690e1997bead"),
        ("AML active-low reset GPIO write", 0x0FAA74, 0x0EAA74, 0x074, "e148fed7938d569e6cc38165693e8d67a16bbaa7d0d6a720abd2d5a72f0c7f5e"),
        ("AML chain UART mapper", 0x0FACF8, 0x0EACF8, 0x028, "8fefcfc1b22b57ba292dfc13c2529fb5b81ed8ec13c8077e0ee7f3ca79fee718"),
        ("AML PSU interface initialize", 0x0FADC4, 0x0EADC4, 0x13C, "61e0237a53b8e234003e17ec4c5b82647ca87e516f9b42a8a68116d4a7ba86e7"),
        ("AML GPIO437 write low", 0x0FAF4C, 0x0EAF4C, 0x080, "89831303fc9f1265ec046a8826dc19f30539333d4a05f23aceb712eddb8b824a"),
        ("AML GPIO437 write high", 0x0FAFE0, 0x0EAFE0, 0x07C, "4e1499250ce992ec2f0c7d867e58c12dd1e663e2176fecf9a685b77cd3b073c2"),
    ),
    (0x3B102D, 0x3B1038, 0x3B1043),
    0x3DA558,
    0x3BA558,
    0x3DC6C0,
    0x3BC6C0,
    0x3A0FEC,
    0x3A0FF8,
    0x3A101A,
    0x3A1064,
    0x39FFEA,
)

_CGMINER_S19XP = (
    0x1012C,
    (
        (0, 0x10000, 0x4F3F8C, 0x4F3F8C, 5, 0x10000),
        (0x4F4F68, 0x514F68, 0x314B8, 0x7D064, 6, 0x10000),
    ),
    ("AML chain UART mapper", 0x10AEAC, 0x0FAEAC, 0x28, "8c351233f54143a9adfea921761b9bc29b1d11107c96fda4ca4d7cbac9998468"),
    (0x527614, 0x52761F, 0x52762A),
    0x515450,
    0x4F5450,
    0x518238,
    0x4F8238,
    (
        (0x507614, 0xFB, bytes.fromhex("d49f9e8dd48f8f82a8c8"), "/dev/ttyS3"),
        (0x50761F, 0x52, bytes.fromhex("7d3637247d26262b0160"), "/dev/ttyS2"),
        (0x50762A, 0xFF, bytes.fromhex("d09b9a89d08b8b86acce"), "/dev/ttyS1"),
    ),
)

_CGMINER_S19JXP = (
    0x1012C,
    (
        (0, 0x10000, 0x4EB194, 0x4EB194, 5, 0x10000),
        (0x4EBF68, 0x50BF68, 0x31478, 0x7D024, 6, 0x10000),
    ),
    ("AML chain UART mapper", 0x107E8C, 0x0F7E8C, 0x28, "e4807988de8605506d9daadc5fcb438cc063efe63465602efce1a42ab8b865e1"),
    (0x51E5D4, 0x51E5DF, 0x51E5EA),
    0x50C450,
    0x4EC450,
    0x50F230,
    0x4EF230,
    (
        (0x4FE5D4, 0x26, bytes.fromhex("094243500952525f7515"), "/dev/ttyS3"),
        (0x4FE5DF, 0xE7, bytes.fromhex("c8838291c893939eb4d5"), "/dev/ttyS2"),
        (0x4FE5EA, 0x38, bytes.fromhex("175c5d4e174c4c416b09"), "/dev/ttyS1"),
    ),
)


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    size: int
    sha256: str
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
    reset_output_gpios: Tuple[int, int, int]
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


@dataclass(frozen=True)
class PsuObservation:
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
class X19AmlModelInspection:
    miner: str
    model: str
    platform: str
    install_type: str
    artifacts: Tuple[ArtifactReceipt, ...]
    hwscan_command: str
    hwscan_route: BinaryRouteReceipt
    cgminer_route: BinaryRouteReceipt
    production_association_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class X19AmlProductionRouteInspection:
    models: Tuple[X19AmlModelInspection, ...]
    chains: Tuple[ProductionChainRoute, ...]
    board_io: BoardGpioObservation
    fans: FanObservation
    psu: PsuObservation
    production_route_kind: str
    controller_routes_are_distinct: bool
    model_bound_hashboard_identity_verified: bool
    unresolved: Tuple[str, ...]
    authority: ProductionRouteAuthority = field(
        default_factory=ProductionRouteAuthority, init=False
    )
    inspection_verified: bool = field(default=False, init=False)


def _build_inspector(
    _s19xp_artifacts=_S19XP_ARTIFACT_SPECS,
    _s19jxp_artifacts=_S19JXP_ARTIFACT_SPECS,
    _s19xp_fw=_S19XP_FW_INFO,
    _s19jxp_fw=_S19JXP_FW_INFO,
    _hw_s19xp=_HWSCAN_S19XP,
    _hw_s19jxp=_HWSCAN_S19JXP,
    _cg_s19xp=_CGMINER_S19XP,
    _cg_s19jxp=_CGMINER_S19JXP,
    _artifact_type=ArtifactReceipt,
    _segment_type=ElfLoadSegment,
    _function_type=FunctionReceipt,
    _binary_type=BinaryRouteReceipt,
    _chain_type=ProductionChainRoute,
    _board_type=BoardGpioObservation,
    _fan_type=FanObservation,
    _psu_type=PsuObservation,
    _model_type=X19AmlModelInspection,
    _inspection_type=X19AmlProductionRouteInspection,
    _sha256=hashlib.sha256,
    _unpack_from=struct.unpack_from,
    _setattr=object.__setattr__,
    _bytes=bytes,
    _tuple=tuple,
    _len=len,
    _type=type,
    _zip=zip,
    _range=range,
    _enumerate=enumerate,
    _any=any,
):
    s19xp_artifacts = _tuple(_tuple(item) for item in _s19xp_artifacts)
    s19jxp_artifacts = _tuple(_tuple(item) for item in _s19jxp_artifacts)
    hw_s19xp = _tuple(_hw_s19xp)
    hw_s19jxp = _tuple(_hw_s19jxp)
    cg_s19xp = _tuple(_cg_s19xp)
    cg_s19jxp = _tuple(_cg_s19jxp)
    route_devices = ("/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1")

    def validate_artifact(raw: bytes, spec) -> ArtifactReceipt:
        if _type(raw) is not _bytes:
            raise TypeError(f"{spec[0]} must be exact bytes")
        artifact_id, size, digest = spec
        if _len(raw) != size:
            raise ValueError(f"{artifact_id} size mismatch")
        if _sha256(raw).hexdigest() != digest:
            raise ValueError(f"{artifact_id} SHA-256 mismatch")
        receipt = _artifact_type(artifact_id, size, digest)
        _setattr(receipt, "verified_by_inspector", True)
        return receipt

    def parse_elf(raw: bytes, expected_entry: int, expected_loads):
        if raw[:16] != b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8:
            raise ValueError("binary is not exact ELF32 little-endian System V")
        header = _unpack_from("<HHIIIIIHHHHHH", raw, 16)
        elf_type, machine, version, entry = header[:4]
        phoff, ehsize, phentsize, phnum = header[4], header[7], header[8], header[9]
        if (
            elf_type != 2
            or machine != 40
            or version != 1
            or entry != expected_entry
            or ehsize != 52
            or phentsize != 32
            or phoff + phnum * phentsize > _len(raw)
        ):
            raise ValueError("ELF identity or program-header bounds mismatch")
        loads = []
        for index in _range(phnum):
            item = _unpack_from("<IIIIIIII", raw, phoff + index * 32)
            if item[0] == 1:
                loads.append((item[1], item[2], item[4], item[5], item[6], item[7]))
        if _tuple(loads) != _tuple(expected_loads):
            raise ValueError("ELF PT_LOAD geometry mismatch")
        if _any(offset + size > _len(raw) for offset, _, size, _, _, _ in loads):
            raise ValueError("ELF PT_LOAD extends beyond artifact")
        return machine, entry, _tuple(_segment_type(*item) for item in loads)

    def va_to_file(va: int, loads) -> int:
        for file_offset, load_va, file_size, _, _, _ in loads:
            if load_va <= va < load_va + file_size:
                return file_offset + va - load_va
        raise ValueError("virtual address is outside file-backed PT_LOAD ranges")

    def make_function(raw: bytes, spec, loads) -> FunctionReceipt:
        name, va, offset, size, digest = spec
        if offset < 0 or offset + size > _len(raw):
            raise ValueError(f"{name} window out of bounds")
        if va_to_file(va, loads) != offset:
            raise ValueError(f"{name} VA/file mapping mismatch")
        if _sha256(raw[offset : offset + size]).hexdigest() != digest:
            raise ValueError(f"{name} window SHA-256 mismatch")
        return _function_type(name, va, offset, size, digest)

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

    def validate_hwscan(raw: bytes, artifact_id: str, spec) -> BinaryRouteReceipt:
        (
            entry,
            loads,
            function_specs,
            pointers,
            table_va,
            table_offset,
            vtable_va,
            vtable_offset,
            plug_offset,
            reset_offset,
            source_offset,
            psu_source_offset,
            psu_label_offset,
        ) = spec
        machine, actual_entry, segments = parse_elf(raw, entry, loads)
        functions = _tuple(make_function(raw, item, loads) for item in function_specs)
        mapper = functions[2]
        if _unpack_from("<3I", raw, table_offset) != _tuple(pointers):
            raise ValueError("hwscan route pointer table mismatch")
        devices = _tuple(c_string(raw, va_to_file(pointer, loads)) for pointer in pointers)
        if devices != route_devices:
            raise ValueError("hwscan UART route mismatch")
        if _unpack_from("<I", raw, vtable_offset)[0] != mapper.virtual_address:
            raise ValueError("hwscan AML vtable mapper pointer mismatch")
        if va_to_file(table_va, loads) != table_offset or va_to_file(vtable_va, loads) != vtable_offset:
            raise ValueError("hwscan table VA/file mapping mismatch")
        if _unpack_from("<3I", raw, plug_offset) != (439, 440, 441):
            raise ValueError("hwscan plug GPIO table mismatch")
        if _unpack_from("<3I", raw, reset_offset) != (454, 455, 456):
            raise ValueError("hwscan reset GPIO table mismatch")
        require(raw, source_offset, b"src/aml/platform.c\x00", "AML source")
        require(raw, psu_source_offset, b"src/aml/psu.c\x00", "PSU source")
        require(raw, psu_label_offset, b"i2c:psu-bus\x00", "PSU label")
        require(raw, functions[1].file_offset + 0x5C, b"\x01\x10\x21\xe2", "reset XOR")
        route = _binary_type(
            artifact_id,
            machine,
            actual_entry,
            segments,
            mapper,
            table_va,
            table_offset,
            vtable_va,
            vtable_offset,
            devices,
            functions,
        )
        _setattr(route, "route_verified", True)
        return route

    def validate_cgminer(raw: bytes, artifact_id: str, spec) -> BinaryRouteReceipt:
        (
            entry,
            loads,
            function_spec,
            pointers,
            table_va,
            table_offset,
            vtable_va,
            vtable_offset,
            encrypted,
        ) = spec
        machine, actual_entry, segments = parse_elf(raw, entry, loads)
        mapper = make_function(raw, function_spec, loads)
        if _unpack_from("<3I", raw, table_offset) != _tuple(pointers):
            raise ValueError("cgminer route pointer table mismatch")
        if _unpack_from("<I", raw, vtable_offset)[0] != mapper.virtual_address:
            raise ValueError("cgminer AML vtable mapper pointer mismatch")
        if va_to_file(table_va, loads) != table_offset or va_to_file(vtable_va, loads) != vtable_offset:
            raise ValueError("cgminer table VA/file mapping mismatch")
        decoded = []
        for pointer, (offset, key, ciphertext, cleartext) in _zip(pointers, encrypted):
            if va_to_file(pointer, loads) != offset:
                raise ValueError("cgminer encoded UART VA/file mapping mismatch")
            require(raw, offset, ciphertext, "cgminer encoded UART")
            value = _bytes(item ^ key for item in ciphertext).decode("ascii")
            if value != cleartext:
                raise ValueError("cgminer UART decode mismatch")
            decoded.append(value)
        devices = _tuple(decoded)
        if devices != route_devices:
            raise ValueError("cgminer production route mismatch")
        route = _binary_type(
            artifact_id,
            machine,
            actual_entry,
            segments,
            mapper,
            table_va,
            table_offset,
            vtable_va,
            vtable_offset,
            devices,
            (mapper,),
        )
        _setattr(route, "route_verified", True)
        return route

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
            "# fan_front_speed0 447",
            "# fan_front_speed1 448",
            "# fan_rear_speed0 449",
            "# fan_rear_speed1 450",
            "echo falling > /sys/class/gpio/gpio447/edge",
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

    def inspect_x19_aml_production_routes(
        *,
        s19xp_hwscan: bytes,
        s19xp_cgminer: bytes,
        s19xp_fw_info: bytes,
        s19xp_s12hwscan: bytes,
        s19xp_s11board: bytes,
        s19jxp_hwscan: bytes,
        s19jxp_cgminer: bytes,
        s19jxp_fw_info: bytes,
        s19jxp_s12hwscan: bytes,
        s19jxp_s11board: bytes,
    ) -> X19AmlProductionRouteInspection:
        """Admit the two exact held rootfs sets and return observations only."""

        model_inputs = (
            (
                "Antminer S19 XP",
                "s19xp",
                _s19xp_fw,
                s19xp_artifacts,
                hw_s19xp,
                cg_s19xp,
                (s19xp_hwscan, s19xp_cgminer, s19xp_fw_info, s19xp_s12hwscan, s19xp_s11board),
            ),
            (
                "Antminer S19j XP",
                "s19j-xp",
                _s19jxp_fw,
                s19jxp_artifacts,
                hw_s19jxp,
                cg_s19jxp,
                (s19jxp_hwscan, s19jxp_cgminer, s19jxp_fw_info, s19jxp_s12hwscan, s19jxp_s11board),
            ),
        )
        models = []
        for miner, model, expected_fw, artifact_specs, hw_spec, cg_spec, raw in model_inputs:
            artifacts = _tuple(validate_artifact(value, spec) for value, spec in _zip(raw, artifact_specs))
            if raw[2] != expected_fw:
                raise ValueError(f"{model} fw-info identity mismatch")
            validate_scripts(raw[3], raw[4])
            hwscan_route = validate_hwscan(raw[0], artifact_specs[0][0], hw_spec)
            cgminer_route = validate_cgminer(raw[1], artifact_specs[1][0], cg_spec)
            if hwscan_route.chain_devices != cgminer_route.chain_devices:
                raise ValueError(f"{model} independent route implementations disagree")
            receipt = _model_type(
                miner,
                model,
                "aml",
                "nand",
                artifacts,
                f"hwscan --platform aml --gen-model-info {model} --gen-def-conf {model}",
                hwscan_route,
                cgminer_route,
            )
            _setattr(receipt, "production_association_verified", True)
            models.append(receipt)

        if models[0].hwscan_route.chain_devices != models[1].hwscan_route.chain_devices:
            raise ValueError("model production routes disagree")
        chains = _tuple(
            _chain_type(index, device, 439 + index, 454 + index, True)
            for index, device in _enumerate(route_devices)
        )
        inspection = _inspection_type(
            models=_tuple(models),
            chains=chains,
            board_io=_board_type(
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
            ),
            fans=_fan_type(
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
            ),
            psu=_psu_type(437, 1, (477, 476), "i2c:psu-bus", True, False, False, False, False),
            production_route_kind="AML direct UART; Cvitek and Zynq variants remain distinct",
            controller_routes_are_distinct=True,
            model_bound_hashboard_identity_verified=False,
            unresolved=(
                "exact deployed hashboard identity remains unresolved for both model compositions",
                "PIC or NoPic selection, PSU family/protocol, voltage units, limits, polarity, safe-off, and ordering remain unresolved",
                "controller revision, exclusive ownership, cold initialization, live enumeration, and failure unwind remain pending",
                "fan setup has no checked tach, airflow, thermal attribution, watchdog, or stop teardown proof",
                "persistent write window, readback, boot selection, rollback, and recovery remain unproved",
            ),
        )
        _setattr(inspection, "inspection_verified", True)
        return inspection

    return inspect_x19_aml_production_routes


inspect_x19_aml_production_routes = _build_inspector()
del _build_inspector
