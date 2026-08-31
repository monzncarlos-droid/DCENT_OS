#!/usr/bin/env python3
"""Verify evidence-only S19k APW121215f facts in the held stock ELF.

No target, I2C adapter, GPIO, or network is accessed.  The checker identifies
the PSU service's exact enable dispatch, the logical PSU-control output, the
disable worker's non-I/O tag-3 barrier, and both checksum algorithms.  It keeps
the profile compatibility discriminator's enum name unresolved and never
promotes a controller call or GPIO write to physical rail proof.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from typing import Optional


DEFAULT_REL = Path(
    ""
    "04-binaries/bosminer.unpacked"
)
EXPECTED_SIZE = 23_963_080
EXPECTED_SHA256 = "5a49dcbe2e2d9f4fb047eca856e71440bd73fc020a817e808b5af3b45a7c8707"

APW_TRAIT_VTABLE_VA = 0x019C_8E78
APW_TRAIT_VTABLE = (
    0x0090_9928,
    0xF0,
    8,
    0x0090_E38C,
    0x0090_FCC8,
    0x0090_FF58,
    0x0091_0334,
    0x0091_0758,
    0x0091_0D20,
    0x0091_1188,
    0x0090_7518,
)
APW_METHODS = (
    (0x18, "init", 0x0090_E38C, 0x0090_E410),
    (0x20, "enable", 0x0090_FCC8, 0x0090_FD70),
    (0x28, "disable", 0x0090_FF58, 0x0090_FFA0),
    (0x30, "set-voltage", 0x0091_0334, 0x0091_038C),
    (0x38, "read-voltage", 0x0091_0758, 0x0091_07A0),
    (0x40, "heartbeat", 0x0091_0D20, 0x0091_0D68),
    (0x48, "read-power", 0x0091_1188, 0x0091_120C),
    (0x50, "shutdown", 0x0090_7518, None),
)

FACTORY_PTR_VA = 0x01AC_DDB8
FACTORY_FN_VA = 0x0090_E2B8
APW_TRAIT_ALLOC_PTR_VA = 0x01AC_F2C8
APW_TRAIT_ALLOC_FN_VA = 0x0090_DFC0
PSU_SERVICE_ASYNC_STATE_MACHINE_FN_VA = 0x00B8_BE50
PSU_ENABLE_LOG_RECORD_VA = 0x019F_BCA8
PSU_ENABLE_LOG_STR_VA = 0x0139_0D52
PSU_ENABLE_LOG = b"PSU: Enable"
PSU_SOURCE_PATH_VA = 0x0139_0BEB
PSU_SOURCE_PATH = b"open/bosminer/bosminer-backend/src/psu.rs"
PSU_ENABLE_SOURCE_LINE = 374
PSU_ENABLE_SOURCE_COLUMN = 42
DISABLE_LOG_STR_VA = 0x0139_0CEA
DISABLE_I2C_ERROR_STR_VA = 0x012E_E28F
DISABLE_WORKER_MESSAGE_TAG = 3
DISABLE_WORKER_LOOP_VA = 0x0091_50E0
DISABLE_WORKER_TAG3_HANDLER_VA = 0x0091_5274
DISABLE_WORKER_REPLY_FN_VA = 0x0091_8330
PSU_CONTROL_PIN_STR_VA = 0x0131_F087
GPIO_MUTEX_ERROR_STR_VA = 0x0132_92E4
GPIO_SOURCE_PATH_STR_VA = 0x0132_92FA
SYSFS_PIN_OUT_VTABLE_VA = 0x019C_E530
SYSFS_PIN_OUT_VTABLE = (0, 8, 8, 0x0093_D4D4)

# Exact AArch64 instruction words.  These bind the critical ordering and
# constants without assigning unproved electrical rail semantics.
INSTRUCTION_PINS = (
    # S19k model builder: model enum 8 and common builder call.
    (0x0082_9C48, 0x5280_0100),
    (0x0082_9C54, 0x5280_0061),
    (0x0082_9C6C, 0x5280_0F02),
    (0x0082_9C94, 0x9400_2E41),
    # S19k lazy profile: versions 0x75/0x76/0x77 and discriminator 4 @ +e0.
    (0x0082_9EF8, 0x5280_0EE9),
    (0x0082_9EFC, 0x5280_0EA8),
    (0x0082_9F04, 0x7900_0809),
    (0x0082_9F0C, 0x72A0_0EC8),
    (0x0082_9F18, 0xB900_0008),
    (0x0082_9F28, 0x5280_0089),
    (0x0082_9F30, 0x3903_8269),
    (0x0082_9F80, 0x5280_0129),
    (0x0082_9F90, 0x9114_E108),
    (0x0082_9FAC, 0xA90C_2668),
    # Version-list selection and compatibility discriminator comparison.
    (0x0092_6BF0, 0xA94C_2017),
    (0x0092_6C14, 0xF840_86E0),
    (0x0092_6C2C, 0x97FF_FFBE),
    (0x0092_6D10, 0x384E_0D2A),
    (0x0092_6D14, 0x384E_0D0B),
    (0x0092_6D18, 0x6B0B_015F),
    # Hardware init opens the object labelled "PSU Control pin" as a PinOut
    # with initial logical state 1.
    (0x0087_EE84, 0x9105_03E0),
    (0x0087_EE88, 0x9401_6E19),
    (0x0087_EE8C, 0xF943_93E2),
    (0x0087_EE90, 0xF943_97E3),
    (0x0087_EE94, 0xB400_0622),
    (0x008D_A6FC, 0xAA08_03F4),
    (0x008D_A700, 0x9100_03E8),
    (0x008D_A704, 0x5280_0021),
    (0x008D_A708, 0x9401_8385),
    (0x0093_B51C, 0xB940_0009),
    (0x0093_B52C, 0x9100_2000),
    (0x0093_B530, 0x1400_003B),
    # The sysfs PinOut implementation forwards the boolean to its write helper.
    (0x0093_D4DC, 0x9100_03E8),
    (0x0093_D4E0, 0x940B_1AF3),
    # APW implementation allocator: allocate the exact 0xf0-byte object and
    # return its data pointer with the APW trait vtable at 0x019c8e78.
    (0x0090_E008, 0x5280_1E00),
    (0x0090_E00C, 0x5280_0101),
    (0x0090_E050, 0x97F3_9A8A),
    (0x0090_E05C, 0xD000_85C1),
    (0x0090_E060, 0x9139_E021),
    # PSU service async state machine: both tracing arms reference the exact
    # `PSU: Enable` record before converging on one common dispatch corridor.
    (0x00B8_C928, 0xF000_736A),
    (0x00B8_C92C, 0x9132_A14A),
    (0x00B8_C978, 0x9419_49C6),
    (0x00B8_CBAC, 0xF000_7369),
    (0x00B8_CBB0, 0x9132_A129),
    # Lock state+0xb0/subobject+0x60; load the resulting PSU trait pair;
    # invoke method slot +0x20; store and immediately poll its returned future.
    (0x00B8_CC34, 0xF940_5A68),
    (0x00B8_CC40, 0x9101_8108),
    (0x00B8_CC44, 0xA90C_A668),
    (0x00B8_CC48, 0x9103_2260),
    (0x00B8_CC4C, 0xAA1A_03E1),
    (0x00B8_CC50, 0x97FE_B3AB),
    (0x00B8_CC54, 0xB400_0540),
    (0x00B8_CC58, 0xF940_6668),
    (0x00B8_CC5C, 0xF900_5E60),
    (0x00B8_CC74, 0xF940_5E60),
    (0x00B8_CC78, 0xA943_A000),
    (0x00B8_CC7C, 0xF940_1108),
    (0x00B8_CC80, 0xD63F_0100),
    (0x00B8_CC84, 0xA90C_8660),
    (0x00B8_CC88, 0xF940_0C28),
    (0x00B8_CC8C, 0xAA1A_03E1),
    (0x00B8_CC90, 0xD63F_0100),
    # Enable: same PSU-control output field, logical 0.
    (0x0090_FE38, 0x9100_A2A0),
    (0x0090_FE3C, 0x2A1F_03E1),
    (0x0090_FE40, 0x9400_B310),
    # Disable: build/await I2C-side future first, then boolean 1.
    (0x0091_0070, 0xF940_0E68),
    (0x0091_0074, 0x9100_A100),
    (0x0091_0078, 0x9400_18FF),
    (0x0091_0088, 0xD63F_0100),
    (0x0091_0180, 0x9100_A2A0),
    (0x0091_0184, 0x5280_0021),
    (0x0091_0188, 0x9400_B23E),
    # I2C completion poll and mutex-protected PinOut method at vtable +0x18.
    # Disable sends message tag 3 through the worker and awaits its reply.
    (0x0091_658C, 0x5280_0068),
    (0x0091_6598, 0x3900_23E8),
    (0x0091_65A8, 0x9400_0A07),
    (0x0091_65D0, 0x9400_0932),
    # Worker dispatch: tags 0/1/2 enter the APW operation branches. Any other
    # tag, including the proven disable tag 3, branches directly to the reply
    # helper with zero and then rejoins the common worker loop. There is no
    # APW backend call in this branch and no disable-specific wire frame.
    (0x0091_5160, 0x3940_E3E8),
    (0x0091_5170, 0x7100_051F),
    (0x0091_517C, 0x5400_01CC),
    (0x0091_51B4, 0x7100_091F),
    (0x0091_51B8, 0x5400_05E1),
    (0x0091_5274, 0xAA18_03E0),
    (0x0091_5278, 0xAA1F_03E1),
    (0x0091_527C, 0x9400_0C2D),
    (0x0091_52AC, 0x17FF_FFA6),
    (0x0093_CAF0, 0xF940_0EC9),
    (0x0093_CB00, 0xD63F_0120),
    # Parser checksum selection: mode 1 is little-endian word-additive;
    # every other mode enters the byte-additive branch.  Wire compare is u16.
    (0x008B_9BB4, 0x3940_004A),
    (0x008B_9BBC, 0x7100_055F),
    (0x008B_9BC4, 0x5400_0081),
    (0x008B_9BC8, 0x9401_90A8),
    (0x008B_9CF0, 0x3840_154B),
    (0x008B_9CF8, 0x0B0B_0108),
    (0x008B_9D04, 0x6B28_213F),
    # Exact little-endian 16-bit word-additive helper, including odd-byte zero
    # extension and the empty-input zero result.
    (0x0091_DE68, 0xB400_0241),
    (0x0091_DE7C, 0x2A1F_03EB),
    (0x0091_DE80, 0x3940_010C),
    (0x0091_DE88, 0xCB0A_0021),
    (0x0091_DE8C, 0x0B0C_000C),
    (0x0091_DE90, 0x0B0B_2180),
    (0x0091_DEA0, 0xF100_043F),
    (0x0091_DEA4, 0x54FF_FEC0),
    (0x0091_DEA8, 0x3940_050B),
    (0x0091_DEB0, 0x2A1F_03E0),
    # Set-voltage command 0x83.
    (0x008B_AA80, 0x5280_106A),
    (0x008B_AA90, 0x3901_87EA),
    # Fixed 350,000,000 ns write-to-read wait.
    (0x008A_5CFC, 0x5292_7001),
    (0x008A_5D10, 0x72A2_9B81),
    # Set-voltage caller: 3 eligible retries, 2-second delay, retry callback,
    # then call the exchange future.
    (0x0091_04BC, 0x5280_006B),
    (0x0091_04C0, 0x5280_004C),
    (0x0091_04DC, 0xF0FF_FC49),
    (0x0091_04E0, 0x911C_8129),
    (0x0091_04EC, 0xA90E_314B),
    (0x0091_04F4, 0xA910_A548),
    (0x0091_0504, 0x97FE_5500),
)


def load_segments(blob: bytes) -> list[tuple[int, int, int]]:
    if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise ValueError("expected ELF64 little-endian stock artifact")
    e_phoff = struct.unpack_from("<Q", blob, 32)[0]
    e_phentsize = struct.unpack_from("<H", blob, 54)[0]
    e_phnum = struct.unpack_from("<H", blob, 56)[0]
    segments: list[tuple[int, int, int]] = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", blob, off
        )
        if p_type == 1 and p_filesz:
            segments.append((p_vaddr, p_offset, p_filesz))
    return segments


def va_to_file(segments: list[tuple[int, int, int]], va: int, size: int) -> int:
    for vaddr, offset, filesz in segments:
        delta = va - vaddr
        if 0 <= delta and delta + size <= filesz:
            return offset + delta
    raise ValueError(f"VA 0x{va:x} size {size} is outside file-backed LOADs")


def read_u32(blob: bytes, segments: list[tuple[int, int, int]], va: int) -> int:
    return struct.unpack_from("<I", blob, va_to_file(segments, va, 4))[0]


def read_u64(blob: bytes, segments: list[tuple[int, int, int]], va: int) -> int:
    return struct.unpack_from("<Q", blob, va_to_file(segments, va, 8))[0]


def read_exact(
    blob: bytes, segments: list[tuple[int, int, int]], va: int, size: int
) -> bytes:
    start = va_to_file(segments, va, size)
    return blob[start : start + size]


def verify(path: Path) -> list[str]:
    blob = path.read_bytes()
    if len(blob) != EXPECTED_SIZE:
        raise ValueError(f"size drift: {len(blob)} != {EXPECTED_SIZE}")
    digest = hashlib.sha256(blob).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"sha256 drift: {digest} != {EXPECTED_SHA256}")
    segments = load_segments(blob)

    vtable = tuple(
        read_u64(blob, segments, APW_TRAIT_VTABLE_VA + index * 8)
        for index in range(len(APW_TRAIT_VTABLE))
    )
    if vtable != APW_TRAIT_VTABLE:
        raise ValueError("APW trait vtable drifted")
    if read_u64(blob, segments, FACTORY_PTR_VA) != FACTORY_FN_VA:
        raise ValueError("S19k APW factory pointer drifted")
    if read_u64(blob, segments, APW_TRAIT_ALLOC_PTR_VA) != APW_TRAIT_ALLOC_FN_VA:
        raise ValueError("S19k APW trait allocator pointer drifted")
    enable_log_record = tuple(
        read_u64(blob, segments, PSU_ENABLE_LOG_RECORD_VA + index * 8)
        for index in range(5)
    )
    expected_enable_log_record = (
        PSU_ENABLE_LOG_STR_VA,
        len(PSU_ENABLE_LOG),
        PSU_SOURCE_PATH_VA,
        len(PSU_SOURCE_PATH),
        PSU_ENABLE_SOURCE_LINE | PSU_ENABLE_SOURCE_COLUMN << 32,
    )
    if enable_log_record != expected_enable_log_record:
        raise ValueError("PSU enable source/log record drifted")
    sysfs_pin_out_vtable = tuple(
        read_u64(blob, segments, SYSFS_PIN_OUT_VTABLE_VA + index * 8)
        for index in range(len(SYSFS_PIN_OUT_VTABLE))
    )
    if sysfs_pin_out_vtable != SYSFS_PIN_OUT_VTABLE:
        raise ValueError("sysfs PinOut vtable drifted")

    for va, expected in INSTRUCTION_PINS:
        observed = read_u32(blob, segments, va)
        if observed != expected:
            raise ValueError(
                f"instruction drift at 0x{va:x}: 0x{observed:08x} != 0x{expected:08x}"
            )

    expected_disable_log = b"PSU: Disable"
    disable_log = read_exact(
        blob, segments, DISABLE_LOG_STR_VA, len(expected_disable_log)
    )
    if disable_log != expected_disable_log:
        raise ValueError(f"disable log string drifted: {disable_log!r}")
    enable_log = read_exact(blob, segments, PSU_ENABLE_LOG_STR_VA, len(PSU_ENABLE_LOG))
    if enable_log != PSU_ENABLE_LOG:
        raise ValueError(f"enable log string drifted: {enable_log!r}")
    psu_source = read_exact(blob, segments, PSU_SOURCE_PATH_VA, len(PSU_SOURCE_PATH))
    if psu_source != PSU_SOURCE_PATH:
        raise ValueError(f"PSU source path drifted: {psu_source!r}")
    expected_i2c_error = b"BUG: failed to receive I2C reply"
    i2c_error = read_exact(
        blob, segments, DISABLE_I2C_ERROR_STR_VA, len(expected_i2c_error)
    )
    if i2c_error != expected_i2c_error:
        raise ValueError(f"disable I2C error string drifted: {i2c_error!r}")
    expected_psu_control = b"PSU Control pin {{ERR:HW3}}"
    psu_control = read_exact(
        blob, segments, PSU_CONTROL_PIN_STR_VA, len(expected_psu_control)
    )
    if psu_control != expected_psu_control:
        raise ValueError(f"PSU-control label drifted: {psu_control!r}")
    expected_gpio_mutex_error = b"BUG: PinIn mutex error"
    gpio_mutex_error = read_exact(
        blob, segments, GPIO_MUTEX_ERROR_STR_VA, len(expected_gpio_mutex_error)
    )
    if gpio_mutex_error != expected_gpio_mutex_error:
        raise ValueError(f"GPIO mutex error string drifted: {gpio_mutex_error!r}")
    expected_gpio_source = b"open/utils-rs/gpio/src/lib.rs"
    gpio_source = read_exact(
        blob, segments, GPIO_SOURCE_PATH_STR_VA, len(expected_gpio_source)
    )
    if gpio_source != expected_gpio_source:
        raise ValueError(f"GPIO source path drifted: {gpio_source!r}")

    method_rendered = ",".join(
        f"+0x{slot:02x}:{name}@0x{constructor:08x}"
        + (f"/poll=0x{poll:08x}" if poll is not None else "")
        for slot, name, constructor, poll in APW_METHODS
    )
    return [
        f"ARTIFACT bytes={len(blob)} sha256={digest}",
        "MODEL Antminer-S19k-Pro enum=8 factory=0x0090e2b8",
        "PROFILE reported-versions=0x75,0x76,0x77 compatibility-discriminator=4(enum-name-unrecovered;not-checksum-mode)",
        f"VTABLE va=0x{APW_TRAIT_VTABLE_VA:08x} size=0xf0 align=8 {method_rendered}",
        "PSU_ENABLE_DISPATCH state-machine=0x00b8be50 source=psu.rs:374:42 log-record=0x019fbca8 lock-driver -> trait-slot=+0x20 -> poll-returned-future",
        "S19K_ENABLE_RESOLUTION allocator=0x0090dfc0 -> vtable=0x019c8e78 -> slot+0x20=0x0090fcc8/poll=0x0090fd70",
        "PSU_CONTROL open-PinOut(initial=1) label='PSU Control pin {{ERR:HW3}}' gpio-crate mutex helper=0x0093ca80",
        "ENABLE lock-psu-control-output -> write-logical-0",
        "DISABLE lock-psu-control-output -> enqueue-worker-tag=3 -> await-worker-ack -> relock-output -> write-logical-1",
        "DISABLE_BARRIER tag=3 handler=0x00915274 reply-zero=0x00918330 no-APW-backend-call worker-continues",
        "CHECKSUM mode=1 little-endian-word-additive; other-modes byte-additive; compare/store low16",
        "SET_VOLTAGE command=0x83 write-to-read=350ms retries-after-initial=3 retry-delay=2s maximum-attempts=4",
        "POWER_RESET_JOIN static=separate-exact-futures/no-single-recovered-transaction; runtime-order belongs to the frozen lifecycle capture",
        "ENABLE_AUTHORITY refused=controller-dispatch+logical-GPIO-write-is-not-voltage-rise-or-physical-rail-proof",
        "SAFEOFF stock-log+future+GPIO-readback are controller evidence; independent rail/current decay is required",
        "RESULT evidence-only; stock disable is not VerifiedRailCut",
    ]


def default_path() -> Path:
    return Path(__file__).resolve().parents[3] / DEFAULT_REL


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", nargs="?", type=Path, default=default_path())
    args = parser.parse_args(argv)
    try:
        for line in verify(args.elf.resolve()):
            print(line)
    except (OSError, ValueError, struct.error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
