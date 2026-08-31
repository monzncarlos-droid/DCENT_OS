#!/usr/bin/env python3
"""Offline byte-exact NAND simulation of the typed S19k Pro mtd5 flash transaction.

This module proves, DESK-SIDE ONLY, that the whole
``mtd5_rootfs_window_flag_commit`` transaction is mechanically executable and
atomicity-classifiable for the EXACT unit geometry observed 2026-08-30:

    mtd0 bootloader   0x00200000 @ 0x00000000
    mtd1 tpl          0x00800000 @ 0x00800000   (6 MiB hole after mtd0)
    mtd2 stock_system 0x03200000 @ 0x01000000
    mtd3 stock_config 0x00500000 @ 0x04200000
    mtd4 overlay      0x02000000 @ 0x04700000
    mtd5 system       0x09900000 @ 0x06700000   erasesize 0x20000 everywhere,
                                                 bad_blocks=0 observed on all six

The simulated transaction legs (each executed with per-op readback):

1. ``backup``  - the six-MTD padbad/omitoob dump shape with duplicate reads
                 (mtd{N}_{name}.padbad.bin), the 64 KiB nand_env.bak +
                 nandrecovery_env.bin CRC images, and the exclusive
                 recovery-flag eraseblock slice (byte0=0x02, all-0xFF tail)
                 admitted per am3_geometry.sh.
2. ``window``  - flash_erase 320 EBs at mtd5-local 0x05100000 followed by
                 nandwrite of the DCENT root payload (0xFF-padded to the erase
                 boundary) with SHA readback of the exact payload span.
3. ``commit``  - the recovery-flag eraseblock rewrite to 0x01: duplicate
                 pre-write snapshots, one-EB erase, full-128-KiB write of the
                 0x01 candidate, full-EB byte compare + semantic byte check
                 (the S99upgrade OTA-08 pattern).
4. ``rollback``- flag 0x02 rewrite, then the stock U-Boot ``recover_to_stock``
                 choreography: nandrecovery_env read from mtd5-local
                 0x04900000 + CRC env import, then ``nand erase.part nvdata``
                 over the U-Boot nvdata span (global 0x04700000..0x10000000,
                 exactly Linux mtd4 overlay + mtd5 system), reset.
5. ``restore`` - full-mtd5 restore from the backup artifact: whole-partition
                 erase, full-image nandwrite, byte-exact readback, and the
                 preserved-partition check returning mtd0..mtd4 pristine.

Fault injection runs at EVERY op boundary (plus progress cuts inside the long
window erase/write and inside the nvdata erase) and each cut is classified
against the transaction's own atomicity model by READING THE BANK, never the
op log's intentions:

* ``before_commit_boots_stock``        - cut before the flag-EB erase: the
  recovery flag is still 0x02 and the stock boot chain (mtd0..mtd3) is
  byte-identical, so the unit still boots stock; re-run install or restore.
* ``inside_commit_window_flag_erased`` - the ONE ambiguous state: the flag EB
  is erased (byte0=0xFF) and U-Boot's dispatch for a non-01/02/03 flag byte
  is NOT pinned by held evidence; the safe rail is restore-from-backup.
* ``after_commit_dcent_boots``         - flag 0x01 written AND verified:
  U-Boot FirstBosThenSetFlag2 boots the verified DCENT window.
* ``rollback_partial_stock_boots`` / ``rollback_complete_stock_boots``.
* ``restore_partial_rerunnable``       - the restore IS the recovery rail.

Honesty rails: this is a Python bytearray, never a device. No transport, no
miner contact, no subprocess, no real NAND, no U-Boot execution (the U-Boot
ops model the NAND side effects of the vendor recover_to_stock sequence).
CLEAR_FOR_FLASH stays false; this module prepares evidence and vocabulary,
never authority. The real interlocks (Toolbox CLEAR_FOR_FLASH, the dcentos
mutation contract, PRODUCTION_EXECUTION_READY, the shell CLEAR_FOR_FLASH
gate) are NOT modeled as flippable here. Erase-before-write physics is
deliberately stricter than raw hardware: a write into a span holding any
non-0xFF byte fails LOUDLY, exactly like the discipline the real writer must
obey. Pristine stock bytes are a deterministic tile, not held unit bytes;
the sim proves SEQUENCE mechanics and classification, not vendor image
content, and nand_env.bak (a separate U-Boot env device) is modeled as a
CRC-valid sidecar image rather than sliced from mtd5.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zlib
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "ERASE_BLOCK",
    "LINUX_PARTITIONS",
    "PartitionPin",
    "WINDOW_LOCAL",
    "WINDOW_BYTES",
    "WINDOW_ERASE_COUNT",
    "FLAG_EB_LOCAL",
    "RECOVERY_ENV_LOCAL",
    "RECOVERY_ENV_LEN",
    "FLAG_INSTALL_COMMIT",
    "FLAG_STOCK_REVERT",
    "FLAG_BOOT_SUCCESS",
    "FLAG_TAIL_ALL_FF_SHA256",
    "UBOOT_NVDATA_GLOBAL_START",
    "UBOOT_NVDATA_GLOBAL_END",
    "SimNandError",
    "SimNandDevice",
    "SimNandBank",
    "build_pristine_bank",
    "TxnOp",
    "install_program",
    "rollback_program",
    "restore_program",
    "BackupArtifact",
    "capture_backup",
    "run_install_transaction",
    "run_rollback_transaction",
    "run_restore_transaction",
    "install_fault_sweep",
    "rollback_fault_sweep",
    "restore_fault_sweep",
    "classify_flag_byte",
    "proc_mtd_rows",
    "synthetic_root_payload",
    "make_env_image",
    "env_crc_ok",
    "flag_candidate",
    "admit_exclusive_flag_eb",
    "main",
]


# --- pinned geometry (2026-08-30 /proc/mtd evidence + held .78 dmesg) ---------------------


ERASE_BLOCK = 0x20000  # 131072 B, uniform across all six partitions


@dataclass(frozen=True)
class PartitionPin:
    index: int
    name: str
    offset: int  # global device offset (the 6 MiB hole follows mtd0)
    size: int

    @property
    def erase_blocks(self) -> int:
        if self.size % ERASE_BLOCK:
            raise SimNandError(f"mtd{self.index} size {self.size:#x} not erase-aligned")
        return self.size // ERASE_BLOCK

    @property
    def backup_name(self) -> str:
        return f"mtd{self.index}_{self.name}.padbad.bin"


# Mirror of s19k_persistent_recovery_verify.PARTITIONS (the canonical desk
# contract); test_geometry_converges_with_recovery_verifier pins both equal.
LINUX_PARTITIONS: Tuple[PartitionPin, ...] = (
    PartitionPin(0, "bootloader", 0x00000000, 0x00200000),
    PartitionPin(1, "tpl", 0x00800000, 0x00800000),
    PartitionPin(2, "stock_system", 0x01000000, 0x03200000),
    PartitionPin(3, "stock_config", 0x04200000, 0x00500000),
    PartitionPin(4, "overlay", 0x04700000, 0x02000000),
    PartitionPin(5, "system", 0x06700000, 0x09900000),
)

PARTITION_BY_INDEX = {pin.index: pin for pin in LINUX_PARTITIONS}
MTD5_BASE = PARTITION_BY_INDEX[5].offset  # 0x06700000 (never the 0x06100000 sum)

# The typed transaction window (am3_geometry.sh pins).
WINDOW_LOCAL = 0x05100000
WINDOW_BYTES = 0x02800000
WINDOW_ERASE_COUNT = 320  # 320 * 0x20000 == 0x02800000

# Recovery machinery inside mtd5 (local offsets; both EB-aligned).
FLAG_EB_LOCAL = 0x04D00000  # eraseblock 616
RECOVERY_ENV_LOCAL = 0x04900000  # eraseblock 584
RECOVERY_ENV_LEN = 0x10000  # 64 KiB

# Recovery flag byte values (s19k_write_recovery_flag.sh vocabulary).
FLAG_INSTALL_COMMIT = 0x01  # InstallArm / FirstBosThenSetFlag2
FLAG_STOCK_REVERT = 0x02  # UbootStockRevert / recover_to_stock (stock state)
FLAG_BOOT_SUCCESS = 0x03  # SuccessfulKeepBos / BootBos

FLAG_TAIL_ALL_FF_SHA256 = hashlib.sha256(b"\xff" * (ERASE_BLOCK - 1)).hexdigest()

# U-Boot stock partition view (live-probe-78 stock capture): nvdata spans
# global 0x04700000..0x10000000, exactly Linux mtd4 overlay + mtd5 system
# (0x02000000 + 0x09900000 == 0x0B900000 == the stock nvdata size). The
# ``nand erase.part nvdata`` inside recover_to_stock erases this whole span.
UBOOT_NVDATA_GLOBAL_START = PARTITION_BY_INDEX[4].offset
UBOOT_NVDATA_GLOBAL_END = PARTITION_BY_INDEX[5].offset + PARTITION_BY_INDEX[5].size

assert WINDOW_ERASE_COUNT * ERASE_BLOCK == WINDOW_BYTES
assert FLAG_EB_LOCAL % ERASE_BLOCK == 0
assert RECOVERY_ENV_LOCAL % ERASE_BLOCK == 0
assert UBOOT_NVDATA_GLOBAL_END - UBOOT_NVDATA_GLOBAL_START == 0x0B900000
assert PARTITION_BY_INDEX[5].erase_blocks == 1224


def proc_mtd_rows() -> str:
    """The exact six-row /proc/mtd text the geometry gate admits."""
    rows = ["dev:    size   erasesize  name"]
    rows.extend(
        f"mtd{pin.index}: {pin.size:08x} {ERASE_BLOCK:08x} {pin.name}"
        for pin in LINUX_PARTITIONS
    )
    return "\n".join(rows) + "\n"


# --- the simulated NAND bank ---------------------------------------------------------------


class SimNandError(RuntimeError):
    """A simulated physics/bounds/contract violation (the transaction failed)."""


def _tile(seed: str) -> bytes:
    """Deterministic 64 KiB tile (2048 chained sha256 digests)."""
    return b"".join(
        hashlib.sha256(f"{seed}:{i}".encode()).digest() for i in range(2048)
    )


_TILE_LEN = 64 * 1024
_STOCK_TILES = {
    f"mtd{pin.index}": _tile(f"STOCK:mtd{pin.index}") for pin in LINUX_PARTITIONS
}


class SimNandDevice:
    """One simulated MTD partition: erase-block granularity with loud
    erase-before-write discipline (a write into a span holding any non-0xFF
    byte fails exactly like the real writer must)."""

    def __init__(self, name: str, size: int, tile: bytes):
        if size <= 0 or size % ERASE_BLOCK:
            raise SimNandError(f"{name}: size {size:#x} is not erase-aligned")
        self.name = name
        self.size = size
        self._tile = tile
        self._data = bytearray(tile * (size // _TILE_LEN))
        if size % _TILE_LEN:
            self._data += tile[: size % _TILE_LEN]

    def stock_bytes(self, offset: int, length: int) -> bytes:
        """Pristine stock reference bytes at any span (tile phase from 0)."""
        self._bounds(offset, length)
        tile = self._tile
        out = bytearray()
        pos = 0
        while pos < length:
            phase = (offset + pos) % _TILE_LEN
            chunk = tile[phase : phase + min(length - pos, _TILE_LEN - phase)]
            out += chunk
            pos += len(chunk)
        return bytes(out)

    def _bounds(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise SimNandError(
                f"{self.name}: span {offset:#x}+{length:#x} exceeds size {self.size:#x}"
            )

    def erase(self, offset: int, length: int) -> None:
        self._bounds(offset, length)
        if offset % ERASE_BLOCK or length % ERASE_BLOCK:
            raise SimNandError(
                f"{self.name}: erase {offset:#x}/{length:#x} is not erase-block aligned"
            )
        self._data[offset : offset + length] = b"\xff" * length

    def write(self, offset: int, data: bytes) -> None:
        length = len(data)
        self._bounds(offset, length)
        if offset % ERASE_BLOCK:
            raise SimNandError(
                f"{self.name}: write offset {offset:#x} is not erase-block aligned"
            )
        span = bytes(self._data[offset : offset + length])
        if span.count(0xFF) != length:
            dirty = next(i for i, b in enumerate(span) if b != 0xFF)
            raise SimNandError(
                f"{self.name}: write at {offset:#x} programs non-erased flash "
                f"(byte {offset + dirty:#x} is not 0xFF) — erase-before-write violated"
            )
        self._data[offset : offset + length] = data

    def read(self, offset: int, length: int) -> bytes:
        self._bounds(offset, length)
        return bytes(self._data[offset : offset + length])

    def is_stock(self, offset: int = 0, length: Optional[int] = None) -> bool:
        if length is None:
            length = self.size - offset
        return self.read(offset, length) == self.stock_bytes(offset, length)

    def is_all_ff(self, offset: int, length: int) -> bool:
        return self.read(offset, length).count(0xFF) == length

    def snapshot(self) -> bytes:
        return bytes(self._data)


def _copy_device(device: SimNandDevice) -> SimNandDevice:
    clone = object.__new__(SimNandDevice)
    clone.name = device.name
    clone.size = device.size
    clone._tile = device._tile
    clone._data = bytearray(device._data)
    return clone


class SimNandBank:
    """The six-partition simulated bank (plus the U-Boot nvdata erase span)."""

    def __init__(self, devices: Optional[Dict[str, SimNandDevice]] = None):
        if devices is None:
            devices = {
                f"mtd{pin.index}": SimNandDevice(
                    f"mtd{pin.index}", pin.size, _STOCK_TILES[f"mtd{pin.index}"]
                )
                for pin in LINUX_PARTITIONS
            }
        self.devices = devices

    def __getitem__(self, name: str) -> SimNandDevice:
        return self.devices[name]

    def copy(self) -> "SimNandBank":
        return SimNandBank({name: _copy_device(d) for name, d in self.devices.items()})

    def preserved_stock(self, mutated: Sequence[str]) -> List[Dict[str, object]]:
        return [
            {
                "partition": name,
                "bytes": hex(device.size),
                "stock_byte_identical": device.is_stock(),
            }
            for name, device in sorted(
                self.devices.items(), key=lambda kv: int(kv[0][3:])
            )
            if name not in mutated
        ]

    def stock_chain_pristine(self) -> bool:
        """mtd0..mtd3 (bootloader, tpl, stock_system, stock_config) untouched."""
        return all(self.devices[f"mtd{i}"].is_stock() for i in range(4))

    def uboot_erase_part_nvdata(self) -> None:
        """``nand erase.part nvdata``: erase global 0x04700000..0x10000000,
        i.e. whole Linux mtd4 overlay + whole Linux mtd5 system."""
        self.devices["mtd4"].erase(0, self.devices["mtd4"].size)
        self.devices["mtd5"].erase(0, self.devices["mtd5"].size)


def build_pristine_bank() -> SimNandBank:
    """The pristine STOCK bank: stock tiles everywhere, plus the two recovery
    regions seeded to their admitted stock shapes — a CRC-valid 64 KiB
    nandrecovery_env image at local 0x04900000 (0xFF-padded to its EB) and
    the exclusive flag EB (byte0=0x02 + all-0xFF tail)."""
    bank = SimNandBank()
    env = make_env_image()
    bank["mtd5"].erase(RECOVERY_ENV_LOCAL, ERASE_BLOCK)
    bank["mtd5"].write(
        RECOVERY_ENV_LOCAL, env + b"\xff" * (ERASE_BLOCK - RECOVERY_ENV_LEN)
    )
    bank["mtd5"].erase(FLAG_EB_LOCAL, ERASE_BLOCK)
    bank["mtd5"].write(FLAG_EB_LOCAL, flag_candidate(FLAG_STOCK_REVERT))
    return bank


def flag_byte(bank: SimNandBank) -> int:
    return bank["mtd5"].read(FLAG_EB_LOCAL, 1)[0]


def classify_flag_byte(value: int) -> str:
    return {
        FLAG_INSTALL_COMMIT: "0x01_install_commit",
        FLAG_STOCK_REVERT: "0x02_stock_revert",
        FLAG_BOOT_SUCCESS: "0x03_boot_success",
        0xFF: "erased_0xFF",
    }.get(value, f"unknown_0x{value:02x}")


# --- payloads and recovery images -----------------------------------------------------------


def synthetic_root_payload(length: int) -> bytes:
    """Deterministic DCENT root payload tile (rehearsal bytes, not image bytes)."""
    tile = _tile("DCENT:s19k-rootfs")
    whole, tail = divmod(length, _TILE_LEN)
    data = tile * whole
    if tail:
        data += tile[:tail]
    return data


def make_env_image(body_text: bytes = b"recover=1\0\0") -> bytes:
    """A 64 KiB U-Boot env image: crc32(body) little-endian + body."""
    if len(body_text) > RECOVERY_ENV_LEN - 4:
        raise SimNandError("env body exceeds the 64 KiB image")
    body = body_text + b"\x00" * (RECOVERY_ENV_LEN - 4 - len(body_text))
    return zlib.crc32(body).to_bytes(4, "little") + body


def env_crc_ok(image: bytes) -> bool:
    if len(image) != RECOVERY_ENV_LEN:
        return False
    body = image[4:]
    return zlib.crc32(body).to_bytes(4, "little") == image[:4]


def flag_candidate(value: int) -> bytes:
    """The full-128-KiB flag EB rewrite candidate: value + all-0xFF tail."""
    if value not in (FLAG_INSTALL_COMMIT, FLAG_STOCK_REVERT, FLAG_BOOT_SUCCESS):
        raise SimNandError(f"refuse flag candidate 0x{value:02x}")
    return bytes([value]) + b"\xff" * (ERASE_BLOCK - 1)


def admit_exclusive_flag_eb(eb: bytes) -> None:
    """am3_geometry.sh dcent_am3_admit_recovery_flag_eraseblock_exclusive:
    byte0 must be a known flag value and the 131071-byte tail all-0xFF."""
    if len(eb) != ERASE_BLOCK:
        raise SimNandError(f"flag EB candidate is {len(eb)} bytes, want {ERASE_BLOCK}")
    if eb[0] not in (FLAG_INSTALL_COMMIT, FLAG_STOCK_REVERT, FLAG_BOOT_SUCCESS):
        raise SimNandError(f"flag EB byte0 0x{eb[0]:02x} is not 01/02/03")
    if hashlib.sha256(eb[1:]).hexdigest() != FLAG_TAIL_ALL_FF_SHA256:
        raise SimNandError("flag EB tail is not all-0xFF; one-byte rewrite unsafe")


# --- the typed transaction program ---------------------------------------------------------


@dataclass(frozen=True)
class TxnOp:
    op: str  # read | write | erase | verify | uboot
    leg: str  # backup | window | commit | rollback | restore
    partition: str  # mtdN | uboot:nvdata | artifact
    offset: int
    length: int
    note: str
    commit_window: bool = False  # True between flag-EB erase and flag verify

    def to_dict(self) -> dict:
        return asdict(self)


def install_program(payload_len: int) -> Tuple[TxnOp, ...]:
    padded = -(-payload_len // ERASE_BLOCK) * ERASE_BLOCK  # nandwrite -p pad
    if padded > WINDOW_BYTES:
        raise SimNandError(f"payload {payload_len:#x} exceeds the 0x02800000 window")
    ops: List[TxnOp] = []
    for pin in LINUX_PARTITIONS:
        ops.append(
            TxnOp(
                "read", "backup", f"mtd{pin.index}", 0, pin.size,
                f"nanddump --bb=padbad --omitoob duplicate read ({pin.backup_name})",
            )
        )
    ops.extend(
        (
            TxnOp("read", "backup", "artifact", 0, RECOVERY_ENV_LEN,
                  "nand_env.bak 64 KiB dd + crc32 admission"),
            TxnOp("read", "backup", "mtd5", RECOVERY_ENV_LOCAL, RECOVERY_ENV_LEN,
                  "slice nandrecovery_env.bin sidecar + crc32 admission"),
            TxnOp("read", "backup", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
                  "slice recovery_flag_eb.bin + exclusive-tail admission"),
            TxnOp("verify", "backup", "artifact", 0, 0,
                  "BACKUP_LEDGER.txt + FULL_RESCUE_LEDGER.txt six-MTD shape"),
        )
    )
    ops.extend(
        (
            TxnOp("verify", "window", "mtd5", FLAG_EB_LOCAL, 1,
                  "pre-mutation boundary: flag byte must still be 0x02"),
            TxnOp("erase", "window", "mtd5", WINDOW_LOCAL, WINDOW_BYTES,
                  f"flash_erase /dev/mtd5 0x05100000 {WINDOW_ERASE_COUNT}"),
            TxnOp("write", "window", "mtd5", WINDOW_LOCAL, padded,
                  "nandwrite -p -s 0x05100000 root (0xFF-padded to erase boundary)"),
            TxnOp("verify", "window", "mtd5", WINDOW_LOCAL, payload_len,
                  "nanddump readback span; sha256 == root payload sha256"),
        )
    )
    ops.extend(
        (
            TxnOp("read", "commit", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
                  "duplicate pre-write EB snapshots; cmp equal; byte0 == 0x02"),
            TxnOp("erase", "commit", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
                  "flash_erase the ONE flag eraseblock — commit window OPENS",
                  commit_window=True),
            TxnOp("write", "commit", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
                  "nandwrite full-128-KiB candidate byte0=0x01 (InstallArm)",
                  commit_window=True),
            TxnOp("verify", "commit", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
                  "full-EB byte compare + byte0 == 0x01 — commit window CLOSES",
                  commit_window=True),
        )
    )
    return tuple(ops)


def rollback_program() -> Tuple[TxnOp, ...]:
    return (
        TxnOp("read", "rollback", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
              "duplicate pre-write EB snapshots; cmp equal"),
        TxnOp("erase", "rollback", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
              "flash_erase the flag eraseblock for the 0x02 rewrite",
              commit_window=True),
        TxnOp("write", "rollback", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
              "nandwrite full-128-KiB candidate byte0=0x02 (UbootStockRevert)",
              commit_window=True),
        TxnOp("verify", "rollback", "mtd5", FLAG_EB_LOCAL, ERASE_BLOCK,
              "full-EB byte compare + byte0 == 0x02", commit_window=True),
        TxnOp("uboot", "rollback", "mtd5", RECOVERY_ENV_LOCAL, RECOVERY_ENV_LEN,
              "recover_env: nand read nandrecovery_env @0x04900000 -> RAM 0x01060000"),
        TxnOp("uboot", "rollback", "artifact", 0, 0,
              "env import 0x10000 (RAM only; crc32 must admit the env image)"),
        TxnOp("uboot", "rollback", "uboot:nvdata", UBOOT_NVDATA_GLOBAL_START,
              UBOOT_NVDATA_GLOBAL_END - UBOOT_NVDATA_GLOBAL_START,
              "nand erase.part nvdata (global 0x04700000..0x10000000 == mtd4+mtd5)"),
        TxnOp("uboot", "rollback", "artifact", 0, 0,
              "reset (vendor recover_to_stock done)"),
    )


def restore_program() -> Tuple[TxnOp, ...]:
    mtd5 = PARTITION_BY_INDEX[5].size
    return (
        TxnOp("verify", "restore", "artifact", 0, 0,
              "ledger re-admission: padbad/omitoob/duplicate + zero-bad-block policy"),
        TxnOp("erase", "restore", "mtd5", 0, mtd5,
              "flash_erase /dev/mtd5 0 1224 (whole partition)"),
        TxnOp("write", "restore", "mtd5", 0, mtd5,
              "nandwrite -p mtd5_pre_install.bin (full 0x09900000 image)"),
        TxnOp("verify", "restore", "mtd5", 0, mtd5,
              "nanddump readback byte-exact == mtd5_pre_install.bin"),
        TxnOp("verify", "restore", "artifact", 0, 0,
              "preserved check: mtd0..mtd4 byte-identical to the backup"),
    )


# --- leg 1: the backup artifact -------------------------------------------------------------


@dataclass
class BackupArtifact:
    """The six-MTD backup bundle shape (in memory; file names per the shared
    mtd{N}_{name}.padbad.bin contract)."""

    dumps: Dict[str, bytes] = field(default_factory=dict)
    dump_sha256: Dict[str, str] = field(default_factory=dict)
    mtd5_pre_install_bin: bytes = b""
    nand_env_bak: bytes = field(default_factory=make_env_image)
    nandrecovery_env_bin: bytes = b""
    recovery_flag_eb_bin: bytes = b""
    duplicate_read_equal: bool = False
    env_crc_ok: bool = False
    recovery_env_crc_ok: bool = False
    flag_eb_exclusive: bool = False

    def to_dict(self) -> dict:
        return {
            "dump_files": {
                name: {"bytes": len(data), "sha256": self.dump_sha256[name]}
                for name, data in sorted(self.dumps.items())
            },
            "mtd5_pre_install_bin_bytes": len(self.mtd5_pre_install_bin),
            "nand_env_bak_bytes": len(self.nand_env_bak),
            "nandrecovery_env_bin_bytes": len(self.nandrecovery_env_bin),
            "recovery_flag_eb_bin_bytes": len(self.recovery_flag_eb_bin),
            "duplicate_read_equal": self.duplicate_read_equal,
            "nand_env_crc_ok": self.env_crc_ok,
            "nandrecovery_env_crc_ok": self.recovery_env_crc_ok,
            "recovery_flag_eb_exclusive": self.flag_eb_exclusive,
            "bad_block_counts": "0-stable-all-six",
            "dump_mode": "padbad+omitoob",
        }


def capture_backup(bank: SimNandBank) -> BackupArtifact:
    """Leg 1: duplicate padbad/omitoob dumps of all six partitions plus the
    nand_env / nandrecovery_env / flag-EB sidecars. Read-only; raises
    SimNandError on any admission failure."""
    artifact = BackupArtifact()
    for pin in LINUX_PARTITIONS:
        device = bank[f"mtd{pin.index}"]
        first = device.read(0, pin.size)
        second = device.read(0, pin.size)  # duplicate read
        if first != second:
            raise SimNandError(f"mtd{pin.index} duplicate read mismatch")
        artifact.dumps[pin.backup_name] = first
        artifact.dump_sha256[pin.backup_name] = hashlib.sha256(first).hexdigest()
    artifact.duplicate_read_equal = True
    artifact.mtd5_pre_install_bin = artifact.dumps[PARTITION_BY_INDEX[5].backup_name]

    if not env_crc_ok(artifact.nand_env_bak):
        raise SimNandError("nand_env.bak crc32 mismatch")
    artifact.env_crc_ok = True

    env_sidecar = bank["mtd5"].read(RECOVERY_ENV_LOCAL, RECOVERY_ENV_LEN)
    if not env_crc_ok(env_sidecar):
        raise SimNandError("nandrecovery_env.bin sidecar crc32 mismatch")
    artifact.nandrecovery_env_bin = env_sidecar
    artifact.recovery_env_crc_ok = True

    flag_eb = bank["mtd5"].read(FLAG_EB_LOCAL, ERASE_BLOCK)
    admit_exclusive_flag_eb(flag_eb)
    artifact.recovery_flag_eb_bin = flag_eb
    artifact.flag_eb_exclusive = True
    return artifact


# --- the executor ---------------------------------------------------------------------------


@dataclass
class TxnRun:
    kind: str = "dcentos.s19k-aml-flash-transaction-sim/v1"
    transaction: str = "mtd5_rootfs_window_flag_commit"
    legs_proven: Tuple[str, ...] = ()
    ops: Tuple[dict, ...] = ()
    fault_cut: Optional[str] = None
    classification: str = ""
    operator_action: str = ""
    notes: Tuple[str, ...] = ()
    flag_byte: str = ""
    window_state: str = ""
    preserved_stock: Tuple[dict, ...] = ()
    backup: Optional[dict] = None
    all_verifies_green: bool = False
    clear_for_flash: bool = False
    simulation: bool = True
    device_contact: str = "none"
    network_contact: str = "none"
    authorizes_execution: bool = False
    persistent_write_authorized: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        out = asdict(self)
        out["legs_proven"] = list(self.legs_proven)
        out["ops"] = list(self.ops)
        out["notes"] = list(self.notes)
        out["preserved_stock"] = list(self.preserved_stock)
        return out


def _window_state(bank: SimNandBank, payload: bytes) -> str:
    span = bank["mtd5"].read(WINDOW_LOCAL, len(payload))
    if span == payload:
        return "dcent-payload-verified"
    padded = -(-len(payload) // ERASE_BLOCK) * ERASE_BLOCK
    if bank["mtd5"].is_all_ff(WINDOW_LOCAL, padded):
        return "erased-not-written"
    if bank["mtd5"].is_stock(WINDOW_LOCAL, len(payload)):
        return "stock-bytes"
    return "partial"


def _ledger(seq: int, op: TxnOp, detail: str, ok: bool) -> dict:
    return {
        "seq": seq,
        "op": op.op,
        "leg": op.leg,
        "partition": op.partition,
        "offset": f"{op.offset:#x}",
        "length": f"{op.length:#x}",
        "commit_window": op.commit_window,
        "note": op.note,
        "verified": ok,
        "detail": detail,
    }


def _execute_ops(
    bank: SimNandBank,
    ops: Sequence[TxnOp],
    payload: bytes,
    artifact: Optional[BackupArtifact],
    cut_after: Optional[int] = None,
) -> Tuple[List[dict], Optional[str]]:
    """Execute ops up to and including ``ops[cut_after]`` (nothing when
    cut_after < 0; everything when cut_after is None). Returns (ledger, error)."""
    ledger: List[dict] = []
    install_candidate = flag_candidate(FLAG_INSTALL_COMMIT)
    rollback_candidate = flag_candidate(FLAG_STOCK_REVERT)
    for seq, op in enumerate(ops):
        if cut_after is not None and seq > cut_after:
            break
        ok = True
        detail = ""
        try:
            if op.partition == "uboot:nvdata":
                # ``nand erase.part nvdata``: whole mtd4 overlay + whole mtd5
                # system, then an all-0xFF readback of the whole span.
                bank.uboot_erase_part_nvdata()
                ok = bank["mtd4"].is_all_ff(
                    0, bank["mtd4"].size
                ) and bank["mtd5"].is_all_ff(0, bank["mtd5"].size)
                detail = "nvdata span all-0xFF" if ok else "NVDATA ERASE INCOMPLETE"
            elif op.op == "read":
                if op.partition == "artifact":
                    # the nand_env.bak sidecar (modeled env image, not mtd5 bytes)
                    image = artifact.nand_env_bak if artifact is not None else make_env_image()
                    ok = len(image) == op.length and env_crc_ok(image)
                    detail = "nand_env.bak crc32 admitted" if ok else "NAND_ENV CRC FAIL"
                elif op.partition == "mtd5" and op.offset == RECOVERY_ENV_LOCAL:
                    image = bank[op.partition].read(op.offset, op.length)
                    ok = env_crc_ok(image)
                    detail = "crc32 admitted" if ok else "CRC MISMATCH"
                elif (
                    op.partition == "mtd5"
                    and op.offset == FLAG_EB_LOCAL
                    and op.length == ERASE_BLOCK
                ):
                    first = bank[op.partition].read(op.offset, op.length)
                    second = bank[op.partition].read(op.offset, op.length)
                    ok = first == second and first[0] in (
                        FLAG_INSTALL_COMMIT,
                        FLAG_STOCK_REVERT,
                        FLAG_BOOT_SUCCESS,
                    )
                    detail = (
                        f"duplicate-equal byte0=0x{first[0]:02x}"
                        if ok
                        else "unstable snapshot or unknown flag byte"
                    )
                else:
                    first = bank[op.partition].read(op.offset, op.length)
                    second = bank[op.partition].read(op.offset, op.length)
                    ok = first == second
                    detail = "duplicate read equal" if ok else "DUPLICATE MISMATCH"
            elif op.op == "erase":
                bank[op.partition].erase(op.offset, op.length)
                ok = bank[op.partition].is_all_ff(op.offset, op.length)
                detail = "readback all-0xFF" if ok else "READBACK NOT 0xFF"
            elif op.op == "write":
                if op.partition == "mtd5" and op.offset == FLAG_EB_LOCAL:
                    use = rollback_candidate if op.leg == "rollback" else install_candidate
                    bank[op.partition].write(op.offset, use)
                    ok = bank[op.partition].read(op.offset, op.length) == use
                    detail = "full-EB readback equal" if ok else "FULL-EB MISMATCH"
                elif (
                    op.partition == "mtd5"
                    and op.offset == 0
                    and op.length == PARTITION_BY_INDEX[5].size
                ):
                    if artifact is None:
                        raise SimNandError("restore without a backup artifact")
                    bank[op.partition].write(0, artifact.mtd5_pre_install_bin)
                    ok = True
                    detail = "full-image nandwrite complete"
                else:
                    padded = bytearray(payload)
                    padded += b"\xff" * (op.length - len(padded))
                    bank[op.partition].write(op.offset, bytes(padded))
                    ok = True
                    detail = "nandwrite -p complete (payload + 0xFF pad)"
            elif op.op == "verify":
                if op.partition == "mtd5" and op.offset == WINDOW_LOCAL:
                    got = bank[op.partition].read(op.offset, op.length)
                    ok = got == payload
                    detail = (
                        "readback sha256:"
                        + hashlib.sha256(got).hexdigest()[:16]
                        + "… == payload"
                        if ok
                        else "READBACK SHA MISMATCH"
                    )
                elif op.partition == "mtd5" and op.offset == FLAG_EB_LOCAL and op.length == ERASE_BLOCK:
                    use = rollback_candidate if op.leg == "rollback" else install_candidate
                    got = bank[op.partition].read(op.offset, op.length)
                    ok = got == use and got[0] == use[0]
                    detail = (
                        f"full-EB equal + byte0=0x{got[0]:02x}"
                        if ok
                        else f"FLAG EB MISMATCH (byte0=0x{got[0]:02x})"
                    )
                elif op.partition == "mtd5" and op.length == 1:
                    got = bank[op.partition].read(op.offset, 1)[0]
                    ok = got == FLAG_STOCK_REVERT
                    detail = (
                        f"flag byte0=0x{got:02x} == 0x02 pre-mutation"
                        if ok
                        else f"flag byte0=0x{got:02x} NOT 0x02 — REFUSING"
                    )
                elif "preserved" in op.note:
                    ok = artifact is not None and bank.stock_chain_pristine() and bank[
                        "mtd4"
                    ].is_stock()
                    detail = "mtd0..mtd4 byte-identical to backup" if ok else "PRESERVED DRIFT"
                else:
                    ok = artifact is not None and artifact.duplicate_read_equal
                    detail = "ledger shape admitted" if ok else "LEDGER REFUSED"
            elif op.op == "uboot":
                if op.partition == "mtd5":
                    image = bank[op.partition].read(op.offset, op.length)
                    ok = env_crc_ok(image)
                    detail = (
                        "nandrecovery_env read into RAM; crc32 ok"
                        if ok
                        else "ENV CRC FAIL"
                    )
                elif "env import" in op.note:
                    env = (
                        artifact.nandrecovery_env_bin
                        if artifact is not None
                        else bank["mtd5"].read(RECOVERY_ENV_LOCAL, RECOVERY_ENV_LEN)
                    )
                    ok = env_crc_ok(env)
                    detail = "env import 0x10000 (RAM)" if ok else "ENV IMPORT REFUSED"
                else:
                    ok = True
                    detail = op.note
            else:
                raise SimNandError(f"unknown op kind {op.op!r}")
        except SimNandError as exc:
            ledger.append(_ledger(seq, op, str(exc), False))
            return ledger, str(exc)
        ledger.append(_ledger(seq, op, detail, ok))
        if not ok:
            return ledger, (
                f"op {seq} ({op.op} {op.partition} @ {op.offset:#x}) failed: {detail}"
            )
    return ledger, None


def run_install_transaction(
    payload: Optional[bytes] = None,
    *,
    cut_after: Optional[int] = None,
    cut_label: Optional[str] = None,
    bank: Optional[SimNandBank] = None,
    artifact: Optional[BackupArtifact] = None,
) -> Tuple[TxnRun, SimNandBank]:
    """Legs 1-3 (backup, window write, flag commit). Returns (run, bank) so
    callers can seed the committed state without re-running."""
    if payload is None:
        payload = synthetic_root_payload(26_000_000)
    if bank is None:
        bank = build_pristine_bank()
    run = TxnRun(fault_cut=cut_label)
    try:
        if artifact is None:
            artifact = capture_backup(bank)
    except SimNandError as exc:
        run.error = str(exc)
        run.classification = "rehearsal_failed"
        return run, bank
    run.backup = artifact.to_dict()
    program = install_program(len(payload))
    ledger, error = _execute_ops(
        bank, program, payload, artifact, cut_after=cut_after
    )
    run.ops = tuple(ledger)
    run.flag_byte = classify_flag_byte(flag_byte(bank))
    run.window_state = _window_state(bank, payload)
    run.preserved_stock = tuple(bank.preserved_stock(["mtd5"]))
    if error is not None:
        run.error = error
        run.classification = "rehearsal_failed"
        return run, bank
    run.all_verifies_green = all(entry["verified"] for entry in ledger) and bool(ledger)
    if cut_after is None:
        run.classification = "transaction_complete"
        run.legs_proven = ("backup", "window", "commit")
        run.notes = (
            "backup: six-MTD padbad/omitoob duplicate dumps + CRC env sidecars + exclusive flag EB",
            "window: 320 EBs erased at local 0x05100000; payload+pad written and readback-verified",
            "commit: flag EB rewritten to 0x01 with full-128-KiB byte compare",
            "mtd0..mtd4 preserved stock-byte-identical throughout",
        )
        run.operator_action = (
            "proceed to the authenticated post-install witness (DCENT boots via "
            "FirstBosThenSetFlag2)"
        )
    return run, bank


def committed_bank(
    payload: Optional[bytes] = None,
) -> Tuple[SimNandBank, bytes]:
    """A pristine bank with the install transaction completed (flag 0x01)."""
    if payload is None:
        payload = synthetic_root_payload(26_000_000)
    run, bank = run_install_transaction(payload)
    if run.error or run.classification != "transaction_complete":
        raise SimNandError(
            f"cannot seed committed bank: {run.error or run.classification}"
        )
    return bank, payload


def run_rollback_transaction(
    bank: Optional[SimNandBank] = None,
    *,
    cut_after: Optional[int] = None,
    cut_label: Optional[str] = None,
) -> Tuple[TxnRun, SimNandBank]:
    """Leg 4: flag 0x02 rewrite + the U-Boot recover_to_stock choreography."""
    if bank is None:
        bank, _ = committed_bank()
    run = TxnRun(fault_cut=cut_label)
    program = rollback_program()
    ledger, error = _execute_ops(bank, program, b"", None, cut_after=cut_after)
    run.ops = tuple(ledger)
    run.flag_byte = classify_flag_byte(flag_byte(bank))
    mtd4_erased = bank["mtd4"].is_all_ff(0, bank["mtd4"].size)
    run.notes = tuple(
        (
            "mtd0..mtd3 stock-byte-identical through the rollback"
            if bank.stock_chain_pristine()
            else "STOCK CHAIN TOUCHED — MUST NEVER HAPPEN",
            f"mtd4 overlay {'erased (inside nvdata span)' if mtd4_erased else 'stock'}",
            "the nandrecovery_env image is read into RAM BEFORE the nvdata erase "
            "consumes its on-NAND copy",
            "the vendor nvdata erase also consumes the flag EB: the FINAL flag "
            "state after a complete rollback is erased (0xFF), with 0x02 verified "
            "mid-transaction at the rewrite boundary",
        )
    )
    run.preserved_stock = tuple(bank.preserved_stock(["mtd4", "mtd5"]))
    if error is not None:
        run.error = error
        run.classification = "rehearsal_failed"
        return run, bank
    run.all_verifies_green = all(entry["verified"] for entry in ledger) and bool(ledger)
    if cut_after is None:
        run.classification = "rollback_complete_stock_boots"
        run.legs_proven = ("rollback",)
        run.operator_action = (
            "unit reboots into stock via vendor recover_to_stock; verify stock boot, "
            "then decide re-install vs closeout"
        )
    return run, bank


def run_restore_transaction(
    backup: Optional[BackupArtifact] = None,
    *,
    bank: Optional[SimNandBank] = None,
    cut_after: Optional[int] = None,
    cut_label: Optional[str] = None,
) -> Tuple[TxnRun, SimNandBank]:
    """Leg 5: full-mtd5 restore from the backup artifact; the bank returns to
    pristine bytes and mtd0..mtd4 are proven untouched."""
    pristine = build_pristine_bank()
    if backup is None:
        backup = capture_backup(pristine)
    if bank is None:
        # a realistic broken state: window half-written, flag EB erased
        bank = build_pristine_bank()
        bank["mtd5"].erase(WINDOW_LOCAL, WINDOW_BYTES)
        bank["mtd5"].write(WINDOW_LOCAL, synthetic_root_payload(3 * ERASE_BLOCK))
        bank["mtd5"].erase(FLAG_EB_LOCAL, ERASE_BLOCK)
    run = TxnRun(fault_cut=cut_label)
    program = restore_program()
    ledger, error = _execute_ops(bank, program, b"", backup, cut_after=cut_after)
    run.ops = tuple(ledger)
    run.flag_byte = classify_flag_byte(flag_byte(bank))
    run.preserved_stock = tuple(bank.preserved_stock(["mtd5"]))
    byte_exact = bank["mtd5"].snapshot() == backup.mtd5_pre_install_bin
    run.notes = tuple(
        (
            f"mtd5 byte-exact vs mtd5_pre_install.bin: {byte_exact}",
            "mtd0..mtd4 byte-identical to the backup",
        )
    )
    if error is not None:
        run.error = error
        run.classification = "rehearsal_failed"
        return run, bank
    run.all_verifies_green = (
        all(entry["verified"] for entry in ledger) and bool(ledger) and byte_exact
    )
    if cut_after is None:
        run.classification = "restore_verified_bank_pristine"
        run.legs_proven = ("restore",)
        run.operator_action = (
            "bank is byte-pristine again; unit boots stock; retain the backup artifact"
        )
    return run, bank


# --- fault classification -------------------------------------------------------------------


def _classify_install_cut(
    program: Sequence[TxnOp], cut: int, bank: SimNandBank, payload: bytes
) -> Tuple[str, str, Tuple[str, ...]]:
    """Read the bank and classify a power cut after ``cut`` ops."""
    flag_erase_pos = next(
        i for i, op in enumerate(program) if op.leg == "commit" and op.op == "erase"
    )
    flag_verify_pos = next(
        i for i, op in enumerate(program) if op.leg == "commit" and op.op == "verify"
    )
    window_state = _window_state(bank, payload)
    stock_chain = bank.stock_chain_pristine()
    notes = [
        f"window region: {window_state}",
        f"recovery flag byte: {classify_flag_byte(flag_byte(bank))}",
        "stock boot chain mtd0..mtd3 byte-identical: "
        + ("yes" if stock_chain else "NO (SIM BUG)"),
    ]
    if cut < flag_erase_pos:
        return (
            "before_commit_boots_stock",
            "no operator recovery required to stay safe: the flag is still 0x02 so "
            "the unit boots stock via recover_to_stock; re-run install from a fresh "
            "backup, or restore mtd5 from the retained backup artifact",
            tuple(notes),
        )
    if cut < flag_verify_pos:
        return (
            "inside_commit_window_flag_erased",
            "STOP: the flag EB is erased (or holds an unverified 0x01) and U-Boot's "
            "dispatch for a non-01/02/03 flag byte is NOT pinned by held evidence. "
            "Do not assume a boot outcome; the safe rail is the restore-from-backup "
            "transaction (flash_erase whole mtd5 + nandwrite mtd5_pre_install.bin)",
            tuple(
                notes
                + [
                    "the DCENT payload itself is already readback-verified at this "
                    "point; only the flag EB state is ambiguous",
                ]
            ),
        )
    return (
        "after_commit_dcent_boots",
        "flag 0x01 written and full-EB verified: U-Boot FirstBosThenSetFlag2 boots "
        "the DCENT window; proceed to the authenticated post-install witness; the "
        "rollback rail remains flag 0x02 -> recover_to_stock",
        tuple(notes),
    )


def install_fault_sweep(
    payload: Optional[bytes] = None,
    *,
    intra_window: bool = True,
) -> List[dict]:
    """One power cut at every op boundary of the install transaction (plus
    progress cuts inside the 320-EB window erase and the padded nandwrite)."""
    if payload is None:
        payload = synthetic_root_payload(26_000_000)
    program = install_program(len(payload))
    entries: List[dict] = []
    base = build_pristine_bank()
    artifact = capture_backup(base)
    for cut in range(-1, len(program)):
        bank = base.copy()
        run, _ = run_install_transaction(
            payload, cut_after=cut, bank=bank, artifact=artifact
        )
        if run.error is not None:
            entries.append(
                {
                    "cut": cut,
                    "ops_executed": cut + 1,
                    "bucket": "rehearsal_failed",
                    "error": run.error,
                    "flag_byte": run.flag_byte,
                }
            )
            continue
        if cut < 0:
            bucket = "before_commit_boots_stock"
            action = (
                "nothing was written; the whole bank is stock-byte-identical — "
                "re-run from the top"
            )
            extra: Tuple[str, ...] = ("zero ops executed; bank pristine",)
        else:
            bucket, action, extra = _classify_install_cut(program, cut, bank, payload)
        entries.append(
            {
                "cut": cut,
                "ops_executed": cut + 1,
                "bucket": bucket,
                "operator_action": action,
                "flag_byte": classify_flag_byte(flag_byte(bank)),
                "window_state": _window_state(bank, payload),
                "stock_chain_pristine_mtd0_3": bank.stock_chain_pristine(),
                "notes": list(extra),
            }
        )
    if intra_window:
        erase_pos = next(
            i for i, op in enumerate(program) if op.leg == "window" and op.op == "erase"
        )
        write_pos = next(
            i for i, op in enumerate(program) if op.leg == "window" and op.op == "write"
        )
        padded = -(-len(payload) // ERASE_BLOCK) * ERASE_BLOCK
        write_ebs = padded // ERASE_BLOCK
        progress: List[Tuple[str, int, int]] = [
            ("erase+80EB", erase_pos, 80),
            ("erase+160EB", erase_pos, 160),
            ("erase+240EB", erase_pos, 240),
            ("erase+319EB", erase_pos, 319),
            ("write+25%", write_pos, max(1, write_ebs // 4)),
            ("write+50%", write_pos, max(1, write_ebs // 2)),
            ("write+75%", write_pos, max(1, 3 * write_ebs // 4)),
        ]
        for label, pos, ebs in progress:
            bank = base.copy()
            run, _ = run_install_transaction(
                payload, cut_after=pos - 1, bank=bank, artifact=artifact
            )
            if run.error is not None:
                entries.append(
                    {
                        "cut": f"{pos}:{label}",
                        "bucket": "rehearsal_failed",
                        "error": run.error,
                    }
                )
                continue
            device = bank["mtd5"]
            if pos == erase_pos:
                device.erase(WINDOW_LOCAL, ebs * ERASE_BLOCK)
                state = "partial-erase (mixed stock/0xFF)"
            else:
                done = min(ebs * ERASE_BLOCK, len(payload))
                device.write(WINDOW_LOCAL, payload[:done])
                state = "partial-write (mixed 0xFF/dcent-bytes)"
            bucket, action, _ = _classify_install_cut(program, pos - 1, bank, payload)
            entries.append(
                {
                    "cut": f"{pos}:{label}",
                    "ops_executed": pos,
                    "bucket": bucket,
                    "operator_action": action,
                    "flag_byte": classify_flag_byte(flag_byte(bank)),
                    "window_state": state,
                    "stock_chain_pristine_mtd0_3": bank.stock_chain_pristine(),
                    "notes": [f"intra-op progress cut inside op {pos} ({label})"],
                }
            )
    return entries


def rollback_fault_sweep(payload: Optional[bytes] = None) -> List[dict]:
    """One power cut at every op boundary of the rollback transaction, run
    from the committed (flag 0x01) state."""
    program = rollback_program()
    entries: List[dict] = []
    seed, used_payload = committed_bank(payload)
    nvdata_pos = next(
        i for i, op in enumerate(program) if op.partition == "uboot:nvdata"
    )
    for cut in range(-1, len(program)):
        bank = seed.copy()
        run, _ = run_rollback_transaction(bank, cut_after=cut)
        if run.error is not None:
            entries.append(
                {
                    "cut": cut,
                    "ops_executed": cut + 1,
                    "bucket": "rehearsal_failed",
                    "error": run.error,
                    "flag_byte": run.flag_byte,
                }
            )
            continue
        mtd4_erased = bank["mtd4"].is_all_ff(0, bank["mtd4"].size)
        mtd5_erased = bank["mtd5"].is_all_ff(0, bank["mtd5"].size)
        if cut < 0:
            bucket = "rollback_partial_stock_boots"
            action = "nothing rolled back yet; flag still 0x01; unit still boots DCENT"
        elif cut < nvdata_pos:
            bucket = "rollback_partial_stock_boots"
            action = (
                "flag rewritten toward 0x02 (or inside its one-EB window); the stock "
                "chain is untouched; on reboot U-Boot recover_to_stock runs or is "
                "re-armed — complete the rollback; restore-from-backup remains the fallback"
            )
        else:
            bucket = "rollback_complete_stock_boots"
            action = (
                "recover_to_stock choreography complete (or its nvdata erase in "
                "progress); stock boots from the untouched stock partitions; re-run "
                "the rollback if the nvdata erase was cut"
            )
        entries.append(
            {
                "cut": cut,
                "ops_executed": cut + 1,
                "bucket": bucket,
                "operator_action": action,
                "flag_byte": classify_flag_byte(flag_byte(bank)),
                "mtd4_overlay_erased": mtd4_erased,
                "mtd5_system_erased": mtd5_erased,
                "stock_chain_pristine_mtd0_3": bank.stock_chain_pristine(),
                "window_state": _window_state(bank, used_payload),
            }
        )
    return entries


def restore_fault_sweep() -> List[dict]:
    """One power cut at every op boundary of the restore transaction."""
    pristine = build_pristine_bank()
    backup = capture_backup(pristine)
    entries: List[dict] = []
    for cut in range(-1, len(restore_program())):
        bank = pristine.copy()
        bank["mtd5"].erase(WINDOW_LOCAL, WINDOW_BYTES)  # a broken state to repair
        run, _ = run_restore_transaction(backup, bank=bank, cut_after=cut)
        restored = bank["mtd5"].snapshot() == backup.mtd5_pre_install_bin
        entries.append(
            {
                "cut": cut,
                "ops_executed": cut + 1,
                "bucket": (
                    "restore_partial_rerunnable"
                    if not restored
                    else "restore_verified_bank_pristine"
                ),
                "operator_action": (
                    "the restore IS the recovery rail: re-run the restore "
                    "transaction until the byte-exact readback passes"
                    if not restored
                    else "bank byte-pristine; unit boots stock"
                ),
                "flag_byte": classify_flag_byte(flag_byte(bank)),
                "mtd5_byte_exact": restored,
                "stock_chain_pristine_mtd0_3": bank.stock_chain_pristine(),
                "error": run.error,
            }
        )
    return entries


# --- CLI ------------------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline NAND simulation of the typed S19k Pro mtd5 flash transaction "
            "(backup, window write, flag commit, rollback, restore). Simulation "
            "only; CLEAR_FOR_FLASH stays false."
        )
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--sweeps",
        action="store_true",
        help="also run the full fault sweeps (install/rollback/restore)",
    )
    args = parser.parse_args(argv)

    install, _ = run_install_transaction()
    seed, _ = committed_bank()
    rollback, _ = run_rollback_transaction(seed.copy())
    restore, _ = run_restore_transaction()
    report: Dict[str, object] = {
        "kind": "dcentos.s19k-aml-flash-transaction-sim/v1",
        "transaction": "mtd5_rootfs_window_flag_commit",
        "geometry": {
            "proc_mtd": proc_mtd_rows(),
            "mtd5_base": hex(MTD5_BASE),
            "window": {
                "local": hex(WINDOW_LOCAL),
                "bytes": hex(WINDOW_BYTES),
                "erase_blocks": WINDOW_ERASE_COUNT,
            },
            "flag_eb_local": hex(FLAG_EB_LOCAL),
            "nandrecovery_env_local": hex(RECOVERY_ENV_LOCAL),
            "uboot_nvdata_span": [
                hex(UBOOT_NVDATA_GLOBAL_START),
                hex(UBOOT_NVDATA_GLOBAL_END),
            ],
            "erasesize": ERASE_BLOCK,
        },
        "install": install.to_dict(),
        "rollback": rollback.to_dict(),
        "restore": restore.to_dict(),
        "clear_for_flash": False,
        "simulation": True,
        "device_contact": "none",
        "network_contact": "none",
        "authorizes_execution": False,
    }
    if args.sweeps:
        report["install_fault_matrix"] = install_fault_sweep()
        report["rollback_fault_matrix"] = rollback_fault_sweep()
        report["restore_fault_matrix"] = restore_fault_sweep()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"install: {install.classification} flag={install.flag_byte} "
            f"window={install.window_state}"
        )
        print(f"rollback: {rollback.classification} flag={rollback.flag_byte}")
        print(f"restore: {restore.classification} flag={restore.flag_byte}")
        print("clear_for_flash=false simulation=true device_contact=none")
    ok = (
        install.all_verifies_green
        and rollback.all_verifies_green
        and restore.all_verifies_green
        and install.clear_for_flash is False
    )
    print(
        "S19K_AML_FLASH_TRANSACTION_SIM_OK"
        if ok
        else "S19K_AML_FLASH_TRANSACTION_SIM_FAILED"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
