#!/usr/bin/env python3
"""Verify a copied S19k AML recovery rehearsal without hardware contact.

The evidence contract proves that one separately-authorized stock-recovery
rehearsal completed before any DCENT_OS write.  It binds the exact AML NAND
layout, duplicate offset-preserving backups, post-restore readbacks, the held
Bitmain-signed stock BMU, and an independent witness.  A successful result is
recovery evidence only: it never grants mutation or persistent-install
authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple


CONTRACT_SCHEMA = "dcentos.s19k-persistent-recovery-evidence/v1"
AUTHORITY_SCHEMA = "dcentos.s19k-stock-recovery-mutation-authority/v1"
DEVICE_SCHEMA = "dcentos.s19k-persistent-recovery-device/v1"
LAYOUT_SCHEMA = "dcentos.s19k-aml-partition-layout/v1"
BACKUP_SCHEMA = "dcentos.s19k-offset-exact-backup/v1"
REHEARSAL_SCHEMA = "dcentos.s19k-stock-restore-rehearsal/v1"
WITNESS_SCHEMA = "dcentos.s19k-stock-restore-independent-witness/v1"
RESULT_SCHEMA = "dcentos.s19k-persistent-recovery-verification/v1"

CONTRACT_FILE = "contract.json"
AUTHORITY_FILE = "mutation_authority.json"
DEVICE_FILE = "device_identity.json"
LAYOUT_FILE = "partition_layout.json"
PROC_MTD_FILE = "proc_mtd.txt"
BACKUP_FILE = "backup_manifest.json"
REHEARSAL_FILE = "rehearsal.json"
WITNESS_FILE = "independent_witness.json"
VERIFICATION_FILE = "verification.json"
BACKUP_DIR = "backup"
READBACK_DIR = "restored_readback"

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_AUTHORITY_WINDOW_SECONDS = 60 * 60
HEX64 = re.compile(r"[0-9a-f]{64}")
ACTOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}")
SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


@dataclass(frozen=True)
class PartitionSpec:
    index: int
    name: str
    offset: int
    size: int
    erasesize: int

    @property
    def backup_name(self) -> str:
        return f"mtd{self.index}_{self.name}.padbad.bin"


@dataclass(frozen=True)
class StockBmuContract:
    filename: str
    size: int
    sha256: str
    aml_record_size: int
    aml_record_sha256: str


@dataclass(frozen=True)
class LeafEvidence:
    size: int
    sha256: str
    data: Optional[bytes]


PARTITIONS: Tuple[PartitionSpec, ...] = (
    PartitionSpec(0, "bootloader", 0x00000000, 0x00200000, 0x00020000),
    # Held .78 dmesg is authoritative for physical offsets: the 6 MiB
    # global-address hole follows the 2 MiB bootloader, so tpl begins at
    # 0x00800000.  /proc/mtd alone contains sizes, not these global offsets.
    # Source:
    # 00-system/cap_init/dmesg.before, lines 368-370 and 485-499.
    PartitionSpec(1, "tpl", 0x00800000, 0x00800000, 0x00020000),
    PartitionSpec(2, "stock_system", 0x01000000, 0x03200000, 0x00020000),
    PartitionSpec(3, "stock_config", 0x04200000, 0x00500000, 0x00020000),
    PartitionSpec(4, "overlay", 0x04700000, 0x02000000, 0x00020000),
    PartitionSpec(5, "system", 0x06700000, 0x09900000, 0x00020000),
)
STOCK_BMU = StockBmuContract(
    filename="Antminer-S19k-Pro-merge-release-20240409060820.bmu",
    size=43_786_317,
    sha256="286cd2eb8a1940ba3dfa6211fb96bfb5d68329acd69fd78891af8b4d74ef3fbe",
    aml_record_size=12_930_048,
    aml_record_sha256="fb14eda438e5d48deed684d1d501068cc71aad46ef21b4b31b5f56f631be767f",
)

EVENTS = (
    "authority-admitted",
    "backup-captured",
    "backup-duplicate-read-verified",
    "signed-stock-fileparser-admitted",
    "signed-stock-restore-applied",
    "signed-stock-boot-verified",
    "original-partitions-restored",
    "restored-readback-verified",
    "original-stock-boot-verified",
    "terminal-safeoff-verified",
)


class PersistentRecoveryError(ValueError):
    """The copied evidence does not prove the recovery rehearsal contract."""


def fail(message: str) -> None:
    raise PersistentRecoveryError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_measure(
    path: Path, label: str, maximum: int, *, retain: bool
) -> LeafEvidence:
    try:
        before = os.lstat(path)
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        fail(
            f"{label} must be a non-empty bounded regular single-link file"
        )
    digest = hashlib.sha256()
    retained = bytearray() if retain else None
    observed_size = 0
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            observed_size += len(block)
            digest.update(block)
            if retained is not None:
                retained.extend(block)
    try:
        after = os.lstat(path)
    except OSError as error:
        fail(f"cannot restat {label}: {error}")
    identity = lambda item: (  # noqa: E731
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_mode,
    )
    if identity(before) != identity(after) or observed_size != before.st_size:
        fail(f"{label} changed while it was read")
    return LeafEvidence(
        size=observed_size,
        sha256=digest.hexdigest(),
        data=bytes(retained) if retained is not None else None,
    )


def _stable_file(path: Path, label: str, maximum: int) -> bytes:
    measured = _stable_measure(path, label, maximum, retain=True)
    assert measured.data is not None
    return measured.data


def _read_json(path: Path, label: str) -> Tuple[bytes, Dict[str, Any]]:
    raw = _stable_file(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not canonical ASCII JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    if raw != canonical_json(value):
        fail(f"{label} is not canonical JSON")
    return raw, value


def _keys(value: Mapping[str, Any], expected: Sequence[str], label: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        fail(
            f"{label} keys are inexact: missing={sorted(wanted - actual)} "
            f"extra={sorted(actual - wanted)}"
        )


def _require(value: Mapping[str, Any], key: str, expected: Any, label: str) -> None:
    if value.get(key) != expected or type(value.get(key)) is not type(expected):
        fail(f"{label} {key} must be exactly {expected!r}")


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _actor(value: Any, label: str) -> str:
    if not isinstance(value, str) or ACTOR_ID.fullmatch(value) is None:
        fail(f"{label} is not a canonical actor identifier")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        fail(f"{label} must be UTC with whole-second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        fail(f"{label} is not a real timestamp: {error}")


def _holes(partitions: Sequence[PartitionSpec]) -> list[dict[str, int]]:
    holes: list[dict[str, int]] = []
    end = 0
    for part in partitions:
        if part.offset > end:
            holes.append({"offset": end, "bytes": part.offset - end})
        if part.offset < end:
            fail("partition contract overlaps")
        end = part.offset + part.size
    return holes


def _proc_mtd_bytes(partitions: Sequence[PartitionSpec]) -> bytes:
    rows = ["dev:    size   erasesize  name"]
    rows.extend(
        f'mtd{part.index}: {part.size:08x} {part.erasesize:08x} "{part.name}"'
        for part in partitions
    )
    return ("\n".join(rows) + "\n").encode("ascii")


def _leaf_names(
    partitions: Sequence[PartitionSpec], stock: StockBmuContract
) -> set[str]:
    names = {
        AUTHORITY_FILE,
        DEVICE_FILE,
        LAYOUT_FILE,
        PROC_MTD_FILE,
        BACKUP_FILE,
        REHEARSAL_FILE,
        WITNESS_FILE,
        stock.filename,
    }
    names.update(f"{BACKUP_DIR}/{part.backup_name}" for part in partitions)
    names.update(f"{READBACK_DIR}/{part.backup_name}" for part in partitions)
    return names


def _validate_static_contract(
    partitions: Sequence[PartitionSpec], stock: StockBmuContract
) -> None:
    if not partitions:
        fail("partition contract is empty")
    if Path(stock.filename).name != stock.filename or not stock.filename.endswith(".bmu"):
        fail("stock BMU contract filename is unsafe")
    _hex64(stock.sha256, "stock BMU contract sha256")
    _hex64(stock.aml_record_sha256, "stock AML record contract sha256")
    if stock.size <= 0 or stock.aml_record_size <= 0:
        fail("stock BMU contract sizes must be positive")
    for expected_index, part in enumerate(partitions):
        if part.index != expected_index:
            fail("partition contract indices must be contiguous from zero")
        if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", part.name) is None:
            fail(f"partition contract name is unsafe: {part.name!r}")
        if (
            part.offset < 0
            or part.size <= 0
            or part.erasesize <= 0
            or part.offset % part.erasesize != 0
            or part.size % part.erasesize != 0
        ):
            fail(f"partition contract geometry is not eraseblock-aligned: mtd{part.index}")
    _holes(partitions)


def _verify_directory_shape(
    evidence_dir: Path,
    partitions: Sequence[PartitionSpec],
    stock: StockBmuContract,
) -> None:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail("evidence directory must be a real non-link directory")
    required_top = {
        CONTRACT_FILE,
        AUTHORITY_FILE,
        DEVICE_FILE,
        LAYOUT_FILE,
        PROC_MTD_FILE,
        BACKUP_FILE,
        REHEARSAL_FILE,
        WITNESS_FILE,
        stock.filename,
        BACKUP_DIR,
        READBACK_DIR,
    }
    observed = {child.name for child in evidence_dir.iterdir()}
    allowed = required_top | {VERIFICATION_FILE}
    if not required_top.issubset(observed) or not observed.issubset(allowed):
        fail(
            "evidence directory entry set is inexact: "
            f"missing={sorted(required_top - observed)} "
            f"extra={sorted(observed - allowed)}"
        )
    for directory_name in (BACKUP_DIR, READBACK_DIR):
        directory = evidence_dir / directory_name
        if not directory.is_dir() or directory.is_symlink():
            fail(f"{directory_name} must be a real non-link directory")
        wanted = {part.backup_name for part in partitions}
        found = {child.name for child in directory.iterdir()}
        if found != wanted:
            fail(
                f"{directory_name} entry set is inexact: "
                f"missing={sorted(wanted - found)} extra={sorted(found - wanted)}"
            )


def _read_and_bind_leaves(
    evidence_dir: Path,
    contract: Mapping[str, Any],
    partitions: Sequence[PartitionSpec],
    stock: StockBmuContract,
) -> Dict[str, LeafEvidence]:
    expected_names = _leaf_names(partitions, stock)
    files = contract.get("files")
    if not isinstance(files, dict) or set(files) != expected_names:
        fail("contract files table does not name the exact evidence leaf set")
    sizes = {
        f"{BACKUP_DIR}/{part.backup_name}": part.size for part in partitions
    }
    sizes.update(
        {f"{READBACK_DIR}/{part.backup_name}": part.size for part in partitions}
    )
    sizes[stock.filename] = stock.size
    retained_names = {
        AUTHORITY_FILE,
        DEVICE_FILE,
        LAYOUT_FILE,
        PROC_MTD_FILE,
        BACKUP_FILE,
        REHEARSAL_FILE,
        WITNESS_FILE,
    }
    raw: Dict[str, LeafEvidence] = {}
    for name in sorted(expected_names):
        record = files.get(name)
        if not isinstance(record, dict):
            fail(f"contract identity for {name} must be an object")
        _keys(record, ("bytes", "sha256"), f"contract identity {name}")
        if (
            not isinstance(record.get("bytes"), int)
            or isinstance(record.get("bytes"), bool)
            or record["bytes"] <= 0
        ):
            fail(f"contract identity bytes for {name} must be a positive integer")
        _hex64(record.get("sha256"), f"contract identity sha256 for {name}")
        maximum = sizes.get(name, MAX_JSON_BYTES)
        measured = _stable_measure(
            evidence_dir / Path(name),
            name,
            maximum,
            retain=name in retained_names,
        )
        observed = {"bytes": measured.size, "sha256": measured.sha256}
        if record != observed:
            fail(f"contract identity mismatch for {name}")
        if name in sizes and measured.size != sizes[name]:
            fail(f"{name} byte length does not match the admitted contract")
        if name == stock.filename and observed["sha256"] != stock.sha256:
            fail("signed stock BMU identity does not match the admitted contract")
        raw[name] = measured
    return raw


def _verify_authority(
    value: Mapping[str, Any], session_id: str, device_id: str
) -> Tuple[str, str, datetime, datetime]:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "authority_id",
            "operator_id",
            "scope",
            "issued_utc",
            "expires_utc",
            "single_use",
            "rehearsal_mutation_authorized",
            "separate_from_dcentos_install",
            "dcentos_write_authorized",
            "persistent_install_authorized",
        ),
        "mutation authority",
    )
    for key, expected in (
        ("schema", AUTHORITY_SCHEMA),
        ("session_id", session_id),
        ("device_id", device_id),
        ("scope", "signed-stock-recovery-rehearsal-only"),
        ("single_use", True),
        ("rehearsal_mutation_authorized", True),
        ("separate_from_dcentos_install", True),
        ("dcentos_write_authorized", False),
        ("persistent_install_authorized", False),
    ):
        _require(value, key, expected, "mutation authority")
    authority_id = _hex64(value.get("authority_id"), "authority_id")
    if authority_id == session_id:
        fail("authority_id must be separate from the rehearsal session_id")
    operator_id = _actor(value.get("operator_id"), "operator_id")
    issued = _utc(value.get("issued_utc"), "authority issued_utc")
    expires = _utc(value.get("expires_utc"), "authority expires_utc")
    if issued >= expires:
        fail("mutation authority expiry must follow issuance")
    if (expires - issued).total_seconds() > MAX_AUTHORITY_WINDOW_SECONDS:
        fail("mutation authority window exceeds one hour")
    return authority_id, operator_id, issued, expires


def _verify_device(
    value: Mapping[str, Any], session_id: str, nand_total_bytes: int
) -> str:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "serial",
            "model",
            "platform",
            "board_target",
            "soc",
            "pcb",
            "nand_device",
            "nand_total_bytes",
            "nand_identity_sha256",
        ),
        "device identity",
    )
    expected = {
        "schema": DEVICE_SCHEMA,
        "session_id": session_id,
        "model": "Antminer S19k Pro",
        "platform": "am3-aml-s19k",
        "board_target": "am3-s19k",
        "soc": "A113D/AXG",
        "pcb": "C81",
        "nand_device": "raw-nand",
        "nand_total_bytes": nand_total_bytes,
    }
    for key, wanted in expected.items():
        _require(value, key, wanted, "device identity")
    device_id = _hex64(value.get("device_id"), "device_id")
    if not isinstance(value.get("serial"), str) or SERIAL.fullmatch(value["serial"]) is None:
        fail("device serial is not canonical")
    _hex64(value.get("nand_identity_sha256"), "nand_identity_sha256")
    return device_id


def _verify_layout(
    value: Mapping[str, Any],
    session_id: str,
    device_id: str,
    proc_mtd: bytes,
    partitions: Sequence[PartitionSpec],
) -> None:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "source",
            "proc_mtd_file",
            "proc_mtd_sha256",
            "nand_total_bytes",
            "holes",
            "partitions",
        ),
        "partition layout",
    )
    for key, expected in (
        ("schema", LAYOUT_SCHEMA),
        ("session_id", session_id),
        ("device_id", device_id),
        ("source", "captured-proc-mtd-plus-global-offset-map"),
        ("proc_mtd_file", PROC_MTD_FILE),
        ("proc_mtd_sha256", _hash(proc_mtd)),
        ("nand_total_bytes", partitions[-1].offset + partitions[-1].size),
        ("holes", _holes(partitions)),
    ):
        _require(value, key, expected, "partition layout")
    if proc_mtd != _proc_mtd_bytes(partitions):
        fail("proc_mtd.txt is not the exact admitted partition table")
    rows = value.get("partitions")
    if not isinstance(rows, list) or len(rows) != len(partitions):
        fail("partition layout must contain the exact partition count")
    for row, part in zip(rows, partitions):
        if not isinstance(row, dict):
            fail("partition layout row must be an object")
        expected = {
            "index": part.index,
            "name": part.name,
            "device": f"mtd{part.index}",
            "offset": part.offset,
            "bytes": part.size,
            "erasesize": part.erasesize,
        }
        if row != expected:
            fail(f"partition layout row mtd{part.index} is not exact")


def _verify_backup(
    value: Mapping[str, Any],
    session_id: str,
    device_id: str,
    partitions: Sequence[PartitionSpec],
    leaves: Mapping[str, LeafEvidence],
) -> list[dict[str, Any]]:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "capture_mode",
            "logical_offsets_preserved",
            "oob",
            "duplicate_streams",
            "stable_zero_bad_blocks_required",
            "backup_complete_before_dcentos_write",
            "dcentos_write_count_at_capture",
            "partitions",
        ),
        "backup manifest",
    )
    for key, expected in (
        ("schema", BACKUP_SCHEMA),
        ("session_id", session_id),
        ("device_id", device_id),
        ("capture_mode", "nanddump-padbad"),
        ("logical_offsets_preserved", True),
        ("oob", "omitted-ecc-regenerated"),
        ("duplicate_streams", True),
        ("stable_zero_bad_blocks_required", True),
        ("backup_complete_before_dcentos_write", True),
        ("dcentos_write_count_at_capture", 0),
    ):
        _require(value, key, expected, "backup manifest")
    rows = value.get("partitions")
    if not isinstance(rows, list) or len(rows) != len(partitions):
        fail("backup manifest must contain the exact partition count")
    verified: list[dict[str, Any]] = []
    for row, part in zip(rows, partitions):
        if not isinstance(row, dict):
            fail("backup manifest partition row must be an object")
        _keys(
            row,
            (
                "index",
                "name",
                "offset",
                "bytes",
                "erasesize",
                "bad_blocks_before",
                "bad_blocks_after",
                "backup_file",
                "backup_sha256",
                "duplicate_read_sha256",
            ),
            f"backup mtd{part.index}",
        )
        backup_name = f"{BACKUP_DIR}/{part.backup_name}"
        digest = leaves[backup_name].sha256
        expected = {
            "index": part.index,
            "name": part.name,
            "offset": part.offset,
            "bytes": part.size,
            "erasesize": part.erasesize,
            "bad_blocks_before": 0,
            "bad_blocks_after": 0,
            "backup_file": backup_name,
            "backup_sha256": digest,
            "duplicate_read_sha256": digest,
        }
        if row != expected:
            fail(f"backup manifest row mtd{part.index} is not exact")
        readback_name = f"{READBACK_DIR}/{part.backup_name}"
        readback_digest = leaves[readback_name].sha256
        if readback_digest != digest:
            fail(f"mtd{part.index} restored readback does not equal its backup bytes")
        verified.append(
            {
                "index": part.index,
                "name": part.name,
                "offset": part.offset,
                "bytes": part.size,
                "sha256": digest,
            }
        )
    return verified


def _load_stock_verifier() -> Any:
    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    verifier_path = tools_dir / "verify_stock_bmu.py"
    if not verifier_path.is_file() or verifier_path.is_symlink():
        fail("tracked verify_stock_bmu.py is absent or unsafe")
    name = "dcent_s19k_persistent_stock_verifier"
    spec = importlib.util.spec_from_file_location(name, verifier_path)
    if spec is None or spec.loader is None:
        fail("cannot load tracked stock BMU verifier")
    old_path = list(sys.path)
    try:
        sys.path.insert(0, os.fspath(tools_dir))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as error:
        fail(f"cannot import tracked stock BMU verifier: {error}")
    finally:
        sys.path[:] = old_path
    return module


def verify_signed_stock_bmu(
    path: Path, contract: StockBmuContract = STOCK_BMU
) -> Dict[str, Any]:
    measured = _stable_measure(
        path, "signed stock BMU", contract.size, retain=False
    )
    if measured.size != contract.size or measured.sha256 != contract.sha256:
        fail("signed stock BMU identity mismatch")
    module = _load_stock_verifier()
    try:
        backend = module.CryptoBackend("cryptography")
        verdict = module.verify_path(os.fspath(path), backend)
    except ImportError as error:
        fail(f"signed stock verification requires cryptography: {error}")
    except Exception as error:
        fail(f"signed stock BMU verification failed: {error}")
    if verdict.get("overall") != "PASS":
        fail("signed stock BMU package-level RSA verification failed")
    merge = verdict.get("merge")
    if not isinstance(merge, dict) or merge.get("crc32_ok") is not True:
        fail("signed stock BMU merge CRC verification failed")
    records = verdict.get("records")
    if not isinstance(records, list) or len(records) != 3:
        fail("signed stock BMU does not contain the exact three control-board records")
    aml = next(
        (
            row
            for row in records
            if isinstance(row, dict) and row.get("subtype") == "AMLCtrl_BHB56XXX"
        ),
        None,
    )
    if not isinstance(aml, dict):
        fail("signed stock BMU AMLCtrl_BHB56XXX record is absent")
    checks = aml.get("checks")
    if not isinstance(checks, dict):
        fail("signed stock AML record checks are absent")
    bmu_signature = checks.get("bmu_signature")
    miner_type = checks.get("miner_type_hash")
    if (
        aml.get("record_size") != contract.aml_record_size
        or aml.get("record_sha256") != contract.aml_record_sha256
        or aml.get("model") != "Antminer S19k Pro"
        or aml.get("components_all_ok") is not True
        or not isinstance(bmu_signature, dict)
        or bmu_signature.get("ok") is not True
        or not isinstance(miner_type, dict)
        or miner_type.get("ok") is not True
        or not str(aml.get("verdict", "")).startswith("PASS")
    ):
        fail("signed stock AML record identity or internal RSA chain failed")
    root = checks.get("root_verifies_miner_pem")
    root_held = isinstance(root, dict) and root.get("ok") is True
    return {
        "signature_classification": (
            "bitmain-rsa-aml-internal-chain-plus-device-fileparser"
        ),
        "merge_crc32_verified": True,
        "three_control_board_records_verified": True,
        "aml_record_sha256": contract.aml_record_sha256,
        "aml_component_signatures_verified": True,
        "aml_bmu_signature_verified": True,
        "aml_root_anchor_held": root_held,
    }


def _verify_rehearsal(
    value: Mapping[str, Any],
    session_id: str,
    device_id: str,
    authority_id: str,
    authority_sha: str,
    layout_sha: str,
    backup_sha: str,
    stock: StockBmuContract,
    issued: datetime,
    expires: datetime,
) -> None:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "authority_id",
            "authority_sha256",
            "layout_sha256",
            "backup_manifest_sha256",
            "stock_bmu_file",
            "stock_bmu_sha256",
            "stock_bmu_bytes",
            "stock_fileparser_subtype",
            "stock_fileparser_signature_verified",
            "stock_restore_completed",
            "stock_boot_model",
            "stock_boot_platform",
            "original_restore_method",
            "original_restore_completed",
            "original_stock_boot_verified",
            "terminal_safeoff_verified",
            "dcentos_write_attempted",
            "dcentos_write_count",
            "events",
        ),
        "rehearsal",
    )
    for key, expected in (
        ("schema", REHEARSAL_SCHEMA),
        ("session_id", session_id),
        ("device_id", device_id),
        ("authority_id", authority_id),
        ("authority_sha256", authority_sha),
        ("layout_sha256", layout_sha),
        ("backup_manifest_sha256", backup_sha),
        ("stock_bmu_file", stock.filename),
        ("stock_bmu_sha256", stock.sha256),
        ("stock_bmu_bytes", stock.size),
        ("stock_fileparser_subtype", "AMLCtrl_BHB56XXX"),
        ("stock_fileparser_signature_verified", True),
        ("stock_restore_completed", True),
        ("stock_boot_model", "Antminer S19k Pro"),
        ("stock_boot_platform", "am3-aml-s19k"),
        ("original_restore_method", "erase-write-each-partition-then-padbad-readback"),
        ("original_restore_completed", True),
        ("original_stock_boot_verified", True),
        ("terminal_safeoff_verified", True),
        ("dcentos_write_attempted", False),
        ("dcentos_write_count", 0),
    ):
        _require(value, key, expected, "rehearsal")
    events = value.get("events")
    if not isinstance(events, list) or len(events) != len(EVENTS):
        fail("rehearsal must contain the exact ordered event set")
    previous: Optional[datetime] = None
    for sequence, (event, name) in enumerate(zip(events, EVENTS), start=1):
        if not isinstance(event, dict):
            fail("rehearsal event must be an object")
        expected_keys = ("sequence", "name", "utc", "dcentos_write_count")
        _keys(event, expected_keys, f"rehearsal event {sequence}")
        _require(event, "sequence", sequence, f"rehearsal event {sequence}")
        _require(event, "name", name, f"rehearsal event {sequence}")
        _require(event, "dcentos_write_count", 0, f"rehearsal event {sequence}")
        observed = _utc(event.get("utc"), f"rehearsal event {sequence} utc")
        if observed < issued or observed > expires:
            fail("rehearsal event falls outside the separate authority window")
        if previous is not None and observed <= previous:
            fail("rehearsal event timestamps must increase strictly")
        previous = observed


def _verify_witness(
    value: Mapping[str, Any],
    session_id: str,
    device_id: str,
    authority_id: str,
    operator_id: str,
    authority_sha: str,
    layout_sha: str,
    backup_sha: str,
    rehearsal_sha: str,
    stock: StockBmuContract,
    partitions: Sequence[PartitionSpec],
    verified_partitions: Sequence[Mapping[str, Any]],
) -> str:
    _keys(
        value,
        (
            "schema",
            "session_id",
            "device_id",
            "authority_id",
            "operator_id",
            "observer_id",
            "authority_sha256",
            "layout_sha256",
            "backup_manifest_sha256",
            "rehearsal_sha256",
            "stock_bmu_sha256",
            "stock_fileparser_signature_verified",
            "restored_readbacks",
            "stock_boot_model",
            "stock_boot_platform",
            "rehearsal_complete",
            "original_bytes_restored",
            "terminal_safeoff_verified",
            "dcentos_write_observed",
            "mutation_authority_granted",
        ),
        "independent witness",
    )
    for key, expected in (
        ("schema", WITNESS_SCHEMA),
        ("session_id", session_id),
        ("device_id", device_id),
        ("authority_id", authority_id),
        ("operator_id", operator_id),
        ("authority_sha256", authority_sha),
        ("layout_sha256", layout_sha),
        ("backup_manifest_sha256", backup_sha),
        ("rehearsal_sha256", rehearsal_sha),
        ("stock_bmu_sha256", stock.sha256),
        ("stock_fileparser_signature_verified", True),
        ("stock_boot_model", "Antminer S19k Pro"),
        ("stock_boot_platform", "am3-aml-s19k"),
        ("rehearsal_complete", True),
        ("original_bytes_restored", True),
        ("terminal_safeoff_verified", True),
        ("dcentos_write_observed", False),
        ("mutation_authority_granted", False),
    ):
        _require(value, key, expected, "independent witness")
    observer_id = _actor(value.get("observer_id"), "observer_id")
    if observer_id == operator_id:
        fail("independent witness must differ from the mutation operator")
    readbacks = value.get("restored_readbacks")
    expected_readbacks = {
        f"{READBACK_DIR}/{part.backup_name}": row["sha256"]
        for part, row in zip(partitions, verified_partitions)
    }
    if readbacks != expected_readbacks:
        fail("independent witness restored-readback identities are inexact")
    return observer_id


def verify_evidence(
    evidence_dir: Path,
    *,
    partitions: Sequence[PartitionSpec] = PARTITIONS,
    stock: StockBmuContract = STOCK_BMU,
    stock_verifier: Callable[[Path, StockBmuContract], Mapping[str, Any]] = (
        verify_signed_stock_bmu
    ),
) -> Dict[str, Any]:
    """Freshly verify one complete, copied, host-only rehearsal bundle."""
    _validate_static_contract(partitions, stock)
    _verify_directory_shape(evidence_dir, partitions, stock)
    contract_raw, contract = _read_json(
        evidence_dir / CONTRACT_FILE, "evidence contract"
    )
    _keys(
        contract,
        (
            "schema",
            "session_id",
            "claim",
            "publication",
            "dcentos_write_attempted",
            "dcentos_write_count",
            "files",
        ),
        "evidence contract",
    )
    for key, expected in (
        ("schema", CONTRACT_SCHEMA),
        ("claim", "pre-dcentos-write-stock-recovery-rehearsal"),
        ("publication", "post-rehearsal-content-manifest"),
        ("dcentos_write_attempted", False),
        ("dcentos_write_count", 0),
    ):
        _require(contract, key, expected, "evidence contract")
    session_id = _hex64(contract.get("session_id"), "session_id")
    leaves = _read_and_bind_leaves(evidence_dir, contract, partitions, stock)

    json_values: Dict[str, Dict[str, Any]] = {}
    for name, label in (
        (AUTHORITY_FILE, "mutation authority"),
        (DEVICE_FILE, "device identity"),
        (LAYOUT_FILE, "partition layout"),
        (BACKUP_FILE, "backup manifest"),
        (REHEARSAL_FILE, "rehearsal"),
        (WITNESS_FILE, "independent witness"),
    ):
        try:
            data = leaves[name].data
            if data is None:
                fail(f"internal error: {label} bytes were not retained")
            value = json.loads(data.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"{label} is not canonical ASCII JSON: {error}")
        if not isinstance(value, dict) or data != canonical_json(value):
            fail(f"{label} is not a canonical JSON object")
        json_values[name] = value

    device_id = _verify_device(
        json_values[DEVICE_FILE],
        session_id,
        partitions[-1].offset + partitions[-1].size,
    )
    authority_id, operator_id, issued, expires = _verify_authority(
        json_values[AUTHORITY_FILE], session_id, device_id
    )
    _verify_layout(
        json_values[LAYOUT_FILE],
        session_id,
        device_id,
        leaves[PROC_MTD_FILE].data or b"",
        partitions,
    )
    verified_partitions = _verify_backup(
        json_values[BACKUP_FILE], session_id, device_id, partitions, leaves
    )
    signature = dict(stock_verifier(evidence_dir / stock.filename, stock))
    required_signature_keys = {
        "signature_classification",
        "merge_crc32_verified",
        "three_control_board_records_verified",
        "aml_record_sha256",
        "aml_component_signatures_verified",
        "aml_bmu_signature_verified",
        "aml_root_anchor_held",
    }
    if set(signature) != required_signature_keys:
        fail("stock verifier returned an inexact result")
    if signature.get("signature_classification") != (
        "bitmain-rsa-aml-internal-chain-plus-device-fileparser"
    ):
        fail("stock verifier returned an unknown signature classification")
    if not isinstance(signature.get("aml_root_anchor_held"), bool):
        fail("stock verifier AML root-anchor disposition is not boolean")
    if any(
        signature.get(key) is not True
        for key in (
            "merge_crc32_verified",
            "three_control_board_records_verified",
            "aml_component_signatures_verified",
            "aml_bmu_signature_verified",
        )
    ):
        fail("stock verifier did not prove the signed AML record")
    if signature.get("aml_record_sha256") != stock.aml_record_sha256:
        fail("stock verifier AML record identity mismatch")

    authority_sha = leaves[AUTHORITY_FILE].sha256
    layout_sha = leaves[LAYOUT_FILE].sha256
    backup_sha = leaves[BACKUP_FILE].sha256
    rehearsal_sha = leaves[REHEARSAL_FILE].sha256
    _verify_rehearsal(
        json_values[REHEARSAL_FILE],
        session_id,
        device_id,
        authority_id,
        authority_sha,
        layout_sha,
        backup_sha,
        stock,
        issued,
        expires,
    )
    observer_id = _verify_witness(
        json_values[WITNESS_FILE],
        session_id,
        device_id,
        authority_id,
        operator_id,
        authority_sha,
        layout_sha,
        backup_sha,
        rehearsal_sha,
        stock,
        partitions,
        verified_partitions,
    )

    result: Dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "claim": "stock-recovery-rehearsed-before-any-dcentos-write",
        "session_id": session_id,
        "device_id": device_id,
        "authority_id": authority_id,
        "operator_id": operator_id,
        "observer_id": observer_id,
        "contract_sha256": _hash(contract_raw),
        "layout_sha256": layout_sha,
        "backup_manifest_sha256": backup_sha,
        "rehearsal_sha256": rehearsal_sha,
        "witness_sha256": leaves[WITNESS_FILE].sha256,
        "stock_bmu": {
            "sha256": stock.sha256,
            "bytes": stock.size,
            **signature,
        },
        "partitions": verified_partitions,
        "separate_mutation_authority_verified": True,
        "stock_restore_rehearsal_verified": True,
        "original_bytes_restored": True,
        "terminal_safeoff_verified": True,
        "dcentos_write_observed": False,
        "dcentos_write_authorized": False,
        "mutation_authority_granted": False,
    }
    result["verification_id"] = _hash(canonical_json(result))
    receipt = evidence_dir / VERIFICATION_FILE
    if receipt.exists():
        if _stable_file(receipt, "workflow verification receipt", MAX_JSON_BYTES) != (
            canonical_json(result)
        ):
            fail("workflow verification receipt is stale or noncanonical")
    return result


def verify_workflow_evidence(evidence_dir: Path) -> Dict[str, Any]:
    """Entry point consumed by ``s19k_gauntlet_workflow.py``."""
    return verify_evidence(evidence_dir)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_evidence(args.evidence_dir.resolve(strict=True))
    except (OSError, PersistentRecoveryError) as error:
        print(f"S19K_PERSISTENT_RECOVERY_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    print(
        "S19K_PERSISTENT_RECOVERY_OK "
        f"verification_id={result['verification_id']} "
        "mutation_authority_granted=false dcentos_write_authorized=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
