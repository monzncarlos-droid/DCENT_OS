#!/usr/bin/env python3
"""Build an offline-only DCENT_OS K210 pipeline sentinel candidate.

This host tool compiles the minimal RISC-V sentinel, audits its ELF loading
contract, extracts a raw application binary, and delegates the byte-exact K210
wrapper/AUP-v2 construction to ``k210_gauntlet.py``. It has no miner transport
and deliberately produces an artifact that is not authorized for installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import k210_gauntlet


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_ROOT = PROJECT_ROOT / "k210-firmware"
BIN_NAME = "dcent-k210-safe-idle-sentinel"
TARGET = "riscv64gc-unknown-none-elf"
TOOLCHAIN = "1.90.0"
K210_ROM_LOAD_BASE = 0x8000_0000
K210_CACHED_RAM_BYTES = 6 * 1024 * 1024
ELF_MACHINE_RISCV = 243
ELF_PT_LOAD = 1


class BuildError(RuntimeError):
    """A candidate build or ELF admission invariant failed."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_k210_elf(data: bytes) -> Dict[str, Any]:
    """Verify the exact ELF64 little-endian RISC-V loading facts we rely on."""

    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise BuildError("candidate is not an ELF file")
    if data[4] != 2:
        raise BuildError(f"candidate ELF class is {data[4]}, expected ELF64")
    if data[5] != 1:
        raise BuildError(
            f"candidate ELF byte order is {data[5]}, expected little-endian"
        )
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 2:
        raise BuildError(f"candidate ELF type is {elf_type}, expected executable")
    if machine != ELF_MACHINE_RISCV:
        raise BuildError(f"candidate ELF machine is {machine}, expected RISC-V")

    entry = struct.unpack_from("<Q", data, 24)[0]
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_entry_size = struct.unpack_from("<H", data, 54)[0]
    program_count = struct.unpack_from("<H", data, 56)[0]
    if entry != K210_ROM_LOAD_BASE:
        raise BuildError(
            f"candidate ELF entry is 0x{entry:016x}, expected 0x{K210_ROM_LOAD_BASE:016x}"
        )
    if program_entry_size < 56 or program_count == 0:
        raise BuildError("candidate ELF has no usable program-header table")
    program_end = program_offset + program_entry_size * program_count
    if program_offset < 64 or program_end > len(data):
        raise BuildError("candidate ELF program-header table exceeds the file")

    load_segments = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        segment_type, flags = struct.unpack_from("<II", data, offset)
        if segment_type != ELF_PT_LOAD:
            continue
        file_offset, virtual_address, physical_address, file_size, memory_size = (
            struct.unpack_from("<QQQQQ", data, offset + 8)
        )
        if file_size > memory_size:
            raise BuildError(
                f"candidate ELF PT_LOAD {index} has filesz greater than memsz"
            )
        if file_offset + file_size > len(data):
            raise BuildError(f"candidate ELF PT_LOAD {index} exceeds the file")
        memory_end = virtual_address + memory_size
        if (
            virtual_address < K210_ROM_LOAD_BASE
            or memory_end < virtual_address
            or memory_end > K210_ROM_LOAD_BASE + K210_CACHED_RAM_BYTES
        ):
            raise BuildError(
                f"candidate ELF PT_LOAD {index} exceeds the cached-RAM contract"
            )
        if physical_address != virtual_address:
            raise BuildError(
                f"candidate ELF PT_LOAD {index} physical/virtual addresses differ"
            )
        load_segments.append(
            {
                "index": index,
                "flags": flags,
                "file_offset": file_offset,
                "virtual_address": f"0x{virtual_address:016x}",
                "physical_address": f"0x{physical_address:016x}",
                "file_size": file_size,
                "memory_size": memory_size,
            }
        )

    if not load_segments:
        raise BuildError("candidate ELF has no PT_LOAD segment")
    if not any(
        int(segment["virtual_address"], 16) == K210_ROM_LOAD_BASE
        and segment["file_size"] > 0
        and segment["flags"] & 1
        for segment in load_segments
    ):
        raise BuildError(
            "candidate ELF has no executable file-backed PT_LOAD at 0x80000000"
        )

    return {
        "class": "ELF64",
        "byte_order": "little-endian",
        "machine": "RISC-V",
        "entry": f"0x{entry:016x}",
        "load_segments": load_segments,
    }


def _run(command: Sequence[str], cwd: Optional[Path] = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "") or ""
        raise BuildError(
            f"command failed: {' '.join(command)}\n{stderr.strip()}"
        ) from exc
    return result.stdout.strip()


def find_llvm_objcopy() -> Path:
    sysroot = Path(_run(["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"]))
    verbose = _run(["rustc", f"+{TOOLCHAIN}", "-vV"])
    host = next(
        (
            line.removeprefix("host:").strip()
            for line in verbose.splitlines()
            if line.startswith("host:")
        ),
        "",
    )
    if not host:
        raise BuildError("rustc did not report a host triple")
    suffix = ".exe" if os.name == "nt" else ""
    tool = sysroot / "lib" / "rustlib" / host / "bin" / f"llvm-objcopy{suffix}"
    if not tool.is_file():
        raise BuildError(
            f"missing {tool}; install llvm-tools-preview for Rust {TOOLCHAIN}"
        )
    return tool


def build_candidate(
    model: str, firmware_version: str, output_dir: Path, overwrite: bool
) -> Dict[str, Any]:
    safe_model = model.lower()
    stem = f"dcent-k210-{safe_model}-safe-idle.experimental"
    aup_path = output_dir / f"{stem}.aup"
    receipt_path = output_dir / f"{stem}.receipt.json"
    raw_path = output_dir / f"{stem}.bin"
    paths = (aup_path, receipt_path, raw_path)
    if not overwrite:
        existing = [str(path) for path in paths if path.exists()]
        if existing:
            raise BuildError(
                f"refusing to overwrite existing output: {', '.join(existing)}"
            )

    _run(
        [
            "cargo",
            f"+{TOOLCHAIN}",
            "build",
            "--locked",
            "--release",
            "--target",
            TARGET,
            "--features",
            "safe-idle-sentinel",
            "--bin",
            BIN_NAME,
        ],
        cwd=FIRMWARE_ROOT,
    )
    elf_path = FIRMWARE_ROOT / "target" / TARGET / "release" / BIN_NAME
    if not elf_path.is_file():
        raise BuildError(f"cargo did not produce {elf_path}")
    elf_bytes = elf_path.read_bytes()
    elf_contract = inspect_k210_elf(elf_bytes)

    objcopy = find_llvm_objcopy()
    rustc_verbose = _run(["rustc", f"+{TOOLCHAIN}", "-vV"])
    cargo_verbose = _run(["cargo", f"+{TOOLCHAIN}", "-Vv"])
    lock_path = FIRMWARE_ROOT / "Cargo.lock"
    if not lock_path.is_file():
        raise BuildError(f"missing locked dependency graph {lock_path}")
    lock_sha256 = _sha256_file(lock_path)
    objcopy_sha256 = _sha256_file(objcopy)
    with tempfile.TemporaryDirectory(prefix="dcent-k210-candidate-") as directory:
        extracted_path = Path(directory) / "sentinel.bin"
        _run([str(objcopy), "-O", "binary", str(elf_path), str(extracted_path)])
        app = extracted_path.read_bytes()
    manifest = k210_gauntlet.load_manifest()
    aup, receipt = k210_gauntlet.build_candidate_package(
        manifest, safe_model, app, firmware_version
    )
    receipt["builder"] = {
        "kind": "safe_idle_pipeline_sentinel",
        "source_crate": str(FIRMWARE_ROOT.relative_to(k210_gauntlet.REPO_ROOT)).replace(
            "\\", "/"
        ),
        "rust_toolchain": TOOLCHAIN,
        "rustc_verbose": rustc_verbose,
        "cargo_verbose": cargo_verbose,
        "cargo_locked": True,
        "cargo_lock_sha256": lock_sha256,
        "llvm_objcopy_sha256": objcopy_sha256,
        "target": TARGET,
        "elf_bytes": len(elf_bytes),
        "elf_sha256": hashlib.sha256(elf_bytes).hexdigest(),
        "elf_contract": elf_contract,
        "raw_path": raw_path.name,
        "raw_sha256": hashlib.sha256(app).hexdigest(),
        "safety_scope": (
            "No board I/O; this cannot assert fans or hash-power off and is not physically safe."
        ),
    }
    encoded_receipt = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(app)
    aup_path.write_bytes(aup)
    receipt_path.write_text(encoded_receipt, encoding="utf-8")
    if _sha256_file(aup_path) != receipt["aup_sha256"]:
        raise BuildError("written AUP digest disagrees with its receipt")
    return {
        "aup": str(aup_path),
        "receipt": str(receipt_path),
        "raw": str(raw_path),
        "aup_sha256": receipt["aup_sha256"],
        "disposition": receipt["disposition"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model", required=True, help="confirmed physical-model manifest ID"
    )
    parser.add_argument("--firmware-version", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--experimental-aes0",
        action="store_true",
        help="acknowledge that AES0 bootability is unmeasured and no install is authorized",
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.experimental_aes0:
        print(
            "K210_BUILD_ERROR: candidate creation requires --experimental-aes0; "
            "target bootability is unmeasured",
            file=sys.stderr,
        )
        return 2
    try:
        result = build_candidate(
            args.model, args.firmware_version, args.out_dir, args.overwrite
        )
    except (BuildError, k210_gauntlet.GauntletError) as exc:
        print(f"K210_BUILD_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
