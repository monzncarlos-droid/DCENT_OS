#!/usr/bin/env python3
"""Isolated equality-gated signer for S19k hermetic release packages.

The signer consumes two exact public unsigned intermediates and their clean
build receipts.  It proves byte equality and validates every public package,
receipt, release-key, native-owner, and stock-recovery input before the first
operation on the private-key path.  It then opens that key exactly once, adds
only ``MANIFEST.sig``, and publishes one no-replace deterministic output stage.

This component has manifest-signing authority for one exact pair only.  It has
no network, install, flash, reboot, target-contact, or mutation authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from typing import Any, NoReturn, Sequence


MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
INCOMPLETE_SENTINEL = ".dcentos-s19k-signing-incomplete"


class SigningError(RuntimeError):
    """One equality, custody, derivation, or publication gate failed."""


def fail(message: str) -> NoReturn:
    raise SigningError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _read_public_regular(path: Path, maximum: int, label: str) -> bytes:
    path = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing")
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a direct regular file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        fail(f"{label} is empty or oversized")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size != metadata.st_size
        ):
            fail(f"{label} changed before open")
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    if len(data) != metadata.st_size or len(data) > maximum:
        fail(f"{label} changed during read")
    if (after.st_dev, after.st_ino, after.st_size) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
    ):
        fail(f"{label} changed during read")
    return data


def _read_private_key_once(path: Path) -> bytes:
    """First and only private-path operation; call only after public admission."""

    path = Path(os.path.abspath(os.fspath(path)))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"private signing key could not be opened after public admission: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("private signing key is not a direct regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_KEY_BYTES:
            fail("private signing key is empty or oversized")
        if os.name != "nt" and metadata.st_mode & 0o077:
            fail("private signing key permissions expose group/other access")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                fail("private signing key was truncated during its one read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail("private signing key grew during its one read")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            fail("private signing key changed during its one read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_verifier(path: Path) -> Any:
    path = Path(os.path.abspath(os.fspath(path)))
    _read_public_regular(path, MAX_JSON_BYTES, "admitted persistent-image verifier")
    spec = importlib.util.spec_from_file_location(
        f"s19k_persistent_image_verify_signer_{_sha256(os.fspath(path).encode())}",
        path,
    )
    if spec is None or spec.loader is None:
        fail("cannot load admitted persistent-image verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        fail(f"admitted persistent-image verifier could not load: {error}")
    for name in (
        "validate_unsigned_build_pair",
        "_parse_package",
        "_validate_package_public_contract",
        "_verify_signed_derivation",
    ):
        if not callable(getattr(module, name, None)):
            fail(f"admitted persistent-image verifier lacks {name}")
    return module


def _sign_manifest(private_raw: bytes, public_raw: bytes, manifest: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        private = serialization.load_pem_private_key(private_raw, password=None)
        public = serialization.load_pem_public_key(public_raw)
    except (ImportError, TypeError, ValueError) as error:
        fail(f"release Ed25519 key material is invalid: {error}")
    if not isinstance(private, Ed25519PrivateKey) or not isinstance(
        public, Ed25519PublicKey
    ):
        fail("release keypair must use Ed25519")
    derived = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    selected = public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if derived != selected:
        fail("release private key does not match the admitted public key")
    signature = private.sign(manifest)
    if len(signature) != 64:
        fail("Ed25519 signer did not emit one exact 64-byte signature")
    try:
        public.verify(signature, manifest)
    except Exception as error:
        fail(f"new manifest signature did not self-verify: {error}")
    return signature


def _build_signed_tar(verifier: Any, unsigned: Any, signature: bytes) -> bytes:
    by_name = {
        verifier._safe_tar_path(member.name): member for member in unsigned.members
    }
    epoch = unsigned.files[verifier.PACKAGE_MANIFEST_PATH]
    manifest = verifier._json_bytes(epoch, "release manifest", canonical=False)
    source_date_epoch = manifest.get("provenance", {}).get("source_date_epoch")
    if isinstance(source_date_epoch, bool) or not isinstance(source_date_epoch, int):
        fail("release manifest source_date_epoch is not an integer")
    names = [
        verifier.PREFIX,
        *sorted(set(unsigned.files) | {verifier.PACKAGE_SIGNATURE_PATH}),
    ]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            if name == verifier.PACKAGE_SIGNATURE_PATH:
                member = tarfile.TarInfo(name)
                member.size = len(signature)
                member.mode = 0o644
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                member.mtime = source_date_epoch
                archive.addfile(member, io.BytesIO(signature))
                continue
            source = by_name.get(name)
            if source is None:
                fail(f"unsigned tar member disappeared before signing: {name}")
            member = tarfile.TarInfo(name)
            member.mode = source.mode
            member.uid = source.uid
            member.gid = source.gid
            member.uname = source.uname
            member.gname = source.gname
            member.mtime = source.mtime
            if source.isdir():
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                value = unsigned.files[name]
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
    result = output.getvalue()
    if len(result) > MAX_PACKAGE_BYTES:
        fail("signed release package exceeds the package-size bound")
    return result


def _write_new(path: Path, data: bytes, *, mode: int = 0o400) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail(f"short write while publishing {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class SigningResult:
    stage: Path
    package: Path
    receipt: Path
    signing_id: str


def sign_equal_unsigned_pair(
    build_a: Path,
    build_b: Path,
    build_a_receipt: Path,
    build_b_receipt: Path,
    public_key: Path,
    native_owner_receipt: Path,
    stock_recovery_receipt: Path,
    private_key: Path,
    output_stage: Path,
    *,
    expected_release_key_sha256: str,
    verifier: Any,
    strict_durability: bool = True,
) -> SigningResult:
    """Sign one exact equal pair; the private path is untouched until admitted."""

    if not HEX_64.fullmatch(expected_release_key_sha256):
        fail("expected release-key SHA-256 must be lowercase hex")

    # Load and validate every public byte first.  Keep this block above the
    # sole call to _read_private_key_once; adversarial tests pin that cutpoint.
    unsigned_a = _read_public_regular(build_a, MAX_PACKAGE_BYTES, "build A unsigned package")
    unsigned_b = _read_public_regular(build_b, MAX_PACKAGE_BYTES, "build B unsigned package")
    if unsigned_a != unsigned_b:
        fail("A/B unsigned packages differ before private-key admission")
    receipt_a = _read_public_regular(build_a_receipt, MAX_JSON_BYTES, "build A receipt")
    receipt_b = _read_public_regular(build_b_receipt, MAX_JSON_BYTES, "build B receipt")
    public_raw = _read_public_regular(public_key, MAX_KEY_BYTES, "trusted release public key")
    native_raw = _read_public_regular(
        native_owner_receipt, MAX_JSON_BYTES, "native-owner receipt"
    )
    recovery_raw = _read_public_regular(
        stock_recovery_receipt, MAX_JSON_BYTES, "stock-recovery receipt"
    )
    try:
        validation = verifier.validate_unsigned_build_pair(
            unsigned_a,
            unsigned_b,
            receipt_a,
            receipt_b,
            public_raw,
            native_raw,
            recovery_raw,
            expected_release_key_sha256=expected_release_key_sha256,
        )
    except Exception as error:
        fail(f"public unsigned pair did not validate: {error}")
    output_stage = Path(os.path.abspath(os.fspath(output_stage)))
    parent = output_stage.parent
    if parent.is_symlink() or not parent.is_dir():
        fail("signer output parent is missing or indirect")
    if output_stage.exists() or output_stage.is_symlink():
        fail("signer output stage already exists; no-replace required")

    # This is intentionally the first operation on private_key.
    private_raw = _read_private_key_once(private_key)
    signature = _sign_manifest(private_raw, public_raw, validation.manifest_bytes)
    signed_raw = _build_signed_tar(verifier, validation.package, signature)
    try:
        signed = verifier._parse_package(
            signed_raw, verifier.SIGNED_PACKAGE_FILE, signature_required=True
        )
        verifier._verify_signed_derivation(
            validation.package,
            signed,
            source_date_epoch=validation.provenance["source_date_epoch"],
        )
        verifier._validate_package_public_contract(
            signed,
            public_raw,
            native_raw,
            recovery_raw,
            validation.build_receipts[0],
            expected_release_key_sha256=expected_release_key_sha256,
            signature_required=True,
        )
    except Exception as error:
        fail(f"derived signed package did not independently validate: {error}")

    body = {
        "schema": verifier.SIGNING_RECEIPT_SCHEMA,
        "build_a_package_sha256": _sha256(unsigned_a),
        "build_a_package_bytes": len(unsigned_a),
        "build_b_package_sha256": _sha256(unsigned_b),
        "build_b_package_bytes": len(unsigned_b),
        "unsigned_package_sha256": _sha256(unsigned_a),
        "unsigned_package_bytes": len(unsigned_a),
        "signed_package_name": verifier.SIGNED_PACKAGE_FILE,
        "signed_package_sha256": _sha256(signed_raw),
        "signed_package_bytes": len(signed_raw),
        "manifest_sha256": _sha256(validation.manifest_bytes),
        "manifest_bytes": len(validation.manifest_bytes),
        "manifest_signature_sha256": _sha256(signature),
        "manifest_signature_bytes": len(signature),
        "release_key_sha256": _sha256(public_raw),
        "release_key_bytes": len(public_raw),
        "source_commit": validation.provenance["source_commit"],
        "source_date_epoch": validation.provenance["source_date_epoch"],
        "build_target": validation.provenance["build_target"],
        "build_arch": validation.provenance["build_arch"],
        "toolchain_id": validation.provenance["toolchain_id"],
        "a_b_equality_verified_before_private_key_open": True,
        "public_inputs_verified_before_private_key_open": True,
        "private_key_open_count": 1,
        "derivation": "add-exact-ed25519-manifest-signature-only",
        "output_no_replace": True,
        "network_used": False,
        "install_authority_granted": False,
        "flash_authority_granted": False,
        "mutation_authority_granted": False,
    }
    receipt = dict(body)
    receipt["signing_id"] = _sha256(_canonical_json(body))
    receipt_raw = _canonical_json(receipt)

    output_stage.mkdir(mode=0o700)
    created: list[Path] = []
    try:
        sentinel = output_stage / INCOMPLETE_SENTINEL
        package_path = output_stage / verifier.SIGNED_PACKAGE_FILE
        receipt_path = output_stage / verifier.SIGNING_RECEIPT_FILE
        _write_new(sentinel, b"incomplete\n", mode=0o600)
        created.append(sentinel)
        _write_new(package_path, signed_raw)
        created.append(package_path)
        _write_new(receipt_path, receipt_raw)
        created.append(receipt_path)
        if strict_durability:
            directory = os.open(
                output_stage,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        sentinel.unlink()
        created.remove(sentinel)
        if strict_durability:
            directory = os.open(
                output_stage,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if os.name != "nt":
            os.chmod(package_path, 0o400)
            os.chmod(receipt_path, 0o400)
            os.chmod(output_stage, 0o500)
        return SigningResult(
            output_stage,
            package_path,
            receipt_path,
            receipt["signing_id"],
        )
    except Exception:
        for path in reversed(created):
            try:
                if path.exists() and not path.is_symlink():
                    os.chmod(path, 0o600)
                    path.unlink()
            except OSError:
                pass
        try:
            os.chmod(output_stage, 0o700)
            output_stage.rmdir()
        except OSError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--build-a", type=Path, required=True)
    result.add_argument("--build-b", type=Path, required=True)
    result.add_argument("--build-a-receipt", type=Path, required=True)
    result.add_argument("--build-b-receipt", type=Path, required=True)
    result.add_argument("--public-key", type=Path, required=True)
    result.add_argument("--native-owner-receipt", type=Path, required=True)
    result.add_argument("--stock-recovery-receipt", type=Path, required=True)
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--output-stage", type=Path, required=True)
    result.add_argument("--expected-release-key-sha256", required=True)
    result.add_argument(
        "--verifier",
        type=Path,
        required=True,
        help="exact verifier component from the admitted sealed source snapshot",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if os.name == "nt":
            fail("production isolated signing must run inside Linux/WSL")
        verifier = _load_verifier(args.verifier)
        result = sign_equal_unsigned_pair(
            args.build_a,
            args.build_b,
            args.build_a_receipt,
            args.build_b_receipt,
            args.public_key,
            args.native_owner_receipt,
            args.stock_recovery_receipt,
            args.private_key,
            args.output_stage,
            expected_release_key_sha256=args.expected_release_key_sha256,
            verifier=verifier,
        )
        print(
            _canonical_json(
                {
                    "stage": os.fspath(result.stage),
                    "package": os.fspath(result.package),
                    "receipt": os.fspath(result.receipt),
                    "signing_id": result.signing_id,
                    "install_authority_granted": False,
                    "flash_authority_granted": False,
                    "mutation_authority_granted": False,
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    except (OSError, SigningError, TypeError, ValueError) as error:
        print(f"S19K_HERMETIC_SIGNING_REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
