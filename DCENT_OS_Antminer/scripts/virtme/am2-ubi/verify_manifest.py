#!/usr/bin/env python3
"""Generate and verify the offline-only AM2 no-fastmap module bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

LOCK_SCHEMA = "dcentos-offline-ubi-input-lock-v1"
MANIFEST_SCHEMA = "dcentos-offline-ubi-module-bundle-v1"
SCOPE = "offline-test-only"
MODULE_FILES = {"ubi": "ubi-nofastmap.ko", "ubifs": "ubifs-nofastmap.ko"}
MODULE_DEPENDS = {"ubi": ["mtd"], "ubifs": ["ubi"]}
REQUIRED_BUILD_ROLES = {
    "linux-source-deb",
    "linux-headers-common-deb",
    "linux-headers-generic-deb",
}
EXPECTED_PACKAGE_ROLES = REQUIRED_BUILD_ROLES | {
    "linux-image-deb",
    "linux-modules-deb",
    "linux-modules-extra-deb",
    "mtd-utils-deb",
    "qemu-system-x86-deb",
}
EXPECTED_TOOLCHAIN = {
    "architecture": "x86_64-linux-gnu",
    "gcc": "11.4.0",
    "binutils": "2.38",
    "make": "4.3",
}
MANIFEST_NON_CLAIMS = [
    "Offline test input only; never install into a product image or physical miner.",
    "Unsigned out-of-tree modules taint the test guest and carry no production trust claim.",
    "Successful emulation is not physical NAND validation.",
]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SRCVERSION_RE = re.compile(r"^[0-9A-F]{23,24}$")
SYMBOL_RE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")
UNSET_RE = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")


class VerificationError(ValueError):
    """An input violated the offline module-bundle contract."""


def _pairs_no_duplicates(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"top-level JSON value in {path} must be an object")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], where: str
) -> None:
    wanted = set(expected)
    found = set(value)
    if found != wanted:
        raise VerificationError(
            f"{where} keys differ: missing={sorted(wanted - found)}, extra={sorted(found - wanted)}"
        )


def _require_sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise VerificationError(f"{where} must be a lowercase SHA-256 hex digest")
    return value


def _safe_basename(value: Any, where: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or Path(value).name != value
        or value in {".", ".."}
    ):
        raise VerificationError(f"{where} must be a non-empty basename")
    return value


def validate_lock(lock: Mapping[str, Any]) -> None:
    _require_exact_keys(
        lock,
        {
            "schema",
            "scope",
            "kernel",
            "packages",
            "embedded_artifacts",
            "toolchain",
            "non_claims",
        },
        "lock",
    )
    if lock["schema"] != LOCK_SCHEMA or lock["scope"] != SCOPE:
        raise VerificationError("lock schema/scope is not offline-test-only v1")
    kernel = lock["kernel"]
    if not isinstance(kernel, dict):
        raise VerificationError("lock.kernel must be an object")
    _require_exact_keys(
        kernel,
        {
            "release",
            "vermagic",
            "vmlinuz_size",
            "vmlinuz_sha256",
            "base_config_sha256",
            "effective_config_sha256",
            "config_delta",
            "expected_module_srcversions",
            "expected_module_parameters",
        },
        "lock.kernel",
    )
    for key in ("release", "vermagic"):
        if not isinstance(kernel[key], str) or not kernel[key]:
            raise VerificationError(f"lock.kernel.{key} must be non-empty")
    if kernel["vmlinuz_size"] != 11725032:
        raise VerificationError("lock kernel image size differs")
    _require_sha256(kernel["vmlinuz_sha256"], "lock.kernel.vmlinuz_sha256")
    _require_sha256(kernel["base_config_sha256"], "lock.kernel.base_config_sha256")
    _require_sha256(
        kernel["effective_config_sha256"], "lock.kernel.effective_config_sha256"
    )
    delta = kernel["config_delta"]
    if delta != {"symbol": "CONFIG_MTD_UBI_FASTMAP", "base": "y", "effective": "n"}:
        raise VerificationError(
            "lock config delta must disable only CONFIG_MTD_UBI_FASTMAP"
        )
    srcversions = kernel["expected_module_srcversions"]
    if not isinstance(srcversions, dict) or set(srcversions) != set(MODULE_FILES):
        raise VerificationError(
            "lock expected_module_srcversions must name ubi and ubifs"
        )
    for name, value in srcversions.items():
        if not isinstance(value, str) or SRCVERSION_RE.fullmatch(value) is None:
            raise VerificationError(f"lock srcversion for {name} is invalid")
    parameters = kernel["expected_module_parameters"]
    if parameters != {"ubi": ["block", "mtd"], "ubifs": []}:
        raise VerificationError("lock module parameter-name closure differs")

    packages = lock["packages"]
    if not isinstance(packages, list) or not packages:
        raise VerificationError("lock.packages must be a non-empty array")
    roles: set[str] = set()
    filenames: set[str] = set()
    required_roles: set[str] = set()
    for index, package in enumerate(packages):
        where = f"lock.packages[{index}]"
        if not isinstance(package, dict):
            raise VerificationError(f"{where} must be an object")
        _require_exact_keys(
            package,
            {
                "role",
                "package",
                "filename",
                "version",
                "architecture",
                "sha256",
                "required_for_build",
            },
            where,
        )
        role = package["role"]
        if not isinstance(role, str) or not role or role in roles:
            raise VerificationError(f"{where}.role must be unique and non-empty")
        roles.add(role)
        if not isinstance(package["package"], str) or not package["package"]:
            raise VerificationError(f"{where}.package must be non-empty")
        filename = _safe_basename(package["filename"], f"{where}.filename")
        if filename in filenames:
            raise VerificationError(f"duplicate package filename: {filename}")
        filenames.add(filename)
        if not isinstance(package["version"], str) or not package["version"]:
            raise VerificationError(f"{where}.version must be non-empty")
        if package["architecture"] not in {"all", "amd64"}:
            raise VerificationError(f"{where}.architecture is not admitted")
        _require_sha256(package["sha256"], f"{where}.sha256")
        if not isinstance(package["required_for_build"], bool):
            raise VerificationError(f"{where}.required_for_build must be boolean")
        if package["required_for_build"]:
            required_roles.add(role)
    if required_roles != REQUIRED_BUILD_ROLES:
        raise VerificationError(f"build input roles differ: {sorted(required_roles)}")
    if roles != EXPECTED_PACKAGE_ROLES:
        raise VerificationError(f"locked package roles differ: {sorted(roles)}")

    embedded = lock["embedded_artifacts"]
    if not isinstance(embedded, list) or len(embedded) != 1:
        raise VerificationError("lock must pin exactly one embedded source tarball")
    artifact = embedded[0]
    if not isinstance(artifact, dict):
        raise VerificationError("embedded artifact must be an object")
    _require_exact_keys(
        artifact, {"role", "path_in_package", "sha256"}, "lock.embedded_artifacts[0]"
    )
    if (
        artifact["role"] != "linux-source-tarball"
        or artifact["path_in_package"]
        != "usr/src/linux-source-5.15.0/linux-source-5.15.0.tar.bz2"
    ):
        raise VerificationError("embedded source tarball identity differs")
    _require_sha256(artifact["sha256"], "lock.embedded_artifacts[0].sha256")

    toolchain = lock["toolchain"]
    if not isinstance(toolchain, dict):
        raise VerificationError("lock.toolchain must be an object")
    _require_exact_keys(
        toolchain, {"architecture", "gcc", "binutils", "make"}, "lock.toolchain"
    )
    if toolchain != EXPECTED_TOOLCHAIN:
        raise VerificationError(f"lock toolchain differs: {toolchain}")
    if not isinstance(lock["non_claims"], list) or not all(
        isinstance(x, str) and x for x in lock["non_claims"]
    ):
        raise VerificationError("lock.non_claims must be non-empty strings")


def verify_inputs(
    lock: Mapping[str, Any], cache_dir: Path, check_all: bool = False
) -> None:
    validate_lock(lock)
    for package in lock["packages"]:
        if not check_all and not package["required_for_build"]:
            continue
        candidate = cache_dir / package["filename"]
        _require_regular_file(candidate, f"package {package['role']}")
        actual = sha256_file(candidate)
        if actual != package["sha256"]:
            raise VerificationError(
                f"package hash differs for {package['filename']}: {actual}"
            )
        verify_debian_control(candidate, package)


def verify_debian_control(path: Path, package: Mapping[str, Any]) -> None:
    for field, key in (
        ("Package", "package"),
        ("Version", "version"),
        ("Architecture", "architecture"),
    ):
        try:
            completed = subprocess.run(
                ["dpkg-deb", "-f", str(path), field],
                check=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                capture_output=True,
            )
        except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
            raise VerificationError(
                f"cannot inspect Debian {field} field: {path}: {exc}"
            ) from exc
        values = completed.stdout.splitlines()
        if values != [package[key]]:
            raise VerificationError(
                f"Debian {field} differs for {path.name}: "
                f"expected={package[key]!r} actual={values!r}"
            )


def package_filename_for_role(lock: Mapping[str, Any], role: str) -> str:
    validate_lock(lock)
    matches = [
        package["filename"] for package in lock["packages"] if package["role"] == role
    ]
    if len(matches) != 1:
        raise VerificationError(f"package role is not uniquely locked: {role}")
    return matches[0]


def verify_embedded_source(lock: Mapping[str, Any], path: Path) -> None:
    validate_lock(lock)
    _require_regular_file(path, "embedded source tarball")
    expected = lock["embedded_artifacts"][0]["sha256"]
    actual = sha256_file(path)
    if actual != expected:
        raise VerificationError(f"embedded source tarball hash differs: {actual}")


def verify_kernel_image(lock: Mapping[str, Any], path: Path) -> None:
    validate_lock(lock)
    _require_regular_file(path, "virtme kernel image")
    kernel = lock["kernel"]
    if path.stat().st_size != kernel["vmlinuz_size"]:
        raise VerificationError("virtme kernel image size differs from lock")
    actual = sha256_file(path)
    if actual != kernel["vmlinuz_sha256"]:
        raise VerificationError(f"virtme kernel image hash differs: {actual}")


def _require_regular_file(path: Path, where: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise VerificationError(f"{where} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise VerificationError(f"{where} must be a regular non-symlink file: {path}")


def parse_config(path: Path) -> Dict[str, str]:
    _require_regular_file(path, "kernel config")
    result: Dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = SYMBOL_RE.fullmatch(line) or UNSET_RE.fullmatch(line)
        if not match:
            continue
        symbol = match.group(1)
        value = (
            match.group(2)
            if len(match.groups()) > 1 and match.group(2) is not None
            else "n"
        )
        if symbol in result:
            raise VerificationError(
                f"duplicate config symbol {symbol} at {path}:{number}"
            )
        result[symbol] = value
    return result


def verify_config_closure(
    lock: Mapping[str, Any], base: Path, effective: Path, delta: Path
) -> None:
    validate_lock(lock)
    _require_regular_file(delta, "config delta")
    if delta.read_bytes() != b"# CONFIG_MTD_UBI_FASTMAP is not set\n":
        raise VerificationError(
            "config.delta must contain exactly the no-fastmap assignment"
        )
    kernel = lock["kernel"]
    if sha256_file(base) != kernel["base_config_sha256"]:
        raise VerificationError("base config hash differs from lock")
    if sha256_file(effective) != kernel["effective_config_sha256"]:
        raise VerificationError("effective config hash differs from lock")
    base_symbols = parse_config(base)
    effective_symbols = parse_config(effective)
    changed = {
        symbol: (base_symbols.get(symbol), effective_symbols.get(symbol))
        for symbol in set(base_symbols) | set(effective_symbols)
        if base_symbols.get(symbol) != effective_symbols.get(symbol)
    }
    expected = {"CONFIG_MTD_UBI_FASTMAP": ("y", "n")}
    if changed != expected:
        raise VerificationError(
            f"config closure differs from the single admitted delta: {changed}"
        )


ModuleMetadataReader = Callable[[Path], Mapping[str, Any]]


def read_modinfo(path: Path) -> Mapping[str, Any]:
    try:
        completed = subprocess.run(
            ["modinfo", str(path)],
            check=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            capture_output=True,
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        raise VerificationError(f"modinfo failed for {path}: {exc}") from exc
    fields: Dict[str, Any] = {"parm": []}
    for line in completed.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if key.strip() == "parm":
            fields["parm"].append(value)
        else:
            fields[key.strip()] = value
    return fields


def _normalize_depends(value: Any) -> List[str]:
    if isinstance(value, str):
        return sorted(item for item in value.split(",") if item)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return sorted(value)
    raise VerificationError("module depends metadata has invalid type")


def _validated_module_metadata(
    name: str, metadata: Mapping[str, Any], lock: Mapping[str, Any]
) -> Dict[str, Any]:
    expected_name = name
    if metadata.get("name") != expected_name:
        raise VerificationError(f"{name} module name differs: {metadata.get('name')!r}")
    vermagic = metadata.get("vermagic")
    if vermagic != lock["kernel"]["vermagic"]:
        raise VerificationError(f"{name} vermagic differs: {vermagic!r}")
    srcversion = metadata.get("srcversion")
    if srcversion != lock["kernel"]["expected_module_srcversions"][name]:
        raise VerificationError(f"{name} srcversion differs: {srcversion!r}")
    depends = _normalize_depends(metadata.get("depends", ""))
    if depends != sorted(MODULE_DEPENDS[name]):
        raise VerificationError(f"{name} dependency closure differs: {depends}")
    parms = metadata.get("parm", [])
    if not isinstance(parms, list) or not all(isinstance(item, str) for item in parms):
        raise VerificationError(f"{name} parameter metadata is invalid")
    if any(item.split(":", 1)[0].startswith("fm_") for item in parms):
        raise VerificationError(
            f"{name} exposes a fastmap parameter despite no-fastmap scope"
        )
    parameter_names = sorted(item.split(":", 1)[0] for item in parms)
    if len(parameter_names) != len(set(parameter_names)):
        raise VerificationError(f"{name} exposes duplicate module parameters")
    if parameter_names != lock["kernel"]["expected_module_parameters"][name]:
        raise VerificationError(
            f"{name} module parameter-name closure differs: {parameter_names}"
        )
    return {
        "name": name,
        "vermagic": vermagic,
        "srcversion": srcversion,
        "depends": depends,
        "parameters": parameter_names,
    }


def build_manifest_document(
    lock: Mapping[str, Any],
    lock_sha256: str,
    base_config: Path,
    effective_config: Path,
    delta: Path,
    modules: Mapping[str, Path],
    metadata_reader: ModuleMetadataReader = read_modinfo,
) -> Dict[str, Any]:
    verify_config_closure(lock, base_config, effective_config, delta)
    module_entries: Dict[str, Any] = {}
    for name in sorted(MODULE_FILES):
        path = modules[name]
        _require_regular_file(path, f"{name} module")
        metadata = _validated_module_metadata(name, metadata_reader(path), lock)
        module_entries[name] = {
            "filename": MODULE_FILES[name],
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            **metadata,
        }
    return {
        "schema": MANIFEST_SCHEMA,
        "scope": SCOPE,
        "product_installable": False,
        "inputs_lock_sha256": lock_sha256,
        "kernel": {
            "release": lock["kernel"]["release"],
            "vermagic": lock["kernel"]["vermagic"],
            "base_config_filename": "config.base",
            "base_config_sha256": lock["kernel"]["base_config_sha256"],
            "effective_config_filename": "config.effective",
            "effective_config_sha256": lock["kernel"]["effective_config_sha256"],
        },
        "config_delta": {
            **lock["kernel"]["config_delta"],
            "filename": "config.delta",
            "sha256": sha256_file(delta),
            "changed_symbols": ["CONFIG_MTD_UBI_FASTMAP"],
        },
        "modules": module_entries,
        "reproducibility": {"independent_builds_compared": 2, "byte_identical": True},
        "non_claims": MANIFEST_NON_CLAIMS,
    }


def verify_bundle_document(
    manifest: Mapping[str, Any],
    bundle_dir: Path,
    lock: Mapping[str, Any],
    lock_sha256: str,
    metadata_reader: ModuleMetadataReader = read_modinfo,
) -> None:
    validate_lock(lock)
    _require_exact_keys(
        manifest,
        {
            "schema",
            "scope",
            "product_installable",
            "inputs_lock_sha256",
            "kernel",
            "config_delta",
            "modules",
            "reproducibility",
            "non_claims",
        },
        "manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["scope"] != SCOPE:
        raise VerificationError("manifest schema/scope is not offline-test-only v1")
    if manifest["product_installable"] is not False:
        raise VerificationError(
            "offline module bundle must never be product-installable"
        )
    if manifest["inputs_lock_sha256"] != lock_sha256:
        raise VerificationError("manifest input-lock hash differs")
    bundled_lock = bundle_dir / "inputs.lock.json"
    _require_regular_file(bundled_lock, "bundled input lock")
    if sha256_file(bundled_lock) != lock_sha256:
        raise VerificationError("bundled input-lock bytes differ from authority")
    expected_kernel = {
        "release": lock["kernel"]["release"],
        "vermagic": lock["kernel"]["vermagic"],
        "base_config_filename": "config.base",
        "base_config_sha256": lock["kernel"]["base_config_sha256"],
        "effective_config_filename": "config.effective",
        "effective_config_sha256": lock["kernel"]["effective_config_sha256"],
    }
    if manifest["kernel"] != expected_kernel:
        raise VerificationError(
            "manifest kernel identity/config hashes differ from lock"
        )
    delta = manifest["config_delta"]
    if not isinstance(delta, dict):
        raise VerificationError("manifest.config_delta must be an object")
    _require_exact_keys(
        delta,
        {"symbol", "base", "effective", "filename", "sha256", "changed_symbols"},
        "manifest.config_delta",
    )
    if {key: delta[key] for key in ("symbol", "base", "effective")} != lock["kernel"][
        "config_delta"
    ]:
        raise VerificationError("manifest config-delta semantics differ")
    if delta["filename"] != "config.delta" or delta["changed_symbols"] != [
        "CONFIG_MTD_UBI_FASTMAP"
    ]:
        raise VerificationError("manifest config-delta filename/closure differs")
    delta_path = bundle_dir / _safe_basename(
        delta["filename"], "manifest.config_delta.filename"
    )
    _require_regular_file(delta_path, "bundled config delta")
    if sha256_file(delta_path) != _require_sha256(
        delta["sha256"], "manifest.config_delta.sha256"
    ):
        raise VerificationError("bundled config-delta hash differs")
    if delta_path.read_bytes() != b"# CONFIG_MTD_UBI_FASTMAP is not set\n":
        raise VerificationError("bundled config delta content differs")
    base_config_path = bundle_dir / _safe_basename(
        manifest["kernel"]["base_config_filename"],
        "manifest.kernel.base_config_filename",
    )
    effective_config_path = bundle_dir / _safe_basename(
        manifest["kernel"]["effective_config_filename"],
        "manifest.kernel.effective_config_filename",
    )
    verify_config_closure(lock, base_config_path, effective_config_path, delta_path)
    if manifest["reproducibility"] != {
        "independent_builds_compared": 2,
        "byte_identical": True,
    }:
        raise VerificationError("manifest lacks a two-build byte-identity claim")
    modules = manifest["modules"]
    if not isinstance(modules, dict) or set(modules) != set(MODULE_FILES):
        raise VerificationError(
            "manifest must contain exactly the paired ubi and ubifs modules"
        )
    for name, expected_filename in MODULE_FILES.items():
        entry = modules[name]
        if not isinstance(entry, dict):
            raise VerificationError(f"manifest module {name} must be an object")
        _require_exact_keys(
            entry,
            {
                "filename",
                "sha256",
                "size",
                "name",
                "vermagic",
                "srcversion",
                "depends",
                "parameters",
            },
            f"manifest.modules.{name}",
        )
        if entry["filename"] != expected_filename:
            raise VerificationError(f"manifest filename differs for {name}")
        path = bundle_dir / _safe_basename(
            entry["filename"], f"manifest.modules.{name}.filename"
        )
        _require_regular_file(path, f"bundled {name} module")
        if (
            not isinstance(entry["size"], int)
            or entry["size"] < 1
            or path.stat().st_size != entry["size"]
        ):
            raise VerificationError(f"bundled {name} size differs")
        if sha256_file(path) != _require_sha256(
            entry["sha256"], f"manifest.modules.{name}.sha256"
        ):
            raise VerificationError(f"bundled {name} hash differs")
        actual_metadata = _validated_module_metadata(name, metadata_reader(path), lock)
        expected_metadata = {
            key: entry[key]
            for key in ("name", "vermagic", "srcversion", "depends", "parameters")
        }
        if actual_metadata != expected_metadata:
            raise VerificationError(f"bundled {name} metadata differs from manifest")
    if manifest["non_claims"] != MANIFEST_NON_CLAIMS:
        raise VerificationError(
            "manifest must retain the exact offline-only non-claims"
        )


def _command_verify_lock(args: argparse.Namespace) -> None:
    validate_lock(load_json(args.lock))


def _command_verify_inputs(args: argparse.Namespace) -> None:
    verify_inputs(load_json(args.lock), args.cache_dir, args.all)


def _command_verify_embedded(args: argparse.Namespace) -> None:
    verify_embedded_source(load_json(args.lock), args.path)


def _command_verify_config(args: argparse.Namespace) -> None:
    verify_config_closure(load_json(args.lock), args.base, args.effective, args.delta)


def _command_verify_kernel(args: argparse.Namespace) -> None:
    verify_kernel_image(load_json(args.lock), args.kernel)


def _command_package_filename(args: argparse.Namespace) -> None:
    print(package_filename_for_role(load_json(args.lock), args.role))


def _command_generate(args: argparse.Namespace) -> None:
    lock = load_json(args.lock)
    validate_lock(lock)
    document = build_manifest_document(
        lock,
        sha256_file(args.lock),
        args.base,
        args.effective,
        args.delta,
        {"ubi": args.ubi, "ubifs": args.ubifs},
    )
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _command_verify_bundle(args: argparse.Namespace) -> None:
    lock = load_json(args.lock)
    verify_bundle_document(
        load_json(args.manifest), args.bundle_dir, lock, sha256_file(args.lock)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_lock_parser = subparsers.add_parser(
        "verify-lock", help="validate lock structure"
    )
    verify_lock_parser.add_argument("--lock", type=Path, required=True)
    verify_lock_parser.set_defaults(handler=_command_verify_lock)
    input_parser = subparsers.add_parser(
        "verify-inputs", help="hash-check cached package inputs"
    )
    input_parser.add_argument("--lock", type=Path, required=True)
    input_parser.add_argument("--cache-dir", type=Path, required=True)
    input_parser.add_argument(
        "--all", action="store_true", help="also require runtime-only package inputs"
    )
    input_parser.set_defaults(handler=_command_verify_inputs)
    embedded_parser = subparsers.add_parser(
        "verify-embedded",
        help="hash-check the source tarball extracted from its package",
    )
    embedded_parser.add_argument("--lock", type=Path, required=True)
    embedded_parser.add_argument("--path", type=Path, required=True)
    embedded_parser.set_defaults(handler=_command_verify_embedded)
    config_parser = subparsers.add_parser(
        "verify-config", help="verify the one-symbol config closure"
    )
    config_parser.add_argument("--lock", type=Path, required=True)
    config_parser.add_argument("--base", type=Path, required=True)
    config_parser.add_argument("--effective", type=Path, required=True)
    config_parser.add_argument("--delta", type=Path, required=True)
    config_parser.set_defaults(handler=_command_verify_config)
    kernel_parser = subparsers.add_parser(
        "verify-kernel", help="verify the exact virtme kernel image"
    )
    kernel_parser.add_argument("--lock", type=Path, required=True)
    kernel_parser.add_argument("--kernel", type=Path, required=True)
    kernel_parser.set_defaults(handler=_command_verify_kernel)
    role_parser = subparsers.add_parser(
        "package-filename", help="resolve one locked package filename by role"
    )
    role_parser.add_argument("--lock", type=Path, required=True)
    role_parser.add_argument("--role", required=True)
    role_parser.set_defaults(handler=_command_package_filename)
    generate_parser = subparsers.add_parser(
        "generate", help="generate a strict module-bundle manifest"
    )
    for name in ("lock", "base", "effective", "delta", "ubi", "ubifs", "output"):
        generate_parser.add_argument(f"--{name}", type=Path, required=True)
    generate_parser.set_defaults(handler=_command_generate)
    bundle_parser = subparsers.add_parser(
        "verify-bundle", help="verify manifest, files, hashes, and modinfo"
    )
    bundle_parser.add_argument("--manifest", type=Path, required=True)
    bundle_parser.add_argument("--lock", type=Path, required=True)
    bundle_parser.add_argument("--bundle-dir", type=Path, required=True)
    bundle_parser.set_defaults(handler=_command_verify_bundle)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except VerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.command != "package-filename":
        print("AM2 offline UBI module-bundle verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
