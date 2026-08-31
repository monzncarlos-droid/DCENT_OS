#!/usr/bin/env python3
"""Validate one campaign-pinned S19k production source-policy record.

This module deliberately does not authenticate a Git commit and does not grant
build, release, install, device-contact, mutation, or flash authority.  It
validates the immutable policy inputs that a later source-admission owner must
consume: a complete authority record is authenticated by one out-of-band pin,
and no individual policy leaf can be selected by an untrusted CLI caller.

The production integration must construct :class:`TrustedCampaignPin` from an
already-authenticated campaign/out-of-band constant.  Loading that pin from the
authority record being checked would collapse the trust boundary and is not an
API offered here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Dict, Iterable, List, Mapping, NoReturn, Sequence, Tuple
import unicodedata


AUTHORITY_SCHEMA = "dcentos.s19k-source-authority/v1"
RESULT_SCHEMA = "dcentos.s19k-source-authority-validation/v1"
CAMPAIGN_SCHEMA = "dcentos.s19k-gauntlet-campaign/v1"
SIGNING_POLICY_SCHEMA = "dcentos.s19k-git-signing-policy/v1"
DEPENDENCY_POLICY_SCHEMA = "dcentos.s19k-hermetic-dependency-policy/v1"
DEPENDENCY_BUNDLE_SCHEMA = "dcentos.s19k-hermetic-dependency-bundle/v2"
TREE_LEDGER_SCHEMA = "dcentos.s19k-git-tree-object-ledger/v1"

SOURCE_SNAPSHOT_PATH = "DCENT_OS_Antminer/scripts/source_snapshot.py"
PERSISTENT_VERIFIER_PATH = (
    "DCENT_OS_Antminer/scripts/s19k_persistent_image_verify.py"
)
RELEASE_SIGNER_PATH = "DCENT_OS_Antminer/scripts/s19k_hermetic_release_signer.py"
HOST_PREFLIGHT_PATH = "DCENT_OS_Antminer/scripts/s19k_hermetic_host_preflight.py"
DEPENDENCY_POLICY_PATH = "DCENT_OS_Antminer/scripts/s19k_hermetic_dependencies.json"

AUTHORITY_CLAIM = (
    "pinned-source-policy-validation-only-no-build-release-install-flash-"
    "contact-or-mutation-authority"
)

MAX_AUTHORITY_BYTES = 1024 * 1024
MAX_CAMPAIGN_BYTES = 32 * 1024 * 1024
MAX_BOUND_FILE_BYTES = 1024 * 1024 * 1024
MAX_GIT_OBJECT_BYTES = 2 * 1024 * 1024 * 1024
MAX_TREE_LEDGER_BYTES = 64 * 1024 * 1024
MAX_TRUST_FILES = 4096
MAX_TRUST_DIRECTORIES = 4096

HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
OPENPGP_SIGNER = re.compile(r"openpgp:(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CAMPAIGN_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

_SCOPE = {
    "build_authority_granted": False,
    "device_contact_authority_granted": False,
    "flash_authority_granted": False,
    "install_authority_granted": False,
    "mutation_authority_granted": False,
    "release_authority_granted": False,
}


class SourceAuthorityError(RuntimeError):
    """A source-authority policy or one of its bound objects was unsafe."""


def fail(message: str) -> NoReturn:
    raise SourceAuthorityError(message)


@dataclass(frozen=True)
class TrustedCampaignPin:
    """One trusted, out-of-band pin; never derive this from authority JSON."""

    campaign_id: str
    campaign_raw_sha256: str
    campaign_raw_bytes: int
    campaign_canonical_sha256: str
    campaign_canonical_bytes: int
    authority_sha256: str
    authority_bytes: int
    authority_validator_path: str
    authority_validator_sha256: str
    authority_validator_bytes: int

    def validate(self) -> None:
        if not isinstance(self.campaign_id, str) or not CAMPAIGN_ID.fullmatch(
            self.campaign_id
        ):
            fail("trusted campaign pin has a malformed campaign identifier")
        for label, value in (
            ("raw campaign manifest SHA-256", self.campaign_raw_sha256),
            ("canonical campaign manifest SHA-256", self.campaign_canonical_sha256),
            ("authority SHA-256", self.authority_sha256),
            ("authority-validator SHA-256", self.authority_validator_sha256),
        ):
            if not isinstance(value, str) or not HEX_64.fullmatch(value):
                fail(f"trusted {label} is malformed")
        for label, value, maximum in (
            ("raw campaign manifest size", self.campaign_raw_bytes, MAX_CAMPAIGN_BYTES),
            (
                "canonical campaign manifest size",
                self.campaign_canonical_bytes,
                MAX_CAMPAIGN_BYTES,
            ),
            ("authority size", self.authority_bytes, MAX_AUTHORITY_BYTES),
            (
                "authority-validator size",
                self.authority_validator_bytes,
                MAX_BOUND_FILE_BYTES,
            ),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > maximum
            ):
                fail(f"trusted {label} is outside its bounded range")
        _require_absolute_spelling(
            self.authority_validator_path,
            "trusted authority-validator path",
        )


def canonical_json(value: object) -> bytes:
    """Return the repository's newline-terminated canonical JSON encoding."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_object(value: object, keys: Iterable[str], label: str) -> Dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        fail(
            f"{label} has an invalid key set "
            f"(missing={sorted(expected - actual)}, extra={sorted(actual - expected)})"
        )
    return value


def _reject_json_constant(value: str) -> NoReturn:
    fail(f"JSON contains a non-finite number: {value}")


def _pairs_without_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains a duplicate object key: {key}")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str, *, canonical: bool) -> Dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be one JSON object")
    if canonical and raw != canonical_json(value):
        fail(f"{label} must use the exact canonical JSON encoding")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _stable_signature(metadata: os.stat_result) -> Tuple[int, ...]:
    values = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
    )
    # NTFS may publish a delayed ctime change between lstat() and fstat() after
    # a completed replacement.  The open-handle identity, size, mode, link
    # count, and mtime remain the Windows race boundary; POSIX retains ctime.
    if os.name != "nt":
        values += (
            getattr(
                metadata,
                "st_ctime_ns",
                int(metadata.st_ctime * 1_000_000_000),
            ),
        )
    return values


def _require_absolute_spelling(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{label} must be a nonempty absolute path")
    path = Path(value)
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    canonical = os.fspath(Path(os.path.abspath(value)))
    if value != canonical:
        fail(f"{label} must use its normalized absolute spelling")
    return path


def _require_exact_case(parent: Path, name: str, label: str) -> None:
    if os.name != "nt":
        return
    try:
        matches = [entry.name for entry in os.scandir(parent) if entry.name.casefold() == name.casefold()]
    except OSError as error:
        fail(f"cannot inspect {label} path spelling: {error}")
    if matches != [name]:
        fail(f"{label} path has a case alias or collision at component {name!r}")


def _lstat_no_alias_components(path: Path, label: str) -> os.stat_result:
    absolute = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(absolute.anchor)
    if not absolute.is_absolute() or not absolute.anchor:
        fail(f"{label} must be absolute")
    current = anchor
    parts = absolute.parts[1:]
    if not parts:
        fail(f"{label} may not be a filesystem root")
    metadata: os.stat_result
    for index, part in enumerate(parts):
        _require_exact_case(current, part, label)
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            fail(f"{label} traverses a symlink or reparse point: {current}")
        if index != len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} has a non-directory path component: {current}")
    return metadata


def _require_directory(path: Path, label: str) -> os.stat_result:
    metadata = _lstat_no_alias_components(path, label)
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a directory")
    return metadata


def _require_regular(path: Path, maximum: int, label: str) -> os.stat_result:
    metadata = _lstat_no_alias_components(path, label)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        fail(f"{label} is not one exact regular file")
    if metadata.st_nlink != 1:
        fail(f"{label} has hard-link aliases")
    if metadata.st_size < 0 or metadata.st_size > maximum:
        fail(f"{label} exceeds its {maximum}-byte bound")
    return metadata


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    before = _require_regular(path, maximum, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    chunks: List[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if _stable_signature(opened) != _stable_signature(before):
            fail(f"{label} changed while being opened")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds its {maximum}-byte bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _require_regular(path, maximum, label)
    if (
        _stable_signature(opened) != _stable_signature(after)
        or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        or (os.name != "nt" and _stable_signature(after) != _stable_signature(current))
    ):
        fail(f"{label} changed while being read")
    return b"".join(chunks)


def _hash_regular(path: Path, maximum: int, label: str) -> Tuple[str, int]:
    raw = _read_regular(path, maximum, label)
    return sha256_bytes(raw), len(raw)


def _safe_relative(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        fail(f"{label} is not a canonical portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in ("", ".", "..") for part in path.parts):
        fail(f"{label} is not a canonical portable relative path")
    for part in path.parts:
        windows_stem = part.split(".", 1)[0].casefold()
        if (
            part.endswith((" ", "."))
            or ":" in part
            or windows_stem in WINDOWS_RESERVED_NAMES
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
        ):
            fail(f"{label} is not portable across production hosts")
    return value


def _join_relative(root: Path, relative: str, label: str) -> Path:
    _require_directory(root, f"{label} root")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        if os.path.commonpath((os.fspath(root), os.fspath(candidate))) != os.fspath(root):
            fail(f"{label} escapes its admitted source root")
    except ValueError:
        fail(f"{label} escapes its admitted source root")
    return candidate


def _identity(
    value: object,
    label: str,
    *,
    absolute_path: bool,
    allow_empty: bool = False,
    maximum: int = MAX_BOUND_FILE_BYTES,
) -> Dict[str, Any]:
    identity = _exact_object(value, ("bytes", "path", "sha256"), label)
    path_value = identity["path"]
    if absolute_path:
        _require_absolute_spelling(path_value, f"{label} path")
    else:
        _safe_relative(path_value, f"{label} path")
    if not isinstance(identity["sha256"], str) or not HEX_64.fullmatch(identity["sha256"]):
        fail(f"{label} SHA-256 is malformed")
    size = identity["bytes"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < (0 if allow_empty else 1)
        or size > maximum
    ):
        fail(f"{label} byte count is outside its bounded range")
    return identity


def _verify_identity(
    path: Path,
    identity: Mapping[str, Any],
    label: str,
    *,
    maximum: int = MAX_BOUND_FILE_BYTES,
) -> None:
    digest, size = _hash_regular(path, maximum, label)
    if digest != identity["sha256"] or size != identity["bytes"]:
        fail(f"{label} differs from the campaign-pinned authority identity")


def _portable_unique(paths: Sequence[str], label: str) -> None:
    if list(paths) != sorted(paths, key=lambda item: item.encode("utf-8")):
        fail(f"{label} is not sorted by UTF-8 byte order")
    if len(paths) != len(set(paths)) or len(paths) != len({path.casefold() for path in paths}):
        fail(f"{label} contains a duplicate or portable case collision")


def _walk_trust_root(root: Path) -> Tuple[List[str], List[str]]:
    _require_directory(root, "OpenPGP trust root")
    files: List[str] = []
    directories: List[str] = []
    for current_raw, names, leaves in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        names.sort(key=lambda name: name.encode("utf-8"))
        leaves.sort(key=lambda name: name.encode("utf-8"))
        for name in names:
            path = current / name
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                fail(f"OpenPGP trust root contains a linked or special directory: {path}")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "OpenPGP trust directory")
            directories.append(relative)
            if len(directories) > MAX_TRUST_DIRECTORIES:
                fail("OpenPGP trust root contains too many directories")
        for name in leaves:
            path = current / name
            _require_regular(path, MAX_BOUND_FILE_BYTES, "OpenPGP trust file")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "OpenPGP trust file")
            files.append(relative)
            if len(files) > MAX_TRUST_FILES:
                fail("OpenPGP trust root contains too many files")
    files.sort(key=lambda item: item.encode("utf-8"))
    directories.sort(key=lambda item: item.encode("utf-8"))
    _portable_unique(files, "OpenPGP trust file walk")
    _portable_unique(directories, "OpenPGP trust directory walk")
    if set(files) & set(directories):
        fail("OpenPGP trust root contains a file/directory path collision")
    return files, directories


def _parse_trust_root(value: object) -> Dict[str, Any]:
    trust = _exact_object(value, ("directories", "files", "path"), "OpenPGP trust root")
    root = _require_absolute_spelling(trust["path"], "OpenPGP trust root path")
    directories_raw = trust["directories"]
    files_raw = trust["files"]
    if not isinstance(directories_raw, list) or len(directories_raw) > MAX_TRUST_DIRECTORIES:
        fail("OpenPGP trust directory ledger is malformed or unbounded")
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_TRUST_FILES:
        fail("OpenPGP trust file ledger is empty, malformed, or unbounded")
    directories = [
        _safe_relative(path, f"OpenPGP trust directory {index}")
        for index, path in enumerate(directories_raw)
    ]
    _portable_unique(directories, "OpenPGP trust directory ledger")
    files: List[Dict[str, Any]] = []
    paths: List[str] = []
    for index, raw in enumerate(files_raw):
        item = _identity(
            raw,
            f"OpenPGP trust file {index}",
            absolute_path=False,
            allow_empty=True,
        )
        files.append(item)
        paths.append(item["path"])
    _portable_unique(paths, "OpenPGP trust file ledger")
    if set(paths) & set(directories):
        fail("OpenPGP trust ledger contains a file/directory path collision")
    expected_parents = set()
    for relative in paths + directories:
        parts = PurePosixPath(relative).parts[:-1]
        for length in range(1, len(parts) + 1):
            expected_parents.add(PurePosixPath(*parts[:length]).as_posix())
    if not expected_parents.issubset(set(directories)):
        fail("OpenPGP trust directory ledger omits a parent directory")
    observed_files, observed_directories = _walk_trust_root(root)
    if observed_files != paths or observed_directories != directories:
        fail("OpenPGP trust root contents differ from the exact authority ledger")
    for item in files:
        path = root.joinpath(*PurePosixPath(item["path"]).parts)
        _verify_identity(path, item, f"OpenPGP trust file {item['path']}")
    return trust


def _signing_policy_id(openpgp: Mapping[str, Any]) -> str:
    trust = openpgp["trust_root"]
    gpg = openpgp["gpg_binary"]
    policy = {
        "schema": SIGNING_POLICY_SCHEMA,
        "allowed_signers": openpgp["allowed_signers"],
        "gpg_binary": gpg["path"],
        "gpg_binary_sha256": gpg["sha256"],
        "gpg_binary_bytes": gpg["bytes"],
        "trust_root": trust["path"],
        "trust_files": trust["files"],
        "trust_directories": trust["directories"],
        "git_system_config": "disabled",
        "git_global_config": "disabled",
        "signature_format": "openpgp",
    }
    return sha256_bytes(canonical_json(policy))


def _new_git_hasher(object_format: str) -> Any:
    if object_format == "sha1":
        try:
            return hashlib.sha1(usedforsecurity=False)
        except TypeError:  # pragma: no cover - older Python compatibility
            return hashlib.sha1()
    if object_format == "sha256":
        return hashlib.sha256()
    fail("source object format must be exactly sha1 or sha256")


def _git_object_oid(object_format: str, object_type: str, raw: bytes) -> str:
    hasher = _new_git_hasher(object_format)
    hasher.update(f"{object_type} {len(raw)}\0".encode("ascii"))
    hasher.update(raw)
    return hasher.hexdigest()


def _verify_commit_object(source: Mapping[str, Any]) -> None:
    identity = source["commit_object"]
    path = Path(identity["path"])
    raw = _read_regular(path, MAX_GIT_OBJECT_BYTES, "retained raw Git commit object")
    if sha256_bytes(raw) != identity["sha256"] or len(raw) != identity["bytes"]:
        fail("retained raw Git commit object differs from source authority")
    if _git_object_oid(source["object_format"], "commit", raw) != source["commit_oid"]:
        fail("retained raw Git commit object does not match its Git object identifier")
    header = raw.split(b"\n\n", 1)[0]
    lines = header.splitlines()
    tree_lines = [line[5:] for line in lines if line.startswith(b"tree ")]
    if not lines or not lines[0].startswith(b"tree ") or len(tree_lines) != 1:
        fail("retained raw Git commit lacks one exact leading tree header")
    try:
        tree_oid = tree_lines[0].decode("ascii", "strict")
    except UnicodeDecodeError:
        fail("retained raw Git commit tree identifier is not ASCII")
    if tree_oid != source["tree_oid"]:
        fail("retained raw Git commit names a different root tree")


def _parse_tree_entries(
    raw: bytes,
    object_format: str,
    prefix: str,
) -> List[Tuple[str, str, str]]:
    oid_bytes = 20 if object_format == "sha1" else 32
    entries: List[Tuple[str, str, str]] = []
    seen_names = set()
    previous_sort_key: bytes | None = None
    offset = 0
    while offset < len(raw):
        space = raw.find(b" ", offset)
        nul = raw.find(b"\0", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or nul + 1 + oid_bytes > len(raw):
            fail("retained Git tree object contains a truncated entry")
        mode_raw = raw[offset:space]
        name_raw = raw[space + 1 : nul]
        oid_raw = raw[nul + 1 : nul + 1 + oid_bytes]
        offset = nul + 1 + oid_bytes
        if name_raw in seen_names:
            fail("retained Git tree object contains a duplicate entry name")
        seen_names.add(name_raw)
        try:
            mode = mode_raw.decode("ascii", "strict")
            name = name_raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            fail("retained Git tree mode or name is not canonical ASCII/UTF-8")
        if name.encode("utf-8") != name_raw or "/" in name:
            fail("retained Git tree entry name is not canonical UTF-8")
        path = f"{prefix}/{name}" if prefix else name
        _safe_relative(path, "retained Git tree path")
        normalized_mode = "040000" if mode == "40000" else mode
        if normalized_mode not in ("040000", "100644", "100755"):
            fail(f"retained Git tree contains unsupported mode {mode} at {path}")
        sort_key = name_raw + (b"/" if normalized_mode == "040000" else b"")
        if previous_sort_key is not None and previous_sort_key >= sort_key:
            fail("retained Git tree entries are not in canonical Git byte order")
        previous_sort_key = sort_key
        entries.append((normalized_mode, oid_raw.hex(), path))
    return entries


def _git_blob_oid(path: Path, object_format: str, label: str) -> str:
    before = _require_regular(path, MAX_GIT_OBJECT_BYTES, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    hasher = _new_git_hasher(object_format)
    hasher.update(f"blob {before.st_size}\0".encode("ascii"))
    total = 0
    try:
        opened = os.fstat(descriptor)
        if _stable_signature(opened) != _stable_signature(before):
            fail(f"{label} changed while being opened")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_GIT_OBJECT_BYTES:
                fail(f"{label} exceeds the Git object bound")
            hasher.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _require_regular(path, MAX_GIT_OBJECT_BYTES, label)
    if (
        total != before.st_size
        or _stable_signature(opened) != _stable_signature(after)
        or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        or (os.name != "nt" and _stable_signature(after) != _stable_signature(current))
    ):
        fail(f"{label} changed while being hashed as a Git blob")
    return hasher.hexdigest()


def _walk_source_tree(root: Path) -> Tuple[List[str], List[str]]:
    _require_directory(root, "admitted immutable source tree")
    files: List[str] = []
    directories: List[str] = []
    portable = set()
    for current_raw, names, leaves in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        names.sort(key=lambda name: name.encode("utf-8"))
        leaves.sort(key=lambda name: name.encode("utf-8"))
        for name in names:
            path = current / name
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                fail(f"admitted source tree contains a linked or special directory: {path}")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "admitted source directory")
            collision = relative.casefold()
            if collision in portable:
                fail("admitted source tree contains a portable path collision")
            portable.add(collision)
            directories.append(relative)
        for name in leaves:
            path = current / name
            _require_regular(path, MAX_GIT_OBJECT_BYTES, "admitted source file")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative, "admitted source file")
            collision = relative.casefold()
            if collision in portable:
                fail("admitted source tree contains a portable path collision")
            portable.add(collision)
            files.append(relative)
    files.sort(key=lambda item: item.encode("utf-8"))
    directories.sort(key=lambda item: item.encode("utf-8"))
    return files, directories


def _verify_tree_ledger(source: Mapping[str, Any], source_root: Path) -> None:
    ledger_identity = source["tree_object_ledger"]
    ledger_path = Path(ledger_identity["path"])
    raw = _read_regular(ledger_path, MAX_TREE_LEDGER_BYTES, "Git tree-object ledger")
    if sha256_bytes(raw) != ledger_identity["sha256"] or len(raw) != ledger_identity["bytes"]:
        fail("Git tree-object ledger differs from source authority")
    ledger = _exact_object(
        _parse_json(raw, "Git tree-object ledger", canonical=True),
        ("object_format", "objects", "root_tree_oid", "schema"),
        "Git tree-object ledger",
    )
    if (
        ledger["schema"] != TREE_LEDGER_SCHEMA
        or ledger["object_format"] != source["object_format"]
        or ledger["root_tree_oid"] != source["tree_oid"]
    ):
        fail("Git tree-object ledger identity differs from source authority")
    raw_objects = ledger["objects"]
    if not isinstance(raw_objects, list) or not raw_objects or len(raw_objects) > 1_000_000:
        fail("Git tree-object ledger is empty, malformed, or unbounded")
    objects: Dict[str, bytes] = {}
    ledger_oids: List[str] = []
    expected_object_paths: List[str] = []
    object_root = ledger_path.parent / "tree-objects"
    _require_directory(object_root, "retained Git tree-object directory")
    for index, raw_item in enumerate(raw_objects):
        item = _exact_object(
            raw_item,
            ("bytes", "oid", "path", "sha256"),
            f"Git tree object {index}",
        )
        oid = item["oid"]
        expected_length = 40 if source["object_format"] == "sha1" else 64
        if not isinstance(oid, str) or not re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", oid):
            fail(f"Git tree object {index} identifier is malformed")
        identity = _identity(
            {"bytes": item["bytes"], "path": item["path"], "sha256": item["sha256"]},
            f"Git tree object {index}",
            absolute_path=False,
            allow_empty=True,
            maximum=MAX_GIT_OBJECT_BYTES,
        )
        expected_path = f"tree-objects/{oid}.raw"
        if identity["path"] != expected_path:
            fail(f"Git tree object {index} path is not identifier-derived")
        path = ledger_path.parent.joinpath(*PurePosixPath(expected_path).parts)
        object_raw = _read_regular(path, MAX_GIT_OBJECT_BYTES, f"Git tree object {oid}")
        if sha256_bytes(object_raw) != identity["sha256"] or len(object_raw) != identity["bytes"]:
            fail(f"Git tree object {oid} differs from its ledger identity")
        if _git_object_oid(source["object_format"], "tree", object_raw) != oid:
            fail(f"Git tree object {oid} bytes do not match its Git identifier")
        if oid in objects:
            fail("Git tree-object ledger contains a duplicate identifier")
        objects[oid] = object_raw
        ledger_oids.append(oid)
        expected_object_paths.append(expected_path)
    if ledger_oids != sorted(ledger_oids):
        fail("Git tree-object ledger is not sorted by object identifier")
    observed_object_files, observed_object_directories = _walk_source_tree(object_root)
    expected_names = [PurePosixPath(path).name for path in expected_object_paths]
    if observed_object_directories or observed_object_files != expected_names:
        fail("retained Git tree-object directory differs from its exact ledger")

    pending: List[Tuple[str, str, Tuple[str, ...]]] = [("", source["tree_oid"], ())]
    used_tree_oids = set()
    directories: List[str] = []
    blobs: List[Tuple[str, str, str]] = []
    portable_paths = set()
    while pending:
        prefix, oid, ancestors = pending.pop(0)
        if oid in ancestors:
            fail("retained Git tree graph contains a cycle")
        if oid not in objects:
            fail(f"retained Git tree graph references missing tree object {oid}")
        used_tree_oids.add(oid)
        for mode, child_oid, path in _parse_tree_entries(
            objects[oid], source["object_format"], prefix
        ):
            collision = path.casefold()
            if collision in portable_paths:
                fail(f"retained Git tree graph contains a portable path collision: {path}")
            portable_paths.add(collision)
            if mode == "040000":
                directories.append(path)
                pending.append((path, child_oid, (*ancestors, oid)))
            else:
                blobs.append((path, mode, child_oid))
            if len(directories) + len(blobs) > 1_000_000:
                fail("retained Git tree graph exceeds its path-count bound")
    if used_tree_oids != set(objects):
        fail("Git tree-object ledger contains unreachable extra objects")
    directories.sort(key=lambda item: item.encode("utf-8"))
    blobs.sort(key=lambda item: item[0].encode("utf-8"))
    observed_files, observed_directories = _walk_source_tree(source_root)
    expected_files = [path for path, _, _ in blobs]
    if observed_files != expected_files or observed_directories != directories:
        fail("admitted source tree paths differ from the retained Git tree graph")
    for relative, mode, blob_oid in blobs:
        path = source_root.joinpath(*PurePosixPath(relative).parts)
        if _git_blob_oid(path, source["object_format"], f"admitted source file {relative}") != blob_oid:
            fail(f"admitted source file bytes differ from Git blob {relative}")
        if os.name != "nt":
            metadata = os.lstat(path)
            observed_mode = "100755" if metadata.st_mode & 0o111 else "100644"
            if observed_mode != mode:
                fail(f"admitted source file mode differs from Git tree {relative}")


def _parse_authority(value: object) -> Dict[str, Any]:
    authority = _exact_object(
        value,
        (
            "authority_id",
            "approved_dependency_bundle",
            "builder",
            "campaign",
            "claim",
            "dependency_policy",
            "openpgp",
            "release_public_key",
            "schema",
            "scope",
            "source",
            "verifiers",
        ),
        "source-authority record",
    )
    body = dict(authority)
    body.pop("authority_id")
    if authority["schema"] != AUTHORITY_SCHEMA or authority["claim"] != AUTHORITY_CLAIM:
        fail("source-authority schema or bounded non-authority claim is invalid")
    if not isinstance(authority["authority_id"], str) or not HEX_64.fullmatch(authority["authority_id"]):
        fail("source-authority identifier is malformed")
    if authority["authority_id"] != sha256_bytes(canonical_json(body)):
        fail("source-authority identifier does not match its canonical body")

    scope = _exact_object(authority["scope"], _SCOPE, "source-authority scope")
    if any(scope[field] is not False for field in _SCOPE):
        fail("source-authority record contains an authority grant")

    campaign = _exact_object(
        authority["campaign"],
        (
            "campaign_id",
            "canonical_bytes",
            "canonical_sha256",
            "manifest_schema",
            "raw_bytes",
            "raw_sha256",
        ),
        "source-authority campaign",
    )
    if not isinstance(campaign["campaign_id"], str) or not CAMPAIGN_ID.fullmatch(campaign["campaign_id"]):
        fail("source-authority campaign identifier is malformed")
    if campaign["manifest_schema"] != CAMPAIGN_SCHEMA:
        fail("source-authority campaign schema is not the S19k campaign schema")
    for label, value in (
        ("raw", campaign["raw_sha256"]),
        ("canonical", campaign["canonical_sha256"]),
    ):
        if not isinstance(value, str) or not HEX_64.fullmatch(value):
            fail(f"source-authority {label} campaign SHA-256 is malformed")
    for label, value in (
        ("raw", campaign["raw_bytes"]),
        ("canonical", campaign["canonical_bytes"]),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_CAMPAIGN_BYTES
        ):
            fail(f"source-authority {label} campaign size is invalid")

    source = _exact_object(
        authority["source"],
        (
            "commit_object",
            "commit_oid",
            "object_format",
            "tree_object_ledger",
            "tree_oid",
        ),
        "source identity",
    )
    if source["object_format"] not in ("sha1", "sha256"):
        fail("source object format must be exactly sha1 or sha256")
    if not isinstance(source["commit_oid"], str) or not GIT_OID.fullmatch(source["commit_oid"]):
        fail("source commit object identifier is malformed")
    if not isinstance(source["tree_oid"], str) or not GIT_OID.fullmatch(source["tree_oid"]):
        fail("source tree object identifier is malformed")
    if len(source["commit_oid"]) != len(source["tree_oid"]):
        fail("source commit and tree object identifiers use different hash formats")
    expected_oid_length = 40 if source["object_format"] == "sha1" else 64
    if len(source["commit_oid"]) != expected_oid_length:
        fail("source object identifiers do not match the declared object format")
    _identity(
        source["commit_object"],
        "retained raw Git commit object",
        absolute_path=True,
        maximum=MAX_GIT_OBJECT_BYTES,
    )
    _identity(
        source["tree_object_ledger"],
        "Git tree-object ledger",
        absolute_path=True,
        maximum=MAX_TREE_LEDGER_BYTES,
    )

    openpgp = _exact_object(
        authority["openpgp"],
        ("allowed_signers", "git_binary", "gpg_binary", "signing_policy_id", "trust_root"),
        "OpenPGP authority",
    )
    signers = openpgp["allowed_signers"]
    if not isinstance(signers, list) or not signers:
        fail("OpenPGP authority has no reviewed signer fingerprints")
    if any(not isinstance(item, str) or not OPENPGP_SIGNER.fullmatch(item) for item in signers):
        fail("OpenPGP signer fingerprints are not canonical full fingerprints")
    _portable_unique(signers, "OpenPGP signer fingerprint ledger")
    git_binary = _identity(openpgp["git_binary"], "Git admission binary", absolute_path=True)
    gpg_binary = _identity(openpgp["gpg_binary"], "GPG admission binary", absolute_path=True)
    trust_root = _parse_trust_root(openpgp["trust_root"])
    if not isinstance(openpgp["signing_policy_id"], str) or not HEX_64.fullmatch(openpgp["signing_policy_id"]):
        fail("OpenPGP signing-policy identifier is malformed")
    if openpgp["signing_policy_id"] != _signing_policy_id(openpgp):
        fail("OpenPGP signing-policy identifier does not match the exact reviewed policy")

    verifiers = _exact_object(
        authority["verifiers"],
        ("host_preflight", "persistent_image", "release_signer", "source_snapshot"),
        "source verifiers",
    )
    source_snapshot = _identity(verifiers["source_snapshot"], "source_snapshot helper", absolute_path=False)
    persistent = _identity(verifiers["persistent_image"], "persistent-image verifier", absolute_path=False)
    release_signer = _identity(
        verifiers["release_signer"], "isolated release signer", absolute_path=False
    )
    host_preflight = _identity(
        verifiers["host_preflight"], "hermetic host preflight", absolute_path=False
    )
    if (
        source_snapshot["path"] != SOURCE_SNAPSHOT_PATH
        or persistent["path"] != PERSISTENT_VERIFIER_PATH
        or release_signer["path"] != RELEASE_SIGNER_PATH
        or host_preflight["path"] != HOST_PREFLIGHT_PATH
    ):
        fail("source-authority verifier paths are not the fixed production paths")
    verifier_paths = [
        source_snapshot["path"],
        persistent["path"],
        release_signer["path"],
        host_preflight["path"],
    ]
    if len({path.casefold() for path in verifier_paths}) != len(verifier_paths):
        fail("source-authority verifier paths collide")

    dependency = _identity(authority["dependency_policy"], "dependency policy", absolute_path=False)
    if dependency["path"] != DEPENDENCY_POLICY_PATH:
        fail("source-authority dependency policy path is not the fixed production path")

    approved_dependency = _exact_object(
        authority["approved_dependency_bundle"],
        ("bundle_id", "descriptor"),
        "approved dependency bundle",
    )
    if (
        not isinstance(approved_dependency["bundle_id"], str)
        or not HEX_64.fullmatch(approved_dependency["bundle_id"])
    ):
        fail("approved dependency bundle identifier is malformed")
    _identity(
        approved_dependency["descriptor"],
        "approved dependency descriptor",
        absolute_path=True,
    )

    builder = _exact_object(
        authority["builder"],
        ("linux_amd64_manifest_digest", "oci_config_digest", "oci_index_digest"),
        "builder OCI identity",
    )
    if any(not isinstance(value, str) or not OCI_DIGEST.fullmatch(value) for value in builder.values()):
        fail("builder OCI identity contains a malformed digest")
    if len(set(builder.values())) != 3:
        fail("builder OCI index, platform manifest, and config digests must be distinct")

    _identity(authority["release_public_key"], "release public key", absolute_path=True)

    absolute_roles = {
        "git": git_binary["path"],
        "gpg": gpg_binary["path"],
        "release": authority["release_public_key"]["path"],
        "trust": trust_root["path"],
        "commit": source["commit_object"]["path"],
        "tree_ledger": source["tree_object_ledger"]["path"],
        "dependency_descriptor": approved_dependency["descriptor"]["path"],
    }
    folded = [os.path.normcase(path).casefold() for path in absolute_roles.values()]
    if len(folded) != len(set(folded)):
        fail("source-authority absolute role paths alias or case-collide")
    return authority


def _verify_campaign(
    path: Path, authority: Mapping[str, Any], pin: TrustedCampaignPin
) -> None:
    raw = _read_regular(path, MAX_CAMPAIGN_BYTES, "S19k campaign manifest")
    raw_digest = sha256_bytes(raw)
    campaign = authority["campaign"]
    if (
        raw_digest != pin.campaign_raw_sha256
        or len(raw) != pin.campaign_raw_bytes
        or raw_digest != campaign["raw_sha256"]
        or len(raw) != campaign["raw_bytes"]
    ):
        fail("raw S19k campaign manifest differs from the out-of-band authority binding")
    value = _parse_json(raw, "S19k campaign manifest", canonical=False)
    canonical = canonical_json(value)
    canonical_digest = sha256_bytes(canonical)
    if (
        canonical_digest != pin.campaign_canonical_sha256
        or len(canonical) != pin.campaign_canonical_bytes
        or canonical_digest != campaign["canonical_sha256"]
        or len(canonical) != campaign["canonical_bytes"]
    ):
        fail(
            "canonical S19k campaign manifest differs from the out-of-band "
            "authority binding"
        )
    if value.get("schema") != CAMPAIGN_SCHEMA:
        fail("S19k campaign manifest schema is invalid")
    if value.get("campaign_id") != pin.campaign_id or value.get("campaign_id") != campaign["campaign_id"]:
        fail("S19k campaign identifier differs from the trusted authority binding")


def _verify_source_files(source_root: Path, authority: Mapping[str, Any]) -> None:
    _require_directory(source_root, "admitted immutable source tree")
    for key, label in (
        ("source_snapshot", "source_snapshot helper"),
        ("persistent_image", "persistent-image verifier"),
        ("release_signer", "isolated release signer"),
        ("host_preflight", "hermetic host preflight"),
    ):
        identity = authority["verifiers"][key]
        path = _join_relative(source_root, identity["path"], label)
        _verify_identity(path, identity, label)

    dependency = authority["dependency_policy"]
    dependency_path = _join_relative(source_root, dependency["path"], "dependency policy")
    raw = _read_regular(dependency_path, MAX_BOUND_FILE_BYTES, "dependency policy")
    if sha256_bytes(raw) != dependency["sha256"] or len(raw) != dependency["bytes"]:
        fail("dependency policy differs from the campaign-pinned authority identity")
    policy = _parse_json(raw, "dependency policy", canonical=True)
    if policy.get("schema") != DEPENDENCY_POLICY_SCHEMA:
        fail("dependency policy schema is invalid")
    policy_builder = policy.get("builder")
    if not isinstance(policy_builder, dict):
        fail("dependency policy lacks a builder identity")
    builder = authority["builder"]
    for key in ("oci_index_digest", "linux_amd64_manifest_digest", "oci_config_digest"):
        if policy_builder.get(key) != builder[key]:
            fail(f"dependency policy builder {key} differs from source authority")
    image = policy_builder.get("image")
    if not isinstance(image, str) or not image.endswith("@" + builder["oci_index_digest"]):
        fail("dependency policy builder image is not bound to the authority OCI index")
    _verify_tree_ledger(authority["source"], source_root)


def _verify_external_files(authority: Mapping[str, Any]) -> None:
    openpgp = authority["openpgp"]
    for key, label in (("git_binary", "Git admission binary"), ("gpg_binary", "GPG admission binary")):
        identity = openpgp[key]
        _verify_identity(Path(identity["path"]), identity, label)
    release = authority["release_public_key"]
    _verify_identity(Path(release["path"]), release, "release public key")
    _verify_commit_object(authority["source"])
    approved = authority["approved_dependency_bundle"]
    descriptor_identity = approved["descriptor"]
    descriptor_raw = _read_regular(
        Path(descriptor_identity["path"]),
        MAX_BOUND_FILE_BYTES,
        "approved dependency descriptor",
    )
    if (
        sha256_bytes(descriptor_raw) != descriptor_identity["sha256"]
        or len(descriptor_raw) != descriptor_identity["bytes"]
    ):
        fail("approved dependency descriptor differs from source authority")
    descriptor = _parse_json(
        descriptor_raw, "approved dependency descriptor", canonical=True
    )
    if descriptor.get("schema") != DEPENDENCY_BUNDLE_SCHEMA:
        fail("approved dependency descriptor schema is invalid")
    if descriptor.get("bundle_id") != approved["bundle_id"]:
        fail("approved dependency descriptor bundle identifier differs from authority")
    descriptor_body = dict(descriptor)
    descriptor_body.pop("bundle_id", None)
    if sha256_bytes(canonical_json(descriptor_body)) != approved["bundle_id"]:
        fail("approved dependency descriptor bundle identifier is not self-authenticating")
    # Rewalk and rehash the trust root after the other external identities so a
    # concurrent replacement cannot be hidden behind the first parse pass.
    _parse_trust_root(openpgp["trust_root"])
    if _signing_policy_id(openpgp) != openpgp["signing_policy_id"]:
        fail("OpenPGP signing policy changed during authority validation")


def verify_source_authority(
    authority_path: Path,
    campaign_manifest_path: Path,
    admitted_source_root: Path,
    trusted_pin: TrustedCampaignPin,
) -> Dict[str, Any]:
    """Verify a complete authority record against one separately trusted pin.

    ``trusted_pin`` must originate outside the authority record.  The function
    intentionally accepts no signer, trust-root, tool, verifier, builder, or
    release-key override arguments.
    """

    if type(trusted_pin) is not TrustedCampaignPin:
        fail("source authority requires a typed out-of-band TrustedCampaignPin")
    trusted_pin.validate()
    validator_path = Path(os.path.abspath(__file__))
    if os.fspath(validator_path) != trusted_pin.authority_validator_path:
        fail("running authority-validator path differs from its out-of-band pin")
    validator_digest, validator_size = _hash_regular(
        validator_path,
        MAX_BOUND_FILE_BYTES,
        "source-authority validator implementation",
    )
    if (
        validator_digest != trusted_pin.authority_validator_sha256
        or validator_size != trusted_pin.authority_validator_bytes
    ):
        fail("running authority-validator bytes differ from their out-of-band pin")
    authority_file = Path(os.path.abspath(os.fspath(authority_path)))
    campaign_file = Path(os.path.abspath(os.fspath(campaign_manifest_path)))
    source_root = Path(os.path.abspath(os.fspath(admitted_source_root)))

    raw = _read_regular(authority_file, MAX_AUTHORITY_BYTES, "source-authority record")
    if sha256_bytes(raw) != trusted_pin.authority_sha256 or len(raw) != trusted_pin.authority_bytes:
        fail("source-authority record differs from its out-of-band campaign pin")
    authority = _parse_authority(_parse_json(raw, "source-authority record", canonical=True))
    if authority["campaign"]["campaign_id"] != trusted_pin.campaign_id:
        fail("source-authority record belongs to a different campaign")
    _verify_campaign(campaign_file, authority, trusted_pin)
    _verify_source_files(source_root, authority)
    _verify_external_files(authority)

    # Re-read both roots at the end.  The result remains a policy validation,
    # never proof that Git/GPG was executed or that the named commit was signed.
    final_authority = _read_regular(authority_file, MAX_AUTHORITY_BYTES, "retained source-authority record")
    final_campaign = _read_regular(campaign_file, MAX_CAMPAIGN_BYTES, "retained S19k campaign manifest")
    final_validator_digest, final_validator_size = _hash_regular(
        validator_path,
        MAX_BOUND_FILE_BYTES,
        "retained source-authority validator implementation",
    )
    if (
        final_authority != raw
        or sha256_bytes(final_campaign) != trusted_pin.campaign_raw_sha256
    ):
        fail("source-authority inputs changed during validation")
    if (
        final_validator_digest != validator_digest
        or final_validator_size != validator_size
    ):
        fail("source-authority validator implementation changed during validation")

    return {
        "schema": RESULT_SCHEMA,
        "authority_id": authority["authority_id"],
        "authority_record_sha256": trusted_pin.authority_sha256,
        "campaign_id": trusted_pin.campaign_id,
        "campaign_raw_sha256": trusted_pin.campaign_raw_sha256,
        "campaign_raw_bytes": trusted_pin.campaign_raw_bytes,
        "campaign_canonical_sha256": trusted_pin.campaign_canonical_sha256,
        "campaign_canonical_bytes": trusted_pin.campaign_canonical_bytes,
        "source_commit": authority["source"]["commit_oid"],
        "source_tree": authority["source"]["tree_oid"],
        "source_object_format": authority["source"]["object_format"],
        "commit_object_sha256": authority["source"]["commit_object"]["sha256"],
        "commit_object_bytes": authority["source"]["commit_object"]["bytes"],
        "tree_object_ledger_sha256": authority["source"]["tree_object_ledger"][
            "sha256"
        ],
        "authority_validator_sha256": trusted_pin.authority_validator_sha256,
        "signing_policy_id": authority["openpgp"]["signing_policy_id"],
        "dependency_policy_sha256": authority["dependency_policy"]["sha256"],
        "approved_dependency_bundle_id": authority["approved_dependency_bundle"][
            "bundle_id"
        ],
        "approved_dependency_descriptor_sha256": authority[
            "approved_dependency_bundle"
        ]["descriptor"]["sha256"],
        "builder": dict(authority["builder"]),
        "release_public_key_sha256": authority["release_public_key"]["sha256"],
        "commit_signature_verified": False,
        "policy_inputs_verified": True,
        "scope": dict(_SCOPE),
        # This is the already-validated exact record, not a second source of
        # caller-selected policy.  The producer consumes tool/trust paths and
        # verifier identities only from this retained projection.
        "validated_authority": authority,
    }


def main(argv: Sequence[str] = ()) -> int:
    """Refuse caller-selected production pins at the command line."""

    parser = argparse.ArgumentParser(
        description=(
            "S19k source-authority library. Production verification is import-only "
            "because its TrustedCampaignPin must come from authenticated caller code."
        )
    )
    parser.add_argument(
        "--describe",
        action="store_true",
        help="print the schema and non-authority boundary",
    )
    args = parser.parse_args(list(argv))
    if args.describe:
        print(
            canonical_json(
                {
                    "schema": AUTHORITY_SCHEMA,
                    "claim": AUTHORITY_CLAIM,
                    "production_cli_verification": False,
                    "reason": "trusted campaign pin must be supplied by authenticated integration code",
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    parser.error(
        "production verification cannot accept caller-selected policy or pin values; "
        "import verify_source_authority with an authenticated TrustedCampaignPin"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
