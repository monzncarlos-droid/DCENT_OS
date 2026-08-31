#!/usr/bin/env python3
"""Fail-closed Linux host preflight for the S19k hermetic producer.

This check grants no build, release, install, target-contact, or flash authority.
It verifies only that production allocation parents and the local Docker service
meet the minimum custody and worst-case capacity contract before allocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Mapping, NoReturn, Sequence


SCHEMA = "dcentos.s19k-hermetic-host-preflight/v1"
GIB = 1024**3
MAX_DEPENDENCY_CLOSURE_BYTES = 64 * GIB
MATERIALIZER_AND_SEALED_COPIES = 2
BUILD_WORKSPACE_BYTES_PER_RUN = 96 * GIB
BUILD_RUNS = 2
PUBLICATION_AND_LOG_BYTES = 8 * GIB
FAILURE_HEADROOM_BYTES = 64 * GIB
REQUIRED_FREE_BYTES = (
    MAX_DEPENDENCY_CLOSURE_BYTES * MATERIALIZER_AND_SEALED_COPIES
    + BUILD_WORKSPACE_BYTES_PER_RUN * BUILD_RUNS
    + PUBLICATION_AND_LOG_BYTES
    + FAILURE_HEADROOM_BYTES
)
MAX_DEPENDENCY_FILES = 1_000_000
REQUIRED_FREE_INODES = 8_000_000
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")


class PreflightError(RuntimeError):
    """The host cannot safely begin a production hermetic run."""


def fail(message: str) -> NoReturn:
    raise PreflightError(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _decode_mountinfo_path(value: str) -> str:
    return MOUNTINFO_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def linux_mount_contract(path: Path) -> tuple[str, frozenset[str], str]:
    if os.name == "nt" or not hasattr(os, "getuid"):
        fail("production hermetic execution requires a Linux host")
    resolved = Path(os.path.realpath(os.fspath(path)))
    try:
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read Linux mount custody for {path}: {error}")
    matches: list[tuple[int, str, frozenset[str], str]] = []
    for row in rows:
        if " - " not in row:
            fail("Linux mountinfo contains a malformed row")
        left_raw, right_raw = row.split(" - ", 1)
        left = left_raw.split()
        right = right_raw.split()
        if len(left) < 6 or len(right) < 3:
            fail("Linux mountinfo contains a truncated row")
        mountpoint = Path(_decode_mountinfo_path(left[4]))
        try:
            inside = os.path.commonpath((resolved, mountpoint)) == os.fspath(mountpoint)
        except ValueError:
            inside = False
        if inside:
            matches.append(
                (len(mountpoint.parts), right[0], frozenset(left[5].split(",")), os.fspath(mountpoint))
            )
    if not matches:
        fail(f"production root has no identifiable Linux mount: {path}")
    _, filesystem, options, mountpoint = max(matches, key=lambda item: item[0])
    return filesystem, options, mountpoint


def verify_private_root(path: Path, label: str) -> dict[str, Any]:
    if not LABEL.fullmatch(label):
        fail(f"invalid production-root label: {label!r}")
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a real directory")
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        fail("production hermetic execution requires POSIX UID/GID custody")
    uid = os.getuid()
    gid = os.getgid()
    if uid < 1000 or gid < 1000:
        fail("production roots require host UID and GID both >=1000")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail(f"{label} is not owned by the executing UID/GID")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} must have exact mode 0700")
    filesystem, options, mountpoint = linux_mount_contract(absolute)
    if filesystem != "ext4" or "rw" not in options:
        fail(f"{label} must be on one writable Linux-native ext4 mount")
    capacity = os.statvfs(absolute)
    free_bytes = capacity.f_bavail * capacity.f_frsize
    free_inodes = capacity.f_favail
    if free_bytes < REQUIRED_FREE_BYTES:
        fail(
            f"{label} filesystem has {free_bytes} free bytes; "
            f"worst-case custody requires {REQUIRED_FREE_BYTES}"
        )
    if free_inodes < REQUIRED_FREE_INODES:
        fail(
            f"{label} filesystem has {free_inodes} free inodes; "
            f"worst-case custody requires {REQUIRED_FREE_INODES}"
        )
    return {
        "label": label,
        "path": os.fspath(absolute),
        "device": metadata.st_dev,
        "filesystem": filesystem,
        "mountpoint": mountpoint,
        "mount_options": sorted(options),
        "mode": "0700",
        "uid": uid,
        "gid": gid,
        "free_bytes": free_bytes,
        "free_inodes": free_inodes,
    }


def _regular_binary_identity(path: Path) -> dict[str, Any]:
    resolved = Path(os.path.realpath(os.fspath(path)))
    metadata = os.lstat(resolved)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Docker client does not resolve to a regular file")
    digest = hashlib.sha256()
    size = 0
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    if size != metadata.st_size:
        fail("Docker client changed while it was hashed")
    return {"path": os.fspath(resolved), "sha256": digest.hexdigest(), "bytes": size}


def verify_docker(docker_binary: str = "docker") -> dict[str, Any]:
    selected = shutil.which(docker_binary)
    if selected is None:
        fail("Docker client is unavailable")
    identity = _regular_binary_identity(Path(selected))
    try:
        completed = subprocess.run(
            (identity["path"], "version", "--format", "{{json .}}"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"Docker service admission failed: {error}")
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        fail("Docker service is unavailable: " + (detail[0] if detail else "unknown error"))
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Docker version output is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail("Docker version output is not an object")
    client = value.get("Client")
    server = value.get("Server")
    if not isinstance(client, dict) or not isinstance(server, dict):
        fail("Docker client/server identity is incomplete")
    for label, section in (("client", client), ("server", server)):
        if not isinstance(section.get("Version"), str) or not section["Version"]:
            fail(f"Docker {label} version is absent")
        if section.get("Os") not in (None, "linux") and label == "server":
            fail("Docker server is not Linux")
    return {
        "binary": identity,
        "client_version": client["Version"],
        "server_version": server["Version"],
        "server_os": server.get("Os", "linux"),
    }


def parse_roots(values: Sequence[str]) -> list[tuple[str, Path]]:
    parsed: list[tuple[str, Path]] = []
    labels: set[str] = set()
    paths: set[str] = set()
    for value in values:
        if "=" not in value:
            fail("each --root must be LABEL=ABSOLUTE_PATH")
        label, raw_path = value.split("=", 1)
        if not LABEL.fullmatch(label) or label in labels:
            fail("production-root labels must be unique canonical tokens")
        path = Path(raw_path)
        if not path.is_absolute() or path != Path(os.path.abspath(os.fspath(path))):
            fail(f"production root {label} is not an absolute normalized path")
        folded = os.path.normcase(os.fspath(path))
        if folded in paths:
            fail("production roots must not repeat a path")
        labels.add(label)
        paths.add(folded)
        parsed.append((label, path))
    if not parsed:
        fail("at least one production allocation root is required")
    return parsed


def build_report(
    roots: Sequence[tuple[str, Path]], docker: Mapping[str, Any]
) -> dict[str, Any]:
    if not roots:
        fail("at least one production allocation root is required")
    labels: set[str] = set()
    normalized: list[tuple[str, Path]] = []
    for label, path in roots:
        absolute = Path(os.path.abspath(os.fspath(path)))
        if not LABEL.fullmatch(label) or label in labels:
            fail("production-root labels must be unique canonical tokens")
        if not path.is_absolute() or path != absolute:
            fail(f"production root {label} is not an absolute normalized path")
        for previous_label, previous in normalized:
            try:
                common = Path(os.path.commonpath((absolute, previous)))
            except ValueError:
                continue
            if common in (absolute, previous):
                fail(
                    "production roots must not repeat or overlap by ancestry: "
                    f"{previous_label}, {label}"
                )
        labels.add(label)
        normalized.append((label, absolute))
    observations = [verify_private_root(path, label) for label, path in normalized]
    devices: dict[int, dict[str, int]] = {}
    for observation in observations:
        device = observation["device"]
        existing = devices.get(device)
        capacity = {
            "free_bytes": observation["free_bytes"],
            "free_inodes": observation["free_inodes"],
        }
        if existing is not None and existing != capacity:
            fail("same-filesystem capacity observations disagree")
        devices[device] = capacity
    return {
        "schema": SCHEMA,
        "claim": "host-custody-and-worst-case-capacity-preflight-only",
        "capacity_model": {
            "max_dependency_closure_bytes": MAX_DEPENDENCY_CLOSURE_BYTES,
            "materializer_and_sealed_copies": MATERIALIZER_AND_SEALED_COPIES,
            "build_workspace_bytes_per_run": BUILD_WORKSPACE_BYTES_PER_RUN,
            "build_runs": BUILD_RUNS,
            "publication_and_log_bytes": PUBLICATION_AND_LOG_BYTES,
            "failure_headroom_bytes": FAILURE_HEADROOM_BYTES,
            "required_free_bytes_per_filesystem": REQUIRED_FREE_BYTES,
            "max_dependency_files": MAX_DEPENDENCY_FILES,
            "required_free_inodes_per_filesystem": REQUIRED_FREE_INODES,
        },
        "docker": dict(docker),
        "docker_trust_nonclaim": (
            "client-bytes-and-client-server-version-only; daemon-endpoint-context-"
            "daemon-id-rootless-kernel-and-security-posture-not-bound"
        ),
        "roots": observations,
        "production_ready": False,
        "release_authority_granted": False,
        "install_authority_granted": False,
        "flash_authority_granted": False,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--docker-binary", default="docker")
    value.add_argument("--root", action="append", default=[], metavar="LABEL=ABSOLUTE_PATH")
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        roots = parse_roots(arguments.root)
        report = build_report(roots, verify_docker(arguments.docker_binary))
    except (OSError, PreflightError) as error:
        print(f"S19K_HERMETIC_HOST_PREFLIGHT_REFUSED: {error}", file=os.sys.stderr)
        return 1
    os.sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
