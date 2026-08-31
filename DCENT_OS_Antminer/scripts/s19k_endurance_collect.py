#!/usr/bin/env python3
"""Run and drain one receipt-bound S19k Track-1 endurance observation.

The collector is the sole supported launcher for the endurance mode.  It keeps
the long-lived runner on one SSH channel while using separate pinned channels
to copy each immutable segment, fsync a host manifest entry, and acknowledge
that exact entry.  A disconnect is a failed observation; the target runner's
watchdog remains responsible for checked SafeOff.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import time
from typing import Iterable

import s19k_endurance_baseline as baseline_builder
import s19k_endurance_verify as verifier


ACK_MARKER = re.compile(
    rb"^S19K_ENDURANCE_ACK_OK sequence=([0-9]+) segment_sha256=([0-9a-f]{64}) manifest_sha256=([0-9a-f]{64})\n$"
)
PUBLICATION_SCRATCH = re.compile(
    r"^\.(?P<target>[A-Za-z0-9_.-]+)\.tmp\.(?P<pid>[1-9][0-9]*)\.(?P<nonce>[0-9a-f]{16})$"
)
PUBLICATION_TARGET = re.compile(r"^[A-Za-z0-9_.-]+$")
TRANSIENT_SSH = 255
NOT_YET_PUBLISHED = 3
FINAL_NAMES = (
    "daemon_terminal",
    "terminal_handoff",
    "safeoff",
    "endurance_receipt",
    "runtime_active_pre_safeoff",
    "runtime_pending",
)
FAILURE_FINAL_NAMES = (
    "daemon_failure",
    "terminal_handoff",
    "safeoff",
    "endurance_failure_receipt",
    "runtime_active_pre_safeoff",
    "runtime_pending",
)


class EnduranceCollectionError(RuntimeError):
    """The off-target evidence transaction could not be completed."""


class CollectedEnduranceFailure(RuntimeError):
    """A failed run produced a fully verified controlled-fault evidence bundle."""

    def __init__(self, receipt: Path, runner_status: int) -> None:
        super().__init__(f"runner_status={runner_status} receipt={receipt}")
        self.receipt = receipt
        self.runner_status = runner_status


def fail(message: str) -> None:
    raise EnduranceCollectionError(message)


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        fail(
            "endurance evidence publication requires POSIX directory fsync; "
            "run the collector inside WSL/Linux, not native Windows Python"
        )
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_private_directory(path: Path, label: str) -> None:
    try:
        os.mkdir(path, 0o700)
    except OSError as error:
        fail(f"cannot create new {label}: {path}: {error}")
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not a real directory after creation: {path}")
    if os.name != "nt" and (
        metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(f"{label} does not have exact current-owner mode 0700: {path}")
    try:
        fsync_directory(path.parent)
    except OSError as error:
        fail(f"cannot fsync parent of {label}: {error}")


def publish_new(path: Path, data: bytes) -> None:
    if not PUBLICATION_TARGET.fullmatch(path.name):
        fail(f"evidence filename is not canonical: {path.name}")
    scratch = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(scratch, flags, 0o600)
    except OSError as error:
        fail(f"cannot create evidence scratch for {path}: {error}")
    linked = False
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                fail(f"short write preparing {path}")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(data)
            or (os.name != "nt" and (
                metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ))
        ):
            fail(f"prepared evidence inode is inexact: {path}")
        try:
            os.link(scratch, path, follow_symlinks=False)
        except OSError as error:
            fail(f"cannot publish new evidence file {path}: {error}")
        linked = True
        fsync_directory(path.parent)
    finally:
        os.close(descriptor)
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass
        except OSError as error:
            if linked:
                fail(f"cannot retire published evidence scratch {scratch}: {error}")
    if linked:
        fsync_directory(path.parent)


def clean_stale_publication_scratch(path: Path, label: str) -> None:
    """Remove only exact private scratch names left by an interrupted publisher."""
    verifier.require_real_directory(path, label)
    changed = False
    for child in list(path.iterdir()):
        match = PUBLICATION_SCRATCH.fullmatch(child.name)
        if match is None:
            continue
        metadata = os.lstat(child)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (os.name != "nt" and (
                metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ))
        ):
            fail(f"{label} contains an inexact publication scratch: {child.name}")
        target = path / match.group("target")
        if target.exists():
            target_metadata = os.lstat(target)
            if (
                not stat.S_ISREG(target_metadata.st_mode)
                or stat.S_ISLNK(target_metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_nlink)
                != (target_metadata.st_dev, target_metadata.st_ino, 2)
            ):
                fail(f"{label} publication scratch is not the target's sole extra link")
        elif metadata.st_nlink != 1:
            fail(f"{label} unpublished scratch has an inexact link count")
        os.unlink(child)
        changed = True
    if changed:
        fsync_directory(path)


def publish_or_match(path: Path, data: bytes, label: str) -> None:
    clean_stale_publication_scratch(path.parent, f"{label} parent")
    if path.exists():
        observed = verifier.stable_regular_bytes(path, label, max(len(data), 65_536))
        if observed != data:
            fail(f"existing {label} differs from the resumed target bytes")
        return
    publish_new(path, data)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_known_host(miner_ip: str, known_hosts: Path, expected: str) -> None:
    data = verifier.stable_regular_bytes(known_hosts, "known-hosts", 1024 * 1024)
    if not data:
        fail("known-hosts is empty")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected):
        fail("expected host key is not a canonical OpenSSH SHA256 fingerprint")
    found = subprocess.run(
        ("ssh-keygen", "-F", miner_ip, "-f", os.fspath(known_hosts)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if found.returncode not in (0, 1):
        fail(f"ssh-keygen could not inspect known-hosts: {found.stderr.decode('utf-8', 'replace').strip()}")
    key_lines = [line for line in found.stdout.splitlines() if line and not line.startswith(b"#") and len(line.split()) >= 3]
    fingerprints: list[str] = []
    for key_line in key_lines:
        fingerprint = subprocess.run(
            ("ssh-keygen", "-lf", "-", "-E", "sha256"),
            input=key_line + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if fingerprint.returncode:
            fail("known-hosts contains a key ssh-keygen cannot fingerprint")
        columns = fingerprint.stdout.decode("ascii", "strict").split()
        if len(columns) < 2:
            fail("ssh-keygen returned a malformed fingerprint")
        fingerprints.append(columns[1])
    if fingerprints != [expected]:
        fail(f"known-hosts must contain exactly the expected key for {miner_ip}")


def self_admit(plan: dict[str, str], baseline_data: bytes, baseline_path: Path) -> None:
    collector_path = Path(__file__)
    collector_data = verifier.stable_regular_bytes(collector_path, "endurance collector", 1024 * 1024)
    verifier_path = collector_path.with_name("s19k_endurance_verify.py")
    verifier_data = verifier.stable_regular_bytes(verifier_path, "endurance verifier", 2 * 1024 * 1024)
    checks = (
        ("collector", collector_data, "endurance_collector_sha256", "endurance_collector_bytes"),
        ("verifier", verifier_data, "endurance_verifier_sha256", "endurance_verifier_bytes"),
        ("baseline", baseline_data, "endurance_baseline_sha256", "endurance_baseline_bytes"),
    )
    for label, data, hash_key, size_key in checks:
        if sha256_bytes(data) != plan[hash_key] or len(data) != int(plan[size_key]):
            fail(f"content-bound {label} bytes do not match the launch plan")
    declaration = int(verifier.parse_baseline(baseline_path)[0]["declared_before_launch_unix_s"])
    if declaration > int(time.time()):
        fail("baseline claims it was declared in the future")


def admit_phase3_provenance(
    args: argparse.Namespace,
    baseline: dict[str, str],
) -> dict[str, bytes]:
    return baseline_builder.verify_against_baseline(
        baseline,
        args.phase3_plan,
        args.phase3_trial_dir,
        args.phase3_wall_power_csv,
        args.phase3_physical_dir,
    )


def verify_stored_phase3_provenance(
    evidence_dir: Path,
    baseline: dict[str, str],
    expected: dict[str, bytes],
) -> str:
    path = evidence_dir / "phase3_provenance"
    verifier.require_real_directory(path, "stored Phase-3 provenance directory")
    clean_stale_publication_scratch(path, "stored Phase-3 provenance directory")
    if tuple(sorted(expected)) != tuple(sorted(baseline_builder.PROVENANCE_FILENAMES)):
        fail("Phase-3 provenance builder returned an inexact file set")
    for filename, _, _, maximum in verifier.PHASE3_PROVENANCE_FILES:
        observed = verifier.stable_regular_bytes(
            path / filename,
            f"stored Phase-3 provenance {filename}",
            maximum,
        )
        if observed != expected[filename]:
            fail(f"stored Phase-3 provenance differs from re-admitted bytes: {filename}")
    return verifier.verify_phase3_provenance(evidence_dir, baseline)


def ssh_base(known_hosts: Path) -> tuple[str, ...]:
    return (
        "ssh", "-F", os.devnull, "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    )


def runner_tokens(plan: dict[str, str]) -> list[str]:
    try:
        tokens = shlex.split(plan["launch"], posix=True)
    except ValueError as error:
        fail(f"cannot parse launch command: {error}")
    if len(tokens) != 15 or tokens[1] != "run" or tokens[2] != plan["remote_dir"]:
        fail("launch command does not have the exact runner argument geometry")
    if any(not token or re.search(r"[\x00-\x20'\"\\$`;|&<>(){}\[\]*?!]", token) for token in tokens):
        fail("launch command contains a shell-active or non-canonical token")
    return tokens


def remote_command(base_tokens: list[str], mode: str, *extra: object) -> str:
    if mode not in ("run", "endurance-read", "endurance-ack", "endurance-final-read"):
        fail("internal collector mode is invalid")
    tokens = list(base_tokens)
    tokens[1] = mode
    tokens.extend(str(item) for item in extra)
    return shlex.join(tokens)


def run_ssh(
    ssh: tuple[str, ...], miner_ip: str, command: str, timeout_s: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            (*ssh, f"root@{miner_ip}", command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        fail(f"SSH evidence operation timed out: {command.split()[1]}: {error}")


def read_segment(
    ssh: tuple[str, ...], miner_ip: str, tokens: list[str], sequence: int,
) -> subprocess.CompletedProcess[bytes]:
    return run_ssh(ssh, miner_ip, remote_command(tokens, "endurance-read", sequence), 30)


def manifest_entry(sequence: int, segment_data: bytes, predecessor: str, collected_ms: int) -> bytes:
    fields = (
        ("schema", verifier.MANIFEST_SCHEMA),
        ("sequence", str(sequence)),
        ("predecessor_manifest_sha256", predecessor),
        ("segment_relative_path", f"segments/segment.{sequence:06}.kv"),
        ("segment_sha256", sha256_bytes(segment_data)),
        ("segment_bytes", str(len(segment_data))),
        ("collected_wall_unix_ms", str(collected_ms)),
        ("publication", "host-create-new-fsync"),
    )
    return "".join(f"{key}={value}\n" for key, value in fields).encode("ascii")


def acknowledge(
    ssh: tuple[str, ...],
    miner_ip: str,
    tokens: list[str],
    sequence: int,
    segment_data: bytes,
    predecessor_manifest: str,
    manifest_data: bytes,
    collected_ms: int,
) -> None:
    segment_sha = sha256_bytes(segment_data)
    manifest_sha = sha256_bytes(manifest_data)
    result = run_ssh(
        ssh,
        miner_ip,
        remote_command(
            tokens,
            "endurance-ack",
            sequence,
            segment_sha,
            len(segment_data),
            predecessor_manifest,
            manifest_sha,
            len(manifest_data),
            collected_ms,
        ),
        30,
    )
    expected = f"S19K_ENDURANCE_ACK_OK sequence={sequence} segment_sha256={segment_sha} manifest_sha256={manifest_sha}\n".encode("ascii")
    if result.returncode or result.stdout != expected or result.stderr:
        fail(
            f"target refused segment {sequence} acknowledgement: rc={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr.decode('utf-8', 'replace').strip()}"
        )


def terminate_runner(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def wait_for_independent_safeoff_decay(
    meter_path: Path,
    final_collected_ms: int,
    safeoff_power_max_mw: int,
    timeout_s: float = 180,
) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = "no post-SafeOff meter samples"
    while time.monotonic() < deadline:
        try:
            rows, _ = verifier.load_meter(meter_path)
            verifier.verify_contiguous_post_safeoff_decay(
                rows,
                final_collected_ms,
                safeoff_power_max_mw,
                "independent post-SafeOff wall-power decay",
            )
            return
        except (verifier.EnduranceVerificationError, OSError) as error:
            last_error = str(error)
        time.sleep(1)
    fail(f"independent post-SafeOff power decay was not observed within {timeout_s:g}s: {last_error}")


def fetch_final_receipt(
    ssh: tuple[str, ...],
    miner_ip: str,
    tokens: list[str],
    name: str,
    timeout_s: float,
) -> bytes:
    deadline = time.monotonic() + timeout_s
    while True:
        result = run_ssh(
            ssh,
            miner_ip,
            remote_command(tokens, "endurance-final-read", name),
            30,
        )
        if result.returncode == 0:
            if result.stderr or not result.stdout or len(result.stdout) > 65_536:
                fail(f"final target receipt {name} returned inexact bytes")
            return result.stdout
        if (
            result.returncode == NOT_YET_PUBLISHED
            and not result.stdout
            and not result.stderr
            and time.monotonic() < deadline
        ):
            time.sleep(1)
            continue
        fail(
            f"could not fetch final target receipt {name}: rc={result.returncode} "
            f"stderr={result.stderr.decode('utf-8', 'replace').strip()}"
        )


def resume_local_manifest_chain(
    evidence_dir: Path,
) -> tuple[
    int,
    str,
    list[tuple[bytes, bytes, int, str]],
    tuple[bytes, int, str, str, int] | None,
]:
    clean_stale_publication_scratch(
        evidence_dir / "segments",
        "resumed segment directory",
    )
    clean_stale_publication_scratch(
        evidence_dir / "manifests",
        "resumed manifest directory",
    )
    segments = verifier._names(
        evidence_dir / "segments",
        verifier.SEGMENT_NAME,
        "resumed segment directory",
        allow_empty=True,
    )
    manifests = verifier._names(
        evidence_dir / "manifests",
        verifier.MANIFEST_NAME,
        "resumed manifest directory",
        allow_empty=True,
    )
    if len(manifests) not in (len(segments), len(segments) + 1):
        fail("resumed evidence is not complete pairs plus at most one manifest-first transaction")
    if len(manifests) > verifier.MAX_SEGMENTS:
        fail("resumed evidence exceeds the declared maximum segment geometry")
    predecessor = verifier.EMPTY_SHA256
    rows: list[tuple[bytes, bytes, int, str]] = []
    for sequence, segment_path in segments:
        segment = verifier.stable_regular_bytes(
            segment_path,
            f"resumed segment {sequence}",
            verifier.MAX_SEGMENT_BYTES,
        )
        fields, _ = verifier.parse_kv_bytes(segment, f"resumed segment {sequence}")
        if fields.get("schema") != verifier.SEGMENT_SCHEMA or fields.get("sequence") != str(sequence):
            fail(f"resumed segment {sequence} has a different identity")
        manifest_path = manifests[sequence][1]
        manifest = verifier.stable_regular_bytes(
            manifest_path,
            f"resumed manifest {sequence}",
            4096,
        )
        manifest_fields, _ = verifier.parse_kv_bytes(
            manifest,
            f"resumed manifest {sequence}",
            verifier.MANIFEST_KEYS,
        )
        expected = manifest_entry(
            sequence,
            segment,
            predecessor,
            int(manifest_fields["collected_wall_unix_ms"]),
        )
        if manifest != expected:
            fail(f"resumed manifest {sequence} does not bind its exact segment/predecessor")
        rows.append(
            (
                segment,
                manifest,
                int(manifest_fields["collected_wall_unix_ms"]),
                predecessor,
            )
        )
        predecessor = sha256_bytes(manifest)
    pending: tuple[bytes, int, str, str, int] | None = None
    if len(manifests) == len(segments) + 1:
        sequence = len(segments)
        manifest = verifier.stable_regular_bytes(
            manifests[sequence][1],
            f"pending resumed manifest {sequence}",
            4096,
        )
        fields, _ = verifier.parse_kv_bytes(
            manifest,
            f"pending resumed manifest {sequence}",
            verifier.MANIFEST_KEYS,
        )
        verifier.require_field(fields, "schema", verifier.MANIFEST_SCHEMA, "pending resumed manifest")
        verifier.require_field(fields, "sequence", str(sequence), "pending resumed manifest")
        verifier.require_field(
            fields,
            "predecessor_manifest_sha256",
            predecessor,
            "pending resumed manifest",
        )
        verifier.require_field(
            fields,
            "segment_relative_path",
            f"segments/segment.{sequence:06}.kv",
            "pending resumed manifest",
        )
        verifier.require_field(
            fields,
            "publication",
            "host-create-new-fsync",
            "pending resumed manifest",
        )
        segment_sha = verifier.require_sha256(
            fields["segment_sha256"],
            "pending resumed segment",
        )
        segment_bytes = verifier.canonical_uint(
            fields["segment_bytes"],
            "pending resumed segment size",
            positive=True,
            maximum=verifier.MAX_SEGMENT_BYTES,
        )
        collected_ms = verifier.canonical_uint(
            fields["collected_wall_unix_ms"],
            "pending resumed collection time",
            positive=True,
        )
        pending = (manifest, collected_ms, predecessor, segment_sha, segment_bytes)
    return len(segments), predecessor, rows, pending


def resume_failure(args: argparse.Namespace) -> Path:
    """Collect a fail-closed bundle after the original collector was killed."""
    plan, plan_data = verifier.parse_plan(args.plan)
    baseline, baseline_data = verifier.parse_baseline(args.baseline)
    if plan["miner_target_sha256"] != sha256_bytes(args.miner_ip.encode("utf-8")):
        fail("miner address does not match the launch-plan target binding")
    if plan["ssh_host_key_sha256"] != args.expected_host_key_sha256:
        fail("operator host-key pin does not match the launch plan")
    verify_known_host(args.miner_ip, args.known_hosts, args.expected_host_key_sha256)
    self_admit(plan, baseline_data, args.baseline)
    phase3_files = admit_phase3_provenance(args, baseline)
    verifier.stable_regular_bytes(args.wall_power_csv, "wall-power CSV", 32 * 1024 * 1024)
    verifier.require_real_directory(args.evidence_dir, "resumed evidence directory")
    for name in ("segments", "manifests", "final", "phase3_provenance"):
        verifier.require_real_directory(args.evidence_dir / name, f"resumed {name} directory")
    clean_stale_publication_scratch(args.evidence_dir, "resumed evidence directory")
    for name in ("segments", "manifests", "final", "phase3_provenance"):
        clean_stale_publication_scratch(
            args.evidence_dir / name,
            f"resumed {name} directory",
        )
    stored_plan = verifier.stable_regular_bytes(
        args.evidence_dir / "launch_plan.kv", "stored launch plan", 65_536
    )
    stored_baseline = verifier.stable_regular_bytes(
        args.evidence_dir / "baseline.kv", "stored baseline", 4096
    )
    if stored_plan != plan_data or stored_baseline != baseline_data:
        fail("resume inputs differ from the original collection admission")
    verify_stored_phase3_provenance(
        args.evidence_dir,
        baseline,
        phase3_files,
    )

    ssh = ssh_base(args.known_hosts)
    tokens = runner_tokens(plan)
    final_dir = args.evidence_dir / "final"
    # Do not acknowledge anything until the daemon has already failed closed;
    # reconnecting early must not accidentally rescue the collector-loss test.
    daemon_failure = fetch_final_receipt(
        ssh,
        args.miner_ip,
        tokens,
        "daemon_failure",
        600,
    )
    publish_or_match(
        final_dir / "daemon_failure",
        daemon_failure,
        "resumed daemon failure",
    )

    sequence, predecessor_manifest, existing, pending = resume_local_manifest_chain(args.evidence_dir)
    for existing_sequence, (segment, manifest, collected_ms, predecessor) in enumerate(existing):
        acknowledge(
            ssh,
            args.miner_ip,
            tokens,
            existing_sequence,
            segment,
            predecessor,
            manifest,
            collected_ms,
        )
    if pending is not None:
        manifest, collected_ms, predecessor, expected_sha, expected_bytes = pending
        observed = read_segment(ssh, args.miner_ip, tokens, sequence)
        if (
            observed.returncode != 0
            or observed.stderr
            or not observed.stdout
            or len(observed.stdout) > verifier.MAX_SEGMENT_BYTES
            or sha256_bytes(observed.stdout) != expected_sha
            or len(observed.stdout) != expected_bytes
        ):
            fail(f"resumed manifest-first segment {sequence} did not match its durable journal")
        fields, _ = verifier.parse_kv_bytes(
            observed.stdout,
            f"resumed manifest-first segment {sequence}",
        )
        if fields.get("schema") != verifier.SEGMENT_SCHEMA or fields.get("sequence") != str(sequence):
            fail(f"resumed manifest-first segment {sequence} has a different identity")
        publish_new(
            args.evidence_dir / "segments" / f"segment.{sequence:06}.kv",
            observed.stdout,
        )
        acknowledge(
            ssh,
            args.miner_ip,
            tokens,
            sequence,
            observed.stdout,
            predecessor,
            manifest,
            collected_ms,
        )
        predecessor_manifest = sha256_bytes(manifest)
        sequence += 1
    while True:
        observed = read_segment(ssh, args.miner_ip, tokens, sequence)
        if observed.returncode == NOT_YET_PUBLISHED and not observed.stdout and not observed.stderr:
            break
        if observed.returncode != 0:
            fail(
                f"resumed target segment read failed: sequence={sequence} "
                f"rc={observed.returncode} stderr={observed.stderr.decode('utf-8', 'replace').strip()}"
            )
        if observed.stderr or not observed.stdout or len(observed.stdout) > verifier.MAX_SEGMENT_BYTES:
            fail(f"resumed segment {sequence} returned inexact bytes or diagnostics")
        if sequence >= verifier.MAX_SEGMENTS:
            fail("resumed target exceeded the declared maximum segment geometry")
        fields, _ = verifier.parse_kv_bytes(observed.stdout, f"resumed segment {sequence}")
        if fields.get("schema") != verifier.SEGMENT_SCHEMA or fields.get("sequence") != str(sequence):
            fail(f"resumed target returned a different segment for sequence {sequence}")
        collected_ms = now_ms()
        manifest = manifest_entry(sequence, observed.stdout, predecessor_manifest, collected_ms)
        publish_new(
            args.evidence_dir / "manifests" / f"manifest.{sequence:06}.kv",
            manifest,
        )
        segment_path = args.evidence_dir / "segments" / f"segment.{sequence:06}.kv"
        publish_new(segment_path, observed.stdout)
        acknowledge(
            ssh,
            args.miner_ip,
            tokens,
            sequence,
            observed.stdout,
            predecessor_manifest,
            manifest,
            collected_ms,
        )
        predecessor_manifest = sha256_bytes(manifest)
        sequence += 1
        if sequence > verifier.MAX_SEGMENTS:
            fail("resumed target exceeded the declared maximum segment geometry")

    final_bytes: dict[str, bytes] = {"daemon_failure": daemon_failure}
    for name in FAILURE_FINAL_NAMES[1:]:
        data = fetch_final_receipt(ssh, args.miner_ip, tokens, name, 180)
        publish_or_match(final_dir / name, data, f"resumed final target receipt {name}")
        final_bytes[name] = data
    collection_path = args.evidence_dir / "FAILURE_COLLECTION.kv"
    if collection_path.exists():
        existing_collection = verifier.stable_regular_bytes(
            collection_path,
            "resumed failure collection receipt",
            4096,
        )
        existing_fields, _ = verifier.parse_kv_bytes(
            existing_collection,
            "resumed failure collection receipt",
            verifier.FAILURE_COLLECTION_KEYS,
        )
        final_collected_ms = int(existing_fields["collected_wall_unix_ms"])
    else:
        final_collected_ms = now_ms()
    collection = (
        "schema=dcentos.s19k-endurance-failure-final-collection/v1\n"
        f"daemon_failure_sha256={sha256_bytes(final_bytes['daemon_failure'])}\n"
        f"terminal_handoff_sha256={sha256_bytes(final_bytes['terminal_handoff'])}\n"
        f"safeoff_sha256={sha256_bytes(final_bytes['safeoff'])}\n"
        f"endurance_failure_receipt_sha256={sha256_bytes(final_bytes['endurance_failure_receipt'])}\n"
        f"runtime_active_pre_safeoff_sha256={sha256_bytes(final_bytes['runtime_active_pre_safeoff'])}\n"
        f"runtime_pending_sha256={sha256_bytes(final_bytes['runtime_pending'])}\n"
        f"collected_wall_unix_ms={final_collected_ms}\n"
        "publication=host-create-new-fsync\n"
    ).encode("ascii")
    publish_or_match(collection_path, collection, "resumed failure collection receipt")
    wait_for_independent_safeoff_decay(
        args.wall_power_csv,
        final_collected_ms,
        int(baseline["safeoff_wall_power_max_mw"]),
    )
    result = verifier.verify_evidence(
        args.evidence_dir,
        args.baseline,
        args.wall_power_csv,
        args.plan,
        expected_failure=True,
    )
    wrapper_status = int(result["wrapper_exit_status"])
    receipt_path = args.evidence_dir / "HOST_ENDURANCE_FAILURE_VERIFICATION.kv"
    if receipt_path.exists():
        existing_host = verifier.stable_regular_bytes(
            receipt_path,
            "resumed host failure verification receipt",
            65_536,
        )
        existing_fields, _ = verifier.parse_kv_bytes(
            existing_host,
            "resumed host failure verification receipt",
        )
        if (
            existing_fields.get("schema") != verifier.FINAL_FAILURE_RECEIPT_SCHEMA
            or existing_fields.get("outcome") != "controlled-failure-evidence-pass"
            or existing_fields.get("wrapper_exit_status") != str(wrapper_status)
            or existing_fields.get("daemon_failure_sha256")
            != result["daemon_failure_sha256"]
            or existing_fields.get("failure_collection_sha256")
            != result["failure_collection_sha256"]
        ):
            fail("existing host failure verification receipt binds different evidence")
    else:
        publish_new(receipt_path, verifier.receipt_bytes(result))
    raise CollectedEnduranceFailure(receipt_path, wrapper_status)


def collect(args: argparse.Namespace) -> Path:
    plan, plan_data = verifier.parse_plan(args.plan)
    baseline, baseline_data = verifier.parse_baseline(args.baseline)
    if plan["miner_target_sha256"] != sha256_bytes(args.miner_ip.encode("utf-8")):
        fail("miner address does not match the launch-plan target binding")
    if plan["ssh_host_key_sha256"] != args.expected_host_key_sha256:
        fail("operator host-key pin does not match the launch plan")
    verify_known_host(args.miner_ip, args.known_hosts, args.expected_host_key_sha256)
    self_admit(plan, baseline_data, args.baseline)
    phase3_files = admit_phase3_provenance(args, baseline)
    verifier.stable_regular_bytes(args.wall_power_csv, "wall-power CSV", 32 * 1024 * 1024)

    create_private_directory(args.evidence_dir, "evidence directory")
    segments_dir = args.evidence_dir / "segments"
    manifests_dir = args.evidence_dir / "manifests"
    final_dir = args.evidence_dir / "final"
    phase3_dir = args.evidence_dir / "phase3_provenance"
    create_private_directory(segments_dir, "segment directory")
    create_private_directory(manifests_dir, "manifest directory")
    create_private_directory(final_dir, "final directory")
    create_private_directory(phase3_dir, "Phase-3 provenance directory")
    for filename in baseline_builder.PROVENANCE_FILENAMES:
        publish_new(phase3_dir / filename, phase3_files[filename])
    verify_stored_phase3_provenance(args.evidence_dir, baseline, phase3_files)
    publish_new(args.evidence_dir / "launch_plan.kv", plan_data)
    publish_new(args.evidence_dir / "baseline.kv", baseline_data)
    collection_start = (
        f"schema=dcentos.s19k-endurance-collection-start/v1\n"
        f"started_wall_unix_ms={now_ms()}\n"
        f"miner_target_sha256={plan['miner_target_sha256']}\n"
        f"ssh_host_key_sha256={plan['ssh_host_key_sha256']}\n"
        f"launch_plan_sha256={sha256_bytes(plan_data)}\n"
        f"baseline_sha256={sha256_bytes(baseline_data)}\n"
        "publication=host-create-new-fsync\n"
    ).encode("ascii")
    publish_new(args.evidence_dir / "COLLECTION_START.kv", collection_start)

    ssh = ssh_base(args.known_hosts)
    tokens = runner_tokens(plan)
    stdout_path = args.evidence_dir / "runner.stdout"
    stderr_path = args.evidence_dir / "runner.stderr"
    stdout_stream = open(stdout_path, "xb", buffering=0)
    stderr_stream = open(stderr_path, "xb", buffering=0)
    process: subprocess.Popen[bytes] | None = None
    runner_status: int | None = None
    try:
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        process = subprocess.Popen(
            (*ssh, f"root@{args.miner_ip}", remote_command(tokens, "run")),
            stdin=subprocess.DEVNULL,
            stdout=stdout_stream,
            stderr=stderr_stream,
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
        sequence = 0
        predecessor_manifest = verifier.EMPTY_SHA256
        last_progress = time.monotonic()
        while True:
            observed = read_segment(ssh, args.miner_ip, tokens, sequence)
            if observed.returncode == 0:
                if observed.stderr or not observed.stdout or len(observed.stdout) > verifier.MAX_SEGMENT_BYTES:
                    fail(f"segment {sequence} read returned inexact bytes or diagnostics")
                fields, _ = verifier.parse_kv_bytes(observed.stdout, f"segment {sequence}")
                if fields.get("schema") != verifier.SEGMENT_SCHEMA or fields.get("sequence") != str(sequence):
                    fail(f"target returned a different segment for sequence {sequence}")
                if sequence >= verifier.MAX_SEGMENTS:
                    fail("target exceeded the declared maximum segment geometry")
                collected_ms = now_ms()
                manifest_data = manifest_entry(
                    sequence,
                    observed.stdout,
                    predecessor_manifest,
                    collected_ms,
                )
                manifest_path = manifests_dir / f"manifest.{sequence:06}.kv"
                publish_new(manifest_path, manifest_data)
                segment_path = segments_dir / f"segment.{sequence:06}.kv"
                publish_new(segment_path, observed.stdout)
                copied = verifier.stable_regular_bytes(
                    segment_path,
                    f"copied segment {sequence}",
                    verifier.MAX_SEGMENT_BYTES,
                )
                if copied != observed.stdout:
                    fail(f"copied segment {sequence} changed before acknowledgement")
                acknowledge(
                    ssh, args.miner_ip, tokens, sequence, copied,
                    predecessor_manifest, manifest_data, collected_ms,
                )
                predecessor_manifest = sha256_bytes(manifest_data)
                sequence += 1
                last_progress = time.monotonic()
                if sequence > verifier.MAX_SEGMENTS:
                    fail("target exceeded the declared maximum segment geometry")
                continue
            if observed.returncode == NOT_YET_PUBLISHED and not observed.stdout and not observed.stderr:
                runner_status = process.poll()
                if runner_status is not None:
                    break
                if time.monotonic() - last_progress >= 300:
                    fail(f"target published no segment {sequence} within the 300-second evidence SLA")
                time.sleep(args.poll_seconds)
                continue
            if observed.returncode == TRANSIENT_SSH:
                fail(f"SSH disconnected during endurance collection: {observed.stderr.decode('utf-8', 'replace').strip()}")
            fail(
                f"target segment read failed: sequence={sequence} rc={observed.returncode} "
                f"stderr={observed.stderr.decode('utf-8', 'replace').strip()}"
            )
        stdout_stream.flush()
        stderr_stream.flush()
        os.fsync(stdout_stream.fileno())
        os.fsync(stderr_stream.fileno())
    except BaseException:
        if process is not None:
            terminate_runner(process)
        raise
    finally:
        stdout_stream.close()
        stderr_stream.close()

    if process is None or runner_status is None or process.returncode != runner_status:
        fail("endurance runner close status is unavailable or inconsistent")
    failure_outcome = runner_status != 0
    final_names = FAILURE_FINAL_NAMES if failure_outcome else FINAL_NAMES
    for name in final_names:
        deadline = time.monotonic() + 180
        while True:
            result = run_ssh(
                ssh, args.miner_ip, remote_command(tokens, "endurance-final-read", name), 30
            )
            if result.returncode == 0:
                if result.stderr or not result.stdout or len(result.stdout) > 65_536:
                    fail(f"final target receipt {name} returned inexact bytes")
                publish_new(final_dir / name, result.stdout)
                break
            if result.returncode == NOT_YET_PUBLISHED and not result.stdout and not result.stderr and time.monotonic() < deadline:
                time.sleep(args.poll_seconds)
                continue
            fail(f"could not fetch final target receipt {name}: rc={result.returncode} stderr={result.stderr.decode('utf-8', 'replace').strip()}")

    final_bytes = {
        name: verifier.stable_regular_bytes(final_dir / name, f"final target receipt {name}", 65_536)
        for name in final_names
    }
    final_collected_ms = now_ms()
    if failure_outcome:
        final_collection = (
            "schema=dcentos.s19k-endurance-failure-final-collection/v1\n"
            f"daemon_failure_sha256={sha256_bytes(final_bytes['daemon_failure'])}\n"
            f"terminal_handoff_sha256={sha256_bytes(final_bytes['terminal_handoff'])}\n"
            f"safeoff_sha256={sha256_bytes(final_bytes['safeoff'])}\n"
            f"endurance_failure_receipt_sha256={sha256_bytes(final_bytes['endurance_failure_receipt'])}\n"
            f"runtime_active_pre_safeoff_sha256={sha256_bytes(final_bytes['runtime_active_pre_safeoff'])}\n"
            f"runtime_pending_sha256={sha256_bytes(final_bytes['runtime_pending'])}\n"
            f"collected_wall_unix_ms={final_collected_ms}\n"
            "publication=host-create-new-fsync\n"
        ).encode("ascii")
        publish_new(args.evidence_dir / "FAILURE_COLLECTION.kv", final_collection)
    else:
        final_collection = (
            "schema=dcentos.s19k-endurance-final-collection/v1\n"
            f"daemon_terminal_sha256={sha256_bytes(final_bytes['daemon_terminal'])}\n"
            f"terminal_handoff_sha256={sha256_bytes(final_bytes['terminal_handoff'])}\n"
            f"safeoff_sha256={sha256_bytes(final_bytes['safeoff'])}\n"
            f"endurance_receipt_sha256={sha256_bytes(final_bytes['endurance_receipt'])}\n"
            f"runtime_active_pre_safeoff_sha256={sha256_bytes(final_bytes['runtime_active_pre_safeoff'])}\n"
            f"runtime_pending_sha256={sha256_bytes(final_bytes['runtime_pending'])}\n"
            f"collected_wall_unix_ms={final_collected_ms}\n"
            "publication=host-create-new-fsync\n"
        ).encode("ascii")
        publish_new(args.evidence_dir / "FINAL_COLLECTION.kv", final_collection)
    wait_for_independent_safeoff_decay(
        args.wall_power_csv,
        final_collected_ms,
        int(baseline["safeoff_wall_power_max_mw"]),
    )

    result = verifier.verify_evidence(
        args.evidence_dir,
        args.baseline,
        args.wall_power_csv,
        args.plan,
        expected_failure=failure_outcome,
    )
    receipt_name = (
        "HOST_ENDURANCE_FAILURE_VERIFICATION.kv"
        if failure_outcome
        else "HOST_ENDURANCE_VERIFICATION.kv"
    )
    receipt_path = args.evidence_dir / receipt_name
    verifier.publish_new(receipt_path, verifier.receipt_bytes(result))
    if failure_outcome:
        raise CollectedEnduranceFailure(receipt_path, runner_status)
    return receipt_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--miner-ip", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--expected-host-key-sha256", required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--phase3-plan", type=Path, required=True)
    parser.add_argument("--phase3-trial-dir", type=Path, required=True)
    parser.add_argument("--phase3-wall-power-csv", type=Path, required=True)
    parser.add_argument("--phase3-physical-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--wall-power-csv", type=Path, required=True)
    parser.add_argument(
        "--resume-failure",
        action="store_true",
        help="reconnect only to collect a target that already failed closed; never relaunch mining",
    )
    parser.add_argument("--poll-seconds", type=float, default=1.0, help=argparse.SUPPRESS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.poll_seconds <= 0 or args.poll_seconds > 10:
        print("ERROR: poll interval is outside (0, 10] seconds", file=sys.stderr)
        return 2
    try:
        receipt = resume_failure(args) if args.resume_failure else collect(args)
        print(f"S19K_ENDURANCE_COLLECTION_OK receipt={receipt}")
        return 0
    except CollectedEnduranceFailure as failure:
        print(
            "S19K_ENDURANCE_CONTROLLED_FAILURE_EVIDENCE_OK "
            f"runner_status={failure.runner_status} receipt={failure.receipt}",
            file=sys.stderr,
        )
        return 1
    except (EnduranceCollectionError, verifier.EnduranceVerificationError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
