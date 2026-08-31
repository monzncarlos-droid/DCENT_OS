#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Deterministic desk audit for the S19k AML on-target stage-1 candidate.

The audit never contacts a miner, opens a device node, signs a capsule, edits
an approval registry, or grants flash authority.  Dynamic checks execute the
script's fixture-only backend under a temporary ordinary-file tree.  The
resulting receipt is suitable for hash-bound review by the release policy, but
the release policy remains intentionally empty until a separate reviewer
chooses to admit the exact script and exact audit bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WORKSPACE_ROOT = PROJECT_ROOT.parents[1]
TOOLBOX_SRC = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
STAGE1 = SCRIPT_DIR / "s19k_aml_transition_stage1.sh"
ROOT_NOOP_FIXTURE = WORKSPACE_ROOT / "stage1.sh"
AUDIT_SCHEMA = "dcentos.s19k-stage1-audit/v1"
STAGE1_SCHEMA = "dcentos.s19k-mtd5-rootfs-window-stage1/v1"
REQUEST_SCHEMA = "dcentos.s19k-stage1-request/v1"
RECEIPT_SCHEMA = "dcentos.s19k-stage1-receipt/v1"
IMPLEMENTATION_ID = "dcentos-s19k-aml-stage1-posix-v1"
FLAG_TAIL_ALL_FF_SHA256 = (
    "7d6d0bf52ce759862d4f62e20d038e0fca09df26dfb34ce2067efa0dc53558f0"
)
FIXTURE_AUTHORIZATION_PRIVATE_SEED_HEX = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
FIXTURE_AUTHORIZATION_PUBLIC_KEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
LIVE_STAGE1_AUTHORIZER_SHA256 = (
    "8a8d744a11490a30f5e821794ad3c6d12c55d940bdbce001369867c8212a6c53"
)
LIVE_STAGE1_AUTHORIZER_BYTES = 467_976
AUTHORIZER_SOURCE = PROJECT_ROOT / "dcentrald" / "s19k-stage1-authorizer"
AUTHORIZER_DESK = (
    WORKSPACE_ROOT
    / "artifacts"
    / "s19k-office-gauntlet"
    / "stage1-authorizer-desk-20260829"
)
AUTHORIZER_BINARY = AUTHORIZER_DESK / "observation-a" / "s19k-stage1-authorizer"


class AuditError(RuntimeError):
    """A stage-1 audit invariant failed."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_text(path: Path, text: str) -> None:
    _write(path, text.encode("ascii"))


def _source_contract_paths() -> tuple[Path, ...]:
    return (
        SCRIPT_DIR / "lib" / "am3_geometry.sh",
        SCRIPT_DIR / "install_amlogic_persistent.sh",
        SCRIPT_DIR / "restore_amlogic_mtd5_from_backup.sh",
        PROJECT_ROOT / "dcentrald" / "dcentrald-common" / "src" / "s19k_am3_install.rs",
        PROJECT_ROOT / "dcentrald" / "dcentrald-common" / "src" / "s19k_nand_env.rs",
        PROJECT_ROOT / "dcentrald" / "dcentrald" / "src" / "main.rs",
        WORKSPACE_ROOT
        / "projects"
        / "dcent-toolbox"
        / "src"
        / "dcent_toolbox"
        / "core"
        / "s19k_aml_first_install.py",
        WORKSPACE_ROOT
        / "projects"
        / "dcent-toolbox"
        / "src"
        / "dcent_toolbox"
        / "core"
        / "s19k_aml_install_executor.py",
        AUTHORIZER_SOURCE / "Cargo.toml",
        AUTHORIZER_SOURCE / "src" / "main.rs",
        AUTHORIZER_DESK / "DESK_OBSERVATION.json",
        AUTHORIZER_DESK / "SHA256SUMS",
        AUTHORIZER_BINARY,
    )


def _static_checks(source: str) -> list[str]:
    authorization_dispatch = source.index(
        'if [ "$SIMULATION" = true ]; then',
        source.index("AUTHORIZATION_SIGNATURE_SHA256=$(sha256_file"),
    )
    authorization_live = source.index("\nelse\n", authorization_dispatch)
    authorization_end = source.index(
        "\nfi\nAUTHORIZATION_VERIFIED=true", authorization_live
    )
    fixture_authorization = source[authorization_dispatch:authorization_live]
    live_authorization = source[authorization_live:authorization_end]
    streaming_start = source.index("readback_rootfs_live_stream() {")
    streaming_end = source.index("\n}\n", streaming_start)
    streaming_readback = source[streaming_start:streaming_end]
    required = {
        "posix_shebang": source.startswith("#!/bin/sh\n"),
        "protocol_schema": STAGE1_SCHEMA in source,
        "request_schema": REQUEST_SCHEMA in source,
        "receipt_schema": RECEIPT_SCHEMA in source,
        "implementation_id": IMPLEMENTATION_ID in source,
        "internal_flash_gate_false": "INTERNAL_CLEAR_FOR_FLASH=false" in source,
        "request_true_is_not_internal_gate": (
            '[ "$REQ_CLEAR_FOR_FLASH" = true ]' in source
            and '[ "$INTERNAL_CLEAR_FOR_FLASH" != true ]' in source
        ),
        "signed_one_shot_authorization": (
            "AUTHORIZATION_SCHEMA_EXPECTED='dcentos.s19k-stage1-authorization/v1'"
            in source
            and "LIVE_AUTHORIZATION_PUBKEY_HEX=" in source
            and "openssl pkeyutl -verify -pubin" in source
            and 'REQUEST_SIGNATURE_FILE="$REQUEST_PATH.sig"' in source
            and "AUTHORIZATION_VERIFIED=true" in source
        ),
        "live_authorizer_exact_internal_pins": (
            "LIVE_STAGE1_AUTHORIZER_SHA256=" in source
            and LIVE_STAGE1_AUTHORIZER_SHA256 in source
            and "LIVE_STAGE1_AUTHORIZER_BYTES=467976" in source
            and "REQ_STAGE1_AUTHORIZER_SHA256=$(json_string stage1_authorizer_sha256)"
            in source
            and "REQ_STAGE1_AUTHORIZER_BYTES=$(json_uint stage1_authorizer_bytes)"
            in source
            and "stage1_authorizer_hash_request_mismatch" in source
            and "stage1_authorizer_bytes_request_mismatch" in source
        ),
        "live_authorizer_same_inode_fd": (
            'AUTHORIZER_FILE="$WORKDIR/$LIVE_STAGE1_AUTHORIZER_NAME"' in source
            and '[ -f "$AUTHORIZER_FILE" ] && [ ! -L "$AUTHORIZER_FILE" ]' in source
            and '[ -x "$AUTHORIZER_FILE" ]' in source
            and 'exec 8<"$AUTHORIZER_FILE"' in source
            and "AUTHORIZER_FD=/proc/self/fd/8" in source
            and '"$AUTHORIZER_FD" \\' in source
            and "--message-fd 4 --signature-fd 5" in source
        ),
        "live_authorizer_no_openssl_dependency": (
            "openssl pkeyutl -verify" in fixture_authorization
            and "openssl" not in live_authorization
            and "LIVE_STAGE1_AUTHORIZER_NAME" in live_authorization
        ),
        "target_kat_remains_false": (
            "STAGE1_AUTHORIZER_TARGET_KAT_VERIFIED=false" in source
            and "STAGE1_AUTHORIZER_TARGET_KAT_VERIFIED=true" not in source
        ),
        "live_rootfs_readback_is_bounded_stream": (
            'readback_fifo="$WORKDIR/rootfs.readback.fifo"' in streaming_readback
            and 'readback_result="$WORKDIR/rootfs.readback.sha256"'
            in streaming_readback
            and 'mkfifo "$readback_fifo"' in streaming_readback
            and 'sha256sum < "$readback_fifo" > "$readback_result" &'
            in streaming_readback
            and '-f "$readback_fifo" "$MTD5"' in streaming_readback
            and 'wait "$readback_consumer_pid"' in streaming_readback
            and "readback_producer_rc" in streaming_readback
            and "readback_consumer_rc" in streaming_readback
            and 'kill "$readback_consumer_pid"' in streaming_readback
            and 'wait "$readback_consumer_pid" 2>/dev/null' in streaming_readback
            and "ROOTFS_READBACK_BYTES=$ROOTFS_BYTES" in streaming_readback
            and "rootfs.readback.bin" not in streaming_readback
        ),
        "tmp_capacity_contract": (
            "TMP_RESERVE_KIB=4096" in source
            and "LIVE_RUNTIME_EXTRA_MAX_BYTES=524288" in source
            and 'df -Pk "$WORKDIR"' in source
            and "tmp_capacity_reserve_not_met" in source
        ),
        "request_and_signature_single_inode_binding": (
            'exec 4<"$REQUEST_PATH"' in source
            and "REQUEST_FD=/proc/self/fd/4" in source
            and 'exec 5<"$REQUEST_SIGNATURE_FILE"' in source
            and "REQUEST_SIGNATURE_FD=/proc/self/fd/5" in source
            and '-rawin -in "$REQUEST_FD" -sigfile "$REQUEST_SIGNATURE_FD"' in source
        ),
        "mode_claim_uses_noclobber": (
            "set -C" in source
            and "schema=dcentos.s19k-stage1-claim/v1" in source
            and "mode_claim_already_exists" in source
            and "MODE_RECEIPT_FILE=''\n    fail_now mode_claim_already_exists" in source
        ),
        "per_mode_receipt_no_replace": (
            'MODE_RECEIPT_FILE="$WORKDIR/stage1-$MODE-receipt.json"' in source
            and '[ ! -e "$MODE_RECEIPT_FILE" ]' in source
            and 'ln "$mode_receipt_tmp" "$MODE_RECEIPT_FILE"' in source
        ),
        "board_target_installer_byte_convergence": (
            "board_target=$(read_first_or_empty /etc/dcentos/board_target | tr -d ' \\t\\r\\n')"
            in source
        ),
        "rootfs_fd_content_binding": (
            'exec 3<"$ROOTFS_FILE"' in source
            and "sha256_file /proc/self/fd/3" in source
            and 'nandwrite -p -s "$ROOTFS_LOCAL_HEX" "$MTD5" /proc/self/fd/3' in source
        ),
        "zero_bad_blocks": "mtd5_bad_blocks_nonzero" in source,
        "safeoff_gpio437_high": (
            "GPIO_SAFE_OFF=437" in source
            and "GPIO_SAFE_OFF_VALUE=1" in source
            and "gpio437_not_safeoff_high" in source
        ),
        "physical_base_observed": (
            '0x000006700000-0x000010000000 : "system"' in source
        ),
        "original_and_candidate_separate": (
            'FLAG_ORIGINAL_FILE="$WORKDIR/recovery_flag_eb.bin"' in source
            and 'FLAG_CANDIDATE_FILE="$WORKDIR/recovery_flag_eb.0x01.bin"' in source
            and 'exec 6<"$FLAG_ORIGINAL_FILE"' in source
            and 'exec 7<"$FLAG_CANDIDATE_FILE"' in source
            and "flag_candidate_tail_differs" in source
        ),
        "full_flag_readback": (
            'cmp -s "$FLAG_READBACK" "$FLAG_CANDIDATE_FD"' in source
            and "flag_readback_hash_mismatch" in source
        ),
        "restore_is_arm_only": (
            "stock_recovery_armed_no_reboot" in source
            and "cannot claim that\n# stock cold-booted" in source
        ),
        "no_reboot_command": all(
            token not in source
            for token in ("\nreboot ", "\nreset ", "shutdown -r", "sysrq-trigger")
        ),
        "unified_terminal_receipts": all(
            state in source
            for state in (
                "preflight_verified_no_write",
                "refused_clear_for_flash_false",
                "refused_pre_mutation",
                "indeterminate_restore_required",
                "installed_commit_verified_no_reboot",
                "stock_recovery_armed_no_reboot",
            )
        ),
        "fixture_never_calls_mtd_tools": (
            'if [ "$SIMULATION" = true ]; then' in source
            and "Fixture mode is a distinct filesystem backend" in source
        ),
    }
    failed = [name for name, passed in required.items() if not passed]
    if failed:
        raise AuditError("static stage1 checks failed: " + ", ".join(failed))

    main = source.index(': > "$OPERATION_LOG"')
    ordered_tokens = (
        "full_revalidate",
        "persist_state preflight_verified_no_write",
        "persist_state pre_mutation_revalidated",
        "erase_rootfs_window ||",
        "write_rootfs ||",
        "readback_rootfs",
        "full_revalidate",
        "erase_flag_eraseblock ||",
        'write_flag_eraseblock "$FLAG_CANDIDATE_FD"',
        "read_current_flag_eraseblock",
        "INSTALL_COMMIT_VERIFIED=true",
        "finish installed_commit_verified_no_reboot",
    )
    cursor = main
    for token in ordered_tokens:
        try:
            cursor = source.index(token, cursor) + len(token)
        except ValueError as exc:
            raise AuditError(f"stage1 operation order missing {token!r}") from exc

    live_gate = source.index(
        'if [ "$INTERNAL_CLEAR_FOR_FLASH" != true ] && [ "$SIMULATION" != true ]',
        main,
    )
    first_erase = source.index("erase_rootfs_window ||", live_gate)
    if live_gate >= first_erase:
        raise AuditError("internal CLEAR_FOR_FLASH gate does not precede rootfs erase")

    return sorted(required)


def _reject_noop_fixture(source: str) -> dict[str, Any]:
    reasons = []
    for token, reason in (
        (STAGE1_SCHEMA, "missing stage1 protocol schema"),
        (IMPLEMENTATION_ID, "missing reviewed implementation id"),
        ("INTERNAL_CLEAR_FOR_FLASH=false", "missing immutable flash interlock"),
        ("erase_rootfs_window ||", "missing ordered rootfs erase"),
        ("write_flag_eraseblock", "missing full recovery-flag eraseblock writer"),
        (RECEIPT_SCHEMA, "missing unified receipt schema"),
    ):
        if token not in source:
            reasons.append(reason)
    if len(reasons) < 6:
        raise AuditError("root no-op fixture unexpectedly resembles audited stage1")
    return {"rejected": True, "reasons": reasons}


def _fixture_identity_record() -> bytes:
    return (
        "BOARD_TARGET=am3-s19k\n"
        "MODEL=Antminer S19K Pro NoPic\n"
        "HWID=S19K-C81\n"
        "PCB=C81\n"
        'BOS_MODEL=model = "Antminer S19K Pro NoPic"\n'
        "DT_MODEL=Amlogic A113D C81\n"
        "DT_COMPATIBLE=amlogic,meson-axg \n"
        "CPU_SYSTEM=Amlogic A113D \n"
    ).encode("ascii")


def _executor_stage1_request(value: Mapping[str, object]) -> bytes:
    """Use the Toolbox's exact request encoder as the shell fixture input."""

    toolbox_src = str(TOOLBOX_SRC)
    if toolbox_src not in sys.path:
        sys.path.insert(0, toolbox_src)
    try:
        from dcent_toolbox.core.s19k_aml_install_executor import (  # type: ignore
            _canonical_stage1_request,
        )
    except (ImportError, OSError) as exc:
        raise AuditError("Toolbox stage1 request encoder is unavailable") from exc
    encoded = _canonical_stage1_request(value)
    independent = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")
    if encoded != independent:
        raise AuditError("Toolbox stage1 request encoding contract drifted")
    return encoded


def _assert_toolbox_receipt_shape(value: Mapping[str, object]) -> None:
    """Mechanically join emitted receipt keys to the Toolbox typed parser."""

    toolbox_src = str(TOOLBOX_SRC)
    if toolbox_src not in sys.path:
        sys.path.insert(0, toolbox_src)
    try:
        from dcent_toolbox.core.s19k_aml_install_executor import (  # type: ignore
            S19kStage1Receipt,
        )
    except (ImportError, OSError) as exc:
        raise AuditError("Toolbox stage1 receipt type is unavailable") from exc
    expected = set(S19kStage1Receipt.__dataclass_fields__)
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise AuditError(
            f"Toolbox/stage1 receipt key drift: missing={missing!r} extra={extra!r}"
        )


def _fixture_tree(
    root: Path,
    *,
    mode: str,
    stage1_sha256: str,
    stage1_bytes: int,
    initial_flag: bytes,
    request_overrides: Optional[Mapping[str, object]] = None,
    remove_request_keys: tuple[str, ...] = (),
) -> tuple[Path, Path, bytes, bytes, bytes]:
    _write_text(root / ".dcent-s19k-stage1-fixture", "dcentos.s19k-stage1-fixture/v1\n")
    _write_text(root / "etc" / "bos_platform", "am3-aml\n")
    _write_text(root / "etc" / "bosminer.toml", 'model = "Antminer S19K Pro NoPic"\n')
    # Deliberate whitespace proves stage1 uses the installer transcript's exact
    # BusyBox-safe first-line BOARD_TARGET semantics.
    _write_text(root / "etc" / "dcentos" / "board_target", " am3-s19k \r\n")
    _write_text(root / "config" / "CONF_MINER_TYPE", "Antminer S19K Pro NoPic\n")
    _write_text(root / "config" / "CONF_HARDWARE_ID", "S19K-C81\n")
    _write_text(root / "config" / "CONF_CONTROL_BOARD", "C81\n")
    _write(root / "proc" / "device-tree" / "model", b"Amlogic A113D C81\n")
    _write(root / "proc" / "device-tree" / "compatible", b"amlogic,meson-axg\0")
    _write_text(root / "proc" / "cpuinfo", "Hardware : Amlogic A113D\n")
    _write_text(
        root / "proc" / "mtd",
        "dev:    size   erasesize  name\n"
        'mtd0: 00200000 00020000 "bootloader"\n'
        'mtd1: 00800000 00020000 "tpl"\n'
        'mtd2: 03200000 00020000 "stock_system"\n'
        'mtd3: 00500000 00020000 "stock_config"\n'
        'mtd4: 02000000 00020000 "overlay"\n'
        'mtd5: 09900000 00020000 "system"\n',
    )
    for name, value in {
        "name": "system\n",
        "size": "160432128\n",
        "erasesize": "131072\n",
        "writesize": "2048\n",
        "bad_blocks": "0\n",
    }.items():
        _write_text(root / "sys" / "class" / "mtd" / "mtd5" / name, value)
    for name, value in {
        "active_low": "0\n",
        "direction": "out\n",
        "value": "1\n",
    }.items():
        _write_text(root / "sys" / "class" / "gpio" / "gpio437" / name, value)
    _write_text(
        root / "dmesg.txt",
        '[    3.805472] 0x000006700000-0x000010000000 : "system"\n',
    )
    _write_text(root / "process.list", "")

    original = b"\x02" + (b"\xff" * (131072 - 1))
    candidate = b"\x01" + original[1:]
    if _sha(original[1:]) != FLAG_TAIL_ALL_FF_SHA256:
        raise AuditError("test fixture all-FF tail hash drift")
    rootfs = (b"DCENT_OS_S19K_ROOTFS_FIXTURE\0" * 8192)[:196608]
    work = root / "work" / _sha(f"scope:{mode}:{_sha(initial_flag)}".encode("ascii"))
    work.mkdir(parents=True)
    _write(work / "dcent-rootfs.img", rootfs)
    _write(work / "recovery_flag_eb.bin", original)
    _write(work / "recovery_flag_eb.0x01.bin", candidate)
    _write(root / "nand" / "flag-current.bin", initial_flag)
    _write(root / "nand" / "rootfs-current.bin", b"preexisting-rootfs-fixture")

    scope_id = work.name
    request = {
        "authority_token_sha256": _sha(f"authority:{scope_id}".encode("ascii")),
        "authorization_public_key_hex": FIXTURE_AUTHORIZATION_PUBLIC_KEY_HEX,
        "authorization_schema": "dcentos.s19k-stage1-authorization/v1",
        "board_target": "am3-s19kpro",
        "capsule_sha256": _sha(b"fixture-capsule"),
        "clear_for_flash": True,
        "eraseblock_size": 131072,
        "identity_record_sha256": _sha(_fixture_identity_record()),
        "mode": mode,
        "mtd5_backup_sha256": _sha(b"fixture-full-mtd5-backup"),
        "mtd5_base_hex": "0x06700000",
        "mtd5_len": 160432128,
        "nand_env_backup_sha256": _sha(b"fixture-nand-env-backup"),
        "nandrecovery_env_sha256": _sha(b"fixture-nandrecovery-env"),
        "original_recovery_flag": 2,
        "persistent_image_verification_id": _sha(b"fixture-persistent-image"),
        "recovery_flag_eraseblock_sha256": _sha(original),
        "recovery_flag_install_candidate_sha256": _sha(candidate),
        "recovery_flag_local_offset_hex": "0x04D00000",
        "rootfs_bytes": len(rootfs),
        "rootfs_erase_count": 320,
        "rootfs_local_offset_hex": "0x05100000",
        "rootfs_mtd": "/dev/mtd5",
        "rootfs_sha256": _sha(rootfs),
        "rootfs_window_hex": "0x02800000",
        "schema": REQUEST_SCHEMA,
        "scope_id": scope_id,
        "source_layout": "braiins-aml-s19k",
        "stage1_authorizer_bytes": LIVE_STAGE1_AUTHORIZER_BYTES,
        "stage1_authorizer_sha256": LIVE_STAGE1_AUTHORIZER_SHA256,
        "stage1_bytes": stage1_bytes,
        "stage1_sha256": stage1_sha256,
        "stock_recovery_device_id": "fixture-device-001",
        "stock_recovery_receipt_sha256": _sha(b"fixture-stock-recovery-receipt"),
        "stock_recovery_verification_id": _sha(b"fixture-stock-recovery"),
    }
    if request_overrides:
        request.update(request_overrides)
    for key in remove_request_keys:
        request.pop(key, None)
    request_path = work / "request.json"
    request_bytes = _executor_stage1_request(request)
    _write(request_path, request_bytes)
    fixture_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(FIXTURE_AUTHORIZATION_PRIVATE_SEED_HEX)
    )
    _write(Path(str(request_path) + ".sig"), fixture_key.sign(request_bytes))
    return work, request_path, rootfs, original, candidate


def _wsl_path(path: Path) -> str:
    # Passing a Windows path through wsl.exe argv can consume backslashes
    # before wslpath sees them.  The audit only uses resolved local drive
    # paths, so perform the unambiguous drive mapping directly.
    raw = str(path.resolve())
    if len(raw) < 3 or raw[1:3] != ":\\":
        raise AuditError(f"cannot map non-drive Windows path into WSL: {raw}")
    return f"/mnt/{raw[0].lower()}/{raw[3:].replace(chr(92), '/')}"


def _run_stage1(
    *, root: Path, work: Path, request: Path, mode: str, cutpoint: str = ""
) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        work_relative = work.relative_to(root).as_posix()
        request_relative = request.relative_to(root).as_posix()
        fixture_buffer = io.BytesIO()
        with tarfile.open(
            fileobj=fixture_buffer, mode="w", format=tarfile.GNU_FORMAT
        ) as archive:
            for fixture_path in sorted(root.rglob("*")):
                archive.add(
                    fixture_path,
                    arcname=fixture_path.relative_to(root).as_posix(),
                    recursive=False,
                )
            archive.add(STAGE1, arcname="stage1.sh", recursive=False)
        fixture_base64 = base64.b64encode(fixture_buffer.getvalue()).decode("ascii")
        # Repeated opens through /proc/self/fd against WSL's DrvFS can take
        # seconds each.  Exercise the exact target shell and stage1 bytes from
        # a private Linux tmpfs copy, then copy receipts and simulated NAND
        # state back to the host fixture for assertions.
        wrapper = (
            f"work_relative={shlex.quote(work_relative)}\n"
            f"request_relative={shlex.quote(request_relative)}\n"
            f"mode={shlex.quote(mode)}\n"
            f"cutpoint={shlex.quote(cutpoint)}\n"
            + r"""scratch=$(/usr/bin/busybox mktemp -d /tmp/dcent-s19k-stage1-audit.XXXXXX) || exit 125
cleanup() {
    cleanup_rc=$?
    trap - EXIT HUP INT TERM
    result_root="$scratch/.stage1-result"
    /usr/bin/busybox mkdir -p "$result_root/nand" \
        "$result_root/$work_relative" || cleanup_rc=126
    /usr/bin/busybox cp "$scratch/nand/flag-current.bin" \
        "$result_root/nand/flag-current.bin" || cleanup_rc=126
    /usr/bin/busybox cp "$scratch/nand/rootfs-current.bin" \
        "$result_root/nand/rootfs-current.bin" || cleanup_rc=126
    for artifact in "$scratch/$work_relative"/stage1-* \
        "$scratch/$work_relative"/rootfs.readback.bin
    do
        [ -e "$artifact" ] || continue
        /usr/bin/busybox cp "$artifact" "$result_root/$work_relative/" \
            || cleanup_rc=126
    done
    (CDPATH= cd "$result_root" && \
        /usr/bin/busybox tar -cf "$scratch/stage1-results.tar" .) \
        || cleanup_rc=126
    printf '%s\n' __DCENT_STAGE1_RESULT_TAR_BASE64__
    /usr/bin/base64 "$scratch/stage1-results.tar" || cleanup_rc=126
    case "$scratch" in
        /tmp/dcent-s19k-stage1-audit.*) /usr/bin/busybox rm -rf -- "$scratch" ;;
        *) cleanup_rc=127 ;;
    esac
    exit "$cleanup_rc"
}
trap cleanup EXIT HUP INT TERM
/usr/bin/base64 -d > "$scratch/fixture.tar" <<'__DCENT_STAGE1_FIXTURE_TAR_BASE64__'
"""
            + fixture_base64
            + r"""
__DCENT_STAGE1_FIXTURE_TAR_BASE64__
/usr/bin/busybox tar -xf "$scratch/fixture.tar" -C "$scratch" || exit 125
cd "$scratch/$work_relative" || exit 125
if [ -n "$cutpoint" ]; then
    env DCENT_S19K_STAGE1_TEST_ROOT="$scratch" \
        DCENT_S19K_STAGE1_TEST_CUTPOINT="$cutpoint" \
        /usr/bin/busybox sh "$scratch/stage1.sh" \
        --request "$scratch/$request_relative" --mode "$mode"
else
    env DCENT_S19K_STAGE1_TEST_ROOT="$scratch" \
        /usr/bin/busybox sh "$scratch/stage1.sh" \
        --request "$scratch/$request_relative" --mode "$mode"
fi
"""
        )
        command = [
            "wsl.exe",
            "/usr/bin/busybox",
            "sh",
            "-s",
        ]
        process = subprocess.run(
            command,
            input=wrapper.encode("ascii"),
            capture_output=True,
            timeout=120,
        )
        combined_stdout = process.stdout.decode("ascii", errors="replace")
        marker = "__DCENT_STAGE1_RESULT_TAR_BASE64__\n"
        if combined_stdout.count(marker) != 1:
            raise AuditError("WSL fixture result archive marker is not exact")
        stage_stdout, encoded_result = combined_stdout.split(marker, 1)
        try:
            result_bytes = base64.b64decode(
                b"".join(encoded_result.encode("ascii").split()), validate=True
            )
        except (ValueError, base64.binascii.Error) as exc:
            raise AuditError("WSL fixture result archive is not valid base64") from exc
        if not result_bytes:
            fixture_stderr = process.stderr.decode("utf-8", errors="replace")
            raise AuditError(
                f"WSL fixture returned an empty result archive: {fixture_stderr!r}"
            )
        with tarfile.open(fileobj=io.BytesIO(result_bytes), mode="r") as archive:
            for member in archive.getmembers():
                member_path = Path(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or member.issym()
                    or member.islnk()
                ):
                    raise AuditError("unsafe fixture result archive member")
            archive.extractall(root, filter="data")
        return subprocess.CompletedProcess(
            process.args,
            process.returncode,
            stage_stdout,
            process.stderr.decode("utf-8", errors="replace"),
        )

    env = os.environ.copy()
    env["DCENT_S19K_STAGE1_TEST_ROOT"] = str(root)
    if cutpoint:
        env["DCENT_S19K_STAGE1_TEST_CUTPOINT"] = cutpoint
    busybox = shutil.which("busybox")
    if busybox is None:
        raise AuditError("busybox is required for the target-shell fixture audit")
    return subprocess.run(
        [busybox, "sh", str(STAGE1), "--request", str(request), "--mode", mode],
        cwd=work,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )


def _run_refusal_case(
    name: str,
    *,
    expected_failure: str,
    request_overrides: Optional[Mapping[str, object]] = None,
    remove_request_keys: tuple[str, ...] = (),
    tamper_signature: bool = False,
) -> dict[str, object]:
    """Prove malformed/tampered authority refuses before fixture mutation."""

    stage1_sha = _sha_file(STAGE1)
    stage1_bytes = STAGE1.stat().st_size
    with tempfile.TemporaryDirectory(prefix="dcent-s19k-stage1-refusal-") as raw:
        root = Path(raw).resolve()
        original = b"\x02" + (b"\xff" * (131072 - 1))
        work, request, _rootfs, _original, _candidate = _fixture_tree(
            root,
            mode="preflight",
            stage1_sha256=stage1_sha,
            stage1_bytes=stage1_bytes,
            initial_flag=original,
            request_overrides=request_overrides,
            remove_request_keys=remove_request_keys,
        )
        if tamper_signature:
            signature_path = Path(str(request) + ".sig")
            signature = bytearray(signature_path.read_bytes())
            signature[0] ^= 0x01
            signature_path.write_bytes(signature)
        rootfs_before = (root / "nand" / "rootfs-current.bin").read_bytes()
        flag_before = (root / "nand" / "flag-current.bin").read_bytes()
        process = _run_stage1(root=root, work=work, request=request, mode="preflight")
        lines = process.stdout.splitlines()
        if len(lines) != 1:
            raise AuditError(f"{name}: refusal did not emit one receipt")
        receipt = json.loads(lines[0])
        _assert_toolbox_receipt_shape(receipt)
        if (
            process.returncode == 0
            or receipt.get("state") != "refused_pre_mutation"
            or receipt.get("failure_code") != expected_failure
            or receipt.get("mutation_started") is not False
            or receipt.get("fixture_mutation_performed") is not False
            or receipt.get("nand_erase_performed") is not False
            or receipt.get("nand_write_performed") is not False
        ):
            raise AuditError(f"{name}: refusal state is not exact: {receipt!r}")
        if (root / "nand" / "rootfs-current.bin").read_bytes() != rootfs_before:
            raise AuditError(f"{name}: refusal changed rootfs fixture")
        if (root / "nand" / "flag-current.bin").read_bytes() != flag_before:
            raise AuditError(f"{name}: refusal changed flag fixture")
        return {
            "name": name,
            "exit_code": process.returncode,
            "state": receipt["state"],
            "failure_code": receipt["failure_code"],
            "authorization_verified": receipt["authorization_verified"],
            "fixture_unchanged": True,
            "nand_erase_performed": False,
            "nand_write_performed": False,
        }


def _run_authorizer_desk_kat() -> dict[str, object]:
    """Run exact ARM desk bytes under QEMU with no OpenSSL in PATH."""

    if _sha_file(AUTHORIZER_BINARY) != LIVE_STAGE1_AUTHORIZER_SHA256:
        raise AuditError("stage1 authorizer desk binary hash drifted")
    if AUTHORIZER_BINARY.stat().st_size != LIVE_STAGE1_AUTHORIZER_BYTES:
        raise AuditError("stage1 authorizer desk binary size drifted")

    with tempfile.TemporaryDirectory(prefix="dcent-s19k-authorizer-kat-") as raw:
        root = Path(raw).resolve()
        message = b'{"schema":"dcentos.s19k-authorizer-desk-kat/v1"}\n'
        key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(FIXTURE_AUTHORIZATION_PRIVATE_SEED_HEX)
        )
        signature = key.sign(message)
        message_path = root / "message.json"
        tampered_path = root / "message.tampered.json"
        signature_path = root / "message.sig"
        _write(message_path, message)
        _write(tampered_path, message[:-2] + b"X\n")
        _write(signature_path, signature)

        def invoke(target: Path) -> subprocess.CompletedProcess[str]:
            if os.name == "nt":
                target_arg = _wsl_path(target)
                signature_arg = _wsl_path(signature_path)
                binary_arg = _wsl_path(AUTHORIZER_BINARY)
                qemu = "/usr/bin/qemu-arm-static"
                command = [
                    "wsl.exe",
                    "/bin/sh",
                ]
            else:
                qemu = shutil.which("qemu-arm-static")
                if qemu != "/usr/bin/qemu-arm-static":
                    raise AuditError(
                        "exact /usr/bin/qemu-arm-static is required for desk KAT"
                    )
                target_arg = str(target)
                signature_arg = str(signature_path)
                binary_arg = str(AUTHORIZER_BINARY)
                command = ["/bin/sh"]
            shell_script = (
                f"exec 4<{shlex.quote(target_arg)}; "
                f"exec 5<{shlex.quote(signature_arg)}; "
                f"exec 8<{shlex.quote(binary_arg)}; "
                "PATH=/nonexistent; export PATH; "
                f"exec {shlex.quote(qemu)} /proc/self/fd/8 "
                f"--public-key-hex {FIXTURE_AUTHORIZATION_PUBLIC_KEY_HEX} "
                "--message-fd 4 --signature-fd 5"
            )
            command.extend(["-c", shell_script])
            return subprocess.run(command, text=True, capture_output=True, timeout=30)

        accepted = invoke(message_path)
        tampered = invoke(tampered_path)
        if accepted.returncode != 0:
            raise AuditError(f"authorizer QEMU accept KAT failed: {accepted.stderr!r}")
        if tampered.returncode != 3:
            raise AuditError(
                f"authorizer QEMU tamper KAT returned {tampered.returncode}"
            )
        return {
            "artifact_sha256": LIVE_STAGE1_AUTHORIZER_SHA256,
            "artifact_bytes": LIVE_STAGE1_AUTHORIZER_BYTES,
            "execution": "qemu-arm-static-desk-only",
            "openssl_in_path": False,
            "same_inode_binary_fd": 8,
            "message_fd": 4,
            "signature_fd": 5,
            "valid_signature_exit_code": accepted.returncode,
            "tampered_message_exit_code": tampered.returncode,
            "stock_target_kat_verified": False,
        }


def _run_fifo_fail_before_open_kat(source: str) -> dict[str, object]:
    """Prove a producer refusal cannot strand the FIFO hash consumer."""

    function_start = source.index("readback_rootfs_live_stream() {")
    function_end = source.index("\n}\n", function_start) + 3
    function_source = source[function_start:function_end]
    harness = f"""#!/bin/sh
set -u
SIMULATION=false
WORKDIR=$PWD
ROOTFS_LOCAL_HEX=0x05100000
ROOTFS_BYTES=16
MTD5=/dev/dcent-fixture-must-not-exist
ROOTFS_SHA256=9f9f5111f7b27a781f1f1ddde5ebc2dd2b8c18c4c4f10770c98f75e8e5f5e598
ROOTFS_READBACK_MODE=none
ROOTFS_READBACK_BYTES=0
ROOTFS_READBACK_SHA256=none
is_sha256() {{
    [ "${{#1}}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
}}
nanddump() {{
    # Deterministic failure before the writer opens its FIFO path.
    return 19
}}
{function_source}
if readback_rootfs_live_stream; then
    exit 20
fi
[ ! -e "$WORKDIR/rootfs.readback.fifo" ] || exit 21
[ "$ROOTFS_READBACK_BYTES" -eq 0 ] || exit 22
[ "$ROOTFS_READBACK_SHA256" = none ] || exit 23
printf '%s\n' fifo-producer-refusal-consumer-reaped
"""
    with tempfile.TemporaryDirectory(prefix="dcent-s19k-fifo-kat-") as raw:
        root = Path(raw).resolve()
        harness_path = root / "fifo-failure-kat.sh"
        _write_text(harness_path, harness)
        if os.name == "nt":
            wrapper = r"""
scratch=$(/usr/bin/busybox mktemp -d /tmp/dcent-s19k-fifo-kat.XXXXXX) || exit 125
trap 'case "$scratch" in /tmp/dcent-s19k-fifo-kat.*) /usr/bin/busybox rm -rf -- "$scratch" ;; esac' EXIT HUP INT TERM
cd "$scratch" || exit 125
/usr/bin/busybox timeout 5 /usr/bin/busybox sh -s
"""
            command = [
                "wsl.exe",
                "/usr/bin/busybox",
                "sh",
                "-c",
                wrapper,
            ]
            shell = "wsl-busybox-sh"
            process = subprocess.run(
                command,
                input=harness.encode("ascii"),
                capture_output=True,
                timeout=15,
            )
            process_stdout = process.stdout.decode("ascii", errors="replace")
            process_stderr = process.stderr.decode("ascii", errors="replace")
        else:
            busybox = shutil.which("busybox")
            if busybox is None:
                raise AuditError("busybox is required for the FIFO failure KAT")
            command = [busybox, "timeout", "5", busybox, "sh", str(harness_path)]
            shell = "busybox-sh"
            process = subprocess.run(
                command,
                cwd=root,
                text=True,
                capture_output=True,
                timeout=15,
            )
            process_stdout = process.stdout
            process_stderr = process.stderr
        if process.returncode != 0:
            raise AuditError(
                "FIFO fail-before-open KAT did not terminate cleanly: "
                f"exit={process.returncode} stderr={process_stderr!r}"
            )
        if process_stdout != "fifo-producer-refusal-consumer-reaped\n":
            raise AuditError("FIFO fail-before-open KAT output drifted")
        return {
            "shell": shell,
            "producer_exit_code": 19,
            "producer_opened_fifo": False,
            "consumer_terminated": True,
            "consumer_reaped": True,
            "fifo_removed": True,
            "bounded_timeout_seconds": 5,
        }


def _run_case(
    name: str,
    *,
    mode: str,
    cutpoint: str = "",
    initial_installed_flag: bool = False,
) -> dict[str, Any]:
    stage1_sha = _sha_file(STAGE1)
    stage1_bytes = STAGE1.stat().st_size
    with tempfile.TemporaryDirectory(prefix="dcent-s19k-stage1-audit-") as raw:
        root = Path(raw).resolve()
        original = b"\x02" + (b"\xff" * (131072 - 1))
        candidate = b"\x01" + original[1:]
        initial = candidate if initial_installed_flag else original
        work, request, rootfs, original, candidate = _fixture_tree(
            root,
            mode=mode,
            stage1_sha256=stage1_sha,
            stage1_bytes=stage1_bytes,
            initial_flag=initial,
        )
        process = _run_stage1(
            root=root, work=work, request=request, mode=mode, cutpoint=cutpoint
        )
        stdout_lines = process.stdout.splitlines()
        if len(stdout_lines) != 1:
            log_path = work / f"stage1-{mode}.log"
            log_text = (
                log_path.read_text("utf-8", errors="replace")
                if log_path.exists()
                else "<missing>"
            )
            raise AuditError(
                f"{name}: stdout must contain one JSON receipt, got {len(stdout_lines)} lines; "
                f"exit={process.returncode} stderr={process.stderr!r} log={log_text!r}"
            )
        try:
            receipt = json.loads(stdout_lines[0])
        except json.JSONDecodeError as exc:
            raise AuditError(f"{name}: invalid receipt JSON: {exc}") from exc
        _assert_toolbox_receipt_shape(receipt)
        disk_receipt_raw = (work / "stage1-receipt.json").read_bytes()
        disk_receipt = json.loads(disk_receipt_raw.decode("ascii"))
        if disk_receipt != receipt:
            raise AuditError(f"{name}: stdout and atomic receipt differ")
        if disk_receipt_raw != _canonical(disk_receipt) + b"\n":
            raise AuditError(f"{name}: receipt is not canonical compact sorted JSON")
        mode_receipt = json.loads(
            (work / f"stage1-{mode}-receipt.json").read_text("ascii")
        )
        if mode_receipt != receipt:
            raise AuditError(f"{name}: stdout and immutable mode receipt differ")
        if receipt.get("schema") != RECEIPT_SCHEMA:
            raise AuditError(f"{name}: receipt schema mismatch")
        if receipt.get("implementation_id") != IMPLEMENTATION_ID:
            raise AuditError(f"{name}: implementation id mismatch")
        if receipt.get("clear_for_flash_internal") is not False:
            raise AuditError(f"{name}: internal flash interlock was not false")
        if receipt.get("writes_authorized") is not False:
            raise AuditError(f"{name}: fixture receipt claimed write authority")
        if receipt.get("postboot_proof_required") is not True:
            raise AuditError(f"{name}: receipt omitted independent postboot proof")
        if (
            receipt.get("tmp_capacity_verified") is not True
            or receipt.get("tmp_reserve_kib") != 4096
            or receipt.get("tmp_runtime_extra_max_bytes") != 524288
        ):
            raise AuditError(f"{name}: tmp capacity receipt contract drifted")
        if receipt.get("authorization_verified") is not True:
            raise AuditError(f"{name}: signed one-shot authorization not verified")
        if receipt.get("authorization_verifier") != "fixture-openssl-pkeyutl":
            raise AuditError(f"{name}: fixture authorization verifier is not exact")
        if (
            receipt.get("stage1_authorizer_bytes") != LIVE_STAGE1_AUTHORIZER_BYTES
            or receipt.get("stage1_authorizer_sha256") != LIVE_STAGE1_AUTHORIZER_SHA256
            or receipt.get("stage1_authorizer_pinned_bytes")
            != LIVE_STAGE1_AUTHORIZER_BYTES
            or receipt.get("stage1_authorizer_pinned_sha256")
            != LIVE_STAGE1_AUTHORIZER_SHA256
            or receipt.get("stage1_authorizer_observed_bytes") != 0
            or receipt.get("stage1_authorizer_observed_sha256") != "none"
            or receipt.get("stage1_authorizer_verified") is not False
            or receipt.get("stage1_authorizer_target_kat_verified") is not False
        ):
            raise AuditError(f"{name}: fixture authorizer identity fields drifted")
        if (
            receipt.get("nand_erase_performed") is not False
            or receipt.get("nand_write_performed") is not False
        ):
            raise AuditError(f"{name}: fixture receipt claimed a NAND operation")
        evidence_keys = (
            "transferred_inputs_verified",
            "identity_verified",
            "geometry_verified",
            "zero_bad_blocks_verified",
            "safeoff_verified",
        )
        if not all(receipt.get(key) is True for key in evidence_keys):
            observed_evidence = {key: receipt.get(key) for key in evidence_keys}
            identity_path = work / "identity.observed"
            observed_identity = (
                identity_path.read_text("ascii", errors="replace")
                if identity_path.exists()
                else "<missing>"
            )
            raise AuditError(
                f"{name}: preflight evidence booleans are incomplete: "
                f"{observed_evidence!r}; state={receipt.get('state')!r}; "
                f"failure={receipt.get('failure_code')!r}; "
                f"identity={observed_identity!r}"
            )

        operations = (
            (work / f"stage1-{mode}-operations.log").read_text("ascii").splitlines()
        )
        current_rootfs = (root / "nand" / "rootfs-current.bin").read_bytes()
        current_flag = (root / "nand" / "flag-current.bin").read_bytes()
        duplicate_invocation: Optional[dict[str, object]] = None
        if name == "preflight":
            immutable_path = work / "stage1-preflight-receipt.json"
            claim_path = work / "stage1-preflight.claim"
            immutable_before = immutable_path.read_bytes()
            claim_before = claim_path.read_bytes()
            replay = _run_stage1(root=root, work=work, request=request, mode=mode)
            replay_lines = replay.stdout.splitlines()
            if len(replay_lines) != 1:
                raise AuditError("duplicate invocation did not return one receipt")
            replay_receipt = json.loads(replay_lines[0])
            if (
                replay.returncode != 2
                or replay_receipt.get("state") != "refused_pre_mutation"
                or replay_receipt.get("failure_code") != "mode_receipt_already_exists"
                or replay_receipt.get("mutation_started") is not False
            ):
                raise AuditError("duplicate invocation was not a pre-mutation refusal")
            if immutable_path.read_bytes() != immutable_before:
                raise AuditError("duplicate invocation replaced terminal mode receipt")
            if claim_path.read_bytes() != claim_before:
                raise AuditError("duplicate invocation changed the O_EXCL claim")
            duplicate_invocation = {
                "exit_code": replay.returncode,
                "state": replay_receipt["state"],
                "failure_code": replay_receipt["failure_code"],
                "immutable_mode_receipt_unchanged": True,
                "claim_unchanged": True,
            }
        return {
            "name": name,
            "mode": mode,
            "cutpoint": cutpoint or None,
            "exit_code": process.returncode,
            "state": receipt["state"],
            "failure_code": receipt["failure_code"],
            "mutation_started": receipt["mutation_started"],
            "restore_required": receipt["restore_required"],
            "install_commit_verified": receipt["install_commit_verified"],
            "stock_recovery_armed": receipt["stock_recovery_armed"],
            "postboot_proof_required": receipt["postboot_proof_required"],
            "authorization_signature_sha256": receipt["authorization_signature_sha256"],
            "authorization_verified": receipt["authorization_verified"],
            "fixture_mutation_performed": receipt["fixture_mutation_performed"],
            "nand_erase_performed": receipt["nand_erase_performed"],
            "nand_write_performed": receipt["nand_write_performed"],
            "last_completed_step": receipt["last_completed_step"],
            "rootfs_readback_sha256": receipt["rootfs_readback_sha256"],
            "rootfs_readback_mode": receipt["rootfs_readback_mode"],
            "recovery_flag_readback": receipt["recovery_flag_readback"],
            "operation_log_sha256": receipt["operation_log_sha256"],
            "operation_names": [line.split(" ", 1)[1] for line in operations],
            "fixture_rootfs_state": (
                "payload"
                if current_rootfs == rootfs
                else "erased"
                if not current_rootfs
                else "other"
            ),
            "fixture_flag_state": (
                "original_0x02"
                if current_flag == original
                else "candidate_0x01"
                if current_flag == candidate
                else "erased"
                if not current_flag
                else "other"
            ),
            "duplicate_invocation": duplicate_invocation,
        }


def _assert_matrix(cases: list[dict[str, Any]]) -> None:
    by_name = {case["name"]: case for case in cases}
    expected = {
        "preflight": (0, "preflight_verified_no_write", False, False),
        "install_success": (0, "installed_commit_verified_no_reboot", True, False),
        "restore_success": (0, "stock_recovery_armed_no_reboot", True, False),
        "cut_before_rootfs_erase": (91, "refused_pre_mutation", False, False),
        "cut_after_rootfs_erase": (91, "indeterminate_restore_required", True, True),
        "cut_after_rootfs_write": (91, "indeterminate_restore_required", True, True),
        "cut_after_rootfs_readback": (91, "indeterminate_restore_required", True, True),
        "cut_before_flag_erase": (91, "indeterminate_restore_required", True, True),
        "cut_after_flag_erase": (91, "indeterminate_restore_required", True, True),
        "cut_after_flag_write": (91, "indeterminate_restore_required", True, True),
        "cut_after_flag_readback": (91, "indeterminate_restore_required", True, True),
        "restore_cut_after_flag_erase": (
            91,
            "indeterminate_restore_required",
            True,
            True,
        ),
    }
    if set(by_name) != set(expected):
        raise AuditError("dynamic case set drift")
    for name, (exit_code, state, mutation, restore) in expected.items():
        case = by_name[name]
        observed = (
            case["exit_code"],
            case["state"],
            case["mutation_started"],
            case["restore_required"],
        )
        if observed != (exit_code, state, mutation, restore):
            raise AuditError(f"{name}: state tuple mismatch: {observed!r}")

    success = by_name["install_success"]
    if not success["install_commit_verified"]:
        raise AuditError("install success lacks verified commit")
    if success["fixture_rootfs_state"] != "payload":
        raise AuditError("install success rootfs fixture does not equal payload")
    if success["fixture_flag_state"] != "candidate_0x01":
        raise AuditError("install success flag fixture is not exact 0x01 candidate")
    if success["recovery_flag_readback"] != 1:
        raise AuditError("install success receipt does not report flag 0x01")
    if success["rootfs_readback_mode"] != "fixture-file":
        raise AuditError("install fixture did not report its isolated readback mode")
    if by_name["preflight"]["rootfs_readback_mode"] != "none":
        raise AuditError("preflight falsely reported a rootfs readback")
    op_names = success["operation_names"]
    ordered = (
        "install.pre_mutation_revalidated",
        "install.rootfs_erased",
        "install.rootfs_written_content_bound_fd",
        "install.rootfs_full_readback_verified",
        "install.pre_commit_all_surfaces_revalidated",
        "install.flag_eraseblock_erased_commit_last",
        "install.flag_full_eraseblock_candidate_written",
        "install.commit_0x01_full_eraseblock_readback_verified_no_reboot",
    )
    cursor = -1
    for token in ordered:
        try:
            cursor = op_names.index(token, cursor + 1)
        except ValueError as exc:
            raise AuditError(f"install operation log order missing {token}") from exc

    restore_case = by_name["restore_success"]
    if not restore_case["stock_recovery_armed"]:
        raise AuditError("restore success does not report stock recovery armed")
    if restore_case["fixture_flag_state"] != "original_0x02":
        raise AuditError(
            "restore success did not restore the exact original 0x02 block"
        )
    if restore_case["recovery_flag_readback"] != 2:
        raise AuditError("restore success receipt does not report flag 0x02")

    if by_name["cut_before_rootfs_erase"]["fixture_rootfs_state"] != "other":
        raise AuditError("pre-mutation cutpoint changed rootfs fixture")
    if by_name["cut_after_rootfs_erase"]["fixture_rootfs_state"] != "erased":
        raise AuditError("post-rootfs-erase cutpoint did not expose erased state")
    if by_name["cut_after_rootfs_write"]["fixture_rootfs_state"] != "payload":
        raise AuditError("post-rootfs-write cutpoint did not expose payload state")
    if by_name["cut_after_flag_erase"]["fixture_flag_state"] != "erased":
        raise AuditError("post-flag-erase cutpoint did not expose erased flag state")
    if by_name["cut_after_flag_write"]["fixture_flag_state"] != "candidate_0x01":
        raise AuditError("post-flag-write cutpoint did not expose candidate state")


def run_audit() -> dict[str, Any]:
    if not STAGE1.is_file() or STAGE1.is_symlink():
        raise AuditError(f"stage1 is missing or a symlink: {STAGE1}")
    if os.name == "nt" and shutil.which("wsl.exe") is None:
        raise AuditError("WSL is required for the POSIX fixture audit on Windows")
    if os.name != "nt" and shutil.which("busybox") is None:
        raise AuditError("busybox is required for the target-shell fixture audit")

    source = STAGE1.read_text("utf-8")
    if os.name == "nt":
        fixture_shell = "busybox-sh"
        syntax_command = [
            "wsl.exe",
            "/usr/bin/busybox",
            "sh",
            "-n",
            _wsl_path(STAGE1),
        ]
    else:
        busybox = shutil.which("busybox")
        assert busybox is not None
        fixture_shell = "busybox-sh"
        syntax_command = [busybox, "sh", "-n", str(STAGE1)]
    syntax = subprocess.run(syntax_command, text=True, capture_output=True, timeout=30)
    if syntax.returncode != 0:
        raise AuditError(f"BusyBox/POSIX shell syntax failed: {syntax.stderr.strip()}")
    static = _static_checks(source)
    noop_source = ROOT_NOOP_FIXTURE.read_text("utf-8")
    noop_rejection = _reject_noop_fixture(noop_source)

    case_specs = (
        ("preflight", "preflight", "", False),
        ("install_success", "install", "", False),
        ("restore_success", "restore", "", True),
        ("cut_before_rootfs_erase", "install", "before_rootfs_erase", False),
        ("cut_after_rootfs_erase", "install", "after_rootfs_erase", False),
        ("cut_after_rootfs_write", "install", "after_rootfs_write", False),
        ("cut_after_rootfs_readback", "install", "after_rootfs_readback", False),
        ("cut_before_flag_erase", "install", "before_flag_erase", False),
        ("cut_after_flag_erase", "install", "after_flag_erase", False),
        ("cut_after_flag_write", "install", "after_flag_write", False),
        ("cut_after_flag_readback", "install", "after_flag_readback", False),
        (
            "restore_cut_after_flag_erase",
            "restore",
            "after_restore_flag_erase",
            True,
        ),
    )
    cases = [
        _run_case(
            name,
            mode=mode,
            cutpoint=cutpoint,
            initial_installed_flag=installed,
        )
        for name, mode, cutpoint, installed in case_specs
    ]
    _assert_matrix(cases)
    adversarial_cases = [
        _run_refusal_case(
            "missing_authorizer_hash",
            expected_failure="request_key_set_not_exact",
            remove_request_keys=("stage1_authorizer_sha256",),
        ),
        _run_refusal_case(
            "wrong_authorizer_hash",
            expected_failure="stage1_authorizer_hash_request_mismatch",
            request_overrides={"stage1_authorizer_sha256": "0" * 64},
        ),
        _run_refusal_case(
            "wrong_authorizer_bytes",
            expected_failure="stage1_authorizer_bytes_request_mismatch",
            request_overrides={
                "stage1_authorizer_bytes": LIVE_STAGE1_AUTHORIZER_BYTES - 1
            },
        ),
        _run_refusal_case(
            "tampered_detached_signature",
            expected_failure="authorization_signature_invalid",
            tamper_signature=True,
        ),
    ]
    authorizer_desk_kat = _run_authorizer_desk_kat()
    fifo_fail_before_open_kat = _run_fifo_fail_before_open_kat(source)

    source_contracts = []
    for path in _source_contract_paths():
        if not path.is_file() or path.is_symlink():
            raise AuditError(f"source contract is missing or a symlink: {path}")
        source_contracts.append(
            {
                "path": path.relative_to(WORKSPACE_ROOT).as_posix(),
                "sha256": _sha_file(path),
                "bytes": path.stat().st_size,
            }
        )

    receipt: dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "implementation_id": IMPLEMENTATION_ID,
        "stage1_protocol_schema": STAGE1_SCHEMA,
        "request_schema": REQUEST_SCHEMA,
        "receipt_schema": RECEIPT_SCHEMA,
        "stage1": {
            "path": STAGE1.relative_to(WORKSPACE_ROOT).as_posix(),
            "sha256": _sha_file(STAGE1),
            "bytes": STAGE1.stat().st_size,
        },
        "authority": {
            "clear_for_flash": False,
            "production_registry_modified": False,
            "live_hardware_contacted": False,
            "network_contacted": False,
            "device_nodes_opened": False,
            "reboot_performed": False,
            "flash_authority_granted": False,
            "dynamic_backend": "ordinary-files-only-fixture",
            "fixture_shell": fixture_shell,
            "fixture_signature_verifier": "host-openssl-pkeyutl",
            "stock_target_signature_verifier_available": False,
            "live_authorizer_candidate_bound_to_stage1": True,
            "live_authorizer_target_kat_verified": False,
            "live_safeoff_custody_transition_implemented_by_toolbox": False,
        },
        "geometry": {
            "board_target": "am3-s19kpro",
            "source_layout": "braiins-aml-s19k",
            "mtd5": "/dev/mtd5",
            "mtd5_base_hex": "0x06700000",
            "mtd5_len": 160432128,
            "rootfs_local_offset_hex": "0x05100000",
            "rootfs_window_hex": "0x02800000",
            "rootfs_erase_count": 320,
            "eraseblock_size": 131072,
            "writesize": 2048,
            "recovery_flag_local_offset_hex": "0x04D00000",
            "recovery_flag_commit": 1,
            "recovery_flag_stock": 2,
            "recovery_flag_successful": 3,
            "gpio437_safeoff": 1,
            "bad_block_policy": "zero-only",
        },
        "tmp_capacity_contract": {
            "capacity_probe": "df-Pk-workdir",
            "available_unit": "KiB",
            "minimum_available_after_transfers_kib": 4096,
            "live_runtime_extra_max_bytes": 524288,
            "rootfs_input_max_bytes": 41943040,
            "authorizer_input_bytes": LIVE_STAGE1_AUTHORIZER_BYTES,
            "stream_fifo": "rootfs.readback.fifo",
            "stream_hash_result": "rootfs.readback.sha256",
            "regular_rootfs_readback_file_live": False,
            "producer_exit_checked_independently": True,
            "consumer_exit_checked_independently": True,
            "failed_producer_consumer_terminated_and_reaped": True,
        },
        "source_contracts": source_contracts,
        "static_checks": static,
        "dynamic_cases": cases,
        "adversarial_cases": adversarial_cases,
        "authorizer_desk_kat": authorizer_desk_kat,
        "fifo_fail_before_open_kat": fifo_fail_before_open_kat,
        "noop_fixture": {
            "path": ROOT_NOOP_FIXTURE.relative_to(WORKSPACE_ROOT).as_posix(),
            "sha256": _sha_file(ROOT_NOOP_FIXTURE),
            "bytes": ROOT_NOOP_FIXTURE.stat().st_size,
            **noop_rejection,
        },
        "conclusions": {
            "preflight_no_hardware_write": True,
            "rootfs_content_bound_before_mutation": True,
            "rootfs_full_readback_before_commit": True,
            "live_rootfs_readback_is_streaming_sha256": True,
            "live_rootfs_sized_readback_file_created": False,
            "live_rootfs_failed_producer_cannot_strand_consumer": True,
            "tmp_capacity_reserve_checked_each_revalidation": True,
            "flag_candidate_separately_content_bound_before_mutation": True,
            "one_shot_request_authorization_signature_verified": True,
            "authorization_pinned_to_release_public_key_for_live_backend": True,
            "authorization_signature_proof_is_fixture_only": True,
            "live_authorizer_exact_hash_and_size_pinned": True,
            "live_authorizer_same_inode_execution": True,
            "live_openssl_dependency_removed": True,
            "authorizer_qemu_accept_and_tamper_reject": True,
            "stock_target_live_authorization_verifier_proven": False,
            "toolbox_live_safeoff_custody_transition_proven": False,
            "canonical_request_encoding": "pretty-sorted-ascii-json-plus-newline",
            "request_bytes_produced_by_toolbox_encoder": True,
            "receipt_keys_exact_match_toolbox_typed_parser": True,
            "mode_claim_is_o_excl_noclobber": True,
            "per_mode_receipt_is_no_replace": True,
            "duplicate_invocation_preserves_claim_and_terminal_receipt": True,
            "flag_nonbyte0_preservation_verified": True,
            "flag_full_eraseblock_readback": True,
            "commit_is_last_nand_operation": True,
            "pre_mutation_failure_is_terminal_refusal": True,
            "post_mutation_failure_is_indeterminate_restore_required": True,
            "restore_reports_arm_only_no_cold_boot_claim": True,
            "live_execute_unreachable": True,
            "production_admission_ready": False,
        },
        "remaining_gates": [
            "run the exact pinned ARMv7 authorizer accept/tamper known-answer test on stock S19k userspace and record ABI/kernel evidence; QEMU desk proof is not target compatibility",
            "capsule and Toolbox must retain exact authorizer member/hash/bytes/upload/receipt convergence before any production admission",
            "Toolbox must exact-bind the proven stock-process stop/GPIO437 SafeOff custody owner and a safe pre-mutation restart route before preflight can converge on a normally mining unit",
            "separate release-policy reviewer must decide whether to admit the exact stage1 and audit hashes",
            "CLEAR_FOR_FLASH remains false and must not be flipped by this audit",
            "production persistent-image receipt and release signing ceremony remain external",
            "exact-unit live preflight, zero-bad-block freshness, SafeOff and recovery rehearsal remain required",
            "power-loss/nand-controller/stock-recovery and postboot evidence require the attended hardware campaign",
        ],
    }
    receipt["audit_id"] = _sha(_canonical(receipt))
    return receipt


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit the S19k AML target-side stage1 using ordinary-file fixtures only"
    )
    parser.add_argument("--output", type=Path, help="write deterministic audit receipt")
    parser.add_argument("--json", action="store_true", help="print receipt JSON")
    args = parser.parse_args(argv)
    try:
        receipt = run_audit()
    except (AuditError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
    if args.output:
        output = args.output.expanduser()
        if output.exists() or output.is_symlink():
            print(
                f"ERROR: output already exists (no-replace): {output}",
                file=os.sys.stderr,
            )
            return 1
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encoded)
    if args.json or not args.output:
        os.sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
