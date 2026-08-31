#!/usr/bin/env python3
"""Bench-laptop collector for the A1246 first-contact read-only discovery pass.

This tool implements two operator conveniences on top of the signed discovery
layer (``k210_discovery_receipt.py`` + ``gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md``):

- ``collect``  - the runbook Section 5 read-only stock-API pass over TCP 4028;
- ``skeleton`` - the discovery-bundle input skeleton for the nine required
  evidence kinds, with the exact-match constants the receipt verifier enforces.

Read-only by construction:

- the only API verbs this tool can ever send are the allowlisted read-only
  queries (``version``, ``stats``, ``estats``, ``summary``, ``pools``); the
  argparse layer refuses any other value and there is no raw-command escape
  hatch flag;
- no write, reboot, or upgrade verb is constructed anywhere in this file;
- the MM3 framing quirk is honored exactly as validated host-only in the
  runbook: read-only API commands are newline-terminated ASCII, responses may
  carry trailing NUL padding (trimmed only when saving), and the raw
  unterminated byte form the legacy MM3 stack uses for control frames is
  never emitted.

Deployment note: this tool runs on the operator's bench laptop against one
host:port named on the command line. The repository's own tests exercise it
against an in-thread loopback fake server only; nothing here contacts a miner
by itself, and a completed pass grants no authority of any kind.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


TOOL_NAME = "k210_discovery_collect"
TOOL_VERSION = "1"
DEFAULT_PORT = 4028
CONNECT_TIMEOUT_S = 10
READ_TIMEOUT_S = 30
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# The complete set of API verbs this tool may ever send. Every entry is a
# read-only query from the runbook's Section 5 discipline; the argparse
# ``choices`` for ``--commands`` is exactly this tuple, so anything else is
# refused by the parser itself.
API_COMMAND_ALLOWLIST = ("estats", "pools", "stats", "summary", "version")
# The runbook's validated bench pass: the two required stock responses plus
# the optional Section 7 estats capture.
DEFAULT_COMMANDS = ("version", "stats", "estats")

# Runbook Section 2 evidence file naming (flat below the evidence root).
RESPONSE_FILENAMES = {
    "estats": "stock_estats_response.json",
    "pools": "stock_pools_response.json",
    "stats": "stock_stats_response.json",
    "summary": "stock_summary_response.json",
    "version": "stock_version_response.json",
}
# Commands whose response is an admissible discovery evidence kind. summary
# and pools are useful bench observations but are NOT bundle evidence kinds.
EVIDENCE_KIND_BY_COMMAND = {
    "estats": "stock_estats_response",
    "stats": "stock_stats_response",
    "version": "stock_version_response",
}

# Held A1246 stock-profile expectations (runbook Section 5 sanity checks and
# the manifest profile ``a1246-a3200lc-2hash``). Deviations are recorded as
# note-level anomalies: the unit may legitimately run a newer stock build.
HELD_PROFILE = {
    "id": "a1246-a3200lc-2hash",
    "stock_firmware_version": "22062202_be77c30_a769bbf",
    "stock_hwtype": "MM3v2_X2",
    "stock_swtype": "MM315",
    "sibling_builds": ("22011901_4ec6bb0_3e42b91", "22011902_4ec6bb0_3e42b91"),
    "three_board_hwtype": "MM3v2_X3",
    "additional_swtype": "MM315_OOW",
}
FIRMWARE_SHAPE_SUFFIX = "_gitshort_gitshort"
PROD_PREFIX = "AvalonMiner"

RUNBOOK_PATH = "DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md"

DISCOVERY_PHASE_ACTIONS = (
    "closed_chassis_stock_power_restoration",
    "deenergized_visual_inspection_power_down",
    "stock_read_only_management_queries",
    "visual_identity_inspection",
)


class CollectError(RuntimeError):
    """The collector refused to proceed (never a miner-side condition)."""


def _load_discovery_module():
    path = Path(__file__).with_name("k210_discovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_discovery_receipt", path)
    if spec is None or spec.loader is None:
        raise CollectError(f"cannot load the discovery receipt contract: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


discovery = _load_discovery_module()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _quote(path: Path) -> str:
    return f'"{path.resolve().as_posix()}"'


def _script_command(script: str) -> str:
    return f"py -3 DCENT_OS_AvalonMiner/scripts/{script}"


# ---------------------------------------------------------------------------
# MM3 framing quirk (runbook Section 5 validated Python fallback)
# ---------------------------------------------------------------------------


def mm3_api_request_bytes(command: str) -> bytes:
    """Encode one read-only API query exactly as the runbook validated it.

    The legacy MM3 stack accepts raw unterminated byte frames for its control
    verb family, but the read-only CGMiner API commands in the runbook's
    validated fallback are newline-terminated ASCII. This tool only ever
    emits the API form; control frames are never constructed here.
    """

    return (command + "\n").encode("ascii")


def mm3_trim_response(data: bytes) -> bytes:
    """Trim the MM3 trailing-NUL padding before saving a response."""

    return data.rstrip(b"\x00")


# ---------------------------------------------------------------------------
# Minimal read-only content validation (anomalies never stop the session)
# ---------------------------------------------------------------------------


def _anomaly(code: str, command: str, severity: str, detail: str) -> dict[str, str]:
    return {
        "code": code,
        "command": command,
        "detail": detail,
        "severity": severity,
    }


def _note(code: str, command: str, detail: str) -> dict[str, str]:
    return _anomaly(code, command, "note", detail)


def _fault(code: str, command: str, detail: str) -> dict[str, str]:
    return _anomaly(code, command, "anomaly", detail)


def _decode_json(payload: bytes, command: str, code_prefix: str):
    try:
        return json.loads(payload.decode("utf-8", errors="replace")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, _fault(
            f"{code_prefix}_not_json", command, f"response is not JSON: {exc}"
        )


def _case_key(mapping: Mapping[str, Any], wanted: str) -> Optional[str]:
    lowered = wanted.lower()
    for key in mapping:
        if key.lower() == lowered:
            return key
    return None


def _status_ok(document: Any, command: str, code_prefix: str) -> list[dict[str, str]]:
    key = _case_key(document, "STATUS") if isinstance(document, dict) else None
    if key is None or not isinstance(document[key], list) or not document[key]:
        return [_fault(f"{code_prefix}_status_missing", command, "no STATUS array")]
    first = document[key][0]
    if not isinstance(first, dict) or str(first.get("Status", "")).upper() != "S":
        return [
            _fault(
                f"{code_prefix}_status_not_ok",
                command,
                f"STATUS[0].Status is {first.get('Status') if isinstance(first, dict) else first!r}, expected S",
            )
        ]
    return []


def validate_version_response(command: str, payload: bytes) -> list[dict[str, str]]:
    """Sanity-check a stock ``version`` response (runbook Section 5)."""

    anomalies: list[dict[str, str]] = []
    document, error = _decode_json(payload, command, "version")
    if error is not None:
        return [error]
    if not isinstance(document, dict):
        return [_fault("version_not_json", command, "response root is not an object")]
    anomalies.extend(_status_ok(document, command, "version"))
    array_key = _case_key(document, "VERSION")
    if array_key is None or not isinstance(document[array_key], list):
        return anomalies + [
            _fault("version_array_missing", command, "no VERSION array")
        ]
    entries = document[array_key]
    if not entries or not isinstance(entries[0], dict):
        return anomalies + [
            _fault("version_array_empty", command, "VERSION array has no object")
        ]
    first = entries[0]

    firmware_key = _case_key(first, "VERSION")
    if firmware_key is None:
        firmware_key = _case_key(first, "VERION")
    if firmware_key is None:
        anomalies.append(
            _fault(
                "version_field_missing",
                command,
                "no firmware field: expected VERSION or the known 2019 VERION "
                "typo spelling; neither is present",
            )
        )
    else:
        firmware = str(first[firmware_key])
        if firmware_key == "VERION":
            anomalies.append(
                _note(
                    "version_field_verion_typo",
                    command,
                    "firmware field uses the VERION spelling (known 2019 "
                    "firmware typo); feed its value into identity."
                    "stock_firmware_version unchanged",
                )
            )
        tail = firmware[8:]
        shape_ok = (
            len(firmware) == 24
            and firmware[:8].isdigit()
            and tail.startswith("_")
            and tail.count("_") == 2
            and all(
                0 < len(part) <= 8 for part in tail[1:].split("_")
            )
        )
        if not shape_ok:
            anomalies.append(
                _fault(
                    "firmware_shape_unexpected",
                    command,
                    f"firmware {firmware!r} is not shaped "
                    "YYMMDDNN_gitshort_gitshort",
                )
            )
        if firmware != HELD_PROFILE["stock_firmware_version"]:
            anomalies.append(
                _note(
                    "firmware_differs_from_held_profile",
                    command,
                    f"observed {firmware!r}; held A1246 stock line is "
                    f"{HELD_PROFILE['stock_firmware_version']!r} (siblings "
                    f"{list(HELD_PROFILE['sibling_builds'])}); the unit may "
                    "have been updated - record exactly what the unit reports",
                )
            )

    for field, expected, extra in (
        ("HWTYPE", HELD_PROFILE["stock_hwtype"], None),
        ("SWTYPE", HELD_PROFILE["stock_swtype"], None),
    ):
        key = _case_key(first, field)
        if key is None:
            anomalies.append(
                _fault(f"{field.lower()}_missing", command, f"no {field} field")
            )
            continue
        observed = str(first[key])
        if observed != expected:
            sibling = (
                f" ({HELD_PROFILE['three_board_hwtype']} appears on 3-board siblings)"
                if field == "HWTYPE"
                else (
                    f" (held sw_list also carries {HELD_PROFILE['additional_swtype']})"
                    if field == "SWTYPE"
                    else ""
                )
            )
            anomalies.append(
                _note(
                    f"{field.lower()}_differs_from_held_profile",
                    command,
                    f"observed {field}={observed!r}, held-profile expectation "
                    f"{expected!r}{sibling or ''}",
                )
            )

    prod_key = None
    for candidate in ("PROD", "Product", "Type"):
        prod_key = _case_key(first, candidate)
        if prod_key is not None:
            break
    if prod_key is None:
        anomalies.append(
            _fault(
                "prod_field_missing",
                command,
                "no PROD/Product/Type product field to check the "
                f"{PROD_PREFIX} prefix",
            )
        )
    else:
        observed = str(first[prod_key])
        if not observed.startswith(PROD_PREFIX):
            anomalies.append(
                _fault(
                    "prod_prefix_mismatch",
                    command,
                    f"product string {observed[:48]!r} does not start with "
                    f"{PROD_PREFIX!r}",
                )
            )

    for field in ("DNA", "MAC", "UPAPI"):
        if _case_key(first, field) is None:
            anomalies.append(
                _note(f"{field.lower()}_missing", command, f"no {field} field")
            )
    return anomalies


def validate_stats_response(command: str, payload: bytes) -> list[dict[str, str]]:
    """Sanity-check a stock ``stats`` response (runbook Section 5)."""

    anomalies: list[dict[str, str]] = []
    document, error = _decode_json(payload, command, "stats")
    if error is not None:
        return [error]
    if not isinstance(document, dict):
        return [_fault("stats_not_json", command, "response root is not an object")]
    anomalies.extend(_status_ok(document, command, "stats"))
    key = _case_key(document, "STATS")
    if key is None or not isinstance(document[key], list) or not document[key]:
        return anomalies + [_fault("stats_array_missing", command, "no STATS array")]
    modules = document[key]
    if len(modules) < 2:
        anomalies.append(
            _fault(
                "stats_module_count",
                command,
                f"STATS has {len(modules)} object(s); expected a miner-level "
                "object followed by per-hashboard module objects",
            )
        )
    elif len(modules) != 3:
        anomalies.append(
            _note(
                "stats_module_count_note",
                command,
                f"STATS has {len(modules)} objects; the held 2-hash ("
                f"{HELD_PROFILE['stock_hwtype']}) expectation is 3 (one "
                "miner-level plus one per hash board) - record the physical "
                "unit as observed",
            )
        )
    return anomalies


def validate_json_only(command: str, payload: bytes) -> list[dict[str, str]]:
    document, error = _decode_json(payload, command, command)
    if error is not None:
        return [error]
    if not isinstance(document, dict):
        return [_fault(f"{command}_not_json", command, "response root is not an object")]
    return _status_ok(document, command, command)


VALIDATORS = {
    "version": validate_version_response,
    "stats": validate_stats_response,
    "estats": validate_json_only,
    "summary": validate_json_only,
    "pools": validate_json_only,
}


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------


def query_api(
    host: str, port: int, command: str
) -> tuple[bytes, int]:
    """Send one newline-terminated query and read to EOF (runbook fallback)."""

    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S) as stream:
        stream.settimeout(READ_TIMEOUT_S)
        stream.sendall(mm3_api_request_bytes(command))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = stream.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise CollectError(
                    f"response for {command!r} exceeds {MAX_RESPONSE_BYTES} bytes"
                )
            chunks.append(chunk)
    return b"".join(chunks), total


def _write_new(path: Path, raw: bytes, label: str) -> None:
    if path.exists():
        raise CollectError(f"refusing to overwrite existing {label}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def collect(
    host: str,
    port: int,
    session_dir: Path,
    commands: Sequence[str],
    operator: Optional[str] = None,
    authorization_reference: Optional[str] = None,
    session_title: Optional[str] = None,
) -> dict[str, Any]:
    """Run the read-only pass and write evidence files + collection log.

    Content mismatches are recorded as anomalies and never stop the session;
    a transport error or hang stops the remaining queries (runbook
    discipline: do not troubleshoot with writes or reboots).
    """

    unknown = [command for command in commands if command not in API_COMMAND_ALLOWLIST]
    if unknown:
        raise CollectError(
            "commands outside the read-only allowlist were requested: "
            + ", ".join(unknown)
        )
    ordered: list[str] = []
    for command in commands:
        if command not in ordered:
            ordered.append(command)

    session_dir.mkdir(parents=True, exist_ok=True)
    existing = [
        str(session_dir / RESPONSE_FILENAMES[command])
        for command in ordered
        if (session_dir / RESPONSE_FILENAMES[command]).exists()
    ]
    if session_dir.joinpath("collection_log.json").exists():
        existing.append(str(session_dir / "collection_log.json"))
    if existing:
        raise CollectError(
            "refusing to overwrite existing evidence (start a fresh session "
            "directory): " + "; ".join(existing)
        )

    session_started = _utc_now()
    events: list[dict[str, str]] = [
        {
            "time_utc": session_started,
            "event": (
                "read-only API pass started; allowlisted commands: "
                + ", ".join(ordered)
                + "; actions limited to stock_read_only_management_queries"
            ),
        }
    ]
    results: list[dict[str, Any]] = []
    anomalies: list[dict[str, str]] = []
    stopped_reason: Optional[str] = None

    for command in ordered:
        started = _utc_now()
        started_mono = time.monotonic()
        try:
            raw, raw_bytes = query_api(host, port, command)
        except (OSError, socket.timeout) as exc:
            stopped_reason = f"transport_error: {type(exc).__name__}: {exc}"
            results.append(
                {
                    "command": command,
                    "evidence_kind": EVIDENCE_KIND_BY_COMMAND.get(command),
                    "file": RESPONSE_FILENAMES[command],
                    "status": "transport_error",
                    "started_at_utc": started,
                    "duration_ms": int((time.monotonic() - started_mono) * 1000),
                    "raw_bytes": None,
                    "saved_bytes": None,
                    "saved_sha256": None,
                }
            )
            events.append(
                {
                    "time_utc": _utc_now(),
                    "event": (
                        f"stopped: API error on {command!r} ({stopped_reason}); "
                        "remaining commands not attempted; no retries, no "
                        "writes, no reboots (runbook Section 5/10 discipline)"
                    ),
                }
            )
            break
        saved = mm3_trim_response(raw)
        if not saved:
            anomalies.append(
                _fault("empty_response", command, "response trimmed to zero bytes")
            )
        file_path = session_dir / RESPONSE_FILENAMES[command]
        _write_new(file_path, saved, f"{command} response")
        found = VALIDATORS[command](command, saved)
        anomalies.extend(found)
        duration_ms = int((time.monotonic() - started_mono) * 1000)
        results.append(
            {
                "command": command,
                "evidence_kind": EVIDENCE_KIND_BY_COMMAND.get(command),
                "file": RESPONSE_FILENAMES[command],
                "status": "captured",
                "started_at_utc": started,
                "duration_ms": duration_ms,
                "raw_bytes": raw_bytes,
                "saved_bytes": len(saved),
                "saved_sha256": hashlib.sha256(saved).hexdigest(),
            }
        )
        events.append(
            {
                "time_utc": _utc_now(),
                "event": (
                    f"{command} captured -> {RESPONSE_FILENAMES[command]} "
                    f"({len(saved)} bytes saved, {len(found)} validation notes); "
                    "read-only query"
                ),
            }
        )

    notes = [
        "anomalies below are recorded only; this tool never retries, repairs, "
        "or sends anything beyond the allowlisted read-only queries",
        "response payloads may contain pool usernames or other credentials; "
        "redact before bundling and never record credentials in this log",
        "stop conditions (burning smell, smoke, fan failure, overtemperature, "
        "any API error or hang) end the session per the runbook safety footer",
    ]
    if any(command in ("summary", "pools") for command in ordered):
        notes.append(
            "summary/pools responses are bench observations, NOT admissible "
            "discovery evidence kinds; keep or move them outside the evidence "
            "root before k210_discovery_receipt.py create"
        )

    log = {
        "session": session_title or "read-only stock API discovery pass",
        "operator": operator or "REPLACE_WITH_OPERATOR_NAME",
        "authorization_reference": authorization_reference
        or "REPLACE_WITH_OPERATOR_AUTHORIZATION_REFERENCE",
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "runbook": RUNBOOK_PATH,
            "read_only_allowlist": list(API_COMMAND_ALLOWLIST),
        },
        "host": host,
        "port": port,
        "commands": ordered,
        "mm3_framing": {
            "request": "ASCII command + one trailing newline (runbook Section 5 "
            "validated fallback)",
            "save_trim": "trailing NUL padding stripped from the saved file",
            "control_frames": "the legacy MM3 raw unterminated control-frame "
            "form is never sent by this tool",
        },
        "session_started_at_utc": session_started,
        "session_closed_at_utc": _utc_now(),
        "command_results": results,
        "events": events,
        "anomalies": anomalies,
        "notes": notes,
        "stopped_reason": stopped_reason,
        "credential_hygiene": {
            "log_records_credentials": False,
            "detail": "only file names, sizes, hashes, and timings are logged; "
            "response bodies are never copied into this log",
        },
        "authority": "a completed pass is recorded observation only; it grants "
        "no contact, configuration, reboot, power, cooling, hashing, write, "
        "install, or release authority",
    }
    _write_new(
        session_dir / "collection_log.json",
        (json.dumps(log, indent=2, sort_keys=True) + "\n").encode("ascii"),
        "collection log",
    )
    return log


# ---------------------------------------------------------------------------
# skeleton
# ---------------------------------------------------------------------------


def _load_manifest(path: Path) -> dict[str, Any]:
    return discovery._load_manifest(path)


def _held_profile(manifest: Mapping[str, Any], profile_id: str) -> Optional[dict]:
    for profile in manifest.get("firmware_profiles", []):
        if isinstance(profile, dict) and profile.get("id") == profile_id:
            return dict(profile)
    return None


def build_skeleton(
    manifest: Mapping[str, Any],
    model: str,
    session_dir: Path,
    unit_label: Optional[str] = None,
) -> dict[str, Any]:
    """Build the discovery-bundle input skeleton for one physical-model row."""

    target = discovery._target(manifest, model)
    variant_rows = [
        row
        for row in manifest.get(discovery.A1246_VARIANT_CONTRACT_KEY, {}).get(
            "variants", []
        )
        if row.get("target_id") == model
    ]
    held_variants = []
    for row in variant_rows:
        profile = _held_profile(manifest, row["profile_id"])
        if profile is None:
            raise CollectError(
                f"variant contract cites missing profile {row['profile_id']}"
            )
        held_variants.append(
            {
                "asic_family": profile["asic_family"],
                "hashboard_count": row["hashboard_count"],
                "hw_list": profile["hw_list"],
                "id": profile["id"],
                "stock_firmware_version": profile["firmware_version"],
                "sw_list": profile["sw_list"],
            }
        )

    slots = []
    for kind in discovery.REQUIRED_EVIDENCE_KINDS:
        if kind in discovery.PHOTO_KINDS:
            method, media_type, suffix = "visual_inspection", "image/png", ".png"
            source = "camera"
        elif kind in discovery.STOCK_RESPONSE_KINDS:
            method, media_type, suffix = (
                "stock_read_only_management",
                "application/json",
                ".json",
            )
            source = "collector"
        else:
            method, media_type, suffix = "offline_record", "application/json", ".json"
            source = "authored"
        slots.append(
            {
                "kind": kind,
                "path": f"{kind}{suffix}",
                "method": method,
                "media_type": media_type,
                "required": True,
                "capture": source,
                "produced_by_collect": kind in EVIDENCE_KIND_BY_COMMAND.values(),
            }
        )
    for kind in ("stock_estats_response", "uart_pad_photo", "flash_marking_photo"):
        if kind in discovery.PHOTO_KINDS:
            method, media_type, suffix = "visual_inspection", "image/png", ".png"
            source = "camera (no probing)"
        else:
            method, media_type, suffix = (
                "stock_read_only_management",
                "application/json",
                ".json",
            )
            source = "collector (optional --commands estats)"
        slots.append(
            {
                "kind": kind,
                "path": f"{kind}{suffix}",
                "method": method,
                "media_type": media_type,
                "required": False,
                "capture": source,
                "produced_by_collect": kind == "stock_estats_response",
            }
        )

    label = unit_label or f"{model}-unit-01"
    evidence_root = session_dir.resolve()
    capture_json = (session_dir.resolve().parent / "capture.json").as_posix()
    bundle_dir = (session_dir.resolve().parent / "signed-bundle").as_posix()

    collect_command = (
        f"{_script_command('k210_discovery_collect.py')} collect "
        f"--host <A1246_IP> --port {DEFAULT_PORT} --session-dir {_quote(session_dir)}"
    )
    next_commands = [
        {
            "step": 1,
            "tool": TOOL_NAME,
            "purpose": "run the read-only 4028 pass into the evidence root",
            "command": collect_command,
        },
        {
            "step": 2,
            "tool": "k210_discovery_receipt.py",
            "purpose": "write the editable capture descriptor",
            "command": (
                f"{_script_command('k210_discovery_receipt.py')} template "
                f"--model {model} --out \"{capture_json}\""
            ),
        },
        {
            "step": 3,
            "tool": "k210_discovery_receipt.py",
            "purpose": "snapshot evidence and sign the bundle (must NOT pre-exist)",
            "command": (
                f"{_script_command('k210_discovery_receipt.py')} create "
                f"--capture \"{capture_json}\" "
                f"--evidence-root {_quote(session_dir)} "
                f"--private-key <OBSERVER_PRIVATE_KEY> "
                f"--bundle-out \"{bundle_dir}\""
            ),
        },
        {
            "step": 4,
            "tool": "k210_discovery_receipt.py",
            "purpose": "directly verify the signed bundle and every evidence byte",
            "command": (
                f"{_script_command('k210_discovery_receipt.py')} verify "
                f"--bundle \"{bundle_dir}\" "
                f"--public-key <OBSERVER_PUBLIC_KEY>"
            ),
        },
    ]

    return {
        "kind": "dcent_k210_discovery_session_skeleton",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "model": model,
        "unit_label": label,
        "generated_at_utc": _utc_now(),
        "manifest_binding": {
            "target_id": model,
            "asic_family": target["asic_family"],
            "marketing_model": target["display_name"],
            "controller_soc": target.get("controller_soc", "K210"),
            "stock_profile": target.get("stock_profile"),
            "variant_profiles": [item["id"] for item in held_variants],
        },
        "authorized_actions": sorted(DISCOVERY_PHASE_ACTIONS),
        "evidence_root": evidence_root.as_posix(),
        "descriptor_path": capture_json,
        "bundle_path": bundle_dir,
        "evidence_slots": slots,
        "identity_expectations": {
            "manufacturer": "Canaan",
            "marketing_model": target["display_name"],
            "controller_soc": "K210",
            "asic_family": (
                "REPLACE_FROM_RESOLVED_STOCK_PROFILE"
                if held_variants
                else target["asic_family"]
            ),
            "asic_family_note": (
                "resolve only after stock VERSION/HWTYPE/SWTYPE and observed "
                "hashboard topology match exactly one held variant; never use "
                f"the generic target family {target['asic_family']!r}"
            ),
            "held_variants": held_variants,
            "expectation_policy": (
                "held-profile values are sanity anchors, not truth: record "
                "exactly what the unit reports; deviations are collected as "
                "note-level anomalies by the collector"
            ),
        },
        "collector": {
            "script": "DCENT_OS_AvalonMiner/scripts/k210_discovery_collect.py",
            "default_port": DEFAULT_PORT,
            "default_commands": list(DEFAULT_COMMANDS),
            "allowlist": list(API_COMMAND_ALLOWLIST),
            "non_bundle_commands": ["summary", "pools"],
        },
        "next_commands": next_commands,
        "no_mutation": {
            "verbs_constructed": "none beyond the read-only query allowlist",
            "note": "the collector has no write, reboot, or upgrade code path "
            "and no escape-hatch flag; the session grants no authority",
        },
    }


def skeleton(
    manifest_path: Path, model: str, session_dir: Path, unit_label: Optional[str]
) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    document = build_skeleton(manifest, model, session_dir, unit_label)
    _write_new(
        session_dir / "discovery_skeleton.json",
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii"),
        "discovery skeleton",
    )
    return document


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser(
        "collect",
        help="run the read-only stock API pass (runbook Section 5)",
    )
    collect_parser.add_argument("--host", required=True, help="miner API host")
    collect_parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    collect_parser.add_argument(
        "--session-dir",
        type=Path,
        required=True,
        help="evidence root for the response files and collection log",
    )
    collect_parser.add_argument(
        "--commands",
        nargs="+",
        default=list(DEFAULT_COMMANDS),
        choices=sorted(API_COMMAND_ALLOWLIST),
        metavar="COMMAND",
        help="read-only API queries to run (allowlist enforced by argparse; "
        "default: the runbook pass version stats estats)",
    )
    collect_parser.add_argument("--operator", help="operator name for the log")
    collect_parser.add_argument(
        "--authorization-reference", help="operator authorization reference for the log"
    )
    collect_parser.add_argument("--session", help="session title for the log")

    skeleton_parser = subparsers.add_parser(
        "skeleton",
        help="write the discovery-bundle input skeleton (nine evidence kinds)",
    )
    skeleton_parser.add_argument("--session-dir", type=Path, required=True)
    skeleton_parser.add_argument("--model", required=True)
    skeleton_parser.add_argument("--unit-label")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "collect":
            log = collect(
                args.host,
                args.port,
                args.session_dir,
                args.commands,
                args.operator,
                args.authorization_reference,
                args.session,
            )
            for anomaly in log["anomalies"]:
                print(
                    f"K210_COLLECT_ANOMALY severity={anomaly['severity']} "
                    f"code={anomaly['code']} command={anomaly['command']}",
                    file=sys.stderr,
                )
            captured = sum(
                1 for item in log["command_results"] if item["status"] == "captured"
            )
            if log["stopped_reason"] is None:
                print(
                    f"K210_COLLECT_OK commands={captured} "
                    f"anomalies={len(log['anomalies'])} "
                    f"session_dir={args.session_dir.resolve().as_posix()}"
                )
                return 0
            print(
                f"K210_COLLECT_STOPPED commands={captured} "
                f"reason={log['stopped_reason']} "
                f"session_dir={args.session_dir.resolve().as_posix()}",
                file=sys.stderr,
            )
            return 1
        document = skeleton(args.manifest, args.model, args.session_dir, args.unit_label)
        print(
            f"K210_SKELETON_WRITTEN model={args.model} "
            f"unit_label={document['unit_label']} "
            f"path={(args.session_dir / 'discovery_skeleton.json').resolve().as_posix()}"
        )
        for step in document["next_commands"]:
            print(f"NEXT step={step['step']} {step['command']}")
        return 0
    except CollectError as exc:
        print(f"K210_COLLECT_ERROR: {exc}", file=sys.stderr)
        return 2
    except discovery.DiscoveryError as exc:
        print(f"K210_COLLECT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
