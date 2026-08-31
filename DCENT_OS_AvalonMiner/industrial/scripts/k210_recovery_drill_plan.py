#!/usr/bin/env python3
"""Generate the dual-path stock-recovery drill plan (Markdown + JSON) for one named K210 unit.

This tool is a pure plan/document generator for the exact-unit stock-recovery
contract (``gauntlet/K210_RECOVERY_RECEIPTS.md`` +
``scripts/k210_recovery_receipt.py``). It produces the drill runbook instance
for a named unit: the two independent full-device backup reads (external
memory programmer + a second existing-flash-independent route, with the
measured K210 ROM-ISP-via-UARTHS option from
`` and
its safety notes), readback verification, cold-boot identity checks, the
controlled interruption drill, the evidence slots matching the recovery
receipt, and the dual operator/witness signing steps.

It never executes anything. It contains no miner, programmer, serial, USB,
GPIO, power, flash, or block-device transport, and the generated plan
deliberately contains no executable flash commands - every hardware step is
expressed as a checklist requirement for the separately authorized,
reviewed, model-specific procedure. A generated plan grants no authority.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


TOOL_NAME = "k210_recovery_drill_plan"
TOOL_VERSION = "1"

RECOVERY_RECEIPTS_DOC = (
    "DCENT_OS_AvalonMiner/gauntlet/K210_RECOVERY_RECEIPTS.md"
)
SOC_CONTRACT_DOC = (
    ""
)

# Tokens that must never appear in a generated plan: this is a plan, not an
# execution script, so no programmer/flasher client names or mutating miner
# API verbs may appear as (even copy-pasteable) commands. Checked at
# generation time and by the test suite.
FORBIDDEN_EXECUTABLE_TOKENS = (
    "ascset",
    "esptool",
    "flashrom",
    "kflash",
    "minipro",
    "openocd",
    "setpool",
    "stm32flash",
    "tl866",
)

PLACEHOLDER_RECEIPT_ID = "REPLACE_WITH_ADMITTED_DISCOVERY_RECEIPT_ID"
PLACEHOLDER_FINGERPRINT = "REPLACE_WITH_UNIT_FINGERPRINT_SHA256"
PLACEHOLDER_IDENTITY = "REPLACE_FROM_ADMITTED_DISCOVERY"


class DrillPlanError(RuntimeError):
    """The drill plan could not be generated from the given inputs."""


def _load_receipt_module():
    path = Path(__file__).with_name("k210_recovery_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_recovery_receipt", path)
    if spec is None or spec.loader is None:
        raise DrillPlanError(f"cannot load the recovery receipt contract: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = _load_receipt_module()

MECHANISM_CLASSES = sorted(recovery.MECHANISM_CLASSES)
INTERRUPTION_KINDS = sorted(recovery.INTERRUPTION_KINDS)
AUTHORIZED_ACTIONS = sorted(recovery.RECOVERY_ACTIONS)
OPERATOR_ROLE = recovery.OPERATOR_ROLE
WITNESS_ROLE = recovery.WITNESS_ROLE
OPERATOR_NAMESPACE = recovery.OPERATOR_NAMESPACE
WITNESS_NAMESPACE = recovery.WITNESS_NAMESPACE

EXTERNAL_PROGRAMMER = "external_memory_programmer"
ROM_ISP = "k210_rom_isp"
VENDOR_BOOTROM = "vendor_service_bootrom"

# Evidence slot specs mirroring the recovery receipt descriptor template
# (id, kind, path) so the operator's evidence tree slots directly into
# k210_recovery_receipt.py template/create.
EVIDENCE_SLOT_SPECS = (
    ("discovery-receipt", "discovery_receipt_copy", "identity/discovery-receipt.json"),
    ("safety", "safety_record", "records/safety.json"),
    ("geometry", "flash_geometry_record", "records/geometry.json"),
    ("backup-a", "stock_backup_image", "images/backup-a.bin"),
    ("backup-a-log", "backup_log", "records/backup-a.json"),
    ("backup-b", "stock_backup_image", "images/backup-b.bin"),
    ("backup-b-log", "backup_log", "records/backup-b.json"),
    ("restore-a-log", "restore_log", "records/restore-a.json"),
    ("restore-a-readback", "full_readback_image", "images/restore-a-readback.bin"),
    ("restore-a-boot", "stock_cold_boot_record", "records/restore-a-boot.json"),
    (
        "restore-a-identity",
        "stock_identity_record",
        "records/restore-a-identity.json",
    ),
    ("restore-b-log", "restore_log", "records/restore-b.json"),
    ("restore-b-readback", "full_readback_image", "images/restore-b-readback.bin"),
    ("restore-b-boot", "stock_cold_boot_record", "records/restore-b-boot.json"),
    (
        "restore-b-identity",
        "stock_identity_record",
        "records/restore-b-identity.json",
    ),
    ("interruption-log", "interruption_log", "records/interruption.json"),
    (
        "interruption-readback",
        "full_readback_image",
        "images/interruption-readback.bin",
    ),
    (
        "interruption-boot",
        "stock_cold_boot_record",
        "records/interruption-boot.json",
    ),
    (
        "interruption-identity",
        "stock_identity_record",
        "records/interruption-identity.json",
    ),
)


def _slot(evidence_id: str, kind: str, path: str) -> dict[str, str]:
    return {
        "id": evidence_id,
        "kind": kind,
        "path": path,
        "media_type": (
            "application/octet-stream"
            if kind in {"stock_backup_image", "full_readback_image"}
            else "application/json"
        ),
        "method": (
            "offline_artifact"
            if kind in {"discovery_receipt_copy", "safety_record"}
            else "authorized_recovery_execution"
        ),
        "produced_by_stage": None,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bind_discovery_receipt(
    path: Optional[Path], model: str, unit_label: str
) -> dict[str, str]:
    if path is None:
        return {
            "discovery_receipt_id": PLACEHOLDER_RECEIPT_ID,
            "unit_fingerprint_sha256": PLACEHOLDER_FINGERPRINT,
            "unit_label": unit_label,
            "target_id": model,
            "source": "placeholder: bind the admitted discovery bundle before the drill",
            "stock_identity": {
                "stock_dna": PLACEHOLDER_IDENTITY,
                "stock_firmware_version": PLACEHOLDER_IDENTITY,
                "stock_hwtype": PLACEHOLDER_IDENTITY,
                "stock_swtype": PLACEHOLDER_IDENTITY,
            },
        }
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DrillPlanError(f"cannot read discovery receipt {path}: {exc}") from exc
    required = ("receipt_id", "unit_fingerprint_sha256", "unit_label", "target_id")
    missing = [key for key in required if not isinstance(document.get(key), str)]
    identity = document.get("identity")
    if not isinstance(identity, dict):
        missing.append("identity")
    if missing:
        raise DrillPlanError(
            f"discovery receipt {path} is missing: {', '.join(missing)}"
        )
    if document["target_id"] != model:
        raise DrillPlanError(
            f"discovery receipt target {document['target_id']!r} does not match "
            f"the planned model {model!r} (exact join required)"
        )
    if document["unit_label"] != unit_label:
        raise DrillPlanError(
            f"discovery receipt unit_label {document['unit_label']!r} does not "
            f"match the planned unit {unit_label!r} (exact join required)"
        )
    stock_identity = {}
    for key in (
        "stock_dna",
        "stock_firmware_version",
        "stock_hwtype",
        "stock_swtype",
    ):
        value = identity.get(key)
        stock_identity[key] = value if isinstance(value, str) else PLACEHOLDER_IDENTITY
    return {
        "discovery_receipt_id": document["receipt_id"],
        "unit_fingerprint_sha256": document["unit_fingerprint_sha256"],
        "unit_label": document["unit_label"],
        "target_id": document["target_id"],
        "source": f"parsed (not re-verified) from {path.as_posix()}",
        "stock_identity": stock_identity,
    }


def _stages(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": "S0-authorization-and-safety",
            "title": "Authorization and safety posture (before any contact)",
            "required": True,
            "tags": [
                "explicit_recovery_authorization",
                "controller_only_power",
                "hash_boards_disconnected",
            ],
            "requirements": [
                "a pre-existing operator authorization naming this exact unit, "
                "the UTC interval, and the exact recovery action set: "
                + ", ".join(AUTHORIZED_ACTIONS),
                "reviewed model-specific procedure for the A1246/MM3 "
                "controller and its flash device(s)",
                "controller-only supply energized; hash-power cables "
                "physically disconnected; independent hash-power cutoff "
                "asserted; cooling adequate for controller-only dissipation",
                "safety record (records/safety.json) authored and signed "
                "before any flash access",
            ],
            "safety_notes": [
                "the interruption drill is destructive by design; schedule it "
                "only after both ordinary recovery paths have succeeded",
                "any unexpected heating, smell, or reset ends the drill and is "
                "recorded",
            ],
        },
        {
            "id": "S1-discovery-prerequisite",
            "title": "Admitted discovery bundle prerequisite (exact join)",
            "required": True,
            "tags": ["admitted_discovery_required", "exact_unit_join"],
            "requirements": [
                "the exact-unit discovery bundle is admitted by the gauntlet "
                "before this drill's evidence can be admitted",
                "recovery is rejected unless discovery receipt ID, unit "
                "fingerprint, unit label, target, and stock identity "
                "exact-match the admitted discovery result",
                "copy the canonical discovery receipt to "
                "identity/discovery-receipt.json below the recovery evidence "
                "root",
            ],
        },
        {
            "id": "S2-flash-geometry",
            "title": "Flash device identification (per controller flash device)",
            "required": True,
            "tags": ["per_device_geometry"],
            "requirements": [
                "record exact technology (spi_nor / spi_nand / emmc), "
                "manufacturer, model, and full capacity for every controller "
                "flash device",
                "identify the part through the external programmer read (for "
                "SPI NOR: JEDEC manufacturer/device ID) - no public source "
                "pins the MM3 flash part; do not assume a capacity",
                "capture records/geometry.json per device",
            ],
        },
        {
            "id": "S3-backup-read-a-external-programmer",
            "title": "Backup read A: external memory programmer",
            "required": True,
            "tags": [
                "two_backup_reads",
                "external_programmer_backup",
                "distinct_mechanisms",
                "distinct_tools",
            ],
            "requirements": [
                f"mechanism class {EXTERNAL_PROGRAMMER} (in-circuit fixture or "
                "off-board read per the reviewed procedure)",
                "full-device read of every controller flash device (exact "
                "capacity bytes, not regions)",
                "record tool identity: name, distinct serial, version",
                "capture images/backup-a.bin plus records/backup-a.json",
            ],
        },
        {
            "id": "S4-backup-read-b-second-route",
            "title": "Backup read B: second existing-flash-independent route",
            "required": True,
            "tags": [
                "two_backup_reads",
                "existing_flash_independent_route",
                "distinct_mechanisms",
                "distinct_tools",
            ],
            "requirements": [
                "choose one concrete option (see the route annexes): B1 "
                f"measured K210 ROM ISP over UARTHS ({ROM_ISP}, recommended) "
                f"or B2 documented vendor service BootROM ({VENDOR_BOOTROM})",
                "the route must not depend on existing flash contents (works "
                "on blank or corrupted flash)",
                "distinct mechanism class and distinct tool (name/serial) "
                "from backup read A",
                "capture images/backup-b.bin plus records/backup-b.json",
                "a stock update API alone is NOT an existing-flash-"
                "independent recovery path and does not qualify",
            ],
        },
        {
            "id": "S5-backup-compare",
            "title": "Independent backup comparison (gate)",
            "required": True,
            "tags": ["identical_byte_count", "identical_sha256"],
            "requirements": [
                "byte counts of backup A and backup B equal the device full "
                "capacity for every flash device",
                "SHA-256 of backup A equals SHA-256 of backup B for every "
                "flash device",
                "any disagreement stops the drill: re-read both routes before "
                "proceeding; never proceed on mismatched backups",
            ],
        },
        {
            "id": "S6-restore-path-a-external-programmer",
            "title": "Restore path A through the external programmer",
            "required": True,
            "tags": [
                "two_restore_paths",
                "external_programmer_restore",
                "full_write",
                "full_readback_equals_backup",
                "cold_boot_stock",
                "stock_identity_matched",
                "separate_records_per_run",
            ],
            "requirements": [
                f"mechanism class {EXTERNAL_PROGRAMMER}",
                "full write of the verified stock backup to every flash "
                "device, then full readback byte-equal to the backup",
                "cold boot to stock and an exact stock identity check "
                "(version/HWTYPE/SWTYPE/DNA class fields versus the "
                "admitted discovery identity)",
                "capture records/restore-a.json, images/restore-a-readback.bin, "
                "records/restore-a-boot.json, records/restore-a-identity.json",
            ],
        },
        {
            "id": "S7-restore-path-b-second-route",
            "title": "Restore path B through the second flash-independent route",
            "required": True,
            "tags": [
                "two_restore_paths",
                "existing_flash_independent_route",
                "full_write",
                "full_readback_equals_backup",
                "cold_boot_stock",
                "stock_identity_matched",
                "separate_records_per_run",
            ],
            "requirements": [
                "same mechanism class and tool as backup read B (the route "
                "must restore with existing flash contents ignored, blank, or "
                "corrupted)",
                "full write, full readback byte-equal to the stock backup, "
                "cold stock boot, exact identity check",
                "capture records/restore-b.json, images/restore-b-readback.bin, "
                "records/restore-b-boot.json, records/restore-b-identity.json",
            ],
        },
        {
            "id": "S8-interruption-drill",
            "title": "Controlled interruption drill (destructive, sacrificial unit only)",
            "required": True,
            "tags": [
                "controlled_restore_interruption",
                "destructive_sacrificial_only",
                "recovered_via_other_admitted_path",
                "full_readback_equals_backup",
                "cold_boot_stock",
                "stock_identity_matched",
            ],
            "requirements": [
                "run only on a sacrificial unit, only after both ordinary "
                "paths succeeded, and only under a specific authorization "
                "that includes controlled interruption and power-cycle actions",
                "choose interruption kind from: " + ", ".join(INTERRUPTION_KINDS),
                "interrupt a restore at a recorded byte offset strictly below "
                "the device full capacity (restore incomplete by design)",
                "recover through the OTHER admitted restore path (A "
                "interrupted -> recover via B, or B interrupted -> recover "
                "via A)",
                "after recovery: full readback byte-equal to the stock "
                "backup, cold stock boot, exact identity check",
                "capture records/interruption.json, "
                "images/interruption-readback.bin, records/interruption-boot.json, "
                "records/interruption-identity.json",
            ],
        },
        {
            "id": "S9-evidence-assembly",
            "title": "Evidence tree assembly (slots match the recovery receipt)",
            "required": True,
            "tags": [
                "evidence_slots_complete",
                "separate_records_per_run",
                "discovery_receipt_copy",
            ],
            "requirements": [
                "one evidence item per slot below; unique ids and paths; "
                "separate logs, readbacks, boot records, and identity records "
                "for each run",
                "generate the descriptor from the admitted discovery receipt "
                "(k210_recovery_receipt.py template), then replace every "
                "placeholder, date, flash geometry, capacity, tool identity, "
                "and evidence path before signing",
                "redact credentials/personal identifiers; never bundle pool "
                "secrets",
            ],
        },
        {
            "id": "S10-dual-signing",
            "title": "Dual operator/witness signing",
            "required": True,
            "tags": [
                "dual_signatures",
                "distinct_principals",
                "distinct_keys",
            ],
            "requirements": [
                f"operator role {OPERATOR_ROLE} signs the exact execution "
                f"record under SSHSIG namespace {OPERATOR_NAMESPACE}",
                f"witness role {WITNESS_ROLE} independently reviews and signs "
                f"the same canonical receipt under namespace {WITNESS_NAMESPACE}",
                "roles must use different principals, private keys, "
                "public-key paths, and key IDs; keys stay outside the "
                "repository",
                "verify both signatures and every snapshotted byte directly "
                "before any admission review",
            ],
        },
        {
            "id": "S11-admission",
            "title": "Gauntlet admission (after trust anchors are pinned)",
            "required": True,
            "tags": ["admission_step", "qualifies_only_stock_restore"],
            "requirements": [
                "pin the two public keys as repository-controlled trust paths "
                "with lowercase SHA-256 key IDs per the recovery receipts doc",
                "supply the admitted discovery bundle and this recovery "
                "bundle together to the gauntlet report",
                "an admitted recovery receipt qualifies ONLY the "
                "stock_restore gate; boot_policy becomes the first blocker "
                "and every write, boot, ASIC, thermal/power, mining, "
                "endurance, and release gate stays blocked",
            ],
        },
    ]


ROM_ISP_ANNEX = {
    "id": "B1-rom-isp-via-uarths",
    "title": "Route B1: measured K210 ROM ISP over UARTHS",
    "mechanism_class": ROM_ISP,
    "facts": [
        "entry: hold the ISP strap IO_16 low at reset release (boards with a "
        "USB-UART console do this with a DTR/RTS sequence; on the MM3 "
        "controller use the strap/console wiring identified during "
        "discovery)",
        "transport: UARTHS (the K210 high-speed UART at 0x38000000), "
        "115200 8N1 default; the K210 has no USB peripheral, all ISP is "
        "over this UART",
        "framing: SLIP - packets delimited by 0xC0 with escapes "
        "0xDB 0xDC / 0xDB 0xDD; every command payload carries a CRC-32",
        "ROM operations: 0xC1 echo, 0xC2 greeting (first frame "
        "C0 C2 00..00 C0), 0xC3 write SRAM, 0xC4 read SRAM, 0xC5 "
        "jump/execute, 0xC6 change baud, 0xD1 ROM debug text",
        "ROM replies: 0xE0 OK, 0xE1 bad data length, 0xE2 bad checksum, "
        "0xE3 invalid command",
        "documented as unauthenticated: no signature, no challenge; the only "
        "documented ISP lock is OTP Fuses B bit 7 (disallow entering ISP), "
        "which Fuses A bit 1 can re-allow",
        "flash independence: ROM ISP can write arbitrary SRAM (0xC3) and "
        "execute (0xC5), so a loaded second-stage stub reads (and could "
        "write/erase) flash with no dependency on existing flash contents - "
        "it works on blank or corrupted flash; during backup reads the "
        "stub's flash-read capability is used and write/erase operations are "
        "deliberately NOT exercised",
    ],
    "safety_notes": [
        "whether the industrial Avalon unit has the ISP-disallow fuse blown "
        "is a per-unit measurement: if the greeting is not answered after a "
        "correctly strapped reset, stop, record the route as not accessible, "
        "and use route B2 - never force entry",
        "never read or transcribe the OTP key area (reads error by design "
        "and the schema forbids key extraction) and never write OTP: "
        "documented as able to brick the chip unrecoverably",
        "controller-only power posture per stage S0; hash boards "
        "disconnected; complete promptly and watch for unexpected resets "
        "(no public source documents a ROM-armed watchdog during ISP)",
        "tool identity (name/serial/version) must be recorded and distinct "
        "from the external programmer",
    ],
}

VENDOR_BOOTROM_ANNEX = {
    "id": "B2-vendor-service-bootrom",
    "title": "Route B2: documented vendor service BootROM",
    "mechanism_class": VENDOR_BOOTROM,
    "requirements": [
        "qualifies only if the vendor documents the service BootROM route "
        "and it does not depend on existing flash contents",
        "arranged through the vendor for this exact unit; record the vendor "
        "case/reference and the returned artifact provenance",
        "the resulting read/restore must still be a full-device image with "
        "recorded tool identity distinct from the external programmer",
    ],
    "safety_notes": [
        "transport custody of the unit or its flash device must be covered "
        "by the authorization and the reviewed procedure",
    ],
}


def _host_commands() -> list[dict[str, str]]:
    receipt = "DCENT_OS_AvalonMiner/scripts/k210_recovery_receipt.py"
    gauntlet = "DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py"
    return [
        {
            "step": 1,
            "purpose": "descriptor template bound to the admitted discovery receipt",
            "command": (
                f"py -3 {receipt} template "
                f"--discovery-receipt \"<DISCOVERY_BUNDLE>/receipt.json\" "
                f"--out <RECOVERY_DESCRIPTOR_JSON>"
            ),
        },
        {
            "step": 2,
            "purpose": "snapshot completed evidence and dual-sign (refuses overwrite)",
            "command": (
                f"py -3 {receipt} create "
                f"--descriptor <RECOVERY_DESCRIPTOR_JSON> "
                f"--evidence-root <RECOVERY_EVIDENCE_ROOT> "
                f"--operator-private-key <OPERATOR_PRIVATE_KEY> "
                f"--witness-private-key <WITNESS_PRIVATE_KEY> "
                f"--bundle-out <RECOVERY_BUNDLE_DIR>"
            ),
        },
        {
            "step": 3,
            "purpose": "verify both signatures and every snapshotted byte",
            "command": (
                f"py -3 {receipt} verify "
                f"--bundle <RECOVERY_BUNDLE_DIR> "
                f"--operator-public-key <OPERATOR_PUBLIC_KEY> "
                f"--witness-public-key <WITNESS_PUBLIC_KEY>"
            ),
        },
        {
            "step": 4,
            "purpose": "admit into the gauntlet (after both trust pins land)",
            "command": (
                f"py -3 {gauntlet} report --corpus required "
                f"--discovery-bundle <DISCOVERY_BUNDLE> "
                f"--recovery-bundle <RECOVERY_BUNDLE_DIR>"
            ),
        },
    ]


def generate_drill_plan(
    manifest: Mapping[str, Any],
    model: str,
    unit_label: str,
    discovery_receipt: Optional[Path] = None,
) -> dict[str, Any]:
    target = recovery._target(manifest, model)
    binding = _bind_discovery_receipt(discovery_receipt, model, unit_label)

    stages = _stages(binding)
    slots = []
    stage_by_slot = {
        "discovery-receipt": "S1-discovery-prerequisite",
        "safety": "S0-authorization-and-safety",
        "geometry": "S2-flash-geometry",
        "backup-a": "S3-backup-read-a-external-programmer",
        "backup-a-log": "S3-backup-read-a-external-programmer",
        "backup-b": "S4-backup-read-b-second-route",
        "backup-b-log": "S4-backup-read-b-second-route",
        "restore-a-log": "S6-restore-path-a-external-programmer",
        "restore-a-readback": "S6-restore-path-a-external-programmer",
        "restore-a-boot": "S6-restore-path-a-external-programmer",
        "restore-a-identity": "S6-restore-path-a-external-programmer",
        "restore-b-log": "S7-restore-path-b-second-route",
        "restore-b-readback": "S7-restore-path-b-second-route",
        "restore-b-boot": "S7-restore-path-b-second-route",
        "restore-b-identity": "S7-restore-path-b-second-route",
        "interruption-log": "S8-interruption-drill",
        "interruption-readback": "S8-interruption-drill",
        "interruption-boot": "S8-interruption-drill",
        "interruption-identity": "S8-interruption-drill",
    }
    for evidence_id, kind, path in EVIDENCE_SLOT_SPECS:
        slot = _slot(evidence_id, kind, path)
        slot["produced_by_stage"] = stage_by_slot[evidence_id]
        slots.append(slot)

    plan = {
        "kind": "dcent_k210_recovery_drill_checklist",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at_utc": _utc_now(),
        "unit_label": unit_label,
        "target_id": model,
        "display_name": target["display_name"],
        "controller_soc": target.get("controller_soc", "K210"),
        "discovery_binding": binding,
        "authorized_actions": AUTHORIZED_ACTIONS,
        "mechanism_classes": MECHANISM_CLASSES,
        "interruption_kinds": INTERRUPTION_KINDS,
        "route_options": {
            "backup_read_a": {
                "mechanism_class": EXTERNAL_PROGRAMMER,
                "required": True,
                "title": "external memory programmer",
            },
            "backup_read_b": [
                {
                    "mechanism_class": ROM_ISP,
                    "title": ROM_ISP_ANNEX["title"],
                    "recommended": True,
                    "facts": ROM_ISP_ANNEX["facts"],
                    "safety_notes": ROM_ISP_ANNEX["safety_notes"],
                },
                {
                    "mechanism_class": VENDOR_BOOTROM,
                    "title": VENDOR_BOOTROM_ANNEX["title"],
                    "recommended": False,
                    "requirements": VENDOR_BOOTROM_ANNEX["requirements"],
                    "safety_notes": VENDOR_BOOTROM_ANNEX["safety_notes"],
                },
            ],
        },
        "stages": stages,
        "evidence_slots": slots,
        "signing": {
            "operator_role": OPERATOR_ROLE,
            "witness_role": WITNESS_ROLE,
            "operator_signature_file": recovery.OPERATOR_SIGNATURE_NAME,
            "witness_signature_file": recovery.WITNESS_SIGNATURE_NAME,
            "operator_namespace": OPERATOR_NAMESPACE,
            "witness_namespace": WITNESS_NAMESPACE,
            "distinct_principals_required": True,
            "distinct_keys_required": True,
        },
        "host_commands": _host_commands(),
        "authority": {
            "generates_plan_only": True,
            "authorizes_any_hardware_action": False,
            "note": "this checklist is a plan, not an executed drill and not "
            "authority; every hardware action requires its own explicit "
            "authorization, reviewed model-specific procedure, and "
            "electrical/thermal controls",
        },
    }
    _guard_no_executable_tokens(plan)
    return plan


def _guard_no_executable_tokens(plan: Mapping[str, Any]) -> None:
    rendered = json.dumps(plan).lower()
    for token in FORBIDDEN_EXECUTABLE_TOKENS:
        if token in rendered:
            raise DrillPlanError(
                f"generated plan would contain executable-tool token "
                f"{token!r}; a drill plan must not embed flash commands"
            )


def render_markdown(plan: Mapping[str, Any]) -> str:
    binding = plan["discovery_binding"]
    identity = binding["stock_identity"]
    lines: list[str] = []
    lines.append(f"# K210 stock-recovery drill card - {plan['unit_label']}")
    lines.append("")
    lines.append(
        f"Generated by `{TOOL_NAME}` v{TOOL_VERSION} on "
        f"{plan['generated_at_utc']} from {RECOVERY_RECEIPTS_DOC}."
    )
    lines.append("")
    lines.append(
        "> **Boundary.** This is a generated plan, not an executed drill and "
        "not authority. The planner has no hardware transport. Every step "
        "below is executed only by the operator under a specific "
        "authorization with a reviewed model-specific procedure. The plan "
        "contains no executable flash commands by construction."
    )
    lines.append("")
    lines.append("## Unit binding (exact join to the admitted discovery bundle)")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| unit label | `{plan['unit_label']}` |")
    lines.append(f"| target | `{plan['target_id']}` ({plan['display_name']}) |")
    lines.append(f"| controller SoC | {plan['controller_soc']} |")
    lines.append(f"| discovery receipt ID | `{binding['discovery_receipt_id']}` |")
    lines.append(
        f"| unit fingerprint SHA-256 | `{binding['unit_fingerprint_sha256']}` |"
    )
    lines.append(f"| binding source | {binding['source']} |")
    lines.append("")
    lines.append("Expected stock identity (must exact-match after every restore):")
    lines.append("")
    lines.append(
        f"- firmware `{identity['stock_firmware_version']}`, HWTYPE "
        f"`{identity['stock_hwtype']}`, SWTYPE `{identity['stock_swtype']}`, "
        f"DNA `{identity['stock_dna']}`"
    )
    lines.append("")
    lines.append("## Authorization envelope")
    lines.append("")
    lines.append(
        "The drill requires a pre-existing operator authorization naming this "
        "exact unit, the UTC interval, and exactly these actions:"
    )
    lines.append("")
    for action in plan["authorized_actions"]:
        lines.append(f"- `{action}`")
    lines.append("")
    lines.append(
        "The interruption drill is destructive by design and additionally "
        "requires a sacrificial unit and an authorization that explicitly "
        "includes controlled interruption and power-cycle actions."
    )
    lines.append("")
    lines.append("## Drill stages")
    lines.append("")
    for stage in plan["stages"]:
        lines.append(f"### {stage['id']} - {stage['title']}")
        lines.append("")
        lines.append(f"Stage tags: {', '.join(stage['tags'])}.")
        lines.append("")
        for requirement in stage["requirements"]:
            lines.append(f"- [ ] {requirement}")
        for note in stage.get("safety_notes", ()):
            lines.append(f"- safety: {note}")
        lines.append("")
    lines.append("## Route B annexes (second existing-flash-independent route)")
    lines.append("")
    annex = plan["route_options"]["backup_read_b"][0]
    lines.append(f"### {annex['title']} (mechanism `{annex['mechanism_class']}`, recommended)")
    lines.append("")
    lines.append("Facts from the K210 SoC boot/flash/ISP desk contract:")
    lines.append("")
    for fact in annex["facts"]:
        lines.append(f"- {fact}")
    lines.append("")
    lines.append("Safety notes:")
    lines.append("")
    for note in annex["safety_notes"]:
        lines.append(f"- {note}")
    lines.append("")
    vendor = plan["route_options"]["backup_read_b"][1]
    lines.append(f"### {vendor['title']} (mechanism `{vendor['mechanism_class']}`)")
    lines.append("")
    for requirement in vendor["requirements"]:
        lines.append(f"- {requirement}")
    for note in vendor["safety_notes"]:
        lines.append(f"- safety: {note}")
    lines.append("")
    lines.append("## Evidence slots (match the recovery receipt exactly)")
    lines.append("")
    lines.append("| id | kind | path | media type | method | produced by |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for slot in plan["evidence_slots"]:
        lines.append(
            f"| `{slot['id']}` | `{slot['kind']}` | `{slot['path']}` | "
            f"{slot['media_type']} | {slot['method']} | {slot['produced_by_stage']} |"
        )
    lines.append("")
    signing = plan["signing"]
    lines.append("## Dual signing and admission (host-only commands)")
    lines.append("")
    lines.append(
        f"Operator role `{signing['operator_role']}` and witness role "
        f"`{signing['witness_role']}` must be distinct principals with "
        "distinct keys, public-key paths, and key IDs. Namespaces: "
        f"`{signing['operator_namespace']}` and "
        f"`{signing['witness_namespace']}`."
    )
    lines.append("")
    for command in plan["host_commands"]:
        lines.append(f"**Step {command['step']} - {command['purpose']}:**")
        lines.append("")
        lines.append(f"    {command['command']}")
        lines.append("")
    lines.append(
        "An admitted recovery receipt qualifies only the `stock_restore` "
        "gate; `boot_policy` becomes the first blocker. Nothing here "
        "qualifies custom-firmware boot, ASIC control, thermal/power safety, "
        "rollback, mining, endurance, release, or production readiness."
    )
    lines.append("")
    markdown = "\n".join(lines)
    lowered = markdown.lower()
    for token in FORBIDDEN_EXECUTABLE_TOKENS:
        if token in lowered:
            raise DrillPlanError(
                f"rendered drill card would contain executable-tool token "
                f"{token!r}"
            )
    return markdown


def write_plan(plan: Mapping[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{plan['unit_label']}-recovery-drill"
    markdown_path = out_dir / f"{base}.md"
    checklist_path = out_dir / f"{base}-checklist.json"
    for path in (markdown_path, checklist_path):
        if path.exists():
            raise DrillPlanError(f"refusing to overwrite existing plan output: {path}")
    markdown_path.write_text(render_markdown(plan), encoding="ascii")
    checklist_path.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return markdown_path, checklist_path


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser(
        "plan", help="generate the dual-path recovery drill plan for one unit"
    )
    plan.add_argument("--model", required=True)
    plan.add_argument("--unit-label", required=True)
    plan.add_argument(
        "--discovery-receipt",
        type=Path,
        default=None,
        help="canonical receipt.json from the admitted discovery bundle "
        "(binds the plan to the exact unit)",
    )
    plan.add_argument("--out-dir", type=Path, default=Path("."))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = recovery.discovery._load_manifest(args.manifest)
        plan = generate_drill_plan(
            manifest, args.model, args.unit_label, args.discovery_receipt
        )
        markdown_path, checklist_path = write_plan(plan, args.out_dir)
        print(
            f"K210_RECOVERY_DRILL_PLAN_WRITTEN unit={args.unit_label} "
            f"model={args.model} markdown={markdown_path.resolve().as_posix()} "
            f"checklist={checklist_path.resolve().as_posix()}"
        )
        return 0
    except (DrillPlanError, recovery.RecoveryError) as exc:
        print(f"K210_RECOVERY_DRILL_PLAN_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
