#!/usr/bin/env python3
"""Verify persistent S19k cold-boot, management, mining, and recovery acceptance."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import s19k_native_live_common as common


SCHEMA = "dcentos.s19k-persistent-acceptance-capture/v2"
RESULT_SCHEMA = "dcentos.s19k-persistent-acceptance-verification/v2"
PHASE = "persistent-acceptance"
FILES = (
    "install-verification.json",
    "cold-boots.csv",
    "management.csv",
    "board-inventory.csv",
    "mining.csv",
    "safeoff-recovery.csv",
    "independent-witness.json",
)
EXTRA_KEYS = (
    "device_id",
    "install_verification_id",
    "install_verification_sha256",
    "expected_image_sha256",
    "acceptance_profile",
    "expected_uart_paths",
)
PROFILES = (
    "bhb56902-only",
    "bhb56903-only",
    "mixed-bhb56902-bhb56903",
    "all-three-uarts-populated",
)
BOARD_NAMES = ("BHB56902", "BHB56903")
ADMITTED_UART_PATHS = ("/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3")
BOOT_HEADER = ("boot", "cold_start", "dcentos_identity", "image_sha256", "safeoff_baseline", "native_owner_admitted", "outcome")
MANAGEMENT_HEADER = ("boot", "ssh", "dashboard", "mcp", "api", "identity_match")
BOARD_HEADER = (
    "boot",
    "physical_slot",
    "uart_path",
    "board_name",
    "asic_id",
    "asic_count",
    "no_pic",
    "serial_number",
    "identity_source",
)
MINING_HEADER = ("boot", "path", "asic_count", "accepted_shares", "temperature_safe", "four_fans", "terminal_safeoff")
RECOVERY_HEADER = ("sequence", "event", "outcome", "stock_bytes_available", "safeoff_verified")


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    manifest_data, manifest, payload = common.verify_manifest(
        evidence_dir,
        schema=SCHEMA,
        phase=PHASE,
        payload_files=FILES,
        extra_keys=EXTRA_KEYS,
    )
    device_id = common.token(manifest["device_id"], "acceptance device_id")
    install_id = common.digest(manifest["install_verification_id"], "install verification_id")
    install_sha = common.digest(manifest["install_verification_sha256"], "install verification SHA-256")
    image_sha = common.digest(manifest["expected_image_sha256"], "expected image SHA-256")
    profile = common.token(manifest["acceptance_profile"], "acceptance profile")
    if profile not in PROFILES:
        common.fail("persistent acceptance profile is not admitted")
    uart_paths = manifest["expected_uart_paths"]
    if (
        not isinstance(uart_paths, list)
        or not all(isinstance(item, str) for item in uart_paths)
        or uart_paths != sorted(uart_paths)
        or len(uart_paths) != len(set(uart_paths))
        or len(uart_paths) not in (2, 3)
        or not set(uart_paths).issubset(ADMITTED_UART_PATHS)
    ):
        common.fail("persistent acceptance UART population is invalid")
    install_data = payload["install-verification.json"]
    if common.sha256(install_data) != install_sha:
        common.fail("persistent acceptance install receipt is not manifest-bound")
    install = common.validate_embedded_receipt(install_data, "persistent install verification")
    if common.verify_receipt_id(install, "persistent install verification") != install_id:
        common.fail("persistent acceptance install verification_id mismatch")
    if install.get("schema") != "dcentos.s19k-persistent-install-verification/v2" or install.get("device_id") != device_id or install.get("image_sha256") != image_sha or install.get("image_recovery_binding_verified") is not True:
        common.fail("persistent acceptance targets a different install/device/image")
    _, boot_rows = common.csv_rows(evidence_dir / "cold-boots.csv", BOOT_HEADER, "persistent cold-boot evidence")
    if len(boot_rows) != 3:
        common.fail("persistent acceptance requires exactly three cold boots")
    for index, row in enumerate(boot_rows, 1):
        if common.csv_uint(row[0], "cold boot ordinal", positive=True) != index:
            common.fail("persistent cold-boot ordinals are not exact")
        if row[1:] != ["true", "DCENT_OS-am3-s19k", image_sha, "checked", "true", "pass"]:
            common.fail("persistent cold boot did not preserve identity/SafeOff/native ownership")
    _, management_rows = common.csv_rows(evidence_dir / "management.csv", MANAGEMENT_HEADER, "persistent management evidence")
    if len(management_rows) != 3:
        common.fail("persistent acceptance requires management evidence for every boot")
    for index, row in enumerate(management_rows, 1):
        if common.csv_uint(row[0], "management boot ordinal", positive=True) != index or row[1:] != ["pass"] * 5:
            common.fail("persistent management surface failed on a cold boot")
    inventory_data, inventory_rows = common.csv_rows(
        evidence_dir / "board-inventory.csv",
        BOARD_HEADER,
        "persistent board inventory evidence",
    )
    expected_inventory_pairs = {
        (str(boot), path) for boot in range(1, 4) for path in uart_paths
    }
    inventory_pairs: set[tuple[str, str]] = set()
    baseline_inventory: list[tuple[int, str, str, str]] | None = None
    all_board_names: set[str] = set()
    all_slots: set[int] = set()
    for boot in range(1, 4):
        observed: list[tuple[int, str, str, str]] = []
        boot_rows = [row for row in inventory_rows if row[0] == str(boot)]
        if len(boot_rows) != len(uart_paths):
            common.fail("persistent board inventory count changed across cold boots")
        for row in boot_rows:
            slot = common.csv_uint(row[1], "persistent physical slot", positive=True)
            if slot not in (1, 2, 3) or row[2] not in uart_paths:
                common.fail("persistent board inventory slot/UART is not admitted")
            pair = (row[0], row[2])
            if pair not in expected_inventory_pairs or pair in inventory_pairs:
                common.fail("persistent board inventory has an unexpected/repeated boot/UART")
            board_name = row[3]
            if (
                board_name not in BOARD_NAMES
                or row[4:7] != ["0x1366", "77", "true"]
                or common.token(row[7], "persistent board serial") != row[7]
                or row[8] != "stock-runtime+eeprom-or-model-joined"
            ):
                common.fail("persistent board inventory identity is not exact BM1366 NoPIC")
            observed.append((slot, row[2], board_name, row[7]))
            inventory_pairs.add(pair)
            all_board_names.add(board_name)
            all_slots.add(slot)
        observed.sort()
        if len({item[0] for item in observed}) != len(observed):
            common.fail("persistent board inventory repeats a physical slot")
        if baseline_inventory is None:
            baseline_inventory = observed
        elif observed != baseline_inventory:
            common.fail("persistent board inventory drifted across cold boots")
    if inventory_pairs != expected_inventory_pairs:
        common.fail("persistent board inventory coverage is incomplete")
    if profile == "bhb56902-only" and all_board_names != {"BHB56902"}:
        common.fail("BHB56902-only acceptance contains another board type")
    if profile == "bhb56903-only" and all_board_names != {"BHB56903"}:
        common.fail("BHB56903-only acceptance contains another board type")
    if (
        profile == "mixed-bhb56902-bhb56903"
        and all_board_names != set(BOARD_NAMES)
    ):
        common.fail("mixed acceptance does not contain both BHB56902 and BHB56903")
    if profile == "all-three-uarts-populated" and (
        set(uart_paths) != set(ADMITTED_UART_PATHS) or all_slots != {1, 2, 3}
    ):
        common.fail("three-UART acceptance does not populate all slots and UARTs")
    _, mining_rows = common.csv_rows(evidence_dir / "mining.csv", MINING_HEADER, "persistent native mining evidence")
    expected_pairs = {(str(boot), path) for boot in range(1, 4) for path in uart_paths}
    seen_pairs: set[tuple[str, str]] = set()
    accepted_total = 0
    for row in mining_rows:
        pair = (row[0], row[1])
        if pair not in expected_pairs or pair in seen_pairs:
            common.fail("persistent native mining evidence has an unexpected/repeated boot/UART")
        if common.csv_uint(row[2], "persistent ASIC count", positive=True) != 77:
            common.fail("persistent native mining did not enumerate exact 77/77")
        accepted = common.csv_uint(row[3], "persistent accepted shares", positive=True)
        if row[4:] != ["true", "true", "true"]:
            common.fail("persistent mining lacks thermal/cooling/SafeOff acceptance")
        accepted_total += accepted
        seen_pairs.add(pair)
    if seen_pairs != expected_pairs:
        common.fail("persistent native mining coverage is incomplete")
    _, recovery_rows = common.csv_rows(evidence_dir / "safeoff-recovery.csv", RECOVERY_HEADER, "persistent recovery acceptance")
    expected_events = (
        ("0", "dcentos-safeoff", "pass", "true", "true"),
        ("1", "stock-restore-executed", "pass", "true", "true"),
        ("2", "stock-cold-boot-verified", "pass", "true", "true"),
        ("3", "dcentos-reinstall-executed", "pass", "true", "true"),
        ("4", "dcentos-cold-boot-after-reinstall", "pass", "true", "true"),
    )
    if tuple(tuple(row) for row in recovery_rows) != expected_events:
        common.fail("persistent SafeOff/recovery acceptance sequence is inexact")
    witness = common.validate_embedded_receipt(payload["independent-witness.json"], "persistent acceptance witness")
    common.exact_object(
        witness,
        ("schema", "device_id", "install_verification_id", "operator", "witness", "cold_boots_sha256", "management_sha256", "board_inventory_sha256", "mining_sha256", "safeoff_recovery_sha256", "terminal_claim_observed"),
        "persistent acceptance witness",
    )
    if witness["schema"] != "dcentos.s19k-persistent-acceptance-witness/v2" or witness["device_id"] != device_id or witness["install_verification_id"] != install_id:
        common.fail("persistent acceptance witness does not join the install")
    operator = common.token(witness["operator"], "acceptance operator")
    witness_name = common.token(witness["witness"], "acceptance witness")
    if operator == witness_name or witness["terminal_claim_observed"] is not True:
        common.fail("persistent acceptance lacks an independent terminal witness")
    for name, key in (
        ("cold-boots.csv", "cold_boots_sha256"),
        ("management.csv", "management_sha256"),
        ("board-inventory.csv", "board_inventory_sha256"),
        ("mining.csv", "mining_sha256"),
        ("safeoff-recovery.csv", "safeoff_recovery_sha256"),
    ):
        if witness[key] != common.sha256(payload[name]):
            common.fail(f"persistent acceptance witness does not bind {name}")
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "claim": "three cold DCENT_OS boots with exact board/UART identity, management, native mining, SafeOff, actual stock restore/boot, and DCENT_OS reinstall/boot",
        "device_id": device_id,
        "run_id": manifest["run_id"],
        "common_clock_id": manifest["common_clock_id"],
        "acceptance_profile": profile,
        "image_sha256": image_sha,
        "install_verification_id": install_id,
        "capture_manifest_sha256": common.sha256(manifest_data),
        "cold_boot_count": 3,
        "native_uart_paths": uart_paths,
        "board_names": sorted(all_board_names),
        "physical_slots": sorted(all_slots),
        "board_inventory_sha256": common.sha256(inventory_data),
        "accepted_share_total": accepted_total,
        "management_surfaces": ["ssh", "dashboard", "mcp", "api"],
        "terminal_safeoff_verified": True,
        "stock_restore_and_cold_boot_verified": True,
        "dcentos_reinstall_and_cold_boot_verified": True,
        "independent_acceptance_verified": True,
        "operator": operator,
        "witness": witness_name,
        "mutation_authority_granted": False,
    }
    return common.add_verification_id(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_workflow_evidence(args.evidence_dir.resolve(strict=True))
    except (OSError, common.NativeLiveEvidenceError) as error:
        print(f"S19K_PERSISTENT_ACCEPTANCE_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(common.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
