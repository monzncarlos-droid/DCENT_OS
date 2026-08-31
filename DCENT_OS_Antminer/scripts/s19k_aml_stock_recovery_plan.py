#!/usr/bin/env python3
"""Validate and render the exact held S19k Pro Amlogic factory-SD plan.

This tool is deliberately offline and plan-only.  It has no SSH, block-device,
mount, burn-tool, GPIO, or NAND execution path.  The admitted vendor archive is
a full erase/reflash carrier, not a DCENT sysupgrade and not a substitute for a
Linux raw-MTD backup restore.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile


ARCHIVE_NAME = "AML-19k-Pro-202311151447-sd-card.zip"
ARCHIVE_BYTES = 23_470_887
ARCHIVE_SHA256 = "46214d02b3c246ad4f98bcbe50b83705392a23a9fa5007120cb21d033e98dcf4"
MEMBERS = (
    "aml_sdc_burn.ini",
    "aml_sdc_burn.UBOOT.ENC",
    "aml_upgrade_package_enc.img",
)
MEMBER_CONTRACT = {
    "aml_sdc_burn.ini": (
        602,
        "23026acac61ff4144e0e70521a91f7d527fd3bb8c31d22efce980900ebf2c5f0",
    ),
    "aml_sdc_burn.UBOOT.ENC": (
        818_688,
        "546ca8c4540ab584792716b2871d42ee304f594880f8c907e1018f68f6ab9cbc",
    ),
    "aml_upgrade_package_enc.img": (
        23_134_392,
        "539da235cdf816a2cbfbf2037b056ad1b2dc5ab704efc97ed0050e6e0b313678",
    ),
}
TOC_BYTES = 11_008
TOC_SHA256 = "efb21fd2d67e651a4ac2d4558a21099ccab250df73032b1c0acecee78cda20d8"
AML_IMAGE_HEADER = {
    "crc": 0x1CCB07DA,
    "version": 2,
    "magic": 0x27B51956,
    "image_bytes": 23_134_392,
    "item_align": 8,
    "item_count": 19,
}


class RecoveryMediaError(ValueError):
    """The archive is not the exact held S19k AML factory recovery carrier."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_member(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name, "r") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _parse_exact_ini(raw: bytes) -> dict[str, str]:
    section: str | None = None
    seen_sections: set[str] = set()
    values: dict[tuple[str, str], str] = {}
    allowed = {
        "common": {"erase_bootloader", "erase_flash", "reboot"},
        "burn_ex": {"package"},
    }
    for raw_line in raw.splitlines():
        stripped = raw_line.strip()
        # The held explanatory comment contains GBK text; functional lines are
        # required to be exact ASCII, matching the INI's own warning.
        if not stripped or stripped.startswith((b";", b"#")):
            continue
        try:
            line = stripped.decode("ascii")
        except UnicodeDecodeError as error:
            raise RecoveryMediaError("functional INI directive is not ASCII") from error
        if line.startswith("["):
            if line not in ("[common]", "[burn_ex]"):
                raise RecoveryMediaError("unknown aml_sdc_burn.ini section")
            section = line[1:-1]
            if section in seen_sections:
                raise RecoveryMediaError("duplicate aml_sdc_burn.ini section")
            seen_sections.add(section)
            continue
        if section is None or line.count("=") != 1:
            raise RecoveryMediaError("directive is unscoped or has ambiguous equals signs")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in allowed[section]:
            raise RecoveryMediaError("unknown or misplaced aml_sdc_burn.ini directive")
        field = (section, key)
        if field in values:
            raise RecoveryMediaError("duplicate aml_sdc_burn.ini directive")
        values[field] = value

    expected = {
        ("common", "erase_bootloader"): "1",
        ("common", "erase_flash"): "1",
        ("common", "reboot"): "1",
        ("burn_ex", "package"): "aml_upgrade_package_enc.img",
    }
    if seen_sections != {"common", "burn_ex"} or values != expected:
        raise RecoveryMediaError("INI is not the exact S19k full-erase/reboot package policy")
    return {f"{section}.{key}": value for (section, key), value in values.items()}


def _parse_exact_aml_header(toc: bytes) -> dict[str, int]:
    if len(toc) != TOC_BYTES:
        raise RecoveryMediaError("AmlImagePack TOC must be exactly 11008 bytes")
    crc, version, magic, image_bytes, item_align, item_count = struct.unpack_from(
        "<IIIQII", toc, 0
    )
    observed = {
        "crc": crc,
        "version": version,
        "magic": magic,
        "image_bytes": image_bytes,
        "item_align": item_align,
        "item_count": item_count,
    }
    if observed != AML_IMAGE_HEADER:
        raise RecoveryMediaError("AmlImagePack header is not the held S19k 19-item v2 pack")
    if hashlib.sha256(toc).hexdigest() != TOC_SHA256:
        raise RecoveryMediaError("AmlImagePack 11008-byte TOC hash mismatch")
    return observed


def validate_archive(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise RecoveryMediaError("archive must be a regular non-symlink file")
    if path.stat().st_size != ARCHIVE_BYTES:
        raise RecoveryMediaError("S19k AML factory archive byte length mismatch")
    archive_sha256 = _sha256_file(path)
    if archive_sha256 != ARCHIVE_SHA256:
        raise RecoveryMediaError("S19k AML factory archive SHA256 mismatch")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if names != MEMBERS or len(set(names)) != len(names):
                raise RecoveryMediaError("archive must contain the exact three canonical members")
            if any(info.is_dir() for info in infos):
                raise RecoveryMediaError("archive must not contain directories")
            for info in infos:
                expected_bytes, expected_sha256 = MEMBER_CONTRACT[info.filename]
                if info.file_size != expected_bytes:
                    raise RecoveryMediaError(f"{info.filename} byte length mismatch")
                if _sha256_member(archive, info.filename) != expected_sha256:
                    raise RecoveryMediaError(f"{info.filename} SHA256 mismatch")
            ini = _parse_exact_ini(archive.read("aml_sdc_burn.ini"))
            with archive.open("aml_upgrade_package_enc.img", "r") as image:
                header = _parse_exact_aml_header(image.read(TOC_BYTES))
    except zipfile.BadZipFile as error:
        raise RecoveryMediaError("archive is not a valid ZIP") from error

    return {
        "archive_sha256": archive_sha256,
        "members": list(MEMBERS),
        "ini": ini,
        "aml_image_header": header,
    }


def render_plan(path: Path, evidence: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "dcentos.s19k-aml-stock-recovery-plan/v1",
        "status": "IMPLEMENTED_EXPERIMENTAL",
        "classification": "vendor-encrypted-amlogic-sd-full-erase-stock-return",
        "archive_name": path.name,
        "archive_sha256": evidence["archive_sha256"],
        "members": evidence["members"],
        "erase_bootloader": True,
        "erase_flash": True,
        "reboot": True,
        "transport": "physical-amlogic-sd-burn",
        "factory_toc_scope": "_aml_dtb+boot+bootloader+recovery+conf-keys+platform",
        "unit_specific_state_restore": False,
        "destroyed_state": ["/config", "/nvdata", "/miner", "device-calibration"],
        "media_preparation": "evidence-bounded-dedicated-fat32-with-exact-three-root-members",
        "required_preburn_backup": "dcentos.s19k-aml-full-logical-rescue/v1-six-mtd-hashes-stable-badblock-counts-boot-nand-transcript-encrypted-offhost-copy",
        "preburn_backup_is_physical_replay": False,
        "required_unit_state_restore": "separately-validated-config+nvdata+miner+eeprom+calibration-import",
        "bench_sequence": [
            "capture-and-verify-FULL_RESCUE_LEDGER.txt-six-mtd-hashes-stable-badblock-counts-boot-nand-transcript-and-encrypted-offhost-copy",
            "validate-unit-specific-config-nvdata-miner-eeprom-calibration-restore-procedure",
            "revalidate-this-exact-archive-and-member-hashes",
            "power-unit-off",
            "insert-dedicated-recovery-card",
            "power-unit-on-and-do-not-interrupt-full-erase-burn",
            "after-vendor-completion-indication-power-off-and-remove-card",
            "boot-and-verify-exact-stock-model-version-config-and-three-hashboard-inventory",
        ],
        "live_choreography": "USB-button-completion-sequence-remains-live-unproven",
        "completion_signal": "LIVE_S19K_AML_VENDOR_INDICATION_REMAINS_TO_BE_CAPTURED",
        "linux_raw_restore_equivalent": False,
        "dcent_sysupgrade": False,
        "clear_for_flash": False,
        "execute": False,
        "remaining_uncertainty": [
            "physical-S19k-AML-BootROM-acceptance",
            "exact-live-completion-indication-and-duration",
            "post-burn-stock-boot-and-configuration-restoration",
            "unit-specific-state-import-after-full-erase",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate exact held S19k AML stock recovery media and print a no-execute plan."
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--json", action="store_true", help="emit the plan as JSON")
    args = parser.parse_args(argv)
    try:
        evidence = validate_archive(args.archive)
        plan = render_plan(args.archive, evidence)
    except (OSError, RecoveryMediaError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        for key, value in plan.items():
            if isinstance(value, list):
                print(f"{key}=" + "+".join(str(item) for item in value))
            else:
                print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
