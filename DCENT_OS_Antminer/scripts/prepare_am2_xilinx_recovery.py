#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Verify or materialize exact AM2 Xilinx vendor recovery media.

This host tool delegates all parsing and exclusive-output safety to
``dcent_toolbox.core.am2_xilinx_recovery``.  It never writes a block device or
contacts a miner.  ``--execute`` only creates a regular local image and its
non-authorizing manifest; physical media use remains a separate operator step.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects/dcent-toolbox/src"
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xilinx_recovery import (  # noqa: E402
    AM2_XILINX_RECOVERY_PROFILES,
    Am2XilinxRecoveryError,
    analyze_am2_xilinx_recovery,
    prepare_am2_xilinx_recovery_artifact,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify or exclusively materialize an exact, byte-identical AM2 "
            "Xilinx vendor recovery image. No device is contacted or opened."
        )
    )
    result.add_argument("--target", help="exact AM2 Xilinx artifact target")
    result.add_argument("--source", type=Path, help="exact local ZIP or raw image")
    result.add_argument("--output", type=Path, help="new regular .img output path")
    result.add_argument(
        "--execute",
        action="store_true",
        help="materialize output; default is read-only analysis/plan",
    )
    result.add_argument(
        "--acknowledge-vendor-nand-installer",
        action="store_true",
        help="acknowledge that booting the resulting vendor image may mutate miner NAND",
    )
    result.add_argument("--list", action="store_true", help="list exact profiles")
    result.add_argument("--json", action="store_true", help="emit structured JSON")
    return result


def _print(value: dict, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    for field in (
        "target",
        "state",
        "success",
        "source_path",
        "source_sha256",
        "image_sha256",
        "output_path",
        "manifest_path",
        "message",
        "proof_ceiling",
        "device_contact",
        "block_device_write",
    ):
        if field in value and value[field] not in ("", None):
            print(f"{field}={value[field]}")


def main() -> int:
    args = parser().parse_args()
    if args.list:
        profiles = [
            {
                "target": target,
                "model": profile.model,
                "asic": profile.asic,
                "source_form": profile.source_form,
                "archive_name": profile.archive_name,
                "archive_sha256": profile.archive_sha256,
                "image_sha256": profile.image_sha256,
                "dcent_build_target": profile.dcent_build_target,
            }
            for target, profile in AM2_XILINX_RECOVERY_PROFILES.items()
        ]
        if args.json:
            print(json.dumps(profiles, indent=2, sort_keys=True))
        else:
            for item in profiles:
                print(
                    f"{item['target']} model={item['model']} asic={item['asic']} "
                    f"source_form={item['source_form']}"
                )
        return 0
    if not args.target:
        parser().error("--target is required unless --list is used")
    if args.execute and args.output is None:
        parser().error("--execute requires --output")

    try:
        analysis = analyze_am2_xilinx_recovery(
            args.target,
            args.source,
            repo_root=WORKSPACE_ROOT,
        )
        if args.output is None:
            _print(analysis.to_dict(), as_json=args.json)
            return 0 if analysis.state != "exact-source-missing" else 2
        if not analysis.source_path:
            _print(analysis.to_dict(), as_json=args.json)
            return 2
        result = prepare_am2_xilinx_recovery_artifact(
            args.target,
            Path(analysis.source_path),
            args.output,
            execute=args.execute,
            acknowledge_vendor_nand_installer=(
                args.acknowledge_vendor_nand_installer
            ),
        )
        _print(result.to_dict(), as_json=args.json)
        return 0 if result.success else 2
    except (Am2XilinxRecoveryError, OSError, ValueError) as exc:
        error = {
            "state": "refused",
            "success": False,
            "message": str(exc),
            "device_contact": "none",
            "block_device_write": "none",
            "execution_state": "not_started",
        }
        _print(error, as_json=args.json)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
