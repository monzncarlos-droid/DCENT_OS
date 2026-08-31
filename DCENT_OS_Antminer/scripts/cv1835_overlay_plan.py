#!/usr/bin/env python3
"""Fail-closed CV1835 overlay planner (no payload, no flash).

CV1835 remains evidence-only. This host-side planner never admits a firmware
blob, sysupgrade tarball, overlay payload, or storage mutation. Every
invocation returns denied / not_implemented and exits 78 (EX_UNAVAILABLE).
Flags such as --payload, --flash, or --execute cannot authorize work.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping, Optional


BOARD_TARGET = "cv1835-s19jpro"
PLAN_SCHEMA = "dcentos.cv1835.overlay-plan.v1"
EX_UNAVAILABLE = 78
DENIED_STATE = "denied"
DENIED_EXECUTION = "not_implemented"

_PLAN: dict[str, Any] = {
    "schema": PLAN_SCHEMA,
    "board_target": BOARD_TARGET,
    "state": DENIED_STATE,
    "execution_state": DENIED_EXECUTION,
    "install_authorization": "denied",
    "payload": None,
    "payload_bytes": 0,
    "flash": False,
    "authority": "none",
    "reason": (
        "CV1835 overlay/sysupgrade is evidence-only; no payload is admitted "
        "and no flash lane exists."
    ),
}


def overlay_plan(argv: Optional[list[str]] = None) -> dict[str, Any]:
    """Return the immutable denial document. argv is recorded, never executed."""
    plan = dict(_PLAN)
    plan["argv"] = list(argv or [])
    return plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan a CV1835 overlay. Always denied: no payload is produced "
            "and no flash is performed."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="write the denial document to stdout (always; this is the only output)",
    )
    parser.add_argument(
        "--payload",
        metavar="PATH",
        help="ignored: a payload path cannot authorize a CV1835 overlay",
    )
    parser.add_argument(
        "--flash",
        action="store_true",
        help="ignored: flash is not implemented",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="ignored: execution is not implemented",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="optional path for the denial JSON only (never a firmware blob)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    plan = overlay_plan(sys.argv[1:] if argv is None else argv)
    encoded = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(encoded)
    sys.stderr.write(
        "ERROR: CV1835 overlay plan denied: not_implemented "
        "(no payload, no flash).\n"
    )
    if args.payload or args.flash or args.execute:
        sys.stderr.write(
            "ERROR: --payload/--flash/--execute cannot authorize this planner.\n"
        )
    if args.output:
        output = args.output
        lowered = output.lower()
        if lowered.endswith((".bin", ".img", ".tar", ".gz", ".bit", ".itb")):
            sys.stderr.write(
                "ERROR: refusing to write a payload-shaped path: %s\n" % output
            )
            return EX_UNAVAILABLE
        try:
            with open(output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
        except OSError as error:
            sys.stderr.write("ERROR: cannot write denial JSON: %s\n" % error)
            return EX_UNAVAILABLE
    return EX_UNAVAILABLE


def assert_plan_is_denied(plan: Mapping[str, Any]) -> None:
    """Host-test helper: the planner document is a denial with no payload."""
    if plan.get("state") != DENIED_STATE:
        raise AssertionError("overlay plan state must be denied")
    if plan.get("execution_state") != DENIED_EXECUTION:
        raise AssertionError("overlay plan execution_state must be not_implemented")
    if plan.get("payload") is not None:
        raise AssertionError("overlay plan must not carry a payload")
    if plan.get("flash") is not False:
        raise AssertionError("overlay plan must not authorize flash")
    if int(plan.get("payload_bytes") or 0) != 0:
        raise AssertionError("overlay plan must not report payload bytes")


if __name__ == "__main__":
    sys.exit(main())
