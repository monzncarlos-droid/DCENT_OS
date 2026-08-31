#!/usr/bin/env python3
"""Ingest operator bench captures for bb-sd-coldboot-diagnosis and mint the
receipt in one step (desk-side; run AFTER the physical bench session).

The operator runs the physical gate per

BB_SD_COLDBOOT_DIAGNOSIS.md — captures may land on the bench host rather
than this tree. This helper copies them in, records the authorization
verbatim, and stages the receipt. It refuses to invent anything: every
capture byte must already exist at --captures-from, and --authorization is
recorded exactly as given (the operator's words, not generated).

Usage:
    py -3 s19jpro_bb_diag_ingest.py \
        --captures-from <dir-or-file list> \
        --authorization-file <operator's authorization.txt> \
        [--verdict-note <one-line H1/H2/H3 observation for trial notes>]
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EV = REPO / ".s19jpro-enablement-evidence/bb-sd-coldboot-diagnosis"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--captures-from", nargs="+", required=True,
        help="capture file(s) or directory copied from the bench host",
    )
    parser.add_argument(
        "--authorization-file", type=Path, required=True,
        help="the operator's authorization.txt (recorded verbatim)",
    )
    parser.add_argument(
        "--verdict-note", default=None,
        help="one-line observation for trial notes (H1/H2/H3 or 'new evidence')",
    )
    args = parser.parse_args(argv)

    authorization = args.authorization_file.read_text(encoding="utf-8").strip()
    if len(authorization) < 40:
        print(
            "REFUSED: authorization text too short — record who authorized "
            "what, when, and for which exact action.",
            file=sys.stderr,
        )
        return 1

    (EV / "serial-capture").mkdir(parents=True, exist_ok=True)
    (EV / "trial").mkdir(parents=True, exist_ok=True)
    staged: list[Path] = []
    for source in args.captures_from:
        source = Path(source)
        if source.is_dir():
            candidates = sorted(
                p for p in source.iterdir()
                if p.is_file() and not p.name.startswith(".")
            )
        else:
            candidates = [source]
        for item in candidates:
            if not item.is_file():
                print(f"REFUSED: not a regular file: {item}", file=sys.stderr)
                return 1
            dest = EV / "serial-capture" / item.name
            if dest.exists():
                print(
                    f"REFUSED: capture already staged with that name: {dest.name} "
                    "(rename or remove; never overwrite evidence)",
                    file=sys.stderr,
                )
                return 1
            shutil.copyfile(item, dest)
            staged.append(dest)
    if not staged:
        print("REFUSED: no capture files found at --captures-from", file=sys.stderr)
        return 1

    (EV / "authorization.txt").write_text(authorization + "\n", encoding="utf-8")
    note = args.verdict_note or "(verdict pending analysis)"
    (EV / "trial" / "bench-notes.md").write_text(
        "# bb-sd-coldboot-diagnosis bench notes\n\n"
        f"Captures staged ({len(staged)}):\n"
        + "".join(f"- serial-capture/{p.name}\n" for p in staged)
        + f"\nOperator observation: {note}\n"
        "(Full H1/H2/H3 adjudication per the card's decision tree follows "
        "from the capture bytes; update this file with the verdict.)\n",
        encoding="utf-8",
    )
    print(f"staged {len(staged)} capture(s) + authorization + trial notes under {EV}")
    print("next: s19jpro_lane_verify.py prepare --phase bb-sd-coldboot-diagnosis "
          "--operator-authorization \"$(cat .../authorization.txt)\" ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
