#!/usr/bin/env python3
"""Keep required exact Rust selectors synchronized and source-resolvable."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parents[1]
WORKFLOW = WORKSPACE / ".github" / "workflows" / "dcentos-offline-gates.yml"
STATIC_GATE = PROJECT / "scripts" / "ci_offline_gates.sh"
PREFIX = "sh ../scripts/run_exact_cargo_test.sh "


parser = argparse.ArgumentParser(
    description="check exact-selector workflow/static parity and Cargo resolution"
)
parser.add_argument(
    "--inventory-only",
    action="store_true",
    help="check synchronized, well-formed inventories without invoking cargo",
)
args = parser.parse_args()


def commands(path: Path) -> list[str]:
    found: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        start = raw.find(PREFIX)
        if start < 0:
            continue
        command = raw[start:].strip()
        if command.endswith("\\"):
            command = command[:-1].rstrip()
        command = command.strip("'\"")
        found.append(command)
    return found


def fail(message: str) -> None:
    print(f"exact selector parity failed: {message}", file=sys.stderr)
    raise SystemExit(1)


workflow_commands = commands(WORKFLOW)
static_commands = commands(STATIC_GATE)

# Stale rename (2026-07-22 continuous audit residual): the closeout pin moved
# from f1_all_proven_* to f1_only_fully_owned_*. Cargo --exact with a stale name
# exits 0 with zero tests — ban the old token everywhere inventories are mined.
STALE_F1 = "f1_all_proven_closeout_arms_use_management_only_on_err"
CURRENT_F1 = "f1_only_fully_owned_closeout_arms_use_management_only_on_err"
all_cmds = "\n".join(workflow_commands + static_commands)
if STALE_F1 in all_cmds:
    fail(f"stale selector {STALE_F1!r} still present (use {CURRENT_F1!r})")
if CURRENT_F1 not in all_cmds:
    fail(f"required selector {CURRENT_F1!r} missing from workflow/static inventories")

workflow_counts = Counter(workflow_commands)
static_counts = Counter(static_commands)
workflow_duplicates = sorted(command for command, count in workflow_counts.items() if count != 1)
static_duplicates = sorted(command for command, count in static_counts.items() if count != 1)
if workflow_duplicates:
    fail(f"workflow duplicates: {workflow_duplicates}")
if static_duplicates:
    fail(f"static inventory duplicates: {static_duplicates}")

workflow_set = set(workflow_commands)
static_set = set(static_commands)
if workflow_set != static_set:
    missing = sorted(workflow_set - static_set)
    stale = sorted(static_set - workflow_set)
    fail(f"missing_from_static={missing}; stale_in_static={stale}")

selectors_by_cargo_args: dict[tuple[str, ...], list[str]] = defaultdict(list)
for command in workflow_commands:
    argv = shlex.split(command)
    selector = argv[2]
    try:
        package = argv[argv.index("-p") + 1]
    except (ValueError, IndexError):
        fail(f"selector lacks an exact package: {command}")
    package_dir = PROJECT / "dcentrald" / package
    if not package_dir.is_dir():
        fail(f"package directory is missing for {command}")
    selectors_by_cargo_args[tuple(argv[3:])].append(selector)

if args.inventory_only:
    print(
        "exact selector inventory parity passed: "
        f"workflow={len(workflow_commands)} static={len(static_commands)} "
        "cargo_resolvable=skipped"
    )
    raise SystemExit(0)

resolved = 0
for cargo_args, selectors in sorted(selectors_by_cargo_args.items()):
    result = subprocess.run(
        ["cargo", "test", *cargo_args, "--", "--list"],
        cwd=PROJECT / "dcentrald",
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        fail(
            "cargo --list failed for "
            f"{shlex.join(cargo_args)}:\n{result.stdout}"
        )
    listed = Counter(
        line.removesuffix(": test")
        for line in result.stdout.splitlines()
        if line.endswith(": test")
    )
    for selector in selectors:
        if listed[selector] != 1:
            fail(
                f"selector {selector!r} resolved {listed[selector]} times under "
                f"cargo test {shlex.join(cargo_args)}"
            )
        resolved += 1

print(
    "exact selector parity passed: "
    f"workflow={len(workflow_commands)} static={len(static_commands)} cargo_resolvable={resolved}"
)
