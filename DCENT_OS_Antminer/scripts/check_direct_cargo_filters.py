#!/usr/bin/env python3
"""Fail closed on workflow cargo test lines that can false-green on zero matches.

`cargo test FILTER` exits successfully when FILTER matches zero tests. Offline
gates that intend to pin a module or substring must either:
  * use `run_exact_cargo_test.sh` (exactly one fully-qualified test), or
  * use `run_filtered_cargo_test.sh` (require ≥1 match then run), or
  * run a full package/binary suite with no positional filter.

This scanner inspects GitHub workflow YAML under `.github/workflows/` for
`cargo test` invocations that still use bare positional filters.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path
from typing import Optional, Tuple

# scripts/ → dcentos/ → projects/ → repo root
PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parents[1]
WORKFLOWS = WORKSPACE / ".github" / "workflows"

# When None, every `*.yml` under `.github/workflows/` is scanned.
# A non-empty tuple limits scope (legacy / focused debug). Full-repo scan is
# the decade default: zero-match cargo filters anywhere in GHA are false-green.
SCOPED: Optional[Tuple[str, ...]] = None

SAFE_PREFIXES = (
    "sh ../scripts/run_exact_cargo_test.sh",
    "sh ../scripts/run_filtered_cargo_test.sh",
    "bash ../scripts/run_exact_cargo_test.sh",
    "bash ../scripts/run_filtered_cargo_test.sh",
)


def fail(msg: str) -> None:
    print(f"direct cargo filter check failed: {msg}", file=sys.stderr)
    raise SystemExit(1)


def extract_run_blocks(text: str) -> list[str]:
    """Pull `run:` scalar and block-scalar command text from a workflow file."""
    lines = text.splitlines()
    commands: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        indent, rest = m.group(1), m.group(2).strip()
        if rest in ("|", ">-", ">", "|-"):
            block: list[str] = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    block.append("")
                    i += 1
                    continue
                if len(nxt) - len(nxt.lstrip(" ")) <= len(indent):
                    break
                block.append(nxt.strip())
                i += 1
            commands.append("\n".join(block))
            continue
        if rest:
            commands.append(rest)
        i += 1
    return commands


def is_safe_cargo_test(cmd: str) -> bool:
    stripped = cmd.strip()
    if not stripped or stripped.startswith("#"):
        return True
    if any(stripped.startswith(p) or p in stripped for p in SAFE_PREFIXES):
        return True
    if "cargo test" not in stripped:
        return True

    # Multi-line shell: check each cargo test subcommand
    risky = []
    for part in re.split(r"(?:&&|\n|;)", stripped):
        part = part.strip()
        if "cargo test" not in part:
            continue
        if any(p in part for p in SAFE_PREFIXES):
            continue
        if _cargo_test_is_safe(part):
            continue
        risky.append(part)
    return not risky


def _cargo_test_is_safe(part: str) -> bool:
    """Return True when the invocation cannot false-green on a zero match."""
    try:
        argv = shlex.split(part)
    except ValueError:
        return False
    if "cargo" not in argv:
        return True
    # Find `test` after cargo
    try:
        cidx = argv.index("cargo")
    except ValueError:
        return True
    if cidx + 1 >= len(argv) or argv[cidx + 1] != "test":
        return True
    args = argv[cidx + 2 :]
    # Split on harness `--`
    if "--" in args:
        cargo_side = args[: args.index("--")]
        harness = args[args.index("--") + 1 :]
    else:
        cargo_side = args
        harness = []

    # Harness --exact is safe only with a filter (still could be zero with exact
    # if name wrong — exact alone without filter runs suite). Prefer exact+name.
    if "--exact" in harness and any(not a.startswith("-") for a in harness):
        return True

    # Positional filter after cargo options (before or after --)
    positionals = [a for a in cargo_side if not a.startswith("-") and a not in ("test",)]
    # cargo test -p pkg --lib FILTER  → FILTER is last positional after flags
    # Known non-filter positionals: package name after -p, bin name after --bin,
    # test binary after --test, feature after --features
    skip_next = False
    filter_candidates: list[str] = []
    i = 0
    while i < len(cargo_side):
        a = cargo_side[i]
        if skip_next:
            skip_next = False
            i += 1
            continue
        if a in (
            "-p",
            "--package",
            "--bin",
            "--test",
            "--features",
            "--target",
            "--manifest-path",
            "--color",
            "-j",
            "--jobs",
        ):
            skip_next = True
            i += 1
            continue
        if a.startswith("--features=") or a.startswith("-p=") or a.startswith("--package="):
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        # positional
        filter_candidates.append(a)
        i += 1

    harness_filters = [a for a in harness if not a.startswith("-")]
    filters = filter_candidates + harness_filters
    if not filters:
        # Full suite: package / lib / workspace — cannot zero-match a filter
        return True
    # Any remaining filter is zero-test-success risk unless handled above
    return False


def workflow_names() -> list[str]:
    if SCOPED is not None:
        return list(SCOPED)
    return sorted(p.name for p in WORKFLOWS.glob("*.yml"))


def main() -> None:
    if not WORKFLOWS.is_dir():
        fail(f"workflows dir missing: {WORKFLOWS}")

    violations: list[str] = []
    scanned = 0
    names = workflow_names()
    for name in names:
        path = WORKFLOWS / name
        if not path.is_file():
            continue
        for cmd in extract_run_blocks(path.read_text(encoding="utf-8")):
            if "cargo test" not in cmd:
                continue
            scanned += 1
            if not is_safe_cargo_test(cmd):
                snippet = " ".join(cmd.split())
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                violations.append(f"{name}: {snippet}")

    if violations:
        print("Unsafe cargo test filters (zero-match can false-green):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print(
            "Use scripts/run_exact_cargo_test.sh or scripts/run_filtered_cargo_test.sh",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print(
        f"direct cargo filter check passed: scanned={scanned} workflows={len(names)} "
        "zero-match-risk=0"
    )


def _selftest() -> None:
    """Host-local unit checks (no cargo)."""
    assert _cargo_test_is_safe("cargo test -p dcentrald-asic --lib")
    assert _cargo_test_is_safe("cargo test -p dcentrald --test wave48_dspic_25_bare_path")
    assert _cargo_test_is_safe(
        "sh ../scripts/run_filtered_cargo_test.sh -p dcentrald-hal --lib -- am2_"
    )
    assert not _cargo_test_is_safe("cargo test -p dcentrald-hal --lib am2_")
    assert not _cargo_test_is_safe(
        "cargo test -p dcentrald --bin dcentrald runtime::safety_watchdog::tests"
    )
    assert is_safe_cargo_test(
        "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- runtime::thread_guard::tests"
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
        print("check_direct_cargo_filters selftest passed")
        raise SystemExit(0)
    main()
