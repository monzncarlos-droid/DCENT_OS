#!/usr/bin/env python3
"""Classify and pin safety-relevant Rust clamp() call sites.

This is intentionally a classification gate, not a blanket ban on clamp().
Only thermal, voltage, frequency, and fan/PWM/duty contexts are load-bearing
for the min>max panic class tracked by the production-readiness plan. Cosmetic
or protocol clamps are left out of this manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


EXPECTED_SAFETY_CLAMP_COUNT = 93
# G30: BM1368 ramp clamp site content/line drift after pure plan thin-wrap;
# classified count unchanged (91). Digest re-pin only.
# G42: BM1391 open-coded freq/25 clamp removed; pure-pin ban string replaces site.
# G43 (2026-08-03, hardware-enablement rank 44): 91 -> 92. ONE new classified
# clamp, `bm1485.rs:605` `target_mhz.clamp(100, 700)`, bounding the PLL divider
# SEARCH target in the new BM1485 (Antminer L3/L3+) Scaffold driver. It is a
# frequency clamp by pattern; it is NOT a live safety clamp — the driver's
# `init_chain`/`set_frequency`/`set_voltage`/`send_work` all return `Err` and it
# cannot energize. Bounds come from `bm1485.md:176-183`, not from a guess.
# Deliberately re-pinned rather than exempted: the manifest classifies by
# pattern, not by reachability, and carving out "unreachable" clamps would make
# the count depend on a judgement this gate cannot verify.
# G44 (2026-08-04, CI clippy-green pass): 92 -> 93. NO new clamp was introduced.
# `serial_mining.rs` already bounded the AM2 BM1362 PIC-heartbeat failure budget
# with `.max(1).min(AM2_BM1362_PIC_HEARTBEAT_MAX_FAILURES)`; clippy::manual_clamp
# flagged it and it was rewritten as `.clamp(1, ..)`, which is equivalent for this
# integer expression. The manifest matches on `.clamp(`, so the effect was to make
# an ALREADY-PRESENT bound VISIBLE to this gate for the first time — coverage went
# up, behaviour did not change. Re-pinned rather than exempted, for the same reason
# as G43: the manifest classifies by pattern, and hand-carving exceptions would put
# the count at the mercy of a judgement it cannot check.
EXPECTED_SAFETY_CLAMP_DIGEST = "b6e29dd913f79eb6fc0f20d8a7549af2544436098bb674743b6ec72b330c48d8"

CLAMP_RE = re.compile(r"\.clamp\s*\(")
COMMENT_PREFIXES = ("//", "///", "//!","/*", "*")

SKIP_CONTEXT_TOKENS = (
    "target_diff",
    "difficulty",
    "donation",
    "version_mask",
    "extranonce",
    "template_refresh_interval_s",
    "heat_reuse_credit",
    "wall_watts.round",
    "state_topic",
)

CATEGORY_TOKENS = (
    ("voltage", ("voltage", "volt", "_mv", " mv", "dac")),
    ("frequency", ("frequency", "freq", "_mhz", "mhz", "pll")),
    ("fan_pwm", ("fan", "pwm", "duty")),
    ("thermal", ("thermal", "temp", "pid", "gain")),
)


@dataclass(frozen=True)
class ClampSite:
    category: str
    path: str
    line: int
    statement: str

    def fingerprint(self) -> str:
        return f"{self.category}|{self.path}|{self.statement}"


def repo_root(script_path: Path) -> Path:
    return script_path.resolve().parents[1]


def normalize_statement(lines: list[str], start: int) -> str:
    chunk: list[str] = []
    for line in lines[start : min(len(lines), start + 10)]:
        stripped = line.strip()
        if stripped:
            chunk.append(stripped)
        if ";" in stripped or stripped.endswith(")") or stripped.endswith(");"):
            break
    return " ".join(" ".join(chunk).split())


def classify(path: str, context: str) -> str | None:
    lowered = context.lower()
    if any(token in lowered for token in SKIP_CONTEXT_TOKENS):
        return None
    for category, tokens in CATEGORY_TOKENS:
        if any(token in lowered for token in tokens):
            return category
    return None


def iter_rust_sources(dcentrald_root: Path) -> Iterator[Path]:
    """Yield immediate Cargo packages' production Rust sources deterministically.

    The workspace keeps packages one directory below ``dcentrald_root``. Using
    each package manifest as the source boundary avoids Cargo output, examples,
    integration tests, fuzz targets, and scratch trees without reserving names
    that remain valid below ``src/`` (for example ``src/target/mod.rs``).
    """
    for manifest in sorted(dcentrald_root.glob("*/Cargo.toml")):
        source_root = manifest.parent / "src"
        if source_root.is_dir():
            yield from sorted(source_root.rglob("*.rs"))


def collect_sites(project_root: Path) -> list[ClampSite]:
    dcentrald_root = project_root / "dcentrald"
    sites: list[ClampSite] = []

    for source in iter_rust_sources(dcentrald_root):
        rel = source.relative_to(project_root).as_posix()
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not CLAMP_RE.search(line) or stripped.startswith(COMMENT_PREFIXES):
                continue
            context_start = max(0, index - 3)
            context_end = min(len(lines), index + 4)
            context = "\n".join(lines[context_start:context_end])
            category = classify(rel, context)
            if category is None:
                continue
            sites.append(
                ClampSite(
                    category=category,
                    path=rel,
                    line=index + 1,
                    statement=normalize_statement(lines, index),
                )
            )
    return sites


def digest_sites(sites: list[ClampSite]) -> str:
    payload = "\n".join(site.fingerprint() for site in sorted(sites, key=ClampSite.fingerprint))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def print_sites(sites: list[ClampSite]) -> None:
    for site in sorted(sites, key=ClampSite.fingerprint):
        line = f"{site.category:9} {site.path}:{site.line}: {site.statement}"
        encoding = sys.stdout.encoding or "utf-8"
        print(line.encode(encoding, errors="replace").decode(encoding))


def verify(sites: list[ClampSite], *, quiet: bool = False) -> bool:
    digest = digest_sites(sites)
    if len(sites) == EXPECTED_SAFETY_CLAMP_COUNT and digest == EXPECTED_SAFETY_CLAMP_DIGEST:
        return True

    if quiet:
        return False

    print(
        "SAFETY_CLAMP_MANIFEST_MISMATCH "
        f"count={len(sites)} expected={EXPECTED_SAFETY_CLAMP_COUNT} "
        f"digest={digest} expected_digest={EXPECTED_SAFETY_CLAMP_DIGEST}",
        file=sys.stderr,
    )
    print_sites(sites)
    return False


def source_discovery_self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="dcentos-safety-clamp-") as temp_dir:
        root = Path(temp_dir) / "dcentrald"
        manifest = root / "crate" / "Cargo.toml"
        source = root / "crate" / "src" / "kept.rs"
        legitimate_target_module = root / "crate" / "src" / "target" / "legitimate.rs"
        generated = root / "crate" / "target" / "debug" / "generated.rs"
        root_generated = root / "target" / "release" / "generated.rs"
        integration_test = root / "crate" / "tests" / "integration.rs"
        scratch_source = root / "scratch" / "src" / "unowned.rs"
        for path in (
            source,
            legitimate_target_module,
            generated,
            root_generated,
            integration_test,
            scratch_source,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("let pwm = value.clamp(0, 100);\n", encoding="utf-8")
        manifest.write_text("[package]\nname = 'fixture'\n", encoding="utf-8")

        discovered = [
            path.relative_to(root).as_posix() for path in iter_rust_sources(root)
        ]
        if discovered != ["crate/src/kept.rs", "crate/src/target/legitimate.rs"]:
            print(
                "SAFETY_CLAMP_SELFTEST_FAILED source discovery included build output: "
                f"{discovered}",
                file=sys.stderr,
            )
            return False
    return True


def self_test(sites: list[ClampSite]) -> bool:
    if not source_discovery_self_test():
        return False
    if verify(sites, quiet=True):
        synthetic = sites + [
            ClampSite(
                category="fan_pwm",
                path="dcentrald/src/synthetic_unclassified.rs",
                line=1,
                statement="let pwm = requested_pwm.clamp(min_pwm, max_pwm);",
            )
        ]
        if verify(synthetic, quiet=True):
            print(
                "SAFETY_CLAMP_SELFTEST_FAILED synthetic unclassified fan/PWM clamp passed",
                file=sys.stderr,
            )
            return False
        print("SAFETY_CLAMP_SELFTEST_OK")
        return True

    # Do NOT return bare False here. `verify(quiet=True)` prints nothing, so a
    # bare return produced a red gate with ZERO output: the CI line says
    # "classified clamp set drifted OR negative control failed" and the operator
    # could not tell which. It is always the FORMER — the negative control below
    # is only reached when verify() passes, so a silent failure can never be it.
    # (2026-08-03: this cost a full investigation to rediscover.)
    print(
        "SAFETY_CLAMP_SELFTEST_FAILED classified clamp set drifted: "
        f"count={len(sites)} expected={EXPECTED_SAFETY_CLAMP_COUNT} "
        f"digest={digest_sites(sites)} "
        f"expected_digest={EXPECTED_SAFETY_CLAMP_DIGEST} "
        "(negative control NOT reached). "
        "Re-run without --self-test to list every classified site.",
        file=sys.stderr,
    )
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-current", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    project_root = repo_root(Path(__file__))
    sites = collect_sites(project_root)
    if args.print_current:
        print(f"count={len(sites)}")
        print(f"digest={digest_sites(sites)}")
        print_sites(sites)
        return 0
    if args.self_test:
        return 0 if self_test(sites) else 1
    return 0 if verify(sites) else 1


if __name__ == "__main__":
    raise SystemExit(main())
