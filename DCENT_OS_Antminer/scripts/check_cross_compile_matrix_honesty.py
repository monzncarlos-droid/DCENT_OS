#!/usr/bin/env python3
"""Static honesty gate for cross-compile-matrix evidence claims.

The matrix's per-target cells run ``cargo check``. That proves target
configuration and type checking under cell RUSTFLAGS — not target-crate
LLVM object codegen, linking, Cortex-A8-specific object lowering,
AArch64 object emission, or release-binary shape.

Continuous-audit residual (2026-07-22 review §P1 cross-target workflow;
closed 2026-07-29 by relabel + this pin): either claims stay cfg/type-check
or real per-cell release builds must be added. This gate fails closed if
the workflow re-claims codegen/link assurance for cargo-check-only cells.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "cross-compile-matrix.yml"
)

# Phrases that must appear so the evidence boundary cannot silently drop.
# Keep each phrase on a single line in the workflow header/comments.
REQUIRED_PHRASES = (
    "cfg/type-check",
    "cargo check",
    "LLVM object codegen",
    "workspace-test-compile-gate",
    "generic armv7-musl only",
    "test-profile link evidence",
    "release builds",
    "HONEST EVIDENCE BOUNDARY",
    # 2026-07-29: release-object smoke closes the "no release proof in matrix" gap
    # without overclaiming full per-cell release builds.
    "armv7-release-object-smoke",
    "release-object smoke",
    "target-release-smoke-armv7",
    # 2026-07-29: AArch64 sibling smoke (Amlogic-class triple), still scoped.
    "aarch64-release-object-smoke",
    "target-release-smoke-aarch64",
)

# Overclaims that describe cargo-check cells as if they emitted/linked
# target objects. Negated / meta lines are filtered in check_forbidden_overclaims.
FORBIDDEN_OVERCLAIM_PATTERNS = (
    re.compile(r"(?i)\bcodegen assurance\b"),
    re.compile(
        r"(?i)verify(?:s|ing)? the (?:A8-specific |Cortex-A8.?specific )?"
        r"codegen path"
    ),
    re.compile(r"(?i)Generic ARMv7 codegen\."),
    re.compile(r"(?i)Cortex-A8 single-issue codegen\s*[—-]"),
    re.compile(r"(?i)Cortex-A53 codegen for Amlogic"),
    re.compile(r"(?i)proves? (?:the )?SV2 client crate cross-compiles"),
)

# Honest / meta wording that discusses the forbidden phrase without claiming it.
_NEGATION_MARKERS = (
    "not prove",
    "does not",
    "do not",
    "does **not**",
    "not a",
    "not cortex",
    "only —",
    "only -",
    "cfg/type-check only",
    "type-check only",
    "without adding",  # "Do not relabel ... without adding real builds"
    "do not relabel",
    "not that it links",
    "no object link claim",
    "no object",
    "not release",
    "not a release",
    "evidence class:",
    "honest evidence boundary",
)

# cargo-check cells must not run cargo build --release without also
# changing the honesty gate's required phrases (intentionally strict).
FORBIDDEN_CHECK_CELL_COMMANDS = (
    re.compile(r"(?m)^\s*cargo\s+(?:\+\S+\s+)?build\b"),
    re.compile(r"(?m)^\s*cargo\s+(?:\+\S+\s+)?test\b(?![^\n]*--no-run)"),
)


def load_workflow(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SystemExit(
            f"missing required workflow: {path}"
        ) from exc


def split_jobs(text: str) -> dict[str, str]:
    """Return top-level job bodies keyed by job id (best-effort YAML slice)."""
    jobs: dict[str, str] = {}
    # Match `  job_id:` under jobs:
    matches = list(re.finditer(r"(?m)^  ([a-zA-Z0-9_-]+):\s*$", text))
    # Only consider jobs after the `jobs:` key.
    jobs_key = re.search(r"(?m)^jobs:\s*$", text)
    if not jobs_key:
        return jobs
    start_idx = jobs_key.end()
    relevant = [m for m in matches if m.start() >= start_idx]
    for i, match in enumerate(relevant):
        job_id = match.group(1)
        body_start = match.end()
        body_end = relevant[i + 1].start() if i + 1 < len(relevant) else len(text)
        jobs[job_id] = text[body_start:body_end]
    return jobs


def check_required_phrases(text: str, failures: list[str]) -> None:
    for phrase in REQUIRED_PHRASES:
        if phrase not in text:
            failures.append(f"missing required honesty phrase: {phrase!r}")


def check_forbidden_overclaims(text: str, failures: list[str]) -> None:
    for pattern in FORBIDDEN_OVERCLAIM_PATTERNS:
        for match in pattern.finditer(text):
            # Allow lines that explicitly negate or meta-discuss the claim.
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            line = text[line_start:line_end]
            lowered = line.lower()
            if any(marker in lowered for marker in _NEGATION_MARKERS):
                continue
            # Also allow when the match itself is inside a quoted forbid instruction.
            if '"' in line and "codegen assurance" in lowered:
                continue
            failures.append(
                f"forbidden overclaim {pattern.pattern!r} near: {line.strip()[:120]}"
            )


def check_cross_check_job(jobs: dict[str, str], failures: list[str]) -> None:
    body = jobs.get("cross-check")
    if body is None:
        failures.append("missing job 'cross-check'")
        return
    if "cargo check" not in body:
        failures.append("cross-check job must invoke cargo check")
    if "cfg/type-check" not in body and "cfg/type-check" not in body.lower():
        # job name is outside body; parent text is checked separately.
        pass
    for pattern in FORBIDDEN_CHECK_CELL_COMMANDS:
        if pattern.search(body):
            failures.append(
                "cross-check job must not run cargo build/test "
                f"(found {pattern.pattern}); keep cells as cargo check "
                "or update honesty gate for real release builds"
            )
    # Must not claim codegen for the three production profiles without builds.
    for bad in (
        "Generic ARMv7 codegen",
        "Cortex-A8 single-issue codegen",
        "Cortex-A53 codegen for Amlogic",
        "verify the A8-specific codegen path",
        "verify the same codegen path",
    ):
        if bad in body or bad in body.replace("—", "-"):
            failures.append(f"cross-check job still claims {bad!r}")


def check_test_compile_job(jobs: dict[str, str], failures: list[str]) -> None:
    body = jobs.get("workspace-test-compile-gate")
    if body is None:
        failures.append("missing job 'workspace-test-compile-gate'")
        return
    if "run_dcentrald_tests.sh" not in body and "cargo test" not in body:
        failures.append(
            "workspace-test-compile-gate must run the test compile path"
        )
    # Job name is on the job line before body; parent text checked for boundary.
    if "armv7-unknown-linux-musleabihf" not in body and "armv7" not in body:
        failures.append(
            "workspace-test-compile-gate must target armv7 musl"
        )


# cargo build --release --workspace (any arg order) inflates smoke → full fleet.
_SMOKE_WORKSPACE_BUILD = re.compile(
    r"(?im)^\s*cargo\s+(?:\+\S+\s+)?build\b[^\n]*--workspace\b"
    r"|^\s*cargo\s+(?:\+\S+\s+)?build\b[^\n]*--release\b[^\n]*--workspace\b"
)
# Cortex-tuned RUSTFLAGS on a "generic only" smoke re-blurs evidence classes.
_SMOKE_CORTEX_CPU = re.compile(
    r"(?i)target-cpu\s*=\s*cortex-a(?:8|53)\b"
)
_SMOKE_CORTEX_NEGATION = (
    "not cortex",
    "generic only",
    "generic armv7",
    "generic aarch64",
    "not a cortex",
    "no cortex",
    "without cortex",
    "not cortex-tuned",
)


def _check_scoped_release_smoke(
    jobs: dict[str, str],
    failures: list[str],
    *,
    job_id: str,
    target_triple: str,
    target_dir_token: str,
) -> None:
    """Shared rules for armv7/aarch64 release-object smoke jobs.

    Scope pins (G8 critic R1 harden):
    - Exact distinct target-dir token required (not bare CARGO_TARGET_DIR alone).
    - cargo build --release --workspace is forbidden (scoped package set only).
    - target-cpu=cortex-a8/a53 without generic/not-cortex negation is forbidden.
    """
    body = jobs.get(job_id)
    if body is None:
        failures.append(f"missing job {job_id!r}")
        return
    if "cargo" not in body or "--release" not in body or "build" not in body:
        failures.append(f"{job_id} must run cargo build --release")
    # Exact token required — bare CARGO_TARGET_DIR: shared-target must FAIL.
    if target_dir_token not in body:
        failures.append(
            f"{job_id} must use distinct CARGO_TARGET_DIR token "
            f"{target_dir_token!r} (shared or missing target dir is fail-closed)"
        )
    if target_triple not in body:
        failures.append(f"{job_id} must target {target_triple}")
    if "dcentos-init" not in body:
        failures.append(
            f"{job_id} must build -p dcentos-init "
            "(PID1 brick-risk release proof)"
        )
    if "dcentrald-common" not in body:
        failures.append(
            f"{job_id} must build -p dcentrald-common "
            "(pure composition/policy release proof)"
        )
    if "dcentrald-api-types" not in body:
        failures.append(
            f"{job_id} must build -p dcentrald-api-types "
            "(API contract types release proof; 2026-07-29 expand)"
        )
    # Ban full-workspace release builds inside smoke jobs.
    if _SMOKE_WORKSPACE_BUILD.search(body):
        failures.append(
            f"{job_id} must not run cargo build --workspace "
            "(scoped release-object smoke only; full-workspace release is "
            "a different evidence class)"
        )
    # Ban Cortex-tuned RUSTFLAGS without explicit generic/not-cortex framing.
    for match in _SMOKE_CORTEX_CPU.finditer(body):
        line_start = body.rfind("\n", 0, match.start()) + 1
        line_end = body.find("\n", match.end())
        if line_end < 0:
            line_end = len(body)
        line = body[line_start:line_end]
        lowered = line.lower()
        if any(marker in lowered for marker in _SMOKE_CORTEX_NEGATION):
            continue
        # Also allow if surrounding job body already states generic-only and
        # the match is inside a negation comment on the same line.
        if "not" in lowered and "cortex" in lowered:
            continue
        failures.append(
            f"{job_id} must not set Cortex-tuned target-cpu on smoke "
            f"(found {match.group(0)!r}); keep generic musl only"
        )
    for bad in (
        "Cortex-A8 release",
        "AArch64 release-object for all cells",
        "full matrix release",
        "Cortex-A53 release for all cells",
        "full-workspace release",
        "full workspace release",
    ):
        if bad in body or bad.lower() in body.lower():
            # Allow meta/negation lines that discuss the forbidden claim.
            for line in body.splitlines():
                if bad.lower() not in line.lower():
                    continue
                lowered = line.lower()
                if any(
                    m in lowered
                    for m in (
                        "not",
                        "not a",
                        "only —",
                        "only -",
                        "scoped",
                        "without",
                        "do not",
                        "does not",
                    )
                ):
                    continue
                failures.append(f"{job_id} overclaims scope: {bad!r}")
                break


def check_release_smoke_job(jobs: dict[str, str], failures: list[str]) -> None:
    """armv7 + aarch64 release-object-smoke: real cargo build --release."""
    _check_scoped_release_smoke(
        jobs,
        failures,
        job_id="armv7-release-object-smoke",
        target_triple="armv7-unknown-linux-musleabihf",
        target_dir_token="target-release-smoke-armv7",
    )
    _check_scoped_release_smoke(
        jobs,
        failures,
        job_id="aarch64-release-object-smoke",
        target_triple="aarch64-unknown-linux-musl",
        target_dir_token="target-release-smoke-aarch64",
    )


def check_workflow(text: str) -> list[str]:
    failures: list[str] = []
    check_required_phrases(text, failures)
    check_forbidden_overclaims(text, failures)
    jobs = split_jobs(text)
    if "cross-check" not in jobs:
        failures.append("workflow missing jobs.cross-check")
    if "workspace-test-compile-gate" not in jobs:
        failures.append("workflow missing jobs.workspace-test-compile-gate")
    if "armv7-release-object-smoke" not in jobs:
        failures.append("workflow missing jobs.armv7-release-object-smoke")
    if "aarch64-release-object-smoke" not in jobs:
        failures.append("workflow missing jobs.aarch64-release-object-smoke")
    check_cross_check_job(jobs, failures)
    check_test_compile_job(jobs, failures)
    check_release_smoke_job(jobs, failures)
    # Job display name honesty (on the job line, not in body slice).
    if not re.search(
        r"(?m)^  cross-check:\s*\n(?:.*\n)*?    name:.*cfg/type-check",
        text,
    ):
        failures.append(
            "cross-check job name must include 'cfg/type-check' "
            "(honest cargo check evidence class)"
        )
    if not re.search(
        r"(?m)^  workspace-test-compile-gate:\s*\n(?:.*\n)*?    name:.*"
        r"generic armv7-musl only",
        text,
    ):
        failures.append(
            "workspace-test-compile-gate job name must state "
            "'generic armv7-musl only'"
        )
    if not re.search(
        r"(?m)^  armv7-release-object-smoke:\s*\n(?:.*\n)*?    name:.*"
        r"release-object smoke",
        text,
    ):
        failures.append(
            "armv7-release-object-smoke job name must include "
            "'release-object smoke'"
        )
    if not re.search(
        r"(?m)^  armv7-release-object-smoke:\s*\n(?:.*\n)*?    name:.*"
        r"generic armv7-musl only",
        text,
    ):
        failures.append(
            "armv7-release-object-smoke job name must state "
            "'generic armv7-musl only'"
        )
    if not re.search(
        r"(?m)^  aarch64-release-object-smoke:\s*\n(?:.*\n)*?    name:.*"
        r"release-object smoke",
        text,
    ):
        failures.append(
            "aarch64-release-object-smoke job name must include "
            "'release-object smoke'"
        )
    if not re.search(
        r"(?m)^  aarch64-release-object-smoke:\s*\n(?:.*\n)*?    name:.*"
        r"generic aarch64-musl only",
        text,
    ):
        failures.append(
            "aarch64-release-object-smoke job name must state "
            "'generic aarch64-musl only'"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    path = Path(args[0]) if args else DEFAULT_WORKFLOW
    text = load_workflow(path)
    failures = check_workflow(text)
    if failures:
        print("check_cross_compile_matrix_honesty: FAIL", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("check_cross_compile_matrix_honesty: PASS")
    print(f"  workflow={path}")
    print("  evidence_class=cfg/type-check (cargo check cells)")
    print(
        "  link_adjacent=workspace-test-compile-gate "
        "(generic armv7-musl test-profile only)"
    )
    print(
        "  release_adjacent=armv7-release-object-smoke "
        "(generic armv7-musl release-object smoke only)"
    )
    print(
        "  release_adjacent=aarch64-release-object-smoke "
        "(generic aarch64-musl release-object smoke only)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
