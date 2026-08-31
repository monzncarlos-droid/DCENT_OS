"""Dynamic K210 unlock workflow orchestrator (host-only).

Reads the K210 gauntlet state plus the persisted lane-completion ledger and
emits the next expert-agent wave: which desk lanes are READY to dispatch,
which are BLOCKED on other lanes, and which operator nodes are AWAITING the
operator's hands. Desk lanes are executed by expert agents; operator nodes
pause the workflow until the coordinator records an operator confirmation.

This tool has no network, serial, USB, GPIO, flash, programmer, JTAG, ISP, or
miner-contact code, and it never mutates gauntlet gates or receipts. A lane
marked complete here is bookkeeping for dispatch, not gate qualification.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
GAUNTLET_SCRIPT = Path(__file__).resolve().parent / "k210_gauntlet.py"
STATE_PATH = Path(__file__).resolve().parents[1] / "gauntlet" / "unlock_state.json"
WAVE_MD = Path(__file__).resolve().parents[1] / "gauntlet" / "K210_UNLOCK_WAVE.md"
WAVE_JSON = Path(__file__).resolve().parents[1] / "gauntlet" / "K210_UNLOCK_WAVE.json"

DESK = "desk"
OPERATOR = "operator"
MAX_STATE_BYTES = 1024 * 1024
MAX_OPERATOR_EVIDENCE_BYTES = 1024 * 1024
LOCK_WAIT_SECONDS = 10.0
OPERATOR_VALIDATOR_CEREMONY = "trust_anchor_ceremony_v1"
OPERATOR_VALIDATOR_GAUNTLET = "gauntlet_gate_v1"
OPERATOR_VALIDATOR_FIXTURE = "fixture_receipt_v1"
OPERATOR_VALIDATOR_CAPTURE = "capture_receipt_v1"
OPERATOR_VALIDATOR_UNIMPLEMENTED = "not_implemented"

SEMANTIC_DESK_LANES = frozenset(
    {
        "w2-codec",
        "w2-firmware",
        "w2-safety",
        "w3-executor",
        "w3-validation",
        "w3-rollback",
    }
)

# Report-only lanes previously advanced on Path.is_file() or a few marker
# strings. These contracts require substantial structured content plus the
# mission's load-bearing claims. They intentionally tolerate reviewed edits to
# shared plans/runbooks while rejecting empty, tiny, or padded generic files.
DESK_REPORT_CONTRACTS: Dict[
    str, Tuple[Tuple[str, int, int, Tuple[str, ...], str], ...]
] = {
    "d0-census": (
        (
            "",
            20_000,
            8,
            ("P1", "P2", "P3", "P4", "capture-required", "A3200"),
            "14bcdceb0ecb02d678f154b2b48caf748233fcce2530ed33f77aa29a01357931",
        ),
    ),
    "d0-soc": (
        (
            "",
            25_000,
            10,
            ("OTP", "AES", "ROM ISP", "JTAG", "measurement"),
            "2d075ec188ac4064cc27de2d4846162fccc60f6756d4ac2108909e9ee7ce2e4a",
        ),
    ),
    "d0-crossera": (
        (
            "",
            12_000,
            6,
            ("224", "A1246", "A1246N", "ciphertext", "SHA-256"),
            "da24801cde4288e6aff502f13f4841d18614bcaf77f066084d664a5a72a28dcf",
        ),
    ),
    "d0-runbooks": (
        (
            "DCENT_OS_AvalonMiner/gauntlet/K210_TRUST_ANCHOR_CEREMONY.md",
            8_000,
            6,
            ("24", "SSHSIG", "namespace", "trust anchor", "not authorize"),
            "3256d320a2f8ce75cf586e1c4fb46a32aa12607fd31625a6538fcbe53102e57a",
        ),
        (
            "DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md",
            18_000,
            10,
            ("NO-GO", "A1246", "de-energized", "STOP", "4028"),
            "507559e98d50ac7bc6daff8eda46274e076d923b495204a9e2b025373c6c4e91",
        ),
    ),
    "d0-bspplan": (
        (
            "DCENT_OS_AvalonMiner/k210-firmware/docs/BSP_PLAN.md",
            20_000,
            12,
            ("SYSCTL", "UARTHS", "FPIOA", "CLINT", "WDT0", "safe idle"),
            "ac49981d65d680dc71f22133de0783c377aed2c789d88675f8643754fef0319e",
        ),
    ),
    "w1-renode": (
        (
            "DCENT_OS_AvalonMiner/k210-firmware/docs/RENODE_FEASIBILITY.md",
            14_000,
            8,
            ("HOST-ONLY", "Renode", "Kendryte K210", "UNSUPPORTED", "NO-GO"),
            "1fa062d652780bc18224007cc43ae550e289e707f098b48057949b3a300ef2a0",
        ),
    ),
    "w1-fixtureplan": (
        (
            "DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIXTURE_QUALIFICATION.md",
            7_000,
            8,
            (
                "NO-GO",
                "independent_cutoff_ready",
                "passive_capture_fixture_ready",
                "back-power",
                "STOP",
            ),
            "30043fd7c7dec8716fad1b9e61bd218e5933b42095f30249f3198dad8d15c070",
        ),
    ),
}


class WorkflowError(Exception):
    pass


@dataclass(frozen=True)
class Lane:
    lane_id: str
    title: str
    expert: str
    kind: str  # desk | operator
    depends_on: Tuple[str, ...] = ()
    runbook: str = ""  # required for operator lanes
    verify: Tuple[str, ...] = ()  # commands run before a desk lane may complete
    mission: str = ""
    owns: Tuple[str, ...] = ()  # file/dir globs the lane may write (dispatch metadata)
    target_gate: str = ""  # gauntlet gate this lane feeds, "" if none
    operator_validator: str = ""  # explicit semantic admission for operator lanes


def _l(*args, **kwargs) -> Lane:
    return Lane(*args, **kwargs)


# Canonical lane registry. `depends_on` may reference any lane id, desk or
# operator. The TERMINAL lane is the unlock itself: it completes only when
# every other lane has completed, mirroring the gauntlet's own requirement
# that every gate qualify before install authority exists.
REGISTRY: Tuple[Lane, ...] = (
    # ---- completed desk lanes (2026-08-23 unblock wave 0) ----
    _l(
        "d0-ingest",
        "A1246/A1246N stock AUPs ingested as held profiles",
        "DCENT_RE",
        DESK,
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_gauntlet.py -q",
        ),
        target_gate="stock_restore",
    ),
    _l(
        "d0-census",
        "Wire-contract asset census (no admissible contract; P1-P4 paths)",
        "DCENT_RE",
        DESK,
        depends_on=(),
        target_gate="asic_control",
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('').is_file()\"",
        ),
    ),
    _l(
        "d0-soc",
        "K210 SoC boot/flash/ISP desk contract + measurement table",
        "DCENT_CE",
        DESK,
        target_gate="boot_policy",
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('').is_file()\"",
        ),
    ),
    _l(
        "d0-crossera",
        "AUP cross-era analysis (224-byte prefix spans A12-A15)",
        "DCENT_RE",
        DESK,
        depends_on=("d0-ingest",),
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('').is_file()\"",
        ),
    ),
    _l(
        "d0-registry",
        "Toolbox 12-profile fail-closed AUP registry",
        "DCENT_SE",
        DESK,
        depends_on=("d0-ingest",),
        verify=(
            "py -3 -m pytest projects/dcent-toolbox/tests/test_avalon_industrial_package.py projects/dcent-toolbox/tests/test_avalon_industrial_package_registry.py -q",
        ),
    ),
    _l(
        "d0-rail",
        "Toolbox K210 evidence-gap install routes",
        "DCENT_SE",
        DESK,
        verify=(
            "py -3 -m pytest projects/dcent-toolbox/tests/test_dcentos_install_target_state.py projects/dcent-toolbox/tests/test_avalon_k210_install_route.py -q",
        ),
    ),
    _l(
        "d0-runbooks",
        "Trust-anchor ceremony + A1246 first-contact runbooks",
        "DCENT_QA",
        DESK,
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('DCENT_OS_AvalonMiner/gauntlet/K210_TRUST_ANCHOR_CEREMONY.md').is_file() and Path('DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md').is_file()\"",
        ),
    ),
    _l(
        "d0-bspplan",
        "K210 no_std BSP plan (driver inventory, profile schema)",
        "DCENT_CE",
        DESK,
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('DCENT_OS_AvalonMiner/k210-firmware/docs/BSP_PLAN.md').is_file()\"",
        ),
    ),
    # ---- wave 1 desk lanes (dispatched 2026-08-23) ----
    _l(
        "w1-bspa",
        "BSP Phase A: sealed physical runtime + separate Renode console",
        "DCENT_CE",
        DESK,
        depends_on=("d0-bspplan",),
        verify=(
            "cd DCENT_OS_AvalonMiner/k210-firmware && cargo +1.90.0 test --locked",
            "cd DCENT_OS_AvalonMiner/k210-firmware && cargo +1.90.0 build --locked --release --target riscv64gc-unknown-none-elf --features phase-a --bin dcent-k210-safe-idle-runtime",
            "cd DCENT_OS_AvalonMiner/k210-firmware && cargo +1.90.0 build --locked --release --target riscv64gc-unknown-none-elf --features renode-console --bin dcent-k210-renode-console",
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_phase_a_runtime.py -q",
        ),
        mission=(
            "Export and host-test sysctl/UARTHS/GPIOHS/FPIOA/CLINT/WDT0 facts; "
            "provide a sealed zero-MMIO dual-hart physical runtime plus a separately "
            "named Renode-only console. No board pin defaults or packageable console."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml",
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.lock",
            "DCENT_OS_AvalonMiner/k210-firmware/build.rs",
            "DCENT_OS_AvalonMiner/k210-firmware/k210-sentinel.ld",
            "DCENT_OS_AvalonMiner/k210-firmware/k210-runtime.ld",
            "DCENT_OS_AvalonMiner/k210-firmware/README.md",
            "DCENT_OS_AvalonMiner/k210-firmware/src/",
            "DCENT_OS_AvalonMiner/scripts/test_k210_phase_a_runtime.py",
        ),
        target_gate="replacement_firmware",
    ),
    _l(
        "w1-capture",
        "K210 capture ingestion (.k210cap) + codec bench skeleton",
        "DCENT_Protocol",
        DESK,
        depends_on=("d0-census",),
        mission=(
            "Parse operator Saleae exports into a canonical bounded capture artifact "
            "with channel->signal mapping, clock-recovery stats, and descriptive frame "
            "hypotheses; no wire-contract claims."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_capture_ingest.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_capture_ingest.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_CAPTURE_ARTIFACT.md",
        ),
        target_gate="asic_control",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_capture_ingest.py -q",
        ),
    ),
    _l(
        "w1-installplan",
        "Toolbox K210 install plan builder (locked until receipts admit)",
        "DCENT_SE",
        DESK,
        depends_on=(
            "d0-rail",
            "d0-registry",
        ),
        mission=(
            "Build a structured install/AUP plan generator whose every step requires "
            "admitted gauntlet receipts; with zero receipts it emits the canonical "
            "refusal enumerating missing gates."
        ),
        owns=(
            "projects/dcent-toolbox/src/dcent_toolbox/core/k210_install_plan.py",
            "projects/dcent-toolbox/tests/test_k210_install_plan.py",
        ),
        target_gate="release_authority",
        verify=(
            "py -3 -m pytest projects/dcent-toolbox/tests/test_k210_install_plan.py -q",
        ),
    ),
    _l(
        "w1-discoverytool",
        "Read-only 4028 discovery collector + recovery drill plan generator",
        "DCENT_QA",
        DESK,
        depends_on=("d0-runbooks",),
        mission=(
            "Bench-laptop collector for the first-contact runbook (allowlisted read-only "
            "4028 commands, MM3 trailing-NUL quirk, evidence-kind file layout, bundle "
            "skeleton) plus a dual-path recovery drill plan generator."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_discovery_collect.py",
            "DCENT_OS_AvalonMiner/scripts/k210_recovery_drill_plan.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_discovery_collect.py",
        ),
        target_gate="exact_model_identity",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_discovery_collect.py -q",
        ),
    ),
    _l(
        "w1-renode",
        "Renode K210 emulation feasibility spike",
        "DCENT_CE",
        DESK,
        mission=(
            "Determine whether Renode's k210 platform can host-test the BSP runtime "
            "and candidate images pre-hardware; report only."
        ),
        owns=("DCENT_OS_AvalonMiner/k210-firmware/docs/RENODE_FEASIBILITY.md",),
        target_gate="replacement_firmware",
        verify=(
            "py -3 -c \"from pathlib import Path; assert Path('DCENT_OS_AvalonMiner/k210-firmware/docs/RENODE_FEASIBILITY.md').is_file()\"",
        ),
    ),
    _l(
        "w1-identityschema",
        "Revision-bound A1246 identity + semantic discovery admission",
        "DCENT_RE",
        DESK,
        depends_on=("d0-ingest", "d0-census"),
        mission=(
            "Split the generic A1246 row into evidence-honest A3200LC/A3201/X2/X3 "
            "variants and derive receipt identity semantically from stock JSON and fully "
            "decoded canonical PNG evidence; carry the resolved profile into gauntlet "
            "restore decisions and reject placeholders, corrupt bytes, and forced labels."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/gauntlet/k210_models.json",
            "DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_a1246_variant_identity.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md",
        ),
        target_gate="exact_model_identity",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_a1246_variant_identity.py -q",
        ),
    ),
    _l(
        "w1-fixtureplan",
        "A1246 EE fixture qualification contract",
        "DCENT_EE",
        DESK,
        depends_on=("d0-soc", "d0-census"),
        mission=(
            "Define the exact-unit controller supply, 1.8V probing, flash isolation, "
            "independent cutoff, cooling custody, ESD, instrument, and stop-condition "
            "evidence required before recovery or wire capture."
        ),
        owns=("DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIXTURE_QUALIFICATION.md",),
        target_gate="thermal_power_safety",
        verify=(
            "py -3 -c \"from pathlib import Path; p=Path('DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIXTURE_QUALIFICATION.md'); t=p.read_text(encoding='utf-8'); assert 'NO-GO' in t and 'independent_cutoff_ready' in t and 'passive_capture_fixture_ready' in t\"",
        ),
    ),
    _l(
        "w1-fixturevalidator",
        "Dual-reviewed exact-unit fixture receipt validator",
        "DCENT_QA",
        DESK,
        depends_on=("w1-fixtureplan", "w1-identityschema"),
        mission=(
            "Implement canonical semantic fixture evidence, two role-separated SSHSIG "
            "reviews, manifest-pinned admission, exact discovery/unit joins, and a "
            "non-authorizing workflow claim. Do not qualify a production gate."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_fixture_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_fixture_receipt.py",
        ),
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_fixture_receipt.py -q",
        ),
    ),
    _l(
        "w1-capturevalidator",
        "Dual-reviewed source-reproducible P1 capture validator",
        "DCENT_Protocol",
        DESK,
        depends_on=("w1-capture", "w1-fixturevalidator"),
        mission=(
            "Bind exact discovery/fixture identity, physical channel maps, source CSVs, "
            "byte-reproduced .k210cap artifacts, safe-idle cutoff evidence, bounded stock "
            "work, cooling custody, and two role-separated SSHSIG reviews. Admit raw P1 "
            "evidence only; do not claim a codec or qualify asic_control."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_capture_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_capture_receipt.py",
        ),
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_capture_receipt.py -q",
        ),
    ),
    _l(
        "w1-routeengine",
        "Fail-closed four-path K210 boot-route policy engine",
        "DCENT_CE",
        DESK,
        depends_on=("d0-soc",),
        mission=(
            "Verify a manifest-pinned signed boot-policy result and deterministically "
            "rank native AES0 flash, ROM-ISP SRAM, JTAG SRAM, and clean replacement-"
            "controller engineering routes. Preserve a fixed false authority ceiling; "
            "never claim that a selected next route is install-ready."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_boot_route.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_BOOT_ROUTE_ADJUDICATION.md",
        ),
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py -q",
        ),
    ),
    # ---- operator nodes (pause the workflow; runbooks required) ----
    _l(
        "op-ceremony",
        "Operator: generate + pin every role-separated trust-anchor key",
        "Operator",
        OPERATOR,
        depends_on=("d0-runbooks",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_TRUST_ANCHOR_CEREMONY.md",
        operator_validator=OPERATOR_VALIDATOR_CEREMONY,
    ),
    _l(
        "op-discovery",
        "Operator: A1246 read-only first-contact discovery session",
        "Operator",
        OPERATOR,
        depends_on=("op-ceremony", "w1-discoverytool", "w1-identityschema"),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIRST_CONTACT_RUNBOOK.md",
        target_gate="exact_model_identity",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-fixture",
        "Operator + EE: qualify the exact A1246 recovery/capture fixture",
        "Operator",
        OPERATOR,
        depends_on=("op-discovery", "w1-fixturevalidator"),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_A1246_FIXTURE_QUALIFICATION.md",
        operator_validator=OPERATOR_VALIDATOR_FIXTURE,
    ),
    _l(
        "op-recovery",
        "Operator: dual-path stock backup/restore + interruption drill",
        "Operator",
        OPERATOR,
        depends_on=("op-discovery", "op-fixture", "d0-soc"),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_RECOVERY_RECEIPTS.md",
        target_gate="stock_restore",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-bootpolicy",
        "Operator: controller-only boot-policy measurement (fuses/ISP/JTAG/AES0 probe)",
        "Operator",
        OPERATOR,
        depends_on=("op-recovery",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_BOOT_POLICY_RECEIPTS.md",
        target_gate="boot_policy",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-capture",
        "Operator: authorized passive wire-contract capture campaign (P1; P3 fixture optional)",
        "Operator",
        OPERATOR,
        depends_on=("op-discovery", "op-fixture", "w1-capturevalidator"),
        runbook="",
        operator_validator=OPERATOR_VALIDATOR_CAPTURE,
    ),
    # ---- wave 2+ desk lanes (unlocked by operator evidence) ----
    _l(
        "w2-codec",
        "K210 ASIC codec from admitted captures (clean-room, per-revision)",
        "DCENT_Protocol",
        DESK,
        depends_on=("op-capture",),
        mission=(
            "Derive the controller<->ASIC codec from admitted capture artifacts only; "
            "admission-gated encoders, hardware-validated decoders, per-revision scope."
        ),
        owns=("shared/dcent-avalon-proto/",),
        target_gate="asic_control",
        verify=(
            "cd shared/dcent-avalon-proto && cargo +1.90.0 test --locked "
            "--test k210_codec_admission",
        ),
    ),
    _l(
        "w2-route",
        "Measured boot-route adjudication across all replacement paths",
        "DCENT_CE",
        DESK,
        depends_on=("w1-routeengine", "op-bootpolicy", "op-discovery", "op-fixture"),
        mission=(
            "Adjudicate normal AES0 flash, ROM-ISP SRAM bootstrap, JTAG SRAM bootstrap, "
            "and a clean replacement-controller path from exact-unit evidence. Record "
            "positive, negative, and not-applicable outcomes without treating one failed "
            "K210 boot path as the end of the A1246 enablement objective."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_boot_route.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py",
            "DCENT_OS_AvalonMiner/scripts/k210_route_replacement_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_route_replacement_receipt.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_BOOT_ROUTE_ADJUDICATION.md",
            "DCENT_OS_AvalonMiner/gauntlet/K210_ROUTE_REPLACEMENT_RECEIPTS.md",
        ),
        target_gate="replacement_firmware",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_boot_route.py -q",
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_route_replacement_receipt.py -q",
        ),
    ),
    _l(
        "w2-firmware",
        "Selected target-bound DCENT runtime (measured route + BSP profile)",
        "DCENT_CE",
        DESK,
        depends_on=("w1-bspa", "w2-route", "op-discovery"),
        mission=(
            "Implement the evidence-selected native-flash, SRAM-bootstrap, or replacement-"
            "controller runtime; bind the BSP to the discovered board and produce the "
            "reproducible reviewed artifact required by that route."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml",
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.lock",
            "DCENT_OS_AvalonMiner/k210-firmware/build.rs",
            "DCENT_OS_AvalonMiner/k210-firmware/k210-sentinel.ld",
            "DCENT_OS_AvalonMiner/k210-firmware/README.md",
            "DCENT_OS_AvalonMiner/k210-firmware/src/",
        ),
        target_gate="replacement_firmware",
        verify=(
            "cd DCENT_OS_AvalonMiner/k210-firmware && cargo +1.90.0 test "
            "--locked --test k210_target_bound_runtime",
        ),
    ),
    _l(
        "op-replacement",
        "Builder + reviewer: admit the exact replacement artifact",
        "Operator",
        OPERATOR,
        depends_on=("w2-firmware", "w2-route", "op-bootpolicy", "op-capture"),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_ROUTE_REPLACEMENT_RECEIPTS.md",
        target_gate="replacement_firmware",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "w2-safety",
        "Thermal/power custody implementation (model limits, cutoff, watchdog)",
        "DCENT_Thermal",
        DESK,
        depends_on=("w2-firmware", "w2-codec"),
        mission=(
            "Implement model-bound thermal/power safety on real BSP I/O with independent "
            "hash-power cut, cooling custody, and latched faults."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.toml",
            "DCENT_OS_AvalonMiner/k210-firmware/Cargo.lock",
            "DCENT_OS_AvalonMiner/k210-firmware/build.rs",
            "DCENT_OS_AvalonMiner/k210-firmware/k210-sentinel.ld",
            "DCENT_OS_AvalonMiner/k210-firmware/README.md",
            "DCENT_OS_AvalonMiner/k210-firmware/src/",
        ),
        target_gate="thermal_power_safety",
        verify=(
            "cd DCENT_OS_AvalonMiner/k210-firmware && cargo +1.90.0 test "
            "--locked --test k210_hardware_safety",
        ),
    ),
    _l(
        "w3-executor",
        "Toolbox K210 install executor unlock under admitted replacement receipt",
        "DCENT_SE",
        DESK,
        depends_on=("w1-installplan", "w2-firmware", "op-bootpolicy", "op-replacement"),
        mission=(
            "Wire the locked plan builder into an executor that runs only against an "
            "admitted, in-scope replacement receipt with recovery-first ordering."
        ),
        owns=(
            "projects/dcent-toolbox/src/dcent_toolbox/core/k210_install_plan.py",
            "projects/dcent-toolbox/src/dcent_toolbox/core/k210_install_executor.py",
            "projects/dcent-toolbox/tests/test_k210_install_executor.py",
        ),
        target_gate="release_authority",
        verify=(
            "py -3 -m pytest projects/dcent-toolbox/tests/test_k210_install_plan.py -q",
            "py -3 -m pytest projects/dcent-toolbox/tests/test_k210_install_executor.py -q",
        ),
    ),
    _l(
        "w3-validation",
        "Signed staged first-light, bench, and endurance evidence validator",
        "DCENT_QA",
        DESK,
        depends_on=("w2-firmware", "w2-safety", "w3-executor"),
        mission=(
            "Admit immutable first-light, bounded bench-mining, and fault/endurance "
            "receipts through distinct role keys and the complete exact-unit route chain."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_bench_endurance_receipt.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_BENCH_ENDURANCE_RECEIPTS.md",
            "DCENT_OS_AvalonMiner/gauntlet/K210_FIRST_LIGHT_RECEIPTS.md",
            "DCENT_OS_AvalonMiner/gauntlet/K210_BENCH_MINING_RECEIPTS.md",
            "DCENT_OS_AvalonMiner/gauntlet/K210_ENDURANCE_FAULT_RECEIPTS.md",
            "DCENT_OS_AvalonMiner/scripts/k210_release_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_release_receipt.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_RELEASE_RECEIPTS.md",
        ),
        target_gate="bench_mining",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_bench_endurance_receipt.py -q",
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_release_receipt.py -q",
        ),
    ),
    _l(
        "w3-rollback",
        "Exact-route rollback and recovery validation harness",
        "DCENT_QA",
        DESK,
        depends_on=("w3-executor", "w2-safety", "op-recovery"),
        mission=(
            "Validate rollback for the selected flash/bootstrap/controller route, including "
            "interruption, readback, stock return, identity rejoin, and no-clobber evidence."
        ),
        owns=(
            "DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py",
            "DCENT_OS_AvalonMiner/scripts/test_k210_route_rollback_receipt.py",
            "DCENT_OS_AvalonMiner/gauntlet/K210_ROUTE_ROLLBACK_RECEIPTS.md",
        ),
        target_gate="rollback_recovery",
        verify=(
            "py -3 -m pytest DCENT_OS_AvalonMiner/scripts/test_k210_route_rollback_receipt.py -q",
        ),
    ),
    _l(
        "op-rollback",
        "Operator: witnessed exact-route rollback/recovery qualification",
        "Operator",
        OPERATOR,
        depends_on=("w3-rollback",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_ROUTE_ROLLBACK_RECEIPTS.md",
        target_gate="rollback_recovery",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-firstlight",
        "Operator + reviewers: staged first light and independent safety proof",
        "Operator",
        OPERATOR,
        depends_on=("w3-validation", "op-rollback"),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_FIRST_LIGHT_RECEIPTS.md",
        target_gate="asic_control",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-bench",
        "Operator + witness: bounded bench mining on the exact unit",
        "Operator",
        OPERATOR,
        depends_on=("op-firstlight",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_BENCH_MINING_RECEIPTS.md",
        target_gate="bench_mining",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-endurance",
        "Operator: witnessed fault-injection and endurance qualification",
        "Operator",
        OPERATOR,
        depends_on=("op-bench",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_ENDURANCE_FAULT_RECEIPTS.md",
        target_gate="endurance_faults",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-preauthorize",
        "Preauthorizer + reviewer: authorize one exact install capstone",
        "Operator",
        OPERATOR,
        depends_on=("op-endurance",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_RELEASE_RECEIPTS.md",
        target_gate="release_authority",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
    _l(
        "op-release",
        "Operator: per-model release admission + witnessed install capstone",
        "Operator",
        OPERATOR,
        depends_on=("op-preauthorize",),
        runbook="DCENT_OS_AvalonMiner/gauntlet/K210_RELEASE_RECEIPTS.md",
        target_gate="release_authority",
        operator_validator=OPERATOR_VALIDATOR_GAUNTLET,
    ),
)

# The terminal lane completes only when every other lane has completed,
# mirroring the gauntlet's own all-gates-qualified requirement.
REGISTRY = REGISTRY + (
    _l(
        "terminal",
        "DCENT_OS enabled on A1246: every gate qualified, executor unlocked",
        "Coordinator",
        "desk",
        depends_on=tuple(sorted(lane.lane_id for lane in REGISTRY)),
        mission=(
            "Terminal node. Completes only when every desk and operator lane above has "
            "completed and the gauntlet reports the exact unit production-ready."
        ),
        verify=(
            "py -3 DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py check "
            "--model a1246 --corpus required --require-production",
        ),
    ),
)


def registry_by_id(registry: Sequence[Lane]) -> Dict[str, Lane]:
    ids = [lane.lane_id for lane in registry]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise WorkflowError(f"duplicate lane ids: {', '.join(dupes)}")
    return {lane.lane_id: lane for lane in registry}


def registry_sha256(registry: Sequence[Lane]) -> str:
    """Bind wave/state presentation to the complete active lane contract."""

    validate_registry(registry)
    projection = [
        {
            "depends_on": list(lane.depends_on),
            "expert": lane.expert,
            "kind": lane.kind,
            "lane_id": lane.lane_id,
            "mission": lane.mission,
            "operator_validator": lane.operator_validator,
            "owns": list(lane.owns),
            "runbook": lane.runbook,
            "target_gate": lane.target_gate,
            "title": lane.title,
            "verify": list(lane.verify),
        }
        for lane in registry
    ]
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(
        b"DCENT-K210-WORKFLOW-REGISTRY-V1\x00" + canonical
    ).hexdigest()


def _normalize_ownership_scope(scope: str) -> Tuple[str, bool]:
    """Return a canonical repo-relative scope and whether it is a directory."""

    if not scope or "\x00" in scope:
        raise WorkflowError(f"invalid empty/NUL ownership scope {scope!r}")
    is_directory = scope.endswith(("/", "\\"))
    normalized = scope.replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    normalized = normalized.rstrip("/")
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or ":" in parts[0]
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise WorkflowError(
            f"ownership scope must be canonical repo-relative: {scope!r}"
        )
    return normalized, is_directory


def ownership_scopes_overlap(left: str, right: str) -> bool:
    """Detect exact and directory-prefix overlap between two lane scopes."""

    left_path, left_directory = _normalize_ownership_scope(left)
    right_path, right_directory = _normalize_ownership_scope(right)
    if left_path == right_path:
        return True
    if left_directory and right_path.startswith(left_path + "/"):
        return True
    if right_directory and left_path.startswith(right_path + "/"):
        return True
    return False


def validate_registry(registry: Sequence[Lane]) -> None:
    by_id = registry_by_id(registry)
    terminal = by_id.get("terminal")
    if terminal is None:
        raise WorkflowError("registry must contain the terminal lane")
    expected = tuple(sorted(i for i in by_id if i != "terminal"))
    if terminal.depends_on != expected:
        raise WorkflowError("terminal lane must depend on every other lane")
    # dependency existence + acyclicity
    visiting: List[str] = []
    done: set = set()

    def visit(lane_id: str) -> None:
        if lane_id in done:
            return
        if lane_id in visiting:
            cycle = " -> ".join(visiting + [lane_id])
            raise WorkflowError(f"dependency cycle: {cycle}")
        visiting.append(lane_id)
        for dep in by_id[lane_id].depends_on:
            if dep not in by_id:
                raise WorkflowError(f"lane {lane_id} depends on unknown lane {dep}")
            visit(dep)
        visiting.pop()
        done.add(lane_id)

    for lane_id in by_id:
        visit(lane_id)
    for lane in registry:
        if lane.kind == OPERATOR and not lane.runbook:
            raise WorkflowError(
                f"operator lane {lane.lane_id} must reference a runbook"
            )
        if lane.kind == OPERATOR and lane.operator_validator not in {
            OPERATOR_VALIDATOR_CEREMONY,
            OPERATOR_VALIDATOR_CAPTURE,
            OPERATOR_VALIDATOR_FIXTURE,
            OPERATOR_VALIDATOR_GAUNTLET,
            OPERATOR_VALIDATOR_UNIMPLEMENTED,
        }:
            raise WorkflowError(
                f"operator lane {lane.lane_id} must declare an explicit semantic validator"
            )
        if lane.kind == DESK and not lane.verify:
            raise WorkflowError(
                f"desk lane {lane.lane_id} must declare verify commands"
            )

    # ownership overlap is allowed only between lanes already ordered by the
    # dependency DAG (never concurrently dispatchable)
    def depends_transitively(
        a: str, b: str
    ) -> bool:  # a depends on b (directly or not)
        seen: set = set()
        stack = list(by_id[a].depends_on)
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur == b:
                return True
            stack.extend(by_id[cur].depends_on)
        return False

    ownable = [lane for lane in registry if lane.kind == DESK and lane.owns]
    for i, a in enumerate(ownable):
        for b in ownable[i + 1 :]:
            overlaps = [
                (left, right)
                for left in a.owns
                for right in b.owns
                if ownership_scopes_overlap(left, right)
            ]
            if overlaps:
                if not (
                    depends_transitively(a.lane_id, b.lane_id)
                    or depends_transitively(b.lane_id, a.lane_id)
                ):
                    raise WorkflowError(
                        f"lanes {a.lane_id} and {b.lane_id} declare overlapping ownership "
                        f"without a dependency ordering between them: {overlaps}"
                    )


def _validated_state(data: object) -> Dict[str, object]:
    if not isinstance(data, dict):
        raise WorkflowError("state must be a JSON object")
    unknown = sorted(set(data) - {"completed", "operator_evidence"})
    if unknown:
        raise WorkflowError(f"state has unknown fields: {unknown}")
    completed = data.get("completed")
    if not isinstance(completed, list) or any(
        not isinstance(lane_id, str) or not lane_id for lane_id in completed
    ):
        raise WorkflowError("state file 'completed' must be a list of lane ids")
    if len(completed) != len(set(completed)):
        raise WorkflowError("state file 'completed' contains duplicate lane ids")
    operator_evidence = data.get("operator_evidence", {})
    if not isinstance(operator_evidence, dict):
        raise WorkflowError("state file 'operator_evidence' must be an object")
    for lane_id, receipt in operator_evidence.items():
        if not isinstance(lane_id, str) or not isinstance(receipt, dict):
            raise WorkflowError("operator evidence entries must be lane-id objects")
        if set(receipt) != {
            "bytes",
            "claim",
            "descriptor",
            "descriptor_sha256",
            "filename",
            "sha256",
            "subject_sha256",
            "validator",
        }:
            raise WorkflowError(
                f"operator evidence for {lane_id} has an invalid field set"
            )
        if (
            isinstance(receipt["bytes"], bool)
            or not isinstance(receipt["bytes"], int)
            or not 1 <= receipt["bytes"] <= MAX_OPERATOR_EVIDENCE_BYTES
            or not isinstance(receipt["filename"], str)
            or not receipt["filename"]
            or not isinstance(receipt["sha256"], str)
            or len(receipt["sha256"]) != 64
            or any(
                character not in "0123456789abcdef" for character in receipt["sha256"]
            )
            or not isinstance(receipt["subject_sha256"], str)
            or len(receipt["subject_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in receipt["subject_sha256"]
            )
            or not isinstance(receipt["validator"], str)
            or receipt["validator"]
            not in {
                OPERATOR_VALIDATOR_CEREMONY,
                OPERATOR_VALIDATOR_CAPTURE,
                OPERATOR_VALIDATOR_FIXTURE,
                OPERATOR_VALIDATOR_GAUNTLET,
            }
            or not isinstance(receipt["claim"], str)
            or not receipt["claim"]
            or len(receipt["claim"]) > 128
            or not isinstance(receipt["descriptor"], dict)
            or not isinstance(receipt["descriptor_sha256"], str)
            or len(receipt["descriptor_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in receipt["descriptor_sha256"]
            )
        ):
            raise WorkflowError(f"operator evidence for {lane_id} is malformed")
        canonical_descriptor = json.dumps(
            receipt["descriptor"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if (
            hashlib.sha256(canonical_descriptor).hexdigest()
            != receipt["descriptor_sha256"]
        ):
            raise WorkflowError(
                f"operator evidence for {lane_id} has a mismatched descriptor digest"
            )
    return {
        "completed": sorted(completed),
        "operator_evidence": dict(sorted(operator_evidence.items())),
    }


def _validated_registry_state(
    data: object,
    registry: Sequence[Lane],
    *,
    revalidate_desk: bool,
    revalidate_evidence: bool,
    revalidate_terminal: bool,
) -> Dict[str, object]:
    """Join persisted completion claims back to the active lane registry."""

    normalized = _validated_state(data)
    validate_registry(registry)
    by_id = registry_by_id(registry)
    completed = set(normalized["completed"])
    evidence = normalized["operator_evidence"]
    unknown = completed - set(by_id)
    if unknown:
        raise WorkflowError(f"state references unknown lanes: {sorted(unknown)}")

    for lane_id in sorted(completed):
        lane = by_id[lane_id]
        missing = sorted(set(lane.depends_on) - completed)
        if missing:
            raise WorkflowError(
                f"persisted lane {lane_id} is not dependency-closed; missing: "
                f"{', '.join(missing)}"
            )
        receipt = evidence.get(lane_id)
        if lane.kind == OPERATOR:
            if receipt is None:
                raise WorkflowError(
                    f"persisted operator lane {lane_id} has no semantic evidence receipt"
                )
            if receipt["validator"] != lane.operator_validator:
                raise WorkflowError(
                    f"persisted operator lane {lane_id} validator no longer matches "
                    "the active registry"
                )
            if revalidate_evidence:
                _revalidate_operator_receipt(lane, receipt)
        elif receipt is not None:
            raise WorkflowError(f"desk lane {lane_id} cannot carry operator evidence")
        elif revalidate_desk and lane_id != "terminal":
            validate_desk_deliverable(lane)
            for command in lane.verify:
                process = _verification_process(command)
                if process.returncode != 0:
                    detail = process.stderr.strip() or process.stdout.strip()
                    raise WorkflowError(
                        f"persisted desk lane {lane_id} verification is stale: "
                        f"{command}: {detail}"
                    )

    for lane_id in evidence:
        lane = by_id.get(lane_id)
        if lane is None:
            raise WorkflowError(f"operator evidence references unknown lane {lane_id}")
        if lane.kind != OPERATOR:
            raise WorkflowError(f"operator evidence references desk lane {lane_id}")
        if lane_id not in completed:
            raise WorkflowError(
                f"operator evidence for {lane_id} exists without a completion claim"
            )

    if revalidate_terminal and "terminal" in completed:
        terminal = by_id["terminal"]
        if _is_canonical_terminal(terminal):
            process = _terminal_verification_process(normalized)
        else:
            process = _verification_process(terminal.verify[0])
        if process.returncode != 0:
            detail = process.stderr.strip() or process.stdout.strip()
            raise WorkflowError(
                "persisted terminal completion is stale: production qualification "
                f"failed: {detail}"
            )
    return normalized


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise WorkflowError(f"refusing to replace symlink output {path}")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    handle: Optional[int] = None
    try:
        handle = os.open(str(temporary), flags, 0o600)
        data = text.encode("utf-8")
        offset = 0
        while offset < len(data):
            offset += os.write(handle, data[offset:])
        os.fsync(handle)
        os.close(handle)
        handle = None
        os.replace(temporary, path)
    except OSError as exc:
        raise WorkflowError(f"cannot atomically write {path}: {exc}") from exc
    finally:
        if handle is not None:
            os.close(handle)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class StateLock:
    """Bounded cross-process exclusion for state read/modify/write cycles."""

    def __init__(self, state_path: Path) -> None:
        self.path = state_path.with_name(state_path.name + ".lock")
        self.acquired = False

    def __enter__(self) -> "StateLock":
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        self.path.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                handle = os.open(
                    str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    payload = f"pid={os.getpid()}\n".encode("ascii")
                    os.write(handle, payload)
                    os.fsync(handle)
                finally:
                    os.close(handle)
                self.acquired = True
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise WorkflowError(
                        f"timed out waiting for workflow state lock {self.path}; "
                        "inspect and remove it only if its owner is no longer running"
                    ) from None
                time.sleep(0.05)
            except OSError as exc:
                raise WorkflowError(
                    f"cannot acquire workflow state lock: {exc}"
                ) from exc

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.acquired:
            try:
                self.path.unlink()
            except OSError as exc:
                raise WorkflowError(
                    f"cannot release workflow state lock: {exc}"
                ) from exc
            finally:
                self.acquired = False


def load_state(
    path: Path = STATE_PATH,
    registry: Optional[Sequence[Lane]] = REGISTRY,
) -> Dict[str, object]:
    if not path.exists():
        empty = {"completed": [], "operator_evidence": {}}
        return (
            _validated_registry_state(
                empty,
                registry,
                revalidate_desk=True,
                revalidate_evidence=True,
                revalidate_terminal=True,
            )
            if registry is not None
            else empty
        )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WorkflowError(f"cannot inspect state file {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WorkflowError(f"state path must be a regular non-symlink file: {path}")
    if metadata.st_size > MAX_STATE_BYTES:
        raise WorkflowError(f"state file exceeds {MAX_STATE_BYTES} bytes")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WorkflowError(f"cannot read workflow state {path}: {exc}") from exc
    data = _strict_json_object(raw, "workflow state")
    if registry is None:
        return _validated_state(data)
    return _validated_registry_state(
        data,
        registry,
        revalidate_desk=True,
        revalidate_evidence=True,
        revalidate_terminal=True,
    )


def save_state(
    state: Dict[str, object],
    path: Path = STATE_PATH,
    registry: Optional[Sequence[Lane]] = None,
) -> None:
    normalized = (
        _validated_registry_state(
            state,
            registry,
            revalidate_desk=False,
            revalidate_evidence=False,
            revalidate_terminal=False,
        )
        if registry is not None
        else _validated_state(state)
    )
    _atomic_write_text(path, json.dumps(normalized, indent=2) + "\n")


def _read_operator_evidence(path: Path) -> Tuple[Dict[str, object], bytes]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WorkflowError(f"cannot inspect operator evidence {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WorkflowError(
            f"operator evidence must be a regular non-symlink file: {path}"
        )
    if not 1 <= metadata.st_size <= MAX_OPERATOR_EVIDENCE_BYTES:
        raise WorkflowError(
            f"operator evidence size must be in 1..{MAX_OPERATOR_EVIDENCE_BYTES} bytes"
        )
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(MAX_OPERATOR_EVIDENCE_BYTES + 1)
            final = os.fstat(stream.fileno())
    except OSError as exc:
        raise WorkflowError(f"cannot read operator evidence {path}: {exc}") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise WorkflowError(
            f"cannot reinspect operator evidence {path}: {exc}"
        ) from exc
    identities = [
        (item.st_size, item.st_mtime_ns, getattr(item, "st_ino", 0))
        for item in (metadata, opened, final, after)
    ]
    if len(raw) != metadata.st_size or len(set(identities)) != 1:
        raise WorkflowError(f"operator evidence changed while being read: {path}")
    return {
        "bytes": metadata.st_size,
        "filename": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }, raw


def _strict_json_object(raw: bytes, label: str) -> Dict[str, object]:
    def reject_duplicates(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
        value: Dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise WorkflowError(f"{label} has duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise WorkflowError(f"{label} must be strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowError(f"{label} root must be an object")
    return value


def _require_exact_fields(
    value: Dict[str, object], expected: Sequence[str], label: str
) -> None:
    missing = sorted(set(expected) - set(value))
    extra = sorted(set(value) - set(expected))
    if missing or extra:
        raise WorkflowError(
            f"{label} fields invalid: missing={missing or 'none'} extra={extra or 'none'}"
        )


def _run_gauntlet(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, str(GAUNTLET_SCRIPT), *arguments],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise WorkflowError(f"operator evidence failed gauntlet admission: {detail}")
    return process


def _verification_process(command: str) -> subprocess.CompletedProcess[str]:
    """Run one static registry command without a platform shell."""

    cwd = REPO_ROOT
    text = command
    if text.startswith("cd "):
        prefix, separator, remainder = text.partition(" && ")
        if not separator:
            raise WorkflowError(f"verify command has unsupported cd syntax: {command}")
        relative = prefix.removeprefix("cd ")
        cwd = _repo_artifact(relative, "verify working directory")
        if not cwd.is_dir():
            raise WorkflowError(
                f"verify working directory is not a directory: {relative}"
            )
        text = remainder
    try:
        arguments = shlex.split(text, posix=True)
    except ValueError as exc:
        raise WorkflowError(f"cannot parse verify command {command!r}: {exc}") from exc
    if not arguments:
        raise WorkflowError("verify command is empty")
    if arguments[:2] == ["py", "-3"]:
        arguments = [sys.executable, *arguments[2:]]
    if arguments[0] not in {sys.executable, "cargo"}:
        raise WorkflowError(
            f"verify executable must be the current Python or cargo: {arguments[0]}"
        )
    return subprocess.run(arguments, capture_output=True, text=True, cwd=str(cwd))


def _manifest_anchor_ids(manifest: Dict[str, object]) -> Dict[str, str]:
    anchors: Dict[str, object] = {}
    for contract_name, contract in sorted(manifest.items()):
        if not contract_name.endswith("_contract") or not isinstance(contract, dict):
            continue
        prefix = contract_name.removesuffix("_contract")
        if "trust_anchor" in contract:
            anchors[f"{prefix}.signer"] = contract["trust_anchor"]
        if "trust_anchors" in contract:
            group = contract["trust_anchors"]
            if not isinstance(group, dict) or not group:
                raise WorkflowError(
                    f"canonical manifest {contract_name} trust anchors are invalid"
                )
            for role_name, anchor in sorted(group.items()):
                anchors[f"{prefix}.{role_name}"] = anchor
    if not anchors:
        raise WorkflowError("canonical manifest declares no trust-anchor contracts")
    result: Dict[str, str] = {}
    paths: set[str] = set()
    roles: set[str] = set()
    for name, anchor in anchors.items():
        if not isinstance(anchor, dict) or set(anchor) != {
            "key_id_sha256",
            "path",
            "role",
        }:
            raise WorkflowError(f"canonical manifest anchor {name} is not pinned")
        key_id = anchor.get("key_id_sha256")
        if (
            not isinstance(key_id, str)
            or len(key_id) != 64
            or any(character not in "0123456789abcdef" for character in key_id)
        ):
            raise WorkflowError(
                f"canonical manifest anchor {name} has an invalid key ID"
            )
        path = anchor.get("path")
        role = anchor.get("role")
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(role, str)
            or not role
        ):
            raise WorkflowError(
                f"canonical manifest anchor {name} has invalid metadata"
            )
        result[name] = key_id
        paths.add(path)
        roles.add(role)
    if (
        len(set(result.values())) != len(result)
        or len(paths) != len(result)
        or len(roles) != len(result)
    ):
        raise WorkflowError(
            "canonical manifest must pin a distinct key, path, and role for every trust anchor"
        )
    return result


def _validate_ceremony_descriptor(descriptor: Dict[str, object]) -> Tuple[str, str]:
    _require_exact_fields(
        descriptor,
        ("anchors", "kind", "manifest", "manifest_sha256", "schema_version"),
        "ceremony descriptor",
    )
    if descriptor["kind"] != "dcent_k210_trust_anchor_ceremony_receipt":
        raise WorkflowError("ceremony descriptor kind is invalid")
    if descriptor["schema_version"] != 1:
        raise WorkflowError("ceremony descriptor schema_version must be 1")
    manifest_rel = "DCENT_OS_AvalonMiner/gauntlet/k210_models.json"
    if descriptor["manifest"] != manifest_rel:
        raise WorkflowError(f"ceremony descriptor manifest must be {manifest_rel}")
    manifest_path = REPO_ROOT / manifest_rel
    try:
        manifest_raw = manifest_path.read_bytes()
        manifest = json.loads(manifest_raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise WorkflowError(f"cannot read canonical K210 manifest: {exc}") from exc
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    if descriptor["manifest_sha256"] != manifest_sha:
        raise WorkflowError(
            "ceremony descriptor does not bind the current manifest bytes"
        )
    anchor_ids = _manifest_anchor_ids(manifest)
    if descriptor["anchors"] != anchor_ids:
        raise WorkflowError(
            "ceremony descriptor anchor IDs do not match the canonical manifest"
        )
    _run_gauntlet(("verify", "--corpus", "required"))
    return "all_distinct_manifest_trust_anchors_pinned", manifest_sha


GAUNTLET_BUNDLES_BY_LANE: Dict[str, Tuple[str, ...]] = {
    "op-discovery": ("discovery_bundle",),
    "op-recovery": ("discovery_bundle", "fixture_bundle", "recovery_bundle"),
    "op-bootpolicy": (
        "discovery_bundle",
        "fixture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
    ),
    "op-replacement": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
    ),
    "op-rollback": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
    ),
    "op-firstlight": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
        "first_light_bundle",
    ),
    "op-bench": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
        "first_light_bundle",
        "bench_bundle",
    ),
    "op-endurance": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
        "first_light_bundle",
        "bench_bundle",
        "endurance_bundle",
    ),
    "op-preauthorize": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
        "first_light_bundle",
        "bench_bundle",
        "endurance_bundle",
        "release_preauthorization_bundle",
    ),
    "op-release": (
        "discovery_bundle",
        "fixture_bundle",
        "capture_bundle",
        "recovery_bundle",
        "boot_policy_bundle",
        "replacement_bundle",
        "rollback_bundle",
        "first_light_bundle",
        "bench_bundle",
        "endurance_bundle",
        "release_preauthorization_bundle",
        "release_bundle",
    ),
}


def _repo_artifact(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise WorkflowError(f"{label} must be a forward-slash repo-relative path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise WorkflowError(f"{label} must be a canonical repo-relative path")
    candidate = REPO_ROOT.joinpath(*path.parts)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise WorkflowError(f"{label} cannot be inspected: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not (
        stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
    ):
        raise WorkflowError(
            f"{label} must be a regular file or directory, not a symlink"
        )
    return candidate


def _desk_contract_text(
    relative: str,
    label: str,
    *,
    minimum_bytes: int,
    expected_sha256: str = "",
) -> str:
    path = _repo_artifact(relative, label)
    if not path.is_file():
        raise WorkflowError(f"{label} must be a regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WorkflowError(f"{label} cannot be read: {exc}") from exc
    if len(raw) < minimum_bytes:
        raise WorkflowError(
            f"{label} is too small for its semantic contract: "
            f"{len(raw)} < {minimum_bytes} bytes"
        )
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise WorkflowError(
            f"{label} differs from its reviewed content digest; re-audit and "
            "update the workflow contract before admitting the revision"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise WorkflowError(f"{label} must be UTF-8 text: {exc}") from exc
    if "\x00" in text or text.strip().lower() in {"placeholder", "todo", "pass"}:
        raise WorkflowError(f"{label} is a placeholder")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _require_contract_tokens(text: str, tokens: Sequence[str], label: str) -> None:
    folded = text.casefold()
    missing = [token for token in tokens if token.casefold() not in folded]
    if missing:
        raise WorkflowError(f"{label} is missing semantic tokens: {missing}")


def _python_test_names(text: str, label: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise WorkflowError(f"{label} is not valid Python: {exc}") from exc
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _validate_python_test_bodies(text: str, label: str) -> None:
    """Reject syntactic test targets whose test bodies make no assertion."""

    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise WorkflowError(f"{label} is not valid Python: {exc}") from exc
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not (
            node.name.startswith("test_")
        ):
            continue
        signals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                if isinstance(child.test, ast.Constant) and child.test.value is True:
                    raise WorkflowError(f"{label} {node.name} uses a trivial assertion")
                signals.append(child)
            elif isinstance(child, ast.Call):
                function = child.func
                if isinstance(function, ast.Attribute) and (
                    function.attr.startswith("assert") or function.attr == "raises"
                ):
                    signals.append(child)
        if not signals:
            raise WorkflowError(f"{label} {node.name} has no semantic assertion")


def _rust_without_comments(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?m)//.*$", "", without_blocks)


def _validate_rust_desk_contract(
    lane_id: str,
    source_path: str,
    test_path: str,
    required_tokens: Sequence[str],
    required_test_names: Sequence[str],
) -> None:
    source = _desk_contract_text(
        source_path, f"{lane_id} implementation", minimum_bytes=1500
    )
    tests = _desk_contract_text(
        test_path, f"{lane_id} admission tests", minimum_bytes=1800
    )
    source_code = _rust_without_comments(source)
    test_code = _rust_without_comments(tests)
    test_count = len(re.findall(r"#\s*\[\s*test\s*\]", test_code))
    if test_count < 8:
        raise WorkflowError(
            f"{lane_id} semantic test contract has only {test_count} tests; 8 required"
        )
    test_names = set(re.findall(r"\bfn\s+(test_[A-Za-z0-9_]+)\s*\(", test_code))
    missing_names = sorted(set(required_test_names) - test_names)
    if missing_names:
        raise WorkflowError(
            f"{lane_id} semantic test contract is missing named cases: {missing_names}"
        )
    folded_tests = test_code.casefold()
    forbidden = (
        "todo!",
        "unimplemented!",
        "assert!(true)",
        "#[ignore",
        "should_panic",
    )
    observed_forbidden = [token for token in forbidden if token in folded_tests]
    if observed_forbidden:
        raise WorkflowError(
            f"{lane_id} semantic tests contain placeholder/bypass constructs: "
            f"{observed_forbidden}"
        )
    assertion_count = len(
        re.findall(r"\b(?:assert|assert_eq|assert_ne|debug_assert)!\s*\(", test_code)
    )
    if assertion_count < test_count:
        raise WorkflowError(
            f"{lane_id} semantic tests contain {assertion_count} assertions for "
            f"{test_count} tests"
        )
    _require_contract_tokens(source_code + "\n" + test_code, required_tokens, lane_id)


def _validate_python_desk_contract(
    lane_id: str,
    source_paths: Sequence[str],
    test_contracts: Sequence[Tuple[str, int, Sequence[str]]],
    required_tokens: Sequence[str],
) -> None:
    combined = []
    for source_path in source_paths:
        combined.append(
            _desk_contract_text(
                source_path, f"{lane_id} implementation", minimum_bytes=2000
            )
        )
    for test_path, minimum_tests, required_names in test_contracts:
        tests = _desk_contract_text(
            test_path, f"{lane_id} semantic tests", minimum_bytes=1800
        )
        names = _python_test_names(tests, f"{lane_id} semantic tests")
        _validate_python_test_bodies(tests, f"{lane_id} semantic tests")
        missing_names = sorted(set(required_names) - names)
        if len(names) < minimum_tests or missing_names:
            raise WorkflowError(
                f"{lane_id} semantic test contract is incomplete: "
                f"count={len(names)} required={minimum_tests} "
                f"missing={missing_names or 'none'}"
            )
        combined.append(tests)
    _require_contract_tokens("\n".join(combined), required_tokens, lane_id)


def _validate_semantic_desk_lane(lane_id: str) -> None:
    if lane_id == "w2-codec":
        _validate_rust_desk_contract(
            lane_id,
            "shared/dcent-avalon-proto/src/k210_codec.rs",
            "shared/dcent-avalon-proto/tests/k210_codec_admission.rs",
            (
                "capture_set_sha256",
                "unit_fingerprint_sha256",
                "variant_profile_id",
                "encode",
                "decode",
                "reject",
                "authority_granted",
            ),
            (
                "test_round_trip_preserves_target_bound_identity",
                "test_cross_unit_and_variant_splices_are_rejected",
                "test_malformed_and_unknown_messages_fail_closed",
                "test_codec_never_grants_install_authority",
            ),
        )
    elif lane_id == "w2-firmware":
        _validate_rust_desk_contract(
            lane_id,
            "DCENT_OS_AvalonMiner/k210-firmware/src/target_bound.rs",
            "DCENT_OS_AvalonMiner/k210-firmware/tests/k210_target_bound_runtime.rs",
            (
                "native_aes0_flash",
                "rom_isp_sram_bootstrap",
                "jtag_sram_bootstrap",
                "clean_replacement_controller",
                "unit_fingerprint_sha256",
                "artifact_set_sha256",
                "safe_idle",
                "authority_granted",
            ),
            (
                "test_all_four_routes_enter_safe_idle_before_any_hash_enable",
                "test_wrong_unit_route_and_artifact_set_are_rejected",
                "test_failed_safety_or_predecessor_evidence_cannot_start_runtime",
                "test_runtime_never_grants_install_authority",
            ),
        )
    elif lane_id == "w2-safety":
        _validate_rust_desk_contract(
            lane_id,
            "DCENT_OS_AvalonMiner/k210-firmware/src/hardware_safety.rs",
            "DCENT_OS_AvalonMiner/k210-firmware/tests/k210_hardware_safety.rs",
            (
                "independent_cutoff",
                "watchdog",
                "stale",
                "latched",
                "cooling",
                "hash_power",
                "authority_granted",
            ),
            (
                "test_hash_power_requires_cooling_cutoff_watchdog_and_fresh_telemetry",
                "test_stale_or_faulted_inputs_latch_safe_idle",
                "test_watchdog_and_independent_cutoff_remain_fail_closed",
                "test_safety_runtime_never_grants_install_authority",
            ),
        )
    elif lane_id == "w3-executor":
        _validate_python_desk_contract(
            lane_id,
            ("projects/dcent-toolbox/src/dcent_toolbox/core/k210_install_executor.py",),
            (
                (
                    "projects/dcent-toolbox/tests/test_k210_install_executor.py",
                    10,
                    (
                        "test_all_four_routes_execute_only_the_selected_deployable_member",
                        "test_release_capstone_and_explicit_operator_confirmation_are_required",
                        "test_cross_route_unit_artifact_and_predecessor_splices_are_rejected",
                        "test_no_clobber_recovery_and_safe_idle_preconditions_fail_closed",
                        "test_dry_run_and_failure_paths_never_grant_install_authority",
                    ),
                ),
            ),
            (
                "route_replacement_receipt_id",
                "route_rollback_receipt_id",
                "installed_artifact_sha256",
                "no_clobber_sha256",
                "selected_route",
                "release_authority",
                "recovery",
                "execute",
                "authority_granted",
            ),
        )
    elif lane_id == "w3-validation":
        _validate_python_desk_contract(
            lane_id,
            (
                "DCENT_OS_AvalonMiner/scripts/k210_bench_endurance_receipt.py",
                "DCENT_OS_AvalonMiner/scripts/k210_release_receipt.py",
            ),
            (
                (
                    "DCENT_OS_AvalonMiner/scripts/test_k210_bench_endurance_receipt.py",
                    9,
                    (
                        "test_three_immutable_stage_receipts_and_gate_progression",
                        "test_non_aes_rom_isp_full_progression",
                        "test_route_adjudication_restoration_and_predecessor_splices_fail",
                    ),
                ),
                (
                    "DCENT_OS_AvalonMiner/scripts/test_k210_release_receipt.py",
                    9,
                    (
                        "test_completed_capstone_exact_joins_and_is_non_generic",
                        "test_scope_broadening_splicing_and_temporal_inversion_fail",
                        "test_preauthorization_signature_and_pinned_anchor_fail_closed",
                    ),
                ),
            ),
            (
                "protocol_reviewer",
                "safety_reviewer",
                "prior_stage_evidence_set_sha256",
                "route_replacement_receipt_id",
                "route_rollback_receipt_id",
                "installed_artifact_sha256",
                "no_clobber_sha256",
                "authority_granted",
            ),
        )
    elif lane_id == "w3-rollback":
        _validate_python_desk_contract(
            lane_id,
            ("DCENT_OS_AvalonMiner/scripts/k210_route_rollback_receipt.py",),
            (
                (
                    "DCENT_OS_AvalonMiner/scripts/test_k210_route_rollback_receipt.py",
                    7,
                    (
                        "test_aes0_interrupted_update_full_restore_round_trip",
                        "test_rom_isp_abort_volatile_reset_and_unchanged_flash_round_trip",
                        "test_jtag_abort_volatile_reset_and_unchanged_flash_round_trip",
                        "test_controller_disconnect_reconnect_and_unchanged_flash_round_trip",
                        "test_cross_route_cross_unit_and_digest_splices_are_rejected",
                        "test_persistence_no_clobber_and_interruption_claims_are_rejected",
                    ),
                ),
            ),
            (
                "schema_version = 2",
                "native_aes0_flash",
                "rom_isp_sram_bootstrap",
                "jtag_sram_bootstrap",
                "clean_replacement_controller",
                "artifact_set_sha256",
                "interface_qualification_sha256",
                "no_clobber_sha256",
                "stock_restoration_sha256",
                "authority_granted",
            ),
        )
    else:
        raise WorkflowError(f"no semantic desk validator exists for {lane_id}")


def validate_desk_deliverable(lane: Lane) -> None:
    """Reject report placeholders and mission-incomplete desk implementations."""

    if lane.kind != DESK or lane.lane_id == "terminal":
        return
    reports = DESK_REPORT_CONTRACTS.get(lane.lane_id)
    if reports is not None:
        for (
            relative,
            minimum_bytes,
            minimum_headings,
            tokens,
            expected_sha256,
        ) in reports:
            text = _desk_contract_text(
                relative,
                f"{lane.lane_id} semantic report",
                minimum_bytes=minimum_bytes,
                expected_sha256=expected_sha256,
            )
            headings = len(re.findall(r"(?m)^#{1,6}\s+\S", text))
            substantive_lines = sum(
                1
                for line in text.splitlines()
                if len(line.strip()) >= 20 and not line.lstrip().startswith("<!--")
            )
            if headings < minimum_headings or substantive_lines < 80:
                raise WorkflowError(
                    f"{lane.lane_id} semantic report lacks reviewed structure: "
                    f"headings={headings}/{minimum_headings} "
                    f"substantive_lines={substantive_lines}/80"
                )
            _require_contract_tokens(text, tokens, f"{lane.lane_id} semantic report")
    if lane.lane_id in SEMANTIC_DESK_LANES:
        _validate_semantic_desk_lane(lane.lane_id)


TERMINAL_BUNDLE_SOURCES: Tuple[Tuple[str, str, str], ...] = (
    ("discovery_bundle", "op-discovery", "--discovery-bundle"),
    ("fixture_bundle", "op-fixture", "--fixture-bundle"),
    ("capture_bundle", "op-capture", "--capture-bundle"),
    ("recovery_bundle", "op-recovery", "--recovery-bundle"),
    ("boot_policy_bundle", "op-bootpolicy", "--boot-policy-bundle"),
    ("replacement_bundle", "op-replacement", "--replacement-bundle"),
    ("rollback_bundle", "op-rollback", "--rollback-bundle"),
    ("first_light_bundle", "op-firstlight", "--first-light-bundle"),
    ("bench_bundle", "op-bench", "--bench-bundle"),
    ("endurance_bundle", "op-endurance", "--endurance-bundle"),
    (
        "release_preauthorization_bundle",
        "op-preauthorize",
        "--release-preauthorization-bundle",
    ),
    ("release_bundle", "op-release", "--release-bundle"),
)


def _is_canonical_terminal(lane: Lane) -> bool:
    return (
        lane.lane_id == "terminal"
        and len(lane.verify) == 1
        and "k210_gauntlet.py check" in lane.verify[0]
        and "--require-production" in lane.verify[0]
    )


def _terminal_bundle_arguments(state: Dict[str, object]) -> List[str]:
    evidence = state.get("operator_evidence")
    if not isinstance(evidence, dict):
        raise WorkflowError("terminal state has no operator evidence map")
    arguments: List[str] = []
    for bundle_name, source_lane, option in TERMINAL_BUNDLE_SOURCES:
        source_receipt = evidence.get(source_lane)
        if not isinstance(source_receipt, dict):
            raise WorkflowError(
                f"terminal cannot reconstruct {bundle_name}: {source_lane} "
                "has no evidence receipt"
            )
        source_descriptor = source_receipt.get("descriptor")
        if not isinstance(source_descriptor, dict):
            raise WorkflowError(
                f"terminal cannot reconstruct {bundle_name}: {source_lane} "
                "descriptor is invalid"
            )
        source_bundles = source_descriptor.get("bundles")
        if not isinstance(source_bundles, dict) or bundle_name not in source_bundles:
            raise WorkflowError(
                f"terminal cannot reconstruct {bundle_name} from {source_lane}"
            )
        canonical_value = source_bundles[bundle_name]
        for lane_id, receipt in evidence.items():
            if not isinstance(receipt, dict):
                continue
            descriptor = receipt.get("descriptor")
            bundles = (
                descriptor.get("bundles") if isinstance(descriptor, dict) else None
            )
            if (
                isinstance(bundles, dict)
                and bundle_name in bundles
                and bundles[bundle_name] != canonical_value
            ):
                raise WorkflowError(
                    f"terminal bundle join mismatch for {bundle_name}: "
                    f"{source_lane} != {lane_id}"
                )
        arguments.extend((option, str(_repo_artifact(canonical_value, bundle_name))))
    return arguments


def _terminal_verification_process(
    state: Dict[str, object],
) -> subprocess.CompletedProcess[str]:
    arguments = [
        sys.executable,
        str(GAUNTLET_SCRIPT),
        "check",
        "--model",
        "a1246",
        "--corpus",
        "required",
        "--format",
        "json",
        *_terminal_bundle_arguments(state),
        "--require-production",
    ]
    return subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _validate_gauntlet_descriptor(
    lane: Lane, descriptor: Dict[str, object]
) -> Tuple[str, str]:
    _require_exact_fields(
        descriptor,
        ("bundles", "kind", "model", "schema_version"),
        f"{lane.lane_id} descriptor",
    )
    if descriptor["kind"] != "dcent_k210_operator_gate_evidence":
        raise WorkflowError(f"{lane.lane_id} descriptor kind is invalid")
    if descriptor["schema_version"] != 1 or descriptor["model"] != "a1246":
        raise WorkflowError(
            f"{lane.lane_id} descriptor must bind schema 1 and model a1246"
        )
    bundles = descriptor["bundles"]
    if not isinstance(bundles, dict):
        raise WorkflowError(f"{lane.lane_id} descriptor bundles must be an object")
    expected = GAUNTLET_BUNDLES_BY_LANE.get(lane.lane_id)
    if expected is None:
        raise WorkflowError(f"no gauntlet bundle contract exists for {lane.lane_id}")
    _require_exact_fields(bundles, expected, f"{lane.lane_id} descriptor bundles")
    arguments: List[str] = [
        "check",
        "--model",
        "a1246",
        "--corpus",
        "required",
        "--format",
        "json",
    ]
    option_names = {
        "discovery_bundle": "--discovery-bundle",
        "fixture_bundle": "--fixture-bundle",
        "capture_bundle": "--capture-bundle",
        "recovery_bundle": "--recovery-bundle",
        "boot_policy_bundle": "--boot-policy-bundle",
        "replacement_bundle": "--replacement-bundle",
        "rollback_bundle": "--rollback-bundle",
        "first_light_bundle": "--first-light-bundle",
        "bench_bundle": "--bench-bundle",
        "endurance_bundle": "--endurance-bundle",
        "release_preauthorization_bundle": "--release-preauthorization-bundle",
        "release_bundle": "--release-bundle",
    }
    for name in expected:
        arguments.extend((option_names[name], str(_repo_artifact(bundles[name], name))))
    process = _run_gauntlet(arguments)
    try:
        result = json.loads(process.stdout)
        gate = result["gates"][lane.target_gate]
        fixture_result = result.get("fixture_qualification")
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowError(
            f"gauntlet returned malformed gate evidence: {exc}"
        ) from exc
    if lane.lane_id in {
        "op-recovery",
        "op-bootpolicy",
        "op-replacement",
        "op-rollback",
        "op-firstlight",
        "op-bench",
        "op-endurance",
        "op-preauthorize",
        "op-release",
    } and (
        not isinstance(fixture_result, dict)
        or fixture_result.get("state") != "verified_signed_fixture_qualification"
        or fixture_result.get("fixture_qualification_eligible") is not True
        or fixture_result.get("authority_granted") is not False
    ):
        raise WorkflowError(
            f"gauntlet did not admit the exact-unit fixture prerequisite for {lane.lane_id}"
        )
    if lane.lane_id == "op-preauthorize":
        admitted = result.get("release_preauthorization")
        if (
            result.get("id") != "a1246"
            or not isinstance(admitted, dict)
            or admitted.get("state") != "verified_exact_scope_preauthorization"
            or admitted.get("install_authority_scope_eligible") is not True
            or admitted.get("authority_granted") is not False
            or admitted.get("generic_future_authority_granted") is not False
            or gate.get("qualifies") is not False
        ):
            raise WorkflowError(
                "gauntlet did not admit a narrow exact-scope release preauthorization"
            )
        canonical = json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return "exact_scope_install_preauthorized", hashlib.sha256(
            canonical
        ).hexdigest()
    if result.get("id") != "a1246" or gate.get("qualifies") is not True:
        raise WorkflowError(
            f"gauntlet did not qualify {lane.target_gate} for the exact a1246 target"
        )
    if lane.lane_id == "op-firstlight":
        thermal_gate = result.get("gates", {}).get("thermal_power_safety", {})
        if thermal_gate.get("qualifies") is not True:
            raise WorkflowError(
                "first-light evidence did not independently qualify thermal_power_safety"
            )
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    claim = (
        "asic_control_and_thermal_power_safety_qualify"
        if lane.lane_id == "op-firstlight"
        else f"{lane.target_gate}_qualifies"
    )
    return claim, hashlib.sha256(canonical).hexdigest()


def _validate_fixture_descriptor(
    lane: Lane, descriptor: Dict[str, object]
) -> Tuple[str, str]:
    _require_exact_fields(
        descriptor,
        ("bundles", "kind", "model", "schema_version"),
        f"{lane.lane_id} descriptor",
    )
    if lane.lane_id != "op-fixture":
        raise WorkflowError("fixture receipt validator is scoped only to op-fixture")
    if descriptor["kind"] != "dcent_k210_operator_fixture_evidence":
        raise WorkflowError("op-fixture descriptor kind is invalid")
    if descriptor["schema_version"] != 1 or descriptor["model"] != "a1246":
        raise WorkflowError("op-fixture descriptor must bind schema 1 and model a1246")
    bundles = descriptor["bundles"]
    if not isinstance(bundles, dict):
        raise WorkflowError("op-fixture descriptor bundles must be an object")
    expected = ("discovery_bundle", "fixture_bundle")
    _require_exact_fields(bundles, expected, "op-fixture descriptor bundles")
    arguments = [
        "check",
        "--model",
        "a1246",
        "--corpus",
        "required",
        "--format",
        "json",
    ]
    for name, option in (
        ("discovery_bundle", "--discovery-bundle"),
        ("fixture_bundle", "--fixture-bundle"),
    ):
        arguments.extend((option, str(_repo_artifact(bundles[name], name))))
    process = _run_gauntlet(arguments)
    try:
        result = json.loads(process.stdout)
        admitted = result["fixture_qualification"]
        thermal_gate = result["gates"]["thermal_power_safety"]
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowError(
            f"gauntlet returned malformed fixture evidence: {exc}"
        ) from exc
    if (
        result.get("id") != "a1246"
        or not isinstance(admitted, dict)
        or admitted.get("state") != "verified_signed_fixture_qualification"
        or admitted.get("fixture_qualification_eligible") is not True
        or admitted.get("authority_granted") is not False
    ):
        raise WorkflowError(
            "gauntlet did not admit the exact-unit fixture qualification"
        )
    if thermal_gate.get("qualifies") is not False:
        raise WorkflowError(
            "fixture admission unexpectedly qualified thermal_power_safety"
        )
    canonical = json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "exact_unit_fixture_qualified", hashlib.sha256(canonical).hexdigest()


def _validate_capture_descriptor(
    lane: Lane, descriptor: Dict[str, object]
) -> Tuple[str, str]:
    _require_exact_fields(
        descriptor,
        ("bundles", "kind", "model", "schema_version"),
        f"{lane.lane_id} descriptor",
    )
    if lane.lane_id != "op-capture":
        raise WorkflowError("capture receipt validator is scoped only to op-capture")
    if descriptor["kind"] != "dcent_k210_operator_capture_evidence":
        raise WorkflowError("op-capture descriptor kind is invalid")
    if descriptor["schema_version"] != 1 or descriptor["model"] != "a1246":
        raise WorkflowError("op-capture descriptor must bind schema 1 and model a1246")
    bundles = descriptor["bundles"]
    if not isinstance(bundles, dict):
        raise WorkflowError("op-capture descriptor bundles must be an object")
    expected = ("discovery_bundle", "fixture_bundle", "capture_bundle")
    _require_exact_fields(bundles, expected, "op-capture descriptor bundles")
    arguments = [
        "check",
        "--model",
        "a1246",
        "--corpus",
        "required",
        "--format",
        "json",
    ]
    for name, option in (
        ("discovery_bundle", "--discovery-bundle"),
        ("fixture_bundle", "--fixture-bundle"),
        ("capture_bundle", "--capture-bundle"),
    ):
        arguments.extend((option, str(_repo_artifact(bundles[name], name))))
    process = _run_gauntlet(arguments)
    try:
        result = json.loads(process.stdout)
        admitted = result["passive_capture_admission"]
        asic_gate = result["gates"]["asic_control"]
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowError(
            f"gauntlet returned malformed capture evidence: {exc}"
        ) from exc
    if (
        result.get("id") != "a1246"
        or not isinstance(admitted, dict)
        or admitted.get("state") != "verified_signed_p1_passive_capture"
        or admitted.get("p1_capture_admission_eligible") is not True
        or admitted.get("authority_granted") is not False
        or admitted.get("wire_contract_claimed") is not False
    ):
        raise WorkflowError(
            "gauntlet did not admit the exact-revision P1 capture corpus"
        )
    if asic_gate.get("qualifies") is not False:
        raise WorkflowError("raw capture admission unexpectedly qualified asic_control")
    canonical = json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "p1_passive_capture_admitted", hashlib.sha256(canonical).hexdigest()


def validate_operator_evidence(lane: Lane, path: Path) -> Dict[str, object]:
    if lane.operator_validator == OPERATOR_VALIDATOR_UNIMPLEMENTED:
        raise WorkflowError(
            f"operator lane {lane.lane_id} is locked: its semantic evidence validator "
            "is not implemented"
        )
    snapshot, raw = _read_operator_evidence(path)
    descriptor = _strict_json_object(raw, f"{lane.lane_id} evidence")
    if lane.operator_validator == OPERATOR_VALIDATOR_CEREMONY:
        claim, subject_sha = _validate_ceremony_descriptor(descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_CAPTURE:
        claim, subject_sha = _validate_capture_descriptor(lane, descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_FIXTURE:
        claim, subject_sha = _validate_fixture_descriptor(lane, descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_GAUNTLET:
        claim, subject_sha = _validate_gauntlet_descriptor(lane, descriptor)
    else:
        raise WorkflowError(f"unsupported operator validator for {lane.lane_id}")
    canonical_descriptor = json.dumps(
        descriptor, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        **snapshot,
        "claim": claim,
        "descriptor": descriptor,
        "descriptor_sha256": hashlib.sha256(canonical_descriptor).hexdigest(),
        "subject_sha256": subject_sha,
        "validator": lane.operator_validator,
    }


def _revalidate_operator_receipt(lane: Lane, receipt: Dict[str, object]) -> None:
    """Replay persisted semantic evidence against current canonical inputs."""

    descriptor = receipt["descriptor"]
    if lane.operator_validator == OPERATOR_VALIDATOR_CEREMONY:
        claim, subject_sha = _validate_ceremony_descriptor(descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_CAPTURE:
        claim, subject_sha = _validate_capture_descriptor(lane, descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_FIXTURE:
        claim, subject_sha = _validate_fixture_descriptor(lane, descriptor)
    elif lane.operator_validator == OPERATOR_VALIDATOR_GAUNTLET:
        claim, subject_sha = _validate_gauntlet_descriptor(lane, descriptor)
    else:
        raise WorkflowError(
            f"persisted operator lane {lane.lane_id} has no replayable validator"
        )
    if claim != receipt["claim"] or subject_sha != receipt["subject_sha256"]:
        raise WorkflowError(
            f"persisted operator evidence for {lane.lane_id} is stale or changed"
        )


def evaluate(
    registry: Sequence[Lane], state: Dict[str, object]
) -> Dict[str, Dict[str, object]]:
    state = _validated_registry_state(
        state,
        registry,
        revalidate_desk=True,
        revalidate_evidence=True,
        revalidate_terminal=True,
    )
    completed = set(state["completed"])
    out: Dict[str, Dict[str, object]] = {}
    for lane in registry:
        if lane.lane_id in completed:
            status = "done"
            missing: List[str] = []
        else:
            missing = [d for d in lane.depends_on if d not in completed]
            if not missing:
                if lane.kind == OPERATOR:
                    status = (
                        "blocked_validator"
                        if lane.operator_validator == OPERATOR_VALIDATOR_UNIMPLEMENTED
                        else "awaiting_operator"
                    )
                else:
                    status = "ready"
            else:
                status = "blocked"
        out[lane.lane_id] = {
            "title": lane.title,
            "expert": lane.expert,
            "kind": lane.kind,
            "status": status,
            "missing_dependencies": missing,
            "runbook": lane.runbook or None,
            "target_gate": lane.target_gate or None,
            "mission": lane.mission or None,
            "operator_validator": lane.operator_validator or None,
        }
    return out


def gauntlet_gate_snapshot(model: str = "a1246") -> Dict[str, Dict[str, object]]:
    cmd = [
        sys.executable,
        str(GAUNTLET_SCRIPT),
        "check",
        "--model",
        model,
        "--format",
        "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise WorkflowError(f"gauntlet check failed: {proc.stderr.strip()}")
    data = json.loads(proc.stdout)
    return {
        gate: {"state": body["state"], "qualifies": body["qualifies"]}
        for gate, body in data["gates"].items()
    }


def emit_wave(
    registry: Sequence[Lane],
    state: Dict[str, object],
    gate_snapshot: Optional[Dict[str, Dict[str, object]]] = None,
    wave_md: Path = WAVE_MD,
    wave_json: Path = WAVE_JSON,
) -> Dict[str, object]:
    ev = evaluate(registry, state)
    normalized_state = _validated_state(state)
    registry_digest = registry_sha256(registry)
    canonical_state = json.dumps(
        normalized_state, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    state_sha256 = hashlib.sha256(
        b"DCENT-K210-WORKFLOW-STATE-V2\x00"
        + bytes.fromhex(registry_digest)
        + canonical_state
    ).hexdigest()
    ready = [i for i, v in ev.items() if v["status"] == "ready"]
    awaiting = [i for i, v in ev.items() if v["status"] == "awaiting_operator"]
    blocked = [i for i, v in ev.items() if v["status"] == "blocked"]
    blocked_validator = [i for i, v in ev.items() if v["status"] == "blocked_validator"]
    done = [i for i, v in ev.items() if v["status"] == "done"]
    payload = {
        "registry_size": len(registry),
        "registry_sha256": registry_digest,
        "state_sha256": state_sha256,
        "ready": ready,
        "awaiting_operator": awaiting,
        "blocked": blocked,
        "blocked_validator": blocked_validator,
        "done": sorted(done),
        "lanes": ev,
        "gauntlet_gates_a1246": gate_snapshot,
    }
    wave_json.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(wave_json, json.dumps(payload, indent=2) + "\n")

    lines: List[str] = [
        "# K210 unlock workflow — current wave",
        "",
        "Host-only dispatch state. Desk lanes are executed by expert agents under the",
        "coordinating session; operator nodes pause the workflow until the operator",
        "confirms the runbook step. Nothing here qualifies gauntlet gates by itself.",
        "",
        f"- done: {len(done)} / {len(registry)} lanes",
        f"- ready to dispatch: {', '.join(ready) or '(none)'}",
        f"- awaiting operator: {', '.join(awaiting) or '(none)'}",
        f"- locked pending validator: {', '.join(blocked_validator) or '(none)'}",
        f"- registry SHA-256: `{registry_digest}`",
        f"- state SHA-256: `{state_sha256}`",
        "",
        "## Ready desk lanes",
        "",
    ]
    for lane_id in ready:
        v = ev[lane_id]
        lines.append(f"### {lane_id} — {v['title']} ({v['expert']})")
        lines.append(f"- mission: {v['mission']}")
        lines.append(f"- feeds gate: {v['target_gate']}")
        lines.append("")
    lines += ["## Awaiting operator", ""]
    for lane_id in awaiting:
        v = ev[lane_id]
        lines.append(f"- **{lane_id}** — {v['title']} → runbook: `{v['runbook']}`")
    lines += ["", "## Locked pending semantic validator", ""]
    for lane_id in blocked_validator:
        v = ev[lane_id]
        lines.append(
            f"- **{lane_id}**: {v['title']}; validator: `{v['operator_validator']}`"
        )
    lines += ["", "## Blocked (missing dependencies)", ""]
    for lane_id in blocked:
        v = ev[lane_id]
        lines.append(
            f"- **{lane_id}** — missing: {', '.join(v['missing_dependencies'])}"
        )
    if gate_snapshot:
        lines += ["", "## Gauntlet gates (a1246 snapshot)", ""]
        for gate, body in gate_snapshot.items():
            mark = "✅" if body["qualifies"] else "❌"
            lines.append(f"- {mark} `{gate}`: {body['state']}")
    lines.append("")
    _atomic_write_text(wave_md, "\n".join(lines))
    return payload


def complete_lane(
    lane_id: str,
    registry: Sequence[Lane],
    state: Dict[str, object],
    operator_confirmed: bool = False,
    operator_evidence: Optional[Path] = None,
    state_path: Path = STATE_PATH,
) -> Dict[str, object]:
    state = _validated_registry_state(
        state,
        registry,
        revalidate_desk=True,
        revalidate_evidence=True,
        revalidate_terminal=True,
    )
    by_id = registry_by_id(registry)
    if lane_id not in by_id:
        raise WorkflowError(f"unknown lane {lane_id}")
    lane = by_id[lane_id]
    if lane_id in state["completed"]:
        raise WorkflowError(f"lane {lane_id} already completed")
    missing = [d for d in lane.depends_on if d not in state["completed"]]
    if missing:
        raise WorkflowError(f"lane {lane_id} blocked on: {', '.join(missing)}")
    if lane.kind == OPERATOR:
        if not operator_confirmed:
            raise WorkflowError(
                f"operator lane {lane_id} requires --operator-confirmed (operator attestation)"
            )
        if operator_evidence is None:
            raise WorkflowError(
                f"operator lane {lane_id} requires --evidence pointing to the "
                "completed runbook's receipt or witnessed evidence manifest"
            )
        evidence = validate_operator_evidence(lane, operator_evidence)
    else:
        if operator_evidence is not None:
            raise WorkflowError("--evidence is valid only for operator lanes")
        if _is_canonical_terminal(lane):
            proc = _terminal_verification_process(state)
            if proc.returncode != 0:
                raise WorkflowError(
                    "verify failed for terminal with reconstructed admitted bundles:"
                    f"\n{proc.stdout}\n{proc.stderr}"
                )
        else:
            validate_desk_deliverable(lane)
            for cmd in lane.verify:
                proc = _verification_process(cmd)
                if proc.returncode != 0:
                    raise WorkflowError(
                        f"verify failed for {lane_id}: {cmd}\n{proc.stdout}\n{proc.stderr}"
                    )
    operator_receipts = dict(state["operator_evidence"])
    if lane.kind == OPERATOR:
        operator_receipts[lane_id] = evidence
    state = {
        "completed": sorted(state["completed"] + [lane_id]),
        "operator_evidence": operator_receipts,
    }
    save_state(state, state_path, registry)
    return state


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=STATE_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("wave", help="emit the current wave manifest")
    sub.add_parser("status", help="print lane statuses")
    cp = sub.add_parser("complete", help="record a lane completion")
    cp.add_argument("--lane", required=True)
    cp.add_argument("--operator-confirmed", action="store_true")
    cp.add_argument(
        "--evidence",
        type=Path,
        help=(
            "operator-lane receipt or witnessed evidence manifest to hash into "
            "the workflow ledger; required with --operator-confirmed"
        ),
    )
    args = parser.parse_args(argv)

    registry = REGISTRY
    validate_registry(registry)
    if args.cmd == "wave":
        with StateLock(args.state):
            state = load_state(args.state, registry=None)
            gates = gauntlet_gate_snapshot()
            payload = emit_wave(registry, state, gates)
        print(
            f"wave: {len(payload['done'])} done, {len(payload['ready'])} ready, "
            f"{len(payload['awaiting_operator'])} awaiting operator -> {WAVE_MD.name}"
        )
        return 0
    if args.cmd == "status":
        state = load_state(args.state, registry=None)
        for lane_id, v in evaluate(registry, state).items():
            print(f"{v['status']:>18}  {lane_id:16} {v['title']}")
        return 0
    if args.cmd == "complete":
        with StateLock(args.state):
            # Reload only after acquiring the lock. Multiple expert agents may
            # complete independent ready lanes concurrently; a pre-lock read
            # would let the last writer silently discard the other completion.
            state = load_state(args.state, registry=None)
            state = complete_lane(
                args.lane,
                registry,
                state,
                operator_confirmed=args.operator_confirmed,
                operator_evidence=args.evidence,
                state_path=args.state,
            )
            gates = gauntlet_gate_snapshot()
            payload = emit_wave(registry, state, gates)
        print(
            f"lane {args.lane} recorded complete; wave: {len(payload['done'])} done, "
            f"{len(payload['ready'])} ready, "
            f"{len(payload['awaiting_operator'])} awaiting operator"
        )
        return 0
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WorkflowError as exc:
        print(f"K210_UNLOCK_WORKFLOW_ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
