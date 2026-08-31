#!/usr/bin/env python3
"""One-shot generator for the Antminer S21 complete-enablement campaign
manifest.

Regenerating overwrites the tracked manifest; any phase identity change must
be re-pinned in tests. Run from the repository root.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OUT = (
    REPO
    / ""
    "S21_ENABLEMENT_CAMPAIGN.json"
)
MODULE_PATH = "DCENT_OS_Antminer/scripts/s21_lane_verify.py"


def ident(rel: str) -> dict[str, object]:
    data = (REPO / rel).read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


PINNED = [
    "DCENT_OS_Antminer/scripts/s21_enablement_workflow.py",
    "DCENT_OS_Antminer/scripts/s21_lane_verify.py",
    "DCENT_OS_Antminer/scripts/test_s21_enablement_workflow.py",
    "DCENT_OS_Antminer/scripts/test_s21_lane_verify.py",
]


def phase(
    pid: str,
    title: str,
    kind: str,
    expert: str,
    deps: list[str],
    mission: str,
    owns: list[str] | None = None,
    verifier: dict[str, object] | None = None,
) -> dict[str, object]:
    if verifier is None:
        verifier = {"kind": "module", "path": MODULE_PATH}
    return {
        "id": pid,
        "title": title,
        "kind": kind,
        "expert": expert,
        "depends_on": deps,
        "owns": owns or [],
        "mission": mission,
        "verifier": verifier,
    }


PHASES: list[dict[str, object]] = [
    phase(
        "offline-repo-contract",
        "Offline controller and lane verifier toolchain",
        "desk",
        "DCENT_QA",
        [],
        "Keep the offline controller, shared lane verifier, and their adversarial tests byte-pinned so every later phase builds on an unmodified toolchain.",
        owns=PINNED,
        verifier={
            "kind": "repo",
            "required_paths": PINNED,
            "required_identities": {p: ident(p) for p in PINNED},
        },
    ),
    phase(
        "variant-matrix-closure",
        "Canonical S21-generation version matrix + hydro fingerprint fix",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract"],
        "Close the canonical S21-generation version matrix (board target x silicon x hashboard x PIC/NoPic x marketing names incl. Hydro/plus-generation) and fix the board_fingerprint.py ladder so S21 Hydro resolves distinctly instead of falling through to the Amlogic plain-S21 class.",
        owns=[
            "",
            "projects/dcent-toolbox/src/dcent_toolbox/unlocks/board_fingerprint.py",
            "projects/dcent-toolbox/tests/test_board_fingerprint.py",
            "SUPPORT_MATRIX.md",
        ],
    ),
    phase(
        "hashboard-revision-atlas",
        "Read-only BHB68xxx/A3HB7xxxx hashboard revision atlas",
        "desk",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Consolidate the read-only S21-generation hashboard atlas (BHB68603..BHB68709, A3HB707xx) with per-SKU PIC/NoPic class and the speculated 0x05 0x11 x21_AES cipher state; EEPROM writes to 0x50-0x57 stay forbidden on am2/am3 lanes.",
        owns=[""],
    ),
    phase(
        "unlock-surface-closure",
        "Complete unlock ladder for every entry firmware state",
        "desk",
        "DCENT_Security",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Audit and document the complete unlock ladder for every S21-generation entry firmware state (locked stock, BraiinsOS, LuxOS, VNish) across AML/XIL boards: signature-bypass version matrix, dcent amlogic-unlock OTG downgrade, rootfs-window lab route, XIL recovery media.",
        owns=[
            "projects/dcent-toolbox/src/dcent_toolbox/cli/commands/unlock.py",
            "projects/dcent-toolbox/src/dcent_toolbox/cli/commands/amlogic_unlock.py",
            "",
        ],
    ),
    phase(
        "nopic-psu-polarity-atlas",
        "NoPic PSU-control polarity atlas (S21-class 1=ON evidence state)",
        "desk",
        "DCENT_EE",
        ["variant-matrix-closure"],
        "Consolidate the TAS5782M NoPic PSU-control map with the software source-of-truth (S21-class logical 1=ON, SafeOff=0) and the explicit open item that neither polarity has been DMM-measured on a rail; forbid transplanting am3-s19k (0=ON) evidence.",
        owns=[""],
    ),
    # -- S21 (Amlogic) lane --------------------------------------------------
    phase(
        "s21-stock-unit-custody",
        "Locked-stock S21 Amlogic bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Take custody of a LOCKED-STOCK S21 Amlogic unit (existing fleet unit, authorized stock revert, or procurement) and record its read-only board fingerprint; .135 runs BraiinsOS and does not qualify for the stock-unlock gate.",
    ),
    phase(
        "s21-stock-unlock-live",
        "Live stock-S21 unlock proof",
        "operator",
        "DCENT_Security",
        ["s21-stock-unit-custody", "unlock-surface-closure"],
        "Under fresh operator authorization, run the stock unlock surface on the locked-stock S21 unit (signature-bypass web package per firmware version matrix, or the dcent amlogic-unlock OTG downgrade) and capture proof; this controller grants no authority.",
    ),
    phase(
        "s21-nopic-polarity-dmm",
        "S21 NoPic PSU polarity DMM rail evidence",
        "operator",
        "DCENT_EE",
        ["nopic-psu-polarity-atlas"],
        "Under fresh operator authorization, close the 'neither side DMM-measured a rail' open item on .135-class hardware with instrumented rail measurements of the S21-class NoPic 1=ON / SafeOff=0 contract.",
    ),
    phase(
        "s21-no-work-safeoff",
        "S21 no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["s21-stock-unlock-live", "s21-nopic-polarity-dmm"],
        "Under fresh operator authorization, collect the S21 no-work/SafeOff gate evidence (rail/GPIO/reset/cooling custody) with the unit producing no hash work.",
    ),
    phase(
        "s21-bounded-work",
        "S21 bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["s21-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial on the S21 target and capture the accepted-share transcript.",
    ),
    phase(
        "s21-eeprom-live-capture",
        "S21 hashboard EEPROM live capture (Phase E from .135)",
        "operator",
        "DCENT_EE",
        ["hashboard-revision-atlas", "s21-nopic-polarity-dmm"],
        "Under fresh operator authorization, capture the first live read-only BHB68xxx hashboard EEPROM dumps from the .135-class unit (Phase E of the EEPROM template atlas); writes stay forbidden.",
    ),
    phase(
        "eeprom-cipher-closure",
        "BHB68xxx EEPROM cipher confirmation or refutation",
        "desk",
        "DCENT_RE",
        ["s21-eeprom-live-capture"],
        "Confirm or refute the speculated 0x05 0x11 x21_AES preamble against the live captures, then extend the EEPROM atlas and the decrypt tooling; reads only.",
        owns=[""],
    ),
    phase(
        "s21-endurance",
        "S21 quiet-home endurance soak",
        "operator",
        "DCENT_Thermal",
        ["s21-bounded-work"],
        "Under fresh operator authorization, run the quiet-home-profile endurance soak with wall-power evidence and thermal custody (cut hash before noise).",
    ),
    phase(
        "s21-persistent-install",
        "S21 guarded rootfs-window persistent install",
        "operator",
        "DCENT_CE",
        ["s21-endurance"],
        "Under fresh, separate, explicit authorization, perform the guarded rootfs-window persistent install (root access, restore-verified backup, package-family match, physical recovery plan) and seal the artifact under artifacts/s21-enablement/.",
    ),
    phase(
        "s21-acceptance",
        "S21 persistent acceptance",
        "operator",
        "DCENT_QA",
        ["s21-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, restore path, and accepted shares on the persistently installed S21 unit.",
    ),
    # -- S21 Pro lane --------------------------------------------------------
    phase(
        "s21pro-first-light-plan",
        "S21 Pro BM1370 first-light operator bench card",
        "desk",
        "DCENT_CE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Produce the sole-executable S21 Pro first-light bench card (BM1370 experimental template, shipped PLL solver, per-chain vs total chip-count proof) modeled on the S19k OPERATOR_BENCH_CARD pattern; the card is the pinned deliverable.",
        owns=[""],
    ),
    phase(
        "s21pro-unit-custody",
        "S21 Pro bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire and take custody of an S21 Pro (am3-s21pro, BM1370) bench unit and record its read-only fingerprint; no bench unit exists today (first-light is a placeholder).",
    ),
    phase(
        "s21pro-first-light",
        "S21 Pro BM1370 cold first-light",
        "operator",
        "DCENT_CE",
        ["s21pro-first-light-plan", "s21pro-unit-custody"],
        "Under fresh operator authorization, achieve cold first-light on the S21 Pro bench unit with no-work instrumented evidence before any hash work.",
    ),
    phase(
        "s21pro-bounded-work",
        "S21 Pro bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["s21pro-first-light"],
        "Under fresh operator authorization, run the bounded staged-mining trial on the S21 Pro unit and capture the accepted-share transcript.",
    ),
    phase(
        "s21pro-endurance",
        "S21 Pro endurance soak",
        "operator",
        "DCENT_Thermal",
        ["s21pro-bounded-work"],
        "Under fresh operator authorization, run the S21 Pro endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "s21pro-persistent-install",
        "S21 Pro guarded rootfs-window persistent install",
        "operator",
        "DCENT_CE",
        ["s21pro-endurance"],
        "Under fresh, separate, explicit authorization, perform the guarded rootfs-window persistent install on S21 Pro and seal the artifact.",
    ),
    phase(
        "s21pro-acceptance",
        "S21 Pro persistent acceptance",
        "operator",
        "DCENT_QA",
        ["s21pro-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, restore path, and accepted shares on the persistently installed S21 Pro unit.",
    ),
    # -- S21 XP lane ---------------------------------------------------------
    phase(
        "s21xp-production-map-closure",
        "S21 XP production UART map + controller contract closure",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Close the exact S21 XP production map (3x91 BM1370 on ttyS3/ttyS2/ttyS1) plus the PIC/PSU/safe lifecycle contract from the S21XP jig RE, the stock FR-1.149 BMU, and the held VNish s21xp corpus; the shared ttyS4/NoPic inheritance stays refused meanwhile.",
        owns=[""],
    ),
    phase(
        "s21xp-admission-promotion",
        "S21 XP TD-003 admission promotion gates",
        "desk",
        "DCENT_CE",
        ["s21xp-production-map-closure"],
        "Complete the S21 XP promotion gates (exact production map, safety lifecycle, storage/recovery) and lift the s21xp intercept from the TD-003 management-only refuse-list in model.rs with ADR-backed evidence.",
        owns=[
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs",
            "DCENT_OS_Antminer/docs/ARCHITECTURE_DECISION_LOG.md",
            "",
        ],
    ),
    phase(
        "s21xp-unit-custody",
        "S21 XP bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire and take custody of an S21 XP (am3-s21xp, 3x91 BM1370) bench unit and record its read-only fingerprint.",
    ),
    phase(
        "s21xp-no-work-safeoff",
        "S21 XP no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["s21xp-admission-promotion", "s21xp-unit-custody"],
        "Under fresh operator authorization, collect the S21 XP no-work/SafeOff gate evidence before any hash work.",
    ),
    phase(
        "s21xp-bounded-work",
        "S21 XP bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["s21xp-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial on S21 XP and capture the accepted-share transcript.",
    ),
    phase(
        "s21xp-endurance",
        "S21 XP endurance soak",
        "operator",
        "DCENT_Thermal",
        ["s21xp-bounded-work"],
        "Under fresh operator authorization, run the S21 XP endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "s21xp-persistent-install",
        "S21 XP guarded persistent install",
        "operator",
        "DCENT_CE",
        ["s21xp-endurance"],
        "Under fresh, separate, explicit authorization, perform the persistent install on S21 XP and seal the artifact.",
    ),
    phase(
        "s21xp-acceptance",
        "S21 XP persistent acceptance",
        "operator",
        "DCENT_QA",
        ["s21xp-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on the persistently installed S21 XP unit.",
    ),
    # -- T21 lane ------------------------------------------------------------
    phase(
        "t21-controller-contract-closure",
        "T21 controller contract closure (PIC/PSU/safe-off)",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Close the T21 controller contract from the held stock FR-1.20 BMU, the VNish t21 corpus, and the ePIC desk evidence: PIC identity/protocol, PSU wire protocol, safe-off polarity, cold-init/failure-unwind, and storage geometry; BM1368 identity is already pinned.",
        owns=[""],
    ),
    phase(
        "t21-admission-promotion",
        "T21 TD-003 admission promotion gates",
        "desk",
        "DCENT_CE",
        ["t21-controller-contract-closure"],
        "Complete the T21 promotion gates and lift the t21 intercept from the TD-003 management-only refuse-list in model.rs with ADR-backed evidence; the revert entrypoint stub must stop refusing before install is admitted.",
        owns=[
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs",
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/experimental.rs",
            "",
        ],
    ),
    phase(
        "t21-unit-custody",
        "T21 bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire and take custody of a T21 (am3-t21, BM1368) bench unit and record its read-only fingerprint.",
    ),
    phase(
        "t21-no-work-safeoff",
        "T21 no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["t21-admission-promotion", "t21-unit-custody"],
        "Under fresh operator authorization, collect the T21 no-work/SafeOff gate evidence before any hash work.",
    ),
    phase(
        "t21-bounded-work",
        "T21 bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["t21-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial on T21 and capture the accepted-share transcript.",
    ),
    phase(
        "t21-endurance",
        "T21 endurance soak",
        "operator",
        "DCENT_Thermal",
        ["t21-bounded-work"],
        "Under fresh operator authorization, run the T21 endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "t21-persistent-install",
        "T21 guarded persistent install",
        "operator",
        "DCENT_CE",
        ["t21-endurance"],
        "Under fresh, separate, explicit authorization, perform the persistent install on T21 and seal the artifact.",
    ),
    phase(
        "t21-acceptance",
        "T21 persistent acceptance",
        "operator",
        "DCENT_QA",
        ["t21-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on the persistently installed T21 unit.",
    ),
    # -- Hydro (XIL Zynq) lane ----------------------------------------------
    phase(
        "hydro-identity-closure",
        "S21 Hydro XIL identity + recovery inventory closure",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Close the S21 Hydro class identity (Zynq 7007S board IDs, BM1370 hydro geometry, which marketing names map to it) from the held recovery image, the U3S21EXPH FR-1.76 unlock payload status, and the s21e-xp-hydro boot/rootfs analyzer evidence.",
        owns=[
            "projects/dcent-toolbox/docs/s21e-xp-hydro-boot-rootfs-evidence.md",
            "projects/dcent-toolbox/docs/held-s21-plus-generation-bmu-evidence.md",
        ],
    ),
    phase(
        "hydro-build-target-plan",
        "Hydro Zynq build-target + recovery-first install plan",
        "desk",
        "DCENT_CE",
        ["hydro-identity-closure"],
        "Write the Hydro build-target plan (am2 Zynq target, recovery-media-first install design, no in-place writer until recovery proof) modeled on the S19j Pro CV1835 plan pattern; the plan document is the pinned deliverable.",
        owns=[""],
    ),
    phase(
        "hydro-unit-custody",
        "S21 Hydro bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire and take custody of an S21 Hydro (XIL Zynq class) bench unit and record its read-only fingerprint.",
    ),
    phase(
        "hydro-recovery-boot",
        "Hydro recovery-media cold boot proof",
        "operator",
        "DCENT_DevOps",
        ["hydro-build-target-plan", "hydro-unit-custody"],
        "Under fresh operator authorization, boot the held Hydro recovery media cold on the bench unit and capture the boot transcript; no in-place flash.",
    ),
    phase(
        "hydro-bounded-work",
        "Hydro bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["hydro-recovery-boot"],
        "Under fresh operator authorization, run the bounded staged-mining trial from the recovery boot and capture the accepted-share transcript.",
    ),
    phase(
        "hydro-persistent-install",
        "Hydro persistent install",
        "operator",
        "DCENT_CE",
        ["hydro-bounded-work"],
        "Under fresh, separate, explicit authorization, perform the persistent install on the Hydro unit and seal the artifact.",
    ),
    phase(
        "hydro-acceptance",
        "Hydro persistent acceptance",
        "operator",
        "DCENT_QA",
        ["hydro-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on the persistently installed Hydro unit.",
    ),
    # -- S21+ generation lane -----------------------------------------------
    phase(
        "plus-generation-identity-closure",
        "S21+ generation identity closure",
        "desk",
        "DCENT_RE",
        ["offline-repo-contract", "variant-matrix-closure"],
        "Close the S21+ generation identity (S21+, S21++, S21 Pro+, S21e, immersion SKUs) from the held BMU subtype-hash evidence: A3HB707xx 3x55 geometry, board revisions, PIC/NoPic class, PSU dialect; never promote across marketing names.",
        owns=[
            "projects/dcent-toolbox/docs/held-s21-plus-generation-bmu-evidence.md",
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs",
        ],
    ),
    phase(
        "plus-admission-promotion",
        "S21+ generation TD-003 admission promotion gates",
        "desk",
        "DCENT_CE",
        ["plus-generation-identity-closure"],
        "Complete the S21+ generation promotion gates and lift the s21plus intercept from the TD-003 management-only refuse-list in model.rs with ADR-backed evidence.",
        owns=[
            "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs",
            "",
        ],
    ),
    phase(
        "plus-unit-custody",
        "S21+ generation bench unit custody",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire and take custody of an S21+ generation (amlogic-s21plus class) bench unit and record its read-only fingerprint.",
    ),
    phase(
        "plus-no-work-safeoff",
        "S21+ no-work/SafeOff physical gate",
        "operator",
        "DCENT_EE",
        ["plus-admission-promotion", "plus-unit-custody"],
        "Under fresh operator authorization, collect the S21+ no-work/SafeOff gate evidence before any hash work.",
    ),
    phase(
        "plus-bounded-work",
        "S21+ bounded staged mining with accepted shares",
        "operator",
        "DCENT_Protocol",
        ["plus-no-work-safeoff"],
        "Under fresh operator authorization, run the bounded staged-mining trial on the S21+ unit and capture the accepted-share transcript.",
    ),
    phase(
        "plus-endurance",
        "S21+ endurance soak",
        "operator",
        "DCENT_Thermal",
        ["plus-bounded-work"],
        "Under fresh operator authorization, run the S21+ endurance soak with wall-power and thermal evidence.",
    ),
    phase(
        "plus-persistent-install",
        "S21+ guarded persistent install",
        "operator",
        "DCENT_CE",
        ["plus-endurance"],
        "Under fresh, separate, explicit authorization, perform the persistent install on the S21+ unit and seal the artifact.",
    ),
    phase(
        "plus-acceptance",
        "S21+ persistent acceptance",
        "operator",
        "DCENT_QA",
        ["plus-persistent-install"],
        "Under fresh operator authorization, verify cold boot, manageability, rollback, and accepted shares on the persistently installed S21+ unit.",
    ),
    # -- CV1835 lane ---------------------------------------------------------
    phase(
        "cv-unit-acquisition",
        "CV1835 S21-class bench unit acquisition",
        "operator",
        "DCENT_EE",
        ["offline-repo-contract"],
        "Acquire a CV1835 S21-class bench unit and record custody plus read-only fingerprint; the CV lane is acquisition-gated and structurally swap-only (dcent_denied_cv1835_swap_or_sd_downgrade).",
    ),
    phase(
        "cv-swap-recovery-plan",
        "CV1835 swap recovery plan",
        "desk",
        "DCENT_CE",
        ["cv-unit-acquisition"],
        "Write the CV1835 S21-class swap recovery plan backed by the acquired unit's captured storage map; the plan document is the pinned deliverable and admits no downgrade or in-place writer.",
        owns=[""],
    ),
    # -- closeout ------------------------------------------------------------
    phase(
        "support-tier-promotion",
        "Evidence-backed support-tier promotion for all seven lanes",
        "desk",
        "DCENT_QA",
        [
            "hashboard-revision-atlas",
            "eeprom-cipher-closure",
            "s21-acceptance",
            "s21pro-acceptance",
            "s21xp-acceptance",
            "t21-acceptance",
            "hydro-acceptance",
            "plus-acceptance",
        ],
        "Promote all seven S21-generation board-target rows in SUPPORT_MATRIX.md to their evidence-backed tiers (adding the missing am2-s21-hydro-xil and cv1835-s21 rows), each with a named artifact path per the support-matrix guardrails.",
        owns=["SUPPORT_MATRIX.md", "DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf"],
    ),
    phase(
        "complete-s21-enablement",
        "Terminal claim: complete S21-generation enablement",
        "terminal",
        "DCENT_QA",
        ["support-tier-promotion", "cv-swap-recovery-plan"],
        "Terminal claim issues only when every dependency is independently verified.",
        verifier={"kind": "terminal"},
    ),
]


def main() -> None:
    manifest = {
        "schema": "dcentos.s21-enablement-campaign/v1",
        "campaign_id": "s21-complete-enablement-20260827",
        "target": (
            "Antminer S21 generation - am3-s21 (BM1368), am3-s21pro "
            "(BM1370), am3-s21xp (BM1370 3x91), am3-t21 (BM1368), the S21+ "
            "generation (amlogic-s21plus class, BM1370 3x55), the S21 Hydro "
            "XIL (Zynq 7007S, BM1370) class, and CV1835 S21-class SKUs"
        ),
        "terminal_claim": (
            "Every Antminer S21-generation board target (am3-s21, am3-s21pro, "
            "am3-s21xp, am3-t21, amlogic-s21plus, the S21 Hydro XIL class, "
            "and the CV1835 S21 class) has an independently verified "
            "unlock-to-persistent-DCENT_OS path with fresh operator-authorized "
            "evidence receipts"
        ),
        "contact_policy": {
            "controller_is_offline_only": True,
            "live_contact_requires_fresh_operator_authorization": True,
            "nand_or_emmc_write_requires_separate_explicit_authorization": True,
            "controller_may_grant_authority": False,
        },
        "artifacts": [],
        "phases": PHASES,
    }
    OUT.write_text(
        json.dumps(manifest, indent=1, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    canonical = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    print("wrote", OUT)
    print("phases:", len(PHASES))
    print("manifest canonical sha256:", hashlib.sha256(canonical).hexdigest())


if __name__ == "__main__":
    main()
