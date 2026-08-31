#!/usr/bin/env python3
"""Stage the unlock-surface-closure and hashboard-revision-atlas evidence.

Desk-only staging helper for campaign s19j-pro-complete-enablement-20260826.
Writes the two evidence directories' content files (receipts are minted
afterwards with s19jpro_lane_verify.py prepare).
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EVIDENCE = REPO / ".s19jpro-enablement-evidence"


def stage_unlock_surface() -> None:
    ev = EVIDENCE / "unlock-surface-closure"
    ev.mkdir(parents=True, exist_ok=True)
    ladder = """# S19j Pro unlock ladder - canonical per-lane/per-state map

Campaign s19j-pro-complete-enablement-20260826, phase unlock-surface-closure.
Every route id below is present in dcent_toolbox/core/installer.py (verified
by condition unlock_routes_present); every web package is built on disk
(condition web_unlock_packages_present). Proof tests:
tests/test_stock_unlock.py, test_unlock_command.py, test_unlocks.py,
test_new_unlocks.py, test_unlock_rehearsal.py, test_amlogic_unlock.py,
test_unlocker2_iv_crack.py, test_install_auto_unlock_stock.py.

## Locked stock entry (the "unlock" proper)

| Lane | Method | Mechanism | Status |
|---|---|---|---|
| XIL (Zynq stock) | `dcent unlock` 5-method cascade | 1. pre-2019-07 CGI overwrite; 2. runme.sh patcher (evidence-gap until Unlocker2 closes); 3. config-restore injection (upload_conf.cgi + restoreConfig.sh); 4. ping injection (network_diag.cgi command injection, strong stock-Zynq route); 5. hostname CVE-2018-11220 (legacy, may reboot) | implemented + proof-laddered (dry_run_ready -> ssh_enabled_via_unlock); live locked-stock proof = campaign phase xil-stock-unlock-live |
| XIL (Zynq stock) | web upload packages | dcentos-signature-bypass.tar.gz, dcentos-ssh-enabler.tar.gz, dcentos-api-enabler.tar.gz (DCENT_OS_Antminer/web_packages/) | built; web-upload install path |
| BB (stock) | bitmain_bb_access | SSH-enable on stock BB (DCENT_OS_Antminer/scripts/bitmain_bb_access + planned toolbox bitmain_bb_* modules per STOCK_BITMAIN_BB_DEEP_INTEL.md) | exploit retained; toolbox moduleization planned; live proof = bb-stock-ssh-unlock-live |
| Amlogic (stock) | `dcent amlogic-unlock` (USB-OTG) | aml_burn_tool flashes pre-lock eMMC image over OTG; A113D; covers S19j Pro / S19k Pro / S21 | the marquee locked-install differentiator; live proof = aml-otg-unlock-live |
| S19j Pro+ (stock) | AML unlock family | same A113D carrier class | pending TD-003 promotion + unit |
| CV1835 (stock) | unresolved | no held unit | acquisition-gated |

## Vendor-firmware entry (no signature lock; SSH/root needed)

| Lane | Firmware | Route(s) |
|---|---|---|
| XIL | BraiinsOS | braiinsos-am2-s19jpro-zynq-runtime / -persistent-lab |
| XIL | LuxOS | luxos-am2-s19jpro-zynq-persistent-lab |
| XIL | VNish | vnish-am2-s19jpro-zynq-persistent-lab + dcentos-analysis-am2-s19jpro-zynq-vnish-splice |
| BB | LuxOS | luxos-am3-bb-uninstall-then-stock-sd_first_boot; stock-am3-bb-sd_first_boot; stock-am3-bb-nand-first-install-lab |
| AML | stock | amlogic-s19jpro-stock-rootfs_window_lab (40 MiB rootfs window, mtd5 @ 0x5100000) |
| AML | VNish | amlogic-vnish-rootfs_window_lab (VnishCgminer detection + --accept-vnish-aml-rootfs-window) |
| Pro+ | stock | amlogic-s19jproplus-stock-rootfs_window_lab |
| any | passthrough | bcb100-s19jpro-passthrough-lab |

## Stock-locked XIL first-install ladder

`dcent am2-first-install` (Wave 3 plan-only staged ladder; toolbox
am2_first_install.py): unlock -> backup -> dry-run -> guarded first flash.
BB NAND ladder: `dcent bb-nand-first-install` (Wave 4): SD cold-boot witness
-> capsule -> live layout capture -> full-NAND backup + restore proof ->
dry-run -> witnessed capstone.

## Standing safety invariants

- Unlock is entry, not authority: every LIVE run needs fresh exact operator
  authorization (campaign contact_policy).
- Degraded-hardware gates stay: fw=0x86 dsPIC refusal, EEPROM header 0x04
  preamble checks in GATHER_STATE preflight (override lab-only).
- AMLCTRL boundary: rootfs-window routes require root SSH, restore-verified
  backup, package-family match, physical recovery plan
  (docs/security/AMLCTRL_BOUNDARY.md).
"""
    (ev / "unlock-ladder.md").write_text(ladder, encoding="utf-8")
    (ev / "analysis.md").write_text(
        "# unlock-surface-closure analysis\n\n"
        "Desk audit only; no unit was contacted.\n\n"
        "Closed: the unlock surface for every S19j Pro lane x firmware state is\n"
        "now enumerated with named, code-present routes. Verified 2026-08-26/27:\n"
        "- 9 install route ids present in core/installer.py (condition).\n"
        "- 3 web unlock packages on disk (condition).\n"
        "- 5-method stock-Zynq cascade + proof ladder documented from\n"
        "  cli/commands/unlock.py docstring (authoritative).\n"
        "- amlogic_unlock.py, bitmain_bb_access, am2_first_install.py,\n"
        "  bb_nand_first_install.py all present in tree.\n\n"
        "Open items routed to their owning phases:\n"
        "- runme.sh patcher remains evidence-gap until Unlocker2 IV crack closes\n"
        "  (test_unlocker2_iv_crack.py is the host-side proof).\n"
        "- Live proofs are separate operator phases (xil-stock-unlock-live,\n"
        "  bb-stock-ssh-unlock-live, aml-otg-unlock-live).\n",
        encoding="utf-8",
    )


def stage_hashboard_atlas() -> None:
    ev = EVIDENCE / "hashboard-revision-atlas"
    ev.mkdir(parents=True, exist_ok=True)
    boards: list[dict[str, object]] = []

    def board(
        name: str,
        pic_class: str,
        carriers: list[str],
        evidence: str,
    ) -> None:
        boards.append(
            {
                "board": name,
                "chip": "BM1362",
                "pic_class": pic_class,
                "carriers": carriers,
                "evidence": evidence,
            }
        )

    board("BHB42601", "PIC/dsPIC", ["am2-s19jpro-zynq (XIL)", "am3-bb-s19jpro (BB)"],
          ".25/.109/.139 decode BHB42601 BOM 0x1000 PCB 0x2001; EEPROM_TEMPLATE_ATLAS L100; MASTER_PROFILE_CATALOG 1.1-1.4")
    board("BHB42603", "NoPic (stock CVCtrl board-name logic)", ["stock corpus"],
          "EEPROM_TEMPLATE_ATLAS L100; stock DAT_005266d8 NoPic classes")
    board("BHB42631", "NoPic", ["stock corpus"], "EEPROM_TEMPLATE_ATLAS L100")
    board("BHB42651", "NoPic", ["stock corpus"], "EEPROM_TEMPLATE_ATLAS L100")
    board("BHB42621", "unknown-unmapped", [],
          "EEPROM_TEMPLATE_ATLAS L100 (BM1362 S19j Pro air-cooled row; PIC class not yet adjudicated)")
    board("BHB42641", "unknown-unmapped", [], "EEPROM_TEMPLATE_ATLAS L100 (same row)")
    board("BHB42611", "NoPic", ["S19j Pro+ / S19a Pro class per catalog"],
          "EEPROM_TEMPLATE_ATLAS L103 (MASTER_PROFILE_CATALOG 1.10); stock NoPic class list")
    board("BHB42632", "NoPic", ["stock corpus"], "stock DAT_005266d8 NoPic classes")
    board("BHB42811", "NoPic (x19_J sub-layout class BHB42801/811/821)", ["S19j class"],
          "EEPROM_TEMPLATE_ATLAS L16 + stock class list")
    board("BHB42821", "NoPic (x19_J)", ["S19j class"], "EEPROM_TEMPLATE_ATLAS L16")
    board("BHB42831", "NoPic", ["stock corpus"], "stock class list")
    board("BHB42841", "NoPic", ["stock corpus"], "stock class list")
    board("BHB42612", "NoPic", ["am3-s19jproplus (S19j Pro+)"],
          "2026-08-09 s19jproplus campaign exact-identity (3x120); Bosminer NoPic roster")
    board("BHB42751", "unknown-unmapped", ["S19j Pro+ (A1b table; no levels.json sample)"],
          "EEPROM_TEMPLATE_ATLAS L104")
    board("BHB42501", "unknown-unmapped", ["S19j Pro A"], "EEPROM_TEMPLATE_ATLAS L105")
    board("BHB42511", "unknown-unmapped", ["S19j Pro A"], "EEPROM_TEMPLATE_ATLAS L105")
    board("BHB42521", "unknown-unmapped", ["S19j Pro A"], "EEPROM_TEMPLATE_ATLAS L105")

    atlas = {
        "schema": "dcentos.s19jpro-hashboard-atlas/v1",
        "campaign_id": "s19j-pro-complete-enablement-20260826",
        "rule": (
            "READ-ONLY: EEPROM 0x50-0x57 writes forbidden at HAL on am2/am3 "
            "lanes; atlas entries are decode/identity facts only"
        ),
        "eeprom_cipher": {
            "preamble": "0x04 0x11",
            "cipher": "XXTEA",
            "layouts": ["x19_plain (layout 0x4)", "x19_J (sub-layout)"],
            "source": "EEPROM_TEMPLATE_ATLAS.md + BOSMINER_EEPROM_PARSERS_RE.md",
        },
        "boards": boards,
        "open_items": [
            "O-ATLAS-1: BHB42xxx live hex dumps still absent (x19_J known-plaintext vs XXTEA key) - capture from .139 remains the atlas GAP (Phase B P0)",
            "O-1: XIL total chip count discrepancy (skus 252 vs 3x126) owned by xil-full-chain-init",
        ],
    }
    (ev / "hashboard-atlas.json").write_text(
        json.dumps(atlas, indent=1) + "\n", encoding="utf-8"
    )
    (ev / "analysis.md").write_text(
        "# hashboard-revision-atlas analysis\n\n"
        "Desk consolidation only; no EEPROM was written or re-read. The campaign\n"
        "hashboard-atlas.json consolidates every S19j-family BHB class from\n"
        "EEPROM_TEMPLATE_ATLAS.md (L100-105 + L16), the stock CVCtrl NoPic class\n"
        "lists, and the 2026-08-09 S19j Pro+ exact-identity campaign (BHB42612).\n"
        "PIC-class unmapped rows are recorded as unknown-unmapped rather than\n"
        "guessed. EEPROM_TEMPLATE_ATLAS.md gains a campaign cross-reference\n"
        "section (same change-set). Read-only rule restated in the JSON.\n",
        encoding="utf-8",
    )


def main() -> None:
    stage_unlock_surface()
    stage_hashboard_atlas()
    print("staged both evidence dirs under", EVIDENCE)


if __name__ == "__main__":
    main()
