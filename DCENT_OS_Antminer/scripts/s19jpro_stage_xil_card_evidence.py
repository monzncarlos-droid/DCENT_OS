#!/usr/bin/env python3
"""Stage the xil-stock-first-install-plan evidence (desk-only)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EV = REPO / ".s19jpro-enablement-evidence/xil-stock-first-install-plan"

ANALYSIS = """# xil-stock-first-install-plan analysis

Pinned deliverable: 
BENCH_CARDS/XIL_STOCK_FIRST_INSTALL.md (marker "OPERATOR BENCH CARD"),
card version 1, 2026-08-27 UTC.

Card content grounding (all verified against sources this session):
- Ladder = the toolbox's own staged plan (am2_first_install.py docstring):
  capsule -> recovery media -> full-NAND backup -> dry-run -> witnessed
  capstone; plan-only, never contacts a miner, never authorizes a write.
- Capsule contract: Ed25519 MANIFEST.sig vs pinned release key; beta ledger
  identity DCENTOS_XIL3_S19jPro_beta20260617.tar sha 0b480552...73cb1, key
  26985575...df83 (root  beta section). The tarball is NOT on disk
  under DCENT_OS_Antminer/output/ today - the card makes re-derivation +
  re-hash an explicit step rather than citing a missing file as authority.
- Safety invariants mirrored from load-bearing rules: fw_setenv-only env
  flips (never raw dd/flash_erase/nandwrite on mtd4), inactive-slot A/B
  writes, degraded-hardware refusals (fw=0x86 dsPIC, EEPROM 0x04 preamble),
  quiet-home posture, separate explicit NAND authorization for the capstone.
- Unlock entry references the campaign unlock ladder (receipt-bound phase
  unlock-surface-closure).

Honest caveats recorded:
1. The toolbox CLI is currently import-broken in the WORKING TREE by a
   PARALLEL SESSION's in-flight WIP (DEVICE_CONTACT_SCAN missing from
   core/discover.py; commands/discover.py imports it). Not a campaign
   change; surfaced, not fixed mid-flight. The card's Step 0 preflight
   (py -3 -m dcent_toolbox --help) guards the bench against executing
   against a broken tree.
2. Card authoring could not run the plan subcommand end-to-end for the same
   reason; the subcommand surface (contract/inspect/plan, args
   --board-target/--source/--capsule, FIRST_INSTALL_TARGETS incl.
   am2-s19jpro-zynq) was verified by source read of am2_first_install.py
   and core/am2_xil_first_install.py.
3. Live steps belong to their own operator phases; this phase closes the
   card-as-deliverable only.
"""


def main() -> None:
    EV.mkdir(parents=True, exist_ok=True)
    (EV / "analysis.md").write_text(ANALYSIS, encoding="utf-8")
    print("staged", EV)


if __name__ == "__main__":
    main()
