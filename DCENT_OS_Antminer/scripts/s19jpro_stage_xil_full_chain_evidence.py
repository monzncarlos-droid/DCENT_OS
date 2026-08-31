#!/usr/bin/env python3
"""Stage the xil-full-chain-init evidence (desk-only)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EV = REPO / ".s19jpro-enablement-evidence/xil-full-chain-init"

ANALYSIS = """# xil-full-chain-init analysis

Pinned deliverable: `DCENT_OS_Antminer/dcentrald/dcentrald/tests/
s19jpro_full_chain_init.rs` (marker `S19JPRO_FULL_CHAIN_126`), written in the
repo's wave54/wave48 source-parse acceptance-test convention.

What the test pins (4 tests, all green):
1. `s19jpro_full_chain_126_roster_metadata_contract` — model.rs
   `s19jproam2` keeps `chips_per_chain_hint: Some(126)` and `s19jproplus`
   keeps `Some(120)`; `dcentrald-silicon-profiles/bm1362.rs` keeps
   `CHIPS_PER_CHAIN: u8 = 126` (live-pinned on .139/.133).
2. `s19jpro_full_chain_126_hybrid_bit8_gate_is_consumed` —
   `s19j_hybrid_mining.rs` consumes `DCENT_AM2_BOARD_CONTROL_BIT8` (the
   2026-06-14 standalone full-roster enum fix).
3. `s19jpro_full_chain_126_standalone_launcher_contract` —
   `run_wave56_25_STANDALONE_MINING.sh` exports the bit8 gate and actively
   `unset`s the four must-not-set env vars (Wave-55a guard list).
4. `s19jpro_full_chain_126_journey_record_exists` — the
   STANDALONE_MINING_JOURNEY.md record carries the 126 evidence and the bit8
   fix reference.

Verification run (2026-08-27 UTC):
- Windows-native host build is impossible for this crate by design
  (dcentrald-hal uses nix/Unix-only APIs; 228 errors) — consistent with the
  repo's convention that daemon test receipts are Linux.
- WSL rustc 1.97.1: `cargo test -p dcentrald --test s19jpro_full_chain_init`
  -> `test result: ok. 4 passed; 0 failed` after full workspace compile.

Scope honesty: this is the source/metadata contract. LIVE full-roster
enumeration on an arbitrary XIL unit (126 unique chip ids per chain at init
without an AC-cycle retry) is proven by the campaign's `xil-bounded-work`
transcript receipt, not by this test. Open item O-1 (skus.conf `S19jPro`
total 252 vs 3x126) is adjudicated by that live roster evidence.
"""


def main() -> None:
    EV.mkdir(parents=True, exist_ok=True)
    (EV / "analysis.md").write_text(ANALYSIS, encoding="utf-8")
    print("staged", EV)


if __name__ == "__main__":
    main()
