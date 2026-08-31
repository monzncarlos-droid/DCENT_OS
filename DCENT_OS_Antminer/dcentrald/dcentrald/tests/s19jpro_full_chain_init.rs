//! S19j Pro campaign (2026-08-26) — XIL full-roster chain enumeration contract.
//!
//! Campaign `s19j-pro-complete-enablement-20260826`, phase
//! `xil-full-chain-init` (pinned marker: `S19JPRO_FULL_CHAIN_126`).
//!
//! History this pins: `a lab unit` XIL bring-up (2026-05-15) enumerated only 28
//! unique chips of the 126-per-chain roster through init, and each XIL attempt
//! needed a fresh AC cycle. The 2026-06-14 standalone fix (board-control
//! `0x42810000 +0x04` bit 8, `DCENT_AM2_BOARD_CONTROL_BIT8`) reached
//! 126-of-126 chips with accepted shares on `a lab unit` — see
//!
//! and memory rule .
//!
//! ## What this test pins
//!
//! 1. The roster metadata is 126 chips/chain for the S19j Pro am2 identity
//!    (`model.rs` `s19jproam2` hint) and 120 for S19j Pro+ — the planner's
//!    source of truth for "full chain".
//! 2. The silicon profile constant agrees (`CHIPS_PER_CHAIN: u8 = 126`,
//!    live-pinned on `a lab unit` / `a lab unit`).
//! 3. The hybrid mining path actually consumes the board-control bit8 gate
//!    (`DCENT_AM2_BOARD_CONTROL_BIT8`) that solved standalone enumeration.
//! 4. The proven standalone launcher exists, exports the bit8 gate, and does
//!    NOT set any of the four must-not-set env vars that re-break the
//!    `a lab unit`-class mining path ( startup-guard list).
//! 5. The standalone journey record exists and carries the 126/126 evidence
//!    pointer.
//!
//! ## Scope honesty
//!
//! This is the source/metadata contract. LIVE full-roster enumeration on an
//! arbitrary XIL unit (126 unique chip ids per chain at init, no AC-cycle
//! retry) is proven by the campaign's `xil-bounded-work` transcript receipt,
//! not by this test. The O-1 open item (skus.conf `S19jPro` total 252 vs
//! 3x126) is adjudicated by the live roster evidence, not here.
//!
//! DO NOT weaken this test: if the launcher, journey doc, or roster metadata
//! change, this forces the change to keep the full-chain contract explicit.
//!
//! Same source-parse rationale as `wave48_dspic_25_bare_path.rs` and
//! `wave54_proven_mining_recipe.rs`: the full contract needs live `a lab unit`-class
//! hardware + operator AC-cycle coordination; source parse is the
//! authoritative regression guard on CI.

const MODEL_RS: &str = include_str!("../src/model.rs");
const HYBRID_RS: &str = include_str!("../src/s19j_hybrid_mining.rs");
const BM1362_RS: &str = include_str!("../../dcentrald-silicon-profiles/src/bm1362.rs");
const LAUNCHER: &str = include_str!("../../../scripts/run_wave56_25_STANDALONE_MINING.sh");
const JOURNEY: &str = include_str!(
    "../../../../../"
);

/// The four env vars that MUST NOT be set on `a lab unit`-class hybrid mining
/// ( `dcentrald` startup guard refuses to start if any is set).
const FORBIDDEN_ENV_VARS: &[&str] = &[
    "DCENT_AM2_PIC_RESET_AND_START_APP",
    "DCENT_AM2_PIC_RESET_STRACE_DERIVED",
    "DCENT_AM2_PSU_LOKI_REGISTER_POINTER",
    "DCENT_AM2_PSU_CALIBRATION_PROBE_WAKE",
];

#[test]
fn s19jpro_full_chain_126_roster_metadata_contract() {
    // 1. `s19jproam2` ModelSpec declares the full 126-chips-per-chain roster.
    let am2_start = MODEL_RS
        .find("\"s19jproam2\" => ModelSpec {")
        .expect("s19jproam2 ModelSpec arm must exist");
    let am2_block = &MODEL_RS[am2_start..am2_start + 600];
    assert!(
        am2_block.contains("chips_per_chain_hint: Some(126)"),
        "s19jproam2 must keep chips_per_chain_hint Some(126); got block:\n{am2_block}"
    );

    // S19j Pro+ keeps its distinct 120 roster (BHB42612, 3x120).
    let plus_start = MODEL_RS
        .find("\"s19jpro+\" | \"s19jproplus\" => ModelSpec {")
        .expect("s19jproplus ModelSpec arm must exist");
    let plus_block = &MODEL_RS[plus_start..plus_start + 600];
    assert!(
        plus_block.contains("chips_per_chain_hint: Some(120)"),
        "s19jproplus must keep chips_per_chain_hint Some(120); got block:\n{plus_block}"
    );

    // 2. Silicon profile agrees (live-pinned on .139 / .133).
    assert!(
        BM1362_RS.contains("pub const CHIPS_PER_CHAIN: u8 = 126;"),
        "bm1362 silicon profile must keep CHIPS_PER_CHAIN = 126"
    );
}

#[test]
fn s19jpro_full_chain_126_hybrid_bit8_gate_is_consumed() {
    // 3. The hybrid path consumes the board-control bit8 enum-fix gate.
    assert!(
        HYBRID_RS.contains("DCENT_AM2_BOARD_CONTROL_BIT8"),
        "s19j_hybrid_mining.rs must consume DCENT_AM2_BOARD_CONTROL_BIT8 \
         (the 2026-06-14 standalone full-roster enum fix)"
    );
}

#[test]
fn s19jpro_full_chain_126_standalone_launcher_contract() {
    // 4a. The proven standalone launcher exists and exports the gate.
    assert!(
        LAUNCHER.contains("export DCENT_AM2_BOARD_CONTROL_BIT8=1"),
        "run_wave56_25_STANDALONE_MINING.sh must export \
         DCENT_AM2_BOARD_CONTROL_BIT8=1"
    );
    // 4b. None of the four must-not-set vars is ever EXPORTED; the launcher
    //     actively scrubs inherited values (unset lines,  guard).
    for forbidden in FORBIDDEN_ENV_VARS {
        assert!(
            !LAUNCHER.contains(&format!("export {forbidden}")),
            "standalone launcher must not export {forbidden} (re-breaks .25-class mining)"
        );
        assert!(
            LAUNCHER.contains(&format!("unset {forbidden}")),
            "standalone launcher must scrub inherited {forbidden} before launch"
        );
    }
}

#[test]
fn s19jpro_full_chain_126_journey_record_exists() {
    // 5. The definitive journey record exists and carries the 126 evidence.
    assert!(
        JOURNEY.contains("126"),
        "STANDALONE_MINING_JOURNEY.md must carry the 126/126 chip evidence"
    );
    assert!(
        JOURNEY.contains("BOARD_CONTROL_BIT8")
            || JOURNEY.contains("bit8")
            || JOURNEY.contains("bit 8"),
        "STANDALONE_MINING_JOURNEY.md must reference the board-control bit8 enum fix"
    );
}
