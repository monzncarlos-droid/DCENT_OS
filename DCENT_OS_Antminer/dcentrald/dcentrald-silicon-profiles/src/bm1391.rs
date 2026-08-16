//! BM1391 data-only silicon profile for S11/S15/T15 scaffolds.
//!
//! The BM1391 ASIC driver remains scaffold-gated and production-unregistered.
//! This module records the host-testable geometry split so S15/T15 metadata can
//! stop borrowing S9 geometry while still refusing live mining by default.

use crate::{Profile, ProfileSource, SiliconTable};

/// BM1391 numeric chip ID from the S11/S15/T15 family catalog.
pub const BM1391_CHIP_ID: u32 = 0x0000_1391;

/// SHA-256 cores per BM1391 chip. **Jig-stated: 256.**
///
/// Source: Bitmain's S17 factory `single-board-test`, whose three BM1391 board
/// paths (`single_BM1391`, `BHB91601`, `BHB91603`) all pass `256` to
/// `calculate_core_number` (the argument is the real count; the fn rounds up to
/// a power of two). Cross-anchored in the same binary by BM1397=672 and
/// BM1385=50, both of which match independently-known values. See the module
/// doc for the full adjudication of the old "128 vs 114" mis-attribution.
pub const BM1391_CORE_NUM: u32 = 256;

/// HashSource S11 jig geometry.
///
/// ⚠️ **Two jigs disagree about the S11 board — do NOT "fix" one to match the
/// other.** This value comes from the HashSource S11 jig. Bitmain's own AMTC
/// jig config for the same product,
///
/// (`Name=S11 HASH board`), declares something different on **two** axes:
///
/// | source | chip | chips/board | cores |
/// |---|---|---|---|
/// | HashSource S11 jig (this constant) | BM1391 (`0x1391`) | **84** | — |
/// | AMTC `Config.ini-V11-S` | **`AsicType=1390`** | **60** | `CoreNum=128` |
///
/// Note `84` is also exactly S9+'s `AsicNum` (`Config.ini-S9+`), the same
/// copy-across shape that produced the false T9+ "63" in
/// `research/models/:26` — so this value is *suspect*,
/// not merely unconfirmed. It is left unchanged because the BM1391 driver is
/// scaffold-gated and production-unregistered (nothing enumerates from it), and
/// because guessing which jig describes the shipped board would be exactly the
/// error being documented.
///
/// ## The "BM1391 core count 128 vs 114" question is CLOSED — both sides are
/// mis-attributed (desk-settled 2026-08-06)
///
/// Neither number is a BM1391 fact. They belong to two *different* other chips:
///
/// - **`128`** comes from `Config.ini-V11-S`, whose own `AsicType` is
///   **1390, not 1391** (`Config.ini-single-BM1390P` agrees: `1390`/`128`).
///   That is a **BM1390** fact.
/// - **`114`** comes from "the S11 jig" —
///   ,
///   which hardcodes `calculate_core_number(114)` in four call sites
///   (`process_config@1AB6C`, `GetBandValue@2B978`, `set_time_control_by_frq@13AB8`,
///   `singleBoardTest@2D274`). **But that binary is not an S11 jig.** Classified
///   by its own lineage rather than its folder name, it self-identifies as
///   `"Miner Type = S9+"` — its *only* `Miner Type` literal — and exports
///   `set_Voltage_S9_plus_plus_BM1387_54`. Its `BM13xx` strings are `BM1387`
///   only; there is no `BM1390`/`BM1391` string anywhere in it. The sole genuine
///   S11 content is `/etc/config/S11_power_type` and one low-power-mode
///   frequency message. So `114` is a **BM1387** fact.
///
/// **CORE COUNT SETTLED 2026-08-06: BM1391 = 256 cores.** An earlier version of
/// this note said "no held artifact states a BM1391 core count at all" — that
/// was wrong; the artifact was simply in a different jig. Bitmain's **S17**
/// factory jig (
/// single-board-test.dec`) has three BM1391 board paths — `single_BM1391`,
/// `BHB91601`, `BHB91603` — and **all three** call
/// `calculate_core_number(256u)` in their `*_calculate_timeout_and_baud`
/// functions. That jig's `calculate_core_number` rounds its argument up to a
/// power of two, so the **argument is the true core count**. Two independent
/// anchors in the same binary confirm the reading: `single_BM1397` passes
/// `672` (matches the host-metadata "BM1397/BM1398 = 672 cores") and
/// `single_BM1385` passes `50` (matches `bm1385.rs`
/// `BM1385_CORES_PER_CHIP = 50`).
///
/// So the historical "128 vs 114" debate was doubly mis-attributed AND had the
/// wrong answer: BM1391 is **256**, matching neither prior candidate.
/// [`BM1391_CORE_NUM`] carries it; `BM1391_PROFILES` still has no power/voltage
/// row (those are genuinely unheld), so the table stays `NamedOnly`.
///
/// This also supplies the **mechanism** for the `84` above: that same
/// S9+-lineage binary is the "HashSource S11 jig", and `84` is exactly S9+'s
/// `AsicNum` (`Config.ini-S9+`). The copy-across is no longer merely suspected.
///
/// Residual: the BM1391 *chips-per-chain* (this `84`) and its power/voltage
/// envelope remain unsettled. The **core count** is no longer a residual — it
/// was found in the S17 jig (see [`BM1391_CORE_NUM`]); the technique that
/// settled BM1385 turned out to apply to a jig we already hold, just not the
/// mislabelled `S11/` one.
pub const BM1391_CHIPS_PER_CHAIN_S11_JIG: u32 = 84;

/// Bitmain AMTC `Config.ini-V11-S` (`Name=S11 HASH board`) readings, retained
/// verbatim so the disagreement above is machine-checkable rather than prose.
/// **Not** a claim about BM1391 — the config's own `AsicType` is `1390`.
pub const AMTC_V11_S_ASIC_TYPE: u32 = 1390;

/// The core count hardcoded by `bitmain-antminer-binaries/S11/single-board-test`
/// (`calculate_core_number(114)`, four call sites).
///
/// Retained as a **BM1387** fact, because that binary self-identifies as
/// `"Miner Type = S9+"`. It is recorded here only so the historical
/// "BM1391 = 114 cores" misreading stays refuted in code rather than in prose.
pub const S11_DIR_JIG_HARDCODED_CORE_NUM: u32 = 114;

/// BM1387's real core count, for the comparison that proves the point above.
#[cfg(test)]
const BM1387_CORE_NUM: u32 = 114;
/// See [`AMTC_V11_S_ASIC_TYPE`]. `AsicNum` from the same config.
pub const AMTC_V11_S_CHIPS_PER_BOARD: u32 = 60;
/// See [`AMTC_V11_S_ASIC_TYPE`]. `CoreNum` from the same config.
pub const AMTC_V11_S_CORE_NUM: u32 = 128;

/// S15 physical geometry remains unresolved. The official guide states
/// 12 domains × 5 = 60 twice, but its LDO paragraph says six chips per domain
/// (12 × 6 = 72), while the exact held S15 cgminer enforces 72 valid replies.
pub const BM1391_CHIPS_PER_CHAIN_S15_SCAFFOLD: Option<u32> = None;

/// T15 physical geometry remains unheld. Its cgminer selects a `60`-named test
/// pattern, but the S15 counterexample proves that selector labels are not
/// physical topology authority.
pub const BM1391_CHIPS_PER_CHAIN_T15_SCAFFOLD: Option<u32> = None;

/// No family-wide chain count may be inferred from the S15's exact 3-chain
/// product topology.
pub const BM1391_CHAIN_COUNT: Option<u32> = None;

/// Single refusal-sentinel host row. No held source establishes a safe S15 or
/// T15 default PLL frequency or voltage, so both setpoints remain zero and the
/// table stays `NamedOnly`.
pub const BM1391_PROFILES: [Profile; 1] = [Profile {
    step: 0,
    freq_mhz: 0,
    voltage_v: 0.0,
    wall_watts: None,
    hashrate_ths: None,
    source: ProfileSource::VendorExtracted,
}];

pub const BM1391_TABLE: SiliconTable = SiliconTable {
    chip_family: "BM1391",
    profiles: &BM1391_PROFILES,
    default_step: 0,
    sweet_spot_step: 0,
    live_status: crate::ChipStatus::NamedOnly,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1391_scaffold_geometry_is_explicit() {
        assert_eq!(BM1391_CHIP_ID, 0x1391);
        assert_eq!(BM1391_CHAIN_COUNT, None);
        assert_eq!(BM1391_CHIPS_PER_CHAIN_S11_JIG, 84);
        // Conflicting S15 guide/binary evidence and T15 physical geometry both
        // stay non-authoritative.
        assert_eq!(BM1391_CHIPS_PER_CHAIN_S15_SCAFFOLD, None);
        assert_eq!(BM1391_CHIPS_PER_CHAIN_T15_SCAFFOLD, None);
        assert_eq!(BM1391_PROFILES[0].freq_mhz, 0);
        assert_eq!(BM1391_PROFILES[0].voltage_v, 0.0);
    }

    /// The two S11 jig sources genuinely disagree. This pins BOTH readings so
    /// nobody can quietly reconcile them by editing one side: any such edit
    /// fails here and forces the adjudication to be made explicitly.
    ///
    /// See the doc on [`BM1391_CHIPS_PER_CHAIN_S11_JIG`] for the full table.
    #[test]
    fn s11_jig_sources_disagree_and_the_disagreement_is_pinned() {
        // Bitmain AMTC `Config.ini-V11-S`, verbatim.
        assert_eq!(AMTC_V11_S_ASIC_TYPE, 1390);
        assert_eq!(AMTC_V11_S_CHIPS_PER_BOARD, 60);
        assert_eq!(AMTC_V11_S_CORE_NUM, 128);

        // The disagreement itself is the load-bearing fact.
        assert_ne!(
            AMTC_V11_S_CHIPS_PER_BOARD, BM1391_CHIPS_PER_CHAIN_S11_JIG,
            "if these ever agree, one side was edited without evidence"
        );
        assert_ne!(
            AMTC_V11_S_ASIC_TYPE,
            BM1391_CHIP_ID & 0xFFFF,
            "AMTC calls the S11 board AsicType=1390, not 0x1391"
        );

        // Guard the category error: 128 cores is evidenced for the AsicType=1390
        // config, so it must never be silently promoted into a BM1391 fact.
        assert_eq!(
            AMTC_V11_S_ASIC_TYPE, 1390,
            "CoreNum=128 belongs to the 1390 config; do not attribute it to BM1391"
        );
    }

    /// Both sides of the historical "BM1391 core count 128 vs 114" question are
    /// mis-attributed. This pins the refutation so neither number can be quietly
    /// promoted into a BM1391 fact.
    #[test]
    fn neither_128_nor_114_is_a_bm1391_core_count() {
        // `128` belongs to the AsicType=1390 config.
        assert_eq!(AMTC_V11_S_ASIC_TYPE, 1390);
        assert_eq!(AMTC_V11_S_CORE_NUM, 128);

        // `114` belongs to a binary that self-identifies as "Miner Type = S9+"
        // and exports set_Voltage_S9_plus_plus_BM1387_54 -- i.e. BM1387 silicon,
        // despite living in a directory named `S11/`.
        assert_eq!(S11_DIR_JIG_HARDCODED_CORE_NUM, BM1387_CORE_NUM);

        // The two candidates are not even the same number, which is precisely
        // why treating either as "the" BM1391 count was never sound.
        assert_ne!(AMTC_V11_S_CORE_NUM, S11_DIR_JIG_HARDCODED_CORE_NUM);

        // The real BM1391 core count (256, from the S17 jig) matches NEITHER
        // historical candidate — the debate had the wrong answer, not just the
        // wrong attribution.
        assert_eq!(BM1391_CORE_NUM, 256);
        assert_ne!(BM1391_CORE_NUM, AMTC_V11_S_CORE_NUM);
        assert_ne!(BM1391_CORE_NUM, S11_DIR_JIG_HARDCODED_CORE_NUM);

        // BM1391 POWER geometry must stay unknown: the profile carries no power
        // or hashrate claim, and the table stays NamedOnly. Core count being
        // known does not unlock energization.
        let row = BM1391_TABLE.default_profile().expect("row");
        assert_eq!(row.wall_watts, None);
        assert_eq!(row.hashrate_ths, None);
        assert_eq!(BM1391_TABLE.live_status, crate::ChipStatus::NamedOnly);
    }

    /// BM1391 = 256 cores, jig-stated, cross-anchored by the BM1397=672 and
    /// BM1385=50 readings from the same S17 jig binary. Pin the fact and the
    /// two anchors so the reading cannot regress to a prior mis-attribution.
    #[test]
    fn bm1391_core_count_is_the_jig_stated_256() {
        assert_eq!(BM1391_CORE_NUM, 256);
        // The anchors that validate the reading method (argument = true count):
        // documented elsewhere as 672 (BM1397) and 50 (BM1385). If BM1391 ever
        // gets "corrected" back to 128 or 114, this fails.
        assert_ne!(
            BM1391_CORE_NUM, 128,
            "128 was BM1390's count (AsicType=1390)"
        );
        assert_ne!(BM1391_CORE_NUM, 114, "114 was BM1387's count (S9+ jig)");
    }

    /// The whole reason BM1391 = 256 is trustworthy is that the SAME method
    /// (`calculate_core_number(arg)`, where the argument is the true count)
    /// reads BM1385 = 50 and BM1397 = 672 in the SAME S17 jig binary — and both
    /// of those match values established completely independently (BM1385 via
    /// its own open-core loop, BM1397 via the register-init sequence). This
    /// binds all three crate constants so the anchor set cannot silently drift:
    /// if BM1385 or BM1397 is ever edited away from its jig value, the
    /// evidentiary basis for BM1391 = 256 is no longer sound and this fails.
    #[test]
    fn s17_jig_core_count_anchor_set_is_mutually_consistent() {
        use crate::{bm1385, bm1397};

        assert_eq!(bm1385::BM1385_CORES_PER_CHIP, 50, "BM1385 anchor moved");
        assert_eq!(bm1397::BM1397_CORES_PER_CHIP, 672, "BM1397 anchor moved");
        assert_eq!(BM1391_CORE_NUM, 256);

        // All three distinct (the method discriminates, it is not a constant
        // that happens to fit), and BM1391 sits between the anchors as a 7nm
        // mid-generation part should.
        assert!(bm1385::BM1385_CORES_PER_CHIP < BM1391_CORE_NUM);
        assert!(BM1391_CORE_NUM < bm1397::BM1397_CORES_PER_CHIP);
    }

    #[test]
    fn bm1391_profile_is_named_only_and_power_unknown() {
        let row = BM1391_TABLE.default_profile().unwrap();
        assert_eq!(BM1391_TABLE.live_status, crate::ChipStatus::NamedOnly);
        assert_eq!(row.wall_watts, None);
        assert_eq!(row.hashrate_ths, None);
        assert!(row.watts_per_ths().is_none());
    }
}
