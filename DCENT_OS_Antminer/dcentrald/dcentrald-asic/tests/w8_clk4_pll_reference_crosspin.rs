//! W8 CLK-4 — cross-crate pin: the declared per-chip PLL reference
//! (`dcentrald-re-catalog::pll_bible::reference_clock_mhz`, previously
//! "consumed by nothing that enforces cross-platform safety", C1 §4 CLK-4)
//! must agree with the reference the PRODUCTION PLL solvers actually assume
//! (`dcentrald_common::pll_model::PLL_REFERENCE_HZ`).
//!
//! Honest scope: the corpus is uniformly 25 MHz today, so this guards future
//! breakage (a non-25 MHz chip RE'd into pll_bible, or a solver reference
//! edit), not a live bug. Mutation-checked: editing either side alone fails.

use dcentrald_common::pll_model::{
    admit_pll_reference, resolve_pll_for_protocol_on_reference, PLL_REFERENCE_HZ,
};
use dcentrald_re_catalog::pll_bible::PLL_EXPECTATIONS;

/// Every pll_bible row's declared reference must equal the solver SSOT.
/// If a chip with a genuinely different XIN is ever RE'd, this test forces
/// the author to confront the solver assumption instead of silently adding a
/// row the production math would mis-clock.
#[test]
fn every_pll_bible_reference_matches_the_production_solver_reference() {
    assert!(!PLL_EXPECTATIONS.is_empty());
    for row in PLL_EXPECTATIONS {
        assert_eq!(
            u32::from(row.reference_clock_mhz) * 1_000_000,
            PLL_REFERENCE_HZ,
            "pll_bible chip {:#06x} declares reference_clock_mhz={} but the \
             production PLL solvers (dcentrald_common::pll_model) assume {} Hz; \
             a PLL table must not be applied against a mismatched reference \
             (W8 CLK-4)",
            row.chip_id,
            row.reference_clock_mhz,
            PLL_REFERENCE_HZ,
        );
    }
}

/// The runtime gate fails closed on the exact hazard C1 names: a 25 MHz
/// table on a 24 MHz reference would land the hash clock at 24/25 × target.
#[test]
fn mismatched_or_undeclared_reference_is_refused_before_any_lookup() {
    assert!(admit_pll_reference(Some(25_000_000)).is_ok());
    assert!(admit_pll_reference(Some(24_000_000)).is_err());
    assert!(admit_pll_reference(None).is_err());

    use dcentrald_common::board_desc::AsicProtocolIdentity;
    let refused =
        resolve_pll_for_protocol_on_reference(AsicProtocolIdentity::Bm1362, 545, Some(24_000_000));
    assert!(refused.is_err(), "24 MHz XIN must refuse the BM1362 table");
    let admitted = resolve_pll_for_protocol_on_reference(
        AsicProtocolIdentity::Bm1362,
        545,
        Some(PLL_REFERENCE_HZ),
    )
    .expect("declared 25 MHz must be admitted");
    // Live rated 545 MHz row must still resolve exactly as before.
    let sol = admitted.expect("BM1362 family is supported offline");
    assert_eq!(sol.actual_freq_mhz, 545);
}
