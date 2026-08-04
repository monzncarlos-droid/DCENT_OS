//! UB-25 / H2 §G-2: chain address stride is DECLARED board data with the
//! historical `floor(256/N)` computation retained as the fallback.
//!
//! Every assertion here fails without the declared-stride SSOT in
//! `dcentrald_common::chain_transport`. The load-bearing property is that
//! *nothing a working board does today changes*: `bm1397plus_addr_interval`
//! stays byte-identical and every DCENT live-proven chip count still resolves
//! to exactly the value it resolved to before.

use dcentrald_common::chain_transport::{
    addr_interval_last_address, bitmain_jig_addr_interval, bm1397plus_addr_interval,
    declared_addr_interval_for_sku, plan_declared_full_population_address_ladder,
    resolve_addr_interval, AddrIntervalError, AddrIntervalSource, TransportOp,
    DECLARED_ADDR_INTERVALS, UNRESOLVED_ADDR_INTERVAL_SKUS,
};

/// The whole point of the change: the two catalog-`Exact` rows the queue named
/// resolve to the corroborated `2`, not the formula's `3`.
///
/// Fails without the change — `resolve_addr_interval` would not exist, and the
/// only stride available for these boards was `bm1397plus_addr_interval` = 3.
#[test]
fn the_two_exact_catalog_rows_resolve_to_the_corroborated_stride() {
    // S19k Pro, BHB56902, 77 chips.
    let d = resolve_addr_interval(Some("BHB56902"), 77).expect("s19kpro stride");
    assert_eq!(d.interval, 2, "BHB56902 stride");
    assert_eq!(d.source, AddrIntervalSource::BoardDeclared);
    assert_eq!(d.last_address, 152); // 76 * 2
    assert_ne!(
        d.interval,
        bm1397plus_addr_interval(77),
        "declared stride must differ from the formula here, or the row is pointless"
    );

    // S21 Pro, A3HB70601-family, 65 chips.
    let d = resolve_addr_interval(Some("A3HB70603"), 65).expect("s21pro stride");
    assert_eq!(d.interval, 2, "A3HB70603 stride");
    assert_eq!(d.source, AddrIntervalSource::BoardDeclared);
    assert_eq!(d.last_address, 128); // 64 * 2
    assert_ne!(d.interval, bm1397plus_addr_interval(65));
}

/// Regression fence: the fallback formula is untouched, so no board that
/// enumerates today can change behaviour.
#[test]
fn the_fallback_formula_is_byte_identical_to_the_shipped_ssot() {
    assert_eq!(bm1397plus_addr_interval(126), 2); // S19j Pro, live-proven
    assert_eq!(bm1397plus_addr_interval(108), 2); // S21 .135, live-proven
    assert_eq!(bm1397plus_addr_interval(77), 3); // unchanged formula value
    assert_eq!(bm1397plus_addr_interval(64), 4);
    assert_eq!(bm1397plus_addr_interval(1), 1); // one-chip rule, not wrap-to-0
    assert_eq!(bm1397plus_addr_interval(0), 1); // empty chain, no divide-by-zero
}

/// Unknown / absent SKUs take the fallback. This is the path every wired
/// production caller is on, and it must stay identical to today.
#[test]
fn unknown_and_absent_skus_take_the_computed_fallback() {
    for (sku, n) in [
        (None, 126u8),
        (Some("BHB42601"), 126), // real SKU, declares nothing
        (Some("NOT-A-SKU"), 126),
        (None, 108),
        (Some("BHB68606"), 108), // S21, all sources already agree
    ] {
        let d = resolve_addr_interval(sku, n).expect("fallback resolves");
        assert_eq!(
            d.source,
            AddrIntervalSource::ComputedFallback,
            "{sku:?}/{n} must fall back"
        );
        assert_eq!(d.interval, bm1397plus_addr_interval(n), "{sku:?}/{n}");
    }
}

/// Every DCENT live-proven enumeration keeps its exact historical stride.
#[test]
fn live_proven_chains_are_bit_for_bit_unchanged() {
    // S19j Pro `a lab unit` / `a lab unit`: 126 chips. S21 `a lab unit`: 108 chips.
    for n in [126u8, 108] {
        let d = resolve_addr_interval(None, n).expect("live chain resolves");
        assert_eq!(d.interval, 2);
        assert_eq!(d.source, AddrIntervalSource::ComputedFallback);
        let declared = plan_declared_full_population_address_ladder(None, n).expect("ladder");
        assert_eq!(declared.len(), n as usize);
        assert_eq!(
            declared.last(),
            Some(&TransportOp::SendSetAddressBm1397Plus {
                addr: (n as u16 - 1) as u8 * 2
            })
        );
    }
}

/// The Bitmain jig bucket rule, decompile-verified in four family binaries.
#[test]
fn bitmain_jig_bucket_matches_the_decompiled_ladder() {
    // N > 128 -> 1
    assert_eq!(bitmain_jig_addr_interval(129), Some(1));
    assert_eq!(bitmain_jig_addr_interval(200), Some(1));
    // 64 < N <= 128 -> 2  (126, 108, 84, 77, 65 all land here)
    for n in [65u8, 77, 84, 88, 91, 108, 110, 114, 120, 126, 128] {
        assert_eq!(bitmain_jig_addr_interval(n), Some(2), "N={n}");
    }
    // 32 < N <= 64 -> 4
    for n in [33u8, 36, 55, 64] {
        assert_eq!(bitmain_jig_addr_interval(n), Some(4), "N={n}");
    }
    // N <= 32 -> the jig refuses; DCENT keeps serving these from the fallback.
    for n in [0u8, 1, 32] {
        assert_eq!(bitmain_jig_addr_interval(n), None, "N={n}");
    }
}

/// Admission rule: every declared row must be corroborated by the jig bucket
/// AND must actually disagree with the fallback (otherwise it is dead weight).
#[test]
fn every_declared_row_is_jig_corroborated_and_beats_the_formula() {
    assert_eq!(DECLARED_ADDR_INTERVALS.len(), 12, "declared roster size");
    for row in DECLARED_ADDR_INTERVALS {
        assert_eq!(
            bitmain_jig_addr_interval(row.chips_per_chain),
            Some(row.interval),
            "{}: declared stride must equal the Bitmain jig bucket",
            row.sku
        );
        assert_ne!(
            row.interval,
            bm1397plus_addr_interval(row.chips_per_chain),
            "{}: a declared row that agrees with the fallback is redundant",
            row.sku
        );
        assert!(
            addr_interval_last_address(row.chips_per_chain, row.interval).is_some(),
            "{}: declared stride must fit the address space",
            row.sku
        );
    }
    // All twelve are the 3 -> 2 correction.
    assert!(DECLARED_ADDR_INTERVALS.iter().all(|r| r.interval == 2));
}

/// The 36-chip board stays UNRESOLVED on the fallback and is never declared.
/// Guards against a future pass "tidying" a three-way split into a guess.
#[test]
fn the_three_way_split_board_stays_on_the_fallback() {
    assert_eq!(UNRESOLVED_ADDR_INTERVAL_SKUS, &["A3HB40601"]);
    assert_eq!(declared_addr_interval_for_sku("A3HB40601"), None);
    let d = resolve_addr_interval(Some("A3HB40601"), 36).expect("resolves");
    assert_eq!(d.source, AddrIntervalSource::ComputedFallback);
    assert_eq!(d.interval, 7, "fallback floor(256/36)");
    // Documented split: jig says 4, ePIC says 2, we compute 7. One source is
    // not enough to declare, and a stride may never be invented.
    assert_eq!(bitmain_jig_addr_interval(36), Some(4));
    assert_ne!(d.interval, 4);
}

/// The 55-chip family is where ePIC alone is WRONG: jig and fallback both say
/// 4. Nothing is declared, and the fallback already yields the jig value.
#[test]
fn the_55_chip_family_shows_epic_alone_is_not_authority() {
    for sku in ["A3HB70701", "A3HB70702", "A3HB70703"] {
        assert_eq!(declared_addr_interval_for_sku(sku), None, "{sku}");
        let d = resolve_addr_interval(Some(sku), 55).expect("resolves");
        assert_eq!(d.source, AddrIntervalSource::ComputedFallback);
        assert_eq!(d.interval, 4);
        assert_eq!(bitmain_jig_addr_interval(55), Some(4));
    }
}

/// The address-space gate is `(N-1) × stride ≤ 255`, not `N × stride ≤ 255`.
/// A 128-chip chain at stride 2 tops out at 254 and is legal — the naive form
/// would refuse it, and the Bitmain jig explicitly admits it.
#[test]
fn address_space_gate_uses_last_address_not_n_times_stride() {
    assert_eq!(addr_interval_last_address(128, 2), Some(254));
    assert_eq!(128u16 * 2, 256, "the naive gate would have refused this");
    let d = resolve_addr_interval(None, 128).expect("128 chips at stride 2 is legal");
    assert_eq!(d.interval, 2);
    assert_eq!(d.last_address, 254);

    assert_eq!(addr_interval_last_address(0, 9), Some(0));
    assert_eq!(addr_interval_last_address(1, 255), Some(0));
    assert_eq!(addr_interval_last_address(2, 255), Some(255));
    assert_eq!(addr_interval_last_address(3, 255), None);
}

/// Fail closed: an unaddressable plan must be an error, never a wrapped ladder
/// that aliases two chips onto one address.
#[test]
fn unaddressable_plans_fail_closed_instead_of_aliasing() {
    // 200 chips at the declared-style stride 2 -> last address 398, overflow.
    // Reached through the ladder planner, which must refuse before emitting.
    let err = plan_declared_full_population_address_ladder(Some("BHB56902"), 200)
        .expect_err("must refuse");
    assert!(matches!(
        err,
        AddrIntervalError::AddressSpaceOverflow {
            chip_count: 200,
            interval: 2,
            last_address: 398,
        }
    ));
    assert!(err.to_string().contains("overflows the 8-bit"));

    let err = resolve_addr_interval(Some("A3HB70601"), 255).expect_err("must refuse");
    assert!(matches!(
        err,
        AddrIntervalError::AddressSpaceOverflow { .. }
    ));
}

/// The declared ladder is the same shape as the legacy one — only the stride
/// source differs — so an adopter cannot silently change the op sequence.
#[test]
fn declared_ladder_shape_matches_the_legacy_planner() {
    let ladder =
        plan_declared_full_population_address_ladder(Some("BHB56902"), 77).expect("s19kpro ladder");
    assert_eq!(ladder.len(), 77);
    assert_eq!(
        ladder.first(),
        Some(&TransportOp::SendSetAddressBm1397Plus { addr: 0 })
    );
    assert_eq!(
        ladder.last(),
        Some(&TransportOp::SendSetAddressBm1397Plus { addr: 152 })
    );
    assert!(ladder
        .iter()
        .all(|op| matches!(op, TransportOp::SendSetAddressBm1397Plus { .. })));
}

#[test]
fn source_labels_are_stable_for_telemetry() {
    assert_eq!(AddrIntervalSource::BoardDeclared.as_str(), "board_declared");
    assert_eq!(
        AddrIntervalSource::ComputedFallback.as_str(),
        "computed_fallback_256_over_n"
    );
}
