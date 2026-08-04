//! Pure hashrate-from-geometry math (decade backlog P2-9).
//!
//! # Why
//!
//! SV2 Standard-channel selection and pool difficulty seeding historically
//! defaulted to S9 ~13.5 TH/s. Multi-TH platforms must seed from **geometry**
//! (chips × frequency × GH/s per MHz), not a product-name default.
//!
//! [`MinerProfile::nominal_hashrate_ghs`] uses full profile geometry
//! (`chain_count × chips_per_chain`). Live enumeration may disagree with the
//! profile (missing boards, partial enum). Engines should prefer
//! [`nominal_hashrate_ghs_from_geometry`] with the **enumerated** chip total
//! when available, then fall back to profile, then refuse fabricated rates.
//!
//! # Status
//!
//! **Production pure math** — HAL-free, host-testable. Callers still own
//! frequency choice and ghs_per_mhz provenance (profile vs silicon table).

/// Single-chip hashrate at `freq_mhz` given linear `ghs_per_mhz`.
///
/// Returns `None` for non-positive / non-finite inputs (fail-closed).
pub fn chip_hashrate_ghs(freq_mhz: u16, ghs_per_mhz: f64) -> Option<f64> {
    if freq_mhz == 0 || !ghs_per_mhz.is_finite() || ghs_per_mhz <= 0.0 {
        return None;
    }
    let ghs = f64::from(freq_mhz) * ghs_per_mhz;
    if ghs.is_finite() && ghs > 0.0 {
        Some(ghs)
    } else {
        None
    }
}

/// Device nominal GH/s from **total enumerated (or planned) chips**.
///
/// `total_chips` is sum across all energized/responding chains — not a
/// marketing product name. Returns `None` when geometry cannot support a
/// positive finite rate (refuse fabricated multi-TH Standard SV2 seeds).
pub fn nominal_hashrate_ghs_from_geometry(
    total_chips: u32,
    freq_mhz: u16,
    ghs_per_mhz: f64,
) -> Option<f32> {
    if total_chips == 0 {
        return None;
    }
    let per_chip = chip_hashrate_ghs(freq_mhz, ghs_per_mhz)?;
    let ghs = f64::from(total_chips) * per_chip;
    if !ghs.is_finite() || ghs <= 0.0 {
        return None;
    }
    Some(ghs as f32)
}

/// Sum per-chain chip counts into a single geometry total.
///
/// Empty slice or all-zero chains → `0` (caller maps to fail-closed nominal).
pub fn total_chips_from_per_chain(chips_per_chain: &[u32]) -> u32 {
    chips_per_chain
        .iter()
        .fold(0u32, |acc, &n| acc.saturating_add(n))
}

/// Profile-style geometry: `chain_count × chips_per_chain`.
///
/// Saturating; returns `None` only when either factor is zero (same refuse
/// semantics as profile nominal).
pub fn total_chips_from_profile_geometry(chain_count: u8, chips_per_chain: u8) -> Option<u32> {
    if chain_count == 0 || chips_per_chain == 0 {
        return None;
    }
    Some(u32::from(chain_count).saturating_mul(u32::from(chips_per_chain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_hashrate_refuses_zero_freq_or_rate() {
        assert!(chip_hashrate_ghs(0, 0.1).is_none());
        assert!(chip_hashrate_ghs(500, 0.0).is_none());
        assert!(chip_hashrate_ghs(500, f64::NAN).is_none());
        assert!(chip_hashrate_ghs(500, -1.0).is_none());
    }

    #[test]
    fn chip_hashrate_is_linear_in_freq() {
        let a = chip_hashrate_ghs(400, 0.05).unwrap();
        let b = chip_hashrate_ghs(800, 0.05).unwrap();
        assert!((b - 2.0 * a).abs() < 1e-9);
    }

    #[test]
    fn geometry_nominal_scales_with_chip_count() {
        // 63 chips × 650 MHz × ~0.33 GH/s/MHz ≈ S9-class order of magnitude
        let one = nominal_hashrate_ghs_from_geometry(63, 650, 0.33).unwrap();
        let two_boards = nominal_hashrate_ghs_from_geometry(126, 650, 0.33).unwrap();
        assert!((two_boards - 2.0 * one).abs() < 1.0);
        assert!(one > 10_000.0); // well above SV2 Standard 1 TH/s footgun band for multi-chip
    }

    #[test]
    fn geometry_nominal_refuses_empty_enum() {
        assert!(nominal_hashrate_ghs_from_geometry(0, 525, 0.2).is_none());
        assert!(nominal_hashrate_ghs_from_geometry(100, 0, 0.2).is_none());
    }

    #[test]
    fn total_chips_from_per_chain_sums_and_saturates_zero() {
        assert_eq!(total_chips_from_per_chain(&[]), 0);
        assert_eq!(total_chips_from_per_chain(&[0, 0]), 0);
        assert_eq!(total_chips_from_per_chain(&[63, 63, 0]), 126);
    }

    #[test]
    fn profile_geometry_total_matches_product() {
        assert_eq!(total_chips_from_profile_geometry(3, 63), Some(189));
        assert!(total_chips_from_profile_geometry(0, 63).is_none());
        assert!(total_chips_from_profile_geometry(3, 0).is_none());
    }

    #[test]
    fn enumerated_partial_board_is_lower_than_full_profile() {
        // Profile claims 3×63; live enum only 2 boards.
        let profile = total_chips_from_profile_geometry(3, 63).unwrap();
        let live = total_chips_from_per_chain(&[63, 63]);
        assert!(live < profile);
        let ghs_profile = nominal_hashrate_ghs_from_geometry(profile, 525, 0.25).unwrap();
        let ghs_live = nominal_hashrate_ghs_from_geometry(live, 525, 0.25).unwrap();
        assert!(ghs_live < ghs_profile);
    }

    /// Structural pin: daemon post-enum paths seed stratum via enumerated chips.
    #[test]
    fn daemon_post_enum_paths_wire_enumerated_stratum_nominal() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let config = std::fs::read_to_string(root.join("dcentrald/src/config.rs")).expect("config");
        for needle in [
            "fn build_stratum_config_with_enumerated_chips",
            "fn resolve_stratum_nominal_hashrate",
            "fn enumerated_nominal_hashrate_ghs",
            "resolve_nominal_hashrate_ghs_with_geometry",
            "nominal_hashrate_ghs_from_geometry",
        ] {
            assert!(
                config.contains(needle),
                "config.rs must ship `{needle}` (P2-9 post-enum fill)"
            );
        }
        for (rel, extra) in [
            (
                "dcentrald/src/daemon.rs",
                "build_stratum_config_with_enumerated_chips",
            ),
            (
                "dcentrald/src/stock_mining.rs",
                "build_stratum_config_with_enumerated_chips",
            ),
            (
                "dcentrald/src/serial_mining.rs",
                "build_stratum_config_with_enumerated_chips",
            ),
            (
                "dcentrald/src/s19j_hybrid_mining.rs",
                "build_stratum_config_with_enumerated_chips",
            ),
        ] {
            let src =
                std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert!(
                src.contains(extra),
                "{rel} must call {extra} after chip geometry is known"
            );
        }
        // Hybrid captures live unique enum into live_enumerated_chips.
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        assert!(
            hybrid.contains("live_enumerated_chips"),
            "hybrid must track live_enumerated_chips for post-enum nominal"
        );
        // Standard daemon sums mining chain chip_count after init.
        let daemon = std::fs::read_to_string(root.join("dcentrald/src/daemon.rs")).expect("daemon");
        assert!(
            daemon.contains("enumerated_total_chips") && daemon.contains("filter(|c| c.mining)"),
            "daemon must sum mining chain chip_count for enumerated_total_chips"
        );
    }
}
