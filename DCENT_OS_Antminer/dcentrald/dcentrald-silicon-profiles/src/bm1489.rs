//! BM1489 silicon characterization table (Antminer L7 â€” Litecoin
//! scrypt mining, large-scale).
//!
//! # ⚠ CORRECTION (Round 15, 2026-08-07) — this table is **L7-only**
//!
//! Earlier revisions of this file, of `dcentrald-asic/src/drivers/bm1489.rs`,
//! and of `registry.rs:516`'s "Scrypt L3+/L7/L9 chain-rail" comment described
//! BM1489 as the ASIC of **both** the L7 and the L9. The L9 half is wrong.
//!
//! The authentic Bitmain L9 stock image `FR-1.19(260302-L9).bmu`
//! (sha256 `2af05a3465ae8f3bdb32a74058f8beb0c4f9246da409441e09d922f05c3aa827`)
//! unpacks to a plaintext CVitek rootfs whose `etc/topol.conf` states
//! `"asic_id": "BM1491"` / `"chip_type": "0x1491"`, and whose
//! `etc/cgminer.conf.factory` selects `"algo": "ltc_1491"`. Its miner binary
//! carries a dedicated `backend/backend_ltc_1491/` source tree. The L9 is
//! **BM1491**, 3 chains × 110 chips, not BM1489.
//!
//! Nothing below is edited on that basis, because none of it was ever L9
//! evidence: every row here derives from L7 repair-doc / vendor-listing
//! figures. The full transcription of the authentic bytes lives in
//! [`crate::scrypt_stock_topology`] (see `L9_BSL41601`), and the write-up is
//! .
//!
//! # ⚠ The L7 attribution itself is NOT stock-proven
//!
//! The stock L7 image `Antminer-L7-release-202301300939.bmu` was also opened
//! this round. Its boot chain is plaintext (Zynq-7000), but `minerfs.image.gz`,
//! `update.image.gz` and `miner.btm.tar.gz` are **encrypted** (Shannon
//! entropy 7.98 / 7.98 / 7.88, no container magic, no held key). So no
//! Bitmain artifact we hold names the L7's ASIC. "L7 = BM1489" rests solely
//! on third-party VNish binaries (`drivers/bm1489.rs:40`). Treat the
//! identity as third-party-sourced, and the numbers below as
//! `Reconstructed`/`OperatorConfirmed` exactly as their `source` fields say.
//!
//! 5 discrete steps from `-2` (eco-low) to `+2` (overclock). Source
//! provenance:
//! - **`SCRYPT_ASIC_CHIPS.md` Â§2 lines 69-93** (live-confirmed from
//!   repair docs + vendor listings): BM1489 = ~19.8 MH/s per chip,
//!   120 chips per board Ã— 4 boards = 480 chips, 9.5 GH/s nameplate at
//!   3,425 W.
//! - **Reconstructed**: linear extrapolation around the operator-known
//!   nameplate point.
//!
//! Sweet spot at Step -2 (~2,700 W / ~7.6 GH/s â‰ˆ 0.355 W/MH) â€” same
//! underclock-efficient pattern as BM1485.
//!
//! `hashrate_ths` field carries GH/s Ã— 1e-3 (scaled for shared `Profile`
//! struct). E.g. 9.5 GH/s â†’ 0.0095. The display layer multiplies by
//! 1e3 for GH/s in scrypt context.

use crate::{Profile, ProfileSource, SiliconTable};

/// The 5 BM1489 silicon profile rows, ordered by `step`.
///
/// `hashrate_ths` field carries GH/s Ã— 1e-3 (scaled for shared struct).
/// Voltage column is the chain-rail voltage in volts.
pub const BM1489_PROFILES: [Profile; 5] = [
    Profile {
        step: -2,
        freq_mhz: 320,
        voltage_v: 12.5,
        wall_watts: Some(2700),
        hashrate_ths: Some(0.007_6), // 7.6 GH/s
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: -1,
        freq_mhz: 380,
        voltage_v: 12.8,
        wall_watts: Some(3050),
        hashrate_ths: Some(0.008_5), // 8.5 GH/s
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: 0,
        freq_mhz: 425,
        voltage_v: 13.0,
        wall_watts: Some(3425),
        hashrate_ths: Some(0.009_5), // 9.5 GH/s â€” L7 nameplate
        source: ProfileSource::OperatorConfirmed,
    },
    Profile {
        step: 1,
        freq_mhz: 470,
        voltage_v: 13.2,
        wall_watts: Some(3850),
        hashrate_ths: Some(0.010_4), // 10.4 GH/s
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: 2,
        freq_mhz: 510,
        voltage_v: 13.4,
        wall_watts: Some(4300),
        hashrate_ths: Some(0.011_2), // 11.2 GH/s
        source: ProfileSource::Reconstructed,
    },
];

/// Canonical BM1489 silicon table. Default = nameplate (Step 0).
/// Sweet spot at Step -2 (~2,700 W / 7.6 GH/s â‰ˆ 0.355 W/MH).
pub const BM1489_TABLE: SiliconTable = SiliconTable {
    chip_family: "BM1489",
    profiles: &BM1489_PROFILES,
    default_step: 0,
    sweet_spot_step: -2,
    // L7 silicon profile only — no live first-hash on dcentrald.
    // NOT L9: the L9 is BM1491 per its own stock topol.conf (Round 15
    // correction, see this module's header and
    // `crate::scrypt_stock_topology::L9_BSL41601`).
    // Register set partially lifted from VNish hwscan strings
    // ( §9), full register addresses
    // still `[GAP]`. Driver is scaffold-only.
    live_status: crate::ChipStatus::RegisterMappedFromRE,
};

/// Per-chip hashrate at L7 nameplate (per RE doc Â§2 line 80:
/// 9.5 GH/s Ã· 480 chips â‰ˆ 19.8 MH/s).
pub const BM1489_PER_CHIP_HASHRATE_MHS: f32 = 19.8;

/// Standard L7 chips per chain (per RE doc Â§2 line 77).
pub const BM1489_CHIPS_PER_CHAIN_L7: u32 = 120;

/// Standard L7 chain count.
pub const BM1489_CHAIN_COUNT_L7: u32 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_five_steps_in_correct_range() {
        assert_eq!(BM1489_TABLE.profiles.len(), 5);
        assert_eq!(BM1489_TABLE.min_step(), -2);
        assert_eq!(BM1489_TABLE.max_step(), 2);
    }

    #[test]
    fn nameplate_default_step_anchors_l7() {
        // L7 nameplate per RE doc: 9.5 GH/s @ 3,425 W.
        let default = BM1489_TABLE.default_profile().unwrap();
        assert_eq!(default.wall_watts, Some(3425));
        // 9.5 GH/s = 0.0095 in our scaled units.
        assert!((default.hashrate_ths.unwrap() - 0.009_5).abs() < 1e-6);
    }

    #[test]
    fn pre_baked_sweet_spot_matches_computed_minimum() {
        let pre = BM1489_TABLE.sweet_spot_profile().unwrap();
        let computed = BM1489_TABLE.computed_sweet_spot().unwrap();
        assert_eq!(pre.step, computed.step);
    }

    #[test]
    fn underclocked_steps_beat_default_efficiency() {
        let default = BM1489_TABLE.default_profile().unwrap();
        let eff_def = default.watts_per_ths().unwrap();
        for step in [-2, -1] {
            let s = BM1489_TABLE.by_step(step).unwrap();
            let eff = s.watts_per_ths().unwrap();
            assert!(
                eff < eff_def,
                "step {} efficiency ({}) should beat default ({})",
                step,
                eff,
                eff_def
            );
        }
    }

    #[test]
    fn l7_hardware_constants_match_re_doc() {
        assert!((BM1489_PER_CHIP_HASHRATE_MHS - 19.8).abs() < 0.001);
        assert_eq!(BM1489_CHIPS_PER_CHAIN_L7, 120);
        assert_eq!(BM1489_CHAIN_COUNT_L7, 4);
        // 120 Ã— 4 = 480 chips total per RE doc Â§2 line 79.
        assert_eq!(BM1489_CHIPS_PER_CHAIN_L7 * BM1489_CHAIN_COUNT_L7, 480);
    }

    #[test]
    fn step_voltage_increases_with_frequency() {
        for window in BM1489_PROFILES.windows(2) {
            assert!(
                window[1].voltage_v >= window[0].voltage_v,
                "voltage non-monotonic at step {}",
                window[1].step
            );
            assert!(
                window[1].freq_mhz > window[0].freq_mhz,
                "frequency non-monotonic at step {}",
                window[1].step
            );
        }
    }

    /// Round 15 (2026-08-07) NEGATIVE pin: BM1489 must never re-absorb the L9.
    ///
    /// The authentic L9 stock image states `asic_id = BM1491` /
    /// `chip_type = 0x1491`. If a future wave re-widens this table to "L7/L9",
    /// the geometry below would silently mis-describe a 3 × 110 BM1491
    /// machine as a 4 × 120 BM1489 one.
    #[test]
    fn l9_is_bm1491_and_this_table_does_not_describe_it() {
        use crate::scrypt_stock_topology::L9_BSL41601;

        // The L9 is a different chip entirely.
        assert_eq!(L9_BSL41601.asic_id, Some("BM1491"));
        assert_eq!(L9_BSL41601.chip_type, Some(0x1491));

        // ...with geometry that contradicts every BM1489 constant here.
        assert_ne!(L9_BSL41601.chain_count, Some(BM1489_CHAIN_COUNT_L7));
        assert_ne!(L9_BSL41601.chips_per_chain, Some(BM1489_CHIPS_PER_CHAIN_L7));
        assert_eq!(L9_BSL41601.total_chips(), Some(330));
        assert_ne!(
            L9_BSL41601.total_chips(),
            Some(BM1489_CHIPS_PER_CHAIN_L7 * BM1489_CHAIN_COUNT_L7),
            "L9 must never be described by the BM1489 480-chip geometry"
        );

        // This table's scope statement must stay L7-only.
        assert_eq!(BM1489_TABLE.chip_family, "BM1489");
    }

    /// Round 15 NEGATIVE pin: the stock L7 image does not identify its ASIC,
    /// so nothing may treat "L7 = BM1489" as Bitmain-sourced.
    #[test]
    fn l7_stock_image_does_not_name_an_asic() {
        use crate::scrypt_stock_topology::L7_STOCK;
        assert_eq!(L7_STOCK.asic_id, None);
        assert_eq!(L7_STOCK.chip_type, None);
        // Only the plaintext boot chain is usable.
        assert_eq!(L7_STOCK.control_board, Some("Zynq-7000"));
    }

    #[test]
    fn json_round_trip_preserves_profile_fields() {
        let original = BM1489_TABLE.by_step(0).unwrap();
        let json = serde_json::to_string(original).unwrap();
        let recovered: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(*original, recovered);
    }
}
