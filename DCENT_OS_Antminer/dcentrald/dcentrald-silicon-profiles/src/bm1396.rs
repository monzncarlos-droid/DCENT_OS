//! BM1396 data-only silicon profile.
//!
//! 2026-08-03 mapping correction (W8-G): BM1396 hosts **S17e / T17e**, not
//! S17+ / T17+ (those carry BM1397, `0x1397`). PR-056's reversed attribution
//! is retracted — see the correction banner in
//! .
//!
//! The previously mis-filed S17+/T17+ curve has been removed. It was consumed
//! by the simulator's S17e row despite describing BM1397 plus-family models.
//! BM1396 now carries no frequency/voltage/power operating point: only the
//! exact T17e topology below is held.
//!
//! Exact signed S17e/T17e production binaries now prove the wire ChipID and
//! per-present-chain geometry. Exact signed-binary Ghidra analysis also proves
//! the runtime PLL solver, exposed from `dcentrald_common::resolve_bm1396_pll`.
//! BM1396 is still intentionally not registered as a runtime chip driver
//! because carrier work transport and electrical safety composition remain
//! incomplete. The data below cannot energize ASICs.

use crate::{Profile, SiliconTable};

/// BM1396 numeric wire ChipID, re-exported from the clean-room common contract.
pub const BM1396_CHIP_ID: u32 = dcentrald_common::BM1396_WIRE_CHIP_ID as u32;

/// S17e ASIC count required for every caller-selected present chain by the
/// exact signed production miner.
pub const BM1396_CHIPS_PER_CHAIN_S17E: u32 =
    dcentrald_common::BM1396_S17E_CHIPS_PER_PRESENT_CHAIN as u32;

/// **T17e chips per hashboard = 78 — first-party, Round 17 (B1).** This is the
/// genuine BM1396 (e-family) anchor.
///
/// Source: Bitmain's own `T17e Maintenance Guide.pdf`, p.9 —
///
/// line 107: *"The hashboard is composed of **78 BM1396 chips**, which are
/// divided into **13 groups**, each group is composed of **6 ICs**"*. Two
/// self-consistent statements (13 × 6 = 78), and it names the chip family
/// (BM1396) directly — the same guide states 1.35 V working voltage for the
/// BM1396 (`[BM1396_T17E_WORKING_VOLTAGE_MV]`). Metadata/identity-only:
/// BM1396 is `NamedOnly`, has no `MinerProfile`, so this feeds no energization,
/// autotuner, or nonce-attribution path.
pub const BM1396_CHIPS_PER_CHAIN_T17E: u32 =
    dcentrald_common::BM1396_T17E_CHIPS_PER_PRESENT_CHAIN as u32;

/// T17e voltage domains along one hashboard chain (`T17e Maintenance Guide`
/// p.9 "divided into 13 groups"; "13th domain" at line 164).
pub const BM1396_DOMAINS_PER_CHAIN_T17E: u32 = 13;

/// T17e BM1396 chips per voltage domain (`T17e Maintenance Guide` p.9
/// "each group is composed of 6 ICs"). 13 × 6 = 78 = [`BM1396_CHIPS_PER_CHAIN_T17E`].
pub const BM1396_CHIPS_PER_DOMAIN_T17E: u32 = 6;

/// T17e BM1396 chip working voltage in mV (`T17e Maintenance Guide` p.9
/// "the working voltage of the BM1396 chip used by the T17e hashboard is
/// 1.35V"). First-party; recorded as identity metadata only.
pub const BM1396_T17E_WORKING_VOLTAGE_MV: u32 = 1350;

/// Empty by construction: no model-correct S17e/T17e operating point is held.
pub const BM1396_PROFILES: [Profile; 0] = [];

pub const BM1396_TABLE: SiliconTable = SiliconTable {
    chip_family: "BM1396",
    profiles: &BM1396_PROFILES,
    default_step: 0,
    sweet_spot_step: 0,
    live_status: crate::ChipStatus::NamedOnly,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1396_identity_is_e_family_only() {
        assert_eq!(BM1396_CHIP_ID, 0x1396);
        assert_eq!(BM1396_CHIPS_PER_CHAIN_S17E, 135);
    }

    /// T17e is the genuine BM1396 (e-family) hashboard. Its geometry comes from
    /// Bitmain's own T17e Maintenance Guide (p.9): 78 BM1396 chips = 13 domains
    /// × 6 ICs. Pin the arithmetic so the two guide statements can never be
    /// silently reconciled apart, and pin the working voltage the same guide
    /// states. Round 17 (B1) first-party anchor.
    #[test]
    fn t17e_bm1396_geometry_is_first_party_and_self_consistent() {
        assert_eq!(BM1396_CHIPS_PER_CHAIN_T17E, 78);
        assert_eq!(BM1396_DOMAINS_PER_CHAIN_T17E, 13);
        assert_eq!(BM1396_CHIPS_PER_DOMAIN_T17E, 6);
        assert_eq!(
            BM1396_DOMAINS_PER_CHAIN_T17E * BM1396_CHIPS_PER_DOMAIN_T17E,
            BM1396_CHIPS_PER_CHAIN_T17E,
            "T17e guide p.9: 13 groups × 6 ICs = 78 BM1396 chips"
        );
        assert_eq!(BM1396_T17E_WORKING_VOLTAGE_MV, 1350);
    }

    #[test]
    fn bm1396_profile_is_data_only_not_live_ready() {
        assert_eq!(BM1396_TABLE.chip_family, "BM1396");
        assert_eq!(BM1396_TABLE.live_status, crate::ChipStatus::NamedOnly);
        assert!(BM1396_TABLE.profiles.is_empty());
        assert!(BM1396_TABLE.default_profile().is_none());
        assert!(BM1396_TABLE.computed_sweet_spot().is_none());
    }
}
