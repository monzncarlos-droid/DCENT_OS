//! BM1385 data-only silicon profile for the Antminer S7 (pre-S9 generation).
//!
//! The BM1385 is Bitmain's **28 nm** SHA-256 die used in the Antminer S7 /
//! S7-LN (mid-2015) — an entire ASIC generation that predates the BM1387/S9
//! and that DCENT_OS previously did not model at all. It is **Generation-1
//! FIL-framed** (4-byte command frames, no `0x55 0xAA` preamble, CRC5 over 27
//! bits, 5-byte nonce/register response), the same broad family shape as
//! BM1387 but with distinct command opcodes.
//!
//! The BM1385 ASIC driver (`dcentrald-asic/src/drivers/bm1385.rs`) is
//! **scaffold-gated and production-unregistered** — there is no live S7 unit
//! on the fleet to validate a bring-up against, so this profile records the
//! host-testable geometry while the driver refuses live mining by default.
//!
//! ## Provenance (all constants below are byte-extracted, not guessed)
//! Bitmain factory `single-board-test` jig, unstripped ARM ELF held at
//!
//! (four on-disk copies; the Z9-mini jig binary bundles the BM1385 protocol).
//! Decompilation tree `…/single-board-test-ok.dec/`:
//!   - `single_BM1385_calculate_timeout_and_baud@9914.c` — `calculate_core_number(50)`.
//!   - `single_BM1385_open_core@9BC4.c` — open-core loop runs `i = 0..=49` (50 cores).
//!   - `single_BM1385_check_nonce@A2D8.c` — nonce core index `a2[3] & 0x3F`, valid `<= 49`.
//!   - `single_BM1385_receive_func@AC14.c` — response frames are **5 bytes** (`v16 / 5`).
//!   - `singleBoardTest_V9_BM1385_45@18774.c` — the jig tests a **45-chip** board
//!     (also AMTC `AMTC_TEST_JIG_RE.md:79-80` "S7-45": 45 chips, 50 cores, 600 MHz).
//!
//! The full 124-entry `freq_pll_1385[]` PLL table (byte-extracted from the ELF
//! `.data` at symbol `freq_pll_1385`, addr `0x2454c`) lives in the driver
//! module — it is consumed there by `pll_params`. This crate has no dependency
//! on `dcentrald-asic`, so the table is not duplicated here.

use crate::{Profile, ProfileSource, SiliconTable};

/// BM1385 catalog key.
///
/// **NOTE:** unlike BM1397+/BM1362 the BM1385 exposes **no readable 16-bit
/// chip-ID register** — the jig identifies boards by counting register-read
/// responses (`check_BM1385_asic_reg`), not by an id word. `0x1385` is a
/// synthetic catalog key (mirroring the `0x1391` convention for BM1391), NOT a
/// value the silicon reports on the wire.
pub const BM1385_CHIP_ID: u32 = 0x0000_1385;

/// SHA-256 cores per BM1385 chip. Jig-verified: `calculate_core_number(50)`
/// and both `single_BM1385_open_core` loops run `i = 0..=49`; `check_nonce`
/// rejects a core index `> 49`.
pub const BM1385_CORES_PER_CHIP: u32 = 50;

/// Chips per S7 hashboard as exercised by the factory jig
/// (`singleBoardTest_V9_BM1385_45`) and AMTC "S7-45". A production S7 pairs
/// several such boards; the per-board count is what the jig proves.
pub const BM1385_CHIPS_PER_BOARD_JIG: u8 = 45;

/// Nonce / register response frame length in bytes. Jig-verified: the receive
/// loop parses `v16 / 5` records of 5 bytes each (`single_BM1385_receive_func`).
/// This is the Gen-1 FIL 5-byte response (nonce[4] + status byte), distinct
/// from BM1387's 9-byte frame.
pub const BM1385_RESPONSE_BYTES: usize = 5;

/// Single conservative host-planning row. Frequency 600 MHz is the AMTC S7-45
/// functional-test point (`AMTC_TEST_JIG_RE.md:79-80`); it also has an exact
/// `freq_pll_1385[]` entry (index 76). Voltage / watts / hashrate are
/// deliberately unknown: the jig sets core voltage via the PIC16F1704 DAC
/// (`V9_set_voltage`) over a 1025-1075 mV core-voltage band, which is NOT a
/// chain-rail volt figure and is NOT a full tuning ladder. Fabricating a
/// wall-watt or J/TH row would be a guess, so these stay `None`.
pub const BM1385_PROFILES: [Profile; 1] = [Profile {
    step: 0,
    freq_mhz: 600,
    voltage_v: 0.0,
    wall_watts: None,
    hashrate_ths: None,
    source: ProfileSource::VendorExtracted,
}];

pub const BM1385_TABLE: SiliconTable = SiliconTable {
    chip_family: "BM1385",
    profiles: &BM1385_PROFILES,
    default_step: 0,
    sweet_spot_step: 0,
    live_status: crate::ChipStatus::NamedOnly,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1385_scaffold_geometry_is_jig_verified() {
        assert_eq!(BM1385_CHIP_ID, 0x1385);
        // 50 cores: calculate_core_number(50) + open_core 0..=49.
        assert_eq!(BM1385_CORES_PER_CHIP, 50);
        // 45-chip board from singleBoardTest_V9_BM1385_45 / AMTC S7-45.
        assert_eq!(BM1385_CHIPS_PER_BOARD_JIG, 45);
        // Gen-1 FIL 5-byte response frame (single_BM1385_receive_func v16/5).
        assert_eq!(BM1385_RESPONSE_BYTES, 5);
    }

    #[test]
    fn bm1385_profile_is_named_only_and_power_unknown() {
        let row = BM1385_TABLE.default_profile().unwrap();
        assert_eq!(BM1385_TABLE.live_status, crate::ChipStatus::NamedOnly);
        assert_eq!(row.freq_mhz, 600);
        // No fabricated power/hashrate numbers.
        assert_eq!(row.wall_watts, None);
        assert_eq!(row.hashrate_ths, None);
        assert!(row.watts_per_ths().is_none());
    }
}
