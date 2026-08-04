//! BM1396 driver scaffold for the T17e / S17e-era hardware (chip ID
//! `0x1396`, 7 nm Gen-2, BM1397-era command-header family).
//!
//! NOTE: BM1396 hosts the **S17e / T17e** products. The S17+ / T17+
//! products carry **BM1397** (chip ID `0x1397`), NOT BM1396.
//!
//! 2026-08-03 mapping correction (W8-G): between 2026-05-16 and this
//! date this header read "S17+ / T17+", installed by PR-056 §5 on the
//! belief that the original "T17e/S17e-era" label was a stray
//! mis-attribution. That judgement was itself wrong — the original
//! header was right. PR-056's model attribution traced only to two
//! comment lines (`bm1393.rs:172`, `asics.rs:155`) and had no
//! measurement behind it; it is retracted in the correction banner of
//! .
//! PR-056's DISPATCH-SAFETY verdict still stands and is unchanged.
//!
//! Important constraints:
//! - The workspace does not yet contain a verified live BM1396 chip ID
//!   (no S17e/T17e unit on the fleet — `UNKNOWN — needs hardware`).
//! - Board-control evidence is split: S17e appears dsPIC-based, while
//!   T17e appears PIC16-based.
//! - Until that is validated on real hardware, this module is intentionally not
//!   registered in `ChipRegistry` and does not implement `ChipDriver`. A
//!   chip enumerating `0x1396` therefore falls through
//!   `ChipRegistry::detect()` to `None` and is **never** silently mapped
//!   onto the registered BM1397 (`0x1397`) driver.

use crate::Result;
use dcentrald_hal::fpga_chain::FpgaChain;

use super::bm139x;

pub struct Bm1396Driver;

impl Default for Bm1396Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1396Driver {
    pub fn new() -> Self {
        Self
    }

    /// BM1396 is expected to share the BM139x FPGA work-time math.
    pub fn calculate_work_time(freq_mhz: u16, midstate_count: u32) -> u32 {
        bm139x::calculate_work_time(freq_mhz, midstate_count)
    }

    /// Shared helper for future BM1396 PLL readback once the register map is
    /// confirmed on live or extracted hardware.
    pub fn read_pll_register(
        chain: &mut FpgaChain,
        chip_addr: u8,
        pll_reg_addr: u8,
    ) -> Result<Option<u32>> {
        bm139x::read_pll_register(chain, chip_addr, pll_reg_addr)
    }

    /// Production pure PLL encode status (G12).
    ///
    /// Offline: always **not admitted** — no die-bound goldens for `0x1396`.
    /// Experimental family-hypothesis encode lives in `dcentrald_common` as
    /// `resolve_bm1396_pll_experimental_family_hypothesis` and is **not** a
    /// ChipDriver path.
    pub fn production_pure_pll_admitted() -> bool {
        dcentrald_common::bm1396_production_pure_pll_admitted()
    }
}
