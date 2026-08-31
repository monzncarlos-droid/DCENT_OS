//! BM1393 (S9 SE / S9k) exact protocol scaffold.
//!
//! Framing, CRC5, 208-core identity and S9 SE/S9k enumeration evidence are
//! recovered. No production carrier, voltage, cooling or energize authority is
//! implied; every hardware-mutating trait method refuses.

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::{AsicError, Result};
use dcentrald_hal::fpga_chain::FpgaChain;

pub const CHIP_ID: u16 = crate::bm1393::CHIP_ID;
pub const CORES_PER_CHIP: u32 = crate::bm1393::CORES_PER_CHIP as u32;
/// Raw ASIC reply width is not established by the nine-byte register-write
/// command or by the two-word FPGA-normalized return record. Zero is an
/// intentional scaffold sentinel; no executor may allocate from it.
pub const RESPONSE_BYTES: usize = 0;
pub const RESPONSE_BYTES_VERIFIED: bool = false;

pub struct Bm1393Driver;

impl Default for Bm1393Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1393Driver {
    pub const fn new() -> Self {
        Self
    }

    /// Exact CRC5 wrapper for offline frame replay.
    pub fn crc5(data: &[u8], bits: u32) -> u8 {
        crate::bm1393::crc5_bits(data, bits)
    }
}

fn refuse<T>(operation: &str) -> Result<T> {
    Err(AsicError::InvalidParameter(format!(
        "BM1393 {operation} is protocol-scaffold only; carrier/electrical admission is unresolved"
    )))
}

impl ChipDriver for Bm1393Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }
    fn chip_name(&self) -> &'static str {
        "BM1393"
    }
    fn cores_per_chip(&self) -> u32 {
        CORES_PER_CHIP
    }
    fn response_length(&self) -> usize {
        RESPONSE_BYTES
    }
    fn default_baud(&self) -> u32 {
        crate::bm1393::BM1393_BAUD_DEFAULT
    }
    fn max_baud(&self) -> u32 {
        crate::bm1393::BM1393_BAUD_DEFAULT
    }

    fn init_chain(&self, _: &mut FpgaChain, _: u8, _: u16) -> Result<()> {
        refuse("init_chain")
    }
    fn set_frequency(&self, _: &mut FpgaChain, _: u8, _: u16) -> Result<()> {
        refuse("set_frequency")
    }
    fn set_voltage(&self, _: &mut PicController, _: u16) -> Result<()> {
        refuse("set_voltage")
    }
    fn send_work(&self, _: &mut FpgaChain, _: &MiningWork) -> Result<u16> {
        refuse("send_work")
    }
    fn decode_nonce(&self, _: &[u32; 2]) -> Result<NonceResult> {
        refuse("decode_nonce")
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        (fpga_clock_hz / (16 * target_baud.max(1))).saturating_sub(1)
    }
    fn ctrl_reg_value(&self) -> u32 {
        0x0000_000c
    }
    fn job_interval_ms(&self, _: u8, _: u16) -> u32 {
        1000
    }
    fn ticket_mask(&self, difficulty: u32) -> u32 {
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::BitReversed,
            difficulty.max(1),
        )
    }
    fn pll_params(&self, _: u16) -> PllConfig {
        // Exact programming lives in `s9se_pll`; the generic trait cannot
        // express its table index/divider pair and must not synthesize one.
        PllConfig {
            fb_div: 0,
            ref_div: 0,
            post_div1: 0,
            post_div2: 0,
            reg_value: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_crc_and_all_mutations_stay_fail_closed() {
        let driver = Bm1393Driver::new();
        assert_eq!(driver.chip_id(), 0x1393);
        assert_eq!(driver.cores_per_chip(), 208);
        assert_eq!(driver.response_length(), 0);
        assert!(!RESPONSE_BYTES_VERIFIED);
        assert_eq!(Bm1393Driver::crc5(&[0x42, 0x05, 0x78], 27), 0x1c);
        assert!(driver.decode_nonce(&[0, 0]).is_err());
    }
}
