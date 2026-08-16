//! BM1396 clean-room protocol helper for S17e / T17e-era hardware.
//!
//! Exact model-specific signed production `bmminer` binaries enforce register
//! zero high word `0x1396` and independently construct the same unified BM139x
//! CRC5 command frames. This establishes the wire identity and read/write
//! framing at `CONFIRMED_MULTI_FIRMWARE`; it is not a live DCENT bench result.
//!
//! Important constraints:
//! - This module intentionally does not implement `ChipDriver`: the held
//!   binaries have not yet yielded a complete FPGA work transport or board
//!   electrical/thermal safety composition. The exact PLL solver and
//!   double-write plan are pure and perform no I/O.
//! - A chip enumerating `0x1396` therefore still falls through
//!   `ChipRegistry::detect()` to `None` and is **never** silently mapped
//!   onto the registered BM1397 (`0x1397`) driver.
//! - The exact binaries prove a framed voltage endpoint at I2C address `0x11`
//!   and a vendor 1800-2100 cV software clamp. They do not read a physical
//!   controller part ID, establish a certified electrical envelope, or admit
//!   a live voltage adapter.

pub struct Bm1396Driver;

// Keep the future hardware-facing module on the same host-testable contract
// used by BoardDesc and admission code. These helpers do not perform I/O.
pub use dcentrald_common::{
    bm1396_baud_plan, bm1396_read_register_frame, bm1396_reset_address_frame,
    bm1396_set_address_frame, bm1396_validate_voltage_response,
    bm1396_voltage_dac_in_vendor_envelope, bm1396_voltage_request_frame,
    bm1396_write_register_frame,
};

impl Default for Bm1396Driver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_signed_bm1396_read_frames_pin_headers_order_and_crc5() {
        assert_eq!(
            bm1396_read_register_frame(true, 0x00, 0x00),
            [0x52, 0x05, 0x00, 0x00, 0x0a]
        );
        assert_eq!(
            bm1396_read_register_frame(false, 0x2a, 0x18),
            [0x42, 0x05, 0x2a, 0x18, 0x1c]
        );
    }

    #[test]
    fn exact_signed_bm1396_write_frames_pin_big_endian_value_and_crc5() {
        assert_eq!(
            bm1396_write_register_frame(true, 0x00, 0x18, 0x1234_5678),
            [0x51, 0x09, 0x00, 0x18, 0x12, 0x34, 0x56, 0x78, 0x0a]
        );
        assert_eq!(
            bm1396_write_register_frame(false, 0x2a, 0x08, 0x4068_0221),
            [0x41, 0x09, 0x2a, 0x08, 0x40, 0x68, 0x02, 0x21, 0x03]
        );
    }

    #[test]
    fn exact_signed_address_reset_and_assignment_frames_are_pinned() {
        assert_eq!(bm1396_reset_address_frame(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(
            bm1396_set_address_frame(134),
            [0x40, 0x05, 0x86, 0x00, 0x12]
        );
        assert_eq!(
            bm1396_set_address_frame(231),
            [0x40, 0x05, 0xe7, 0x00, 0x0b]
        );
        assert_eq!(
            bm1396_set_address_frame(252),
            [0x40, 0x05, 0xfc, 0x00, 0x02]
        );
    }

    #[test]
    fn protocol_recovery_does_not_register_a_live_driver() {
        let registry_source = include_str!("mod.rs");
        assert!(
            !registry_source.contains("register(Box::new(bm1396::Bm1396Driver"),
            "wire framing alone must not authorize BM1396 energization"
        );
        let this_source = include_str!("bm1396.rs");
        let forbidden_impl = concat!("impl Chip", "Driver for Bm1396Driver");
        assert!(!this_source.contains(forbidden_impl));
    }
}

impl Bm1396Driver {
    pub fn new() -> Self {
        Self
    }

    /// Whether the exact signed-firmware pure PLL solver is admitted.
    ///
    /// This does not admit carrier I/O or register the ChipDriver.
    pub fn production_pure_pll_admitted() -> bool {
        dcentrald_common::bm1396_production_pure_pll_admitted()
    }

    /// Thin wrapper over the exact signed S17e/T17e pure PLL solver.
    pub fn resolve_pll(
        target_mhz: f32,
        old_register_value: u32,
    ) -> Option<dcentrald_common::Bm1396PllSolution> {
        dcentrald_common::resolve_bm1396_pll(target_mhz, old_register_value)
    }

    /// Exact pure primary-PLL double-write plan. BoardDesc carrier admission
    /// remains closed, so this helper cannot energize hardware by itself.
    pub fn plan_frequency_program_ops(
        target_mhz: u16,
    ) -> Option<Vec<dcentrald_common::TransportOp>> {
        dcentrald_common::plan_bm1396_frequency_program_ops(target_mhz)
    }
}
