//! Pure BM1489 protocol facts recovered from the held L7 VNish 1.2.7 binary.
//!
//! This is an offline replay/encoding contract. The binary is third-party
//! software and its configuration selector is not a physical silicon probe.
//! Nothing here authorizes UART I/O, ASIC writes, carrier use, rail mutation,
//! work dispatch, or mining.

use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1489_L7_VNISH_CGMINER_SIZE: usize = 5_793_556;
pub const BM1489_L7_VNISH_CGMINER_SHA256: &str =
    "59f948ee356af0dfd7056505bbf025bfba2b29038825bec456e276ec7aa22db8";
pub const BM1489_L7_VNISH_CGMINER_MD5: &str = "7a96485cb3e1b9eed882ca006498b749";
/// The exact config parser maps the literal `BM1489` to this API-table selector.
pub const BM1489_L7_VNISH_API_SELECTOR: u32 = 6;

pub const BM1489_REGISTER_PLL0: u8 = 0x08;
pub const BM1489_REGISTER_BAUD_CONTROL: u8 = 0x18;
pub const BM1489_REGISTER_COMMAND_STATUS: u8 = 0x1c;
pub const BM1489_REGISTER_ANALOG_MUX: u8 = 0x2c;
pub const BM1489_REGISTER_INIT_CONTROL: u8 = 0x34;
pub const BM1489_REGISTER_CORE_CONTROL: u8 = 0x3c;

pub const BM1489_WRITE_BROADCAST_HEADER: u8 = 0x51;
pub const BM1489_WRITE_ADDRESSED_HEADER: u8 = 0x41;
pub const BM1489_READ_BROADCAST_HEADER: u8 = 0x52;
pub const BM1489_READ_ADDRESSED_HEADER: u8 = 0x42;
pub const BM1489_CHAIN_INACTIVE_HEADER: u8 = 0x53;
pub const BM1489_SET_ADDRESS_HEADER: u8 = 0x40;
pub const BM1489_WRITE_FRAME_LENGTH: u8 = 0x09;
pub const BM1489_SHORT_FRAME_LENGTH: u8 = 0x05;

pub const BM1489_WRITE_SETTLE_MS: u32 = 500;
pub const BM1489_READ_OUTER_ATTEMPTS: u8 = 5;
pub const BM1489_READ_QUEUE_POLLS_PER_ATTEMPT: u8 = 8;
pub const BM1489_READ_PRE_POLL_DELAY: u32 = 10;
pub const BM1489_READ_POST_POLL_DELAY: u32 = 5;

/// Exact selector-six startup constants from `FUN_000d96c8`.
pub const BM1489_STARTUP_SETTLE_MS: u32 = 30;
pub const BM1489_STARTUP_FIXED_CORE_CONTROL: u32 = 0xc000_04ff;
/// The apparent runtime-dependent helper loop is opaque-predicate noise:
/// `x * (x - 1)` is even for every wrapping `u32`, so its low bit is always
/// clear and the helper executes exactly once.
pub const BM1489_STARTUP_TICKET_HELPER_CALLS: u8 = 1;
pub const BM1489_STARTUP_TICKET_HELPER_DEPENDS_ON_RUNTIME_BSS: bool = false;

/// Exact selector-six PLL search profile consumed by `FUN_000d9f6c` through
/// the common solver at `FUN_000ebd38`.
pub const BM1489_PLL_REFERENCE_MHZ: f64 = 25.0;
pub const BM1489_PLL_VCO_MAX_MHZ: f64 = 3_200.0;
pub const BM1489_PLL_PROFILE_UNUSED_2400_MHZ: f64 = 2_400.0;
pub const BM1489_PLL_VCO_MIN_MHZ: f64 = 1_600.0;
pub const BM1489_PLL_FIELD6_MAX: u8 = 2;
pub const BM1489_PLL_FIELD12_MAX: u16 = 250;
pub const BM1489_PLL_FIELD3_MAX: u8 = 7;
pub const BM1489_PLL_INITIAL_ERROR_MHZ: f64 = 25.0;
pub const BM1489_PLL_COMPARISON_EPSILON_MHZ: f64 = f64::from_bits(0x3fb9_9999_9999_999a);
pub const BM1489_PLL_REFDIV2_VCO_MAX_MHZ: f64 = f64::from_bits(0x40a8_6a33_3333_3333);

/// Selector-six API slots for drive-strength and relay configuration return
/// success without emitting a wire transaction.
pub const BM1489_DRIVE_STRENGTH_API_EMITS_WIRE_IO: bool = false;
pub const BM1489_RELAY_API_EMITS_WIRE_IO: bool = false;

/// Immutable no-authority boundary for this third-party static-RE contract.
pub const BM1489_L7_CONTRACT_IDENTIFIES_PHYSICAL_SILICON: bool = false;
pub const BM1489_L7_CONTRACT_AUTHORIZES_LIVE_IO: bool = false;
pub const BM1489_L7_CONTRACT_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1489_L7_CONTRACT_AUTHORIZES_WORK_DISPATCH: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7VnishError {
    UnsupportedBaud(u32),
    NoPllCandidate(i32),
    PllField12OutOfRange(u16),
    PllField6OutOfRange(u8),
    PllField3HighOutOfRange(u8),
    PllField3LowOutOfRange(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489RegisterWritePlan {
    pub frame: [u8; 9],
    /// The exact generic writer checks the corresponding register shadow.
    pub requires_shadow_match: bool,
    pub settle_after_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489TicketParameterPlan {
    pub low_half: Bm1489RegisterWritePlan,
    pub high_half: Bm1489RegisterWritePlan,
}

/// Exact hardware-facing startup spine recovered from selector-six API slot 9.
///
/// This is an offline plan, not an executor. The opaque ticket word is supplied
/// by the generic API caller; its relationship to share difficulty is not
/// established by this function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489StartupPlan {
    pub assert_init: Bm1489RegisterWritePlan,
    pub clear_init: Bm1489RegisterWritePlan,
    pub fixed_core_control: Bm1489RegisterWritePlan,
    pub ticket: Bm1489TicketParameterPlan,
    /// `FUN_000dc1dc` attempts the high-half write only after the low-half
    /// write succeeds.
    pub ticket_high_requires_low_success: bool,
    /// Failure of the fixed core-control write only enters a bounded
    /// diagnostic block before startup proceeds.
    pub fixed_core_failure_is_diagnostic_only: bool,
    /// The outer startup function ignores the generic-write and ticket-helper
    /// results and returns zero.
    pub write_results_affect_outer_return: bool,
    pub observed_outer_return: i32,
    pub exact_ticket_helper_calls: u8,
}

impl Bm1489StartupPlan {
    /// Static recovery never authorizes live UART or ASIC mutation.
    pub const fn authorizes_live_io(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489BaudPlan {
    pub requested_baud: u32,
    pub register_value: u32,
    pub write: Bm1489RegisterWritePlan,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489PllSolution {
    pub requested_mhz: i32,
    pub actual_mhz: f64,
    pub absolute_error_mhz: f64,
    pub vco_mhz: f64,
    pub field12: u16,
    pub field6: u8,
    pub field3_high: u8,
    pub field3_low: u8,
    pub register_value: u32,
}

impl Bm1489PllSolution {
    /// Solver success is only a replay result. It does not prove PLL lock,
    /// clock accuracy, a safe output frequency, or live carrier authority.
    pub const fn authorizes_pll_write(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489PllPlan {
    pub solution: Bm1489PllSolution,
    pub write: Bm1489RegisterWritePlan,
}

/// Build the exact selector-six register-write frame.
pub fn bm1489_register_write_frame(
    broadcast: bool,
    chip_address: u8,
    register: u8,
    value: u32,
) -> [u8; 9] {
    let mut frame = [0_u8; 9];
    frame[0] = if broadcast {
        BM1489_WRITE_BROADCAST_HEADER
    } else {
        BM1489_WRITE_ADDRESSED_HEADER
    };
    frame[1] = BM1489_WRITE_FRAME_LENGTH;
    frame[2] = if broadcast { 0 } else { chip_address };
    frame[3] = register;
    frame[4..8].copy_from_slice(&value.to_be_bytes());
    frame[8] = stock_bitmain_crc5(&frame[..8], 64);
    frame
}

/// Build the exact selector-six read request. Response matching is by chain,
/// chip address, and register; this function does not model the host queue.
pub fn bm1489_register_read_frame(broadcast: bool, chip_address: u8, register: u8) -> [u8; 5] {
    let mut frame = [0_u8; 5];
    frame[0] = if broadcast {
        BM1489_READ_BROADCAST_HEADER
    } else {
        BM1489_READ_ADDRESSED_HEADER
    };
    frame[1] = BM1489_SHORT_FRAME_LENGTH;
    frame[2] = if broadcast { 0 } else { chip_address };
    frame[3] = register;
    frame[4] = stock_bitmain_crc5(&frame[..4], 32);
    frame
}

pub fn bm1489_chain_inactive_frame() -> [u8; 5] {
    let mut frame = [
        BM1489_CHAIN_INACTIVE_HEADER,
        BM1489_SHORT_FRAME_LENGTH,
        0,
        0,
        0,
    ];
    frame[4] = stock_bitmain_crc5(&frame[..4], 32);
    frame
}

pub fn bm1489_set_address_frame(new_address: u8) -> [u8; 5] {
    let mut frame = [
        BM1489_SET_ADDRESS_HEADER,
        BM1489_SHORT_FRAME_LENGTH,
        new_address,
        0,
        0,
    ];
    frame[4] = stock_bitmain_crc5(&frame[..4], 32);
    frame
}

const fn write_plan(frame: [u8; 9], settle_after_ms: u32) -> Bm1489RegisterWritePlan {
    Bm1489RegisterWritePlan {
        frame,
        requires_shadow_match: true,
        settle_after_ms,
    }
}

/// Split the caller-supplied 32-bit ticket parameter exactly as selector six
/// does. Its relationship to share difficulty is not established here.
pub fn bm1489_ticket_parameter_plan(parameter: u32) -> Bm1489TicketParameterPlan {
    let low = 0xc002_0000 | (parameter & 0xffff);
    let high = 0xc004_0000 | ((parameter >> 16) & 0xffff);
    Bm1489TicketParameterPlan {
        low_half: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_CORE_CONTROL, low),
            0,
        ),
        high_half: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_CORE_CONTROL, high),
            BM1489_WRITE_SETTLE_MS,
        ),
    }
}

/// Build the exact selector-six startup spine from `FUN_000d96c8` and its
/// ticket helper `FUN_000dc1dc`.
pub fn bm1489_startup_plan(ticket_parameter: u32) -> Bm1489StartupPlan {
    let low = 0xc002_0000 | (ticket_parameter & 0xffff);
    let high = 0xc004_0000 | ((ticket_parameter >> 16) & 0xffff);
    Bm1489StartupPlan {
        assert_init: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_INIT_CONTROL, 3),
            BM1489_STARTUP_SETTLE_MS,
        ),
        clear_init: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_INIT_CONTROL, 0),
            BM1489_STARTUP_SETTLE_MS,
        ),
        fixed_core_control: write_plan(
            bm1489_register_write_frame(
                true,
                0,
                BM1489_REGISTER_CORE_CONTROL,
                BM1489_STARTUP_FIXED_CORE_CONTROL,
            ),
            BM1489_STARTUP_SETTLE_MS,
        ),
        ticket: Bm1489TicketParameterPlan {
            low_half: write_plan(
                bm1489_register_write_frame(true, 0, BM1489_REGISTER_CORE_CONTROL, low),
                0,
            ),
            high_half: write_plan(
                bm1489_register_write_frame(true, 0, BM1489_REGISTER_CORE_CONTROL, high),
                0,
            ),
        },
        ticket_high_requires_low_success: true,
        fixed_core_failure_is_diagnostic_only: true,
        write_results_affect_outer_return: false,
        observed_outer_return: 0,
        exact_ticket_helper_calls: BM1489_STARTUP_TICKET_HELPER_CALLS,
    }
}

pub fn bm1489_analog_mux_plan(value: u32) -> Bm1489RegisterWritePlan {
    write_plan(
        bm1489_register_write_frame(true, 0, BM1489_REGISTER_ANALOG_MUX, value),
        BM1489_WRITE_SETTLE_MS,
    )
}

pub fn bm1489_baud_register_value(baud: u32) -> Result<u32, Bm1489L7VnishError> {
    let base = 0x0700_60f5;
    match baud {
        38_400 => Ok(base | 0x1000),
        460_800 => Ok(base + 0x600),
        921_600 | 1_041_666 => Ok(base + 0x200),
        1_500_000 | 1_562_500 => Ok(base + 0x100),
        3_000_000 | 3_125_000 | 6_250_000 | 12_500_000 => Ok(base),
        unsupported => Err(Bm1489L7VnishError::UnsupportedBaud(unsupported)),
    }
}

pub fn bm1489_baud_plan(baud: u32) -> Result<Bm1489BaudPlan, Bm1489L7VnishError> {
    let register_value = bm1489_baud_register_value(baud)?;
    Ok(Bm1489BaudPlan {
        requested_baud: baud,
        register_value,
        write: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_BAUD_CONTROL, register_value),
            0,
        ),
    })
}

/// Pack the four neutral-width fields returned by the exact PLL solver. This
/// does not claim field names, solve a frequency, or authorize a PLL write.
pub fn bm1489_pack_pll_fields(
    field12: u16,
    field6: u8,
    field3_high: u8,
    field3_low: u8,
) -> Result<u32, Bm1489L7VnishError> {
    if field12 > 0x0fff {
        return Err(Bm1489L7VnishError::PllField12OutOfRange(field12));
    }
    if field6 > 0x3f {
        return Err(Bm1489L7VnishError::PllField6OutOfRange(field6));
    }
    if field3_high > 7 {
        return Err(Bm1489L7VnishError::PllField3HighOutOfRange(field3_high));
    }
    if field3_low > 7 {
        return Err(Bm1489L7VnishError::PllField3LowOutOfRange(field3_low));
    }
    Ok(0xa000_0000
        | (u32::from(field12) << 16)
        | (u32::from(field6) << 8)
        | (u32::from(field3_high) << 4)
        | u32::from(field3_low))
}

/// Replay the exact selector-six/common-solver search and construct its
/// register-`0x08` write.
///
/// Search order is field6 2->1, low post-divider 1->7, and high post-divider
/// low->7. Stock replaces a prior candidate unless the new absolute error is
/// at least 0.1 MHz worse, and exits early only below 0.1 MHz. It can therefore
/// return success for a materially inexact request; this pure contract records
/// that weakness and does not authorize the resulting write.
pub fn bm1489_pll_plan(requested_mhz: i32) -> Result<Bm1489PllPlan, Bm1489L7VnishError> {
    let target = f64::from(requested_mhz);
    let mut best: Option<Bm1489PllSolution> = None;
    let mut best_error = BM1489_PLL_INITIAL_ERROR_MHZ;

    for field6 in (1..=BM1489_PLL_FIELD6_MAX).rev() {
        for field3_low in 1..=BM1489_PLL_FIELD3_MAX {
            for field3_high in field3_low..=BM1489_PLL_FIELD3_MAX {
                let post_divider_product = u16::from(field3_low) * u16::from(field3_high);
                let field12_f64 =
                    (f64::from(field3_high) * target * f64::from(field3_low) * f64::from(field6)
                        / BM1489_PLL_REFERENCE_MHZ)
                        .trunc();
                if !(1.0..=f64::from(BM1489_PLL_FIELD12_MAX)).contains(&field12_f64) {
                    continue;
                }
                let field12 = field12_f64 as u16;
                let vco_mhz = BM1489_PLL_REFERENCE_MHZ * f64::from(field12) / f64::from(field6);
                if vco_mhz < BM1489_PLL_VCO_MIN_MHZ - BM1489_PLL_COMPARISON_EPSILON_MHZ
                    || vco_mhz > BM1489_PLL_VCO_MAX_MHZ + BM1489_PLL_COMPARISON_EPSILON_MHZ
                    || (field6 != 1 && vco_mhz > BM1489_PLL_REFDIV2_VCO_MAX_MHZ)
                {
                    continue;
                }
                let actual_mhz = vco_mhz / f64::from(post_divider_product);
                let absolute_error_mhz = (target - actual_mhz).abs();
                if best.is_some()
                    && best_error + BM1489_PLL_COMPARISON_EPSILON_MHZ <= absolute_error_mhz
                {
                    continue;
                }
                let register_value =
                    bm1489_pack_pll_fields(field12, field6, field3_high, field3_low)?;
                let solution = Bm1489PllSolution {
                    requested_mhz,
                    actual_mhz,
                    absolute_error_mhz,
                    vco_mhz,
                    field12,
                    field6,
                    field3_high,
                    field3_low,
                    register_value,
                };
                best = Some(solution);
                best_error = absolute_error_mhz;
                if absolute_error_mhz < BM1489_PLL_COMPARISON_EPSILON_MHZ {
                    return Ok(Bm1489PllPlan {
                        solution,
                        write: write_plan(
                            bm1489_register_write_frame(
                                true,
                                0,
                                BM1489_REGISTER_PLL0,
                                register_value,
                            ),
                            0,
                        ),
                    });
                }
            }
        }
    }

    let solution = best.ok_or(Bm1489L7VnishError::NoPllCandidate(requested_mhz))?;
    Ok(Bm1489PllPlan {
        solution,
        write: write_plan(
            bm1489_register_write_frame(true, 0, BM1489_REGISTER_PLL0, solution.register_value),
            0,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_selector_and_no_authority_boundary_are_pinned() {
        assert_eq!(BM1489_L7_VNISH_API_SELECTOR, 6);
        assert!(!BM1489_L7_CONTRACT_IDENTIFIES_PHYSICAL_SILICON);
        assert!(!BM1489_L7_CONTRACT_AUTHORIZES_LIVE_IO);
        assert!(!BM1489_L7_CONTRACT_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1489_L7_CONTRACT_AUTHORIZES_WORK_DISPATCH);
        assert!(!BM1489_DRIVE_STRENGTH_API_EMITS_WIRE_IO);
        assert!(!BM1489_RELAY_API_EMITS_WIRE_IO);
    }

    #[test]
    fn register_write_is_big_endian_and_crc5_protected() {
        assert_eq!(
            bm1489_register_write_frame(false, 0x2a, BM1489_REGISTER_BAUD_CONTROL, 0x0700_61f5),
            [0x41, 0x09, 0x2a, 0x18, 0x07, 0x00, 0x61, 0xf5, 0x19]
        );
    }

    #[test]
    fn short_command_frames_match_exact_goldens() {
        assert_eq!(
            bm1489_register_read_frame(true, 0x77, BM1489_REGISTER_COMMAND_STATUS),
            [0x52, 0x05, 0x00, 0x1c, 0x09]
        );
        assert_eq!(
            bm1489_register_read_frame(false, 0x2a, BM1489_REGISTER_COMMAND_STATUS),
            [0x42, 0x05, 0x2a, 0x1c, 0x08]
        );
        assert_eq!(
            bm1489_chain_inactive_frame(),
            [0x53, 0x05, 0x00, 0x00, 0x03]
        );
        assert_eq!(
            bm1489_set_address_frame(0x2a),
            [0x40, 0x05, 0x2a, 0x00, 0x19]
        );
    }

    #[test]
    fn ticket_parameter_is_split_into_two_core_control_writes() {
        let plan = bm1489_ticket_parameter_plan(0x1234_5678);
        assert_eq!(
            plan.low_half.frame,
            [0x51, 0x09, 0x00, 0x3c, 0xc0, 0x02, 0x56, 0x78, 0x17]
        );
        assert_eq!(
            plan.high_half.frame,
            [0x51, 0x09, 0x00, 0x3c, 0xc0, 0x04, 0x12, 0x34, 0x0a]
        );
        assert_eq!(plan.low_half.settle_after_ms, 0);
        assert_eq!(plan.high_half.settle_after_ms, 500);
    }

    #[test]
    fn startup_spine_is_exactly_one_ticket_helper_call() {
        let plan = bm1489_startup_plan(0x1234_5678);
        assert_eq!(
            plan.assert_init.frame,
            [0x51, 0x09, 0x00, 0x34, 0x00, 0x00, 0x00, 0x03, 0x14]
        );
        assert_eq!(
            plan.clear_init.frame,
            [0x51, 0x09, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x1b]
        );
        assert_eq!(
            plan.fixed_core_control.frame,
            [0x51, 0x09, 0x00, 0x3c, 0xc0, 0x00, 0x04, 0xff, 0x1f]
        );
        assert_eq!(plan.assert_init.settle_after_ms, 30);
        assert_eq!(plan.clear_init.settle_after_ms, 30);
        assert_eq!(plan.fixed_core_control.settle_after_ms, 30);
        assert_eq!(
            plan.ticket.low_half.frame,
            [0x51, 0x09, 0x00, 0x3c, 0xc0, 0x02, 0x56, 0x78, 0x17]
        );
        assert_eq!(
            plan.ticket.high_half.frame,
            [0x51, 0x09, 0x00, 0x3c, 0xc0, 0x04, 0x12, 0x34, 0x0a]
        );
        assert_eq!(plan.ticket.low_half.settle_after_ms, 0);
        assert_eq!(plan.ticket.high_half.settle_after_ms, 0);
        assert!(plan.ticket_high_requires_low_success);
        assert!(plan.fixed_core_failure_is_diagnostic_only);
        assert!(!plan.write_results_affect_outer_return);
        assert_eq!(plan.observed_outer_return, 0);
        assert_eq!(plan.exact_ticket_helper_calls, 1);
        assert!(!BM1489_STARTUP_TICKET_HELPER_DEPENDS_ON_RUNTIME_BSS);
        assert!(!plan.authorizes_live_io());
    }

    #[test]
    fn analog_mux_is_register_2c_not_a_relay_operation() {
        let plan = bm1489_analog_mux_plan(0x0102_0304);
        assert_eq!(plan.frame[3], 0x2c);
        assert_eq!(&plan.frame[4..8], &[1, 2, 3, 4]);
        assert_eq!(plan.settle_after_ms, 500);
    }

    #[test]
    fn baud_mapping_pins_every_accepted_literal_and_sentinels() {
        let cases = [
            (38_400, 0x0700_70f5),
            (460_800, 0x0700_66f5),
            (921_600, 0x0700_62f5),
            (1_041_666, 0x0700_62f5),
            (1_500_000, 0x0700_61f5),
            (1_562_500, 0x0700_61f5),
            (3_000_000, 0x0700_60f5),
            (3_125_000, 0x0700_60f5),
            (6_250_000, 0x0700_60f5),
            (12_500_000, 0x0700_60f5),
        ];
        for (baud, expected) in cases {
            assert_eq!(bm1489_baud_register_value(baud), Ok(expected));
        }
        for rejected in [0, 115_200, 1_562_499, 3_124_999, 12_500_001] {
            assert_eq!(
                bm1489_baud_register_value(rejected),
                Err(Bm1489L7VnishError::UnsupportedBaud(rejected))
            );
        }
    }

    #[test]
    fn pll_packer_is_exact_and_fail_closed() {
        assert_eq!(bm1489_pack_pll_fields(0xabc, 0x2d, 6, 3), Ok(0xaabc_2d63));
        assert_eq!(
            bm1489_pack_pll_fields(0x1000, 0, 0, 0),
            Err(Bm1489L7VnishError::PllField12OutOfRange(0x1000))
        );
        assert!(bm1489_pack_pll_fields(0, 0x40, 0, 0).is_err());
        assert!(bm1489_pack_pll_fields(0, 0, 8, 0).is_err());
        assert!(bm1489_pack_pll_fields(0, 0, 0, 8).is_err());
    }

    #[test]
    fn held_pll_solver_profile_and_exact_frequency_goldens_are_pinned() {
        assert_eq!(BM1489_PLL_REFERENCE_MHZ.to_bits(), 25.0_f64.to_bits());
        assert_eq!(BM1489_PLL_VCO_MIN_MHZ.to_bits(), 1_600.0_f64.to_bits());
        assert_eq!(BM1489_PLL_VCO_MAX_MHZ.to_bits(), 3_200.0_f64.to_bits());
        assert_eq!(BM1489_PLL_PROFILE_UNUSED_2400_MHZ, 2_400.0);
        assert_eq!(BM1489_PLL_REFDIV2_VCO_MAX_MHZ, 3_125.1);
        assert_eq!(BM1489_PLL_COMPARISON_EPSILON_MHZ, 0.1);

        let cases = [
            (50, (140, 2, 7, 5), 0xa08c_0275),
            (100, (144, 2, 6, 3), 0xa090_0263),
            (300, (144, 2, 6, 1), 0xa090_0261),
            (850, (136, 2, 2, 1), 0xa088_0221),
            (3_125, (250, 2, 1, 1), 0xa0fa_0211),
            (3_200, (128, 1, 1, 1), 0xa080_0111),
        ];
        for (requested, fields, register_value) in cases {
            let plan = bm1489_pll_plan(requested).unwrap();
            assert_eq!(
                (
                    plan.solution.field12,
                    plan.solution.field6,
                    plan.solution.field3_high,
                    plan.solution.field3_low,
                ),
                fields
            );
            assert_eq!(plan.solution.actual_mhz, f64::from(requested));
            assert_eq!(plan.solution.absolute_error_mhz, 0.0);
            assert_eq!(plan.solution.register_value, register_value);
            assert_eq!(plan.write.frame[3], BM1489_REGISTER_PLL0);
            assert_eq!(&plan.write.frame[4..8], &register_value.to_be_bytes());
            assert!(!plan.solution.authorizes_pll_write());
        }
    }

    #[test]
    fn stock_solver_can_accept_inexact_candidates_but_never_authorizes_them() {
        let low = bm1489_pll_plan(40).unwrap().solution;
        assert_eq!(
            (low.field12, low.field6, low.field3_high, low.field3_low),
            (78, 1, 7, 7)
        );
        assert_eq!(low.vco_mhz, 1_950.0);
        assert!((low.actual_mhz - 39.795_918_367_346_935).abs() < f64::EPSILON);
        assert!(low.absolute_error_mhz > BM1489_PLL_COMPARISON_EPSILON_MHZ);
        assert!(!low.authorizes_pll_write());

        let high = bm1489_pll_plan(3_201).unwrap().solution;
        assert_eq!(high.actual_mhz, 3_200.0);
        assert_eq!(high.absolute_error_mhz, 1.0);
        for refused in [i32::MIN, -1, 0, 32, 4_000, i32::MAX] {
            assert_eq!(
                bm1489_pll_plan(refused),
                Err(Bm1489L7VnishError::NoPllCandidate(refused))
            );
        }
    }

    #[test]
    fn read_polling_contract_is_bounded() {
        assert_eq!(BM1489_READ_OUTER_ATTEMPTS, 5);
        assert_eq!(BM1489_READ_QUEUE_POLLS_PER_ATTEMPT, 8);
        assert_eq!(BM1489_READ_PRE_POLL_DELAY, 10);
        assert_eq!(BM1489_READ_POST_POLL_DELAY, 5);
    }
}
