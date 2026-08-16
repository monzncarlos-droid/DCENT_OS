//! Pure BM1396 PIC command framing recovered from the exact signed S17e/T17e
//! production miners, plus the independently sourced physical-part identity.
//! This module performs no I/O and grants no rail authority.
//!
//! S17e SHA-256 `819bd5ee...c8243`: generic backends `0xbba24` / `0xbc450`,
//! wrappers reset/enable/disable/heartbeat `0x54228` / `0x5426c` / `0x542a8` /
//! `0x542e4`. T17e SHA-256 `d0f14d84...5ffe`: backends `0xbca3c` / `0xbd468`,
//! wrappers `0x54e38` / `0x54e7c` / `0x54eb8` / `0x54ef4`.

use crate::bm1396_contract::Bm1396Model;

pub const BM1396_PIC_CHAIN_SLOT_COUNT: u8 = 16;
pub const BM1396_PIC_I2C_BASE_ADDRESS: u8 = 0x20;
pub const BM1396_PIC_PREAMBLE: [u8; 2] = [0x55, 0xaa];
pub const BM1396_PIC_MAX_ATTEMPTS: u8 = 4;
pub const BM1396_PIC_WRITE_TO_READ_WAIT_MS: u32 = 500;
pub const BM1396_PIC_POST_READ_WAIT_MS: u32 = 500;
pub const BM1396_PIC_INVALID_REPLY_SLEEP_MS: u32 = 1_000;
pub const BM1396_PIC_RAIL_OPCODE: u8 = 0x15;
#[cfg(feature = "recovery-tool")]
pub const BM1396_PIC_APPLICATION_RESET_OPCODE: u8 = 0x07;
#[cfg(feature = "recovery-tool")]
pub const BM1396_PIC_JUMP_TO_APP_OPCODE: u8 = 0x06;
pub const BM1396_PIC_VERSION_OPCODE: u8 = 0x17;
pub const BM1396_PIC_VERSION_RESPONSE_LEN: u8 = 5;
pub const BM1396_PIC_HEARTBEAT_OPCODE: u8 = 0x16;
pub const BM1396_PIC_HEARTBEAT_RESPONSE_LEN: u8 = 6;
pub const BM1396_PIC_HEARTBEAT_PER_CHAIN_DELAY_CALL_VALUE: u32 = 10;
pub const BM1396_PIC_HEARTBEAT_SCAN_SLEEP_MS: u32 = 10_000;
pub const BM1396_PIC_VOLTAGE_DIRECT_SET_SETTLE_MS: u32 = 300;
pub const BM1396_PIC_VOLTAGE_TOLERANCE_V_F64_BITS: u64 = 0x3ff0_0000_0000_0000;
pub const BM1396_PIC_VOLTAGE_MAX_OUTER_ITERATIONS: u8 = 30;
pub const BM1396_PIC_VOLTAGE_INTERCHECK_SLEEP_MS: u32 = 1_000;
pub const BM1396_PIC_VOLTAGE_FAILURE_ERROR_CODE: u8 = 8;
/// Maximum payload whose complete `payload_len + 6` frame fits the exact
/// transport's eight-bit send count without wrapping.
pub const BM1396_PIC_MAX_REQUEST_PAYLOAD_LEN: usize = 249;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396PicEndpoint {
    /// Logical runtime chain slot. The seven-bit address alone is not a unique
    /// chain identity because the recovered formula masks it to three bits.
    pub chain_slot: u8,
    pub i2c_address: u8,
}

/// Physical hashboard controller populated by each exact BM1396 model.
///
/// This is intentionally separate from [`Bm1396PicImplementationRoute`]. The
/// route discriminator is selected from a software board profile and is not a
/// silicon probe. Physical identity instead comes from the model-co-bundled
/// AMTC programming payloads and, for T17e, the maintenance schematic:
///
/// - `S17ePIC.hex` is the 24-bit dsPIC image, byte-identical to `S17PIC.hex`;
/// - `T17ePIC.hex` is the PIC16 image, byte-identical to `S17+PIC.hex` and
///   `T17+PIC.hex`, with PIC16 config words `0x3f94` / `0x1ffe`;
/// - the T17e schematic labels U3 `PIC16F1704-I/SL`.
///
/// The physical part does not select a generic DCENT driver. Both BM1396 rows
/// remain bound to the separately recovered framed application ABI, with live
/// carrier and mutation authority closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PicPhysicalPart {
    Dspic33Ep16Gs202,
    Pic16F1704,
}

pub const fn bm1396_pic_physical_part_for_model(model: Bm1396Model) -> Bm1396PicPhysicalPart {
    match model {
        Bm1396Model::S17e => Bm1396PicPhysicalPart::Dspic33Ep16Gs202,
        Bm1396Model::T17e => Bm1396PicPhysicalPart::Pic16F1704,
    }
}

pub const fn bm1396_pic_endpoint(chain_slot: u8) -> Option<Bm1396PicEndpoint> {
    if chain_slot >= BM1396_PIC_CHAIN_SLOT_COUNT {
        return None;
    }
    Some(Bm1396PicEndpoint {
        chain_slot,
        i2c_address: BM1396_PIC_I2C_BASE_ADDRESS | (chain_slot & 0x07),
    })
}

/// The 2020 binaries add a board-profile-selected pointer to a 32-bit PIC
/// implementation discriminator. It is not probed from the wire. Route names
/// stay observational even though independent artifacts now establish the
/// physical parts, because selector value alone is not part identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PicImplementationRoute {
    DiscriminatorZero,
    DiscriminatorOne,
}

pub const fn bm1396_pic_implementation_route(
    discriminator: u32,
) -> Option<Bm1396PicImplementationRoute> {
    match discriminator {
        0 => Some(Bm1396PicImplementationRoute::DiscriminatorZero),
        1 => Some(Bm1396PicImplementationRoute::DiscriminatorOne),
        _ => None,
    }
}

/// Exact matched-profile route in the signed 2020 model binaries. The route
/// does not itself establish the physical controller part number.
pub const fn bm1396_pic_implementation_route_for_model(
    model: Bm1396Model,
) -> Bm1396PicImplementationRoute {
    match model {
        Bm1396Model::S17e => Bm1396PicImplementationRoute::DiscriminatorZero,
        Bm1396Model::T17e => Bm1396PicImplementationRoute::DiscriminatorOne,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396PicFrameError {
    PayloadTooLong { observed: usize },
}

/// Build `[55, AA, payload_len+4, opcode, payload..., sum_hi, sum_lo]`.
/// The additive u16 checksum covers length, opcode, and payload and is encoded
/// big-endian, unlike the separate I2C-0x11 voltage endpoint checksum.
fn bm1396_pic_request_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>, Bm1396PicFrameError> {
    if payload.len() > BM1396_PIC_MAX_REQUEST_PAYLOAD_LEN {
        return Err(Bm1396PicFrameError::PayloadTooLong {
            observed: payload.len(),
        });
    }
    let Some(length) = payload
        .len()
        .checked_add(4)
        .and_then(|v| u8::try_from(v).ok())
    else {
        return Err(Bm1396PicFrameError::PayloadTooLong {
            observed: payload.len(),
        });
    };
    let checksum = payload
        .iter()
        .fold(u16::from(length) + u16::from(opcode), |sum, byte| {
            sum.wrapping_add(u16::from(*byte))
        });
    let mut frame = Vec::with_capacity(payload.len() + 6);
    frame.extend(BM1396_PIC_PREAMBLE);
    frame.push(length);
    frame.push(opcode);
    frame.extend(payload);
    frame.extend(checksum.to_be_bytes());
    Ok(frame)
}

/// Exact stock response acceptance. There is no response-checksum check.
///
/// A two-byte response must be `[opcode, 1]`. Longer replies must begin with
/// `[expected_len, opcode]`; all remaining bytes are unchecked by stock.
pub fn bm1396_pic_response_accepted(response: &[u8], expected_len: u8, opcode: u8) -> bool {
    if response.len() != usize::from(expected_len) || expected_len < 2 {
        return false;
    }
    if expected_len == 2 {
        response == [opcode, 0x01]
    } else {
        response[0] == expected_len && response[1] == opcode
    }
}

pub fn bm1396_pic_rail_enable_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_RAIL_OPCODE, &[1]).expect("fixed BM1396 rail payload")
}

pub fn bm1396_pic_rail_disable_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_RAIL_OPCODE, &[0]).expect("fixed BM1396 rail payload")
}

#[cfg(feature = "recovery-tool")]
pub fn bm1396_pic_application_reset_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_APPLICATION_RESET_OPCODE, &[])
        .expect("fixed BM1396 application-reset payload")
}

#[cfg(feature = "recovery-tool")]
pub fn bm1396_pic_jump_to_app_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_JUMP_TO_APP_OPCODE, &[])
        .expect("fixed BM1396 jump-to-app payload")
}

pub fn bm1396_pic_version_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_VERSION_OPCODE, &[]).expect("fixed BM1396 version payload")
}

pub fn bm1396_pic_heartbeat_frame() -> Vec<u8> {
    bm1396_pic_request_frame(BM1396_PIC_HEARTBEAT_OPCODE, &[])
        .expect("fixed BM1396 heartbeat payload")
}

/// Safe representation of the recovered heartbeat-counter behavior: success
/// clears and failure only increments/logs. Stock uses a signed native `+1`;
/// DCENT saturates instead of reproducing overflow. There is no stock threshold,
/// rail cut, or recovery action in this thread.
pub const fn bm1396_safe_heartbeat_failure_count(previous: u32, accepted: bool) -> u32 {
    if accepted {
        0
    } else {
        previous.saturating_add(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1396PicVoltageCheckError {
    NoActiveChains,
    NonFiniteTarget { observed: f64 },
    NonFiniteActual { chain_index: usize, observed: f64 },
}

/// Exact all-active-chain tolerance check. Equality at 1.0 V passes. The
/// caller supplies only readings for chains it currently marks active.
pub fn bm1396_pic_voltage_sample_passes(
    target_v: f64,
    active_chain_actual_v: &[f64],
) -> Result<bool, Bm1396PicVoltageCheckError> {
    if !target_v.is_finite() {
        return Err(Bm1396PicVoltageCheckError::NonFiniteTarget { observed: target_v });
    }
    if active_chain_actual_v.is_empty() {
        return Err(Bm1396PicVoltageCheckError::NoActiveChains);
    }
    let tolerance = f64::from_bits(BM1396_PIC_VOLTAGE_TOLERANCE_V_F64_BITS);
    for (chain_index, actual) in active_chain_actual_v.iter().copied().enumerate() {
        if !actual.is_finite() {
            return Err(Bm1396PicVoltageCheckError::NonFiniteActual {
                chain_index,
                observed: actual,
            });
        }
        if (actual - target_v).abs() > tolerance {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396PicVoltageIterationDecision {
    Success,
    RetryAfterSleep { completed_iterations: u8 },
    FatalError(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396PicVoltageIterationError {
    IterationBudgetExhausted,
    MissingSecondCheckAfterPass,
    UnexpectedSecondCheckAfterFailure,
}

/// Fold one exact outer verification iteration. A passing first check requires
/// a second check after 1 s. Any failure consumes the iteration and adds the
/// bottom 1 s sleep; the thirtieth failed iteration routes fatal error 8.
pub const fn bm1396_pic_voltage_verification_iteration(
    completed_iterations: u8,
    first_check_passed: bool,
    second_check_passed: Option<bool>,
) -> Result<Bm1396PicVoltageIterationDecision, Bm1396PicVoltageIterationError> {
    if completed_iterations >= BM1396_PIC_VOLTAGE_MAX_OUTER_ITERATIONS {
        return Err(Bm1396PicVoltageIterationError::IterationBudgetExhausted);
    }
    match (first_check_passed, second_check_passed) {
        (true, Some(true)) => Ok(Bm1396PicVoltageIterationDecision::Success),
        (true, Some(false)) | (false, None) => {
            let completed_iterations = completed_iterations + 1;
            if completed_iterations == BM1396_PIC_VOLTAGE_MAX_OUTER_ITERATIONS {
                Ok(Bm1396PicVoltageIterationDecision::FatalError(
                    BM1396_PIC_VOLTAGE_FAILURE_ERROR_CODE,
                ))
            } else {
                Ok(Bm1396PicVoltageIterationDecision::RetryAfterSleep {
                    completed_iterations,
                })
            }
        }
        (true, None) => Err(Bm1396PicVoltageIterationError::MissingSecondCheckAfterPass),
        (false, Some(_)) => Err(Bm1396PicVoltageIterationError::UnexpectedSecondCheckAfterFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_preserves_logical_slot_while_exposing_exact_masked_address() {
        assert_eq!(
            bm1396_pic_endpoint(0),
            Some(Bm1396PicEndpoint {
                chain_slot: 0,
                i2c_address: 0x20,
            })
        );
        assert_eq!(bm1396_pic_endpoint(7).unwrap().i2c_address, 0x27);
        assert_eq!(
            bm1396_pic_endpoint(8),
            Some(Bm1396PicEndpoint {
                chain_slot: 8,
                i2c_address: 0x20,
            })
        );
        assert_eq!(bm1396_pic_endpoint(15).unwrap().i2c_address, 0x27);
        assert_eq!(bm1396_pic_endpoint(16), None);
        assert_eq!(
            bm1396_pic_implementation_route(0),
            Some(Bm1396PicImplementationRoute::DiscriminatorZero)
        );
        assert_eq!(
            bm1396_pic_implementation_route(1),
            Some(Bm1396PicImplementationRoute::DiscriminatorOne)
        );
        assert_eq!(bm1396_pic_implementation_route(2), None);
        assert_eq!(bm1396_pic_implementation_route(0x100), None);
        assert_eq!(bm1396_pic_implementation_route(0x101), None);
        assert_eq!(
            bm1396_pic_implementation_route_for_model(Bm1396Model::S17e),
            Bm1396PicImplementationRoute::DiscriminatorZero
        );
        assert_eq!(
            bm1396_pic_implementation_route_for_model(Bm1396Model::T17e),
            Bm1396PicImplementationRoute::DiscriminatorOne
        );
    }

    #[test]
    fn physical_part_identity_is_model_bound_and_not_derived_from_route_number() {
        assert_eq!(
            bm1396_pic_physical_part_for_model(Bm1396Model::S17e),
            Bm1396PicPhysicalPart::Dspic33Ep16Gs202
        );
        assert_eq!(
            bm1396_pic_physical_part_for_model(Bm1396Model::T17e),
            Bm1396PicPhysicalPart::Pic16F1704
        );

        // Keep the two evidence axes visibly distinct: route values are a
        // matched-profile software contract, while part identities come from
        // the model-co-bundled MCU payloads and physical documentation.
        assert_eq!(
            bm1396_pic_implementation_route_for_model(Bm1396Model::S17e),
            Bm1396PicImplementationRoute::DiscriminatorZero
        );
        assert_eq!(
            bm1396_pic_implementation_route_for_model(Bm1396Model::T17e),
            Bm1396PicImplementationRoute::DiscriminatorOne
        );
    }

    #[test]
    fn exact_command_frames_are_pinned() {
        assert_eq!(
            bm1396_pic_rail_enable_frame(),
            [0x55, 0xaa, 0x05, 0x15, 0x01, 0x00, 0x1b]
        );
        assert_eq!(
            bm1396_pic_rail_disable_frame(),
            [0x55, 0xaa, 0x05, 0x15, 0x00, 0x00, 0x1a]
        );
        assert_eq!(
            bm1396_pic_version_frame(),
            [0x55, 0xaa, 0x04, 0x17, 0x00, 0x1b]
        );
        assert_eq!(
            bm1396_pic_heartbeat_frame(),
            [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a]
        );
        assert_eq!(BM1396_PIC_MAX_ATTEMPTS, 4);
        assert_eq!(BM1396_PIC_WRITE_TO_READ_WAIT_MS, 500);
        assert_eq!(BM1396_PIC_POST_READ_WAIT_MS, 500);
        assert_eq!(BM1396_PIC_INVALID_REPLY_SLEEP_MS, 1_000);
        assert_eq!(BM1396_PIC_VERSION_RESPONSE_LEN, 5);
        assert!(bm1396_pic_request_frame(0, &[0; 249]).is_ok());
        assert_eq!(
            bm1396_pic_request_frame(0, &[0; 250]),
            Err(Bm1396PicFrameError::PayloadTooLong { observed: 250 })
        );
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn destructive_command_symbols_exist_only_for_recovery_tool() {
        assert_eq!(
            bm1396_pic_application_reset_frame(),
            [0x55, 0xaa, 0x04, 0x07, 0x00, 0x0b]
        );
        assert_eq!(
            bm1396_pic_jump_to_app_frame(),
            [0x55, 0xaa, 0x04, 0x06, 0x00, 0x0a]
        );
    }

    #[test]
    fn stock_response_acceptance_is_exact_and_deliberately_weak_for_long_replies() {
        assert!(bm1396_pic_response_accepted(&[0x15, 1], 2, 0x15));
        assert!(!bm1396_pic_response_accepted(&[0x15, 0], 2, 0x15));
        assert!(bm1396_pic_response_accepted(
            &[6, 0x16, 0xde, 0xad, 0xbe, 0xef],
            6,
            0x16
        ));
        assert!(!bm1396_pic_response_accepted(
            &[6, 0x15, 0xde, 0xad, 0xbe, 0xef],
            6,
            0x16
        ));
        assert!(!bm1396_pic_response_accepted(&[0x16, 1], 6, 0x16));
    }

    #[test]
    fn stock_heartbeat_counter_has_no_safety_threshold() {
        assert_eq!(bm1396_safe_heartbeat_failure_count(0, false), 1);
        assert_eq!(bm1396_safe_heartbeat_failure_count(99, false), 100);
        assert_eq!(
            bm1396_safe_heartbeat_failure_count(u32::MAX, false),
            u32::MAX
        );
        assert_eq!(bm1396_safe_heartbeat_failure_count(100, true), 0);
        assert_eq!(BM1396_PIC_HEARTBEAT_PER_CHAIN_DELAY_CALL_VALUE, 10);
        assert_eq!(BM1396_PIC_HEARTBEAT_SCAN_SLEEP_MS, 10_000);
    }

    #[test]
    fn pic_voltage_verifier_requires_two_consecutive_checks_and_is_bounded() {
        assert_eq!(
            bm1396_pic_voltage_sample_passes(20.0, &[19.0, 20.5, 21.0]),
            Ok(true)
        );
        assert_eq!(bm1396_pic_voltage_sample_passes(20.0, &[18.99]), Ok(false));
        assert_eq!(
            bm1396_pic_voltage_sample_passes(20.0, &[]),
            Err(Bm1396PicVoltageCheckError::NoActiveChains)
        );
        assert_eq!(
            bm1396_pic_voltage_verification_iteration(0, true, Some(true)),
            Ok(Bm1396PicVoltageIterationDecision::Success)
        );
        assert_eq!(
            bm1396_pic_voltage_verification_iteration(0, true, Some(false)),
            Ok(Bm1396PicVoltageIterationDecision::RetryAfterSleep {
                completed_iterations: 1,
            })
        );
        assert_eq!(
            bm1396_pic_voltage_verification_iteration(29, false, None),
            Ok(Bm1396PicVoltageIterationDecision::FatalError(8))
        );
        assert_eq!(
            bm1396_pic_voltage_verification_iteration(30, false, None),
            Err(Bm1396PicVoltageIterationError::IterationBudgetExhausted)
        );
        assert_eq!(BM1396_PIC_VOLTAGE_DIRECT_SET_SETTLE_MS, 300);
        assert_eq!(BM1396_PIC_VOLTAGE_INTERCHECK_SLEEP_MS, 1_000);
    }
}
