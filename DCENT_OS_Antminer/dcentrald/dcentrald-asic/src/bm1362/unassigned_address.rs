//! Strict BM1362 reset-baseline GetAddress response validation.
//!
//! Before address assignment BM1362 returns a 9-byte wire frame:
//! `AA 55 13 62 03 00 00 00 0D`. The serial HAL removes `AA 55`, so callers
//! supply the retained 7-byte body. This is a different protocol shape from
//! the 11-byte assigned-address response and must never be parsed as one.

use std::num::NonZeroU8;

use crate::protocol::bm13xx_command_response_crc5;

pub const UNASSIGNED_ADDRESS_BODY_BYTES: usize = 7;
const RECORDED_PAYLOAD: [u8; 6] = [0x13, 0x62, 0x03, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnassignedAddressResponseError {
    Length { observed: usize },
    JobResponseTrailer { trailer: u8 },
    UnsupportedTrailerFlags { trailer: u8 },
    CrcMismatch { expected: u8, observed: u8 },
    NotRecordedBm1362Payload { observed: [u8; 6] },
}

pub fn parse_unassigned_address_body(body: &[u8]) -> Result<(), UnassignedAddressResponseError> {
    if body.len() != UNASSIGNED_ADDRESS_BODY_BYTES {
        return Err(UnassignedAddressResponseError::Length {
            observed: body.len(),
        });
    }
    let trailer = body[6];
    if trailer & 0x80 != 0 {
        return Err(UnassignedAddressResponseError::JobResponseTrailer { trailer });
    }
    if trailer & 0x60 != 0 {
        return Err(UnassignedAddressResponseError::UnsupportedTrailerFlags { trailer });
    }
    let expected = bm13xx_command_response_crc5(&body[..6]);
    let observed = trailer & 0x1f;
    if observed != expected {
        return Err(UnassignedAddressResponseError::CrcMismatch { expected, observed });
    }
    if body[..6] != RECORDED_PAYLOAD {
        return Err(UnassignedAddressResponseError::NotRecordedBm1362Payload {
            observed: body[..6].try_into().expect("length checked above"),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedUnassignedAddressResponse {
    pub response_index: usize,
    pub reason: UnassignedAddressResponseError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnassignedAddressWindowError {
    Empty,
    TooManyResponses { observed: usize },
    Rejected(Vec<RejectedUnassignedAddressResponse>),
}

/// CRC-clean reset-baseline response-window evidence.
///
/// Repetition is deliberately represented only as a frame count. It is not
/// unique-chip or population evidence.
#[must_use = "unassigned BM1362 evidence must be bound to one route generation"]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBm1362UnassignedAddressWindow {
    observed_frames: NonZeroU8,
}

impl ValidatedBm1362UnassignedAddressWindow {
    pub const fn observed_frames(&self) -> NonZeroU8 {
        self.observed_frames
    }
}

pub fn validate_unassigned_address_window<'a, I>(
    responses: I,
) -> Result<ValidatedBm1362UnassignedAddressWindow, UnassignedAddressWindowError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let responses = responses.into_iter().collect::<Vec<_>>();
    if responses.is_empty() {
        return Err(UnassignedAddressWindowError::Empty);
    }
    let observed_frames = u8::try_from(responses.len()).map_err(|_| {
        UnassignedAddressWindowError::TooManyResponses {
            observed: responses.len(),
        }
    })?;
    let observed_frames =
        NonZeroU8::new(observed_frames).ok_or(UnassignedAddressWindowError::Empty)?;

    let rejected = responses
        .into_iter()
        .enumerate()
        .filter_map(|(response_index, response)| {
            parse_unassigned_address_body(response).err().map(|reason| {
                RejectedUnassignedAddressResponse {
                    response_index,
                    reason,
                }
            })
        })
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        return Err(UnassignedAddressWindowError::Rejected(rejected));
    }

    Ok(ValidatedBm1362UnassignedAddressWindow { observed_frames })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKED_BODY: [u8; UNASSIGNED_ADDRESS_BODY_BYTES] =
        [0x13, 0x62, 0x03, 0x00, 0x00, 0x00, 0x0d];

    #[test]
    fn parses_retained_reset_baseline_body() {
        parse_unassigned_address_body(&LOCKED_BODY).unwrap();
        let window = validate_unassigned_address_window([
            &LOCKED_BODY[..],
            &LOCKED_BODY[..],
            &LOCKED_BODY[..],
        ])
        .unwrap();
        assert_eq!(window.observed_frames().get(), 3);
    }

    #[test]
    fn assigned_shape_and_every_integrity_adjacent_mutation_are_rejected() {
        assert!(matches!(
            parse_unassigned_address_body(&[0u8; 9]),
            Err(UnassignedAddressResponseError::Length { observed: 9 })
        ));
        for index in 0..LOCKED_BODY.len() {
            let mut mutated = LOCKED_BODY;
            mutated[index] ^= 1;
            assert!(
                parse_unassigned_address_body(&mutated).is_err(),
                "index {index}"
            );
        }
        let mut job = LOCKED_BODY;
        job[6] |= 0x80;
        assert!(matches!(
            parse_unassigned_address_body(&job),
            Err(UnassignedAddressResponseError::JobResponseTrailer { .. })
        ));
        let mut flags = LOCKED_BODY;
        flags[6] |= 0x20;
        assert!(matches!(
            parse_unassigned_address_body(&flags),
            Err(UnassignedAddressResponseError::UnsupportedTrailerFlags { .. })
        ));
    }

    #[test]
    fn window_rejects_empty_malformed_and_unbounded_input() {
        assert!(matches!(
            validate_unassigned_address_window(std::iter::empty::<&[u8]>()),
            Err(UnassignedAddressWindowError::Empty)
        ));
        let bad = [0u8; UNASSIGNED_ADDRESS_BODY_BYTES];
        assert!(matches!(
            validate_unassigned_address_window([&LOCKED_BODY[..], &bad[..]]),
            Err(UnassignedAddressWindowError::Rejected(rejected)) if rejected.len() == 1
        ));
        let responses = vec![LOCKED_BODY; usize::from(u8::MAX) + 1];
        assert!(matches!(
            validate_unassigned_address_window(responses.iter().map(|body| &body[..])),
            Err(UnassignedAddressWindowError::TooManyResponses { observed: 256 })
        ));
    }
}
