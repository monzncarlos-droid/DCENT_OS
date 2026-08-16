//! Sealed BM1398 GetAddress admission for NBP1901 / S19 Pro (RE-4A desk work).
//!
//! This is the BM1397/BM1398-class **0x52** response dialect: a 7-byte body after
//! the HAL strips `AA 55`. It is intentionally separate from the BM1362/BM136x
//! 9-byte dual-broadcast ChipAddress parser in `dcentrald_asic::serial_chip_address`,
//! which must keep rejecting BM1398 (`UnsupportedIdentityLayout`).
//!
//! Host-testable pure protocol admission (lives in api-types next to the NBP1901
//! pins). Minting [`Nbp1901Bm1398GetAddressAdmission`] proves an exact 114-frame
//! CRC-clean BM1398 reset-baseline window matching
//! [`crate::bm1398_protocol::S19_PRO_NBP1901_CHAIN_SPEC`]. It does **not** energize
//! rails, authorize voltage/ASIC mutation, raise baud, open cores, or clear the
//! native BM1398 `NOT IMPLEMENTED` bail in `serial_mining`.
//!
//! Locked unassigned payload: ChipAddress reset `0x1398_1800` -> body
//! `[0x13, 0x98, 0x18, 0x00, 0x00, 0x00]` + response CRC5 (retained sibling
//! BM1397 vector `[0x13, 0x97, 0x18, 0x00, 0x00, 0x00]/0x06` pins the layout).

use std::num::NonZeroU8;

use crate::bm1398_protocol::{BM1398_CHIP_SPEC, S19_PRO_NBP1901_CHAIN_SPEC};

/// Bytes after the `AA 55` preamble in a BM1398/BM1397-class GetAddress response.
pub const BM1398_GET_ADDRESS_BODY_BYTES: usize = 7;

/// Exact NBP1901 / S19 Pro population required to mint sealed admission.
pub const NBP1901_BM1398_EXPECTED_CHIP_COUNT: u16 = S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count;

/// ChipAddress reset-baseline payload before the CRC trailer.
///
/// `0x1398` ChipID, `0x18` CORE_NUM encoding, address/reserved zeros — matches
/// the documented BM1398 ChipAddress reset word `0x13981800`.
const RECORDED_UNASSIGNED_PAYLOAD: [u8; 6] = [0x13, 0x98, 0x18, 0x00, 0x00, 0x00];

/// BM13xx *command-response* CRC5 (init `0x03`). Byte-identical to
/// `dcentrald_asic::protocol::bm13xx_command_response_crc5` so this host-safe
/// crate can validate GetAddress bodies without linking the Unix HAL.
///
/// Source contract: `contracts/asic-wire/v1/bm13xx-response-crc5.json`.
fn bm13xx_command_response_crc5(data: &[u8]) -> u8 {
    let mut crc = 0x03u8 & 0x1f;
    for &byte in data {
        for bit_index in (0..8).rev() {
            let data_bit = (byte >> bit_index) & 1;
            let feedback = data_bit ^ ((crc >> 4) & 1);
            crc = (((crc >> 3) & 1) << 4)
                | ((((crc >> 2) & 1) ^ data_bit) << 3)
                | ((((crc >> 1) & 1) ^ feedback) << 2)
                | ((crc & 1) << 1)
                | feedback;
        }
    }
    crc
}

/// One CRC-verified BM1398 reset-baseline GetAddress body.
///
/// Fields are private so callers cannot rewrap raw serial bytes as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398GetAddressObservation {
    chip_id: u16,
    core_num_encoding: u8,
}

impl Bm1398GetAddressObservation {
    pub const fn chip_id(self) -> u16 {
        self.chip_id
    }

    pub const fn core_num_encoding(self) -> u8 {
        self.core_num_encoding
    }
}

/// Why a response body is not BM1398 GetAddress evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1398GetAddressResponseError {
    Length { observed: usize },
    JobResponseTrailer { trailer: u8 },
    UnsupportedTrailerFlags { trailer: u8 },
    CrcMismatch { expected: u8, observed: u8 },
    NotRecordedBm1398Payload { observed: [u8; 6] },
}

/// Parse one exact 7-byte BM1398 GetAddress response body (HAL-stripped).
pub fn parse_bm1398_get_address_body(
    body: &[u8],
) -> Result<Bm1398GetAddressObservation, Bm1398GetAddressResponseError> {
    if body.len() != BM1398_GET_ADDRESS_BODY_BYTES {
        return Err(Bm1398GetAddressResponseError::Length {
            observed: body.len(),
        });
    }
    let trailer = body[6];
    if trailer & 0x80 != 0 {
        return Err(Bm1398GetAddressResponseError::JobResponseTrailer { trailer });
    }
    if trailer & 0x60 != 0 {
        return Err(Bm1398GetAddressResponseError::UnsupportedTrailerFlags { trailer });
    }
    let expected = bm13xx_command_response_crc5(&body[..6]);
    let observed = trailer & 0x1f;
    if observed != expected {
        return Err(Bm1398GetAddressResponseError::CrcMismatch { expected, observed });
    }
    if body[..6] != RECORDED_UNASSIGNED_PAYLOAD {
        return Err(Bm1398GetAddressResponseError::NotRecordedBm1398Payload {
            observed: body[..6].try_into().expect("length checked above"),
        });
    }
    debug_assert_eq!(BM1398_CHIP_SPEC.chip_id, 0x1398);
    Ok(Bm1398GetAddressObservation {
        chip_id: BM1398_CHIP_SPEC.chip_id,
        core_num_encoding: RECORDED_UNASSIGNED_PAYLOAD[2],
    })
}

/// Rejected frame plus its stable index in the supplied window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedBm1398GetAddressResponse {
    pub response_index: usize,
    pub reason: Bm1398GetAddressResponseError,
}

/// Why a complete GetAddress window cannot mint NBP1901 sealed admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nbp1901Bm1398GetAddressAdmissionError {
    Empty,
    TooManyResponses { observed: usize },
    PopulationMismatch { observed: usize, expected: u16 },
    Rejected(Vec<RejectedBm1398GetAddressResponse>),
}

/// Move-only sealed admission for an exact NBP1901/S19 Pro BM1398 GetAddress window.
///
/// Deliberately not `Clone` or `Copy`. Population is exact-114 only; wrong-SKU
/// counts (76 / 113 / 115) and malformed streams never mint this value.
#[must_use = "NBP1901 BM1398 GetAddress admission must be bound by one consumer"]
#[derive(Debug, PartialEq, Eq)]
pub struct Nbp1901Bm1398GetAddressAdmission {
    _seal: Seal,
    observed_frames: NonZeroU8,
}

#[derive(Debug, PartialEq, Eq)]
enum Seal {
    Admitted,
}

impl Nbp1901Bm1398GetAddressAdmission {
    pub const fn observed_frames(&self) -> NonZeroU8 {
        self.observed_frames
    }

    pub const fn expected_chip_count(&self) -> u16 {
        NBP1901_BM1398_EXPECTED_CHIP_COUNT
    }

    pub const fn chip_id(&self) -> u16 {
        BM1398_CHIP_SPEC.chip_id
    }
}

/// Admit an exact 114-frame CRC-clean BM1398 reset-baseline GetAddress window.
///
/// One malformed, sibling-family, CRC-damaged, or wrong-count response rejects
/// the complete window. Frame count is the NBP1901 population gate — not a
/// claim that both XIL UARTs are owned.
pub fn admit_nbp1901_bm1398_get_address_window<'a, I>(
    responses: I,
) -> Result<Nbp1901Bm1398GetAddressAdmission, Nbp1901Bm1398GetAddressAdmissionError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let responses = responses.into_iter().collect::<Vec<_>>();
    if responses.is_empty() {
        return Err(Nbp1901Bm1398GetAddressAdmissionError::Empty);
    }
    if responses.len() > u8::MAX as usize {
        return Err(Nbp1901Bm1398GetAddressAdmissionError::TooManyResponses {
            observed: responses.len(),
        });
    }
    if responses.len() as u16 != NBP1901_BM1398_EXPECTED_CHIP_COUNT {
        return Err(Nbp1901Bm1398GetAddressAdmissionError::PopulationMismatch {
            observed: responses.len(),
            expected: NBP1901_BM1398_EXPECTED_CHIP_COUNT,
        });
    }

    let rejected = responses
        .iter()
        .enumerate()
        .filter_map(|(response_index, response)| {
            parse_bm1398_get_address_body(response).err().map(|reason| {
                RejectedBm1398GetAddressResponse {
                    response_index,
                    reason,
                }
            })
        })
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        return Err(Nbp1901Bm1398GetAddressAdmissionError::Rejected(rejected));
    }

    let observed_frames = NonZeroU8::new(responses.len() as u8)
        .ok_or(Nbp1901Bm1398GetAddressAdmissionError::Empty)?;
    Ok(Nbp1901Bm1398GetAddressAdmission {
        _seal: Seal::Admitted,
        observed_frames,
    })
}

/// Build the locked CRC-clean unassigned BM1398 GetAddress body (host tests).
pub fn locked_bm1398_unassigned_get_address_body() -> [u8; BM1398_GET_ADDRESS_BODY_BYTES] {
    let mut body = [0u8; BM1398_GET_ADDRESS_BODY_BYTES];
    body[..6].copy_from_slice(&RECORDED_UNASSIGNED_PAYLOAD);
    body[6] = bm13xx_command_response_crc5(&RECORDED_UNASSIGNED_PAYLOAD);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("bm1398_get_address.rs");

    #[test]
    fn locked_body_matches_retained_layout_and_crc() {
        let body = locked_bm1398_unassigned_get_address_body();
        assert_eq!(&body[..6], &RECORDED_UNASSIGNED_PAYLOAD);
        assert_eq!(body[6], 0x04, "BM1398 unassigned CRC5 must stay pinned");
        // Sibling BM1397 retained vector pins the same CORE_NUM / zero layout.
        assert_eq!(
            bm13xx_command_response_crc5(&[0x13, 0x97, 0x18, 0x00, 0x00, 0x00]),
            0x06
        );
        let obs = parse_bm1398_get_address_body(&body).unwrap();
        assert_eq!(obs.chip_id(), 0x1398);
        assert_eq!(obs.core_num_encoding(), 0x18);
        assert_eq!(obs.chip_id(), BM1398_CHIP_SPEC.chip_id);
    }

    #[test]
    fn exact_114_window_mints_sealed_nbp1901_admission() {
        let body = locked_bm1398_unassigned_get_address_body();
        let responses = vec![body; 114];
        let admission =
            admit_nbp1901_bm1398_get_address_window(responses.iter().map(|b| &b[..]))
                .expect("exact 114 BM1398 frames must admit NBP1901");
        assert_eq!(admission.observed_frames().get(), 114);
        assert_eq!(admission.expected_chip_count(), 114);
        assert_eq!(admission.chip_id(), 0x1398);
        assert_eq!(
            admission.expected_chip_count(),
            S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count
        );
    }

    #[test]
    fn refuses_s19_non_pro_76_and_off_by_one_populations() {
        let body = locked_bm1398_unassigned_get_address_body();
        for count in [76usize, 113, 115] {
            let responses = vec![body; count];
            assert!(
                matches!(
                    admit_nbp1901_bm1398_get_address_window(responses.iter().map(|b| &b[..])),
                    Err(Nbp1901Bm1398GetAddressAdmissionError::PopulationMismatch {
                        observed,
                        expected: 114
                    }) if observed == count
                ),
                "count {count} must refuse NBP1901 seal"
            );
        }
    }

    #[test]
    fn refuses_empty_unbounded_and_malformed_streams() {
        assert!(matches!(
            admit_nbp1901_bm1398_get_address_window(std::iter::empty::<&[u8]>()),
            Err(Nbp1901Bm1398GetAddressAdmissionError::Empty)
        ));

        let body = locked_bm1398_unassigned_get_address_body();
        let mut bad_window = vec![body; 114];
        bad_window[50] = [0u8; BM1398_GET_ADDRESS_BODY_BYTES];
        assert!(matches!(
            admit_nbp1901_bm1398_get_address_window(bad_window.iter().map(|b| &b[..])),
            Err(Nbp1901Bm1398GetAddressAdmissionError::Rejected(rejected))
                if rejected.len() == 1 && rejected[0].response_index == 50
        ));

        let too_many = vec![body; usize::from(u8::MAX) + 1];
        assert!(matches!(
            admit_nbp1901_bm1398_get_address_window(too_many.iter().map(|b| &b[..])),
            Err(Nbp1901Bm1398GetAddressAdmissionError::TooManyResponses { observed: 256 })
        ));
    }

    #[test]
    fn parse_rejects_length_crc_job_flags_and_sibling_payloads() {
        assert!(matches!(
            parse_bm1398_get_address_body(&[0u8; 9]),
            Err(Bm1398GetAddressResponseError::Length { observed: 9 })
        ));
        // BM1362 unassigned 7-byte shape must not launder as BM1398.
        assert!(matches!(
            parse_bm1398_get_address_body(&[0x13, 0x62, 0x03, 0x00, 0x00, 0x00, 0x0d]),
            Err(Bm1398GetAddressResponseError::NotRecordedBm1398Payload { .. })
        ));
        // BM1397 sibling ChipID.
        let mut bm1397 = locked_bm1398_unassigned_get_address_body();
        bm1397[1] = 0x97;
        bm1397[6] = bm13xx_command_response_crc5(&bm1397[..6]);
        assert!(matches!(
            parse_bm1398_get_address_body(&bm1397),
            Err(Bm1398GetAddressResponseError::NotRecordedBm1398Payload { .. })
        ));

        let locked = locked_bm1398_unassigned_get_address_body();
        for index in 0..locked.len() {
            let mut mutated = locked;
            mutated[index] ^= 1;
            assert!(
                parse_bm1398_get_address_body(&mutated).is_err(),
                "index {index}"
            );
        }
        let mut job = locked;
        job[6] |= 0x80;
        assert!(matches!(
            parse_bm1398_get_address_body(&job),
            Err(Bm1398GetAddressResponseError::JobResponseTrailer { .. })
        ));
        let mut flags = locked;
        flags[6] |= 0x20;
        assert!(matches!(
            parse_bm1398_get_address_body(&flags),
            Err(Bm1398GetAddressResponseError::UnsupportedTrailerFlags { .. })
        ));
    }

    #[test]
    fn capability_has_no_public_mint_clone_or_copy_surface() {
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("pub struct Nbp1901Bm1398GetAddressAdmission"));
        assert!(production.contains("_seal: Seal"));
        assert!(!production.contains("impl Clone for Nbp1901Bm1398GetAddressAdmission"));
        assert!(!production.contains("impl Copy for Nbp1901Bm1398GetAddressAdmission"));
        assert!(production.contains("admit_nbp1901_bm1398_get_address_window"));
    }

    #[test]
    fn dialect_constant_is_bm139x_seven_byte_not_bm1362_nine() {
        assert_eq!(BM1398_GET_ADDRESS_BODY_BYTES, 7);
        assert_eq!(
            BM1398_GET_ADDRESS_BODY_BYTES,
            usize::from(BM1398_CHIP_SPEC.response.body_bytes)
        );
        assert_eq!(NBP1901_BM1398_EXPECTED_CHIP_COUNT, 114);
        // Address + UART-relay plan remain load-bearing on the chain spec pin.
        assert_eq!(S19_PRO_NBP1901_CHAIN_SPEC.voltage_domain_count, 38);
        assert_eq!(
            S19_PRO_NBP1901_CHAIN_SPEC.production_uart_relay_writes.len(),
            12
        );
        // BM1362 serial ChipAddress bodies are 9 bytes; this dialect must not
        // silently widen to that shape.
        assert_ne!(BM1398_GET_ADDRESS_BODY_BYTES, 9);
    }
}
