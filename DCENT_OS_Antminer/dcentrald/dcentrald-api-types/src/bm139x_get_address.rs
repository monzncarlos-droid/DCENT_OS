//! BM1397/BM1398-class GetAddress sealed admission (0x52 dialect).
//!
//! Pure / host-testable. Parses cold GetAddress response bodies after the HAL
//! has stripped the `AA 55` preamble. This is **not** the BM136x 9-byte
//! dual-broadcast ChipAddress layout in [`crate`]-adjacent serial parsers —
//! BM1397/BM1398 use the 7-byte 0x52-class response dialect.
//!
//! Sealed admission for NBP1901/S19 Pro binds the observed CRC-clean frame
//! count to [`crate::bm1398_protocol::S19_PRO_NBP1901_CHAIN_SPEC`]'s expected
//! chip count (114). Wrong counts (76 / 113 / 115) and malformed streams fail
//! closed. This module never opens a UART, never energizes a rail, and never
//! weakens the native BM1398 `NOT IMPLEMENTED` gate in product paths.
//!
//! # Retained wire vector
//!
//! S17 Saleae `S17_BasicTest_Cap1.sal` (BM1397 cold GetAddress):
//! `AA 55 | 13 97 18 00 00 00 06`. Body after preamble strip is seven bytes;
//! CRC-5 covers the first six (command/register response init `0x03`).

use crate::bm1398_protocol::{BM1398_CHIP_SPEC, S19_PRO_NBP1901_CHAIN_SPEC};
use dcentrald_common::AsicProtocolIdentity;

/// Bytes after the `AA 55` preamble in a BM1397/BM1398 GetAddress response.
pub const BM139X_GET_ADDRESS_BODY_BYTES: usize = 7;

/// Core-count encoding observed on BM1397/BM1398 ChipAddress/GetAddress
/// readback (`0x1397_1800` / `0x1398_1800` identity word).
pub const BM139X_CORE_COUNT_ENCODING: u8 = 0x18;

/// One CRC-verified BM1397/BM1398-class GetAddress observation.
///
/// Fields are private so callers cannot rewrap raw bytes as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm139xGetAddressObservation {
    identity: AsicProtocolIdentity,
    chip_id: u16,
}

impl Bm139xGetAddressObservation {
    pub const fn identity(self) -> AsicProtocolIdentity {
        self.identity
    }

    pub const fn chip_id(self) -> u16 {
        self.chip_id
    }
}

/// Why a response body is not exact BM139x GetAddress evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm139xGetAddressResponseError {
    Length { observed: usize },
    JobResponseTrailer { trailer: u8 },
    UnsupportedTrailerFlags { trailer: u8 },
    CrcMismatch { expected: u8, observed: u8 },
    UnknownChipId { observed: u16 },
    UnsupportedIdentity { identity: AsicProtocolIdentity },
    CoreCountEncoding { expected: u8, observed: u8 },
    ReservedBytes { observed: [u8; 3] },
}

/// Why a GetAddress window cannot seal NBP1901/S19 Pro admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1398Nbp1901GetAddressAdmissionError {
    Empty,
    Rejected {
        response_index: usize,
        reason: Bm139xGetAddressResponseError,
    },
    MixedIdentity {
        response_index: usize,
        first: AsicProtocolIdentity,
        observed: AsicProtocolIdentity,
    },
    NotBm1398 {
        identity: AsicProtocolIdentity,
    },
    ChipCountMismatch {
        expected: u16,
        observed: u16,
    },
}

/// Move-only sealed admission that a GetAddress window matches the NBP1901 /
/// S19 Pro composition (exactly 114 CRC-clean BM1398 frames).
///
/// Deliberately not `Clone` / `Copy`: consuming this value is how a later
/// bring-up plugin would bind one route generation. Minting it does **not**
/// authorize voltage, address assignment, or mining work.
#[must_use = "sealed BM1398 NBP1901 GetAddress admission must be bound by one consumer"]
#[derive(Debug, PartialEq, Eq)]
pub struct Bm1398Nbp1901GetAddressAdmission {
    _seal: Seal,
    observed_chip_count: u16,
}

#[derive(Debug, PartialEq, Eq)]
enum Seal {
    Admitted,
}

impl Bm1398Nbp1901GetAddressAdmission {
    pub const fn observed_chip_count(&self) -> u16 {
        self.observed_chip_count
    }

    pub const fn expected_chip_count(&self) -> u16 {
        S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count
    }

    pub const fn chip_id(&self) -> u16 {
        BM1398_CHIP_SPEC.chip_id
    }
}

/// Command/register response CRC-5 (init `0x03`), byte-identical to
/// `dcentrald_asic::protocol::bm13xx_command_response_crc5` for the retained
/// BM1397 Saleae vector. Kept local so this module stays HAL-free / Windows-
/// host testable inside `dcentrald-api-types`.
fn bm139x_command_response_crc5(data: &[u8]) -> u8 {
    let mut crc = 0x03u8;
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
    crc & 0x1f
}

/// Parse one exact 7-byte BM1397/BM1398 GetAddress response body.
///
/// Cold unaddressed replies carry reserved zeros in bytes `[3..6)`. Trailer
/// bit 7 (job) and bits 6:5 (unsupported) fail closed.
pub fn parse_bm139x_get_address_body(
    body: &[u8],
) -> Result<Bm139xGetAddressObservation, Bm139xGetAddressResponseError> {
    if body.len() != BM139X_GET_ADDRESS_BODY_BYTES {
        return Err(Bm139xGetAddressResponseError::Length {
            observed: body.len(),
        });
    }

    let trailer = body[6];
    if trailer & 0x80 != 0 {
        return Err(Bm139xGetAddressResponseError::JobResponseTrailer { trailer });
    }
    if trailer & 0x60 != 0 {
        return Err(Bm139xGetAddressResponseError::UnsupportedTrailerFlags { trailer });
    }
    let expected = bm139x_command_response_crc5(&body[..6]);
    let observed = trailer & 0x1f;
    if observed != expected {
        return Err(Bm139xGetAddressResponseError::CrcMismatch { expected, observed });
    }

    let chip_id = u16::from_be_bytes([body[0], body[1]]);
    let identity = AsicProtocolIdentity::from_chip_id(chip_id).ok_or(
        Bm139xGetAddressResponseError::UnknownChipId { observed: chip_id },
    )?;
    match identity {
        AsicProtocolIdentity::Bm1397 | AsicProtocolIdentity::Bm1398 => {}
        other => {
            return Err(Bm139xGetAddressResponseError::UnsupportedIdentity { identity: other });
        }
    }
    if body[2] != BM139X_CORE_COUNT_ENCODING {
        return Err(Bm139xGetAddressResponseError::CoreCountEncoding {
            expected: BM139X_CORE_COUNT_ENCODING,
            observed: body[2],
        });
    }
    if body[3..6] != [0, 0, 0] {
        return Err(Bm139xGetAddressResponseError::ReservedBytes {
            observed: [body[3], body[4], body[5]],
        });
    }

    Ok(Bm139xGetAddressObservation { identity, chip_id })
}

/// Seal a GetAddress window to the NBP1901/S19 Pro composition.
///
/// Requires every response to be a CRC-clean BM1398 cold GetAddress body and
/// the frame count to equal
/// [`S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count`] (114). One malformed
/// frame, a BM1397-only window, or a wrong count refuses the seal.
pub fn admit_bm1398_nbp1901_get_address_window<'a, I>(
    responses: I,
) -> Result<Bm1398Nbp1901GetAddressAdmission, Bm1398Nbp1901GetAddressAdmissionError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let responses = responses.into_iter().collect::<Vec<_>>();
    if responses.is_empty() {
        return Err(Bm1398Nbp1901GetAddressAdmissionError::Empty);
    }

    let expected = S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count;
    let mut identity = None;
    for (response_index, response) in responses.iter().enumerate() {
        match parse_bm139x_get_address_body(response) {
            Ok(observation) => {
                if let Some(first) = identity {
                    if first != observation.identity() {
                        return Err(Bm1398Nbp1901GetAddressAdmissionError::MixedIdentity {
                            response_index,
                            first,
                            observed: observation.identity(),
                        });
                    }
                } else {
                    identity = Some(observation.identity());
                }
            }
            Err(reason) => {
                return Err(Bm1398Nbp1901GetAddressAdmissionError::Rejected {
                    response_index,
                    reason,
                });
            }
        }
    }

    let identity = identity.ok_or(Bm1398Nbp1901GetAddressAdmissionError::Empty)?;
    if identity != AsicProtocolIdentity::Bm1398 {
        return Err(Bm1398Nbp1901GetAddressAdmissionError::NotBm1398 { identity });
    }

    let observed = match u16::try_from(responses.len()) {
        Ok(n) => n,
        Err(_) => {
            return Err(Bm1398Nbp1901GetAddressAdmissionError::ChipCountMismatch {
                expected,
                observed: u16::MAX,
            });
        }
    };
    if observed != expected {
        return Err(Bm1398Nbp1901GetAddressAdmissionError::ChipCountMismatch {
            expected,
            observed,
        });
    }

    Ok(Bm1398Nbp1901GetAddressAdmission {
        _seal: Seal::Admitted,
        observed_chip_count: observed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(chip_id: u16) -> [u8; BM139X_GET_ADDRESS_BODY_BYTES] {
        let [hi, lo] = chip_id.to_be_bytes();
        let mut body = [hi, lo, BM139X_CORE_COUNT_ENCODING, 0, 0, 0, 0];
        body[6] = bm139x_command_response_crc5(&body[..6]);
        body
    }

    #[test]
    fn saleae_bm1397_vector_is_crc_valid() {
        let saleae = [0x13, 0x97, 0x18, 0x00, 0x00, 0x00, 0x06];
        assert_eq!(bm139x_command_response_crc5(&saleae[..6]), 0x06);
        let observation = parse_bm139x_get_address_body(&saleae).unwrap();
        assert_eq!(observation.identity(), AsicProtocolIdentity::Bm1397);
        assert_eq!(observation.chip_id(), 0x1397);
    }

    #[test]
    fn bm1398_cold_get_address_body_parses() {
        let frame = body(0x1398);
        assert_eq!(&frame[..4], &0x1398_1800_u32.to_be_bytes());
        assert_eq!(frame[6], 0x04, "CRC pin for 0x1398_1800 cold body");
        let observation = parse_bm139x_get_address_body(&frame).unwrap();
        assert_eq!(observation.identity(), AsicProtocolIdentity::Bm1398);
    }

    #[test]
    fn refuses_bm1362_nine_byte_dialect_and_wrong_family() {
        // BM1362 9-byte body must not launder through the 0x52-class parser.
        let bm1362_nine = [0x13, 0x62, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d];
        assert!(matches!(
            parse_bm139x_get_address_body(&bm1362_nine),
            Err(Bm139xGetAddressResponseError::Length { observed: 9 })
        ));

        let bm1362_as_seven = {
            let mut b = [0x13, 0x62, 0x03, 0x00, 0x00, 0x00, 0];
            b[6] = bm139x_command_response_crc5(&b[..6]);
            b
        };
        assert!(matches!(
            parse_bm139x_get_address_body(&bm1362_as_seven),
            Err(Bm139xGetAddressResponseError::UnsupportedIdentity {
                identity: AsicProtocolIdentity::Bm1362,
            })
        ));
    }

    #[test]
    fn refuses_malformed_streams() {
        assert!(matches!(
            parse_bm139x_get_address_body(&[]),
            Err(Bm139xGetAddressResponseError::Length { observed: 0 })
        ));

        let valid = body(0x1398);
        let mut bad_crc = valid;
        bad_crc[6] ^= 1;
        assert!(matches!(
            parse_bm139x_get_address_body(&bad_crc),
            Err(Bm139xGetAddressResponseError::CrcMismatch { .. })
        ));

        let mut job = valid;
        job[6] |= 0x80;
        assert!(matches!(
            parse_bm139x_get_address_body(&job),
            Err(Bm139xGetAddressResponseError::JobResponseTrailer { .. })
        ));

        let mut flags = valid;
        flags[6] = (flags[6] & 0x1f) | 0x20;
        assert!(matches!(
            parse_bm139x_get_address_body(&flags),
            Err(Bm139xGetAddressResponseError::UnsupportedTrailerFlags { .. })
        ));

        let mut wrong_core = valid;
        wrong_core[2] = 0x03;
        wrong_core[6] = bm139x_command_response_crc5(&wrong_core[..6]);
        assert!(matches!(
            parse_bm139x_get_address_body(&wrong_core),
            Err(Bm139xGetAddressResponseError::CoreCountEncoding {
                expected: BM139X_CORE_COUNT_ENCODING,
                observed: 0x03,
            })
        ));

        let mut reserved = valid;
        reserved[5] = 1;
        reserved[6] = bm139x_command_response_crc5(&reserved[..6]);
        assert!(matches!(
            parse_bm139x_get_address_body(&reserved),
            Err(Bm139xGetAddressResponseError::ReservedBytes { .. })
        ));
    }

    #[test]
    fn nbp1901_seal_admits_exactly_114_bm1398_frames() {
        let frame = body(0x1398);
        let window = vec![frame; 114];
        let admission = admit_bm1398_nbp1901_get_address_window(window.iter().map(|b| &b[..]))
            .expect("114 BM1398 frames must seal NBP1901");
        assert_eq!(admission.observed_chip_count(), 114);
        assert_eq!(
            admission.expected_chip_count(),
            S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count
        );
        assert_eq!(admission.chip_id(), 0x1398);
        assert_eq!(
            admission.expected_chip_count(),
            S19_PRO_NBP1901_ADDRESS_PLAN_CHIP_COUNT_PIN
        );
    }

    /// Local pin so the seal cannot drift from the address-plan population
    /// without also updating [`S19_PRO_NBP1901_CHAIN_SPEC`].
    const S19_PRO_NBP1901_ADDRESS_PLAN_CHIP_COUNT_PIN: u16 = 114;

    #[test]
    fn nbp1901_seal_refuses_wrong_counts() {
        let frame = body(0x1398);
        for wrong in [76u16, 113, 115] {
            let window = vec![frame; wrong as usize];
            assert!(
                matches!(
                    admit_bm1398_nbp1901_get_address_window(window.iter().map(|b| &b[..])),
                    Err(Bm1398Nbp1901GetAddressAdmissionError::ChipCountMismatch {
                        expected: 114,
                        observed,
                    }) if observed == wrong
                ),
                "count {wrong} must refuse NBP1901 seal"
            );
        }
    }

    #[test]
    fn nbp1901_seal_refuses_bm1397_window_even_at_114() {
        let frame = body(0x1397);
        let window = vec![frame; 114];
        assert!(matches!(
            admit_bm1398_nbp1901_get_address_window(window.iter().map(|b| &b[..])),
            Err(Bm1398Nbp1901GetAddressAdmissionError::NotBm1398 {
                identity: AsicProtocolIdentity::Bm1397,
            })
        ));
    }

    #[test]
    fn nbp1901_seal_refuses_malformed_member_and_empty() {
        assert!(matches!(
            admit_bm1398_nbp1901_get_address_window(std::iter::empty()),
            Err(Bm1398Nbp1901GetAddressAdmissionError::Empty)
        ));

        let good = body(0x1398);
        let mut bad = good;
        bad[6] ^= 1;
        let mut window = vec![good; 114];
        window[50] = bad;
        assert!(matches!(
            admit_bm1398_nbp1901_get_address_window(window.iter().map(|b| &b[..])),
            Err(Bm1398Nbp1901GetAddressAdmissionError::Rejected {
                response_index: 50,
                reason: Bm139xGetAddressResponseError::CrcMismatch { .. },
            })
        ));
    }

    #[test]
    fn sealed_admission_has_no_public_clone_or_copy_surface() {
        let source = include_str!("bm139x_get_address.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("struct Bm1398Nbp1901GetAddressAdmission"));
        assert!(production.contains("_seal: Seal"));
        assert!(!production.contains("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct Bm1398Nbp1901GetAddressAdmission"));
        assert!(!production.contains("impl Clone for Bm1398Nbp1901GetAddressAdmission"));
        assert!(!production.contains("impl Copy for Bm1398Nbp1901GetAddressAdmission"));
    }

    #[test]
    fn address_plan_and_chain_spec_agree_on_114() {
        assert_eq!(S19_PRO_NBP1901_CHAIN_SPEC.expected_chip_count, 114);
        assert_eq!(
            crate::bm1398_protocol::S19_PRO_NBP1901_ADDRESS_PLAN
                .hardware_address(113),
            Some(226)
        );
    }
}
