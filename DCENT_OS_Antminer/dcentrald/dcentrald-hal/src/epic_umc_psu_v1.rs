//! Pure decoder for ePIC UMC OS's proprietary PSU-v1 `read_iout_0xe2_v1` reply.
//!
//! This module deliberately contains no I2C handle, request builder, device
//! constructor, retry loop, or production dispatch.  It reconstructs only the
//! reply acceptance behavior observed in the held Xilinx `bms-miner`:
//!
//! - artifact SHA-256:
//!   `b42f2335a4993b868687671095929e6a58a324cd00ada58fd069213b58aeb506`
//! - EHABI unwind coverage containing the async poll:
//!   `0x0067c2b0..0x0067d80b`
//! - E2 decode: `0x0067d00c..0x0067d048`
//! - stats call/consume window inside the `0x00780e40` state machine:
//!   `BL 0x007814a0` through `0x0078152c` (duplicated inside the
//!   `0x00781ff0` state machine at `BL 0x00782650` through `0x007826dc`)
//!
//! Reproduction details and the reason provisional Ghidra function names are
//! not used as boundaries are recorded in
//!
//! EPIC-UMC-XILINX-PSU-E2-RE.md`.
//!
//! The vendor decoder is intentionally permissive: bytes 0 and 1 are ignored,
//! and bytes 2 and 3 participate in the additive checksum but are not checked
//! as a length or opcode.  Tightening those checks here would not reproduce
//! the evidence.  A future live driver may choose a stricter policy, but it
//! must be a separate type and remain disabled until its full transport and
//! model gates are validated.

/// No live transport or runtime dispatcher exists for this evidence-only
/// decoder.  This constant is an explicit assertion for capability ledgers
/// and compile-time tests; changing it is not sufficient to enable dispatch.
pub const LIVE_DISPATCH_AVAILABLE: bool = false;

/// Exact eight-byte reply shape consumed by the ePIC PSU-v1 E2 path.
///
/// Fixed sizing keeps short reads outside the decoder.  The held implementation
/// performs eight separate one-byte I2C transfers and aborts on the first
/// transfer error before reaching its decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpicUmcIoutE2V1Reply([u8; 8]);

impl EpicUmcIoutE2V1Reply {
    /// Construct a reply from an already-complete, transport-independent frame.
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Return the captured bytes without interpreting the unvalidated header.
    pub const fn into_bytes(self) -> [u8; 8] {
        self.0
    }
}

/// Output-current sample in the unit used by the held E2 implementation.
///
/// The decoder converts the little-endian payload directly to `f32`.  Both
/// identified stats callers then divide that value by `1000.0` before storing
/// current and multiply it by similarly normalized volts to obtain watts.
/// Thus the strongest binary-backed unit statement is milliamperes here and
/// amperes at the stats boundary; physical calibration remains live-validation
/// pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpicUmcMilliamps(u16);

impl EpicUmcMilliamps {
    /// Raw unsigned milliamperes returned by the vendor decoder.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Convert to the amperes representation used by the vendor stats caller.
    pub fn as_amperes(self) -> f32 {
        f32::from(self.0) / 1000.0
    }
}

/// Typed checksum failures from the held E2 decoder.
///
/// The vendor error object retains `payload` and `received_checksum`. DCENT
/// additionally reports `calculated_checksum` as an explicitly enriched,
/// host-derived diagnostic so a failed frame can be audited without repeating
/// arithmetic outside this pure decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpicUmcIoutE2V1DecodeError {
    /// Payload `0xF5F5` with a mismatching checksum selects the vendor's
    /// "PSU firmware has crashed" error.  A checksum-valid `0xF5F5` is
    /// accepted as `62965` milliamperes by the held implementation.
    FirmwareCrashSentinel {
        payload: u16,
        calculated_checksum: u16,
        received_checksum: u16,
    },
    /// All other checksum mismatches select the vendor's generic mismatch
    /// error.
    ChecksumMismatch {
        payload: u16,
        calculated_checksum: u16,
        received_checksum: u16,
    },
}

/// Decode one complete ePIC UMC PSU-v1 E2 current reply.
///
/// Checksum parity is exact: the unsigned sum of bytes 2 through 5 is compared
/// with the little-endian `u16` in bytes 6 and 7.  Bytes 0 and 1 are not read;
/// byte 2 is not validated as a length and byte 3 is not validated as `0xE2`.
pub fn decode_iout_e2_v1(
    reply: EpicUmcIoutE2V1Reply,
) -> Result<EpicUmcMilliamps, EpicUmcIoutE2V1DecodeError> {
    let bytes = reply.0;
    let payload = u16::from_le_bytes([bytes[4], bytes[5]]);
    let received = u16::from_le_bytes([bytes[6], bytes[7]]);
    let calculated =
        u16::from(bytes[2]) + u16::from(bytes[3]) + u16::from(bytes[4]) + u16::from(bytes[5]);

    if calculated != received {
        if payload == 0xF5F5 {
            return Err(EpicUmcIoutE2V1DecodeError::FirmwareCrashSentinel {
                payload,
                calculated_checksum: calculated,
                received_checksum: received,
            });
        }
        return Err(EpicUmcIoutE2V1DecodeError::ChecksumMismatch {
            payload,
            calculated_checksum: calculated,
            received_checksum: received,
        });
    }

    Ok(EpicUmcMilliamps(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_not_available() {
        assert!(!LIVE_DISPATCH_AVAILABLE);
    }

    #[test]
    fn decodes_little_endian_milliamps_and_vendor_amp_scaling() {
        // Sum(04 E2 34 12) = 0x012C; payload 0x1234 = 4660 mA.
        let reply = EpicUmcIoutE2V1Reply::new([0x55, 0xAA, 0x04, 0xE2, 0x34, 0x12, 0x2C, 0x01]);
        let sample = decode_iout_e2_v1(reply).expect("synthetic arithmetic KAT must decode");
        assert_eq!(sample.get(), 0x1234);
        assert_eq!(sample.as_amperes(), 4.66);
    }

    #[test]
    fn accepts_zero_payload_with_matching_checksum() {
        let reply = EpicUmcIoutE2V1Reply::new([0x55, 0xAA, 0x04, 0xE2, 0, 0, 0xE6, 0]);
        assert_eq!(decode_iout_e2_v1(reply), Ok(EpicUmcMilliamps(0)));
    }

    #[test]
    fn reproduces_unvalidated_preamble_length_and_opcode() {
        // Bytes 0/1 are ignored.  Bytes 2/3 are checksum inputs only:
        // Sum(99 7F 34 12) = 0x015E.
        let reply = EpicUmcIoutE2V1Reply::new([0x00, 0x00, 0x99, 0x7F, 0x34, 0x12, 0x5E, 0x01]);
        assert_eq!(decode_iout_e2_v1(reply), Ok(EpicUmcMilliamps(0x1234)));
    }

    #[test]
    fn accepts_checksum_valid_f5f5_as_numeric_current() {
        // Sum(04 E2 F5 F5) = 0x02D0.  This follows the held code's actual
        // ordering: the sentinel only changes which error a later checksum
        // mismatch returns.
        let reply = EpicUmcIoutE2V1Reply::new([0x55, 0xAA, 0x04, 0xE2, 0xF5, 0xF5, 0xD0, 0x02]);
        assert_eq!(decode_iout_e2_v1(reply), Ok(EpicUmcMilliamps(0xF5F5)));
    }

    #[test]
    fn maps_bad_checksum_f5f5_to_firmware_crash_sentinel() {
        let reply = EpicUmcIoutE2V1Reply::new([0x55, 0xAA, 0x04, 0xE2, 0xF5, 0xF5, 0, 0]);
        assert_eq!(
            decode_iout_e2_v1(reply),
            Err(EpicUmcIoutE2V1DecodeError::FirmwareCrashSentinel {
                payload: 0xF5F5,
                calculated_checksum: 0x02D0,
                received_checksum: 0,
            })
        );
    }

    #[test]
    fn maps_other_bad_checksum_to_generic_mismatch() {
        let reply = EpicUmcIoutE2V1Reply::new([0x55, 0xAA, 0x04, 0xE2, 0x34, 0x12, 0, 0]);
        assert_eq!(
            decode_iout_e2_v1(reply),
            Err(EpicUmcIoutE2V1DecodeError::ChecksumMismatch {
                payload: 0x1234,
                calculated_checksum: 0x012C,
                received_checksum: 0,
            })
        );
    }
}
