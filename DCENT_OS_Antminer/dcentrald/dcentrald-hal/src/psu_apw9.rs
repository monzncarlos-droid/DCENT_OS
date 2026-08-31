//! Fail-closed host types for held S17/S17 Pro APW9 framed I²C evidence.
//!
//! Ported from `dcent_toolbox.core.apw9_framed_i2c` as **host-only**
//! encode/decode. This module has no I²C handle, no GPIO, and no live
//! dispatch. SET_VOLTAGE is refused: a structurally valid echo does not
//! prove the rail moved, and no millivolt LSB is invented here.
//!
//! Held request vectors (Toolbox `test_apw9_framed_i2c.py`):
//! - GET_FIRMWARE_VERSION `55 aa 04 01 05 00`
//! - GET_TYPE_VERSION `55 aa 04 02 06 00`
//! - SET DAC `0xC8` `55 aa 06 83 c8 00 51 01` (evidence bytes only)

use crate::{HalError, Result};

/// No live transport or runtime dispatcher exists for this codec.
pub const LIVE_DISPATCH_AVAILABLE: bool = false;

/// Linux 7-bit I²C address from the shared signed-root sender.
pub const APW9_I2C_ADDR_7BIT: u8 = 0x10;
/// Register/selector byte used by the held sender. Distinct from the jig's
/// packed FPGA selector `0x52`.
pub const APW9_I2C_REGISTER: u8 = 0x11;
/// Jig packed FPGA selector observation. Never a Linux I²C address.
pub const APW9_JIG_PACKED_FPGA_SELECTOR: u8 = 0x52;
/// Exact positive APW9 identity byte from the jig probe.
pub const APW9_JIG_IDENTITY_BYTE: u8 = 0xF5;

pub const APW9_PREAMBLE: [u8; 2] = [0x55, 0xAA];
pub const APW9_MIN_FRAME_BYTES: usize = 6;
pub const APW9_MAX_FRAME_BYTES: usize = 257;
pub const APW9_FIXED_REPLY_BYTES: usize = 8;

pub const APW9_CMD_GET_FIRMWARE_VERSION: u8 = 0x01;
pub const APW9_CMD_GET_TYPE_VERSION: u8 = 0x02;
/// Held SET opcode. [`Apw9Codec::set_voltage_mv`] refuses; this constant is
/// not a write grant.
pub const APW9_CMD_SET_VOLTAGE: u8 = 0x83;

/// Pinned held SET frame for DAC `0xC8`. Decode-only evidence.
pub const APW9_HELD_SET_VOLTAGE_DAC_C8: [u8; 8] = [0x55, 0xAA, 0x06, 0x83, 0xC8, 0x00, 0x51, 0x01];

/// Commands present in both exact signed S17 and S17 Pro roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apw9Command {
    GetFirmwareVersion,
    GetTypeVersion,
}

impl Apw9Command {
    pub const fn opcode(self) -> u8 {
        match self {
            Self::GetFirmwareVersion => APW9_CMD_GET_FIRMWARE_VERSION,
            Self::GetTypeVersion => APW9_CMD_GET_TYPE_VERSION,
        }
    }

    pub const fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            APW9_CMD_GET_FIRMWARE_VERSION => Some(Self::GetFirmwareVersion),
            APW9_CMD_GET_TYPE_VERSION => Some(Self::GetTypeVersion),
            _ => None,
        }
    }
}

/// One checksum-verified immutable frame. Host types only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apw9Frame {
    pub raw: Vec<u8>,
    pub length_field: u8,
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub checksum: u16,
}

/// Fail-closed APW9 host codec. Constructing this type does not open a bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct Apw9Codec;

impl Apw9Codec {
    pub const fn new() -> Self {
        Self
    }

    /// Unsigned 16-bit additive checksum of `body` (LEN+CMD+payload).
    pub fn additive_checksum16(body: &[u8]) -> u16 {
        body.iter()
            .fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)))
    }

    /// Encode a held GET request. SET is not an admitted encoder.
    pub fn encode_request(command: Apw9Command) -> Vec<u8> {
        Self::encode_known(command.opcode(), &[])
    }

    fn encode_known(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let length_field = 4 + payload.len();
        let mut body = Vec::with_capacity(2 + payload.len());
        body.push(length_field as u8);
        body.push(opcode);
        body.extend_from_slice(payload);
        let checksum = Self::additive_checksum16(&body);
        let mut frame = Vec::with_capacity(2 + body.len() + 2);
        frame.extend_from_slice(&APW9_PREAMBLE);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&checksum.to_le_bytes());
        frame
    }

    /// Fail closed on one immutable frame.
    pub fn decode_frame(raw: &[u8]) -> Result<Apw9Frame> {
        if raw.len() < APW9_MIN_FRAME_BYTES || raw.len() > APW9_MAX_FRAME_BYTES {
            return Err(HalError::PsuProtocolOwned(
                "APW9 frame length is outside bounded policy".into(),
            ));
        }
        if raw[..2] != APW9_PREAMBLE {
            return Err(HalError::PsuProtocolOwned(
                "APW9 frame preamble mismatch".into(),
            ));
        }
        let length_field = raw[2];
        if usize::from(length_field) < 4 || usize::from(length_field) + 2 != raw.len() {
            return Err(HalError::PsuProtocolOwned(
                "APW9 frame length field mismatch".into(),
            ));
        }
        let opcode = raw[3];
        let checksum = u16::from_le_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
        let expected = Self::additive_checksum16(&raw[2..raw.len() - 2]);
        if checksum != expected {
            return Err(HalError::PsuProtocolOwned(
                "APW9 frame additive checksum mismatch".into(),
            ));
        }
        Ok(Apw9Frame {
            raw: raw.to_vec(),
            length_field,
            opcode,
            payload: raw[4..raw.len() - 2].to_vec(),
            checksum,
        })
    }

    /// Decode and exact-shape-check one admitted GET request.
    pub fn decode_request(raw: &[u8]) -> Result<Apw9Frame> {
        let frame = Self::decode_frame(raw)?;
        let Some(command) = Apw9Command::from_opcode(frame.opcode) else {
            return Err(HalError::PsuProtocolOwned(
                "APW9 request opcode is not an admitted GET command".into(),
            ));
        };
        let canonical = Self::encode_request(command);
        if frame.raw != canonical {
            return Err(HalError::PsuProtocolOwned(
                "APW9 request is not the canonical held GET shape".into(),
            ));
        }
        Ok(frame)
    }

    /// SET is refused. Held SET bytes may be decoded as a frame; they are
    /// never a write grant and never prove a rail change.
    pub fn set_voltage_mv(&self, mv: u16) -> Result<()> {
        let _ = mv;
        Err(HalError::PsuProtocolOwned(
            "APW9 SET_VOLTAGE refused: fail-closed host codec (desk-now 2026-08-19); no millivolt LSB, no I2C, reply echo is not rail proof"
                .into(),
        ))
    }

    /// Recognize only the exact positive APW9 marker. Do not infer APW8.
    pub fn classify_jig_probe_byte(raw_byte: u8) -> (&'static str, bool) {
        if raw_byte == APW9_JIG_IDENTITY_BYTE {
            ("apw9-3600w-marker-observed", true)
        } else {
            (
                "not-apw9-marker; vendor-jig-fallback-to-apw8-is-not-an-authorized-identity",
                false,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_get_vectors_and_checksum() {
        assert_eq!(
            Apw9Codec::encode_request(Apw9Command::GetFirmwareVersion),
            [0x55, 0xAA, 0x04, 0x01, 0x05, 0x00]
        );
        assert_eq!(
            Apw9Codec::encode_request(Apw9Command::GetTypeVersion),
            [0x55, 0xAA, 0x04, 0x02, 0x06, 0x00]
        );
        assert_eq!(
            Apw9Codec::additive_checksum16(&[0x06, 0x83, 0xC8, 0x00]),
            0x0151
        );
        let held = Apw9Codec::decode_frame(&APW9_HELD_SET_VOLTAGE_DAC_C8).unwrap();
        assert_eq!(held.opcode, APW9_CMD_SET_VOLTAGE);
        assert_eq!(held.payload, vec![0xC8, 0x00]);
        assert!(Apw9Codec::decode_request(&APW9_HELD_SET_VOLTAGE_DAC_C8).is_err());
    }

    #[test]
    fn set_voltage_is_refused_and_does_not_encode() {
        let codec = Apw9Codec::new();
        let err = codec
            .set_voltage_mv(14500)
            .expect_err("APW9 SET must refuse");
        let rendered = err.to_string();
        assert!(rendered.contains("APW9 SET_VOLTAGE refused"), "{rendered}");
        assert!(!LIVE_DISPATCH_AVAILABLE);
        assert_eq!(APW9_I2C_ADDR_7BIT, 0x10);
        assert_eq!(APW9_I2C_REGISTER, 0x11);
        assert_ne!(APW9_JIG_PACKED_FPGA_SELECTOR, APW9_I2C_ADDR_7BIT);
    }

    #[test]
    fn jig_probe_does_not_infer_apw8() {
        let (class, hit) = Apw9Codec::classify_jig_probe_byte(APW9_JIG_IDENTITY_BYTE);
        assert!(hit);
        assert_eq!(class, "apw9-3600w-marker-observed");
        let (class, hit) = Apw9Codec::classify_jig_probe_byte(0x00);
        assert!(!hit);
        assert!(class.contains("not-apw9-marker"));
    }

    #[test]
    fn malformed_frames_fail_closed() {
        assert!(Apw9Codec::decode_frame(&[]).is_err());
        assert!(Apw9Codec::decode_frame(&[0x54, 0xAA, 0x04, 0x01, 0x05, 0x00]).is_err());
        assert!(Apw9Codec::decode_frame(&[0x55, 0xAA, 0x04, 0x01, 0x05, 0x01]).is_err());
    }
}
