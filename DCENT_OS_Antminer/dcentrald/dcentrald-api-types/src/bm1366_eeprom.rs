//! BHB56902 (BM1366 / S19k Pro) hashboard-EEPROM block — byte-exact plaintext layout.
//!
//! # Provenance
//!
//! Recovered 2026-07-24 from Bitmain's factory jig
//!  (ARM32 LE) via
//! GhidraMCP: `read_board_info_from_eeprom @0x2885c`, legacy decode path gating on
//! `len == 0x48` with CRC5 `FUN_000287d4` over `(0x48-1)*8 = 568` bits. Documented in
//! .
//!
//! # Relationship to [`crate::zhiju_eeprom`]
//!
//! This is the BHB56xxx sibling of the BHB42xxx zhiju block. The two share, PROVEN
//! across three jig binaries:
//! - the SAME CRC5 ([`crate::zhiju_eeprom::bitmain_crc5`], poly 0x05 / init 0x1F /
//!   MSB-first / no final XOR) — reused here unchanged, not re-derived, and
//! - the SAME identity-field layout through the identity block (SN@0x03[17],
//!   die@0x14[2], marking@0x16[13], bin@0x23, ft@0x24[4]).
//!
//! They DIVERGE in two ways this module handles conservatively:
//! - **Preamble byte 0** is `0x05` (BHB56xxx family / AES-keyed) vs `0x04` (BHB42xxx /
//!   XXTEA). This byte is the family discriminator.
//! - **Block length is `0x48` (72 bytes)** — 6 bytes longer than the zhiju `0x42`. The
//!   extra span (`0x34..=0x46`) plus the two config-selected sensor selectors
//!   (`0x2D`, `0x32`) are NOT pinned by the jig's field dump, so they are exposed RAW
//!   and never interpreted here (see the module ambiguity notes). Do NOT copy the
//!   zhiju sensor offsets onto this family.
//!
//! # Status
//!
//! **Experimental — decode only.** No HAL, no I/O, no write path. This does not by
//! itself authorize any hardware mutation; a caller pairs a decoded identity with the
//! platform admission rules. `verify_crc5` ships FAIL-OPEN (a mismatch is a WARN, never
//! a board rejection) until validated against a real decrypted BHB56902 vector — a
//! wrong check rejects good boards.
//!
//! Cipher note: the BHB56xxx `(0x05,0x11)` AES key derivation is deliberately NOT
//! recovered or shipped (DMCA/license). Callers that need decrypted contents route
//! through the board's own parser (SSH). This module consumes already-plaintext bytes.

use crate::zhiju_eeprom::{bitmain_crc5, Crc5Check};
use serde::{Deserialize, Serialize};

/// Offsets from the start of the plaintext block. Identity fields match zhiju exactly.
pub mod offset {
    pub const ALGORITHM_AND_KEY_VERSION: usize = 0x00;
    pub const BOARD_INFO_LENGTH: usize = 0x01;
    pub const HASHBOARD_SN: usize = 0x03;
    pub const CHIP_DIE: usize = 0x14;
    pub const CHIP_MARKING: usize = 0x16;
    pub const CHIP_BIN: usize = 0x23;
    pub const CHIP_FT_PROGRAM_VERSION: usize = 0x24;
    /// First config-selected temp-sensor model selector (raw; `& 0x7F`). Distinct from
    /// the zhiju `asic_sensor` byte — do NOT reuse zhiju's 0x28.
    pub const SENSOR_SELECTOR_A: usize = 0x2D;
    /// Second config-selected temp-sensor model selector (raw). Dual-sensor position.
    pub const SENSOR_SELECTOR_B: usize = 0x32;
    /// Start of the extended (BHB56902-only) test-data tail. Two BE u16s at 0x34/0x36,
    /// then bytes to 0x46. Semantics (voltage/freq/nonce_rate/temp) NOT pinned by the
    /// jig dump — exposed raw.
    pub const EXTENDED_TAIL: usize = 0x34;
    /// CRC5 byte (the block's last byte).
    pub const BOARD_INFO_CRC5: usize = 0x47;
}

/// Field widths (identity block, shared with zhiju).
pub const HASHBOARD_SN_LEN: usize = 17;
pub const CHIP_DIE_LEN: usize = 2;
pub const CHIP_MARKING_LEN: usize = 13;
pub const CHIP_FT_PROGRAM_VERSION_LEN: usize = 4;
/// Raw span of the extended tail (`0x34..=0x46`), exposed without interpretation.
pub const EXTENDED_TAIL_LEN: usize = offset::BOARD_INFO_CRC5 - offset::EXTENDED_TAIL;

/// Exact block length gate. The jig ENFORCES `block[1] == 0x48` before decoding — we
/// adopt the same posture (never trust the length byte as free CRC coverage input).
pub const BM1366_BLOCK_LEN: usize = 0x48;

/// Family preamble byte 0 for BHB56xxx (BM1366/68/70). BHB42xxx is `0x04`.
pub const BHB56XXX_ALGORITHM_BYTE: u8 = 0x05;

/// Decoded BHB56902 hashboard-EEPROM identity block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bhb56902Record {
    pub algorithm_and_key_version: u8,
    pub board_info_length: u8,
    pub hashboard_sn: String,
    pub chip_die: String,
    pub chip_marking: String,
    pub chip_bin: u8,
    pub chip_ft_program_version: [u8; CHIP_FT_PROGRAM_VERSION_LEN],
    /// Raw sensor-model selector A (`0x2D`, masked `& 0x7F`). Model enum NOT decoded —
    /// requires a real sample.
    pub sensor_selector_a: u8,
    /// Raw sensor-model selector B (`0x32`, masked `& 0x7F`).
    pub sensor_selector_b: u8,
    /// The extended (BHB56902-only) tail bytes `0x34..=0x46`, uninterpreted.
    pub extended_tail: Vec<u8>,
    /// Stored CRC5 byte (`0x47`). NOT validated in the decode — use [`Bhb56902Record::verify_crc5`].
    pub board_info_crc5: u8,
}

/// Decode failure for [`decode_bhb56902_block`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum Bhb56902DecodeError {
    Truncated {
        got: usize,
        need: usize,
    },
    /// `block[1]` did not equal the expected `0x48` length gate.
    WrongLength {
        got: u8,
        expected: u8,
    },
    /// Wrong family preamble byte 0 (expected `0x05`).
    WrongFamily {
        got: u8,
    },
    NonAsciiField {
        field: &'static str,
        offset: usize,
    },
}

impl core::fmt::Display for Bhb56902DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { got, need } => {
                write!(f, "BHB56902 block truncated: got {got}, need {need}")
            }
            Self::WrongLength { got, expected } => {
                write!(
                    f,
                    "BHB56902 length gate: block[1]=0x{got:02x}, expected 0x{expected:02x}"
                )
            }
            Self::WrongFamily { got } => {
                write!(f, "BHB56902 wrong family byte 0x{got:02x}, expected 0x05")
            }
            Self::NonAsciiField { field, offset } => {
                write!(
                    f,
                    "BHB56902 field '{field}' at offset {offset} is not printable ASCII"
                )
            }
        }
    }
}

impl std::error::Error for Bhb56902DecodeError {}

fn read_ascii(
    plaintext: &[u8],
    start: usize,
    len: usize,
    field: &'static str,
) -> Result<String, Bhb56902DecodeError> {
    let bytes = &plaintext[start..start + len];
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return Err(Bhb56902DecodeError::NonAsciiField {
            field,
            offset: start,
        });
    }
    Ok(bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect::<String>()
        .trim_end()
        .to_string())
}

/// Decode a plaintext BHB56902 block. `plaintext` must be post-cipher and at least
/// [`BM1366_BLOCK_LEN`] bytes. Enforces both the family byte (`0x05`) and the exact
/// length gate (`block[1] == 0x48`) before trusting any field.
pub fn decode_bhb56902_block(plaintext: &[u8]) -> Result<Bhb56902Record, Bhb56902DecodeError> {
    if plaintext.len() < BM1366_BLOCK_LEN {
        return Err(Bhb56902DecodeError::Truncated {
            got: plaintext.len(),
            need: BM1366_BLOCK_LEN,
        });
    }
    let family = plaintext[offset::ALGORITHM_AND_KEY_VERSION];
    if family != BHB56XXX_ALGORITHM_BYTE {
        return Err(Bhb56902DecodeError::WrongFamily { got: family });
    }
    let length = plaintext[offset::BOARD_INFO_LENGTH];
    if length as usize != BM1366_BLOCK_LEN {
        return Err(Bhb56902DecodeError::WrongLength {
            got: length,
            expected: BM1366_BLOCK_LEN as u8,
        });
    }

    let mut chip_ft_program_version = [0u8; CHIP_FT_PROGRAM_VERSION_LEN];
    chip_ft_program_version.copy_from_slice(
        &plaintext[offset::CHIP_FT_PROGRAM_VERSION
            ..offset::CHIP_FT_PROGRAM_VERSION + CHIP_FT_PROGRAM_VERSION_LEN],
    );

    Ok(Bhb56902Record {
        algorithm_and_key_version: family,
        board_info_length: length,
        hashboard_sn: read_ascii(
            plaintext,
            offset::HASHBOARD_SN,
            HASHBOARD_SN_LEN,
            "hashboard_sn",
        )?,
        chip_die: read_ascii(plaintext, offset::CHIP_DIE, CHIP_DIE_LEN, "chip_die")?,
        chip_marking: read_ascii(
            plaintext,
            offset::CHIP_MARKING,
            CHIP_MARKING_LEN,
            "chip_marking",
        )?,
        chip_bin: plaintext[offset::CHIP_BIN],
        chip_ft_program_version,
        sensor_selector_a: plaintext[offset::SENSOR_SELECTOR_A] & 0x7F,
        sensor_selector_b: plaintext[offset::SENSOR_SELECTOR_B] & 0x7F,
        extended_tail: plaintext[offset::EXTENDED_TAIL..offset::BOARD_INFO_CRC5].to_vec(),
        board_info_crc5: plaintext[offset::BOARD_INFO_CRC5],
    })
}

impl Bhb56902Record {
    /// Recompute the stored CRC5 over the fixed block span (`data[..0x47]`, `0x47 * 8`
    /// bits) and compare against `data[0x47]`. Same fail-OPEN posture and same
    /// coverage-source lesson as [`crate::zhiju_eeprom::ZhijuInformationBlock::verify_crc5`]:
    /// the coverage is the fixed span, NOT the length byte. `data` must be the full
    /// plaintext block. Returns a status, never rejects.
    pub fn verify_crc5(&self, data: &[u8]) -> Crc5Check {
        if data.len() <= offset::BOARD_INFO_CRC5 {
            return Crc5Check::Unknown;
        }
        let stored = data[offset::BOARD_INFO_CRC5] & 0x1F;
        let computed = bitmain_crc5(
            &data[..offset::BOARD_INFO_CRC5],
            offset::BOARD_INFO_CRC5 * 8,
        );
        if computed == stored {
            Crc5Check::Match
        } else {
            Crc5Check::Mismatch { computed, stored }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; BM1366_BLOCK_LEN];
        b[offset::ALGORITHM_AND_KEY_VERSION] = BHB56XXX_ALGORITHM_BYTE; // 0x05
        b[offset::BOARD_INFO_LENGTH] = BM1366_BLOCK_LEN as u8; // 0x48
        b[offset::HASHBOARD_SN..offset::HASHBOARD_SN + HASHBOARD_SN_LEN]
            .copy_from_slice(b"BHB56902AB2345678");
        b[offset::CHIP_DIE..offset::CHIP_DIE + CHIP_DIE_LEN].copy_from_slice(b"BB");
        b[offset::CHIP_MARKING..offset::CHIP_MARKING + CHIP_MARKING_LEN]
            .copy_from_slice(b"BM1366AA\0\0\0\0\0");
        b[offset::CHIP_BIN] = b'3';
        b[offset::CHIP_FT_PROGRAM_VERSION..offset::CHIP_FT_PROGRAM_VERSION + 4]
            .copy_from_slice(&[1, 2, 3, 4]);
        b[offset::SENSOR_SELECTOR_A] = 0x8A; // high bit set -> masked to 0x0A
        b[offset::SENSOR_SELECTOR_B] = 0x05;
        b
    }

    #[test]
    fn decodes_identity_block() {
        let d = decode_bhb56902_block(&sample()).unwrap();
        assert_eq!(d.algorithm_and_key_version, 0x05);
        assert_eq!(d.board_info_length, 0x48);
        assert_eq!(d.hashboard_sn, "BHB56902AB2345678");
        assert_eq!(d.chip_die, "BB");
        assert_eq!(d.chip_marking, "BM1366AA");
        assert_eq!(d.chip_ft_program_version, [1, 2, 3, 4]);
        // Sensor selectors are masked to 7 bits (model enum NOT decoded).
        assert_eq!(d.sensor_selector_a, 0x0A);
        assert_eq!(d.sensor_selector_b, 0x05);
        // Extended tail is exposed raw, exactly 0x34..=0x46 (19 bytes).
        assert_eq!(d.extended_tail.len(), EXTENDED_TAIL_LEN);
        assert_eq!(EXTENDED_TAIL_LEN, 0x47 - 0x34);
    }

    #[test]
    fn length_gate_is_enforced() {
        let mut b = sample();
        b[offset::BOARD_INFO_LENGTH] = 0x42; // zhiju length on a BHB56 block
        assert_eq!(
            decode_bhb56902_block(&b),
            Err(Bhb56902DecodeError::WrongLength {
                got: 0x42,
                expected: 0x48
            })
        );
    }

    #[test]
    fn family_byte_is_enforced() {
        let mut b = sample();
        b[offset::ALGORITHM_AND_KEY_VERSION] = 0x04; // BHB42xxx family
        assert_eq!(
            decode_bhb56902_block(&b),
            Err(Bhb56902DecodeError::WrongFamily { got: 0x04 })
        );
    }

    #[test]
    fn truncated_block_refused() {
        let mut b = sample();
        b.truncate(BM1366_BLOCK_LEN - 1);
        assert!(matches!(
            decode_bhb56902_block(&b),
            Err(Bhb56902DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn non_ascii_marking_fails_loud() {
        let mut b = sample();
        b[offset::CHIP_MARKING + 1] = 0xFF;
        assert_eq!(
            decode_bhb56902_block(&b),
            Err(Bhb56902DecodeError::NonAsciiField {
                field: "chip_marking",
                offset: offset::CHIP_MARKING
            })
        );
    }

    /// The BHB56902 CRC5 is the SAME algorithm as the zhiju/BM1398 CRC5 — reuse, not
    /// re-derivation. Round-trip over the fixed 0x47 span.
    #[test]
    fn crc5_reuses_shared_algorithm_and_round_trips() {
        let mut b = sample();
        let crc = bitmain_crc5(&b[..offset::BOARD_INFO_CRC5], offset::BOARD_INFO_CRC5 * 8);
        b[offset::BOARD_INFO_CRC5] = crc;
        let d = decode_bhb56902_block(&b).unwrap();
        assert_eq!(d.verify_crc5(&b), Crc5Check::Match);

        let mut wrong = b.clone();
        wrong[offset::BOARD_INFO_CRC5] = crc ^ 0x01;
        assert!(matches!(
            decode_bhb56902_block(&wrong).unwrap().verify_crc5(&wrong),
            Crc5Check::Mismatch { .. }
        ));
    }

    #[test]
    fn offsets_and_length_are_pinned() {
        // Identity offsets are byte-identical to zhiju (corroborated).
        assert_eq!(
            offset::HASHBOARD_SN,
            crate::zhiju_eeprom::offset::HASHBOARD_SN
        );
        assert_eq!(offset::CHIP_DIE, crate::zhiju_eeprom::offset::CHIP_DIE);
        assert_eq!(
            offset::CHIP_MARKING,
            crate::zhiju_eeprom::offset::CHIP_MARKING
        );
        assert_eq!(offset::CHIP_BIN, crate::zhiju_eeprom::offset::CHIP_BIN);
        // But the block is 6 bytes longer and the CRC moves to 0x47.
        assert_eq!(BM1366_BLOCK_LEN, 0x48);
        assert_eq!(offset::BOARD_INFO_CRC5, 0x47);
        assert_eq!(
            BM1366_BLOCK_LEN - crate::zhiju_eeprom::ZHIJU_BLOCK_MIN_LEN,
            6
        );
    }
}
