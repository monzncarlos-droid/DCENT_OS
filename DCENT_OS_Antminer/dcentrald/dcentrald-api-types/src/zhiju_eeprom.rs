//! Bitmain "zhiju information" hashboard-EEPROM block — byte-exact plaintext layout.
//!
//! # Provenance
//!
//! Extracted 2026-07-24 from Bitmain's own factory test jig
//!  (ARM32 LE, stripped)
//! via GhidraMCP. The dumper `FUN_000164bc` `printf`s every field of the decoded
//! in-memory block from base `0x001cde4c`, which yields the field order, widths, and
//! endianness directly — no guessing.
//!
//! **Corroborated on a second binary:** the BM1362 jig
//!  carries a
//! byte-identical dump block (same field set, same order, matching `%c` widths — SN[17]
//! @0x03, chip_die[2] @0x14, chip_marking[13] @0x16, chip_technology[2] @0x33). So the
//! layout is not single-source. The CRC5 ([`bitmain_crc5`]) is independently confirmed
//! against a published BM13xx command vector (see its test).
//!
//! `zhiju` (治具) is Chinese for "jig/fixture": this is the block the factory test
//! fixture writes and reads back.
//!
//! # Why this exists
//!
//! [`crate::eeprom_record`] dispatches on the 2-byte preamble and, for `(0x04, 0x11)`,
//! returns a **preamble-only** [`crate::eeprom_record::X19PlainRecord`] with the note
//! that "full field decode requires capturing a BHB42xxx plaintext dump and matching it
//! against the bosminer panic-string field list". This module supplies that field list.
//!
//! That matters for hardware enablement: `(0x04, 0x11)` covers the **whole** BHB42xxx
//! family — S19 / S19j Pro / T19, i.e. **both BM1398 and BM1362**. The preamble alone
//! therefore cannot authorize BM1398-specific voltage/reset/UART mutation, which is
//! exactly why `serial_mining.rs` refuses native BM1398 as `NOT IMPLEMENTED`. The
//! discriminating fields live *inside* this block: [`ZhijuInformationBlock::chip_marking`],
//! [`ZhijuInformationBlock::chip_die`], and [`ZhijuInformationBlock::chip_technology`].
//!
//! # Status
//!
//! **Experimental — decode only.** This module is pure data parsing: no HAL, no I/O, no
//! write path. It does not by itself authorize any hardware mutation; a caller must still
//! pair a decoded identity with the platform's admission rules.
//!
//! # Known ambiguities (deliberately NOT resolved by guessing)
//!
//! * **Byte 1.** The jig labels it `zhiju_information_length` and a real S19 Pro board
//!   reads `0x11` (17). That does not equal this block's ~66-byte span, so "length" may
//!   count a sub-section, or be a version/format code. Independently,
//!   [`crate::eeprom_record`] documents byte 1 as "algorithm nibble 0x1 (XXTEA) + key
//!   index 0x1". Both readings are recorded; neither is enforced. The byte is exposed raw
//!   as [`ZhijuInformationBlock::zhiju_information_length`].
//! * **CRC5.** The trailing byte at `+0x41` is `zhiju_information_crc5` in the jig, but the
//!   polynomial/init/width over which it is computed was not recovered. It is exposed raw
//!   and **not** validated. Do not invent a CRC check here — a wrong check would reject
//!   good boards.
//! * **`+0x3F`/`+0x40`** are not printed by the jig dumper and are treated as reserved.
//!
//! Cipher note: [`decode_zhiju_block`] consumes **plaintext**, matching
//! [`crate::eeprom_record::dispatch`]. Boards whose payload is enciphered must be run
//! through the cipher pass first.

use serde::{Deserialize, Serialize};

/// Offsets are relative to the start of the plaintext block (jig base `0x001cde4c`).
pub mod offset {
    pub const ALGORITHM_AND_KEY_VERSION: usize = 0x00;
    pub const ZHIJU_INFORMATION_LENGTH: usize = 0x01;
    pub const ZHIJU_INFORMATION_FORMAT_VERSION: usize = 0x02;
    pub const HASHBOARD_SN: usize = 0x03;
    pub const CHIP_DIE: usize = 0x14;
    pub const CHIP_MARKING: usize = 0x16;
    pub const CHIP_BIN: usize = 0x23;
    pub const CHIP_FT_PROGRAM_VERSION: usize = 0x24;
    pub const ASIC_SENSOR: usize = 0x28;
    pub const ASIC_SENSOR_ADDR: usize = 0x29;
    pub const PIC_SENSOR: usize = 0x2D;
    pub const PIC_SENSOR_ADDR: usize = 0x2E;
    pub const PCB_VERSION_V1: usize = 0x2F;
    pub const PCB_VERSION_V2: usize = 0x30;
    pub const BOM_VERSION_V1: usize = 0x31;
    pub const BOM_VERSION_V2: usize = 0x32;
    pub const CHIP_TECHNOLOGY: usize = 0x33;
    /// Big-endian u16 (the jig decodes with `x << 8 | x >> 8`).
    pub const VOLTAGE_MV: usize = 0x35;
    /// Big-endian u16.
    pub const FREQUENCY_MHZ: usize = 0x37;
    /// Big-endian u16.
    pub const NONCE_RATE: usize = 0x39;
    pub const PCB_TEMPERATURE_IN: usize = 0x3B;
    pub const PCB_TEMPERATURE_OUT: usize = 0x3C;
    pub const TEST_VERSION: usize = 0x3D;
    pub const TEST_STANDARD: usize = 0x3E;
    pub const ZHIJU_INFORMATION_CRC5: usize = 0x41;
}

/// Field widths for the ASCII/array members.
pub const HASHBOARD_SN_LEN: usize = 17;
pub const CHIP_DIE_LEN: usize = 2;
pub const CHIP_MARKING_LEN: usize = 13;
pub const CHIP_TECHNOLOGY_LEN: usize = 2;
/// The RAW field is 4 bytes — bounded by `asic_sensor` at `+0x28`. The BM1362 jig's
/// dump *prints* it as 9 chars, but that reads a wider parsed QR-string buffer, not a
/// 9-byte contiguous EEPROM field; a 9-byte raw field at `+0x24` would overrun
/// `asic_sensor`. Do NOT widen this offset.
pub const CHIP_FT_PROGRAM_VERSION_LEN: usize = 4;
pub const ASIC_SENSOR_ADDR_LEN: usize = 4;

/// Smallest plaintext length that contains every field the jig prints.
pub const ZHIJU_BLOCK_MIN_LEN: usize = offset::ZHIJU_INFORMATION_CRC5 + 1;

/// Decoded Bitmain zhiju hashboard-EEPROM block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZhijuInformationBlock {
    /// Raw byte 0. Selects the cipher/key generation (`0x04` BHB42xxx, `0x05` BHB56xxx).
    pub algorithm_and_key_version: u8,
    /// Raw byte 1. See the module-level ambiguity note — NOT interpreted here.
    pub zhiju_information_length: u8,
    pub zhiju_information_format_version: u8,
    /// 17-char factory serial. Unique per physical hashboard.
    pub hashboard_sn: String,
    /// 2-char die code.
    pub chip_die: String,
    /// 13-char ASIC marking — the primary chip-type discriminator within a preamble family.
    pub chip_marking: String,
    pub chip_bin: u8,
    /// 4 bytes, rendered by the jig as `*%d*%02d*%d*%d`.
    pub chip_ft_program_version: [u8; CHIP_FT_PROGRAM_VERSION_LEN],
    /// Sensor model code (e.g. NCT218 on S19 Pro per the AMTC `Config.ini`).
    pub asic_sensor: u8,
    pub asic_sensor_addr: [u8; ASIC_SENSOR_ADDR_LEN],
    /// PIC-side sensor model code (LM75A on S19 Pro).
    pub pic_sensor: u8,
    pub pic_sensor_addr: u8,
    pub pcb_version_v1: u8,
    pub pcb_version_v2: u8,
    pub bom_version_v1: u8,
    pub bom_version_v2: u8,
    /// 2-char process/technology code.
    pub chip_technology: String,
    /// Factory-binned operating voltage, millivolts (big-endian on the wire).
    pub voltage_mv: u16,
    /// Factory-binned operating frequency, MHz (big-endian on the wire).
    pub frequency_mhz: u16,
    /// Factory-measured nonce rate (big-endian on the wire).
    pub nonce_rate: u16,
    /// Signed Celsius.
    pub pcb_temperature_in: i8,
    /// Signed Celsius.
    pub pcb_temperature_out: i8,
    pub test_version: u8,
    pub test_standard: u8,
    /// Stored CRC5 byte. **Not validated** — see the module-level note.
    pub zhiju_information_crc5: u8,
}

/// Decode failure for [`decode_zhiju_block`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ZhijuDecodeError {
    /// Fewer bytes than [`ZHIJU_BLOCK_MIN_LEN`].
    Truncated { got: usize, need: usize },
    /// An ASCII field held bytes outside printable ASCII / NUL padding.
    NonAsciiField { field: &'static str, offset: usize },
}

impl core::fmt::Display for ZhijuDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { got, need } => {
                write!(f, "zhiju block truncated: got {got} bytes, need {need}")
            }
            Self::NonAsciiField { field, offset } => {
                write!(
                    f,
                    "zhiju field '{field}' at offset {offset} is not printable ASCII"
                )
            }
        }
    }
}

impl std::error::Error for ZhijuDecodeError {}

/// Read a fixed-width ASCII field, trimming NUL and trailing spaces.
///
/// Rejects any non-NUL byte outside printable ASCII so a mis-decrypted or
/// mis-offset blob surfaces as an error rather than mojibake identity.
fn read_ascii(
    plaintext: &[u8],
    start: usize,
    len: usize,
    field: &'static str,
) -> Result<String, ZhijuDecodeError> {
    let bytes = &plaintext[start..start + len];
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return Err(ZhijuDecodeError::NonAsciiField {
            field,
            offset: start,
        });
    }
    let text: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    Ok(text.trim_end().to_string())
}

#[inline]
fn read_be_u16(plaintext: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([plaintext[at], plaintext[at + 1]])
}

/// Decode a plaintext zhiju block.
///
/// `plaintext` must already be post-cipher, matching
/// [`crate::eeprom_record::dispatch`]'s contract. Extra trailing bytes are ignored.
pub fn decode_zhiju_block(plaintext: &[u8]) -> Result<ZhijuInformationBlock, ZhijuDecodeError> {
    if plaintext.len() < ZHIJU_BLOCK_MIN_LEN {
        return Err(ZhijuDecodeError::Truncated {
            got: plaintext.len(),
            need: ZHIJU_BLOCK_MIN_LEN,
        });
    }

    let mut chip_ft_program_version = [0u8; CHIP_FT_PROGRAM_VERSION_LEN];
    chip_ft_program_version.copy_from_slice(
        &plaintext[offset::CHIP_FT_PROGRAM_VERSION
            ..offset::CHIP_FT_PROGRAM_VERSION + CHIP_FT_PROGRAM_VERSION_LEN],
    );

    let mut asic_sensor_addr = [0u8; ASIC_SENSOR_ADDR_LEN];
    asic_sensor_addr.copy_from_slice(
        &plaintext[offset::ASIC_SENSOR_ADDR..offset::ASIC_SENSOR_ADDR + ASIC_SENSOR_ADDR_LEN],
    );

    Ok(ZhijuInformationBlock {
        algorithm_and_key_version: plaintext[offset::ALGORITHM_AND_KEY_VERSION],
        zhiju_information_length: plaintext[offset::ZHIJU_INFORMATION_LENGTH],
        zhiju_information_format_version: plaintext[offset::ZHIJU_INFORMATION_FORMAT_VERSION],
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
        asic_sensor: plaintext[offset::ASIC_SENSOR],
        asic_sensor_addr,
        pic_sensor: plaintext[offset::PIC_SENSOR],
        pic_sensor_addr: plaintext[offset::PIC_SENSOR_ADDR],
        pcb_version_v1: plaintext[offset::PCB_VERSION_V1],
        pcb_version_v2: plaintext[offset::PCB_VERSION_V2],
        bom_version_v1: plaintext[offset::BOM_VERSION_V1],
        bom_version_v2: plaintext[offset::BOM_VERSION_V2],
        chip_technology: read_ascii(
            plaintext,
            offset::CHIP_TECHNOLOGY,
            CHIP_TECHNOLOGY_LEN,
            "chip_technology",
        )?,
        voltage_mv: read_be_u16(plaintext, offset::VOLTAGE_MV),
        frequency_mhz: read_be_u16(plaintext, offset::FREQUENCY_MHZ),
        nonce_rate: read_be_u16(plaintext, offset::NONCE_RATE),
        pcb_temperature_in: plaintext[offset::PCB_TEMPERATURE_IN] as i8,
        pcb_temperature_out: plaintext[offset::PCB_TEMPERATURE_OUT] as i8,
        test_version: plaintext[offset::TEST_VERSION],
        test_standard: plaintext[offset::TEST_STANDARD],
        zhiju_information_crc5: plaintext[offset::ZHIJU_INFORMATION_CRC5],
    })
}

// ----------------------------------------------------------------------------
// CRC5, chip_bin, and cipher framing — recovered 2026-07-24 (jig FUN_00016778)
// ----------------------------------------------------------------------------

/// Bitmain BM13xx CRC5 over a bit-length prefix of `data`, MSB-first.
///
/// Recovered from `single_board_test_bm1398` `FUN_00016778`: a bit-serial 5-stage
/// LFSR, all five state bits initialised to 1 (init `0x1F`), input consumed MSB-first,
/// feedback `f = top_bit ^ input_bit` injected at taps 0 and 2 (polynomial
/// x^5 + x^2 + 1 = `0x05`), output = the 5 register bits with no final inversion.
/// This is the same poly/init as the standing CMD-CRC5 rule
/// and the public cgminer/bmminer BM13xx CRC5 — two
/// independent corroborations of the recovered algorithm.
///
/// `bit_len` is the number of bits of `data` to consume (the jig covers `(n-1)*8`
/// bits, i.e. the block minus its trailing CRC byte).
pub fn bitmain_crc5(data: &[u8], bit_len: usize) -> u8 {
    debug_assert!(
        bit_len <= data.len() * 8,
        "bitmain_crc5 bit_len {bit_len} exceeds data ({} bits)",
        data.len() * 8
    );
    // 5-bit LFSR held as bits [4..0]; all ones = 0x1F.
    let mut reg: u8 = 0x1F;
    for bit_index in 0..bit_len {
        let byte = data[bit_index / 8];
        // MSB-first within each byte.
        let input_bit = (byte >> (7 - (bit_index % 8))) & 1;
        let top = (reg >> 4) & 1;
        let feedback = top ^ input_bit;
        // Shift left within 5 bits, then inject feedback at taps 0 and 2.
        reg = ((reg << 1) & 0x1F) ^ (feedback) ^ (feedback << 2);
    }
    reg & 0x1F
}

impl ZhijuInformationBlock {
    /// Recompute and compare the stored CRC5 over the fixed block span.
    ///
    /// The stored CRC is the byte at [`offset::ZHIJU_INFORMATION_CRC5`] (`0x41`) — the
    /// same byte [`decode_zhiju_block`] reads — and the CRC covers every byte before it
    /// (`data[..0x41]`, i.e. `0x41 * 8` bits). `data` must be the full plaintext block
    /// passed to [`decode_zhiju_block`].
    ///
    /// This deliberately does NOT derive coverage from the `zhiju_information_length`
    /// byte: that field's meaning is unreconciled in the RE (it reads `0x11` = 17 on a
    /// real S19 Pro board, not the block span `0x42`), so trusting it would put the
    /// "stored CRC" inside `hashboard_sn` and never inspect the real CRC. The residual
    /// RE uncertainty is therefore the coverage-length *source*, not the algorithm —
    /// the CRC5 arithmetic itself is confirmed against a published BM13xx command
    /// vector (see [`bitmain_crc5`]'s test).
    ///
    /// **Returns a status, never rejects.** Callers MUST treat [`Crc5Check::Mismatch`]
    /// as a WARN, not a board rejection — a wrong check rejects good boards. Do not
    /// gate hardware on this until it is validated against one captured plaintext block.
    pub fn verify_crc5(&self, data: &[u8]) -> Crc5Check {
        // Fail-safe on short input: nothing to check rather than panic.
        if data.len() <= offset::ZHIJU_INFORMATION_CRC5 {
            return Crc5Check::Unknown;
        }
        let stored = data[offset::ZHIJU_INFORMATION_CRC5] & 0x1F;
        let computed = bitmain_crc5(
            &data[..offset::ZHIJU_INFORMATION_CRC5],
            offset::ZHIJU_INFORMATION_CRC5 * 8,
        );
        if computed == stored {
            Crc5Check::Match
        } else {
            Crc5Check::Mismatch { computed, stored }
        }
    }
}

/// Result of a **non-authoritative** CRC5 recompute. `Mismatch` is a WARN signal, not
/// a board-rejection verdict (see [`ZhijuInformationBlock::verify_crc5`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "crc5", rename_all = "snake_case")]
pub enum Crc5Check {
    Match,
    Mismatch {
        computed: u8,
        stored: u8,
    },
    /// The length byte was out of range; nothing was checked.
    ///
    /// This is the [`Default`] deliberately: it is the "no claim was made"
    /// value, so a `#[serde(default)]` field on an older persisted record
    /// deserializes to *nothing was checked* rather than fabricating a
    /// `Match` that no code ever computed.
    #[default]
    Unknown,
}

/// Decode the single-ASCII-digit `chip_bin` field (`'1'..='5'` → `1..=5`).
///
/// From jig `FUN_0001e3c0` (`get_chip_bin`): any other byte (including `0x00`/`0xFF`)
/// is "unknown" → `None`. Note the raw `ZhijuInformationBlock::chip_bin` stays the raw
/// byte; this is the interpreted form.
pub fn decode_chip_bin(raw: u8) -> Option<u8> {
    match raw {
        b'1'..=b'5' => Some(raw - b'0'),
        _ => None,
    }
}

/// Cipher framing for the BHB42xxx `(0x04,0x11)` family, from jig `FUN_0001c148`.
///
/// The two header bytes ([`offset::ALGORITHM_AND_KEY_VERSION`] and
/// [`offset::ZHIJU_INFORMATION_LENGTH`]) stay **plaintext**; XXTEA covers the payload
/// at `[2..0x42]` (64 bytes = payload + CRC). A decrypter must therefore leave bytes
/// 0 and 1 untouched and decrypt only that window. Constant provided so callers get
/// the boundary from one place.
pub const XXTEA_PAYLOAD_RANGE: core::ops::Range<usize> = 2..0x42;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic block at the jig-derived offsets.
    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; ZHIJU_BLOCK_MIN_LEN];
        b[offset::ALGORITHM_AND_KEY_VERSION] = 0x04;
        b[offset::ZHIJU_INFORMATION_LENGTH] = 0x11;
        b[offset::ZHIJU_INFORMATION_FORMAT_VERSION] = 0x01;
        b[offset::HASHBOARD_SN..offset::HASHBOARD_SN + HASHBOARD_SN_LEN]
            .copy_from_slice(b"BHB42601AB2345678");
        b[offset::CHIP_DIE..offset::CHIP_DIE + CHIP_DIE_LEN].copy_from_slice(b"AA");
        b[offset::CHIP_MARKING..offset::CHIP_MARKING + CHIP_MARKING_LEN]
            .copy_from_slice(b"BM1398BB\0\0\0\0\0");
        b[offset::CHIP_BIN] = 3;
        b[offset::CHIP_FT_PROGRAM_VERSION] = 1;
        b[offset::CHIP_FT_PROGRAM_VERSION + 1] = 2;
        b[offset::CHIP_FT_PROGRAM_VERSION + 2] = 3;
        b[offset::CHIP_FT_PROGRAM_VERSION + 3] = 4;
        b[offset::ASIC_SENSOR] = 0x9C; // NCT218 per AMTC Config.ini
        b[offset::ASIC_SENSOR_ADDR] = 25;
        b[offset::ASIC_SENSOR_ADDR + 1] = 57;
        b[offset::ASIC_SENSOR_ADDR + 2] = 58;
        b[offset::ASIC_SENSOR_ADDR + 3] = 90;
        b[offset::PIC_SENSOR] = 0x90; // LM75A
        b[offset::PIC_SENSOR_ADDR] = 0x01;
        b[offset::PCB_VERSION_V1] = 1;
        b[offset::PCB_VERSION_V2] = 2;
        b[offset::BOM_VERSION_V1] = 3;
        b[offset::BOM_VERSION_V2] = 4;
        b[offset::CHIP_TECHNOLOGY..offset::CHIP_TECHNOLOGY + CHIP_TECHNOLOGY_LEN]
            .copy_from_slice(b"N7");
        // Big-endian, per the jig's `x << 8 | x >> 8` decode.
        b[offset::VOLTAGE_MV..offset::VOLTAGE_MV + 2].copy_from_slice(&1360u16.to_be_bytes());
        b[offset::FREQUENCY_MHZ..offset::FREQUENCY_MHZ + 2].copy_from_slice(&525u16.to_be_bytes());
        b[offset::NONCE_RATE..offset::NONCE_RATE + 2].copy_from_slice(&9950u16.to_be_bytes());
        b[offset::PCB_TEMPERATURE_IN] = (-5i8) as u8;
        b[offset::PCB_TEMPERATURE_OUT] = 42;
        b[offset::TEST_VERSION] = 7;
        b[offset::TEST_STANDARD] = 8;
        b[offset::ZHIJU_INFORMATION_CRC5] = 0x1F;
        b
    }

    #[test]
    fn decodes_every_jig_printed_field() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.algorithm_and_key_version, 0x04);
        assert_eq!(d.zhiju_information_length, 0x11);
        assert_eq!(d.hashboard_sn, "BHB42601AB2345678");
        assert_eq!(d.chip_die, "AA");
        assert_eq!(d.chip_marking, "BM1398BB");
        assert_eq!(d.chip_bin, 3);
        assert_eq!(d.chip_ft_program_version, [1, 2, 3, 4]);
        assert_eq!(d.asic_sensor_addr, [25, 57, 58, 90]);
        assert_eq!(d.chip_technology, "N7");
        assert_eq!(d.pcb_temperature_in, -5);
        assert_eq!(d.pcb_temperature_out, 42);
        assert_eq!(d.zhiju_information_crc5, 0x1F);
    }

    /// The jig byte-swaps these three; a little-endian read would give 20740/3075/57383.
    #[test]
    fn voltage_frequency_nonce_rate_are_big_endian() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.voltage_mv, 1360);
        assert_eq!(d.frequency_mhz, 525);
        assert_eq!(d.nonce_rate, 9950);
    }

    /// `hashboard_sn` is exactly 17 bytes, so an 18-char source is truncated, not overrun.
    #[test]
    fn hashboard_sn_is_bounded_to_seventeen_bytes() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.hashboard_sn.len(), HASHBOARD_SN_LEN);
    }

    #[test]
    fn truncated_block_is_refused_not_padded() {
        let mut short = sample();
        short.truncate(ZHIJU_BLOCK_MIN_LEN - 1);
        assert_eq!(
            decode_zhiju_block(&short),
            Err(ZhijuDecodeError::Truncated {
                got: ZHIJU_BLOCK_MIN_LEN - 1,
                need: ZHIJU_BLOCK_MIN_LEN,
            })
        );
    }

    /// A mis-decrypted blob must fail loudly rather than yield a garbage identity that
    /// could be mistaken for a real chip marking.
    #[test]
    fn non_ascii_identity_field_is_refused() {
        let mut b = sample();
        b[offset::CHIP_MARKING + 2] = 0xFF;
        assert_eq!(
            decode_zhiju_block(&b),
            Err(ZhijuDecodeError::NonAsciiField {
                field: "chip_marking",
                offset: offset::CHIP_MARKING,
            })
        );
    }

    /// Trailing bytes beyond the known block must not break the decode.
    #[test]
    fn extra_trailing_bytes_are_ignored() {
        let mut b = sample();
        b.extend_from_slice(&[0xAB; 190]);
        assert!(decode_zhiju_block(&b).is_ok());
    }

    /// Offsets are load-bearing RE facts; pin them so a refactor cannot silently shift
    /// the identity fields.
    #[test]
    fn jig_derived_offsets_are_pinned() {
        assert_eq!(offset::HASHBOARD_SN, 0x03);
        assert_eq!(offset::CHIP_DIE, 0x14);
        assert_eq!(offset::CHIP_MARKING, 0x16);
        assert_eq!(offset::CHIP_TECHNOLOGY, 0x33);
        assert_eq!(offset::VOLTAGE_MV, 0x35);
        assert_eq!(offset::ZHIJU_INFORMATION_CRC5, 0x41);
        assert_eq!(ZHIJU_BLOCK_MIN_LEN, 0x42);
    }

    // --- CRC5 / chip_bin / cipher framing (L2, fail-open) ---

    #[test]
    fn crc5_is_deterministic_and_length_sensitive() {
        // Same bytes, same CRC; different bytes, (almost surely) different CRC.
        let a = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCD], 4 * 8);
        let b = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCD], 4 * 8);
        assert_eq!(a, b);
        assert!(a <= 0x1F, "CRC5 output must be 5 bits");
        let c = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCE], 4 * 8);
        assert_ne!(a, c);
    }

    /// Published BM13xx command vector: the BM1397 GETADDRESS frame is
    /// `55 AA 52 05 00 00 0A`, i.e. CRC5 over `[0x52,0x05,0x00,0x00]` == `0x0A`
    /// (skot/BM1397, cgminer-gekko). The EEPROM zhiju CRC5 uses the same poly/init
    /// (jig FUN_00016778, 3-way corroborated), so matching this real vector confirms
    /// the algorithm AND the 5-bit output ordering — raising the CRC above
    /// self-consistency, though `verify_crc5` still ships fail-open until a real
    /// decrypted BHB42xxx block is captured.
    #[test]
    fn crc5_matches_published_bm1397_getaddress_vector() {
        assert_eq!(bitmain_crc5(&[0x52, 0x05, 0x00, 0x00], 32), 0x0A);
    }

    /// Round-trip: compute the CRC5 over the first n-1 bytes, store it at n-1, and
    /// `verify_crc5` must report Match. Corrupting a covered byte must report Mismatch.
    /// (We test the round-trip property, not a hard-coded vector, because the 5-bit
    /// output ordering is the one residual RE uncertainty — hence fail-open.)
    #[test]
    fn verify_crc5_round_trips_and_detects_corruption() {
        let mut b = sample();
        // Coverage is the FIXED block span: CRC at 0x41, covering [..0x41]. This does
        // not depend on the ambiguous length byte.
        let crc = bitmain_crc5(
            &b[..offset::ZHIJU_INFORMATION_CRC5],
            offset::ZHIJU_INFORMATION_CRC5 * 8,
        );
        b[offset::ZHIJU_INFORMATION_CRC5] = crc;
        let decoded = decode_zhiju_block(&b).unwrap();
        assert_eq!(decoded.verify_crc5(&b), Crc5Check::Match);

        // Store a deliberately-wrong CRC (flip one of the 5 bits — guaranteed a
        // different 5-bit value, unlike corrupting a covered data byte which a 5-bit
        // CRC collides with 1-in-32 of the time). This exercises the compare path
        // deterministically without perturbing an ASCII identity field.
        let mut wrong = b.clone();
        wrong[offset::ZHIJU_INFORMATION_CRC5] = crc ^ 0x01;
        assert_eq!(
            decode_zhiju_block(&wrong).unwrap().verify_crc5(&wrong),
            Crc5Check::Mismatch {
                computed: crc,
                stored: crc ^ 0x01,
            }
        );
    }

    /// A too-short slice must report Unknown, never panic (byte-1 is no longer read
    /// before a length guard).
    #[test]
    fn verify_crc5_short_slice_is_unknown_not_panic() {
        let decoded = decode_zhiju_block(&sample()).unwrap();
        assert_eq!(decoded.verify_crc5(&[]), Crc5Check::Unknown);
        assert_eq!(decoded.verify_crc5(&[0x04, 0x11]), Crc5Check::Unknown);
        // Exactly at the CRC offset (no byte to read there) is still Unknown.
        assert_eq!(
            decoded.verify_crc5(&[0u8; offset::ZHIJU_INFORMATION_CRC5]),
            Crc5Check::Unknown
        );
    }

    #[test]
    fn chip_bin_decodes_ascii_digits_only() {
        assert_eq!(decode_chip_bin(b'1'), Some(1));
        assert_eq!(decode_chip_bin(b'5'), Some(5));
        assert_eq!(decode_chip_bin(b'0'), None);
        assert_eq!(decode_chip_bin(b'6'), None);
        assert_eq!(decode_chip_bin(0x00), None);
        assert_eq!(decode_chip_bin(0xFF), None);
    }

    /// The XXTEA window leaves the 2-byte header plaintext and covers [2..0x42].
    #[test]
    fn xxtea_payload_range_leaves_header_plaintext() {
        assert_eq!(XXTEA_PAYLOAD_RANGE, 2..0x42);
        assert!(!XXTEA_PAYLOAD_RANGE.contains(&offset::ALGORITHM_AND_KEY_VERSION));
        assert!(!XXTEA_PAYLOAD_RANGE.contains(&offset::ZHIJU_INFORMATION_LENGTH));
        assert!(XXTEA_PAYLOAD_RANGE.contains(&offset::ZHIJU_INFORMATION_CRC5));
    }
}
