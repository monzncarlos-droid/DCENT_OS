//! AMTC BM1366 software-pattern record evidence.
//!
//! The jig reads fixed 48-byte records into a 60-byte work slot.  A record
//! carries an expected logical nonce, twelve header-tail bytes, and a
//! 32-byte midstate.  It does not contain a raw 11-byte UART response,
//! response CRC, job-id byte, or captured version word.

pub const AMTC_BM1366_PATTERN_RECORD_LEN: usize = 48;
pub const AMTC_BM1366_PATTERN_8_SIZE: u64 = 43_255_296;
pub const AMTC_BM1366_PATTERN_8_RECORDS: u64 = 901_152;
pub const AMTC_BM1366_PATTERN_8_SHA256: &str =
    "63F83AA8FBABEF784E90553A26EAE51A04DFC2E11EBC154470A40B19183F35F8";
pub const AMTC_BM1366_PATTERN_SUPER_SIZE: u64 = 5_376;
pub const AMTC_BM1366_PATTERN_SUPER_RECORDS: u64 = 112;
pub const AMTC_BM1366_PATTERN_SUPER_SHA256: &str =
    "0A23F0B4927282AA52AD6E8C389AC8C453D1B7937FFF40F634D47EE4909237C";

pub const BM1366_BIG_CORES: u8 = 112;
pub const BM1366_SMALL_CORES_PER_BIG_CORE: u8 = 8;
pub const BM1366_LAST_BIG_CORE_SMALL_CORES: u8 = 6;
pub const BM1366_TOTAL_CORES: u16 = 894;
/// The held AMTC logical expected nonce stores the big-core ordinal in bits
/// 31..25. This is a normalized jig value, not a raw UART byte-order claim.
pub const AMTC_BM1366_EXPECTED_NONCE_BIG_CORE_SHIFT: u32 = 25;
pub const AMTC_BM1366_EXPECTED_NONCE_BIG_CORE_MASK: u32 = 0x7F;
pub const AMTC_BM1366_PATTERN_SUPER_FIRST_EXPECTED_NONCE: u32 = 0x0000_0E12;
pub const AMTC_BM1366_PATTERN_SUPER_LAST_EXPECTED_NONCE: u32 = 0xDE00_13C1;
/// Exact corpus census after decoding bits 31..25 of all 901,152 eight-
/// midstate records: cores 0..110 each occur 8,064 times; core 111 occurs
/// 6,048 times. The 3/4 tail independently agrees with six rather than eight
/// physical small cores under the last big core.
pub const AMTC_BM1366_PATTERN_8_REGULAR_BIG_CORE_RECORDS: u64 = 8_064;
pub const AMTC_BM1366_PATTERN_8_LAST_BIG_CORE_RECORDS: u64 = 6_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmtcBm1366PatternRecord {
    /// LE u32 loaded by the ARM jig and compared to the normalized received
    /// nonce. This is a logical golden value, not a raw UART byte-order claim.
    pub expected_nonce: u32,
    pub header_tail: [u8; 12],
    pub midstate: [u8; 32],
}

pub fn parse_amtc_bm1366_pattern_record(
    record: &[u8],
) -> Result<AmtcBm1366PatternRecord, &'static str> {
    if record.len() != AMTC_BM1366_PATTERN_RECORD_LEN {
        return Err("AMTC BM1366 pattern record must be exactly 48 bytes");
    }
    Ok(AmtcBm1366PatternRecord {
        expected_nonce: u32::from_le_bytes(record[0..4].try_into().unwrap()),
        header_tail: record[4..16].try_into().unwrap(),
        midstate: record[16..48].try_into().unwrap(),
    })
}

/// Decode the physical big-core ordinal from an AMTC-normalized logical
/// expected nonce. Values 112..127 are retained by the seven-bit field but
/// refused as non-physical; no clamping is allowed.
pub const fn amtc_bm1366_expected_nonce_big_core(expected_nonce: u32) -> Option<u8> {
    let core = ((expected_nonce >> AMTC_BM1366_EXPECTED_NONCE_BIG_CORE_SHIFT)
        & AMTC_BM1366_EXPECTED_NONCE_BIG_CORE_MASK) as u8;
    if core < BM1366_BIG_CORES {
        Some(core)
    } else {
        None
    }
}

/// AMTC's physical core ordinal: `big_core*8 + small_core`, with only six
/// small cores under big core 111. Invalid combinations are not clamped.
pub fn amtc_bm1366_core_ordinal(big_core: u8, small_core: u8) -> Option<u16> {
    if big_core >= BM1366_BIG_CORES || small_core >= BM1366_SMALL_CORES_PER_BIG_CORE {
        return None;
    }
    if big_core == BM1366_BIG_CORES - 1 && small_core >= BM1366_LAST_BIG_CORE_SMALL_CORES {
        return None;
    }
    Some(u16::from(big_core) * u16::from(BM1366_SMALL_CORES_PER_BIG_CORE) + u16::from(small_core))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPER_FIRST: [u8; 48] = [
        0x12, 0x0E, 0x00, 0x00, 0x8C, 0x1F, 0x0D, 0x17, 0xC3, 0xF0, 0x4D, 0x60, 0xC6, 0xD4, 0xAB,
        0xE8, 0x1B, 0xE1, 0xC7, 0x5E, 0x72, 0x9A, 0xE4, 0xA7, 0x4E, 0x54, 0x3D, 0x67, 0x9E, 0xC3,
        0x3D, 0xBD, 0x8E, 0xAA, 0xC0, 0xB8, 0x26, 0xF5, 0xFE, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x26, 0xE4, 0x58,
    ];
    const MID8_FIRST: [u8; 48] = [
        0xAC, 0x15, 0x00, 0x00, 0x8C, 0x1F, 0x0D, 0x17, 0xC3, 0xF0, 0x4D, 0x60, 0xC6, 0xD4, 0xAB,
        0xE8, 0x1B, 0xE1, 0xC7, 0x5E, 0x72, 0x9A, 0xE4, 0xA7, 0x4E, 0x54, 0x3D, 0x67, 0x9E, 0xC3,
        0x3D, 0xBD, 0x8E, 0xAA, 0xC0, 0xB8, 0x26, 0xF5, 0xFE, 0x65, 0x0F, 0x53, 0xAB, 0xD8, 0x00,
        0x00, 0x00, 0x00,
    ];

    #[test]
    fn held_first_records_pin_nonce_tail_midstate_layout() {
        let super_record = parse_amtc_bm1366_pattern_record(&SUPER_FIRST).unwrap();
        let mid8_record = parse_amtc_bm1366_pattern_record(&MID8_FIRST).unwrap();
        assert_eq!(
            super_record.expected_nonce,
            AMTC_BM1366_PATTERN_SUPER_FIRST_EXPECTED_NONCE
        );
        assert_eq!(mid8_record.expected_nonce, 0x0000_15AC);
        assert_eq!(super_record.header_tail, mid8_record.header_tail);
        assert_eq!(super_record.header_tail[0], 0x8C);
        assert_eq!(super_record.header_tail[11], 0xE8);
        assert_eq!(super_record.midstate[0], 0x1B);
        assert_eq!(super_record.midstate[31], 0x58);
        assert_eq!(mid8_record.midstate[24..28], [0x0F, 0x53, 0xAB, 0xD8]);
    }

    #[test]
    fn held_file_sizes_are_integral_record_counts() {
        assert_eq!(
            AMTC_BM1366_PATTERN_8_SIZE / AMTC_BM1366_PATTERN_RECORD_LEN as u64,
            AMTC_BM1366_PATTERN_8_RECORDS
        );
        assert_eq!(
            AMTC_BM1366_PATTERN_SUPER_SIZE / AMTC_BM1366_PATTERN_RECORD_LEN as u64,
            AMTC_BM1366_PATTERN_SUPER_RECORDS
        );
    }

    #[test]
    fn physical_core_geometry_is_894_without_clamping() {
        assert_eq!(amtc_bm1366_core_ordinal(0, 0), Some(0));
        assert_eq!(amtc_bm1366_core_ordinal(110, 7), Some(887));
        assert_eq!(amtc_bm1366_core_ordinal(111, 5), Some(893));
        assert_eq!(amtc_bm1366_core_ordinal(111, 6), None);
        assert_eq!(amtc_bm1366_core_ordinal(111, 7), None);
        assert_eq!(amtc_bm1366_core_ordinal(112, 0), None);
        assert_eq!(BM1366_TOTAL_CORES, 894);
    }

    #[test]
    fn held_expected_nonce_high_bits_pin_all_physical_big_cores() {
        assert_eq!(
            amtc_bm1366_expected_nonce_big_core(AMTC_BM1366_PATTERN_SUPER_FIRST_EXPECTED_NONCE),
            Some(0)
        );
        assert_eq!(
            amtc_bm1366_expected_nonce_big_core(AMTC_BM1366_PATTERN_SUPER_LAST_EXPECTED_NONCE),
            Some(111)
        );
        assert_eq!(amtc_bm1366_expected_nonce_big_core(112u32 << 25), None);
        assert_eq!(amtc_bm1366_expected_nonce_big_core(u32::MAX), None);
        assert_eq!(
            u64::from(BM1366_BIG_CORES - 1) * AMTC_BM1366_PATTERN_8_REGULAR_BIG_CORE_RECORDS
                + AMTC_BM1366_PATTERN_8_LAST_BIG_CORE_RECORDS,
            AMTC_BM1366_PATTERN_8_RECORDS
        );
        assert_eq!(
            AMTC_BM1366_PATTERN_8_LAST_BIG_CORE_RECORDS * 4,
            AMTC_BM1366_PATTERN_8_REGULAR_BIG_CORE_RECORDS * 3
        );
    }

    #[test]
    fn wrong_record_lengths_are_refused() {
        assert!(parse_amtc_bm1366_pattern_record(&SUPER_FIRST[..47]).is_err());
        let mut long = SUPER_FIRST.to_vec();
        long.push(0);
        assert!(parse_amtc_bm1366_pattern_record(&long).is_err());
    }
}
