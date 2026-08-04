// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — CRC implementations
// Faithful port from ESP-Miner crc.c / crc.h

/// CRC16 lookup table (CCITT polynomial 0x1021)
#[rustfmt::skip]
pub const CRC16_TABLE: [u16; 256] = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
];

/// CRC5 calculation using polynomial x^5 + x^2 + 1 (MSB-first).
/// Exact port of crc5() from crc.c.
#[inline]
pub fn crc5(data: &[u8]) -> u8 {
    let mut crc: u8 = 0x1F;

    for &byte_val in data {
        let mut byte = byte_val;
        for _ in 0..8 {
            let bit = (byte >> 7) & 1;
            byte <<= 1;

            let new_bit = ((crc >> 4) ^ bit) & 1;
            crc = ((crc << 1) | new_bit) ^ (new_bit << 2);
            crc &= 0x1F;
        }
    }

    crc
}

/// CRC16 with initial value 0x0000 (loop-unrolled version).
/// Exact port of crc16() from crc.c.
#[inline]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 4 bytes at a time
    while i + 4 <= len {
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ data[i]) as usize] ^ (crc << 8);
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ data[i + 1]) as usize] ^ (crc << 8);
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ data[i + 2]) as usize] ^ (crc << 8);
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ data[i + 3]) as usize] ^ (crc << 8);
        i += 4;
    }

    // Process remaining bytes
    while i < len {
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ data[i]) as usize] ^ (crc << 8);
        i += 1;
    }

    crc
}

/// CRC16 with initial value 0xFFFF ("CRC16/FALSE").
/// Exact port of crc16_false() from crc.c.
/// Used for job packet checksums.
#[inline]
pub fn crc16_false(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;

    for &byte_val in data {
        crc = CRC16_TABLE[((crc >> 8) as u8 ^ byte_val) as usize] ^ (crc << 8);
    }

    crc
}

// ─── MSBT0501 / LT0051 (Hammer DC0x, Scrypt) CRCs ───────────────────────────
//
// 🔴 THE SHARPEST TRAP IN THE MSBT0501 PROTOCOL (MSBT0501_PROTOCOL.md §3, §8):
// the chip uses TWO different CRCs and only ONE of them is Bitmain's.
//
//   * CRC-5  (register commands + every response) IS Bitmain's, byte for byte
//     — verified, not assumed, across 29,585 vectors. So [`crc5`] above is
//     reused directly and [`crc5_bits`] is only its bit-length generalisation.
//   * CRC-16 (93-byte work packets) is poly **0x8005** / CRC-16/CMS —
//     **NOT** Bitmain's 0x1021. No 0x1021 constant exists anywhere in any of
//     the five DC/BC-lineage vendor images.
//
// The asymmetry is what makes it dangerous: checking the CRC-5 against BM1485
// SUCCEEDS, which breeds false confidence in the CRC-16. [`crc16_false`] above
// is the 0x1021 CCITT-FALSE table CRC used by every BM13xx job packet and
// **must never be used for LT0051** — a wrong work-packet CRC gives a
// perfectly-formed frame that the chip silently discards, i.e. link health
// looks perfect and the hashrate is zero.

/// CRC-16/CMS — poly `0x8005`, init `0xFFFF`, non-reflected, no final XOR.
///
/// The MSBT0501 work-packet checksum (`FUN_4205a23c` @ IROM `0x4205a23c`;
/// constants read from the DC02 v2.0.2 literal pool at `0x4203f4ac` = `0x8005`
/// and `0x4203ebe4` = `0xFFFF`). Transmitted **big-endian** in the frame's last
/// two bytes: `frame[len-2] = crc >> 8`, `frame[len-1] = crc & 0xFF`.
///
/// ⚠ This is a DIFFERENT algorithm from [`crc16_false`] (poly `0x1021`). On the
/// same input they give `0xAEE7` vs `0x29B1`. Do not "unify" them.
///
/// Check value: `crc16_cms(b"123456789") == 0xAEE7`.
#[inline]
pub fn crc16_cms(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8005
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// CRC-5 over an explicit number of **bits** (poly `0x05`, init `0x1F`,
/// MSB-first, no final XOR).
///
/// The MSBT0501 receive validator calls its CRC-5 with a bit count
/// (`FUN_4205a178(buf + 2, 0x40)` — 64 bits = response bytes 2..9), so the
/// driver mirrors that signature exactly rather than assuming byte alignment.
/// For a byte-aligned `nbits` this is identical to [`crc5`]; a pinned test
/// asserts that equivalence so the two implementations cannot drift.
///
/// `nbits` is clamped to the bits actually available in `data`.
#[inline]
pub fn crc5_bits(data: &[u8], nbits: usize) -> u8 {
    let nbits = nbits.min(data.len() * 8);
    let mut crc: u8 = 0x1F;
    for i in 0..nbits {
        let bit = (data[i >> 3] >> (7 - (i & 7))) & 1;
        let top = (crc >> 4) & 1;
        crc = (crc << 1) & 0x1F;
        if (top ^ bit) != 0 {
            crc ^= 0x05;
        }
    }
    crc
}

// ─── KF1950 (WhatsMiner K-series) CRC ───────────────────────────────────────
//
// UNTESTED — RESEARCH DRIVER. Used only when the `asic-kf1950` Cargo feature
// is enabled. See `kf1950.rs` and the canonical RE doc at
//  for context.

/// CRC-8 with polynomial `0x31`, MSB-first, no reflection, `xorOut = 0`.
///
/// Used by the KF1950 (WhatsMiner K-series) protocol. Sourced from the
/// kuenrg153/ESP-Miner KF1950 driver fork. Same poly + ordering as Bitmain
/// BM1397 — supporting evidence that K-series is BM1397-derivative
/// (canonical RE doc §3).
///
/// Default `init` is `0xFF` for almost every command frame; `0x3A` is used
/// for the single address-assignment frame (canonical RE doc §2.3 Phase 3).
///
/// CONFIDENCE: HIGH (90%) — standard CRC-8/MAXIM-style algorithm, polynomial
/// and MSB-first ordering documented explicitly in the fork's source.
#[inline]
pub fn crc8_0x31(data: &[u8], init: u8) -> u8 {
    let mut crc = init;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x31;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc5_known_value() {
        // Test with a known command packet (without CRC byte)
        // From the C code: read address 00 on all chips
        // Header=0x52, len=0x05, data=0x00,0x00
        let data = [0x52, 0x05, 0x00, 0x00];
        let result = crc5(&data);
        // The C code sends 0x0A as the CRC5 byte for this packet
        assert_eq!(result, 0x0A);
    }

    #[test]
    fn test_crc5_verify_zero() {
        // When CRC5 is appended, checking the full buffer should give 0
        // This is the property used in receive_work() validation
        let data = [0x52, 0x05, 0x00, 0x00, 0x1A];
        assert_eq!(crc5(&data), 0);
    }

    #[test]
    fn test_crc16_false_initial() {
        // Empty data with init=0xFFFF should return 0xFFFF
        let data: [u8; 0] = [];
        assert_eq!(crc16_false(&data), 0xFFFF);
    }

    #[test]
    fn crc16_xmodem_known_answer() {
        // crc16() is init=0x0000, poly 0x1021, no reflection = CRC-16/XMODEM,
        // whose canonical "123456789" check value is 0x31C3. This pins the table.
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn crc16_false_known_answer() {
        // CRC-16/CCITT-FALSE (init=0xFFFF) canonical "123456789" check = 0x29B1.
        // This CRC trailers EVERY job packet, so a table/init typo here = every job
        // silently rejected by every chip (zero hashrate). Was previously tested
        // ONLY on empty input.
        assert_eq!(crc16_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn crc16_unrolled_matches_naive_bitwise() {
        // The 4-byte loop-unrolled crc16() must equal an INDEPENDENT naive bitwise
        // CRC-16/XMODEM across every `len % 4` remainder boundary (0..=64), so an
        // unrolled-path or table divergence can never slip in silently.
        fn crc16_naive(data: &[u8]) -> u16 {
            let mut crc: u16 = 0;
            for &b in data {
                crc ^= (b as u16) << 8;
                for _ in 0..8 {
                    crc = if crc & 0x8000 != 0 {
                        (crc << 1) ^ 0x1021
                    } else {
                        crc << 1
                    };
                }
            }
            crc
        }
        for len in 0..=64usize {
            let data: Vec<u8> = (0..len)
                .map(|i| i.wrapping_mul(31).wrapping_add(7) as u8)
                .collect();
            assert_eq!(
                crc16(&data),
                crc16_naive(&data),
                "unrolled crc16 diverged from the naive reference at len={len}"
            );
        }
    }

    // ── MSBT0501 / LT0051 ───────────────────────────────────────────────

    #[test]
    fn crc16_cms_published_check_value() {
        // THE pin the protocol contract demands (MSBT0501_PROTOCOL.md §8 #1):
        // the catalogue check value for CRC-16/CMS. If this ever reads 0x29B1
        // somebody swapped in the Bitmain 0x1021 CRC and every Scrypt work
        // packet is silently discarded by the chip (perfect link, zero shares).
        assert_eq!(crc16_cms(b"123456789"), 0xAEE7);
    }

    #[test]
    fn crc16_cms_is_not_the_bitmain_job_crc() {
        // Explicit anti-confusion pin: the two CRC-16s must disagree, and
        // crc16_false must still be CCITT-FALSE.
        assert_eq!(crc16_false(b"123456789"), 0x29B1);
        assert_ne!(crc16_cms(b"123456789"), crc16_false(b"123456789"));
        for len in 0..48usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            if len > 0 {
                assert_ne!(
                    crc16_cms(&data),
                    crc16_false(&data),
                    "CMS(0x8005) and CCITT-FALSE(0x1021) collided at len={len} — \
                     check that crc16_cms really uses poly 0x8005"
                );
            }
        }
        // Empty input: both are just the shared init value.
        assert_eq!(crc16_cms(&[]), 0xFFFF);
    }

    #[test]
    fn crc5_bits_matches_the_documented_msbt0501_vectors() {
        // Regression vectors published in MSBT0501_PROTOCOL.md §3.1, produced
        // from a literal transliteration of the instruction-level read of
        // FUN_4205a178 and cross-checked against a conventional
        // poly-0x05/init-0x1F CRC-5 over 29,585 vectors.
        assert_eq!(crc5_bits(&[0x00, 0x00, 0x00, 0x00], 32), 0x1B);
        assert_eq!(crc5_bits(&[0x52, 0x05, 0x00, 0x00], 32), 0x0A);
        assert_eq!(crc5_bits(&[0x41, 0x09, 0x00, 0x0C], 32), 0x1D);
        // nbits == 0 returns the seed.
        assert_eq!(crc5_bits(&[0xFF; 4], 0), 0x1F);
    }

    #[test]
    fn crc5_bits_is_the_byte_crc5_generalised() {
        // The bit-length form must be EXACTLY the existing byte-oriented CRC-5
        // on byte-aligned inputs — that equivalence is what lets the LT0051
        // driver reuse the proven Bitmain CRC-5 rather than fork it.
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 91 + 3) as u8).collect();
            assert_eq!(
                crc5_bits(&data, len * 8),
                crc5(&data),
                "crc5_bits diverged from crc5 at len={len}"
            );
        }
        // Sub-byte lengths are honoured (not rounded up to a whole byte).
        assert_ne!(crc5_bits(&[0xFF], 4), crc5_bits(&[0xFF], 8));
        // Over-long nbits clamps to the available data instead of reading OOB.
        assert_eq!(crc5_bits(&[0xAA, 0x55], 9999), crc5(&[0xAA, 0x55]));
    }

    // ── crc8_0x31 (KF1950) ──────────────────────────────────────────────

    #[test]
    fn test_crc8_0x31_empty_returns_init() {
        // Empty payload yields the init value (no XOR work happens).
        assert_eq!(crc8_0x31(&[], 0xFF), 0xFF);
        assert_eq!(crc8_0x31(&[], 0x3A), 0x3A);
    }

    #[test]
    fn test_crc8_0x31_zero_byte_zero_init() {
        // Single zero byte with zero init => no feedback => zero out.
        assert_eq!(crc8_0x31(&[0x00], 0x00), 0x00);
    }

    #[test]
    fn test_crc8_0x31_deterministic() {
        // Same input + init => same output every time.
        let a = crc8_0x31(&[0x10, 0x00, 0x06], 0xFF);
        let b = crc8_0x31(&[0x10, 0x00, 0x06], 0xFF);
        assert_eq!(a, b);
    }

    #[test]
    fn test_crc8_0x31_init_changes_output() {
        // Address-assignment payload with default vs special init must differ.
        let payload = [
            0x00u8, 0x14, 0x02, 0x00, 0x01, 0xE1, 0x00, 0x01, 0x02, 0x04, 0x01, 0x30,
        ];
        let with_default = crc8_0x31(&payload, 0xFF);
        let with_addr_init = crc8_0x31(&payload, 0x3A);
        assert_ne!(with_default, with_addr_init);
    }

    #[test]
    fn test_crc8_0x31_append_self_verifies_zero() {
        // CRC-8 check property: if you append the CRC byte to the message
        // and then run CRC again over the full buffer with the same init,
        // the result is zero.
        let data = [0x12u8, 0x34, 0x02, 0x13, 0xF4];
        let crc = crc8_0x31(&data, 0xFF);
        let mut framed = data.to_vec();
        framed.push(crc);
        assert_eq!(crc8_0x31(&framed, 0xFF), 0);
    }
}
