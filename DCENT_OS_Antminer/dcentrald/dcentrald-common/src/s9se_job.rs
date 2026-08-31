//! S9 SE FPGA `send_job` / `parse_job_to_soc` packet (desk-only).
//!
//! S9 SE `cgminer` exports `send_job` and is the T11 CE sibling of S9k
//! `parse_job_to_soc@29BAC` / `send_job@29F2C` (88-byte header + coinbase +
//! 32-byte merkles + CRC-16). This module decodes and plans. It never
//! writes DHASH or admits mining.

use crate::s9se_work::refuse_s9se_work_dispatch;

/// `part_job.token_type = 82`.
pub const JOB_TYPE: u8 = 0x52;
/// `memcpy(tmp_buf, &part_job, 88u)`.
pub const JOB_HEADER_LEN: usize = 88;
pub const JOB_CRC_LEN: usize = 2;
/// `buf_len = coinbase_len + 32 * merkles + 90`.
pub const JOB_TRAILER_OVERHEAD: usize = 90;
pub const MERKLE_BRANCH_LEN: usize = 32;
/// Producer default `part_job.asic_diff = 15`.
pub const DEFAULT_ASIC_DIFF: u8 = 15;
/// Byte 9 bit 0: `pool->swork.clean`.
pub const FLAG_CLEAN: u8 = 0x01;
/// Byte 9 bit 1: ticket-update (`| 2`).
pub const FLAG_TICKET_UPDATE: u8 = 0x02;

/// FPGA PHY job buffers (`set_job_start_address(PHY + …)`).
pub const JOB_BUFFER_A_PHY_OFF: u32 = 0x0020_0000;
pub const JOB_BUFFER_B_PHY_OFF: u32 = 0x0021_0000;
/// Userspace `fpga_mem` aliases (`bitmain_axi_init`).
pub const JOB_BUFFER_A_MAP_OFF: u32 = 0x0008_0000;
pub const JOB_BUFFER_B_MAP_OFF: u32 = 0x0008_4000;

/// `set_dhash_acc_control(ctrl & 0xFFFFFF3F | 0x80)` then wait `0x40` clear.
pub const DHASH_RUN_BIT: u32 = 0x40;
pub const DHASH_BIT7: u32 = 0x80;
pub const DHASH_STOP_PRESERVE: u32 = 0xFFFF_FF3F;
/// Final start: `(opt_multi_version << 8) & 0xF00 | ctrl & 0xFFFFF0BF | 0x8060`.
pub const DHASH_START_OR: u32 = 0x8060;
pub const DHASH_START_PRESERVE: u32 = 0xFFFF_F0BF;
pub const DHASH_VERSION_SHIFT: u32 = 8;
pub const DHASH_VERSION_MASK: u32 = 0xF00;
/// `bitmain_soc_init` / reopen: `ctrl & 0xFFFF70DF | 0x8100`.
pub const DHASH_SOC_INIT_PRESERVE: u32 = 0xFFFF_70DF;
pub const DHASH_SOC_INIT_OR: u32 = 0x8100;
/// `send_job` path when the pool does not support AB: `ctrl & 0xFFFF709F | 0x8160`.
pub const DHASH_NO_AB_PRESERVE: u32 = 0xFFFF_709F;
pub const DHASH_NO_AB_OR: u32 = 0x8160;
/// `set_block_header_version_1(bbversion | 0x4000)`.
pub const VERSION_1_AB_OR: u32 = 0x4000;
pub const NONCE_FIFO_ENABLE: u32 = 0x0001_0000;
pub const TIMEOUT_ENABLE: u32 = 0x8000_0000;
pub const TIMEOUT_MASK: u32 = 0x0001_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeJobError {
    TooShort { observed: usize },
    WrongType { observed: u8 },
    LengthMismatch { declared: usize, observed: usize },
    BadCrc { expected: u16, observed: u16 },
    WorkDispatchRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S9SeJobPacket {
    pub flags: u8,
    pub asic_diff: u8,
    pub job_id: u32,
    pub version: u32,
    pub previous_hash: [u8; 32],
    pub ntime: u32,
    pub nbits: u32,
    pub coinbase_len: u16,
    pub nonce2_offset: u16,
    pub nonce2_size: u8,
    pub merkle_count: u16,
    pub nonce2: u64,
    pub support_ab: bool,
    pub version_num: u32,
}

/// CRC-16/Modbus: reflected poly `0xA001`, init `0xFFFF` (`CRC16@1AE00`).
pub fn s9se_job_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Stock SHA-256 midstate padding length for a coinbase of `len` bytes.
pub fn coinbase_padding_len(coinbase_len: usize) -> usize {
    if coinbase_len & 0x3f <= 55 {
        ((coinbase_len >> 6) + 1) << 6
    } else {
        ((coinbase_len >> 6) + 2) << 6
    }
}

/// `send_job` coinbase pad: `0x80` then bit-length at the last 4 bytes (bswap of `8*len`).
pub fn pad_coinbase(coinbase: &[u8]) -> Vec<u8> {
    let pad_len = coinbase_padding_len(coinbase.len());
    let mut out = vec![0u8; pad_len];
    out[..coinbase.len()].copy_from_slice(coinbase);
    if coinbase.len() < pad_len {
        out[coinbase.len()] = 0x80;
    }
    if pad_len >= 4 {
        let bits = (coinbase.len() as u32).saturating_mul(8).swap_bytes();
        out[pad_len - 4..].copy_from_slice(&bits.to_le_bytes());
    }
    out
}

pub fn dhash_stop_word(previous: u32) -> u32 {
    (previous & DHASH_STOP_PRESERVE) | DHASH_BIT7
}

pub fn dhash_start_word(previous: u32, version_num: u32) -> u32 {
    ((version_num << DHASH_VERSION_SHIFT) & DHASH_VERSION_MASK)
        | (previous & DHASH_START_PRESERVE)
        | DHASH_START_OR
}

/// VIL soc-init / reopen DHASH word. Not a TX permit.
pub fn dhash_soc_init_word(previous: u32) -> u32 {
    (previous & DHASH_SOC_INIT_PRESERVE) | DHASH_SOC_INIT_OR
}

/// `send_job` DHASH start when `pool->support_ab` is false.
pub fn dhash_start_no_ab_word(previous: u32) -> u32 {
    (previous & DHASH_NO_AB_PRESERVE) | DHASH_NO_AB_OR
}

/// `set_block_header_version_1` value. Not a TX permit.
pub fn block_header_version_1(bbversion: u32) -> u32 {
    bbversion | VERSION_1_AB_OR
}

/// `set_job_length` = padded coinbase + 32 × merkle count.
pub fn job_length_bytes(coinbase_padding_len: usize, merkle_count: u16) -> u32 {
    (coinbase_padding_len + 32 * usize::from(merkle_count)) as u32
}

/// `send_job` packs `prev_hash` as eight LE words into `axi[80..=87]`.
pub fn pack_pre_header_hash_words(prev_hash: &[u8; 32]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, word) in out.iter_mut().enumerate() {
        let b = &prev_hash[i * 4..i * 4 + 4];
        *word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    out
}

pub fn job_start_phy(buffer_a: bool) -> u32 {
    if buffer_a {
        JOB_BUFFER_A_PHY_OFF
    } else {
        JOB_BUFFER_B_PHY_OFF
    }
}

pub fn coinbase_nonce2_word(padding_len: usize, nonce2_offset: u16, nonce2_bytes: u8) -> u32 {
    (u32::from(nonce2_bytes) << 8)
        | (u32::from(nonce2_offset) << 16)
        | (u32::from((padding_len >> 6) as u8))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// Decode one stock `parse_job_to_soc` packet. Not a work-TX permit.
pub fn decode_s9se_job(data: &[u8]) -> Result<S9SeJobPacket, S9SeJobError> {
    if data.len() < JOB_HEADER_LEN + JOB_CRC_LEN {
        return Err(S9SeJobError::TooShort {
            observed: data.len(),
        });
    }
    let typ = data[0];
    if typ != JOB_TYPE {
        return Err(S9SeJobError::WrongType { observed: typ });
    }
    let declared = read_u32_le(data, 4).ok_or(S9SeJobError::TooShort {
        observed: data.len(),
    })? as usize
        + 8;
    if declared != data.len() {
        return Err(S9SeJobError::LengthMismatch {
            declared,
            observed: data.len(),
        });
    }
    let coinbase_len = read_u16_le(data, 0x3c).ok_or(S9SeJobError::TooShort {
        observed: data.len(),
    })?;
    let merkle_count = read_u16_le(data, 0x42).ok_or(S9SeJobError::TooShort {
        observed: data.len(),
    })?;
    let payload_end =
        JOB_HEADER_LEN + usize::from(coinbase_len) + usize::from(merkle_count) * MERKLE_BRANCH_LEN;
    let required = payload_end + JOB_CRC_LEN;
    if required != data.len() {
        return Err(S9SeJobError::LengthMismatch {
            declared: required,
            observed: data.len(),
        });
    }
    let expected = s9se_job_crc16(&data[..payload_end]);
    let observed = read_u16_le(data, payload_end).ok_or(S9SeJobError::TooShort {
        observed: data.len(),
    })?;
    if expected != observed {
        return Err(S9SeJobError::BadCrc { expected, observed });
    }
    let previous_hash: [u8; 32] =
        data[0x14..0x34]
            .try_into()
            .map_err(|_| S9SeJobError::TooShort {
                observed: data.len(),
            })?;
    Ok(S9SeJobPacket {
        flags: data[0x09],
        asic_diff: data[0x0a],
        job_id: read_u32_le(data, 0x0c).unwrap_or(0),
        version: read_u32_le(data, 0x10).unwrap_or(0),
        previous_hash,
        ntime: read_u32_le(data, 0x34).unwrap_or(0),
        nbits: read_u32_le(data, 0x38).unwrap_or(0),
        coinbase_len,
        nonce2_offset: read_u16_le(data, 0x3e).unwrap_or(0),
        nonce2_size: data[0x40],
        merkle_count,
        nonce2: read_u64_le(data, 0x48).unwrap_or(0),
        support_ab: data[0x50] != 0,
        version_num: read_u32_le(data, 0x54).unwrap_or(0),
    })
}

/// Pack a minimal header+payload+CRC job. Desk fixture only.
pub fn pack_s9se_job(
    job: &S9SeJobPacket,
    coinbase: &[u8],
    merkles: &[u8],
) -> Result<Vec<u8>, S9SeJobError> {
    if coinbase.len() != usize::from(job.coinbase_len) {
        return Err(S9SeJobError::LengthMismatch {
            declared: usize::from(job.coinbase_len),
            observed: coinbase.len(),
        });
    }
    let merkle_len = usize::from(job.merkle_count) * MERKLE_BRANCH_LEN;
    if merkles.len() != merkle_len {
        return Err(S9SeJobError::LengthMismatch {
            declared: merkle_len,
            observed: merkles.len(),
        });
    }
    let buf_len = coinbase.len() + merkle_len + JOB_TRAILER_OVERHEAD;
    let mut out = vec![0u8; buf_len];
    out[0] = JOB_TYPE;
    let body = (buf_len - 8) as u32;
    out[4..8].copy_from_slice(&body.to_le_bytes());
    out[0x09] = job.flags;
    out[0x0a] = job.asic_diff;
    out[0x0c..0x10].copy_from_slice(&job.job_id.to_le_bytes());
    out[0x10..0x14].copy_from_slice(&job.version.to_le_bytes());
    out[0x14..0x34].copy_from_slice(&job.previous_hash);
    out[0x34..0x38].copy_from_slice(&job.ntime.to_le_bytes());
    out[0x38..0x3c].copy_from_slice(&job.nbits.to_le_bytes());
    out[0x3c..0x3e].copy_from_slice(&job.coinbase_len.to_le_bytes());
    out[0x3e..0x40].copy_from_slice(&job.nonce2_offset.to_le_bytes());
    out[0x40] = job.nonce2_size;
    out[0x42..0x44].copy_from_slice(&job.merkle_count.to_le_bytes());
    out[0x48..0x50].copy_from_slice(&job.nonce2.to_le_bytes());
    out[0x50] = u8::from(job.support_ab);
    out[0x54..0x58].copy_from_slice(&job.version_num.to_le_bytes());
    out[JOB_HEADER_LEN..JOB_HEADER_LEN + coinbase.len()].copy_from_slice(coinbase);
    out[JOB_HEADER_LEN + coinbase.len()..buf_len - JOB_CRC_LEN].copy_from_slice(merkles);
    let crc = s9se_job_crc16(&out[..buf_len - JOB_CRC_LEN]);
    out[buf_len - 2..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn refuse_s9se_job_dispatch() -> Result<(), S9SeJobError> {
    match refuse_s9se_work_dispatch() {
        Err(_) => Err(S9SeJobError::WorkDispatchRefused),
        Ok(()) => Err(S9SeJobError::WorkDispatchRefused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> (S9SeJobPacket, Vec<u8>, Vec<u8>) {
        let coinbase = vec![0u8; 80];
        let job = S9SeJobPacket {
            flags: FLAG_CLEAN | FLAG_TICKET_UPDATE,
            asic_diff: DEFAULT_ASIC_DIFF,
            job_id: 7,
            version: 0x2000_0000,
            previous_hash: [0x11; 32],
            ntime: 0x5c24_0001,
            nbits: 0x1705_a3a3,
            coinbase_len: 80,
            nonce2_offset: 32,
            nonce2_size: 4,
            merkle_count: 1,
            nonce2: 0x0102_0304,
            support_ab: true,
            version_num: 2,
        };
        (job, coinbase, vec![0x22; 32])
    }

    #[test]
    fn pack_then_decode_round_trips_stock_header() {
        let (job, coinbase, merkles) = sample_job();
        let bytes = pack_s9se_job(&job, &coinbase, &merkles).unwrap();
        assert_eq!(bytes[0], JOB_TYPE);
        assert_eq!(bytes.len(), 80 + 32 + 90);
        let back = decode_s9se_job(&bytes).unwrap();
        assert_eq!(back.job_id, 7);
        assert_eq!(back.asic_diff, 15);
        assert_eq!(back.flags & FLAG_TICKET_UPDATE, FLAG_TICKET_UPDATE);
        assert_eq!(back.coinbase_len, 80);
        assert_eq!(back.merkle_count, 1);
        assert_eq!(back.version_num, 2);
        assert_eq!(back.previous_hash[0], 0x11);
        assert!(decode_s9se_job(&bytes[1..]).is_err());
        let mut bad = bytes.clone();
        bad[0] = 0x12;
        assert!(matches!(
            decode_s9se_job(&bad),
            Err(S9SeJobError::WrongType { observed: 0x12 })
        ));
        let mut crc_bad = bytes;
        let last = crc_bad.len() - 1;
        crc_bad[last] ^= 0xff;
        assert!(matches!(
            decode_s9se_job(&crc_bad),
            Err(S9SeJobError::BadCrc { .. })
        ));
    }

    #[test]
    fn coinbase_padding_and_dhash_words_match_stock() {
        assert_eq!(coinbase_padding_len(55), 64);
        assert_eq!(coinbase_padding_len(56), 128);
        assert_eq!(coinbase_padding_len(80), 128);
        let padded = pad_coinbase(&[1, 2, 3]);
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[3], 0x80);
        assert_eq!(dhash_stop_word(0xFFFF_FFFF), 0xFFFF_FFBF);
        assert_eq!(dhash_start_word(0, 2) & DHASH_VERSION_MASK, 0x200);
        assert_eq!(dhash_start_word(0, 2) & DHASH_START_OR, DHASH_START_OR);
        assert_eq!(dhash_soc_init_word(0xFFFF_FFFF), 0xFFFF_F1DF);
        assert_eq!(dhash_start_no_ab_word(0), DHASH_NO_AB_OR);
        assert_eq!(block_header_version_1(0x2000_0000), 0x2000_4000);
        assert_eq!(job_length_bytes(128, 1), 160);
        assert_eq!(pack_pre_header_hash_words(&[0x11; 32])[0], 0x1111_1111);
        assert_eq!(job_start_phy(true), 0x0020_0000);
        assert_eq!(job_start_phy(false), 0x0021_0000);
        assert_eq!(
            refuse_s9se_job_dispatch(),
            Err(S9SeJobError::WorkDispatchRefused)
        );
    }
}
