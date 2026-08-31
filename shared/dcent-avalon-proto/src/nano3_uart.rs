// SPDX-License-Identifier: GPL-3.0-or-later
//
// Receive codec for the native Nano 3 Linux <-> mining-controller UART.
//
// This is NOT the K230 `mm_pkg` IPC protocol used by the published Nano 3S
// split-core firmware.  Stock Nano 3 Linux `btcminer` talks to its controller
// on `/dev/ttyS1` using the compact `CN` envelope decoded here.
//
// Evidence boundary (stock Nano 3 btcminer SHA-256 e6c11630...ca6751):
//   - uart_init                    0x000be4e0
//   - data_toast_recv_thread      0x000b54b0
//   - data_toast_receive/send     0x000b57a0 / 0x000b58d0
//   - polling                     0x0002d060 (0x50/0x51 handlers)
//   - crc16                       0x0014d6a0, table 0x00238840
//
// This module deliberately has no encoder or device I/O.  The separately
// bounded `nano3_uart_tx` module serializes only held-binary-proven packet
// components; it still grants no transmit or mining authority and refuses a
// complete init/job contract while required semantics remain unresolved.

/// Bytes before the variable payload.
pub const HEADER_LEN: usize = 12;

/// Largest payload accepted by stock `data_toast_recv_thread`.
pub const MAX_PAYLOAD_LEN: usize = 128;

/// Largest complete native UART frame.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// Fixed size of one nonce result in a 0x50 payload.
pub const NONCE_RECORD_LEN: usize = 16;

/// Bytes consumed by the proven portion of a 0x51 summary-status payload.
pub const SUMMARY_STATUS_LEN: usize = 52;

/// Exact send attempts stock permits for each type-0x33 polling exchange.
pub const STOCK_POLL_ATTEMPT_LIMIT: u8 = 5;

/// Exact receive timeout for each type-0x33 polling attempt.
pub const STOCK_POLL_RESPONSE_TIMEOUT_MS: u32 = 200;

/// Consecutive failed polling exchanges after which stock detaches the module.
pub const STOCK_POLL_MISSES_BEFORE_DETACH: u8 = 30;

/// Native UART frame magic, centralized for RX stream recovery and the
/// evidence-bounded pure TX serializer.
pub const MAGIC: [u8; 2] = *b"CN";

/// Receive packet types explicitly handled by the held stock binary.
///
/// Names remain numeric where the binary proves dispatch but not a stable
/// semantic contract.  This prevents a guessed telemetry meaning from becoming
/// API surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RxType {
    DetectAck = 0x11,
    SyncAck = 0x13,
    InfoResponse = 0x15,
    Nonce = 0x50,
    SummaryStatus = 0x51,
    Status52 = 0x52,
    Status53 = 0x53,
    Status54 = 0x54,
    Status55 = 0x55,
    Status60 = 0x60,
    Status71 = 0x71,
}

impl TryFrom<u8> for RxType {
    type Error = Nano3UartError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x11 => Self::DetectAck,
            0x13 => Self::SyncAck,
            0x15 => Self::InfoResponse,
            0x50 => Self::Nonce,
            0x51 => Self::SummaryStatus,
            0x52 => Self::Status52,
            0x53 => Self::Status53,
            0x54 => Self::Status54,
            0x55 => Self::Status55,
            0x60 => Self::Status60,
            0x71 => Self::Status71,
            other => return Err(Nano3UartError::UnsupportedRxType(other)),
        })
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3UartError {
    #[error("native UART frame is shorter than the {HEADER_LEN}-byte header: {0} bytes")]
    TooShort(usize),

    #[error("bad native UART magic: expected 43 4e, got {0:02x} {1:02x}")]
    BadMagic(u8, u8),

    #[error("native UART payload length {0} exceeds {MAX_PAYLOAD_LEN}")]
    PayloadTooLong(usize),

    #[error("native UART frame length mismatch: header declares {declared}, got {actual}")]
    LengthMismatch { declared: usize, actual: usize },

    #[error("native UART CRC mismatch: expected 0x{expected:04x}, calculated 0x{calculated:04x}")]
    CrcMismatch { expected: u16, calculated: u16 },

    #[error("unsupported native UART receive type 0x{0:02x}")]
    UnsupportedRxType(u8),

    #[error("packet type mismatch: expected 0x{expected:02x}, got 0x{actual:02x}")]
    UnexpectedType { expected: u8, actual: u8 },

    #[error("nonce payload length {0} is not a multiple of {NONCE_RECORD_LEN}")]
    NoncePayloadMisaligned(usize),

    #[error(
        "summary-status payload is too short: expected at least {SUMMARY_STATUS_LEN}, got {0}"
    )]
    SummaryStatusTooShort(usize),
}

/// One completely validated, borrowed native UART envelope.
///
/// Packet type stays numeric so offline capture analysis can inspect both
/// directions without implying that an observed TX type is safe to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeUartEnvelope<'a> {
    pub packet_type: u8,
    pub option: u8,
    pub index: u16,
    pub count: u16,
    pub payload: &'a [u8],
    pub crc: u16,
}

/// A completely validated, borrowed receive frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxFrame<'a> {
    pub packet_type: RxType,
    pub option: u8,
    pub index: u16,
    pub count: u16,
    pub payload: &'a [u8],
    pub crc: u16,
}

/// Decode exactly one native UART envelope without assigning direction or
/// packet semantics.
///
/// The input must contain one whole frame and nothing else.  Stream resync and
/// buffering belong to a later transport layer; silently accepting a prefix or
/// trailing bytes here would weaken the safety boundary.
pub fn decode_native_uart_envelope(bytes: &[u8]) -> Result<NativeUartEnvelope<'_>, Nano3UartError> {
    if bytes.len() < HEADER_LEN {
        return Err(Nano3UartError::TooShort(bytes.len()));
    }
    if bytes[..2] != MAGIC {
        return Err(Nano3UartError::BadMagic(bytes[0], bytes[1]));
    }

    let payload_len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(Nano3UartError::PayloadTooLong(payload_len));
    }

    let declared = HEADER_LEN + payload_len;
    if bytes.len() != declared {
        return Err(Nano3UartError::LengthMismatch {
            declared,
            actual: bytes.len(),
        });
    }

    let expected = u16::from_le_bytes([bytes[2], bytes[3]]);
    let calculated = crc16_xmodem(&bytes[4..]);
    if expected != calculated {
        return Err(Nano3UartError::CrcMismatch {
            expected,
            calculated,
        });
    }

    Ok(NativeUartEnvelope {
        packet_type: bytes[4],
        option: bytes[5],
        index: u16::from_le_bytes([bytes[6], bytes[7]]),
        count: u16::from_le_bytes([bytes[8], bytes[9]]),
        payload: &bytes[HEADER_LEN..],
        crc: expected,
    })
}

/// Decode exactly one native receive frame and apply the held RX allowlist.
pub fn decode_rx_frame(bytes: &[u8]) -> Result<RxFrame<'_>, Nano3UartError> {
    let envelope = decode_native_uart_envelope(bytes)?;
    Ok(RxFrame {
        packet_type: RxType::try_from(envelope.packet_type)?,
        option: envelope.option,
        index: envelope.index,
        count: envelope.count,
        payload: envelope.payload,
        crc: envelope.crc,
    })
}

/// CRC-16/XMODEM used by the native UART envelope.
///
/// Parameters: polynomial 0x1021, init 0x0000, refin=false, refout=false,
/// xorout=0x0000.  The resulting u16 is stored little-endian in frame bytes 2-3.
pub fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
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

/// One 16-byte result record from a 0x50 packet.
///
/// Mixed endianness is intentional and matches stock polling at 0x2d6ac:
/// job CRC is big-endian, pool index and nonce2 are little-endian, and the wire
/// nonce is byte-reversed before stock submits it to cgminer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceRecord {
    pub job_id_crc: u16,
    pub pool_index: u16,
    pub nonce2: u32,
    pub nonce: u32,
    pub asic_id: u8,
    pub miner_id: u8,
    pub ntime_offset: u8,
    /// Low nibble passed to stock `submit_nonce2_nonce` as `mid_id`.
    pub mid_id: u8,
    /// High nibble.  Stock ignores the record when this is zero.
    pub valid_marker: u8,
}

impl NonceRecord {
    pub fn is_valid(self) -> bool {
        self.valid_marker != 0
    }
}

/// Borrowed iterator over validated 0x50 nonce records.
pub struct NonceRecords<'a> {
    chunks: core::slice::ChunksExact<'a, u8>,
}

impl Iterator for NonceRecords<'_> {
    type Item = NonceRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.chunks.next()?;
        Some(NonceRecord {
            job_id_crc: u16::from_be_bytes([record[0], record[1]]),
            pool_index: u16::from_le_bytes([record[2], record[3]]),
            nonce2: u32::from_le_bytes(record[4..8].try_into().expect("fixed nonce chunk")),
            nonce: u32::from_be_bytes(record[8..12].try_into().expect("fixed nonce chunk")),
            asic_id: record[12],
            miner_id: record[13],
            ntime_offset: record[14],
            mid_id: record[15] & 0x0f,
            valid_marker: record[15] >> 4,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.chunks.size_hint()
    }
}

impl ExactSizeIterator for NonceRecords<'_> {}

pub fn nonce_records<'a>(frame: &RxFrame<'a>) -> Result<NonceRecords<'a>, Nano3UartError> {
    if frame.packet_type != RxType::Nonce {
        return Err(Nano3UartError::UnexpectedType {
            expected: RxType::Nonce as u8,
            actual: frame.packet_type as u8,
        });
    }
    if !frame.payload.len().is_multiple_of(NONCE_RECORD_LEN) {
        return Err(Nano3UartError::NoncePayloadMisaligned(frame.payload.len()));
    }
    Ok(NonceRecords {
        chunks: frame.payload.chunks_exact(NONCE_RECORD_LEN),
    })
}

/// Proven 52-byte prefix of a 0x51 summary-status response.
///
/// The held binary proves a few consumer-facing meanings (`LW`, `DH`, `TA`,
/// `Core`, work level, target temperature, soft-off, LCD adapter) but not every
/// producer-side field name.  Unproven fields stay explicitly raw.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SummaryStatus<'a> {
    pub hash_status: u8,
    pub raw_01: u32,
    /// Printed by stock as `LW` (local work).
    pub local_work: u32,
    pub raw_09: u64,
    /// Printed by stock as `DH`.
    pub dh: f64,
    /// Printed by stock as `DHspd`.
    pub dh_speed: f64,
    /// Printed by stock as `TA`; its low byte is also the ASIC-count bound.
    pub total_asics: u32,
    pub asic_count: u8,
    /// Four bytes copied into stock's NUL-terminated `Core` field.
    pub core_tag: [u8; 4],
    pub raw_41: u16,
    pub raw_43: u8,
    /// Initialized to -273 by stock and consumed by its temperature path.
    pub temperature_raw: i32,
    pub work_level: u8,
    pub target_temperature: u8,
    pub soft_off: u8,
    pub lcd_adapter: u8,
    pub trailing: &'a [u8],
}

/// What the held stock implementation would place in its next type-0x33 poll.
///
/// This is an observation-only classification. In particular,
/// `StatefulResetSelector` is not authority to serialize or send selector 1;
/// the public TX research surface intentionally exposes selector 0 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockNextPollAction {
    ReadOnlySelector,
    StatefulResetSelector,
}

impl SummaryStatus<'_> {
    pub const fn stock_next_poll_action(&self) -> StockNextPollAction {
        match self.hash_status {
            4 | 7 => StockNextPollAction::StatefulResetSelector,
            _ => StockNextPollAction::ReadOnlySelector,
        }
    }
}

pub fn summary_status<'a>(frame: &RxFrame<'a>) -> Result<SummaryStatus<'a>, Nano3UartError> {
    if frame.packet_type != RxType::SummaryStatus {
        return Err(Nano3UartError::UnexpectedType {
            expected: RxType::SummaryStatus as u8,
            actual: frame.packet_type as u8,
        });
    }
    let p = frame.payload;
    if p.len() < SUMMARY_STATUS_LEN {
        return Err(Nano3UartError::SummaryStatusTooShort(p.len()));
    }

    let total_asics = u32::from_le_bytes(p[33..37].try_into().expect("checked status prefix"));
    Ok(SummaryStatus {
        hash_status: p[0],
        raw_01: u32::from_le_bytes(p[1..5].try_into().expect("checked status prefix")),
        local_work: u32::from_le_bytes(p[5..9].try_into().expect("checked status prefix")),
        raw_09: u64::from_le_bytes(p[9..17].try_into().expect("checked status prefix")),
        dh: f64::from_bits(u64::from_le_bytes(
            p[17..25].try_into().expect("checked status prefix"),
        )),
        dh_speed: f64::from_bits(u64::from_le_bytes(
            p[25..33].try_into().expect("checked status prefix"),
        )),
        total_asics,
        asic_count: total_asics as u8,
        core_tag: p[37..41].try_into().expect("checked status prefix"),
        raw_41: u16::from_le_bytes(p[41..43].try_into().expect("checked status prefix")),
        raw_43: p[43],
        temperature_raw: i32::from_le_bytes(p[44..48].try_into().expect("checked status prefix")),
        work_level: p[48],
        target_temperature: p[49],
        soft_off: p[50],
        lcd_adapter: p[51],
        trailing: &p[SUMMARY_STATUS_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(packet_type: u8, option: u8, index: u16, count: u16, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= MAX_PAYLOAD_LEN);
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&[0, 0]);
        bytes.push(packet_type);
        bytes.push(option);
        bytes.extend_from_slice(&index.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(payload);
        let crc = crc16_xmodem(&bytes[4..]);
        bytes[2..4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn crc_matches_xmodem_canonical_check() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
    }

    #[test]
    fn crc_matches_held_binary_detect_envelope_kat() {
        // TX bytes reconstructed from detect_modules solely as a CRC/envelope KAT.
        // No TX serializer is exposed by this module.
        let protected = [0x10, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0];
        assert_eq!(crc16_xmodem(&protected), 0x7622);
    }

    #[test]
    fn crc_matches_held_binary_read_only_poll_envelope_kat() {
        // Normal stock polling uses a zero payload.  A BE value of one in the
        // same payload selects the stateful reset path and is intentionally not
        // represented here or by any public encoder.
        let protected = [0x33, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0];
        assert_eq!(crc16_xmodem(&protected), 0x1d1d);
    }

    #[test]
    fn decodes_each_proven_receive_type_and_header_endianness() {
        let types = [
            0x11, 0x13, 0x15, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x60, 0x71,
        ];
        for packet_type in types {
            let bytes = fixture(packet_type, 0xa5, 0x1234, 0x5678, &[1, 2, 3]);
            let frame = decode_rx_frame(&bytes).unwrap();
            assert_eq!(frame.packet_type as u8, packet_type);
            assert_eq!(frame.option, 0xa5);
            assert_eq!(frame.index, 0x1234);
            assert_eq!(frame.count, 0x5678);
            assert_eq!(frame.payload, [1, 2, 3]);
        }
    }

    #[test]
    fn rejects_every_unproven_receive_type() {
        let supported = [
            0x11, 0x13, 0x15, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x60, 0x71,
        ];
        for packet_type in 0u8..=u8::MAX {
            if supported.contains(&packet_type) {
                continue;
            }
            let bytes = fixture(packet_type, 0, 0, 1, &[]);
            assert_eq!(
                decode_rx_frame(&bytes),
                Err(Nano3UartError::UnsupportedRxType(packet_type))
            );
        }
    }

    #[test]
    fn frame_validation_fails_closed() {
        assert_eq!(decode_rx_frame(&[0; 11]), Err(Nano3UartError::TooShort(11)));

        let mut bad_magic = fixture(0x11, 0, 0, 1, &[]);
        bad_magic[0] = b'X';
        assert_eq!(
            decode_rx_frame(&bad_magic),
            Err(Nano3UartError::BadMagic(b'X', b'N'))
        );

        let mut too_long = fixture(0x11, 0, 0, 1, &[]);
        too_long[10..12].copy_from_slice(&129u16.to_le_bytes());
        assert_eq!(
            decode_rx_frame(&too_long),
            Err(Nano3UartError::PayloadTooLong(129))
        );

        let bytes = fixture(0x11, 0, 0, 1, &[1, 2]);
        assert_eq!(
            decode_rx_frame(&bytes[..bytes.len() - 1]),
            Err(Nano3UartError::LengthMismatch {
                declared: 14,
                actual: 13
            })
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_rx_frame(&trailing),
            Err(Nano3UartError::LengthMismatch {
                declared: 14,
                actual: 15
            })
        );

        let mut bad_crc = bytes;
        bad_crc[12] ^= 1;
        assert!(matches!(
            decode_rx_frame(&bad_crc),
            Err(Nano3UartError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn decodes_mixed_endian_nonce_record() {
        let record = [
            0x12, 0x34, // job CRC, BE
            0x78, 0x56, // pool index, LE
            0x04, 0x03, 0x02, 0x01, // nonce2, LE
            0xde, 0xad, 0xbe, 0xef, // semantic nonce, BE after stock revw
            9, 0, 7, 0xa3, // ASIC, miner, ntime, valid/mid
        ];
        let bytes = fixture(0x50, 0, 0, 1, &record);
        let frame = decode_rx_frame(&bytes).unwrap();
        let records: Vec<_> = nonce_records(&frame).unwrap().collect();
        assert_eq!(
            records,
            [NonceRecord {
                job_id_crc: 0x1234,
                pool_index: 0x5678,
                nonce2: 0x01020304,
                nonce: 0xdeadbeef,
                asic_id: 9,
                miner_id: 0,
                ntime_offset: 7,
                mid_id: 3,
                valid_marker: 10,
            }]
        );
        assert!(records[0].is_valid());
    }

    #[test]
    fn nonce_parser_rejects_wrong_type_and_partial_record() {
        let wrong = fixture(0x51, 0, 0, 1, &[]);
        let wrong = decode_rx_frame(&wrong).unwrap();
        assert!(matches!(
            nonce_records(&wrong),
            Err(Nano3UartError::UnexpectedType { .. })
        ));

        let partial = fixture(0x50, 0, 0, 1, &[0; 15]);
        let partial = decode_rx_frame(&partial).unwrap();
        assert_eq!(
            nonce_records(&partial).err(),
            Some(Nano3UartError::NoncePayloadMisaligned(15))
        );
    }

    #[test]
    fn decodes_proven_summary_status_prefix_and_preserves_extension() {
        let mut payload = Vec::new();
        payload.push(4);
        payload.extend_from_slice(&0x01020304u32.to_le_bytes());
        payload.extend_from_slice(&0x11223344u32.to_le_bytes());
        payload.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        payload.extend_from_slice(&12.5f64.to_le_bytes());
        payload.extend_from_slice(&0.125f64.to_le_bytes());
        payload.extend_from_slice(&10u32.to_le_bytes());
        payload.extend_from_slice(b"8510");
        payload.extend_from_slice(&0x3344u16.to_le_bytes());
        payload.push(0x55);
        payload.extend_from_slice(&(-17i32).to_le_bytes());
        payload.extend_from_slice(&[2, 90, 6, 0xff, 0xaa]);

        let bytes = fixture(0x51, 0, 0, 1, &payload);
        let frame = decode_rx_frame(&bytes).unwrap();
        let status = summary_status(&frame).unwrap();
        assert_eq!(status.hash_status, 4);
        assert_eq!(status.raw_01, 0x01020304);
        assert_eq!(status.local_work, 0x11223344);
        assert_eq!(status.raw_09, 0x0102030405060708);
        assert_eq!(status.dh, 12.5);
        assert_eq!(status.dh_speed, 0.125);
        assert_eq!(status.total_asics, 10);
        assert_eq!(status.asic_count, 10);
        assert_eq!(status.core_tag, *b"8510");
        assert_eq!(status.raw_41, 0x3344);
        assert_eq!(status.raw_43, 0x55);
        assert_eq!(status.temperature_raw, -17);
        assert_eq!(status.work_level, 2);
        assert_eq!(status.target_temperature, 90);
        assert_eq!(status.soft_off, 6);
        assert_eq!(status.lcd_adapter, 0xff);
        assert_eq!(status.trailing, [0xaa]);
    }

    #[test]
    fn summary_status_classifies_stock_stateful_reset_without_encoding_it() {
        assert_eq!(STOCK_POLL_ATTEMPT_LIMIT, 5);
        assert_eq!(STOCK_POLL_RESPONSE_TIMEOUT_MS, 200);
        assert_eq!(STOCK_POLL_MISSES_BEFORE_DETACH, 30);

        for hash_status in [4, 7] {
            let mut payload = [0u8; SUMMARY_STATUS_LEN];
            payload[0] = hash_status;
            let bytes = fixture(0x51, 0, 0, 1, &payload);
            let frame = decode_rx_frame(&bytes).unwrap();
            assert_eq!(
                summary_status(&frame).unwrap().stock_next_poll_action(),
                StockNextPollAction::StatefulResetSelector
            );
        }

        for hash_status in [0, 1, 3, 5, 6, 8, u8::MAX] {
            let mut payload = [0u8; SUMMARY_STATUS_LEN];
            payload[0] = hash_status;
            let bytes = fixture(0x51, 0, 0, 1, &payload);
            let frame = decode_rx_frame(&bytes).unwrap();
            assert_eq!(
                summary_status(&frame).unwrap().stock_next_poll_action(),
                StockNextPollAction::ReadOnlySelector
            );
        }
        // There remains no public selector-1 encoder in this module.
    }

    #[test]
    fn summary_parser_rejects_wrong_type_and_short_payload() {
        let wrong = fixture(0x50, 0, 0, 1, &[]);
        let wrong = decode_rx_frame(&wrong).unwrap();
        assert!(matches!(
            summary_status(&wrong),
            Err(Nano3UartError::UnexpectedType { .. })
        ));

        let short = fixture(0x51, 0, 0, 1, &[0; SUMMARY_STATUS_LEN - 1]);
        let short = decode_rx_frame(&short).unwrap();
        assert_eq!(
            summary_status(&short),
            Err(Nano3UartError::SummaryStatusTooShort(
                SUMMARY_STATUS_LEN - 1
            ))
        );
    }
}
