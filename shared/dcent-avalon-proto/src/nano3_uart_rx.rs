// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounded receive-side state for the native Nano 3 controller UART.
//
// This module deliberately contains no encoder and performs no I/O.  It turns
// an untrusted byte stream into owned, fully envelope-validated RX frames and
// admits nonce records only when they can be associated unambiguously with one
// of the three job snapshots retained by the held stock implementation.
// Structural admission is not Bitcoin share validation: the caller must still
// reconstruct the exact header and verify its hash against the assigned target.

use std::collections::VecDeque;

use crate::nano3_uart::{
    crc16_xmodem, decode_rx_frame, Nano3UartError, NonceRecord, RxFrame, RxType, HEADER_LEN, MAGIC,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
};

const MAGIC_FIRST: u8 = MAGIC[0];
const MAGIC_SECOND: u8 = MAGIC[1];

/// Stock attempts to match a nonce against the current and two older jobs.
pub const RECENT_JOB_LIMIT: usize = 3;

/// Highest micro-job selector proven for stock's type-0x27 words (0, 2, 4, 8).
pub const MAX_NANO3_MID_ID: u8 = 3;

/// The only ASIC count admitted for the held non-S Nano 3 profile.
///
/// Re-exported from the explicit identity profile so the RX and daemon custody
/// gates cannot drift apart. Identity still grants no TX or mining authority.
pub use crate::nano3_profile::NANO3_REQUIRED_ASIC_COUNT as NANO3_ASIC_COUNT;

/// An owned, fully envelope-validated receive frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRxFrame {
    pub packet_type: RxType,
    pub option: u8,
    pub index: u16,
    pub count: u16,
    pub payload: Vec<u8>,
    pub crc: u16,
}

impl OwnedRxFrame {
    pub fn as_borrowed(&self) -> RxFrame<'_> {
        RxFrame {
            packet_type: self.packet_type,
            option: self.option,
            index: self.index,
            count: self.count,
            payload: &self.payload,
            crc: self.crc,
        }
    }
}

impl From<RxFrame<'_>> for OwnedRxFrame {
    fn from(frame: RxFrame<'_>) -> Self {
        Self {
            packet_type: frame.packet_type,
            option: frame.option,
            index: frame.index,
            count: frame.count,
            payload: frame.payload.to_vec(),
            crc: frame.crc,
        }
    }
}

/// Fixed-capacity bytewise stream decoder.
///
/// Noise before `CN` is discarded.  A second `C` while waiting for `N` is
/// retained as the beginning of a new candidate, which handles overlapping
/// `CCN` input without losing the valid prefix.  Invalid length, CRC, and type
/// errors are surfaced to the caller; after the error the decoder remains
/// usable and resumes its magic scan.  It never buffers more than 140 bytes.
#[derive(Debug, Clone)]
pub struct RxStreamDecoder {
    buffer: [u8; MAX_FRAME_LEN],
    buffered: usize,
    expected: Option<usize>,
}

impl Default for RxStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RxStreamDecoder {
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_FRAME_LEN],
            buffered: 0,
            expected: None,
        }
    }

    pub const fn buffered_len(&self) -> usize {
        self.buffered
    }

    /// Consume one byte and return at most one complete validated frame.
    pub fn push_byte(&mut self, byte: u8) -> Result<Option<OwnedRxFrame>, Nano3UartError> {
        match self.buffered {
            0 => {
                if byte == MAGIC_FIRST {
                    self.buffer[0] = byte;
                    self.buffered = 1;
                }
                return Ok(None);
            }
            1 => {
                if byte == MAGIC_SECOND {
                    self.buffer[1] = byte;
                    self.buffered = 2;
                } else if byte == MAGIC_FIRST {
                    // Preserve this byte as a possible overlapping prefix.
                    self.buffer[0] = byte;
                } else {
                    self.reset();
                }
                return Ok(None);
            }
            _ => {}
        }

        // MAX_FRAME_LEN is an invariant: expected length is validated as soon
        // as the complete header arrives, before any payload byte is accepted.
        debug_assert!(self.buffered < MAX_FRAME_LEN);
        self.buffer[self.buffered] = byte;
        self.buffered += 1;

        if self.buffered == HEADER_LEN {
            let payload_len = u16::from_le_bytes([self.buffer[10], self.buffer[11]]) as usize;
            if payload_len > MAX_PAYLOAD_LEN {
                self.retain_trailing_magic_prefix();
                return Err(Nano3UartError::PayloadTooLong(payload_len));
            }
            self.expected = Some(HEADER_LEN + payload_len);
        }

        if self.expected != Some(self.buffered) {
            return Ok(None);
        }

        let result = decode_rx_frame(&self.buffer[..self.buffered]).map(OwnedRxFrame::from);
        if result.is_ok() {
            self.reset();
        } else {
            self.retain_trailing_magic_prefix();
        }
        result.map(Some)
    }

    fn reset(&mut self) {
        self.buffered = 0;
        self.expected = None;
    }

    fn retain_trailing_magic_prefix(&mut self) {
        let retain = self.buffered > 0 && self.buffer[self.buffered - 1] == MAGIC_FIRST;
        self.reset();
        if retain {
            self.buffer[0] = MAGIC_FIRST;
            self.buffered = 1;
        }
    }
}

/// Identity carried on the wire for a retained Stratum job snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nano3JobIdentity {
    pub job_id_crc: u16,
    pub pool_index: u16,
    /// Process-local monotonic identity.  This is not sent to hardware.
    pub generation: u64,
}

/// One retained job plus the full caller-owned material needed for later
/// cryptographic share validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentNano3Job<T> {
    pub identity: Nano3JobIdentity,
    pub job: T,
}

/// Current plus two older Nano 3 jobs, matching the held stock search depth.
#[derive(Debug, Clone)]
pub struct Nano3RecentJobs<T> {
    jobs: VecDeque<RecentNano3Job<T>>,
    next_generation: u64,
}

impl<T> Default for Nano3RecentJobs<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Nano3RecentJobs<T> {
    pub fn new() -> Self {
        Self {
            jobs: VecDeque::with_capacity(RECENT_JOB_LIMIT),
            next_generation: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Retain a new job as the current snapshot and return its wire identity.
    ///
    /// Only the CRC is retained here; `job` must contain the full immutable
    /// work snapshot required to rebuild and hash a returned nonce.
    pub fn remember(
        &mut self,
        job_id: &str,
        pool_index: u16,
        job: T,
    ) -> Result<Nano3JobIdentity, NonceAdmissionError> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(NonceAdmissionError::GenerationExhausted)?;
        let identity = Nano3JobIdentity {
            job_id_crc: crc16_xmodem(job_id.as_bytes()),
            pool_index,
            generation,
        };

        if self.jobs.len() == RECENT_JOB_LIMIT {
            self.jobs.pop_back();
        }
        self.jobs.push_front(RecentNano3Job { identity, job });
        debug_assert!(self.jobs.len() <= RECENT_JOB_LIMIT);
        Ok(identity)
    }

    /// Structurally admit a nonce and bind it to exactly one retained job.
    ///
    /// This does **not** validate proof of work.  A successful result is only a
    /// candidate; the caller must use `matched_job.job` to rebuild the exact
    /// Bitcoin header, apply ntime/version semantics, hash it, and compare the
    /// hash with the assigned target before submitting a share.
    pub fn admit_nonce_candidate(
        &self,
        record: NonceRecord,
        detected_asic_count: u8,
    ) -> Result<StructurallyAdmittedNonce<'_, T>, NonceAdmissionError> {
        if detected_asic_count != NANO3_ASIC_COUNT {
            return Err(NonceAdmissionError::WrongDetectedAsicCount {
                observed: detected_asic_count,
                required: NANO3_ASIC_COUNT,
            });
        }
        if !record.is_valid() {
            return Err(NonceAdmissionError::InvalidMarker);
        }
        if record.miner_id != 0 {
            return Err(NonceAdmissionError::UnexpectedMinerId(record.miner_id));
        }
        if record.asic_id >= detected_asic_count {
            return Err(NonceAdmissionError::AsicOutOfRange {
                observed: record.asic_id,
                detected: detected_asic_count,
            });
        }
        if record.mid_id > MAX_NANO3_MID_ID {
            return Err(NonceAdmissionError::UnsupportedMidId(record.mid_id));
        }

        let mut matches = self.jobs.iter().enumerate().filter(|(_, job)| {
            job.identity.job_id_crc == record.job_id_crc
                && job.identity.pool_index == record.pool_index
        });
        let Some((history_slot, matched_job)) = matches.next() else {
            return Err(NonceAdmissionError::UnknownJob {
                job_id_crc: record.job_id_crc,
                pool_index: record.pool_index,
            });
        };
        if matches.next().is_some() {
            // CRC16 plus pool index is the entire wire identity.  Two retained
            // matches cannot be distinguished safely, even if their full job
            // ids or generations differ.
            return Err(NonceAdmissionError::AmbiguousJob {
                job_id_crc: record.job_id_crc,
                pool_index: record.pool_index,
            });
        }

        Ok(StructurallyAdmittedNonce {
            record,
            history_slot,
            matched_job,
        })
    }
}

/// A structurally valid nonce candidate.  Possessing this value is not proof
/// of work and grants no authority to submit it to a pool.
#[derive(Debug, Clone, Copy)]
pub struct StructurallyAdmittedNonce<'a, T> {
    record: NonceRecord,
    /// Zero is current, one and two are older snapshots.
    history_slot: usize,
    matched_job: &'a RecentNano3Job<T>,
}

impl<'a, T> StructurallyAdmittedNonce<'a, T> {
    pub const fn record(&self) -> NonceRecord {
        self.record
    }

    pub const fn history_slot(&self) -> usize {
        self.history_slot
    }

    pub const fn matched_job(&self) -> &'a RecentNano3Job<T> {
        self.matched_job
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NonceAdmissionError {
    #[error("Nano 3 nonce admission requires {required} detected ASICs, observed {observed}")]
    WrongDetectedAsicCount { observed: u8, required: u8 },

    #[error("Nano 3 nonce record has a zero validity marker")]
    InvalidMarker,

    #[error("Nano 3 nonce record has unsupported miner id {0}; only zero is admitted")]
    UnexpectedMinerId(u8),

    #[error("Nano 3 nonce ASIC id {observed} is outside detected count {detected}")]
    AsicOutOfRange { observed: u8, detected: u8 },

    #[error("Nano 3 nonce micro-job id {0} is unsupported; only 0 through 3 are proven")]
    UnsupportedMidId(u8),

    #[error("Nano 3 nonce references unknown job CRC 0x{job_id_crc:04x}, pool {pool_index}")]
    UnknownJob { job_id_crc: u16, pool_index: u16 },

    #[error("Nano 3 nonce wire identity is ambiguous: CRC 0x{job_id_crc:04x}, pool {pool_index}")]
    AmbiguousJob { job_id_crc: u16, pool_index: u16 },

    #[error("Nano 3 process-local job generation counter exhausted")]
    GenerationExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx_fixture(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![MAGIC_FIRST, MAGIC_SECOND, 0, 0, packet_type, 0];
        bytes.extend_from_slice(&0x1234u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(payload);
        let crc = crc16_xmodem(&bytes[4..]);
        bytes[2..4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn feed(decoder: &mut RxStreamDecoder, bytes: &[u8]) -> Vec<OwnedRxFrame> {
        bytes
            .iter()
            .filter_map(|&byte| decoder.push_byte(byte).unwrap())
            .collect()
    }

    fn record(identity: Nano3JobIdentity) -> NonceRecord {
        NonceRecord {
            job_id_crc: identity.job_id_crc,
            pool_index: identity.pool_index,
            nonce2: 7,
            nonce: 0x1234_5678,
            asic_id: 9,
            miner_id: 0,
            ntime_offset: 1,
            mid_id: 2,
            valid_marker: 1,
        }
    }

    #[test]
    fn stream_decoder_recovers_from_noise_and_overlapping_magic() {
        let frame = rx_fixture(0x11, &[1, 2, 3]);
        let mut input = vec![0, b'X', b'C', b'C'];
        input.extend_from_slice(&frame[1..]);

        let mut decoder = RxStreamDecoder::new();
        let decoded = feed(&mut decoder, &input);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].packet_type, RxType::DetectAck);
        assert_eq!(decoded[0].index, 0x1234);
        assert_eq!(decoded[0].payload, [1, 2, 3]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn stream_decoder_handles_fragmentation_and_back_to_back_frames() {
        let first = rx_fixture(0x13, &[]);
        let second = rx_fixture(0x51, &[0; 52]);
        let mut decoder = RxStreamDecoder::new();
        let mut decoded = Vec::new();
        for chunk in first
            .iter()
            .chain(second.iter())
            .copied()
            .collect::<Vec<_>>()
            .chunks(3)
        {
            decoded.extend(feed(&mut decoder, chunk));
        }
        assert_eq!(
            decoded.iter().map(|f| f.packet_type).collect::<Vec<_>>(),
            [RxType::SyncAck, RxType::SummaryStatus]
        );
    }

    #[test]
    fn stream_decoder_rejects_oversize_before_buffering_payload_and_recovers() {
        let mut bad = rx_fixture(0x11, &[]);
        bad[10..12].copy_from_slice(&((MAX_PAYLOAD_LEN + 1) as u16).to_le_bytes());
        let mut decoder = RxStreamDecoder::new();
        let mut error = None;
        for byte in bad {
            if let Err(err) = decoder.push_byte(byte) {
                error = Some(err);
            }
        }
        assert_eq!(
            error,
            Some(Nano3UartError::PayloadTooLong(MAX_PAYLOAD_LEN + 1))
        );
        assert!(decoder.buffered_len() <= 1);

        let good = rx_fixture(0x11, &[]);
        assert_eq!(feed(&mut decoder, &good).len(), 1);
    }

    #[test]
    fn stream_decoder_surfaces_crc_failure_then_recovers() {
        let mut bad = rx_fixture(0x11, &[1]);
        *bad.last_mut().unwrap() ^= 1;
        let mut decoder = RxStreamDecoder::new();
        let mut saw_crc_error = false;
        for byte in bad {
            if matches!(
                decoder.push_byte(byte),
                Err(Nano3UartError::CrcMismatch { .. })
            ) {
                saw_crc_error = true;
            }
        }
        assert!(saw_crc_error);
        assert_eq!(feed(&mut decoder, &rx_fixture(0x13, &[])).len(), 1);
    }

    #[test]
    fn recent_jobs_are_strictly_bounded_to_current_plus_two_old() {
        let mut jobs = Nano3RecentJobs::new();
        let first = jobs.remember("job-1", 0, "first").unwrap();
        jobs.remember("job-2", 0, "second").unwrap();
        jobs.remember("job-3", 0, "third").unwrap();
        let newest = jobs.remember("job-4", 0, "fourth").unwrap();
        assert_eq!(jobs.len(), RECENT_JOB_LIMIT);

        assert!(matches!(
            jobs.admit_nonce_candidate(record(first), 10),
            Err(NonceAdmissionError::UnknownJob { .. })
        ));
        let admitted = jobs.admit_nonce_candidate(record(newest), 10).unwrap();
        assert_eq!(admitted.history_slot(), 0);
        assert_eq!(admitted.matched_job().job, "fourth");
    }

    #[test]
    fn nonce_admission_requires_marker_miner_and_asic_bounds() {
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("job", 3, ()).unwrap();

        let mut candidate = record(identity);
        candidate.valid_marker = 0;
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, 10).unwrap_err(),
            NonceAdmissionError::InvalidMarker
        );

        let mut candidate = record(identity);
        candidate.miner_id = 1;
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, 10).unwrap_err(),
            NonceAdmissionError::UnexpectedMinerId(1)
        );

        let candidate = record(identity);
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, 0).unwrap_err(),
            NonceAdmissionError::WrongDetectedAsicCount {
                observed: 0,
                required: NANO3_ASIC_COUNT,
            }
        );
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, 11).unwrap_err(),
            NonceAdmissionError::WrongDetectedAsicCount {
                observed: 11,
                required: NANO3_ASIC_COUNT,
            }
        );
        let mut candidate = record(identity);
        candidate.asic_id = NANO3_ASIC_COUNT;
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, NANO3_ASIC_COUNT)
                .unwrap_err(),
            NonceAdmissionError::AsicOutOfRange {
                observed: NANO3_ASIC_COUNT,
                detected: NANO3_ASIC_COUNT,
            }
        );

        let mut candidate = record(identity);
        candidate.mid_id = MAX_NANO3_MID_ID + 1;
        assert_eq!(
            jobs.admit_nonce_candidate(candidate, NANO3_ASIC_COUNT)
                .unwrap_err(),
            NonceAdmissionError::UnsupportedMidId(MAX_NANO3_MID_ID + 1)
        );
    }

    #[test]
    fn nonce_admission_matches_both_crc_and_pool_index() {
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("job", 3, "snapshot").unwrap();
        let mut candidate = record(identity);
        candidate.pool_index = 4;
        assert!(matches!(
            jobs.admit_nonce_candidate(candidate, 10),
            Err(NonceAdmissionError::UnknownJob { .. })
        ));
    }

    #[test]
    fn duplicate_wire_identity_is_rejected_as_ambiguous() {
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("same-id", 2, "old snapshot").unwrap();
        jobs.remember("same-id", 2, "new snapshot").unwrap();

        assert!(matches!(
            jobs.admit_nonce_candidate(record(identity), 10),
            Err(NonceAdmissionError::AmbiguousJob { .. })
        ));
    }

    #[test]
    fn structurally_admitted_nonce_is_explicitly_only_a_candidate() {
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("job", 1, [0xabu8; 80]).unwrap();
        let admitted = jobs.admit_nonce_candidate(record(identity), 10).unwrap();
        assert_eq!(admitted.matched_job().job, [0xab; 80]);
        assert_eq!(admitted.record().nonce, 0x1234_5678);
        // No API in this module submits the candidate or declares target proof.
    }
}
